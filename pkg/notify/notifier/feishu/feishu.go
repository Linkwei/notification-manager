package feishu

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	json "github.com/json-iterator/go"
	"github.com/kubesphere/notification-manager/pkg/async"
	"github.com/kubesphere/notification-manager/pkg/constants"
	"github.com/kubesphere/notification-manager/pkg/controller"
	"github.com/kubesphere/notification-manager/pkg/internal"
	"github.com/kubesphere/notification-manager/pkg/internal/feishu"
	"github.com/kubesphere/notification-manager/pkg/notify/notifier"
	"github.com/kubesphere/notification-manager/pkg/template"
	"github.com/kubesphere/notification-manager/pkg/utils"
)

const (
	TokenAPI                   = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
	BatchAPI                   = "https://open.feishu.cn/open-apis/message/v4/batch_send/"
	DefaultSendTimeout         = time.Second * 3
	DefaultPostTemplate        = `{{ template "nm.feishu.post" . }}`
	DefaultTextTemplate        = `{{ template "nm.feishu.text" . }}`
	DefaultInteractiveTemplate = `{{ template "nm.feishu.interactive" . }}`
	DefaultExpires             = time.Hour * 2
	ExceedLimitCode            = 9499
)

type Notifier struct {
	notifierCtl  *controller.Controller
	receiver     *feishu.Receiver
	timeout      time.Duration
	logger       log.Logger
	tmpl         *template.Template
	ats          *notifier.AccessTokenService
	tokenExpires time.Duration

	sentSuccessfulHandler *func([]*template.Alert)
}

type Message struct {
	MsgType    string         `json:"msg_type"`
	Content    messageContent `json:"content"`
	Department []string       `json:"department_ids,omitempty"`
	User       []string       `json:"user_ids,omitempty"`
	Timestamp  int64          `json:"timestamp,omitempty"`
	Sign       string         `json:"sign,omitempty"`
}

type messageContent struct {
	Post interface{} `json:"post,omitempty"`
	Text string      `json:"text,omitempty"`
	Card interface{} `json:"card,omitempty"`
}

type Response struct {
	Code        int          `json:"code"`
	Msg         string       `json:"msg"`
	AccessToken string       `json:"tenant_access_token"`
	Data        responseData `json:"data,omitempty"`
	Expire      int          `json:"expire"`
}

type responseData struct {
	InvalidDepartment []string `json:"invalid_department_ids"`
	InvalidUser       []string `json:"invalid_user_ids"`
}

type InteractiveMessage struct {
	MsgType    string      `json:"msg_type"`
	Card       interface{} `json:"card"`
	Department []string    `json:"department_ids,omitempty"`
	User       []string    `json:"user_ids,omitempty"`
	Timestamp  int64       `json:"timestamp,omitempty"`
	Sign       string      `json:"sign,omitempty"`
}

func NewFeishuNotifier(logger log.Logger, receiver internal.Receiver, notifierCtl *controller.Controller) (notifier.Notifier, error) {

	_ = level.Info(logger).Log("msg", "FeishuNotifier: creating new feishu notifier")

	n := &Notifier{
		notifierCtl:  notifierCtl,
		logger:       logger,
		timeout:      DefaultSendTimeout,
		ats:          notifier.GetAccessTokenService(),
		tokenExpires: DefaultExpires,
	}

	_ = level.Debug(logger).Log("msg", "FeishuNotifier: initialized with default settings",
		"timeout", DefaultSendTimeout, "tokenExpires", DefaultExpires)

	opts := notifierCtl.ReceiverOpts
	tmplType := constants.Interactive
	tmplName := ""
	if opts != nil && opts.Global != nil && !utils.StringIsNil(opts.Global.Template) {
		tmplName = opts.Global.Template
		_ = level.Debug(logger).Log("msg", "FeishuNotifier: using global template", "template", tmplName)
	}

	if opts != nil && opts.Feishu != nil {
		_ = level.Debug(logger).Log("msg", "FeishuNotifier: processing feishu options")

		if opts.Feishu.NotificationTimeout != nil {
			n.timeout = time.Second * time.Duration(*opts.Feishu.NotificationTimeout)
			_ = level.Debug(logger).Log("msg", "FeishuNotifier: set notification timeout", "timeout", n.timeout)
		}

		if !utils.StringIsNil(opts.Feishu.Template) {
			tmplName = opts.Feishu.Template
			_ = level.Debug(logger).Log("msg", "FeishuNotifier: using feishu template", "template", tmplName)
		}

		if !utils.StringIsNil(opts.Feishu.TmplType) {
			tmplType = opts.Feishu.TmplType
			_ = level.Debug(logger).Log("msg", "FeishuNotifier: using feishu template type", "tmplType", tmplType)
		}

		if opts.Feishu.TokenExpires != 0 {
			n.tokenExpires = opts.Feishu.TokenExpires
			_ = level.Debug(logger).Log("msg", "FeishuNotifier: set token expires", "tokenExpires", n.tokenExpires)
		}
	}

	n.receiver = receiver.(*feishu.Receiver)
	_ = level.Debug(logger).Log("msg", "FeishuNotifier: receiver type cast successful",
		"receiverName", n.receiver.Name, "receiverType", n.receiver.Type)

	if utils.StringIsNil(n.receiver.TmplType) {
		n.receiver.TmplType = tmplType
		_ = level.Debug(logger).Log("msg", "FeishuNotifier: set default template type", "tmplType", tmplType)
	}

	if utils.StringIsNil(n.receiver.TmplName) {
		if tmplName != "" {
			n.receiver.TmplName = tmplName
			_ = level.Debug(logger).Log("msg", "FeishuNotifier: set template name from options", "tmplName", tmplName)
		} else {
			if n.receiver.TmplType == constants.Post {
				n.receiver.TmplName = DefaultPostTemplate
				_ = level.Debug(logger).Log("msg", "FeishuNotifier: using default post template")
			} else if n.receiver.TmplType == constants.Text {
				n.receiver.TmplName = DefaultTextTemplate
				_ = level.Debug(logger).Log("msg", "FeishuNotifier: using default text template")
			} else if n.receiver.TmplType == constants.Interactive {
				n.receiver.TmplName = DefaultInteractiveTemplate
				_ = level.Debug(logger).Log("msg", "FeishuNotifier: using default interactive template")
			}
		}
	}

	_ = level.Info(logger).Log("msg", "FeishuNotifier: final configuration",
		"tmplType", n.receiver.TmplType, "tmplName", n.receiver.TmplName)

	var err error
	n.tmpl, err = notifierCtl.GetReceiverTmpl(n.receiver.TmplText)
	if err != nil {
		_ = level.Error(logger).Log("msg", "FeishuNotifier: create receiver template error", "error", err.Error())
		return nil, err
	}

	_ = level.Info(logger).Log("msg", "FeishuNotifier: created successfully",
		"receiverName", n.receiver.Name, "hasChatBot", n.receiver.ChatBot != nil,
		"userCount", len(n.receiver.User), "departmentCount", len(n.receiver.Department))

	return n, nil
}

func (n *Notifier) SetSentSuccessfulHandler(h *func([]*template.Alert)) {
	n.sentSuccessfulHandler = h
}

func (n *Notifier) Notify(ctx context.Context, data *template.Data) error {
	_ = level.Info(n.logger).Log("msg", "FeishuNotifier: starting notification",
		"alertCount", len(data.Alerts), "tmplType", n.receiver.TmplType, "tmplName", n.receiver.TmplName)

	content, err := n.tmpl.Text(n.receiver.TmplName, data)
	if err != nil {
		_ = level.Error(n.logger).Log("msg", "FeishuNotifier: generate message error", "error", err.Error())
		return err
	}

	_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: generated content",
		"contentLength", len(content), "tmplType", n.receiver.TmplType)

	group := async.NewGroup(ctx)

	if n.receiver.ChatBot != nil {
		_ = level.Info(n.logger).Log("msg", "FeishuNotifier: adding chatbot task",
			"hasWebhook", n.receiver.ChatBot.Webhook != nil, "hasSecret", n.receiver.ChatBot.Secret != nil,
			"keywords", utils.ArrayToString(n.receiver.ChatBot.Keywords, ","))

		group.Add(func(stopCh chan interface{}) {
			err := n.sendToChatBot(ctx, content)
			if err == nil {
				_ = level.Info(n.logger).Log("msg", "FeishuNotifier: chatbot notification sent successfully")
				if n.sentSuccessfulHandler != nil {
					(*n.sentSuccessfulHandler)(data.Alerts)
				}
			} else {
				_ = level.Error(n.logger).Log("msg", "FeishuNotifier: chatbot notification failed", "error", err.Error())
			}
			stopCh <- err
		})
	}

	if len(n.receiver.User) > 0 || len(n.receiver.Department) > 0 {
		_ = level.Info(n.logger).Log("msg", "FeishuNotifier: adding batch send task",
			"userCount", len(n.receiver.User), "departmentCount", len(n.receiver.Department),
			"users", utils.ArrayToString(n.receiver.User, ","),
			"departments", utils.ArrayToString(n.receiver.Department, ","))

		group.Add(func(stopCh chan interface{}) {
			err := n.batchSend(ctx, content)
			if err == nil {
				_ = level.Info(n.logger).Log("msg", "FeishuNotifier: batch notification sent successfully")
				if n.sentSuccessfulHandler != nil {
					(*n.sentSuccessfulHandler)(data.Alerts)
				}
			} else {
				_ = level.Error(n.logger).Log("msg", "FeishuNotifier: batch notification failed", "error", err.Error())
			}
			stopCh <- err
		})
	}

	_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: waiting for all tasks to complete")
	err = group.Wait()

	if err != nil {
		_ = level.Error(n.logger).Log("msg", "FeishuNotifier: notification completed with errors", "error", err.Error())
	} else {
		_ = level.Info(n.logger).Log("msg", "FeishuNotifier: notification completed successfully")
	}

	return err
}

func (n *Notifier) sendToChatBot(ctx context.Context, content string) error {
	_ = level.Info(n.logger).Log("msg", "FeishuNotifier: starting chatbot notification",
		"tmplType", n.receiver.TmplType, "contentLength", len(content))

	// Interactive类型单独处理，使用InteractiveMessage结构
	if n.receiver.TmplType == constants.Interactive {
		return n.sendToChatBotInteractive(ctx, content)
	}

	keywords := ""
	if len(n.receiver.ChatBot.Keywords) != 0 {
		keywords = fmt.Sprintf("[Keywords] %s", utils.ArrayToString(n.receiver.ChatBot.Keywords, ","))
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: adding keywords to message", "keywords", keywords)
	}

	message := &Message{MsgType: n.receiver.TmplType}
	_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: creating message", "msgType", n.receiver.TmplType)

	if n.receiver.TmplType == constants.Post {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: processing post message")
		post := make(map[string]interface{})
		if err := json.Unmarshal([]byte(content), &post); err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: unmarshal failed", "error", err)
			return err
		}

		if len(keywords) > 0 {
			_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: adding keywords to post message")
			for k, v := range post {
				p := v.(map[string]interface{})
				items := p["content"].([]interface{})
				items = append(items, []interface{}{
					map[string]string{
						"tag":  "text",
						"text": keywords,
					},
				})
				p["content"] = items
				post[k] = p
			}
		}

		message.Content.Post = post
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: post message created successfully")
	} else if n.receiver.TmplType == constants.Text {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: processing text message")
		message.Content.Text = content
		if len(keywords) > 0 {
			message.Content.Text = fmt.Sprintf("%s\n\n%s", content, keywords)
			_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: keywords added to text message")
		}
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: text message created successfully")
	} else {
		_ = level.Error(n.logger).Log("msg", "FeishuNotifier: unknown message type", "type", n.receiver.TmplType)
		return utils.Errorf("Unknown message type, %s", n.receiver.TmplType)
	}

	if n.receiver.ChatBot.Secret != nil {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: processing signature verification")
		secret, err := n.notifierCtl.GetCredential(n.receiver.ChatBot.Secret)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: get secret error", "error", err.Error())
			return err
		}

		message.Timestamp = time.Now().Unix()
		message.Sign, err = genSign(secret, message.Timestamp)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: calculate signature error", "error", err.Error())
			return err
		}
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: signature calculated successfully", "timestamp", message.Timestamp)
	}

	send := func() (bool, error) {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: getting webhook credential")
		webhook, err := n.notifierCtl.GetCredential(n.receiver.ChatBot.Webhook)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: get webhook credential failed", "error", err.Error())
			return false, err
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: preparing HTTP request", "webhook", webhook)
		var buf bytes.Buffer
		if err := utils.JsonEncode(&buf, message); err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: json encode failed", "error", err.Error())
			return false, err
		}

		request, err := http.NewRequest(http.MethodPost, webhook, &buf)
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: HTTP request body", "body", buf.String())
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: create HTTP request", "request", request)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: create HTTP request failed", "error", err.Error())
			return false, err
		}
		request.Header.Set("Content-Type", "application/json; charset=utf-8")

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: sending HTTP request", "url", webhook, "method", http.MethodPost)
		respBody, err := utils.DoHttpRequest(ctx, nil, request)
		if err != nil && len(respBody) == 0 {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: HTTP request failed", "error", err.Error())
			return false, err
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: received response", "responseLength", len(respBody))
		var resp Response
		if err := utils.JsonUnmarshal(respBody, &resp); err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: unmarshal response failed", "error", err.Error())
			return false, err
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: response parsed", "code", resp.Code, "msg", resp.Msg)

		if resp.Code == 0 {
			_ = level.Info(n.logger).Log("msg", "FeishuNotifier: chatbot message sent successfully")
			return false, nil
		}

		// 9499 means the API call exceeds the limit, need to retry.
		if resp.Code == ExceedLimitCode {
			_ = level.Warn(n.logger).Log("msg", "FeishuNotifier: API rate limit exceeded, will retry", "code", resp.Code, "msg", resp.Msg)
			return true, utils.Errorf("%d, %s", resp.Code, resp.Msg)
		}

		_ = level.Error(n.logger).Log("msg", "FeishuNotifier: chatbot message failed", "code", resp.Code, "msg", resp.Msg)
		return false, utils.Errorf("%d, %s", resp.Code, resp.Msg)
	}

	start := time.Now()
	defer func() {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: send message to chatbot", "used", time.Since(start).String())
	}()

	retry := 0
	// The retries will continue until the send times out and the context is cancelled.
	// There is only one case that triggers the retry mechanism, that is, the API call exceeds the limit.
	// The maximum frequency for sending notifications to chatbot is 5 times/second and 100 times/minute.
	for {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: attempting to send message", "retry", retry)
		needRetry, err := send()
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: send notification to chatbot error", "error", err.Error(), "retry", retry)
		}
		if needRetry {
			retry = retry + 1
			_ = level.Info(n.logger).Log("msg", "FeishuNotifier: retry to send notification to chatbot", "retry", retry)
			time.Sleep(time.Second)
			continue
		}

		_ = level.Info(n.logger).Log("msg", "FeishuNotifier: chatbot notification completed", "retry", retry, "success", err == nil)
		return err
	}
}

func (n *Notifier) batchSend(ctx context.Context, content string) error {
	_ = level.Info(n.logger).Log("msg", "FeishuNotifier: starting batch send notification",
		"tmplType", n.receiver.TmplType, "contentLength", len(content),
		"userCount", len(n.receiver.User), "departmentCount", len(n.receiver.Department))

	// Interactive类型单独处理，使用InteractiveMessage结构
	if n.receiver.TmplType == constants.Interactive {
		return n.batchSendInteractive(ctx, content)
	}

	message := &Message{MsgType: n.receiver.TmplType}
	_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: creating batch message", "msgType", n.receiver.TmplType)

	if n.receiver.TmplType == constants.Post {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: processing post message for batch send")
		post := make(map[string]interface{})
		if err := json.Unmarshal([]byte(content), &post); err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: unmarshal failed", "error", err)
			return err
		}
		message.Content.Post = post
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: post message created for batch send")
	} else if n.receiver.TmplType == constants.Text {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: processing text message for batch send")
		message.Content.Text = content
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: text message created for batch send")
	} else {
		_ = level.Error(n.logger).Log("msg", "FeishuNotifier: unknown message type", "type", n.receiver.TmplType)
		return utils.Errorf("Unknown message type, %s", n.receiver.TmplType)
	}

	message.User = n.receiver.User
	message.Department = n.receiver.Department
	_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: message recipients set",
		"users", utils.ArrayToString(n.receiver.User, ","),
		"departments", utils.ArrayToString(n.receiver.Department, ","))

	send := func(retry int) (bool, error) {
		if n.receiver.Config == nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: config is nil")
			return false, utils.Error("FeishuNotifier: config is nil")
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: getting access token", "retry", retry)
		accessToken, err := n.getToken(ctx, n.receiver)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: get token failed", "error", err.Error(), "retry", retry)
			return false, err
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: preparing HTTP request for batch send", "retry", retry)
		var buf bytes.Buffer
		if err := utils.JsonEncode(&buf, message); err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: json encode failed", "error", err.Error(), "retry", retry)
			return false, err
		}

		request, err := http.NewRequest(http.MethodPost, BatchAPI, &buf)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: create HTTP request failed", "error", err.Error(), "retry", retry)
			return false, err
		}
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
		request.Header.Set("Content-Type", "application/json; charset=utf-8")

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: sending HTTP request for batch send", "url", BatchAPI, "method", http.MethodPost, "retry", retry)
		respBody, err := utils.DoHttpRequest(ctx, nil, request)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: HTTP request failed", "error", err.Error(), "retry", retry)
			return false, err
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: received response for batch send", "responseLength", len(respBody), "retry", retry)
		var resp Response
		if err := utils.JsonUnmarshal(respBody, &resp); err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: unmarshal response failed", "error", err.Error(), "retry", retry)
			return false, err
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: response parsed for batch send", "code", resp.Code, "msg", resp.Msg, "retry", retry)

		if resp.Code == 0 {
			if len(resp.Data.InvalidUser) > 0 || len(resp.Data.InvalidDepartment) > 0 {
				e := ""
				if len(resp.Data.InvalidUser) > 0 {
					e = fmt.Sprintf("invalid user %s, ", resp.Data.InvalidUser)
				}
				if len(resp.Data.InvalidDepartment) > 0 {
					e = fmt.Sprintf("%sinvalid department %s, ", e, resp.Data.InvalidDepartment)
				}

				_ = level.Warn(n.logger).Log("msg", "FeishuNotifier: batch send completed with invalid recipients",
					"invalidUsers", utils.ArrayToString(resp.Data.InvalidUser, ","),
					"invalidDepartments", utils.ArrayToString(resp.Data.InvalidDepartment, ","))
				return false, utils.Error(strings.TrimSuffix(e, ", "))
			}

			_ = level.Info(n.logger).Log("msg", "FeishuNotifier: batch message sent successfully", "retry", retry)
			return false, nil
		}

		// 9499 means the API call exceeds the limit, need to retry.
		if resp.Code == ExceedLimitCode {
			_ = level.Warn(n.logger).Log("msg", "FeishuNotifier: API rate limit exceeded, will retry", "code", resp.Code, "msg", resp.Msg, "retry", retry)
			return true, utils.Errorf("%d, %s", resp.Code, resp.Msg)
		}

		_ = level.Error(n.logger).Log("msg", "FeishuNotifier: batch message failed", "code", resp.Code, "msg", resp.Msg, "retry", retry)
		return false, utils.Errorf("%d, %s", resp.Code, resp.Msg)
	}

	start := time.Now()
	defer func() {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: send message", "used", time.Since(start).String(),
			"user", utils.ArrayToString(n.receiver.User, ","),
			"department", utils.ArrayToString(n.receiver.Department, ","))
	}()

	retry := 0
	// The retries will continue until the send times out and the context is cancelled.
	// There is only one case that triggers the retry mechanism, that is, the API call exceeds the limit.
	// The maximum frequency for sending notifications to the same user is 5 times/second.
	for {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: attempting to send batch message", "retry", retry)
		needRetry, err := send(retry)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: send notification error", "error", err, "retry", retry)
		}
		if needRetry {
			retry = retry + 1
			_ = level.Info(n.logger).Log("msg", "FeishuNotifier: retry to send notification", "retry", retry)
			time.Sleep(time.Second)
			continue
		}

		_ = level.Info(n.logger).Log("msg", "FeishuNotifier: batch notification completed", "retry", retry, "success", err == nil)
		return err
	}
}

func (n *Notifier) getToken(ctx context.Context, r *feishu.Receiver) (string, error) {
	_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: starting token retrieval")

	appID, err := n.notifierCtl.GetCredential(r.AppID)
	if err != nil {
		_ = level.Error(n.logger).Log("msg", "FeishuNotifier: get appID credential failed", "error", err.Error())
		return "", err
	}

	appSecret, err := n.notifierCtl.GetCredential(r.AppSecret)
	if err != nil {
		_ = level.Error(n.logger).Log("msg", "FeishuNotifier: get appSecret credential failed", "error", err.Error())
		return "", err
	}

	_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: credentials retrieved successfully", "appID", appID)

	get := func(ctx context.Context) (string, time.Duration, error) {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: requesting new token from feishu API")

		body := make(map[string]string)
		body["app_id"] = appID
		body["app_secret"] = appSecret

		var buf bytes.Buffer
		if err := utils.JsonEncode(&buf, body); err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: encode message error", "error", err.Error())
			return "", 0, err
		}

		var request *http.Request
		request, err = http.NewRequest(http.MethodPost, TokenAPI, &buf)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: create token request failed", "error", err.Error())
			return "", 0, err
		}
		request.Header.Set("Content-Type", "application/json; charset=utf-8")

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: sending token request", "url", TokenAPI, "method", http.MethodPost)
		respBody, err := utils.DoHttpRequest(ctx, nil, request)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: token request failed", "error", err.Error())
			return "", 0, err
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: received token response", "responseLength", len(respBody))
		resp := &Response{}
		err = utils.JsonUnmarshal(respBody, resp)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: unmarshal token response failed", "error", err.Error())
			return "", 0, err
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: token response parsed", "code", resp.Code, "msg", resp.Msg, "expire", resp.Expire)

		if resp.Code != 0 {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: token request failed", "code", resp.Code, "msg", resp.Msg)
			return "", 0, utils.Errorf("%d, %s", resp.Code, resp.Msg)
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: get token", "key", appID, "expire", resp.Expire)
		return resp.AccessToken, time.Duration(resp.Expire) * time.Second, nil
	}

	token, err := n.ats.GetToken(ctx, appID+" | "+appSecret, get)
	if err != nil {
		_ = level.Error(n.logger).Log("msg", "FeishuNotifier: get token from service failed", "error", err.Error())
	} else {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: token retrieved successfully", "tokenLength", len(token))
	}

	return token, err
}

func genSign(secret string, timestamp int64) (string, error) {
	_ = level.Debug(log.NewNopLogger()).Log("msg", "FeishuNotifier: generating signature", "timestamp", timestamp)

	stringToSign := fmt.Sprintf("%v", timestamp) + "\n" + secret
	var data []byte
	h := hmac.New(sha256.New, []byte(stringToSign))
	_, err := h.Write(data)
	if err != nil {
		_ = level.Error(log.NewNopLogger()).Log("msg", "FeishuNotifier: signature generation failed", "error", err.Error())
		return "", err
	}
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	_ = level.Debug(log.NewNopLogger()).Log("msg", "FeishuNotifier: signature generated successfully", "signatureLength", len(signature))
	return signature, nil
}

func (n *Notifier) batchSendInteractive(ctx context.Context, content string) error {
	_ = level.Info(n.logger).Log("msg", "FeishuNotifier: starting interactive batch send notification",
		"contentLength", len(content),
		"userCount", len(n.receiver.User), "departmentCount", len(n.receiver.Department))

	// 创建Interactive消息，使用InteractiveMessage结构
	interactiveMessage := &InteractiveMessage{MsgType: constants.Interactive}
	_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: creating interactive batch message", "msgType", constants.Interactive)

	// 解析Interactive卡片内容
	card := make(map[string]interface{})
	if err := json.Unmarshal([]byte(content), &card); err != nil {
		_ = level.Error(n.logger).Log("msg", "FeishuNotifier: unmarshal interactive card failed", "error", err, "content", content)
		return err
	}

	_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: interactive card parsed successfully", "cardType", fmt.Sprintf("%T", card))
	interactiveMessage.Card = card

	interactiveMessage.User = n.receiver.User
	interactiveMessage.Department = n.receiver.Department
	_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: interactive message recipients set",
		"users", utils.ArrayToString(n.receiver.User, ","),
		"departments", utils.ArrayToString(n.receiver.Department, ","))

	send := func(retry int) (bool, error) {
		if n.receiver.Config == nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: config is nil")
			return false, utils.Error("FeishuNotifier: config is nil")
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: getting access token for interactive message", "retry", retry)
		accessToken, err := n.getToken(ctx, n.receiver)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: get token failed for interactive message", "error", err.Error(), "retry", retry)
			return false, err
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: preparing HTTP request for interactive batch send", "retry", retry)
		var buf bytes.Buffer
		if err := utils.JsonEncode(&buf, interactiveMessage); err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: json encode failed for interactive message", "error", err.Error(), "retry", retry)
			return false, err
		}

		request, err := http.NewRequest(http.MethodPost, BatchAPI, &buf)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: create HTTP request failed for interactive message", "error", err.Error(), "retry", retry)
			return false, err
		}
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
		request.Header.Set("Content-Type", "application/json; charset=utf-8")

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: sending HTTP request for interactive batch send", "url", BatchAPI, "method", http.MethodPost, "retry", retry)
		respBody, err := utils.DoHttpRequest(ctx, nil, request)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: HTTP request failed for interactive message", "error", err.Error(), "retry", retry)
			return false, err
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: received response for interactive batch send", "responseLength", len(respBody), "retry", retry)
		var resp Response
		if err := utils.JsonUnmarshal(respBody, &resp); err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: unmarshal response failed for interactive message", "error", err.Error(), "retry", retry)
			return false, err
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: response parsed for interactive batch send", "code", resp.Code, "msg", resp.Msg, "retry", retry)

		if resp.Code == 0 {
			if len(resp.Data.InvalidUser) > 0 || len(resp.Data.InvalidDepartment) > 0 {
				e := ""
				if len(resp.Data.InvalidUser) > 0 {
					e = fmt.Sprintf("invalid user %s, ", resp.Data.InvalidUser)
				}
				if len(resp.Data.InvalidDepartment) > 0 {
					e = fmt.Sprintf("%sinvalid department %s, ", e, resp.Data.InvalidDepartment)
				}

				_ = level.Warn(n.logger).Log("msg", "FeishuNotifier: interactive batch send completed with invalid recipients",
					"invalidUsers", utils.ArrayToString(resp.Data.InvalidUser, ","),
					"invalidDepartments", utils.ArrayToString(resp.Data.InvalidDepartment, ","))
				return false, utils.Error(strings.TrimSuffix(e, ", "))
			}

			_ = level.Info(n.logger).Log("msg", "FeishuNotifier: interactive batch message sent successfully", "retry", retry)
			return false, nil
		}

		// 9499 means the API call exceeds the limit, need to retry.
		if resp.Code == ExceedLimitCode {
			_ = level.Warn(n.logger).Log("msg", "FeishuNotifier: API rate limit exceeded for interactive message, will retry", "code", resp.Code, "msg", resp.Msg, "retry", retry)
			return true, utils.Errorf("%d, %s", resp.Code, resp.Msg)
		}

		_ = level.Error(n.logger).Log("msg", "FeishuNotifier: interactive batch message failed", "code", resp.Code, "msg", resp.Msg, "retry", retry)
		return false, utils.Errorf("%d, %s", resp.Code, resp.Msg)
	}

	start := time.Now()
	defer func() {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: send interactive message", "used", time.Since(start).String(),
			"user", utils.ArrayToString(n.receiver.User, ","),
			"department", utils.ArrayToString(n.receiver.Department, ","))
	}()

	retry := 0
	// The retries will continue until the send times out and the context is cancelled.
	// There is only one case that triggers the retry mechanism, that is, the API call exceeds the limit.
	// The maximum frequency for sending notifications to the same user is 5 times/second.
	for {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: attempting to send interactive batch message", "retry", retry)
		needRetry, err := send(retry)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: send interactive notification error", "error", err, "retry", retry)
		}
		if needRetry {
			retry = retry + 1
			_ = level.Info(n.logger).Log("msg", "FeishuNotifier: retry to send interactive notification", "retry", retry)
			time.Sleep(time.Second)
			continue
		}

		_ = level.Info(n.logger).Log("msg", "FeishuNotifier: interactive batch notification completed", "retry", retry, "success", err == nil)
		return err
	}
}

func (n *Notifier) sendToChatBotInteractive(ctx context.Context, content string) error {
	_ = level.Info(n.logger).Log("msg", "FeishuNotifier: starting interactive chatbot notification",
		"contentLength", len(content))

	// 创建Interactive消息，使用InteractiveMessage结构
	interactiveMessage := &InteractiveMessage{MsgType: constants.Interactive}
	_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: creating interactive chatbot message", "msgType", constants.Interactive)

	// 解析Interactive卡片内容
	card := make(map[string]interface{})
	if err := json.Unmarshal([]byte(content), &card); err != nil {
		_ = level.Error(n.logger).Log("msg", "FeishuNotifier: unmarshal interactive card failed", "error", err, "content", content)
		return err
	}

	_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: interactive card parsed successfully", "cardType", fmt.Sprintf("%T", card))
	interactiveMessage.Card = card

	if n.receiver.ChatBot.Secret != nil {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: processing signature verification for interactive message")
		secret, err := n.notifierCtl.GetCredential(n.receiver.ChatBot.Secret)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: get secret error for interactive message", "error", err.Error())
			return err
		}

		interactiveMessage.Timestamp = time.Now().Unix()
		interactiveMessage.Sign, err = genSign(secret, interactiveMessage.Timestamp)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: calculate signature error for interactive message", "error", err.Error())
			return err
		}
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: interactive signature calculated successfully", "timestamp", interactiveMessage.Timestamp)
	}

	send := func() (bool, error) {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: getting webhook credential for interactive message")
		webhook, err := n.notifierCtl.GetCredential(n.receiver.ChatBot.Webhook)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: get webhook credential failed for interactive message", "error", err.Error())
			return false, err
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: preparing HTTP request for interactive chatbot", "webhook", webhook)
		var buf bytes.Buffer
		if err := utils.JsonEncode(&buf, interactiveMessage); err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: json encode failed for interactive message", "error", err.Error())
			return false, err
		}

		request, err := http.NewRequest(http.MethodPost, webhook, &buf)
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: HTTP request body for interactive", "body", buf.String())
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: create HTTP request for interactive", "request", request)
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: create HTTP request failed for interactive message", "error", err.Error())
			return false, err
		}
		request.Header.Set("Content-Type", "application/json; charset=utf-8")

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: sending HTTP request for interactive chatbot", "url", webhook, "method", http.MethodPost)
		respBody, err := utils.DoHttpRequest(ctx, nil, request)
		if err != nil && len(respBody) == 0 {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: HTTP request failed for interactive message", "error", err.Error())
			return false, err
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: received response for interactive chatbot", "responseLength", len(respBody))
		var resp Response
		if err := utils.JsonUnmarshal(respBody, &resp); err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: unmarshal response failed for interactive message", "error", err.Error())
			return false, err
		}

		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: response parsed for interactive chatbot", "code", resp.Code, "msg", resp.Msg)

		if resp.Code == 0 {
			_ = level.Info(n.logger).Log("msg", "FeishuNotifier: interactive chatbot message sent successfully")
			return false, nil
		}

		// 9499 means the API call exceeds the limit, need to retry.
		if resp.Code == ExceedLimitCode {
			_ = level.Warn(n.logger).Log("msg", "FeishuNotifier: API rate limit exceeded for interactive chatbot, will retry", "code", resp.Code, "msg", resp.Msg)
			return true, utils.Errorf("%d, %s", resp.Code, resp.Msg)
		}

		_ = level.Error(n.logger).Log("msg", "FeishuNotifier: interactive chatbot message failed", "code", resp.Code, "msg", resp.Msg)
		return false, utils.Errorf("%d, %s", resp.Code, resp.Msg)
	}

	start := time.Now()
	defer func() {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: send interactive message to chatbot", "used", time.Since(start).String())
	}()

	retry := 0
	// The retries will continue until the send times out and the context is cancelled.
	// There is only one case that triggers the retry mechanism, that is, the API call exceeds the limit.
	// The maximum frequency for sending notifications to chatbot is 5 times/second and 100 times/minute.
	for {
		_ = level.Debug(n.logger).Log("msg", "FeishuNotifier: attempting to send interactive message to chatbot", "retry", retry)
		needRetry, err := send()
		if err != nil {
			_ = level.Error(n.logger).Log("msg", "FeishuNotifier: send interactive notification to chatbot error", "error", err.Error(), "retry", retry)
		}
		if needRetry {
			retry = retry + 1
			_ = level.Info(n.logger).Log("msg", "FeishuNotifier: retry to send interactive notification to chatbot", "retry", retry)
			time.Sleep(time.Second)
			continue
		}

		_ = level.Info(n.logger).Log("msg", "FeishuNotifier: interactive chatbot notification completed", "retry", retry, "success", err == nil)
		return err
	}
}
