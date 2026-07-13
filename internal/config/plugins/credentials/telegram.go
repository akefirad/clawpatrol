package credentials

// telegram_bot_token: bot token lives in the URL path
// (/bot<TOKEN>/<METHOD>) and sometimes in the request body
// (setWebhook posts a URL containing the token). We swap every
// occurrence of the operator-emitted placeholder with the real secret
// — operator's CLI uses the placeholder verbatim; gateway substitutes
// globally so the token never hits the upstream as the placeholder
// and never leaks to logs.
//
// It also implements HITLNotifier: the gateway posts human_approver
// approval prompts to a Telegram chat via the Bot API sendMessage.
// Read-only — the prompt links to the dashboard where the operator
// approves/denies; there are no in-chat Approve/Deny buttons (that
// needs a WebhookProvider + gateway callback route, a later slice).
//
// Telegram doesn't appear in `clawpatrol env` because Telegram SDKs
// take the token as an explicit argument rather than reading it from
// the env, so there's nothing to "push down".

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// telegramPlaceholder is the bot-token placeholder operators put in
// their SDK config / URL when running through the gateway.
const telegramPlaceholder = "0000000000:clawpatrol-placeholder-do-not-use"

// TelegramBotToken is part of the clawpatrol plugin API.
type TelegramBotToken struct{}

// InjectHTTP is part of the clawpatrol plugin API.
func (t *TelegramBotToken) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	if len(sec.Bytes) == 0 || req.URL == nil {
		return nil
	}
	actualToken := string(sec.Bytes)
	swap := func(s string) string {
		return strings.ReplaceAll(s, telegramPlaceholder, actualToken)
	}

	if strings.Contains(req.URL.Path, telegramPlaceholder) {
		req.URL.Path = swap(req.URL.Path)
		// Drop the encoded form so http.Client re-encodes from .Path.
		req.URL.RawPath = ""
	}
	if strings.Contains(req.URL.RawQuery, telegramPlaceholder) {
		req.URL.RawQuery = swap(req.URL.RawQuery)
	}

	if req.Body != nil && req.Body != http.NoBody {
		buf, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return err
		}
		if bytes.Contains(buf, []byte(telegramPlaceholder)) {
			buf = bytes.ReplaceAll(buf, []byte(telegramPlaceholder), sec.Bytes)
		}
		req.Body = io.NopCloser(bytes.NewReader(buf))
		req.ContentLength = int64(len(buf))
	}
	return nil
}

// SecretSlots is part of the clawpatrol plugin API.
func (*TelegramBotToken) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{{Label: "Telegram bot token"}}
}

// telegramTextLimit is Telegram's hard cap on a sendMessage text
// (4096 UTF-8 chars); we stay just under it.
const telegramTextLimit = 4000

// telegramAPIBase is the Bot API host. The bot token is spliced into
// the path (/bot<TOKEN>/<method>) per the Telegram Bot API. A var so
// tests can point it at a local server.
//
// Notifier HTTP budget mirrors the Slack notifier: a short timeout
// (the HITL request is parked waiting on this call) and a single
// retry on a transient failure.
var (
	telegramAPIBase       = "https://api.telegram.org"
	telegramHTTPClient    = &http.Client{Timeout: 5 * time.Second}
	telegramNotifyBackoff = 500 * time.Millisecond
)

// NotifyHITL delivers a read-only approval prompt to a Telegram chat
// via the Bot API sendMessage: a plain-text summary of the pending
// request plus a link to the dashboard where the operator approves or
// denies. It is the notifier half of the credential (HITLNotifier);
// InjectHTTP above is the token-injection half.
//
// The human_approver `channel` is the Telegram chat id (numeric id or
// @username; passed through verbatim). Read-only by design: no inline
// Approve/Deny keyboard and no callback handling — those need a
// WebhookProvider and a gateway route, a later slice.
func (t *TelegramBotToken) NotifyHITL(ctx context.Context, req runtime.ApproveRequest, target runtime.HITLTarget) error {
	if req.Secrets == nil {
		return errors.New("no secret store on request")
	}
	sec, err := req.Secrets.Get(target.CredentialName)
	if err != nil {
		return fmt.Errorf("fetch credential %s: %w", target.CredentialName, err)
	}
	token := string(sec.Bytes)
	if token == "" {
		return fmt.Errorf("credential %s has no bot token (paste via dashboard)", target.CredentialName)
	}
	if strings.TrimSpace(target.Channel) == "" {
		return errors.New("telegram notify: no chat id (set the human_approver channel to the target chat id)")
	}

	payload, _ := json.Marshal(map[string]any{
		"chat_id":                  target.Channel,
		"text":                     telegramHITLText(req, target),
		"disable_web_page_preview": true,
	})
	if err := telegramSendMessage(ctx, token, payload); err != nil {
		// The token is spliced into the Bot API URL path, so a transport
		// error (which embeds the request URL) would otherwise leak it.
		// Scrub every occurrence before the error is returned or logged.
		return errors.New(strings.ReplaceAll(err.Error(), token, "<redacted>"))
	}
	return nil
}

// telegramHITLText renders the prompt body. Plain text (no parse_mode)
// so request paths / body samples containing Markdown or HTML
// metacharacters need no escaping and can't break the message.
func telegramHITLText(req runtime.ApproveRequest, target runtime.HITLTarget) string {
	endpoint := runtime.HITLEndpointLabel(req)
	title := runtime.HITLTitle(req.Method, endpoint)
	queryLabel := runtime.HITLQueryLabel(req.Endpoint)

	var b strings.Builder
	b.WriteString("🔐 clawpatrol approval needed\n\n")
	b.WriteString(title)
	if p := strings.TrimSpace(req.Path); p != "" {
		b.WriteString("\n" + queryLabel + ": " + slackTrunc(p, 500))
	}
	if msg := strings.TrimSpace(target.Message); msg != "" {
		b.WriteString("\n\n" + slackTrunc(msg, 1500))
	}
	if req.Profile != "" {
		b.WriteString("\nagent: " + req.Profile)
	}
	if r := strings.TrimSpace(req.Reason); r != "" {
		b.WriteString("\nreason: " + slackTrunc(r, 500))
	}
	if bs := strings.TrimSpace(req.BodySample); bs != "" {
		b.WriteString("\n\nBody:\n" + slackTrunc(bs, 1500))
	}
	link := strings.TrimRight(target.DashboardURL, "/") + "/#hitl/" + target.PendingID
	b.WriteString("\n\nApprove or deny on the dashboard: " + link)
	return slackTrunc(b.String(), telegramTextLimit)
}

// telegramSendMessage POSTs the sendMessage payload, retrying once on a
// transient failure. The bot token is in the URL path, so the retry log
// deliberately omits the underlying error (which embeds the URL); the
// final error is returned to the caller, which scrubs the token.
func telegramSendMessage(ctx context.Context, token string, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	url := telegramAPIBase + "/bot" + token + "/sendMessage"
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		hreq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		hreq.Header.Set("Content-Type", "application/json; charset=utf-8")

		resp, err := telegramHTTPClient.Do(hreq)
		if err != nil {
			lastErr = err
		} else {
			lastErr = telegramDecodeResponse(resp)
			_ = resp.Body.Close()
		}
		if lastErr == nil {
			return nil
		}
		if attempt == 2 {
			return lastErr
		}
		log.Printf("telegram notify: sendMessage failed on attempt %d, retrying once", attempt)
		timer := time.NewTimer(telegramNotifyBackoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}

// telegramDecodeResponse maps a Bot API reply to an error. Telegram
// error descriptions don't carry the token, so they are safe to
// surface verbatim.
func telegramDecodeResponse(resp *http.Response) error {
	if resp == nil {
		return errors.New("telegram sendMessage: missing response")
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var result struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(raw, &result)
	if resp.StatusCode >= 400 || !result.OK {
		if result.Description != "" {
			return fmt.Errorf("telegram sendMessage error: %s", result.Description)
		}
		return fmt.Errorf("telegram sendMessage error: HTTP %d", resp.StatusCode)
	}
	return nil
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*TelegramBotToken)(nil)
	var _ runtime.HITLNotifier = (*TelegramBotToken)(nil)
	config.Register(&config.Plugin{
		Kind:           config.KindCredential,
		Type:           "telegram_bot_token",
		Disambiguators: []string{"placeholder"},
		New:            newer[TelegramBotToken](),
		Runtime:        (*TelegramBotToken)(nil),
		Build:          passthrough,
		Emit:           emptyEmit,
	})
}
