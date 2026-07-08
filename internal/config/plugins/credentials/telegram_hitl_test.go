package credentials

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// fakeSecretStore returns one fixed secret regardless of name.
type fakeSecretStore struct {
	sec runtime.Secret
	err error
}

func (f fakeSecretStore) Get(string) (runtime.Secret, error) { return f.sec, f.err }

func TestTelegramNotifyHITLPostsSendMessage(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = rw.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer srv.Close()

	orig := telegramAPIBase
	telegramAPIBase = srv.URL
	defer func() { telegramAPIBase = orig }()

	tok := &TelegramBotToken{}
	req := runtime.ApproveRequest{
		Secrets: fakeSecretStore{sec: runtime.Secret{Bytes: []byte("123:ABC-token")}},
		Method:  "GET",
		Path:    "/v1/secret",
		Profile: "dev2",
		Reason:  "reading AWS secret values requires manual approval",
	}
	target := runtime.HITLTarget{
		CredentialName: "telegram",
		Channel:        "-100987654321",
		PendingID:      "pending-7",
		DashboardURL:   "https://gw.example.test/",
	}

	if err := tok.NotifyHITL(t.Context(), req, target); err != nil {
		t.Fatalf("NotifyHITL: %v", err)
	}

	if !strings.HasPrefix(gotPath, "/bot123:ABC-token/") || !strings.HasSuffix(gotPath, "/sendMessage") {
		t.Fatalf("request path = %q, want /bot<token>/sendMessage", gotPath)
	}
	if gotBody["chat_id"] != "-100987654321" {
		t.Fatalf("chat_id = %v, want -100987654321", gotBody["chat_id"])
	}
	text, _ := gotBody["text"].(string)
	for _, want := range []string{"Approve GET", "dev2", "pending-7", "https://gw.example.test/#hitl/pending-7"} {
		if !strings.Contains(text, want) {
			t.Fatalf("message text %q missing %q", text, want)
		}
	}
}

// A Bot API error (e.g. bad chat_id) must surface, and the returned
// error must not leak the bot token that is spliced into the URL path.
func TestTelegramNotifyHITLRedactsTokenOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusBadRequest)
		_, _ = rw.Write([]byte(`{"ok":false,"description":"Bad Request: chat not found"}`))
	}))
	defer srv.Close()

	orig := telegramAPIBase
	telegramAPIBase = srv.URL
	defer func() { telegramAPIBase = orig }()

	const token = "123:SECRET-token"
	tok := &TelegramBotToken{}
	req := runtime.ApproveRequest{Secrets: fakeSecretStore{sec: runtime.Secret{Bytes: []byte(token)}}}
	target := runtime.HITLTarget{CredentialName: "telegram", Channel: "42", PendingID: "p1"}

	err := tok.NotifyHITL(t.Context(), req, target)
	if err == nil {
		t.Fatal("NotifyHITL: want error on Bot API failure, got nil")
	}
	if !strings.Contains(err.Error(), "chat not found") {
		t.Fatalf("error = %v, want Bot API description surfaced", err)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("error leaked the bot token: %v", err)
	}
}

func TestTelegramNotifyHITLRequiresChatID(t *testing.T) {
	tok := &TelegramBotToken{}
	req := runtime.ApproveRequest{Secrets: fakeSecretStore{sec: runtime.Secret{Bytes: []byte("t")}}}
	if err := tok.NotifyHITL(t.Context(), req, runtime.HITLTarget{CredentialName: "telegram"}); err == nil {
		t.Fatal("want error when channel/chat id is empty, got nil")
	}
}
