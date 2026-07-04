package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"

	"github.com/denoland/clawpatrol/internal/config"
)

// fakeAWSSSOFlow is a minimal OAuthFlowProvider whose OAuthFlow() reports
// Flow "aws_sso" — enough for apiOAuthStart's lookupOAuthFlow to resolve the
// dispatch without importing the real credential type (a different package).
type fakeAWSSSOFlow struct{}

func (fakeAWSSSOFlow) OAuthFlow() *config.OAuthIntegration {
	return &config.OAuthIntegration{
		Type: "aws_sso",
		Flow: "aws_sso",
		OAuth: config.OAuthConfig{
			AuthURL:   "https://acme.awsapps.com/start",
			DeviceURL: "us-east-1",
		},
	}
}

// awsSSOMockServer stands up a fake ssooidc endpoint (the three REST-JSON
// paths the device flow hits) and points newSSOOIDCClient at it for the
// duration of the test. tokenHandler serves POST /token so each test can
// choose pending vs. success.
func awsSSOMockServer(t *testing.T, tokenHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/client/register", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"clientId": "cid", "clientSecret": "csec"})
	})
	mux.HandleFunc("/device_authorization", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"deviceCode":              "dc",
			"userCode":                "UC-1234",
			"verificationUri":         "https://device.sso.us-east-1.amazonaws.com/",
			"verificationUriComplete": "https://device.sso.us-east-1.amazonaws.com/?user_code=UC-1234",
			"expiresIn":               600,
			"interval":                5,
		})
	})
	mux.HandleFunc("/token", tokenHandler)
	srv := httptest.NewServer(mux)

	prev := newSSOOIDCClient
	newSSOOIDCClient = func(region string) *ssooidc.Client {
		return ssooidc.New(ssooidc.Options{
			Region:       region,
			BaseEndpoint: aws.String(srv.URL),
			Credentials:  aws.AnonymousCredentials{},
		})
	}
	t.Cleanup(func() {
		newSSOOIDCClient = prev
		srv.Close()
	})
	return srv
}

func newAWSSSOTestMux() (*webMux, *OAuthRegistry) {
	reg := &OAuthRegistry{
		integrations: map[string]*OAuthIntegration{
			"sso": {ID: "sso", Type: "aws_sso", Flow: "aws_sso"},
		},
		states: map[string]*oauthState{},
	}
	w := &webMux{g: &Gateway{oauth: reg}, sessions: map[string]*oauthSession{}}
	return w, reg
}

// TestOAuthDispatchReachesAWSSSOHandlers drives the shared apiOAuthStart /
// apiOAuthDevicePoll entry points over HTTP (not the aws_sso handlers directly)
// and asserts the Flow=="aws_sso" dispatch actually routes to the aws_sso
// handlers — not the generic RFC-8628 pollDeviceFlow. A wrong flow string or a
// dropped arm would leave the feature dead end-to-end while the direct-call
// unit tests stayed green.
func TestOAuthDispatchReachesAWSSSOHandlers(t *testing.T) {
	awsSSOMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		// /token: report the user hasn't approved yet. Only pollAWSSSODeviceFlow
		// maps AuthorizationPendingException → "authorization_pending"; the
		// generic pollDeviceFlow would not produce this from a JSON ssooidc 400.
		w.Header().Set("X-Amzn-Errortype", "AuthorizationPendingException")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"AuthorizationPendingException","message":"pending"}`))
	})
	w, _ := newAWSSSOTestMux()
	// apiOAuthStart resolves the flow from the policy via lookupOAuthFlow.
	w.g.policy.Store(&config.CompiledPolicy{
		Credentials: map[string]*config.Entity{"sso": {Body: fakeAWSSSOFlow{}}},
	})

	// Start: must reach startAWSSSODeviceFlow (device payload with a user code).
	startRec := httptest.NewRecorder()
	startReq := httptest.NewRequest("POST", "/api/oauth/start?id=sso", nil)
	w.apiOAuthStart(startRec, startReq)
	if startRec.Code != 200 {
		t.Fatalf("apiOAuthStart status = %d, body = %s", startRec.Code, startRec.Body.String())
	}
	var start struct {
		Flow     string `json:"flow"`
		State    string `json:"state"`
		UserCode string `json:"user_code"`
	}
	if err := json.Unmarshal(startRec.Body.Bytes(), &start); err != nil {
		t.Fatalf("decode start: %v (%s)", err, startRec.Body.String())
	}
	if start.UserCode != "UC-1234" {
		t.Fatalf("user_code = %q — apiOAuthStart did not dispatch to startAWSSSODeviceFlow", start.UserCode)
	}

	// Poll: apiOAuthDevicePoll resolves the flow from the registry (sess.id) and
	// must reach pollAWSSSODeviceFlow — proven by the aws_sso-specific mapping.
	pollRec := httptest.NewRecorder()
	pollReq := httptest.NewRequest("POST", "/api/oauth/device-poll?state="+start.State, nil)
	w.apiOAuthDevicePoll(pollRec, pollReq)
	var poll map[string]any
	_ = json.Unmarshal(pollRec.Body.Bytes(), &poll)
	if poll["error"] != "authorization_pending" {
		t.Fatalf("device-poll response = %v — did not dispatch to pollAWSSSODeviceFlow", poll)
	}
}

// TestStartAWSSSODeviceFlow drives RegisterClient + StartDeviceAuthorization
// against the mock and asserts the dashboard gets the user-code UI payload
// and a session was stashed with everything the poll step needs.
func TestStartAWSSSODeviceFlow(t *testing.T) {
	awsSSOMockServer(t, func(http.ResponseWriter, *http.Request) {})
	w, _ := newAWSSSOTestMux()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/oauth/start?id=sso", nil)
	it := &OAuthIntegration{ID: "sso", Flow: "aws_sso", OAuth: OAuthConfig{
		AuthURL:   "https://acme.awsapps.com/start",
		DeviceURL: "us-east-1",
	}}
	w.startAWSSSODeviceFlow(rec, req, "sso", it)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Flow            string `json:"flow"`
		State           string `json:"state"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if out.Flow != "device" {
		t.Errorf("flow = %q, want device (so the dashboard renders the user-code UI)", out.Flow)
	}
	if out.UserCode != "UC-1234" {
		t.Errorf("user_code = %q, want UC-1234", out.UserCode)
	}
	if !strings.Contains(out.VerificationURI, "user_code=UC-1234") {
		t.Errorf("verification_uri = %q, want the complete verification URI", out.VerificationURI)
	}
	// The session must carry client id/secret, device code, and region so
	// the poll step can complete CreateToken.
	sess := w.sessions[out.State]
	if sess == nil {
		t.Fatal("no session stashed for the returned state")
	}
	if parts := strings.Split(sess.verifier, "|"); len(parts) != 4 ||
		parts[0] != "cid" || parts[2] != "dc" || parts[3] != "us-east-1" {
		t.Errorf("session verifier = %q, want cid|csec|dc|us-east-1 shape", sess.verifier)
	}
}

// TestAWSSSOSessionSurvivesExchangePath guards the nil-cfg invariant: sessions
// are looked up by state alone, so any authenticated client can POST an aws_sso
// state to /api/oauth/exchange (instead of /device-poll). exchangeOAuthCode's
// first act is sess.cfg.Endpoint.TokenURL, so a nil cfg would panic the handler.
// The start step must stash a non-nil cfg; the exchange then degrades to a
// failed HTTP call (400) rather than a crash.
func TestAWSSSOSessionSurvivesExchangePath(t *testing.T) {
	awsSSOMockServer(t, func(http.ResponseWriter, *http.Request) {})
	w, _ := newAWSSSOTestMux()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/oauth/start?id=sso", nil)
	it := &OAuthIntegration{ID: "sso", Flow: "aws_sso", OAuth: OAuthConfig{
		AuthURL:   "https://acme.awsapps.com/start",
		DeviceURL: "us-east-1",
	}}
	w.startAWSSSODeviceFlow(rec, req, "sso", it)

	var out struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode start: %v (%s)", err, rec.Body.String())
	}
	if sess := w.sessions[out.State]; sess == nil || sess.cfg == nil {
		t.Fatalf("aws_sso session must stash a non-nil cfg to keep the exchange path from panicking; got %+v", sess)
	}

	// The exchange path must not panic (it recovers here as a plain 4xx/5xx).
	exRec := httptest.NewRecorder()
	body := `{"state":"` + out.State + `","code":"whatever"}`
	exReq := httptest.NewRequest("POST", "/api/oauth/exchange", strings.NewReader(body))
	w.apiOAuthExchange(exRec, exReq)
	if exRec.Code == 200 {
		t.Fatalf("exchange of an aws_sso state unexpectedly succeeded: %s", exRec.Body.String())
	}
}

// TestStartAWSSSODeviceFlowMissingConfig asserts the start step fails with a
// 500 when the credential's start_url / region didn't make it onto the OAuth
// config, rather than calling ssooidc with empty inputs.
func TestStartAWSSSODeviceFlowMissingConfig(t *testing.T) {
	cases := []struct {
		name            string
		authURL, devURL string
	}{
		{"missing start_url", "", "us-east-1"},
		{"missing region", "https://acme.awsapps.com/start", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := newAWSSSOTestMux()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/api/oauth/start?id=sso", nil)
			it := &OAuthIntegration{ID: "sso", Flow: "aws_sso", OAuth: OAuthConfig{AuthURL: tc.authURL, DeviceURL: tc.devURL}}
			w.startAWSSSODeviceFlow(rec, req, "sso", it)
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("status = %d, want 500 for %s", rec.Code, tc.name)
			}
		})
	}
}

// TestPollAWSSSODeviceFlowSuccess exchanges the device code for a token and
// asserts it is persisted through the registry (dashboard sees connected).
func TestPollAWSSSODeviceFlowSuccess(t *testing.T) {
	awsSSOMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"accessToken":  "sso-access-token",
			"tokenType":    "Bearer",
			"expiresIn":    3600,
			"refreshToken": "sso-refresh-token",
		})
	})
	w, reg := newAWSSSOTestMux()
	w.sessions["st"] = &oauthSession{state: "st", id: "sso", verifier: "cid|csec|dc|us-east-1"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/oauth/device-poll?state=st", nil)
	w.pollAWSSSODeviceFlow(rec, req, w.sessions["st"])

	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["connected"] != true {
		t.Errorf("response = %v, want connected=true", out)
	}
	if connected, _ := reg.Status("sso"); !connected {
		t.Error("registry Status(sso) not connected — token was not persisted")
	}
	// The refresh token the mock returned MUST NOT have been persisted:
	// aws_sso has no refresh branch and an empty TokenURL, so a stored refresh
	// token would produce the cryptic `unsupported protocol scheme ""` on
	// expiry. Read the persisted token back and assert it's empty — this pins
	// the most safety-relevant intentional behavior in the flow so a future
	// "helpful" edit that persists it fails the suite.
	st := reg.get("sso")
	if st == nil {
		t.Fatal("no oauth state persisted for sso")
	}
	got, err := st.source.Token()
	if err != nil {
		t.Fatalf("read back persisted token: %v", err)
	}
	if got.RefreshToken != "" {
		t.Errorf("persisted refresh_token = %q, want empty (aws_sso must drop it until refresh lands)", got.RefreshToken)
	}
	// Session must be consumed on success.
	if _, ok := w.sessions["st"]; ok {
		t.Error("session not deleted after successful token exchange")
	}
}

// TestPollAWSSSODeviceFlowPending surfaces authorization_pending (the user
// hasn't approved yet) to the dashboard's polling loop without persisting
// anything.
func TestPollAWSSSODeviceFlowPending(t *testing.T) {
	awsSSOMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Amzn-Errortype", "AuthorizationPendingException")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"AuthorizationPendingException","message":"pending"}`))
	})
	w, reg := newAWSSSOTestMux()
	w.sessions["st"] = &oauthSession{state: "st", id: "sso", verifier: "cid|csec|dc|us-east-1"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/oauth/device-poll?state=st", nil)
	w.pollAWSSSODeviceFlow(rec, req, w.sessions["st"])

	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["error"] != "authorization_pending" {
		t.Errorf("response = %v, want error=authorization_pending", out)
	}
	if connected, _ := reg.Status("sso"); connected {
		t.Error("registry shows connected on a pending poll — must not persist")
	}
	// The session must survive so the dashboard can keep polling.
	if _, ok := w.sessions["st"]; !ok {
		t.Error("session deleted on a pending poll; polling can no longer continue")
	}
}

// TestPollAWSSSODeviceFlowTerminalErrors verifies the known terminal ssooidc
// errors are mapped to the RFC-8628 codes the dashboard expects (not a raw
// AWS exception string), and that the dead session is deleted so it doesn't
// linger until GC.
func TestPollAWSSSODeviceFlowTerminalErrors(t *testing.T) {
	cases := []struct {
		name, errType, wantCode string
	}{
		{"device code expired", "ExpiredTokenException", "expired_token"},
		{"user denied", "AccessDeniedException", "access_denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			awsSSOMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Amzn-Errortype", tc.errType)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"__type":"` + tc.errType + `","message":"terminal"}`))
			})
			w, reg := newAWSSSOTestMux()
			w.sessions["st"] = &oauthSession{state: "st", id: "sso", verifier: "cid|csec|dc|us-east-1"}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/api/oauth/device-poll?state=st", nil)
			w.pollAWSSSODeviceFlow(rec, req, w.sessions["st"])

			var out map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &out)
			if out["error"] != tc.wantCode {
				t.Errorf("response = %v, want error=%s", out, tc.wantCode)
			}
			if connected, _ := reg.Status("sso"); connected {
				t.Error("registry shows connected on a terminal error — must not persist")
			}
			// The dead session must be deleted, not left for the GC.
			if _, ok := w.sessions["st"]; ok {
				t.Error("session not deleted on a terminal error")
			}
		})
	}
}

// TestPollAWSSSODeviceFlowTransientKeepsSession verifies a transient
// CreateToken failure (here AWS InternalServerException, a documented-retryable
// 5xx) does NOT abort the device login: it returns a 5xx and keeps the session
// so the dashboard's next poll tick can recover.
func TestPollAWSSSODeviceFlowTransientKeepsSession(t *testing.T) {
	awsSSOMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Amzn-Errortype", "InternalServerException")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"__type":"InternalServerException","message":"transient"}`))
	})
	w, reg := newAWSSSOTestMux()
	w.sessions["st"] = &oauthSession{state: "st", id: "sso", verifier: "cid|csec|dc|us-east-1"}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/oauth/device-poll?state=st", nil)
	w.pollAWSSSODeviceFlow(rec, req, w.sessions["st"])

	if rec.Code < 500 {
		t.Errorf("status = %d, want a 5xx on a transient error", rec.Code)
	}
	if connected, _ := reg.Status("sso"); connected {
		t.Error("registry shows connected on a transient error — must not persist")
	}
	// The session MUST survive so the next poll tick can recover.
	if _, ok := w.sessions["st"]; !ok {
		t.Error("session deleted on a transient error; the device login can no longer recover")
	}
}
