package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
)

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
