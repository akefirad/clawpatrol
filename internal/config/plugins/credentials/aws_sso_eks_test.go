package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// stubSSOEKSEndpoint satisfies the awsEKSSSOParams contract so
// SignHTTPRequest can read (cluster, region, account, role) without
// standing up a real KubernetesEndpoint.
type stubSSOEKSEndpoint struct {
	cluster, region, account, role string
}

func (s *stubSSOEKSEndpoint) AWSEKSSSOAuthParams() (cluster, region, account, role string) {
	return s.cluster, s.region, s.account, s.role
}

const (
	ssoTestToken   = "sso-access-token-abc"
	ssoTestAccount = "123456789012"
	ssoTestRole    = "EKSAdmin"

	ssoMintedAKID   = "ASIAMINTEDCREDS00001"
	ssoMintedSecret = "minted-secret-access-key"
	ssoMintedToken  = "minted-session-token"
)

// mockSSO is an httptest server standing in for the SSO portal's
// GetRoleCredentials endpoint (the single mocked boundary). It counts
// mints and records the bearer token / account / role it last saw.
type mockSSO struct {
	server *httptest.Server

	mints      atomic.Int64
	gotToken   atomic.Value // string
	gotAccount atomic.Value // string
	gotRole    atomic.Value // string
	expiration int64        // epoch milliseconds
}

func newMockSSO(t *testing.T, expiration int64) *mockSSO {
	t.Helper()
	m := &mockSSO{expiration: expiration}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mints.Add(1)
		m.gotToken.Store(r.Header.Get("X-Amz-Sso_bearer_token"))
		m.gotAccount.Store(r.URL.Query().Get("account_id"))
		m.gotRole.Store(r.URL.Query().Get("role_name"))

		body, err := json.Marshal(map[string]map[string]any{
			"roleCredentials": {
				"accessKeyId":     ssoMintedAKID,
				"secretAccessKey": ssoMintedSecret,
				"sessionToken":    ssoMintedToken,
				"expiration":      m.expiration,
			},
		})
		if err != nil {
			t.Errorf("marshal role creds: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockSSO) mintCount() int64 { return m.mints.Load() }

func (m *mockSSO) lastToken() string {
	v, _ := m.gotToken.Load().(string)
	return v
}

// credFor builds an aws_sso_eks_credential whose sso-client seam points
// at the mock server, so tests exercise the real GetRoleCredentials
// request/response path without a real SSO portal.
func (m *mockSSO) credFor(ssoRegion string) *AWSSSOEKSCredential {
	return &AWSSSOEKSCredential{
		Region: ssoRegion,
		newClient: func(region string) *sso.Client {
			return sso.New(sso.Options{
				Region:       region,
				BaseEndpoint: aws.String(m.server.URL),
				Credentials:  aws.AnonymousCredentials{},
			})
		},
	}
}

func expiresInMillis(d time.Duration) int64 { return time.Now().Add(d).UnixMilli() }

// TestAWSSSOEKSCredentialSignHTTPRequestEmitsEKSBearer is the primary
// seam test: given an SSO session and an endpoint's
// (cluster, region, account, role), the credential stamps an
// Authorization: Bearer k8s-aws-v1.<…> whose decoded payload is an STS
// GetCallerIdentity presigned URL scoped to the endpoint's (STS) region
// and carrying the x-k8s-aws-id cluster header + X-Amz-Expires=60.
func TestAWSSSOEKSCredentialSignHTTPRequestEmitsEKSBearer(t *testing.T) {
	m := newMockSSO(t, expiresInMillis(time.Hour))
	// Two-region contract: credential region (SSO portal) differs from
	// the endpoint region (cluster/STS). The bearer must be scoped to the
	// endpoint region.
	cred := m.credFor("eu-central-1")
	ep := &stubSSOEKSEndpoint{cluster: "my-cluster", region: "us-west-2", account: ssoTestAccount, role: ssoTestRole}

	req, err := http.NewRequest("GET", "https://k8s.example/api/v1/namespaces", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	sec := runtime.Secret{Kind: "oauth_bearer", Bytes: []byte(ssoTestToken)}
	if err := cred.SignHTTPRequest(context.Background(), req, sec, ep); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// The mint used the delivered SSO token + the endpoint's account/role.
	if got := m.lastToken(); got != ssoTestToken {
		t.Errorf("GetRoleCredentials bearer = %q, want %q", got, ssoTestToken)
	}
	if got, _ := m.gotAccount.Load().(string); got != ssoTestAccount {
		t.Errorf("account_id = %q, want %q", got, ssoTestAccount)
	}
	if got, _ := m.gotRole.Load().(string); got != ssoTestRole {
		t.Errorf("role_name = %q, want %q", got, ssoTestRole)
	}

	auth := req.Header.Get("Authorization")
	const wantPrefix = "Bearer k8s-aws-v1."
	if !strings.HasPrefix(auth, wantPrefix) {
		t.Fatalf("Authorization = %q, want prefix %q", auth, wantPrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(auth, wantPrefix))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	u, err := url.Parse(string(raw))
	if err != nil {
		t.Fatalf("parse presigned url %q: %v", raw, err)
	}
	// Scoped to the ENDPOINT (STS) region, not the credential's SSO region.
	if want := "sts.us-west-2.amazonaws.com"; u.Host != want {
		t.Errorf("host = %q, want %q (endpoint/STS region, not the SSO portal region)", u.Host, want)
	}
	q := u.Query()
	if got := q.Get("Action"); got != "GetCallerIdentity" {
		t.Errorf("Action = %q, want GetCallerIdentity", got)
	}
	if !strings.Contains(q.Get("X-Amz-SignedHeaders"), "x-k8s-aws-id") {
		t.Errorf("X-Amz-SignedHeaders = %q, must include x-k8s-aws-id", q.Get("X-Amz-SignedHeaders"))
	}
	// Credential scope must carry the SSO-minted temporary access key.
	if got := q.Get("X-Amz-Credential"); !strings.HasPrefix(got, ssoMintedAKID+"/") {
		t.Errorf("X-Amz-Credential = %q, want prefix %q", got, ssoMintedAKID+"/")
	}
	if got := q.Get("X-Amz-Expires"); got != "60" {
		t.Errorf("X-Amz-Expires = %q, want 60", got)
	}
	// STS-issued temporary creds carry a session token → it must ride along.
	if q.Get("X-Amz-Security-Token") != ssoMintedToken {
		t.Errorf("X-Amz-Security-Token = %q, want the minted session token %q", q.Get("X-Amz-Security-Token"), ssoMintedToken)
	}
}

// TestAWSSSOEKSCredentialCachesRoleCredentials asserts a burst of
// requests for the same (account, role) triggers exactly one
// GetRoleCredentials mint.
func TestAWSSSOEKSCredentialCachesRoleCredentials(t *testing.T) {
	m := newMockSSO(t, expiresInMillis(time.Hour))
	cred := m.credFor("eu-central-1")
	ep := &stubSSOEKSEndpoint{cluster: "my-cluster", region: "us-west-2", account: ssoTestAccount, role: ssoTestRole}
	sec := runtime.Secret{Bytes: []byte(ssoTestToken)}

	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", "https://k8s.example/api/v1/namespaces", nil)
		if err := cred.SignHTTPRequest(context.Background(), req, sec, ep); err != nil {
			t.Fatalf("sign #%d: %v", i, err)
		}
	}
	if got := m.mintCount(); got != 1 {
		t.Errorf("GetRoleCredentials mints = %d, want 1 (cached per account/role)", got)
	}
}

// TestAWSSSOEKSCredentialFailsClosedMissingAccountRole asserts a
// misconfigured cluster (no account/role) denies without minting.
func TestAWSSSOEKSCredentialFailsClosedMissingAccountRole(t *testing.T) {
	m := newMockSSO(t, expiresInMillis(time.Hour))
	cred := m.credFor("eu-central-1")
	sec := runtime.Secret{Bytes: []byte(ssoTestToken)}

	for _, ep := range []*stubSSOEKSEndpoint{
		{cluster: "my-cluster", region: "us-west-2", account: "", role: ssoTestRole},
		{cluster: "my-cluster", region: "us-west-2", account: ssoTestAccount, role: ""},
	} {
		req, _ := http.NewRequest("GET", "https://k8s.example/", nil)
		err := cred.SignHTTPRequest(context.Background(), req, sec, ep)
		if err == nil || !strings.Contains(err.Error(), "account_id / role_name") {
			t.Errorf("err = %v, want one mentioning account_id / role_name", err)
		}
		if req.Header.Get("Authorization") != "" {
			t.Errorf("Authorization stamped despite fail-closed: %q", req.Header.Get("Authorization"))
		}
	}
	if got := m.mintCount(); got != 0 {
		t.Errorf("GetRoleCredentials mints = %d, want 0 (must not mint when misconfigured)", got)
	}
}

// TestAWSSSOEKSCredentialFailsClosedEmptyToken asserts an empty/expired
// SSO token denies with a recognizable reconnect error and no mint.
func TestAWSSSOEKSCredentialFailsClosedEmptyToken(t *testing.T) {
	m := newMockSSO(t, expiresInMillis(time.Hour))
	cred := m.credFor("eu-central-1")
	ep := &stubSSOEKSEndpoint{cluster: "my-cluster", region: "us-west-2", account: ssoTestAccount, role: ssoTestRole}

	req, _ := http.NewRequest("GET", "https://k8s.example/", nil)
	err := cred.SignHTTPRequest(context.Background(), req, runtime.Secret{}, ep)
	if err == nil || !strings.Contains(err.Error(), "reconnect AWS SSO") {
		t.Fatalf("err = %v, want one mentioning reconnect AWS SSO", err)
	}
	if req.Header.Get("Authorization") != "" {
		t.Errorf("Authorization stamped despite empty token: %q", req.Header.Get("Authorization"))
	}
	if got := m.mintCount(); got != 0 {
		t.Errorf("GetRoleCredentials mints = %d, want 0 (no session → no mint)", got)
	}
}

// TestAWSSSOEKSCredentialRejectsNonEKSEndpoint asserts binding to an
// endpoint that doesn't expose the SSO auth params fails closed.
func TestAWSSSOEKSCredentialRejectsNonEKSEndpoint(t *testing.T) {
	cred := &AWSSSOEKSCredential{Region: "eu-central-1"}
	req, _ := http.NewRequest("GET", "https://k8s.example/", nil)
	err := cred.SignHTTPRequest(context.Background(), req, runtime.Secret{Bytes: []byte(ssoTestToken)}, struct{}{})
	if err == nil || !strings.Contains(err.Error(), "EKS SSO auth params") {
		t.Fatalf("err = %v, want one mentioning EKS SSO auth params", err)
	}
}

// TestAWSSSOEKSCredentialOAuthFlow asserts the credential declares the
// aws_sso device flow with the start URL + region wired into the shape
// startAWSSSODeviceFlow reads (AuthURL = start URL, DeviceURL = region).
func TestAWSSSOEKSCredentialOAuthFlow(t *testing.T) {
	cred := &AWSSSOEKSCredential{StartURL: "https://my-org.awsapps.com/start", Region: "eu-central-1"}
	flow := cred.OAuthFlow()
	if flow == nil {
		t.Fatal("OAuthFlow() = nil")
	}
	if flow.Flow != "aws_sso" {
		t.Errorf("Flow = %q, want aws_sso", flow.Flow)
	}
	if flow.OAuth.AuthURL != cred.StartURL {
		t.Errorf("AuthURL = %q, want %q", flow.OAuth.AuthURL, cred.StartURL)
	}
	if flow.OAuth.DeviceURL != cred.Region {
		t.Errorf("DeviceURL = %q, want %q (SSO region)", flow.OAuth.DeviceURL, cred.Region)
	}
}
