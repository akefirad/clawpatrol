package credentials

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// mockSSO stands up a fake sso GetRoleCredentials endpoint and points
// newSSOClient at it. It returns a call counter so tests can assert
// caching (at most one mint per role). Minted creds are the canonical AWS
// example key so reSignProxiedRequest produces a valid SigV4 signature.
func mockSSO(t *testing.T) *int32 {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"roleCredentials": map[string]any{
				"accessKeyId":     "AKIDEXAMPLE",
				"secretAccessKey": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
				"sessionToken":    "FwoGZXIvYXdzEXAMPLE",
				"expiration":      time.Now().Add(time.Hour).UnixMilli(),
			},
		})
	}))
	prev := newSSOClient
	newSSOClient = func(region string) *sso.Client {
		return sso.New(sso.Options{
			Region:       region,
			BaseEndpoint: aws.String(srv.URL),
			Credentials:  aws.AnonymousCredentials{},
		})
	}
	t.Cleanup(func() {
		newSSOClient = prev
		srv.Close()
	})
	return &calls
}

// mockSSOPerAccount returns creds whose access-key-id encodes the
// requested account, so a test can prove a request routes to the right
// role. account_id / role_name arrive as query params (verified against
// the sso serializer).
func mockSSOPerAccount(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := r.URL.Query().Get("account_id")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"roleCredentials": map[string]any{
				"accessKeyId":     "AKID-" + account,
				"secretAccessKey": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
				"sessionToken":    "sess-" + account,
				"expiration":      time.Now().Add(time.Hour).UnixMilli(),
			},
		})
	}))
	prev := newSSOClient
	newSSOClient = func(region string) *sso.Client {
		return sso.New(sso.Options{Region: region, BaseEndpoint: aws.String(srv.URL), Credentials: aws.AnonymousCredentials{}})
	}
	t.Cleanup(func() {
		newSSOClient = prev
		srv.Close()
	})
}

func ssoCredFixture() *AWSSSOCredential {
	return &AWSSSOCredential{
		StartURL: "https://acme.awsapps.com/start",
		Region:   "us-east-1",
		Roles: []AWSSSORole{
			{AccountID: "111111111111", RoleName: "Admin", Placeholder: "AKIAPROD0ADMIN000000"},
		},
	}
}

// ssoTokenSecret is the SSO access token the OAuthRegistry hands the
// credential at sign time.
func ssoTokenSecret() runtime.Secret {
	return runtime.Secret{Kind: "oauth_bearer", Bytes: []byte("sso-access-token")}
}

// signedReq builds a request the agent's aws-cli would have signed with
// the given placeholder access-key-id (scope names the real service +
// region, exactly as botocore emits).
func signedReq(t *testing.T, placeholderAKID string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("POST", "https://dynamodb.eu-west-1.amazonaws.com/", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+placeholderAKID+
		"/20260609/us-west-2/dynamodb/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=deadbeef")
	req.Header.Set("X-Amz-Content-Sha256", "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")
	return req
}

// TestAWSSSOCredentialMintsAndReSigns verifies the credential self-dispatches
// on the placeholder access-key-id, mints that role's real creds from the
// SSO token via GetRoleCredentials, and re-signs the request with them —
// the client's placeholder signature is replaced and the incoming scope is
// preserved.
func TestAWSSSOCredentialMintsAndReSigns(t *testing.T) {
	mockSSO(t)
	c := ssoCredFixture()
	req := signedReq(t, "AKIAPROD0ADMIN000000")

	if err := c.SignHTTPRequest(context.Background(), req, ssoTokenSecret(), struct{}{}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("Authorization = %q, want a fresh SigV4 signature", auth)
	}
	if strings.Contains(auth, "deadbeef") {
		t.Errorf("Authorization still carries the client placeholder signature: %q", auth)
	}
	if !strings.Contains(auth, "Credential=AKIDEXAMPLE/") {
		t.Errorf("Authorization = %q, want re-signed with the minted role key AKIDEXAMPLE", auth)
	}
	if !strings.Contains(auth, "/us-west-2/dynamodb/aws4_request") {
		t.Errorf("Authorization = %q, want the scope from the incoming header (us-west-2/dynamodb)", auth)
	}
	// STS-issued role creds carry a session token → the signer must stamp it.
	if req.Header.Get("X-Amz-Security-Token") != "FwoGZXIvYXdzEXAMPLE" {
		t.Errorf("X-Amz-Security-Token = %q, want the minted role session token", req.Header.Get("X-Amz-Security-Token"))
	}
}

// TestAWSSSOCredentialRoleCredsCached verifies a second request for the same
// role serves cached creds — at most one GetRoleCredentials mint.
func TestAWSSSOCredentialRoleCredsCached(t *testing.T) {
	calls := mockSSO(t)
	c := ssoCredFixture()
	for i := 0; i < 3; i++ {
		if err := c.SignHTTPRequest(context.Background(), signedReq(t, "AKIAPROD0ADMIN000000"), ssoTokenSecret(), struct{}{}); err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("GetRoleCredentials called %d times, want 1 (creds must be cached)", got)
	}
}

// TestAWSSSOCredentialUnknownPlaceholderFailsClosed verifies a request whose
// placeholder matches no role mapping is rejected, left un-re-signed, and
// never triggers a mint.
func TestAWSSSOCredentialUnknownPlaceholderFailsClosed(t *testing.T) {
	calls := mockSSO(t)
	c := ssoCredFixture()
	req := signedReq(t, "AKIAUNKNOWN000000000")

	err := c.SignHTTPRequest(context.Background(), req, ssoTokenSecret(), struct{}{})
	if err == nil || !strings.Contains(err.Error(), "no role mapping") {
		t.Fatalf("err = %v, want one mentioning the missing role mapping", err)
	}
	if strings.Contains(req.Header.Get("Authorization"), "deadbeef") == false {
		t.Errorf("request was re-signed despite no matching role; Authorization = %q", req.Header.Get("Authorization"))
	}
	if atomic.LoadInt32(calls) != 0 {
		t.Error("GetRoleCredentials was called for an unmatched placeholder")
	}
}

// TestAWSSSOCredentialNoSigV4Errors verifies a request without a parseable
// SigV4 access-key-id is rejected (nothing to route on).
func TestAWSSSOCredentialNoSigV4Errors(t *testing.T) {
	mockSSO(t)
	c := ssoCredFixture()
	req, err := http.NewRequest("GET", "https://dynamodb.eu-west-1.amazonaws.com/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := c.SignHTTPRequest(context.Background(), req, ssoTokenSecret(), struct{}{}); err == nil {
		t.Fatal("expected an error when the request carries no SigV4 access-key-id")
	}
}

// TestAWSSSOCredentialNoSSOTokenErrors verifies that when the role matches
// but no SSO token is available (not connected), signing fails closed.
func TestAWSSSOCredentialNoSSOTokenErrors(t *testing.T) {
	mockSSO(t)
	c := ssoCredFixture()
	req := signedReq(t, "AKIAPROD0ADMIN000000")
	err := c.SignHTTPRequest(context.Background(), req, runtime.Secret{}, struct{}{})
	if err == nil || !strings.Contains(err.Error(), "SSO token") {
		t.Fatalf("err = %v, want one mentioning the missing SSO token", err)
	}
}

// TestAWSSSOCredentialZeroExpirationErrors verifies that creds returned with
// a zero expiration are rejected rather than cached as a permanently-expired
// entry (which would re-mint on every request — latency + AWS throttling).
func TestAWSSSOCredentialZeroExpirationErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"roleCredentials": map[string]any{
				"accessKeyId":     "AKIDEXAMPLE",
				"secretAccessKey": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
				"sessionToken":    "FwoGZXIvYXdzEXAMPLE",
				"expiration":      0,
			},
		})
	}))
	prev := newSSOClient
	newSSOClient = func(region string) *sso.Client {
		return sso.New(sso.Options{Region: region, BaseEndpoint: aws.String(srv.URL), Credentials: aws.AnonymousCredentials{}})
	}
	t.Cleanup(func() { newSSOClient = prev; srv.Close() })

	c := ssoCredFixture()
	req := signedReq(t, "AKIAPROD0ADMIN000000")
	err := c.SignHTTPRequest(context.Background(), req, ssoTokenSecret(), struct{}{})
	if err == nil || !strings.Contains(err.Error(), "no expiration") {
		t.Fatalf("err = %v, want one mentioning the missing expiration", err)
	}
}

// TestAWSSSOCredentialMultiRoleSwitching verifies one credential with two
// role mappings routes each request to the role its placeholder selects,
// minting a distinct identity per role within a single session.
func TestAWSSSOCredentialMultiRoleSwitching(t *testing.T) {
	mockSSOPerAccount(t)
	c := &AWSSSOCredential{
		StartURL: "https://acme.awsapps.com/start",
		Region:   "us-east-1",
		Roles: []AWSSSORole{
			{AccountID: "111111111111", RoleName: "Admin", Placeholder: "AKIAPROD0ADMIN000000"},
			{AccountID: "222222222222", RoleName: "ReadOnly", Placeholder: "AKIADEV00READONLY000"},
		},
	}

	mint := func(placeholder string) string {
		req := signedReq(t, placeholder)
		if err := c.SignHTTPRequest(context.Background(), req, ssoTokenSecret(), struct{}{}); err != nil {
			t.Fatalf("sign %s: %v", placeholder, err)
		}
		return req.Header.Get("Authorization")
	}

	if auth := mint("AKIAPROD0ADMIN000000"); !strings.Contains(auth, "Credential=AKID-111111111111/") {
		t.Errorf("prod-admin request minted %q, want the account-111111111111 identity", auth)
	}
	if auth := mint("AKIADEV00READONLY000"); !strings.Contains(auth, "Credential=AKID-222222222222/") {
		t.Errorf("dev-readonly request minted %q, want the account-222222222222 identity", auth)
	}
}

func TestSigV4AccessKeyID(t *testing.T) {
	cases := []struct {
		name, header, want string
	}{
		{"well-formed", "AWS4-HMAC-SHA256 Credential=AKIAPROD0ADMIN000000/20260609/ap-south-1/s3/aws4_request, SignedHeaders=host, Signature=abc", "AKIAPROD0ADMIN000000"},
		{"missing", "Bearer something", ""},
		{"truncated scope", "AWS4-HMAC-SHA256 Credential=AKID/20260609/s3, SignedHeaders=host", ""},
		{"not aws4_request", "AWS4-HMAC-SHA256 Credential=AKID/20260609/ap-south-1/s3/v2_request, Signature=abc", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sigV4AccessKeyID(tc.header); got != tc.want {
				t.Errorf("sigV4AccessKeyID(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

func TestAWSSSORoleForPlaceholder(t *testing.T) {
	c := &AWSSSOCredential{Roles: []AWSSSORole{
		{AccountID: "111111111111", RoleName: "Admin", Placeholder: "AKIAPROD0ADMIN000000"},
		{AccountID: "222222222222", RoleName: "ReadOnly", Placeholder: "AKIADEV00READONLY000"},
	}}
	if r := c.roleForPlaceholder("AKIADEV00READONLY000"); r == nil || r.RoleName != "ReadOnly" {
		t.Errorf("roleForPlaceholder(dev) = %+v, want the ReadOnly role", r)
	}
	if r := c.roleForPlaceholder("AKIANOPE000000000000"); r != nil {
		t.Errorf("roleForPlaceholder(unknown) = %+v, want nil", r)
	}
	if r := c.roleForPlaceholder(""); r != nil {
		t.Errorf("roleForPlaceholder(empty) = %+v, want nil (empty must not match empty placeholder)", r)
	}
}

// TestAWSSSOCredentialOAuthFlow asserts the credential declares the
// non-standard aws_sso device flow and carries its per-instance start URL
// + SSO region on the OAuth config (so the flow handler needs no policy
// lookup). This is what registers the dashboard "Connect" card and makes
// the SSO token persist under the credential's name.
func TestAWSSSOCredentialOAuthFlow(t *testing.T) {
	var _ config.OAuthFlowProvider = (*AWSSSOCredential)(nil)

	c := &AWSSSOCredential{StartURL: "https://acme.awsapps.com/start", Region: "eu-west-1"}
	fl := c.OAuthFlow()
	if fl == nil {
		t.Fatal("OAuthFlow() returned nil")
	}
	if fl.Flow != "aws_sso" {
		t.Errorf("Flow = %q, want aws_sso", fl.Flow)
	}
	if fl.OAuth.AuthURL != "https://acme.awsapps.com/start" {
		t.Errorf("OAuth.AuthURL = %q, want the start URL", fl.OAuth.AuthURL)
	}
	if fl.OAuth.DeviceURL != "eu-west-1" {
		t.Errorf("OAuth.DeviceURL = %q, want the SSO region", fl.OAuth.DeviceURL)
	}
}
