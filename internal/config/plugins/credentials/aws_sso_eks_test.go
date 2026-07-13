package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/hashicorp/hcl/v2"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/plugins/endpoints"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// Compile-time pin: the real kubernetes endpoint must satisfy the
// awsEKSSSOParams contract this credential reads at request time.
// Without this, renaming AWSEKSSSOAuthParams on either side still
// compiles and all tests pass, but production breaks at request time.
// (endpoints does not import credentials, so there is no cycle.)
var _ awsEKSSSOParams = (*endpoints.KubernetesEndpoint)(nil)

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
// mints and records the bearer token / account / role it last saw, and
// tallies mints per (account, role) so cache-isolation tests can assert
// no cross-contamination.
//
// The returned key material (akid/secret/token) defaults to the minted
// constants but is overridable so a test can simulate a malformed-200
// (empty material) response. releaseMint, when non-nil, blocks each
// handler until closed — the single-flight burst test uses it.
type mockSSO struct {
	server *httptest.Server

	akid, secret, token string
	releaseMint         chan struct{}

	mints      atomic.Int64
	gotToken   atomic.Value // string
	gotAccount atomic.Value // string
	gotRole    atomic.Value // string
	expiration int64        // epoch milliseconds

	mu    sync.Mutex
	byKey map[string]int // "account/role" → mint count
}

func newMockSSO(t *testing.T, expiration int64) *mockSSO {
	t.Helper()
	m := &mockSSO{
		expiration: expiration,
		akid:       ssoMintedAKID,
		secret:     ssoMintedSecret,
		token:      ssoMintedToken,
		byKey:      make(map[string]int),
	}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.releaseMint != nil {
			<-m.releaseMint
		}
		m.mints.Add(1)
		account := r.URL.Query().Get("account_id")
		role := r.URL.Query().Get("role_name")
		m.gotToken.Store(r.Header.Get("X-Amz-Sso_bearer_token"))
		m.gotAccount.Store(account)
		m.gotRole.Store(role)
		m.mu.Lock()
		m.byKey[account+"/"+role]++
		m.mu.Unlock()

		body, err := json.Marshal(map[string]map[string]any{
			"roleCredentials": {
				"accessKeyId":     m.akid,
				"secretAccessKey": m.secret,
				"sessionToken":    m.token,
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

func (m *mockSSO) mintsFor(account, role string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.byKey[account+"/"+role]
}

func (m *mockSSO) lastToken() string {
	v, _ := m.gotToken.Load().(string)
	return v
}

// minter builds a core ssoMinter whose sso-client seam points at the
// mock server — the direct-minter equivalent of credFor, used to port
// the sibling plugin's minter-level tests.
func (m *mockSSO) minter(region, token string, window time.Duration) *ssoMinter {
	return newSSOMinter(region, token, window, func(region string) *sso.Client {
		return sso.New(sso.Options{
			Region:       region,
			BaseEndpoint: aws.String(m.server.URL),
			Credentials:  aws.AnonymousCredentials{},
		})
	})
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

// TestAWSSSOEKSCredentialSessionReuseSuppressesOwnFlow asserts the
// session-reuse seam: when `session` names another credential, this
// credential runs no OAuth flow of its own (OAuthFlow == nil, so the
// dashboard shows no second Connect card) and OAuthSessionSource surfaces
// the owner the host aliases its token to. With no session it runs its
// own flow as before.
func TestAWSSSOEKSCredentialSessionReuseSuppressesOwnFlow(t *testing.T) {
	reuse := &AWSSSOEKSCredential{Session: "aws-sso", Region: "eu-central-1"}
	if flow := reuse.OAuthFlow(); flow != nil {
		t.Errorf("OAuthFlow() = %+v, want nil when session is set (no second Connect card)", flow)
	}
	if got := reuse.OAuthSessionSource(); got != "aws-sso" {
		t.Errorf("OAuthSessionSource() = %q, want %q", got, "aws-sso")
	}

	own := &AWSSSOEKSCredential{StartURL: "https://my-org.awsapps.com/start", Region: "eu-central-1"}
	if flow := own.OAuthFlow(); flow == nil {
		t.Error("OAuthFlow() = nil, want its own aws_sso flow when session is unset")
	}
	if got := own.OAuthSessionSource(); got != "" {
		t.Errorf("OAuthSessionSource() = %q, want empty when session is unset", got)
	}
}

// TestValidateAWSSSOEKSCredential covers the load-time login-shape rules:
// region is always required, and exactly one of start_url (own login) or
// session (reuse) must be set.
func TestValidateAWSSSOEKSCredential(t *testing.T) {
	ctx := &config.BuildCtx{Block: &hcl.Block{}}
	cases := []struct {
		name    string
		cred    *AWSSSOEKSCredential
		wantErr string // substring the diagnostics must mention; "" = valid
	}{
		{"own login", &AWSSSOEKSCredential{StartURL: "https://org.awsapps.com/start", Region: "eu-central-1"}, ""},
		{"session reuse", &AWSSSOEKSCredential{Session: "aws-sso", Region: "eu-central-1"}, ""},
		{"missing region", &AWSSSOEKSCredential{StartURL: "https://org.awsapps.com/start"}, "region"},
		{"neither start_url nor session", &AWSSSOEKSCredential{Region: "eu-central-1"}, "start_url"},
		{"both start_url and session", &AWSSSOEKSCredential{StartURL: "https://org.awsapps.com/start", Session: "aws-sso", Region: "eu-central-1"}, "not both"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			diags := validateAWSSSOEKSCredential(tc.cred, tc.name, ctx)
			if tc.wantErr == "" {
				if diags.HasErrors() {
					t.Fatalf("diags = %v, want none", diags)
				}
				return
			}
			if !diags.HasErrors() {
				t.Fatalf("diags = none, want one mentioning %q", tc.wantErr)
			}
			if !strings.Contains(diags.Error(), tc.wantErr) {
				t.Errorf("diags = %q, want one mentioning %q", diags.Error(), tc.wantErr)
			}
		})
	}
}

// TestAWSSSOEKSCredentialFailsClosedEmptyMaterial asserts a
// malformed-but-200 GetRoleCredentials response (valid expiration, but
// empty key material) fails closed: no bearer is stamped, and the empty
// material is not cached — a second sign re-mints rather than serving a
// cached garbage credential until expiry.
func TestAWSSSOEKSCredentialFailsClosedEmptyMaterial(t *testing.T) {
	m := newMockSSO(t, expiresInMillis(time.Hour))
	m.akid = ""   // simulate empty accessKeyId in an otherwise-200 response
	m.secret = "" // and empty secretAccessKey
	cred := m.credFor("eu-central-1")
	ep := &stubSSOEKSEndpoint{cluster: "my-cluster", region: "us-west-2", account: ssoTestAccount, role: ssoTestRole}
	sec := runtime.Secret{Bytes: []byte(ssoTestToken)}

	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", "https://k8s.example/", nil)
		err := cred.SignHTTPRequest(context.Background(), req, sec, ep)
		if err == nil || !strings.Contains(err.Error(), "empty credential material") {
			t.Fatalf("sign #%d err = %v, want one mentioning empty credential material", i, err)
		}
		if req.Header.Get("Authorization") != "" {
			t.Errorf("Authorization stamped despite empty material: %q", req.Header.Get("Authorization"))
		}
	}
	// Empty material must not be cached: each sign re-mints (a cached bad
	// credential would suppress the second mint and be served until expiry).
	if got := m.mintCount(); got != 2 {
		t.Errorf("GetRoleCredentials mints = %d, want 2 (empty material must not be cached)", got)
	}
}

// TestAWSSSOEKSCredentialRebuildsMinterOnTokenSwap asserts the
// single-slot minter rebuilds when the SSO token changes (a reconnect):
// after swapping sec.Bytes, the next sign performs a fresh mint carrying
// the NEW bearer rather than serving role credentials from the stale
// session's cache.
func TestAWSSSOEKSCredentialRebuildsMinterOnTokenSwap(t *testing.T) {
	m := newMockSSO(t, expiresInMillis(time.Hour))
	cred := m.credFor("eu-central-1")
	ep := &stubSSOEKSEndpoint{cluster: "my-cluster", region: "us-west-2", account: ssoTestAccount, role: ssoTestRole}

	const firstToken = "sso-token-first"
	req1, _ := http.NewRequest("GET", "https://k8s.example/", nil)
	if err := cred.SignHTTPRequest(context.Background(), req1, runtime.Secret{Bytes: []byte(firstToken)}, ep); err != nil {
		t.Fatalf("sign #1: %v", err)
	}
	if got := m.mintCount(); got != 1 {
		t.Fatalf("after first sign mints = %d, want 1", got)
	}
	if got := m.lastToken(); got != firstToken {
		t.Errorf("first mint bearer = %q, want %q", got, firstToken)
	}

	// Reconnect: the SSO device flow delivers a new access token.
	const secondToken = "sso-token-second"
	req2, _ := http.NewRequest("GET", "https://k8s.example/", nil)
	if err := cred.SignHTTPRequest(context.Background(), req2, runtime.Secret{Bytes: []byte(secondToken)}, ep); err != nil {
		t.Fatalf("sign #2: %v", err)
	}
	// The minter must rebuild and re-mint with the new token — not serve the
	// first session's cached (account, role) credentials.
	if got := m.mintCount(); got != 2 {
		t.Errorf("after token swap mints = %d, want 2 (minter must rebuild)", got)
	}
	if got := m.lastToken(); got != secondToken {
		t.Errorf("second mint bearer = %q, want the swapped token %q", got, secondToken)
	}
}

// TestAWSSSOEKSCredentialOneCredentialManyClusters is the PR's headline
// capability: one SSO credential serving many clusters/accounts. Two
// endpoints carrying different (account, role) must each drive a
// distinct mint with the correct account/role and share no cache entry.
func TestAWSSSOEKSCredentialOneCredentialManyClusters(t *testing.T) {
	m := newMockSSO(t, expiresInMillis(time.Hour))
	cred := m.credFor("eu-central-1")
	sec := runtime.Secret{Bytes: []byte(ssoTestToken)}

	const (
		accountA, roleA = "111111111111", "EKSAdmin"
		accountB, roleB = "222222222222", "EKSReadOnly"
	)
	epA := &stubSSOEKSEndpoint{cluster: "cluster-a", region: "us-west-2", account: accountA, role: roleA}
	epB := &stubSSOEKSEndpoint{cluster: "cluster-b", region: "eu-west-1", account: accountB, role: roleB}

	// Sign each endpoint twice: the per-(account,role) cache must collapse
	// each pair's repeat to a single mint while keeping the pairs distinct.
	for _, ep := range []*stubSSOEKSEndpoint{epA, epB, epA, epB} {
		req, _ := http.NewRequest("GET", "https://k8s.example/", nil)
		if err := cred.SignHTTPRequest(context.Background(), req, sec, ep); err != nil {
			t.Fatalf("sign %s/%s: %v", ep.account, ep.role, err)
		}
	}

	if got := m.mintCount(); got != 2 {
		t.Errorf("total mints = %d, want 2 (one per distinct account/role, cached thereafter)", got)
	}
	if got := m.mintsFor(accountA, roleA); got != 1 {
		t.Errorf("mints for %s/%s = %d, want 1", accountA, roleA, got)
	}
	if got := m.mintsFor(accountB, roleB); got != 1 {
		t.Errorf("mints for %s/%s = %d, want 1", accountB, roleB, got)
	}
}

// The following three tests are ports of the sibling plugin's
// minter_test.go (clawpatrol-plugin-aws/internal/awssso) against the
// core ssoMinter, covering the subtle expiry-window and single-flight
// behaviors the CredentialsCache owns.

// TestSSOMinterRefreshesWithinExpiryWindow: credentials that expire
// inside the refresh window read as expired on retrieval, so every call
// re-mints. (Port of TestMinter_RefreshesWithinExpiryWindow.)
func TestSSOMinterRefreshesWithinExpiryWindow(t *testing.T) {
	// Expire in 30s with a 60s window → always inside the window.
	m := newMockSSO(t, expiresInMillis(30*time.Second))
	minter := m.minter("eu-central-1", ssoTestToken, time.Minute)

	if _, err := minter.credentials(context.Background(), ssoTestAccount, ssoTestRole); err != nil {
		t.Fatalf("mint #1: %v", err)
	}
	if _, err := minter.credentials(context.Background(), ssoTestAccount, ssoTestRole); err != nil {
		t.Fatalf("mint #2: %v", err)
	}
	if got := m.mintCount(); got != 2 {
		t.Errorf("mints = %d, want 2 (creds inside the expiry window must re-mint)", got)
	}
}

// TestSSOMinterSingleFlightUnderConcurrentBurst: a concurrent burst for
// one (account, role) collapses to a single mint. (Port of
// TestMinter_SingleFlightUnderConcurrentBurst.)
func TestSSOMinterSingleFlightUnderConcurrentBurst(t *testing.T) {
	m := newMockSSO(t, expiresInMillis(time.Hour))
	m.releaseMint = make(chan struct{})
	minter := m.minter("eu-central-1", ssoTestToken, time.Minute)

	const burst = 20
	var wg sync.WaitGroup
	errCh := make(chan error, burst)
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := minter.credentials(context.Background(), ssoTestAccount, ssoTestRole)
			errCh <- err
		}()
	}
	// Let the burst pile up on a single in-flight mint, then release it.
	time.Sleep(50 * time.Millisecond)
	close(m.releaseMint)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent mint: %v", err)
		}
	}
	if got := m.mintCount(); got != 1 {
		t.Errorf("mints = %d, want 1 (a concurrent burst must trigger exactly one mint)", got)
	}
}

// TestSSOMinterRejectsNonPositiveExpiration: a zero / negative
// expiration is rejected rather than cached as permanently expired.
// (Port of TestMinter_RejectsNonPositiveExpiration.)
func TestSSOMinterRejectsNonPositiveExpiration(t *testing.T) {
	for _, exp := range []int64{0, -1000} {
		m := newMockSSO(t, exp)
		minter := m.minter("eu-central-1", ssoTestToken, time.Minute)
		if _, err := minter.credentials(context.Background(), ssoTestAccount, ssoTestRole); err == nil {
			t.Errorf("expiration %d: err = nil, want rejection", exp)
		}
	}
}
