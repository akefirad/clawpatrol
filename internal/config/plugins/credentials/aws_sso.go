package credentials

// aws_sso_credential: AWS IAM Identity Center (SSO) credentials.
//
// One authentication (start_url + SSO region → one dashboard device login
// → one stored SSO token) fans out to many (account, role) mappings, each
// bound to a distinct placeholder access-key-id. The credential
// SELF-DISPATCHES: it reads the placeholder access-key-id the agent's
// aws-cli signed with out of the SigV4 Authorization header, selects the
// matching role mapping, mints that role's real (short-lived) credentials
// via sso:GetRoleCredentials using the stored SSO token, and re-signs the
// request with them — the agent never holds real creds. Because a single
// credential covers all roles, no core disambiguator is used (role
// selection is internal to this credential).
//
// Credential source: the SSO access token is delivered as sec.Bytes via
// the OAuthRegistry (see OAuthFlow + the gateway's OAuth-flow secret path);
// the dashboard device login that obtains it lives in the gateway's OAuth
// engine (Flow="aws_sso"). Per-role temporary credentials are cached in
// memory (aws.CredentialsCache: expiry-margin + single-flight refresh), so
// a burst of requests triggers at most one GetRoleCredentials call and the
// cache repopulates from the stored token after a restart. SSO-token
// refresh for long sessions is a later slice (akefirad/clawpatrol#6);
// multi-role switching + explicit no-profile-deny semantics land in #5.
//
// Re-signing reuses aws_credential's reSignProxiedRequest verbatim (same
// package; that method uses no receiver state) — no modification to aws.go.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// awsSSOExpiryWindow refreshes cached role credentials this long before
// their true expiry, so a request never signs with about-to-expire creds
// and the refresh (a GetRoleCredentials call) happens ahead of expiry.
const awsSSOExpiryWindow = 5 * time.Minute

// newSSOClient builds the sso client for a region. A package var so tests
// can point it at a mock server. sso:GetRoleCredentials is unauthenticated
// (the SSO access token is passed as a parameter), so no AWS credentials
// are configured.
var newSSOClient = func(region string) *sso.Client {
	return sso.New(sso.Options{Region: region})
}

// AWSSSORole is one switchable (account, role) mapping. Placeholder is a
// distinct access-key-id the agent signs with (seeded into the agent's
// ~/.aws/credentials as a profile) so the gateway can tell which role a
// request intends.
type AWSSSORole struct {
	AccountID   string `hcl:"account_id"`
	RoleName    string `hcl:"role_name"`
	Placeholder string `hcl:"placeholder"`
}

// AWSSSOCredential is the aws_sso_credential plugin body: one SSO
// authentication plus a list of role mappings.
type AWSSSOCredential struct {
	// StartURL is the AWS access portal URL of the IAM Identity Center
	// instance (e.g. https://mycompany.awsapps.com/start).
	StartURL string `hcl:"start_url"`
	// Region is the SSO region the Identity Center instance lives in.
	Region string `hcl:"region"`
	// Roles is the set of switchable (account, role) mappings, each
	// keyed by a distinct placeholder access-key-id.
	Roles []AWSSSORole `hcl:"role,block"`

	// rt holds request-time cache state (SSO client + per-role credential
	// caches + latest token). Pointer + lazy alloc so the config body
	// carries no lock (never copy-locked) and hand-built instances in
	// tests work without a Build step. Guarded by awsSSORuntimeMu for
	// allocation; awsSSORuntime.mu guards its own contents.
	rt *awsSSORuntime
}

// awsSSORuntime is the per-credential request-time cache.
type awsSSORuntime struct {
	mu     sync.Mutex
	client *sso.Client
	caches map[string]*aws.CredentialsCache // key: "<account>/<role>"
	token  string                           // latest SSO access token
}

func (rt *awsSSORuntime) currentToken() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.token
}

// awsSSORuntimeMu guards lazy allocation of AWSSSOCredential.rt only.
var awsSSORuntimeMu sync.Mutex

func (c *AWSSSOCredential) runtimeState() *awsSSORuntime {
	awsSSORuntimeMu.Lock()
	defer awsSSORuntimeMu.Unlock()
	if c.rt == nil {
		c.rt = &awsSSORuntime{caches: map[string]*aws.CredentialsCache{}}
	}
	return c.rt
}

// sigV4AccessKeyID extracts the access-key-id from a SigV4 Authorization
// header's `Credential=<AKID>/<date>/<region>/<service>/aws4_request`
// element. Returns "" when the header is missing or malformed. (Sibling
// of aws.go's parseSigV4CredentialScope, which returns service/region;
// this returns the leading access-key-id we route on.)
func sigV4AccessKeyID(authHeader string) string {
	const marker = "Credential="
	i := strings.Index(authHeader, marker)
	if i < 0 {
		return ""
	}
	scope := authHeader[i+len(marker):]
	if j := strings.IndexAny(scope, ", "); j >= 0 {
		scope = scope[:j]
	}
	parts := strings.Split(scope, "/")
	if len(parts) != 5 || parts[4] != "aws4_request" {
		return ""
	}
	return parts[0]
}

// roleForPlaceholder returns the role mapping whose placeholder equals
// the given access-key-id, or nil when none matches.
func (c *AWSSSOCredential) roleForPlaceholder(akid string) *AWSSSORole {
	for i := range c.Roles {
		if c.Roles[i].Placeholder != "" && c.Roles[i].Placeholder == akid {
			return &c.Roles[i]
		}
	}
	return nil
}

// roleCreds returns the (cached) temporary credentials for a role, minting
// them via sso:GetRoleCredentials with the current SSO token on a cache
// miss / near-expiry. Refresh is expiry-margin + single-flight (both from
// aws.CredentialsCache).
func (c *AWSSSOCredential) roleCreds(ctx context.Context, role AWSSSORole, ssoToken string) (aws.Credentials, error) {
	rt := c.runtimeState()
	rt.mu.Lock()
	rt.token = ssoToken
	if rt.client == nil {
		rt.client = newSSOClient(c.Region)
	}
	key := role.AccountID + "/" + role.RoleName
	cache := rt.caches[key]
	if cache == nil {
		prov := &ssoRoleProvider{
			client:    rt.client,
			accountID: role.AccountID,
			roleName:  role.RoleName,
			tokenFn:   rt.currentToken,
		}
		cache = aws.NewCredentialsCache(prov, func(o *aws.CredentialsCacheOptions) {
			o.ExpiryWindow = awsSSOExpiryWindow
		})
		rt.caches[key] = cache
	}
	rt.mu.Unlock()
	return cache.Retrieve(ctx)
}

// ssoRoleProvider is the aws.CredentialsProvider the per-role cache wraps:
// each Retrieve mints fresh temporary credentials for one (account, role)
// from the current SSO token.
type ssoRoleProvider struct {
	client    *sso.Client
	accountID string
	roleName  string
	tokenFn   func() string
}

func (p *ssoRoleProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	token := p.tokenFn()
	if token == "" {
		return aws.Credentials{}, fmt.Errorf("aws_sso_credential: no SSO token (connect AWS SSO in the dashboard)")
	}
	out, err := p.client.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: aws.String(token),
		AccountId:   aws.String(p.accountID),
		RoleName:    aws.String(p.roleName),
	})
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("aws_sso_credential: GetRoleCredentials(%s/%s): %w", p.accountID, p.roleName, err)
	}
	rc := out.RoleCredentials
	if rc == nil || aws.ToString(rc.AccessKeyId) == "" {
		return aws.Credentials{}, fmt.Errorf("aws_sso_credential: GetRoleCredentials(%s/%s) returned no credentials", p.accountID, p.roleName)
	}
	return aws.Credentials{
		AccessKeyID:     aws.ToString(rc.AccessKeyId),
		SecretAccessKey: aws.ToString(rc.SecretAccessKey),
		SessionToken:    aws.ToString(rc.SessionToken),
		Source:          "aws_sso_credential",
		CanExpire:       true,
		// SSO returns Expiration as epoch milliseconds.
		Expires: time.UnixMilli(rc.Expiration),
	}, nil
}

// SignHTTPRequest is part of the clawpatrol plugin API. It self-dispatches
// on the placeholder access-key-id the agent signed with, mints that
// role's real credentials (cached) from the stored SSO token, and re-signs
// the request with them.
func (c *AWSSSOCredential) SignHTTPRequest(ctx context.Context, req *http.Request, sec runtime.Secret, _ any) error {
	akid := sigV4AccessKeyID(req.Header.Get("Authorization"))
	if akid == "" {
		return fmt.Errorf("aws_sso_credential: request carries no SigV4 access-key-id to route on")
	}
	role := c.roleForPlaceholder(akid)
	if role == nil {
		// Unknown placeholder → no role. Fail closed rather than
		// re-signing under an unintended identity. (Multi-role dispatch
		// and the explicit no-profile-deny semantics land in a later slice.)
		return fmt.Errorf("aws_sso_credential: no role mapping for placeholder access-key-id %q", akid)
	}
	ssoToken := string(sec.Bytes)
	if ssoToken == "" {
		return fmt.Errorf("aws_sso_credential: no SSO token available (connect AWS SSO in the dashboard)")
	}
	creds, err := c.roleCreds(ctx, *role, ssoToken)
	if err != nil {
		return err
	}
	// Hand the minted creds to aws_credential's re-signer via a secret it
	// understands; reSignProxiedRequest derives service/region from the
	// request and reuses/recomputes the payload hash. It uses no
	// AWSCredential receiver state, so a zero-value receiver is fine.
	roleSec := runtime.Secret{Extras: map[string]string{
		"access_key_id":     creds.AccessKeyID,
		"secret_access_key": creds.SecretAccessKey,
		"session_token":     creds.SessionToken,
	}}
	return (&AWSCredential{}).reSignProxiedRequest(ctx, req, roleSec)
}

// OAuthFlow is part of the clawpatrol plugin API. It registers this
// credential with the gateway's OAuth registry so the dashboard renders a
// "Connect" card and the SSO token persists like every other OAuth-flow
// credential. AWS SSO's device flow is non-standard (JSON ssooidc
// RegisterClient / StartDeviceAuthorization / CreateToken), so it runs
// under the dedicated Flow="aws_sso" branch in the gateway's OAuth engine.
//
// The per-instance start URL + SSO region ride on the OAuth config so the
// flow handler needs no policy lookup: AuthURL carries the access-portal
// start URL, and DeviceURL carries the SSO region (the ssooidc endpoint is
// derived from it). No client id/secret/token are set here — the device
// flow registers a client dynamically and the registry owns the token.
func (c *AWSSSOCredential) OAuthFlow() *config.OAuthIntegration {
	return &config.OAuthIntegration{
		Type: "aws_sso",
		Flow: "aws_sso",
		OAuth: config.OAuthConfig{
			AuthURL:   c.StartURL,
			DeviceURL: c.Region,
		},
	}
}

// Note: aws_sso_credential intentionally does NOT implement
// EnvPushdownProvider. Unlike aws_credential it pushes no default
// AWS_ACCESS_KEY_ID/SECRET — role selection is per-request via the
// per-role placeholder the agent's ~/.aws/credentials profile supplies,
// so there is no ambient default identity (a no-profile call has no
// creds and is denied). See akefirad/clawpatrol#5.

func init() {
	var _ runtime.HTTPRequestSigner = (*AWSSSOCredential)(nil)
	var _ config.OAuthFlowProvider = (*AWSSSOCredential)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "aws_sso_credential",
		New:     newer[AWSSSOCredential](),
		Runtime: (*AWSSSOCredential)(nil),
		Build:   passthrough,
		Emit: func(body any, _ string, hb *hclwrite.Body) {
			c := body.(*AWSSSOCredential)
			hb.SetAttributeValue("start_url", cty.StringVal(c.StartURL))
			hb.SetAttributeValue("region", cty.StringVal(c.Region))
			for _, r := range c.Roles {
				rb := hb.AppendNewBlock("role", nil).Body()
				rb.SetAttributeValue("account_id", cty.StringVal(r.AccountID))
				rb.SetAttributeValue("role_name", cty.StringVal(r.RoleName))
				rb.SetAttributeValue("placeholder", cty.StringVal(r.Placeholder))
			}
		},
	})
}
