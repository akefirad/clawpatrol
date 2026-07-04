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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// placeholderShape accepts an AKID-ish token: uppercase letters + digits,
// 16–32 chars. Kept permissive (not a strict 20-char AKIA-prefixed AKID)
// since placeholders only need to be signable + distinct — but it rejects
// the separators (/, comma, space) that would break the SigV4 Credential=
// scope so sigV4AccessKeyID can't parse the routing key out of it.
var placeholderShape = regexp.MustCompile(`^[A-Z0-9]{16,32}$`)

// awsAccountIDShape is the AWS 12-digit account number.
var awsAccountIDShape = regexp.MustCompile(`^[0-9]{12}$`)

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
//
// POLICY CAVEAT: role selection is invisible to the rules engine. The http
// facet exposes method/path/query/headers/body — not the matched
// (account, role) — so every role on one credential shares ONE policy
// surface: an endpoint's rules are effectively the UNION across all its
// mapped roles. An agent that can pass the shared rules can mint the most
// privileged configured role. To isolate a high-privilege role, put it on
// its OWN aws_sso_credential bound to its OWN endpoint (host-matched), and
// attach the stricter rules there.
//
// IMPROVEMENT: expose the matched (account, role) to policy — a CEL-visible
// field or per-role endpoint bindings — so rules can discriminate per role
// instead of per shared endpoint. Deferred: it touches the facet/policy
// engine, not just this plugin.
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
	// caches + latest token). A pointer so the config body carries no lock
	// (never copy-locked). Allocated by the Build hook (buildAWSSSO) so it's
	// non-nil at request time; runtimeState() lazily allocs only for
	// hand-built test instances that skip Build. awsSSORuntime.mu guards its
	// own contents.
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

func (c *AWSSSOCredential) runtimeState() *awsSSORuntime {
	// Production credentials are initialized by buildAWSSSO (the Build hook),
	// so rt is non-nil by request time and this is a plain field read — no
	// process-global lock across instances. The nil branch only covers
	// hand-built test instances that skip Build; those are constructed on a
	// single goroutine, and any test exercising concurrency must initialize
	// rt first (call buildAWSSSO / newRuntime) so no two goroutines race here.
	if c.rt == nil {
		c.rt = newAWSSSORuntime()
	}
	return c.rt
}

func newAWSSSORuntime() *awsSSORuntime {
	return &awsSSORuntime{caches: map[string]*aws.CredentialsCache{}}
}

// buildAWSSSO is the plugin Build hook: it eagerly allocates the request-time
// runtime state so rt is never nil at request time. This is what lets
// runtimeState() avoid a process-global allocation lock (see #6). Build
// returns the same *AWSSSOCredential pointer the runtime stores as its Body.
func buildAWSSSO(decoded any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
	c := decoded.(*AWSSSOCredential)
	c.rt = newAWSSSORuntime()
	return c, nil
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

// NOTE (SSO access-token refresh — DEFERRED, see akefirad/clawpatrol#6):
// The per-ROLE temporary credentials are refreshed automatically here (the
// aws.CredentialsCache re-mints them before expiry). The SSO ACCESS TOKEN
// itself (ssoToken, delivered via the OAuthRegistry) is NOT refreshed: when
// it expires (IAM Identity Center default ~8h) the operator re-connects via
// the dashboard.
//
// What the operator actually sees on expiry: aws_sso has no setToken refresh
// branch, and the device-flow poll deliberately does NOT persist a refresh
// token (see oauth_aws_sso.go), so the OAuth layer surfaces the clean error
// `token expired and refresh token is not set` rather than attempting a
// refresh against an empty TokenURL (which would log a cryptic `unsupported
// protocol scheme ""`). GetRoleCredentials is never reached — the token
// lookup fails first; main.go logs `secret <name>: ... — forwarding without
// injection` and the request forwards with the placeholder signature (AWS
// then 403s). Graceful-ish degradation with a legible cause, not a break.
//
// To add refresh later: (1) persist the refresh token again in the poll,
// and (2) register an awsSSORefreshSource for Flow=="aws_sso" in the
// gateway's OAuth setToken switch (mirror anthropicRefreshSource), calling
// ssooidc CreateToken(grant_type=refresh_token). The open question is WHERE
// to persist the client secret it needs: the `credentials` table has
// `client_id` + `refresh_token` but no `client_secret` column. Options (to
// be decided): pack clientId+clientSecret into the existing client_id
// column, add a client_secret column (schema migration), or use the blob
// store. Parked pending that decision.

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
	// A zero Expiration would become time.UnixMilli(0) = 1970, which with
	// CanExpire:true makes aws.CredentialsCache treat the entry as already
	// expired — so every request re-mints (latency + AWS throttling /
	// TooManyRequestsException). AWS always populates it; treat a zero as an
	// error rather than caching a permanently-expired entry.
	if rc.Expiration == 0 {
		return aws.Credentials{}, fmt.Errorf("aws_sso_credential: GetRoleCredentials(%s/%s) returned no expiration", p.accountID, p.roleName)
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
		// Unknown placeholder → no role, so we do NOT re-sign under an
		// unintended identity. Returning an error here is only "fail closed"
		// at the credential: the gateway's signer path (main.go) logs a sign
		// error and still forwards the request upstream bearing the agent's
		// placeholder signature, which AWS then rejects (InvalidClientTokenId).
		// So the request is effectively denied, but by AWS, not the gateway.
		//
		// IMPROVEMENT (akefirad/clawpatrol#16): prefer a true gateway-level
		// rejection (a 4xx/502, like the transform-credential fail-closed
		// branch in main.go) so an unknown placeholder never egresses at all.
		// That means teaching the signer path to fail closed on error, which
		// changes behavior for all signers (aws_credential included) —
		// deferred to keep this additive.
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

// validateAWSSSO rejects configs that would dispatch ambiguously or fail
// the SSO login: a distinct placeholder per role is what lets the gateway
// route a request to the right role, so duplicates (or empty fields) are
// load-time errors rather than silent request-time surprises.
func validateAWSSSO(decoded any, name string, _ *config.BuildCtx) hcl.Diagnostics {
	c := decoded.(*AWSSSOCredential)
	var diags hcl.Diagnostics
	add := func(msg string) {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "invalid aws_sso_credential",
			Detail:   fmt.Sprintf("credential %q: %s", name, msg),
		})
	}
	if c.StartURL == "" {
		add("start_url is required (the IAM Identity Center access-portal URL)")
	}
	if c.Region == "" {
		add("region is required (the SSO region)")
	}
	if len(c.Roles) == 0 {
		add("must declare at least one role mapping")
	}
	seen := map[string]bool{}
	for i, r := range c.Roles {
		if r.AccountID == "" || r.RoleName == "" || r.Placeholder == "" {
			add(fmt.Sprintf("role #%d: account_id, role_name, and placeholder are all required", i+1))
		}
		if r.AccountID != "" && !awsAccountIDShape.MatchString(r.AccountID) {
			add(fmt.Sprintf("role #%d: account_id %q must be a 12-digit AWS account number", i+1, r.AccountID))
		}
		if r.Placeholder == "" {
			continue
		}
		// A placeholder that can't survive SigV4 signing never routes: aws-cli
		// signs with it, but the resulting Credential= scope no longer splits
		// into 5 parts, sigV4AccessKeyID returns "", and every request fails
		// with the unhelpful "carries no SigV4 access-key-id". Catch it here.
		if !placeholderShape.MatchString(r.Placeholder) {
			add(fmt.Sprintf("role #%d: placeholder %q must look like an access-key-id (16–32 uppercase letters/digits, no separators) so it survives SigV4 signing and stays routable", i+1, r.Placeholder))
		}
		// Reject the ambient placeholder aws_credential pushes into the agent
		// env (AWS_ACCESS_KEY_ID=phAWSKeyID). Reusing it here cross-wires the
		// two credential types when both are configured on the same gateway.
		if r.Placeholder == phAWSKeyID {
			add(fmt.Sprintf("role #%d: placeholder %q collides with aws_credential's ambient placeholder — pick a distinct access-key-id", i+1, r.Placeholder))
		}
		if seen[r.Placeholder] {
			add(fmt.Sprintf("duplicate placeholder %q — each role needs a distinct placeholder access-key-id so requests route unambiguously", r.Placeholder))
		}
		seen[r.Placeholder] = true
	}
	return diags
}

func init() {
	var _ runtime.HTTPRequestSigner = (*AWSSSOCredential)(nil)
	var _ config.OAuthFlowProvider = (*AWSSSOCredential)(nil)
	config.Register(&config.Plugin{
		Kind:     config.KindCredential,
		Type:     "aws_sso_credential",
		New:      newer[AWSSSOCredential](),
		Runtime:  (*AWSSSOCredential)(nil),
		Validate: validateAWSSSO,
		Build:    buildAWSSSO,
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
