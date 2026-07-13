package credentials

// aws_sso_eks_credential: mint an EKS API-server bearer token from an
// AWS SSO session.
//
// This is the SSO counterpart to the static-key aws_credential's EKS
// path. It reuses the pieces core already owns and adds only the small
// SSO→temp-creds bridge in the middle:
//
//   - the core aws_sso OAuth device flow (Flow == "aws_sso") delivers the
//     persisted SSO access token as this credential's runtime Secret
//     (sec.Bytes), identical to how anthropic_oauth_subscription receives
//     its bearer;
//   - sso:GetRoleCredentials(account, role) exchanges that token for
//     temporary SigV4 credentials, cached per (account, role) — see
//     aws_sso_minter.go;
//   - the existing STS GetCallerIdentity presign → k8s-aws-v1.<base64url>
//     bearer (mintEKSBearerToken in aws.go) turns those creds into the
//     bearer EKS accepts, including the x-k8s-aws-id cluster header and
//     the X-Amz-Expires=60 quirk aws-iam-authenticator requires.
//
// Cluster identity lives on the kubernetes endpoint (cluster/region/
// account/role); the SSO session lives on this credential. One SSO
// credential therefore serves many clusters/accounts.
//
// Two-region contract: this credential's `region` is the SSO portal
// region (for GetRoleCredentials); the endpoint's `region` is the
// cluster/STS region (for the presign). They are independent and must
// not be conflated.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// ssoMintTimeout bounds the single sso:GetRoleCredentials mint this
// credential performs on the proxied request's context (which typically
// carries no deadline). The OAuth flows bound their upstream calls with
// the analogous main.oauthUpstreamTimeout; this is the credential-package
// counterpart, since that const is not exported. The STS presign is local
// computation and is deliberately left unbounded.
const ssoMintTimeout = 15 * time.Second

// AWSSSOEKSCredential is part of the clawpatrol plugin API.
//
// StartURL + Region drive the aws_sso OAuth flow (see OAuthFlow): the
// start URL is the SSO access-portal URL, and Region is the SSO portal
// region. There is no secret slot — the SSO access token is delivered as
// the runtime Secret by the core OAuth device flow.
//
// Session is the session-reuse alternative to StartURL: set it (instead
// of start_url) to the bare name of another AWS SSO credential and this
// credential borrows that credential's SSO login rather than prompting a
// second AWS SSO device login. The host resolves the borrowed token via
// OAuthSessionSource + the OAuthRegistry alias path; Region is still
// required either way (it scopes sso:GetRoleCredentials).
type AWSSSOEKSCredential struct {
	// StartURL is the AWS SSO access-portal start URL, e.g.
	// https://my-org.awsapps.com/start. Empty when Session is set (this
	// credential then reuses another credential's login and needs no
	// start URL of its own).
	StartURL string `hcl:"start_url,optional"`
	// Region is the SSO portal region — where GetRoleCredentials is
	// called. Independent of the cluster/STS region on the endpoint.
	Region string `hcl:"region"`
	// Session, when set, is the bare name of the AWS SSO credential whose
	// device login this credential reuses. Mutually exclusive with
	// StartURL: with Session set this credential runs no OAuth flow of its
	// own (OAuthFlow returns nil, so the dashboard shows no Connect card)
	// and its SSO access token resolves to the named credential's session.
	Session string `hcl:"session,optional"`

	// newClient is the sso-client seam; nil in production (direct
	// in-process client), set by tests to point at a mock server.
	newClient ssoClientFunc

	// mu guards minter + curToken. The decoded body persists for the
	// compiled policy's lifetime and is shared across concurrent
	// requests, so the per-(account,role) credential cache it holds must
	// be built under a lock.
	mu       sync.Mutex
	minter   *ssoMinter
	curToken string
}

// awsEKSSSOParams is the contract the kubernetes endpoint satisfies so
// this credential can read the full (cluster, region, account, role)
// tuple at request time without importing the endpoint package (which
// would be an import cycle). It is the account/role-carrying widening of
// the endpoint's static-key AWSEKSAuthParams contract.
type awsEKSSSOParams interface {
	AWSEKSSSOAuthParams() (cluster, region, account, role string)
}

// SignHTTPRequest is part of the clawpatrol plugin API. It fails closed
// on any missing input (endpoint params, account/role, SSO token) by
// returning an error rather than stamping a bad or unauthenticated
// bearer. This is credential-level fail-closed only: on a sign error the
// host (cmd/clawpatrol/main.go) currently logs and still forwards the
// request upstream without injection (shared behavior with
// aws_credential), so these branches prevent a bad bearer but do not by
// themselves stop the request from reaching the apiserver. Returning a
// host-layer 502 on kubernetes sign errors is tracked as a follow-up.
func (c *AWSSSOEKSCredential) SignHTTPRequest(ctx context.Context, req *http.Request, sec runtime.Secret, endpoint any) error {
	params, ok := endpoint.(awsEKSSSOParams)
	if !ok {
		return errors.New("aws_sso_eks_credential: endpoint does not expose EKS SSO auth params " +
			"(bind this credential to a kubernetes endpoint with cluster_name/region/account_id/role_name)")
	}
	cluster, region, account, role := params.AWSEKSSSOAuthParams()
	if cluster == "" || region == "" {
		return errors.New("aws_sso_eks_credential: kubernetes endpoint missing cluster_name / region")
	}
	// Fail closed on a misconfigured cluster: without account/role we
	// cannot select the SSO role to assume, and must not mint.
	if account == "" || role == "" {
		return errors.New("aws_sso_eks_credential: kubernetes endpoint missing account_id / role_name " +
			"(required to select the AWS SSO role to assume for this cluster)")
	}
	if c.Region == "" {
		return errors.New("aws_sso_eks_credential: credential missing region (the SSO portal region)")
	}
	// The SSO access token is delivered as the runtime Secret's Bytes by
	// the core aws_sso device flow. An empty token means no session (or an
	// expired one — the flow persists no refresh token, so expiry surfaces
	// as an empty token): fail closed with a recognizable reconnect signal.
	token := string(sec.Bytes)
	if token == "" {
		return errors.New("aws_sso_eks_credential: no AWS SSO session — reconnect AWS SSO in the dashboard")
	}

	// Bound the mint: it is the only network hop in this signer and runs on
	// the proxied request's context, which typically carries no deadline —
	// a hung or mid-response-stalled SSO portal would otherwise wedge the
	// cluster request for as long as the agent holds the connection. This
	// ctx timeout bounds the *caller*: the outer CredentialsCache.Retrieve
	// returns after ssoMintTimeout. It does NOT itself cancel the in-flight
	// GetRoleCredentials — Retrieve runs the provider under a suppressedContext
	// that nils this deadline — so the network op is bounded separately by the
	// SSO client's own http.Client timeout (see newSSOClient in
	// aws_sso_minter.go). The account/role are already named by the minter's
	// own error wrap, so this call site drops the pair to avoid a doubled
	// "A/R … A/R" chain.
	mintCtx, cancel := context.WithTimeout(ctx, ssoMintTimeout)
	defer cancel()
	creds, err := c.minterFor(token).credentials(mintCtx, account, role)
	if err != nil {
		return fmt.Errorf("aws_sso_eks_credential: exchange SSO token for role credentials "+
			"(reconnect AWS SSO if the session has expired): %w", err)
	}

	// Feed the temporary creds into the same STS-presign EKS-bearer path
	// aws_credential uses, tagged with this credential's provenance so a
	// presign failure logs against aws_sso_eks_credential rather than
	// aws_credential. Note the two regions: the presign is scoped to the
	// endpoint's cluster/STS region, not the credential's SSO region. This
	// presign is local computation, so it is deliberately left on ctx.
	bearer, err := mintEKSBearerToken(ctx, "aws_sso_eks_credential", creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, region, cluster)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	return nil
}

// minterFor returns the ssoMinter for the current SSO token, rebuilding
// it when the token changes (a reconnect / refresh). A single slot is
// kept — one SSO credential is one session — so the per-(account,role)
// cache survives a burst of requests but does not grow as tokens rotate.
func (c *AWSSSOEKSCredential) minterFor(token string) *ssoMinter {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.minter == nil || c.curToken != token {
		c.minter = newSSOMinter(c.Region, token, ssoRoleExpiryWindow, c.newClient)
		c.curToken = token
	}
	return c.minter
}

// OAuthSessionSource is the session-reuse seam (see the
// oauthSessionReferencer contract in cmd/clawpatrol/oauth_aws_sso.go):
// when non-empty it names the credential that owns the AWS SSO login
// this credential reuses, so the host resolves this credential's token
// to that credential's session instead of demanding a second AWS SSO
// device login. Empty means this credential runs its own login.
func (c *AWSSSOEKSCredential) OAuthSessionSource() string { return c.Session }

// OAuthFlow declares the aws_sso device flow so the dashboard Connect
// card drives the existing core SSO login and the persisted SSO access
// token is delivered as this credential's runtime Secret. AuthURL is the
// SSO start URL the operator verifies; DeviceURL carries the SSO region
// (the shape startAWSSSODeviceFlow reads).
//
// Returns nil when Session is set: this credential then reuses the named
// credential's SSO login, so it registers no OAuth integration and the
// dashboard renders no (redundant) Connect card for it.
func (c *AWSSSOEKSCredential) OAuthFlow() *config.OAuthIntegration {
	if c.Session != "" {
		return nil
	}
	return &config.OAuthIntegration{
		Flow: "aws_sso",
		OAuth: config.OAuthConfig{
			AuthURL:   c.StartURL,
			DeviceURL: c.Region,
		},
	}
}

// validateAWSSSOEKSCredential enforces the login shape at load time so a
// misconfiguration surfaces as a visible policy error rather than a
// request-time sign failure that forwards uninjected: region (the SSO
// portal region for sso:GetRoleCredentials) is always required, and
// exactly one of start_url (own device login) or session (reuse another
// credential's login) must be set.
func validateAWSSSOEKSCredential(d any, name string, ctx *config.BuildCtx) hcl.Diagnostics {
	c, ok := d.(*AWSSSOEKSCredential)
	if !ok {
		return nil
	}
	defRange := ctx.Block.DefRange
	var diags hcl.Diagnostics
	if c.Region == "" {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Missing region on credential %q", name),
			Detail:   "region is the AWS SSO portal region (where sso:GetRoleCredentials is called) and is always required.",
			Subject:  &defRange,
		})
	}
	switch {
	case c.StartURL == "" && c.Session == "":
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Missing start_url on credential %q", name),
			Detail:   `set start_url to run this credential's own AWS SSO device login, or set session = "<credential>" to reuse another credential's SSO login.`,
			Subject:  &defRange,
		})
	case c.StartURL != "" && c.Session != "":
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("Conflicting login config on credential %q", name),
			Detail:   "set either start_url (own AWS SSO device login) or session (reuse another credential's login), not both.",
			Subject:  &defRange,
		})
	}
	return diags
}

func init() {
	var _ runtime.HTTPRequestSigner = (*AWSSSOEKSCredential)(nil)
	var _ config.OAuthFlowProvider = (*AWSSSOEKSCredential)(nil)
	config.Register(&config.Plugin{
		Kind:     config.KindCredential,
		Type:     "aws_sso_eks_credential",
		New:      newer[AWSSSOEKSCredential](),
		Runtime:  (*AWSSSOEKSCredential)(nil),
		Validate: validateAWSSSOEKSCredential,
		Build:    passthrough,
		Emit: func(body any, _ string, b *hclwrite.Body) {
			e := body.(*AWSSSOEKSCredential)
			// start_url and session are mutually exclusive; emit only the
			// one that's set so a round-trip doesn't resurrect the other.
			if e.StartURL != "" {
				b.SetAttributeValue("start_url", cty.StringVal(e.StartURL))
			}
			b.SetAttributeValue("region", cty.StringVal(e.Region))
			if e.Session != "" {
				b.SetAttributeValue("session", cty.StringVal(e.Session))
			}
		},
	})
}
