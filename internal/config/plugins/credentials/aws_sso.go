package credentials

// aws_sso_credential: AWS IAM Identity Center (SSO) credentials.
//
// One authentication (start_url + SSO region → one device login → one
// stored SSO token) fans out to many (account, role) mappings, each
// bound to a distinct placeholder access-key-id. The credential
// SELF-DISPATCHES: it reads the placeholder access-key-id the agent's
// aws-cli signed with out of the SigV4 Authorization header, selects
// the matching role mapping, and re-signs the request with that role's
// real credentials — the agent never holds real creds. Because a
// single credential covers all roles, no core disambiguator is used or
// needed (role selection is internal to this credential).
//
// SLICE 1 (this file, initial cut — see akefirad/clawpatrol#2): schema +
// self-dispatch + re-sign for a role sourcing its "real" creds from the
// credential's SEEDED secret slots (no live SSO yet). Later slices add
// the SSO device-login (#3), live sso:GetRoleCredentials + caching (#4),
// per-request multi-role switching + unknown→deny (#5), token refresh
// (#6), and policy examples (#7). Re-signing reuses aws_credential's
// reSignProxiedRequest verbatim (same package; that method uses no
// receiver state) — no modification to aws.go.

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// AWSSSORole is one switchable (account, role) mapping. Placeholder is
// a distinct access-key-id the agent signs with (seeded into the
// agent's ~/.aws/credentials as a profile) so the gateway can tell
// which role a request intends.
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

// SignHTTPRequest is part of the clawpatrol plugin API. It self-dispatches
// on the placeholder access-key-id the agent signed with, then re-signs
// the request with that role's real credentials.
//
// SLICE 1: the real credentials come from the credential's seeded secret
// slots (the `sec` passed in). A later slice sources them per-role from
// the SSO credential cache and passes a per-role runtime.Secret here
// instead — the re-sign call is identical.
func (c *AWSSSOCredential) SignHTTPRequest(ctx context.Context, req *http.Request, sec runtime.Secret, _ any) error {
	akid := sigV4AccessKeyID(req.Header.Get("Authorization"))
	if akid == "" {
		return fmt.Errorf("aws_sso_credential: request carries no SigV4 access-key-id to route on")
	}
	if role := c.roleForPlaceholder(akid); role == nil {
		// Unknown placeholder → no role. Fail closed rather than
		// re-signing under an unintended identity. (Multi-role dispatch
		// and the explicit no-profile-deny semantics land in a later slice.)
		return fmt.Errorf("aws_sso_credential: no role mapping for placeholder access-key-id %q", akid)
	}
	// Re-sign with the (seeded, for now) real creds. reSignProxiedRequest
	// derives service/region from the request and reuses/recomputes the
	// payload hash; it uses no AWSCredential receiver state, so a
	// zero-value receiver is fine and avoids duplicating the logic.
	return (&AWSCredential{}).reSignProxiedRequest(ctx, req, sec)
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

// SecretSlots is part of the clawpatrol plugin API.
//
// SLICE 1: the seeded per-role credentials live in these slots (same slot
// names aws_credential uses, so the shared reSignProxiedRequest reads
// them). A later slice replaces the seeded slots with the SSO token
// material once live sso:GetRoleCredentials lands.
func (*AWSSSOCredential) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{
		{Name: "access_key_id", Label: "Seeded AWS access key ID",
			Description: "Slice-1 seed for re-signing; superseded by SSO-derived per-role creds in a later slice."},
		{Name: "secret_access_key", Label: "Seeded AWS secret access key",
			Description: "Slice-1 seed."},
		{Name: "session_token", Label: "Seeded AWS session token (optional)",
			Description: "Slice-1 seed; present for STS-issued temporary credentials."},
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
