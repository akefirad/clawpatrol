package credentials

// AWS SSO → temporary SigV4 credentials bridge.
//
// This is the small middle piece the aws_sso_eks_credential needs and
// core did not previously own: turning an SSO access token into
// short-lived role credentials via sso:GetRoleCredentials, cached per
// (account, role). It is a direct in-process port of the sibling
// clawpatrol-plugin-aws minter (internal/awssso/minter.go), minus the
// brokered-dial seam — core is not sandboxed, so the SSO client dials
// the portal directly instead of routing through the gateway.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
)

// ssoRoleExpiryWindow is the refresh margin applied to every cached role
// credential: the aws.CredentialsCache re-mints once the credentials are
// within this window of expiry. Mirrors the sibling plugin's 5-minute
// window so a burst of requests collapses onto a single mint while a
// still-valid-but-nearly-expired credential is refreshed ahead of use.
const ssoRoleExpiryWindow = 5 * time.Minute

// ssoClientFunc builds an SSO client for a region. It is the overridable
// sso-client seam: production defaults it to a direct in-process client,
// tests point it at a mock server.
type ssoClientFunc func(region string) *sso.Client

// newSSOClient is the default sso-client seam: a direct in-process
// client. GetRoleCredentials authenticates with the SSO bearer token
// (carried in the request), not SigV4, so no signing credentials are
// configured.
func newSSOClient(region string) *sso.Client {
	return sso.New(sso.Options{
		Region:      region,
		Credentials: aws.AnonymousCredentials{},
	})
}

// ssoCacheKey identifies one credential cache: temporary credentials are
// minted and cached per target account and role.
type ssoCacheKey struct {
	account string
	role    string
}

// ssoMinter mints and caches temporary role credentials for one SSO
// session (one access token). It holds an aws.CredentialsCache per
// (account, role); each cache single-flights concurrent retrievals and
// refreshes only inside ssoRoleExpiryWindow. Safe for concurrent use.
type ssoMinter struct {
	token        string
	expiryWindow time.Duration
	client       *sso.Client // built once; region is fixed per instance

	mu     sync.Mutex
	caches map[ssoCacheKey]*aws.CredentialsCache
}

// newSSOMinter builds a minter for the SSO portal region and access
// token. newClient is the sso-client seam; nil defaults to the direct
// in-process client. The SSO client is built once: the region is fixed
// for the instance and sso.Client is safe for concurrent reuse.
func newSSOMinter(region, token string, expiryWindow time.Duration, newClient ssoClientFunc) *ssoMinter {
	if newClient == nil {
		newClient = newSSOClient
	}
	return &ssoMinter{
		token:        token,
		expiryWindow: expiryWindow,
		client:       newClient(region),
		caches:       make(map[ssoCacheKey]*aws.CredentialsCache),
	}
}

// credentials returns temporary credentials for (account, role), minting
// via sso:GetRoleCredentials on a cold or expired cache and serving the
// cached value otherwise.
func (m *ssoMinter) credentials(ctx context.Context, account, role string) (aws.Credentials, error) {
	creds, err := m.cacheFor(account, role).Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("mint credentials for %s/%s: %w", account, role, err)
	}
	return creds, nil
}

// cacheFor returns the credential cache for (account, role), creating it
// on first use.
func (m *ssoMinter) cacheFor(account, role string) *aws.CredentialsCache {
	key := ssoCacheKey{account: account, role: role}

	m.mu.Lock()
	defer m.mu.Unlock()

	if cache, ok := m.caches[key]; ok {
		return cache
	}
	cache := aws.NewCredentialsCache(&ssoRoleProvider{
		client:  m.client,
		token:   m.token,
		account: account,
		role:    role,
	}, func(o *aws.CredentialsCacheOptions) {
		o.ExpiryWindow = m.expiryWindow
	})
	m.caches[key] = cache
	return cache
}

// ssoRoleProvider is the aws.CredentialsProvider that mints one role's
// credentials via sso:GetRoleCredentials. The enclosing
// aws.CredentialsCache owns caching, the expiry window, and single-flight
// refresh.
type ssoRoleProvider struct {
	client  *sso.Client
	token   string
	account string
	role    string
}

// Retrieve mints fresh credentials from the SSO portal.
func (p *ssoRoleProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	out, err := p.client.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: aws.String(p.token),
		AccountId:   aws.String(p.account),
		RoleName:    aws.String(p.role),
	})
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("sso GetRoleCredentials: %w", err)
	}
	rc := out.RoleCredentials
	if rc == nil {
		return aws.Credentials{}, errors.New("sso GetRoleCredentials: empty role credentials")
	}
	// Guard a zero/negative expiration rather than caching a permanently
	// expired entry (Expiration is epoch milliseconds).
	if rc.Expiration <= 0 {
		return aws.Credentials{}, fmt.Errorf("sso GetRoleCredentials: non-positive expiration %d", rc.Expiration)
	}
	return aws.Credentials{
		AccessKeyID:     aws.ToString(rc.AccessKeyId),
		SecretAccessKey: aws.ToString(rc.SecretAccessKey),
		SessionToken:    aws.ToString(rc.SessionToken),
		Source:          "aws_sso GetRoleCredentials",
		AccountID:       p.account,
		CanExpire:       true,
		Expires:         time.UnixMilli(rc.Expiration),
	}, nil
}
