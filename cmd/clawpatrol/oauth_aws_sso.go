package main

// AWS IAM Identity Center (SSO) device-authorization flow.
//
// AWS SSO's device flow is non-RFC-8628: it speaks the ssooidc JSON API
// (RegisterClient → StartDeviceAuthorization → CreateToken) rather than
// form-encoded endpoints, so — like the codex `openai_device` flow — it
// gets its own branch in the gateway's OAuth engine. These two functions
// hold that branch's logic; the only edit to oauth.go itself is the
// two-line dispatch in apiOAuthStart / apiOAuthDevicePoll.
//
// The resulting SSO access token (+ refresh token) is persisted through
// the standard OAuthRegistry path, exactly like every other OAuth-flow
// credential; a later slice reads it back to mint per-role credentials
// via sso:GetRoleCredentials (akefirad/clawpatrol#4).

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssooidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"golang.org/x/oauth2"
)

// isRetryableCreateTokenErr reports whether a CreateToken failure is transient
// rather than terminal: the oauthUpstreamTimeout deadline / a cancel, a network
// error, or AWS InternalServerException (a documented-retryable 5xx). Such a
// blip during the approval window must NOT abort the device login — keep the
// session so the next poll tick recovers, mirroring pollOpenAIDeviceFlow /
// pollDeviceFlow (which return a 5xx and keep the session).
func isRetryableCreateTokenErr(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var ise *ssooidctypes.InternalServerException
	return errors.As(err, &ise)
}

// newSSOOIDCClient builds the ssooidc client for a region. A package var
// so tests can point it at a mock server (ssooidc RegisterClient /
// StartDeviceAuthorization / CreateToken are unauthenticated APIs, so no
// credentials are configured).
var newSSOOIDCClient = func(region string) *ssooidc.Client {
	return ssooidc.New(ssooidc.Options{Region: region})
}

// startAWSSSODeviceFlow kicks off the ssooidc device flow: dynamically
// register a public client, start device authorization, and return the
// verification URL + user code for the dashboard's device-code UI. The
// client id/secret + device code + region are packed into the session so
// pollAWSSSODeviceFlow can complete the exchange.
//
// startURL + SSO region ride on the OAuth config (AuthURL = the access
// portal start URL; DeviceURL carries the SSO region — see the credential's
// OAuthFlow()), so no policy lookup is needed here.
func (w *webMux) startAWSSSODeviceFlow(rw http.ResponseWriter, r *http.Request, id string, it *OAuthIntegration) {
	startURL := it.OAuth.AuthURL
	region := it.OAuth.DeviceURL
	if startURL == "" || region == "" {
		http.Error(rw, "aws_sso: credential is missing start_url / region", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), oauthUpstreamTimeout)
	defer cancel()

	client := newSSOOIDCClient(region)
	// NOTE (akefirad/clawpatrol#6): every Connect registers a fresh OIDC
	// client. Registrations are valid ~90 days and the AWS CLI caches them
	// for exactly this reason; re-registering each time is wasteful but
	// harmless. Caching the registration (client id + secret + expiry, e.g.
	// in the blob store) is deferred INTO the refresh work: refresh needs the
	// persisted client_secret anyway, so both are solved together in #6.
	reg, err := client.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String("clawpatrol"),
		ClientType: aws.String("public"),
	})
	if err != nil {
		http.Error(rw, "aws_sso register client: "+err.Error(), http.StatusBadGateway)
		return
	}
	da, err := client.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     reg.ClientId,
		ClientSecret: reg.ClientSecret,
		StartUrl:     aws.String(startURL),
	})
	if err != nil {
		http.Error(rw, "aws_sso start device authorization: "+err.Error(), http.StatusBadGateway)
		return
	}

	state := randomString(32)
	w.mu.Lock()
	w.sessions[state] = &oauthSession{
		state:   state,
		id:      id,
		created: time.Now(),
		// Pack the fields pollAWSSSODeviceFlow needs (CreateToken has no
		// session of its own) into verifier, mirroring openai_device.
		verifier: strings.Join([]string{
			aws.ToString(reg.ClientId),
			aws.ToString(reg.ClientSecret),
			aws.ToString(da.DeviceCode),
			region,
		}, "|"),
		cfg: &oauth2.Config{ClientID: aws.ToString(reg.ClientId)},
	}
	for k, s := range w.sessions {
		if time.Since(s.created) > 10*time.Minute {
			delete(w.sessions, k)
		}
	}
	w.mu.Unlock()

	verificationURI := aws.ToString(da.VerificationUriComplete)
	if verificationURI == "" {
		verificationURI = aws.ToString(da.VerificationUri)
	}
	interval := da.Interval
	if interval <= 0 {
		interval = 5
	}
	// Tag as plain "device" so the dashboard's ConnectModal renders the
	// user-code UI (it switches on flow === "device"); the aws_sso branch
	// is selected at poll time by the integration's Flow.
	writeJSON(rw, map[string]any{
		"flow":             "device",
		"state":            state,
		"user_code":        aws.ToString(da.UserCode),
		"verification_uri": verificationURI,
		"interval":         interval,
		"expires_in":       da.ExpiresIn,
	})
}

// pollAWSSSODeviceFlow runs one CreateToken poll. authorization_pending /
// slow_down are surfaced to the dashboard's polling loop; success persists
// the SSO access + refresh token through the standard registry path.
func (w *webMux) pollAWSSSODeviceFlow(rw http.ResponseWriter, r *http.Request, sess *oauthSession) {
	parts := strings.SplitN(sess.verifier, "|", 4)
	if len(parts) != 4 {
		http.Error(rw, "aws_sso: corrupt session", http.StatusInternalServerError)
		return
	}
	clientID, clientSecret, deviceCode, region := parts[0], parts[1], parts[2], parts[3]

	ctx, cancel := context.WithTimeout(r.Context(), oauthUpstreamTimeout)
	defer cancel()
	client := newSSOOIDCClient(region)
	out, err := client.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     aws.String(clientID),
		ClientSecret: aws.String(clientSecret),
		GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
		DeviceCode:   aws.String(deviceCode),
	})
	if err != nil {
		// The user hasn't finished the browser approval yet — keep polling.
		var pending *ssooidctypes.AuthorizationPendingException
		if errors.As(err, &pending) {
			writeJSON(rw, map[string]string{"error": "authorization_pending"})
			return
		}
		// Polling too fast — the dashboard should back off.
		var slow *ssooidctypes.SlowDownException
		if errors.As(err, &slow) {
			writeJSON(rw, map[string]string{"error": "slow_down"})
			return
		}
		// Transient failure (ctx deadline, network blip, AWS 5xx): keep the
		// session and return a 5xx so the dashboard's next poll tick recovers,
		// instead of aborting the whole device login on one hiccup during the
		// approval window. Mirrors the sibling device flows.
		if isRetryableCreateTokenErr(ctx, err) {
			log.Printf("aws_sso poll: transient CreateToken error (keeping session): %v", err)
			http.Error(rw, "aws_sso poll: temporary upstream error", http.StatusBadGateway)
			return
		}
		// Everything below is terminal (the dashboard stops polling on any
		// non-pending error). Delete the dead session now rather than letting
		// it linger until the 10-minute GC.
		w.mu.Lock()
		delete(w.sessions, sess.state)
		w.mu.Unlock()
		// Map the known terminal ssooidc errors to the RFC-8628 codes the
		// dashboard expects, mirroring the pending/slow_down handling above:
		// the device code expired, or the user clicked "deny".
		var expired *ssooidctypes.ExpiredTokenException
		if errors.As(err, &expired) {
			writeJSON(rw, map[string]string{"error": "expired_token"})
			return
		}
		var denied *ssooidctypes.AccessDeniedException
		if errors.As(err, &denied) {
			writeJSON(rw, map[string]string{"error": "access_denied"})
			return
		}
		writeJSON(rw, map[string]any{"error": "create_token", "detail": err.Error()})
		return
	}
	if aws.ToString(out.AccessToken) == "" {
		writeJSON(rw, map[string]string{"error": "authorization_pending"})
		return
	}

	tok := &oauth2.Token{
		AccessToken: aws.ToString(out.AccessToken),
		TokenType:   aws.ToString(out.TokenType),
		// Deliberately NOT persisting out.RefreshToken until real SSO-token
		// refresh lands (see the DEFERRED note in aws_sso.go / #6). Nothing
		// can redeem it yet: aws_sso has no setToken refresh branch, so its
		// OAuthConfig.TokenURL is empty. If we stored the refresh token, the
		// oauth2 layer would, on expiry, try to refresh against "" and fail
		// with a cryptic `unsupported protocol scheme ""`. Omitting it makes
		// expiry surface as the clean `token expired and refresh token is not
		// set` — a clear "reconnect AWS SSO" signal. Restore persistence
		// together with the refresh branch when #6 lands.
	}
	if out.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	}

	w.mu.Lock()
	delete(w.sessions, sess.state)
	w.mu.Unlock()
	if err := w.g.oauth.Set(r.Context(), sess.id, tok); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, map[string]any{"connected": true, "expires": tok.Expiry.Unix()})
}
