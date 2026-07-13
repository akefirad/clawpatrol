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
// The resulting SSO access token is persisted through the standard
// OAuthRegistry path, exactly like every other OAuth-flow credential (the
// refresh token is deliberately dropped in this cut — see the oauth2.Token
// construction below). The token is delivered as the credential secret to
// whichever credential declares Flow:"aws_sso"; in this design that reader
// is the external AWS SSO plugin (akefirad/clawpatrol-plugin-aws#1), not an
// in-tree credential.

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssooidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"golang.org/x/oauth2"

	"github.com/denoland/clawpatrol/internal/config"
)

// oauthSessionReferencer is implemented by a credential whose OAuth
// session is owned by a *different* credential: instead of running its
// own device login it reuses the owner's persisted token. The only
// implementer today is aws_sso_eks_credential (`session = "<owner>"`),
// so an operator who runs both the plain AWS SSO credential and the EKS
// one logs into AWS SSO once, not twice.
type oauthSessionReferencer interface {
	// OAuthSessionSource returns the bare name of the credential that
	// owns the SSO session to reuse, or "" to run an own login.
	OAuthSessionSource() string
}

// registerSSOSessionAliases wires every session-referencing credential's
// id to the credential that owns its OAuth session, so the secret store
// resolves the borrowed token through OAuthRegistry.Token's alias path.
// Called from registerOAuthCredentials on boot and every policy reload.
// Idempotent and additive, mirroring registerOAuthCredentials: a renamed
// owner leaves a stale alias that harmlessly resolves to no token.
func registerSSOSessionAliases(reg *OAuthRegistry, policy *config.CompiledPolicy) {
	if reg == nil || policy == nil {
		return
	}
	for name, ent := range policy.Credentials {
		ref, ok := ent.Body.(oauthSessionReferencer)
		if !ok {
			continue
		}
		if src := ref.OAuthSessionSource(); src != "" {
			reg.SetAlias(name, src)
		}
	}
}

// isRetryableCreateTokenErr reports whether a CreateToken failure is transient
// rather than terminal: the oauthUpstreamTimeout deadline / a cancel, a network
// error, or AWS InternalServerException (a documented-retryable 5xx). Such a
// blip during the approval window must NOT abort the device login — keep the
// session so the next poll tick recovers, mirroring pollOpenAIDeviceFlow /
// pollDeviceFlow (which return a 5xx and keep the session).
//
// Terminal ssooidc errors (AccessDenied / ExpiredToken / UnauthorizedClient)
// are classified FIRST, before the ctx.Err() transient short-circuit: ctx
// derives from the request, so a browser navigating away mid-poll cancels it,
// and a terminal error arriving on that same tick would otherwise be
// misclassified as transient and leave the dead session lingering until the
// 10-minute GC instead of being deleted immediately. (authorization_pending /
// slow_down are handled by the caller before this and stay transient.)
func isRetryableCreateTokenErr(ctx context.Context, err error) bool {
	var denied *ssooidctypes.AccessDeniedException
	var expired *ssooidctypes.ExpiredTokenException
	var unauthorized *ssooidctypes.UnauthorizedClientException
	if errors.As(err, &denied) || errors.As(err, &expired) || errors.As(err, &unauthorized) {
		return false
	}
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

// awsSSODeviceSession carries the ssooidc fields pollAWSSSODeviceFlow needs
// to complete CreateToken (which has no session of its own). It is
// JSON-encoded into oauthSession.verifier at start and decoded on poll.
// JSON, not a delimiter join: AWS returns an opaque clientSecret/deviceCode
// whose charset is undocumented, and a literal '|' in either would misalign
// a pipe-packed tail (folding the device code / region forward).
type awsSSODeviceSession struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	DeviceCode   string `json:"device_code"`
	Region       string `json:"region"`
}

// startAWSSSODeviceFlow kicks off the ssooidc device flow: dynamically
// register a public client, start device authorization, and return the
// verification URL + user code for the dashboard's device-code UI. The
// client id/secret + device code + region are packed into the session so
// pollAWSSSODeviceFlow can complete the exchange.
//
// startURL + SSO region ride on the OAuth config (AuthURL = the access
// portal start URL; DeviceURL carries the SSO region — set by the
// integration declaring Flow:"aws_sso", i.e. the external plugin), so no
// policy lookup is needed here.
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
		// Log the raw aws-sdk detail server-side; return a generic message to
		// the browser (matches the codebase's don't-surface-raw-detail rule).
		log.Printf("aws_sso register client: %v", err)
		http.Error(rw, "aws_sso: register client failed", http.StatusBadGateway)
		return
	}
	da, err := client.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     reg.ClientId,
		ClientSecret: reg.ClientSecret,
		StartUrl:     aws.String(startURL),
	})
	if err != nil {
		log.Printf("aws_sso start device authorization: %v", err)
		http.Error(rw, "aws_sso: start device authorization failed", http.StatusBadGateway)
		return
	}
	// Defensive (mirrors startOpenAIDeviceFlow rejecting empty fields): a 200
	// with an empty user/device code would otherwise render a blank Connect
	// card and make every poll fail opaquely. AWS populates these on success.
	if aws.ToString(da.UserCode) == "" || aws.ToString(da.DeviceCode) == "" {
		log.Printf("aws_sso start device authorization: empty user/device code in response")
		http.Error(rw, "aws_sso: empty device authorization response", http.StatusBadGateway)
		return
	}

	// Pack the fields pollAWSSSODeviceFlow needs into verifier as JSON.
	sessData, err := json.Marshal(awsSSODeviceSession{
		ClientID:     aws.ToString(reg.ClientId),
		ClientSecret: aws.ToString(reg.ClientSecret),
		DeviceCode:   aws.ToString(da.DeviceCode),
		Region:       region,
	})
	if err != nil {
		log.Printf("aws_sso start: encode session: %v", err)
		http.Error(rw, "aws_sso: encode session failed", http.StatusInternalServerError)
		return
	}

	state := randomString(32)
	w.mu.Lock()
	w.sessions[state] = &oauthSession{
		state:   state,
		id:      id,
		created: time.Now(),
		// pollAWSSSODeviceFlow reads everything it needs from verifier and
		// never dereferences sess.cfg. But sessions are looked up by state
		// alone, so other endpoints (apiOAuthExchange → exchangeOAuthCode →
		// sess.cfg.Endpoint.TokenURL) can reach this session and would panic
		// on a nil cfg. Every other flow stashes a non-nil cfg; keep that
		// invariant with a minimal one so the exchange path degrades to a
		// failed HTTP call instead of a nil-pointer panic.
		cfg:      &oauth2.Config{ClientID: aws.ToString(reg.ClientId)},
		verifier: string(sessData),
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
	var sd awsSSODeviceSession
	if err := json.Unmarshal([]byte(sess.verifier), &sd); err != nil ||
		sd.ClientID == "" || sd.ClientSecret == "" || sd.DeviceCode == "" || sd.Region == "" {
		http.Error(rw, "aws_sso: corrupt session", http.StatusInternalServerError)
		return
	}
	clientID, clientSecret, deviceCode, region := sd.ClientID, sd.ClientSecret, sd.DeviceCode, sd.Region

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
		// Unknown terminal error: log the raw aws-sdk detail server-side, return
		// a generic code to the browser (no raw operation/RequestID/endpoint).
		log.Printf("aws_sso poll: CreateToken failed: %v", err)
		writeJSON(rw, map[string]string{"error": "create_token"})
		return
	}
	if aws.ToString(out.AccessToken) == "" {
		// A success (err==nil) with no access token is an upstream anomaly, not
		// a real pending state — treat as pending (avoid persisting an empty
		// token) but log it, so it doesn't silently spin until code expiry.
		log.Printf("aws_sso poll: CreateToken succeeded with an empty access token (treating as pending)")
		writeJSON(rw, map[string]string{"error": "authorization_pending"})
		return
	}

	tok := &oauth2.Token{
		AccessToken: aws.ToString(out.AccessToken),
		TokenType:   aws.ToString(out.TokenType),
		// Deliberately NOT persisting out.RefreshToken until real SSO-token
		// refresh lands (akefirad/clawpatrol#6). Nothing
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
		// The device code is already consumed, so a successfully-minted SSO
		// token is being lost here — log it (this is the only server-side
		// trace) and return a generic message rather than echoing the raw
		// (possibly DB-driver) error to the browser.
		log.Printf("aws_sso poll: persist token for %q failed: %v", sess.id, err)
		http.Error(rw, "aws_sso: failed to persist token", http.StatusInternalServerError)
		return
	}
	resp := map[string]any{"connected": true}
	// Only report an expiry when there's a real one — a zero tok.Expiry would
	// otherwise serialize as a year-1 epoch. (AWS always returns ExpiresIn; the
	// dashboard reads expires_at from the status endpoint regardless.)
	if !tok.Expiry.IsZero() {
		resp["expires"] = tok.Expiry.Unix()
	}
	writeJSON(rw, resp)
}
