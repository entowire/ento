package control

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
)

// OIDCConfig enables SSO: a device logs in with the OAuth 2.0 device authorization grant
// (RFC 8628) and is bound to the user. The user's groups decide approval, admin rights and the
// device's groups, so access follows identity instead of manual approval.
type OIDCConfig struct {
	Issuer        string   // e.g. https://id.example.com/realms/team
	ClientID      string   // confidential client with the device authorization grant enabled
	ClientSecret  string   //
	ConnectTo     []string // optional host:port list dialled instead of the issuer's host (TLS still verifies the issuer name)
	GroupsClaim   string   // ID token claim holding the user's groups (default "groups")
	ApproveGroups []string // users in any of these groups get their devices approved
	AdminGroups   []string // users in any of these groups get admin devices
	// OperatorGroups: users in any of these groups (and not admins) get operator devices, which
	// administer within limits that keep every change reversible (store.Peer.Operator).
	OperatorGroups []string
	// AppRedirects are the addresses apps on devices catch (RFC 8252), registered with the provider
	// for this client: a device starting a sign-in with one of them gets an ordinary sign-in
	// (authorization code with PKCE) that ends in its app, which hands the code back (0.56), so its
	// person types no code. Empty: device sign-ins only.
	AppRedirects []string

	// TokenKey (32 bytes) encrypts the refresh token each sign-in yields, kept in the store so that
	// every RefreshInterval (default 2 minutes) a control node asks the provider, with it, whether
	// the user still has access and with which groups: a refusal (user disabled, deleted or signed
	// out there) ends the device's session at once, changed groups apply at once, an unreachable
	// provider changes nothing. Without a key no token is kept, and access ends only with the
	// session limits (Config.SessionIdle, SessionMax).
	TokenKey        []byte
	RefreshInterval time.Duration
	// Refusals are the token endpoint's answers to a refresh that mean the user's access is
	// withdrawn (default DefaultRefusals: RFC 6749's invalid_grant). Providers that answer
	// otherwise are named here, e.g. Rauthy: 401 Disabled (user disabled), 404 NotFound (user
	// deleted, or the token unknown). Every other failure counts as the provider failing, which never
	// cuts access: a wrong client secret must not sign everyone out.
	Refusals []Refusal
}

// Refusal is one answer of the token endpoint that withdraws access: an HTTP status and the
// "error" field of its JSON body.
type Refusal struct {
	Status int
	Error  string
}

// DefaultRefusals is what RFC 6749 (5.2) prescribes for a refresh token that is no longer valid.
var DefaultRefusals = []Refusal{{Status: http.StatusBadRequest, Error: "invalid_grant"}}

// ParseRefusals reads a comma-separated list of STATUS:ERROR (e.g. "400:invalid_grant,401:Disabled").
func ParseRefusals(s string) ([]Refusal, error) {
	var out []Refusal
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		status, errName, ok := strings.Cut(part, ":")
		code, err := strconv.Atoi(status)
		if !ok || err != nil || code < 400 || code > 499 || errName == "" {
			return nil, fmt.Errorf("refusal %q: want STATUS:ERROR with a 4xx status, e.g. 400:invalid_grant", part)
		}
		out = append(out, Refusal{Status: code, Error: errName})
	}
	if len(out) == 0 {
		return nil, errors.New("no refusals given")
	}
	return out, nil
}

// refused reports whether a token endpoint answer withdraws the user's access.
func (c OIDCConfig) refused(status int, errName string) bool {
	refusals := c.Refusals
	if len(refusals) == 0 {
		refusals = DefaultRefusals
	}
	for _, r := range refusals {
		if r.Status == status && r.Error == errName {
			return true
		}
	}
	return false
}

// oidcProvider performs device logins against the identity provider.
type oidcProvider struct {
	cfg    OIDCConfig
	client *http.Client

	keys      jwksCache // the provider's signing keys (oidc_jwt.go)
	mu        sync.Mutex
	discovery *oidcDiscovery
	logins    map[int64]*deviceLogin // by peer ID
}

type oidcDiscovery struct {
	Issuer                      string   `json:"issuer"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	JWKSURI                     string   `json:"jwks_uri"`
	TokenEndpoint               string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	ScopesSupported             []string `json:"scopes_supported"`
}

// scopes asks for an offline refresh token where the provider offers one and tokens are kept: it is
// bound to the user rather than to their browser session, so signing out of another application in
// the browser does not end the VPN, while disabling or deleting the user still does. (Providers
// without the scope, such as Google, issue refresh tokens all the same.)
//
// The groups claim's scope is asked for too where the provider lists it (Rauthy: "groups"): some
// providers put the claim in tokens only when its scope was requested, and without it the person's
// groups never arrive (0.38.3). offline_access stays last: a provider refusing it is asked again
// without it.
func (o *oidcProvider) scopes(d *oidcDiscovery) string {
	scope := "openid profile email"
	if claim := o.cfg.GroupsClaim; claim != "" && slices.Contains(d.ScopesSupported, claim) && !slices.Contains([]string{"openid", "profile", "email", "offline_access"}, claim) {
		scope += " " + claim
	}
	if len(o.cfg.TokenKey) > 0 && slices.Contains(d.ScopesSupported, "offline_access") {
		scope += " offline_access"
	}
	return scope
}

type deviceLogin struct {
	state   string // pending, done, failed
	user    string
	errMsg  string
	expires time.Time

	// A sign-in for an app (startApp): what finishApp checks and sends to the token endpoint. The
	// verifier and the nonce never leave the control node.
	app      bool
	oauth    string // the state sent to the provider
	verifier string
	nonce    string
	redirect string
}

// appLoginLifetime: how long a sign-in for an app waits for its code.
const appLoginLifetime = 10 * time.Minute

func newOIDCProvider(cfg OIDCConfig) *oidcProvider {
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if len(cfg.ConnectTo) == 0 {
				return dialer.DialContext(ctx, network, addr)
			}
			var lastErr error
			for _, target := range cfg.ConnectTo {
				c, err := dialer.DialContext(ctx, network, target)
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
	return &oidcProvider{cfg: cfg, client: &http.Client{Timeout: 15 * time.Second, Transport: transport},
		logins: map[int64]*deviceLogin{}}
}

func (o *oidcProvider) discover(ctx context.Context) (*oidcDiscovery, error) {
	o.mu.Lock()
	d := o.discovery
	o.mu.Unlock()
	if d != nil {
		return d, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(o.cfg.Issuer, "/")+"/.well-known/openid-configuration", nil)
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery: HTTP %d", resp.StatusCode)
	}
	d = &oidcDiscovery{}
	if err := json.NewDecoder(resp.Body).Decode(d); err != nil {
		return nil, err
	}
	if d.Issuer != o.cfg.Issuer || d.TokenEndpoint == "" || d.DeviceAuthorizationEndpoint == "" {
		return nil, errors.New("oidc discovery: issuer mismatch or no device authorization support")
	}
	o.mu.Lock()
	o.discovery = d
	o.mu.Unlock()
	return d, nil
}

func (o *oidcProvider) postForm(ctx context.Context, endpoint string, form url.Values, out any) (int, error) {
	form.Set("client_id", o.cfg.ClientID)
	form.Set("client_secret", o.cfg.ClientSecret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := o.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
}

// start begins a device login for a peer and polls the token endpoint in the background.
func (o *oidcProvider) start(ctx context.Context, peerID int64, onDone func(claims idClaims, refreshToken string)) (api.LoginStart, error) {
	d, err := o.discover(ctx)
	if err != nil {
		return api.LoginStart{}, err
	}
	var auth struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
		Error                   string `json:"error"`
	}
	scope := o.scopes(d)
	code, err := o.postForm(ctx, d.DeviceAuthorizationEndpoint, url.Values{"scope": {scope}}, &auth)
	if err == nil && code == http.StatusBadRequest && auth.Error == "invalid_scope" && strings.HasSuffix(scope, " offline_access") {
		// The provider offers offline tokens, but not to this client: an ordinary refresh token,
		// which may end with the user's browser session there.
		code, err = o.postForm(ctx, d.DeviceAuthorizationEndpoint, url.Values{"scope": {strings.TrimSuffix(scope, " offline_access")}}, &auth)
	}
	if err != nil {
		return api.LoginStart{}, err
	}
	if code != http.StatusOK || auth.DeviceCode == "" {
		return api.LoginStart{}, fmt.Errorf("device authorization refused: HTTP %d %s", code, auth.Error)
	}
	if auth.Interval <= 0 {
		auth.Interval = 5
	}
	login := &deviceLogin{state: "pending", expires: time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second)}
	o.mu.Lock()
	o.logins[peerID] = login
	o.mu.Unlock()
	go o.poll(d, peerID, login, auth.DeviceCode, time.Duration(auth.Interval)*time.Second, onDone)
	// The link with the code in it is not passed on (0.50, I3): it lets anyone who has a device send
	// a person a link that signs that device in as them. The person types the code their device
	// shows, which proves the device is in front of them.
	return api.LoginStart{VerificationURI: auth.VerificationURI,
		UserCode: auth.UserCode, ExpiresIn: auth.ExpiresIn}, nil
}

// startApp begins a sign-in for an app on the device (OIDCConfig.AppRedirects): an ordinary sign-in
// with the provider (authorization code, PKCE, a nonce) whose result goes to redirect, the app's
// own address. Only this device can finish it (finishApp): the state is bound to it, and the code
// is worth nothing without the verifier, which stays here. A link sent to someone else ends in
// their own app, whose device did not start it: refused. loginHint names the person who was
// signed in on the device, if anyone.
func (o *oidcProvider) startApp(ctx context.Context, peerID int64, redirect, loginHint string) (api.LoginStart, error) {
	d, err := o.discover(ctx)
	if err != nil {
		return api.LoginStart{}, err
	}
	if d.AuthorizationEndpoint == "" {
		return api.LoginStart{}, errors.New("the identity provider names no authorization endpoint")
	}
	login := &deviceLogin{state: "pending", expires: time.Now().Add(appLoginLifetime), app: true,
		oauth: uiRandom(), verifier: uiRandom(), nonce: uiRandom(), redirect: redirect}
	sum := sha256.Sum256([]byte(login.verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {o.cfg.ClientID}, "redirect_uri": {redirect},
		"scope": {o.scopes(d)}, "state": {login.oauth}, "nonce": {login.nonce},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	if loginHint != "" {
		q.Set("login_hint", loginHint)
	}
	sep := "?"
	if strings.Contains(d.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	o.mu.Lock()
	o.logins[peerID] = login // a new start ends any sign-in of this device in progress
	o.mu.Unlock()
	return api.LoginStart{AuthorizationURL: d.AuthorizationEndpoint + sep + q.Encode(),
		ExpiresIn: int(appLoginLifetime / time.Second)}, nil
}

// appRedirect reports whether redirect is an app's address this control node may send sign-ins to.
func (o *oidcProvider) appRedirect(redirect string) bool {
	return redirect != "" && slices.Contains(o.cfg.AppRedirects, redirect)
}

// errAppLogin is a code the device cannot use: no sign-in for an app of its own in progress, or not
// that one (the state differs), or expired. Nothing is sent to the provider.
var errAppLogin = errors.New("no sign-in of this device is waiting for this code: start the sign-in again")

// finishApp completes the device's sign-in for an app with what the provider sent the app: the
// code is exchanged (with the verifier) only when the state is the one this device's sign-in sent;
// the ID token must carry its nonce. It succeeds once: the sign-in is over either way.
func (o *oidcProvider) finishApp(ctx context.Context, peerID int64, req api.LoginCodeRequest, onDone func(idClaims, string)) (deviceLogin, error) {
	o.mu.Lock()
	login := o.logins[peerID]
	ok := login != nil && login.app && login.state == "pending" && time.Now().Before(login.expires) &&
		subtle.ConstantTimeCompare([]byte(req.State), []byte(login.oauth)) == 1
	if ok {
		login.state = "exchanging" // a second code for it is refused while this one is used
	}
	o.mu.Unlock()
	if !ok {
		return deviceLogin{}, errAppLogin
	}
	finish := func(state, user, msg string) deviceLogin {
		o.mu.Lock()
		defer o.mu.Unlock()
		login.state, login.user, login.errMsg = state, user, msg
		login.verifier, login.nonce = "", ""
		return *login
	}
	if req.Error != "" {
		return finish("failed", "", "the identity provider refused: "+req.Error), nil
	}
	d, err := o.discover(ctx)
	if err != nil {
		return finish("failed", "", err.Error()), nil
	}
	var tok struct {
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		Error        string `json:"error"`
	}
	code, err := o.postForm(ctx, d.TokenEndpoint, url.Values{"grant_type": {"authorization_code"},
		"code": {req.Code}, "redirect_uri": {login.redirect}, "code_verifier": {login.verifier}}, &tok)
	if err != nil || code != http.StatusOK || tok.IDToken == "" {
		return finish("failed", "", fmt.Sprintf("login refused: HTTP %d %s", code, tok.Error)), nil
	}
	claims, err := o.verifyIDToken(ctx, tok.IDToken, login.nonce)
	if err != nil {
		return finish("failed", "", "invalid ID token: "+err.Error()), nil
	}
	onDone(claims, tok.RefreshToken)
	return finish("done", claims.name(), ""), nil
}

func (o *oidcProvider) poll(d *oidcDiscovery, peerID int64, login *deviceLogin, deviceCode string, interval time.Duration, onDone func(idClaims, string)) {
	finish := func(state, user, msg string) {
		o.mu.Lock()
		login.state, login.user, login.errMsg = state, user, msg
		o.mu.Unlock()
	}
	for time.Now().Before(login.expires) {
		time.Sleep(interval)
		o.mu.Lock()
		superseded := o.logins[peerID] != login
		o.mu.Unlock()
		if superseded {
			return
		}
		var tok struct {
			IDToken      string `json:"id_token"`
			RefreshToken string `json:"refresh_token"`
			Error        string `json:"error"`
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		code, err := o.postForm(ctx, d.TokenEndpoint, url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceCode},
		}, &tok)
		cancel()
		switch {
		case err != nil:
			continue // transient; try again
		case tok.Error == "authorization_pending":
			continue
		case tok.Error == "slow_down":
			interval += 5 * time.Second
			continue
		case code != http.StatusOK || tok.IDToken == "":
			finish("failed", "", "login refused: "+tok.Error)
			return
		}
		// Verified against the provider's keys, although it came straight from the token endpoint
		// (0.50: TLS alone stood in for the signature before).
		vctx, vcancel := context.WithTimeout(context.Background(), 15*time.Second)
		claims, err := o.verifyIDToken(vctx, tok.IDToken, "")
		vcancel()
		if err != nil {
			finish("failed", "", "invalid ID token: "+err.Error())
			return
		}
		onDone(claims, tok.RefreshToken)
		finish("done", claims.name(), "")
		return
	}
	finish("failed", "", "login expired")
}

func (o *oidcProvider) status(peerID int64) (deviceLogin, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	l, ok := o.logins[peerID]
	if !ok {
		return deviceLogin{}, false
	}
	out := *l
	if out.state == "exchanging" {
		out.state = "pending" // the app's code is being exchanged
	}
	out.verifier, out.nonce, out.oauth = "", "", ""
	return out, true
}

// idClaims is the part of an ID token ento uses.
type idClaims struct {
	Issuer            string          `json:"iss"`
	Subject           string          `json:"sub"`
	Audience          json.RawMessage `json:"aud"`
	Email             string          `json:"email"`
	PreferredUsername string          `json:"preferred_username"`
	raw               map[string]json.RawMessage
}

func (c idClaims) name() string {
	if c.Email != "" {
		return c.Email
	}
	if c.PreferredUsername != "" {
		return c.PreferredUsername
	}
	return c.Subject
}

func (c idClaims) hasAudience(clientID string) bool {
	var one string
	if json.Unmarshal(c.Audience, &one) == nil {
		return one == clientID
	}
	var many []string
	return json.Unmarshal(c.Audience, &many) == nil && slices.Contains(many, clientID)
}

// groups returns the groups claim, without the leading "/" some providers add to group paths.
func (c idClaims) groups(claim string) []string {
	var gs []string
	if err := json.Unmarshal(c.raw[claim], &gs); err != nil {
		return nil
	}
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		if g = strings.TrimPrefix(g, "/"); g != "" {
			out = append(out, g)
		}
	}
	return out
}

func parseIDToken(tok string) (idClaims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return idClaims{}, errors.New("malformed ID token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return idClaims{}, err
	}
	var c idClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return idClaims{}, err
	}
	if err := json.Unmarshal(payload, &c.raw); err != nil {
		return idClaims{}, err
	}
	return c, nil
}

// access is what a user's groups give their devices.
type access struct {
	approved, admin, operator bool
	groups                    []string
}

func accessOf(cfg OIDCConfig, c idClaims) access {
	groups := c.groups(cfg.GroupsClaim)
	in := func(list []string) bool {
		for _, g := range groups {
			if slices.Contains(list, g) {
				return true
			}
		}
		return false
	}
	a := access{admin: in(cfg.AdminGroups), groups: groups}
	a.operator = !a.admin && in(cfg.OperatorGroups)
	a.approved = a.admin || a.operator || in(cfg.ApproveGroups)
	return a
}

// same reports whether a device's person layer already has this access (groups in any order).
func (a access) same(p store.Peer) bool {
	sorted := func(gs []string) []string { gs = slices.Clone(gs); slices.Sort(gs); return gs }
	pl := p.Person
	return a.approved == pl.Approved && a.admin == pl.Admin && a.operator == pl.Operator &&
		slices.Equal(sorted(a.groups), sorted(pl.Groups))
}

// update is the change of a device's person layer to this access.
func (a access) update() store.PeerUpdate {
	return store.PeerUpdate{PersonApproved: &a.approved, PersonAdmin: &a.admin, PersonOperator: &a.operator, PersonGroups: &a.groups}
}

// applyLogin binds a peer to the person who signed in on it and opens its person layer with the
// rights of their groups; its machine layer stays as it is.
func applyLogin(ctx context.Context, st store.Store, cfg OIDCConfig, peerID int64, c idClaims) (store.Peer, error) {
	a := accessOf(cfg, c)
	user, name, login := c.Subject, c.name(), c.PreferredUsername
	now, on := time.Now(), true
	u := a.update()
	u.User, u.UserName, u.UserLogin, u.LoginAt = &user, &name, &login, &now
	u.PersonActive, u.PersonSince, u.PersonActivityAt = &on, &now, &now
	return st.UpdatePeer(ctx, peerID, u)
}

// withdrawnError: the identity provider refused a device's refresh token (the user was disabled,
// deleted or signed out there, or their session ended).
type withdrawnError struct{ reason string }

func (e *withdrawnError) Error() string { return "refused by the identity provider: " + e.reason }

// refresh asks the identity provider for fresh tokens with a device's refresh token. It returns the
// new ID token's claims (nil when the provider sent none), and the refresh token to keep (empty:
// keep the old one). A refusal is a *withdrawnError; anything else that fails (unreachable, an error
// of the provider, an unexpected answer) is an ordinary error, which must never cut access.
func (o *oidcProvider) refresh(ctx context.Context, refreshToken string) (*idClaims, string, error) {
	d, err := o.discover(ctx)
	if err != nil {
		return nil, "", err
	}
	var tok struct {
		IDToken          string `json:"id_token"`
		RefreshToken     string `json:"refresh_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		Message          string `json:"message"` // Rauthy's description
	}
	code, err := o.postForm(ctx, d.TokenEndpoint, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}, &tok)
	switch {
	case err != nil:
		return nil, "", fmt.Errorf("token endpoint: %w", err)
	case code != http.StatusOK && o.cfg.refused(code, tok.Error):
		reason := tok.ErrorDescription
		if reason == "" {
			reason = tok.Message
		}
		if reason == "" {
			reason = tok.Error
		}
		return nil, "", &withdrawnError{reason: reason}
	case code != http.StatusOK:
		return nil, "", fmt.Errorf("token endpoint: %s", strings.TrimSpace(fmt.Sprintf("HTTP %d %s", code, tok.Error)))
	}
	if tok.IDToken == "" {
		return nil, tok.RefreshToken, nil
	}
	// Verified as at sign-in. One that fails is an ordinary error: it changes nothing (a withdrawal
	// comes as a refusal, which needs no token).
	c, err := o.verifyIDToken(ctx, tok.IDToken, "")
	if err != nil {
		return nil, "", fmt.Errorf("token endpoint: invalid ID token: %w", err)
	}
	// Some providers put the groups only into the first ID token: without the claim the groups are
	// unknown (an empty list would mean the user left them all).
	if _, ok := c.raw[o.cfg.GroupsClaim]; !ok {
		return nil, tok.RefreshToken, nil
	}
	return &c, tok.RefreshToken, nil
}
