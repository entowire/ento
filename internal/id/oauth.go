package id

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"entowire.com/ento/internal/store"
)

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// authRequest is an authorization request waiting for the person's passkey.
type authRequest struct {
	Client    string `json:"client"`
	Redirect  string `json:"redirect"`
	State     string `json:"state"`
	Nonce     string `json:"nonce"`
	Challenge string `json:"challenge"`
	Scope     string `json:"scope"`
}

// codeGrant is what an authorization code stands for.
type codeGrant struct {
	Client    string    `json:"client"`
	Redirect  string    `json:"redirect"`
	Nonce     string    `json:"nonce"`
	Challenge string    `json:"challenge"`
	Scope     string    `json:"scope"`
	Person    string    `json:"person"`
	AuthTime  time.Time `json:"auth_time"`
	Method    string    `json:"method"`
}

// deviceGrant is a device authorization (RFC 8628) under way.
type deviceGrant struct {
	Client   string    `json:"client"`
	Scope    string    `json:"scope"`
	UserCode string    `json:"user_code"`
	Status   string    `json:"status"` // pending, approved or denied
	Person   string    `json:"person,omitempty"`
	AuthTime time.Time `json:"auth_time,omitzero"`
	Method   string    `json:"method,omitempty"`
}

// userCodeRef leads from a user code to its device grant.
type userCodeRef struct {
	Device string `json:"device"` // the device grant's key
}

// confirmation is a device code that came in a link, signed in for, waiting for the person's answer.
type confirmation struct {
	UserCode string    `json:"user_code"`
	Person   string    `json:"person"`
	AuthTime time.Time `json:"auth_time"`
	Method   string    `json:"method"`
}

// refreshGrant is what a refresh token stands for: the person's sign-in for a client.
type refreshGrant struct {
	Client   string    `json:"client"`
	Scope    string    `json:"scope"`
	Person   string    `json:"person"`
	AuthTime time.Time `json:"auth_time"`
	Method   string    `json:"method"`
}

// accessGrant is what an access token stands for (userinfo).
type accessGrant struct {
	Client string `json:"client"`
	Scope  string `json:"scope"`
	Person string `json:"person"`
}

// checkAuthRequest checks an authorization request. Without a known client and redirect address
// (known false) nothing may be sent back; otherwise a failure is an OAuth error (code, description)
// for the redirect address.
func (p *Provider) checkAuthRequest(q url.Values) (req authRequest, c Client, known bool, code, desc string) {
	c, ok := p.client(q.Get("client_id"))
	redirect := q.Get("redirect_uri")
	if !ok || !slices.Contains(c.RedirectURIs, redirect) {
		return req, c, false, "", ""
	}
	req = authRequest{Client: c.ID, Redirect: redirect, State: q.Get("state"), Nonce: q.Get("nonce"),
		Challenge: q.Get("code_challenge"), Scope: q.Get("scope")}
	switch {
	case q.Get("response_type") != "code":
		return req, c, true, "unsupported_response_type", "code only"
	case !slices.Contains(strings.Fields(q.Get("scope")), "openid"):
		return req, c, true, "invalid_scope", "openid is required"
	case q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) < 43 || len(q.Get("code_challenge")) > 128:
		return req, c, true, "invalid_request", "PKCE with S256 is required"
	case len(q.Get("nonce")) > 512 || len(q.Get("state")) > 2048 || len(q.Get("scope")) > 512:
		return req, c, true, "invalid_request", "nonce, state or scope too long"
	case slices.Contains(strings.Fields(q.Get("prompt")), "none"):
		// The provider keeps no session: every sign-in takes the person's way in.
		return req, c, true, "login_required", "a sign-in is required"
	}
	return req, c, true, "", ""
}

// errorRedirect is where an authorization request that failed sends the browser back to.
func (p *Provider) errorRedirect(req authRequest, code, desc string) string {
	v := url.Values{"error": {code}, "error_description": {desc}, "iss": {p.Issuer()}}
	if req.State != "" {
		v.Set("state", req.State)
	}
	return withQuery(req.Redirect, v)
}

// authorize is the authorization endpoint: it checks the request and shows the sign-in page.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req, c, known, code, desc := p.checkAuthRequest(q)
	// Nothing is sent to an address that is not the client's: errors before this point are shown.
	if !known {
		p.audit(r, "id_authorize", "client "+q.Get("client_id")+": unknown client or redirect URI", "denied")
		p.page(w, http.StatusBadRequest, pageData{Mode: "error", Message: "This sign-in comes from an unknown application or goes to an unknown address."})
		return
	}
	if code != "" {
		http.Redirect(w, r, p.errorRedirect(req, code, desc), http.StatusFound)
		return
	}
	id := secret(24)
	if err := p.putState(r.Context(), "request:"+id, kindRequest, "", req, requestLifetime); err != nil {
		p.cfg.Logf("identity provider: authorization request: %v", err)
		http.Redirect(w, r, p.errorRedirect(req, "temporarily_unavailable", "store unavailable"), http.StatusFound)
		return
	}
	p.page(w, http.StatusOK, pageData{Mode: "authorize", Request: id, Client: c.name()})
}

// codeFor answers an authorization request for a person who signed in with method: the address the
// browser goes back to, with a code.
func (p *Provider) codeFor(r *http.Request, req authRequest, person store.IDPerson, method string) (string, error) {
	code := secret(32)
	cg := codeGrant{Client: req.Client, Redirect: req.Redirect, Nonce: req.Nonce, Challenge: req.Challenge, Scope: req.Scope,
		Person: person.ID, AuthTime: p.cfg.Now(), Method: method}
	if err := p.putState(r.Context(), "code:"+hash("code", code), kindCode, person.ID, cg, codeLifetime); err != nil {
		return "", err
	}
	p.audit(r, "id_signin", person.Email+" client="+req.Client+" with "+method, "ok")
	v := url.Values{"code": {code}, "iss": {p.Issuer()}}
	if req.State != "" {
		v.Set("state", req.State)
	}
	return withQuery(req.Redirect, v), nil
}

// finishAuthorize sends the browser back to the client with a code for the person.
func (p *Provider) finishAuthorize(w http.ResponseWriter, r *http.Request, g goal, person store.IDPerson, method string) {
	var req authRequest
	if _, err := p.getState(r.Context(), "request:"+g.Request, true, &req); err != nil {
		fail(w, http.StatusGone, "This sign-in has expired. Go back to the application and start again.")
		return
	}
	to, err := p.codeFor(r, req, person, method)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "The sign-in could not finish. Try again in a moment.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": to})
}

func withQuery(u string, v url.Values) string {
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return u + sep + v.Encode()
}

// userCodeAlphabet has no vowels (no words) and no easily confused letters (RFC 8628 6.1).
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

func newUserCode() string {
	out := make([]byte, 0, 9)
	for len(out) < 9 {
		if len(out) == 4 {
			out = append(out, '-')
			continue
		}
		// 240 is the largest multiple of 20 below 256: bytes from it on are drawn again, so that
		// every letter is as likely.
		if b := randomBytes(1)[0]; b < 240 {
			out = append(out, userCodeAlphabet[int(b)%len(userCodeAlphabet)])
		}
	}
	return string(out)
}

// normalizeUserCode accepts a code as people type it: any case, with or without the dash or spaces.
func normalizeUserCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if strings.ContainsRune(userCodeAlphabet, r) {
			b.WriteRune(r)
		}
	}
	c := b.String()
	if len(c) != 8 {
		return c
	}
	return c[:4] + "-" + c[4:]
}

// deviceAuthorization is the device authorization endpoint (RFC 8628 3.1).
func (p *Provider) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "form")
		return
	}
	c, ok := p.authClient(r)
	if !ok {
		p.audit(r, "id_device", "client authentication failed", "denied")
		w.Header().Set("WWW-Authenticate", `Basic realm="ento id"`)
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if !c.DeviceGrant {
		tokenError(w, http.StatusBadRequest, "unauthorized_client", "the device grant is not enabled for this client")
		return
	}
	scope := r.PostForm.Get("scope")
	if len(scope) > 512 {
		tokenError(w, http.StatusBadRequest, "invalid_scope", "scope too long")
		return
	}
	deviceCode := secret(32)
	key := "device:" + hash("device", deviceCode)
	var code string
	for range 5 {
		code = newUserCode()
		if _, err := p.cfg.Store.IDState(r.Context(), "user:"+code, p.cfg.Now()); errors.Is(err, store.ErrNotFound) {
			break
		}
	}
	d := deviceGrant{Client: c.ID, Scope: scope, UserCode: code, Status: "pending"}
	if err := p.putState(r.Context(), key, kindDevice, "", d, deviceLifetime); err != nil {
		tokenError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "store unavailable")
		return
	}
	if err := p.putState(r.Context(), "user:"+code, kindDevice, "", userCodeRef{Device: key}, deviceLifetime); err != nil {
		tokenError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "store unavailable")
		return
	}
	verify := p.Issuer() + "/device"
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code": deviceCode, "user_code": code,
		"verification_uri": verify, "verification_uri_complete": verify + "?" + url.Values{"user_code": {code}}.Encode(),
		"expires_in": int(deviceLifetime / time.Second), "interval": int(devicePoll / time.Second),
	})
}

// deviceByUserCode returns a device grant, its key and its record, from its user code.
func (p *Provider) deviceByUserCode(r *http.Request, code string) (deviceGrant, store.IDState, error) {
	var ref userCodeRef
	if _, err := p.getState(r.Context(), "user:"+code, false, &ref); err != nil {
		return deviceGrant{}, store.IDState{}, err
	}
	var d deviceGrant
	s, err := p.getState(r.Context(), ref.Device, false, &d)
	return d, s, err
}

// answerDevice approves or denies a pending device grant.
func (p *Provider) answerDevice(r *http.Request, code string, person store.IDPerson, authTime time.Time, method string, approve bool) error {
	d, s, err := p.deviceByUserCode(r, code)
	if err != nil {
		return err
	}
	if d.Status != "pending" {
		return store.ErrNotFound
	}
	d.Status, d.Person, d.AuthTime, d.Method = "denied", person.ID, authTime, method
	if approve {
		d.Status = "approved"
	}
	return p.putState(r.Context(), s.Key, kindDevice, person.ID, d, s.ExpiresAt.Sub(p.cfg.Now()))
}

// finishDevice approves a typed code at once; a code that came in a link waits for the person to
// accept it, so that a link someone else sent cannot sign a device in without them seeing it.
func (p *Provider) finishDevice(w http.ResponseWriter, r *http.Request, c goal, person store.IDPerson, method string) {
	d, _, err := p.deviceByUserCode(r, c.UserCode)
	if err != nil || d.Status != "pending" {
		fail(w, http.StatusGone, "This code has expired or was already used. Start the sign-in on the device again.")
		return
	}
	cl, _ := p.client(d.Client)
	now := p.cfg.Now()
	if c.FromLink {
		id := secret(24)
		if err := p.putState(r.Context(), "confirm:"+id, kindConfirm, person.ID, confirmation{UserCode: c.UserCode, Person: person.ID, AuthTime: now, Method: method}, confirmLifetime); err != nil {
			fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"confirm": id, "client": cl.name(), "person": personName(person)})
		return
	}
	if err := p.answerDevice(r, c.UserCode, person, now, method, true); err != nil {
		fail(w, http.StatusGone, "This code has expired or was already used. Start the sign-in on the device again.")
		return
	}
	p.audit(r, "id_device", person.Email+" client="+d.Client+" code typed, with "+method, "ok")
	writeJSON(w, http.StatusOK, map[string]string{"done": "approved", "client": cl.name(), "person": personName(person)})
}

// deviceAnswer takes the person's answer to a device code that came in a link.
func (p *Provider) deviceAnswer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Confirm string `json:"confirm"`
		Accept  bool   `json:"accept"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	var c confirmation
	if _, err := p.getState(r.Context(), "confirm:"+in.Confirm, true, &c); err != nil {
		fail(w, http.StatusGone, "This request has expired. Start the sign-in on the device again.")
		return
	}
	person, err := p.cfg.Store.IDPerson(r.Context(), c.Person)
	if err != nil || person.Disabled {
		fail(w, http.StatusForbidden, "This account cannot sign in.")
		return
	}
	if err := p.answerDevice(r, c.UserCode, person, c.AuthTime, c.Method, in.Accept); err != nil {
		fail(w, http.StatusGone, "This code has expired or was already used. Start the sign-in on the device again.")
		return
	}
	result, done := "ok", "approved"
	if !in.Accept {
		result, done = "denied", "declined"
	}
	p.audit(r, "id_device", person.Email+" code from a link: "+done, result)
	writeJSON(w, http.StatusOK, map[string]string{"done": done})
}

func tokenError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// token is the token endpoint.
func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "form")
		return
	}
	c, ok := p.authClient(r)
	if !ok {
		p.audit(r, "id_token", "client authentication failed", "denied")
		w.Header().Set("WWW-Authenticate", `Basic realm="ento id"`)
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		p.tokenCode(w, r, c)
	case "refresh_token":
		p.tokenRefresh(w, r, c)
	case deviceGrantType:
		if !c.DeviceGrant {
			tokenError(w, http.StatusBadRequest, "unauthorized_client", "the device grant is not enabled for this client")
			return
		}
		p.tokenDevice(w, r, c)
	default:
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "authorization_code, refresh_token or "+deviceGrantType)
	}
}

func (p *Provider) tokenCode(w http.ResponseWriter, r *http.Request, c Client) {
	var g codeGrant
	if _, err := p.getState(r.Context(), "code:"+hash("code", r.PostForm.Get("code")), true, &g); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			p.audit(r, "id_token", "client "+c.ID+": unknown, expired or used code", "denied")
			tokenError(w, http.StatusBadRequest, "invalid_grant", "unknown, expired or used code")
			return
		}
		tokenError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "store unavailable")
		return
	}
	verifier := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if g.Client != c.ID || g.Redirect != r.PostForm.Get("redirect_uri") ||
		subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(verifier[:])), []byte(g.Challenge)) != 1 {
		p.audit(r, "id_token", "client "+c.ID+": client, redirect URI or PKCE verifier does not match the code", "denied")
		tokenError(w, http.StatusBadRequest, "invalid_grant", "client, redirect URI or code verifier does not match")
		return
	}
	p.issue(w, r, c, refreshGrant{Client: c.ID, Scope: g.Scope, Person: g.Person, AuthTime: g.AuthTime, Method: g.Method}, g.Nonce, "")
}

func (p *Provider) tokenDevice(w http.ResponseWriter, r *http.Request, c Client) {
	key := "device:" + hash("device", r.PostForm.Get("device_code"))
	var d deviceGrant
	if _, err := p.getState(r.Context(), key, false, &d); err != nil || d.Client != c.ID {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			tokenError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "store unavailable")
			return
		}
		tokenError(w, http.StatusBadRequest, "expired_token", "unknown or expired device code")
		return
	}
	switch d.Status {
	case "pending":
		tokenError(w, http.StatusBadRequest, "authorization_pending", "waiting for the person")
		return
	case "denied":
		p.cfg.Store.TakeIDState(r.Context(), key, p.cfg.Now())
		tokenError(w, http.StatusBadRequest, "access_denied", "the person declined")
		return
	}
	// Approved: the code is used once.
	if _, err := p.cfg.Store.TakeIDState(r.Context(), key, p.cfg.Now()); err != nil {
		tokenError(w, http.StatusBadRequest, "expired_token", "unknown or expired device code")
		return
	}
	p.issue(w, r, c, refreshGrant{Client: c.ID, Scope: d.Scope, Person: d.Person, AuthTime: d.AuthTime, Method: d.Method}, "", "")
}

// tokenRefresh answers a refresh: refused once the person is disabled or deleted. The refresh token
// stays the same (no rotation, so a lost answer never signs anyone out) and lasts refreshLifetime
// from its last use.
func (p *Provider) tokenRefresh(w http.ResponseWriter, r *http.Request, c Client) {
	tok := r.PostForm.Get("refresh_token")
	key := "refresh:" + hash("refresh", tok)
	var g refreshGrant
	if _, err := p.getState(r.Context(), key, false, &g); err != nil || g.Client != c.ID {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			tokenError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "store unavailable")
			return
		}
		tokenError(w, http.StatusBadRequest, "invalid_grant", "unknown or expired refresh token")
		return
	}
	p.issue(w, r, c, g, "", tok)
}

// issue answers the token endpoint with tokens for a person who may still sign in: an ID token, an
// access token and, unless refreshing one, a refresh token (refreshing extends it).
func (p *Provider) issue(w http.ResponseWriter, r *http.Request, c Client, g refreshGrant, nonce, refreshing string) {
	out, err := p.tokens(r.Context(), c, g, nonce, refreshing)
	if err != nil {
		tokenError(w, err.status, err.code, err.desc)
		return
	}
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, out)
}

// tokenErr is why tokens were not issued, as the token endpoint says it.
type tokenErr struct {
	status     int
	code, desc string
}

func (e *tokenErr) Error() string { return e.code + ": " + e.desc }

// tokens makes the tokens of a grant (issue).
func (p *Provider) tokens(ctx context.Context, c Client, g refreshGrant, nonce, refreshing string) (map[string]any, *tokenErr) {
	personID, scope, authTime := g.Person, g.Scope, g.AuthTime
	person, err := p.cfg.Store.IDPerson(ctx, personID)
	if err != nil || person.Disabled {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, &tokenErr{http.StatusServiceUnavailable, "temporarily_unavailable", "store unavailable"}
		}
		p.cfg.Store.DeleteIDStates(ctx, personID, kindRefresh)
		return nil, &tokenErr{http.StatusBadRequest, "invalid_grant", "the account is disabled or deleted"}
	}
	now := p.cfg.Now()
	claims := p.claims(person, scope)
	claims["iss"], claims["aud"], claims["iat"], claims["exp"] = p.Issuer(), c.ID, now.Unix(), now.Add(tokenLifetime).Unix()
	claims["auth_time"] = authTime.Unix()
	if amr := methodAMR(g.Method); amr != nil {
		claims["amr"] = amr
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	idToken, err := p.sign(claims)
	if err != nil {
		return nil, &tokenErr{http.StatusInternalServerError, "server_error", "signing failed"}
	}
	access := secret(32)
	if err := p.putState(ctx, "access:"+hash("access", access), kindAccess, person.ID,
		accessGrant{Client: c.ID, Scope: scope, Person: person.ID}, tokenLifetime); err != nil {
		return nil, &tokenErr{http.StatusServiceUnavailable, "temporarily_unavailable", "store unavailable"}
	}
	refresh := refreshing
	if refresh == "" {
		refresh = secret(32)
	}
	if err := p.putState(ctx, "refresh:"+hash("refresh", refresh), kindRefresh, person.ID,
		refreshGrant{Client: c.ID, Scope: scope, Person: person.ID, AuthTime: authTime, Method: g.Method}, refreshLifetime); err != nil {
		return nil, &tokenErr{http.StatusServiceUnavailable, "temporarily_unavailable", "store unavailable"}
	}
	out := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": int(tokenLifetime / time.Second),
		"id_token": idToken, "scope": scope}
	if refreshing == "" {
		out["refresh_token"] = refresh
	}
	return out, nil
}

// claims are what tokens and userinfo say of a person. The groups are always given: ento decides
// with them.
func (p *Provider) claims(x store.IDPerson, scope string) map[string]any {
	groups := slices.Clone(x.Groups)
	if groups == nil {
		groups = []string{}
	}
	slices.Sort(groups)
	c := map[string]any{"sub": x.ID, "groups": groups}
	scopes := strings.Fields(scope)
	if slices.Contains(scopes, "email") || slices.Contains(scopes, "openid") {
		c["email"], c["email_verified"] = x.Email, true
		c["preferred_username"] = x.Email
	}
	if slices.Contains(scopes, "profile") {
		c["name"] = personName(x)
		if x.GivenName != "" {
			c["given_name"] = x.GivenName
		}
		if x.FamilyName != "" {
			c["family_name"] = x.FamilyName
		}
	}
	return c
}

// userinfo answers for the person of an access token.
func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	var g accessGrant
	if ok {
		_, err := p.getState(r.Context(), "access:"+hash("access", strings.TrimSpace(tok)), false, &g)
		ok = err == nil
	}
	var person store.IDPerson
	if ok {
		var err error
		person, err = p.cfg.Store.IDPerson(r.Context(), g.Person)
		ok = err == nil && !person.Disabled
	}
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	writeJSON(w, http.StatusOK, p.claims(person, g.Scope))
}

// methodAMR is how a way of signing in shows in tokens (RFC 8176's values).
func methodAMR(m string) []string {
	switch m {
	case MethodPasskey:
		return []string{"hwk", "user"}
	case MethodPasswordPasskey:
		return []string{"pwd", "hwk", "mfa"}
	case MethodPasswordTOTP:
		return []string{"pwd", "otp", "mfa"}
	}
	return nil
}
