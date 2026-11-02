package control

// The device sign-in provider (0.32). Control nodes can be an OpenID Connect provider for one
// client, typically the organisation's own identity provider (Keycloak brokering to it), at
// https://<AdminUI>/device: it signs in the person of the device the browser runs on, without a
// password or key, because that device's person layer (person.go) is open. A browser reaches the
// control nodes over the tunnel, so the connection's overlay address names the device, as for the
// admin interface; nothing else is asked.
//
// It vouches only while that is recent: the person layer must be open, and the device must have
// signed its person in to a service (through this provider) or opened the layer (a sign-in, or an
// approved login on the desktop) within SignInConfig.Idle (default 6 hours). After that it answers
// access_denied, and the identity provider falls back to its own sign-in until the person signs in
// to ento again. It never vouches for devices admitted through a link (their person belongs to
// another network), suspended devices, or devices without a person.
//
// Codes live in the store (either control node may redeem them), are used once, last a minute, and
// are bound to the client, its redirect URI, a PKCE challenge (required) and the person layer they
// were given in, which must still be open when the code is redeemed. ID tokens are signed with
// ES256 by a key every control node shares (SignInConfig.Key).
//
// What it proves is the device, not the program on it, like the admin interface: any program of the
// device's person can sign them in this way while it lasts. The identity provider decides what such
// a sign-in may reach; a deployment can keep passkey confirmations and ento's own sign-in on its full
// sign-in.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"entowire.com/ento/internal/store"
)

// SignInConfig configures the device sign-in provider (Config.SignIn).
type SignInConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string          // exact matches only
	Key          *ecdsa.PrivateKey // P-256; the same on every control node
	// Idle: the device stops vouching for its person this long after it last signed them in, or after
	// their person layer opened, whichever is later (0: DefaultSignInIdle).
	Idle time.Duration
}

// DefaultSignInIdle is how long a device vouches for its person without a sign-in.
const DefaultSignInIdle = 6 * time.Hour

const (
	signInPath          = "/device"
	signInCodeLifetime  = time.Minute
	signInTokenLifetime = 5 * time.Minute
	signInPerMinute     = 20 // authorizations per device and minute, on each node
)

// ParseSignInKey reads the provider's signing key: a P-256 private key, PKCS #8 or SEC 1 DER, in
// base64 (openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform DER | base64 -w0).
func ParseSignInKey(b64 string) (*ecdsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, errors.New("not base64")
	}
	var k any
	if k, err = x509.ParsePKCS8PrivateKey(der); err != nil {
		if k, err = x509.ParseECPrivateKey(der); err != nil {
			return nil, errors.New("not a PKCS #8 or SEC 1 private key")
		}
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 key")
	}
	return ec, nil
}

func (s *Server) signInIssuer() string { return "https://" + s.cfg.AdminUI + signInPath }

func (s *Server) signInIdle() time.Duration {
	if s.cfg.SignIn.Idle > 0 {
		return s.cfg.SignIn.Idle
	}
	return DefaultSignInIdle
}

// isSignInPath reports whether the admin interface's name serves this path to the provider.
func (s *Server) isSignInPath(p string) bool {
	return s.cfg.SignIn != nil && (p == signInPath || strings.HasPrefix(p, signInPath+"/"))
}

// serveSignIn answers the provider's paths (any device may call them; the provider decides).
func (s *Server) serveSignIn(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	switch strings.TrimPrefix(r.URL.Path, signInPath) {
	case "/.well-known/openid-configuration":
		s.signInDiscovery(w)
	case "/jwks":
		s.signInJWKS(w)
	case "/authorize":
		s.signInAuthorize(w, r)
	case "/token":
		s.signInToken(w, r)
	default:
		writeErr(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) signInDiscovery(w http.ResponseWriter) {
	iss := s.signInIssuer()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         iss,
		"authorization_endpoint":                         iss + "/authorize",
		"token_endpoint":                                 iss + "/token",
		"jwks_uri":                                       iss + "/jwks",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"ES256"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                               []string{"openid", "profile", "email"},
		"claims_supported":                               []string{"sub", "preferred_username", "email", "acr", "auth_time", "nonce"},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (s *Server) signInJWK() map[string]string {
	pub := s.cfg.SignIn.Key.PublicKey
	b := make([]byte, 65)
	pub.X.FillBytes(b[1:33])
	pub.Y.FillBytes(b[33:])
	x, y := base64.RawURLEncoding.EncodeToString(b[1:33]), base64.RawURLEncoding.EncodeToString(b[33:])
	// RFC 7638 thumbprint: the required members in lexicographic order, no spaces.
	t := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	return map[string]string{"kty": "EC", "crv": "P-256", "x": x, "y": y, "use": "sig", "alg": "ES256",
		"kid": base64.RawURLEncoding.EncodeToString(t[:])}
}

func (s *Server) signInJWKS(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{s.signInJWK()}})
}

// signInVouch reports whether the device may sign its person in now, and if not, why (for the
// audit line).
func (s *Server) signInVouch(r *http.Request, p store.Peer, now time.Time) (bool, string) {
	switch {
	case p.ID == 0:
		return false, "not an enrolled device"
	case p.Suspended:
		return false, "suspended device"
	case p.Authority != "":
		return false, "admitted through a link (its person belongs to another network)"
	case p.User == "" || p.UserLogin == "":
		return false, "no person signed in on this device (ento agent login)"
	case !p.Person.Active || !p.Person.Approved:
		return false, "the person's session on this device is closed (sign in again, or log in on the desktop)"
	}
	last := p.Person.Since
	used, err := s.cfg.Store.LastSignIn(r.Context(), p.ID, p.Person.Since)
	if err != nil {
		return false, "store unavailable"
	}
	if used.After(last) {
		last = used
	}
	if idle := s.signInIdle(); now.Sub(last) > idle {
		return false, fmt.Sprintf("stale: no sign-in through this device since %s (more than %s; sign in to ento again)",
			last.UTC().Format(time.RFC3339), idle)
	}
	return true, ""
}

// signInAuthorize is the authorization endpoint: the browser arrives from the client with an
// authorization request, and is sent back with a code (the device vouches) or access_denied.
func (s *Server) signInAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET")
		return
	}
	q := r.URL.Query()
	cfg := s.cfg.SignIn
	redirect := q.Get("redirect_uri")
	// Nothing is sent to an address that is not the client's: errors before this point are shown.
	if q.Get("client_id") != cfg.ClientID || !slices.Contains(cfg.RedirectURIs, redirect) {
		s.audit(r, nil, "device_signin", "unknown client or redirect URI", "denied")
		h := w.Header()
		h.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "Unknown client or redirect address.\n")
		return
	}
	back := func(v url.Values) {
		v.Set("state", q.Get("state"))
		v.Set("iss", s.signInIssuer())
		sep := "?"
		if strings.Contains(redirect, "?") {
			sep = "&"
		}
		http.Redirect(w, r, redirect+sep+v.Encode(), http.StatusFound)
	}
	fail := func(code, desc string) { back(url.Values{"error": {code}, "error_description": {desc}}) }
	switch {
	case q.Get("response_type") != "code":
		fail("unsupported_response_type", "code only")
		return
	case !slices.Contains(strings.Fields(q.Get("scope")), "openid"):
		fail("invalid_scope", "openid is required")
		return
	case q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) < 43:
		fail("invalid_request", "PKCE with S256 is required")
		return
	case len(q.Get("nonce")) > 512 || len(q.Get("state")) > 2048:
		fail("invalid_request", "nonce or state too long")
		return
	case slices.Contains(strings.Fields(q.Get("prompt")), "login") || q.Get("max_age") == "0":
		// The client asks for a fresh sign-in by the person (a confirmation): a device vouching is
		// not one, so its own sign-in runs.
		s.audit(r, nil, "device_signin", "fresh sign-in asked (prompt=login): left to the client's own sign-in", "denied")
		fail("access_denied", "a fresh sign-in was asked for")
		return
	}
	addr, ok := caller(r)
	if !ok {
		fail("access_denied", "unknown device")
		return
	}
	if !s.signInAllow(addr.Unmap().String()) {
		s.audit(r, nil, "device_signin", fmt.Sprintf("more than %d sign-ins a minute: refused", signInPerMinute), "denied")
		fail("access_denied", "too many sign-ins from this device")
		return
	}
	now := time.Now()
	p, err := s.cfg.Store.PeerByAddress(r.Context(), addr.Unmap())
	switch {
	case errors.Is(err, store.ErrNotFound):
		p = store.Peer{Hostname: "unknown", Address: addr.Unmap()}
	case err != nil:
		s.audit(r, nil, "device_signin", "device lookup failed (database unavailable)", "failed")
		fail("access_denied", "this device cannot vouch for anyone now")
		return
	}
	if ok, why := s.signInVouch(r, p, now); !ok {
		by := &p
		if p.ID == 0 {
			by = nil
		}
		s.audit(r, by, "device_signin", why, "denied")
		fail("access_denied", "this device does not vouch for anyone now")
		return
	}
	code, err := newSignInSecret()
	if err != nil {
		fail("server_error", "no code")
		return
	}
	if err := s.cfg.Store.CreateSignInCode(r.Context(), store.SignInCode{Hash: signInHash(code), PeerID: p.ID, PersonSince: p.Person.Since,
		ClientID: cfg.ClientID, RedirectURI: redirect, Nonce: q.Get("nonce"), Challenge: q.Get("code_challenge"),
		ExpiresAt: now.Add(signInCodeLifetime)}); err != nil {
		s.cfg.Logf("device sign-in code: %v", err)
		fail("server_error", "no code")
		return
	}
	if err := s.cfg.Store.RecordSignIn(r.Context(), p.ID, p.Person.Since, now); err != nil {
		s.cfg.Logf("device sign-in record of peer %d: %v", p.ID, err)
	}
	s.audit(r, &p, "device_signin", userLabel(p)+" login="+p.UserLogin, "ok")
	back(url.Values{"code": {code}})
}

// signInToken is the token endpoint: the client redeems a code for an ID token.
func (s *Server) signInToken(w http.ResponseWriter, r *http.Request) {
	tokenErr := func(status int, code, desc string) {
		writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
	}
	if r.Method != http.MethodPost {
		tokenErr(http.StatusMethodNotAllowed, "invalid_request", "POST")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		tokenErr(http.StatusBadRequest, "invalid_request", "form")
		return
	}
	cfg := s.cfg.SignIn
	id, secret, basic := r.BasicAuth()
	if basic {
		// RFC 6749 2.3.1: both are form-encoded inside the header.
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != cfg.ClientID || subtle.ConstantTimeCompare([]byte(secret), []byte(cfg.ClientSecret)) != 1 {
		s.audit(r, nil, "device_signin_token", "client authentication failed", "denied")
		w.Header().Set("WWW-Authenticate", `Basic realm="device sign-in"`)
		tokenErr(http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		tokenErr(http.StatusBadRequest, "unsupported_grant_type", "authorization_code only")
		return
	}
	now := time.Now()
	c, err := s.cfg.Store.TakeSignInCode(r.Context(), signInHash(r.PostForm.Get("code")), now)
	if errors.Is(err, store.ErrNotFound) {
		s.audit(r, nil, "device_signin_token", "unknown, expired or used code", "denied")
		tokenErr(http.StatusBadRequest, "invalid_grant", "unknown, expired or used code")
		return
	}
	if err != nil {
		tokenErr(http.StatusServiceUnavailable, "temporarily_unavailable", "store unavailable")
		return
	}
	verifier := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if c.ClientID != id || c.RedirectURI != r.PostForm.Get("redirect_uri") ||
		subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(verifier[:])), []byte(c.Challenge)) != 1 {
		s.audit(r, nil, "device_signin_token", "redirect URI or PKCE verifier does not match the code", "denied")
		tokenErr(http.StatusBadRequest, "invalid_grant", "redirect URI or code verifier does not match")
		return
	}
	// The device must still vouch: same person layer, still open, not suspended since.
	p, err := s.peerByID(r.Context(), c.PeerID)
	if err != nil || p.Suspended || p.Authority != "" || !p.Person.Active || !p.Person.Approved || !p.Person.Since.Equal(c.PersonSince) || p.User == "" {
		s.audit(r, nil, "device_signin_token", fmt.Sprintf("peer %d: its person's session ended before the code was redeemed", c.PeerID), "denied")
		tokenErr(http.StatusBadRequest, "invalid_grant", "the device no longer vouches for its person")
		return
	}
	claims := map[string]any{
		"iss": s.signInIssuer(), "sub": p.User, "aud": id, "iat": now.Unix(), "exp": now.Add(signInTokenLifetime).Unix(),
		"auth_time": p.Person.Since.Unix(), "preferred_username": p.UserLogin, "acr": "device",
	}
	if c.Nonce != "" {
		claims["nonce"] = c.Nonce
	}
	if strings.Contains(p.UserName, "@") {
		claims["email"] = p.UserName
	}
	idToken, err := s.signJWT(claims)
	if err != nil {
		tokenErr(http.StatusInternalServerError, "server_error", "signing failed")
		return
	}
	access, err := newSignInSecret()
	if err != nil {
		tokenErr(http.StatusInternalServerError, "server_error", "no token")
		return
	}
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer",
		"expires_in": int(signInTokenLifetime / time.Second), "id_token": idToken})
}

// signJWT signs claims as a compact JWS with ES256.
func (s *Server) signJWT(claims map[string]any) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": s.signInJWK()["kid"]})
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	in := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(in))
	rr, ss, err := ecdsa.Sign(rand.Reader, s.cfg.SignIn.Key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	rr.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func newSignInSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func signInHash(code string) string {
	sum := sha256.Sum256([]byte("ento-device-signin-v1\x00" + code))
	return hex.EncodeToString(sum[:])
}

// signInAllow counts a device's authorizations on this node: at most signInPerMinute a minute.
func (s *Server) signInAllow(addr string) bool {
	s.signInMu.Lock()
	defer s.signInMu.Unlock()
	now := time.Now()
	if s.signInSeen == nil || now.Sub(s.signInWindow) > time.Minute {
		s.signInSeen, s.signInWindow = map[string]int{}, now
	}
	s.signInSeen[addr]++
	return s.signInSeen[addr] <= signInPerMinute
}
