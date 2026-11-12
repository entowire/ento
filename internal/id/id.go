// Package id is a network's own identity provider: an OpenID Connect provider at https://<Name>/,
// served by the control nodes on their overlay port 443 (TLS ends there), whose people sign in with
// passkeys. People, groups, passkeys and every short-lived record (authorization requests, codes,
// passkey ceremonies, setup links, refresh grants) are in the network's own database
// (store.IDStore), so that either control node answers any step. ID tokens are signed with ES256
// by a key every control node shares, kept outside the database.
//
// It serves what ento and the apps of a network need, and nothing else:
//   - the authorization code flow with PKCE (S256, required), for the dashboard, the apps and other
//     services of the network (confidential clients only);
//   - the device authorization grant (RFC 8628) for the agent's sign-in, on one screen: a code that
//     came in a link is shown and must be accepted after the passkey, a typed one is approved when
//     the passkey is;
//   - refresh tokens, which the control nodes use every few minutes to learn whether a person still
//     has access and with which groups: refused (invalid_grant) once the person is disabled or
//     deleted;
//   - userinfo;
//   - one-time setup links, with which a person without a passkey registers their first.
//
// Every sign-in takes a passkey with user verification: there is no session at the provider, so a
// second sign-in asks again. Passkeys are verified with github.com/go-webauthn/webauthn, the
// relying party being Name.
package id

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"entowire.com/ento/internal/store"
)

// Client is an application that signs people in with the provider. Every client is confidential:
// it authenticates with its secret at the token endpoint.
type Client struct {
	ID           string   `json:"id"`
	Name         string   `json:"name,omitempty"` // shown to the person ("" : the ID)
	Secret       string   `json:"secret"`
	RedirectURIs []string `json:"redirect_uris"` // exact matches only
	// DeviceGrant lets the client use the device authorization grant (RFC 8628).
	DeviceGrant bool `json:"device_grant,omitempty"`
}

func (c Client) name() string {
	if c.Name != "" {
		return c.Name
	}
	return c.ID
}

// Config configures a provider.
type Config struct {
	Name    string            // the provider's host name: its issuer is https://<Name>, its passkeys' relying party Name
	Title   string            // the network's name, shown on the pages and to passkey managers ("": Name)
	Key     *ecdsa.PrivateKey // P-256, signs ID tokens; the same on every control node
	Clients []Client
	Store   Store
	// Audit records what the provider did or refused: the action, its target and result (ok,
	// denied or failed). nil: nothing is recorded.
	Audit func(r *http.Request, action, target, result string)
	Logf  func(format string, args ...any)
	// Now is the clock (nil: time.Now).
	Now func() time.Time
	// Origin is where the pages are served ("": https://<Name>); tests use http://localhost:PORT.
	Origin string
	// Here, HereOrigin and HereClient let people sign in on the device their browser runs on
	// (here.go): HereOrigin is the second origin the pages are served on, which only the device
	// itself reaches (its own name and port, https://<Name>:<port>), and HereClient the built-in
	// client whose tokens Here receives.
	Here       Here
	HereOrigin string
	HereClient string
}

// Lifetimes and limits.
const (
	requestLifetime   = 10 * time.Minute    // an authorization request, between the client and the passkey
	ceremonyLifetime  = 5 * time.Minute     // a passkey ceremony
	codeLifetime      = time.Minute         // an authorization code
	deviceLifetime    = 10 * time.Minute    // a device code
	devicePoll        = 5 * time.Second     // the interval devices are told to poll at
	confirmLifetime   = 2 * time.Minute     // a device code awaiting the person's answer
	tokenLifetime     = 10 * time.Minute    // ID and access tokens
	refreshLifetime   = 30 * 24 * time.Hour // a refresh grant, from its last use
	DefaultSetupLink  = 24 * time.Hour      // a setup link, unless the caller says otherwise
	maxForm           = 64 << 10            // a request body
	attemptsPerMinute = 30                  // passkey ceremonies a minute from one address, on each node
)

// State kinds (store.IDState.Kind), and their keys' prefixes.
const (
	kindRequest  = "request"  // "request:" + id
	kindCeremony = "ceremony" // "ceremony:" + id
	kindCode     = "code"     // "code:" + hash
	kindDevice   = "device"   // "device:" + hash of the device code; "user:" + user code
	kindConfirm  = "confirm"  // "confirm:" + id
	kindRefresh  = "refresh"  // "refresh:" + hash
	kindAccess   = "access"   // "access:" + hash
	kindSetup    = "setup"    // "setup:" + hash
	kindFail     = "fail"     // "fail:" + person: wrong passwords and codes
	kindPassword = "password" // "password:" + id: a password checked, its second step to come
	kindAccount  = "account"  // "account:" + hash: a session of the account page
	kindNewApp   = "newapp"   // "newapp:" + id: an app secret offered, not confirmed yet
)

// Provider is a running identity provider.
type Provider struct {
	cfg   Config
	wa    *webauthn.WebAuthn
	jwk   map[string]string
	mux   *http.ServeMux
	swept time.Time

	limitMu  sync.Mutex
	limitWin time.Time
	limitN   map[string]int
}

// New checks cfg and returns a provider.
func New(cfg Config) (*Provider, error) {
	switch {
	case cfg.Name == "" || strings.ContainsAny(cfg.Name, "/:@ "):
		return nil, errors.New("the provider needs a host name")
	case cfg.Key == nil:
		return nil, errors.New("the provider needs a signing key")
	case cfg.Store == nil:
		return nil, errors.New("the provider needs a store")
	}
	seen := map[string]bool{}
	for _, c := range cfg.Clients {
		switch {
		case c.ID == "" || seen[c.ID]:
			return nil, fmt.Errorf("client %q: missing or repeated ID", c.ID)
		case len(c.Secret) < 16:
			return nil, fmt.Errorf("client %s: a secret of at least 16 characters is required", c.ID)
		case len(c.RedirectURIs) == 0 && !c.DeviceGrant:
			return nil, fmt.Errorf("client %s: no redirect URI and no device grant", c.ID)
		}
		for _, u := range c.RedirectURIs {
			if p, err := url.Parse(u); err != nil || p.Scheme == "" || p.Fragment != "" {
				return nil, fmt.Errorf("client %s: redirect URI %q is not an absolute URI without a fragment", c.ID, u)
			}
		}
		seen[c.ID] = true
	}
	if cfg.Title == "" {
		cfg.Title = cfg.Name
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Origin == "" {
		cfg.Origin = "https://" + cfg.Name
	}
	origins := []string{cfg.Origin}
	if cfg.HereOrigin != "" {
		// A passkey of Name works on the device's own origin too: the same host, another port.
		origins = append(origins, cfg.HereOrigin)
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.Name,
		RPDisplayName: cfg.Title,
		RPOrigins:     origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
		// No extension is asked for and none is relied on, so an output a client adds unasked is ignored:
		// Android's passkey manager always returns credProps, which would otherwise fail every passkey made there.
		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyLifetime},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyLifetime},
		},
	})
	if err != nil {
		return nil, err
	}
	p := &Provider{cfg: cfg, wa: wa, jwk: publicJWK(cfg.Key)}
	p.routes()
	return p, nil
}

// Issuer is the provider's issuer identifier.
func (p *Provider) Issuer() string { return "https://" + p.cfg.Name }

// Handler serves the provider.
func (p *Provider) Handler() http.Handler { return p.mux }

func (p *Provider) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	m.HandleFunc("GET /jwks", p.jwks)
	m.HandleFunc("GET /authorize", p.authorize)
	m.HandleFunc("POST /token", p.token)
	m.HandleFunc("POST /device_authorization", p.deviceAuthorization)
	m.HandleFunc("GET /userinfo", p.userinfo)
	m.HandleFunc("POST /userinfo", p.userinfo)
	m.HandleFunc("GET /device", p.devicePage)
	m.HandleFunc("GET /setup", p.setupPage)
	m.HandleFunc("GET "+HerePath, p.herePage)
	m.HandleFunc("POST /passkey/begin", p.passkeyBegin)
	m.HandleFunc("POST /passkey/finish", p.passkeyFinish)
	m.HandleFunc("POST /password", p.passwordStep)
	m.HandleFunc("POST /password/passkey", p.passwordPasskey)
	m.HandleFunc("POST /password/totp", p.passwordTOTP)
	m.HandleFunc("GET /account", p.accountPage)
	m.HandleFunc("GET /account/state", p.accountState)
	m.HandleFunc("POST /account/password", p.accountPassword)
	m.HandleFunc("POST /account/passkey/begin", p.accountPasskeyBegin)
	m.HandleFunc("POST /account/passkey/finish", p.accountPasskeyFinish)
	m.HandleFunc("POST /account/passkey/delete", p.accountPasskeyDelete)
	m.HandleFunc("POST /account/totp/begin", p.accountTOTPBegin)
	m.HandleFunc("POST /account/totp/finish", p.accountTOTPFinish)
	m.HandleFunc("POST /account/totp/delete", p.accountTOTPDelete)
	m.HandleFunc("POST /account/signout", p.accountSignOut)
	m.HandleFunc("POST /setup/password", p.setupPassword)
	m.HandleFunc("POST /setup/totp", p.setupTOTP)
	m.HandleFunc("POST /device/answer", p.deviceAnswer)
	m.HandleFunc("POST /setup/begin", p.setupBegin)
	m.HandleFunc("POST /setup/finish", p.setupFinish)
	m.HandleFunc("GET /{$}", p.homePage)
	m.HandleFunc("GET /ento-id.js", p.script)
	m.HandleFunc("GET /ento-id.css", p.style)
	p.mux = http.NewServeMux()
	p.mux.Handle("/", headers(m, p))
}

// headers sets what every answer carries, and sweeps expired state now and then.
func headers(next http.Handler, p *Provider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
			"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		p.sweep(r.Context())
		next.ServeHTTP(w, r)
	})
}

// sweep deletes expired state, at most once a minute on each node.
func (p *Provider) sweep(ctx context.Context) {
	now := p.cfg.Now()
	p.limitMu.Lock()
	due := now.Sub(p.swept) > time.Minute
	if due {
		p.swept = now
	}
	p.limitMu.Unlock()
	if due {
		if err := p.cfg.Store.ExpireIDStates(ctx, now); err != nil {
			p.cfg.Logf("identity provider: expiring state: %v", err)
		}
	}
}

// allow counts passkey ceremonies from one address on this node: at most attemptsPerMinute a minute.
func (p *Provider) allow(r *http.Request) bool {
	addr := r.RemoteAddr
	if i := strings.LastIndexByte(addr, ':'); i > 0 {
		addr = addr[:i]
	}
	p.limitMu.Lock()
	defer p.limitMu.Unlock()
	now := p.cfg.Now()
	if p.limitN == nil || now.Sub(p.limitWin) > time.Minute {
		p.limitN, p.limitWin = map[string]int{}, now
	}
	p.limitN[addr]++
	return p.limitN[addr] <= attemptsPerMinute
}

func (p *Provider) audit(r *http.Request, action, target, result string) {
	if p.cfg.Audit != nil {
		p.cfg.Audit(r, action, target, result)
	}
}

func (p *Provider) client(id string) (Client, bool) {
	for _, c := range p.cfg.Clients {
		if c.ID == id {
			return c, true
		}
	}
	return Client{}, false
}

// authClient authenticates the client of a token endpoint request (client_secret_basic or
// client_secret_post).
func (p *Provider) authClient(r *http.Request) (Client, bool) {
	id, secret, basic := r.BasicAuth()
	if basic {
		// RFC 6749 2.3.1: both are form-encoded inside the header.
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	c, ok := p.client(id)
	if !ok || subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) != 1 {
		return Client{}, false
	}
	return c, true
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	iss := p.Issuer()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         iss,
		"authorization_endpoint":                         iss + "/authorize",
		"token_endpoint":                                 iss + "/token",
		"device_authorization_endpoint":                  iss + "/device_authorization",
		"userinfo_endpoint":                              iss + "/userinfo",
		"jwks_uri":                                       iss + "/jwks",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token", deviceGrantType},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"ES256"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                               []string{"openid", "profile", "email", "groups", "offline_access"},
		"claims_supported":                               []string{"sub", "email", "email_verified", "name", "given_name", "family_name", "preferred_username", "groups", "auth_time", "nonce"},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{p.jwk}})
}

// publicJWK is the key's public half as a JWK, its key ID the RFC 7638 thumbprint.
func publicJWK(k *ecdsa.PrivateKey) map[string]string {
	b := make([]byte, 64)
	k.PublicKey.X.FillBytes(b[:32])
	k.PublicKey.Y.FillBytes(b[32:])
	x, y := base64.RawURLEncoding.EncodeToString(b[:32]), base64.RawURLEncoding.EncodeToString(b[32:])
	t := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	return map[string]string{"kty": "EC", "crv": "P-256", "x": x, "y": y, "use": "sig", "alg": "ES256",
		"kid": base64.RawURLEncoding.EncodeToString(t[:])}
}

// sign signs claims as a compact JWS with ES256.
func (p *Provider) sign(claims map[string]any) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": p.jwk["kid"]})
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	in := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(in))
	rr, ss, err := ecdsa.Sign(rand.Reader, p.cfg.Key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	rr.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// putState stores v as JSON under key.
func (p *Provider) putState(ctx context.Context, key, kind, person string, v any, life time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return p.cfg.Store.PutIDState(ctx, store.IDState{Key: key, Kind: kind, Person: person, Data: b, ExpiresAt: p.cfg.Now().Add(life)})
}

// getState reads what is under key into v; take removes it too.
func (p *Provider) getState(ctx context.Context, key string, take bool, v any) (store.IDState, error) {
	var s store.IDState
	var err error
	if take {
		s, err = p.cfg.Store.TakeIDState(ctx, key, p.cfg.Now())
	} else {
		s, err = p.cfg.Store.IDState(ctx, key, p.cfg.Now())
	}
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(s.Data, v)
}

// secret returns a new random secret of n bytes, base64url.
func secret(n int) string { return base64.RawURLEncoding.EncodeToString(randomBytes(n)) }

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail
	}
	return b
}

// hash is how secrets are kept: never themselves.
func hash(purpose, s string) string {
	sum := sha256.Sum256([]byte("ento-id-v1\x00" + purpose + "\x00" + s))
	return hex.EncodeToString(sum[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// fail answers a call of the pages with a message for the person.
func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// readJSON decodes a call of the pages.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if !sameOrigin(r) {
		fail(w, http.StatusForbidden, "This page's calls come from this page only.")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "Unreadable request.")
		return false
	}
	return true
}

// sameOrigin: the pages' calls carry a JSON body and come from the provider's own pages, which other
// sites cannot make a browser send (the content type needs a preflight, never answered).
func sameOrigin(r *http.Request) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return false
	}
	site := r.Header.Get("Sec-Fetch-Site")
	return site == "" || site == "same-origin"
}

// personName is how a person is shown.
func personName(x store.IDPerson) string {
	n := strings.TrimSpace(x.GivenName + " " + x.FamilyName)
	if n == "" {
		return x.Email
	}
	return n
}

func clientNames(cs []Client) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ID)
	}
	slices.Sort(out)
	return out
}
