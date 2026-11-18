package id

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"entowire.com/ento/internal/oidcrp"
	"entowire.com/ento/internal/store"
)

// providers (Google Workspace, Microsoft Entra ID, Okta, any other) that people sign in through,
// instead of a passkey here: the page offers "Continue with <provider>", the provider signs the
// person in (code flow with PKCE, a nonce, its ID token checked against its published keys), and
// its sign-in stands for theirs: method "provider", allowed by the sign-in policies like the others.
//
// An outside provider signs in only people the network already has: the first time, the person
// whose address its ID token names (verified, and in the provider's domains when it has some); from
// then on only that same account there (store.IDPerson.Links: its issuer and subject), whatever
// address it later shows, so that an address given to someone else signs no one in. The people,
// their groups and their roles stay the network's, managed in the dashboard: a provider that sends
// no groups (Google) works as well as one that does.
//
// The providers are a setting of the network's database (SettingUpstreams), changed by the control
// nodes' admin API; each client secret is kept sealed with a key derived from the provider's
// signing key, bound to its issuer.

// MethodProvider is a sign-in through an outside provider.
const MethodProvider = "provider"

// SettingUpstreams holds the network's outside providers (JSON, []Upstream).
const SettingUpstreams = "id_upstreams"

// UpstreamCallback is where an outside provider sends the person back; it is registered with the
// provider as https://<id name>/upstream/callback (and, for the device's own sign-in, on its origin).
const UpstreamCallback = "/upstream/callback"

// Upstream is an outside provider people sign in through.
type Upstream struct {
	Name     string   `json:"name"`              // short and lower case: google, microsoft
	Title    string   `json:"title"`             // on the button: "Continue with <Title>"
	Issuer   string   `json:"issuer"`            // exactly as its discovery names it
	ClientID string   `json:"client_id"`         // a confidential client with UpstreamCallback registered
	Secret   string   `json:"secret"`            // sealed (SealUpstreamSecret)
	Domains  []string `json:"domains,omitempty"` // only addresses in these domains ("": any)
}

var upstreamName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// CheckUpstream says what is wrong with u ("" when nothing), and normalizes it.
func CheckUpstream(u *Upstream) error {
	u.Name = strings.ToLower(strings.TrimSpace(u.Name))
	u.Title = strings.TrimSpace(u.Title)
	u.Issuer = strings.TrimSpace(u.Issuer)
	u.ClientID = strings.TrimSpace(u.ClientID)
	for i, d := range u.Domains {
		u.Domains[i] = strings.ToLower(strings.Trim(strings.TrimSpace(d), "@."))
	}
	u.Domains = slices.DeleteFunc(u.Domains, func(d string) bool { return d == "" })
	iss, err := url.Parse(u.Issuer)
	switch {
	case !upstreamName.MatchString(u.Name):
		return errors.New("a provider's name is lower case letters, digits and -, starting with a letter (e.g. google)")
	case u.Title == "" || len(u.Title) > 40:
		return errors.New("a provider needs a title of at most 40 characters (e.g. Google)")
	case err != nil || iss.Scheme != "https" || iss.Host == "" || iss.RawQuery != "" || iss.Fragment != "":
		return errors.New("the issuer is an https address (e.g. https://accounts.google.com)")
	case u.ClientID == "":
		return errors.New("a provider needs its client ID")
	}
	return nil
}

// Upstreams are the network's outside providers.
func Upstreams(ctx context.Context, st Store) ([]Upstream, error) {
	v, ok, err := st.Setting(ctx, SettingUpstreams)
	if err != nil || !ok || v == "" {
		return nil, err
	}
	var out []Upstream
	if err := json.Unmarshal([]byte(v), &out); err != nil {
		return nil, fmt.Errorf("%s: %w", SettingUpstreams, err)
	}
	return out, nil
}

// EncodeUpstreams is the setting's value for ups.
func EncodeUpstreams(ups []Upstream) string {
	if len(ups) == 0 {
		return ""
	}
	b, _ := json.Marshal(ups)
	return string(b)
}

func upstreamAEAD(key *ecdsa.PrivateKey) cipher.AEAD {
	m := hmac.New(sha256.New, key.D.FillBytes(make([]byte, 32)))
	m.Write([]byte("ento-id-upstream-v1"))
	b, _ := aes.NewCipher(m.Sum(nil))
	g, _ := cipher.NewGCM(b)
	return g
}

// SealUpstreamSecret seals a provider's client secret with the provider's key (the same on every
// control node), bound to its issuer.
func SealUpstreamSecret(key *ecdsa.PrivateKey, issuer, secret string) string {
	a := upstreamAEAD(key)
	nonce := randomBytes(a.NonceSize())
	return base64.StdEncoding.EncodeToString(a.Seal(nonce, nonce, []byte(secret), []byte(issuer)))
}

func (p *Provider) upstreamSecret(u Upstream) (string, error) {
	b, err := base64.StdEncoding.DecodeString(u.Secret)
	a := upstreamAEAD(p.cfg.Key)
	if err != nil || len(b) < a.NonceSize() {
		return "", errors.New("the client secret is unreadable")
	}
	plain, err := a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], []byte(u.Issuer))
	if err != nil {
		return "", errors.New("the client secret does not open with this network's key")
	}
	return string(plain), nil
}

// upstreamMeta is what a provider publishes (its discovery), kept for an hour, and its keys.
type upstreamMeta struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	fetched               time.Time
	keys                  *oidcrp.Keys
}

const upstreamMetaLife = time.Hour

type upstreamCache struct {
	mu   sync.Mutex
	meta map[string]*upstreamMeta
}

// upstreamHTTP calls outside providers (outbound only: nothing listens for them, and connections out to providers are allowed).
var upstreamHTTP = &http.Client{Timeout: 15 * time.Second}

// DiscoverUpstream fetches an issuer's discovery and checks it is a provider people can sign in
// through here: the same issuer, an authorization and a token endpoint, published keys.
func (p *Provider) DiscoverUpstream(ctx context.Context, issuer string) error {
	_, err := discoverUpstream(ctx, p.upstreamClient(), issuer)
	return err
}

func discoverUpstream(ctx context.Context, c *http.Client, issuer string) (*upstreamMeta, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("the provider's discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the provider's discovery: HTTP %d", resp.StatusCode)
	}
	var m upstreamMeta
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, fmt.Errorf("the provider's discovery: %w", err)
	}
	switch {
	case m.Issuer != issuer:
		// Microsoft's shared endpoints (common, organizations) name a placeholder: a tenant's own
		// issuer is needed, so that only its accounts sign in.
		return nil, fmt.Errorf("the provider names itself %q, not %q: use its own issuer (Microsoft: https://login.microsoftonline.com/<tenant ID>/v2.0)", m.Issuer, issuer)
	case m.AuthorizationEndpoint == "" || m.TokenEndpoint == "" || m.JWKSURI == "":
		return nil, errors.New("the provider's discovery names no authorization endpoint, token endpoint or keys")
	}
	return &m, nil
}

func (p *Provider) upstreamMeta(ctx context.Context, u Upstream) (*upstreamMeta, error) {
	p.ups.mu.Lock()
	m := p.ups.meta[u.Issuer]
	p.ups.mu.Unlock()
	if m != nil && p.cfg.Now().Sub(m.fetched) < upstreamMetaLife {
		return m, nil
	}
	m, err := discoverUpstream(ctx, p.upstreamClient(), u.Issuer)
	if err != nil {
		return nil, err
	}
	m.fetched = p.cfg.Now()
	uri := m.JWKSURI
	m.keys = &oidcrp.Keys{Client: p.upstreamClient(), URI: func(context.Context) (string, error) { return uri, nil }}
	p.ups.mu.Lock()
	if p.ups.meta == nil {
		p.ups.meta = map[string]*upstreamMeta{}
	}
	p.ups.meta[u.Issuer] = m
	p.ups.mu.Unlock()
	return m, nil
}

func (p *Provider) upstreamClient() *http.Client {
	if p.cfg.UpstreamHTTP != nil {
		return p.cfg.UpstreamHTTP
	}
	return upstreamHTTP
}

// upstream returns the network's provider named name.
func (p *Provider) upstream(ctx context.Context, name string) (Upstream, bool) {
	ups, err := Upstreams(ctx, p.cfg.Store)
	if err != nil {
		p.cfg.Logf("identity provider: %v", err)
		return Upstream{}, false
	}
	for _, u := range ups {
		if u.Name == name {
			return u, true
		}
	}
	return Upstream{}, false
}

// upstreamFor reports whether one of ups can sign x in: an account there linked to x already, or
// one whose domains take x's address (a provider without domains might: it is counted).
func upstreamFor(x store.IDPerson, ups []Upstream) bool {
	at := strings.LastIndexByte(x.Email, '@')
	for _, u := range ups {
		if x.Links[u.Issuer] != "" {
			return true
		}
		if len(u.Domains) == 0 || at >= 0 && slices.Contains(u.Domains, x.Email[at+1:]) {
			return true
		}
	}
	return false
}

// upstreamLogin is a sign-in at an outside provider under way, under "upstream:" + its state.
type upstreamLogin struct {
	goal
	Provider string    `json:"provider"`
	Issuer   string    `json:"issuer"`
	Nonce    string    `json:"nonce"`
	Verifier string    `json:"verifier"`
	Redirect string    `json:"redirect"`
	Started  time.Time `json:"started"`
}

const kindUpstream = "upstream" // "upstream:" + state

// upstreamBegin starts a sign-in at an outside provider for a goal: the address the browser goes to.
func (p *Provider) upstreamBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		goal
		Provider string `json:"provider"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !p.allow(r) {
		fail(w, http.StatusTooManyRequests, "Too many attempts. Wait a minute and try again.")
		return
	}
	if msg := p.checkGoal(r, &in.goal); msg != "" {
		fail(w, http.StatusGone, msg)
		return
	}
	u, ok := p.upstream(r.Context(), in.Provider)
	if !ok {
		fail(w, http.StatusNotFound, "This way of signing in is not offered any more. Reload the page.")
		return
	}
	m, err := p.upstreamMeta(r.Context(), u)
	if err != nil {
		p.cfg.Logf("identity provider: %s: %v", u.Name, err)
		fail(w, http.StatusBadGateway, u.Title+" does not answer. Try again in a moment, or sign in another way.")
		return
	}
	// The provider sends the person back to the origin they started on: the device's own sign-in
	// stays on the device's origin, where only that device reaches it.
	origin := p.Issuer()
	if p.cfg.Origin != "" {
		origin = p.cfg.Origin
	}
	if in.Goal == "here" {
		origin = p.cfg.HereOrigin
	}
	state, nonce, verifier := secret(24), secret(24), secret(32)
	login := upstreamLogin{goal: in.goal, Provider: u.Name, Issuer: u.Issuer, Nonce: nonce, Verifier: verifier,
		Redirect: origin + UpstreamCallback, Started: p.cfg.Now()}
	if err := p.putState(r.Context(), "upstream:"+state, kindUpstream, "", login, requestLifetime); err != nil {
		fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {u.ClientID}, "redirect_uri": {login.Redirect},
		"scope": {"openid email profile"}, "state": {state}, "nonce": {nonce},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		// Each sign-in asks again where the provider allows it (there is no session here either);
		// "select_account" lets a person with several accounts there choose.
		"max_age": {"0"}, "prompt": {"select_account"}}
	if len(u.Domains) == 1 {
		q.Set("hd", u.Domains[0]) // Google: only that Workspace's accounts are offered
	}
	sep := "?"
	if strings.Contains(m.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": m.AuthorizationEndpoint + sep + q.Encode()})
}

// upstreamPage is where the provider sends the person back: the page finishes the sign-in
// (upstreamFinish) and goes on as a passkey's would.
func (p *Provider) upstreamPage(w http.ResponseWriter, r *http.Request) {
	p.page(w, http.StatusOK, pageData{Mode: "upstream"})
}

// upstreamClaims are what a provider's ID token says about the person.
type upstreamClaims struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified any      `json:"email_verified"` // a boolean, or "true" (some providers)
	HostedDomain  string   `json:"hd"`             // Google Workspace
	AuthTime      *float64 `json:"auth_time"`
	Name          string   `json:"name"`
}

func (c upstreamClaims) unverified() bool {
	switch v := c.EmailVerified.(type) {
	case bool:
		return !v
	case string:
		return v != "true"
	}
	return false // not said: the provider's addresses are its own (Microsoft names none)
}

// upstreamFinish exchanges the provider's code, checks its ID token and signs the person it names
// in, for the goal the sign-in started with; the answer is a passkey sign-in's, with that goal.
func (p *Provider) upstreamFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		State string `json:"state"`
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	var login upstreamLogin
	if in.State == "" {
		fail(w, http.StatusGone, "This sign-in has expired. Start again.")
		return
	}
	if _, err := p.getState(r.Context(), "upstream:"+in.State, true, &login); err != nil {
		fail(w, http.StatusGone, "This sign-in has expired. Start again.")
		return
	}
	u, ok := p.upstream(r.Context(), login.Provider)
	if !ok || u.Issuer != login.Issuer {
		fail(w, http.StatusGone, "This way of signing in is not offered any more. Start again.")
		return
	}
	if in.Error != "" || in.Code == "" {
		what := in.Error
		if what == "" {
			what = "no code"
		}
		p.audit(r, "id_signin", u.Name+": the provider answered "+what, "denied")
		fail(w, http.StatusForbidden, u.Title+" did not sign you in ("+what+"). Start again.")
		return
	}
	person, err := p.upstreamPerson(r.Context(), u, login, in.Code)
	if err != nil {
		who := person.Email
		if who == "" {
			who = u.Name
		}
		p.audit(r, "id_signin", who+" via "+u.Name+": "+err.Error(), "denied")
		var ref *refusal
		msg := "This sign-in did not work. Start again, or sign in another way."
		if errors.As(err, &ref) {
			msg = ref.msg
		}
		fail(w, http.StatusForbidden, msg)
		return
	}
	a, err := p.access(r.Context(), person)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
		return
	}
	if !slices.Contains(a.allowed, MethodProvider) {
		p.audit(r, "id_signin", person.Email+": "+MethodProvider+" is not allowed for this account", "denied")
		fail(w, http.StatusForbidden, "Your account may not sign in with "+u.Title+": use your passkey.")
		return
	}
	// The goal goes on as after a passkey; the page needs to know which it was.
	rec := &capture{h: http.Header{}, code: http.StatusOK}
	p.complete(rec, r, login.goal, person, MethodProvider)
	for k, v := range rec.h {
		w.Header()[k] = v
	}
	var out map[string]any
	if rec.code != http.StatusOK || json.Unmarshal(rec.buf.Bytes(), &out) != nil {
		w.WriteHeader(rec.code)
		w.Write(rec.buf.Bytes())
		return
	}
	out["goal"] = login.goal
	writeJSON(w, http.StatusOK, out)
}

// upstreamPerson exchanges the code and returns the person the ID token names, linking them to
// the provider's account at their first sign-in through it.
func (p *Provider) upstreamPerson(ctx context.Context, u Upstream, login upstreamLogin, code string) (store.IDPerson, error) {
	m, err := p.upstreamMeta(ctx, u)
	if err != nil {
		return store.IDPerson{}, err
	}
	sec, err := p.upstreamSecret(u)
	if err != nil {
		return store.IDPerson{}, err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {login.Redirect},
		"code_verifier": {login.Verifier}, "client_id": {u.ClientID}, "client_secret": {sec}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, m.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := p.upstreamClient().Do(req)
	if err != nil {
		return store.IDPerson{}, fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	var tok struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		Desc    string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil || resp.StatusCode != http.StatusOK || tok.IDToken == "" {
		return store.IDPerson{}, fmt.Errorf("token endpoint: HTTP %d %s %s", resp.StatusCode, tok.Error, tok.Desc)
	}
	payload, err := m.keys.Verify(ctx, tok.IDToken)
	if err != nil {
		return store.IDPerson{}, err
	}
	if err := oidcrp.Check(payload, u.Issuer, []string{u.ClientID}, login.Nonce, p.cfg.Now()); err != nil {
		return store.IDPerson{}, err
	}
	var c upstreamClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return store.IDPerson{}, errors.New("unreadable ID token")
	}
	if c.AuthTime != nil && time.Unix(int64(*c.AuthTime), 0).Before(login.Started.Add(-upstreamFresh)) {
		return store.IDPerson{}, &refusal{msg: u.Title + " did not ask you to sign in again. Sign out there, or start again.",
			err: errors.New("the provider did not sign the person in again (auth_time)")}
	}
	email := strings.ToLower(strings.TrimSpace(c.Email))
	// The account linked already signs its person in, whatever address it shows now.
	people, err := p.cfg.Store.IDPeople(ctx)
	if err != nil {
		return store.IDPerson{}, err
	}
	for _, x := range people {
		if x.Links[u.Issuer] == c.Subject {
			if x.Disabled {
				return x, &refusal{msg: "Your account is disabled. Ask your administrator.", err: errors.New("disabled")}
			}
			return p.signedInVia(ctx, x)
		}
	}
	switch {
	case email == "":
		return store.IDPerson{}, &refusal{msg: u.Title + " did not tell us your address. Ask your administrator.", err: errors.New("no address in the ID token")}
	case c.unverified():
		return store.IDPerson{Email: email}, &refusal{msg: "Your address at " + u.Title + " is not verified.", err: errors.New("address not verified")}
	}
	if len(u.Domains) > 0 {
		at := strings.LastIndexByte(email, '@')
		if at < 0 || !slices.Contains(u.Domains, email[at+1:]) || (c.HostedDomain != "" && !slices.Contains(u.Domains, c.HostedDomain)) {
			return store.IDPerson{Email: email}, &refusal{msg: "This account is not one of this network's. Sign in with your work account.",
				err: errors.New("address outside the provider's domains")}
		}
	}
	x, err := p.cfg.Store.IDPersonByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		return store.IDPerson{Email: email}, &refusal{msg: "There is no account for " + email + " here. Ask your administrator to add you.",
			err: errors.New("no such person")}
	}
	if err != nil {
		return store.IDPerson{}, err
	}
	if x.Disabled {
		return x, &refusal{msg: "Your account is disabled. Ask your administrator.", err: errors.New("disabled")}
	}
	if x.Links[u.Issuer] != "" {
		// Linked to another account there: an address now someone else's signs no one in.
		return x, &refusal{msg: "Your account here is linked to another " + u.Title + " account. Ask your administrator.",
			err: errors.New("linked to another account at the provider")}
	}
	x, err = p.cfg.Store.UpdateIDPerson(ctx, x.ID, func(y store.IDPerson) (store.IDPerson, error) {
		if y.Links[u.Issuer] != "" && y.Links[u.Issuer] != c.Subject {
			return y, errors.New("linked to another account at the provider")
		}
		if y.Links == nil {
			y.Links = map[string]string{}
		}
		y.Links[u.Issuer] = c.Subject
		y.LastSignIn = p.cfg.Now()
		return y, nil
	})
	if err != nil {
		return store.IDPerson{}, err
	}
	p.cfg.Logf("identity provider: %s linked to their %s account", x.Email, u.Name)
	return x, nil
}

// upstreamFresh is how long before the sign-in started a provider's own sign-in may have been,
// when it says (auth_time).
const upstreamFresh = 5 * time.Minute

func (p *Provider) signedInVia(ctx context.Context, x store.IDPerson) (store.IDPerson, error) {
	return p.cfg.Store.UpdateIDPerson(ctx, x.ID, func(y store.IDPerson) (store.IDPerson, error) {
		y.LastSignIn = p.cfg.Now()
		return y, nil
	})
}

// UnlinkUpstream forgets the account at the provider with issuer that signs person in: their next
// sign-in through it links the account their address then names.
func (p *Provider) UnlinkUpstream(ctx context.Context, person, issuer string) error {
	_, err := p.cfg.Store.UpdateIDPerson(ctx, person, func(y store.IDPerson) (store.IDPerson, error) {
		if y.Links[issuer] == "" {
			return y, store.ErrNotFound
		}
		delete(y.Links, issuer)
		return y, nil
	})
	return err
}

// refusal is why a provider's sign-in signs no one in: msg for the person, err for the audit.
type refusal struct {
	msg string
	err error
}

func (e *refusal) Error() string { return e.err.Error() }

// capture keeps a handler's answer, to be passed on changed.
type capture struct {
	h    http.Header
	code int
	buf  bytes.Buffer
}

func (c *capture) Header() http.Header         { return c.h }
func (c *capture) Write(b []byte) (int, error) { return c.buf.Write(b) }
func (c *capture) WriteHeader(code int)        { c.code = code }
