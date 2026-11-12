package id

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"entowire.com/ento/internal/id/idtest"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

const (
	testName   = "id.example.net"
	testSecret = "0123456789abcdef-secret"
	testApp    = "https://net.example.net/ui/callback"
)

type fixture struct {
	t     *testing.T
	p     *Provider
	st    *store.Memory
	h     http.Handler
	audit []string
	now   time.Time
}

func newFixture(t *testing.T) *fixture { return newFixtureWith(t, nil) }

func newFixtureWith(t *testing.T, change func(*Config)) *fixture {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, st: store.NewMemory(ipam.Space{Prefix: netip.MustParsePrefix("100.64.0.0/16")}), now: time.Now()}
	cfg := Config{Name: testName, Title: "Example", Key: k, Store: f.st,
		Clients: []Client{{ID: "ento", Name: "ento", Secret: testSecret, RedirectURIs: []string{testApp}, DeviceGrant: true}},
		Audit: func(_ *http.Request, action, target, result string) {
			f.audit = append(f.audit, action+" "+result+" "+target)
		},
		Now: func() time.Time { return f.now },
	}
	if change != nil {
		change(&cfg)
	}
	f.p, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.h = f.p.Handler()
	return f
}

func (f *fixture) do(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, req)
	return w
}

// call posts JSON as the pages do, and decodes the answer.
func (f *fixture) call(path string, in any, want int) map[string]any {
	f.t.Helper()
	b, _ := json.Marshal(in)
	req := httptest.NewRequest("POST", "https://"+testName+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 15)")
	w := f.do(req)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != want {
		f.t.Fatalf("%s: %d %s, want %d", path, w.Code, w.Body, want)
	}
	return out
}

func (f *fixture) form(path string, v url.Values) (int, map[string]any) {
	req := httptest.NewRequest("POST", "https://"+testName+path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := f.do(req)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// person makes a person with a passkey, through a setup link, and returns their authenticator.
func (f *fixture) person(email string, groups ...string) (store.IDPerson, *idtest.Authenticator) {
	f.t.Helper()
	ctx := context.Background()
	x, err := f.p.NewPerson(ctx, email, "Ana", "Pop", groups)
	if err != nil {
		f.t.Fatal(err)
	}
	link, _, err := f.p.SetupLink(ctx, x.ID, 0, "")
	if err != nil {
		f.t.Fatal(err)
	}
	a := idtest.New(f.t, testName)
	s := strings.SplitN(link, "#", 2)[1]
	start := f.call("/setup/begin", map[string]any{"secret": s}, 200)
	f.call("/setup/finish", map[string]any{"ceremony": start["ceremony"], "credential": a.Create(start["publicKey"].(map[string]any))}, 200)
	return x, a
}

var requestRE = regexp.MustCompile(`data-request="([^"]+)"`)

// authorize starts an authorization request and returns its ID.
func (f *fixture) authorize(challenge string) string {
	f.t.Helper()
	q := url.Values{"client_id": {"ento"}, "redirect_uri": {testApp}, "response_type": {"code"}, "scope": {"openid email profile groups"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"st"}, "nonce": {"nn"}}
	w := f.do(httptest.NewRequest("GET", "https://"+testName+"/authorize?"+q.Encode(), nil))
	if w.Code != 200 {
		f.t.Fatalf("authorize: %d %s", w.Code, w.Body)
	}
	m := requestRE.FindStringSubmatch(w.Body.String())
	if m == nil {
		f.t.Fatal("no request on the page")
	}
	return m[1]
}

// signIn runs a passkey sign-in for begin and returns the provider's answer.
func (f *fixture) signIn(a *idtest.Authenticator, begin map[string]any, want int) map[string]any {
	f.t.Helper()
	start := f.call("/passkey/begin", begin, 200)
	return f.call("/passkey/finish", map[string]any{"ceremony": start["ceremony"], "credential": a.Get(start["publicKey"].(map[string]any))}, want)
}

func pkce() (verifier, challenge string) {
	verifier = secret(32)
	s := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(s[:])
}

// verifyJWT checks an ID token with the provider's published key and returns its claims.
func (f *fixture) verifyJWT(tok string) map[string]any {
	f.t.Helper()
	w := f.do(httptest.NewRequest("GET", "https://"+testName+"/jwks", nil))
	var set struct{ Keys []map[string]string }
	json.Unmarshal(w.Body.Bytes(), &set)
	k := set.Keys[0]
	x, _ := base64.RawURLEncoding.DecodeString(k["x"])
	y, _ := base64.RawURLEncoding.DecodeString(k["y"])
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	parts := strings.Split(tok, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		f.t.Fatal("ID token signature does not verify")
	}
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	json.Unmarshal(body, &c)
	return c
}

func TestAuthorizationCode(t *testing.T) {
	f := newFixture(t)
	ana, a := f.person("Ana@Example.com", "admins")
	verifier, challenge := pkce()
	req := f.authorize(challenge)
	out := f.signIn(a, map[string]any{"goal": "authorize", "request": req}, 200)
	u, err := url.Parse(out["redirect"].(string))
	if err != nil || !strings.HasPrefix(out["redirect"].(string), testApp+"?") || u.Query().Get("state") != "st" || u.Query().Get("iss") != "https://"+testName {
		t.Fatalf("redirect %v", out["redirect"])
	}
	code := u.Query().Get("code")

	// A wrong verifier, client secret or redirect gets nothing, and the code is then used up.
	bad := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testApp}, "code_verifier": {"wrong" + verifier},
		"client_id": {"ento"}, "client_secret": {testSecret}}
	if st, out := f.form("/token", bad); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier: %d %v", st, out)
	}

	req = f.authorize(challenge)
	out = f.signIn(a, map[string]any{"goal": "authorize", "request": req}, 200)
	u, _ = url.Parse(out["redirect"].(string))
	code = u.Query().Get("code")
	if st, _ := f.form("/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testApp},
		"code_verifier": {verifier}, "client_id": {"ento"}, "client_secret": {"not the secret"}}); st != 401 {
		t.Fatalf("wrong client secret: %d", st)
	}
	st, tok := f.form("/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testApp},
		"code_verifier": {verifier}, "client_id": {"ento"}, "client_secret": {testSecret}})
	if st != 200 {
		t.Fatalf("token: %d %v", st, tok)
	}
	c := f.verifyJWT(tok["id_token"].(string))
	if c["sub"] != ana.ID || c["email"] != "ana@example.com" || c["nonce"] != "nn" || c["aud"] != "ento" || c["iss"] != "https://"+testName ||
		c["name"] != "Ana Pop" || !slices.Equal(anyStrings(c["groups"]), []string{"admins"}) {
		t.Fatalf("claims %v", c)
	}
	if st, _ := f.form("/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testApp},
		"code_verifier": {verifier}, "client_id": {"ento"}, "client_secret": {testSecret}}); st != 400 {
		t.Fatalf("a code used twice: %d", st)
	}

	// userinfo
	r := httptest.NewRequest("GET", "https://"+testName+"/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	if w := f.do(r); w.Code != 200 || !strings.Contains(w.Body.String(), "ana@example.com") {
		t.Fatalf("userinfo: %d %s", w.Code, w.Body)
	}

	// Refresh: new groups show; once disabled, refused with invalid_grant (what ento takes as
	// withdrawn access), and the person's passkey signs no one in.
	f.p.UpdatePerson(context.Background(), ana.ID, func(x store.IDPerson) (store.IDPerson, error) { x.Groups = []string{"admins", "ops"}; return x, nil })
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {"ento"}, "client_secret": {testSecret}}
	st, rt := f.form("/token", refresh)
	if st != 200 || !slices.Equal(anyStrings(f.verifyJWT(rt["id_token"].(string))["groups"]), []string{"admins", "ops"}) {
		t.Fatalf("refresh: %d %v", st, rt)
	}
	f.p.UpdatePerson(context.Background(), ana.ID, func(x store.IDPerson) (store.IDPerson, error) { x.Disabled = true; return x, nil })
	if st, out := f.form("/token", refresh); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("refresh of a disabled person: %d %v", st, out)
	}
	if w := f.do(r); w.Code != 401 {
		t.Fatalf("userinfo of a disabled person: %d", w.Code)
	}
	f.signIn(a, map[string]any{"goal": "authorize", "request": f.authorize(challenge)}, 403)
}

func anyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestAuthorizeRefusals(t *testing.T) {
	f := newFixture(t)
	_, challenge := pkce()
	base := url.Values{"client_id": {"ento"}, "redirect_uri": {testApp}, "response_type": {"code"}, "scope": {"openid"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"st"}}
	get := func(change func(url.Values)) *httptest.ResponseRecorder {
		q := url.Values{}
		for k, v := range base {
			q[k] = slices.Clone(v)
		}
		change(q)
		return f.do(httptest.NewRequest("GET", "https://"+testName+"/authorize?"+q.Encode(), nil))
	}
	// Unknown client or redirect: shown, never sent anywhere.
	for _, ch := range []func(url.Values){
		func(q url.Values) { q.Set("client_id", "other") },
		func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") },
	} {
		if w := get(ch); w.Code != 400 || w.Header().Get("Location") != "" {
			t.Fatalf("unknown client or redirect: %d %v", w.Code, w.Header())
		}
	}
	for name, ch := range map[string]func(url.Values){
		"invalid_request":           func(q url.Values) { q.Del("code_challenge") },
		"invalid_scope":             func(q url.Values) { q.Set("scope", "email") },
		"unsupported_response_type": func(q url.Values) { q.Set("response_type", "token") },
		"login_required":            func(q url.Values) { q.Set("prompt", "none") },
	} {
		w := get(ch)
		loc, _ := url.Parse(w.Header().Get("Location"))
		if w.Code != 302 || loc.Query().Get("error") != name || loc.Query().Get("state") != "st" {
			t.Fatalf("%s: %d %s", name, w.Code, w.Header().Get("Location"))
		}
	}
	// The pages' calls need JSON and the page's own origin.
	req := httptest.NewRequest("POST", "https://"+testName+"/passkey/begin", strings.NewReader(`{"purpose":"authorize"}`))
	req.Header.Set("Content-Type", "text/plain")
	if w := f.do(req); w.Code != 403 {
		t.Fatalf("a form post: %d", w.Code)
	}
	req = httptest.NewRequest("POST", "https://"+testName+"/passkey/begin", strings.NewReader(`{"purpose":"authorize"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if w := f.do(req); w.Code != 403 {
		t.Fatalf("a cross-site call: %d", w.Code)
	}
}

func TestPasskeyChecks(t *testing.T) {
	f := newFixture(t)
	_, a := f.person("ana@example.com")
	_, challenge := pkce()

	// No user verification: refused.
	a.NoUV = true
	f.signIn(a, map[string]any{"goal": "authorize", "request": f.authorize(challenge)}, 403)
	a.NoUV = false

	// Another site's assertion (another origin): refused.
	a.Origin = "https://evil.example"
	f.signIn(a, map[string]any{"goal": "authorize", "request": f.authorize(challenge)}, 403)
	a.Origin = "https://" + testName

	// An unknown passkey: refused.
	stranger := idtest.New(t, testName)
	stranger.Handle = []byte("someone")
	f.signIn(stranger, map[string]any{"goal": "authorize", "request": f.authorize(challenge)}, 403)

	// A counter that goes back (a copied passkey): refused.
	f.signIn(a, map[string]any{"goal": "authorize", "request": f.authorize(challenge)}, 200)
	a.Counter = 0
	f.signIn(a, map[string]any{"goal": "authorize", "request": f.authorize(challenge)}, 403)

	// A ceremony is used once.
	start := f.call("/passkey/begin", map[string]any{"goal": "authorize", "request": f.authorize(challenge)}, 200)
	a.Counter = 100
	cred := a.Get(start["publicKey"].(map[string]any))
	f.call("/passkey/finish", map[string]any{"ceremony": start["ceremony"], "credential": cred}, 200)
	f.call("/passkey/finish", map[string]any{"ceremony": start["ceremony"], "credential": cred}, 410)
}

func TestSetupLink(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	x, err := f.p.NewPerson(ctx, "bo@example.com", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.NewPerson(ctx, "BO@example.com", "", "", nil); !errors.Is(err, store.ErrExists) {
		t.Fatalf("same address twice: %v", err)
	}
	old, _, _ := f.p.SetupLink(ctx, x.ID, 0, "")
	link, exp, err := f.p.SetupLink(ctx, x.ID, time.Hour, "https://net.example.net/")
	if err != nil || !strings.HasPrefix(link, "https://"+testName+"/setup#") || !exp.Equal(f.now.Add(time.Hour)) {
		t.Fatalf("link %q %v %v", link, exp, err)
	}
	// A new link replaces the old one.
	f.call("/setup/begin", map[string]any{"secret": strings.SplitN(old, "#", 2)[1]}, 410)

	s := strings.SplitN(link, "#", 2)[1]
	a := idtest.New(t, testName)
	start := f.call("/setup/begin", map[string]any{"secret": s}, 200)
	if start["email"] != "bo@example.com" {
		t.Fatalf("setup shows %v", start["email"])
	}
	// A failed attempt leaves the link usable.
	bad := idtest.New(t, testName)
	bad.Origin = "https://evil.example"
	f.call("/setup/finish", map[string]any{"ceremony": start["ceremony"], "credential": bad.Create(start["publicKey"].(map[string]any))}, 400)
	start = f.call("/setup/begin", map[string]any{"secret": s}, 200)
	out := f.call("/setup/finish", map[string]any{"ceremony": start["ceremony"], "credential": a.Create(start["publicKey"].(map[string]any))}, 200)
	if out["next"] != "https://net.example.net/" {
		t.Fatalf("next %v", out["next"])
	}
	keys, _ := f.st.IDPasskeys(ctx, x.ID)
	if len(keys) != 1 || keys[0].Name != "Android" {
		t.Fatalf("passkeys %+v", keys)
	}
	// Used once; an account with a passkey gets no link.
	f.call("/setup/begin", map[string]any{"secret": s}, 410)
	if _, _, err := f.p.SetupLink(ctx, x.ID, 0, ""); !errors.Is(err, ErrSetUp) {
		t.Fatalf("link for an account with a passkey: %v", err)
	}
	// Deleting the person deletes their passkey: it signs no one in.
	if err := f.p.DeletePerson(ctx, x.ID); err != nil {
		t.Fatal(err)
	}
	_, challenge := pkce()
	f.signIn(a, map[string]any{"goal": "authorize", "request": f.authorize(challenge)}, 403)
}

func TestDeviceGrant(t *testing.T) {
	f := newFixture(t)
	ana, a := f.person("ana@example.com", "users")
	client := url.Values{"client_id": {"ento"}, "client_secret": {testSecret}}
	start := func() (string, string) {
		st, out := f.form("/device_authorization", url.Values{"client_id": {"ento"}, "client_secret": {testSecret}, "scope": {"openid email groups"}})
		if st != 200 || !strings.HasSuffix(out["verification_uri_complete"].(string), "user_code="+out["user_code"].(string)) {
			t.Fatalf("device authorization: %d %v", st, out)
		}
		return out["device_code"].(string), out["user_code"].(string)
	}
	poll := func(dc string) (int, map[string]any) {
		v := url.Values{"grant_type": {deviceGrantType}, "device_code": {dc}}
		for k, x := range client {
			v[k] = x
		}
		return f.form("/token", v)
	}

	// A typed code: approved with the passkey.
	dc, uc := start()
	if st, out := poll(dc); st != 400 || out["error"] != "authorization_pending" {
		t.Fatalf("pending: %d %v", st, out)
	}
	typed := strings.ToLower(strings.ReplaceAll(uc, "-", " "))
	if out := f.signIn(a, map[string]any{"goal": "device", "user_code": typed}, 200); out["done"] != "approved" {
		t.Fatalf("typed code: %v", out)
	}
	st, tok := poll(dc)
	if st != 200 || f.verifyJWT(tok["id_token"].(string))["sub"] != ana.ID || tok["refresh_token"] == nil {
		t.Fatalf("token: %d %v", st, tok)
	}
	if st, out := poll(dc); st != 400 || out["error"] != "expired_token" {
		t.Fatalf("a device code used twice: %d %v", st, out)
	}

	// A code from a link waits for the person's answer: declined, then accepted.
	dc, uc = start()
	out := f.signIn(a, map[string]any{"goal": "device", "user_code": uc, "from_link": true}, 200)
	if out["confirm"] == nil || out["done"] != nil {
		t.Fatalf("a code from a link was approved at once: %v", out)
	}
	if st, _ := poll(dc); st != 400 {
		t.Fatal("approved before the answer")
	}
	f.call("/device/answer", map[string]any{"confirm": out["confirm"], "accept": false}, 200)
	if st, out := poll(dc); st != 400 || out["error"] != "access_denied" {
		t.Fatalf("declined: %d %v", st, out)
	}
	dc, uc = start()
	out = f.signIn(a, map[string]any{"goal": "device", "user_code": uc, "from_link": true}, 200)
	f.call("/device/answer", map[string]any{"confirm": out["confirm"], "accept": true}, 200)
	if st, _ := poll(dc); st != 200 {
		t.Fatalf("accepted: %d", st)
	}
	f.call("/device/answer", map[string]any{"confirm": out["confirm"], "accept": true}, 410)

	// Unknown codes, and expiry.
	f.call("/passkey/begin", map[string]any{"goal": "device", "user_code": "BBBB-BBBB"}, 410)
	dc, _ = start()
	f.now = f.now.Add(deviceLifetime + time.Second)
	if st, out := poll(dc); st != 400 || out["error"] != "expired_token" {
		t.Fatalf("expired: %d %v", st, out)
	}
}

func TestDiscoveryAndPages(t *testing.T) {
	f := newFixture(t)
	w := f.do(httptest.NewRequest("GET", "https://"+testName+"/.well-known/openid-configuration", nil))
	var d map[string]any
	json.Unmarshal(w.Body.Bytes(), &d)
	if d["issuer"] != "https://"+testName || d["device_authorization_endpoint"] != "https://"+testName+"/device_authorization" {
		t.Fatalf("discovery %v", d)
	}
	for _, path := range []string{"/", "/device", "/setup", "/ento-id.js", "/ento-id.css"} {
		w := f.do(httptest.NewRequest("GET", "https://"+testName+path, nil))
		b, _ := io.ReadAll(w.Body)
		if w.Code != 200 || len(b) == 0 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
}

func TestUserCode(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c := newUserCode()
		if len(c) != 9 || c[4] != '-' || normalizeUserCode(strings.ToLower(c)) != c {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
	}
	if len(seen) < 195 {
		t.Fatalf("only %d different codes of 200", len(seen))
	}
}

// TestUnaskedExtensionOutputs: a client's extension output nobody asked for (Android's passkey manager
// always returns credProps) does not fail a passkey, which it did with the library's default.
func TestUnaskedExtensionOutputs(t *testing.T) {
	f := newFixture(t)
	if got := f.p.wa.Config.ExtensionsUnsolicitedOutputPolicy; got != protocol.UnsolicitedOutputPolicyIgnore {
		t.Fatalf("unsolicited extension outputs: policy %v, want ignore", got)
	}
	out := protocol.AuthenticationExtensionsClientOutputs{CredProps: &protocol.CredentialPropertiesOutput{}}
	if err := out.Verify(protocol.SessionExtensions{}, protocol.CreateCeremony, f.p.wa.Config.ExtensionsUnsolicitedOutputPolicy); err != nil {
		t.Fatalf("credProps unasked: %v", err)
	}
}
