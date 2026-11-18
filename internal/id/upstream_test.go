package id

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"entowire.com/ento/internal/store"
)

// fakeUpstream is an outside OpenID Connect provider: its discovery, keys and token endpoint. The
// test says what each code's ID token holds; the token endpoint checks the client, the redirect
// and the PKCE verifier as a real one would.
type fakeUpstream struct {
	t     *testing.T
	srv   *httptest.Server
	key   *ecdsa.PrivateKey
	mu    sync.Mutex
	codes map[string]fakeCode
	// auto, if set, signs in at once whoever comes to the authorization endpoint, as these claims
	// (the browser test: the person's own sign-in there is the provider's business).
	auto map[string]any
}

type fakeCode struct {
	claims    map[string]any
	redirect  string
	challenge string
}

const fakeClient, fakeSecret = "fake-client", "fake-secret"

func newFakeUpstream(t *testing.T) *fakeUpstream {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u := &fakeUpstream{t: t, key: k, codes: map[string]fakeCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": u.srv.URL, "authorization_endpoint": u.srv.URL + "/auth",
			"token_endpoint": u.srv.URL + "/token", "jwks_uri": u.srv.URL + "/jwks"})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		b := func(n []byte) string { return base64.RawURLEncoding.EncodeToString(n) }
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
			"x": b(k.X.FillBytes(make([]byte, 32))), "y": b(k.Y.FillBytes(make([]byte, 32)))}}})
	})
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		u.mu.Lock()
		auto := u.auto
		u.mu.Unlock()
		if auto == nil || q.Get("client_id") != fakeClient || q.Get("response_type") != "code" {
			http.Error(w, "not here", http.StatusBadRequest)
			return
		}
		now := time.Now()
		claims := map[string]any{"iss": u.srv.URL, "aud": fakeClient, "nonce": q.Get("nonce"), "iat": now.Unix(),
			"exp": now.Add(5 * time.Minute).Unix(), "auth_time": now.Unix()}
		for k, v := range auto {
			claims[k] = v
		}
		code := secret(12)
		u.mu.Lock()
		u.codes[code] = fakeCode{claims: claims, redirect: q.Get("redirect_uri"), challenge: q.Get("code_challenge")}
		u.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		u.mu.Lock()
		c, ok := u.codes[r.PostForm.Get("code")]
		delete(u.codes, r.PostForm.Get("code"))
		u.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || r.PostForm.Get("client_id") != fakeClient || r.PostForm.Get("client_secret") != fakeSecret ||
			r.PostForm.Get("redirect_uri") != c.redirect || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": u.sign(c.claims), "token_type": "Bearer", "access_token": "x"})
	})
	u.srv = httptest.NewServer(mux)
	t.Cleanup(u.srv.Close)
	return u
}

func (u *fakeUpstream) sign(claims map[string]any) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	signed := enc(map[string]string{"alg": "ES256", "kid": "k1", "typ": "JWT"}) + "." + enc(claims)
	h := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, u.key, h[:])
	if err != nil {
		u.t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

// newUpstreamFixture is a provider with the fake upstream as its outside provider "fake".
func newUpstreamFixture(t *testing.T, domains ...string) (*fixture, *fakeUpstream) {
	up := newFakeUpstream(t)
	f := newFixtureWith(t, func(c *Config) { c.UpstreamHTTP = up.srv.Client() })
	u := Upstream{Name: "fake", Title: "Fake", Issuer: up.srv.URL, ClientID: fakeClient,
		Secret: SealUpstreamSecret(f.p.cfg.Key, up.srv.URL, fakeSecret), Domains: domains}
	if err := f.st.SetSetting(context.Background(), SettingUpstreams, EncodeUpstreams([]Upstream{u})); err != nil {
		t.Fatal(err)
	}
	return f, up
}

// viaUpstream signs in through the fake provider for goal, its ID token holding claims (and the
// sign-in's own issuer, audience, nonce and times unless claims say otherwise), and returns the
// finish's answer, checked against want.
func (f *fixture) viaUpstream(up *fakeUpstream, goal map[string]any, claims map[string]any, want int) map[string]any {
	f.t.Helper()
	goal["provider"] = "fake"
	out := f.call("/upstream/begin", goal, 200)
	to, err := url.Parse(out["url"].(string))
	if err != nil || !strings.HasPrefix(out["url"].(string), up.srv.URL+"/auth?") {
		f.t.Fatalf("begin sends the browser to %v", out["url"])
	}
	q := to.Query()
	if q.Get("client_id") != fakeClient || q.Get("redirect_uri") != "https://"+testName+UpstreamCallback || q.Get("code_challenge_method") != "S256" {
		f.t.Fatalf("authorization request: %v", q)
	}
	full := map[string]any{"iss": up.srv.URL, "aud": fakeClient, "nonce": q.Get("nonce"),
		"iat": f.now.Unix(), "exp": f.now.Add(5 * time.Minute).Unix(), "auth_time": f.now.Unix()}
	for k, v := range claims {
		if v == nil {
			delete(full, k)
		} else {
			full[k] = v
		}
	}
	code := secret(12)
	up.mu.Lock()
	up.codes[code] = fakeCode{claims: full, redirect: q.Get("redirect_uri"), challenge: q.Get("code_challenge")}
	up.mu.Unlock()
	return f.call("/upstream/finish", map[string]any{"state": q.Get("state"), "code": code}, want)
}

func TestUpstreamSignIn(t *testing.T) {
	f, up := newUpstreamFixture(t)
	ctx := context.Background()
	ana, err := f.p.NewPerson(ctx, "ana@example.com", "Ana", "Pop", []string{"admins"})
	if err != nil {
		t.Fatal(err)
	}

	// The page offers the provider.
	w := f.do(httptest.NewRequest("GET", "https://"+testName+"/account", nil))
	if !strings.Contains(w.Body.String(), `data-providers="[{&#34;name&#34;:&#34;fake&#34;,&#34;title&#34;:&#34;Fake&#34;}]"`) {
		t.Fatalf("the page does not offer the provider: %s", w.Body)
	}

	// An application's sign-in, the first through the provider: Ana's address links her account there.
	verifier := "a-verifier-that-is-long-enough-for-pkce-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	req := f.authorize(base64.RawURLEncoding.EncodeToString(sum[:]))
	out := f.viaUpstream(up, map[string]any{"goal": "authorize", "request": req},
		map[string]any{"sub": "g-ana", "email": "Ana@Example.com", "email_verified": true}, 200)
	if !strings.HasPrefix(out["redirect"].(string), testApp+"?code=") || out["goal"].(map[string]any)["goal"] != "authorize" {
		t.Fatalf("authorize via the provider: %v", out)
	}
	if x, _ := f.st.IDPerson(ctx, ana.ID); x.Links[up.srv.URL] != "g-ana" || x.LastSignIn.IsZero() {
		t.Fatalf("not linked: %+v", x)
	}
	if !f.audited("id_signin ok ana@example.com client=ento with provider") {
		t.Fatalf("audit: %v", f.audit)
	}

	// The account page, by the same account showing another address now: still Ana.
	out = f.viaUpstream(up, map[string]any{"goal": "account"}, map[string]any{"sub": "g-ana", "email": "ana.pop@other.example"}, 200)
	if out["redirect"] != "/account" {
		t.Fatalf("account via the provider: %v", out)
	}

	// Another account showing Ana's address signs no one in: hers is linked to g-ana.
	f.viaUpstream(up, map[string]any{"goal": "account"}, map[string]any{"sub": "g-mallory", "email": "ana@example.com", "email_verified": true}, 403)
	if !f.audited("linked to another account at the provider") {
		t.Fatalf("audit: %v", f.audit)
	}

	// Refused: an address nobody has here, an unverified one, none, a token for another sign-in,
	// one for another client, a stale sign-in there.
	refused := []map[string]any{
		{"sub": "g-bo", "email": "bo@example.com"},
		{"sub": "g-cy", "email": "cy@example.com", "email_verified": false},
		{"sub": "g-dee"},
		{"sub": "g-ana", "nonce": "another"},
		{"sub": "g-ana", "aud": "another-client"},
		{"sub": "g-ana", "auth_time": f.now.Add(-time.Hour).Unix()},
		{"sub": "g-ana", "iss": "https://elsewhere.example"},
	}
	for _, c := range refused {
		f.viaUpstream(up, map[string]any{"goal": "account"}, c, 403)
	}

	// A disabled person is refused, linked or not.
	if _, err := f.st.UpdateIDPerson(ctx, ana.ID, func(y store.IDPerson) (store.IDPerson, error) { y.Disabled = true; return y, nil }); err != nil {
		t.Fatal(err)
	}
	f.viaUpstream(up, map[string]any{"goal": "account"}, map[string]any{"sub": "g-ana"}, 403)

	// A state is used once.
	f.call("/upstream/finish", map[string]any{"state": "unknown", "code": "x"}, 410)
}

// TestUpstreamDomains: a provider with domains links only addresses there (and Google's hd).
func TestUpstreamDomains(t *testing.T) {
	f, up := newUpstreamFixture(t, "example.com")
	ctx := context.Background()
	if _, err := f.p.NewPerson(ctx, "ana@example.com", "Ana", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.NewPerson(ctx, "bo@outside.example", "Bo", "", nil); err != nil {
		t.Fatal(err)
	}
	out := f.call("/upstream/begin", map[string]any{"goal": "account", "provider": "fake"}, 200)
	if !strings.Contains(out["url"].(string), "hd=example.com") {
		t.Fatalf("one domain is passed as Google's hint: %v", out["url"])
	}
	f.viaUpstream(up, map[string]any{"goal": "account"}, map[string]any{"sub": "g-bo", "email": "bo@outside.example"}, 403)
	f.viaUpstream(up, map[string]any{"goal": "account"}, map[string]any{"sub": "g-ana", "email": "ana@example.com", "hd": "other.example"}, 403)
	f.viaUpstream(up, map[string]any{"goal": "account"}, map[string]any{"sub": "g-ana", "email": "ana@example.com", "hd": "example.com"}, 200)
}

// TestUpstreamPolicy: the provider is a way of signing in like the others: a policy that leaves it
// out refuses it, and it counts as a way in only for people it can sign in.
func TestUpstreamPolicy(t *testing.T) {
	f, up := newUpstreamFixture(t, "example.com")
	ctx := context.Background()
	x, err := f.p.NewPerson(ctx, "ana@example.com", "Ana", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	ups, _ := Upstreams(ctx, f.st)
	if !setUpWith(x, ups) {
		t.Fatal("a person in the provider's domain has a way in")
	}
	if setUpWith(store.IDPerson{Email: "bo@outside.example"}, ups) {
		t.Fatal("a person outside the provider's domains has none")
	}
	if err := f.st.SetSetting(ctx, SettingDefaultSignin, MethodPasskey); err != nil {
		t.Fatal(err)
	}
	f.viaUpstream(up, map[string]any{"goal": "account"}, map[string]any{"sub": "g-ana", "email": "ana@example.com"}, 403)
	if !f.audited("provider is not allowed for this account") {
		t.Fatalf("audit: %v", f.audit)
	}
}

func setUpWith(x store.IDPerson, ups []Upstream) bool {
	for _, m := range Has(x, 0, ups) {
		if m == MethodProvider {
			return true
		}
	}
	return false
}

func (f *fixture) audited(part string) bool {
	for _, a := range f.audit {
		if strings.Contains(a, part) {
			return true
		}
	}
	return false
}
