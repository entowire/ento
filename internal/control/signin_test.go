package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

const (
	testSignInClient   = "keycloak"
	testSignInSecret   = "a-client-secret-of-at-least-32-characters"
	testSignInRedirect = "https://id.example.test/realms/team/broker/ento/endpoint"
	testVerifier       = "a-pkce-code-verifier-of-enough-length-0123456789"
)

// verifyJWT checks an ES256 token and returns its claims.
func verifyJWT(tok string, pub *ecdsa.PublicKey) (map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWS")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, errors.New("bad signature encoding")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, errors.New("bad signature")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	return claims, json.Unmarshal(body, &claims)
}

type signInTest struct {
	t   *testing.T
	ctx context.Context
	st  *store.Memory
	s   *Server
	key *ecdsa.PrivateKey
}

func newSignInTest(t *testing.T) *signInTest {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	space, err := ipam.New(netip.MustParsePrefix("100.72.0.0/16"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory(space)
	ck, _ := wgtypes.GeneratePrivateKey()
	if _, err := st.RegisterControlNode(context.Background(), store.ControlNode{Name: "c1", PublicKey: ck.PublicKey(), Endpoint: "192.0.2.1:51821", LastSeen: time.Now()}); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{Store: st, AdminUI: "net.example.test", Logf: t.Logf,
		SignIn: &SignInConfig{ClientID: testSignInClient, ClientSecret: testSignInSecret, RedirectURIs: []string{testSignInRedirect}, Key: key}}}
	return &signInTest{t: t, ctx: context.Background(), st: st, s: s, key: key}
}

// device enrolls a device; with a user, its person layer opened at since.
func (x *signInTest) device(name, user string, since time.Time) store.Peer {
	x.t.Helper()
	if _, _, err := IssueToken(x.ctx, x.st, TokenOptions{Approve: true}); err != nil {
		x.t.Fatal(err)
	}
	toks, _ := x.st.ActiveTokens(x.ctx, time.Now())
	k, _ := wgtypes.GeneratePrivateKey()
	p, err := x.st.Redeem(x.ctx, toks[len(toks)-1].TempAddress, k.PublicKey(), name, "linux", time.Now(), nil)
	if err != nil {
		x.t.Fatal(err)
	}
	if user != "" {
		login, mail, yes := user, user+"@example.test", true
		if p, err = x.st.UpdatePeer(x.ctx, p.ID, store.PeerUpdate{User: &user, UserName: &mail, UserLogin: &login, LoginAt: &since,
			PersonApproved: &yes, PersonActive: &yes, PersonSince: &since, PersonActivityAt: &since}); err != nil {
			x.t.Fatal(err)
		}
	}
	return p
}

func challenge(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorize sends the device's browser to the authorization endpoint and returns the redirect's
// query (nil when it is not a redirect to the client).
func (x *signInTest) authorize(from netip.Addr, mod func(url.Values)) (int, url.Values) {
	x.t.Helper()
	q := url.Values{"client_id": {testSignInClient}, "redirect_uri": {testSignInRedirect}, "response_type": {"code"},
		"scope": {"openid profile"}, "state": {"st-1"}, "nonce": {"n-1"}, "code_challenge": {challenge(testVerifier)}, "code_challenge_method": {"S256"}}
	if mod != nil {
		mod(q)
	}
	r := httptest.NewRequest("GET", "https://net.example.test/device/authorize?"+q.Encode(), nil)
	r.RemoteAddr = netip.AddrPortFrom(from, 40000).String()
	w := httptest.NewRecorder()
	x.s.adminUIHandler().ServeHTTP(w, r)
	loc := w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.HasPrefix(loc, testSignInRedirect+"?") {
		return w.Code, nil
	}
	u, _ := url.Parse(loc)
	return w.Code, u.Query()
}

func (x *signInTest) token(form url.Values, basic bool) (int, map[string]any) {
	x.t.Helper()
	if form.Get("grant_type") == "" {
		form.Set("grant_type", "authorization_code")
	}
	if !basic {
		form.Set("client_id", testSignInClient)
		if form.Get("client_secret") == "" {
			form.Set("client_secret", testSignInSecret)
		}
	}
	r := httptest.NewRequest("POST", "https://net.example.test/device/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "100.72.9.9:40000" // the identity provider's server: any address
	if basic {
		r.SetBasicAuth(url.QueryEscape(testSignInClient), url.QueryEscape(testSignInSecret))
	}
	w := httptest.NewRecorder()
	x.s.adminUIHandler().ServeHTTP(w, r)
	var out map[string]any
	json.NewDecoder(w.Body).Decode(&out)
	return w.Code, out
}

func TestSignInDiscovery(t *testing.T) {
	x := newSignInTest(t)
	for path, want := range map[string]string{"/device/.well-known/openid-configuration": `"issuer":"https://net.example.test/device"`, "/device/jwks": `"alg":"ES256"`} {
		r := httptest.NewRequest("GET", "https://net.example.test"+path, nil)
		r.RemoteAddr = "100.72.200.1:1234" // not even a device: these are public within the network
		w := httptest.NewRecorder()
		x.s.adminUIHandler().ServeHTTP(w, r)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: HTTP %d %s", path, w.Code, w.Body)
		}
	}
	// The key in the JWKS verifies the provider's tokens.
	jwk := x.s.signInJWK()
	xb, _ := base64.RawURLEncoding.DecodeString(jwk["x"])
	yb, _ := base64.RawURLEncoding.DecodeString(jwk["y"])
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	tok, err := x.s.signJWT(map[string]any{"sub": "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if c, err := verifyJWT(tok, pub); err != nil || c["sub"] != "alice" {
		t.Fatalf("token from the JWKS key: %v %v", c, err)
	}
}

func TestSignInVouchesForTheDevicesPerson(t *testing.T) {
	x := newSignInTest(t)
	laptop := x.device("laptop", "alice", time.Now().Add(-time.Hour))
	code, q := x.authorize(laptop.Address, nil)
	if q == nil || q.Get("code") == "" || q.Get("state") != "st-1" || q.Get("iss") != "https://net.example.test/device" {
		t.Fatalf("authorize: HTTP %d %v", code, q)
	}
	// The wrong verifier, redirect URI or secret get nothing, and do not use the code up... except
	// that a code is single use: a failed redemption consumes it too.
	if c, out := x.token(url.Values{"code": {q.Get("code")}, "redirect_uri": {testSignInRedirect}, "code_verifier": {testVerifier}, "client_secret": {"wrong-secret-wrong-secret-wrong-secret"}}, false); c != http.StatusUnauthorized || out["error"] != "invalid_client" {
		t.Errorf("wrong secret: HTTP %d %v", c, out)
	}
	c, out := x.token(url.Values{"code": {q.Get("code")}, "redirect_uri": {testSignInRedirect}, "code_verifier": {testVerifier}}, true)
	if c != http.StatusOK {
		t.Fatalf("token: HTTP %d %v", c, out)
	}
	claims, err := verifyJWT(out["id_token"].(string), &x.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "alice" || claims["aud"] != testSignInClient || claims["nonce"] != "n-1" || claims["preferred_username"] != "alice" ||
		claims["iss"] != "https://net.example.test/device" || claims["email"] != "alice@example.test" {
		t.Errorf("claims: %v", claims)
	}
	if c, out := x.token(url.Values{"code": {q.Get("code")}, "redirect_uri": {testSignInRedirect}, "code_verifier": {testVerifier}}, false); c != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Errorf("code used twice: HTTP %d %v", c, out)
	}
	// PKCE and the redirect URI are bound to the code.
	for name, f := range map[string]url.Values{
		"wrong verifier": {"redirect_uri": {testSignInRedirect}, "code_verifier": {"another-verifier-another-verifier-another-v"}},
		"wrong redirect": {"redirect_uri": {testSignInRedirect + "x"}, "code_verifier": {testVerifier}},
	} {
		_, q := x.authorize(laptop.Address, nil)
		f.Set("code", q.Get("code"))
		if c, out := x.token(f, false); c != http.StatusBadRequest || out["error"] != "invalid_grant" {
			t.Errorf("%s: HTTP %d %v", name, c, out)
		}
	}
	// The person's session ends between the browser's visit and the redemption: no token.
	_, q = x.authorize(laptop.Address, nil)
	off := false
	x.st.UpdatePeer(x.ctx, laptop.ID, store.PeerUpdate{PersonActive: &off})
	if c, out := x.token(url.Values{"code": {q.Get("code")}, "redirect_uri": {testSignInRedirect}, "code_verifier": {testVerifier}}, false); c != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Errorf("person signed out before redemption: HTTP %d %v", c, out)
	}
}

func TestSignInRefuses(t *testing.T) {
	x := newSignInTest(t)
	now := time.Now()
	denied := func(name string, from netip.Addr, mod func(url.Values)) {
		t.Helper()
		code, q := x.authorize(from, mod)
		if q == nil || q.Get("error") != "access_denied" || q.Get("code") != "" || q.Get("state") != "st-1" {
			t.Errorf("%s: HTTP %d %v, want access_denied", name, code, q)
		}
	}
	server := x.device("server", "", time.Time{})
	denied("device without a person", server.Address, nil)
	denied("not a device", netip.MustParseAddr("100.72.250.250"), nil)
	closed := x.device("closed", "bob", now.Add(-time.Hour))
	off := false
	x.st.UpdatePeer(x.ctx, closed.ID, store.PeerUpdate{PersonActive: &off})
	denied("person's session closed", closed.Address, nil)
	susp := x.device("susp", "carol", now.Add(-time.Hour))
	yes := true
	x.st.UpdatePeer(x.ctx, susp.ID, store.PeerUpdate{Suspended: &yes})
	denied("suspended", susp.Address, nil)

	// Stale: opened 7 hours ago, never used since.
	old := x.device("old", "dave", now.Add(-7*time.Hour))
	denied("stale session", old.Address, nil)
	// A sign-in an hour ago in the same session keeps it fresh; one in an earlier session does not.
	x.st.RecordSignIn(x.ctx, old.ID, old.Person.Since.Add(-time.Hour), now.Add(-time.Hour))
	denied("sign-in of an earlier session", old.Address, nil)
	x.st.RecordSignIn(x.ctx, old.ID, old.Person.Since, now.Add(-time.Hour))
	if _, q := x.authorize(old.Address, nil); q.Get("code") == "" {
		t.Errorf("used an hour ago: %v, want a code", q)
	}
	// Each sign-in slides the window: it was just recorded.
	if last, _ := x.st.LastSignIn(x.ctx, old.ID, old.Person.Since); time.Since(last) > time.Minute {
		t.Errorf("last sign-in %s, want now", last)
	}

	// Malformed requests from a good device: sent back with the error, never with a code.
	ok := x.device("ok", "erin", now)
	// A fresh sign-in asked for (a confirmation): the client's own sign-in, not the device.
	denied("prompt=login", ok.Address, func(q url.Values) { q.Set("prompt", "login") })
	denied("prompt=consent login", ok.Address, func(q url.Values) { q.Set("prompt", "consent login") })
	denied("max_age=0", ok.Address, func(q url.Values) { q.Set("max_age", "0") })
	if _, q := x.authorize(ok.Address, func(q url.Values) { q.Set("prompt", "none") }); q.Get("code") == "" {
		t.Errorf("prompt=none: %v, want a code", q)
	}
	for name, mod := range map[string]func(url.Values){
		"no PKCE":    func(q url.Values) { q.Del("code_challenge") },
		"plain PKCE": func(q url.Values) { q.Set("code_challenge_method", "plain") },
		"no openid":  func(q url.Values) { q.Set("scope", "profile") },
		"implicit":   func(q url.Values) { q.Set("response_type", "id_token") },
		"long nonce": func(q url.Values) { q.Set("nonce", strings.Repeat("n", 600)) },
	} {
		if _, q := x.authorize(ok.Address, mod); q == nil || q.Get("error") == "" || q.Get("code") != "" {
			t.Errorf("%s: %v, want an error", name, q)
		}
	}
	// Unknown client or redirect address: shown, never redirected.
	for name, mod := range map[string]func(url.Values){
		"other client":   func(q url.Values) { q.Set("client_id", "other") },
		"other redirect": func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") },
	} {
		if code, q := x.authorize(ok.Address, mod); code != http.StatusBadRequest || q != nil {
			t.Errorf("%s: HTTP %d %v, want 400 without a redirect", name, code, q)
		}
	}
}

func TestSignInLinkedDeviceRefused(t *testing.T) {
	x := newSignInTest(t)
	// A device admitted through a link, with a person signed in at home: not this network's person.
	tk, _ := wgtypes.GeneratePrivateKey()
	rec, err := x.st.CreateToken(x.ctx, store.Token{PublicKey: tk.PublicKey(), PresharedKey: tk, Authority: "home", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	k, _ := wgtypes.GeneratePrivateKey()
	p, err := x.st.Redeem(x.ctx, rec.TempAddress, k.PublicKey(), "visitor", "linux", time.Now(),
		&store.Grant{Authority: "home", UserName: "frank@example.test", Hostname: "home-laptop", Until: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	// Even with a person layer as a sign-in would give one (it cannot: M6), it is not vouched for.
	user, now, yes := "frank", time.Now(), true
	if p, err = x.st.UpdatePeer(x.ctx, p.ID, store.PeerUpdate{User: &user, UserLogin: &user, PersonApproved: &yes, PersonActive: &yes, PersonSince: &now}); err != nil {
		t.Fatal(err)
	}
	if p.Authority == "" {
		t.Fatal("not admitted through a link")
	}
	if _, q := x.authorize(p.Address, nil); q == nil || q.Get("error") != "access_denied" {
		t.Errorf("linked device: %v, want access_denied", q)
	}
}

func TestSignInRateLimit(t *testing.T) {
	x := newSignInTest(t)
	p := x.device("busy", "gina", time.Now())
	for i := 0; i < signInPerMinute; i++ {
		if _, q := x.authorize(p.Address, nil); q.Get("code") == "" {
			t.Fatalf("authorization %d refused: %v", i+1, q)
		}
	}
	if _, q := x.authorize(p.Address, nil); q.Get("error") != "access_denied" {
		t.Errorf("authorization over the limit: %v", q)
	}
}

func TestParseSignInKey(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p8, _ := x509.MarshalPKCS8PrivateKey(k)
	sec1, _ := x509.MarshalECPrivateKey(k)
	for name, der := range map[string][]byte{"pkcs8": p8, "sec1": sec1} {
		got, err := ParseSignInKey(base64.StdEncoding.EncodeToString(der) + "\n")
		if err != nil || !got.Equal(k) {
			t.Errorf("%s: %v", name, err)
		}
	}
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKCS8PrivateKey(k384)
	for name, in := range map[string]string{"P-384": base64.StdEncoding.EncodeToString(der384), "not base64": "%%%", "empty": ""} {
		if _, err := ParseSignInKey(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
