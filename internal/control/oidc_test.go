package control

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

// fakeProvider implements the discovery, device authorization and token endpoints of an OpenID
// provider. The first device-code poll is answered with authorization_pending. Refresh tokens
// rotate strictly (each one works once), and Mode sets how refreshes are answered: "ok", "disabled"
// and "deleted" (refused with invalid_grant), "rauthy-disabled" and "rauthy-deleted" (Rauthy's
// answers: 401 Disabled, 404 NotFound), "down" (HTTP 503), "drop" (connection closed), "noid"
// (new tokens without an ID token), "nogroups" (an ID token without the groups claim).
type fakeProvider struct {
	*httptest.Server
	mu          sync.Mutex
	email       string
	login       string // preferred_username ("": none)
	groups      []string
	mode        string
	scope       string // of the last device authorization
	noOffline   bool   // refuse offline_access
	groupsScope bool   // list "groups" in discovery (Rauthy)
	valid       map[string]bool
	next        int
	refreshes   int
	challenge   string // PKCE, of the last browser sign-in
	key         ed25519.PrivateKey
	nonce       string // of the last browser sign-in, put into its ID token
	fresh       bool   // the last browser sign-in asked for a new sign-in (prompt=login, max_age=0)
	// token: how ID tokens are made: "" signed and valid; "forged" (another key), "expired",
	// "otheraud" (another client), "unsigned" (alg none).
	token string
}

func (f *fakeProvider) setToken(mode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.token = mode
}

// codeTokens answers a browser sign-in: its nonce, and auth_time now when it asked for a fresh
// sign-in, else an hour ago (the provider's open session). "stale" leaves the session's time. Locked.
func (f *fakeProvider) codeTokens(w http.ResponseWriter) {
	auth := time.Now().Add(-time.Hour).Unix()
	if f.fresh && f.token != "stale" {
		auth = time.Now().Unix()
	}
	c := map[string]any{"iss": f.URL, "sub": "user-42", "aud": "ento", "email": f.email, "groups": f.groups,
		"nonce": f.nonce, "auth_time": auth}
	if f.token == "othernonce" {
		c["nonce"] = "another"
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at", "token_type": "Bearer", "id_token": f.idToken(c)})
}

// idToken signs claims as the provider does (EdDSA, its published key), or as mode says. Locked.
func (f *fakeProvider) idToken(c map[string]any) string {
	now := time.Now().Unix()
	c["iat"], c["exp"] = now, now+300
	alg, key := "EdDSA", f.key
	switch f.token {
	case "expired":
		c["iat"], c["exp"] = now-3600, now-1800
	case "otheraud":
		c["aud"] = "someone-else"
	case "forged":
		_, key, _ = ed25519.GenerateKey(nil)
	case "unsigned":
		alg = "none"
	}
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": "k1"})
	b, _ := json.Marshal(c)
	signed := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	if alg == "none" {
		return signed + "."
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(signed)))
}

func (f *fakeProvider) set(mode string, groups []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode = mode
	if groups != nil {
		f.groups = groups
	}
}

// scopesSupported is what discovery lists: "groups" only for a provider like Rauthy (groupsScope).
func (f *fakeProvider) scopesSupported() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.groupsScope {
		return []string{"openid", "profile", "email", "groups", "offline_access"}
	}
	return []string{"openid", "profile", "email", "offline_access"}
}

func (f *fakeProvider) refreshCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshes
}

// tokens answers with an ID token of the current groups and a new refresh token. Called locked.
func (f *fakeProvider) tokens(w http.ResponseWriter, withID bool) {
	f.next++
	rt := fmt.Sprintf("rt-%d", f.next)
	f.valid[rt] = true
	out := map[string]string{"access_token": "at", "refresh_token": rt, "token_type": "Bearer"}
	if withID {
		c := map[string]any{"iss": f.URL, "sub": "user-42", "aud": "ento", "email": f.email, "groups": f.groups}
		if f.login != "" {
			c["preferred_username"] = f.login
		}
		if f.mode == "nogroups" {
			delete(c, "groups")
		}
		out["id_token"] = f.idToken(c)
	}
	_ = json.NewEncoder(w).Encode(out)
}

func fakeIdP(t *testing.T, email string, groups []string) *fakeProvider {
	var polls atomic.Int32
	_, key, _ := ed25519.GenerateKey(nil)
	f := &fakeProvider{email: email, groups: groups, mode: "ok", valid: map[string]bool{}, key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "kid": "k1",
			"alg": "EdDSA", "use": "sig", "x": base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}}})
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.URL, "token_endpoint": f.URL + "/token", "device_authorization_endpoint": f.URL + "/device",
			"authorization_endpoint": f.URL + "/authorize", "jwks_uri": f.URL + "/jwks",
			"scopes_supported": f.scopesSupported(),
		})
	})
	// The browser sign-in (authorization code with PKCE): the person is signed in at once.
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.challenge, f.nonce, f.fresh = q.Get("code_challenge"), q.Get("nonce"), q.Get("prompt") == "login" && q.Get("max_age") == "0"
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=code-1&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_secret") != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}
		f.mu.Lock()
		f.scope = r.Form.Get("scope")
		refuse := f.noOffline && strings.Contains(f.scope, "offline_access")
		f.mu.Unlock()
		if refuse {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_scope"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dev-123", "user_code": "ABCD-EFGH", "verification_uri": f.URL + "/activate",
			"verification_uri_complete": f.URL + "/activate?code=ABCD-EFGH", "expires_in": 60, "interval": 1,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		refused := func(desc string) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": desc})
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Form.Get("grant_type") == "authorization_code" {
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("client_secret") != "s3cret" || r.Form.Get("code") != "code-1" ||
				base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
				refused("bad code or verifier")
				return
			}
			f.codeTokens(w)
			return
		}
		if r.Form.Get("grant_type") == "refresh_token" {
			if r.Form.Get("client_secret") != "s3cret" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
				return
			}
			f.refreshes++
			switch f.mode {
			case "down":
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			case "drop":
				conn, _, _ := w.(http.Hijacker).Hijack()
				conn.Close()
				return
			case "disabled":
				refused("User disabled")
				return
			case "deleted":
				refused("Session not active")
				return
			case "rauthy-disabled": // Rauthy 0.37: not RFC 6749's invalid_grant
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{"timestamp": 1, "error": "Disabled", "message": "User is not enabled"})
				return
			case "rauthy-deleted":
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"timestamp": 1, "error": "NotFound", "message": "No results found"})
				return
			}
			rt := r.Form.Get("refresh_token")
			if !f.valid[rt] {
				refused("Invalid refresh token")
				return
			}
			delete(f.valid, rt)
			f.tokens(w, f.mode != "noid")
			return
		}
		if r.Form.Get("device_code") != "dev-123" {
			refused("")
			return
		}
		if polls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
			return
		}
		f.tokens(w, true)
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func TestSSOLogin(t *testing.T) {
	for _, tc := range []struct {
		name         string
		groups       []string
		devices      []string
		wantApproved bool
		wantAdmin    bool
	}{
		{"staff member is approved", []string{"/staff"}, []string{"laptops"}, true, false},
		{"admin on an admin device administers", []string{"/staff", "/admins"}, []string{"laptops", "admin"}, true, true},
		{"admin on another device does not", []string{"/staff", "/admins"}, []string{"laptops"}, true, false},
		{"outsider keeps only the device's own groups", []string{"/contractors"}, []string{"laptops"}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			idp := fakeIdP(t, "alice@example.com", tc.groups)
			space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
			st := store.NewMemory(space)
			key, _ := wgtypes.GeneratePrivateKey()
			port := freeUDPPort(t)
			srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port,
				Endpoint: fmt.Sprintf("127.0.0.1:%d", port), Space: space, Store: st, Logf: t.Logf,
				OIDC: &OIDCConfig{Issuer: idp.URL, ClientID: "ento", ClientSecret: "s3cret",
					ApproveGroups: []string{"staff"}, AdminGroups: []string{"admins"}}})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()

			// The device's invitation gives it a group, so it is in (0.43: groups decide); the sign-in
			// adds its person's groups, and their role where the device is in that role's group (0.54).
			tok, _, _ := IssueToken(ctx, st, TokenOptions{Groups: tc.devices})
			srv.checkVersion(ctx)
			dev, res := enroll(t, tok, "laptop")
			if !res.Approved {
				t.Fatal("a device with groups is not in")
			}

			var start api.LoginStart
			if code := dev.do(t, "POST", api.PathLogin, nil, &start); code != 200 {
				t.Fatalf("login start: HTTP %d", code)
			}
			// The bare address and the code, never the link with the code in it (I3).
			if start.UserCode != "ABCD-EFGH" || start.VerificationURI == "" || start.VerificationURIComplete != "" {
				t.Fatalf("unexpected login start %+v", start)
			}
			deadline := time.Now().Add(20 * time.Second)
			var status api.LoginStatus
			for time.Now().Before(deadline) {
				dev.do(t, "GET", api.PathLogin, nil, &status)
				if status.State != "pending" {
					break
				}
				time.Sleep(300 * time.Millisecond)
			}
			if status.State != "done" || status.User != "alice@example.com" {
				t.Fatalf("login did not complete: %+v", status)
			}
			var nm api.NetMap
			dev.do(t, "GET", api.PathNetMap, nil, &nm)
			if nm.Self.Approved != tc.wantApproved || nm.Self.Admin != tc.wantAdmin {
				t.Fatalf("approved=%v admin=%v, want %v/%v", nm.Self.Approved, nm.Self.Admin, tc.wantApproved, tc.wantAdmin)
			}
			peer, _ := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
			if peer.User != "user-42" || peer.UserName != "alice@example.com" || len(peer.Person.Groups) != len(tc.groups) || !peer.Person.Active {
				t.Fatalf("peer not bound to the user: %+v", peer)
			}
		})
	}
}

// ID tokens are verified against the provider's keys (I2): forged, unsigned, expired and other
// clients' tokens give nothing, at login, at refresh and at the dashboard's sign-in.
func TestIDTokenVerification(t *testing.T) {
	idp := fakeIdP(t, "alice@example.com", []string{"staff"})
	o := newOIDCProvider(OIDCConfig{Issuer: idp.URL, ClientID: "ento", ClientSecret: "s3cret"})
	ctx := context.Background()
	claims := func() map[string]any {
		return map[string]any{"iss": idp.URL, "sub": "user-42", "aud": "ento", "email": "alice@example.com", "nonce": "n1"}
	}
	idp.mu.Lock()
	good := idp.idToken(claims())
	idp.mu.Unlock()
	if c, err := o.verifyIDToken(ctx, good, "n1"); err != nil || c.Subject != "user-42" {
		t.Fatalf("a valid token: %+v %v", c, err)
	}
	if _, err := o.verifyIDToken(ctx, good, "n2"); err == nil {
		t.Error("another sign-in's nonce: accepted")
	}
	for _, mode := range []string{"forged", "expired", "otheraud", "unsigned"} {
		idp.setToken(mode)
		idp.mu.Lock()
		bad := idp.idToken(claims())
		idp.mu.Unlock()
		if _, err := o.verifyIDToken(ctx, bad, ""); err == nil {
			t.Errorf("%s token: accepted", mode)
		}
	}
	other := claims()
	other["iss"] = "https://elsewhere.example"
	idp.setToken("")
	idp.mu.Lock()
	bad := idp.idToken(other)
	idp.mu.Unlock()
	if _, err := o.verifyIDToken(ctx, bad, ""); err == nil {
		t.Error("another issuer's token: accepted")
	}

	// A refresh answered with a forged token changes nothing: an ordinary error, not a withdrawal.
	idp.setToken("forged")
	idp.mu.Lock()
	idp.valid["rt-x"] = true
	idp.mu.Unlock()
	c, _, err := o.refresh(ctx, "rt-x")
	var w *withdrawnError
	if err == nil || c != nil || errors.As(err, &w) {
		t.Fatalf("refresh with a forged token: %v %v", c, err)
	}
}
