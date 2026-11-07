package control

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

// Signing in on the admin interface (0.49): it opens for the person signed in on the device in ento,
// not for anyone else or with nobody signed in there, and closes when they sign out of ento.
func TestAdminInterfaceSignIn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	idp := fakeIdP(t, "alice@example.com", []string{"admins"})
	certFile, keyFile, pool := selfSigned(t, t.TempDir(), "net.example.test")
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port, Endpoint: fmt.Sprintf("127.0.0.1:%d", port),
		Space: space, Store: st, Logf: t.Logf, Version: "test",
		OIDC:    &OIDCConfig{Issuer: idp.URL, ClientID: "ento", ClientSecret: "s3cret"},
		AdminUI: "net.example.test", AdminUICert: certFile, AdminUIKey: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	tok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Admin: true})
	srv.checkVersion(ctx)
	dev, res := enroll(t, tok, "laptop")
	p, _ := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
	ui := uiClient(dev, "net.example.test", pool, srv.Address())
	ui.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	browser := &http.Client{CheckRedirect: ui.CheckRedirect} // to the provider, outside the tunnel

	// signIn walks the browser through the sign-in and returns the callback's status.
	signIn := func() int {
		resp, err := ui.Get("https://net.example.test/ui/signin")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			return resp.StatusCode
		}
		at, err := browser.Get(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		at.Body.Close()
		back, err := ui.Get(at.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		back.Body.Close()
		return back.StatusCode
	}
	var state uiState
	if code := uiDo(t, ui, "GET", "/ui/session", nil, nil, &state); code != 200 || !state.SignIn || state.Person != "" {
		t.Fatalf("session state: %d %+v", code, state)
	}
	// Nobody signed in on the device: no sign-in.
	if code := signIn(); code != http.StatusForbidden {
		t.Fatalf("nobody on the device: HTTP %d", code)
	}
	// Someone else signed in on the device: the provider's person is not them.
	on, other, alice := true, "user-7", "user-42"
	name := "bob@example.com"
	if _, err := st.UpdatePeer(ctx, p.ID, store.PeerUpdate{User: &other, UserName: &name, PersonActive: &on, PersonApproved: &on}); err != nil {
		t.Fatal(err)
	}
	if code := signIn(); code != http.StatusForbidden {
		t.Fatalf("another person on the device: HTTP %d", code)
	}
	if code := uiDo(t, ui, "GET", api.PathInfo, nil, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("API after a refused sign-in: %d", code)
	}
	// The same person: the page opens.
	name = "alice@example.com"
	if _, err := st.UpdatePeer(ctx, p.ID, store.PeerUpdate{User: &alice, UserName: &name}); err != nil {
		t.Fatal(err)
	}
	if code := uiDo(t, ui, "GET", "/ui/session", nil, nil, &state); code != 200 || state.Person != "alice@example.com" {
		t.Fatalf("session state: %d %+v", code, state)
	}
	// The same person without a role, on a device that is an admin itself: nothing (I1): a sign-in
	// carries the person's rights, never the device's.
	if code := signIn(); code != http.StatusForbidden {
		t.Fatalf("a person without a role on an admin device: HTTP %d", code)
	}
	// An operator person.
	if _, err := st.UpdatePeer(ctx, p.ID, store.PeerUpdate{PersonOperator: &on, PersonGroups: &[]string{"operators"}}); err != nil {
		t.Fatal(err)
	}
	// The provider's open session, not a fresh sign-in: refused; so are a forged token (I2) and
	// another sign-in's nonce.
	for mode, want := range map[string]int{"stale": http.StatusForbidden, "forged": http.StatusBadGateway, "othernonce": http.StatusBadGateway} {
		idp.setToken(mode)
		if code := signIn(); code != want {
			t.Fatalf("%s: HTTP %d, want %d", mode, code, want)
		}
	}
	idp.setToken("")
	if code := signIn(); code != http.StatusFound {
		t.Fatalf("sign-in: HTTP %d", code)
	}
	idp.mu.Lock()
	fresh := idp.fresh
	idp.mu.Unlock()
	if !fresh {
		t.Fatal("the sign-in did not ask the provider for a fresh one (prompt=login, max_age=0)")
	}
	if code := uiDo(t, ui, "GET", api.PathInfo, nil, nil, nil); code != 200 {
		t.Fatalf("API after signing in: %d", code)
	}
	// It acts with the operator's rights, not the admin device's.
	if code := uiDo(t, ui, "POST", api.PathTokens, uiChange, api.CreateTokenRequest{Admin: true, TTLSeconds: 600}, nil); code != http.StatusForbidden {
		t.Fatalf("an operator's session makes an admin token: HTTP %d", code)
	}
	// They sign out of ento on the device: the page closes with it.
	off := false
	if _, err := st.UpdatePeer(ctx, p.ID, store.PeerUpdate{PersonActive: &off}); err != nil {
		t.Fatal(err)
	}
	if code := uiDo(t, ui, "GET", api.PathInfo, nil, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("API after signing out of ento: %d", code)
	}
}
