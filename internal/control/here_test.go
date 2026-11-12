package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/id/idtest"
)

// hereCall calls the device's own sign-in as a browser on the device at addr would, through the
// listener at api.SignInPort.
func hereCall(t *testing.T, srv *Server, addr, method, path string, in any) *httptest.ResponseRecorder {
	t.Helper()
	var body *bytes.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	} else {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, hereOrigin(testIDName)+path, body)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = addr + ":50123"
	req = req.WithContext(context.WithValue(req.Context(), hereKey{}, true))
	w := httptest.NewRecorder()
	srv.id.Handler().ServeHTTP(w, req)
	return w
}

// hereSignIn signs a person in with their passkey on the device's own page, from the device at addr.
func hereSignIn(t *testing.T, srv *Server, addr string, a *idtest.Authenticator, then string, want int) map[string]any {
	t.Helper()
	w := hereCall(t, srv, addr, "POST", "/passkey/begin", map[string]any{"goal": "here", "then": then})
	var begin map[string]any
	json.Unmarshal(w.Body.Bytes(), &begin)
	if w.Code != 200 {
		if w.Code != want {
			t.Fatalf("begin: %d %s, want %d", w.Code, w.Body, want)
		}
		return begin
	}
	a.Origin = hereOrigin(testIDName)
	w = hereCall(t, srv, addr, "POST", "/passkey/finish", map[string]any{"ceremony": begin["ceremony"], "credential": a.Get(begin["publicKey"].(map[string]any))})
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != want {
		t.Fatalf("finish: %d %s, want %d", w.Code, w.Body, want)
	}
	return out
}

// TestHereSignIn: the device's own sign-in (constitution 2.5, 0.57). Only a device whose agent says
// it keeps the port to itself gets it; a person who signs in there is signed in on the device, any
// person on any device; the dashboard opens with the same sign-in.
func TestHereSignIn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st, logs := idNode(t, ctx)
	person := func(email string, groups ...string) (api.Person, *idtest.Authenticator) {
		p, link, _, err := invitePerson(ctx, srv.people, email, groups)
		if err != nil {
			t.Fatal(err)
		}
		a := idtest.New(t, testIDName)
		setUp(t, srv, link.Link, a)
		return p, a
	}
	ana, anaKey := person("ana@example.com", "admins", "staff")
	bo, boKey := person("bo@example.com", "staff")
	tok, _, _ := IssueToken(ctx, st, TokenOptions{Admin: true, Approve: true, Groups: []string{"admin"}})
	srv.checkVersion(ctx)
	laptop, res := enroll(t, tok, "laptop")

	// Its agent has not said it guards the port: a device code, and the page refuses it.
	var ls api.LoginStart
	laptop.do(t, "POST", api.PathLogin, api.LoginStartRequest{Here: true}, &ls)
	if ls.AuthorizationURL != "" || ls.UserCode == "" {
		t.Fatalf("unguarded start: %+v", ls)
	}
	if w := hereCall(t, srv, res.Address, "GET", "/here", nil); w.Code != 403 || !strings.Contains(w.Body.String(), "sudo ento agent login") {
		t.Fatalf("unguarded page: %d %s", w.Code, w.Body)
	}
	hereSignIn(t, srv, res.Address, anaKey, "", 410)

	// It says so at its check-in: the device's own sign-in, nothing to type.
	if code := laptop.do(t, "POST", api.PathCheckIn, api.CheckInRequest{HereGuard: true}, nil); code != 200 {
		t.Fatalf("check-in: %d", code)
	}
	ls = api.LoginStart{}
	laptop.do(t, "POST", api.PathLogin, api.LoginStartRequest{Here: true}, &ls)
	if ls.AuthorizationURL != hereOrigin(testIDName)+"/here" || ls.UserCode != "" {
		t.Fatalf("guarded start: %+v", ls)
	}
	// Not through the device's own port (the provider's name on 443): no device to sign in.
	idCall(t, srv, "/passkey/begin", map[string]any{"goal": "here"}, 410)

	out := hereSignIn(t, srv, res.Address, anaKey, "", 200)
	if out["done"] != "device" || !strings.HasSuffix(out["device"].(string), "laptop") {
		t.Fatalf("here: %v", out)
	}
	if s := waitLogin(t, laptop); s.State != "done" || s.User != "ana@example.com" {
		t.Fatalf("laptop: %+v", s)
	}
	if p := peerAt(t, st, res.Address); p.User != ana.ID || !p.Person.Active || !p.Admin {
		t.Fatalf("laptop after Ana: user %q active %v admin %v", p.User, p.Person.Active, p.Admin)
	}
	if !(logs.count("on the device's own sign-in") > 0) || !(logs.count("binding=new") > 0) {
		t.Fatal("no audit of the device's own sign-in")
	}

	// Bo signs in on it next, without anyone's approval but his passkey: Ana is signed out.
	hereSignIn(t, srv, res.Address, boKey, "", 200)
	if p := peerAt(t, st, res.Address); p.User != bo.ID || p.Admin {
		t.Fatalf("laptop after Bo: user %q admin %v", p.User, p.Admin)
	}
	if !(logs.count("binding=changed") > 0) {
		t.Fatal("no binding=changed")
	}

	// The dashboard: Ana's sign-in there opens it, on this device only, once.
	srv.cfg.AdminUI = "net.example.com"
	out = hereSignIn(t, srv, res.Address, anaKey, thenUI, 200)
	next, _ := url.Parse(out["next"].(string))
	if next.Host != "net.example.com" || next.Path != uiHerePath || next.Query().Get("t") == "" {
		t.Fatalf("then=ui: %v", out)
	}
	open := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		srv.uiHere(w, httptest.NewRequest("GET", next.String(), nil), peerAt(t, st, res.Address))
		return w
	}
	if w := open(); w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Set-Cookie"), uiCookie) {
		t.Fatalf("dashboard: %d %s", w.Code, w.Body)
	}
	if w := open(); w.Code != http.StatusBadRequest {
		t.Fatalf("ticket used twice: %d", w.Code)
	}

	// Another device that says nothing: refused, whoever signs in.
	tok2, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true})
	_, res2 := enroll(t, tok2, "server")
	hereSignIn(t, srv, res2.Address, anaKey, "", 410)
	if p := peerAt(t, st, res2.Address); p.User != "" {
		t.Fatalf("server bound to %q", p.User)
	}

	// Its agent stops saying so (an older version): refused again.
	laptop.do(t, "POST", api.PathCheckIn, api.CheckInRequest{}, nil)
	if w := hereCall(t, srv, res.Address, "GET", "/here", nil); w.Code != 403 {
		t.Fatalf("after the guard ended: %d", w.Code)
	}
}

// TestHereInvitation: the first administrator's invited computer sets the account up on its own
// sign-in page and is signed in with the same passkey.
func TestHereInvitation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st, _ := idNode(t, ctx)
	p, _, _, err := invitePerson(ctx, srv.people, "cy@example.com", []string{"admins", "staff"})
	if err != nil {
		t.Fatal(err)
	}
	tok, tk, _ := IssueToken(ctx, st, TokenOptions{Admin: true, Approve: true, Groups: []string{"admin"}})
	if err := InviteWithToken(ctx, st, tk, "cy@example.com"); err != nil {
		t.Fatal(err)
	}
	srv.checkVersion(ctx)
	laptop, res := enroll(t, tok, "laptop")
	laptop.do(t, "POST", api.PathCheckIn, api.CheckInRequest{HereGuard: true}, nil)
	var ls api.LoginStart
	laptop.do(t, "POST", api.PathLogin, api.LoginStartRequest{Here: true}, &ls)
	prefix := hereOrigin(testIDName) + "/setup#"
	if !strings.HasPrefix(ls.AuthorizationURL, prefix) {
		t.Fatalf("invited start: %+v", ls)
	}
	a := idtest.New(t, testIDName)
	a.Origin = hereOrigin(testIDName)
	sec := strings.TrimPrefix(ls.AuthorizationURL, prefix)
	var start map[string]any
	json.Unmarshal(hereCall(t, srv, res.Address, "POST", "/setup/begin", map[string]any{"secret": sec}).Body.Bytes(), &start)
	w := hereCall(t, srv, res.Address, "POST", "/setup/finish", map[string]any{"ceremony": start["ceremony"], "credential": a.Create(start["publicKey"].(map[string]any))})
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 200 || out["done"] != "device" {
		t.Fatalf("setup: %d %s", w.Code, w.Body)
	}
	if s := waitLogin(t, laptop); s.State != "done" {
		t.Fatalf("laptop: %+v", s)
	}
	if got := peerAt(t, st, res.Address); got.User != p.ID || !got.Admin {
		t.Fatalf("laptop: user %q admin %v", got.User, got.Admin)
	}
}
