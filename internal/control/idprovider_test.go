package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/id/idtest"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

const testIDName = "id.example.net"

// idNode starts a control node that is its network's identity provider and signs its devices in
// with it, keeping refresh tokens checked a millisecond after each sign-in or check.
func idNode(t *testing.T, ctx context.Context) (*Server, store.Store, *logLines) {
	t.Helper()
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	port := freeUDPPort(t)
	logs := &logLines{t: t}
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port,
		Endpoint: fmt.Sprintf("127.0.0.1:%d", port), Space: space, Store: st, Logf: logs.logf,
		ID: &IDConfig{Name: testIDName, Title: "Example", Key: signing, Disabled: true},
		OIDC: &OIDCConfig{Issuer: IDIssuer(testIDName), ClientID: "ento", ClientSecret: IDClientSecret(signing, "ento"),
			ApproveGroups: []string{"staff"}, AdminGroups: []string{"admins"}, AppRedirects: []string{"com.entowire.ento://signed-in"},
			TokenKey: make([]byte, 32), RefreshInterval: time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv, st, logs
}

// idCall posts JSON to the provider as its pages do.
func idCall(t *testing.T, srv *Server, path string, in any, want int) map[string]any {
	t.Helper()
	b, _ := json.Marshal(in)
	req := httptest.NewRequest("POST", "https://"+testIDName+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.id.Handler().ServeHTTP(w, req)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != want {
		t.Fatalf("%s: %d %s, want %d", path, w.Code, w.Body, want)
	}
	return out
}

func TestOwnIdentityProvider(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st, logs := idNode(t, ctx)
	if srv.people == nil || srv.people.kind() != "ento" {
		t.Fatal("the dashboard's people are not the provider's")
	}

	// An administrator invites Ana; she makes her passkey with the link.
	ana, link, created, err := invitePerson(ctx, srv.people, "Ana@Example.com", []string{"staff"})
	if err != nil || !created || !ana.Setup {
		t.Fatalf("invite: %+v %v %v", ana, created, err)
	}
	if _, _, _, err := invitePerson(ctx, srv.people, "ana@example.com", nil); err != nil {
		t.Fatalf("a new link for an account not set up: %v", err)
	}
	link, _ = srv.people.setupLink(ctx, ana.ID)
	a := idtest.New(t, testIDName)
	secret := link.Link[strings.Index(link.Link, "#")+1:]
	start := idCall(t, srv, "/setup/begin", map[string]any{"secret": secret}, 200)
	idCall(t, srv, "/setup/finish", map[string]any{"ceremony": start["ceremony"], "credential": a.Create(start["publicKey"].(map[string]any))}, 200)
	if _, _, _, err := invitePerson(ctx, srv.people, "ana@example.com", nil); err == nil {
		t.Fatal("a set-up account got a new link")
	}
	if ps, _ := srv.people.list(ctx); len(ps) != 1 || ps[0].Setup || ps[0].Email != "ana@example.com" {
		t.Fatalf("people: %+v", ps)
	}
	// Recovery from the command line: reset, then a new link (her passkey goes).
	if _, _, _, err := InvitePersonID(ctx, st, IDConfig{Name: testIDName, Key: srv.cfg.ID.Key}, "ana@example.com", nil, false, false); err == nil {
		t.Fatal("a link for a set-up account without --reset")
	}
	if _, l, _, err := InvitePersonID(ctx, st, IDConfig{Name: testIDName, Key: srv.cfg.ID.Key}, "ana@example.com", nil, true, false); err != nil || l.Link == "" {
		t.Fatalf("reset: %v", err)
	}
	link, _ = srv.people.setupLink(ctx, ana.ID)
	a = idtest.New(t, testIDName)
	secret = link.Link[strings.Index(link.Link, "#")+1:]
	start = idCall(t, srv, "/setup/begin", map[string]any{"secret": secret}, 200)
	idCall(t, srv, "/setup/finish", map[string]any{"ceremony": start["ceremony"], "credential": a.Create(start["publicKey"].(map[string]any))}, 200)

	// Her device signs in: the device grant, answered with her passkey on the provider's page.
	tok, _, _ := IssueToken(ctx, st, TokenOptions{Groups: []string{"laptops"}})
	srv.checkVersion(ctx)
	dev, res := enroll(t, tok, "laptop")
	var ls api.LoginStart
	if code := dev.do(t, "POST", api.PathLogin, nil, &ls); code != 200 || ls.UserCode == "" || !strings.HasPrefix(ls.VerificationURI, "https://"+testIDName+"/device") {
		t.Fatalf("login start: %d %+v", code, ls)
	}
	begin := idCall(t, srv, "/passkey/begin", map[string]any{"goal": "device", "user_code": ls.UserCode}, 200)
	idCall(t, srv, "/passkey/finish", map[string]any{"ceremony": begin["ceremony"], "credential": a.Get(begin["publicKey"].(map[string]any))}, 200)
	var status api.LoginStatus
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		dev.do(t, "GET", api.PathLogin, nil, &status)
		if status.State != "pending" {
			break
		}
	}
	if status.State != "done" || status.User != "ana@example.com" {
		t.Fatalf("login: %+v", status)
	}
	p := peerAt(t, st, res.Address)
	if p.User != ana.ID || !p.Approved || !p.Person.Active {
		t.Fatalf("after sign-in: %+v", p)
	}

	// Her groups change in the dashboard: the device follows at the next check.
	groups := []string{"staff", "ops"}
	if err := srv.people.update(ctx, ana.ID, api.UpdatePersonRequest{Groups: &groups}); err != nil {
		t.Fatal(err)
	}
	check(ctx, srv)
	if p := peerAt(t, st, res.Address); len(p.Person.Groups) != 2 {
		t.Fatalf("groups after the change: %+v", p.Person.Groups)
	}

	// Disabled (a leaver): withdrawn at the next check.
	off := false
	if err := srv.people.update(ctx, ana.ID, api.UpdatePersonRequest{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	check(ctx, srv)
	if p := peerAt(t, st, res.Address); p.Person.Approved || logs.count("action=sso_withdrawn") != 1 {
		t.Fatalf("a disabled person's device: %+v", p)
	}
	// What the provider did is in the network's audit.
	entries, _ := st.Audit(ctx, store.AuditQuery{Limit: 100})
	var seen []string
	for _, e := range entries {
		if strings.HasPrefix(e.Action, "id_") {
			seen = append(seen, e.Action)
		}
	}
	if !strings.Contains(strings.Join(seen, " "), "id_setup") || !strings.Contains(strings.Join(seen, " "), "id_device") {
		t.Fatalf("audit: %v", seen)
	}
}

func TestIDClientSecret(t *testing.T) {
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if IDClientSecret(k1, "ento") != IDClientSecret(k1, "ento") || IDClientSecret(k1, "ento") == IDClientSecret(k2, "ento") ||
		IDClientSecret(k1, "ento") == IDClientSecret(k1, "other") || len(IDClientSecret(k1, "ento")) < 40 {
		t.Fatal("client secrets are not derived per key and client")
	}
}

// The provider is served on the control node's overlay port 443 under its name, TLS ending there:
// to enrolled devices that are not suspended.
func TestOwnIdentityProviderServed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	certFile, keyFile, pool := selfSigned(t, t.TempDir(), testIDName)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	listen := l.Addr().String()
	l.Close()
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	signing, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	port := freeUDPPort(t)
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port, Endpoint: fmt.Sprintf("127.0.0.1:%d", port),
		Space: space, Store: st, Logf: t.Logf,
		ID:   &IDConfig{Name: testIDName, Key: signing, Cert: certFile, CertKey: keyFile, Listen: listen},
		OIDC: &OIDCConfig{Issuer: IDIssuer(testIDName), ClientID: "ento", ClientSecret: IDClientSecret(signing, "ento")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	tok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"laptops"}})
	srv.checkVersion(ctx)
	dev, res := enroll(t, tok, "laptop")
	c := uiClient(dev, testIDName, pool, srv.Address())
	resp, err := c.Get("https://" + testIDName + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	json.NewDecoder(resp.Body).Decode(&d)
	resp.Body.Close()
	if resp.StatusCode != 200 || d["issuer"] != IDIssuer(testIDName) {
		t.Fatalf("discovery over the tunnel: %d %v", resp.StatusCode, d)
	}

	// Also on the host address (for services beside the control nodes), with the same certificate.
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: testIDName, RootCAs: pool}}}
	if resp, err := hc.Get("https://" + listen + "/.well-known/openid-configuration"); err != nil || resp.StatusCode != 200 {
		t.Fatalf("on the host address: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}

	// Suspended: the connection ends before TLS.
	p := peerAt(t, st, res.Address)
	yes := true
	if _, err := st.UpdatePeer(ctx, p.ID, store.PeerUpdate{Suspended: &yes}); err != nil {
		t.Fatal(err)
	}
	c = uiClient(dev, testIDName, pool, srv.Address())
	c.Timeout = 3 * time.Second
	if resp, err := c.Get("https://" + testIDName + "/"); err == nil {
		resp.Body.Close()
		t.Fatal("a suspended device reached the provider")
	}
}

// A network whose sign-in moved to the control nodes: its devices' groups are added to the
// provider, never taken off the devices.
func TestOwnIdentityProviderKeepsDeviceGroups(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st, _ := idNode(t, ctx)
	tok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"servers", "kitchen"}})
	srv.checkVersion(ctx)
	_, res := enroll(t, tok, "box")
	srv.syncGroups(ctx)
	p := peerAt(t, st, res.Address)
	if len(p.Machine.Groups) != 2 {
		t.Fatalf("the device's groups after the sync: %v", p.Machine.Groups)
	}
	have, _ := srv.people.groups(ctx)
	for _, g := range p.Machine.Groups {
		if !slices.Contains(have, g) {
			t.Fatalf("%s not in the provider: %v", g, have)
		}
	}
}

// waitLogin waits for a device's sign-in to end and returns its status.
func waitLogin(t *testing.T, dev *testClient) api.LoginStatus {
	t.Helper()
	var status api.LoginStatus
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		dev.do(t, "GET", api.PathLogin, nil, &status)
		if status.State != "pending" && status.State != "exchanging" {
			break
		}
	}
	return status
}

// setUp answers a setup link with a new passkey, and returns the provider's answer.
func setUp(t *testing.T, srv *Server, link string, a *idtest.Authenticator) map[string]any {
	t.Helper()
	if !strings.HasPrefix(link, "https://"+testIDName+"/setup#") {
		t.Fatalf("not a setup link: %q", link)
	}
	sec := link[strings.Index(link, "#")+1:]
	start := idCall(t, srv, "/setup/begin", map[string]any{"secret": sec}, 200)
	return idCall(t, srv, "/setup/finish", map[string]any{"ceremony": start["ceremony"], "credential": a.Create(start["publicKey"].(map[string]any))}, 200)
}

// The first administrator's one invitation (0.57): their words name their account; the phone that
// redeems them gets, when it starts signing in, a setup link that ends in its sign-in; one passkey,
// and the phone is signed in as them. A computer the same way with its device code. Nobody else's
// sign-in binds an invited device.
func TestInvitation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st, _ := idNode(t, ctx)
	invite := func(email, host string) (*testClient, api.RedeemResponse, api.Person) {
		p, _, _, err := invitePerson(ctx, srv.people, email, []string{"admins", "staff"})
		if err != nil {
			t.Fatal(err)
		}
		tok, tk, _ := IssueToken(ctx, st, TokenOptions{Admin: true, Approve: true, Groups: []string{"admin"}})
		if err := InviteWithToken(ctx, st, tk, email); err != nil {
			t.Fatal(err)
		}
		srv.checkVersion(ctx)
		dev, res := enroll(t, tok, host)
		return dev, res, p
	}

	// The phone: its app's sign-in is a setup link; the passkey made, the app is opened with a code.
	phone, res, ana := invite("ana@example.com", "phone")
	var ls api.LoginStart
	if code := phone.do(t, "POST", api.PathLogin, api.LoginStartRequest{Redirect: "com.entowire.ento://signed-in"}, &ls); code != 200 {
		t.Fatalf("login start: %d", code)
	}
	anaKey := idtest.New(t, testIDName)
	out := setUp(t, srv, ls.AuthorizationURL, anaKey)
	back, _ := url.Parse(out["next"].(string))
	if back.Scheme != "com.entowire.ento" || back.Query().Get("code") == "" {
		t.Fatalf("after the setup: %v", out)
	}
	if code := phone.do(t, "POST", api.PathLoginCode, api.LoginCodeRequest{Code: back.Query().Get("code"), State: back.Query().Get("state")}, nil); code != 200 {
		t.Fatalf("login code: %d", code)
	}
	if st := waitLogin(t, phone); st.State != "done" {
		t.Fatalf("phone: %+v", st)
	}
	if p := peerAt(t, st, res.Address); p.User != ana.ID || !p.Admin {
		t.Fatalf("phone after the invitation: user %q admin %v", p.User, p.Admin)
	}

	// A computer: its device code's page is a setup link; once set up, the code is approved.
	laptop, res2, bo := invite("bo@example.com", "laptop")
	ls = api.LoginStart{}
	laptop.do(t, "POST", api.PathLogin, nil, &ls)
	out = setUp(t, srv, ls.VerificationURI, idtest.New(t, testIDName))
	if out["done"] != "device" {
		t.Fatalf("after the setup: %v", out)
	}
	if st := waitLogin(t, laptop); st.State != "done" {
		t.Fatalf("laptop: %+v", st)
	}
	if p := peerAt(t, st, res2.Address); p.User != bo.ID {
		t.Fatalf("laptop after the invitation: user %q", p.User)
	}

	// A device invited for Cy, signed in by Ana (the device's code typed on the provider's page):
	// refused, and the device is bound to nobody.
	tablet, res3, _ := invite("cy@example.com", "tablet")
	ls = api.LoginStart{}
	tablet.do(t, "POST", api.PathLogin, nil, &ls)
	if !strings.Contains(ls.VerificationURI, "/setup#") || ls.UserCode == "" {
		t.Fatalf("tablet start: %+v", ls)
	}
	begin := idCall(t, srv, "/passkey/begin", map[string]any{"goal": "device", "user_code": ls.UserCode}, 200)
	idCall(t, srv, "/passkey/finish", map[string]any{"ceremony": begin["ceremony"], "credential": anaKey.Get(begin["publicKey"].(map[string]any))}, 200)
	if st := waitLogin(t, tablet); st.State != "failed" || !strings.Contains(st.Error, "invited for another account") {
		t.Fatalf("tablet signed in by another: %+v", st)
	}
	if p := peerAt(t, st, res3.Address); p.User != "" {
		t.Fatalf("tablet bound to %q", p.User)
	}
}
