package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

// selfSigned writes a certificate for names and its key into dir and returns their paths.
func selfSigned(t *testing.T, dir string, names ...string) (string, string, *x509.CertPool) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(k)
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
	pool := x509.NewCertPool()
	c, _ := x509.ParseCertificate(der)
	pool.AddCert(c)
	return cert, key, pool
}

// uiClient is an HTTPS client of the admin interface through a test device's tunnel, with a cookie
// jar like a browser's.
func uiClient(dev *testClient, name string, pool *x509.CertPool, ctl netip.Addr) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Timeout: 20 * time.Second, Jar: jar, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: name, RootCAs: pool},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dev.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ctl, 443))
		},
	}}
}

func uiDo(t *testing.T, c *http.Client, method, path string, hdr map[string]string, in, out any) int {
	t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "https://net.example.test"+path, body)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode
}

// uiChange are the headers the interface's own page sends with a change.
var uiChange = map[string]string{"X-Ento-UI": "1", "Origin": "https://net.example.test", "Sec-Fetch-Site": "same-origin"}

// pairCode asks for the page's code, as the page does when it has no session.
func pairCode(t *testing.T, ui *http.Client) string {
	t.Helper()
	var st uiState
	if code := uiDo(t, ui, "POST", "/ui/session", uiChange, nil, &st); code != 200 || st.State != "pending" || st.Code == "" {
		t.Fatalf("page code: HTTP %d %+v", code, st)
	}
	return st.Code
}

// approve approves a page's code from dev, as `ento admin ui CODE` does, and returns the status.
func approve(t *testing.T, dev *testClient, code string) int {
	t.Helper()
	return dev.do(t, "POST", api.PathAdminUI, api.ApproveAdminUIRequest{Code: code}, nil)
}

// openSession opens a session of the interface for dev: the page shows a code, dev approves it.
func openSession(t *testing.T, dev *testClient, ui *http.Client) {
	t.Helper()
	if code := approve(t, dev, pairCode(t, ui)); code != 200 {
		t.Fatalf("approve the page: HTTP %d", code)
	}
}

// startUITest starts a control node with the admin interface and an identity provider behind
// port 443 (a TLS echo server), and enrolls an admin device and a plain one.
func startUITest(t *testing.T, ctx context.Context) (srv *Server, st store.Store, pool *x509.CertPool, admin, user *testClient) {
	t.Helper()
	certFile, keyFile, pool := selfSigned(t, t.TempDir(), "net.example.test", "id.example.test")
	idpCert, _ := tls.LoadX509KeyPair(certFile, keyFile)
	idp, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{idpCert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idp.Close() })
	go func() {
		for {
			c, err := idp.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	mem := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	srv, err = Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port, Endpoint: fmt.Sprintf("127.0.0.1:%d", port),
		Space: space, Store: mem, Logf: t.Logf, Version: "test",
		OIDC:    &OIDCConfig{Issuer: "https://id.example.test/x", ClientID: "c", ClientSecret: "s", ConnectTo: []string{idp.Addr().String()}},
		AdminUI: "net.example.test", AdminUICert: certFile, AdminUIKey: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	adminTok, _, _ := IssueToken(ctx, mem, TokenOptions{Approve: true, Admin: true})
	userTok, _, _ := IssueToken(ctx, mem, TokenOptions{Approve: true, Groups: []string{"staff"}})
	srv.checkVersion(ctx)
	admin, _ = enroll(t, adminTok, "admin-laptop")
	user, _ = enroll(t, userTok, "phone")
	signInRoles(t, mem)
	return srv, mem, pool, admin, user
}

// The interface answers in a session of the device only, opened when the device approves the code
// the page shows with its key: nothing secret leaves the page, and no program without the key can
// open one. Sessions open administration only.
func TestAdminInterfaceSessions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st, pool, admin, user := startUITest(t, ctx)
	ctl := srv.Address()
	ui := uiClient(admin, "net.example.test", pool, ctl)

	// The page loads, its API does not answer without a session. It carries the version that served
	// it (the script tells the person when the control plane runs another), and browsers ask again
	// every time.
	if code := uiDo(t, ui, "GET", "/", nil, nil, nil); code != 200 {
		t.Fatalf("page: %d", code)
	}
	if resp, err := ui.Get("https://net.example.test/"); err != nil {
		t.Fatal(err)
	} else {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		v := srv.cfg.Version
		if resp.Header.Get("Cache-Control") != "no-cache" || !strings.Contains(string(b), `<meta name="ento-version" content="`+v+`">`) ||
			!strings.Contains(string(b), `src="app.js?v=`+v+`"`) {
			t.Fatalf("page: Cache-Control %q, version %q missing", resp.Header.Get("Cache-Control"), v)
		}
	}
	if code := uiDo(t, ui, "GET", api.PathInfo, nil, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("API without a session: %d", code)
	}
	var addr api.AdminUI
	if code := admin.do(t, "GET", api.PathAdminUI, nil, &addr); code != 200 || addr.URL != "https://net.example.test/" {
		t.Fatalf("interface address: %d %+v", code, addr)
	}

	// The page shows a code, the same until approved.
	code := pairCode(t, ui)
	if again := pairCode(t, ui); again != code {
		t.Fatalf("the page's code changed: %s, then %s", code, again)
	}
	var state uiState
	if c := uiDo(t, ui, "GET", "/ui/session", nil, nil, &state); c != 200 || state.State != "pending" || state.Code != code {
		t.Fatalf("pending state: %d %+v", c, state)
	}

	// A program on the admin device without its key approves nothing (nor administers).
	admin.unsigned = true
	if c := approve(t, admin, code); c != http.StatusUnauthorized {
		t.Fatalf("unsigned approval: %d", c)
	}
	if c := admin.do(t, "POST", api.PathTokens, api.CreateTokenRequest{Admin: true, Approve: true}, nil); c != http.StatusUnauthorized {
		t.Fatalf("unsigned admin token: %d", c)
	}
	admin.unsigned = false
	if c := approve(t, admin, "ZZZZ-ZZZZ"); c != http.StatusNotFound {
		t.Fatalf("a code no page shows: %d", c)
	}
	// Another admin device cannot approve this device's page.
	otherTok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Admin: true})
	srv.checkVersion(ctx)
	other, _ := enroll(t, otherTok, "other-laptop")
	signInRoles(t, st)
	if c := approve(t, other, code); c != http.StatusNotFound {
		t.Fatalf("approved by another device: %d", c)
	}

	// Approved (typed in lower case, without the dash): the page opens, and the approval names it.
	var approved api.ApprovedAdminUI
	if c := admin.do(t, "POST", api.PathAdminUI, api.ApproveAdminUIRequest{Code: strings.ToLower(strings.ReplaceAll(code, "-", ""))}, &approved); c != 200 ||
		!strings.Contains(approved.Browser, "Go-http-client") || approved.OpenedAt == "" {
		t.Fatalf("approve: %d %+v", c, approved)
	}
	if c := uiDo(t, ui, "GET", "/ui/session", nil, nil, &state); c != 200 || state.State != "open" {
		t.Fatalf("state after approval: %d %+v", c, state)
	}
	var info api.AdminInfo
	if c := uiDo(t, ui, "GET", api.PathInfo, nil, nil, &info); c != 200 || info.Self.Hostname != "z-admin-laptop" {
		t.Fatalf("API in a session: %d %+v", c, info.Self)
	}
	if c := approve(t, admin, code); c != http.StatusNotFound {
		t.Fatalf("a code approved twice: %d", c)
	}

	// A session opens administration only: not approvals, sign-in or credentials for linked networks.
	for _, call := range []struct{ method, path string }{
		{"POST", api.PathAdminUI}, {"POST", api.PathLogin}, {"POST", api.PathLinks + "/acme/credential"},
	} {
		if c := uiDo(t, ui, call.method, call.path, uiChange, map[string]string{"code": "X", "public_key": "x"}, nil); c != http.StatusForbidden {
			t.Fatalf("%s %s through a session: %d", call.method, call.path, c)
		}
	}

	// Another device can use neither the session cookie nor its own page approved by this device.
	otherUI := uiClient(other, "net.example.test", pool, ctl)
	u, _ := url.Parse("https://net.example.test/")
	cookies := ui.Jar.Cookies(u)
	otherUI.Jar.SetCookies(u, cookies)
	if c := uiDo(t, otherUI, "GET", api.PathInfo, nil, nil, nil); c != http.StatusUnauthorized {
		t.Fatalf("another device's session cookie: %d", c)
	}
	otherJar, _ := cookiejar.New(nil)
	otherUI.Jar = otherJar
	if c := approve(t, admin, pairCode(t, otherUI)); c != http.StatusNotFound {
		t.Fatalf("another device's page approved by this one: %d", c)
	}
	_ = user

	// The page's own refresh is not use; a request of the person is.
	hash := uiHash(cookies[0].Value)
	quiet := time.Now().Add(-20 * time.Minute)
	if err := st.TouchUISession(ctx, hash, quiet); err != nil {
		t.Fatal(err)
	}
	if c := uiDo(t, ui, "GET", api.PathPeers, map[string]string{uiAutoHeader: "1"}, nil, nil); c != 200 {
		t.Fatalf("refresh: %d", c)
	}
	if u, _ := st.UISession(ctx, hash, time.Now()); u.LastUsed.After(quiet.Add(time.Second)) {
		t.Fatal("the page's own refresh kept the session alive")
	}
	if c := uiDo(t, ui, "GET", api.PathPeers, nil, nil, nil); c != 200 {
		t.Fatalf("request: %d", c)
	}
	if u, _ := st.UISession(ctx, hash, time.Now()); !u.LastUsed.After(quiet.Add(time.Minute)) {
		t.Fatal("a request did not count as use")
	}

	// Unused for longer than the idle limit, the session ends.
	if err := st.TouchUISession(ctx, hash, time.Now().Add(-uiSessionIdle-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if c := uiDo(t, ui, "GET", api.PathInfo, nil, nil, nil); c != http.StatusUnauthorized {
		t.Fatalf("idle session: %d", c)
	}

	// Signing out ends a session.
	openSession(t, admin, ui)
	if c := uiDo(t, ui, "DELETE", "/ui/session", uiChange, nil, nil); c != http.StatusNoContent {
		t.Fatalf("sign out: %d", c)
	}
	if c := uiDo(t, ui, "GET", api.PathInfo, nil, nil, nil); c != http.StatusUnauthorized {
		t.Fatalf("API after signing out: %d", c)
	}

	// Pages waiting for approval are limited per device.
	jarless := &http.Client{Timeout: ui.Timeout, Transport: ui.Transport}
	n := 0
	for ; n < 2*uiMaxPending; n++ {
		if c := uiDo(t, jarless, "POST", "/ui/session", uiChange, nil, nil); c == http.StatusTooManyRequests {
			break
		}
	}
	if n != uiMaxPending {
		t.Fatalf("pending pages: %d accepted", n)
	}

	// A device that is no longer an admin loses its session's answers at once.
	openJar, _ := cookiejar.New(nil)
	ui.Jar = openJar
	srv.cfg.Store.ExpireUISessions(ctx, time.Now().Add(time.Hour)) // the pending pages above
	openSession(t, admin, ui)
	var self api.PeerInfo
	if c := other.do(t, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, info.Self.ID), api.UpdatePeerRequest{Admin: ptr(false)}, &self); c != 200 || self.Admin {
		t.Fatalf("take admin away: %d", c)
	}
	// Its admin person now only views here, so the page still opens, but the session has ended.
	if c := uiDo(t, ui, "GET", api.PathInfo, nil, nil, nil); c != http.StatusUnauthorized {
		t.Fatalf("session of a former admin device: %d", c)
	}
	// Made an admin again, it does not get the old session back.
	if c := other.do(t, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, info.Self.ID), api.UpdatePeerRequest{Admin: ptr(true)}, nil); c != 200 {
		t.Fatalf("give admin back: %d", c)
	}
	if c := uiDo(t, ui, "GET", api.PathInfo, nil, nil, nil); c != http.StatusUnauthorized {
		t.Fatalf("old session after the role came back: %d", c)
	}
}

func TestAdminInterface(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	certFile, keyFile, pool := selfSigned(t, t.TempDir(), "net.example.test", "id.example.test")

	// The identity provider behind port 443 for every other name: a TLS echo server.
	idpCert, _ := tls.LoadX509KeyPair(certFile, keyFile)
	idp, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{idpCert}})
	if err != nil {
		t.Fatal(err)
	}
	defer idp.Close()
	go func() {
		for {
			c, err := idp.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port, Endpoint: fmt.Sprintf("127.0.0.1:%d", port),
		Space: space, Store: st, Logf: t.Logf, Version: "test",
		OIDC:    &OIDCConfig{Issuer: "https://id.example.test/x", ClientID: "c", ClientSecret: "s", ConnectTo: []string{idp.Addr().String()}},
		AdminUI: "net.example.test", AdminUICert: certFile, AdminUIKey: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	adminTok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Admin: true})
	userTok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"staff"}})
	srv.checkVersion(ctx)
	admin, _ := enroll(t, adminTok, "admin-laptop")
	user, userRes := enroll(t, userTok, "phone")
	signInRoles(t, st)
	ctl := srv.Address()
	ui := uiClient(admin, "net.example.test", pool, ctl)
	change := uiChange
	openSession(t, admin, ui)

	// The page and the overview, for an admin device.
	req, _ := http.NewRequest("GET", "https://net.example.test/", nil)
	resp, err := ui.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(page), "<title>Dashboard") {
		t.Fatalf("page: %d", resp.StatusCode)
	}
	var info api.AdminInfo
	if code := uiDo(t, ui, "GET", api.PathInfo, nil, nil, &info); code != 200 || info.Self.Hostname != "z-admin-laptop" || info.Self.ReportedHostname != "admin-laptop" || len(info.Controls) != 1 || info.Version != "test" {
		t.Fatalf("info: %d %+v", code, info)
	}

	// Another device is no administrator: its connection ends before TLS, so it gets neither data
	// nor the page, not even the interface's certificate.
	for _, path := range []string{api.PathInfo, "/", "/app.js"} {
		req, _ := http.NewRequest("GET", "https://net.example.test"+path, nil)
		if resp, err := uiClient(user, "net.example.test", pool, ctl).Do(req); err == nil {
			resp.Body.Close()
			t.Fatalf("%s for a plain device: %d, want no connection", path, resp.StatusCode)
		}
	}

	// Changes only from the interface itself.
	var peers []api.PeerInfo
	uiDo(t, ui, "GET", api.PathPeers, nil, nil, &peers)
	var phone api.PeerInfo
	for _, p := range peers {
		if p.Hostname == "z-phone" {
			phone = p
		}
	}
	path := fmt.Sprintf("%s/%d", api.PathPeers, phone.ID)
	suspend := api.UpdatePeerRequest{Suspended: ptr(true)}
	for name, hdr := range map[string]map[string]string{
		"no header":        {},
		"other origin":     {"X-Ento-UI": "1", "Origin": "https://evil.example"},
		"cross-site fetch": {"X-Ento-UI": "1", "Sec-Fetch-Site": "cross-site"},
	} {
		if code := uiDo(t, ui, "PATCH", path, hdr, suspend, nil); code != http.StatusForbidden {
			t.Fatalf("%s: change accepted (%d)", name, code)
		}
	}

	// Suspension: no approval restores it, only resuming.
	var p api.PeerInfo
	if code := uiDo(t, ui, "PATCH", path, change, suspend, &p); code != 200 || !p.Suspended || p.Approved {
		t.Fatalf("suspend: %d %+v", code, p)
	}
	if code := uiDo(t, ui, "PATCH", path, change, api.UpdatePeerRequest{Approved: ptr(true)}, nil); code != http.StatusConflict {
		t.Fatalf("approve while suspended: %d", code)
	}
	// A suspended device is no WireGuard peer of the control node any more: it reaches nothing.
	if err := srv.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	cutCtx, cutCancel := context.WithTimeout(ctx, 3*time.Second)
	req, _ = http.NewRequestWithContext(cutCtx, "GET", fmt.Sprintf("http://%s%s?since=0", ctl, api.PathNetMap), nil)
	if resp, err := user.http.Do(req); err == nil {
		resp.Body.Close()
		t.Fatalf("the suspended device still reached the control plane: HTTP %d", resp.StatusCode)
	}
	cutCancel()
	var resumed api.PeerInfo
	if code := uiDo(t, ui, "PATCH", path, change, api.UpdatePeerRequest{Suspended: ptr(false), Approved: ptr(true)}, &resumed); code != 200 || resumed.Suspended || !resumed.Approved {
		t.Fatalf("resume: %d %+v", code, resumed)
	}
	if err := srv.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	var nm api.NetMap
	if code := user.do(t, "GET", api.PathNetMap+"?since=0", nil, &nm); code != 200 || !nm.Self.Approved || nm.Self.Suspended {
		t.Fatalf("network map after resuming: %d %+v", code, nm.Self)
	}
	if code := uiDo(t, ui, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, info.Self.ID), change, suspend, nil); code != http.StatusBadRequest {
		t.Fatalf("an admin suspended itself: %d", code)
	}

	// Tokens: created with their creator, listed, revoked once.
	var created api.CreateTokenResponse
	if code := uiDo(t, ui, "POST", api.PathTokens, change, api.CreateTokenRequest{Groups: []string{"staff"}, TTLSeconds: 600}, &created); code != 201 ||
		created.Token == "" {
		t.Fatalf("create token: %d", code)
	}
	var toks []api.TokenInfo
	uiDo(t, ui, "GET", api.PathTokens, nil, nil, &toks)
	var mine *api.TokenInfo
	for i := range toks {
		if toks[i].CreatedBy != "" && strings.Contains(toks[i].CreatedBy, "admin-laptop") {
			mine = &toks[i]
		}
	}
	if mine == nil {
		t.Fatalf("new token not listed with its creator: %+v", toks)
	}
	tokPath := fmt.Sprintf("%s/%d", api.PathTokens, mine.ID)
	if code := uiDo(t, ui, "DELETE", tokPath, change, nil, nil); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}
	if code := uiDo(t, ui, "DELETE", tokPath, change, nil, nil); code != http.StatusNotFound {
		t.Fatalf("revoke twice: %d", code)
	}

	// Wrong name in the Host header.
	req, _ = http.NewRequest("GET", "https://net.example.test"+api.PathInfo, nil)
	req.Host = "other.example.test"
	if resp, err := ui.Do(req); err != nil || resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("other host: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}

	// Every other name still reaches the identity provider, TLS end to end.
	raw, err := admin.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ctl, 443))
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, &tls.Config{ServerName: "id.example.test", RootCAs: pool})
	defer tc.Close()
	if _, err := tc.Write([]byte("hello")); err != nil {
		t.Fatalf("identity provider through port 443: %v", err)
	}
	buf := make([]byte, 5)
	_ = tc.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("identity provider echo: %q %v", buf, err)
	}

	// The plain API refuses browsers.
	req, _ = http.NewRequest("GET", fmt.Sprintf("http://%s%s", ctl, api.PathInfo), nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if resp, err := admin.http.Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("browser request on the plain API: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}
	if code := admin.do(t, "GET", api.PathInfo, nil, nil); code != 200 {
		t.Fatalf("plain API for the command line: %d", code)
	}
	_ = userRes
}

func ptr[T any](v T) *T { return &v }
