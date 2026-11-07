package control

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

// logLines keeps a control node's log lines for a test to look for.
type logLines struct {
	t     *testing.T
	mu    sync.Mutex
	lines []string
}

func (l *logLines) logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	l.mu.Lock()
	l.lines = append(l.lines, line)
	l.mu.Unlock()
	l.t.Log(line)
}

func (l *logLines) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, line := range l.lines {
		if strings.Contains(line, sub) {
			n++
		}
	}
	return n
}

// ssoNode starts a control node signing devices in with the fake provider and keeping their
// refresh tokens, due for a check a millisecond after each sign-in or check.
func ssoNode(t *testing.T, ctx context.Context, idp *fakeProvider, refusals ...Refusal) (*Server, store.Store, *logLines) {
	t.Helper()
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	logs := &logLines{t: t}
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port,
		Endpoint: fmt.Sprintf("127.0.0.1:%d", port), Space: space, Store: st, Logf: logs.logf,
		OIDC: &OIDCConfig{Issuer: idp.URL, ClientID: "ento", ClientSecret: "s3cret",
			ApproveGroups: []string{"staff"}, AdminGroups: []string{"admins"},
			TokenKey: make([]byte, 32), RefreshInterval: time.Millisecond, Refusals: refusals}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv, st, logs
}

// ssoLogin signs a device in through the fake provider.
func ssoLogin(t *testing.T, dev *testClient) {
	t.Helper()
	if code := dev.do(t, "POST", api.PathLogin, nil, &api.LoginStart{}); code != 200 {
		t.Fatalf("login start: HTTP %d", code)
	}
	var status api.LoginStatus
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		dev.do(t, "GET", api.PathLogin, nil, &status)
		if status.State != "pending" {
			break
		}
	}
	if status.State != "done" {
		t.Fatalf("login did not complete: %+v", status)
	}
}

// check runs one round of the refresher once the device's token is due.
func check(ctx context.Context, srv *Server) {
	time.Sleep(5 * time.Millisecond)
	srv.refreshDue(ctx)
}

func peerAt(t *testing.T, st store.Store, addr string) store.Peer {
	t.Helper()
	p, err := st.PeerByAddress(context.Background(), netip.MustParseAddr(addr))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSSORefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	idp := fakeIdP(t, "alice@example.com", []string{"/staff"})
	srv, st, logs := ssoNode(t, ctx, idp)
	tok, _, _ := IssueToken(ctx, st, TokenOptions{Groups: []string{"laptops"}})
	srv.checkVersion(ctx)
	dev, res := enroll(t, tok, "laptop")
	ssoLogin(t, dev)
	if p := peerAt(t, st, res.Address); !p.Approved || p.Admin {
		t.Fatalf("after sign-in: %+v", p)
	}
	idp.mu.Lock()
	scope := idp.scope
	idp.mu.Unlock()
	if !strings.Contains(scope, "offline_access") {
		t.Fatalf("no offline token asked for: %q", scope)
	}

	// Nothing changed: the rotated token is kept (the fake accepts each token once).
	check(ctx, srv)
	check(ctx, srv)
	if p := peerAt(t, st, res.Address); !p.Approved || idp.refreshCount() != 2 || logs.count("sso_changed") != 0 {
		t.Fatalf("unchanged user: %+v, %d refreshes", p, idp.refreshCount())
	}

	// The username (preferred_username) is taken from a refresh too, as for devices that signed in
	// before ento kept it: no change of access, so no audit line.
	idp.mu.Lock()
	idp.login = "alice"
	idp.mu.Unlock()
	check(ctx, srv)
	if p := peerAt(t, st, res.Address); p.UserLogin != "alice" || logs.count("sso_changed") != 0 {
		t.Fatalf("username from a refresh: %q, %d sso_changed", p.UserLogin, logs.count("sso_changed"))
	}
	// The device's own network map names its person (`ento agent whoami`).
	var self api.NetMap
	if dev.do(t, "GET", api.PathNetMap, nil, &self); self.Self.User != "alice" || self.Self.UserName != "alice@example.com" {
		t.Fatalf("the map's self: user %q, name %q", self.Self.User, self.Self.UserName)
	}

	// Groups changed at the provider: the device follows at the next check.
	idp.set("ok", []string{"/staff", "/admins"})
	check(ctx, srv)
	if p := peerAt(t, st, res.Address); !p.Admin || len(p.Groups) != 3 || logs.count("action=sso_changed") != 1 {
		t.Fatalf("after joining admins: %+v", p)
	}
	var nm api.NetMap
	if dev.do(t, "GET", api.PathNetMap, nil, &nm); !nm.Self.Admin {
		t.Fatal("the network map does not show the new role")
	}

	// A provider without an ID token in refresh answers, or without the groups in it: groups
	// unknown, nothing changes. Nor does another order of the same groups.
	for _, mode := range []string{"noid", "nogroups"} {
		idp.set(mode, nil)
		check(ctx, srv)
		if p := peerAt(t, st, res.Address); !p.Approved || !p.Admin || len(p.Groups) != 3 {
			t.Fatalf("after a refresh in mode %s: %+v", mode, p)
		}
	}
	idp.set("ok", []string{"/admins", "/staff"})
	check(ctx, srv)
	if logs.count("action=sso_changed") != 1 {
		t.Fatal("the same groups in another order counted as a change")
	}

	// The provider down or unreachable: nothing is cut, reported once, and its return once.
	idp.set("down", nil)
	check(ctx, srv)
	idp.set("drop", nil)
	check(ctx, srv)
	if p := peerAt(t, st, res.Address); !p.Approved || logs.count("action=sso_refresh_unavailable") != 1 {
		t.Fatalf("while the provider is down: %+v", p)
	}
	idp.set("ok", nil)
	check(ctx, srv)
	if logs.count("available again") != 1 || logs.count("action=sso_refresh_unavailable") != 2 {
		t.Fatal("the provider's return is not reported")
	}

	// Left the groups that give access (a mover): signed out.
	idp.set("ok", []string{"/contractors"})
	check(ctx, srv)
	// The device keeps its own groups (0.43); the person's rights end.
	if p := peerAt(t, st, res.Address); p.Person.Approved || p.Admin {
		t.Fatalf("after leaving every group with access: %+v", p)
	}

	// Disabled at the provider (a leaver): withdrawn at the next check, and not asked about again.
	for _, mode := range []string{"disabled", "deleted"} {
		idp.set("ok", []string{"/staff"})
		ssoLogin(t, dev)
		if p := peerAt(t, st, res.Address); !p.Approved {
			t.Fatalf("signed in again: %+v", p)
		}
		idp.set(mode, nil)
		before := logs.count("action=sso_withdrawn")
		check(ctx, srv)
		if p := peerAt(t, st, res.Address); p.Person.Approved || logs.count("action=sso_withdrawn") != before+1 {
			t.Fatalf("%s user: %+v", mode, p)
		}
		n := idp.refreshCount()
		check(ctx, srv)
		if idp.refreshCount() != n {
			t.Fatalf("%s user: still asked about", mode)
		}
	}
}

// A provider that refuses otherwise than RFC 6749 (Rauthy: 401 Disabled, 404 NotFound) withdraws
// access only where its answers are named as refusals; by default they count as the provider
// failing, which never cuts access.
func TestSSORefusals(t *testing.T) {
	for _, mode := range []string{"rauthy-disabled", "rauthy-deleted"} {
		t.Run(mode+" by default", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			idp := fakeIdP(t, "alice@example.com", []string{"/staff"})
			srv, st, logs := ssoNode(t, ctx, idp)
			tok, _, _ := IssueToken(ctx, st, TokenOptions{Groups: []string{"laptops"}})
			srv.checkVersion(ctx)
			dev, res := enroll(t, tok, "laptop")
			ssoLogin(t, dev)
			idp.set(mode, nil)
			check(ctx, srv)
			if p := peerAt(t, st, res.Address); !p.Approved || logs.count("action=sso_withdrawn") != 0 || logs.count("action=sso_refresh_unavailable") != 1 {
				t.Fatalf("an unnamed answer cut access: %+v", p)
			}
		})
		t.Run(mode+" named", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			idp := fakeIdP(t, "alice@example.com", []string{"/staff"})
			refusals, err := ParseRefusals("400:invalid_grant,401:Disabled,404:NotFound")
			if err != nil {
				t.Fatal(err)
			}
			srv, st, logs := ssoNode(t, ctx, idp, refusals...)
			tok, _, _ := IssueToken(ctx, st, TokenOptions{Groups: []string{"laptops"}})
			srv.checkVersion(ctx)
			dev, res := enroll(t, tok, "laptop")
			ssoLogin(t, dev)
			idp.set(mode, nil)
			check(ctx, srv)
			if p := peerAt(t, st, res.Address); p.Person.Approved || logs.count("action=sso_withdrawn") != 1 {
				t.Fatalf("a named refusal did not withdraw access: %+v", p)
			}
		})
	}
	// A wrong client secret (401 invalid_client) is the deployment's fault, never the user's.
	c := OIDCConfig{Refusals: []Refusal{{401, "Disabled"}, {404, "NotFound"}}}
	if c.refused(401, "invalid_client") || c.refused(401, "Unauthorized") || !c.refused(401, "Disabled") {
		t.Fatal("refusals match the wrong answers")
	}
	if !(OIDCConfig{}).refused(400, "invalid_grant") || (OIDCConfig{}).refused(401, "Disabled") {
		t.Fatal("the default is not RFC 6749's invalid_grant alone")
	}
	for _, bad := range []string{"", "invalid_grant", "200:ok", "401:", "x:Disabled"} {
		if _, err := ParseRefusals(bad); err == nil {
			t.Errorf("ParseRefusals(%q) accepted", bad)
		}
	}
}

// A provider that lists the groups claim's scope (Rauthy) is asked for it, before offline_access;
// one that does not list it is not.
func TestSSOGroupsScope(t *testing.T) {
	for _, listed := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		idp := fakeIdP(t, "alice@example.com", []string{"/staff"})
		idp.groupsScope = listed
		srv, st, _ := ssoNode(t, ctx, idp)
		tok, _, _ := IssueToken(ctx, st, TokenOptions{Groups: []string{"laptops"}})
		srv.checkVersion(ctx)
		dev, _ := enroll(t, tok, "laptop")
		ssoLogin(t, dev)
		idp.mu.Lock()
		scope := idp.scope
		idp.mu.Unlock()
		want := "openid profile email offline_access"
		if listed {
			want = "openid profile email groups offline_access"
		}
		if scope != want {
			t.Errorf("groups scope listed=%v: asked for %q, want %q", listed, scope, want)
		}
		cancel()
	}
}

// A provider that offers offline tokens but not to this client still signs devices in.
func TestSSOWithoutOfflineAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	idp := fakeIdP(t, "alice@example.com", []string{"/staff"})
	idp.noOffline = true
	srv, st, _ := ssoNode(t, ctx, idp)
	tok, _, _ := IssueToken(ctx, st, TokenOptions{Groups: []string{"laptops"}})
	srv.checkVersion(ctx)
	dev, res := enroll(t, tok, "laptop")
	ssoLogin(t, dev)
	idp.set("disabled", nil)
	check(ctx, srv)
	if p := peerAt(t, st, res.Address); p.Person.Approved {
		t.Fatalf("not checked with an ordinary refresh token: %+v", p)
	}
}

// A check that began before the device was signed in again changes nothing: that sign-in stands.
func TestSSORefreshAfterNewSignIn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	idp := fakeIdP(t, "alice@example.com", []string{"/staff"})
	srv, st, _ := ssoNode(t, ctx, idp)
	tok, _, _ := IssueToken(ctx, st, TokenOptions{Groups: []string{"laptops"}})
	srv.checkVersion(ctx)
	dev, res := enroll(t, tok, "laptop")
	ssoLogin(t, dev)
	time.Sleep(5 * time.Millisecond)
	claimed, err := st.ClaimSSOTokens(ctx, time.Now(), time.Now().Add(time.Hour), 10)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	ssoLogin(t, dev) // a new sign-in, with a new token
	idp.set("deleted", nil)
	if srv.refreshDevice(ctx, claimed[0]) {
		t.Fatal("a stale check withdrew the device")
	}
	if p := peerAt(t, st, res.Address); !p.Approved {
		t.Fatalf("the new sign-in was undone: %+v", p)
	}
}

func TestSealToken(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	sealed, err := sealToken(key, 7, "rt-secret")
	if err != nil || strings.Contains(sealed, "rt-secret") {
		t.Fatalf("seal: %q %v", sealed, err)
	}
	if got, err := openToken(key, 7, sealed); err != nil || got != "rt-secret" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := openToken(key, 8, sealed); err == nil {
		t.Fatal("opened as another device's token")
	}
	if _, err := openToken(make([]byte, 32), 7, sealed); err == nil {
		t.Fatal("opened with another key")
	}
}

func TestSuspendUser(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	idp := fakeIdP(t, "alice@example.com", []string{"/staff"})
	srv, st, logs := ssoNode(t, ctx, idp)
	adminTok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Admin: true, Groups: []string{"admins"}})
	srv.checkVersion(ctx)
	admin, _ := enroll(t, adminTok, "admin-host")
	var addrs []string
	for _, host := range []string{"laptop", "phone"} {
		tok, _, _ := IssueToken(ctx, st, TokenOptions{Groups: []string{"laptops"}})
		srv.checkVersion(ctx)
		dev, res := enroll(t, tok, host)
		ssoLogin(t, dev)
		addrs = append(addrs, res.Address)
	}
	// A namesake admitted through a linked network is someone else.
	tk, _ := wgtypes.GeneratePrivateKey()
	rec, err := st.CreateToken(ctx, store.Token{PublicKey: tk.PublicKey(), PresharedKey: tk, Authority: "home", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	k, _ := wgtypes.GeneratePrivateKey()
	linked, err := st.Redeem(ctx, rec.TempAddress, k.PublicKey(), "visitor", "linux", time.Now(),
		&store.Grant{Authority: "home", UserName: "alice@example.com", Hostname: "home-laptop", Until: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	var out api.SuspendUserResult
	if code := admin.do(t, "POST", api.PathUserSuspension, api.SuspendUserRequest{User: "Alice@Example.com", Suspended: true}, &out); code != 200 || len(out.Changed) != 2 {
		t.Fatalf("suspend: HTTP %d %+v", code, out)
	}
	for _, a := range addrs {
		if p := peerAt(t, st, a); !p.Suspended || p.Approved {
			t.Fatalf("not suspended: %+v", p)
		}
	}
	if p, _ := st.PeerByAddress(ctx, linked.Address); p.Suspended {
		t.Fatal("the linked namesake was suspended")
	}
	if logs.count("action=user_suspended") != 1 {
		t.Fatal("no audit line")
	}
	// Their tokens are gone: the provider is not asked about them any more.
	n := idp.refreshCount()
	check(ctx, srv)
	if idp.refreshCount() != n {
		t.Fatal("suspended devices still checked")
	}
	if code := admin.do(t, "POST", api.PathUserSuspension, api.SuspendUserRequest{User: "nobody"}, nil); code != http.StatusNotFound {
		t.Fatalf("unknown user: HTTP %d", code)
	}
	if code := admin.do(t, "POST", api.PathUserSuspension, api.SuspendUserRequest{User: "user-42", Suspended: false}, &out); code != 200 || len(out.Changed) != 2 {
		t.Fatalf("resume by subject: HTTP %d %+v", code, out)
	}
	if p := peerAt(t, st, addrs[0]); p.Suspended || p.Approved {
		t.Fatalf("resumed device must sign in again: %+v", p)
	}
}

func TestLinkTTL(t *testing.T) {
	user, server := store.Peer{User: "user-42"}, store.Peer{}
	plain := &Server{cfg: Config{SessionIdle: time.Hour}, oidc: &oidcProvider{cfg: OIDCConfig{}}}
	checked := &Server{cfg: Config{SessionIdle: time.Hour}, oidc: &oidcProvider{cfg: OIDCConfig{TokenKey: make([]byte, 32)}}}
	for _, tc := range []struct {
		s    *Server
		p    store.Peer
		ttl  time.Duration
		want time.Duration
	}{
		{plain, server, 12 * time.Hour, 12 * time.Hour},
		{plain, user, 12 * time.Hour, time.Hour},
		{checked, user, 12 * time.Hour, ssoLinkTTL},
		{checked, user, 5 * time.Minute, 5 * time.Minute},
		{checked, server, 12 * time.Hour, 12 * time.Hour},
	} {
		if got := tc.s.linkTTL(tc.p, tc.ttl); got != tc.want {
			t.Errorf("linkTTL(%+v, %v) = %v, want %v", tc.p, tc.ttl, got, tc.want)
		}
	}
}

// Signing in opens a device's person layer on top of its machine layer (0.27): a device approved by
// its token (a laptop in group laptops) keeps its groups and gets the person's beside them.
func TestLoginOnlyForSSODevices(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	idp := fakeIdP(t, "alice@example.com", []string{"/admins"})
	srv, st, logs := ssoNode(t, ctx, idp)
	tok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"laptops"}})
	srv.checkVersion(ctx)
	machine, res := enroll(t, tok, "laptop-m")
	ssoLogin(t, machine)
	p := peerAt(t, st, res.Address)
	if !p.Admin || p.User == "" || !slices.Contains(p.Groups, "device:laptops") || !slices.Contains(p.Groups, "admins") ||
		!slices.Equal(p.Machine.Groups, []string{"device:laptops"}) || !p.Machine.Approved || p.Machine.Admin {
		t.Fatalf("a sign-in on a token-approved device: %+v", p)
	}
	if logs.count("action=login") != 1 {
		t.Fatal("the sign-in on the token-approved device is not recorded")
	}
	open, _, _ := IssueToken(ctx, st, TokenOptions{Groups: []string{"laptops"}})
	srv.checkVersion(ctx)
	laptop, _ := enroll(t, open, "laptop")
	ssoLogin(t, laptop)
	// The first sign-in binds the device (the SIEM raises it when it makes an admin device), the
	// next one by the same person does not.
	if logs.count("action=login") != 2 || logs.count("admin=true operator=false groups=device:laptops,admins binding=new") != 2 {
		t.Fatal("the first sign-in is not recorded as a new binding")
	}
	time.Sleep(10 * time.Millisecond)
	ssoLogin(t, laptop)
	if logs.count("binding=same") != 1 {
		t.Fatal("the second sign-in by the same person is not recorded as the same binding")
	}
}

// Tests sign in as often as they need; TestLoginRateLimit checks the limit itself.
func init() { loginInterval = 0 }

func TestLoginRateLimit(t *testing.T) {
	saved := loginInterval
	loginInterval = 5 * time.Second
	defer func() { loginInterval = saved }()
	s := &Server{}
	now := time.Now()
	if !s.loginAllowed(1, now) || s.loginAllowed(1, now.Add(time.Second)) {
		t.Fatal("a second start within the interval was allowed (or the first refused)")
	}
	if !s.loginAllowed(2, now.Add(time.Second)) {
		t.Fatal("another device was held back")
	}
	if !s.loginAllowed(1, now.Add(6*time.Second)) {
		t.Fatal("a start after the interval was refused")
	}
}

// A token this node's key does not open is kept (another node, or this one with the right key, may
// still open it), audited, and tried again an hour later; before 0.51 it was deleted, and that
// person was never checked again (2026-11-03 review, I8).
func TestSSOTokenUnreadableKept(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	idp := fakeIdP(t, "alice@example.com", []string{"/staff"})
	srv, st, logs := ssoNode(t, ctx, idp)
	tok, _, _ := IssueToken(ctx, st, TokenOptions{Groups: []string{"laptops"}})
	srv.checkVersion(ctx)
	dev, res := enroll(t, tok, "laptop")
	ssoLogin(t, dev)
	p := peerAt(t, st, res.Address)

	other := make([]byte, 32)
	other[0] = 1
	sealed, _ := sealToken(other, p.ID, "refresh-from-another-key")
	if err := st.SetSSOToken(ctx, store.SSOToken{PeerID: p.ID, Subject: p.User, Encrypted: sealed, NextCheck: time.Now()}); err != nil {
		t.Fatal(err)
	}
	check(ctx, srv)
	if n := logs.count("sso_token_unreadable"); n != 1 {
		t.Fatalf("%d sso_token_unreadable lines", n)
	}
	// Still there, due in about an hour, and not asked about again before that.
	due, err := st.ClaimSSOTokens(ctx, time.Now().Add(unreadableRetry+time.Minute), time.Now().Add(2*unreadableRetry), 10)
	if err != nil || len(due) != 1 || due[0].Encrypted != sealed || time.Until(due[0].NextCheck) < unreadableRetry-time.Minute {
		t.Fatalf("the unreadable token was not kept for later: %+v, %v", due, err)
	}
	if n := idp.refreshCount(); n != 0 {
		t.Fatalf("the provider was asked %d times with a token that did not open", n)
	}
}

// A control node whose token key differs from the network's (its canary) does not start; after
// ForgetSSOTokens (`ento control sso-forget`), a new key is the network's.
func TestTokenKeyCanary(t *testing.T) {
	ctx := context.Background()
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	a, b := make([]byte, 32), make([]byte, 32)
	b[0] = 1
	if err := checkTokenKey(ctx, st, a); err != nil {
		t.Fatalf("first key: %v", err)
	}
	if err := checkTokenKey(ctx, st, a); err != nil {
		t.Fatalf("the same key again: %v", err)
	}
	if err := checkTokenKey(ctx, st, b); err != errTokenKey {
		t.Fatalf("another key: %v", err)
	}
	// Start refuses it before anything listens.
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	_, err := Start(ctx, Config{Name: "c2", PrivateKey: key, ListenPort: port, Endpoint: fmt.Sprintf("127.0.0.1:%d", port),
		Space: space, Store: st, Logf: t.Logf, OIDC: &OIDCConfig{Issuer: "https://id.example.com", ClientID: "ento",
			ClientSecret: "s", TokenKey: b}})
	if err != errTokenKey {
		t.Fatalf("Start with another key: %v", err)
	}
	if _, err := st.ForgetSSOTokens(ctx); err != nil {
		t.Fatal(err)
	}
	if err := checkTokenKey(ctx, st, b); err != nil {
		t.Fatalf("the new key after forgetting: %v", err)
	}
}
