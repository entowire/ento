package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/credential"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
	"entowire.com/ento/internal/token"
)

func startTestNetwork(t *testing.T, ctx context.Context, prefix string) (*Server, *store.Memory) {
	t.Helper()
	space, _ := ipam.New(netip.MustParsePrefix(prefix))
	st := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port,
		Endpoint: fmt.Sprintf("127.0.0.1:%d", port), Space: space, Store: st, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv, st
}

// adminOf enrolls an approved admin in a test network.
func adminOf(t *testing.T, ctx context.Context, srv *Server, st store.Store, host string, groups ...string) *testClient {
	t.Helper()
	tok, _, err := IssueToken(ctx, st, TokenOptions{Approve: true, Admin: true, Groups: groups})
	if err != nil {
		t.Fatal(err)
	}
	srv.checkVersion(ctx)
	c, _ := enroll(t, tok, host)
	return c
}

// redeemWith redeems an authority token for key, presenting cred.
func redeemWith(t *testing.T, tokStr string, key wgtypes.Key, cred string) (int, api.RedeemResponse) {
	t.Helper()
	tok, err := token.Parse(tokStr)
	if err != nil {
		t.Fatal(err)
	}
	creds, _ := token.Derive(tok.Secret)
	temp := newTestClient(t, creds.PrivateKey, creds.PresharedKey, tok.TempAddress, tok.Controls[0])
	defer temp.dev.Close()
	var res api.RedeemResponse
	code := temp.do(t, "POST", api.PathRedeem, api.RedeemRequest{PublicKey: key.PublicKey().String(), Hostname: "ignored",
		OS: "test", Credential: cred}, &res)
	return code, res
}

func TestLinkedNetworks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	home, homeStore := startTestNetwork(t, ctx, "100.64.0.0/16")
	acme, acmeStore := startTestNetwork(t, ctx, "100.65.0.0/16")

	homeAdmin := adminOf(t, ctx, home, homeStore, "ops-laptop", "admins", "operators")
	acmeAdmin := adminOf(t, ctx, acme, acmeStore, "acme-server", "servers")

	// Home: create the link; its public key is what acme registers.
	var link api.LinkInfo
	if code := homeAdmin.do(t, "POST", api.PathAdminLinks, api.CreateLinkRequest{Name: "acme", Groups: []string{"operators"},
		Grant: []string{"operators", "admins"}, TTLSeconds: 3600}, &link); code != 201 {
		t.Fatalf("create link: HTTP %d", code)
	}
	// Acme: register the authority (it may only assign "operators", for at most 30 minutes).
	var auth api.CreateAuthorityResponse
	if code := acmeAdmin.do(t, "POST", api.PathAuthorities, api.CreateAuthorityRequest{Name: "home", PublicKey: link.PublicKey,
		Groups: []string{"operators"}, MaxTTLSeconds: 1800}, &auth); code != 201 {
		t.Fatalf("create authority: HTTP %d", code)
	}
	// Before the token is imported, home cannot hand out credentials.
	devKey, _ := wgtypes.GeneratePrivateKey()
	req := api.LinkCredentialRequest{PublicKey: devKey.PublicKey().String(), Join: true}
	if code := homeAdmin.do(t, "POST", api.PathLinks+"/acme/credential", req, nil); code != http.StatusConflict {
		t.Fatalf("credential before token import: HTTP %d", code)
	}
	if code := homeAdmin.do(t, "PUT", api.PathAdminLinks+"/acme/token", api.SetLinkTokenRequest{Token: auth.Token}, nil); code != 204 {
		t.Fatalf("import token: HTTP %d", code)
	}

	// A home device outside the link's groups gets nothing.
	var tok api.CreateTokenResponse
	homeAdmin.do(t, "POST", api.PathTokens, api.CreateTokenRequest{Approve: true, Groups: []string{"staff"}, TTLSeconds: 600}, &tok)
	staff, _ := enroll(t, tok.Token, "staff-laptop")
	if code := staff.do(t, "POST", api.PathLinks+"/acme/credential", req, nil); code != http.StatusForbidden {
		t.Fatalf("staff device got a credential: HTTP %d", code)
	}

	var lc api.LinkCredentialResponse
	if code := homeAdmin.do(t, "POST", api.PathLinks+"/acme/credential", req, &lc); code != 200 || lc.Token == "" {
		t.Fatalf("credential: HTTP %d", code)
	}
	acme.checkVersion(ctx)
	// Only the agent asks: a program on the device without its key gets nothing.
	homeAdmin.unsigned = true
	if code := homeAdmin.do(t, "POST", api.PathLinks+"/acme/credential", req, nil); code != http.StatusUnauthorized {
		t.Fatalf("unsigned credential request: HTTP %d", code)
	}
	homeAdmin.unsigned = false
	// The credential names itself and the device at home, for both networks' records.
	pub, _ := credential.ParsePublicKey(link.PublicKey)
	claims, err := credential.Verify(pub, lc.Credential, time.Now())
	if err != nil || claims.ID == "" || claims.DeviceID == "" {
		t.Fatalf("credential claims: %+v %v", claims, err)
	}

	// The authority token needs a credential, for the key being enrolled.
	if code, _ := redeemWith(t, lc.Token, devKey, ""); code != http.StatusForbidden {
		t.Fatalf("redeem without credential: HTTP %d", code)
	}
	otherKey, _ := wgtypes.GeneratePrivateKey()
	if code, _ := redeemWith(t, lc.Token, otherKey, lc.Credential); code != http.StatusForbidden {
		t.Fatalf("redeem with another key's credential: HTTP %d", code)
	}
	code, res := redeemWith(t, lc.Token, devKey, lc.Credential)
	if code != 200 || !res.Approved {
		t.Fatalf("redeem: HTTP %d %+v", code, res)
	}
	dev := newTestClient(t, devKey, wgtypes.Key{}, netip.MustParseAddr(res.Address), mustControl(t, lc.Token))

	var peers []api.PeerInfo
	acmeAdmin.do(t, "GET", api.PathPeers, nil, &peers)
	var admitted api.PeerInfo
	for _, p := range peers {
		if p.Authority == "home" {
			admitted = p
		}
	}
	// Named after the authority and its name at home (without the prefix of a device named after
	// its host name); with no user signed in, the credential names the device as the user.
	if admitted.Hostname != "home-ops-laptop" || admitted.ReportedHostname != "z-ops-laptop" ||
		admitted.User != "home:z-ops-laptop" || len(admitted.Groups) != 1 ||
		admitted.Groups[0] != "home:operators" || admitted.ApprovedUntil == "" {
		t.Fatalf("admitted device: %+v", admitted)
	}
	until, _ := time.Parse(time.RFC3339, admitted.ApprovedUntil)
	if until.After(time.Now().Add(31 * time.Minute)) {
		t.Fatalf("approval exceeds the authority's maximum: %s", admitted.ApprovedUntil)
	}

	// Acme's policy decides what the device reaches.
	acmeAdmin.do(t, "POST", api.PathPolicies, api.Policy{Source: "home:operators", Destination: "servers"}, nil)
	var nm api.NetMap
	if code := dev.do(t, "GET", api.PathNetMap, nil, &nm); code != 200 || len(nm.Peers) != 1 || nm.Peers[0].Hostname != "z-acme-server" {
		t.Fatalf("netmap: HTTP %d %+v", code, nm)
	}

	// Renewal with a fresh credential, without the token (that is for joining only).
	var fresh api.LinkCredentialResponse
	homeAdmin.do(t, "POST", api.PathLinks+"/acme/credential", api.LinkCredentialRequest{PublicKey: devKey.PublicKey().String()}, &fresh)
	if fresh.Token != "" || fresh.Credential == "" {
		t.Fatalf("renewal credential: %+v", fresh)
	}
	var renewed api.RenewCredentialResponse
	if code := dev.do(t, "POST", api.PathCredential, api.RenewCredentialRequest{Credential: fresh.Credential}, &renewed); code != 200 {
		t.Fatalf("renew: HTTP %d", code)
	}
	// One key per device and linked network: another key only by joining again, which replaces it.
	if code := homeAdmin.do(t, "POST", api.PathLinks+"/acme/credential", api.LinkCredentialRequest{PublicKey: otherKey.PublicKey().String()}, nil); code != http.StatusConflict {
		t.Fatalf("credential for a second key: HTTP %d", code)
	}
	var wrong api.LinkCredentialResponse
	homeAdmin.do(t, "POST", api.PathLinks+"/acme/credential", api.LinkCredentialRequest{PublicKey: otherKey.PublicKey().String(), Join: true}, &wrong)
	if code := dev.do(t, "POST", api.PathCredential, api.RenewCredentialRequest{Credential: wrong.Credential}, nil); code != http.StatusForbidden {
		t.Fatalf("renew with another key's credential: HTTP %d", code)
	}
	if code := homeAdmin.do(t, "POST", api.PathLinks+"/acme/credential", api.LinkCredentialRequest{PublicKey: devKey.PublicKey().String()}, nil); code != http.StatusConflict {
		t.Fatalf("renewal for a replaced key: HTTP %d", code)
	}
	homeAdmin.do(t, "POST", api.PathLinks+"/acme/credential", req, &lc) // joins again with devKey
	// Devices enrolled with ordinary tokens cannot use the renewal endpoint.
	if code := acmeAdmin.do(t, "POST", api.PathCredential, api.RenewCredentialRequest{Credential: lc.Credential}, nil); code != http.StatusForbidden {
		t.Fatalf("renew from a normal peer: HTTP %d", code)
	}

	// A suspended authority's devices lose their approval and cannot renew until it is resumed.
	if code := acmeAdmin.do(t, "PATCH", api.PathAuthorities+"/home", api.UpdateAuthorityRequest{Suspended: ptr(true)}, nil); code != 204 {
		t.Fatalf("suspend authority: HTTP %d", code)
	}
	dev.do(t, "GET", api.PathNetMap, nil, &nm)
	if nm.Self.Approved {
		t.Fatal("device of a suspended authority still approved")
	}
	homeAdmin.do(t, "POST", api.PathLinks+"/acme/credential", req, &lc)
	if code := dev.do(t, "POST", api.PathCredential, api.RenewCredentialRequest{Credential: lc.Credential}, nil); code != http.StatusForbidden {
		t.Fatalf("renewal under a suspended authority: HTTP %d", code)
	}
	var auths []api.AuthorityInfo
	acmeAdmin.do(t, "GET", api.PathAuthorities, nil, &auths)
	if len(auths) != 1 || !auths[0].Suspended {
		t.Fatalf("authorities: %+v", auths)
	}
	acmeAdmin.do(t, "PATCH", api.PathAuthorities+"/home", api.UpdateAuthorityRequest{Suspended: ptr(false)}, nil)
	if code := dev.do(t, "POST", api.PathCredential, api.RenewCredentialRequest{Credential: lc.Credential}, nil); code != 200 {
		t.Fatalf("renewal after resuming: HTTP %d", code)
	}
	dev.do(t, "GET", api.PathNetMap, nil, &nm)
	if !nm.Self.Approved {
		t.Fatal("device not approved again after resuming its authority")
	}

	// Its home network refused a renewal (its person signed out): the device ends its approval at
	// once, and acme's other peers lose it; the next credential approves it again.
	if code := dev.do(t, "POST", api.PathCredentialEnd, struct{}{}, nil); code != http.StatusNoContent {
		t.Fatalf("end credential: HTTP %d", code)
	}
	if dev.do(t, "GET", api.PathNetMap, nil, &nm); nm.Self.Approved || len(nm.Peers) != 0 {
		t.Fatalf("approved after ending its credential: %+v", nm)
	}
	if code := acmeAdmin.do(t, "POST", api.PathCredentialEnd, struct{}{}, nil); code != http.StatusForbidden {
		t.Fatalf("end credential of a normal peer: HTTP %d", code)
	}
	homeAdmin.do(t, "POST", api.PathLinks+"/acme/credential", req, &lc)
	if code := dev.do(t, "POST", api.PathCredential, api.RenewCredentialRequest{Credential: lc.Credential}, nil); code != 200 {
		t.Fatalf("renewal after ending: HTTP %d", code)
	}
	if dev.do(t, "GET", api.PathNetMap, nil, &nm); !nm.Self.Approved {
		t.Fatal("device not approved again by a credential after ending")
	}

	// Without renewal the approval lapses.
	past := time.Now().Add(-time.Second)
	if _, err := acmeStore.UpdatePeer(ctx, admitted.ID, store.PeerUpdate{ApprovedUntil: &past}); err != nil {
		t.Fatal(err)
	}
	acme.expire(ctx)
	dev.do(t, "GET", api.PathNetMap, nil, &nm)
	if nm.Self.Approved || len(nm.Peers) != 0 {
		t.Fatalf("expired device still approved: %+v", nm)
	}

	// Deleting the authority removes its devices at once.
	if code := acmeAdmin.do(t, "DELETE", api.PathAuthorities+"/home", nil, nil); code != 204 {
		t.Fatalf("delete authority: HTTP %d", code)
	}
	// Its key is gone from WireGuard too: the device cannot even reach the control plane.
	acmeAdmin.do(t, "GET", api.PathPeers, nil, &peers)
	for _, p := range peers {
		if p.Authority != "" {
			t.Fatalf("device of a deleted authority left: %+v", p)
		}
	}
	if err := acme.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	status, _ := acme.wg.Status()
	if _, ok := status[devKey.PublicKey()]; ok {
		t.Fatal("device of a deleted authority still configured in WireGuard")
	}
	tokOf, _ := token.Parse(lc.Token)
	enrollKey, _ := token.Derive(tokOf.Secret)
	if _, ok := status[enrollKey.PublicKey]; ok {
		t.Fatal("enrollment key of a deleted authority still configured in WireGuard")
	}
}

func mustControl(t *testing.T, s string) token.Control {
	tok, err := token.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return tok.Controls[0]
}

// Two layers (0.27): a laptop approved by its token (group laptops) keeps what its machine layer
// gives it with nobody signed in; its person's layer (operators) ends when the person is idle, signs
// out or the laptop starts again, never for its age, and leaves the machine's alone.
func TestSSOSessions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := &logLines{t: t}
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port, Endpoint: fmt.Sprintf("127.0.0.1:%d", port),
		Space: space, Store: st, Logf: logs.logf, SessionIdle: 8 * time.Hour,
		OIDC: &OIDCConfig{Issuer: "https://id.example.invalid/realms/x", ClientID: "c", ClientSecret: "s"}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	admin := adminOf(t, ctx, srv, st, "admin-host", "admins")
	device := func(name string, groups ...string) (*testClient, store.Peer) {
		tok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: groups, Name: name})
		srv.checkVersion(ctx)
		c, res := enroll(t, tok, name)
		p, _ := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
		return c, p
	}
	laptop, lp := device("laptop-1", "laptops")
	_, sp := device("server-1", "servers")
	admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "laptops", Destination: "servers", OneWay: true, Ports: []string{"tcp/1514"}}, nil)
	admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "operators", Destination: "servers"}, nil)
	// The person's layer, as a sign-in as an operator opens it (opened ten hours ago, active since).
	open := func(since, activity time.Time) {
		user, login, yes, groups := "alice", time.Now(), true, []string{"operators"}
		if _, err := st.UpdatePeer(ctx, lp.ID, store.PeerUpdate{User: &user, LoginAt: &login, PersonApproved: &yes, PersonOperator: &yes,
			PersonGroups: &groups, PersonActive: &yes, PersonSince: &since, PersonActivityAt: &activity}); err != nil {
			t.Fatal(err)
		}
		srv.checkVersion(ctx)
	}
	netmap := func() api.NetMap {
		var nm api.NetMap
		laptop.do(t, "GET", api.PathNetMap, nil, &nm)
		return nm
	}
	server := func(nm api.NetMap) *api.Peer {
		for i := range nm.Peers {
			if nm.Peers[i].Address == sp.Address.String() {
				return &nm.Peers[i]
			}
		}
		return nil
	}
	ago := func(d time.Duration) time.Time { return time.Now().Add(-d) }
	checkIn := func(token, boot string, idle int64) string {
		var res api.CheckInResponse
		if code := laptop.do(t, "POST", api.PathCheckIn, api.CheckInRequest{Token: token, BootID: boot, PersonIdle: &idle}, &res); code != 200 {
			t.Fatalf("check-in: HTTP %d", code)
		}
		return res.Token
	}

	// Open ten hours, active an hour ago: no age limit, so it stays open.
	open(ago(10*time.Hour), ago(time.Hour))
	if _, err := st.UpdatePeer(ctx, lp.ID, store.PeerUpdate{PersonReports: func() *bool { b := true; return &b }()}); err != nil {
		t.Fatal(err)
	}
	srv.expire(ctx)
	nm := netmap()
	if !nm.Self.PersonActive || !nm.Self.Operator || !slices.Contains(nm.Self.Groups, "operators") || !slices.Contains(nm.Self.Groups, "device:laptops") {
		t.Fatalf("an active person layer ended for its age: %+v", nm.Self)
	}
	if p := server(nm); p == nil || !slices.Equal(p.Machine, []string{"tcp/1514"}) {
		t.Fatalf("what the machine layer alone may open on the server: %+v", p)
	}
	// The person's administration counts as their activity.
	if code := laptop.do(t, "GET", api.PathPeers, nil, nil); code != 200 {
		t.Fatalf("the operator's API: HTTP %d", code)
	}
	if p, _ := st.PeerByAddress(ctx, lp.Address); time.Since(p.Person.ActivityAt) > time.Minute {
		t.Fatalf("administration not counted as activity: %v", p.Person.ActivityAt)
	}

	// A check-in reports the person's traffic; the first boot is noted, a second one closes the
	// layer (nothing a person opened survives a restart).
	tok := checkIn("", "boot-a", 30)
	tok = checkIn(tok, "boot-a", 20)
	if !netmap().Self.PersonActive {
		t.Fatal("a check-in of the same boot closed the person layer")
	}
	checkIn(tok, "boot-b", -1)
	nm = netmap()
	if nm.Self.PersonActive || nm.Self.Operator || slices.Contains(nm.Self.Groups, "operators") || !nm.Self.Approved || nm.Self.LoginRequired {
		t.Fatalf("after a new boot: %+v", nm.Self)
	}
	// The machine layer stays: the laptop still reaches the server (the SIEM's port), not as an operator.
	if p := server(nm); p == nil {
		t.Fatal("the machine layer lost the server")
	}
	if code := laptop.do(t, "GET", api.PathPeers, nil, nil); code != http.StatusForbidden {
		t.Fatalf("the operator's API without the person layer: HTTP %d", code)
	}

	// Idle: nothing of the person for nine hours closes it (the device reports, so LastSeen does not count).
	open(ago(10*time.Hour), ago(9*time.Hour))
	srv.expire(ctx)
	if netmap().Self.PersonActive {
		t.Fatal("an idle person layer stayed open")
	}

	// Signing out: a logout for a layer opened earlier changes nothing; for the open one, it closes.
	open(time.Now(), time.Now())
	stale := ago(time.Hour).UTC().Format(time.RFC3339Nano)
	if code := laptop.do(t, "POST", api.PathLogout, api.LogoutRequest{PersonSince: stale}, nil); code != http.StatusNoContent || !netmap().Self.PersonActive {
		t.Fatalf("a stale logout: HTTP %d", code)
	}
	if code := laptop.do(t, "POST", api.PathLogout, api.LogoutRequest{PersonSince: netmap().Self.PersonSince}, nil); code != http.StatusNoContent {
		t.Fatalf("logout: HTTP %d", code)
	}
	if nm := netmap(); nm.Self.PersonActive || !nm.Self.Approved {
		t.Fatalf("after logout: %+v", nm.Self)
	}
	if code := laptop.do(t, "POST", api.PathLogout, api.LogoutRequest{}, nil); code != http.StatusNoContent {
		t.Fatalf("a second logout: HTTP %d", code)
	}

	// Its agent still asks for the credential of a link only the person's groups may join: refused,
	// and said to be a session that ended (routine), not a device that may never join.
	if code := admin.do(t, "POST", api.PathAdminLinks, api.CreateLinkRequest{Name: "acme", Groups: []string{"operators"},
		Grant: []string{"operators"}, TTLSeconds: 3600}, nil); code != http.StatusCreated {
		t.Fatalf("create link: HTTP %d", code)
	}
	linkKey, _ := wgtypes.GeneratePrivateKey()
	ask := api.LinkCredentialRequest{PublicKey: linkKey.PublicKey().String(), Join: true}
	if code := laptop.do(t, "POST", api.PathLinks+"/acme/credential", ask, nil); code != http.StatusForbidden {
		t.Fatalf("link credential with the person's session ended: HTTP %d", code)
	}
	if logs.countAll("action=link_credential", "link acme: no person signed in on this device (their session ended)", "result=denied") != 1 {
		t.Error("the refusal does not say the person's session ended")
	}
	// A device no person ever signed in on: refused, without that note.
	never, _ := device("laptop-2", "laptops")
	if code := never.do(t, "POST", api.PathLinks+"/acme/credential", ask, nil); code != http.StatusForbidden {
		t.Fatalf("link credential of a device no person signed in on: HTTP %d", code)
	}
	if logs.countAll("action=link_credential", "laptop-2", `target="link acme"`, "result=denied") != 1 ||
		logs.countAll("action=link_credential", "laptop-2", "session ended") != 0 {
		t.Error("a device no person signed in on was not refused plainly")
	}

	// A week after the last full sign-in, only signing in again brings the person's rights back.
	old := ago(store.PersonReopen + time.Hour)
	if _, err := st.UpdatePeer(ctx, lp.ID, store.PeerUpdate{LoginAt: &old}); err != nil {
		t.Fatal(err)
	}
	if nm := netmap(); !nm.Self.LoginRequired || !nm.Self.Approved {
		t.Fatalf("a week later: %+v", nm.Self)
	}
}

// Devices that are not approved (new, or whose session ended) reach the identity provider through
// the control node, so they can sign in; nothing else.
func TestIdentityProviderForward(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, perDevice := idpFirstByte, idpPerDevice
	idpFirstByte, idpPerDevice = 2*time.Second, 2
	defer func() { idpFirstByte, idpPerDevice = first, perDevice }()
	idp, err := net.Listen("tcp", "127.0.0.1:0")
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
		Space: space, Store: st, Logf: t.Logf, SessionIdle: time.Hour,
		OIDC: &OIDCConfig{Issuer: "https://id.example.invalid/x", ClientID: "c", ClientSecret: "s",
			ConnectTo: []string{"127.0.0.1:1", idp.Addr().String()}}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	tok, _, err := IssueToken(ctx, st, TokenOptions{}) // not approved
	if err != nil {
		t.Fatal(err)
	}
	srv.checkVersion(ctx)
	dev, res := enroll(t, tok, "new-laptop")
	if res.Approved {
		t.Fatal("device approved")
	}
	// The holder of an enrollment token that is not redeemed yet gets nothing through port 443.
	pending, _, err := IssueToken(ctx, st, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	srv.checkVersion(ctx)
	ptok, _ := token.Parse(pending)
	creds, _ := token.Derive(ptok.Secret)
	holder := newTestClient(t, creds.PrivateKey, creds.PresharedKey, ptok.TempAddress, ptok.Controls[0])
	if hc, err := holder.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(srv.Address(), IdentityProviderPort)); err == nil {
		_, _ = hc.Write([]byte("hello"))
		_ = hc.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, _ := io.ReadFull(hc, make([]byte, 5)); n == 5 {
			t.Fatal("a token holder reached the identity provider")
		}
		hc.Close()
	}

	c, err := dev.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(srv.Address(), IdentityProviderPort))
	if err != nil {
		t.Fatalf("identity provider not reachable through the control node: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("forwarded %q, %v", buf, err)
	}

	// A connection that sends nothing is closed after idpFirstByte; while it is open it counts
	// towards the device's limit (2 here: c and this one), so a third is refused.
	silent, err := dev.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(srv.Address(), IdentityProviderPort))
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	time.Sleep(200 * time.Millisecond)
	third, err := dev.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(srv.Address(), IdentityProviderPort))
	if err == nil {
		_, _ = third.Write([]byte("hello"))
		_ = third.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, _ := io.ReadFull(third, make([]byte, 5)); n == 5 {
			t.Fatal("a connection beyond the device's limit was forwarded")
		}
		third.Close()
	}
	_ = silent.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := silent.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a silent connection stayed open: %v", err)
	}
}

// A device of an authority has one membership in the linked network: joining again with a new key
// replaces it (same name and address). The authority's devices can be capped, and its enrollment
// token replaced.
func TestLinkedMemberships(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	home, homeStore := startTestNetwork(t, ctx, "100.64.0.0/16")
	acme, acmeStore := startTestNetwork(t, ctx, "100.65.0.0/16")
	homeAdmin := adminOf(t, ctx, home, homeStore, "ops-laptop", "operators")
	otherAdmin := adminOf(t, ctx, home, homeStore, "ops-desktop", "operators")
	acmeAdmin := adminOf(t, ctx, acme, acmeStore, "acme-server", "servers")
	var link api.LinkInfo
	homeAdmin.do(t, "POST", api.PathAdminLinks, api.CreateLinkRequest{Name: "acme", Groups: []string{"operators"},
		Grant: []string{"operators"}, TTLSeconds: 3600}, &link)
	var auth api.CreateAuthorityResponse
	if code := acmeAdmin.do(t, "POST", api.PathAuthorities, api.CreateAuthorityRequest{Name: "home", PublicKey: link.PublicKey,
		Groups: []string{"operators"}, MaxDevices: 1}, &auth); code != 201 {
		t.Fatalf("create authority: HTTP %d", code)
	}
	homeAdmin.do(t, "PUT", api.PathAdminLinks+"/acme/token", api.SetLinkTokenRequest{Token: auth.Token}, nil)
	acme.checkVersion(ctx)

	join := func(c *testClient) (wgtypes.Key, int, api.RedeemResponse) {
		t.Helper()
		k, _ := wgtypes.GeneratePrivateKey()
		var lc api.LinkCredentialResponse
		if code := c.do(t, "POST", api.PathLinks+"/acme/credential", api.LinkCredentialRequest{PublicKey: k.PublicKey().String(), Join: true}, &lc); code != 200 {
			t.Fatalf("join: credential HTTP %d", code)
		}
		code, res := redeemWith(t, lc.Token, k, lc.Credential)
		return k, code, res
	}
	homeDevices := func() []api.PeerInfo {
		var peers, out []api.PeerInfo
		acmeAdmin.do(t, "GET", api.PathPeers, nil, &peers)
		for _, p := range peers {
			if p.Authority == "home" {
				out = append(out, p)
			}
		}
		return out
	}

	_, code, first := join(homeAdmin)
	if code != 200 {
		t.Fatalf("first membership: HTTP %d", code)
	}
	k2, code, second := join(homeAdmin) // state lost at home: a new key
	if code != 200 || second.Address != first.Address {
		t.Fatalf("second membership: HTTP %d, address %s (was %s)", code, second.Address, first.Address)
	}
	devs := homeDevices()
	if len(devs) != 1 || devs[0].PublicKey != k2.PublicKey().String() || devs[0].Hostname != "home-ops-laptop" {
		t.Fatalf("memberships after joining twice: %+v", devs)
	}

	// The authority may have one device: another device of home is refused, until the limit grows.
	if _, code, _ := join(otherAdmin); code != http.StatusConflict {
		t.Fatalf("a device beyond the authority's limit: HTTP %d", code)
	}
	if code := acmeAdmin.do(t, "PUT", api.PathAuthorities+"/home/limit", api.AuthorityLimitRequest{MaxDevices: 2}, nil); code != 204 {
		t.Fatalf("raise the limit: HTTP %d", code)
	}
	if _, code, _ := join(otherAdmin); code != 200 {
		t.Fatalf("a device within the raised limit: HTTP %d", code)
	}
	var auths []api.AuthorityInfo
	acmeAdmin.do(t, "GET", api.PathAuthorities, nil, &auths)
	if len(auths) != 1 || auths[0].MaxDevices != 2 || auths[0].Devices != 2 || auths[0].Suspended {
		t.Fatalf("authorities: %+v", auths)
	}

	// A new enrollment token replaces the old one, which no longer is a WireGuard peer.
	oldTok, _ := token.Parse(auth.Token)
	oldKey, _ := token.Derive(oldTok.Secret)
	var rotated api.RotateAuthorityTokenResponse
	if code := acmeAdmin.do(t, "POST", api.PathAuthorities+"/home/token", nil, &rotated); code != 200 || rotated.Token == "" || rotated.Token == auth.Token {
		t.Fatalf("rotate token: HTTP %d", code)
	}
	if err := acme.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	status, _ := acme.wg.Status()
	if _, ok := status[oldKey.PublicKey]; ok {
		t.Fatal("the replaced enrollment token is still a WireGuard peer")
	}
	homeAdmin.do(t, "PUT", api.PathAdminLinks+"/acme/token", api.SetLinkTokenRequest{Token: rotated.Token}, nil)
	k3, code, joined := join(homeAdmin)
	if code != 200 {
		t.Fatalf("join with the new token: HTTP %d", code)
	}
	if devs := homeDevices(); len(devs) != 2 {
		t.Fatalf("memberships after the new token: %+v", devs)
	}

	// A membership from before credentials named the home device gets it at its next renewal.
	mine, err := acmeStore.PeerByPublicKey(ctx, k3.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acmeStore.UpdatePeer(ctx, mine.ID, store.PeerUpdate{AuthorityDevice: ptr("")}); err != nil {
		t.Fatal(err)
	}
	member := newTestClient(t, k3, wgtypes.Key{}, netip.MustParseAddr(joined.Address), mustControl(t, rotated.Token))
	var lc api.LinkCredentialResponse
	homeAdmin.do(t, "POST", api.PathLinks+"/acme/credential", api.LinkCredentialRequest{PublicKey: k3.PublicKey().String()}, &lc)
	if code := member.do(t, "POST", api.PathCredential, api.RenewCredentialRequest{Credential: lc.Credential}, nil); code != 200 {
		t.Fatalf("renewal of an older membership: HTTP %d", code)
	}
	if p, _ := acmeStore.PeerByPublicKey(ctx, k3.PublicKey()); p.AuthorityDevice == "" {
		t.Fatal("the renewal did not record the home device")
	}

	// Leaving (ento agent unlink, or unused for a week) deletes the membership, which then no longer
	// counts against the authority's devices; a device of the network's own does not leave this way.
	if code := member.do(t, "POST", api.PathLeave, struct{}{}, nil); code != http.StatusNoContent {
		t.Fatalf("leave: HTTP %d", code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := acmeStore.PeerByPublicKey(ctx, k3.PublicKey()); errors.Is(err, store.ErrNotFound) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := acmeStore.PeerByPublicKey(ctx, k3.PublicKey()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the membership stays after leaving: %v", err)
	}
	if devs := homeDevices(); len(devs) != 1 {
		t.Fatalf("memberships after one left: %+v", devs)
	}
	if code := acmeAdmin.do(t, "POST", api.PathLeave, struct{}{}, nil); code != http.StatusForbidden {
		t.Fatalf("a device of the network's own left: HTTP %d", code)
	}
}

// An authority's limit counts from the credential's issue time: a long credential is cut there, and
// one presented after it is refused (it cannot buy fresh limits by being presented again).
func TestGrantForLimitFromIssue(t *testing.T) {
	now := time.Now()
	a := store.Authority{Name: "home", Groups: []string{"operators"}, MaxTTL: time.Hour}
	c := credential.Claims{Key: "k", Groups: []string{"operators"}, IssuedAt: now.Add(-50 * time.Minute).Unix(),
		ExpiresAt: now.Add(10 * time.Hour).Unix()}
	if g := grantFor(a, c); !g.Until.Equal(c.Issued().Add(time.Hour)) {
		t.Fatalf("until %s, want an hour after issue (%s)", g.Until, c.Issued().Add(time.Hour))
	}
	c.IssuedAt = now.Add(-2 * time.Hour).Unix()
	if g := grantFor(a, c); now.Before(g.Until) {
		t.Fatalf("a credential issued two hours ago still admits until %s", g.Until)
	}
}

type downStore struct{ store.Store }

func (downStore) PeerByAddress(context.Context, netip.Addr) (store.Peer, error) {
	return store.Peer{}, errors.New("connection refused")
}

func (downStore) AddAudit(context.Context, store.AuditEntry) error {
	return errors.New("connection refused")
}

// A database that does not answer (a failover) refuses the identity forward as a failure, never as
// a denial of a stranger (which the SIEM counts as repeated denials of the devices it refused).
func TestIdentityForwardDatabaseDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := net.Dial("tcp", ln.Addr().String()); err == nil {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	srv := &Server{cfg: Config{Store: downStore{}, Logf: func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }}}
	srv.forwardIdentity(context.Background(), c, []string{"127.0.0.1:1"})
	// The journal line is the record, and says so when the database did not take it (0.53).
	if len(lines) != 2 || !strings.Contains(lines[0], "device lookup failed") || !strings.HasSuffix(lines[0], "result=failed") ||
		!strings.Contains(lines[1], "not stored in the database") {
		t.Fatalf("audit: %q", lines)
	}
}

// A one-way policy with ports reaches the network maps as what each peer may open: the destination
// accepts the source on those ports, the source accepts nothing from the destination. Operators may
// change a policy's rules, except a policy that requires posture checks.
func TestPolicyRulesInMaps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st := startTestNetwork(t, ctx, "100.64.0.0/16")
	admin := adminOf(t, ctx, srv, st, "ops-laptop", "staff")
	tok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"servers"}})
	srv.checkVersion(ctx)
	server, sres := enroll(t, tok, "web-1")
	var pol api.Policy
	if code := admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "staff", Destination: "servers", OneWay: true,
		Ports: []string{"tcp/443", "tcp/22", "tcp/22"}}, &pol); code != http.StatusCreated {
		t.Fatalf("add: HTTP %d", code)
	}
	if !pol.OneWay || !slices.Equal(pol.Ports, []string{"tcp/22", "tcp/443"}) || len(pol.Warnings) == 0 {
		t.Fatalf("policy: %+v (the warning names devices whose agents do not enforce it)", pol)
	}
	srv.checkVersion(ctx)
	var nmServer, nmAdmin api.NetMap
	server.do(t, "GET", api.PathNetMap, nil, &nmServer)
	admin.do(t, "GET", api.PathNetMap, nil, &nmAdmin)
	if !nmServer.Filter || len(nmServer.Peers) != 1 || !slices.Equal(nmServer.Peers[0].Accept, []string{"tcp/22", "tcp/443"}) {
		t.Fatalf("the server's map: %+v", nmServer)
	}
	if !nmAdmin.Filter || len(nmAdmin.Peers) != 1 || nmAdmin.Peers[0].Address != sres.Address || len(nmAdmin.Peers[0].Accept) != 0 {
		t.Fatalf("the laptop's map: %+v", nmAdmin)
	}
	if code := admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "staff", Destination: "servers"}, nil); code != http.StatusConflict {
		t.Fatalf("the same groups with other rules: HTTP %d", code)
	}
	if code := admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "staff", Destination: "db", Ports: []string{"tcp/99999"}}, nil); code != http.StatusBadRequest {
		t.Fatalf("a bad port: HTTP %d", code)
	}
	var changed api.Policy
	// Rules go one way (0.52): a request for both ways (one_way false, as an older ento admin sends
	// it) changes the ports only.
	if code := admin.do(t, "PUT", fmt.Sprintf("%s/%d/rules", api.PathPolicies, pol.ID), api.PolicyRulesRequest{Ports: []string{"all"}}, &changed); code != 200 ||
		!changed.OneWay || changed.Ports != nil {
		t.Fatalf("rules changed: HTTP %d %+v", code, changed)
	}
	srv.checkVersion(ctx)
	server.do(t, "GET", api.PathNetMap, nil, &nmServer)
	admin.do(t, "GET", api.PathNetMap, nil, &nmAdmin)
	if !slices.Equal(nmServer.Peers[0].Accept, []string{"all"}) || len(nmAdmin.Peers[0].Accept) != 0 {
		t.Fatalf("one way, every port: %+v / %+v", nmServer.Peers, nmAdmin.Peers)
	}
	// An operator may change the rules of a policy without checks, not of one with checks.
	opTok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"ops"}})
	srv.checkVersion(ctx)
	op, opRes := enroll(t, opTok, "op-laptop")
	p, _ := st.PeerByAddress(ctx, netip.MustParseAddr(opRes.Address))
	yes := true
	if _, err := st.UpdatePeer(ctx, p.ID, store.PeerUpdate{Operator: &yes}); err != nil {
		t.Fatal(err)
	}
	var oneWay api.Policy
	if code := op.do(t, "PUT", fmt.Sprintf("%s/%d/rules", api.PathPolicies, pol.ID), api.PolicyRulesRequest{OneWay: true}, &oneWay); code != 200 {
		t.Fatalf("an operator changing a policy without checks: HTTP %d", code)
	}
	// One way on every port relies on the source devices (they must refuse the servers), not on the
	// servers (they accept everything from the source anyway).
	if len(oneWay.Warnings) != 1 || !strings.Contains(oneWay.Warnings[0], "ops-laptop") || strings.Contains(oneWay.Warnings[0], "web-1") {
		t.Fatalf("one way, every port: warnings %q", oneWay.Warnings)
	}
	if _, err := st.AddPostureCheck(ctx, store.PostureCheck{Name: "enc", DiskEncryption: true, MaxAge: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetPolicyPosture(ctx, pol.ID, []string{"enc"}); err != nil {
		t.Fatal(err)
	}
	if code := op.do(t, "PUT", fmt.Sprintf("%s/%d/rules", api.PathPolicies, pol.ID), api.PolicyRulesRequest{}, nil); code != http.StatusForbidden {
		t.Fatalf("an operator changing a guarded policy: HTTP %d", code)
	}
}
