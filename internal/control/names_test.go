package control

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

// TestDeviceNames: a token can name its device; others are named z-<host name>; administrators
// rename devices or confirm the host name they reported, and nothing is written when a change is
// refused.
func TestDeviceNames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port,
		Endpoint: fmt.Sprintf("127.0.0.1:%d", port), Space: space, Store: st, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	adminTok, _, err := IssueToken(ctx, st, TokenOptions{Approve: true, Admin: true, Name: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	srv.checkVersion(ctx)
	admin, _ := enroll(t, adminTok, "whatever-it-says")
	signInRoles(t, st)

	token := func(req api.CreateTokenRequest) (int, string) {
		t.Helper()
		req.TTLSeconds = 600
		var res api.CreateTokenResponse
		code := admin.do(t, "POST", api.PathTokens, req, &res)
		return code, res.Token
	}
	peer := func(name string) api.PeerInfo {
		t.Helper()
		var peers []api.PeerInfo
		admin.do(t, "GET", api.PathPeers, nil, &peers)
		for _, p := range peers {
			if p.Hostname == name {
				return p
			}
		}
		t.Fatalf("no device named %s in %+v", name, peers)
		return api.PeerInfo{}
	}
	rename := func(id int64, req api.UpdatePeerRequest) (int, api.PeerInfo) {
		t.Helper()
		var p api.PeerInfo
		code := admin.do(t, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, id), req, &p)
		return code, p
	}
	name := func(s string) *string { return &s }

	if p := peer("ops"); p.ReportedHostname != "whatever-it-says" {
		t.Fatalf("named token: %+v", p)
	}
	for _, bad := range []string{"z-web", "Web", "web.example.com", "-web"} {
		if code, _ := token(api.CreateTokenRequest{Name: bad}); code != 400 {
			t.Errorf("token named %q: HTTP %d", bad, code)
		}
	}
	if code, _ := token(api.CreateTokenRequest{Replace: true}); code != 400 {
		t.Errorf("replace without a name: HTTP %d", code)
	}
	if code, _ := token(api.CreateTokenRequest{Name: "ops"}); code != 409 {
		t.Errorf("token for a taken name: HTTP %d", code)
	}
	code, webTok := token(api.CreateTokenRequest{Name: "web", Approve: true})
	var toks []api.TokenInfo
	admin.do(t, "GET", api.PathTokens, nil, &toks)
	if code != 201 || len(toks) != 1 || toks[0].Name != "web" {
		t.Fatalf("named token: HTTP %d, %+v", code, toks)
	}
	enroll(t, webTok, "ip-10-1-2-3")
	_, phoneTok := token(api.CreateTokenRequest{})
	enroll(t, phoneTok, "Pixel 7")
	phone := peer("z-pixel-7")
	if phone.ReportedHostname != "Pixel 7" {
		t.Fatalf("self-named device: %+v", phone)
	}

	// Renames: checked, unique, and nothing changes when refused.
	for bad, want := range map[string]int{"z-mine": 400, "Pixel": 400, "web": 409} {
		if code, _ := rename(phone.ID, api.UpdatePeerRequest{Hostname: name(bad)}); code != want {
			t.Errorf("rename to %q: HTTP %d, want %d", bad, code, want)
		}
	}
	if code, _ := rename(phone.ID, api.UpdatePeerRequest{Hostname: name("x"), UseReportedHostname: true}); code != 400 {
		t.Errorf("rename and confirm at once: HTTP %d", code)
	}
	suspended := true
	rename(phone.ID, api.UpdatePeerRequest{Suspended: &suspended})
	approve := true
	if code, _ := rename(phone.ID, api.UpdatePeerRequest{Hostname: name("phone"), Approved: &approve}); code != 409 {
		t.Errorf("approving a suspended device: HTTP %d", code)
	}
	if p := peer("z-pixel-7"); !p.Suspended {
		t.Fatalf("refused change was written: %+v", p)
	}

	// Confirming the reported host name drops the prefix, in one step.
	if code, p := rename(phone.ID, api.UpdatePeerRequest{UseReportedHostname: true}); code != 200 || p.Hostname != "pixel-7" {
		t.Fatalf("confirm: HTTP %d, %+v", code, p)
	}
	// Other devices see the new name.
	var nm api.NetMap
	admin.do(t, "GET", api.PathNetMap, nil, &nm)
	if nm.Self.Hostname != "ops" {
		t.Errorf("netmap self: %+v", nm.Self)
	}
	if code, p := rename(phone.ID, api.UpdatePeerRequest{Hostname: name("phone")}); code != 200 || p.Hostname != "phone" {
		t.Fatalf("rename: HTTP %d, %+v", code, p)
	}

	// A named token for a device that exists needs replace; its device takes the name and address.
	web := peer("web")
	if code, _ := token(api.CreateTokenRequest{Name: "web"}); code != 409 {
		t.Errorf("token for web: HTTP %d", code)
	}
	_, replaceTok := token(api.CreateTokenRequest{Name: "web", Replace: true, Approve: true})
	enroll(t, replaceTok, "ip-10-1-2-4")
	if p := peer("web"); p.ID == web.ID || p.Address != web.Address || p.ReportedHostname != "ip-10-1-2-4" {
		t.Fatalf("replaced web: %+v (was %+v)", p, web)
	}
}
