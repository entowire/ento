package control

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
)

// Constitution 6: a plain WireGuard peer joins through a gateway. Its configuration has one peer,
// the gateway, with their preshared key; a device a rule lets reach it has it through that gateway
// (and the gateway, though no rule links the two); the gateway carries it, with what each device may
// open on it, and the control node's tunnel with the gateway carries its address; the relay carries
// what passes between the device and the gateway for it. It is never in a role's group, its
// gateway is a Linux device with the agent, and it is no gateway itself.
func TestPlainPeers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st := startTestNetwork(t, ctx, "100.64.0.0/16")
	admin := adminOf(t, ctx, srv, st, "admin-1")
	issue := func(name, os string, groups ...string) (*testClient, store.Peer) {
		t.Helper()
		tok, _, err := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: groups, Name: name})
		if err != nil {
			t.Fatal(err)
		}
		srv.checkVersion(ctx)
		c, res := enrollAs(t, tok, name, os)
		p, err := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
		if err != nil {
			t.Fatal(err)
		}
		return c, p
	}
	cg, gw := issue("gw-1", "linux", "servers")
	cl, laptop := issue("laptop-1", "linux", "laptops")
	_, mac := issue("mac-1", "darwin", "servers")
	// Laptops reach printers, printers nothing; no rule between laptops and servers (the gateway).
	if _, err := st.AddPolicy(ctx, store.Policy{Source: "device:laptops", Destination: "device:printers"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.ObservePeer(ctx, gw.PublicKey, "198.51.100.7:51830", time.Now()); err != nil {
		t.Fatal(err)
	}

	var res api.PlainResponse
	if code := admin.do(t, "POST", api.PathPlain, api.PlainRequest{Name: "printer-1", Via: "gw-1", Groups: []string{"printers"}}, &res); code != 200 {
		t.Fatalf("add: HTTP %d", code)
	}
	for _, want := range []string{"PrivateKey = ", "Address = " + res.Address + "/32", "PublicKey = " + gw.PublicKey.String(),
		"PresharedKey = ", "AllowedIPs = 100.64.0.0/16", "Endpoint = 198.51.100.7:51830", "PersistentKeepalive = 25"} {
		if !strings.Contains(res.Config, want) {
			t.Fatalf("the configuration has no %q:\n%s", want, res.Config)
		}
	}
	if strings.Contains(res.Config, "<this device's private key") {
		t.Fatal("a key pair made here is not in the configuration")
	}
	printer, err := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
	if err != nil || printer.OS != store.PlainOS || !printer.Approved || !slices.Contains(printer.Groups, "device:printers") {
		t.Fatalf("the plain peer: %+v, %v", printer, err)
	}
	// A key made on the device: the configuration leaves the private key to it.
	devKey, _ := wgtypes.GeneratePrivateKey()
	var res2 api.PlainResponse
	if code := admin.do(t, "POST", api.PathPlain, api.PlainRequest{Name: "router-1", Via: "gw-1", Groups: []string{"printers"},
		PublicKey: devKey.PublicKey().String(), Endpoint: "gw.example.com:51830"}, &res2); code != 200 {
		t.Fatalf("add with a key: HTTP %d", code)
	}
	if !strings.Contains(res2.Config, "<this device's private key") || !strings.Contains(res2.Config, "Endpoint = gw.example.com:51830") {
		t.Fatalf("configuration for a key made on the device:\n%s", res2.Config)
	}
	srv.checkVersion(ctx)

	get := func(c *testClient) api.NetMap {
		t.Helper()
		var nm api.NetMap
		if code := c.do(t, "GET", api.PathNetMap, nil, &nm); code != 200 {
			t.Fatalf("netmap: HTTP %d", code)
		}
		return nm
	}
	// The laptop: the printer through the gateway, and the gateway as its peer.
	nmL := get(cl)
	e := peerIn(t, nmL, printer)
	if e.Via != gw.PublicKey.String() || len(e.Endpoints) != 0 {
		t.Fatalf("the laptop's entry for the printer: %+v", e)
	}
	g := peerIn(t, nmL, gw)
	if len(g.Accept) != 0 {
		t.Fatalf("the gateway may open %v on the laptop, with no rule between them", g.Accept)
	}
	// The gateway: carries the printer, what the laptop may open on it, the laptop as its peer.
	nmG := get(cg)
	var carried *api.PlainPeer
	for i := range nmG.Self.Plain {
		if nmG.Self.Plain[i].Address == printer.Address.String() {
			carried = &nmG.Self.Plain[i]
		}
	}
	if carried == nil || carried.PresharedKey == "" || !strings.Contains(res.Config, "PresharedKey = "+carried.PresharedKey) {
		t.Fatalf("the gateway does not carry the printer with its key: %+v", nmG.Self.Plain)
	}
	if acc := carried.Accept[laptop.Address.String()]; !slices.Equal(acc, []string{"all"}) {
		t.Fatalf("what the laptop may open on the printer: %v (%v)", acc, carried.Accept)
	}
	peerIn(t, nmG, laptop)
	if len(nmG.Self.Plain) != 2 {
		t.Fatalf("the gateway carries %d plain peers, want 2", len(nmG.Self.Plain))
	}
	// The control node's tunnel with the gateway carries the printer's address; the printer has none.
	cfg, _ := srv.wg.dev.IpcGet()
	gwBlock := cfg[strings.Index(cfg, "public_key="+hexKey(gw.PublicKey)):]
	if next := strings.Index(gwBlock[1:], "public_key="); next > 0 {
		gwBlock = gwBlock[:next+1]
	}
	if !strings.Contains(gwBlock, "allowed_ip="+printer.Address.String()+"/32") {
		t.Fatalf("the gateway's tunnel does not carry the printer:\n%s", gwBlock)
	}
	if strings.Contains(cfg, "public_key="+hexKey(printer.PublicKey)) {
		t.Fatal("the plain peer is a WireGuard peer of the control node")
	}
	// The relay: laptop and gateway, linked by the printer only.
	if tbl := srv.relay.table.Load(); !tbl.permits(laptop, gw) || !tbl.permits(gw, laptop) {
		t.Fatal("the relay refuses the laptop and the printer's gateway")
	}

	// Refused: a role's group, a gateway without the kernel's WireGuard, a plain peer as a gateway
	// (of plain peers, or of a route), a role for a plain peer later.
	for name, req := range map[string]api.PlainRequest{
		"admin":    {Name: "p-2", Via: "gw-1", Groups: []string{"admin"}},
		"operator": {Name: "p-3", Via: "gw-1", Groups: []string{"operator"}},
		"darwin":   {Name: "p-4", Via: "mac-1", Groups: []string{"printers"}},
		"plain":    {Name: "p-5", Via: "printer-1", Groups: []string{"printers"}},
		"nobody":   {Name: "p-6", Via: "nobody", Groups: []string{"printers"}},
		"taken":    {Name: "printer-1", Via: "gw-1", Groups: []string{"printers"}},
	} {
		code := admin.do(t, "POST", api.PathPlain, req, nil)
		if code < 400 {
			t.Errorf("%s: HTTP %d, want a refusal", name, code)
		}
	}
	_ = mac
	if code := admin.do(t, "POST", api.PathRoutes, api.Route{Name: "lan", Networks: []string{"10.9.0.0/24"}, Via: "printer-1"}, nil); code != http.StatusBadRequest {
		t.Errorf("a route through a plain peer: HTTP %d, want 400", code)
	}
	groups := []string{"device:admin"}
	if code := admin.do(t, "PATCH", api.PathPeers+"/"+strconv.FormatInt(printer.ID, 10), api.UpdatePeerRequest{Groups: &groups}, nil); code != http.StatusBadRequest {
		t.Errorf("a plain peer into admin: HTTP %d, want 400", code)
	}
	// Ordinary users cannot add one (full administration only).
	if code := cl.do(t, "POST", api.PathPlain, api.PlainRequest{Name: "p-7", Via: "gw-1"}, nil); code != http.StatusForbidden {
		t.Errorf("a plain peer added by a non-admin: HTTP %d, want 403", code)
	}

	// The printer deleted: gone from the gateway's map, its address from the gateway's tunnel.
	if err := st.DeletePeer(ctx, printer.ID); err != nil {
		t.Fatal(err)
	}
	srv.checkVersion(ctx)
	if nmG := get(cg); len(nmG.Self.Plain) != 1 {
		t.Fatalf("after deleting the printer the gateway carries %d", len(nmG.Self.Plain))
	}
	cfg, _ = srv.wg.dev.IpcGet()
	if strings.Contains(cfg, "allowed_ip="+printer.Address.String()+"/32") {
		t.Fatal("a deleted plain peer's address is still on the gateway's tunnel")
	}
}
