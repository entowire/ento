//go:build linux

package agent

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
)

func resetClaims(t *testing.T) {
	claims.Lock()
	claims.m = map[string]*claim{}
	claims.Unlock()
	t.Cleanup(func() {
		claims.Lock()
		claims.m = map[string]*claim{}
		claims.Unlock()
	})
}

// Joining refuses a network the device is in, and one whose range overlaps one of its networks;
// a join picks the next interface and a free port, and --network finds the network's directory.
func TestJoinChecks(t *testing.T) {
	dir := t.TempDir()
	first := State{Address: netip.MustParseAddr("100.68.1.1"), Network: netip.MustParsePrefix("100.68.0.0/16"), RecordDomain: "entowire.com"}
	if err := SaveState(dir, first); err != nil {
		t.Fatal(err)
	}
	md := netip.MustParsePrefix("100.82.0.0/16")
	if err := CheckJoin(dir, "md.entowire.net", md); err != nil {
		t.Fatalf("a network apart refused: %v", err)
	}
	if err := CheckJoin(dir, "entowire.com", md); err == nil || !strings.Contains(err.Error(), "in entowire.com already") {
		t.Fatalf("the first network again: %v", err)
	}
	if err := CheckJoin(dir, "other.example", netip.MustParsePrefix("100.68.0.0/16")); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("an overlapping range: %v", err)
	}
	m, err := RequestJoin(dir, "md.entowire.net", md, "TOKEN", "ento0", 51830)
	if err != nil {
		t.Fatal(err)
	}
	if m.Interface != "ento1" || m.ListenPort <= 51830 {
		t.Fatalf("membership %+v, want ento1 and a port above the first's", m)
	}
	if b, err := os.ReadFile(filepath.Join(NetworkDir(dir, "md.entowire.net"), enrollFile)); err != nil || strings.TrimSpace(string(b)) != "TOKEN" {
		t.Fatalf("the invitation for the agent: %q, %v", b, err)
	}
	if err := CheckJoin(dir, "md2.example", netip.MustParsePrefix("100.82.0.0/16")); err == nil {
		t.Fatal("a range overlapping a joined network's was taken")
	}
	m2, err := RequestJoin(dir, "ic.entowire.net", netip.MustParsePrefix("100.81.0.0/16"), "T2", "ento0", 51830)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Interface != "ento2" || m2.ListenPort == m.ListenPort {
		t.Fatalf("second membership %+v next to %+v", m2, m)
	}
	if got := Networks(dir); !slices.Equal(got, []string{"ic.entowire.net", "md.entowire.net"}) {
		t.Fatalf("networks %v", got)
	}
	for domain, want := range map[string]string{"": dir, "entowire.com": dir, "MD.entowire.net.": NetworkDir(dir, "md.entowire.net")} {
		if got, err := NetworkStateDir(dir, domain); err != nil || got != want {
			t.Fatalf("--network %q: %q, %v; want %q", domain, got, err, want)
		}
	}
	if _, err := NetworkStateDir(dir, "nowhere.example"); err == nil {
		t.Fatal("a network the device is not in was found")
	}
	if err := RequestLeave(dir, "entowire.com"); err == nil {
		t.Fatal("the first network can be left like a joined one")
	}
	if err := RequestLeave(dir, "md.entowire.net"); err != nil || !exists(filepath.Join(NetworkDir(dir, "md.entowire.net"), "remove")) {
		t.Fatalf("leave: %v", err)
	}
}

// A route that overlaps another network's range or route is left to that network, whichever is
func TestClaimRoutes(t *testing.T) {
	resetClaims(t)
	claimNetwork("ento0", State{Network: netip.MustParsePrefix("100.68.0.0/16"), RecordDomain: "entowire.com"})
	claimNetwork("ento1", State{Network: netip.MustParsePrefix("100.82.0.0/16"), RecordDomain: "md.entowire.net"})
	p := netip.MustParsePrefix
	got := claimRoutes("ento1", []netip.Prefix{p("10.84.0.0/16"), p("100.68.1.0/24"), p("192.168.7.0/24")})
	if !got[p("10.84.0.0/16")] || got[p("100.68.1.0/24")] || !got[p("192.168.7.0/24")] {
		t.Fatalf("granted %v: a route into the first network's range was taken", got)
	}
	got = claimRoutes("ento0", []netip.Prefix{p("10.84.1.0/24"), p("10.0.0.0/8"), p("172.16.0.0/12")})
	if got[p("10.84.1.0/24")] || got[p("10.0.0.0/8")] || !got[p("172.16.0.0/12")] {
		t.Fatalf("granted %v: a route overlapping another network's route was taken", got)
	}
	if again := claimRoutes("ento1", []netip.Prefix{p("10.84.0.0/16")}); !again[p("10.84.0.0/16")] {
		t.Fatal("the network holding a route lost it")
	}
	resetClaims(t)
	claimNetwork("ento0", State{Network: p("100.68.0.0/16")})
	claimRoutes("ento0", []netip.Prefix{p("10.84.0.0/16")})
	if r := takenRange("ento2", p("10.84.0.0/16")); r == "" {
		t.Fatal("a joining network's range overlapping a route in use was not refused")
	}
}

// A network's resolver leaves out the names another network of the device holds; its own record's
func TestClaimNames(t *testing.T) {
	resetClaims(t)
	claimNetwork("ento0", State{Network: netip.MustParsePrefix("100.68.0.0/16"), RecordDomain: "entowire.com"})
	claimNetwork("ento1", State{Network: netip.MustParsePrefix("100.82.0.0/16"), RecordDomain: "md.entowire.net"})
	first := &resolverConf{domain: "entowire.internal.", names: map[string]netip.Addr{},
		fixed: map[string][]netip.Addr{"id.entowire.com.": nil}, zones: []resolverZone{{zone: "md.entowire.net."}}}
	if dropped := claimNames("ento0", "entowire.com.", first); !slices.Equal(dropped, []string{"md.entowire.net"}) {
		t.Fatalf("the first network kept another's domain: dropped %v", dropped)
	}
	md := &resolverConf{domain: "entowire.internal.", names: map[string]netip.Addr{"nas.entowire.internal.": netip.MustParseAddr("100.82.1.9")},
		fixed: map[string][]netip.Addr{"id.md.entowire.net.": nil, "id.entowire.com.": nil},
		zones: []resolverZone{{zone: "office.entowire.com."}, {zone: "lan.example."}}}
	dropped := claimNames("ento1", "md.entowire.net.", md)
	want := []string{"entowire.internal", "id.entowire.com", "office.entowire.com"}
	if !slices.Equal(dropped, want) {
		t.Fatalf("dropped %v, want %v", dropped, want)
	}
	if _, ok := md.fixed["id.md.entowire.net."]; md.domain != "" || len(md.names) != 0 || !ok || len(md.fixed) != 1 || len(md.zones) != 1 || md.zones[0].zone != "lan.example." {
		t.Fatalf("what remains: %+v", md)
	}
	// A network claiming another's own domain does not take it from it.
	setClaim("ento0", func(c *claim) { c.names = append(c.names, "md.entowire.net.") })
	own := &resolverConf{names: map[string]netip.Addr{}, fixed: map[string][]netip.Addr{"id.md.entowire.net.": nil}}
	if dropped := claimNames("ento1", "md.entowire.net.", own); len(dropped) != 0 {
		t.Fatalf("a network lost names in its own domain: %v", dropped)
	}
}

// A joined network's interface has a table of its own, and every network's filter keeps the
// device from forwarding between its interfaces.
func TestMemberFilterAndIsolation(t *testing.T) {
	resetClaims(t)
	for name, want := range map[string]string{"ento0": "ento-filter", "wg-x": "ento-filter", "ento1": "ento-filter-ento1", "ento12": "ento-filter-ento12", "enl-acme": "ento-filter"} {
		if got := filterTable(name); got != want {
			t.Fatalf("table of %s: %s, want %s", name, got, want)
		}
	}
	key := func() wgtypes.Key { k, _ := wgtypes.GeneratePrivateKey(); return k }
	newRunner := func(name, addr, network, domain string, member bool) (*runner, *fakeTunnel) {
		tun := &fakeTunnel{name: name}
		rel, err := newRelayer(netip.MustParseAddr("127.0.0.1"), 51820, t.Logf, func(*net.UDPAddr) (*net.UDPConn, error) {
			return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { rel.Close() })
		st := State{PrivateKey: Key(key()), Address: netip.MustParseAddr(addr), Network: netip.MustParsePrefix(network), RecordDomain: domain}
		claimNetwork(name, st)
		return &runner{cfg: Config{Logf: t.Logf, StateDir: t.TempDir()}, env: netEnv{ns: netns.None()}, ifc: tun, relay: rel, st: st, member: member,
			paths: map[wgtypes.Key]*path{}, postureWake: make(chan struct{}, 1), personChanged: make(chan struct{})}, tun
	}
	first, firstTun := newRunner("ento0", "100.68.1.1", "100.68.0.0/16", "entowire.com", false)
	md, mdTun := newRunner("ento1", "100.82.1.1", "100.82.0.0/16", "md.entowire.net", true)
	if !first.home() || md.home() || md.linked() {
		t.Fatal("the first network is not home, or a joined one is")
	}
	gw := func(net string, route string) api.NetMap {
		return api.NetMap{Version: 1, Filter: true, Network: net, Self: api.Self{Address: "x", Approved: true},
			Peers: []api.Peer{{PublicKey: key().PublicKey().String(), Address: strings.TrimSuffix(net, "0.0/16") + "1.5", Hostname: "gw",
				Endpoints: []string{"192.0.2.9:51820"}, Routes: []string{route}, Accept: []string{"all"}}}}
	}
	if err := first.apply(gw("100.68.0.0/16", "10.84.0.0/16")); err != nil {
		t.Fatal(err)
	}
	// md's gateway offers a more specific route inside the first network's: md does not take it.
	if err := md.apply(gw("100.82.0.0/16", "10.84.1.0/24")); err != nil {
		t.Fatal(err)
	}
	allowed := func(tun *fakeTunnel) []netip.Prefix {
		tun.mu.Lock()
		defer tun.mu.Unlock()
		var out []netip.Prefix
		for _, p := range tun.peers {
			out = append(out, p.AllowedIPs...)
		}
		return out
	}
	if a := allowed(firstTun); !slices.Contains(a, netip.MustParsePrefix("10.84.0.0/16")) {
		t.Fatalf("the first network's route is missing: %v", a)
	}
	if a := allowed(mdTun); slices.Contains(a, netip.MustParsePrefix("10.84.1.0/24")) {
		t.Fatalf("md took a route inside the first network's: %v", a)
	}
	if err := first.apply(gw("100.68.0.0/16", "10.84.0.0/16")); err != nil {
		t.Fatal(err)
	}
	for tun, other := range map[*fakeTunnel]string{firstTun: "ento1", mdTun: "ento0"} {
		tun.mu.Lock()
		f := tun.filter
		tun.mu.Unlock()
		if f == nil || !slices.Contains(f.isolate, other) || !strings.Contains(f.key, "isolate "+other) {
			t.Fatalf("%s's filter does not keep %s apart: %+v", tun.name, other, f)
		}
	}
}

// A peer offering a default route (or an IPv6 one) claims nothing: it would otherwise overlap
// every other network's routes.
func TestDefaultRouteClaimsNothing(t *testing.T) {
	resetClaims(t)
	key := func() wgtypes.Key { k, _ := wgtypes.GeneratePrivateKey(); return k }
	rel, err := newRelayer(netip.MustParseAddr("127.0.0.1"), 51820, t.Logf, func(*net.UDPAddr) (*net.UDPConn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rel.Close()
	st := State{PrivateKey: Key(key()), Address: netip.MustParseAddr("100.82.1.1"), Network: netip.MustParsePrefix("100.82.0.0/16")}
	a := &runner{cfg: Config{Logf: t.Logf, StateDir: t.TempDir()}, env: netEnv{ns: netns.None()}, ifc: &fakeTunnel{name: "ento1"}, relay: rel, st: st, member: true,
		paths: map[wgtypes.Key]*path{}, postureWake: make(chan struct{}, 1), personChanged: make(chan struct{})}
	nm := api.NetMap{Version: 1, Network: "100.82.0.0/16", Self: api.Self{Address: "100.82.1.1", Approved: true},
		Peers: []api.Peer{{PublicKey: key().PublicKey().String(), Address: "100.82.1.5", Endpoints: []string{"192.0.2.9:51820"},
			Routes: []string{"0.0.0.0/0", "fd00::/8"}}}}
	if err := a.apply(nm); err != nil {
		t.Fatal(err)
	}
	if got := claimRoutes("ento0", []netip.Prefix{netip.MustParsePrefix("10.84.0.0/16")}); !got[netip.MustParsePrefix("10.84.0.0/16")] {
		t.Fatal("a default route of one network took every route from the others")
	}
}
