package agent

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
)

// fakeTunnel records what the agent configures; its filter fails while failFilter is set.
type fakeTunnel struct {
	mu         sync.Mutex
	failFilter bool
	peers      []PeerConfig
	name       string         // the interface's name ("" for ento-test)
	filter     *inboundFilter // the filter last applied
}

func (f *fakeTunnel) SetAddress(netip.Prefix) error            { return nil }
func (f *fakeTunnel) AddRoute(netip.Prefix) error              { return nil }
func (f *fakeTunnel) RemoveRoute(netip.Prefix) error           { return nil }
func (f *fakeTunnel) RepairAddress(netip.Prefix) (bool, error) { return false, nil }
func (f *fakeTunnel) Status() (map[wgtypes.Key]PeerStatus, error) {
	return map[wgtypes.Key]PeerStatus{}, nil
}
func (f *fakeTunnel) Close() error  { return nil }
func (f *fakeTunnel) Delete() error { return nil }
func (f *fakeTunnel) IfName() string {
	if f.name != "" {
		return f.name
	}
	return "ento-test"
}
func (f *fakeTunnel) SetExit(bool) error             { return nil }
func (f *fakeTunnel) PersonTraffic() (uint64, error) { return 0, nil }
func (f *fakeTunnel) Configure(_ wgtypes.Key, desired []PeerConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peers = append([]PeerConfig(nil), desired...)
	return nil
}
func (f *fakeTunnel) SetFilter(filter *inboundFilter) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFilter {
		return errors.New("nf_tables missing")
	}
	f.filter = filter
	return nil
}

// A filter that cannot be applied leaves only the control nodes as peers, says why (status and
// check-ins), and the network's peers come back once it applies (2026-11-03 review, D2).
func TestApplyFailingFilter(t *testing.T) {
	key := func() wgtypes.Key { k, _ := wgtypes.GeneratePrivateKey(); return k }
	priv, ctl, peer := key(), key().PublicKey(), key().PublicKey()
	tun := &fakeTunnel{failFilter: true}
	rel, err := newRelayer(netip.MustParseAddr("127.0.0.1"), 51820, t.Logf, func(*net.UDPAddr) (*net.UDPConn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rel.Close()
	controls := []api.Control{{PublicKey: ctl.String(), Address: "100.64.0.1", Endpoint: "192.0.2.1:51821"}}
	a := &runner{cfg: Config{Logf: t.Logf, StateDir: t.TempDir()}, env: netEnv{ns: netns.None()}, ifc: tun, relay: rel,
		st:    State{PrivateKey: Key(priv), Address: netip.MustParseAddr("100.64.1.2"), Network: netip.MustParsePrefix("100.64.0.0/16"), Controls: controls},
		paths: map[wgtypes.Key]*path{}, postureWake: make(chan struct{}, 1), personChanged: make(chan struct{})}
	nm := api.NetMap{Version: 2, Controls: controls, Filter: true,
		Self:  api.Self{Address: "100.64.1.2", Approved: true},
		Peers: []api.Peer{{PublicKey: peer.String(), Address: "100.64.1.3", Endpoints: []string{"192.0.2.9:51820"}, Accept: []string{"all"}}}}

	done := make(chan error, 1)
	go func() { done <- a.apply(nm) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("apply did not return (a lock taken twice?)")
	}
	tun.mu.Lock()
	got := tun.peers
	tun.mu.Unlock()
	if len(got) != 1 || got[0].PublicKey != ctl {
		t.Fatalf("with a failing filter the peers are %v, want the control node alone", got)
	}
	a.mu.Lock()
	why := a.filterErr
	a.mu.Unlock()
	if !strings.Contains(why, "nf_tables missing") {
		t.Fatalf("the reason is not kept for status and check-ins: %q", why)
	}

	tun.mu.Lock()
	tun.failFilter = false
	tun.mu.Unlock()
	if err := a.apply(nm); err != nil {
		t.Fatal(err)
	}
	tun.mu.Lock()
	got = tun.peers
	tun.mu.Unlock()
	a.mu.Lock()
	why = a.filterErr
	a.mu.Unlock()
	if len(got) != 2 || why != "" {
		t.Fatalf("once the filter applies: peers %v, reason %q", got, why)
	}
}
