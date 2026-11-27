package agent

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"github.com/vishvananda/netns"
)

// pskRunner is a runner with one control node that sets preshared keys, on a fake tunnel.
func pskRunner(t *testing.T, st func(*State)) (*runner, *fakeTunnel, api.Control, wgtypes.Key) {
	t.Helper()
	priv, _ := wgtypes.GeneratePrivateKey()
	ctlPriv, _ := wgtypes.GeneratePrivateKey()
	ctlKey := ctlPriv.PublicKey()
	tun := &fakeTunnel{status: map[wgtypes.Key]PeerStatus{}}
	rel, err := newRelayer(netip.MustParseAddr("127.0.0.1"), 51820, t.Logf, func(*net.UDPAddr) (*net.UDPConn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rel.Close() })
	ctl := api.Control{Name: "c1", PublicKey: ctlKey.String(), Address: "100.64.0.1", Endpoint: "192.0.2.1:51821", PresharedKeys: true}
	s := State{PrivateKey: Key(priv), Address: netip.MustParseAddr("100.64.1.2"), Network: netip.MustParsePrefix("100.64.0.0/16"),
		Controls: []api.Control{ctl}}
	st(&s)
	a := &runner{cfg: Config{Logf: t.Logf, StateDir: t.TempDir()}, env: netEnv{ns: netns.None()}, ifc: tun, relay: rel, st: s,
		paths: map[wgtypes.Key]*path{}, postureWake: make(chan struct{}, 1), personChanged: make(chan struct{})}
	a.last = api.NetMap{Version: 1, Controls: s.Controls, Self: api.Self{Address: "100.64.1.2", Approved: true}}
	if err := a.apply(a.last); err != nil {
		t.Fatal(err)
	}
	return a, tun, ctl, ctlKey
}

// ctlPSK is the preshared key the fake tunnel has for the control node.
func ctlPSK(t *testing.T, tun *fakeTunnel, ctl wgtypes.Key) wgtypes.Key {
	t.Helper()
	tun.mu.Lock()
	defer tun.mu.Unlock()
	for _, p := range tun.peers {
		if p.PublicKey == ctl {
			return p.PresharedKey
		}
	}
	t.Fatal("no control peer")
	return wgtypes.Key{}
}

// handshake makes a fresh handshake with the control node (after the key in use was set).
func handshake(tun *fakeTunnel, ctl wgtypes.Key) {
	time.Sleep(5 * time.Millisecond)
	tun.mu.Lock()
	tun.status[ctl] = PeerStatus{LastHandshake: time.Now()}
	tun.mu.Unlock()
}

// noAnswer has the map loop fail as if no control node answered for long, at the next turn.
func noAnswer(a *runner, ctl api.Control) {
	a.unansweredSince = time.Now().Add(-2 * pskTryAfter)
	a.pskTryAt = time.Now().Add(-2 * pskTryAfter)
	a.resolvePSK(false, ctl)
}

func mustGenKey(t *testing.T) wgtypes.Key {
	k, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The agent finds the key the control nodes have (psk.go): only a handshake made after the key in
// use was set proves it, and it settles on that key.
func TestPresharedKeySettles(t *testing.T) {
	t.Run("reset: none", func(t *testing.T) {
		k := mustGenKey(t)
		a, tun, ctl, ctlKey := pskRunner(t, func(s *State) { s.PresharedKey = optionalKey(k); s.PSKAt = time.Now() })
		if got := ctlPSK(t, tun, ctlKey); got != k {
			t.Fatalf("set %v, want the state's key", got)
		}
		// An answer with a session from before proves nothing: nothing changes.
		tun.status[ctlKey] = PeerStatus{LastHandshake: time.Now().Add(-time.Minute)}
		a.resolvePSK(true, ctl)
		if keyOf(a.st.PresharedKey) != k {
			t.Fatal("settled on an old handshake")
		}
		noAnswer(a, ctl) // the control nodes forgot it: try none
		if got := ctlPSK(t, tun, ctlKey); got != (wgtypes.Key{}) {
			t.Fatalf("trying %v, want none", got)
		}
		handshake(tun, ctlKey)
		a.resolvePSK(true, ctl)
		if a.st.PresharedKey != nil || a.pskTry != 0 {
			t.Fatalf("after a handshake without a key: %+v, try %d", a.st.PresharedKey, a.pskTry)
		}
		a.mu.Lock()
		due := a.pskDue()
		a.mu.Unlock()
		if !due {
			t.Fatal("no new key due after the reset")
		}
	})
	t.Run("confirmation lost: next", func(t *testing.T) {
		k, n := mustGenKey(t), mustGenKey(t)
		a, tun, ctl, ctlKey := pskRunner(t, func(s *State) {
			s.PresharedKey, s.NextPresharedKey, s.NextPSKTag = optionalKey(k), optionalKey(n), "tag"
		})
		if got := ctlPSK(t, tun, ctlKey); got != n {
			t.Fatal("an open change does not use the next key")
		}
		handshake(tun, ctlKey)
		a.resolvePSK(true, ctl)
		if keyOf(a.st.PresharedKey) != n || a.st.NextPresharedKey != nil || a.st.NextPSKTag != "" {
			t.Fatalf("not settled on the next key: %+v", a.st)
		}
	})
	t.Run("change not taken: current", func(t *testing.T) {
		k, n := mustGenKey(t), mustGenKey(t)
		a, tun, ctl, ctlKey := pskRunner(t, func(s *State) {
			s.PresharedKey, s.NextPresharedKey, s.NextPSKTag = optionalKey(k), optionalKey(n), "tag"
		})
		noAnswer(a, ctl) // first other candidate: the current key
		if got := ctlPSK(t, tun, ctlKey); got != k {
			t.Fatalf("trying %v, want the current key", got)
		}
		handshake(tun, ctlKey)
		a.resolvePSK(true, ctl)
		if keyOf(a.st.PresharedKey) != k || a.st.NextPresharedKey != nil {
			t.Fatalf("not settled on the current key: %+v", a.st)
		}
		if got := ctlPSK(t, tun, ctlKey); got != k {
			t.Fatal("the settled key is not the one in use")
		}
	})
	t.Run("turns", func(t *testing.T) {
		k := mustGenKey(t)
		a, tun, ctl, ctlKey := pskRunner(t, func(s *State) { s.PresharedKey = optionalKey(k) })
		want := []wgtypes.Key{{}, k, {}, k} // another candidate, the believed key again, ...
		for i, w := range want {
			noAnswer(a, ctl)
			if got := ctlPSK(t, tun, ctlKey); got != w {
				t.Fatalf("turn %d: %v, want %v", i+1, got, w)
			}
		}
		// A control node that sets no preshared keys gets none, whatever the agent has.
		a.st.Controls[0].PresharedKeys = false
		a.pskTry = 0
		if err := a.apply(a.last); err != nil {
			t.Fatal(err)
		}
		if got := ctlPSK(t, tun, ctlKey); got != (wgtypes.Key{}) {
			t.Fatal("a key on the tunnel with an older control node")
		}
	})
}

// A pair's key (Constitution 9.1): the map's next key once its time has come by the control nodes'
// clock (not the device's), applied when it comes.
func TestPairKeySwitch(t *testing.T) {
	cur, next := mustGenKey(t), mustGenKey(t)
	peerPriv, _ := wgtypes.GeneratePrivateKey()
	peerKey := peerPriv.PublicKey()
	a, tun, _, _ := pskRunner(t, func(s *State) {})
	peerPSK := func() wgtypes.Key {
		tun.mu.Lock()
		defer tun.mu.Unlock()
		for _, p := range tun.peers {
			if p.PublicKey == peerKey {
				return p.PresharedKey
			}
		}
		t.Fatal("no such peer")
		return wgtypes.Key{}
	}
	withPair := func(at time.Time) api.NetMap {
		nm := a.last
		nm.Filter = true
		nm.Peers = []api.Peer{{PublicKey: peerKey.String(), Address: "100.64.1.3", Accept: []string{"all"},
			PresharedKey: cur.String(), PresharedKeyNext: next.String(), PresharedKeyAt: at.Unix()}}
		return nm
	}
	// The control nodes' clock is an hour ahead of the device's: their "in 2 s" is the device's
	// in 2 s, not an hour ago.
	a.mu.Lock()
	a.clockOffset = time.Hour
	a.mu.Unlock()
	nm := withPair(time.Now().Add(time.Hour + 2*time.Second))
	if err := a.apply(nm); err != nil {
		t.Fatal(err)
	}
	if got := peerPSK(); got != cur {
		t.Fatal("switched before its time by the control nodes' clock")
	}
	deadline := time.Now().Add(5 * time.Second)
	for peerPSK() != next {
		if time.Now().After(deadline) {
			t.Fatal("not switched when its time came")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// A map whose next key is due already: in use at once; none at all: the current one.
	nm = withPair(time.Now().Add(time.Hour - time.Second))
	if err := a.apply(nm); err != nil {
		t.Fatal(err)
	}
	if peerPSK() != next {
		t.Fatal("a next key whose time has passed is not used")
	}
	nm.Peers[0].PresharedKeyNext, nm.Peers[0].PresharedKeyAt = "", 0
	if err := a.apply(nm); err != nil {
		t.Fatal(err)
	}
	if peerPSK() != cur {
		t.Fatal("the current key is not used")
	}
}
