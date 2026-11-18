package agent

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
)

func testKey(t *testing.T) wgtypes.Key {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey()
}

// A control node can make the agent relay only for peers of the network map: frames for other keys
// open no socket, and the sockets of peers that left the map are closed.
func TestRelayOnlyForMapPeers(t *testing.T) {
	// The "kernel" side: where relayed packets are handed over.
	wg, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()
	r, err := newRelayer(netip.MustParseAddr("127.0.0.1"), wg.LocalAddr().(*net.UDPAddr).Port, t.Logf,
		func(*net.UDPAddr) (*net.UDPConn, error) {
			return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.SetControls([]api.Control{{Address: "127.0.0.1"}})
	ctl, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()

	known, stranger := testKey(t), testKey(t)
	r.SetPeers(map[wgtypes.Key]bool{known: true})
	frame := func(k wgtypes.Key, payload string) []byte {
		b := append([]byte{api.RelayVersion}, k[:]...)
		return append(b, payload...)
	}
	send := func(b []byte) {
		if _, err := ctl.WriteToUDP(b, r.overlay.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
	}
	send(frame(stranger, "no"))
	send(frame(known, "yes"))
	buf := make([]byte, 100)
	_ = wg.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := wg.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "yes" {
		t.Fatalf("relayed packet: %q, %v", buf[:n], err)
	}
	r.mu.Lock()
	_, strangerSocket := r.sockets[stranger]
	knownSocket := r.sockets[known]
	r.mu.Unlock()
	if strangerSocket || knownSocket == nil {
		t.Fatalf("sockets: stranger %v, known %v", strangerSocket, knownSocket != nil)
	}

	r.SetPeers(map[wgtypes.Key]bool{})
	r.mu.Lock()
	left := len(r.sockets)
	r.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d sockets left after the peer left the map", left)
	}
	if _, err := knownSocket.WriteToUDP([]byte("x"), wg.LocalAddr().(*net.UDPAddr)); err == nil {
		t.Fatal("the departed peer's socket is still open")
	}
}

func TestRelaySocketCap(t *testing.T) {
	r := &relayer{sockets: map[wgtypes.Key]*net.UDPConn{}, closed: make(chan struct{})}
	for len(r.sockets) < maxRelaySockets {
		r.sockets[testKey(t)] = nil
	}
	if _, err := r.socket(testKey(t)); err == nil {
		t.Fatal("a socket beyond the cap was opened")
	}
}

// The agent keeps its relay port open through stateful host firewalls: an empty frame (the header
// alone, which control nodes ignore) goes to every control node at once and every interval.
func TestRelayKeepOpen(t *testing.T) {
	ctl, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	r, err := newRelayer(netip.MustParseAddr("127.0.0.1"), 51820, t.Logf, func(*net.UDPAddr) (*net.UDPConn, error) {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	})
	if err != nil {
		t.Fatal(err)
	}
	r.ctlPort = ctl.LocalAddr().(*net.UDPAddr).Port
	r.SetControls([]api.Control{{Address: "127.0.0.1"}})
	go r.keepOpen(50 * time.Millisecond)
	buf := make([]byte, 100)
	for i := 0; i < 2; i++ {
		_ = ctl.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, from, err := ctl.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n != api.RelayHeaderLen || buf[0] != api.RelayVersion {
			t.Fatalf("frame %d: %x", i, buf[:n])
		}
		if from.Port != r.overlay.LocalAddr().(*net.UDPAddr).Port {
			t.Fatalf("sent from port %d, not the relay socket's", from.Port)
		}
	}
	r.Close()
}
