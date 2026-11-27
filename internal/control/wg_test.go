package control

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// presharedKeyOf reads the preshared key the device has for peer.
func presharedKeyOf(t *testing.T, w *userspaceWG, peer wgtypes.Key) string {
	t.Helper()
	cfg, err := w.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, block := range strings.Split(cfg, "public_key=")[1:] {
		k, rest, _ := strings.Cut(block, "\n")
		if k != hexKey(peer) {
			continue
		}
		for _, line := range strings.Split(rest, "\n") {
			if v, ok := strings.CutPrefix(line, "preshared_key="); ok {
				return v
			}
		}
	}
	t.Fatalf("no peer %s", peer)
	return ""
}

// A changed preshared key is set in place (Constitution 9.2): the running session keeps carrying
// traffic even while the two ends' keys differ, and the key, also an all-zero one, is what the
// device then holds. Removing and adding the peer again, as before, dropped the session, and with
// keys that differ no new one could start.
func TestPresharedKeyInPlace(t *testing.T) {
	ka, _ := wgtypes.GeneratePrivateKey()
	kb, _ := wgtypes.GeneratePrivateKey()
	addrA, addrB := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.1.1")
	portA, portB := freeUDPPort(t), freeUDPPort(t)
	// Not t.Logf: the devices' workers may still log while they stop, after the test.
	logf := func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }
	a, err := newUserspaceWG(ka, portA, addrA, 1380, logf)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := newUserspaceWG(kb, portB, addrB, 1380, logf)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	psk := func() wgtypes.Key { k, _ := wgtypes.GenerateKey(); return k }
	// Only a knows b's endpoint and starts the handshake (b learns a's from it): two ends that
	// both start one at once can leave one of them waiting for WireGuard's 15 s retry.
	sync := func(w *userspaceWG, peer wgtypes.Key, ip netip.Addr, port int, key wgtypes.Key) {
		t.Helper()
		ep := ""
		if w == a {
			ep = "127.0.0.1:" + strconv.Itoa(port)
		}
		if err := w.Sync(map[wgtypes.Key]wgPeer{peer: {PresharedKey: key, AllowedIP: ip, Endpoint: ep}}); err != nil {
			t.Fatal(err)
		}
	}

	// b answers every connection with "ok" on its overlay address.
	l, err := b.net.ListenTCPAddrPort(netip.AddrPortFrom(addrB, 7000))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("ok"))
			c.Close()
		}
	}()
	reach := func(within time.Duration) error {
		ctx, cancel := context.WithTimeout(context.Background(), within)
		defer cancel()
		c, err := a.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(addrB, 7000))
		if err != nil {
			return err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(within))
		got, err := io.ReadAll(c)
		if err == nil && string(got) != "ok" {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	p1 := psk()
	// b first, so that a's handshake on being configured finds b ready.
	sync(b, ka.PublicKey(), addrA, portA, p1)
	sync(a, kb.PublicKey(), addrB, portB, p1)
	if err := reach(10 * time.Second); err != nil {
		t.Fatalf("no tunnel with the first key: %v", err)
	}

	// Only a changes its key: the session stays, so b is still reached.
	p2 := psk()
	sync(a, kb.PublicKey(), addrB, portB, p2)
	if got := presharedKeyOf(t, a, kb.PublicKey()); got != hexKey(p2) {
		t.Fatalf("a holds %s, want the new key", got)
	}
	if err := reach(3 * time.Second); err != nil {
		t.Fatalf("the session was lost when one end changed its key: %v", err)
	}
	sync(b, ka.PublicKey(), addrA, portA, p2)
	if err := reach(3 * time.Second); err != nil {
		t.Fatalf("no tunnel once both ends have the new key: %v", err)
	}

	// Removing the key in place: an all-zero key on the device, the session kept.
	sync(a, kb.PublicKey(), addrB, portB, wgtypes.Key{})
	sync(b, ka.PublicKey(), addrA, portA, wgtypes.Key{})
	if got := presharedKeyOf(t, a, kb.PublicKey()); got != hexKey(wgtypes.Key{}) {
		t.Fatalf("a holds %s after the key was removed, want none", got)
	}
	if err := reach(3 * time.Second); err != nil {
		t.Fatalf("the session was lost when the key was removed: %v", err)
	}
}
