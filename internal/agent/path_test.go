package agent

import (
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
)

// A peer without a session is relayed only when something was sent to it and no session came of
// it within directTimeout: an idle quiet peer (a phone, 0.34) has no session and is no failure.
func TestChoosePathIdlePeer(t *testing.T) {
	rel, err := newRelayer(mustAddr("127.0.0.1"), 51820, t.Logf, func(a *net.UDPAddr) (*net.UDPConn, error) {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rel.Close()
	a := &runner{cfg: Config{Logf: t.Logf}, relay: rel, paths: map[wgtypes.Key]*path{}}
	key, _ := wgtypes.GeneratePrivateKey()
	peer := api.Peer{Hostname: "phone-1", Address: "100.64.0.9", Endpoints: []string{"203.0.113.9:51820"}}
	check := func(st PeerStatus, relayed bool) {
		t.Helper()
		pc := PeerConfig{PublicKey: key.PublicKey(), Endpoint: "203.0.113.9:51820"}
		if err := a.choosePath(&pc, peer, st); err != nil {
			t.Fatal(err)
		}
		if got := pc.Endpoint != "203.0.113.9:51820"; got != relayed {
			t.Fatalf("relayed = %v, want %v (endpoint %s)", got, relayed, pc.Endpoint)
		}
	}
	check(PeerStatus{}, false)
	ps := a.paths[key.PublicKey()]
	ps.since = time.Now().Add(-time.Hour) // long idle: still direct
	check(PeerStatus{}, false)
	check(PeerStatus{TxBytes: 148}, false) // a handshake sent: an attempt starts now
	check(PeerStatus{TxBytes: 296}, false)
	ps.since = time.Now().Add(-directTimeout - time.Second)
	check(PeerStatus{TxBytes: 444}, true) // no session within directTimeout
}
