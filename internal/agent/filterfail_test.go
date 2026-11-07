package agent

import (
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A filter that cannot be applied leaves only the control nodes as peers (D2, constitution 2.4):
// the device fails closed.
func TestControlPeersOnly(t *testing.T) {
	k := func() wgtypes.Key { p, _ := wgtypes.GeneratePrivateKey(); return p.PublicKey() }
	c1, c2, peer := k(), k(), k()
	got := controlPeersOnly([]PeerConfig{{PublicKey: c1}, {PublicKey: peer}, {PublicKey: c2}}, map[wgtypes.Key]bool{c1: true, c2: true})
	if len(got) != 2 || got[0].PublicKey != c1 || got[1].PublicKey != c2 {
		t.Fatalf("kept %v", got)
	}
}
