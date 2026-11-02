package control

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/token"
)

func TestCheckGroups(t *testing.T) {
	for _, ok := range []string{"operators", "msp:operators", "Team Leads", "a"} {
		if err := checkGroups([]string{ok}, false); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", " padded", "a,b", "tab\there", "new\nline", "*", string(make([]byte, 65))} {
		if checkGroups([]string{bad}, false) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := checkGroups([]string{"*"}, true); err != nil {
		t.Errorf("* in a policy: %v", err)
	}
}

func TestLinkedNetwork(t *testing.T) {
	key := func() wgtypes.Key { k, _ := wgtypes.GeneratePrivateKey(); return k.PublicKey() }
	c1 := token.Control{PublicKey: key(), Endpoint: "192.0.2.1:51821", Address: netip.MustParseAddr("100.66.0.1")}
	c2 := token.Control{PublicKey: key(), Endpoint: "192.0.2.2:51821", Address: netip.MustParseAddr("100.66.0.2")}
	enc := func(cs ...token.Control) string {
		s, err := token.Token{Secret: [32]byte{1}, TempAddress: netip.MustParseAddr("100.66.255.1"), Controls: cs}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	eps, a := linkedNetwork(enc(c1, c2))
	_, b := linkedNetwork(enc(c2, c1)) // another link's token, control nodes in another order
	_, c := linkedNetwork(enc(token.Control{PublicKey: key(), Endpoint: "198.51.100.1:51821", Address: netip.MustParseAddr("100.67.0.1")}))
	if a == "" || a != b || a == c || len(eps) != 2 {
		t.Errorf("networks %q %q %q, endpoints %v", a, b, c, eps)
	}
	if _, id := linkedNetwork("not a token"); id != "" {
		t.Error("an invalid token names a network")
	}
}
