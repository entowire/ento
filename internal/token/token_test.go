package token

import (
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestRoundTrip(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	k1, _ := wgtypes.GeneratePrivateKey()
	k2, _ := wgtypes.GeneratePrivateKey()
	in := Token{
		Secret:      secret,
		TempAddress: netip.MustParseAddr("100.64.255.7"),
		Controls: []Control{
			{PublicKey: k1.PublicKey(), Endpoint: "203.0.113.10:51821", Address: netip.MustParseAddr("100.64.0.1")},
			{PublicKey: k2.PublicKey(), Endpoint: "vpn.example.com:51821", Address: netip.MustParseAddr("100.64.0.2")},
		},
	}
	s, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, "ento1:") {
		t.Fatalf("unexpected prefix: %s", s)
	}
	out, err := Parse("  " + s + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if out.Secret != in.Secret || out.TempAddress != in.TempAddress || len(out.Controls) != 2 {
		t.Fatalf("round trip mismatch: %+v", out)
	}
	for i := range in.Controls {
		if out.Controls[i] != in.Controls[i] {
			t.Fatalf("control %d mismatch: %+v != %+v", i, out.Controls[i], in.Controls[i])
		}
	}
}

func TestDeriveIsDeterministicAndConsistent(t *testing.T) {
	secret, _ := NewSecret()
	a, err := Derive(secret)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Derive(secret)
	if a != b {
		t.Fatal("derivation is not deterministic")
	}
	// The derived public key must match what WireGuard computes from the private key.
	if a.PrivateKey.PublicKey() != a.PublicKey {
		t.Fatal("derived public key does not match the private key")
	}
	if a.PresharedKey == a.PrivateKey {
		t.Fatal("preshared key must differ from the private key")
	}
	other, _ := NewSecret()
	c, _ := Derive(other)
	if c.PublicKey == a.PublicKey {
		t.Fatal("different secrets produced the same key")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "ento1:", "ento1:!!!", "abc", "ento1:AQ"} {
		if _, err := Parse(s); err == nil {
			t.Fatalf("expected error for %q", s)
		}
	}
}
