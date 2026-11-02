package token

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWordlist(t *testing.T) {
	sum := sha256.Sum256([]byte(effLargeWordlist))
	if got := hex.EncodeToString(sum[:]); got != "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e" {
		t.Fatalf("the embedded wordlist is not the EFF's: %s", got)
	}
	if len(words) != 7772 || len(wordSet) != 7772 {
		t.Fatalf("%d words (%d distinct), want 7772 (the EFF's 7776 without the four with a hyphen)", len(words), len(wordSet))
	}
	w, err := NewWords()
	if err != nil || len(w) != WordCount {
		t.Fatal(w, err)
	}
	for _, x := range w {
		if !wordSet[x] {
			t.Fatalf("%q is no word of the list", x)
		}
	}
}

func TestParseWords(t *testing.T) {
	want := "abacus zoom gumdrop dropbox snowdrop"
	for _, in := range []string{want, "Abacus-ZOOM, gumdrop.dropbox\tsnowdrop\n", " abacus_zoom/gumdrop  dropbox;snowdrop "} {
		w, err := ParseWords(in)
		if err != nil || strings.Join(w, " ") != want {
			t.Errorf("%q: %v %v", in, w, err)
		}
	}
	for _, in := range []string{"abacus zoom gumdrop dropbox", "abacus zoom gumdrop dropbox snowdrop zoom", "abacus zoom gumdrop dropbox snowdrip", "drop-down zoom gumdrop dropbox snowdrop"} {
		if _, err := ParseWords(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func testRecord(t *testing.T) Record {
	t.Helper()
	k1, _ := wgtypes.GeneratePrivateKey()
	k2, _ := wgtypes.GeneratePrivateKey()
	return Record{Network: netip.MustParsePrefix("100.64.0.0/16"), Controls: []Control{
		{PublicKey: k1.PublicKey(), Endpoint: "198.51.100.1:51821", Address: netip.MustParseAddr("100.64.0.1")},
		{PublicKey: k2.PublicKey(), Endpoint: "node-b.example.net:51821", Address: netip.MustParseAddr("100.64.0.2")},
	}}
}

func TestRecord(t *testing.T) {
	r := testRecord(t)
	txt := r.String()
	got, err := ParseRecord(txt + " later=field")
	if err != nil || got.String() != txt {
		t.Fatalf("round trip: %v\n%s\n%s", err, txt, got.String())
	}
	// The identity is the range and the keys: endpoints, addresses and order do not change it.
	moved := Record{Network: r.Network, Controls: []Control{r.Controls[1], r.Controls[0]}}
	moved.Controls[0].Endpoint = "203.0.113.9:51821"
	if moved.Fingerprint() != r.Fingerprint() {
		t.Error("the fingerprint depends on endpoints or order")
	}
	other := testRecord(t)
	if other.Fingerprint() == r.Fingerprint() || len(r.Fingerprint()) != 19 {
		t.Errorf("fingerprints %s, %s", r.Fingerprint(), other.Fingerprint())
	}
	for _, bad := range []string{
		"", "ento2 net=100.64.0.0/16", "ento1 c=" + r.Controls[0].PublicKey.String() + ",1.2.3.4:5,100.64.0.1",
		"ento1 net=100.64.0.0/24 c=" + r.Controls[0].PublicKey.String() + ",1.2.3.4:5,100.64.0.1",
		"ento1 net=100.64.0.0/16",
		"ento1 net=100.64.0.0/16 c=notakey,1.2.3.4:5,100.64.0.1",
		"ento1 net=100.64.0.0/16 c=" + r.Controls[0].PublicKey.String() + ",1.2.3.4,100.64.0.1",
		"ento1 net=100.64.0.0/16 c=" + r.Controls[0].PublicKey.String() + ",1.2.3.4:5,100.65.0.1",
	} {
		if _, err := ParseRecord(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got, err := FindRecord([]string{"v=spf1 -all", txt}); err != nil || got != txt {
		t.Errorf("find: %q %v", got, err)
	}
	if _, err := FindRecord([]string{txt, txt}); err == nil {
		t.Error("two records accepted")
	}
	if _, err := FindRecord([]string{"v=spf1 -all"}); err == nil {
		t.Error("no record accepted")
	}
}

// The device rebuilds the token the control node derived: the same secret, temporary key and
// enrollment address from the same words and network, others from other words or another network.
func TestWordsToken(t *testing.T) {
	r := testRecord(t)
	w := []string{"abacus", "zoom", "gumdrop", "dropbox", "snowdrop"}
	a, err := r.Token(w)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := r.Token(w)
	if a.Secret != b.Secret || a.TempAddress != b.TempAddress || len(a.Controls) != 2 {
		t.Fatal("not deterministic")
	}
	if !a.TempAddress.Is4() || a.TempAddress.As4()[2] != 255 || a.TempAddress.As4()[3] == 0 || a.TempAddress.As4()[3] == 255 ||
		!r.Network.Contains(a.TempAddress) {
		t.Fatalf("enrollment address %s", a.TempAddress)
	}
	if _, err := a.Encode(); err != nil {
		t.Fatal(err)
	}
	c, _ := r.Token([]string{"abacus", "zoom", "gumdrop", "dropbox", "snowman"})
	other := testRecord(t)
	d, _ := other.Token(w)
	if c.Secret == a.Secret || d.Secret == a.Secret {
		t.Fatal("other words or another network give the same secret")
	}
}
