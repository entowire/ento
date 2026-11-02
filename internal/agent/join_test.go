package agent

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/token"
)

func TestWordsToken(t *testing.T) {
	k, _ := wgtypes.GeneratePrivateKey()
	rec := token.Record{Network: netip.MustParsePrefix("100.64.0.0/16"), Controls: []token.Control{
		{PublicKey: k.PublicKey(), Endpoint: "198.51.100.1:51821", Address: netip.MustParseAddr("100.64.0.1")}}}
	a, err := WordsToken(rec.String(), "abacus zoom gumdrop dropbox snowdrop")
	if err != nil || !strings.HasPrefix(a, "ento1:") {
		t.Fatalf("%q %v", a, err)
	}
	b, _ := WordsToken(rec.String(), "ABACUS-zoom, gumdrop dropbox.snowdrop")
	if a != b {
		t.Error("the same words, typed otherwise, give another token")
	}
	if _, err := WordsToken(rec.String(), "abacus zoom gumdrop"); err == nil {
		t.Error("three words accepted")
	}
	if _, err := WordsToken("v=spf1 -all", "abacus zoom gumdrop dropbox snowdrop"); err == nil {
		t.Error("a record that is none accepted")
	}
	for _, d := range []string{"", "exa mple.com", "example.com/x", "ex_ample.com"} {
		if _, err := LookupRecord(context.Background(), d, ResolverVia(nil)); err == nil || !strings.Contains(err.Error(), "not a domain") {
			t.Errorf("%q: %v", d, err)
		}
	}
}
