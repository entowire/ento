//go:build linux && !android

package agent

import (
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestJumpsTo(t *testing.T) {
	rules := []*nftables.Rule{
		{Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept}}},
		{Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: "ts-input"}}},
	}
	if !jumpsTo(rules, "ts-input") || jumpsTo(rules[:1], "ts-input") || jumpsTo(rules, "other") {
		t.Fatal("jumpsTo")
	}
}

func TestOverlayWarningsOutsideCGNAT(t *testing.T) {
	if w := OverlayWarnings(netip.MustParsePrefix("10.90.0.0/16")); w != nil {
		t.Fatalf("a network outside 100.64.0.0/10 was warned about: %v", w)
	}
}
