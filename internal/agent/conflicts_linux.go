//go:build linux && !android

package agent

import (
	"net"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// cgnat is the shared address space (RFC 6598) that Tailscale also numbers its devices from.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// OverlayWarnings names what on this device keeps the network (an overlay prefix) from working:
// Tailscale's firewall drops every packet from 100.64.0.0/10 that does not arrive on tailscale0,
// which, when the network is in that range, is every answer from its control nodes and peers. The
// tunnel still comes up and handshakes, so nothing else tells.
func OverlayWarnings(network netip.Prefix) []string {
	if !network.IsValid() || !network.Overlaps(cgnat) {
		return nil
	}
	switch {
	case tailscaleDropsCGNAT():
		return []string{"Tailscale's firewall drops packets from 100.64.0.0/10 that do not arrive on tailscale0, " +
			"so nothing on this network (" + network.String() + ") answers this device: run " +
			"`sudo tailscale set --netfilter-mode=nodivert` (or stop tailscaled)"}
	case interfaceExists("tailscale0"):
		return []string{"Tailscale runs here and numbers from 100.64.0.0/10 too: if this network does not answer, " +
			"its firewall is the likely cause (`sudo tailscale set --netfilter-mode=nodivert`)"}
	}
	return nil
}

func interfaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

// tailscaleDropsCGNAT reports whether a base chain at the input hook jumps to Tailscale's ts-input
// chain (its rules drop 100.64.0.0/10 from any other interface). In nodivert mode the chain exists
// but nothing jumps to it.
func tailscaleDropsCGNAT() bool {
	c, err := nftables.New()
	if err != nil {
		return false
	}
	chains, err := c.ListChains()
	if err != nil {
		return false
	}
	for _, ch := range chains {
		if ch.Hooknum == nil || *ch.Hooknum != *nftables.ChainHookInput {
			continue
		}
		rules, err := c.GetRules(ch.Table, ch)
		if err != nil {
			continue
		}
		if jumpsTo(rules, "ts-input") {
			return true
		}
	}
	return false
}

func jumpsTo(rules []*nftables.Rule, chain string) bool {
	for _, r := range rules {
		for _, e := range r.Exprs {
			if v, ok := e.(*expr.Verdict); ok && (v.Kind == expr.VerdictJump || v.Kind == expr.VerdictGoto) && v.Chain == chain {
				return true
			}
		}
	}
	return false
}
