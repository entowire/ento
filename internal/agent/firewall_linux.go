//go:build linux

package agent

import (
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"entowire.com/ento/internal/api"
)

// linkFirewallTable is the nftables table the agent owns in a linked network's namespace.
const linkFirewallTable = "ento"

// applyLinkFirewall makes a linked network's namespace accept only what this device asked for:
// return traffic of its own connections, loopback, and relayed WireGuard frames from the linked
// network's control nodes (controls, a /24). Members of the linked network cannot open connections
// to the device, and nothing is forwarded.
//
//	table inet ento {
//	  chain input   { type filter hook input priority filter; policy drop;
//	                  iifname "lo" accept
//	                  ct state established,related accept
//	                  ip saddr <controls> udp dport 3479 accept }
//	  chain forward { type filter hook forward priority filter; policy drop; }
//	}
func applyLinkFirewall(ns netns.NsHandle, controls netip.Prefix) error {
	c, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		return err
	}
	defer c.CloseLasting()

	// Replace the table as a whole, in one transaction.
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return err
	}
	for _, t := range tables {
		if t.Name == linkFirewallTable {
			c.DelTable(t)
		}
	}
	t := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: linkFirewallTable})
	drop := nftables.ChainPolicyDrop
	input := c.AddChain(&nftables.Chain{Name: "input", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &drop})
	c.AddChain(&nftables.Chain{Name: "forward", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &drop})

	accept := &expr.Verdict{Kind: expr.VerdictAccept}
	c.AddRule(&nftables.Rule{Table: t, Chain: input, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("lo")},
		accept,
	}})
	c.AddRule(&nftables.Rule{Table: t, Chain: input, Exprs: []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:  binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		accept,
	}})
	controls = controls.Masked()
	mask := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	if bits := controls.Bits(); bits > 0 {
		m := uint32(0xffffffff) << (32 - bits)
		mask = netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(m >> 24), byte(m >> 16), byte(m >> 8), byte(m)}), 32)
	}
	c.AddRule(&nftables.Rule{Table: t, Chain: input, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask.Addr().AsSlice(), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: controls.Addr().AsSlice()},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(api.RelayPort)},
		accept,
	}})
	return c.Flush()
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n)
	return b
}
