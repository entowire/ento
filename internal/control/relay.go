package control

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
)

// relayTable is the immutable view the relay forwards with; it is rebuilt on every reconcile.
type relayTable struct {
	byAddr   map[netip.Addr]store.Peer
	byKey    map[wgtypes.Key]store.Peer
	policies []store.Policy
	posture  *postureState // nil when no policy requires posture checks
	routes   []store.Route
	gateways map[string]store.Peer
}

// permits reports whether src may send relayed packets to dst: both approved and allowed to talk, by
// a policy between them or a route one reaches through the other.
func (t *relayTable) permits(src, dst store.Peer) bool {
	return src.Approved && dst.Approved && src.ID != dst.ID &&
		(allowed(src, dst, t.policies, t.posture) || routeLinked(src, dst, t.routes, t.gateways, t.policies, t.posture))
}

func newRelayTable(peers []store.Peer, policies []store.Policy, posture *postureState, routes []store.Route) *relayTable {
	t := &relayTable{byAddr: map[netip.Addr]store.Peer{}, byKey: map[wgtypes.Key]store.Peer{}, policies: policies,
		posture: posture, routes: routes, gateways: routeGateways(routes, peers)}
	for _, p := range peers {
		t.byAddr[p.Address] = p
		t.byKey[p.PublicKey] = p
	}
	return t
}

// relay forwards WireGuard packets between peers that cannot reach each other directly. It runs
// inside the tunnel: the sender is authenticated by its overlay address, and the payload is a
// WireGuard packet encrypted end to end between the two peers, so this node cannot read it.
type relay struct {
	table atomic.Pointer[relayTable]
	conn  net.PacketConn
	logf  func(string, ...any)
}

func (s *Server) startRelay(ctx context.Context) error {
	conn, err := s.wg.net.ListenUDPAddrPort(netip.AddrPortFrom(s.self.Address, api.RelayPort))
	if err != nil {
		return err
	}
	s.relay = &relay{conn: conn, logf: s.cfg.Logf}
	s.relay.table.Store(newRelayTable(nil, nil, nil, nil))
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	go s.relay.serve()
	return nil
}

func (r *relay) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := r.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n <= api.RelayHeaderLen || buf[0] != api.RelayVersion {
			continue
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		srcAddr, _ := netip.AddrFromSlice(ua.IP)
		t := r.table.Load()
		src, ok := t.byAddr[srcAddr.Unmap()]
		if !ok {
			continue
		}
		dst, ok := t.byKey[wgtypes.Key(buf[1:api.RelayHeaderLen])]
		if !ok || !t.permits(src, dst) {
			continue
		}
		// Rewrite the header in place: the receiver needs to know who sent the packet.
		copy(buf[1:api.RelayHeaderLen], src.PublicKey[:])
		_, _ = r.conn.WriteTo(buf[:n], &net.UDPAddr{IP: dst.Address.AsSlice(), Port: api.RelayPort})
	}
}
