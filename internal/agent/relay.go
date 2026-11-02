package agent

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
)

// relayer carries WireGuard packets for peers that cannot be reached directly through a control
// node. For each relayed peer it binds a local UDP socket and points the kernel WireGuard peer at
// it; packets arriving there are wrapped in a relay frame and sent to the control node over the
// agent's own tunnel. Frames coming back are unwrapped and handed to the kernel from the socket
// of the sending peer, so WireGuard sees a stable endpoint per peer. The payload stays encrypted
// end to end between the two peers.
type relayer struct {
	overlay  *net.UDPConn // bound to this agent's overlay address and api.RelayPort
	wgPort   int
	control  atomic.Pointer[netip.Addr]
	controls atomic.Pointer[map[netip.Addr]bool]  // frames are only accepted from these
	peers    atomic.Pointer[map[wgtypes.Key]bool] // and only for these: the network map's peers
	logf     func(string, ...any)
	mu       sync.Mutex
	sockets  map[wgtypes.Key]*net.UDPConn
	closed   chan struct{}
}

// maxRelaySockets bounds the local sockets, whatever a control node sends (one per relayed peer).
const maxRelaySockets = 1024

// newRelayer binds the overlay socket with listen (inside the network's namespace); the local
// sockets the kernel sends relayed packets to stay in the agent's namespace, where the WireGuard
// interface's own socket lives.
func newRelayer(address netip.Addr, wgPort int, logf func(string, ...any), listen func(*net.UDPAddr) (*net.UDPConn, error)) (*relayer, error) {
	conn, err := listen(&net.UDPAddr{IP: address.AsSlice(), Port: api.RelayPort})
	if err != nil {
		return nil, fmt.Errorf("relay socket: %w", err)
	}
	r := &relayer{overlay: conn, wgPort: wgPort, logf: logf, sockets: map[wgtypes.Key]*net.UDPConn{}, closed: make(chan struct{})}
	go r.fromControl()
	return r, nil
}

// SetControl selects the control node that relays outgoing packets.
func (r *relayer) SetControl(a netip.Addr) { r.control.Store(&a) }

func (r *relayer) Close() {
	close(r.closed)
	r.overlay.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sockets {
		s.Close()
	}
}

// Endpoint returns the local endpoint the kernel must use for a relayed peer.
func (r *relayer) Endpoint(peer wgtypes.Key) (string, error) {
	s, err := r.socket(peer)
	if err != nil {
		return "", err
	}
	return s.LocalAddr().String(), nil
}

func (r *relayer) socket(peer wgtypes.Key) (*net.UDPConn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sockets[peer]; ok {
		return s, nil
	}
	if len(r.sockets) >= maxRelaySockets {
		return nil, errors.New("too many relayed peers")
	}
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	r.sockets[peer] = s
	go r.toControl(peer, s)
	return s, nil
}

// toControl forwards what the kernel sends to a relayed peer's local socket.
func (r *relayer) toControl(peer wgtypes.Key, s *net.UDPConn) {
	buf := make([]byte, 65535)
	buf[0] = api.RelayVersion
	copy(buf[1:api.RelayHeaderLen], peer[:])
	for {
		n, _, err := s.ReadFromUDP(buf[api.RelayHeaderLen:])
		if err != nil {
			return
		}
		ctl := r.control.Load()
		if ctl == nil {
			continue
		}
		_, _ = r.overlay.WriteToUDP(buf[:api.RelayHeaderLen+n], &net.UDPAddr{IP: ctl.AsSlice(), Port: api.RelayPort})
	}
}

// fromControl hands relayed packets to the kernel, from the sending peer's local socket.
func (r *relayer) fromControl() {
	buf := make([]byte, 65535)
	wg := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: r.wgPort}
	for {
		n, from, err := r.overlay.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-r.closed:
				return
			default:
				continue
			}
		}
		if n <= api.RelayHeaderLen || buf[0] != api.RelayVersion {
			continue
		}
		// Only control nodes relay; they are the only ones allowed to send to this port.
		if !r.isControl(from) {
			continue
		}
		// Only for peers of the network map: a socket and a goroutine per key a control node names
		// would let it exhaust the agent.
		key := wgtypes.Key(buf[1:api.RelayHeaderLen])
		if !r.isPeer(key) {
			continue
		}
		s, err := r.socket(key)
		if err != nil {
			continue
		}
		_, _ = s.WriteToUDP(buf[api.RelayHeaderLen:n], wg)
	}
}

// SetControls records the control node addresses relayed frames may come from.
func (r *relayer) SetControls(controls []api.Control) {
	m := map[netip.Addr]bool{}
	for _, c := range controls {
		if a, err := netip.ParseAddr(c.Address); err == nil {
			m[a] = true
		}
	}
	r.controls.Store(&m)
}

func (r *relayer) isControl(from *net.UDPAddr) bool {
	m := r.controls.Load()
	if m == nil {
		return false
	}
	a, ok := netip.AddrFromSlice(from.IP)
	return ok && (*m)[a.Unmap()]
}

// SetPeers records the network map's peers: relayed frames for any other key are dropped, and the
// local sockets of peers no longer in the map are closed (their goroutines end with them).
func (r *relayer) SetPeers(keys map[wgtypes.Key]bool) {
	m := maps.Clone(keys)
	r.peers.Store(&m)
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, s := range r.sockets {
		if !m[k] {
			s.Close()
			delete(r.sockets, k)
		}
	}
}

func (r *relayer) isPeer(k wgtypes.Key) bool {
	m := r.peers.Load()
	return m != nil && (*m)[k]
}
