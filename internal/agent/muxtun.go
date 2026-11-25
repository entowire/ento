package agent

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// Several networks on a phone (Android, 0.60). A mobile system gives an app one VPN interface, so
// every network the phone is in shares it: muxTUN reads what the system sends into the interface
// and hands each packet to the network whose range or routes hold its destination (the first
// network takes the rest: its exit), each network's WireGuard running on a port of its own; what
// any network writes goes to the one interface. The networks stay apart as on Linux
// networks.go).
//
// The system picks one source address for a packet whatever its destination, often the first
// network's: a packet for another network leaves with that network's own address instead (its
// addresses and checksums rewritten), and the answers get the address the program used back.

// muxTUN shares one TUN interface between the networks' ports.
type muxTUN struct {
	dev   tun.Device
	batch int
	mtu   int

	mu    sync.Mutex
	ports []*muxPort // [0] the first network: everything no other port claims

	wmu sync.Mutex // writes to dev

	nat natTable

	closeOnce sync.Once
	closed    chan struct{}
}

// muxHeadroom is the room left before each packet read from the interface.
const muxHeadroom = 16

func newMuxTUN(dev tun.Device) *muxTUN {
	m := &muxTUN{dev: dev, batch: max(dev.BatchSize(), 1), closed: make(chan struct{})}
	m.mtu, _ = dev.MTU()
	if m.mtu <= 0 {
		m.mtu = 1420
	}
	m.nat.m = map[natKey]natFlow{}
	go m.readLoop()
	go m.sweep()
	return m
}

// port adds a network's port: name is its interface name for the agent (claims), addr its address
// on the interface. The first port added takes every packet no other port claims.
func (m *muxTUN) port(name string, addr netip.Addr) *muxPort {
	p := &muxPort{m: m, name: name, addr: addr, in: make(chan []byte, 1024), events: make(chan tun.Event, 1), done: make(chan struct{})}
	p.events <- tun.EventUp
	m.mu.Lock()
	m.ports = append(m.ports, p)
	m.mu.Unlock()
	return p
}

func (m *muxTUN) remove(p *muxPort) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, q := range m.ports {
		if q == p {
			m.ports = append(m.ports[:i:i], m.ports[i+1:]...)
			return
		}
	}
}

// Close closes the interface; the ports stop.
func (m *muxTUN) Close() error {
	var err error
	m.closeOnce.Do(func() {
		close(m.closed)
		err = m.dev.Close()
	})
	return err
}

// pick returns the port for a packet to dst: the longest prefix any port claims, else the first.
func (m *muxTUN) pick(dst netip.Addr) *muxPort {
	m.mu.Lock()
	defer m.mu.Unlock()
	var best *muxPort
	bits := -1
	for _, p := range m.ports {
		for _, n := range p.claims() {
			if n.Bits() > bits && n.Contains(dst) {
				best, bits = p, n.Bits()
			}
		}
	}
	if best == nil && len(m.ports) > 0 {
		best = m.ports[0]
	}
	return best
}

func (m *muxTUN) readLoop() {
	bufs := make([][]byte, m.batch)
	sizes := make([]int, m.batch)
	for i := range bufs {
		bufs[i] = make([]byte, muxHeadroom+m.mtu+64)
	}
	for {
		n, err := m.dev.Read(bufs, sizes, muxHeadroom)
		if err != nil {
			if errors.Is(err, tun.ErrTooManySegments) {
				continue
			}
			m.Close()
			m.mu.Lock()
			for _, p := range m.ports {
				p.fail(err)
			}
			m.mu.Unlock()
			return
		}
		for i := 0; i < n; i++ {
			pkt := bufs[i][muxHeadroom : muxHeadroom+sizes[i]]
			src, dst, ok := ipv4Addrs(pkt)
			if !ok {
				continue // IPv6: the VPN has no IPv6 address
			}
			p := m.pick(dst)
			if p == nil {
				continue
			}
			out := make([]byte, len(pkt))
			copy(out, pkt)
			if src != p.addr && p.addr.IsValid() {
				m.nat.out(out, src, p.addr)
			}
			select {
			case p.in <- out:
			default: // a network that does not read keeps no other from the interface
			}
		}
	}
}

func (m *muxTUN) write(p *muxPort, bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		if len(b) > offset {
			m.nat.in(b[offset:], p.addr)
		}
	}
	m.wmu.Lock()
	defer m.wmu.Unlock()
	return m.dev.Write(bufs, offset)
}

func (m *muxTUN) sweep() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-m.closed:
			return
		case <-t.C:
			m.nat.expire(time.Now())
		}
	}
}

// muxPort is one network's view of the shared interface: a tun.Device for its WireGuard.
type muxPort struct {
	m      *muxTUN
	name   string
	addr   netip.Addr
	in     chan []byte
	events chan tun.Event
	prefix atomic.Pointer[[]netip.Prefix]

	once sync.Once
	done chan struct{}
	err  atomic.Pointer[error]
}

// setClaims sets the networks whose packets go to this port: its range and its routes.
func (p *muxPort) setClaims(list []netip.Prefix) { p.prefix.Store(&list) }

func (p *muxPort) claims() []netip.Prefix {
	if l := p.prefix.Load(); l != nil {
		return *l
	}
	return nil
}

func (p *muxPort) fail(err error) {
	p.err.Store(&err)
	p.once.Do(func() { close(p.done) })
}

func (p *muxPort) File() *os.File           { return nil }
func (p *muxPort) MTU() (int, error)        { return p.m.mtu, nil }
func (p *muxPort) Name() (string, error)    { return p.name, nil }
func (p *muxPort) Events() <-chan tun.Event { return p.events }
func (p *muxPort) BatchSize() int           { return p.m.batch }

func (p *muxPort) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	var first []byte
	select {
	case first = <-p.in:
	case <-p.done:
		if e := p.err.Load(); e != nil {
			return 0, *e
		}
		return 0, os.ErrClosed
	}
	n := 0
	put := func(b []byte) {
		sizes[n] = copy(bufs[n][offset:], b)
		n++
	}
	put(first)
	for n < len(bufs) {
		select {
		case b := <-p.in:
			put(b)
		default:
			return n, nil
		}
	}
	return n, nil
}

func (p *muxPort) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-p.done:
		return 0, os.ErrClosed
	default:
	}
	return p.m.write(p, bufs, offset)
}

// Close takes the port off the interface; the first port's also closes the interface.
func (p *muxPort) Close() error {
	p.once.Do(func() { close(p.done) })
	p.m.remove(p)
	p.m.mu.Lock()
	last := len(p.m.ports) == 0
	p.m.mu.Unlock()
	if last {
		return p.m.Close()
	}
	return nil
}

// --- addresses ---------------------------------------------------------------------------------------

// ipv4Addrs returns an IPv4 packet's source and destination.
func ipv4Addrs(p []byte) (src, dst netip.Addr, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return src, dst, false
	}
	return netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20])), true
}

// natKey is a flow as the network sees it: protocol, the network's own address and port (or ICMP
// echo identifier), the far end and its port.
type natKey struct {
	proto     byte
	own       netip.Addr
	ownPort   uint16
	other     netip.Addr
	otherPort uint16
}

type natFlow struct {
	orig netip.Addr // the address the program used
	seen time.Time
}

// natTable remembers the flows whose source was rewritten.
type natTable struct {
	sync.Mutex
	m map[natKey]natFlow
}

const (
	natIdleTCP   = 2 * time.Hour
	natIdleOther = 3 * time.Minute
)

// packetPorts returns a packet's ports (ICMP: the echo identifier as both), and where its transport
// header starts; ok false when it has none it can read.
func packetPorts(p []byte) (proto byte, sport, dport uint16, l4 int, ok bool) {
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl {
		return 0, 0, 0, 0, false
	}
	if binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 { // a later fragment: no transport header
		return p[9], 0, 0, ihl, true
	}
	proto = p[9]
	switch proto {
	case 6, 17:
		if len(p) < ihl+4 {
			return 0, 0, 0, 0, false
		}
		return proto, binary.BigEndian.Uint16(p[ihl:]), binary.BigEndian.Uint16(p[ihl+2:]), ihl, true
	case 1:
		if len(p) >= ihl+8 && (p[ihl] == 8 || p[ihl] == 0) { // echo request, reply
			id := binary.BigEndian.Uint16(p[ihl+4:])
			return proto, id, id, ihl, true
		}
		return proto, 0, 0, ihl, true
	}
	return proto, 0, 0, ihl, true
}

// out rewrites the source of a packet leaving for a network from src to own, and remembers it.
func (t *natTable) out(p []byte, src, own netip.Addr) {
	proto, sport, dport, l4, ok := packetPorts(p)
	if !ok {
		return
	}
	dst := netip.AddrFrom4([4]byte(p[16:20]))
	t.Lock()
	t.m[natKey{proto, own, sport, dst, dport}] = natFlow{orig: src, seen: time.Now()}
	t.Unlock()
	rewrite(p, 12, own, proto, l4)
}

// in gives an answer from a network the address its program used back.
func (t *natTable) in(p []byte, own netip.Addr) {
	src, dst, ok := ipv4Addrs(p)
	if !ok || dst != own {
		return
	}
	proto, sport, dport, l4, ok := packetPorts(p)
	if !ok {
		return
	}
	t.Lock()
	f, found := t.m[natKey{proto, own, dport, src, sport}]
	if found {
		f.seen = time.Now()
		t.m[natKey{proto, own, dport, src, sport}] = f
	}
	t.Unlock()
	if found {
		rewrite(p, 16, f.orig, proto, l4)
	}
}

func (t *natTable) expire(now time.Time) {
	t.Lock()
	defer t.Unlock()
	for k, f := range t.m {
		idle := natIdleOther
		if k.proto == 6 {
			idle = natIdleTCP
		}
		if now.Sub(f.seen) > idle {
			delete(t.m, k)
		}
	}
}

// rewrite puts addr at offset at (12: source, 16: destination) of an IPv4 packet and corrects its
// header's checksum and, for TCP and UDP, the transport's (the address is in its pseudo-header).
func rewrite(p []byte, at int, addr netip.Addr, proto byte, l4 int) {
	old := [4]byte(p[at : at+4])
	nw := addr.As4()
	copy(p[at:at+4], nw[:])
	fixChecksum(p[10:12], old, nw)
	if binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
		return // a later fragment: the checksum is in the first
	}
	switch proto {
	case 6:
		if len(p) >= l4+18 {
			fixChecksum(p[l4+16:l4+18], old, nw)
		}
	case 17:
		if len(p) >= l4+8 && (p[l4+6] != 0 || p[l4+7] != 0) { // 0: no checksum
			fixChecksum(p[l4+6:l4+8], old, nw)
			if p[l4+6] == 0 && p[l4+7] == 0 {
				p[l4+6], p[l4+7] = 0xff, 0xff
			}
		}
	}
}

// fixChecksum updates a ones' complement checksum for 4 bytes changed from old to nw (RFC 1624).
func fixChecksum(sum []byte, old, nw [4]byte) {
	c := uint32(^binary.BigEndian.Uint16(sum))
	for i := 0; i < 4; i += 2 {
		c += uint32(^binary.BigEndian.Uint16(old[i:]))
		c += uint32(binary.BigEndian.Uint16(nw[i:]))
	}
	for c>>16 != 0 {
		c = (c & 0xffff) + c>>16
	}
	binary.BigEndian.PutUint16(sum, ^uint16(c))
}
