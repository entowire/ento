package agent

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

// filterTUN applies the inbound filter in the agent's own WireGuard (macOS, Windows, Android, Linux
// with --userspace): what WireGuard writes towards the system passes the filter, and what the system
// sends is noted, so that UDP answers pass.
type filterTUN struct {
	tun.Device
	filter atomic.Pointer[inboundFilter]
	flows  udpFlows
	dns    atomic.Pointer[tunDNS]
	// person counts the bytes of the person's traffic the system sent (the filter's person rules).
	person atomic.Uint64
}

func newFilterTUN(t tun.Device) *filterTUN { return &filterTUN{Device: t} }

func (t *filterTUN) set(f *inboundFilter) { t.filter.Store(f) }

// Read is what the system sends into the network.
func (t *filterTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(bufs, sizes, offset)
	t.interceptDNS(bufs, sizes, offset, n)
	if f := t.filter.Load(); f != nil {
		for i := 0; i < n; i++ {
			p := bufs[i][offset : offset+sizes[i]]
			t.flows.outbound(p)
			if f.person != nil && f.person.counts(p, f.accept) {
				t.person.Add(uint64(len(p)))
			}
		}
	}
	return n, err
}

// Write is what arrives from the network for the system; packets the filter refuses are dropped
// (and counted as written: WireGuard does not resend them).
func (t *filterTUN) Write(bufs [][]byte, offset int) (int, error) {
	f := t.filter.Load()
	if f == nil {
		return t.Device.Write(bufs, offset)
	}
	keep := make([][]byte, 0, len(bufs))
	for _, b := range bufs {
		if len(b) <= offset {
			continue
		}
		if f.passes(b[offset:], &t.flows) {
			keep = append(keep, b)
		} else {
			f.logDrops.note(b[offset:])
		}
	}
	if len(keep) > 0 {
		if _, err := t.Device.Write(keep, offset); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}

// tunDNS is a resolver in the packet path: UDP queries to addr port 53 are answered by r, never
// sent into the network (a phone's VPN: its app may not listen on port 53).
type tunDNS struct {
	addr netip.Addr
	r    *resolver
}

// setDNS puts a resolver in the packet path at addr (r nil: none).
func (t *filterTUN) setDNS(addr netip.Addr, r *resolver) {
	if r == nil {
		t.dns.Store(nil)
		return
	}
	t.dns.Store(&tunDNS{addr: addr, r: r})
}

// interceptDNS takes the DNS queries to the resolver in the packet path out of a batch read from
// the system (their size becomes 0, which WireGuard skips: its buffers belong to its own elements,
// so they are never moved) and answers them in the background.
func (t *filterTUN) interceptDNS(bufs [][]byte, sizes []int, offset, n int) {
	d := t.dns.Load()
	if d == nil {
		return
	}
	for i := 0; i < n; i++ {
		p := bufs[i][offset : offset+sizes[i]]
		if src, sport, q, ok := dnsQueryTo(p, d.addr); ok {
			sizes[i] = 0
			q = append([]byte(nil), q...)
			go func() {
				if a := d.r.exchange(q, src); a != nil {
					pkt := udpPacket(d.addr, 53, src, sport, a)
					buf := make([]byte, offset+len(pkt))
					copy(buf[offset:], pkt)
					_, _ = t.Device.Write([][]byte{buf}, offset)
				}
			}()
		}
	}
}

// dnsQueryTo reads an IPv4 UDP datagram to addr port 53 (not a fragment): its source, source port
// and payload.
func dnsQueryTo(p []byte, addr netip.Addr) (netip.Addr, uint16, []byte, bool) {
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 17 || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
		return netip.Addr{}, 0, nil, false
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl+8 || netip.AddrFrom4([4]byte(p[16:20])) != addr {
		return netip.Addr{}, 0, nil, false
	}
	l4 := p[ihl:]
	if binary.BigEndian.Uint16(l4[2:4]) != 53 {
		return netip.Addr{}, 0, nil, false
	}
	end := min(int(binary.BigEndian.Uint16(p[2:4])), len(p))
	if end < ihl+8 {
		return netip.Addr{}, 0, nil, false
	}
	return netip.AddrFrom4([4]byte(p[12:16])), binary.BigEndian.Uint16(l4[0:2]), p[ihl+8 : end], true
}

// udpPacket builds an IPv4 UDP datagram (UDP checksum computed).
func udpPacket(src netip.Addr, sport uint16, dst netip.Addr, dport uint16, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	s, d := src.As4(), dst.As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[10:12], ^checksum(p[:20], 0))
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	// Pseudo-header: addresses, protocol, UDP length.
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], s[:])
	copy(pseudo[4:8], d[:])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(8+len(payload)))
	c := ^checksum(p[20:], checksum(pseudo, 0))
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(p[26:28], c)
	return p
}

// checksum adds b to the one's complement sum start (RFC 1071), folded to 16 bits.
func checksum(b []byte, start uint16) uint16 {
	sum := uint32(start)
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}
