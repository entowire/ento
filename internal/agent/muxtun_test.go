package agent

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun"

	"entowire.com/ento/internal/api"
)

// ipChecksum is the ones' complement sum used by IPv4, TCP and UDP.
func ipChecksum(parts ...[]byte) uint16 {
	var sum uint32
	for _, b := range parts {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// testPacket builds an IPv4 packet of proto (6 TCP, 17 UDP, 1 ICMP echo) with valid checksums.
func testPacket(proto byte, src, dst string, sport, dport uint16) []byte {
	var l4 []byte
	switch proto {
	case 6:
		l4 = make([]byte, 20+4)
		binary.BigEndian.PutUint16(l4[0:], sport)
		binary.BigEndian.PutUint16(l4[2:], dport)
		l4[12] = 5 << 4
		copy(l4[20:], "data")
	case 17:
		l4 = make([]byte, 8+4)
		binary.BigEndian.PutUint16(l4[0:], sport)
		binary.BigEndian.PutUint16(l4[2:], dport)
		binary.BigEndian.PutUint16(l4[4:], uint16(len(l4)))
		copy(l4[8:], "data")
	case 1:
		l4 = make([]byte, 8)
		l4[0] = 8
		binary.BigEndian.PutUint16(l4[4:], sport)
	}
	p := make([]byte, 20+len(l4))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64
	p[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(p[12:], s[:])
	copy(p[16:], d[:])
	copy(p[20:], l4)
	binary.BigEndian.PutUint16(p[10:], ipChecksum(p[:20]))
	setL4Checksum(p)
	return p
}

func pseudo(p []byte) []byte {
	ps := make([]byte, 12)
	copy(ps, p[12:20])
	ps[9] = p[9]
	binary.BigEndian.PutUint16(ps[10:], uint16(len(p)-20))
	return ps
}

func setL4Checksum(p []byte) {
	switch p[9] {
	case 6:
		p[36], p[37] = 0, 0
		binary.BigEndian.PutUint16(p[36:], ipChecksum(pseudo(p), p[20:]))
	case 17:
		p[26], p[27] = 0, 0
		binary.BigEndian.PutUint16(p[26:], ipChecksum(pseudo(p), p[20:]))
	case 1:
		p[22], p[23] = 0, 0
		binary.BigEndian.PutUint16(p[22:], ipChecksum(p[20:]))
	}
}

// checksumsValid reports whether a packet's IPv4 and transport checksums verify.
func checksumsValid(t *testing.T, p []byte) {
	t.Helper()
	if ipChecksum(p[:20]) != 0 {
		t.Fatalf("IPv4 header checksum wrong")
	}
	switch p[9] {
	case 6, 17:
		if ipChecksum(pseudo(p), p[20:]) != 0 {
			t.Fatalf("transport checksum wrong (proto %d)", p[9])
		}
	case 1:
		if ipChecksum(p[20:]) != 0 {
			t.Fatalf("ICMP checksum wrong")
		}
	}
}

func TestNATRewritesAndRestores(t *testing.T) {
	for _, proto := range []byte{6, 17, 1} {
		var nat natTable
		nat.m = map[natKey]natFlow{}
		own := netip.MustParseAddr("100.85.0.7")
		p := testPacket(proto, "100.68.0.9", "10.20.0.5", 40000, 22)
		nat.out(p, netip.MustParseAddr("100.68.0.9"), own)
		if src, _, _ := ipv4Addrs(p); src != own {
			t.Fatalf("proto %d: source %s, want %s", proto, src, own)
		}
		checksumsValid(t, p)

		var reply []byte
		if proto == 1 {
			reply = testPacket(1, "10.20.0.5", own.String(), 40000, 40000)
			reply[20] = 0
			setL4Checksum(reply)
		} else {
			reply = testPacket(proto, "10.20.0.5", own.String(), 22, 40000)
		}
		nat.in(reply, own)
		if _, dst, _ := ipv4Addrs(reply); dst != netip.MustParseAddr("100.68.0.9") {
			t.Fatalf("proto %d: answer to %s, want the program's address back", proto, dst)
		}
		checksumsValid(t, reply)

		// An answer to a flow the table does not know is left alone.
		other := testPacket(proto, "10.20.0.6", own.String(), 22, 40001)
		nat.in(other, own)
		if _, dst, _ := ipv4Addrs(other); dst != own {
			t.Fatalf("proto %d: unknown flow rewritten to %s", proto, dst)
		}
	}
}

func TestNATExpires(t *testing.T) {
	var nat natTable
	nat.m = map[natKey]natFlow{}
	own := netip.MustParseAddr("100.85.0.7")
	nat.out(testPacket(17, "100.68.0.9", "10.20.0.5", 5000, 53), netip.MustParseAddr("100.68.0.9"), own)
	nat.out(testPacket(6, "100.68.0.9", "10.20.0.5", 5001, 22), netip.MustParseAddr("100.68.0.9"), own)
	nat.expire(time.Now().Add(10 * time.Minute))
	if len(nat.m) != 1 {
		t.Fatalf("after 10 idle minutes %d flows left, want the TCP one", len(nat.m))
	}
	nat.expire(time.Now().Add(3 * time.Hour))
	if len(nat.m) != 0 {
		t.Fatalf("after 3 idle hours %d flows left", len(nat.m))
	}
}

// fakeTUN is a TUN interface fed and read by the test.
type fakeTUN struct {
	in      chan []byte
	written chan []byte
	closed  chan struct{}
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{in: make(chan []byte, 16), written: make(chan []byte, 16), closed: make(chan struct{})}
}

func (f *fakeTUN) File() *os.File           { return nil }
func (f *fakeTUN) MTU() (int, error)        { return 1380, nil }
func (f *fakeTUN) Name() (string, error)    { return "tun0", nil }
func (f *fakeTUN) Events() <-chan tun.Event { return nil }
func (f *fakeTUN) BatchSize() int           { return 1 }
func (f *fakeTUN) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}
func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-f.in:
		sizes[0] = copy(bufs[0][offset:], p)
		return 1, nil
	case <-f.closed:
		return 0, os.ErrClosed
	}
}
func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		f.written <- append([]byte(nil), b[offset:]...)
	}
	return len(bufs), nil
}

func readPort(t *testing.T, p *muxPort) []byte {
	t.Helper()
	done := make(chan []byte, 1)
	go func() {
		bufs := [][]byte{make([]byte, 2000)}
		sizes := []int{0}
		if n, err := p.Read(bufs, sizes, 16); err == nil && n == 1 {
			done <- bufs[0][16 : 16+sizes[0]]
		}
	}()
	select {
	case b := <-done:
		return b
	case <-time.After(2 * time.Second):
		t.Fatalf("nothing reached port %s", p.name)
		return nil
	}
}

func TestMuxSendsEachPacketToItsNetwork(t *testing.T) {
	f := newFakeTUN()
	m := newMuxTUN(f)
	defer m.Close()
	first := m.port("tun0", netip.MustParseAddr("100.68.0.9"))
	first.setClaims([]netip.Prefix{netip.MustParsePrefix("100.68.0.0/16")})
	second := m.port("ento1", netip.MustParseAddr("100.85.0.7"))
	second.setClaims([]netip.Prefix{netip.MustParsePrefix("100.85.0.0/16"), netip.MustParsePrefix("10.20.0.0/16")})

	// The other network's range, sent with the first network's address (the system's choice): it
	// leaves with the network's own address.
	f.in <- testPacket(6, "100.68.0.9", "100.85.0.1", 40000, 443)
	got := readPort(t, second)
	if src, dst, _ := ipv4Addrs(got); src != netip.MustParseAddr("100.85.0.7") || dst != netip.MustParseAddr("100.85.0.1") {
		t.Fatalf("second network got %s -> %s", src, dst)
	}
	checksumsValid(t, got)

	// Its route too.
	f.in <- testPacket(17, "100.68.0.9", "10.20.0.5", 5353, 53)
	got = readPort(t, second)
	if _, dst, _ := ipv4Addrs(got); dst != netip.MustParseAddr("10.20.0.5") {
		t.Fatalf("route went elsewhere: %s", dst)
	}

	// The first network's own range, and everything else (its exit), go to the first, unchanged.
	for _, dst := range []string{"100.68.0.1", "1.1.1.1"} {
		want := testPacket(6, "100.68.0.9", dst, 40001, 443)
		f.in <- append([]byte(nil), want...)
		got = readPort(t, first)
		if string(got) != string(want) {
			t.Fatalf("packet to %s changed or misrouted", dst)
		}
	}

	// The answer from the second network gets the program's address back on the interface.
	reply := testPacket(6, "100.85.0.1", "100.85.0.7", 443, 40000)
	buf := make([]byte, 16+len(reply))
	copy(buf[16:], reply)
	if _, err := second.Write([][]byte{buf}, 16); err != nil {
		t.Fatal(err)
	}
	select {
	case w := <-f.written:
		if _, dst, _ := ipv4Addrs(w); dst != netip.MustParseAddr("100.68.0.9") {
			t.Fatalf("answer written to %s, want 100.68.0.9", dst)
		}
		checksumsValid(t, w)
	case <-time.After(2 * time.Second):
		t.Fatal("answer not written to the interface")
	}

	// A port closed takes its networks off: their packets go to the first.
	second.Close()
	f.in <- testPacket(6, "100.68.0.9", "100.85.0.1", 40002, 443)
	readPort(t, first)
}

func TestFirstResolverAnswersOtherNetworksNames(t *testing.T) {
	first := newResolver(netip.MustParseAddr("100.68.0.9"), t.Logf)
	fc := newResolverConf(&api.DNSConfig{Domain: "entowire.internal", Records: []api.Host{{Name: "phone", Address: "100.68.0.9"}}})
	fc.upstream = []string{"192.0.2.53:53"}
	first.set(fc)
	other := newResolver(netip.MustParseAddr("100.85.0.7"), t.Logf)
	other.set(newResolverConf(&api.DNSConfig{Domain: "njoy.internal", Records: []api.Host{{Name: "fs", Address: "100.85.0.20"}},
		Forwards: []api.DNSForward{{Zone: "corp.njoy.example", Servers: []string{"10.20.0.53"}}}}))
	inproc.Lock()
	inproc.resolvers = map[string]*resolver{"tun0": first, "ento1": other}
	inproc.Unlock()
	defer func() {
		inproc.Lock()
		inproc.resolvers = nil
		inproc.Unlock()
	}()
	query := func(name string) []byte {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		q, _ := b.Finish()
		return q
	}
	answerA := func(a []byte) string {
		var p dnsmessage.Parser
		if _, err := p.Start(a); err != nil {
			t.Fatal(err)
		}
		_ = p.SkipAllQuestions()
		if _, err := p.AnswerHeader(); err != nil {
			return ""
		}
		r, _ := p.AResource()
		return netip.AddrFrom4(r.A).String()
	}
	self := netip.MustParseAddr("100.68.0.9")
	if a, _ := first.route(query("phone.entowire.internal."), self); answerA(a) != "100.68.0.9" {
		t.Fatalf("own name: %q", answerA(a))
	}
	if a, _ := first.route(query("fs.njoy.internal."), self); answerA(a) != "100.85.0.20" {
		t.Fatalf("the other network's name: %q", answerA(a))
	}
	if _, servers := first.route(query("x.corp.njoy.example."), self); len(servers) != 1 || servers[0] != "10.20.0.53:53" {
		t.Fatalf("the other network's forwarded zone went to %v", servers)
	}
	if _, servers := first.route(query("example.com."), self); len(servers) != 1 || servers[0] != "192.0.2.53:53" {
		t.Fatalf("every other name went to %v, want the phone's DNS", servers)
	}
}
