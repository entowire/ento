package agent

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun"

	"entowire.com/ento/internal/api"
)

func TestChooseExit(t *testing.T) {
	nm := api.NetMap{Peers: []api.Peer{
		{PublicKey: "k1", Address: "100.64.1.2", Hostname: "office-gw", Exits: []api.ExitOffer{{Route: "office"}}},
		{PublicKey: "k2", Address: "100.64.1.3", Hostname: "cloud-gw", Exits: []api.ExitOffer{{Route: "cloud", Default: true}}},
	}}
	for _, c := range []struct{ choice, want string }{
		{"", "cloud"}, {"office", "office"}, {"cloud", "cloud"}, {ExitOff, ""}, {"elsewhere", ""},
	} {
		got, ok := chooseExit(nm, c.choice)
		if ok != (c.want != "") || got.Route != c.want {
			t.Errorf("choice %q: %+v %v, want %q", c.choice, got, ok, c.want)
		}
	}
	if o, _ := chooseExit(nm, "office"); o.Key != "k1" || o.Via != "office-gw" || o.Addr != netip.MustParseAddr("100.64.1.2") {
		t.Errorf("the office exit: %+v", o)
	}
	nm.Self.Exit = true // an exit itself uses none
	if _, ok := chooseExit(nm, "office"); ok {
		t.Error("an exit uses another")
	}
	dir := t.TempDir()
	if ExitChoice(dir) != "" {
		t.Fatal("a choice without a file")
	}
	for _, c := range []string{"office", ExitOff, ""} {
		if err := SetExitChoice(dir, c); err != nil || ExitChoice(dir) != c {
			t.Fatalf("choice %q: %v, read %q", c, err, ExitChoice(dir))
		}
	}
	if SetExitChoice(dir, "../etc") == nil {
		t.Fatal("a choice that is no name")
	}
}

// The resolver answers the device itself: the network's names, forwarded zones through their
// servers, other names through the exit or the upstream servers; the devices using it as their exit
// through the system's resolvers; nobody else.
func TestResolver(t *testing.T) {
	// A name server that answers every query with its own ID and a marker byte.
	server := func(mark byte) string {
		up, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { up.Close() })
		go func() {
			buf := make([]byte, 512)
			for {
				n, from, err := up.ReadFromUDP(buf)
				if err != nil {
					return
				}
				_, _ = up.WriteToUDP(append(append([]byte(nil), buf[:n]...), mark), from)
			}
		}()
		upTCP, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: up.LocalAddr().(*net.UDPAddr).Port})
		if err != nil {
			t.Skipf("TCP on the name server's port: %v", err)
		}
		t.Cleanup(func() { upTCP.Close() })
		go func() {
			for {
				c, err := upTCP.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					if q, err := readTCPMessage(c); err == nil {
						_ = writeTCPMessage(c, append(q, mark))
					}
				}()
			}
		}()
		return up.LocalAddr().String()
	}
	system, office, exit := server('S'), server('O'), server('X')
	self := netip.MustParseAddr("127.0.0.2")
	r, err := startResolver(self, 0, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	r.system = func() []string { return []string{system} }
	conf := newResolverConf(&api.DNSConfig{Domain: "Example.Internal",
		Records:  []api.Host{{Name: "laptop-1", Address: "100.64.1.2"}, {Name: "nas.office", Address: "192.168.10.5"}, {Name: "laptop-1", Address: "10.0.0.1"}},
		Forwards: []api.DNSForward{{Zone: "corp.example.com", Servers: []string{"127.0.0.1"}}}})
	conf.zones[0].servers = []string{office} // the test's server listens on another port than 53
	r.set(conf)
	at := r.udp.LocalAddr().String()
	query := func(name string, typ dnsmessage.Type) []byte {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
		q, _ := b.Finish()
		return q
	}
	ask := func(from string, q []byte) []byte {
		c, err := net.DialUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(from), 0)), net.UDPAddrFromAddrPort(netip.MustParseAddrPort(at)))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = c.Write(q)
		buf := make([]byte, 512)
		n, err := c.Read(buf)
		if err != nil {
			return nil
		}
		return buf[:n]
	}
	parse := func(a []byte) (dnsmessage.RCode, []netip.Addr) {
		var p dnsmessage.Parser
		h, err := p.Start(a)
		if err != nil {
			t.Fatalf("answer %x: %v", a, err)
		}
		_ = p.SkipAllQuestions()
		var addrs []netip.Addr
		for {
			rh, err := p.AnswerHeader()
			if err != nil {
				break
			}
			if rh.Type == dnsmessage.TypeA {
				res, _ := p.AResource()
				addrs = append(addrs, netip.AddrFrom4(res.A))
			} else {
				_ = p.SkipAnswer()
			}
		}
		return h.RCode, addrs
	}
	for _, c := range []struct {
		name  string
		typ   dnsmessage.Type
		rcode dnsmessage.RCode
		addr  string
	}{
		{"laptop-1.example.internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, "100.64.1.2"}, // the first record wins
		{"LAPTOP-1.example.internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, "100.64.1.2"},
		{"laptop-1.example.internal.", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, ""},
		{"nas.office.example.internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, "192.168.10.5"},
		{"office.example.internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, ""},
		{"example.internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, ""},
		{"nobody.example.internal.", dnsmessage.TypeA, dnsmessage.RCodeNameError, ""},
		{"example.com.", dnsmessage.TypeA, dnsmessage.RCodeRefused, ""}, // neither exit nor upstream
	} {
		a := ask("127.0.0.2", query(c.name, c.typ))
		if a == nil {
			t.Fatalf("%s: no answer", c.name)
		}
		rcode, addrs := parse(a)
		if rcode != c.rcode || (c.addr == "") != (len(addrs) == 0) || c.addr != "" && addrs[0].String() != c.addr {
			t.Errorf("%s %v: %v %v, want %v %s", c.name, c.typ, rcode, addrs, c.rcode, c.addr)
		}
	}
	marked := func(a []byte, mark byte) bool { return len(a) > 12 && a[len(a)-1] == mark }
	if a := ask("127.0.0.2", query("git.corp.example.com.", dnsmessage.TypeA)); !marked(a, 'O') {
		t.Errorf("forwarded zone: %x", a)
	}
	// Other names: through the exit while one is in use, else the upstream servers.
	exitConf := *conf
	exitConf.exit = netip.MustParseAddr("127.0.0.1")
	r.set(&exitConf)
	if _, servers := r.route(query("example.com.", dnsmessage.TypeA), self); len(servers) != 1 || servers[0] != "127.0.0.1:53" {
		t.Errorf("an exit in use: %v", servers)
	}
	upConf := *conf
	upConf.upstream = []string{exit}
	r.set(&upConf)
	if a := ask("127.0.0.2", query("example.com.", dnsmessage.TypeA)); !marked(a, 'X') {
		t.Errorf("upstream: %x", a)
	}
	// The names the control nodes serve (an identity provider's): answered by the resolver itself
	// with every control node's address, also without a domain (a device not approved yet), never
	// asked of the upstream servers, whose DNS may drop answers pointing at shared addresses.
	fixedConf := newResolverConf(&api.DNSConfig{Fixed: []api.Host{{Name: "ID.Example.com", Address: "100.64.0.1"},
		{Name: "id.example.com.", Address: "100.64.0.2"}, {Name: "id.example.com", Address: "100.64.0.1"}, {Name: "bad", Address: "nope"}}})
	fixedConf.upstream = []string{exit}
	r.set(fixedConf)
	if d := fixedConf.domains(); !slices.Equal(d, []string{"id.example.com"}) || fixedConf.domain != "" {
		t.Errorf("routing domains %v, domain %q", d, fixedConf.domain)
	}
	if rcode, addrs := parse(ask("127.0.0.2", query("id.EXAMPLE.com.", dnsmessage.TypeA))); rcode != dnsmessage.RCodeSuccess ||
		!slices.Equal(addrs, []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2")}) {
		t.Errorf("fixed name: %v %v", rcode, addrs)
	}
	if rcode, addrs := parse(ask("127.0.0.2", query("id.example.com.", dnsmessage.TypeAAAA))); rcode != dnsmessage.RCodeSuccess || len(addrs) != 0 {
		t.Errorf("fixed name, AAAA: %v %v", rcode, addrs)
	}
	if a := ask("127.0.0.2", query("www.example.com.", dnsmessage.TypeA)); !marked(a, 'X') {
		t.Errorf("other names with fixed ones: %x", a)
	}
	if a := ask("127.0.0.1", query("id.example.com.", dnsmessage.TypeA)); a != nil {
		t.Fatalf("answered a stranger a fixed name: %x", a)
	}
	r.set(&upConf)

	// A device using this one as its exit: everything through the system's resolvers; a stranger:
	// nothing.
	if a := ask("127.0.0.1", query("example.com.", dnsmessage.TypeA)); a != nil {
		t.Fatalf("answered a stranger: %x", a)
	}
	upConf.clients = map[netip.Addr]bool{netip.MustParseAddr("127.0.0.1"): true}
	r.set(&upConf)
	if a := ask("127.0.0.1", query("laptop-1.example.internal.", dnsmessage.TypeA)); !marked(a, 'S') {
		t.Errorf("exit client: %x", a)
	}
	c, err := net.Dial("tcp4", at)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := writeTCPMessage(c, query("example.com.", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	if a, err := readTCPMessage(c); err != nil || !marked(a, 'S') {
		t.Fatalf("exit client over TCP: %x %v", a, err)
	}
}

// capturingTUN records what is written towards the system.
type capturingTUN struct {
	tun.Device
	written chan []byte
}

func (c *capturingTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		c.written <- append([]byte(nil), b[offset:]...)
	}
	return len(bufs), nil
}

// A phone's resolver is in the packet path: a query to the network's DNS address never enters the
// network, and the answer comes back as a well-formed IPv4 UDP datagram.
func TestResolverInPath(t *testing.T) {
	network := netip.MustParsePrefix("100.64.0.0/16")
	self, dnsAddr := netip.MustParseAddr("100.64.1.7"), dnsAddress(network)
	if dnsAddr.String() != "100.64.0.255" {
		t.Fatalf("DNS address %s", dnsAddr)
	}
	r := newResolver(self, t.Logf)
	r.set(newResolverConf(&api.DNSConfig{Domain: "example.internal", Records: []api.Host{{Name: "nas", Address: "192.168.10.5"}}}))
	ct := &capturingTUN{written: make(chan []byte, 4)}
	ft := newFilterTUN(ct)
	ft.setDNS(dnsAddr, r)
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("nas.example.internal."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	const offset = 16
	query := udpPacket(self, 40000, dnsAddr, 53, q)
	other := udpPacket(self, 40001, netip.MustParseAddr("100.64.1.9"), 53, q) // DNS to a device: not ours
	bufs := [][]byte{make([]byte, offset+len(query)), make([]byte, offset+len(other))}
	copy(bufs[0][offset:], query)
	copy(bufs[1][offset:], other)
	sizes := []int{len(query), len(other)}
	ft.interceptDNS(bufs, sizes, offset, 2)
	if sizes[0] != 0 || sizes[1] != len(other) {
		t.Fatalf("sizes after interception %v", sizes)
	}
	var p []byte
	select {
	case p = <-ct.written:
	case <-time.After(2 * time.Second):
		t.Fatal("no answer written")
	}
	if len(p) < 28 || netip.AddrFrom4([4]byte(p[12:16])) != dnsAddr || netip.AddrFrom4([4]byte(p[16:20])) != self ||
		binary.BigEndian.Uint16(p[20:22]) != 53 || binary.BigEndian.Uint16(p[22:24]) != 40000 {
		t.Fatalf("answer datagram %x", p)
	}
	if checksum(p[:20], 0) != 0xffff {
		t.Fatal("IPv4 header checksum")
	}
	pseudo := append(append(append([]byte{}, p[12:20]...), 0, 17), p[24:26]...)
	if checksum(p[20:], checksum(pseudo, 0)) != 0xffff {
		t.Fatal("UDP checksum")
	}
	var parser dnsmessage.Parser
	if _, err := parser.Start(p[28:]); err != nil {
		t.Fatal(err)
	}
	_ = parser.SkipAllQuestions()
	if a, err := parser.AnswerHeader(); err != nil || a.Type != dnsmessage.TypeA {
		t.Fatalf("answer %v %v", a, err)
	}
	if res, _ := parser.AResource(); netip.AddrFrom4(res.A).String() != "192.168.10.5" {
		t.Fatalf("answer address %v", res.A)
	}
}
