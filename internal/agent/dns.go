package agent

// The agent's resolver (0.25 for exits, 0.26 internal DNS), on the device's overlay address, port
// 53, UDP and TCP; on a phone, whose app may not listen on port 53, in the agent's packet path
// instead, on an overlay address no device ever gets (dnsAddress, filtertun.go). It answers the
// device itself (the system's resolver sends it the network's names):
//
//   - the names the control nodes serve (the identity provider's, the admin interface's; 0.30.1,
//     api.DNSConfig.Fixed), with the addresses the network map gives, whatever other DNS says;
//   - names in the network's domain, from the network map (api.DNSConfig): the devices the device
//     reaches and the names administrators gave addresses; nothing else exists in it;
//   - names in a forwarded zone: asked of the zone's name servers (through the tunnel, a route);
//   - any other name: asked of the exit's gateway while an exit is in use, else of the upstream
//     servers when the device has them (a phone, whose VPN sends it every name), else refused.
//
// On a device that is an exit, it also answers the devices that use it, passing their queries to
// the system's resolvers (/etc/resolv.conf) unchanged: their names are resolved where their traffic
// leaves. Nobody else gets an answer (and the inbound filter lets nobody else reach the port).

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"entowire.com/ento/internal/api"
)

// resolverConf is what the resolver answers with; replaced as a whole.
type resolverConf struct {
	domain string                  // fully qualified, lowercase ("example.internal."), "" for none
	names  map[string]netip.Addr   // fully qualified, lowercase
	fixed  map[string][]netip.Addr // names outside the domain the resolver answers itself (fully qualified)
	zones  []resolverZone          // longest first
	exit   netip.Addr              // the exit's gateway, for every other name (invalid: no exit in use)
	// upstream: for every other name without an exit (a phone's DNS servers, host:53).
	upstream []string
	clients  map[netip.Addr]bool // devices using this one as their exit
}

type resolverZone struct {
	zone    string // fully qualified, lowercase
	servers []string
}

// newResolverConf builds the resolver's configuration from a network map's DNS (nil: none).
func newResolverConf(dns *api.DNSConfig) *resolverConf {
	c := &resolverConf{names: map[string]netip.Addr{}, fixed: map[string][]netip.Addr{}, clients: map[netip.Addr]bool{}}
	if dns == nil {
		return c
	}
	for _, h := range dns.Fixed {
		a, err := netip.ParseAddr(h.Address)
		if n, ok := fqdn(h.Name); ok && n != "." && err == nil && a.Is4() && !slices.Contains(c.fixed[n], a) {
			c.fixed[n] = append(c.fixed[n], a)
		}
	}
	if d, ok := fqdn(dns.Domain); ok {
		c.domain = d
		for _, r := range dns.Records {
			a, err := netip.ParseAddr(r.Address)
			if n, ok := fqdn(r.Name + "." + dns.Domain); ok && err == nil && a.Is4() {
				if _, taken := c.names[n]; !taken { // the first wins (devices come first)
					c.names[n] = a
				}
			}
		}
	}
	for _, f := range dns.Forwards {
		z, ok := fqdn(f.Zone)
		if !ok || z == "." {
			continue
		}
		var servers []string
		for _, s := range f.Servers {
			if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
				servers = append(servers, netip.AddrPortFrom(a, 53).String())
			}
		}
		if len(servers) > 0 {
			c.zones = append(c.zones, resolverZone{zone: z, servers: servers})
		}
	}
	slices.SortFunc(c.zones, func(a, b resolverZone) int { return len(b.zone) - len(a.zone) })
	return c
}

// fqdn lowercases a name and ends it with a dot (false: not a usable name).
func fqdn(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "." {
		return ".", s == "."
	}
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s, len(s) <= 254
}

// within reports whether name is zone or in it (both fully qualified).
func within(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// domains are the routing domains of the device's system resolver: the network's domain, the
// forwarded zones and the fixed names (without final dots).
func (c *resolverConf) domains() []string {
	var out []string
	if c.domain != "" {
		out = append(out, strings.TrimSuffix(c.domain, "."))
	}
	for n := range c.fixed {
		out = append(out, strings.TrimSuffix(n, "."))
	}
	for _, z := range c.zones {
		out = append(out, strings.TrimSuffix(z.zone, "."))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

type resolver struct {
	addr  netip.Addr // the device's own address: queries from it are the device's
	udp   *net.UDPConn
	tcp   *net.TCPListener // both nil: in the packet path only
	conf  atomic.Pointer[resolverConf]
	logf  func(string, ...any)
	slots chan struct{} // queries in flight
	wg    sync.WaitGroup
	// system returns the system's resolvers, for the devices using this one as their exit (default:
	// the nameservers of /etc/resolv.conf; tests set it).
	system func() []string
}

const (
	dnsTimeout  = 4 * time.Second
	dnsInFlight = 256
	dnsTTL      = 60 // seconds, the network's names
)

// newResolver makes a resolver for the device with address addr, answering nobody yet.
func newResolver(addr netip.Addr, logf func(string, ...any)) *resolver {
	r := &resolver{addr: addr, logf: logf, slots: make(chan struct{}, dnsInFlight), system: systemResolvers}
	r.conf.Store(newResolverConf(nil))
	return r
}

// startResolver listens on addr:port (53; tests: 0, a free port, the same for TCP).
func startResolver(addr netip.Addr, port uint16, logf func(string, ...any)) (*resolver, error) {
	u, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, port)))
	if err != nil {
		return nil, err
	}
	port = uint16(u.LocalAddr().(*net.UDPAddr).Port)
	t, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, port)))
	if err != nil {
		u.Close()
		return nil, err
	}
	r := newResolver(addr, logf)
	r.udp, r.tcp = u, t
	r.wg.Add(2)
	go r.serveUDP()
	go r.serveTCP()
	return r, nil
}

func (r *resolver) set(c *resolverConf) { r.conf.Store(c) }

func (r *resolver) close() {
	if r.udp != nil {
		r.udp.Close()
		r.tcp.Close()
	}
	r.wg.Wait()
}

// dnsAddress is where a phone's VPN sends DNS queries (its resolver is in the packet path): the
// last address of the network's control range, which no device ever gets (ipam: control nodes
// x.x.0.1-254).
func dnsAddress(network netip.Prefix) netip.Addr {
	b := network.Masked().Addr().As4()
	b[2], b[3] = 0, 255
	return netip.AddrFrom4(b)
}

// exchange answers one query from src over UDP: its own answer or the servers' (nil: none). It
// blocks while servers are asked.
func (r *resolver) exchange(q []byte, src netip.Addr) []byte {
	answer, servers := r.route(q, src)
	if answer != nil || len(servers) == 0 {
		return answer
	}
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	default:
		return nil // too many in flight: the client asks again
	}
	return exchangeUDP(q, servers)
}

// systemResolvers are the nameservers of /etc/resolv.conf as host:53 (the local resolver when it
// names none, as the C library does).
func systemResolvers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return []string{"127.0.0.1:53"}
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if a, err := netip.ParseAddr(fields[1]); err == nil {
				out = append(out, netip.AddrPortFrom(a.WithZone(""), 53).String())
			}
		}
	}
	if len(out) == 0 {
		return []string{"127.0.0.1:53"}
	}
	return out
}

// route decides a query: an answer of the resolver's own, or the servers to ask (both nil: no
// answer at all).
func (r *resolver) route(q []byte, src netip.Addr) (answer []byte, servers []string) {
	c := r.conf.Load()
	if c.clients[src] {
		return nil, r.notSelf(r.system())
	}
	if src != r.addr {
		return nil, nil // only this device itself
	}
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil || h.Response {
		return nil, nil
	}
	qs, err := p.Question()
	if err != nil {
		return nil, nil
	}
	name := strings.ToLower(qs.Name.String())
	if addrs, ok := c.fixed[name]; ok {
		if qs.Type != dnsmessage.TypeA && qs.Type != dnsmessage.TypeALL {
			return reply(h, qs, dnsmessage.RCodeSuccess), nil // no AAAA: the control nodes are IPv4 inside the tunnel
		}
		return reply(h, qs, dnsmessage.RCodeSuccess, addrs...), nil
	}
	zone := slices.IndexFunc(c.zones, func(z resolverZone) bool { return within(name, z.zone) })
	switch {
	case zone >= 0 && (c.domain == "" || !within(name, c.domain) || len(c.zones[zone].zone) > len(c.domain)):
		return nil, c.zones[zone].servers
	case c.domain != "" && within(name, c.domain):
		return c.answer(h, qs, name), nil
	case c.exit.IsValid():
		return nil, []string{netip.AddrPortFrom(c.exit, 53).String()}
	case len(c.upstream) > 0:
		return nil, c.upstream
	}
	return reply(h, qs, dnsmessage.RCodeRefused), nil
}

// notSelf drops this resolver's own address from a list of servers (never ask itself).
func (r *resolver) notSelf(list []string) []string {
	return slices.DeleteFunc(slices.Clone(list), func(s string) bool {
		ap, err := netip.ParseAddrPort(s)
		return err == nil && ap.Addr() == r.addr
	})
}

// answer answers a name in the network's domain.
func (c *resolverConf) answer(h dnsmessage.Header, qs dnsmessage.Question, name string) []byte {
	if a, ok := c.names[name]; ok {
		if qs.Type != dnsmessage.TypeA && qs.Type != dnsmessage.TypeALL {
			return reply(h, qs, dnsmessage.RCodeSuccess) // the name exists, without such a record
		}
		return reply(h, qs, dnsmessage.RCodeSuccess, a)
	}
	if name == c.domain {
		return reply(h, qs, dnsmessage.RCodeSuccess)
	}
	for n := range c.names { // a name with names below it (office. for nas.office.) exists too
		if strings.HasSuffix(n, "."+name) {
			return reply(h, qs, dnsmessage.RCodeSuccess)
		}
	}
	return reply(h, qs, dnsmessage.RCodeNameError)
}

// reply builds an answer to a query: rcode, and an A record for each address.
func reply(h dnsmessage.Header, qs dnsmessage.Question, rcode dnsmessage.RCode, addrs ...netip.Addr) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: rcode != dnsmessage.RCodeRefused,
		RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: rcode})
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(qs) != nil {
		return nil
	}
	if len(addrs) > 0 && b.StartAnswers() != nil {
		return nil
	}
	for _, a := range addrs {
		if b.AResource(dnsmessage.ResourceHeader{Name: qs.Name, Class: dnsmessage.ClassINET, TTL: dnsTTL}, dnsmessage.AResource{A: a.As4()}) != nil {
			return nil
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

func (r *resolver) serveUDP() {
	defer r.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := r.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n < 12 {
			continue
		}
		q := append([]byte(nil), buf[:n]...)
		answer, servers := r.route(q, from.Addr().Unmap())
		if answer != nil {
			_, _ = r.udp.WriteToUDPAddrPort(answer, from)
			continue
		}
		if len(servers) == 0 {
			continue
		}
		select {
		case r.slots <- struct{}{}:
		default:
			continue // too many in flight: the client asks again
		}
		go func() {
			defer func() { <-r.slots }()
			if a := exchangeUDP(q, servers); a != nil {
				_, _ = r.udp.WriteToUDPAddrPort(a, from)
			}
		}()
	}
}

// exchangeUDP asks the servers in turn; nil when none answered.
func exchangeUDP(q []byte, servers []string) []byte {
	buf := make([]byte, 65535)
	for _, up := range servers {
		c, err := net.Dial("udp", up)
		if err != nil {
			continue
		}
		_ = c.SetDeadline(time.Now().Add(dnsTimeout))
		if _, err := c.Write(q); err != nil {
			c.Close()
			continue
		}
		for {
			n, err := c.Read(buf)
			if err != nil {
				break
			}
			if n >= 12 && buf[0] == q[0] && buf[1] == q[1] { // the answer to this query
				c.Close()
				return append([]byte(nil), buf[:n]...)
			}
		}
		c.Close()
	}
	return nil
}

func (r *resolver) serveTCP() {
	defer r.wg.Done()
	for {
		c, err := r.tcp.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
		conf := r.conf.Load()
		if err != nil || ap.Addr().Unmap() != r.addr && !conf.clients[ap.Addr().Unmap()] {
			c.Close()
			continue
		}
		select {
		case r.slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-r.slots }()
			defer c.Close()
			r.relayTCP(c, ap.Addr().Unmap())
		}()
	}
}

// relayTCP answers the queries of one client connection.
func (r *resolver) relayTCP(c net.Conn, src netip.Addr) {
	for {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		q, err := readTCPMessage(c)
		if err != nil || len(q) < 12 {
			return
		}
		answer, servers := r.route(q, src)
		if answer == nil && len(servers) > 0 {
			answer = exchangeTCP(q, servers)
		}
		if answer == nil {
			return
		}
		if err := writeTCPMessage(c, answer); err != nil {
			return
		}
	}
}

func exchangeTCP(q []byte, servers []string) []byte {
	for _, up := range servers {
		ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", up)
		cancel()
		if err != nil {
			continue
		}
		_ = c.SetDeadline(time.Now().Add(dnsTimeout))
		var a []byte
		if err = writeTCPMessage(c, q); err == nil {
			a, err = readTCPMessage(c)
		}
		c.Close()
		if err == nil && len(a) >= 12 {
			return a
		}
	}
	return nil
}

func readTCPMessage(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	m := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err := io.ReadFull(r, m)
	return m, err
}

func writeTCPMessage(w io.Writer, m []byte) error {
	b := make([]byte, 2+len(m))
	binary.BigEndian.PutUint16(b, uint16(len(m)))
	copy(b[2:], m)
	_, err := w.Write(b)
	return err
}
