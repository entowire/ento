package control

// Internal DNS (0.26). With a domain (administrators' choice, 0.55, else Config.DNSDomain, e.g.
// "example.internal"), every device's
// agent answers the names in it, from its network map: the devices of its map (by name) and the
// names administrators give addresses (a printer in an office behind a route), and it asks the name
// servers of forwarded zones (an office's own DNS, through its route) for their names. The control
// plane says, in each device's map, which names that device may resolve: itself, the devices in its
// map, and administrators' names whose address it can reach (a device in its map, a network it
// reaches through a route, or an address outside the network and every route); forwarded zones
// likewise, with the servers it can reach. A device name wins over an administrator's name.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
)

// maxDNSServers limits the name servers of a forwarded zone.
const maxDNSServers = 4

// dnsName checks a DNS name (lowercase letters, digits and dashes in labels of at most 63, at most
// 253 in all) and returns it lowercased, without a final dot.
func dnsName(s string) (string, error) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" || len(s) > 253 {
		return "", errors.New("a name has 1 to 253 characters")
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", fmt.Errorf("%q: labels have 1 to 63 characters and neither start nor end with a dash", s)
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", fmt.Errorf("%q: letters, digits, dashes and dots only", s)
			}
		}
	}
	return s, nil
}

// CheckDNSDomain validates the domain of a network's internal DNS: at least two labels (a single
// label is left to the system's own name resolution).
func CheckDNSDomain(d string) (string, error) {
	n, err := dnsName(d)
	if err != nil {
		return "", err
	}
	if !strings.Contains(n, ".") {
		return "", fmt.Errorf("%q: use at least two labels, such as example.internal", n)
	}
	return n, nil
}

// dnsReachable reports whether a device with this map reaches an address: a device of its map,
// a network it reaches through a route (or serves), or an address outside the network and every
// route.
func dnsReachable(nm api.NetMap, overlay netip.Prefix, routes []store.Route) func(netip.Addr) bool {
	addrs := map[netip.Addr]bool{}
	var nets []netip.Prefix
	if a, err := netip.ParseAddr(nm.Self.Address); err == nil {
		addrs[a] = true
	}
	add := func(list []string) {
		for _, s := range list {
			if p, err := netip.ParsePrefix(s); err == nil && p.Bits() > 0 {
				nets = append(nets, p)
			}
		}
	}
	add(nm.Self.Routes)
	for _, p := range nm.Peers {
		if a, err := netip.ParseAddr(p.Address); err == nil {
			addrs[a] = true
		}
		add(p.Routes)
	}
	return func(a netip.Addr) bool {
		if addrs[a] || slices.ContainsFunc(nets, func(n netip.Prefix) bool { return n.Contains(a) }) {
			return true
		}
		if overlay.Contains(a) {
			return false
		}
		for _, r := range routes {
			if slices.ContainsFunc(r.Networks, func(n netip.Prefix) bool { return n.Contains(a) }) {
				return false
			}
		}
		return true
	}
}

// dnsConfig is the internal DNS of a device's map (nil: the network has none).
func (s *Server) dnsConfig(ctx context.Context, nm api.NetMap) (*api.DNSConfig, error) {
	fixed := s.fixedNames(nm)
	if s.dnsDomain() == "" || !nm.Self.Approved {
		if len(fixed) == 0 {
			return nil, nil
		}
		return &api.DNSConfig{Fixed: fixed}, nil
	}
	records, err := s.cfg.Store.DNSRecords(ctx)
	if err != nil {
		return nil, err
	}
	forwards, err := s.cfg.Store.DNSForwards(ctx)
	if err != nil {
		return nil, err
	}
	routes, err := s.cfg.Store.Routes(ctx)
	if err != nil {
		return nil, err
	}
	reach := dnsReachable(nm, s.cfg.Space.Prefix, routes)
	out := &api.DNSConfig{Domain: s.dnsDomain(), Fixed: fixed}
	// An administrator's record wins over a device's name (A2): a device renamed to it never takes
	// the name over.
	recorded := map[string]bool{}
	for _, r := range records {
		recorded[r.Name] = true
	}
	devices := map[string]bool{}
	device := func(name, addr string) {
		if name != "" && !devices[name] && !recorded[name] {
			devices[name] = true
			out.Records = append(out.Records, api.Host{Name: name, Address: addr})
		}
	}
	device(nm.Self.Hostname, nm.Self.Address)
	for _, p := range nm.Peers {
		device(p.Hostname, p.Address)
	}
	for _, r := range records {
		if reach(r.Address) {
			out.Records = append(out.Records, api.Host{Name: r.Name, Address: r.Address.String()})
		}
	}
	for _, f := range forwards {
		var servers []string
		for _, a := range f.Servers {
			if reach(a) {
				servers = append(servers, a.String())
			}
		}
		if len(servers) > 0 {
			out.Forwards = append(out.Forwards, api.DNSForward{Zone: f.Zone, Servers: servers})
		}
	}
	return out, nil
}

// fixedNames are the names this node serves on its overlay address, port 443, pointed at every
// control node's overlay address (api.DNSConfig.Fixed): forwarded services' (Config.Forwards), the
// identity provider's, when the control
// nodes forward it (an identity provider devices reach directly keeps its own addresses), and the
// admin interface's; then the network's service names as this node resolved them (servicenames.go). A device must reach them to sign in, approved or not, whatever the DNS of the
// network it is on makes of names that point at shared addresses.
func (s *Server) fixedNames(nm api.NetMap) []api.Host {
	var names []string
	if s.cfg.OIDC != nil && len(s.cfg.OIDC.ConnectTo) > 0 {
		if u, err := url.Parse(s.cfg.OIDC.Issuer); err == nil && u.Hostname() != "" && net.ParseIP(u.Hostname()) == nil {
			names = append(names, strings.ToLower(u.Hostname()))
		}
	}
	if s.cfg.AdminUI != "" {
		names = append(names, strings.ToLower(s.cfg.AdminUI))
	}
	for n := range s.cfg.Forwards {
		names = append(names, strings.ToLower(n))
	}
	slices.Sort(names)
	names = slices.Compact(names)
	var out []api.Host
	for _, n := range names {
		for _, c := range nm.Controls {
			if a, err := netip.ParseAddr(c.Address); err == nil && a.Is4() {
				out = append(out, api.Host{Name: n, Address: a.String()})
			}
		}
	}
	if p := s.services.Load(); p != nil {
		for _, h := range *p {
			if !slices.Contains(names, h.Name) { // a name the control nodes serve keeps their addresses
				out = append(out, h)
			}
		}
	}
	return out
}

// loadDNSDomain takes the domain administrators chose from the store (reconcile, on every change).
func (s *Server) loadDNSDomain(ctx context.Context) error {
	v, ok, err := s.cfg.Store.Setting(ctx, store.SettingDNSDomain)
	if err != nil {
		return err
	}
	if ok && v != "" {
		s.domain.Store(&v)
	} else {
		s.domain.Store(nil)
	}
	return nil
}

// dnsDomain is the network's internal DNS domain: administrators' choice, else the control nodes'
// --dns-domain ("": none).
func (s *Server) dnsDomain() string {
	if p := s.domain.Load(); p != nil {
		return *p
	}
	return s.cfg.DNSDomain
}

// handleSetDNSDomain sets or changes the domain (admins, 0.55). Every device's name moves to the
// new domain with its next map; added names and forwarded zones keep theirs (relative to it, or
// their own zone).
func (s *Server) handleSetDNSDomain(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.DNSDomain
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	d, err := CheckDNSDomain(req.Domain)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	old := s.dnsDomain()
	if d == old {
		writeJSON(w, http.StatusOK, api.DNSDomain{Domain: d})
		return
	}
	forwards, err := s.cfg.Store.DNSForwards(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	for _, f := range forwards {
		if f.Zone == d || strings.HasSuffix(d, "."+f.Zone) {
			writeErr(w, http.StatusConflict, fmt.Sprintf("the zone %s is forwarded to other name servers: delete that first", f.Zone))
			return
		}
	}
	if err := s.cfg.Store.SetSetting(r.Context(), store.SettingDNSDomain, d); err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.domain.Store(&d)
	from := old
	if from == "" {
		from = "none"
	}
	s.audit(r, &self, "dns_domain_changed", fmt.Sprintf("domain %s (was %s)", d, from), "ok")
	s.checkVersion(r.Context())
	writeJSON(w, http.StatusOK, api.DNSDomain{Domain: d})
}

// noDNS refuses a change to the internal DNS of a network without a domain.
func (s *Server) noDNS(w http.ResponseWriter) bool {
	if s.dnsDomain() == "" {
		writeErr(w, http.StatusConflict, "this network has no internal DNS yet: set its domain first (ento admin dns domain NAME)")
		return true
	}
	return false
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (s *Server) handleListDNS(w http.ResponseWriter, r *http.Request, _ store.Peer) {
	records, err := s.cfg.Store.DNSRecords(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	forwards, err := s.cfg.Store.DNSForwards(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	peers, err := s.cfg.Store.Peers(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	out := api.DNSAdmin{Domain: s.dnsDomain(), Records: []api.DNSRecord{}, Forwards: []api.DNSForward{}}
	for _, rec := range records {
		a := api.DNSRecord{Name: rec.Name, Address: rec.Address.String(), CreatedAt: stamp(rec.CreatedAt), CreatedBy: rec.CreatedBy}
		if slices.ContainsFunc(peers, func(p store.Peer) bool { return p.Hostname == rec.Name }) {
			a.Warnings = []string{"a device has this name: this record answers for it, not the device"}
		}
		out.Records = append(out.Records, a)
	}
	for _, f := range forwards {
		a := api.DNSForward{Zone: f.Zone, CreatedAt: stamp(f.CreatedAt), CreatedBy: f.CreatedBy}
		for _, s := range f.Servers {
			a.Servers = append(a.Servers, s.String())
		}
		out.Forwards = append(out.Forwards, a)
	}
	writeJSON(w, http.StatusOK, out)
}

// relativeName checks a name for the network's domain and returns it relative to the domain (a
// full name in the domain is accepted).
func (s *Server) relativeName(name string) (string, error) {
	n, err := dnsName(name)
	if err != nil {
		return "", err
	}
	if n == s.dnsDomain() {
		return "", errors.New("the domain itself has no address: name something in it")
	}
	return strings.TrimSuffix(n, "."+s.dnsDomain()), nil
}

func (s *Server) handleAddDNSRecord(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.noDNS(w) {
		return
	}
	var req api.DNSRecord
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	name, err := s.relativeName(req.Name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(req.Address))
	if err != nil || !addr.Is4() {
		writeErr(w, http.StatusBadRequest, "the address is an IPv4 address")
		return
	}
	rec := store.DNSRecord{Name: name, Address: addr, CreatedAt: time.Now(), CreatedBy: peerLabel(self)}
	if err := s.cfg.Store.AddDNSRecord(r.Context(), rec); err != nil {
		if errors.Is(err, store.ErrExists) {
			writeErr(w, http.StatusConflict, "that name has an address: delete it first")
			return
		}
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "dns_record_added", fmt.Sprintf("name %s.%s %s", name, s.dnsDomain(), addr), "ok")
	s.checkVersion(r.Context())
	writeJSON(w, http.StatusCreated, api.DNSRecord{Name: name, Address: addr.String(), CreatedAt: stamp(rec.CreatedAt), CreatedBy: rec.CreatedBy})
}

func (s *Server) handleDeleteDNSRecord(w http.ResponseWriter, r *http.Request, self store.Peer) {
	name := r.PathValue("name")
	if err := s.cfg.Store.DeleteDNSRecord(r.Context(), name); err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "dns_record_deleted", "name "+name, "ok")
	s.checkVersion(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAddDNSForward(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.noDNS(w) {
		return
	}
	var req api.DNSForward
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	zone, err := dnsName(req.Zone)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if zone == s.dnsDomain() {
		writeErr(w, http.StatusBadRequest, "the network's own domain is answered by its devices; forward a zone in it or another one")
		return
	}
	if len(req.Servers) == 0 || len(req.Servers) > maxDNSServers {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("a forwarded zone has 1 to %d name servers", maxDNSServers))
		return
	}
	f := store.DNSForward{Zone: zone, CreatedAt: time.Now(), CreatedBy: peerLabel(self)}
	for _, s := range req.Servers {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || !a.Is4() {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("%q is no IPv4 address", s))
			return
		}
		f.Servers = append(f.Servers, a)
	}
	if err := s.cfg.Store.AddDNSForward(r.Context(), f); err != nil {
		if errors.Is(err, store.ErrExists) {
			writeErr(w, http.StatusConflict, "that zone is forwarded: delete it first")
			return
		}
		s.respondStoreErr(w, err)
		return
	}
	servers := make([]string, 0, len(f.Servers))
	for _, a := range f.Servers {
		servers = append(servers, a.String())
	}
	s.audit(r, &self, "dns_forward_added", fmt.Sprintf("zone %s to %s", zone, strings.Join(servers, ",")), "ok")
	s.checkVersion(r.Context())
	writeJSON(w, http.StatusCreated, api.DNSForward{Zone: zone, Servers: servers, CreatedAt: stamp(f.CreatedAt), CreatedBy: f.CreatedBy})
}

func (s *Server) handleDeleteDNSForward(w http.ResponseWriter, r *http.Request, self store.Peer) {
	zone := r.PathValue("zone")
	if err := s.cfg.Store.DeleteDNSForward(r.Context(), zone); err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "dns_forward_deleted", "zone "+zone, "ok")
	s.checkVersion(r.Context())
	w.WriteHeader(http.StatusNoContent)
}
