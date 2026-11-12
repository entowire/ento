package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Several networks on one device (0.51). Besides the network the agent was installed with (the
// first: its state is the state directory itself), each network the device joined with
// `ento join DOMAIN` has a state directory of its own, <state dir>/networks/<domain>/:
//
//	network.json  the membership: its domain, range, interface and WireGuard port (written by join)
//	enroll.token  the invitation, until the agent has redeemed it
//	error         why the last enrollment failed
//	remove        written by `ento leave`: forget the network on this device
//	state.json, agent.json, ...  what the first network keeps in the state directory, for this one
//
// Each network runs in the device's own namespace on an interface of its own, as an equal of the
// first: its own key and hardware key, rights, filter, posture reports, sign-in and DNS. The
// device forwards nothing between them, and no network's routes or names take another's

// Membership is a network the device joined besides the first.
type Membership struct {
	Domain     string       `json:"domain"`
	Network    netip.Prefix `json:"network"` // from its record, checked against the others at join
	Interface  string       `json:"interface"`
	ListenPort int          `json:"listen_port"`
}

const (
	membershipFile = "network.json"
	enrollFile     = "enroll.token"
)

// NetworksDir is where the networks a device joined besides the first are kept.
func NetworksDir(stateDir string) string { return filepath.Join(stateDir, "networks") }

// NetworkDir is the state directory of a network joined besides the first.
func NetworkDir(stateDir, domain string) string { return filepath.Join(NetworksDir(stateDir), domain) }

var validDomain = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidDomain reports whether d can name a network's domain (lowercase, at least two labels).
func ValidDomain(d string) bool { return len(d) <= 253 && validDomain.MatchString(d) }

// Networks lists the domains of the networks joined besides the first, sorted.
func Networks(stateDir string) []string {
	entries, _ := os.ReadDir(NetworksDir(stateDir))
	var out []string
	for _, e := range entries {
		if e.IsDir() && ValidDomain(e.Name()) && exists(filepath.Join(NetworksDir(stateDir), e.Name(), membershipFile)) {
			out = append(out, e.Name())
		}
	}
	return out
}

// LoadMembership reads a joined network's membership.
func LoadMembership(stateDir, domain string) (Membership, error) {
	var m Membership
	b, err := os.ReadFile(filepath.Join(NetworkDir(stateDir, domain), membershipFile))
	if errors.Is(err, os.ErrNotExist) {
		return m, fmt.Errorf("this device has not joined %s", domain)
	}
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("corrupt %s: %w", membershipFile, err)
	}
	return m, nil
}

// FirstDomain is the domain of the device's first network ("" when the control nodes never named
// it: older than 0.15, or no --record-domain).
func FirstDomain(stateDir string) string {
	st, err := LoadState(stateDir)
	if err != nil {
		return ""
	}
	return strings.ToLower(st.RecordDomain)
}

// NetworkStateDir returns the state directory of the network with domain: the state directory
// itself for the first network (or for "" ), else the joined network's.
func NetworkStateDir(stateDir, domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" || domain == FirstDomain(stateDir) {
		return stateDir, nil
	}
	if !ValidDomain(domain) {
		return "", fmt.Errorf("%q is not a network's domain", domain)
	}
	if !exists(filepath.Join(NetworkDir(stateDir, domain), membershipFile)) {
		// The networks are in the agent's state, root's: without it none can be seen, and the
		// list below would be empty (0.53.1; the first network's sign-in alone goes through the
		// agent for others).
		if _, err := os.ReadDir(stateDir); errors.Is(err, os.ErrPermission) {
			return "", fmt.Errorf("--network %s needs the agent's state, which is root's: run the command with sudo", domain)
		}
		known := []string{}
		if d := FirstDomain(stateDir); d != "" {
			known = append(known, d)
		}
		known = append(known, Networks(stateDir)...)
		return "", fmt.Errorf("this device is not in %s (it is in: %s)", domain, strings.Join(known, ", "))
	}
	return NetworkDir(stateDir, domain), nil
}

// networkInUse is one network of the device as joining another checks it.
type networkInUse struct {
	domain  string
	network netip.Prefix
	iface   string
	port    int
}

// networksInUse lists the device's networks: the first, the joined ones and the linked ones.
func networksInUse(stateDir string, firstIface string, firstPort int) []networkInUse {
	var out []networkInUse
	if st, err := LoadState(stateDir); err == nil {
		n := networkInUse{domain: strings.ToLower(st.RecordDomain), network: st.Network, iface: firstIface, port: firstPort}
		if r, ok := RunningAgent(stateDir); ok && r.Interface != "" {
			n.iface = r.Interface
		}
		out = append(out, n)
	}
	for _, d := range Networks(stateDir) {
		if m, err := LoadMembership(stateDir, d); err == nil {
			out = append(out, networkInUse{domain: m.Domain, network: m.Network, iface: m.Interface, port: m.ListenPort})
		}
	}
	for _, l := range Links(stateDir) {
		if ls, err := LoadLinkState(stateDir, l); err == nil {
			out = append(out, networkInUse{domain: "linked network " + l, network: ls.Network, port: ls.ListenPort})
		}
	}
	return out
}

// CheckJoin refuses a network the device is in already, or whose range overlaps one of its
func CheckJoin(stateDir, domain string, network netip.Prefix) error {
	if _, err := LoadState(stateDir); err != nil {
		return fmt.Errorf("join another network once this device is in one (ento agent install --join DOMAIN): %w", err)
	}
	for _, n := range networksInUse(stateDir, "", 0) {
		if n.domain == domain {
			return fmt.Errorf("this device is in %s already", domain)
		}
		if n.network.IsValid() && network.Overlaps(n.network) {
			return fmt.Errorf("%s uses %s, which overlaps %s of %s on this device: two networks with overlapping ranges cannot both be reached",
				domain, network, n.network, n.domain)
		}
	}
	// The routes the running networks use (through gateways) are theirs as well.
	dirs := []string{stateDir}
	for _, d := range Networks(stateDir) {
		dirs = append(dirs, NetworkDir(stateDir, d))
	}
	for _, dir := range dirs {
		r, ok := RunningAgent(dir)
		if !ok {
			continue
		}
		for _, s := range r.Routes {
			if n, err := netip.ParsePrefix(s); err == nil && n.Overlaps(network) {
				return fmt.Errorf("%s uses %s, which overlaps the route %s this device uses: two networks with overlapping ranges cannot both be reached",
					domain, network, n)
			}
		}
	}
	if exists(NetworkDir(stateDir, domain)) {
		return fmt.Errorf("%s is being joined already (ento leave %s gives up)", domain, domain)
	}
	return nil
}

// RequestJoin hands the running agent a network to join with its invitation: it picks the
// network's interface (ento1, ento2, ...) and WireGuard port (51831 and up, free ones), and writes
// the membership and the token for the agent, which enrolls and brings the network up.
func RequestJoin(stateDir, domain string, network netip.Prefix, token string, firstIface string, firstPort int) (Membership, error) {
	if !networksSupported {
		return Membership{}, errNoNetworks
	}
	if !ValidDomain(domain) {
		return Membership{}, fmt.Errorf("%q is not a network's domain", domain)
	}
	if err := CheckJoin(stateDir, domain, network); err != nil {
		return Membership{}, err
	}
	used := networksInUse(stateDir, firstIface, firstPort)
	m := Membership{Domain: domain, Network: network}
	for i := 1; m.Interface == ""; i++ {
		name := "ento" + strconv.Itoa(i)
		if !slices.ContainsFunc(used, func(n networkInUse) bool { return n.iface == name }) {
			m.Interface = name
		}
	}
	for p := firstPort + 1; p <= 65535 && m.ListenPort == 0; p++ {
		if !slices.ContainsFunc(used, func(n networkInUse) bool { return n.port == p }) && udpPortFree(p) {
			m.ListenPort = p
		}
	}
	if m.ListenPort == 0 {
		return Membership{}, errors.New("no free UDP port for the network's WireGuard")
	}
	dir := NetworkDir(stateDir, domain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Membership{}, err
	}
	if err := protectStateDir(dir); err != nil {
		return Membership{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, enrollFile), []byte(token+"\n"), 0o600); err != nil {
		return Membership{}, err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Membership{}, err
	}
	// The membership last: the agent acts on a directory once it has one.
	if err := os.WriteFile(filepath.Join(dir, membershipFile+".tmp"), b, 0o600); err != nil {
		return Membership{}, err
	}
	return m, os.Rename(filepath.Join(dir, membershipFile+".tmp"), filepath.Join(dir, membershipFile))
}

// RequestLeave asks the running agent to forget a joined network.
func RequestLeave(stateDir, domain string) error {
	if _, err := LoadMembership(stateDir, domain); err != nil {
		if domain == FirstDomain(stateDir) {
			return fmt.Errorf("%s is this device's first network: ento agent uninstall --purge forgets it", domain)
		}
		return err
	}
	return os.WriteFile(filepath.Join(NetworkDir(stateDir, domain), "remove"), nil, 0o600)
}

// JoinError returns why the last attempt to join the network failed, "" for nothing.
func JoinError(stateDir, domain string) string {
	b, _ := os.ReadFile(filepath.Join(NetworkDir(stateDir, domain), "error"))
	return strings.TrimSpace(string(b))
}

// errNoNetworks: joining more than one network is done on Linux only, for now.
var errNoNetworks = errors.New("this device can be in one network only for now: joining more is supported on Linux")

// --- claims ------------------------------------------------------------------------------------

// claim is what one network of the agent holds in the device's own namespace: its range, the
// routes it routes into its interface, its domain (from its record, which is its own) and the
// names its resolver answers. Another network's routes and names that overlap it are left out
// route nor its names with a zone of its own.
type claim struct {
	network netip.Prefix
	routes  []netip.Prefix
	domain  string   // the record's domain, fully qualified ("" for none)
	names   []string // the internal domain, forwarded zones and fixed names in use, fully qualified
}

var claims = struct {
	sync.Mutex
	m map[string]*claim // by interface name
}{m: map[string]*claim{}}

// setClaim changes the claim of the network on interface ifName.
func setClaim(ifName string, change func(*claim)) {
	claims.Lock()
	defer claims.Unlock()
	c := claims.m[ifName]
	if c == nil {
		c = &claim{}
		claims.m[ifName] = c
	}
	change(c)
}

func dropClaim(ifName string) {
	claims.Lock()
	defer claims.Unlock()
	delete(claims.m, ifName)
}

// otherClaims returns copies of the claims of the networks on other interfaces than ifName, and
// those interfaces' names, sorted.
func otherClaims(ifName string) ([]claim, []string) {
	claims.Lock()
	defer claims.Unlock()
	var out []claim
	var names []string
	for n, c := range claims.m {
		if n == ifName {
			continue
		}
		names = append(names, n)
		out = append(out, claim{network: c.network, routes: slices.Clone(c.routes), domain: c.domain, names: slices.Clone(c.names)})
	}
	slices.Sort(names)
	return out, names
}

// namesOverlap reports whether one of two fully qualified names is the other or in it.
func namesOverlap(a, b string) bool { return within(a, b) || within(b, a) }

// takenName reports whether name (fully qualified) is another network's: it overlaps another's
// domain or one of the names it uses, and is not in own, the network's own domain (its record's
// domain is its own whatever another network claims).
func takenName(name, own string, others []claim) bool {
	if own != "" && within(name, own) {
		return false
	}
	for _, c := range others {
		if c.domain != "" && namesOverlap(name, c.domain) {
			return true
		}
		for _, n := range c.names {
			if namesOverlap(name, n) {
				return true
			}
		}
	}
	return false
}

// withoutTaken leaves out of a resolver configuration the names another network of the device
// holds, and returns what it left out.
func (c *resolverConf) withoutTaken(own string, others []claim) []string {
	var dropped []string
	if c.domain != "" && takenName(c.domain, own, others) {
		dropped = append(dropped, strings.TrimSuffix(c.domain, "."))
		c.domain, c.names = "", map[string]netip.Addr{}
	}
	for n := range c.fixed {
		if takenName(n, own, others) {
			dropped = append(dropped, strings.TrimSuffix(n, "."))
			delete(c.fixed, n)
		}
	}
	zones := c.zones[:0]
	for _, z := range c.zones {
		if takenName(z.zone, own, others) {
			dropped = append(dropped, strings.TrimSuffix(z.zone, "."))
			continue
		}
		zones = append(zones, z)
	}
	c.zones = zones
	slices.Sort(dropped)
	return dropped
}

// claimedNames are the names a resolver configuration answers, fully qualified.
func (c *resolverConf) claimedNames() []string {
	var out []string
	if c.domain != "" {
		out = append(out, c.domain)
	}
	for n := range c.fixed {
		out = append(out, n)
	}
	for _, z := range c.zones {
		out = append(out, z.zone)
	}
	slices.Sort(out)
	return out
}

// recordFQDN is a record domain fully qualified ("" for none).
func recordFQDN(d string) string {
	if d == "" {
		return ""
	}
	n, ok := fqdn(d)
	if !ok || n == "." {
		return ""
	}
	return n
}

// claimNetwork records a network's range and domain as its own, from its state.
func claimNetwork(ifName string, st State) {
	setClaim(ifName, func(c *claim) { c.network, c.domain = st.Network.Masked(), recordFQDN(st.RecordDomain) })
}

// preloadClaims records the ranges and domains of the joined networks before any network of the
// agent starts (each network's claim is replaced by its runner's once that starts).
func preloadClaims(stateDir string) {
	for _, d := range Networks(stateDir) {
		m, err := LoadMembership(stateDir, d)
		if err != nil {
			continue
		}
		st, err := LoadState(NetworkDir(stateDir, d))
		if err != nil {
			setClaim(m.Interface, func(c *claim) { c.network, c.domain = m.Network, recordFQDN(m.Domain) })
			continue
		}
		if st.RecordDomain == "" {
			st.RecordDomain = m.Domain
		}
		claimNetwork(m.Interface, st)
	}
}

// claimRoutes takes, of the routes a network's map offers (candidates), those no other network of
// the device holds or overlaps, records them as the network's, and returns them. Checked and
// recorded at once, so that two networks offering the same route never both take it: the first
// keeps it.
func claimRoutes(ifName string, candidates []netip.Prefix) map[netip.Prefix]bool {
	claims.Lock()
	defer claims.Unlock()
	var taken []netip.Prefix
	for n, c := range claims.m {
		if n == ifName {
			continue
		}
		if c.network.IsValid() {
			taken = append(taken, c.network)
		}
		taken = append(taken, c.routes...)
	}
	granted := map[netip.Prefix]bool{}
	var own []netip.Prefix
	for _, n := range candidates {
		if granted[n] || slices.ContainsFunc(taken, n.Overlaps) {
			continue
		}
		granted[n] = true
		own = append(own, n)
	}
	c := claims.m[ifName]
	if c == nil {
		c = &claim{}
		claims.m[ifName] = c
	}
	c.routes = own
	return granted
}

// claimNames leaves out of a network's resolver configuration the names another network of the
// device holds, records what remains as the network's, and returns what it left out; at once, as
// claimRoutes. own is the network's record domain (fully qualified), which stays its own.
func claimNames(ifName, own string, conf *resolverConf) []string {
	claims.Lock()
	defer claims.Unlock()
	var others []claim
	for n, c := range claims.m {
		if n != ifName {
			others = append(others, *c)
		}
	}
	dropped := conf.withoutTaken(own, others)
	c := claims.m[ifName]
	if c == nil {
		c = &claim{}
		claims.m[ifName] = c
	}
	c.names = conf.claimedNames()
	return dropped
}

var memberIfaceName = regexp.MustCompile(`^ento[1-9][0-9]{0,2}$`)

// memberInterface reports whether ifName is the name join gives a joined network's interface.
func memberInterface(ifName string) bool { return memberIfaceName.MatchString(ifName) }

// takenRange returns the range or route of another network of the device that network overlaps
// ("" for none).
func takenRange(ifName string, network netip.Prefix) string {
	claims.Lock()
	defer claims.Unlock()
	for n, c := range claims.m {
		if n == ifName {
			continue
		}
		if c.network.IsValid() && c.network.Overlaps(network) {
			return c.network.String()
		}
		for _, r := range c.routes {
			if r.Overlaps(network) {
				return r.String()
			}
		}
	}
	return ""
}
