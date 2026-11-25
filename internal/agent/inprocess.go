package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
)

// The agent inside a mobile app (RunOnTUN): the network the app was set up with (the first) and
// every network it joined since (0.60, the same state as on Linux: networks.go), each on a port of
// the one VPN interface (muxtun.go). The app reaches each through the functions below, which take
// the network's domain ("" for the first).

// current is the first network's runner; inproc holds the joined networks' and what the first
// network's resolver needs of theirs.
var current atomic.Pointer[runner]

var inproc struct {
	sync.Mutex
	members   map[string]*runner   // by domain
	resolvers map[string]*resolver // by interface name, every network's that has one
	protect   func(fd int) bool    // the app's VpnService.protect, while the agent runs
}

// RunOnTUN runs the device's networks on a TUN interface someone else created and configured (the
// first network's address and routes, and every joined network's): a mobile system's VPN service
// hands over its file descriptor. protect, if set, receives WireGuard's own sockets to exempt them
// from that interface (Android's VpnService.protect). Linked networks are not run.
func RunOnTUN(ctx context.Context, cfg Config, t tunDevice, protect func(fd int) bool) error {
	cfg.defaults()
	st, err := LoadState(cfg.StateDir)
	if err != nil {
		return err
	}
	mux := newMuxTUN(t)
	name, _ := t.Name()
	first := mux.port(name, st.Address)
	first.setClaims([]netip.Prefix{st.Network.Masked()})
	inproc.Lock()
	inproc.protect = protect
	inproc.Unlock()
	defer func() {
		inproc.Lock()
		inproc.protect = nil
		inproc.Unlock()
	}()
	env := hostEnv()
	env.open = func(cfg Config) (tunnel, error) { return userspaceOnTUN(first, cfg.ListenPort, protect, cfg.Logf) }
	preloadClaims(cfg.StateDir)
	var a *runner
	a, err = startRunner(cfg, env, st, portSync(first, &a))
	if err != nil {
		mux.Close()
		return err
	}
	defer a.close()
	syncPort(first, a)
	current.Store(a)
	defer current.Store(nil)
	go a.reevaluate(ctx)
	go a.reportPosture(ctx)
	go a.checkIns(ctx)
	networksDone := make(chan struct{})
	go func() { runJoinedInProcess(ctx, cfg, mux, protect); close(networksDone) }()
	defer func() { <-networksDone }() // the joined networks are down before the first goes
	return a.loop(ctx)
}

// portSync keeps a port's claims and the network's resolver up to date with every map the network
// applies (apply holds a.mu). The runner is known once started; the first map is applied before.
func portSync(p *muxPort, a **runner) func(api.NetMap) {
	return func(api.NetMap) {
		if r := *a; r != nil {
			syncPortLocked(p, r)
		}
	}
}

func syncPort(p *muxPort, a *runner) {
	a.mu.Lock()
	defer a.mu.Unlock()
	syncPortLocked(p, a)
}

// syncPortLocked: the caller holds a.mu.
func syncPortLocked(p *muxPort, a *runner) {
	list := []netip.Prefix{a.st.Network.Masked()}
	for n := range a.osRoutes {
		list = append(list, n)
	}
	p.setClaims(list)
	inproc.Lock()
	defer inproc.Unlock()
	if inproc.resolvers == nil {
		inproc.resolvers = map[string]*resolver{}
	}
	if a.resolver != nil {
		inproc.resolvers[p.name] = a.resolver
	} else {
		delete(inproc.resolvers, p.name)
	}
}

// runJoinedInProcess runs the networks joined besides the first, each on a port of mux, until ctx
// ends; it starts networks joined since and stops those left.
func runJoinedInProcess(ctx context.Context, cfg Config, mux *muxTUN, protect func(fd int) bool) {
	type member struct {
		cancel context.CancelFunc
		done   chan struct{}
	}
	running := map[string]*member{}
	stop := func(d string) {
		if m, ok := running[d]; ok {
			m.cancel()
			<-m.done
			delete(running, d)
		}
	}
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		joined := Networks(cfg.StateDir)
		for d := range running {
			if !slices.Contains(joined, d) || exists(filepath.Join(NetworkDir(cfg.StateDir, d), "remove")) {
				stop(d)
			}
		}
		for _, d := range joined {
			if _, ok := running[d]; ok || exists(filepath.Join(NetworkDir(cfg.StateDir, d), "remove")) {
				continue
			}
			m, err := LoadMembership(cfg.StateDir, d)
			if err != nil {
				continue
			}
			mcfg := memberConfig(cfg, m)
			st, err := LoadState(mcfg.StateDir)
			if err != nil {
				continue // not enrolled: JoinInProcess enrolls before it writes the membership
			}
			p := mux.port(m.Interface, st.Address)
			p.setClaims([]netip.Prefix{st.Network.Masked()})
			env := hostEnv()
			env.open = func(c Config) (tunnel, error) { return userspaceOnTUN(p, c.ListenPort, protect, c.Logf) }
			var a *runner
			a, err = startNetwork(mcfg, env, st, portSync(p, &a), true)
			if err != nil {
				p.Close()
				mcfg.Logf("start: %v", err)
				continue
			}
			syncPort(p, a)
			a.announces = true
			mctx, cancel := context.WithCancel(ctx)
			mr := &member{cancel: cancel, done: make(chan struct{})}
			inproc.Lock()
			if inproc.members == nil {
				inproc.members = map[string]*runner{}
			}
			inproc.members[d] = a
			inproc.Unlock()
			go a.reevaluate(mctx)
			go a.reportPosture(mctx)
			go a.checkIns(mctx)
			go func() {
				defer close(mr.done)
				defer func() {
					inproc.Lock()
					delete(inproc.members, d)
					delete(inproc.resolvers, p.name)
					inproc.Unlock()
					dropMapApprovals(mcfg.StateDir)
					a.close()
				}()
				_ = a.loop(mctx)
			}()
			running[d] = mr
			mcfg.Logf("up as %s", st.Address)
		}
		select {
		case <-ctx.Done():
			for d := range running {
				stop(d)
			}
			return
		case <-t.C:
		}
	}
}

// otherResolvers returns the resolvers of the device's other in-process networks than r's.
func otherResolvers(r *resolver) []*resolver {
	inproc.Lock()
	defer inproc.Unlock()
	var out []*resolver
	for _, o := range inproc.resolvers {
		if o != r {
			out = append(out, o)
		}
	}
	return out
}

// inProcessRunner returns the running agent of a network: "" or the first network's domain for the
// first, else a joined network's.
func inProcessRunner(domain string) *runner {
	a := current.Load()
	if domain == "" || (a != nil && a.st.RecordDomain == domain) {
		return a
	}
	inproc.Lock()
	defer inproc.Unlock()
	return inproc.members[domain]
}

// CheckJoinInProcess refuses another network before its words are asked for: one the phone is in,
func CheckJoinInProcess(stateDir, domain string, network netip.Prefix) error {
	if st, err := LoadState(stateDir); err == nil && strings.EqualFold(st.RecordDomain, domain) {
		return fmt.Errorf("this phone is in %s already (its first network)", domain)
	}
	if err := CheckJoin(stateDir, domain, network); err != nil {
		return err
	}
	for _, r := range InProcessRoutes() {
		if n, err := netip.ParsePrefix(r); err == nil && n.Bits() > 0 && n.Overlaps(network) {
			return fmt.Errorf("%s uses %s, which overlaps the route %s this phone uses: two networks with overlapping ranges cannot both be reached",
				domain, network, n)
		}
	}
	return nil
}

// JoinInProcess joins another network from inside the app (0.60): the record of the network's
// domain (_ento.<domain>, already looked up and confirmed) and the token its words make. It enrolls
// at once, on a network stack of its own, and writes the membership only once enrolled; the running
// agent brings the network up within seconds (runJoinedInProcess).
func JoinInProcess(ctx context.Context, cfg Config, domain string, network netip.Prefix, tok string) error {
	cfg.defaults()
	first, err := LoadState(cfg.StateDir)
	if err != nil {
		return err
	}
	if err := CheckJoinInProcess(cfg.StateDir, domain, network); err != nil {
		return err
	}
	preloadClaims(cfg.StateDir)
	if a := current.Load(); a == nil {
		claimNetwork("first", first) // the first network's range, while its agent is not running
		defer dropClaim("first")
	}
	m, err := RequestJoin(cfg.StateDir, domain, network, tok, "tun0", cfg.ListenPort)
	if err != nil {
		return err
	}
	dir := NetworkDir(cfg.StateDir, domain)
	fail := func(err error) error {
		_ = os.RemoveAll(dir)
		return err
	}
	// RequestJoin wrote the membership for an agent that enrolls by itself; here enrollment comes
	// first, so the membership waits until the state is there.
	mpath := filepath.Join(dir, membershipFile)
	mb, err := os.ReadFile(mpath)
	if err != nil {
		return fail(err)
	}
	if err := os.Remove(mpath); err != nil {
		return fail(err)
	}
	mcfg := memberConfig(cfg, m)
	perm, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fail(err)
	}
	env := hostEnv()
	env.enrollTunnel = func(c Config, addr netip.Addr) (tunnel, *http.Client, error) {
		return openNetstack(addr, c.MTU, c.Logf)
	}
	st, err := enroll(ctx, mcfg, env, tok, perm, "")
	if err != nil {
		return fail(err)
	}
	if st.Network.Masked() != m.Network.Masked() {
		return fail(fmt.Errorf("enrolled as %s, but in range %s while the network's record named %s: not kept (an administrator deletes the device there)",
			st.Address, st.Network, m.Network))
	}
	st.RecordDomain = domain
	if err := SaveState(dir, st); err != nil {
		return fail(err)
	}
	_ = os.Remove(filepath.Join(dir, enrollFile))
	if err := os.WriteFile(mpath, mb, 0o600); err != nil {
		return fail(err)
	}
	mcfg.Logf("joined as %s", st.Address)
	return nil
}

// LeaveInProcess forgets a joined network on this device (the network keeps the device until an
// administrator deletes it): the running agent stops it, then its state goes.
func LeaveInProcess(stateDir, domain string) error {
	if err := RequestLeave(stateDir, domain); err != nil {
		return err
	}
	for i := 0; i < 50 && inProcessRunner(domain) != nil; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if inProcessRunner(domain) != nil {
		return errors.New("the network did not stop: try again")
	}
	dropMapApprovals(NetworkDir(stateDir, domain))
	return os.RemoveAll(NetworkDir(stateDir, domain))
}

// InProcessRoutes returns the routes' networks every running network wants in the tunnel, sorted,
// with 0.0.0.0/0 while the first network's exit is in use: a mobile system's VPN fixes its routes
// when it is created, so the app creates it again when these change.
func InProcessRoutes() []string {
	var all []*runner
	if a := current.Load(); a != nil {
		all = append(all, a)
	}
	inproc.Lock()
	for _, a := range inproc.members {
		all = append(all, a)
	}
	inproc.Unlock()
	var out []string
	for _, a := range all {
		a.mu.Lock()
		for n := range a.osRoutes {
			out = append(out, n.String())
		}
		if a.exit != nil {
			out = append(out, exitNetwork.String())
		}
		a.mu.Unlock()
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// InProcessSelf returns what a network's map says about the device itself (approval, groups,
// whether its sign-in ended), once one arrived.
func InProcessSelf(domain string) (api.Self, bool) {
	a := inProcessRunner(domain)
	if a == nil {
		return api.Self{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.last.Self, a.version != 0
}

// InProcessPeers returns a running network's peers, whether it runs, and whether its person must
// sign in.
func InProcessPeers(domain string) (map[wgtypes.Key]PeerStatus, bool, bool) {
	a := inProcessRunner(domain)
	if a == nil {
		return nil, false, false
	}
	st, err := a.ifc.Status()
	if err != nil {
		return nil, true, a.loginRequired
	}
	return st, true, a.loginRequired
}

// InProcessDNS returns the DNS server the VPN names, "" for none: the first network's resolver in
// the packet path (dnsAddress), once it can answer every name (an exit in use, or the phone's DNS
// servers known: SetUpstreamDNS). It sends the joined networks' names to theirs.
func InProcessDNS() string {
	a := current.Load()
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.resolver == nil {
		return ""
	}
	c := a.resolver.conf.Load()
	if !c.exit.IsValid() && len(c.upstream) == 0 {
		return ""
	}
	return dnsAddress(a.st.Network).String()
}

// InProcessExit returns the exit the first network uses ("" when none): the app routes 0.0.0.0/0
// into its VPN then (InProcessRoutes lists it). Exits are the first network's only.
func InProcessExit() string {
	a := current.Load()
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.exit == nil {
		return ""
	}
	return a.exit.Route
}

// InProcessExits returns the exits the first network offers.
func InProcessExits() []RunningExit {
	a := current.Load()
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.runningExits()
}

// InProcessPosture returns a network's latest posture report, when it made one, and the checks the
// device fails there.
func InProcessPosture(domain string) (*api.Posture, time.Time, []api.PostureFailure) {
	a := inProcessRunner(domain)
	if a == nil {
		return nil, time.Time{}, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.posture, a.postureAt, slices.Clone(a.failing)
}

// inProcessProtect returns the app's socket protection while the agent runs (nil otherwise).
func inProcessProtect() func(fd int) bool {
	inproc.Lock()
	defer inproc.Unlock()
	return inproc.protect
}
