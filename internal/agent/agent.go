package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/hwsig"
	"entowire.com/ento/internal/token"
)

// netEnv is where a network lives on this device: the agent's own namespace for the home network,
// a namespace of its own for each linked network. Sockets talking to a network's control plane
// are created inside its namespace.
type netEnv struct {
	ns        netns.NsHandle // Linux: the network's namespace (None: the agent's own)
	http      *http.Client
	listenUDP func(laddr *net.UDPAddr) (*net.UDPConn, error)
	open      func(cfg Config) (tunnel, error)
	// enrollTunnel, when set, provides the temporary tunnel an enrollment runs over (with addr, the
	// token's temporary address) and the HTTP client that reaches the control plane through it.
	enrollTunnel func(cfg Config, addr netip.Addr) (tunnel, *http.Client, error)
}

func hostEnv() netEnv {
	return netEnv{ns: netns.None(), http: httpClient, open: openHostTunnel,
		listenUDP: func(laddr *net.UDPAddr) (*net.UDPConn, error) {
			return net.ListenUDP("udp4", laddr)
		}}
}

func (e netEnv) openIface(cfg Config) (tunnel, error) { return e.open(cfg) }

// Config configures an agent.
type Config struct {
	Version    string // of the running binary, announced in <state dir>/agent.json
	StateDir   string
	Interface  string
	ListenPort int
	MTU        int
	// Userspace runs WireGuard inside the agent on a TUN interface even where the kernel has
	// WireGuard (Linux); it is the only way on other systems.
	Userspace bool
	// Hostname is the name the device enrolls under (default: the system's host name).
	Hostname string
	// LinkIdle: a linked network nothing was sent to for this long is left (0: never).
	LinkIdle time.Duration
	// Quiet (0.34) is for devices on a battery whose radio wakes for every packet (phones): no
	// keepalives to any peer (the network map's long poll keeps the way to a control node open),
	// and pending sign-in approvals learned from the network map instead of a poll of their own.
	Quiet bool
	// HardwareKey (0.31): HardwareKeyAuto (the default) binds a key held by the TPM, where there is
	// one, which signs check-ins and certifies a WireGuard key changed daily; HardwareKeyOff never
	// does. TPMDevice is the TPM (default /dev/tpmrm0; a socket: a software TPM, for tests).
	HardwareKey string
	TPMDevice   string
	// LogDrops (0.29) logs the new connections the inbound filter refuses, at most 20 a minute:
	// in the kernel's log (nftables, prefix "ento-filter drop: ") or, with WireGuard in the agent,
	// as the agent's own lines in the same format. LogDropsOff keeps install from carrying it over
	// from the service installed before.
	LogDrops    bool
	LogDropsOff bool
	// NoSelfUpdate (0.37) leaves releases the home network's map offers alone (selfupdate.go).
	NoSelfUpdate bool
	Logf         func(format string, args ...any)
}

func (c *Config) defaults() {
	if c.StateDir == "" {
		c.StateDir = DefaultStateDir
	}
	if c.Interface == "" {
		c.Interface = "ento0"
	}
	if c.ListenPort == 0 {
		c.ListenPort = 51830
	}
	if c.MTU == 0 {
		c.MTU = 1380
	}
	if c.Logf == nil {
		c.Logf = log.Printf
	}
}

// staleHandshake is how old a peer's last handshake may be before the agent points it at the
// endpoint from the network map again (otherwise WireGuard's own roaming is left alone).
const staleHandshake = 3 * time.Minute

// Enroll redeems a token: it reaches the control plane with the token's temporary key, registers a
// freshly generated permanent key and saves the resulting state. It does nothing if already enrolled.
func Enroll(ctx context.Context, cfg Config, tokenText string) (State, error) {
	cfg.defaults()
	if st, err := LoadState(cfg.StateDir); err == nil {
		return st, nil
	} else if !errors.Is(err, ErrNotEnrolled) {
		return State{}, err
	}
	perm, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return State{}, err
	}
	st, err := enroll(ctx, cfg, hostEnv(), tokenText, perm, "")
	if err != nil {
		return State{}, err
	}
	if err := SaveState(cfg.StateDir, st); err != nil {
		return State{}, err
	}
	return st, nil
}

// enroll redeems a token in env with the permanent key perm (and, for an authority's token, a
// credential for perm) and returns the new state without saving it.
func enroll(ctx context.Context, cfg Config, env netEnv, tokenText string, perm wgtypes.Key, credential string) (State, error) {
	tok, err := token.Parse(tokenText)
	if err != nil {
		return State{}, err
	}
	creds, err := token.Derive(tok.Secret)
	if err != nil {
		return State{}, err
	}
	enrollTunnel := env.enrollTunnel
	if enrollTunnel == nil {
		enrollTunnel = func(cfg Config, addr netip.Addr) (tunnel, *http.Client, error) {
			ifc, err := env.openIface(cfg)
			if err != nil {
				return nil, nil, err
			}
			if err := ifc.SetAddress(netip.PrefixFrom(addr, 32)); err != nil {
				ifc.Close()
				return nil, nil, err
			}
			return ifc, env.http, nil
		}
	}
	ifc, httpc, err := enrollTunnel(cfg, tok.TempAddress)
	if err != nil {
		return State{}, err
	}
	defer ifc.Close()
	var peers []PeerConfig
	for _, c := range tok.Controls {
		peers = append(peers, PeerConfig{PublicKey: c.PublicKey, PresharedKey: creds.PresharedKey,
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(c.Address, 32)}, Endpoint: c.Endpoint, Keepalive: keepalive})
		if err := ifc.AddRoute(netip.PrefixFrom(c.Address, 32)); err != nil {
			return State{}, err
		}
	}
	if err := ifc.Configure(creds.PrivateKey, peers); err != nil {
		return State{}, err
	}

	hostname := cfg.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	req := api.RedeemRequest{PublicKey: perm.PublicKey().String(), Hostname: hostname, OS: runtime.GOOS, Credential: credential}
	var res api.RedeemResponse
	var lastErr error
	for attempt := 0; attempt < 5 && ctx.Err() == nil; attempt++ {
		for _, c := range tok.Controls {
			lastErr = postJSON(ctx, httpc, fmt.Sprintf("http://%s%s", c.Address, api.PathRedeem), req, &res)
			if lastErr == nil {
				break
			}
			cfg.Logf("redeem via %s: %v", c.Address, lastErr)
			var he httpError
			if errors.As(lastErr, &he) && he.code == http.StatusForbidden {
				return State{}, fmt.Errorf("enrollment refused: %w", lastErr)
			}
		}
		if lastErr == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if lastErr != nil {
		return State{}, fmt.Errorf("enrollment failed: %w", lastErr)
	}

	st := State{PrivateKey: Key(perm), Controls: res.Controls}
	if st.Address, err = netip.ParseAddr(res.Address); err != nil {
		return State{}, err
	}
	if st.Network, err = netip.ParsePrefix(res.Network); err != nil {
		return State{}, err
	}
	cfg.Logf("enrolled as %s (approved: %v)", st.Address, res.Approved)
	return st, nil
}

// Run keeps the interface in sync with the network map until ctx is cancelled, together with the
// linked networks of this device.
func Run(ctx context.Context, cfg Config) error {
	cfg.defaults()
	st, err := LoadState(cfg.StateDir)
	if err != nil {
		return err
	}
	// Two agents on one state would also trade its check-in tokens, which looks like a copied
	// identity (and suspends a device bound to a person). Where the process can be told apart from
	// another that got its PID (Linux, macOS), a second one refuses to start.
	if r, ok := RunningAgent(cfg.StateDir); ok && r.PID != os.Getpid() && runtime.GOOS != "windows" && agentProcess(r.PID) {
		return fmt.Errorf("another agent (process %d) is running with %s: stop it first (ento agent down, or stop the service)", r.PID, cfg.StateDir)
	}
	// The key signs this device's calls: keep it from other users (Windows: a state directory made
	// before it was locked down at every write).
	if err := protectStateDir(cfg.StateDir); err != nil {
		cfg.Logf("state directory: %v", err)
	}
	// An agent that runs is up, however it was started: a mark left by Down no longer applies.
	if err := setDown(cfg.StateDir, false); err != nil {
		cfg.Logf("%v", err)
	}
	a, err := startRunner(cfg, hostEnv(), st, nil)
	if err != nil {
		return err
	}
	defer a.close()
	for _, w := range OverlayWarnings(st.Network) {
		cfg.Logf("WARNING: %s", w)
	}
	a.startHardwareKey()
	a.announces = true
	a.announce()
	go a.reevaluate(ctx)
	go a.reportPosture(ctx)
	go a.checkIns(ctx)
	go manageLinks(ctx, cfg, a)
	go serveSessions(ctx, cfg)
	return a.loop(ctx)
}

// startRunner configures a network's interface from its state.
func startRunner(cfg Config, env netEnv, st State, onApply func(api.NetMap)) (*runner, error) {
	ifc, err := env.openIface(cfg)
	if err != nil {
		return nil, err
	}
	if err := ifc.SetAddress(netip.PrefixFrom(st.Address, st.Network.Bits())); err != nil {
		ifc.Close()
		return nil, err
	}
	rel, err := newRelayer(st.Address, cfg.ListenPort, cfg.Logf, env.listenUDP)
	if err != nil {
		ifc.Close()
		return nil, err
	}
	a := &runner{cfg: cfg, env: env, st: st, ifc: ifc, relay: rel, onApply: onApply, started: time.Now(),
		paths: map[wgtypes.Key]*path{}, last: api.NetMap{Controls: st.Controls}, postureWake: make(chan struct{}, 1),
		personChanged: make(chan struct{})}
	if err := a.apply(a.last); err != nil {
		a.close()
		return nil, err
	}
	return a, nil
}

// home reports whether the runner is the device's own network (not a linked network, which lives in
// a namespace of its own: exits and the system's DNS are none of its business).
func (a *runner) home() bool { return a.saveFn == nil && !a.env.ns.IsOpen() }

// save persists the state; the caller holds a.mu.
func (a *runner) save() error {
	if a.saveFn != nil {
		return a.saveFn(a.st)
	}
	return SaveState(a.cfg.StateDir, a.st)
}

func (a *runner) close() {
	a.mu.Lock()
	a.announces = false
	if a.exit != nil { // the system's own routing and names again
		a.syncExit(nil)
	}
	if a.dnsApplied != "" { // the system's own names again
		a.applySystemDNS(dnsSettings{})
	}
	if a.resolver != nil {
		a.resolver.close()
		a.resolver = nil
	}
	a.mu.Unlock()
	a.relay.Close()
	a.ifc.Close()
}

// key returns the device's private key in this network.
func (a *runner) key() wgtypes.Key {
	a.mu.Lock()
	defer a.mu.Unlock()
	return wgtypes.Key(a.st.PrivateKey)
}

// controls returns the control nodes currently known.
func (a *runner) controls() []api.Control {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]api.Control(nil), a.st.Controls...)
}

// directTimeout is how long a peer gets to complete a direct handshake before its traffic is
// relayed through a control node.
const directTimeout = 20 * time.Second

// path tracks how a mesh peer is reached.
type path struct {
	since   time.Time // when the current direct attempt started
	direct  string    // endpoint the direct attempt uses
	relayed bool
	// tx is what WireGuard had sent to the peer at the last look; waiting, whether something was
	// sent without a session since (an attempt that started at since). An idle peer without
	// keepalives has no session and sends nothing: not a failed direct path.
	tx      int64
	waiting bool
}

type runner struct {
	cfg     Config
	env     netEnv
	onApply func(api.NetMap)  // called with every applied network map (linked networks)
	saveFn  func(State) error // persists a changed state; nil: the home state in cfg.StateDir
	st      State
	ifc     tunnel
	relay   *relayer
	current int // index of the control node in use
	version int64

	// moved.go: since when no control node has answered, the last lookup of the network record,
	// and what it last logged.
	unansweredSince time.Time
	movedLookup     time.Time
	movedNoted      string

	dropLog *dropLog // Config.LogDrops, with WireGuard in the agent

	// hwkey.go: the hardware key (nil: none), whether it is bound, what status shows of it, the
	// last binding attempt; a key change under way, whether the pending key is the one in use, and
	// when the keys were last swapped while a change's outcome is open.
	hw            hwsig.Signer
	hwBound       bool
	hwNote        string
	hwTried       time.Time
	rotating      bool
	swappedKey    bool
	pendingSwapAt time.Time

	loginRequired bool // last reported by the home network (home runner only)
	// personActive: whether the person's layer is open, as the home network last said (home
	// runner only); personChanged is closed and replaced when that changes, so that linked
	// networks renew their credentials at once (a session that ended must end their access too).
	personActive  bool
	personChanged chan struct{}
	// cut: this linked network's peers are dropped (its home network refused to renew the
	// credential); the control nodes stay, so that a renewal can bring them back.
	cut       bool
	announces bool // writes <state dir>/agent.json (the home network of a service or `agent run`)

	mu    sync.Mutex
	last  api.NetMap
	paths map[wgtypes.Key]*path
	// osRoutes are the routes' networks routed into the interface now; skipped those left out
	// because a network of this device overlaps them (logged once).
	osRoutes map[netip.Prefix]bool
	skipped  map[netip.Prefix]bool
	// announcedRoutes: the routes and served networks agent.json shows (routesKey).
	announcedRoutes string
	// userspaceGateway: a route's gateway on the agent's own WireGuard was told it does not forward.
	userspaceGateway bool
	// exit: the exit in use (nil: none); exitSet once the routing was made to match, exitAt when it
	// was last checked; exitNoted the last thing logged about an exit left unused.
	exit      *exitPick
	exitSet   bool
	exitAt    time.Time
	exitNoted string
	// resolver: the agent's resolver (dns.go), nil when nothing needs it; dnsApplied: the system's
	// DNS settings made for it (dnsSettings.key, "" for none), dnsAt when; dnsNoted the last thing
	// logged about it.
	resolver *resolver
	// personCount: the interface's count of the person's traffic, as last read; onTraffic, when
	// set, is told when it moved (a linked network's last use).
	personCount uint64
	onTraffic   func()
	dnsInit     bool
	dnsApplied  string
	dnsAt       time.Time
	dnsNoted    string
	// The latest posture report the control plane took, and the checks the device fails.
	posture   *api.Posture
	postureAt time.Time
	failing   []api.PostureFailure
	// user and userName: the person the device is bound to (api.Self), for announce.
	user, userName string
	announceMu     sync.Mutex // serialises announce's writes
	// failingFile, when set, keeps the failing checks for `ento agent status` (linked networks).
	failingFile string
	postureWake chan struct{} // asks for a report now
	attestErr   string        // why the latest attestation failed, as logged (reportPosture only)
	started     time.Time     // when the runner started (awaitReport)
}

// announce writes what `ento agent status` shows of the running agent (home network only).
func (a *runner) announce() {
	if !a.announces {
		return
	}
	// One announce at a time, snapshot and write together: announce is called from several
	// goroutines, and an older snapshot written after a newer one (or two writes through the same
	// temporary file) would show stale or broken state.
	a.announceMu.Lock()
	defer a.announceMu.Unlock()
	a.mu.Lock()
	r := Running{Version: a.cfg.Version, PID: os.Getpid(), Links: linksSupported, Interface: a.ifc.IfName(),
		LoginRequired: a.loginRequired, Posture: a.posture, PostureFailing: slices.Clone(a.failing),
		User: a.user, UserName: a.userName, Serves: slices.Clone(a.last.Self.Routes), ExitFor: a.last.Self.Exit,
		Exits: a.runningExits()}
	if a.last.DNS != nil && a.resolver != nil {
		r.DNSDomain, r.Resolver = a.last.DNS.Domain, a.resolver.addr.String()
	}
	r.PersonActive, r.PersonSince = a.last.Self.PersonActive, a.last.Self.PersonSince
	r.HardwareKey = a.hwNote
	if !a.st.KeyCreatedAt.IsZero() {
		r.KeyCreatedAt = a.st.KeyCreatedAt.UTC().Format(time.RFC3339)
	}
	for n := range a.osRoutes {
		r.Routes = append(r.Routes, n.String())
	}
	slices.Sort(r.Routes)
	if !a.postureAt.IsZero() {
		r.PostureReportedAt = a.postureAt.UTC().Format(time.RFC3339)
	}
	a.mu.Unlock()
	if err := writeRunning(a.cfg, r); err != nil {
		a.cfg.Logf("announce: %v", err)
	}
}

// reevaluate re-applies the last network map periodically, so peers that fail to connect
// directly are switched to the relay even when nothing else changes.
func (a *runner) reevaluate(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.mu.Lock()
			nm := a.last
			a.mu.Unlock()
			prefix := netip.PrefixFrom(a.st.Address, a.st.Network.Bits())
			if fixed, err := a.ifc.RepairAddress(prefix); err != nil {
				a.cfg.Logf("check %s: %v", a.ifc.IfName(), err)
			} else if fixed {
				a.cfg.Logf("%s had lost its address or was down (another program, e.g. NetworkManager's Disconnect, changed it): put back", a.ifc.IfName())
				a.mu.Lock()
				if a.dnsApplied != "" {
					a.dnsApplied = "?" // the system's resolver forgot the interface's settings with it
				}
				a.mu.Unlock()
			}
			if err := a.apply(nm); err != nil {
				a.cfg.Logf("apply network map: %v", err)
			}
			a.watchPersonTraffic()
		}
	}
}

func (a *runner) loop(ctx context.Context) error {
	backoff := time.Second
	for ctx.Err() == nil {
		ctls := a.controls()
		ctl := ctls[a.current%len(ctls)]
		if addr, err := netip.ParseAddr(ctl.Address); err == nil {
			a.relay.SetControl(addr)
		}
		var nm api.NetMap
		url := fmt.Sprintf("http://%s%s?since=%d", ctl.Address, api.PathNetMap, a.version)
		if a.cfg.Quiet && a.saveFn == nil { // approvals come with the map (0.34)
			url += fmt.Sprintf("&approvals=%d", mapApprovalsCount())
		}
		// Signed although control nodes do not require it yet, so that a later version can.
		req, err := signedRequest(ctx, http.MethodGet, url, nil, a.key(), ctl)
		if err == nil {
			err = doJSON(a.env.http, req, &nm)
		}
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			a.cfg.Logf("network map from %q (%s): %v", ctl.Name, ctl.Address, err)
			a.noteMapResult(ctx, false)
			a.resolvePendingKey(false)
			a.current++ // fail over to the next control node
			time.Sleep(backoff)
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		a.noteMapResult(ctx, true)
		a.resolvePendingKey(true)
		if nm.Version != a.version {
			a.cfg.Logf("network map v%d from %q: %d peers (approved: %v)", nm.Version, ctl.Name, len(nm.Peers), nm.Self.Approved)
		}
		if err := a.apply(nm); err != nil {
			a.cfg.Logf("apply network map: %v", err)
			time.Sleep(time.Second)
			continue
		}
		a.version = nm.Version
		if a.cfg.Quiet && a.saveFn == nil {
			noteMapApprovals(nm)
		}
		if a.home() {
			a.confirmUpdate()
			a.maybeUpdate(ctx, ctl, nm.Update)
		}
		if nm.Self.RotateKey && a.saveFn == nil {
			go a.rotateKey(ctx, "asked by the control plane")
		}
		if routes := a.routesKey(); a.saveFn == nil && routes != a.announcedRoutes {
			a.announcedRoutes = routes
			a.announce()
		}
		if a.saveFn == nil && (nm.Self.LoginRequired != a.loginRequired || nm.Self.User != a.user || nm.Self.UserName != a.userName) {
			a.mu.Lock()
			ended := nm.Self.LoginRequired && !a.loginRequired
			a.loginRequired, a.user, a.userName = nm.Self.LoginRequired, nm.Self.User, nm.Self.UserName
			a.mu.Unlock()
			if ended {
				a.cfg.Logf("the single sign-on session of this device ended; run `sudo ento agent login` to reconnect")
			}
			a.announce()
		}
		if a.saveFn == nil {
			a.mu.Lock()
			changed := nm.Self.PersonActive != a.personActive
			if changed {
				a.personActive = nm.Self.PersonActive
				close(a.personChanged)
				a.personChanged = make(chan struct{})
			}
			a.mu.Unlock()
			if changed {
				a.announce() // `ento agent status` shows the session as it is now (it showed the last one written)
			}
		}
		if nm.Self.Approved {
			a.setFailing(nm.Self.PostureFailing)
		}
	}
	return nil
}

// personChange returns a channel closed when the person's layer next opens or ends (home runner).
func (a *runner) personChange() <-chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.personChanged
}

// setCut drops a linked network's peers (on) or brings them back (off), applying the last map again.
func (a *runner) setCut(on bool) error {
	a.mu.Lock()
	if a.cut == on {
		a.mu.Unlock()
		return nil
	}
	a.cut = on
	nm := a.last
	a.mu.Unlock()
	return a.apply(nm)
}

// apply configures WireGuard from a network map and persists a changed control node list.
func (a *runner) apply(nm api.NetMap) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.last = nm
	a.relay.SetControls(a.st.Controls)
	if len(nm.Controls) > 0 && !sameControls(nm.Controls, a.st.Controls) || nm.RecordDomain != "" && nm.RecordDomain != a.st.RecordDomain {
		if len(nm.Controls) > 0 {
			a.st.Controls = nm.Controls
		}
		if nm.RecordDomain != "" {
			a.st.RecordDomain = nm.RecordDomain
		}
		if err := a.save(); err != nil {
			return err
		}
	}
	status, err := a.ifc.Status()
	if err != nil {
		return err
	}
	var desired []PeerConfig
	controls := map[wgtypes.Key]bool{}
	for _, c := range a.st.Controls {
		pc, err := peerConfig(c.PublicKey, c.Address, []string{c.Endpoint}, status, true)
		if err != nil {
			return err
		}
		if !a.cfg.Quiet {
			pc.Keepalive = keepalive
		}
		controls[pc.PublicKey] = true
		desired = append(desired, pc)
	}
	seen := map[wgtypes.Key]bool{}
	wantRoutes := map[netip.Prefix]bool{}
	var local []netip.Prefix
	var exit *exitPick
	if a.saveFn == nil { // the device's own namespace, where its other networks are
		local = localNetworks(a.ifc.IfName())
	}
	if a.home() {
		if o, ok := chooseExit(nm, ExitChoice(a.cfg.StateDir)); ok {
			if exitsSupported(a.ifc) {
				exit = &o
			} else {
				a.noteExit(fmt.Sprintf("exit %s through %q left unused: this system cannot use exits yet (Linux and Android can)", o.Route, o.Via))
			}
		}
	}
	exitPeer := false
	peers := nm.Peers
	if a.cut {
		peers = nil
	}
	for _, p := range peers {
		pc, err := peerConfig(p.PublicKey, p.Address, p.Endpoints, status, false)
		if err != nil {
			return err
		}
		if !a.cfg.Quiet && !p.Quiet { // a quiet peer (a phone) is sent nothing it did not ask for
			pc.Keepalive = keepalive
		}
		pc.AllowedIPs = append(pc.AllowedIPs, a.routeNetworks(p, local, wantRoutes)...)
		if exit != nil && p.PublicKey == exit.Key && !controls[pc.PublicKey] && !seen[pc.PublicKey] {
			pc.AllowedIPs = append(pc.AllowedIPs, exitNetwork)
			exitPeer = true
		}
		// A map peer with a control node's key would replace the control node's own peer (and its
		// routes), and a key listed twice the earlier entry: both are dropped.
		if controls[pc.PublicKey] || seen[pc.PublicKey] {
			a.cfg.Logf("network map: peer %q (%s) dropped: its key is a control node's or listed twice", p.Hostname, p.Address)
			continue
		}
		seen[pc.PublicKey] = true
		if err := a.choosePath(&pc, p, status[pc.PublicKey]); err != nil {
			return err
		}
		desired = append(desired, pc)
	}
	for k := range a.paths {
		if !seen[k] {
			delete(a.paths, k)
		}
	}
	a.relay.SetPeers(seen)
	if err := a.ifc.Configure(wgtypes.Key(a.st.PrivateKey), desired); err != nil {
		return err
	}
	a.syncRoutes(wantRoutes)
	if a.home() {
		if !exitPeer {
			exit = nil
		}
		a.syncExit(exit)
	}
	if (len(nm.Self.Routes) > 0 || nm.Self.Exit) && !kernelTunnel(a.ifc) && !a.userspaceGateway {
		a.userspaceGateway = true
		what := strings.Join(nm.Self.Routes, ", ")
		if nm.Self.Exit {
			what = strings.TrimPrefix(what+", an exit", ", ")
		}
		a.cfg.Logf("this device is the gateway of %s, but it forwards only with the kernel's WireGuard (Linux, without --userspace)", what)
	}
	// What each peer may open on this device (a map of control nodes before 0.19 has no filter, and
	// everything passes as before). A filter that cannot be applied is logged; the peers stay.
	filter := filterFromMap(nm)
	if filter != nil && a.cfg.LogDrops {
		if a.dropLog == nil {
			a.dropLog = &dropLog{logf: a.cfg.Logf, iface: a.ifc.IfName()}
		}
		filter.logDrops = a.dropLog
		filter.key += "\nlog drops"
	}
	switch {
	case filter == nil:
	case !a.home(): // a linked network: everything the device sends there is its person's work
		filter.countPerson(&personRules{all: true, controls: filter.controls})
	case filter.person != nil:
		r := *filter.person
		r.exit = exit != nil && !exitForMachine(nm, *exit)
		filter.countPerson(&r)
	}
	if err := a.ifc.SetFilter(filter); err != nil {
		a.cfg.Logf("inbound filter: %v", err)
	}
	if a.home() {
		a.syncResolver(nm, filter)
	}
	if a.onApply != nil {
		a.onApply(nm)
	}
	return nil
}

// choosePath decides between the direct endpoint and the relay for a mesh peer. A peer is tried
// directly first; when something was sent to it and no handshake followed within directTimeout it
// is relayed (an idle peer without a session, such as a quiet phone, is not a failed path). It is
// tried directly again when the endpoint published for it changes (e.g. it moved to another network).
func (a *runner) choosePath(pc *PeerConfig, p api.Peer, st PeerStatus) error {
	direct := ""
	if len(p.Endpoints) > 0 {
		direct = p.Endpoints[0]
	}
	ps, ok := a.paths[pc.PublicKey]
	if !ok || ps.direct != direct {
		ps = &path{since: time.Now(), direct: direct}
		a.paths[pc.PublicKey] = ps
	}
	fresh := !st.LastHandshake.IsZero() && time.Since(st.LastHandshake) < staleHandshake
	grew := st.TxBytes > ps.tx
	ps.tx = st.TxBytes
	switch {
	case fresh:
		ps.waiting = false
	case grew && !ps.waiting: // sending without a session: a direct attempt starts
		ps.waiting, ps.since = true, time.Now()
	}
	if !ps.relayed && !fresh && (direct == "" || ps.waiting && time.Since(ps.since) > directTimeout) {
		ps.relayed = true
		a.cfg.Logf("peer %q (%s): no direct path, relaying through the control plane", p.Hostname, p.Address)
	}
	if ps.relayed {
		ep, err := a.relay.Endpoint(pc.PublicKey)
		if err != nil {
			return err
		}
		pc.Endpoint = ep
	}
	return nil
}

// peerConfig builds a peer's configuration. The endpoint from the network map is only applied to
// new peers, control nodes (whose endpoint is authoritative), and peers without a recent
// handshake; otherwise WireGuard's roaming keeps the path it found.
func peerConfig(pub, addr string, endpoints []string, status map[wgtypes.Key]PeerStatus, control bool) (PeerConfig, error) {
	key, err := wgtypes.ParseKey(pub)
	if err != nil {
		return PeerConfig{}, err
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return PeerConfig{}, err
	}
	pc := PeerConfig{PublicKey: key, AllowedIPs: []netip.Prefix{netip.PrefixFrom(ip, 32)}}
	st, known := status[key]
	fresh := known && !st.LastHandshake.IsZero() && time.Since(st.LastHandshake) < staleHandshake
	if len(endpoints) > 0 && (control || !fresh) {
		pc.Endpoint = endpoints[0]
	}
	return pc, nil
}

func sameControls(a, b []api.Control) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

var httpClient = &http.Client{
	Timeout: 40 * time.Second,
	Transport: &http.Transport{
		DialContext:       (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		DisableKeepAlives: false,
	},
}

func getJSON(ctx context.Context, c *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	return doJSON(c, req, out)
}

func postJSON(ctx context.Context, c *http.Client, url string, in, out any) error {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(json.NewEncoder(pw).Encode(in)) }()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, pr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// Enrollment talks from the temporary address, which disappears right after: never reuse
	// that connection for later requests.
	req.Close = true
	return doJSON(c, req, out)
}

// httpError is a non-2xx answer from a control node.
type httpError struct {
	code    int
	msg     string
	failing []api.PostureFailure // the posture checks a link refused a credential over
}

func (e httpError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.code, e.msg) }

// PostureRefusal returns the posture checks a control node named when it refused the device (a
// link's credential), nil when the error is about something else.
func PostureRefusal(err error) []api.PostureFailure {
	var he httpError
	if errors.As(err, &he) {
		return he.failing
	}
	return nil
}

// HTTPStatus returns the HTTP status of a control node's answer an error carries, 0 when none.
func HTTPStatus(err error) int {
	var he httpError
	if errors.As(err, &he) {
		return he.code
	}
	return 0
}

func doJSON(c *http.Client, req *http.Request, out any) error {
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return httpError{code: resp.StatusCode, msg: e.Error, failing: e.PostureFailing}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// EnrollInProcess enrolls like Enroll, but runs the temporary tunnel on a network stack inside the
// agent: no interface, no privileges. For systems where the interface is made by someone else
// (a mobile system's VPN service) and exists only once the device knows its address.
func EnrollInProcess(ctx context.Context, cfg Config, tokenText string) (State, error) {
	cfg.defaults()
	if st, err := LoadState(cfg.StateDir); err == nil {
		return st, nil
	} else if !errors.Is(err, ErrNotEnrolled) {
		return State{}, err
	}
	perm, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return State{}, err
	}
	env := hostEnv()
	env.enrollTunnel = func(cfg Config, addr netip.Addr) (tunnel, *http.Client, error) {
		return openNetstack(addr, cfg.MTU, cfg.Logf)
	}
	st, err := enroll(ctx, cfg, env, tokenText, perm, "")
	if err != nil {
		return State{}, err
	}
	return st, SaveState(cfg.StateDir, st)
}

// RunOnTUN runs the home network like Run, on a TUN interface someone else created and configured
// (address and routes of the state's network): a mobile system's VPN service hands over its file
// descriptor. protect, if set, receives WireGuard's own sockets to exempt them from that interface
// (Android's VpnService.protect). Linked networks are not run.
func RunOnTUN(ctx context.Context, cfg Config, t tunDevice, protect func(fd int) bool) error {
	cfg.defaults()
	st, err := LoadState(cfg.StateDir)
	if err != nil {
		return err
	}
	env := hostEnv()
	env.open = func(cfg Config) (tunnel, error) { return userspaceOnTUN(t, cfg.ListenPort, protect, cfg.Logf) }
	a, err := startRunner(cfg, env, st, nil)
	if err != nil {
		return err
	}
	defer a.close()
	current.Store(a)
	defer current.Store(nil)
	go a.reevaluate(ctx)
	go a.reportPosture(ctx)
	go a.checkIns(ctx)
	return a.loop(ctx)
}

// current is the runner of RunOnTUN, for Peers of an in-process agent (no control socket there).
var current atomic.Pointer[runner]

// InProcessRoutes returns the routes' networks the agent running in this process (RunOnTUN) wants
// in the tunnel, sorted, with 0.0.0.0/0 while an exit is in use: a mobile system's VPN fixes its
// routes when it is created, so the app creates it again when these change.
func InProcessRoutes() []string {
	a := current.Load()
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.osRoutes)+1)
	for n := range a.osRoutes {
		out = append(out, n.String())
	}
	if a.exit != nil {
		out = append(out, exitNetwork.String())
	}
	slices.Sort(out)
	return out
}

// InProcessSelf returns what the network map of the agent running in this process (RunOnTUN) says
// about the device itself (approval, groups, whether its sign-in ended), once one arrived.
func InProcessSelf() (api.Self, bool) {
	a := current.Load()
	if a == nil {
		return api.Self{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.last.Self, a.version != 0
}

// InProcessPeers returns the peers of the agent running in this process (RunOnTUN), if any.
func InProcessPeers() (map[wgtypes.Key]PeerStatus, bool, bool) {
	a := current.Load()
	if a == nil {
		return nil, false, false
	}
	st, err := a.ifc.Status()
	if err != nil {
		return nil, true, a.loginRequired
	}
	return st, true, a.loginRequired
}

// routeNetworks are the networks this device reaches through peer p (its routes), less those that
// overlap a network the device is on (in the office itself, the LAN is reached directly; routing it
// into the tunnel would also capture WireGuard's own packets to the gateway). They go into want.
func (a *runner) routeNetworks(p api.Peer, local []netip.Prefix, want map[netip.Prefix]bool) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range p.Routes {
		n, err := netip.ParsePrefix(s)
		if err != nil || !n.Addr().Is4() || n.Bits() == 0 || want[n] {
			continue
		}
		if slices.ContainsFunc(local, n.Overlaps) {
			if a.skipped == nil {
				a.skipped = map[netip.Prefix]bool{}
			}
			if !a.skipped[n] {
				a.skipped[n] = true
				a.cfg.Logf("route %s through %q left out: this device is on a network that overlaps it", n, p.Hostname)
			}
			continue
		}
		delete(a.skipped, n)
		want[n] = true
		out = append(out, n)
	}
	return out
}

// syncRoutes routes the wanted networks into the interface and takes away those no longer wanted.
func (a *runner) syncRoutes(want map[netip.Prefix]bool) {
	if a.osRoutes == nil {
		a.osRoutes = map[netip.Prefix]bool{}
	}
	for n := range want {
		if a.osRoutes[n] {
			continue
		}
		if err := a.ifc.AddRoute(n); err != nil {
			a.cfg.Logf("route %s: %v", n, err)
			continue
		}
		a.osRoutes[n] = true
		a.cfg.Logf("route %s into %s", n, a.ifc.IfName())
	}
	for n := range a.osRoutes {
		if want[n] {
			continue
		}
		if err := a.ifc.RemoveRoute(n); err != nil {
			a.cfg.Logf("remove route %s: %v", n, err)
			continue
		}
		delete(a.osRoutes, n)
		a.cfg.Logf("route %s taken away", n)
	}
}

// localNetworks are the IPv4 networks of this device's interfaces, but the tunnel's and loopback.
func localNetworks(tunnel string) []netip.Prefix {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, ifc := range ifs {
		if ifc.Name == tunnel || ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, ad := range addrs {
			if n, ok := ad.(*net.IPNet); ok {
				if p, ok := netip.AddrFromSlice(n.IP); ok && p.Unmap().Is4() {
					ones, _ := n.Mask.Size()
					out = append(out, netip.PrefixFrom(p.Unmap(), ones).Masked())
				}
			}
		}
	}
	return out
}

// routesKey describes the routes this device uses and the networks it serves, to notice a change.
func (a *runner) routesKey() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var r []string
	for n := range a.osRoutes {
		r = append(r, n.String())
	}
	slices.Sort(r)
	exit := ""
	if a.exit != nil {
		exit = a.exit.Route + "@" + a.exit.Via
	}
	dns := ""
	if a.last.DNS != nil && a.resolver != nil {
		dns = a.last.DNS.Domain
	}
	return strings.Join(r, ",") + "|" + strings.Join(a.last.Self.Routes, ",") + "|" + exit + "|" + fmt.Sprint(a.last.Self.Exit, a.runningExits()) + "|" + dns
}
