// Package control implements a control node: userspace WireGuard, the control API inside the
// tunnel, and the reconciliation of WireGuard peers with the shared store.
package control

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/attest"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/reqsig"
	"entowire.com/ento/internal/store"
	"entowire.com/ento/internal/update"
)

// Config configures a control node.
type Config struct {
	Name       string      // unique name of this node
	PrivateKey wgtypes.Key // this node's WireGuard key
	ListenPort int         // UDP port of the WireGuard socket
	Endpoint   string      // public host:port agents use to reach this node
	Space      ipam.Space
	Store      store.Store
	MTU        int
	Logf       func(format string, args ...any)

	// Changes, if set, signals that the store changed (e.g. PostgreSQL NOTIFY). Polling remains as
	// a fallback.
	Changes <-chan struct{}

	// OIDC, if set, lets devices log in with SSO (see OIDCConfig).
	OIDC *OIDCConfig

	// People, if set, lets administrators manage the identity provider's people (people.go).
	People *PeopleConfig

	// NoGateways are groups whose devices are never a route's gateway or an exit (the operator's own
	// infrastructure in a network, say): such routes are refused, and existing ones never used.
	NoGateways []string

	// The groups that give a device's own groups a role (roles.go); empty: the identity provider's
	// role groups, else admins and operators. ViewerGroups open the administration read-only
	// (empty: viewers).
	AdminGroups, OperatorGroups, ViewerGroups []string

	// The person layer of devices bound to a person by SSO (person.go): it ends after SessionIdle
	// without the person's traffic, or SessionMax after it opened (0, the default: never for its
	// age). Zero disables a limit. ReopenServices are the sign-ins (PAM services) whose approval
	// reopens it (nil: DefaultReopenServices).
	SessionIdle    time.Duration
	SessionMax     time.Duration
	ReopenServices []string

	// CloneResponse is what a check-in that suspects a copied identity does (checkin.go): CloneAuto
	// (default: suspend devices bound to a person by single sign-on, report others), CloneSuspend,
	// CloneReport.
	CloneResponse string

	// Hosts are published in the network map (see api.NetMap.Hosts).
	Hosts []api.Host
	// DNSDomain is the domain of the network's internal DNS (dns.go; "": none), checked with
	// CheckDNSDomain.
	DNSDomain string
	// LinkForwards are published in the network map (see api.NetMap.LinkForwards).
	LinkForwards []api.Forward
	// RecordDomain is published in the network map (see api.NetMap.RecordDomain); the node checks
	// that the record there names it (record.go).
	RecordDomain string
	// ServiceNames are the names of the network's services (servicenames.go): the node resolves them
	// with its own DNS and gives every device their addresses inside the network (api.DNSConfig.Fixed).
	ServiceNames []string

	// Android key attestation (posture.go, package attest). AttestationRevocations is where the
	// list of revoked attestation certificates is fetched ("": Google's, attest.DefaultRevocationsURL;
	// "off": not checked, which keys leaked from phones make unsafe), once a device sends an
	// attestation. AndroidApps, when set, are the only apps whose attestations count.
	AttestationRevocations string
	AndroidApps            []attest.App

	// AdminUI, if set, is the name of the admin web interface, served on port 443 of the node's
	// overlay address with the certificate and key in these files (see adminui.go).
	AdminUI     string
	AdminUICert string
	AdminUIKey  string

	// Forwards are services this node passes through on its overlay address, port 443, by the TLS
	// server name a device asks for (name → targets, host:port tried in order; TLS stays end to end):
	// what every enrolled device must reach although its policies open nothing on the servers, as
	// an installer the device fetches before anything else (0.33). Same rules as the identity
	// provider's forward: enrolled, not suspended devices; audited per connection (forward_connection).
	Forwards map[string][]string
	// SignIn, if set, makes the control nodes a sign-in provider for the person of the calling device
	// (signin.go), at https://<AdminUI>/device; it needs AdminUI.
	SignIn *SignInConfig

	// Version of the software, shown to administrators; a release (X.Y.Z) is offered to the
	// network's devices (updates.go) when UpdatesDir is set: downloaded from Releases
	// (update.DefaultReleases when empty) and kept there. Devices of group UpdatesExcept are never
	// offered one (an environment's members, updated by their deployments).
	Version       string
	UpdatesDir    string
	Releases      string
	UpdatesExcept string
}

const (
	reconcileInterval = 2 * time.Second
	versionPoll       = time.Second
	longPollTimeout   = 25 * time.Second
	seenWriteInterval = 30 * time.Second
	handshakeFresh    = 3 * time.Minute
)

// Server is a running control node.
type Server struct {
	cfg     Config
	release releaseCache
	self    store.ControlNode
	wg      *userspaceWG
	http    *http.Server
	reconMu sync.Mutex

	verMu   sync.Mutex
	version int64
	changed chan struct{} // closed and replaced whenever the version changes

	seenMu   sync.Mutex
	lastSeen map[wgtypes.Key]time.Time
	lastEP   map[wgtypes.Key]string

	// Temporary keys of tokens this node just redeemed stay configured for a short while, so the
	// redeem response (and retries) can still reach the agent over them.
	graceMu sync.Mutex
	grace   map[wgtypes.Key]gracePeer

	relay  *relay
	oidc   *oidcProvider
	people *rauthyPeople

	nonces  reqsig.Nonces // of signed requests accepted by this node
	uiSwept time.Time     // when expired sessions of the admin interface were last deleted
	// approvalsSwept is when sign-in approvals older than a day were last deleted.
	approvalsSwept time.Time
	// cloneAudited: when each device's reported suspicion of a copied identity was last audited.
	cloneMu      sync.Mutex
	cloneAudited map[int64]time.Time
	// activityNoted: when each device's person's administration was last recorded as activity.
	activityMu    sync.Mutex
	activityNoted map[int64]time.Time

	unsignedMu sync.Mutex
	unsigned   map[int64]time.Time // when a device's refused unsigned call was last audited

	postureMu sync.Mutex // one evaluation at a time (posture.go)

	// The refresher (ssotoken.go, one goroutine): since when the identity provider could not be
	// asked, and when that was last reported.
	idpDownSince, idpReported time.Time

	// The device sign-in provider's count of authorizations per device in the current minute.
	signInMu     sync.Mutex
	signInSeen   map[string]int
	signInWindow time.Time

	idpMu    sync.Mutex
	idpConns map[netip.Addr]int // open identity-provider connections per device (idp.go)

	loginMu     sync.Mutex
	loginStarts map[int64]time.Time // when each device last started a sign-in (handleLoginStart)

	// The revocation list of attestation certificates (nil: not checked), fetched from the first
	// attestation on (revocations), until runCtx ends.
	rev     *attest.Revocations
	revOnce sync.Once
	runCtx  context.Context

	services atomic.Pointer[[]api.Host] // ServiceNames as last resolved (servicenames.go)
}

type gracePeer struct {
	peer    wgPeer
	expires time.Time
}

const redeemGrace = 2 * time.Minute

// Start registers the node, brings up WireGuard and serves the API on the overlay address.
func Start(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.MTU == 0 {
		cfg.MTU = 1380
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if si := cfg.SignIn; si != nil {
		switch {
		case cfg.AdminUI == "":
			return nil, errors.New("device sign-in needs the admin interface's name and certificate")
		case si.ClientID == "" || si.ClientSecret == "" || len(si.RedirectURIs) == 0 || si.Key == nil:
			return nil, errors.New("device sign-in needs a client ID, its secret, redirect URIs and a signing key")
		}
	}
	cfg.NoGateways = deviceGroups(cfg.NoGateways)
	self, err := cfg.Store.RegisterControlNode(ctx, store.ControlNode{
		Name: cfg.Name, PublicKey: cfg.PrivateKey.PublicKey(), Endpoint: cfg.Endpoint, LastSeen: time.Now(),
	})
	if err != nil {
		return nil, fmt.Errorf("register control node: %w", err)
	}
	wg, err := newUserspaceWG(cfg.PrivateKey, cfg.ListenPort, self.Address, cfg.MTU, cfg.Logf)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	s := &Server{
		cfg: cfg, self: self, wg: wg, changed: make(chan struct{}),
		lastSeen: map[wgtypes.Key]time.Time{}, lastEP: map[wgtypes.Key]string{},
		grace: map[wgtypes.Key]gracePeer{}, runCtx: ctx,
	}
	switch cfg.AttestationRevocations {
	case "off":
	case "":
		s.rev = attest.NewRevocations(attest.DefaultRevocationsURL, cfg.Logf)
	default:
		s.rev = attest.NewRevocations(cfg.AttestationRevocations, cfg.Logf)
	}
	if cfg.OIDC != nil {
		s.oidc = newOIDCProvider(*cfg.OIDC)
	}
	if cfg.People != nil {
		s.people = newPeople(*cfg.People)
	}
	s.prefixDeviceGroups(ctx)
	s.rolesFromGroups(ctx)
	// Groups come from the identity provider only: checked at start, then every 30 seconds.
	go func() {
		s.syncGroups(ctx)
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.syncGroups(ctx)
			}
		}
	}()
	// The heartbeat: every minute this node records that it runs, so the others (and the dashboard)
	// can tell a running control node from one that stopped.
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				if err := cfg.Store.ControlNodeSeen(ctx, cfg.Name, now); err != nil && ctx.Err() == nil {
					cfg.Logf("heartbeat: %v", err)
				}
			}
		}
	}()
	if s.version, err = cfg.Store.Version(ctx); err != nil {
		wg.Close()
		return nil, err
	}
	if err := s.startRelay(ctx); err != nil {
		wg.Close()
		return nil, fmt.Errorf("relay: %w", err)
	}
	var idpTargets []string
	if cfg.OIDC != nil {
		idpTargets = cfg.OIDC.ConnectTo
	}
	if len(idpTargets) > 0 || cfg.AdminUI != "" || len(cfg.Forwards) > 0 {
		if err := s.start443(ctx, idpTargets); err != nil {
			wg.Close()
			return nil, fmt.Errorf("port 443 (identity provider, admin interface): %w", err)
		}
	}
	if err := s.reconcile(ctx); err != nil {
		wg.Close()
		return nil, err
	}
	ln, err := wg.net.ListenTCPAddrPort(netip.AddrPortFrom(self.Address, api.ControlPort))
	if err != nil {
		wg.Close()
		return nil, err
	}
	s.http = &http.Server{
		Handler:           noBrowsers(s.routes()),
		ReadHeaderTimeout: 10 * time.Second,
		// No ReadTimeout: it would also cancel the network map's long polls; request bodies are
		// bounded in size instead (noBrowsers).
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 64 << 10,
		BaseContext:    func(net.Listener) context.Context { return ctx },
	}
	go func() {
		if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			cfg.Logf("control api: %v", err)
		}
	}()
	go s.loop(ctx)
	if cfg.UpdatesDir != "" {
		if s.cfg.Releases == "" {
			s.cfg.Releases = update.DefaultReleases
		}
		go s.releaseLoop(ctx)
	}
	if cfg.RecordDomain != "" {
		go s.recordLoop(ctx)
	}
	if len(cfg.ServiceNames) > 0 {
		s.resolveServices(ctx, "") // before the first network maps, then every few minutes
		go s.servicesLoop(ctx)
	}
	if cfg.OIDC != nil {
		if len(cfg.OIDC.TokenKey) == 32 {
			go s.refreshLoop(ctx)
		} else {
			cfg.Logf("sso: no token key: refresh tokens are not kept, so access ends only with the session limits")
		}
	}
	cfg.Logf("control node %s up: overlay %s, WireGuard :%d, public key %s", cfg.Name, self.Address, cfg.ListenPort, self.PublicKey)
	return s, nil
}

// Address returns the node's overlay address.
func (s *Server) Address() netip.Addr { return s.self.Address }

// Close stops the node.
func (s *Server) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.http.Shutdown(ctx)
	s.wg.Close()
}

func (s *Server) loop(ctx context.Context) {
	recon := time.NewTicker(reconcileInterval)
	poll := time.NewTicker(versionPoll)
	posture := time.NewTicker(postureEvery)
	defer recon.Stop()
	defer poll.Stop()
	defer posture.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.cfg.Changes:
			s.checkVersion(ctx)
		case <-poll.C:
			s.checkVersion(ctx)
		case <-recon.C:
			if err := s.reconcile(ctx); err != nil {
				s.cfg.Logf("reconcile: %v", err)
			}
			s.observe(ctx)
			s.expire(ctx)
		case <-posture.C:
			// Reports age: a device whose report got too old fails the checks that need it.
			if _, err := s.evaluatePosture(ctx, 0); err != nil {
				s.cfg.Logf("posture: %v", err)
			}
		}
	}
}

// checkVersion wakes long-polling agents and reconciles when the store version moved.
func (s *Server) checkVersion(ctx context.Context) {
	v, err := s.cfg.Store.Version(ctx)
	if err != nil {
		s.cfg.Logf("version: %v", err)
		return
	}
	s.verMu.Lock()
	moved := v != s.version
	if moved {
		s.version = v
		close(s.changed)
		s.changed = make(chan struct{})
	}
	s.verMu.Unlock()
	if moved {
		if err := s.reconcile(ctx); err != nil {
			s.cfg.Logf("reconcile: %v", err)
		}
	}
}

// waitChange blocks until the version exceeds since or the timeout expires, and returns the
// current version.
func (s *Server) waitChange(ctx context.Context, since int64, timeout time.Duration) int64 {
	t := time.NewTimer(timeout)
	defer t.Stop()
	for {
		s.verMu.Lock()
		v, ch := s.version, s.changed
		s.verMu.Unlock()
		if v > since {
			return v
		}
		select {
		case <-ch:
		case <-t.C:
			return v
		case <-ctx.Done():
			return v
		}
	}
}

// waitChangeOrApprovals waits as waitChange does, and also returns when the number of approvals
// waiting for the device's person differs from known; it returns the version and that number.
// Approvals live in the store, which every control node shares, so the number is looked at every
// few seconds (the store answers the cheap question, is anything pending at all, first).
func (s *Server) waitChangeOrApprovals(ctx context.Context, self store.Peer, since int64, known int, timeout time.Duration) (int64, int) {
	deadline := time.Now().Add(timeout)
	for {
		count := known
		if p, err := s.pendingFor(ctx, self, time.Now()); err == nil {
			count = len(p)
		}
		left := time.Until(deadline)
		if count != known || left <= 0 {
			s.verMu.Lock()
			v := s.version
			s.verMu.Unlock()
			return v, count
		}
		wctx, cancel := context.WithTimeout(ctx, min(left, 2*approvalPoll))
		v := s.waitChange(wctx, since, left)
		cancel()
		if v > since || ctx.Err() != nil {
			if p, err := s.pendingFor(ctx, self, time.Now()); err == nil {
				count = len(p)
			}
			return v, count
		}
	}
}

// reconcile makes the WireGuard peers match the store: every enrolled peer (so it can always reach
// the control plane) and every active enrollment token.
func (s *Server) reconcile(ctx context.Context) error {
	s.reconMu.Lock()
	defer s.reconMu.Unlock()
	peers, err := s.cfg.Store.Peers(ctx)
	if err != nil {
		return err
	}
	tokens, err := s.cfg.Store.ActiveTokens(ctx, time.Now())
	if err != nil {
		return err
	}
	policies, err := s.cfg.Store.Policies(ctx)
	if err != nil {
		return err
	}
	var ps *postureState
	if needsPosture(policies) {
		if ps, err = loadPosture(ctx, s.cfg.Store, time.Now()); err != nil {
			return err
		}
	}
	routes, err := s.cfg.Store.Routes(ctx)
	if err != nil {
		return err
	}
	s.relay.table.Store(newRelayTable(peers, policies, ps, routes))
	desired := make(map[wgtypes.Key]wgPeer, len(peers)+len(tokens))
	for _, p := range peers {
		// A suspended device is no WireGuard peer of the control nodes at all: it reaches nothing,
		// not even the control plane, until it is resumed.
		if p.Suspended {
			continue
		}
		desired[p.PublicKey] = wgPeer{AllowedIP: p.Address, Endpoint: p.Endpoint, Quiet: quietOS(p.OS)}
	}
	for _, t := range tokens {
		desired[t.PublicKey] = wgPeer{AllowedIP: t.TempAddress, PresharedKey: t.PresharedKey}
	}
	now := time.Now()
	s.graceMu.Lock()
	for k, g := range s.grace {
		if now.After(g.expires) {
			delete(s.grace, k)
		} else if _, ok := desired[k]; !ok {
			desired[k] = g.peer
		}
	}
	s.graceMu.Unlock()
	return s.wg.Sync(desired)
}

// observe records the endpoints WireGuard observed for peers with a fresh handshake. These are the
// public addresses other peers use to reach them directly.
func (s *Server) observe(ctx context.Context) {
	status, err := s.wg.Status()
	if err != nil {
		s.cfg.Logf("wireguard status: %v", err)
		return
	}
	now := time.Now()
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	for k, st := range status {
		if st.LastHandshake.IsZero() || now.Sub(st.LastHandshake) > handshakeFresh {
			continue
		}
		if st.Endpoint == s.lastEP[k] && now.Sub(s.lastSeen[k]) < seenWriteInterval {
			continue
		}
		previous, changed, err := s.cfg.Store.ObservePeer(ctx, k, st.Endpoint, st.LastHandshake)
		if err != nil && !errors.Is(err, store.ErrNotFound) { // tokens are not peers
			s.cfg.Logf("observe peer: %v", err)
			continue
		}
		// A device reaching us from another address (not just another NAT port) is worth knowing:
		// the same key used from elsewhere may be a copied key.
		if changed && previous != "" && hostOf(previous) != hostOf(st.Endpoint) {
			if p, err := s.cfg.Store.PeerByPublicKey(ctx, k); err == nil {
				s.audit(nil, &p, "endpoint_changed", fmt.Sprintf("%s from %s to %s", peerLabel(p), hostOf(previous), hostOf(st.Endpoint)), "ok")
			}
		}
		s.lastEP[k], s.lastSeen[k] = st.Endpoint, now
	}
}

func hostOf(endpoint string) string {
	if ap, err := netip.ParseAddrPort(endpoint); err == nil {
		return ap.Addr().String()
	}
	return endpoint
}
