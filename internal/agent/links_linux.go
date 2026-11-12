//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/names"
)

const linksSupported = true

// linkRetry is how long a failed join waits before the next attempt.
const linkRetry = 30 * time.Second

type linkRunner struct {
	cancel context.CancelFunc
	done   chan struct{}
	a      *runner
}

// manageLinks joins, runs and leaves linked networks as their directories ask, until ctx ends.
func manageLinks(ctx context.Context, cfg Config, home *runner) {
	running := map[string]*linkRunner{}
	failed := map[string]time.Time{}
	quick := map[string]int{} // joins refused in a row only for want of a recent posture report
	proxies := map[string]*linkProxy{}
	stopProxy := func(name string) {
		if p, ok := proxies[name]; ok {
			p.stop()
			delete(proxies, name)
		}
	}
	stopAll := func() {
		for name := range proxies {
			stopProxy(name)
		}
		for _, lr := range running {
			lr.cancel()
			<-lr.done
		}
	}
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		for _, name := range Links(cfg.StateDir) {
			dir := filepath.Join(LinksDir(cfg.StateDir), name)
			if exists(filepath.Join(dir, "remove")) {
				stopProxy(name)
				if lr, ok := running[name]; ok {
					leaveLink(ctx, lr.a)
					lr.cancel()
					<-lr.done
					delete(running, name)
				}
				if err := teardownLink(cfg, name); err != nil {
					cfg.Logf("link %s: leave: %v", name, err)
					continue
				}
				cfg.Logf("link %s: left", name)
				continue
			}
			if _, ok := running[name]; ok {
				if used := linkLastUsed(cfg.StateDir, name); cfg.LinkIdle > 0 && !used.IsZero() && time.Since(used) > cfg.LinkIdle {
					cfg.Logf("link %s: nothing sent to it since %s: leaving it (ento agent link %s joins it again)", name,
						used.Local().Format(time.RFC3339), name)
					if err := RequestUnlink(cfg.StateDir, name); err != nil {
						cfg.Logf("link %s: %v", name, err)
					}
					continue
				}
				syncProxy(cfg, name, proxies, stopProxy)
				continue
			}
			ls, err := LoadLinkState(cfg.StateDir, name)
			if errors.Is(err, ErrNotEnrolled) {
				if !exists(filepath.Join(dir, "request")) || time.Since(failed[name]) < linkRetry {
					continue
				}
				if ls, err = joinLink(ctx, cfg, home, name); err != nil {
					failed[name] = time.Now()
					if onlyStale(PostureRefusal(err)) && quick[name] < staleRetries {
						quick[name]++ // a report was just asked for: try again in a few seconds
						failed[name] = time.Now().Add(staleRetry - linkRetry)
					} else {
						quick[name] = 0
					}
					cfg.Logf("link %s: join: %v", name, err)
					_ = os.WriteFile(filepath.Join(dir, "error"), []byte(err.Error()), 0o600)
					continue
				}
				delete(quick, name)
				_ = os.Remove(filepath.Join(dir, "request"))
				_ = os.Remove(filepath.Join(dir, "error"))
			} else if err != nil {
				cfg.Logf("link %s: %v", name, err)
				continue
			}
			lr, err := runLink(ctx, cfg, home, name, ls)
			if err != nil {
				cfg.Logf("link %s: start: %v", name, err)
				continue
			}
			if linkLastUsed(cfg.StateDir, name).IsZero() { // joined now, or before its use was kept
				markLinkUsed(cfg.StateDir, name, true)
			}
			running[name] = lr
		}
		select {
		case <-ctx.Done():
			stopAll()
			return
		case <-t.C:
		}
	}
}

func linkConfig(cfg Config, name string, port int) Config {
	c := cfg
	c.Interface, c.ListenPort = linkInterface(name), port
	logf := cfg.Logf
	c.Logf = func(format string, args ...any) { logf("link "+name+": "+format, args...) }
	return c
}

// freeUDPPort picks the WireGuard port of a new linked network: any port the system hands out.
func freeUDPPort() (int, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return 0, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port, nil
}

// joinLink asks the home network for the linked network's token and a credential for a fresh
// key, and enrolls in the linked network from its own namespace.
func joinLink(ctx context.Context, cfg Config, home *runner, name string) (LinkState, error) {
	perm, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return LinkState{}, err
	}
	port, err := freeUDPPort()
	if err != nil {
		return LinkState{}, err
	}
	res, _, err := homeCredential(ctx, home, name, linkHomeFailingFile(cfg.StateDir, name),
		api.LinkCredentialRequest{PublicKey: perm.PublicKey().String(), Join: true})
	if err != nil {
		return LinkState{}, fmt.Errorf("credential from the home network: %w", err)
	}
	if res.Token == "" {
		return LinkState{}, fmt.Errorf("the home network sent no token for %s (a control node older than this agent?)", name)
	}
	ns, err := openNamespace(name)
	if err != nil {
		return LinkState{}, err
	}
	defer ns.Close()
	lcfg := linkConfig(cfg, name, port)
	st, err := enroll(ctx, lcfg, nsEnv(ns), res.Token, perm, res.Credential)
	if err != nil {
		return LinkState{}, err
	}
	ls := LinkState{State: st, ListenPort: port}
	ls.ApprovedUntil, _ = time.Parse(time.RFC3339, res.ExpiresAt)
	if err := saveLinkState(cfg.StateDir, name, ls); err != nil {
		return LinkState{}, err
	}
	lcfg.Logf("joined as %s in namespace %s", st.Address, NamespaceName(name))
	return ls, nil
}

// runLink brings a linked network up in its namespace and keeps it in sync, renewing the
// device's credential through the home network.
func runLink(ctx context.Context, cfg Config, home *runner, name string, ls LinkState) (*linkRunner, error) {
	ns, err := openNamespace(name)
	if err != nil {
		return nil, err
	}
	lcfg := linkConfig(cfg, name, ls.ListenPort)
	// The control nodes of a network use the first /24 of its range.
	controls := netip.PrefixFrom(ls.Network.Addr(), 24)
	if err := applyLinkFirewall(ns, controls); err != nil {
		ns.Close()
		return nil, fmt.Errorf("firewall: %w", err)
	}
	env := nsEnv(ns)
	var mu sync.Mutex // guards ls
	fwd := newForwarder(ns, dialIn(home.env.ns), lcfg.Logf)
	var hostsMu sync.Mutex
	var linked map[string][]string // names published by the linked network
	rewriteHosts := func() {
		hostsMu.Lock()
		defer hostsMu.Unlock()
		if err := writeHosts(name, mergeHosts(linked, fwd.hostNames(), lcfg.Logf)); err != nil {
			lcfg.Logf("hosts: %v", err)
		}
	}
	a, err := startRunner(lcfg, env, ls.State, func(nm api.NetMap) {
		hosts := map[string][]string{}
		add := func(name, addr string) {
			if h := hostLabel(name); h != "" && addr != "" {
				hosts[h] = append(hosts[h], addr)
			}
		}
		for _, c := range nm.Controls {
			add(c.Name, c.Address)
		}
		for _, p := range nm.Peers {
			// Device names never have dots (package names); an older control plane's might, and
			// such a name could stand for a real domain in this namespace.
			add(names.Label(p.Hostname), p.Address)
		}
		for _, h := range nm.Hosts {
			add(h.Name, h.Address)
		}
		if nm.DNS != nil && nm.DNS.Domain != "" { // the linked network's internal names, in full
			for _, r := range nm.DNS.Records {
				add(r.Name+"."+nm.DNS.Domain, r.Address)
			}
		}
		hostsMu.Lock()
		linked = hosts
		hostsMu.Unlock()
		rewriteHosts()
	})
	if err != nil {
		ns.Close()
		return nil, err
	}
	a.failingFile = linkFailingFile(cfg.StateDir, name)
	writeFailing(a.failingFile, nil) // from an earlier run
	a.saveFn = func(st State) error {
		mu.Lock()
		defer mu.Unlock()
		ls.State = st
		return saveLinkState(cfg.StateDir, name, ls)
	}
	lctx, cancel := context.WithCancel(ctx)
	lr := &linkRunner{cancel: cancel, done: make(chan struct{}), a: a}
	a.onTraffic = func() { markLinkUsed(cfg.StateDir, name, false) }
	var wg sync.WaitGroup
	wg.Add(5)
	go func() { defer wg.Done(); a.reevaluate(lctx) }()
	go func() { defer wg.Done(); a.reportPosture(lctx) }()
	go func() { defer wg.Done(); syncForwards(lctx, home, fwd, rewriteHosts) }()
	go func() { defer wg.Done(); _ = a.loop(lctx) }()
	go func() {
		defer wg.Done()
		renewLink(lctx, lcfg, home, a, name, func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return ls.ApprovedUntil
		}, func(until time.Time) {
			mu.Lock()
			defer mu.Unlock()
			ls.ApprovedUntil = until
			if err := saveLinkState(cfg.StateDir, name, ls); err != nil {
				lcfg.Logf("save: %v", err)
			}
		})
	}()
	go func() {
		wg.Wait()
		fwd.close()
		a.close()
		ns.Close()
		close(lr.done)
	}()
	lcfg.Logf("up as %s in namespace %s", ls.Address, NamespaceName(name))
	return lr, nil
}

// renewLink renews the device's credential when half of its remaining lifetime has passed (and
// at the latest every hour), and at once when the person's session at home opens or ends,
// retrying every minute on failure (sooner when the home network only lacked a recent posture
// report). When the home network refuses, the access ends now (endLink), not when the credential
// expires: a person who signed out, or may no longer join, must not keep it for minutes.
func renewLink(ctx context.Context, cfg Config, home *runner, a *runner, name string, until func() time.Time, set func(time.Time)) {
	quick := 0
	for {
		wait := time.Until(until()) / 2
		// At least a few seconds: a credential that is already expired (or a control node that hands
		// out expired ones) must not make this loop spin.
		wait = max(min(wait, time.Hour), 5*time.Second)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		case <-home.personChange():
		}
		stale, refused, err := renewOnce(ctx, home, a, name, linkHomeFailingFile(cfg.StateDir, name), set)
		if err == nil {
			quick = 0
			if err := a.setCut(false); err != nil {
				cfg.Logf("peers: %v", err)
			}
			continue
		}
		if ctx.Err() != nil {
			return
		}
		cfg.Logf("credential renewal: %v", err)
		if refused {
			endLink(ctx, cfg, a, set)
		}
		retry := time.Minute
		if stale && quick < staleRetries {
			quick, retry = quick+1, staleRetry
		} else {
			quick = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		case <-home.personChange():
		}
	}
}

// endLink ends the device's access to a linked network whose credential its home network refused
// to renew: its peers there are dropped at once, and its control nodes are asked to withdraw the
// approval the last credential gave (control nodes older than 0.35.1 cannot: they keep it until
// it expires, but nothing of this device reaches their peers).
func endLink(ctx context.Context, cfg Config, a *runner, set func(time.Time)) {
	if err := a.setCut(true); err != nil {
		cfg.Logf("peers: %v", err)
	}
	linked := &AdminClient{Controls: a.controls(), Key: a.key(), HTTP: a.env.http}
	switch err := linked.Do(ctx, http.MethodPost, api.PathCredentialEnd, struct{}{}, nil); {
	case err == nil:
		set(time.Now())
		cfg.Logf("access ended (the home network refused the credential); a renewed credential brings it back")
	case HTTPStatus(err) == http.StatusNotFound || HTTPStatus(err) == http.StatusMethodNotAllowed:
		cfg.Logf("access ended on this device (the home network refused the credential); its control nodes keep the approval until it expires (they are older than ento 0.35.1)")
	default:
		cfg.Logf("access ended on this device (the home network refused the credential); its control nodes were not told (%v) and keep the approval until it expires", err)
	}
}

// renewOnce renews the device's credential for a linked network. A refusal of the home network over
// the device's posture is kept in homeFailing (for ento status) until a renewal succeeds;
// stale reports a refusal only for want of a recent posture report (homeCredential); refused, any
// other refusal of the home network (it answered: this device gets no credential).
func renewOnce(ctx context.Context, home *runner, a *runner, name, homeFailing string, set func(time.Time)) (stale, refused bool, err error) {
	pub := a.key().PublicKey()
	res, stale, err := homeCredential(ctx, home, name, homeFailing, api.LinkCredentialRequest{PublicKey: pub.String()})
	if err != nil {
		code := HTTPStatus(err)
		return stale, !stale && (code == http.StatusForbidden || code == http.StatusNotFound), fmt.Errorf("home network: %w", err)
	}
	var renewed api.RenewCredentialResponse
	linked := &AdminClient{Controls: a.controls(), Key: a.key(), HTTP: a.env.http}
	if err := linked.Do(ctx, "POST", api.PathCredential, api.RenewCredentialRequest{Credential: res.Credential}, &renewed); err != nil {
		return false, false, fmt.Errorf("linked network: %w", err)
	}
	t, err := time.Parse(time.RFC3339, renewed.ApprovedUntil)
	if err != nil {
		return false, false, err
	}
	set(t)
	return false, false, nil
}

// teardownLink deletes a linked network's interface, namespace and directory.
func teardownLink(cfg Config, name string) error {
	if err := removeLinkNetwork(name); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(LinksDir(cfg.StateDir), name))
}

// removeLinkNetwork deletes a linked network's interface and namespace, keeping its state.
func removeLinkNetwork(name string) error {
	if ns, err := netns.GetFromName(NamespaceName(name)); err == nil {
		if h, err := netlink.NewHandleAt(ns); err == nil {
			if l, err := h.LinkByName(linkInterface(name)); err == nil {
				_ = h.LinkDel(l)
			}
			h.Close()
		}
		ns.Close()
	}
	return closeNamespace(name)
}

// syncForwards applies the home network's forwards to a linked namespace as they change.
func syncForwards(ctx context.Context, home *runner, fwd *forwarder, rewriteHosts func()) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		home.mu.Lock()
		fs := validForwards(home.last.LinkForwards, home.st.Network)
		home.mu.Unlock()
		if fwd.apply(fs) {
			rewriteHosts()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// mergeHosts combines the linked network's names with the forwarded services of the home
// network. Forwarded names win: a linked network cannot point them at its own addresses.
func mergeHosts(linked map[string][]string, forwarded map[string]string, logf func(string, ...any)) map[string][]string {
	out := make(map[string][]string, len(linked)+len(forwarded))
	for name, addrs := range linked {
		if _, ok := forwarded[name]; ok {
			logf("hosts: ignoring %s from the linked network: it is a forwarded service of the home network", name)
			continue
		}
		out[name] = addrs
	}
	for name, addr := range forwarded {
		out[name] = []string{addr}
	}
	return out
}

// syncProxy starts, moves or stops a running linked network's proxy as its proxy file asks.
func syncProxy(cfg Config, name string, proxies map[string]*linkProxy, stop func(string)) {
	want := LinkProxy(cfg.StateDir, name)
	if p, ok := proxies[name]; ok && p.setting == want {
		return
	}
	stop(name)
	if want == "" {
		return
	}
	ls, err := LoadLinkState(cfg.StateDir, name)
	if err != nil {
		return
	}
	ns, err := openNamespace(name)
	if err != nil {
		cfg.Logf("link %s: proxy: %v", name, err)
		return
	}
	p, err := startLinkProxy(name, ns, ls.Network, want, cfg.Logf)
	if err != nil {
		ns.Close()
		cfg.Logf("link %s: proxy: %v", name, err)
		return
	}
	proxies[name] = p
	cfg.Logf("link %s: proxy on %s", name, want)
}

// usedFile keeps when something was last sent into a linked network (RFC 3339), so that one nobody
// uses is left after Config.LinkIdle, also across restarts of the agent.
const usedFile = "used"

var linkUsed = struct {
	sync.Mutex
	written map[string]time.Time
}{written: map[string]time.Time{}}

// markLinkUsed records that a linked network was used now: on disk at most once an hour (force:
// now).
func markLinkUsed(stateDir, name string, force bool) {
	linkUsed.Lock()
	defer linkUsed.Unlock()
	if !force && time.Since(linkUsed.written[name]) < time.Hour {
		return
	}
	now := time.Now()
	path := filepath.Join(LinksDir(stateDir), name, usedFile)
	if err := os.WriteFile(path+".tmp", []byte(now.UTC().Format(time.RFC3339)+"\n"), 0o600); err == nil && os.Rename(path+".tmp", path) == nil {
		linkUsed.written[name] = now
	}
}

// linkLastUsed is when a linked network was last used (zero: not known).
func linkLastUsed(stateDir, name string) time.Time {
	b, err := os.ReadFile(filepath.Join(LinksDir(stateDir), name, usedFile))
	if err != nil {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
	return t
}

// leaveLink tells a linked network's control plane that the device leaves it, so that its
// membership is deleted there too (it would otherwise stay, unapproved, counting against its
// authority's devices). Best effort: the network deletes memberships that are not renewed anyway
// only by hand.
func leaveLink(ctx context.Context, a *runner) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c := &AdminClient{Controls: a.controls(), Key: a.key(), HTTP: a.env.http}
	if err := c.Do(ctx, http.MethodPost, api.PathLeave, struct{}{}, nil); err != nil {
		a.cfg.Logf("leave: the network was not told (%v): its administrators can delete the membership", err)
		return
	}
	a.cfg.Logf("left: the network deleted the membership")
}
