//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Networks joined besides the first run beside it in the device's own namespace (networks.go).
const networksSupported = true

type memberRunner struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// manageNetworks enrolls in, runs and forgets the networks joined besides the first as their
// directories ask, until ctx ends; then it stops them all.
func manageNetworks(ctx context.Context, cfg Config) {
	running := map[string]*memberRunner{}
	failed := map[string]time.Time{}
	stop := func(d string) {
		if mr, ok := running[d]; ok {
			mr.cancel()
			<-mr.done
			delete(running, d)
		}
	}
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		for _, d := range Networks(cfg.StateDir) {
			dir := NetworkDir(cfg.StateDir, d)
			m, err := LoadMembership(cfg.StateDir, d)
			if err != nil {
				cfg.Logf("network %s: %v", d, err)
				continue
			}
			mcfg := memberConfig(cfg, m)
			if exists(filepath.Join(dir, "remove")) {
				stop(d)
				if err := forgetNetwork(mcfg, m); err != nil {
					mcfg.Logf("leave: %v", err)
					continue
				}
				mcfg.Logf("left on this device (the network keeps it until an administrator deletes it)")
				continue
			}
			if _, ok := running[d]; ok {
				continue
			}
			st, err := LoadState(dir)
			if errors.Is(err, ErrNotEnrolled) {
				if !exists(filepath.Join(dir, enrollFile)) || time.Since(failed[d]) < linkRetry {
					continue
				}
				if st, err = enrollNetwork(ctx, mcfg, m); err != nil {
					failed[d] = time.Now()
					mcfg.Logf("join: %v", err)
					_ = os.WriteFile(filepath.Join(dir, "error"), []byte(err.Error()), 0o600)
					continue
				}
				_ = os.Remove(filepath.Join(dir, "error"))
			} else if err != nil {
				mcfg.Logf("%v", err)
				continue
			}
			mr, err := runNetwork(ctx, mcfg, st)
			if err != nil {
				mcfg.Logf("start: %v", err)
				continue
			}
			running[d] = mr
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

// memberConfig is the agent's configuration for a joined network: its own state directory,
// interface and port, and its lines in the log named after it.
func memberConfig(cfg Config, m Membership) Config {
	c := cfg
	c.StateDir, c.Interface, c.ListenPort = NetworkDir(cfg.StateDir, m.Domain), m.Interface, m.ListenPort
	logf := cfg.Logf
	c.Logf = func(format string, args ...any) { logf("network "+m.Domain+": "+format, args...) }
	return c
}

// enrollNetwork redeems a joined network's invitation (enroll.token) on the network's interface,
// and keeps the membership only if the network's range is the one its record named and overlaps
// nothing another network of the device holds.
func enrollNetwork(ctx context.Context, cfg Config, m Membership) (State, error) {
	if taken := takenRange(m.Interface, m.Network); taken != "" {
		return State{}, fmt.Errorf("its range %s overlaps %s, which another network of this device uses", m.Network, taken)
	}
	b, err := os.ReadFile(filepath.Join(cfg.StateDir, enrollFile))
	if err != nil {
		return State{}, err
	}
	perm, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return State{}, err
	}
	st, err := enroll(ctx, cfg, hostEnv(), string(b), perm, "")
	if err != nil {
		return State{}, err
	}
	if st.Network.Masked() != m.Network.Masked() {
		return State{}, fmt.Errorf("enrolled as %s, but in range %s while the network's record named %s: not kept (an administrator deletes the device there)",
			st.Address, st.Network, m.Network)
	}
	st.RecordDomain = m.Domain
	if err := SaveState(cfg.StateDir, st); err != nil {
		return State{}, err
	}
	_ = os.Remove(filepath.Join(cfg.StateDir, enrollFile))
	return st, nil
}

// runNetwork brings a joined network up on its interface and keeps it in sync until ctx ends, as
// Run does the first: its own posture reports, check-ins and hardware key, no exits, releases or
// linked networks.
func runNetwork(ctx context.Context, cfg Config, st State) (*memberRunner, error) {
	a, err := startNetwork(cfg, hostEnv(), st, nil, true)
	if err != nil {
		return nil, err
	}
	for _, w := range OverlayWarnings(st.Network) {
		cfg.Logf("WARNING: %s", w)
	}
	if err := markOwnPackets(a.ifc); err != nil {
		cfg.Logf("mark WireGuard's packets (they would take the first network's exit while one is in use): %v", err)
	}
	a.startHardwareKey()
	a.announces = true
	a.announce()
	ctx, cancel := context.WithCancel(ctx)
	mr := &memberRunner{cancel: cancel, done: make(chan struct{})}
	go a.reevaluate(ctx)
	go a.reportPosture(ctx)
	go a.checkIns(ctx)
	go func() {
		defer close(mr.done)
		defer a.close()
		_ = a.loop(ctx)
	}()
	cfg.Logf("up on %s as %s", cfg.Interface, st.Address)
	return mr, nil
}

// forgetNetwork takes a joined network off the device: its interface, its inbound filter's table
// and its state directory.
func forgetNetwork(cfg Config, m Membership) error {
	if err := deleteWireGuard(netns.None(), m.Interface); err != nil {
		return err
	}
	if err := applyInboundFilter(netns.None(), m.Interface, nil); err != nil {
		return fmt.Errorf("remove the inbound filter of %s: %w", m.Interface, err)
	}
	dropClaim(m.Interface)
	return os.RemoveAll(cfg.StateDir)
}

// memberInterfaces are the interfaces of the networks joined besides the first.
func memberInterfaces(stateDir string) []string {
	var out []string
	for _, d := range Networks(stateDir) {
		if m, err := LoadMembership(stateDir, d); err == nil && !slices.Contains(out, m.Interface) {
			out = append(out, m.Interface)
		}
	}
	return out
}

// markOwnPackets marks a joined network's own WireGuard packets as the first network's are while it
// uses an exit, so that they leave by the device's own connection, not through the exit.
func markOwnPackets(t tunnel) error {
	mark := exitMark
	switch i := t.(type) {
	case *Iface:
		return i.wg.ConfigureDevice(i.Name, wgtypes.Config{FirewallMark: &mark})
	case *userTunnel:
		if !i.noOS {
			return i.dev.IpcSet(fmt.Sprintf("fwmark=%d\n", mark))
		}
	}
	return nil
}
