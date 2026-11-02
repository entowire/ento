package agent

// Exits (0.25): a device that a policy lets use an exit route is offered it on the gateway's peer
// (api.Peer.Exits). The device decides: <state dir>/exit holds "off", a route's name, or nothing (the
// exit used by default, if one is offered). In use, the gateway's peer carries 0.0.0.0/0 and the
// system sends everything but the device's own networks and WireGuard's packets into the tunnel:
//
//   - Linux: WireGuard's packets get a firewall mark; two rules (both IPv4 and IPv6) look up the main
//     table without its default route, then send unmarked packets to a table of their own, whose
//     IPv4 default leads into the interface and whose IPv6 default is unreachable (it would leave
//     beside the exit). As wg-quick does it, with other numbers. systemd-resolved sends every name
//     to the agent's resolver (dns.go), which asks the gateway's, on its overlay address.
//   - Android: the VPN service routes 0.0.0.0/0 (InProcessRoutes) and names the agent's resolver as
//     its DNS server (InProcessDNS); IPv6 stays blocked, as the VPN has none.
//   - macOS, Windows: not yet; an exit offered or chosen there is left unused, with a log line.
//
// A device that is an exit itself uses none (its forwarded traffic would go back into the tunnel).
// It is no kill switch: while the agent is stopped or restarts, traffic takes its normal path.

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/names"
)

const exitChoiceFile = "exit"

const (
	exitMark     = 0x7873 // WireGuard's own packets while an exit is in use
	exitTable    = 0x7873 // the routing table with the default route into the interface
	exitRulePref = 31770  // and +1: the two rules (clear of Tailscale's 52xx and wg-quick's 327xx)
)

// ExitOff is the choice of no exit at all, not even one used by default.
const ExitOff = "off"

// ExitChoice returns the device's choice of exit: "" (the one used by default, if any), ExitOff or a
// route's name.
func ExitChoice(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, exitChoiceFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// SetExitChoice records the device's choice of exit ("" for the one used by default); the running
// agent applies it within seconds.
func SetExitChoice(dir, choice string) error {
	path := filepath.Join(dir, exitChoiceFile)
	if choice == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	if choice != ExitOff && names.Check(choice) != nil {
		return fmt.Errorf("%q is no exit's name (ento agent status lists those offered)", choice)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(choice+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// exitPick is the exit a device uses: the route, and its gateway's peer.
type exitPick struct {
	Route   string
	Default bool
	Key     string // the gateway's public key
	Addr    netip.Addr
	Via     string // the gateway's name
}

// offeredExits lists the exits a network map offers the device, sorted by route.
func offeredExits(nm api.NetMap) []exitPick {
	var out []exitPick
	for _, p := range nm.Peers {
		a, err := netip.ParseAddr(p.Address)
		if err != nil || !a.Is4() {
			continue
		}
		for _, o := range p.Exits {
			out = append(out, exitPick{Route: o.Route, Default: o.Default, Key: p.PublicKey, Addr: a, Via: p.Hostname})
		}
	}
	slices.SortFunc(out, func(a, b exitPick) int { return strings.Compare(a.Route, b.Route) })
	return out
}

// chooseExit returns the exit the device uses with this map and choice (ok false: none).
func chooseExit(nm api.NetMap, choice string) (exitPick, bool) {
	if choice == ExitOff || nm.Self.Exit {
		return exitPick{}, false
	}
	for _, o := range offeredExits(nm) {
		if choice == o.Route || choice == "" && o.Default {
			return o, true
		}
	}
	return exitPick{}, false
}

// exitNetwork is what the gateway's peer carries for an exit.
var exitNetwork = netip.MustParsePrefix("0.0.0.0/0")

// InProcessExit returns the exit the agent running in this process (RunOnTUN) uses ("" when none):
// the app routes 0.0.0.0/0 into its VPN then (InProcessRoutes lists it).
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

// InProcessExits returns the exits offered to the agent running in this process (RunOnTUN).
func InProcessExits() []RunningExit {
	a := current.Load()
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.runningExits()
}

// noteExit logs what keeps an exit unused, once while it stays the same; the caller holds a.mu.
func (a *runner) noteExit(msg string) {
	if msg != a.exitNoted {
		a.exitNoted = msg
		a.cfg.Logf("%s", msg)
	}
}

// syncExit makes the routing match the exit in use (the system's DNS follows in syncResolver): on a change,
// and once a minute while one is in use (something may have removed its rules); once at the start,
// to clean up after an agent that stopped without. The caller holds a.mu.
func (a *runner) syncExit(exit *exitPick) {
	same := (exit == nil) == (a.exit == nil) && (exit == nil || *exit == *a.exit)
	if same && a.exitSet && (exit == nil || time.Since(a.exitAt) < time.Minute) {
		return
	}
	if err := a.ifc.SetExit(exit != nil); err != nil {
		a.noteExit(fmt.Sprintf("exit: %v", err))
		if exit != nil {
			// Not in use after all; the routing it may have half made goes again.
			_ = a.ifc.SetExit(false)
			exit = nil
			same = a.exit == nil
		}
	}
	if !same {
		if exit != nil {
			a.cfg.Logf("exit %s through %q (%s) in use: all internet traffic goes through it (ento agent exit off to stop)", exit.Route, exit.Via, exit.Addr)
			a.exitNoted = ""
		} else if a.exit != nil {
			a.cfg.Logf("exit %s no longer in use: traffic takes its normal path", a.exit.Route)
		}
	}
	a.exit, a.exitSet, a.exitAt = exit, true, time.Now()
	if !same && a.announces {
		go a.announce() // it takes a.mu, which the caller holds
	}
}

// RunningExit is an exit offered to the device, as agent.json shows it.
type RunningExit struct {
	Route   string `json:"route"`
	Via     string `json:"via"`
	Default bool   `json:"default,omitempty"`
	InUse   bool   `json:"in_use,omitempty"`
}

// runningExits lists the exits offered to the device; the caller holds a.mu.
func (a *runner) runningExits() []RunningExit {
	var out []RunningExit
	for _, o := range offeredExits(a.last) {
		out = append(out, RunningExit{Route: o.Route, Via: o.Via, Default: o.Default,
			InUse: a.exit != nil && a.exit.Route == o.Route && a.exit.Key == o.Key})
	}
	return out
}

// exitForMachine reports whether the device's machine layer alone may use the exit (its traffic
// through it is then not the person's).
func exitForMachine(nm api.NetMap, e exitPick) bool {
	for _, p := range nm.Peers {
		if p.PublicKey != e.Key {
			continue
		}
		for _, o := range p.Exits {
			if o.Route == e.Route {
				return o.Machine
			}
		}
	}
	return false
}
