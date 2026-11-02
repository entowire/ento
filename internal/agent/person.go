package agent

// The person layer, as the agent sees it (0.27; the control package has the design). While it is
// open, the agent counts what the device sends into the tunnel that its machine layer alone would
// not (the network map says what that allows: api.Peer.Machine, RouteMachine, ExitOffer.Machine),
// and everything a linked network's namespace sends but to its control nodes: that is the person's
// traffic. Check-ins report how long ago it last moved, and the device's boot; ento agent logout
// closes the layer (pending until the control plane can be told).

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ports"
)

// personRules tell the person's traffic from the machine's. A packet the device sends counts when it
// goes to a peer, a network behind a gateway or (exit) anywhere through an exit, and the machine
// layer alone may not open it; all counts every packet but those to control nodes (a linked
// network: nothing there is the machine's).
type personRules struct {
	all      bool
	controls map[netip.Addr]bool
	overlay  netip.Prefix
	peers    map[netip.Addr]ports.Set // what the machine layer may open on each peer (absent: nothing)
	routes   []routeRule              // in each network behind a gateway
	exit     bool                     // an exit is in use that only the person may use
}

func (r *personRules) key() string {
	if r == nil {
		return ""
	}
	var k []string
	for a, set := range r.peers {
		k = append(k, "m "+a.String()+" "+setKey(set))
	}
	for _, rr := range r.routes {
		k = append(k, "n "+rr.network.String()+" "+setKey(rr.set))
	}
	slices.Sort(k)
	return fmt.Sprintf("person all=%v exit=%v %s", r.all, r.exit, strings.Join(k, ";"))
}

// personRulesFrom reads a map's person rules (nil: the person layer is closed).
func personRulesFrom(nm api.NetMap, f *inboundFilter) *personRules {
	if !nm.Self.PersonActive || f == nil {
		return nil
	}
	r := &personRules{controls: f.controls, overlay: f.overlay, peers: map[netip.Addr]ports.Set{}}
	for _, p := range nm.Peers {
		a, err := netip.ParseAddr(p.Address)
		if err != nil || !a.Is4() {
			continue
		}
		if len(p.Machine) > 0 {
			r.peers[a] = ports.ParseSet(p.Machine)
		}
		for _, rm := range p.RouteMachine {
			if n, err := netip.ParsePrefix(rm.Network); err == nil {
				list := rm.Ports
				if len(list) == 0 {
					list = []string{"all"}
				}
				r.routes = append(r.routes, routeRule{network: n.Masked(), set: ports.ParseSet(list)})
			}
		}
	}
	return r
}

// counts reports whether a packet the device sends (IPv4) is the person's. accept is what the
// destination may open on the device: a packet from such a port is taken for an answer (the agent's
// own WireGuard has no connection tracking; the kernel's table uses it instead).
func (r *personRules) counts(p []byte, accept map[netip.Addr]ports.Set) bool {
	if r == nil || len(p) < 20 || p[0]>>4 != 4 {
		return false
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl {
		return false
	}
	dst := netip.AddrFrom4([4]byte(p[16:20]))
	if r.controls[dst] {
		return false
	}
	if r.all {
		return true
	}
	proto, sport, dport := "", uint16(0), uint16(0)
	l4 := p[ihl:]
	fragment := binary.BigEndian.Uint16(p[6:8])&0x1fff != 0
	switch p[9] {
	case 6, 17:
		proto = map[byte]string{6: "tcp", 17: "udp"}[p[9]]
		if !fragment && len(l4) >= 4 {
			sport, dport = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
		}
	case 1:
		if fragment || len(l4) < 1 || l4[0] != 8 {
			return false // answers and errors: not opened by the device
		}
		proto = "icmp"
	}
	if proto != "icmp" && proto != "" && sport != 0 && accept[dst].Allows(proto, sport) {
		return false // an answer from a port the peer may open
	}
	machine := func(set ports.Set) bool {
		if proto == "" || set.All() {
			return set.All()
		}
		return set.Allows(proto, dport)
	}
	if r.overlay.Contains(dst) {
		return !machine(r.peers[dst])
	}
	for _, rr := range r.routes {
		if rr.network.Contains(dst) {
			return !machine(rr.set)
		}
	}
	return r.exit
}

// personSeen is when the agent last saw the person's traffic (Unix nanoseconds; 0: not since it
// started), in any network.
var personSeen atomic.Int64

func notePersonTraffic() { personSeen.Store(time.Now().UnixNano()) }

// personIdle is how many seconds ago the person's traffic last moved, -1 when not since the agent
// started.
func personIdle() int64 {
	t := personSeen.Load()
	if t == 0 {
		return -1
	}
	return int64(time.Since(time.Unix(0, t)) / time.Second)
}

// watchPersonTraffic reads the interface's count of the person's traffic and notes movement.
func (a *runner) watchPersonTraffic() {
	n, err := a.ifc.PersonTraffic()
	if err != nil {
		return
	}
	if n != a.personCount && n > 0 { // more, or anything since the count started over
		notePersonTraffic()
		if a.onTraffic != nil {
			a.onTraffic()
		}
	}
	a.personCount = n
}

// bootID identifies the current boot of the system ("" where it cannot be told).
func bootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err == nil {
		return strings.TrimSpace(string(b))
	}
	return sysBootID()
}

const logoutFile = "logout.pending"

// Logout closes the person layer of the device (ento agent logout): it tells the control plane,
// within timeout; if it cannot, the running agent tells it when it can. The person layer the agent
// last announced is named, so a logout delivered late never closes a layer opened since.
func Logout(ctx context.Context, cfg Config, timeout time.Duration) (delivered bool, err error) {
	cfg.defaults()
	st, err := LoadState(cfg.StateDir)
	if err != nil {
		return false, err
	}
	since := ""
	if r, ok := RunningAgent(cfg.StateDir); ok {
		since = r.PersonSince
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c := &AdminClient{Controls: st.Controls, Key: wgtypes.Key(st.PrivateKey), HTTP: &http.Client{Timeout: timeout}}
	if err := c.Do(ctx, http.MethodPost, api.PathLogout, api.LogoutRequest{PersonSince: since}, nil); err == nil {
		_ = os.Remove(filepath.Join(cfg.StateDir, logoutFile))
		return true, nil
	} else if HTTPStatus(err) == http.StatusNotFound || HTTPStatus(err) == http.StatusMethodNotAllowed {
		return false, errors.New("the control plane has no person layers (older than ento 0.27)")
	}
	tmp := filepath.Join(cfg.StateDir, logoutFile+".tmp")
	if err := os.WriteFile(tmp, []byte(since+"\n"), 0o600); err != nil {
		return false, err
	}
	return false, os.Rename(tmp, filepath.Join(cfg.StateDir, logoutFile))
}

// sendPendingLogout delivers a logout that could not be delivered when it was asked for.
func (a *runner) sendPendingLogout(ctx context.Context) {
	path := filepath.Join(a.cfg.StateDir, logoutFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) || err != nil {
		return
	}
	c := &AdminClient{Controls: a.controls(), Key: a.key(), HTTP: a.env.http}
	err = c.Do(ctx, http.MethodPost, api.PathLogout, api.LogoutRequest{PersonSince: strings.TrimSpace(string(b))}, nil)
	if err == nil || HTTPStatus(err) == http.StatusNotFound || HTTPStatus(err) == http.StatusBadRequest {
		_ = os.Remove(path)
		if err == nil {
			a.cfg.Logf("person layer: the logout asked for while the control plane could not be reached is delivered")
		}
	}
}
