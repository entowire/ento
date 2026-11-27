package agent

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
)

// plainPeers are the WireGuard peers of the plain WireGuard peers this device carries as their
// gateway (Constitution 6.2): each its own address, its preshared key from its configuration (9.3),
// no endpoint (it comes to the gateway: WireGuard learns where from), no keepalive. Only the
// kernel's WireGuard on Linux forwards their traffic (filter_linux.go); elsewhere they are left
// out, and said so once. The caller holds a.mu.
func (a *runner) plainPeers(nm api.NetMap, controls, seen map[wgtypes.Key]bool) []PeerConfig {
	if len(nm.Self.Plain) == 0 {
		a.plainNoted = false
		return nil
	}
	if !plainSupported(a.ifc) || a.linked() {
		if !a.plainNoted {
			a.plainNoted = true
			a.cfg.Logf("this device carries %d plain WireGuard peers, but only a Linux device with the kernel's WireGuard forwards for them: left out", len(nm.Self.Plain))
		}
		return nil
	}
	var out []PeerConfig
	for _, p := range nm.Self.Plain {
		key, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(p.Address)
		if err != nil || !ip.Is4() || controls[key] || seen[key] {
			continue
		}
		seen[key] = true
		pc := PeerConfig{PublicKey: key, AllowedIPs: []netip.Prefix{netip.PrefixFrom(ip, 32)}}
		if p.PresharedKey != "" {
			if k, err := wgtypes.ParseKey(p.PresharedKey); err == nil {
				pc.PresharedKey = k
			}
		}
		out = append(out, pc)
	}
	return out
}

// plainSeenEvery is how often a gateway reports its plain peers' handshakes: often enough for the
// admin page's "online" (a handshake within 3 minutes), or ENTO_PLAIN_SEEN_EVERY (tests).
func plainSeenEvery() time.Duration {
	if d, err := time.ParseDuration(os.Getenv("ENTO_PLAIN_SEEN_EVERY")); err == nil && d > 0 {
		return d
	}
	return time.Minute
}

// reportPlainSeen tells the control nodes, while this device carries plain WireGuard peers, when
// each last had a handshake with it: the control nodes have no tunnel of their own with them, so
// this is their last seen. Control nodes older than 0.62.1 take none: it stops asking.
func (a *runner) reportPlainSeen(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(plainSeenEvery()):
		}
		a.mu.Lock()
		keys := map[wgtypes.Key]string{}
		for _, p := range a.last.Self.Plain {
			if k, err := wgtypes.ParseKey(p.PublicKey); err == nil {
				keys[k] = p.PublicKey
			}
		}
		a.mu.Unlock()
		if len(keys) == 0 || !plainSupported(a.ifc) {
			continue
		}
		status, err := a.ifc.Status()
		if err != nil {
			continue
		}
		req := api.PlainSeen{Handshakes: map[string]int64{}}
		for k, s := range keys {
			if hs := status[k].LastHandshake; !hs.IsZero() {
				req.Handshakes[s] = hs.Unix()
			}
		}
		if len(req.Handshakes) == 0 {
			continue
		}
		c := &AdminClient{Controls: a.controls(), Key: a.key(), HTTP: a.env.http}
		err = c.Do(ctx, http.MethodPost, api.PathPlainSeen, req, nil)
		if st := HTTPStatus(err); st == http.StatusNotFound || st == http.StatusMethodNotAllowed {
			return
		}
	}
}
