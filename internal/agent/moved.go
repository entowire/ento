package agent

// Moved control nodes (0.29). A device keeps its control nodes' keys, endpoints and overlay
// addresses in its state and learns changes from the network map, which it can only fetch from a
// control node. Control nodes rebuilt elsewhere (new public addresses, while the device was away)
// would leave it with nowhere to go. So, once none has answered for movedAfter, it looks up the
// network record of the domain the map named (api.NetMap.RecordDomain: TXT _ento.<domain>, the
// record words enroll with) and takes the endpoints it gives for the keys the device already
// trusts. Keys and overlay addresses never change this way: a forged record can only send the
// device's handshakes to an address where nobody holds a control node's key, which whoever forges
// its DNS answers could disrupt anyway.

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/token"
)

const (
	movedAfter    = 5 * time.Minute  // without an answer from any control node
	movedInterval = 10 * time.Minute // between lookups while that lasts
)

// movedTimes returns movedAfter and movedInterval, or both ENTO_MOVED_AFTER (a duration, for
// tests).
func movedTimes() (after, interval time.Duration) {
	if d, err := time.ParseDuration(os.Getenv("ENTO_MOVED_AFTER")); err == nil && d > 0 {
		return d, d
	}
	return movedAfter, movedInterval
}

// movedEndpoints returns controls with the endpoints a network record gives for their keys, and a
// description of each change (none: nothing to change).
func movedEndpoints(controls []api.Control, rec token.Record) ([]api.Control, []string) {
	out := append([]api.Control(nil), controls...)
	var changes []string
	for i, c := range out {
		for _, rc := range rec.Controls {
			if rc.PublicKey.String() == c.PublicKey && rc.Endpoint != c.Endpoint {
				changes = append(changes, fmt.Sprintf("%q from %s to %s", c.Name, c.Endpoint, rc.Endpoint))
				out[i].Endpoint = rc.Endpoint
			}
		}
	}
	return out, changes
}

// recordResolver is the resolver the record is looked up with: the system's, or in an app (no
// system resolver Go can use) the DNS servers of the network beside the VPN (SetUpstreamDNS).
func recordResolver() *net.Resolver {
	servers := upstream() // host:53
	if len(servers) == 0 {
		return nil
	}
	hosts := make([]string, 0, len(servers))
	for _, s := range servers {
		if h, _, err := net.SplitHostPort(s); err == nil {
			hosts = append(hosts, h)
		}
	}
	return ResolverVia(hosts)
}

// noteMapResult tracks how long no control node has answered (ok: one just did) and, after
// movedAfter, looks up where they went, at most every movedInterval. The home network only: a
// linked network's membership is renewed through the home network instead.
func (a *runner) noteMapResult(ctx context.Context, ok bool) {
	if ok || a.saveFn != nil {
		a.unansweredSince = time.Time{}
		return
	}
	now := time.Now()
	if a.unansweredSince.IsZero() {
		a.unansweredSince = now
	}
	domain := a.recordDomain()
	after, interval := movedTimes()
	if domain == "" || now.Sub(a.unansweredSince) < after || now.Sub(a.movedLookup) < interval {
		return
	}
	a.movedLookup = now
	go a.findMoved(ctx, domain)
}

// recordDomain is the domain whose network record names the control nodes ("": none known).
func (a *runner) recordDomain() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.last.RecordDomain != "" {
		return a.last.RecordDomain
	}
	return a.st.RecordDomain
}

// findMoved looks up the network record and applies the endpoints it gives the known keys.
func (a *runner) findMoved(ctx context.Context, domain string) {
	note := func(msg string) {
		a.mu.Lock()
		changed := msg != a.movedNoted
		a.movedNoted = msg
		a.mu.Unlock()
		if changed {
			a.cfg.Logf("%s", msg)
		}
	}
	text, err := LookupRecord(ctx, domain, recordResolver())
	if err != nil {
		note(fmt.Sprintf("no control node answers; %v", err))
		return
	}
	rec, err := token.ParseRecord(text)
	if err != nil {
		note(fmt.Sprintf("no control node answers; the network record %s.%s: %v", token.RecordName, domain, err))
		return
	}
	a.mu.Lock()
	controls, changes := movedEndpoints(a.st.Controls, rec)
	if len(changes) == 0 {
		a.mu.Unlock()
		note(fmt.Sprintf("no control node answers, and the network record %s.%s names no other endpoint for them", token.RecordName, domain))
		return
	}
	a.st.Controls = controls
	if len(a.last.Controls) > 0 { // the map in use would put the old endpoints back
		a.last.Controls, _ = movedEndpoints(a.last.Controls, rec)
	}
	nm := a.last
	a.movedNoted = ""
	err = a.save()
	a.mu.Unlock()
	a.cfg.Logf("control nodes moved, says the network record %s.%s: %s", token.RecordName, domain, strings.Join(changes, ", "))
	if err != nil {
		a.cfg.Logf("save state: %v", err)
	}
	if err := a.apply(nm); err != nil {
		a.cfg.Logf("apply network map: %v", err)
	}
}
