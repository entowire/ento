package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"entowire.com/ento/internal/api"
)

// Service names (0.30.2). A network's services often have public DNS names that point at addresses
// inside the network (a team's chat, its SIEM): reachable only through the tunnel, yet resolved by
// whatever DNS a device's network offers. Home routers and filtering resolvers drop answers that
// point at private or shared addresses (rebinding protection), and such a device cannot reach the
// services by name. With --service-names, the control nodes resolve those names with their own DNS
// and give every device the addresses (api.DNSConfig.Fixed), which its agent answers itself. Only
// addresses inside the network's range are given: a control node never points a name elsewhere
// than the network itself would. Resolved at start and every few minutes; devices get changes
// with their next network map (at most a long poll later).

const servicesEvery = 5 * time.Minute

func (s *Server) servicesLoop(ctx context.Context) {
	last := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(servicesEvery):
		}
		last = s.resolveServices(ctx, last)
	}
}

// resolveServices resolves the service names, keeps the outcome for the network maps and logs it
// when it differs from last; it returns the outcome's description.
func (s *Server) resolveServices(ctx context.Context, last string) string {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	lookup := func(ctx context.Context, name string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip4", name)
	}
	hosts, notes := resolveServiceNames(ctx, lookup, s.cfg.ServiceNames, s.cfg.Space.Prefix, s.services.Load())
	s.services.Store(&hosts)
	msg := "service names: " + strings.Join(notes, "; ")
	if msg != last && ctx.Err() == nil {
		s.cfg.Logf("%s", msg)
	}
	return msg
}

// resolveServiceNames looks each name up and keeps its IPv4 addresses inside network. A name that
// does not resolve keeps the addresses it had (prev), so a resolver's hiccup takes nothing away.
func resolveServiceNames(ctx context.Context, lookup func(context.Context, string) ([]netip.Addr, error), names []string,
	network netip.Prefix, prev *[]api.Host) ([]api.Host, []string) {
	var out []api.Host
	var notes []string
	for _, name := range names {
		addrs, err := lookup(ctx, name)
		var kept []string
		for _, a := range addrs {
			if a = a.Unmap(); a.Is4() && network.Contains(a) {
				kept = append(kept, a.String())
			}
		}
		slices.Sort(kept)
		kept = slices.Compact(kept)
		switch {
		case err != nil && prev != nil:
			for _, h := range *prev {
				if h.Name == name {
					kept = append(kept, h.Address)
				}
			}
			notes = append(notes, fmt.Sprintf("%s: %v (keeping %d address(es))", name, err, len(kept)))
		case err != nil:
			notes = append(notes, fmt.Sprintf("%s: %v", name, err))
		case len(kept) == 0:
			notes = append(notes, fmt.Sprintf("%s: no address inside %s, left out", name, network))
		default:
			notes = append(notes, name+" "+strings.Join(kept, ","))
		}
		for _, a := range kept {
			out = append(out, api.Host{Name: name, Address: a})
		}
	}
	return out, notes
}
