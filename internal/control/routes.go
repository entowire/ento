package control

// Routes: networks behind a gateway device (an office LAN behind a machine there). A route names its
// networks and its gateway; a policy whose destination is "route:NAME" lets its source devices reach
// those networks, on its ports. The control plane gives those devices the gateway as a peer that
// carries the networks (Peer.Routes; their agents route the networks into the tunnel) and gives the
// gateway, for each of them, what they may open there (Peer.RouteAccept; its agent forwards that and
// nothing else, hiding them behind its own LAN address). Who may reach a route is never implied: a
// policy between groups does not reach routes, and "*" as a source still needs a policy to the route.
//
// An exit is a route without networks: the devices a policy lets use it may send all their internet
// traffic through its gateway (0.25). They are offered it (Peer.Exits) and choose it themselves
// (ento agent exit), unless the route is used by default; the gateway gets 0.0.0.0/0 in their
// RouteAccept and forwards to public addresses only (never to private ranges or itself: those take
// a route of their own), and answers their DNS queries.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/names"
	"entowire.com/ento/internal/ports"
	"entowire.com/ento/internal/store"
)

// routePrefix marks a policy destination that is a route, not a group.
const routePrefix = "route:"

// gatewayAgents is the first agent version that forwards to a route's networks, exitAgents the first
// that is an exit.
const (
	gatewayAgents = "0.24.0"
	exitAgents    = "0.25.0"
)

// exitNetwork stands for everything in an exit's RouteAccept.
const exitNetwork = "0.0.0.0/0"

// maxRouteNetworks limits the networks of one route.
const maxRouteNetworks = 16

func isRoute(dest string) bool { return strings.HasPrefix(dest, routePrefix) }

// routeAccess returns the port rules the policies give p in route r (ok false: none reaches it).
// Posture checks are applied as for policies between groups.
func routeAccess(p store.Peer, r store.Route, policies []store.Policy, ps *postureState) ([]string, bool) {
	var lists [][]string
	for _, pol := range policies {
		if pol.Destination != routePrefix+r.Name || !inGroup(p, pol.Source) {
			continue
		}
		if len(pol.Posture) > 0 && !ps.passes(p, pol.Posture) {
			continue
		}
		lists = append(lists, pol.Ports)
	}
	if len(lists) == 0 {
		return nil, false
	}
	return ports.Union(lists...), true
}

// routeGateways maps each route to its gateway, among approved devices that are not suspended.
// neverGateway returns the group of p whose devices are never gateways (Config.NoGateways), if any.
func neverGateway(p store.Peer, groups []string) string {
	for _, g := range groups {
		if slices.Contains(p.Groups, g) || slices.Contains(p.Machine.Groups, g) {
			return g
		}
	}
	return ""
}

// usableRoutes leaves out the routes whose gateway is a device that may never be one: devices never
// learn them, so nothing goes through it.
func usableRoutes(routes []store.Route, peers []store.Peer, noGateways []string) []store.Route {
	if len(noGateways) == 0 {
		return routes
	}
	gws := routeGateways(routes, peers)
	out := routes[:0:0]
	for _, r := range routes {
		if gw, ok := gws[r.Name]; ok && neverGateway(gw, noGateways) != "" {
			continue
		}
		out = append(out, r)
	}
	return out
}

func routeGateways(routes []store.Route, peers []store.Peer) map[string]store.Peer {
	byName := map[string]store.Peer{}
	for _, p := range peers {
		if p.Approved && !p.Suspended {
			byName[p.Hostname] = p
		}
	}
	out := map[string]store.Peer{}
	for _, r := range routes {
		if gw, ok := byName[r.Via]; ok {
			out[r.Name] = gw
		}
	}
	return out
}

func networkStrings(nets []netip.Prefix) []string {
	out := make([]string, 0, len(nets))
	for _, n := range nets {
		out = append(out, n.String())
	}
	return out
}

// addRoutes adds to self's network map what routes give it: the gateways it reaches networks
// through, and, for a gateway, what each peer may open in the networks it serves. A peer that only a
// route connects to self is added to the map (it must be able to answer), opening nothing on self
// itself.
func addRoutes(nm *api.NetMap, self store.Peer, peers []store.Peer, routes []store.Route, policies []store.Policy, ps *postureState) {
	idx := map[string]int{}
	for i, p := range nm.Peers {
		idx[p.PublicKey] = i
	}
	entry := func(p store.Peer) *api.Peer {
		k := p.PublicKey.String()
		if i, ok := idx[k]; ok {
			return &nm.Peers[i]
		}
		var eps []string
		if p.Endpoint != "" {
			eps = append(eps, p.Endpoint)
		}
		nm.Peers = append(nm.Peers, api.Peer{PublicKey: k, Address: p.Address.String(), Hostname: p.Hostname, Endpoints: eps,
			Accept: acceptFrom(self, p, policies, ps)})
		idx[k] = len(nm.Peers) - 1
		return &nm.Peers[len(nm.Peers)-1]
	}
	gateways := routeGateways(routes, peers)
	for _, r := range routes {
		gw, ok := gateways[r.Name]
		if !ok {
			continue
		}
		nets := networkStrings(r.Networks)
		if r.Exit {
			nets = []string{exitNetwork}
		}
		if gw.ID == self.ID {
			if r.Exit {
				nm.Self.Exit = true
			} else {
				nm.Self.Routes = append(nm.Self.Routes, nets...)
			}
			for _, p := range peers {
				if p.ID == self.ID || !p.Approved || p.Suspended {
					continue
				}
				rules, ok := routeAccess(p, r, policies, ps)
				if !ok {
					continue
				}
				e := entry(p)
				for _, n := range nets {
					e.RouteAccept = append(e.RouteAccept, api.RouteRule{Network: n, Ports: rules})
				}
			}
			continue
		}
		if _, ok := routeAccess(self, r, policies, ps); ok {
			e := entry(gw)
			if r.Exit {
				e.Exits = append(e.Exits, api.ExitOffer{Route: r.Name, Default: r.Default})
			} else {
				e.Routes = append(e.Routes, nets...)
			}
		}
	}
}

// routeLinked reports whether a route connects a and b (one reaches a network through the other).
func routeLinked(a, b store.Peer, routes []store.Route, gateways map[string]store.Peer, policies []store.Policy, ps *postureState) bool {
	for _, r := range routes {
		gw, ok := gateways[r.Name]
		if !ok {
			continue
		}
		if gw.ID == b.ID {
			if _, ok := routeAccess(a, r, policies, ps); ok {
				return true
			}
		}
		if gw.ID == a.ID {
			if _, ok := routeAccess(b, r, policies, ps); ok {
				return true
			}
		}
	}
	return false
}

// checkRouteNetworks validates a route's networks: IPv4, given as networks (no host bits), not the
// overlay range or inside it, none overlapping another route's.
func checkRouteNetworks(list []string, overlay netip.Prefix, others []store.Route) ([]netip.Prefix, error) {
	if len(list) == 0 || len(list) > maxRouteNetworks {
		return nil, fmt.Errorf("a route has between 1 and %d networks", maxRouteNetworks)
	}
	var out []netip.Prefix
	for _, s := range list {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("%q is no IPv4 network (CIDR, like 192.168.10.0/24)", s)
		}
		if p.Masked() != p {
			return nil, fmt.Errorf("%s has host bits set: %s is the network", p, p.Masked())
		}
		if p.Bits() == 0 {
			return nil, errors.New("a route to everything (all traffic through a gateway) is not a route: it comes as an exit")
		}
		if p.Overlaps(overlay) {
			return nil, fmt.Errorf("%s overlaps the network's own range %s", p, overlay)
		}
		for _, q := range out {
			if p.Overlaps(q) {
				return nil, fmt.Errorf("%s and %s overlap", p, q)
			}
		}
		for _, o := range others {
			for _, q := range o.Networks {
				if p.Overlaps(q) {
					return nil, fmt.Errorf("%s overlaps %s of route %s", p, q, o.Name)
				}
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// routeWarnings names what keeps a route from working yet: its gateway missing, not approved, not
// Linux, or with an agent older than gatewayAgents (exitAgents for an exit).
func (s *Server) routeWarnings(ctx context.Context, r store.Route) []string {
	peers, err := s.cfg.Store.Peers(ctx)
	if err != nil {
		return nil
	}
	gw, ok := routeGateways([]store.Route{r}, peers)[r.Name]
	if !ok {
		return []string{fmt.Sprintf("no approved device is named %s: the route works once one is", r.Via)}
	}
	if g := neverGateway(gw, s.cfg.NoGateways); g != "" {
		return []string{fmt.Sprintf("never used: %s is in %s, whose devices are never gateways", r.Via, g)}
	}
	ps, err := loadPosture(ctx, s.cfg.Store, time.Now())
	if err != nil {
		return nil
	}
	f := ps.facts[gw.ID]
	switch {
	case f == nil:
		return []string{fmt.Sprintf("%s has not reported yet: a gateway runs ento %s or later, on Linux", gw.Hostname, gatewayAgents)}
	case f.OS != "linux":
		return []string{fmt.Sprintf("%s runs %s: only Linux devices forward to a route's networks", gw.Hostname, f.OS)}
	}
	need := gatewayAgents
	if r.Exit {
		need = exitAgents
	}
	if c, ok := compareVersions(f.Agent, need); !ok || c < 0 {
		return []string{fmt.Sprintf("%s runs ento %s: it forwards from %s on", gw.Hostname, f.Agent, need)}
	}
	return nil
}

func apiRoute(r store.Route) api.Route {
	out := api.Route{Name: r.Name, Networks: networkStrings(r.Networks), Via: r.Via, Exit: r.Exit, Default: r.Default, CreatedBy: r.CreatedBy}
	if !r.CreatedAt.IsZero() {
		out.CreatedAt = r.CreatedAt.UTC().Format(time.RFC3339)
	}
	return out
}

func (s *Server) handleListRoutes(w http.ResponseWriter, r *http.Request, _ store.Peer) {
	routes, err := s.cfg.Store.Routes(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	out := make([]api.Route, 0, len(routes))
	for _, rt := range routes {
		a := apiRoute(rt)
		a.Warnings = s.routeWarnings(r.Context(), rt)
		out = append(out, a)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAddRoute(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.Route
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := names.Check(req.Name); err != nil {
		writeErr(w, http.StatusBadRequest, "route name: "+err.Error())
		return
	}
	if err := names.Check(req.Via); err != nil {
		writeErr(w, http.StatusBadRequest, "gateway: name the device (as peers shows it)")
		return
	}
	if len(s.cfg.NoGateways) > 0 {
		peers, err := s.cfg.Store.Peers(r.Context())
		if err != nil {
			s.respondStoreErr(w, err)
			return
		}
		for _, p := range peers {
			if p.Hostname == req.Via {
				if g := neverGateway(p, s.cfg.NoGateways); g != "" {
					writeErr(w, http.StatusBadRequest, fmt.Sprintf("%s is in %s, whose devices are never gateways in this network", req.Via, g))
					return
				}
			}
		}
	}
	others, err := s.cfg.Store.Routes(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	var nets []netip.Prefix
	switch {
	case req.Exit && len(req.Networks) > 0:
		err = errors.New("an exit has no networks: it carries everything but private ranges, which take routes of their own")
	case req.Default && !req.Exit:
		err = errors.New("only an exit is used by default; a route's networks are reached by whoever a policy lets")
	case !req.Exit:
		nets, err = checkRouteNetworks(req.Networks, s.cfg.Space.Prefix, others)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rt := store.Route{Name: req.Name, Networks: nets, Via: req.Via, Exit: req.Exit, Default: req.Default, CreatedAt: time.Now(), CreatedBy: peerLabel(self)}
	if err := s.cfg.Store.AddRoute(r.Context(), rt); err != nil {
		if errors.Is(err, store.ErrExists) {
			writeErr(w, http.StatusConflict, "a route of that name exists")
			return
		}
		s.respondStoreErr(w, err)
		return
	}
	what := strings.Join(networkStrings(nets), ",")
	if rt.Exit {
		what = "exit"
		if rt.Default {
			what = "exit default"
		}
	}
	s.audit(r, &self, "route_added", fmt.Sprintf("route %s %s via %s", rt.Name, what, rt.Via), "ok")
	s.checkVersion(r.Context())
	out := apiRoute(rt)
	out.Warnings = s.routeWarnings(r.Context(), rt)
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handleDeleteRoute(w http.ResponseWriter, r *http.Request, self store.Peer) {
	name := r.PathValue("name")
	policies, err := s.cfg.Store.Policies(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	if i := slices.IndexFunc(policies, func(p store.Policy) bool { return p.Destination == routePrefix+name }); i >= 0 {
		writeErr(w, http.StatusConflict, fmt.Sprintf("policy %d leads to this route: remove it first", policies[i].ID))
		return
	}
	if err := s.cfg.Store.DeleteRoute(r.Context(), name); err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "route_deleted", "route "+name, "ok")
	s.checkVersion(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

// checkPolicyRoute validates a policy's ends where routes are concerned: a route is only ever a
// destination, and it must exist.
func (s *Server) checkPolicyRoute(ctx context.Context, pol store.Policy) error {
	if isRoute(pol.Source) {
		return errors.New("a route is only ever a destination")
	}
	if !isRoute(pol.Destination) {
		return nil
	}
	routes, err := s.cfg.Store.Routes(ctx)
	if err != nil {
		return err
	}
	name := strings.TrimPrefix(pol.Destination, routePrefix)
	if !slices.ContainsFunc(routes, func(r store.Route) bool { return r.Name == name }) {
		return fmt.Errorf("no route %s (ento admin routes)", name)
	}
	return nil
}
