package control

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"entowire.com/ento/internal/store"
)

// Groups decide a device's access and role (0.43): no separate approval or role to set.
//
//   - isolated: a device in it is treated as unapproved: it reaches nothing and nothing reaches it,
//     whoever is signed in on it. A new device without groups of its own lands in it; giving it
//     groups (and taking it out of isolated) lets it in.
//   - The admin and operator groups (Config.AdminGroups, Config.OperatorGroups; the identity
//     provider's role groups when single sign-on is on) give a device those roles, as a person's
//     groups give theirs. Only admins put devices in them or take them out.
//   - The viewer groups (Config.ViewerGroups) open the dashboard and the admin API read-only.

// Device groups and people groups are kept apart (0.44): a device group's name carries
// DevicePrefix wherever it is stored (ento's store, the identity provider), which the dashboard and
// the CLI never show; people groups have none, so the identity provider's tokens stay plain. The
// same name can be both.
const DevicePrefix = "device:"

// The built-in device groups: isolated (kept apart), admin and operator (the device's role).
const (
	IsolatedGroup       = DevicePrefix + "isolated"
	DeviceAdminGroup    = DevicePrefix + "admin"
	DeviceOperatorGroup = DevicePrefix + "operator"
)

// isDeviceGroup reports whether a group is a device group.
func isDeviceGroup(g string) bool { return strings.HasPrefix(g, DevicePrefix) }

// deviceGroups gives a device's groups their prefix (what the CLI and older clients send plain).
// Authority groups ("msp:operators") and "*" stay as they are.
func deviceGroups(gs []string) []string {
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		if g == "isolated" { // 0.43's name
			g = IsolatedGroup
		}
		if !isDeviceGroup(g) && g != "*" && !strings.Contains(g, ":") {
			g = DevicePrefix + g
		}
		if !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out
}

// hasGroup reports whether groups hold g: a plain name (a rule, a link or a setting written without
// a kind) matches the device group of that name too; device:NAME only the device group.
func hasGroup(groups []string, g string) bool {
	return slices.Contains(groups, g) || !strings.Contains(g, ":") && slices.Contains(groups, DevicePrefix+g)
}

func isolated(p store.Peer) bool {
	for _, g := range []string{IsolatedGroup, "isolated"} {
		if slices.Contains(p.Machine.Groups, g) || slices.Contains(p.Groups, g) {
			return true
		}
	}
	return false
}

// withIsolation marks isolated devices unapproved, for the network map.
func withIsolation(p store.Peer) store.Peer {
	if isolated(p) {
		p.Approved = false
	}
	return p
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

// adminGroups are the device groups that make a device an admin (built in: device:admin), and
// operatorGroups those that make it an operator; people's roles come from the identity provider's
// role groups (OIDCConfig). personAdminGroups are those, for the people API's checks.
func (s *Server) adminGroups() []string {
	if len(s.cfg.AdminGroups) > 0 {
		return deviceGroups(s.cfg.AdminGroups)
	}
	return []string{DeviceAdminGroup}
}

func (s *Server) operatorGroups() []string {
	if len(s.cfg.OperatorGroups) > 0 {
		return deviceGroups(s.cfg.OperatorGroups)
	}
	return []string{DeviceOperatorGroup}
}

func (s *Server) personAdminGroups() []string {
	if s.cfg.OIDC != nil && len(s.cfg.OIDC.AdminGroups) > 0 {
		return s.cfg.OIDC.AdminGroups
	}
	return []string{"admins"}
}

func (s *Server) viewerGroups() []string {
	if len(s.cfg.ViewerGroups) > 0 {
		return s.cfg.ViewerGroups
	}
	return []string{"viewers"}
}

// isViewer reports whether an approved device may look at the administration (its person's groups
// while signed in; viewer groups are people groups).
func (s *Server) isViewer(p store.Peer) bool {
	return p.Approved && !p.Suspended && !isolated(p) && intersects(p.Groups, s.viewerGroups())
}

// roleSet is the role groups among groups, sorted.
func (s *Server) roleSet(groups []string) []string {
	var out []string
	for _, g := range groups {
		if slices.Contains(s.adminGroups(), g) || slices.Contains(s.operatorGroups(), g) {
			out = append(out, g)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// groupRights is what a device's own groups give its machine layer: approval unless isolated (and
// some groups at all), and its roles.
func (s *Server) groupRights(groups []string) (approved, admin, operator bool) {
	approved = len(groups) > 0 && !slices.Contains(groups, IsolatedGroup)
	return approved, intersects(groups, s.adminGroups()), intersects(groups, s.operatorGroups())
}

// placeNewDevice puts a device that just joined in isolated when it has no groups of its own, and
// otherwise gives its machine layer what its groups say. Devices of an authority keep what the
// authority gives them.
func (s *Server) placeNewDevice(ctx context.Context, p store.Peer) (store.Peer, error) {
	if p.Authority != "" {
		return p, nil
	}
	groups := deviceGroups(p.Machine.Groups)
	// An administrator or operator token (ento admin token --admin, the first administrator's words)
	// means that role's group, besides any groups it names: a device's role is only ever its groups.
	switch {
	case p.Machine.Admin && !intersects(groups, s.adminGroups()):
		groups = append(groups, s.adminGroups()[0])
	case p.Machine.Operator && !p.Machine.Admin && !intersects(groups, s.operatorGroups()):
		groups = append(groups, s.operatorGroups()[0])
	}
	if len(groups) == 0 {
		groups = []string{IsolatedGroup}
	}
	approved, admin, operator := s.groupRights(groups)
	return s.cfg.Store.UpdatePeer(ctx, p.ID, store.PeerUpdate{Groups: &groups, Approved: &approved, Admin: &admin, Operator: &operator})
}

// rolesFromGroups makes every device's own role what its groups say (0.47): a device made an admin
// or operator before, by a token or `ento control admin`, without being in that role's group, is put
// in it, so its role shows in its groups and goes with them. Run at start; changes nothing twice.
func (s *Server) rolesFromGroups(ctx context.Context) {
	peers, err := s.cfg.Store.Peers(ctx)
	if err != nil {
		s.cfg.Logf("device roles: %v", err)
		return
	}
	for _, p := range peers {
		if p.Authority != "" {
			continue
		}
		groups := slices.Clone(p.Machine.Groups)
		if p.Machine.Admin && !intersects(groups, s.adminGroups()) {
			groups = append(groups, s.adminGroups()[0])
		}
		if p.Machine.Operator && !intersects(groups, s.operatorGroups()) && !intersects(groups, s.adminGroups()) {
			groups = append(groups, s.operatorGroups()[0])
		}
		_, admin, operator := s.groupRights(groups)
		if slices.Equal(groups, p.Machine.Groups) && admin == p.Machine.Admin && operator == p.Machine.Operator {
			continue
		}
		if _, err := s.cfg.Store.UpdatePeer(ctx, p.ID, store.PeerUpdate{Groups: &groups, Admin: &admin, Operator: &operator}); err != nil {
			s.cfg.Logf("device roles of %s: %v", p.Hostname, err)
			continue
		}
		s.audit(nil, nil, "device_roles_from_groups", fmt.Sprintf("%s groups=%s admin=%v operator=%v",
			peerLabel(p), strings.Join(groups, ","), admin, operator), "ok")
	}
}

// dropDeviceAdmin takes a device out of the admin groups once an admin person has signed in on it
// (0.47): from then on its admin rights are that person's, while they are signed in, and end with
// their session. The device keeps its other groups and its approval. The first administrator's device
// (enrolled with admin words) is how a network starts; this ends that once a person holds the role.
func (s *Server) dropDeviceAdmin(ctx context.Context, p store.Peer) store.Peer {
	if p.Authority != "" || !p.Person.Active || !p.Person.Admin || !intersects(p.Machine.Groups, s.adminGroups()) {
		return p
	}
	groups := slices.DeleteFunc(slices.Clone(p.Machine.Groups), func(g string) bool { return slices.Contains(s.adminGroups(), g) })
	_, admin, operator := s.groupRights(groups)
	updated, err := s.cfg.Store.UpdatePeer(ctx, p.ID, store.PeerUpdate{Groups: &groups, Admin: &admin, Operator: &operator})
	if err != nil {
		s.cfg.Logf("device admin of %s: %v", p.Hostname, err)
		return p
	}
	s.audit(nil, &updated, "device_admin_dropped", fmt.Sprintf("%s: %s signed in as an admin; the device's own admin group is gone (groups=%s)",
		peerLabel(updated), userLabel(updated), strings.Join(groups, ",")), "ok")
	return updated
}

// prefixDeviceGroups gives the devices' own groups their prefix, once, for a network that ran an
// ento before 0.44: "servers" becomes "device:servers". Rules keep their plain names, which match
// both kinds. Devices of an authority keep the authority's groups.
func (s *Server) prefixDeviceGroups(ctx context.Context) {
	peers, err := s.cfg.Store.Peers(ctx)
	if err != nil {
		s.cfg.Logf("device groups: %v", err)
		return
	}
	for _, p := range peers {
		if p.Authority != "" {
			continue
		}
		want := deviceGroups(p.Machine.Groups)
		if slices.Equal(want, p.Machine.Groups) {
			continue
		}
		if _, err := s.cfg.Store.UpdatePeer(ctx, p.ID, store.PeerUpdate{Groups: &want}); err != nil {
			s.cfg.Logf("device groups of %s: %v", p.Hostname, err)
			continue
		}
		s.cfg.Logf("device groups of %s: %s", p.Hostname, strings.Join(want, ","))
	}
}

// builtinDeviceGroups are always present in the identity provider: losing isolated there must never
// let a device in.
var builtinDeviceGroups = []string{IsolatedGroup, DeviceAdminGroup, DeviceOperatorGroup}

// syncGroups keeps the devices' groups to those the identity provider has, the only source of
// groups where people are managed here: a device group gone there is taken off every device at
// once. Authority groups are the authority's. A provider out of reach changes nothing.
func (s *Server) syncGroups(ctx context.Context) {
	if s.people == nil {
		return
	}
	if err := s.people.ensureGroups(ctx, builtinDeviceGroups); err != nil {
		return
	}
	have, err := s.people.groups(ctx)
	if err != nil {
		return
	}
	peers, err := s.cfg.Store.Peers(ctx)
	if err != nil {
		return
	}
	for _, p := range peers {
		if p.Authority != "" {
			continue
		}
		keep := slices.DeleteFunc(slices.Clone(p.Machine.Groups), func(g string) bool { return isDeviceGroup(g) && !slices.Contains(have, g) })
		if len(keep) == len(p.Machine.Groups) {
			continue
		}
		_, admin, operator := s.groupRights(keep) // a role group deleted there takes the role with it
		if _, err := s.cfg.Store.UpdatePeer(ctx, p.ID, store.PeerUpdate{Groups: &keep, Admin: &admin, Operator: &operator}); err != nil {
			s.cfg.Logf("groups of %s: %v", p.Hostname, err)
			continue
		}
		s.cfg.Logf("groups of %s: no longer in the identity provider, now %s", p.Hostname, strings.Join(keep, ","))
		s.audit(nil, nil, "groups_synced", fmt.Sprintf("%s groups=%s (gone from the identity provider)", peerLabel(p), strings.Join(keep, ",")), "ok")
	}
}

// personRoles are the people groups that give each role, for the dashboard.
func (s *Server) personRoles() map[string][]string {
	out := map[string][]string{"admin": s.personAdminGroups(), "viewer": s.viewerGroups()}
	if s.cfg.OIDC != nil && len(s.cfg.OIDC.OperatorGroups) > 0 {
		out["operator"] = s.cfg.OIDC.OperatorGroups
	} else {
		out["operator"] = []string{"operators"}
	}
	return out
}
