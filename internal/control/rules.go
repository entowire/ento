package control

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"entowire.com/ento/internal/store"
)

// everyone signed in, nobody signed in, or anyone (signed in or not), on a device group or any
// device. It is kept in a policy's Source as one string:
//
//	engineers on device:laptops   engineers signed in on a device of laptops
//	*signed-in on device:servers  anyone signed in, on a device of servers
//	device:servers                anyone or nobody, on a device of servers (as before 0.53)
//	engineers                     engineers signed in, on any device (as before 0.53)
//
// so that a control node older than 0.53 matches no device with a new one: it lets less through,
// never more. Names with "*" are no group's (people groups are lowercase letters, digits, - _ / :).
const (
	// WhoAnyone: whoever is signed in on the device, or nobody.
	WhoAnyone = "*"
	// WhoSignedIn: anyone signed in on the device (Everyone in the constitution).
	WhoSignedIn = "*signed-in"
	// WhoNobody: a device with nobody signed in.
	WhoNobody = "*nobody"
	// onSep joins who and the device group in a policy's Source.
	onSep = " on "
	// ServicePrefix marks a rule's destination that is a forwarded service (by name, no ports).
	ServicePrefix = "service:"
)

// splitSource gives a rule's source as who and the device group it is on ("" for any device). A
// device group alone is anyone on it; a people group alone, its people on any device.
func splitSource(src string) (who, on string) {
	if i := strings.LastIndex(src, onSep+DevicePrefix); i >= 0 {
		return src[:i], src[i+len(onSep):]
	}
	if isDeviceGroup(src) {
		return WhoAnyone, src
	}
	return src, ""
}

// joinSource is the policy Source for who on a device group ("" or "*": any device), in its
// shortest form: anyone on a group is the group alone, as rules were written before 0.53.
func joinSource(who, on string) string {
	if on == "*" {
		on = ""
	}
	switch {
	case on == "":
		return who
	case who == WhoAnyone:
		return on
	}
	return who + onSep + on
}

func isService(g string) bool { return strings.HasPrefix(g, ServicePrefix) }

// personOn reports whether a person is signed in on p with their rights now (the person layer is
// open and approved), as the device's derived rights count them.
func personOn(p store.Peer) bool {
	return p.User != "" && p.Person.Active && p.Person.Approved && !isolated(p)
}

// whoMatches reports whether who (a rule source's people side) holds for p.
func whoMatches(p store.Peer, who string) bool {
	switch who {
	case WhoAnyone:
		return true
	case WhoSignedIn:
		return personOn(p)
	case WhoNobody:
		return !personOn(p)
	}
	// A people group: the person signed in on p is in it (their groups count only while they are).
	// A plain name of a rule written before 0.53 matches a device group of that name too (3.3).
	return hasGroup(p.Groups, who)
}

// sourceIn reports whether p is one of a composite source's devices (who on a device group).
func sourceIn(p store.Peer, src string) bool {
	who, on := splitSource(src)
	if on != "" && !slices.Contains(p.Groups, on) {
		return false
	}
	return whoMatches(p, who)
}

// sourcesOverlap reports whether two rule ends can select the same devices, going by the names: a
// conservative answer for posture checks (bypasses). Two plain groups compare as they did before
// 0.53 (sameGroup: different groups count as apart); a source of who on devices overlaps another
// end where both its who and its devices can, and a plain name may then be either kind (3.3).
func sourcesOverlap(a, b string) bool {
	if a == "*" || b == "*" {
		return true
	}
	newForm := func(x string) bool { return strings.HasPrefix(x, "*") || strings.Contains(x, onSep) }
	if !newForm(a) && !newForm(b) {
		return sameGroup(a, b)
	}
	whoOverlap := func(x, y string) bool {
		switch {
		case x == WhoAnyone || y == WhoAnyone || x == y:
			return true
		case x == WhoNobody || y == WhoNobody: // nobody against a group or everyone signed in
			return false
		case x == WhoSignedIn || y == WhoSignedIn:
			return true
		}
		return sameGroup(x, y)
	}
	onOverlap := func(x, y string) bool { return x == "" || y == "" || sameGroup(x, y) }
	readings := func(x string) [][2]string {
		w, o := splitSource(x)
		out := [][2]string{{w, o}}
		if !newForm(x) && !strings.Contains(x, ":") { // a plain name: maybe a device group
			out = append(out, [2]string{WhoAnyone, DevicePrefix + x})
		}
		return out
	}
	for _, x := range readings(a) {
		for _, y := range readings(b) {
			if whoOverlap(x[0], y[0]) && onOverlap(x[1], y[1]) {
				return true
			}
		}
	}
	return false
}

// ruleGroups lists the groups a rule names, for what uses a group (keepGroups, deleting one).
func ruleGroups(p store.Policy) []string {
	who, on := splitSource(p.Source)
	var out []string
	for _, g := range []string{who, on, p.Destination} {
		if g != "" && !strings.HasPrefix(g, "*") && !isRoute(g) && !isService(g) {
			out = append(out, g)
		}
	}
	return out
}

// ruleSource checks and builds a new rule's source from who and on as an API request gives them
// (on "" and "*": any device). who is resolved to its kind; with on, it must be a people group,
// everyone signed in, nobody or anyone.
func (s *Server) ruleSource(ctx context.Context, who, on string) (string, error) {
	if strings.Contains(who, onSep) {
		if on != "" {
			return "", errors.New("a source with \" on \" names its devices already")
		}
		who, on = splitSource(who)
	}
	switch who {
	case WhoSignedIn, WhoNobody, WhoAnyone:
	default:
		if strings.HasPrefix(who, "*") {
			return "", fmt.Errorf("%q: who is a people group, %s (everyone signed in), %s (nobody signed in) or * (anyone)", who, WhoSignedIn, WhoNobody)
		}
		resolved, err := s.resolveRuleGroup(ctx, who)
		if err != nil {
			return "", err
		}
		who = resolved
		if on != "" && on != "*" && (isDeviceGroup(who) || strings.Contains(who, ":")) {
			return "", fmt.Errorf("%s is no people group: a rule is who (people) on which devices", strings.TrimPrefix(who, DevicePrefix))
		}
		if err := checkGroups([]string{who}, true); err != nil {
			return "", err
		}
	}
	if isRoute(who) || isService(who) {
		return "", errors.New("routes and forwarded services are only ever destinations")
	}
	if on != "" && on != "*" {
		if isRoute(on) || isService(on) || strings.HasPrefix(on, "*") {
			return "", fmt.Errorf("%q: on names a device group or * (any device)", on)
		}
		if !strings.Contains(on, ":") {
			on = DevicePrefix + on
		}
		if !isDeviceGroup(on) {
			return "", fmt.Errorf("%s is no device group", on)
		}
		if err := checkGroups([]string{on}, false); err != nil {
			return "", err
		}
	}
	return joinSource(who, on), nil
}

// checkService validates a rule to a forwarded service: one this node forwards, without ports.
func (s *Server) checkService(dest string, ports []string) error {
	if !isService(dest) {
		return nil
	}
	name := strings.TrimPrefix(dest, ServicePrefix)
	if _, ok := s.cfg.Forwards[name]; !ok {
		return fmt.Errorf("no forwarded service %s (the control nodes' --forward)", name)
	}
	if len(ports) > 0 {
		return errors.New("a forwarded service is reached by name, on its own port: no ports")
	}
	return nil
}

// serviceNames are the forwarded services rules can name (Config.Forwards), sorted.
func (s *Server) serviceNames() []string {
	out := make([]string, 0, len(s.cfg.Forwards))
	for name := range s.cfg.Forwards {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// serviceAllowed reports whether a rule lets dev reach the forwarded service name (3.2): one whose
// destination is the service, whose source dev is (posture checks as for other rules). Full
// administration reaches every forwarded service without a rule (5.2). The database not answering
// is an error: the caller refuses, and says why. Full administration is a person in admins
// signed in on a device in admin, never either alone.
func (s *Server) serviceAllowed(ctx context.Context, dev store.Peer, name string) (bool, error) {
	if !dev.Approved || dev.Suspended || isolated(dev) {
		return false, nil
	}
	if dev.Machine.Admin && personOn(dev) && dev.Person.Admin {
		return true, nil
	}
	policies, err := s.cfg.Store.Policies(ctx)
	if err != nil {
		return false, err
	}
	var ps *postureState
	for _, pol := range policies {
		if pol.Destination != ServicePrefix+name || !inGroup(dev, pol.Source) {
			continue
		}
		if len(pol.Posture) > 0 {
			if ps == nil {
				if ps, err = loadPosture(ctx, s.cfg.Store, time.Now()); err != nil {
					return false, err
				}
			}
			if !ps.passes(dev, pol.Posture) {
				continue
			}
		}
		return true, nil
	}
	return false, nil
}

// serviceRulesSetting marks a forwarded service whose rules were made (ruleServices): its key is
// this prefix and the service's name.
const serviceRulesSetting = "service_rules:"

// ruleServices gives each forwarded service, the first time a control node of 0.53 or later
// forwards it, the rules that let through whom it let through before: every enrolled device (anyone
// on any device), or, with --forward-people, the people in those roles. A setting, written once the
// rules are in place, remembers each service, so that removing a rule later is not undone at the
// next start; adding the same rule twice (two nodes starting at once, or a start that failed half
// way) keeps one.
func (s *Server) ruleServices(ctx context.Context) error {
	for _, name := range s.serviceNames() {
		if _, done, err := s.cfg.Store.Setting(ctx, serviceRulesSetting+name); err != nil {
			return err
		} else if done {
			continue
		}
		var sources []string
		if roles := s.cfg.ForwardPeople[name]; len(roles) > 0 {
			pr := s.personRoles()
			for _, r := range roles {
				sources = append(sources, pr[r]...)
			}
		} else {
			sources = []string{WhoAnyone}
		}
		for _, src := range sources {
			p, err := s.cfg.Store.AddPolicy(ctx, store.Policy{Source: src, Destination: ServicePrefix + name, OneWay: true})
			if err != nil {
				return fmt.Errorf("forwarded service %s: %w", name, err)
			}
			s.audit(nil, nil, "policy_added", policyLabel(p)+" (the service's rule, as it was reached before 0.53)", "ok")
		}
		if _, err := s.cfg.Store.KeepSetting(ctx, serviceRulesSetting+name, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	return nil
}
