package control

import (
	"context"
	"fmt"
	"slices"

	"entowire.com/ento/internal/ports"
	"entowire.com/ento/internal/store"
)

// destination, whose answers return, and both ways is two policies. Policies made both ways before
// are split when a control node starts, so that nothing reaches more or less than before:
//
//   - a group to itself is the same either way: it is made one way;
//   - A both ways B becomes A to B (as it was) and B to A with its ports (merged into an existing
//     B to A without posture checks);
//   - one with posture checks stays as it is (its checks apply to whichever side opens, which no
//     pair of one-way policies says), and so does one whose reverse requires checks of its own:
//     the admin page shows them as old rules both ways, for an admin to replace.

// splitTwoWay splits the policies made both ways, as above.
func (s *Server) splitTwoWay(ctx context.Context) error {
	all, err := s.cfg.Store.Policies(ctx)
	if err != nil {
		return err
	}
	for k := range all {
		p := all[k]
		if p.OneWay {
			continue
		}
		own := p.Ports // what the source may open on the destination: its own, and a two-way reverse's
		if len(p.Posture) > 0 {
			s.cfg.Logf("policy %d (%s both ways %s) requires posture checks: kept both ways, for an admin to replace with one-way policies", p.ID, p.Source, p.Destination)
			continue
		}
		if p.Source != p.Destination {
			i := slices.IndexFunc(all, func(o store.Policy) bool { return o.Source == p.Destination && o.Destination == p.Source })
			switch {
			case i < 0:
				rev, err := s.cfg.Store.AddPolicy(ctx, store.Policy{Source: p.Destination, Destination: p.Source, OneWay: true, Ports: p.Ports})
				if err != nil {
					return fmt.Errorf("policy %d: its reverse: %w", p.ID, err)
				}
				s.cfg.Logf("policy %d (%s both ways %s): its reverse is policy %d, %s to %s", p.ID, p.Source, p.Destination, rev.ID, rev.Source, rev.Destination)
			case len(all[i].Posture) > 0:
				s.cfg.Logf("policy %d (%s both ways %s): its reverse, policy %d, requires posture checks: kept both ways, for an admin to replace",
					p.ID, p.Source, p.Destination, all[i].ID)
				continue
			default:
				rev := all[i]
				merged := union(rev.Ports, p.Ports)
				if !rev.OneWay { // it let p's source open on p's destination too
					own = union(p.Ports, rev.Ports)
				}
				if !slices.Equal(merged, rev.Ports) || !rev.OneWay {
					if _, err := s.cfg.Store.SetPolicyRules(ctx, rev.ID, true, merged); err != nil {
						return fmt.Errorf("policy %d: its reverse %d: %w", p.ID, rev.ID, err)
					}
				}
				all[i].OneWay, all[i].Ports = true, merged // done with it too
				s.cfg.Logf("policy %d (%s both ways %s): its reverse is policy %d, now with its ports too", p.ID, p.Source, p.Destination, rev.ID)
			}
		}
		if _, err := s.cfg.Store.SetPolicyRules(ctx, p.ID, true, own); err != nil {
			return fmt.Errorf("policy %d: %w", p.ID, err)
		}
		all[k].OneWay = true
		s.cfg.Logf("policy %d is one way now: %s to %s (rules go one way)", p.ID, p.Source, p.Destination)
	}
	return nil
}

// union is ports.Union as policies keep it: nil for all.
func union(a, b []string) []string {
	u := ports.Union(a, b)
	if slices.Equal(u, []string{"all"}) {
		return nil
	}
	return u
}
