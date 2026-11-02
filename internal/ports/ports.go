// Package ports reads and matches the port rules of policies: what a device may open on another.
//
// A rule is one of
//
//	all              everything
//	tcp | udp        every port of that protocol
//	tcp/22           one port
//	tcp/8000-8100    a range
//	icmp             echo requests (ping); answers and errors pass anyway
//
// A list of rules allows what any of them allows; an empty list (on a policy) allows everything.
package ports

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Rule is one parsed rule. From and To are 0 for a whole protocol.
type Rule struct {
	Proto    string // "all", "tcp", "udp", "icmp"
	From, To uint16
}

// Parse reads one rule.
func Parse(s string) (Rule, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	proto, rng, hasPort := strings.Cut(s, "/")
	switch proto {
	case "all", "icmp":
		if hasPort {
			return Rule{}, fmt.Errorf("port rule %q: %s takes no port", s, proto)
		}
		return Rule{Proto: proto}, nil
	case "tcp", "udp":
	default:
		return Rule{}, fmt.Errorf("port rule %q: tcp/PORT, tcp/FROM-TO, udp/..., tcp, udp, icmp or all", s)
	}
	if !hasPort {
		return Rule{Proto: proto}, nil
	}
	lo, hi, isRange := strings.Cut(rng, "-")
	from, err := port(lo)
	if err != nil {
		return Rule{}, fmt.Errorf("port rule %q: %w", s, err)
	}
	to := from
	if isRange {
		if to, err = port(hi); err != nil {
			return Rule{}, fmt.Errorf("port rule %q: %w", s, err)
		}
		if to < from {
			return Rule{}, fmt.Errorf("port rule %q: the range ends before it starts", s)
		}
	}
	return Rule{Proto: proto, From: from, To: to}, nil
}

func port(s string) (uint16, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%q is not a port (1-65535)", s)
	}
	return uint16(n), nil
}

// String writes a rule in its canonical form.
func (r Rule) String() string {
	switch {
	case r.From == 0:
		return r.Proto
	case r.From == r.To:
		return fmt.Sprintf("%s/%d", r.Proto, r.From)
	}
	return fmt.Sprintf("%s/%d-%d", r.Proto, r.From, r.To)
}

// Canonical parses a list of rules and returns it in canonical form, sorted and without repeats;
// a list that allows everything (it holds "all") is ["all"].
func Canonical(list []string) ([]string, error) {
	var out []string
	for _, s := range list {
		if strings.TrimSpace(s) == "" {
			continue
		}
		r, err := Parse(s)
		if err != nil {
			return nil, err
		}
		if r.Proto == "all" {
			return []string{"all"}, nil
		}
		out = append(out, r.String())
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// Set is a parsed list of rules.
type Set []Rule

// ParseSet parses a list; rules that do not parse are left out (lists come checked from the control
// nodes; a newer rule an older agent does not know allows nothing rather than everything).
func ParseSet(list []string) Set {
	var s Set
	for _, x := range list {
		if r, err := Parse(x); err == nil {
			s = append(s, r)
		}
	}
	return s
}

// All reports whether the set allows everything.
func (s Set) All() bool {
	return slices.ContainsFunc(s, func(r Rule) bool { return r.Proto == "all" })
}

// Allows reports whether a new connection with this protocol ("tcp", "udp", "icmp") to this port
// (0 for icmp) is allowed.
func (s Set) Allows(proto string, port uint16) bool {
	for _, r := range s {
		switch {
		case r.Proto == "all":
			return true
		case r.Proto != proto:
		case r.From == 0, port >= r.From && port <= r.To:
			return true
		}
	}
	return false
}

// Union merges lists of rules (each one canonical): everything if any allows everything.
func Union(lists ...[]string) []string {
	var all []string
	for _, l := range lists {
		if len(l) == 0 || slices.Contains(l, "all") {
			return []string{"all"}
		}
		all = append(all, l...)
	}
	out, _ := Canonical(all)
	return out
}
