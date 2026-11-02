package control

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"entowire.com/ento/internal/api"
)

// ParseLinkForwards parses --link-forwards: comma-separated entries NAME:PORT=TARGET[+TARGET...],
// each TARGET an address:port inside network, e.g.
//
//	id.example.com:443=100.64.0.1:443+100.64.0.2:443
func ParseLinkForwards(s string, network netip.Prefix) ([]api.Forward, error) {
	var out []api.Forward
	seen := map[string]bool{}
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		svc, targets, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("link forward %q: want NAME:PORT=TARGET[+TARGET...]", entry)
		}
		name, portStr, ok := strings.Cut(svc, ":")
		port, err := strconv.Atoi(portStr)
		if !ok || err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("link forward %q: invalid port", entry)
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if !ValidForwardName(name) {
			return nil, fmt.Errorf("link forward %q: invalid name", entry)
		}
		if seen[svc] {
			return nil, fmt.Errorf("link forward %q: duplicate", entry)
		}
		seen[svc] = true
		f := api.Forward{Name: name, Port: port}
		for _, t := range strings.Split(targets, "+") {
			ap, err := netip.ParseAddrPort(strings.TrimSpace(t))
			if err != nil || !network.Contains(ap.Addr()) {
				return nil, fmt.Errorf("link forward %q: target %q is not an address:port in %s", entry, t, network)
			}
			f.Targets = append(f.Targets, ap.String())
		}
		out = append(out, f)
	}
	return out, nil
}

// ValidForwardName reports whether name is a DNS name usable for a forwarded service: lowercase
// labels of letters, digits and dashes, at least two of them.
func ValidForwardName(name string) bool {
	labels := strings.Split(name, ".")
	if len(name) > 253 || len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// ParseForwards reads --forward: comma-separated NAME=HOST:PORT[+HOST:PORT...], the services a
// control node passes through on its overlay port 443 by TLS server name (Config.Forwards).
func ParseForwards(s string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, list, ok := strings.Cut(entry, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if !ok || name == "" {
			return nil, fmt.Errorf("--forward %q: want NAME=HOST:PORT[+HOST:PORT...]", entry)
		}
		if _, err := dnsName(name); err != nil || !strings.Contains(name, ".") {
			return nil, fmt.Errorf("--forward %q: %q is not a host name", entry, name)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("--forward: %s twice", name)
		}
		for _, t := range strings.Split(list, "+") {
			host, port, err := net.SplitHostPort(strings.TrimSpace(t))
			if err != nil || host == "" || port == "" {
				return nil, fmt.Errorf("--forward %q: %q is not host:port", entry, t)
			}
			out[name] = append(out[name], net.JoinHostPort(host, port))
		}
	}
	return out, nil
}
