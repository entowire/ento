//go:build linux

package agent

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"entowire.com/ento/internal/api"
)

func TestValidForwards(t *testing.T) {
	home := netip.MustParsePrefix("100.64.0.0/16")
	got := validForwards([]api.Forward{
		{Name: "id.example.com", Port: 443, Targets: []string{"100.64.0.1:443", "10.0.0.1:443"}},
		{Name: "outside.example.com", Port: 443, Targets: []string{"10.0.0.1:443"}}, // no target in home
		{Name: "Bad Name", Port: 443, Targets: []string{"100.64.0.1:443"}},
		{Name: "single", Port: 443, Targets: []string{"100.64.0.1:443"}},
		{Name: "a.example.com", Port: 70000, Targets: []string{"100.64.0.1:443"}},
	}, home)
	if len(got) != 1 || got[0].Name != "id.example.com" || len(got[0].Targets) != 1 {
		t.Fatalf("got %+v", got)
	}
}

// Two names hashing to the same slot get distinct addresses, the later one in name order the next.
func TestForwardNamesCollision(t *testing.T) {
	var fs []api.Forward
	for i := 0; i < maxForwardNames; i++ {
		fs = append(fs, api.Forward{Name: fmt.Sprintf("s%d.example.com", i), Port: 1})
	}
	names := forwardNames(fs)
	seen := map[string]bool{}
	for _, a := range names {
		if seen[a] {
			t.Fatalf("address %s given twice", a)
		}
		seen[a] = true
	}
	if len(names) != maxForwardNames {
		t.Fatalf("%d names", len(names))
	}
}

func TestForwardNamesAndMerge(t *testing.T) {
	names := forwardNames([]api.Forward{{Name: "b.example.com", Port: 1}, {Name: "a.example.com", Port: 1}, {Name: "a.example.com", Port: 2}})
	if len(names) != 2 || names["a.example.com"] == names["b.example.com"] ||
		!strings.HasPrefix(names["a.example.com"], "127.2.") || !strings.HasPrefix(names["b.example.com"], "127.2.") {
		t.Fatalf("names %v", names)
	}
	// Adding or removing another forward keeps every name's address.
	more := forwardNames([]api.Forward{{Name: "0.example.com", Port: 1}, {Name: "a.example.com", Port: 1}, {Name: "b.example.com", Port: 1}})
	if more["a.example.com"] != names["a.example.com"] || more["b.example.com"] != names["b.example.com"] {
		t.Fatalf("addresses moved: %v then %v", names, more)
	}
	merged := mergeHosts(map[string][]string{"a.example.com": {"100.66.0.9"}, "srv": {"100.66.1.1"}}, names, t.Logf)
	if len(merged["a.example.com"]) != 1 || merged["a.example.com"][0] != names["a.example.com"] || merged["srv"][0] != "100.66.1.1" {
		t.Fatalf("merged %v", merged)
	}
}
