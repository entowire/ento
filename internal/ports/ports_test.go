package ports

import (
	"slices"
	"testing"
)

func TestParseAndCanonical(t *testing.T) {
	good := map[string]string{"tcp/22": "tcp/22", " TCP/443 ": "tcp/443", "udp/53": "udp/53", "tcp/8000-8100": "tcp/8000-8100",
		"tcp/80-80": "tcp/80", "tcp": "tcp", "icmp": "icmp", "all": "all"}
	for in, want := range good {
		r, err := Parse(in)
		if err != nil || r.String() != want {
			t.Errorf("Parse(%q) = %v, %v; want %s", in, r, err, want)
		}
	}
	for _, bad := range []string{"tcp/0", "tcp/70000", "tcp/90-80", "icmp/8", "sctp/1", "22", "tcp/x", "all/1", "tcp/1-"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
	c, err := Canonical([]string{"tcp/443", "tcp/22", "tcp/22", "", "icmp"})
	if err != nil || !slices.Equal(c, []string{"icmp", "tcp/22", "tcp/443"}) {
		t.Fatalf("Canonical: %v %v", c, err)
	}
	if c, _ := Canonical([]string{"tcp/22", "all"}); !slices.Equal(c, []string{"all"}) {
		t.Fatalf("Canonical with all: %v", c)
	}
}

func TestAllows(t *testing.T) {
	s := ParseSet([]string{"tcp/22", "tcp/8000-8100", "udp", "icmp", "bogus/1"})
	for _, c := range []struct {
		proto string
		port  uint16
		want  bool
	}{{"tcp", 22, true}, {"tcp", 23, false}, {"tcp", 8050, true}, {"tcp", 8101, false}, {"udp", 9, true},
		{"icmp", 0, true}, {"tcp", 0, false}} {
		if got := s.Allows(c.proto, c.port); got != c.want {
			t.Errorf("Allows(%s, %d) = %v", c.proto, c.port, got)
		}
	}
	if (Set{}).Allows("tcp", 22) || !ParseSet([]string{"all"}).Allows("udp", 1) || !ParseSet([]string{"all"}).All() {
		t.Fatal("empty or all set")
	}
}

func TestUnion(t *testing.T) {
	if u := Union([]string{"tcp/22"}, []string{"tcp/443", "tcp/22"}); !slices.Equal(u, []string{"tcp/22", "tcp/443"}) {
		t.Fatalf("Union: %v", u)
	}
	if u := Union([]string{"tcp/22"}, nil); !slices.Equal(u, []string{"all"}) {
		t.Fatalf("Union with an unrestricted list: %v", u)
	}
}
