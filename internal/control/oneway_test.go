package control

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

// Policies made both ways before 0.52 are split into one-way policies that let through what they
func TestSplitTwoWay(t *testing.T) {
	ctx := context.Background()
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	add := func(p store.Policy) store.Policy {
		t.Helper()
		got, err := st.AddPolicy(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if _, err := st.AddPostureCheck(ctx, store.PostureCheck{Name: "enc", DiskEncryption: true, MaxAge: time.Hour}); err != nil {
		t.Fatal(err)
	}
	self := add(store.Policy{Source: "servers", Destination: "servers"})                                   // a group to itself
	plain := add(store.Policy{Source: "laptops", Destination: "db", Ports: []string{"tcp/5432"}})          // no reverse yet
	merge := add(store.Policy{Source: "ops", Destination: "web", Ports: []string{"tcp/22"}})               // a one-way reverse exists
	rev := add(store.Policy{Source: "web", Destination: "ops", OneWay: true, Ports: []string{"tcp/9100"}}) //
	both1 := add(store.Policy{Source: "a", Destination: "b", Ports: []string{"tcp/1"}})                    // both ways twice
	both2 := add(store.Policy{Source: "b", Destination: "a", Ports: []string{"tcp/2"}})                    //
	guarded := add(store.Policy{Source: "phones", Destination: "mail", Posture: []string{"enc"}})          // kept
	revGuarded := add(store.Policy{Source: "x", Destination: "y"})                                         // its reverse has checks
	add(store.Policy{Source: "y", Destination: "x", OneWay: true, Posture: []string{"enc"}})               //
	_ = revGuarded

	s := &Server{cfg: Config{Store: st, Logf: t.Logf}}
	if err := s.splitTwoWay(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.splitTwoWay(ctx); err != nil { // again: nothing more to do
		t.Fatal(err)
	}
	all, err := st.Policies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	get := func(src, dst string) store.Policy {
		t.Helper()
		i := slices.IndexFunc(all, func(p store.Policy) bool { return p.Source == src && p.Destination == dst })
		if i < 0 {
			t.Fatalf("no policy %s -> %s in %+v", src, dst, all)
		}
		return all[i]
	}
	want := func(src, dst string, oneWay bool, ports ...string) {
		t.Helper()
		p := get(src, dst)
		if p.OneWay != oneWay || !slices.Equal(p.Ports, ports) {
			t.Fatalf("%s -> %s: one way %v, ports %v; want %v, %v", src, dst, p.OneWay, p.Ports, oneWay, ports)
		}
	}
	want("servers", "servers", true)
	want("laptops", "db", true, "tcp/5432")
	want("db", "laptops", true, "tcp/5432")
	want("ops", "web", true, "tcp/22")
	want("web", "ops", true, "tcp/22", "tcp/9100")
	want("a", "b", true, "tcp/1", "tcp/2")
	want("b", "a", true, "tcp/1", "tcp/2")
	want("phones", "mail", false)
	want("x", "y", false)
	if len(all) != 10 {
		t.Fatalf("%d policies, want 10 (one reverse added): %+v", len(all), all)
	}
	for _, p := range []store.Policy{self, plain, merge, rev, both1, both2, guarded} {
		if get(p.Source, p.Destination).ID != p.ID {
			t.Fatalf("policy %d was replaced", p.ID)
		}
	}
}
