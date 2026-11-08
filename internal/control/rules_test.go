package control

import (
	"context"
	"net/netip"
	"testing"

	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

// testDevice is a test device in device groups, with a person in people groups signed in on it (none:
// nobody signed in).
func testDevice(id int64, devGroups []string, person ...string) store.Peer {
	p := store.Peer{ID: id, Approved: true, Hostname: "d", Machine: store.Rights{Approved: true, Groups: devGroups}}
	p.Groups = append([]string{}, devGroups...)
	if len(person) > 0 {
		p.User = "sub"
		p.Person = store.PersonLayer{Active: true, Rights: store.Rights{Approved: true, Groups: person}}
		p.Groups = append(p.Groups, person...)
	}
	return p
}

// group alone and a people group alone keep their meaning from before 0.53.
func TestRuleSource(t *testing.T) {
	for _, c := range []struct{ who, on, src string }{
		{"engineers", "device:laptops", "engineers on device:laptops"},
		{WhoAnyone, "device:servers", "device:servers"},
		{"engineers", "", "engineers"},
		{"engineers", "*", "engineers"},
		{WhoSignedIn, "device:laptops", "*signed-in on device:laptops"},
		{WhoNobody, "", "*nobody"},
	} {
		if got := joinSource(c.who, c.on); got != c.src {
			t.Errorf("join %q %q: %q, want %q", c.who, c.on, got, c.src)
		}
		who, on := splitSource(c.src)
		wantOn := c.on
		if wantOn == "*" {
			wantOn = ""
		}
		if who != c.who || on != wantOn {
			t.Errorf("split %q: %q %q", c.src, who, on)
		}
	}
	laptopEng := testDevice(1, []string{"device:laptops"}, "engineers")
	laptopNobody := testDevice(2, []string{"device:laptops"})
	serverEng := testDevice(3, []string{"device:servers"}, "engineers")
	laptopSales := testDevice(4, []string{"device:laptops"}, "sales")
	for _, c := range []struct {
		src  string
		p    store.Peer
		want bool
	}{
		{"engineers on device:laptops", laptopEng, true},
		{"engineers on device:laptops", serverEng, false},   // the right person, another device
		{"engineers on device:laptops", laptopSales, false}, // the right device, another person
		{"engineers on device:laptops", laptopNobody, false},
		{"*signed-in on device:laptops", laptopSales, true},
		{"*signed-in on device:laptops", laptopNobody, false},
		{"*nobody on device:laptops", laptopNobody, true},
		{"*nobody on device:laptops", laptopEng, false},
		{"*nobody", serverEng, false},
		{"device:laptops", laptopNobody, true},
		{"device:laptops", laptopEng, true},
		{"engineers", serverEng, true},
		{"engineers", laptopNobody, false},
	} {
		if got := inGroup(c.p, c.src); got != c.want {
			t.Errorf("%q on device %d: %v, want %v", c.src, c.p.ID, got, c.want)
		}
	}
	// A device's machine alone (what its traffic counts as without its person) has nobody on it.
	if inGroup(laptopEng.MachineOnly(), "engineers on device:laptops") {
		t.Error("the machine alone counts as its person")
	}
	// A destination is never a rule's source form, and forwarded services and routes are no group.
	for _, g := range []string{"service:agent.example.com", "route:office"} {
		if inGroup(laptopEng, g) {
			t.Errorf("%s matched a device", g)
		}
	}
}

// An older control node reads a new source as a group no device is in: it lets less through.
func TestRuleSourceFailsClosed(t *testing.T) {
	p := testDevice(1, []string{"device:laptops"}, "engineers")
	for _, src := range []string{"engineers on device:laptops", WhoSignedIn, WhoNobody} {
		if hasGroup(p.Groups, src) {
			t.Errorf("%q is a group of the device for a control node before 0.53", src)
		}
	}
}

func TestRuleSourceChecks(t *testing.T) {
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	s := &Server{cfg: Config{Store: st, Logf: t.Logf}}
	ctx := context.Background()
	for _, c := range []struct{ who, on, want string }{
		{"engineers", "laptops", "engineers on device:laptops"},
		{"engineers", "device:laptops", "engineers on device:laptops"},
		{"*", "laptops", "device:laptops"},
		{WhoSignedIn, "*", WhoSignedIn},
		{"engineers on device:laptops", "", "engineers on device:laptops"},
	} {
		got, err := s.ruleSource(ctx, c.who, c.on)
		if err != nil || got != c.want {
			t.Errorf("%q on %q: %q %v, want %q", c.who, c.on, got, err, c.want)
		}
	}
	for _, c := range []struct{ who, on string }{
		{"device:servers", "laptops"}, // a device group is no who
		{"*root", ""},
		{"engineers", "route:office"},
		{"engineers", "service:x.example.com"},
		{"route:office", ""},
		{"engineers on device:laptops", "servers"},
	} {
		if got, err := s.ruleSource(ctx, c.who, c.on); err == nil {
			t.Errorf("%q on %q accepted: %q", c.who, c.on, got)
		}
	}
}

// Posture checks: a rule of who on devices that could select the same devices as one with checks
// counts as overlapping it; plain groups compare as before.
func TestSourcesOverlap(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"engineers on device:laptops", "engineers", true},
		{"engineers on device:laptops", "device:laptops", true},
		{"engineers on device:laptops", "laptops", true}, // a plain name may be the device group
		{"engineers on device:laptops", "sales on device:laptops", false},
		{"engineers on device:laptops", "engineers on device:servers", false},
		{"*signed-in on device:laptops", "engineers", true},
		{"*nobody on device:laptops", "engineers", false},
		{"*nobody on device:laptops", "device:laptops", true},
		{"engineers", "sales", false},
		{"laptops", "device:laptops", true},
		{"*", "sales on device:laptops", true},
	} {
		if got := sourcesOverlap(c.a, c.b); got != c.want {
			t.Errorf("%q and %q: %v, want %v", c.a, c.b, got, c.want)
		}
		if got := sourcesOverlap(c.b, c.a); got != c.want {
			t.Errorf("%q and %q: %v, want %v", c.b, c.a, got, c.want)
		}
	}
	// An operator's rule without checks that reaches the same devices as an admin's with them.
	guarded := store.Policy{ID: 1, Source: "engineers on device:laptops", Destination: "device:servers", Posture: []string{"disk"}, OneWay: true}
	if !bypasses(store.Policy{Source: "engineers", Destination: "device:servers", OneWay: true}, guarded) {
		t.Error("engineers on any device bypasses the checks of engineers on laptops")
	}
	if bypasses(store.Policy{Source: "sales on device:laptops", Destination: "device:servers", OneWay: true}, guarded) {
		t.Error("another people group counts as a bypass")
	}
}

// Forwarded services are reached by rules (3.2): what a node forwarded before 0.53 gets, once, the
// rules that let through whom it did; removing one is not undone; full administration needs none.
func TestServiceRules(t *testing.T) {
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	ctx := context.Background()
	s := &Server{cfg: Config{Store: st, Logf: t.Logf,
		Forwards:      map[string][]string{"agent.example.com": {"h:1"}, "platform.example.com": {"h:2"}},
		ForwardPeople: map[string][]string{"platform.example.com": {"admin"}}}}
	if err := s.ruleServices(ctx); err != nil {
		t.Fatal(err)
	}
	pols, _ := st.Policies(ctx)
	have := map[string]bool{}
	for _, p := range pols {
		have[p.Source+" -> "+p.Destination] = true
	}
	if len(pols) != 2 || !have["* -> service:agent.example.com"] || !have["admins -> service:platform.example.com"] {
		t.Fatalf("the services' rules: %+v", pols)
	}
	nobody := testDevice(1, []string{"device:laptops"})
	admin := testDevice(2, []string{"device:laptops"}, "admins")
	if ok, _ := s.serviceAllowed(ctx, nobody, "agent.example.com"); !ok {
		t.Error("anyone on any device does not reach agent")
	}
	if ok, _ := s.serviceAllowed(ctx, nobody, "platform.example.com"); ok {
		t.Error("a device without its person reached platform")
	}
	if ok, _ := s.serviceAllowed(ctx, admin, "platform.example.com"); !ok {
		t.Error("an admin did not reach platform")
	}
	isolatedDev := testDevice(3, []string{"device:isolated"})
	if ok, _ := s.serviceAllowed(ctx, isolatedDev, "agent.example.com"); ok {
		t.Error("an isolated device reached a forwarded service")
	}
	for _, p := range pols {
		if p.Destination == "service:agent.example.com" {
			_ = st.DeletePolicy(ctx, p.ID)
		}
	}
	if ok, _ := s.serviceAllowed(ctx, nobody, "agent.example.com"); ok {
		t.Error("reached agent without a rule")
	}
	if err := s.ruleServices(ctx); err != nil {
		t.Fatal(err)
	}
	if pols, _ := st.Policies(ctx); len(pols) != 1 {
		t.Fatalf("the removed rule came back: %+v", pols)
	}
	// Full administration: a person in admins on a device in admin.
	full := testDevice(4, []string{"device:admin"}, "admins")
	full.Machine.Admin, full.Person.Admin, full.Admin = true, true, true
	if ok, _ := s.serviceAllowed(ctx, full, "agent.example.com"); !ok {
		t.Error("full administration did not reach a service")
	}
	machineAdmin := testDevice(5, []string{"device:admin"})
	machineAdmin.Machine.Admin, machineAdmin.Admin = true, true
	if ok, _ := s.serviceAllowed(ctx, machineAdmin, "agent.example.com"); ok {
		t.Error("a device in admin with nobody signed in reached a service without a rule")
	}
}
