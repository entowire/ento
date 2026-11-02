package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"6.8.0-142-generic", "6.1", 1, true},
		{"6.1", "6.1.0", 0, true},
		{"6.0.19", "6.1", -1, true},
		{"10.0.26100.2033", "10.0.22631", 1, true},
		{"10.0.19045", "10.0.22631", -1, true},
		{"14.5", "14.0", 1, true},
		{"13", "14", -1, true},
		{"6.10", "6.9", 1, true}, // numeric, not lexical
		{"5.4.0+deb", "5.4", 0, true},
		{"", "6.1", 0, false},
		{"unknown", "6.1", 0, false},
		{"6.1", "", 0, false},
	} {
		got, ok := compareVersions(c.a, c.b)
		if got != c.want || ok != c.ok {
			t.Errorf("compareVersions(%q, %q) = %d %v, want %d %v", c.a, c.b, got, ok, c.want, c.ok)
		}
	}
}

func TestEvaluateCheck(t *testing.T) {
	yes, no := ptr(true), ptr(false)
	now := time.Now()
	check := store.PostureCheck{Name: "baseline", DiskEncryption: true, Firewall: true,
		MinOS: map[string]string{"linux": "6.1", "windows": "10.0.22631"}, MaxAge: 30 * time.Minute}
	good := api.Posture{Format: 1, OS: "linux", OSVersion: "6.8.0-1-generic", DiskEncryption: yes, Firewall: yes}
	for _, c := range []struct {
		name  string
		facts *api.Posture
		at    time.Time
		want  string
	}{
		{"passes", &good, now, ""},
		{"no report", nil, time.Time{}, "no report"},
		{"stale", &good, now.Add(-31 * time.Minute), "no report in 30m"},
		{"not encrypted", &api.Posture{OS: "linux", OSVersion: "6.8", DiskEncryption: no, Firewall: yes}, now, "disk not encrypted"},
		{"unknown facts", &api.Posture{OS: "linux", OSVersion: "6.8"}, now, "disk encryption unknown, firewall unknown"},
		{"old kernel", &api.Posture{OS: "linux", OSVersion: "5.15.0-1", DiskEncryption: yes, Firewall: no}, now,
			"firewall off, Linux 5.15.0-1 is older than 6.1"},
		{"no version", &api.Posture{OS: "windows", DiskEncryption: yes, Firewall: yes}, now, "Windows version unknown"},
		{"system not limited", &api.Posture{OS: "darwin", OSVersion: "11.0", DiskEncryption: yes, Firewall: yes}, now, ""},
		{"unknown system", &api.Posture{OS: "plan9", DiskEncryption: yes, Firewall: yes}, now, "system unknown"},
	} {
		if got := evaluateCheck(check, c.facts, c.at, now); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// Secure boot, and the default age.
	sb := store.PostureCheck{Name: "sb", SecureBoot: true}
	if got := evaluateCheck(sb, &api.Posture{OS: "linux", SecureBoot: no}, now.Add(-29*time.Minute), now); got != "secure boot off" {
		t.Errorf("secure boot: %q", got)
	}
	if got := evaluateCheck(sb, &api.Posture{OS: "linux", SecureBoot: yes}, now.Add(-31*time.Minute), now); got != "no report in 30m" {
		t.Errorf("default age: %q", got)
	}
	// Anti-malware: off and unknown both fail.
	av := store.PostureCheck{Name: "av", Antimalware: true}
	for facts, want := range map[*api.Posture]string{
		{OS: "windows", Antimalware: yes}: "", {OS: "windows", Antimalware: no}: "anti-malware off",
		{OS: "linux"}: "anti-malware unknown",
	} {
		if got := evaluateCheck(av, facts, now, now); got != want {
			t.Errorf("anti-malware %v: %q, want %q", facts.Antimalware, got, want)
		}
	}
}

// TestPostureAllowed checks how a policy's checks filter its source devices, both ways.
func TestPostureAllowed(t *testing.T) {
	peer := func(id int64, groups ...string) store.Peer {
		return store.Peer{ID: id, Approved: true, Groups: groups}
	}
	laptop, server, staffOK, staffBad := peer(1, "laptops"), peer(2, "servers"), peer(3, "staff"), peer(4, "staff")
	ps := &postureState{now: time.Now(), checks: map[string]store.PostureCheck{"enc": {Name: "enc", DiskEncryption: true}},
		reports: map[int64]store.PostureReport{
			1: {PeerID: 1, Results: map[string]string{"enc": "disk not encrypted"}},
			3: {PeerID: 3, Results: map[string]string{"enc": ""}},
			4: {PeerID: 4, Results: map[string]string{"enc": "no report"}},
		}, facts: map[int64]*api.Posture{}}
	checked := []store.Policy{{Source: "laptops", Destination: "servers", Posture: []string{"enc"}},
		{Source: "staff", Destination: "staff", Posture: []string{"enc"}}}
	if allowed(laptop, server, checked, ps) || allowed(server, laptop, checked, ps) {
		t.Error("a failing source device reaches its destination")
	}
	// A failing device in both groups of a policy is left out of it entirely.
	if allowed(staffOK, staffBad, checked, ps) || allowed(staffBad, staffOK, checked, ps) {
		t.Error("a failing device is reached as a destination of the policy it fails")
	}
	ps.reports[1] = store.PostureReport{PeerID: 1, Results: map[string]string{"enc": ""}}
	if !allowed(laptop, server, checked, ps) || !allowed(server, laptop, checked, ps) {
		t.Error("a passing source device is left out")
	}
	// Without a stored result (just required), the check is evaluated on the spot: no report fails.
	other := peer(5, "laptops")
	if allowed(other, server, checked, ps) {
		t.Error("a device without a report passes")
	}
	// A policy without checks is not affected; without any posture state, checks fail closed.
	plain := append(checked, store.Policy{Source: "staff", Destination: "servers"})
	if !allowed(staffBad, server, plain, ps) {
		t.Error("a policy without checks is affected")
	}
	if allowed(laptop, server, checked, nil) {
		t.Error("no posture state: a check passed")
	}
}

// countAll counts the log lines that contain every one of substrings.
func (l *logLines) countAll(substrings ...string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, line := range l.lines {
		if !slices.ContainsFunc(substrings, func(s string) bool { return !strings.Contains(line, s) }) {
			n++
		}
	}
	return n
}

func TestPostureChecks(t *testing.T) {
	savedGap, savedHold := postureReportGap, postureHoldDown
	postureReportGap, postureHoldDown = 0, 0
	defer func() { postureReportGap, postureHoldDown = savedGap, savedHold }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	space, _ := ipam.New(netip.MustParsePrefix("100.72.0.0/16"))
	st := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	logs := &logLines{t: t}
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port,
		Endpoint: fmt.Sprintf("127.0.0.1:%d", port), Space: space, Store: st, Logf: logs.logf})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	admin := adminOf(t, ctx, srv, st, "admin", "admins")
	device := func(host string, groups ...string) (*testClient, store.Peer) {
		tok, _, err := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: groups})
		if err != nil {
			t.Fatal(err)
		}
		srv.checkVersion(ctx)
		c, res := enroll(t, tok, host)
		p, err := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
		if err != nil {
			t.Fatal(err)
		}
		return c, p
	}
	op, opPeer := device("op", "operators")
	if _, err := st.UpdatePeer(ctx, opPeer.ID, store.PeerUpdate{Operator: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	laptop, laptopPeer := device("laptop", "laptops")
	server, _ := device("server", "servers")
	phone, _ := device("phone", "phones")
	netmap := func(c *testClient) api.NetMap {
		t.Helper()
		var nm api.NetMap
		if code := c.do(t, "GET", api.PathNetMap, nil, &nm); code != http.StatusOK {
			t.Fatalf("netmap: HTTP %d", code)
		}
		return nm
	}
	sees := func(c *testClient, host string) bool {
		for _, p := range netmap(c).Peers {
			if p.Hostname == host {
				return true
			}
		}
		return false
	}
	relays := func(src, dst string) bool {
		if err := srv.reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		tbl := srv.relay.table.Load()
		var a, b store.Peer
		for _, p := range tbl.byKey {
			switch p.Hostname {
			case src:
				a = p
			case dst:
				b = p
			}
		}
		return tbl.permits(a, b)
	}

	// Checks: admins add them, operators only read them.
	check := api.PostureCheck{Name: "enc", DiskEncryption: true, MinOS: map[string]string{"linux": "6.1"}}
	if code := op.do(t, "POST", api.PathPostureChecks, check, nil); code != http.StatusForbidden {
		t.Fatalf("operator adds a check: HTTP %d", code)
	}
	var created api.PostureCheck
	if code := admin.do(t, "POST", api.PathPostureChecks, check, &created); code != http.StatusCreated || created.MaxAgeSeconds != 1800 {
		t.Fatalf("add check: HTTP %d %+v", code, created)
	}
	for _, bad := range []api.PostureCheck{{Name: "Bad Name"}, {Name: "x", MinOS: map[string]string{"beos": "5"}},
		{Name: "x", MinOS: map[string]string{"linux": "6.1; rm"}}, {Name: "x", MaxAgeSeconds: 60},
		{Name: "x", MinOS: map[string]string{"windows": "11"}}} {
		if code := admin.do(t, "POST", api.PathPostureChecks, bad, nil); code != http.StatusBadRequest {
			t.Errorf("invalid check %+v: HTTP %d", bad, code)
		}
	}
	if code := admin.do(t, "POST", api.PathPostureChecks, check, nil); code != http.StatusConflict {
		t.Errorf("duplicate check: HTTP %d", code)
	}
	var checks []api.PostureCheck
	if code := op.do(t, "GET", api.PathPostureChecks, nil, &checks); code != http.StatusOK || len(checks) != 1 {
		t.Fatalf("operator lists checks: HTTP %d %+v", code, checks)
	}
	if logs.countAll("action=posture_check_added", "check enc disk_encryption=true", "min_os=linux=6.1 max_age=30m", "result=ok") != 1 {
		t.Error("check not audited")
	}

	// Policies: only admins attach checks.
	if code := op.do(t, "POST", api.PathPolicies, api.Policy{Source: "laptops", Destination: "servers", Posture: []string{"enc"}}, nil); code != http.StatusForbidden {
		t.Fatalf("operator attaches a check: HTTP %d", code)
	}
	if code := op.do(t, "POST", api.PathPolicies, api.Policy{Source: "laptops", Destination: "servers", Posture: []string{"enc check=forged"}}, nil); code != http.StatusBadRequest {
		t.Fatalf("operator names an invalid check: HTTP %d", code)
	}
	if logs.countAll("forged") != 0 {
		t.Error("an invalid check name reached an audit line")
	}
	if code := admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "laptops", Destination: "servers", Posture: []string{"nope"}}, nil); code != http.StatusBadRequest {
		t.Fatalf("unknown check: HTTP %d", code)
	}
	var pol api.Policy
	if code := admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "laptops", Destination: "servers", Posture: []string{"enc"}}, &pol); code != http.StatusCreated {
		t.Fatalf("policy with a check: HTTP %d", code)
	}
	if code := op.do(t, "POST", api.PathPolicies, api.Policy{Source: "phones", Destination: "servers"}, nil); code != http.StatusCreated {
		t.Fatalf("operator adds a policy without checks: HTTP %d", code)
	}
	if code := admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "laptops", Destination: "servers"}, nil); code != http.StatusConflict {
		t.Fatalf("the same policy without its checks: HTTP %d", code)
	}
	if logs.countAll("action=policy_added", fmt.Sprintf("policy %d device:laptops <-> device:servers posture=enc", pol.ID)) != 1 {
		t.Error("policy's checks not audited")
	}

	// No report: the laptop is left out, and told why; devices of other policies are not affected.
	nm := netmap(laptop)
	if len(nm.Peers) != 0 || len(nm.Self.PostureFailing) != 1 || nm.Self.PostureFailing[0] != (api.PostureFailure{Check: "enc", Reason: "no report"}) {
		t.Fatalf("laptop without a report: %+v", nm)
	}
	if sees(server, "z-laptop") || !sees(server, "z-phone") || !sees(phone, "z-server") || relays("z-laptop", "z-server") {
		t.Fatal("a device without a report is in the network map or the relay")
	}
	if len(netmap(phone).Self.PostureFailing) != 0 {
		t.Fatal("a device no policy requires checks of fails one")
	}
	if logs.countAll("action=posture_", "z-laptop") != 0 {
		t.Error("a device enrolled a moment ago, without a report yet, was audited")
	}

	// Reports are signed calls.
	report := api.Posture{Format: 1, OS: "linux", OSVersion: "6.8.0-1-generic", DiskEncryption: ptr(false), Firewall: ptr(true)}
	laptop.unsigned = true
	if code := laptop.do(t, "POST", api.PathPosture, report, nil); code != http.StatusUnauthorized {
		t.Fatalf("unsigned report: HTTP %d", code)
	}
	laptop.unsigned = false
	var res api.PostureResult
	if code := laptop.do(t, "POST", api.PathPosture, report, &res); code != http.StatusOK ||
		len(res.Failing) != 1 || res.Failing[0].Reason != "disk not encrypted" {
		t.Fatalf("report: HTTP %d %+v", code, res)
	}
	if code := laptop.do(t, "POST", api.PathPosture, map[string]any{"os": "linux"}, nil); code != http.StatusBadRequest {
		t.Fatalf("report without a format: HTTP %d", code)
	}
	if nm := netmap(laptop); len(nm.Peers) != 0 || nm.Self.PostureFailing[0].Reason != "disk not encrypted" {
		t.Fatalf("failing laptop: %+v", nm)
	}
	if logs.countAll("action=posture_failed", "z-laptop", "check=enc reason=disk not encrypted", "result=denied") != 1 {
		t.Error("failure not audited")
	}
	report.Firewall = ptr(false) // another fact, the same failure
	laptop.do(t, "POST", api.PathPosture, report, nil)
	report.Firewall = ptr(true)
	laptop.do(t, "POST", api.PathPosture, report, nil)
	if logs.countAll("action=posture_failed", "z-laptop") != 1 {
		t.Error("the same failure was audited again")
	}

	// Reports closer together than the gap are refused, whichever control node they reach.
	postureReportGap = time.Hour
	if code := laptop.do(t, "POST", api.PathPosture, report, nil); code != http.StatusTooManyRequests {
		t.Fatalf("report too soon: HTTP %d", code)
	}
	postureReportGap = 0

	// Hold-down: a device that just started failing over its facts keeps failing for a while,
	// even when it reports facts that pass; then it passes on the next evaluation.
	postureHoldDown = time.Hour
	report.DiskEncryption = ptr(true)
	if code := laptop.do(t, "POST", api.PathPosture, report, &res); code != http.StatusOK ||
		len(res.Failing) != 1 || res.Failing[0].Reason != "disk not encrypted" || sees(server, "z-laptop") {
		t.Fatalf("passing report during the hold-down: HTTP %d %+v", code, res)
	}
	postureHoldDown = 0
	report.DiskEncryption = ptr(false)

	// Passing: in again, audited once.
	report.DiskEncryption = ptr(true)
	if code := laptop.do(t, "POST", api.PathPosture, report, &res); code != http.StatusOK || len(res.Failing) != 0 {
		t.Fatalf("passing report: HTTP %d %+v", code, res)
	}
	if !sees(laptop, "z-server") || !sees(server, "z-laptop") || len(netmap(laptop).Self.PostureFailing) != 0 || !relays("z-laptop", "z-server") {
		t.Fatal("a passing device is left out")
	}
	if logs.countAll("action=posture_passed", "z-laptop", "check=enc", "result=ok") != 1 {
		t.Error("pass not audited")
	}
	if code := laptop.do(t, "POST", api.PathPosture, report, nil); code != http.StatusOK {
		t.Fatal(code)
	}
	if logs.countAll("action=posture_passed") != 1 {
		t.Error("an unchanged result was audited again")
	}

	// What admins see: the report and every check.
	var peers []api.PeerInfo
	admin.do(t, "GET", api.PathPeers, nil, &peers)
	for _, p := range peers {
		switch p.Hostname {
		case "z-laptop":
			if p.Posture == nil || p.Posture.OSVersion != "6.8.0-1-generic" || p.PostureReportedAt == "" || len(p.PostureChecks) != 1 ||
				!p.PostureChecks[0].Passed || !p.PostureChecks[0].Required {
				b, _ := json.Marshal(p)
				t.Errorf("laptop as admins see it: %s", b)
			}
		case "z-phone":
			if p.Posture != nil || len(p.PostureChecks) != 1 || p.PostureChecks[0].Passed || p.PostureChecks[0].Required {
				t.Errorf("phone as admins see it: %+v", p)
			}
		}
	}

	// An old system fails; so does a report that got too old.
	report.OSVersion = "5.15.0"
	laptop.do(t, "POST", api.PathPosture, report, &res)
	if len(res.Failing) != 1 || res.Failing[0].Reason != "Linux 5.15.0 is older than 6.1" || sees(server, "z-laptop") {
		t.Fatalf("old kernel: %+v", res)
	}
	report.OSVersion = "6.1.0"
	laptop.do(t, "POST", api.PathPosture, report, &res)
	if len(res.Failing) != 0 || !sees(server, "z-laptop") {
		t.Fatalf("kernel 6.1.0: %+v", res)
	}
	facts, _ := json.Marshal(report)
	if err := st.SetPostureReport(ctx, laptopPeer.ID, facts, time.Now().Add(-31*time.Minute), 0); err != nil {
		t.Fatal(err)
	}
	v, _ := st.Version(ctx)
	if _, err := srv.evaluatePosture(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if v2, _ := st.Version(ctx); v2 == v {
		t.Fatal("a stale report did not change the version")
	}
	srv.checkVersion(ctx)
	if sees(server, "z-laptop") || netmap(laptop).Self.PostureFailing[0].Reason != "no report in 30m" {
		t.Fatal("a stale report passes")
	}
	// Audited apart from failing facts (a laptop asleep), and not as a denial.
	if logs.countAll("action=posture_stale", "z-laptop", "reason=no report in 30m", "result=ok") != 1 ||
		logs.countAll("action=posture_failed", "reason=no report") != 0 {
		t.Error("stale report not audited as such")
	}

	// Another policy connecting the same devices without the checks makes them moot: operators
	// cannot add one, admins are warned (also of the reverse order, policies work both ways).
	if code := op.do(t, "POST", api.PathPolicies, api.Policy{Source: "servers", Destination: "laptops"}, nil); code != http.StatusForbidden {
		t.Fatalf("operator bypasses a policy's checks: HTTP %d", code)
	}
	if code := op.do(t, "POST", api.PathPolicies, api.Policy{Source: "*", Destination: "servers"}, nil); code != http.StatusForbidden {
		t.Fatalf("operator bypasses a policy's checks with *: HTTP %d", code)
	}
	if logs.countAll("action=policy_added", "z-op", fmt.Sprintf("would bypass policy %d", pol.ID), "result=denied") != 2 {
		t.Error("refused bypass not audited")
	}
	var reverse api.Policy
	if code := admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "servers", Destination: "laptops"}, &reverse); code != http.StatusCreated ||
		len(reverse.Warnings) != 1 || !strings.Contains(reverse.Warnings[0], fmt.Sprintf("which policy %d requires", pol.ID)) {
		t.Fatalf("admin adds the reverse policy: HTTP %d %+v", code, reverse)
	}
	if !sees(server, "z-laptop") {
		t.Fatal("the reverse policy does not let the laptop through (the warning is wrong)")
	}
	if code := admin.do(t, "DELETE", fmt.Sprintf("%s/%d", api.PathPolicies, reverse.ID), nil, nil); code != http.StatusNoContent {
		t.Fatal(code)
	}
	if sees(server, "z-laptop") {
		t.Fatal("the laptop is still let through")
	}

	// Changing and removing: admins only; a check in use cannot be deleted.
	polPath := fmt.Sprintf("%s/%d", api.PathPolicies, pol.ID)
	if code := op.do(t, "PATCH", polPath, api.UpdatePolicyRequest{}, nil); code != http.StatusForbidden {
		t.Errorf("operator changes a policy's checks: HTTP %d", code)
	}
	if code := op.do(t, "DELETE", polPath, nil, nil); code != http.StatusForbidden {
		t.Errorf("operator removes a policy with checks: HTTP %d", code)
	}
	if code := op.do(t, "DELETE", api.PathPostureChecks+"/enc", nil, nil); code != http.StatusForbidden {
		t.Errorf("operator deletes a check: HTTP %d", code)
	}
	if code := admin.do(t, "DELETE", api.PathPostureChecks+"/enc", nil, nil); code != http.StatusConflict {
		t.Errorf("deleting a check in use: HTTP %d", code)
	}
	var changed api.Policy
	if code := admin.do(t, "PATCH", polPath, api.UpdatePolicyRequest{Posture: []string{}}, &changed); code != http.StatusOK ||
		changed.ID != pol.ID || len(changed.Posture) != 0 {
		t.Fatalf("remove the policy's checks: HTTP %d %+v", code, changed)
	}
	if !sees(server, "z-laptop") || len(netmap(laptop).Self.PostureFailing) != 0 {
		t.Fatal("a policy without checks still leaves the laptop out")
	}
	if logs.countAll("action=policy_posture", fmt.Sprintf("policy %d device:laptops <-> device:servers (was enc)", pol.ID)) != 1 {
		t.Error("policy change not audited")
	}
	if code := admin.do(t, "DELETE", api.PathPostureChecks+"/enc", nil, nil); code != http.StatusNoContent {
		t.Errorf("delete check: HTTP %d", code)
	}
	if logs.countAll("action=posture_check_deleted", "check enc") != 1 {
		t.Error("check deletion not audited")
	}
}

func TestBypasses(t *testing.T) {
	pol := func(src, dst string, checks ...string) store.Policy {
		return store.Policy{ID: 1, Source: src, Destination: dst, Posture: checks}
	}
	guarded := pol("laptops", "servers", "enc")
	for _, c := range []struct {
		name string
		o    store.Policy
		want bool
	}{
		{"itself", pol("laptops", "servers", "enc"), false},
		{"reverse order, no checks", pol("servers", "laptops"), true},
		{"reverse order, the same checks (of the servers)", pol("servers", "laptops", "enc"), true},
		{"everyone to servers", pol("*", "servers"), true},
		{"laptops to everyone", pol("laptops", "*"), true},
		{"everyone to everyone, the same checks", pol("*", "*", "enc"), false},
		{"other groups", pol("phones", "servers"), false},
		{"laptops among themselves", pol("laptops", "laptops"), false},
		{"laptops to servers via a wider check set", pol("laptops", "*", "enc", "fw"), false},
		{"laptops to everyone with another check", pol("laptops", "*", "fw"), true},
	} {
		if got := bypasses(c.o, guarded); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if bypasses(pol("laptops", "servers"), pol("servers", "laptops")) {
		t.Error("a policy without checks has nothing to bypass")
	}
}

// What a peer may open on a device follows the policies' direction and ports.
func TestAcceptFrom(t *testing.T) {
	laptop := store.Peer{ID: 1, Approved: true, Groups: []string{"staff"}}
	server := store.Peer{ID: 2, Approved: true, Groups: []string{"servers"}}
	db := store.Peer{ID: 3, Approved: true, Groups: []string{"db"}}
	policies := []store.Policy{
		{ID: 1, Source: "staff", Destination: "servers", OneWay: true, Ports: []string{"tcp/22", "tcp/443"}},
		{ID: 2, Source: "servers", Destination: "db", Ports: []string{"tcp/5432"}},
		{ID: 3, Source: "staff", Destination: "servers", OneWay: true, Ports: []string{"icmp"}},
	}
	cases := []struct {
		name       string
		self, from store.Peer
		want       []string
	}{
		{"staff opens on servers", server, laptop, []string{"icmp", "tcp/22", "tcp/443"}},
		{"servers only answer staff", laptop, server, nil},
		{"two-way: servers open on db", db, server, []string{"tcp/5432"}},
		{"two-way: db opens on servers", server, db, []string{"tcp/5432"}},
		{"no policy", db, laptop, nil},
	}
	for _, c := range cases {
		if got := acceptFrom(c.self, c.from, policies, nil); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	all := append(policies, store.Policy{ID: 4, Source: "staff", Destination: "servers"})
	if got := acceptFrom(server, laptop, all, nil); !slices.Equal(got, []string{"all"}) {
		t.Errorf("a policy without ports allows everything: %v", got)
	}
	if got := acceptFrom(laptop, server, all, nil); !slices.Equal(got, []string{"all"}) {
		t.Errorf("a two-way policy without ports lets servers open everything on staff too: %v", got)
	}
}
