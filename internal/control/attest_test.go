package control

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/attest/attesttest"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
	"entowire.com/ento/internal/token"
)

func TestEvaluateAndroid(t *testing.T) {
	yes := ptr(true)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	check := store.PostureCheck{Name: "phones", SecureBoot: true, MaxPatchAge: map[string]int{"android": 90}, MaxAge: 30 * time.Minute}
	attested := &api.Attested{SecurityLevel: "tee", BootState: "verified", Locked: true}
	for _, c := range []struct {
		name  string
		facts api.Posture
		want  string
	}{
		{"passes", api.Posture{OS: "android", SecureBoot: yes, Attested: attested, PatchLevel: "2026-08"}, ""},
		{"no attestation", api.Posture{OS: "android", PatchLevel: "2026-09-05"}, "verified boot not attested"},
		{"attestation that does not count", api.Posture{OS: "android", PatchLevel: "2026-09-05",
			Attested: &api.Attested{Error: "made for another device key"}}, "verified boot not attested: made for another device key"},
		{"unlocked", api.Posture{OS: "android", SecureBoot: ptr(false), PatchLevel: "2026-09",
			Attested: &api.Attested{SecurityLevel: "tee", BootState: "unverified"}}, "verified boot: bootloader unlocked"},
		{"custom system", api.Posture{OS: "android", SecureBoot: ptr(false), PatchLevel: "2026-09",
			Attested: &api.Attested{SecurityLevel: "tee", BootState: "self-signed", Locked: true}}, "verified boot: a system its maker did not sign"},
		{"old patch", api.Posture{OS: "android", SecureBoot: yes, Attested: attested, PatchLevel: "2026-07"},
			"security patch 2026-07 is older than 90d"},
		{"patch unknown", api.Posture{OS: "android", SecureBoot: yes, Attested: attested}, "security patch level unknown"},
		// Other systems: secure boot as before, patch age not limited.
		{"linux", api.Posture{OS: "linux", SecureBoot: yes}, ""},
		{"linux without secure boot", api.Posture{OS: "linux"}, "secure boot unknown"},
	} {
		if got := evaluateCheck(check, &c.facts, now, now); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if got := oldestPatch(api.Attested{PatchLevel: "2026-09", VendorPatchLevel: "2026-05-05", BootPatchLevel: "2026-09-05"}); got != "2026-05-05" {
		t.Errorf("oldest patch: %q", got)
	}
	if got := oldestPatch(api.Attested{}); got != "" {
		t.Errorf("no patch: %q", got)
	}
}

// A phone's verified boot counts only as its secure hardware attests it, verified by the control
// node; the attested patch level replaces the one the phone reports.
func TestAttestedPosture(t *testing.T) {
	savedGap, savedHold, savedRoots := postureReportGap, postureHoldDown, attestRoots
	hw := attesttest.New(t)
	postureReportGap, postureHoldDown, attestRoots = 0, 0, hw.Roots()
	defer func() { postureReportGap, postureHoldDown, attestRoots = savedGap, savedHold, savedRoots }()
	var fetched atomic.Int32
	revocations := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetched.Add(1)
		w.Write([]byte(`{"entries": {"dead": {"status": "REVOKED", "reason": "KEY_COMPROMISE"}}}`))
	}))
	defer revocations.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	space, _ := ipam.New(netip.MustParsePrefix("100.73.0.0/16"))
	st := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	logs := &logLines{t: t}
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port, Endpoint: fmt.Sprintf("127.0.0.1:%d", port),
		Space: space, Store: st, Logf: logs.logf, AttestationRevocations: revocations.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	admin := adminOf(t, ctx, srv, st, "admin", "admins")
	tok, _, err := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"phones"}})
	if err != nil {
		t.Fatal(err)
	}
	srv.checkVersion(ctx)
	phone, _ := enroll(t, tok, "phone")
	device := [32]byte(phone.key.PublicKey())

	for _, bad := range []api.PostureCheck{{Name: "x", MaxPatchAgeDays: map[string]int{"linux": 90}},
		{Name: "x", MaxPatchAgeDays: map[string]int{"android": 10}}} {
		if code := admin.do(t, "POST", api.PathPostureChecks, bad, nil); code != http.StatusBadRequest {
			t.Errorf("invalid check %+v: HTTP %d", bad, code)
		}
	}
	var created api.PostureCheck
	check := api.PostureCheck{Name: "phones", SecureBoot: true, MaxPatchAgeDays: map[string]int{"android": 90}}
	if code := admin.do(t, "POST", api.PathPostureChecks, check, &created); code != http.StatusCreated || created.MaxPatchAgeDays["android"] != 90 {
		t.Fatalf("add check: HTTP %d %+v", code, created)
	}
	if logs.countAll("action=posture_check_added", "check phones", "secure_boot=true", "max_patch_age=android=90d") != 1 {
		t.Error("check not audited")
	}
	if code := admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "phones", Destination: "servers", Posture: []string{"phones"}}, nil); code != http.StatusCreated {
		t.Fatalf("policy: HTTP %d", code)
	}

	month := func(ago int) (string, int) {
		d := time.Now().AddDate(0, -ago, 0)
		return d.Format("2006-01-02"), d.Year()*100 + int(d.Month())
	}
	recent, recentMonth := month(1)
	_, oldMonth := month(6)
	report := func(p api.Posture) api.PostureResult {
		t.Helper()
		p.Format, p.OS, p.OSVersion = 1, "android", "16"
		var res api.PostureResult
		if code := phone.do(t, "POST", api.PathPosture, p, &res); code != http.StatusOK {
			t.Fatalf("report: HTTP %d", code)
		}
		return res
	}
	reasons := func(res api.PostureResult) string {
		var out []string
		for _, f := range res.Failing {
			out = append(out, f.Reason)
		}
		return strings.Join(out, "; ")
	}

	// Without an attestation, what the phone says of its boot does not count.
	res := report(api.Posture{SecureBoot: ptr(true), PatchLevel: recent})
	if reasons(res) != "verified boot not attested" || res.Attested != nil {
		t.Fatalf("no attestation: %+v", res)
	}
	if fetched.Load() != 0 {
		t.Fatal("the revocation list was fetched before any attestation arrived")
	}

	// An attestation of this phone, in order: passes, and the control node says what it found.
	spec := attesttest.Good(device)
	spec.Patch = recentMonth
	a, _ := hw.Attest(t, device, spec, time.Now())
	res = report(api.Posture{PatchLevel: recent, Attestation: a})
	if reasons(res) != "" || res.Attested == nil || res.Attested.BootState != "verified" || !res.Attested.Locked {
		t.Fatalf("attested phone: %+v %+v", res, res.Attested)
	}
	if fetched.Load() != 1 {
		t.Errorf("revocation list fetched %d times", fetched.Load())
	}
	reports, _ := st.PostureReports(ctx)
	if len(reports) != 1 || strings.Contains(string(reports[0].Facts), "attestation") || strings.Contains(string(reports[0].Facts), "chain") ||
		!strings.Contains(string(reports[0].Facts), `"secure_boot":true`) {
		t.Errorf("stored facts: %s", reports[0].Facts)
	}

	// The hardware says the bootloader is unlocked: the phone fails, whatever it says itself.
	spec.State, spec.Locked = 2, false
	a, _ = hw.Attest(t, device, spec, time.Now())
	if res = report(api.Posture{SecureBoot: ptr(true), PatchLevel: recent, Attestation: a}); reasons(res) != "verified boot: bootloader unlocked" {
		t.Fatalf("unlocked phone: %+v", res)
	}

	// The attested patch level counts, not the one the phone reports.
	spec = attesttest.Good(device)
	spec.Patch = oldMonth
	a, _ = hw.Attest(t, device, spec, time.Now())
	res = report(api.Posture{PatchLevel: recent, Attestation: a})
	if !strings.HasPrefix(reasons(res), "security patch ") || !strings.HasSuffix(reasons(res), "is older than 90d") {
		t.Fatalf("old attested patch: %+v", res)
	}

	// Another device's attestation (a copy of another phone's) does not count for this one.
	other := [32]byte{9}
	a, _ = hw.Attest(t, other, attesttest.Good(other), time.Now())
	if res = report(api.Posture{PatchLevel: recent, Attestation: a}); reasons(res) != "verified boot not attested: made for another device key" {
		t.Fatalf("another device's attestation: %+v", res)
	}

	// Audited when the outcome changes, with the reason.
	if logs.countAll("action=posture_failed", "check=phones", "reason=verified boot: bootloader unlocked") != 1 {
		t.Error("failure not audited")
	}
}

// Words come with a join code and its QR code for phones: the domain the admin names (the admin
// page: its own), else the control nodes' record domain.
func TestTokenJoinCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	space, _ := ipam.New(netip.MustParsePrefix("100.74.0.0/16"))
	st := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port, Endpoint: fmt.Sprintf("127.0.0.1:%d", port),
		Space: space, Store: st, Logf: t.Logf, RecordDomain: "net.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	admin := adminOf(t, ctx, srv, st, "admin", "admins")
	rec, err := NetworkRecord(ctx, st, space.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		domain, want string
	}{{"Example.COM", "example.com"}, {"", "net.example.org"}} {
		var res api.CreateTokenResponse
		if code := admin.do(t, "POST", api.PathTokens, api.CreateTokenRequest{TTLSeconds: 3600, Words: true, QRDomain: c.domain}, &res); code != http.StatusCreated {
			t.Fatalf("words: HTTP %d", code)
		}
		j, err := token.ParseJoinCode(res.JoinCode)
		if err != nil || j.Domain != c.want || j.Fingerprint != rec.Fingerprint() || strings.Join(j.Words, " ") != res.Words {
			t.Errorf("join code %q: %+v %v", res.JoinCode, j, err)
		}
		if !strings.HasPrefix(res.QRSVG, "<svg ") {
			t.Errorf("QR code %q", res.QRSVG)
		}
	}
	// A domain only with words, and a domain it must be.
	for _, bad := range []api.CreateTokenRequest{{TTLSeconds: 3600, QRDomain: "example.com"}, {TTLSeconds: 3600, Words: true, QRDomain: "not a domain"}} {
		if code := admin.do(t, "POST", api.PathTokens, bad, nil); code != http.StatusBadRequest {
			t.Errorf("%+v: HTTP %d", bad, code)
		}
	}
	// Tokens never come as QR codes.
	var res api.CreateTokenResponse
	if code := admin.do(t, "POST", api.PathTokens, api.CreateTokenRequest{TTLSeconds: 3600}, &res); code != http.StatusCreated || res.JoinCode != "" || res.QRSVG != "" {
		t.Errorf("token: HTTP %d %+v", code, res)
	}
}
