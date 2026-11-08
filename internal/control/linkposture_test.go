package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

// TestLinkPosture: a link that requires posture checks gives credentials (and, joining, the linked
// network's token) only to devices that pass them now, tells the others why, and audits each change
// once. With the memory store, and with PostgreSQL when ENTO_TEST_POSTGRES names a database the
// test may wipe.
func TestLinkPosture(t *testing.T) {
	space, _ := ipam.New(netip.MustParsePrefix("100.73.0.0/16"))
	t.Run("memory", func(t *testing.T) { testLinkPosture(t, space, store.NewMemory(space)) })
	dsn := os.Getenv("ENTO_TEST_POSTGRES")
	if dsn == "" {
		return
	}
	t.Run("postgres", func(t *testing.T) {
		ctx := context.Background()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		_, err = conn.Exec(ctx, `DROP TABLE IF EXISTS ento_settings, ento_state, ento_control_nodes, ento_peers, ento_tokens,
			ento_policies, ento_authorities, ento_links, ento_link_keys, ento_admin_sessions, ento_sso_tokens, ento_posture,
			ento_posture_checks, ento_link_posture, ento_approvals, ento_checkins, ento_hwkeys, ento_routes, ento_dns_records, ento_dns_forwards,
			ento_ui_sessions, ento_signin_codes, ento_signin_use, ento_update_policy, ento_release_offers CASCADE`)
		conn.Close(ctx)
		if err != nil {
			t.Fatal(err)
		}
		st, err := store.OpenPostgres(ctx, dsn, space)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		testLinkPosture(t, space, st)
	})
}

func testLinkPosture(t *testing.T, space ipam.Space, st store.Store) {
	savedGap, savedHold := postureReportGap, postureHoldDown
	postureReportGap, postureHoldDown = 0, 0
	defer func() { postureReportGap, postureHoldDown = savedGap, savedHold }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	logs := &logLines{t: t}
	home, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port,
		Endpoint: fmt.Sprintf("127.0.0.1:%d", port), Space: space, Store: st, Logf: logs.logf})
	if err != nil {
		t.Fatal(err)
	}
	defer home.Close()
	acme, acmeStore := startTestNetwork(t, ctx, "100.74.0.0/16")
	acmeAdmin := adminOf(t, ctx, acme, acmeStore, "acme-admin", "admins")
	admin := adminOf(t, ctx, home, st, "admin", "admins")
	device := func(host string, groups ...string) (*testClient, store.Peer) {
		tok, _, err := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: groups})
		if err != nil {
			t.Fatal(err)
		}
		home.checkVersion(ctx)
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
	signInRoles(t, st)
	laptop, laptopPeer := device("laptop", "operators")
	if code := admin.do(t, "POST", api.PathPostureChecks, api.PostureCheck{Name: "enc", DiskEncryption: true}, nil); code != http.StatusCreated {
		t.Fatalf("add check: HTTP %d", code)
	}

	// Creating a link with checks: admins only, and the checks must exist.
	create := api.CreateLinkRequest{Name: "acme", Groups: []string{"operators"}, Grant: []string{"operators"}, TTLSeconds: 3600,
		Posture: []string{"enc"}}
	if code := op.do(t, "POST", api.PathAdminLinks, create, nil); code != http.StatusForbidden {
		t.Fatalf("operator creates a link: HTTP %d", code)
	}
	bad := create
	bad.Posture = []string{"enc", "nope"}
	var e api.Error
	if code := admin.do(t, "POST", api.PathAdminLinks, bad, &e); code != http.StatusBadRequest || e.Error != `no posture check named "nope"` {
		t.Fatalf("link requiring a check that does not exist: HTTP %d %+v", code, e)
	}
	bad.Posture = []string{"enc check=forged"}
	if code := admin.do(t, "POST", api.PathAdminLinks, bad, nil); code != http.StatusBadRequest || logs.countAll("forged") != 0 {
		t.Fatalf("invalid check name: HTTP %d", code)
	}
	var link api.LinkInfo
	if code := admin.do(t, "POST", api.PathAdminLinks, create, &link); code != http.StatusCreated || !slices.Equal(link.Posture, []string{"enc"}) {
		t.Fatalf("create link: HTTP %d %+v", code, link)
	}
	if logs.countAll("action=link_created", "link acme groups=operators grant=operators ttl=1h0m0s posture=enc", "result=ok") != 1 {
		t.Error("link's checks not audited")
	}
	plain := create
	plain.Name, plain.Posture = "plain", nil
	if code := admin.do(t, "POST", api.PathAdminLinks, plain, nil); code != http.StatusCreated {
		t.Fatalf("create plain link: HTTP %d", code)
	}
	var auth api.CreateAuthorityResponse
	if code := acmeAdmin.do(t, "POST", api.PathAuthorities, api.CreateAuthorityRequest{Name: "home", PublicKey: link.PublicKey,
		Groups: []string{"operators"}, MaxTTLSeconds: 1800}, &auth); code != http.StatusCreated {
		t.Fatalf("create authority: HTTP %d", code)
	}
	for _, name := range []string{"acme", "plain"} {
		if code := admin.do(t, "PUT", api.PathAdminLinks+"/"+name+"/token", api.SetLinkTokenRequest{Token: auth.Token}, nil); code != http.StatusNoContent {
			t.Fatalf("import token: HTTP %d", code)
		}
	}
	var links []api.LinkInfo
	if code := op.do(t, "GET", api.PathAdminLinks, nil, &links); code != http.StatusOK || len(links) != 2 ||
		!slices.Equal(links[0].Posture, []string{"enc"}) || links[1].Posture != nil {
		t.Fatalf("operator lists links: HTTP %d %+v", code, links)
	}

	devKey, _ := wgtypes.GeneratePrivateKey()
	join := api.LinkCredentialRequest{PublicKey: devKey.PublicKey().String(), Join: true}
	ask := func(req api.LinkCredentialRequest, link string, want int, reason string) api.LinkCredentialResponse {
		t.Helper()
		var e api.Error
		var res api.LinkCredentialResponse
		var out any = &res
		if want != http.StatusOK {
			out = &e
		}
		code := laptop.do(t, "POST", api.PathLinks+"/"+link+"/credential", req, out)
		if code != want {
			t.Fatalf("credential for %s: HTTP %d, want %d (%+v)", link, code, want, e)
		}
		if want == http.StatusOK && (res.Credential == "" || req.Join && res.Token == "") {
			t.Fatalf("credential for %s: %+v", link, res)
		}
		if want != http.StatusOK && (res.Credential != "" || res.Token != "") {
			t.Fatalf("refused, yet answered with a credential: %+v", res)
		}
		if reason != "" && (len(e.PostureFailing) != 1 || e.PostureFailing[0] != (api.PostureFailure{Check: "enc", Reason: reason}) ||
			e.Error != fmt.Sprintf("this device fails the posture checks link %s requires: enc (%s)", link, reason)) {
			t.Fatalf("refusal for %s: %+v, want reason %q", link, e, reason)
		}
		return res
	}
	credential := func(link string, want int, reason string) { t.Helper(); ask(join, link, want, reason) }

	// No report: refused, with the reason, audited once however often the device asks, as stale (no
	// failing fact: a device asking before its first report). A link without checks is not affected.
	credential("acme", http.StatusForbidden, "no report")
	credential("acme", http.StatusForbidden, "no report")
	if logs.countAll("action=link_posture_stale", "z-laptop", "link=acme check=enc reason=no report", "result=ok") != 1 ||
		logs.countAll("action=link_posture_failed") != 0 {
		t.Error("refusal without a report not audited once as stale")
	}
	if logs.countAll("action=link_credential", "z-laptop", "link acme") != 0 {
		t.Error("a refused device got a credential line")
	}
	if k, err := st.LinkKey(ctx, "acme", laptopPeer.ID); err == nil {
		t.Fatalf("a refused device's key was recorded: %s", k)
	}
	credential("plain", http.StatusOK, "")

	// Failing facts: refused with them, audited as a failure (a new outcome), once.
	report := api.Posture{Format: 1, OS: "linux", OSVersion: "6.8.0", DiskEncryption: ptr(false)}
	if code := laptop.do(t, "POST", api.PathPosture, report, nil); code != http.StatusOK {
		t.Fatalf("report: HTTP %d", code)
	}
	credential("acme", http.StatusForbidden, "disk not encrypted")
	credential("acme", http.StatusForbidden, "disk not encrypted")
	if logs.countAll("action=link_posture_failed", "z-laptop", "link=acme check=enc reason=disk not encrypted", "result=denied") != 1 {
		t.Error("the failing fact after a missing report not audited once")
	}

	// Passing: a credential and the token, audited once.
	report.DiskEncryption = ptr(true)
	laptop.do(t, "POST", api.PathPosture, report, nil)
	credential("acme", http.StatusOK, "")
	credential("acme", http.StatusOK, "")
	if logs.countAll("action=link_posture_passed", "z-laptop", "link=acme check=enc", "result=ok") != 1 {
		t.Error("pass not audited once")
	}
	held, err := st.LinkKey(ctx, "acme", laptopPeer.ID)
	if err != nil || held != devKey.PublicKey() {
		t.Fatalf("key held after joining: %q %v", held, err)
	}

	// Renewals are refused the same way once the device fails (the credential it holds just
	// expires), and its key stays the one it holds.
	renew := api.LinkCredentialRequest{PublicKey: devKey.PublicKey().String()}
	ask(renew, "acme", http.StatusOK, "")
	report.DiskEncryption = ptr(false)
	laptop.do(t, "POST", api.PathPosture, report, nil)
	ask(renew, "acme", http.StatusForbidden, "disk not encrypted")
	ask(renew, "acme", http.StatusForbidden, "disk not encrypted")
	if logs.countAll("action=link_posture_failed", "z-laptop", "link=acme check=enc reason=disk not encrypted") != 2 {
		t.Error("renewal refusal not audited once")
	}
	if k, err := st.LinkKey(ctx, "acme", laptopPeer.ID); err != nil || k != held {
		t.Fatalf("key after a refused renewal: %q %v", k, err)
	}
	report.DiskEncryption = ptr(true)
	laptop.do(t, "POST", api.PathPosture, report, nil)
	if res := ask(renew, "acme", http.StatusOK, ""); res.Token != "" {
		t.Fatalf("a renewal got the linked network's token: %+v", res)
	}
	if logs.countAll("action=link_posture_passed", "z-laptop", "link=acme check=enc") != 2 {
		t.Error("renewal pass not audited")
	}

	// A report that got too old fails again (fail closed), audited again.
	facts, _ := json.Marshal(report)
	if err := st.SetPostureReport(ctx, laptopPeer.ID, facts, time.Now().Add(-31*time.Minute), 0); err != nil {
		t.Fatal(err)
	}
	credential("acme", http.StatusForbidden, "no report in 30m")
	if logs.countAll("action=link_posture_stale", "z-laptop", "link=acme check=enc reason=no report in 30m", "result=ok") != 1 {
		t.Error("stale report not audited")
	}

	// The same evaluation as policies: a device that just started failing a check a policy requires
	// of it keeps failing it for the hold-down, for the link too.
	var pol api.Policy
	if code := admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "operators", Destination: "servers", Posture: []string{"enc"}}, &pol); code != http.StatusCreated {
		t.Fatalf("policy: HTTP %d", code)
	}
	report.DiskEncryption = ptr(false)
	laptop.do(t, "POST", api.PathPosture, report, nil)
	postureHoldDown = time.Hour
	report.DiskEncryption = ptr(true)
	laptop.do(t, "POST", api.PathPosture, report, nil)
	credential("acme", http.StatusForbidden, "disk not encrypted")
	postureHoldDown = 0
	if _, err := home.evaluatePosture(ctx, 0); err != nil {
		t.Fatal(err)
	}
	credential("acme", http.StatusOK, "")

	// A check a link requires cannot be deleted.
	if code := admin.do(t, "DELETE", fmt.Sprintf("%s/%d", api.PathPolicies, pol.ID), nil, nil); code != http.StatusNoContent {
		t.Fatalf("remove policy: HTTP %d", code)
	}
	if code := admin.do(t, "DELETE", api.PathPostureChecks+"/enc", nil, &e); code != http.StatusConflict ||
		e.Error != "posture check enc is required by link acme: take it off there first" {
		t.Fatalf("deleting a check a link requires: HTTP %d %+v", code, e)
	}

	// Changing a link's checks: admins only; the checks must exist; none lets every device of its
	// groups through again.
	path := api.PathAdminLinks + "/acme"
	none := []string{}
	if code := op.do(t, "PATCH", path, api.UpdateLinkRequest{Posture: &none}, nil); code != http.StatusForbidden {
		t.Fatalf("operator changes a link's checks: HTTP %d", code)
	}
	if code := admin.do(t, "PATCH", path, api.UpdateLinkRequest{}, nil); code != http.StatusBadRequest {
		t.Fatalf("change without checks: HTTP %d", code)
	}
	// What `ento admin link create --posture` asks first to tell 0.14 from older control nodes (405).
	if code := admin.do(t, "PATCH", api.PathAdminLinks+"/probe", api.UpdateLinkRequest{}, nil); code != http.StatusBadRequest {
		t.Fatalf("probe: HTTP %d", code)
	}
	if code := admin.do(t, "PATCH", path, api.UpdateLinkRequest{Posture: &[]string{"nope"}}, nil); code != http.StatusBadRequest {
		t.Fatalf("change to a check that does not exist: HTTP %d", code)
	}
	if code := admin.do(t, "PATCH", api.PathAdminLinks+"/nope", api.UpdateLinkRequest{Posture: &none}, nil); code != http.StatusNotFound {
		t.Fatalf("change of a link that does not exist: HTTP %d", code)
	}
	if err := st.SetPostureReport(ctx, laptopPeer.ID, facts, time.Now().Add(-31*time.Minute), 0); err != nil {
		t.Fatal(err)
	}
	credential("acme", http.StatusForbidden, "no report in 30m")
	var changed api.LinkInfo
	if code := admin.do(t, "PATCH", path, api.UpdateLinkRequest{Posture: &none}, &changed); code != http.StatusOK || changed.Posture != nil {
		t.Fatalf("remove the link's checks: HTTP %d %+v", code, changed)
	}
	if logs.countAll("action=link_posture", "link acme posture=none (was enc)", "result=ok") != 1 {
		t.Error("change not audited")
	}
	credential("acme", http.StatusOK, "")
	if code := admin.do(t, "PATCH", path, api.UpdateLinkRequest{Posture: &[]string{"enc"}}, &changed); code != http.StatusOK ||
		!slices.Equal(changed.Posture, []string{"enc"}) {
		t.Fatalf("require the check again: HTTP %d %+v", code, changed)
	}
	// The results recorded under the old checks are forgotten: the failure is audited anew.
	credential("acme", http.StatusForbidden, "no report in 30m")
	if logs.countAll("action=link_posture_stale", "z-laptop", "link=acme check=enc reason=no report in 30m") != 3 {
		t.Error("failure under the new checks not audited")
	}
	if logs.countAll("action=link_posture_failed", "z-laptop") != 3 {
		t.Errorf("failures over facts: %d lines, want 3", logs.countAll("action=link_posture_failed", "z-laptop"))
	}

	// A second check that starts failing is audited on its own, the first one not again.
	if code := admin.do(t, "POST", api.PathPostureChecks, api.PostureCheck{Name: "fw", Firewall: true}, nil); code != http.StatusCreated {
		t.Fatalf("add check: HTTP %d", code)
	}
	if code := admin.do(t, "PATCH", path, api.UpdateLinkRequest{Posture: &[]string{"enc", "fw"}}, nil); code != http.StatusOK {
		t.Fatalf("require two checks: HTTP %d", code)
	}
	report.DiskEncryption, report.Firewall = ptr(false), ptr(true)
	laptop.do(t, "POST", api.PathPosture, report, nil)
	credential("acme", http.StatusForbidden, "disk not encrypted")
	report.Firewall = ptr(false)
	laptop.do(t, "POST", api.PathPosture, report, nil)
	var two api.Error
	if code := laptop.do(t, "POST", api.PathLinks+"/acme/credential", join, &two); code != http.StatusForbidden || len(two.PostureFailing) != 2 {
		t.Fatalf("two failing checks: HTTP %d %+v", code, two)
	}
	if logs.countAll("action=link_posture_failed", "z-laptop", "check=enc") != 4 ||
		logs.countAll("action=link_posture_failed", "z-laptop", "link=acme check=fw reason=firewall off") != 1 {
		t.Errorf("second failing check: enc %d, fw %d", logs.countAll("action=link_posture_failed", "z-laptop", "check=enc"),
			logs.countAll("action=link_posture_failed", "z-laptop", "check=fw"))
	}
	if logs.countAll("action=link_posture_failed", "z-op") != 0 || logs.countAll("action=link_posture_passed", "z-op") != 0 {
		t.Error("a device that never asked was audited")
	}
}
