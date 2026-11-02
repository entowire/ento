package agent

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"entowire.com/ento/internal/api"
)

func tri(b *bool) string {
	if b == nil {
		return "unknown"
	}
	if *b {
		return "on"
	}
	return "off"
}

func TestPostureParsers(t *testing.T) {
	cases := []struct {
		name string
		got  *bool
		want string
	}{
		{"fdesetup on", parseFdesetup("FileVault is On.\n"), "on"},
		{"fdesetup encrypting", parseFdesetup("FileVault is On.\nEncryption in progress: Percent completed = 34.2\n"), "on"},
		{"fdesetup off", parseFdesetup("FileVault is Off.\n"), "off"},
		{"fdesetup error", parseFdesetup("Error: unable to determine status\n"), "unknown"},
		{"socketfilterfw on", parseSocketFilterFW("Firewall is enabled. (State = 1)\n"), "on"},
		{"socketfilterfw block all", parseSocketFilterFW("Firewall is blocking all non-essential incoming connections. (State = 2)\n"), "on"},
		{"socketfilterfw off", parseSocketFilterFW("Firewall is disabled. (State = 0)\n"), "off"},
		{"socketfilterfw garbage", parseSocketFilterFW("socketfilterfw: permission denied\n"), "unknown"},
		{"bitlocker on", parseBitLocker("C:=1\r\nD:=0\r\n=0\r\n", "C:"), "on"},
		{"bitlocker other drive", parseBitLocker("C:=0\r\nD:=1\r\n", "D:"), "on"},
		{"bitlocker off", parseBitLocker("C:=0\r\n", "C:"), "off"},
		{"bitlocker locked", parseBitLocker("C:=2\r\n", "C:"), "unknown"},
		{"bitlocker drive missing", parseBitLocker("D:=1\r\n", "C:"), "unknown"},
		{"manage-bde on", parseManageBDE(manageBDEOn), "on"},
		{"manage-bde off", parseManageBDE("    Protection Status:    Protection Off\n"), "off"},
		{"manage-bde other language", parseManageBDE("    Schutzstatus:    Der Schutz ist aktiviert.\n"), "unknown"},
		{"iptables policy drop", parseIptablesInput("-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n"), "on"},
		{"iptables reject rule", parseIptablesInput("-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j REJECT --reject-with icmp-host-prohibited\n"), "on"},
		{"iptables open", parseIptablesInput("-P INPUT ACCEPT\n"), "off"},
		{"iptables last rule drops", parseIptablesInput("-P INPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n-A INPUT -j DROP\n"), "on"},
		{"iptables drops invalid only", parseIptablesInput("-P INPUT ACCEPT\n-A INPUT -m conntrack --ctstate INVALID -j DROP\n"), "off"},
		{"iptables fail2ban only", parseIptablesInput("-P INPUT ACCEPT\n-N f2b-sshd\n-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n-A INPUT -s 192.0.2.7/32 -j REJECT --reject-with icmp-port-unreachable\n"), "off"},
		{"iptables reject, then accept", parseIptablesInput("-P INPUT ACCEPT\n-A INPUT -j REJECT\n-A INPUT -j ACCEPT\n"), "off"},
		{"iptables nothing", parseIptablesInput(""), "unknown"},
	}
	for _, c := range cases {
		if got := tri(c.got); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	if v := parseSwVers("14.5\n"); v != "14.5" {
		t.Errorf("sw_vers: %q", v)
	}
	if v := parseSwVers("sw_vers: error\n"); v != "" {
		t.Errorf("sw_vers garbage: %q", v)
	}
	if d := parseOSRelease("NAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"12\"\n"); d != "debian 12" {
		t.Errorf("os-release: %q", d)
	}
	if d := parseOSRelease("ID='arch'\n"); d != "arch" {
		t.Errorf("os-release without a version: %q", d)
	}
}

const manageBDEOn = `BitLocker Drive Encryption: Configuration Tool version 10.0.26100
Copyright (C) 2013 Microsoft Corporation. All rights reserved.

Disk volumes that can be protected with
BitLocker Drive Encryption:
Volume C: [Windows]
[OS Volume]

    Size:                 475.69 GB
    BitLocker Version:    2.0
    Conversion Status:    Used Space Only Encrypted
    Percentage Encrypted: 100.0%
    Encryption Method:    XTS-AES 128
    Protection Status:    Protection On
    Lock Status:          Unlocked
    Identification Field: Unknown
    Key Protectors:
        TPM
        Numerical Password
`

func TestWindowsFirewallProfiles(t *testing.T) {
	one, zero := uint32(1), uint32(0)
	cases := []struct {
		name     string
		profiles []firewallProfile
		want     string
	}{
		{"all on", []firewallProfile{{Local: &one}, {Local: &one}, {Local: &one}}, "on"},
		{"public off", []firewallProfile{{Local: &one}, {Local: &one}, {Local: &zero}}, "off"},
		{"policy wins", []firewallProfile{{Policy: &zero, Local: &one}, {Local: &one}, {Local: &one}}, "off"},
		{"policy turns on", []firewallProfile{{Policy: &one, Local: &zero}, {Local: &one}, {Local: &one}}, "on"},
		{"one unknown", []firewallProfile{{Local: &one}, {}, {Local: &one}}, "unknown"},
		{"unknown and off", []firewallProfile{{}, {Local: &zero}, {Local: &one}}, "off"},
		{"nothing", nil, "unknown"},
	}
	for _, c := range cases {
		if got := tri(windowsFirewallOn(c.profiles)); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestLinuxFirewallChains(t *testing.T) {
	cases := []struct {
		name   string
		chains []nftChain
		listed bool
		want   string
	}{
		{"not listed", nil, false, "unknown"},
		{"no chains", nil, true, "off"},
		{"input policy drop", []nftChain{{InputHook: true, PolicyDrop: true}}, true, "on"},
		{"input ends in reject (firewalld)", []nftChain{{InputHook: true, EndsInDrop: true}}, true, "on"},
		{"policy accept, some drops only (fail2ban)", []nftChain{{InputHook: true}}, true, "off"},
		{"input accepting everything", []nftChain{{InputHook: true}}, true, "off"},
	}
	for _, c := range cases {
		if got := tri(linuxFirewallOn(c.chains, c.listed)); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestExternalPosture(t *testing.T) {
	defer external.Store(nil)
	yes := true
	SetExternalPosture(api.Posture{OSVersion: "14", Distribution: "SDK 34", PatchLevel: "2026-09-05", DiskEncryption: &yes})
	p := withExternal(api.Posture{OS: "android", Firewall: &yes})
	if p.OSVersion != "14" || p.Distribution != "SDK 34" || p.PatchLevel != "2026-09-05" || tri(p.DiskEncryption) != "on" ||
		tri(p.Firewall) != "on" || p.ScreenLock != nil {
		t.Fatalf("%+v", p)
	}
	// On Android, secure boot is what the control plane found in the phone's attestation.
	for _, c := range []struct {
		attested *api.Attested
		want     string
	}{
		{nil, "verified boot not attested"},
		{&api.Attested{Error: "made for another device key"}, "verified boot not attested: made for another device key"},
		{&api.Attested{SecurityLevel: "tee", BootState: "verified", Locked: true}, "verified boot attested (tee)"},
		{&api.Attested{SecurityLevel: "tee", BootState: "unverified"}, "bootloader UNLOCKED (attested, unverified)"},
		{&api.Attested{SecurityLevel: "strongbox", BootState: "self-signed", Locked: true}, "verified boot SELF-SIGNED (attested)"},
	} {
		p.Attested = c.attested
		want := "disk encrypted, firewall on, " + c.want + ", screen lock unknown, anti-malware unknown; android 14 (SDK 34), patch 2026-09-05"
		if s := PostureSummary(p); s != want {
			t.Errorf("summary: %q, want %q", s, want)
		}
	}
	p.Attested = nil
	if !samePosture(p, withExternal(api.Posture{OS: "android", Firewall: &yes})) {
		t.Error("the same facts differ")
	}
	no := false
	if samePosture(p, withExternal(api.Posture{OS: "android", Firewall: &no})) {
		t.Error("different facts are the same")
	}
}

func TestPostureCollectTimeout(t *testing.T) {
	savedTimeout, savedCollect := postureTimeout, collect
	defer func() {
		postureTimeout, collect = savedTimeout, savedCollect
		postureCache.Lock()
		postureCache.at, postureCache.facts, postureCache.collected = time.Time{}, api.Posture{}, false
		postureCache.Unlock()
	}()
	postureCache.Lock()
	postureCache.at, postureCache.facts, postureCache.collected = time.Time{}, api.Posture{}, false
	postureCache.Unlock()
	postureTimeout = 50 * time.Millisecond
	hang := func(ctx context.Context) api.Posture {
		<-ctx.Done()
		time.Sleep(10 * time.Millisecond)
		return api.Posture{}
	}

	// Nothing collected before: nothing to report.
	collect = hang
	if _, ok := currentPosture(context.Background(), "1"); ok {
		t.Fatal("a collection that timed out is reported")
	}
	// A complete collection, then one that hangs: the complete one stands.
	yes := true
	collect = func(context.Context) api.Posture { return api.Posture{OSVersion: "6.8.0", Firewall: &yes} }
	if p, ok := currentPosture(context.Background(), "1"); !ok || p.OSVersion != "6.8.0" {
		t.Fatalf("%v %+v", ok, p)
	}
	postureCache.Lock()
	postureCache.at = time.Time{} // due again
	postureCache.Unlock()
	collect = hang
	p, ok := currentPosture(context.Background(), "1")
	if !ok || p.OSVersion != "6.8.0" || tri(p.Firewall) != "on" || p.OS != runtime.GOOS || p.Agent != "1" {
		t.Fatalf("the earlier facts are not kept: %v %+v", ok, p)
	}
}

func TestPostureDue(t *testing.T) {
	yes, no := true, false
	a := api.Posture{Format: 1, OS: "linux", Firewall: &yes}
	b := api.Posture{Format: 1, OS: "linux", Firewall: &no}
	now := wallNow()
	if strings.Contains(now.String(), "m=") {
		t.Fatal("wallNow keeps the monotonic reading")
	}
	cases := []struct {
		name   string
		facts  api.Posture
		sentAt time.Time
		force  bool
		want   bool
	}{
		{"never sent", a, time.Time{}, false, true},
		{"same, recent", a, now.Add(-time.Minute), false, false},
		{"changed", b, now.Add(-time.Minute), false, true},
		{"same, 10 minutes old", a, now.Add(-postureReportEvery), false, true},
		// A device that slept: its last report is old by the wall clock.
		{"same, sent before a sleep of an hour", a, now.Add(-time.Hour), false, true},
		{"asked for", a, now.Add(-time.Minute), true, true},
	}
	for _, c := range cases {
		if got := postureDue(c.facts, a, c.sentAt, now, c.force); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestStaleFailureWakesReporter(t *testing.T) {
	a := &runner{cfg: Config{Logf: func(string, ...any) {}}, postureWake: make(chan struct{}, 1)}
	a.setFailing([]api.PostureFailure{{Check: "enc", Reason: "disk not encrypted"}})
	select {
	case <-a.postureWake:
		t.Fatal("a failing fact asks for a report")
	default:
	}
	a.setFailing([]api.PostureFailure{{Check: "enc", Reason: "no report in 30m"}})
	select {
	case <-a.postureWake:
	default:
		t.Fatal("a stale report does not ask for a new one")
	}
	a.setFailing(nil)
	select {
	case <-a.postureWake:
		t.Fatal("passing asks for a report")
	default:
	}
}

func TestLinkFailingFile(t *testing.T) {
	dir := t.TempDir()
	path := linkFailingFile(dir, "acme")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	a := &runner{cfg: Config{Logf: func(string, ...any) {}}, postureWake: make(chan struct{}, 1), failingFile: path}
	a.setFailing([]api.PostureFailure{{Check: "fw", Reason: "firewall off"}})
	if got := LinkPostureFailing(dir, "acme"); len(got) != 1 || got[0].Check != "fw" || got[0].Reason != "firewall off" {
		t.Fatalf("%+v", got)
	}
	a.setFailing(nil)
	if got := LinkPostureFailing(dir, "acme"); len(got) != 0 {
		t.Fatalf("still failing: %+v", got)
	}
}

func TestAntimalwareParser(t *testing.T) {
	for out, want := range map[string]string{
		"av=397568\r\n":                    "on",  // Microsoft Defender, real-time protection on
		"av=393472\r\n":                    "off", // registered, real-time protection off
		"av=393472\r\nav=266240\r\n":       "on",  // Defender off, another product on
		"defender=True,True\r\n":           "on",  // a server edition: Defender itself
		"defender=True,False\r\n":          "off",
		"":                                 "unknown",
		"Get-MpComputerStatus : error\r\n": "unknown",
	} {
		if got := tri(parseAntimalware(out)); got != want {
			t.Errorf("%q: %s, want %s", out, got, want)
		}
	}
	if got := tri(linuxAntimalware([]string{"bash", "clamonacc"})); got != "on" {
		t.Errorf("clamonacc: %s", got)
	}
	if got := tri(linuxAntimalware([]string{"clamd"})); got != "unknown" {
		t.Errorf("clamd alone (no on-access scanning): %s", got)
	}
}

func TestParseNftChainJSON(t *testing.T) {
	head := `{"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}}, {"chain": {"family": "inet", "table": "firewalld", "name": "filter_INPUT", "handle": 1, "type": "filter", "hook": "input", "prio": 10, "policy": "accept"}}`
	rich := `{"rule": {"family": "inet", "table": "firewalld", "chain": "filter_INPUT", "handle": 2, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "100.64.1.1"}}, {"match": {"op": "==", "left": {"ct": {"key": "proto-dst", "dir": "original"}}, "right": 22}}, {"accept": null}]}}`
	rule := func(exprs string) string {
		return `{"rule": {"family": "inet", "table": "firewalld", "chain": "filter_INPUT", "handle": 9, "expr": [` + exprs + `]}}`
	}
	for _, c := range []struct {
		name, out string
		want      bool
		err       bool
	}{
		{"ends in reject (firewalld)", head + `, ` + rich + `, ` + rule(`{"counter": {"packets": 0, "bytes": 0}}, {"reject": {"type": "icmpx", "expr": "admin-prohibited"}}`) + `]}`, true, false},
		{"ends in drop", head + `, ` + rule(`{"drop": null}`) + `]}`, true, false},
		{"iptables-nft REJECT", head + `, ` + rule(`{"xt": {"type": "target", "name": "REJECT"}}`) + `]}`, true, false},
		{"ends in a rule that matches", head + `, ` + rule(`{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "invalid"}}, {"drop": null}`) + `]}`, false, false},
		{"ends in accept", head + `, ` + rich + `]}`, false, false},
		{"no rules", head + `]}`, false, false},
		{"not JSON", "Error: No such file or directory", false, true},
	} {
		got, err := parseNftChainJSON(c.out)
		if got != c.want || (err != nil) != c.err {
			t.Errorf("%s: %v, %v", c.name, got, err)
		}
	}
}
