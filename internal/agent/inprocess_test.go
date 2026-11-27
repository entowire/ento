package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLeaveFirstInProcess: on a phone every network can be left (0.61). Leaving the first moves the
// network joined next (by domain) into the state directory; what the device keeps stays; leaving
// the last leaves the phone in none.
func TestLeaveFirstInProcess(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := SaveState(dir, State{RecordDomain: "a.example.com"}); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(dir, exitChoiceFile), "office\n")
	write(filepath.Join(dir, runningFile), "{}")
	for _, d := range []string{"b.example.com", "c.example.com"} {
		if err := SaveState(NetworkDir(dir, d), State{RecordDomain: d}); err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(NetworkDir(dir, d), membershipFile), `{"domain":"`+d+`"}`)
	}
	write(filepath.Join(NetworkDir(dir, "b.example.com"), exitChoiceFile), "off\n")
	write(filepath.Join(dir, defaultNetworkFile), "b.example.com\n")
	write(filepath.Join(dir, "update-pending.json"), "{}")

	if err := LeaveFirstInProcess(dir); err != nil {
		t.Fatal(err)
	}
	if d := FirstDomain(dir); d != "b.example.com" {
		t.Fatalf("first after leaving a: %q", d)
	}
	if c := ExitChoice(dir); c != ExitOff {
		t.Fatalf("exit choice: b's (off) expected, got %q", c)
	}
	if exists(filepath.Join(dir, runningFile)) {
		t.Fatal("a's agent.json stayed")
	}
	if exists(NetworkDir(dir, "b.example.com")) {
		t.Fatal("b's directory stayed")
	}
	if exists(filepath.Join(dir, defaultNetworkFile)) {
		t.Fatal("the default network named b, now first: kept")
	}
	if !exists(filepath.Join(dir, "update-pending.json")) {
		t.Fatal("the device's own file went")
	}
	if n := Networks(dir); len(n) != 1 || n[0] != "c.example.com" {
		t.Fatalf("joined after leaving a: %v", n)
	}

	if err := LeaveFirstInProcess(dir); err != nil {
		t.Fatal(err)
	}
	if d := FirstDomain(dir); d != "c.example.com" || len(Networks(dir)) != 0 {
		t.Fatalf("first %q, joined %v", d, Networks(dir))
	}
	if err := LeaveFirstInProcess(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err == nil {
		t.Fatal("still in a network after leaving the last")
	}
	if err := LeaveFirstInProcess(dir); err == nil {
		t.Fatal("left a network the phone is not in")
	}
}

// TestAppExitOneAtATime: on a phone any network's exit can be used, but one at a time (0.61).
func TestAppExitOneAtATime(t *testing.T) {
	defer appExit.Store(nil)
	a := &runner{ifc: &userTunnel{noOS: true}, st: State{RecordDomain: "a.example.com"}}
	b := &runner{ifc: &userTunnel{noOS: true}, st: State{RecordDomain: "b.example.com"}, member: true}
	if !b.exitsHere() {
		t.Fatal("a joined network on a phone may not use exits")
	}
	if (&runner{ifc: &userTunnel{}, member: true}).exitsHere() {
		t.Fatal("a joined network elsewhere may use exits")
	}
	if o := takeAppExit(a); o != "" {
		t.Fatalf("a: %q", o)
	}
	if o := takeAppExit(a); o != "" {
		t.Fatalf("a again: %q", o)
	}
	if o := takeAppExit(b); o != "a.example.com" {
		t.Fatalf("b while a's exit is in use: %q", o)
	}
	a.syncExit(nil) // a stops using it
	if o := takeAppExit(b); o != "" {
		t.Fatalf("b after a stopped: %q", o)
	}
	if appExit.Load() != b {
		t.Fatal("b does not hold the exit")
	}
	// Elsewhere (no app's VPN) only the first network uses exits: nothing is held.
	defer appExit.Store(nil)
	appExit.Store(nil)
	if o := takeAppExit(&runner{ifc: &userTunnel{}}); o != "" || appExit.Load() != nil {
		t.Fatal("an exit held outside an app's VPN")
	}
}
