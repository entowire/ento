package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The unit lets the agent write the directory of its binary, so that it can update itself (D1),
// and starts it through the command's link.
func TestUnitAllowsSelfUpdate(t *testing.T) {
	u := fmt.Sprintf(unit, installBinary, "/var/lib/ento", "ento0", 51830, 1380, "", "")
	var rw []string
	for _, l := range strings.Split(u, "\n") {
		if v, ok := strings.CutPrefix(l, "ReadWritePaths="); ok {
			rw = strings.Fields(v)
		}
	}
	if !slices.Contains(rw, installDir) || filepath.Dir(installReal) != installDir || !strings.Contains(u, "ExecStart="+installBinary+" ") {
		t.Fatalf("the unit does not let the agent replace %s: ReadWritePaths %v", installReal, rw)
	}
	dir := t.TempDir()
	cmd, real := filepath.Join(dir, "ento"), filepath.Join(dir, "lib-ento")
	os.WriteFile(cmd, []byte("old binary"), 0o755)
	if err := linkCommand(cmd, real); err != nil {
		t.Fatal(err)
	}
	if dest, err := os.Readlink(cmd); err != nil || dest != real {
		t.Fatalf("the command is not a link to the binary: %q %v", dest, err)
	}
	if err := linkCommand(cmd, real); err != nil {
		t.Fatalf("again: %v", err)
	}
}

func TestUnitArgs(t *testing.T) {
	installed := fmt.Sprintf(unit, installBinary, "/var/lib/ento", "ento0", 51830, 1380, "", "")
	args := unitArgs(installed)
	if !isAgentCommand(args) || args[2] != "run" || stateDirArg(args) != "/var/lib/ento" || slices.Contains(args, "--log-drops") {
		t.Errorf("installed unit: %q", args)
	}
	logging := unitArgs(fmt.Sprintf(unit, installBinary, "/var/lib/ento", "ento0", 51830, 1380, " --log-drops", ""))
	if !slices.Contains(logging, "--log-drops") || logging[len(logging)-1] != "--log-drops" {
		t.Errorf("installed unit with drop logging: %q", logging)
	}
	// A unit written by hand (or by other tooling), its command continued on a second line.
	member := "[Service]\n" +
		"ExecStartPre=+/usr/bin/mkdir -p -m 0700 /var/lib/ento\n" +
		"ExecStart=/opt/ento/bin/ento up --state-dir /var/lib/ento --interface ento0 \\\n" +
		"  --listen-port 51830 --mtu 1380\n"
	args = unitArgs(member)
	if stateDirArg(args) != "/var/lib/ento" || !slices.Contains(args, "--listen-port") {
		t.Errorf("continued unit: %q", args)
	}
	if unitArgs("[Service]\nExecStartPre=/bin/true\n") != nil {
		t.Error("ExecStartPre taken for ExecStart")
	}
}

// The TPM's group goes into the unit, so the agent (without CAP_DAC_OVERRIDE) can open the device;
// nothing without a TPM, or for a device root owns.
func TestTPMGroupLine(t *testing.T) {
	if tpmGroupLine("/nonexistent/tpmrm0") != "" {
		t.Error("a group for a missing TPM")
	}
	f, err := os.CreateTemp(t.TempDir(), "tpm")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	line := tpmGroupLine(f.Name())
	if os.Getgid() == 0 {
		if line != "" {
			t.Errorf("a group for a device root owns: %q", line)
		}
	} else if !strings.Contains(line, "SupplementaryGroups=") {
		t.Errorf("no group line for a device of gid %d: %q", os.Getgid(), line)
	}
	if u := fmt.Sprintf(unit, installBinary, "/var/lib/ento", "ento0", 51830, 1380, "", line); line != "" && !strings.Contains(u, line) {
		t.Error("the line is not in the unit")
	}
}

// Without systemd, install refuses before anything is asked or written (0.56.6, a QNAP NAS).
func TestServiceSupported(t *testing.T) {
	old := systemdDir
	defer func() { systemdDir = old }()
	systemdDir = t.TempDir()
	if err := ServiceSupported(); err != nil {
		t.Fatalf("with systemd: %v", err)
	}
	systemdDir = filepath.Join(systemdDir, "missing")
	if err := ServiceSupported(); err == nil || !strings.Contains(err.Error(), "systemd") {
		t.Fatalf("without systemd: %v", err)
	}
	if err := Install(Config{StateDir: t.TempDir()}, "token", false); err == nil || !strings.Contains(err.Error(), "systemd") {
		t.Fatalf("Install without systemd: %v", err)
	}
}
