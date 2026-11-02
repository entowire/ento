package agent

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

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
		"ExecStart=/opt/ento/bin/ento agent up --state-dir /var/lib/ento --interface ento0 \\\n" +
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
