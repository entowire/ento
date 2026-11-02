//go:build darwin && !ios

package agent

import (
	"context"
	"os"

	"entowire.com/ento/internal/api"
)

// collectPlatform finds out the posture of a Mac: its product version (sw_vers), FileVault
// (fdesetup), the application firewall (socketfilterfw) and XProtect, the system's own
// anti-malware (present: on; it cannot be turned off without disabling System Integrity
// Protection). Secure boot and screen lock stay unknown.
func collectPlatform(ctx context.Context) api.Posture {
	p := api.Posture{OS: "darwin"}
	if out, err := runFixed(ctx, "/usr/bin/sw_vers", "-productVersion"); err == nil {
		p.OSVersion = parseSwVers(out)
	}
	if out, err := runFixed(ctx, "/usr/bin/fdesetup", "status"); err == nil {
		p.DiskEncryption = parseFdesetup(out)
	}
	if out, err := runFixed(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"); err == nil {
		p.Firewall = parseSocketFilterFW(out)
	}
	for _, b := range []string{"/Library/Apple/System/Library/CoreServices/XProtect.bundle", "/System/Library/CoreServices/XProtect.bundle"} {
		if _, err := os.Stat(b); err == nil {
			p.Antimalware = boolPtr(true)
			break
		}
	}
	return p
}
