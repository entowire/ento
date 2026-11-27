//go:build darwin && !ios

package agent

import (
	"context"

	"entowire.com/ento/internal/api"
)

// collectPlatform finds out the posture of a Mac: its product version (sw_vers), FileVault
// (fdesetup) and the application firewall (socketfilterfw). Secure boot and screen lock stay
// unknown.
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
	return p
}
