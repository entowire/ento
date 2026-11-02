package agent

import (
	"context"
	"regexp"
)

var platformUUID = regexp.MustCompile(`"IOPlatformUUID" = "([0-9A-Fa-f-]+)"`)

// machineID is the Mac's IOPlatformUUID.
func machineID(ctx context.Context) string {
	out, err := runFixed(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil {
		return ""
	}
	if m := platformUUID.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}
