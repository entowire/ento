//go:build linux

package agent

import (
	"context"
	"os"
	"strings"
)

// machineID is systemd's machine ID (Android: none here; the app gives ANDROID_ID).
func machineID(context.Context) string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" && id != "uninitialized" {
				return id
			}
		}
	}
	return ""
}
