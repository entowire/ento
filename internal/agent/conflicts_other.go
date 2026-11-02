//go:build !linux || android

package agent

import "net/netip"

// OverlayWarnings: nothing known to check on this system.
func OverlayWarnings(netip.Prefix) []string { return nil }
