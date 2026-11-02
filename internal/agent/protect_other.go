//go:build !android

package agent

import (
	"fmt"

	"golang.zx2c4.com/wireguard/device"
)

// protectSockets is only needed (and possible) on Android.
func protectSockets(*device.Device, func(fd int) bool) error {
	return fmt.Errorf("protect: not supported on this system")
}
