//go:build linux

package agent

import "golang.zx2c4.com/wireguard/wgctrl"

// ownListenPort is the port of the device's kernel WireGuard interface name, if it exists already
// (an agent restarting: the interface outlived it).
var ownListenPort = func(name string) (int, bool) {
	c, err := wgctrl.New()
	if err != nil {
		return 0, false
	}
	defer c.Close()
	d, err := c.Device(name)
	if err != nil || d.ListenPort == 0 {
		return 0, false
	}
	return d.ListenPort, true
}
