package agent

import (
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Peers returns WireGuard's view of the home network's peers, from the running agent's interface
// (kernel or in-process: both answer on the standard WireGuard interfaces).
func Peers(cfg Config) (map[wgtypes.Key]PeerStatus, error) {
	cfg.defaults()
	name := cfg.Interface
	if r, ok := RunningAgent(cfg.StateDir); ok && r.Interface != "" {
		name = r.Interface
	}
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	dev, err := c.Device(name)
	if err != nil {
		return nil, err
	}
	return deviceStatus(dev), nil
}
