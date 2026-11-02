//go:build linux && !android

package agent

import (
	"entowire.com/ento/internal/hwsig"
	"entowire.com/ento/internal/tpmkey"
)

// openHardwareKey opens the device's key in its TPM (nil without a TPM).
func openHardwareKey(cfg Config) (hwsig.Signer, error) {
	dev := cfg.TPMDevice
	if dev == "" {
		dev = tpmkey.DefaultDevice
	}
	if !tpmkey.Available(dev) {
		return nil, nil
	}
	k, err := tpmkey.Load(dev, cfg.StateDir)
	if err != nil {
		return nil, err
	}
	return k, nil
}
