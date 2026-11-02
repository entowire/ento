//go:build !linux || android

package agent

import "entowire.com/ento/internal/hwsig"

// openHardwareKey: no hardware key on this system yet (macOS's Secure Enclave and Windows' TPM
// later; Android's Keystore key serves posture attestation).
func openHardwareKey(Config) (hwsig.Signer, error) { return nil, nil }
