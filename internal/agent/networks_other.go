//go:build !linux

package agent

import "context"

// Joining more than one network is done on Linux only, for now (networks.go).
const networksSupported = false

func manageNetworks(ctx context.Context, cfg Config) {}

func memberInterfaces(stateDir string) []string { return nil }
