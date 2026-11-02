//go:build !windows

package main

import "context"

// runService is for Windows services; elsewhere the service manager (systemd, launchd) runs the
// agent as an ordinary process.
func runService(func(ctx context.Context) error, string) (bool, error) { return false, nil }
