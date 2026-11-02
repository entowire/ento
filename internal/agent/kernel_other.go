//go:build !linux

package agent

// kernelTunnel reports whether t is the kernel's WireGuard: only on Linux.
func kernelTunnel(tunnel) bool { return false }
