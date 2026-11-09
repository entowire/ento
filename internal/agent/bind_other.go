//go:build !windows

package agent

import "golang.zx2c4.com/wireguard/conn"

// newBind is WireGuard's UDP socket: wireguard-go's default (bind_windows.go says why not there).
func newBind() conn.Bind { return conn.NewDefaultBind() }
