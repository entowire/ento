//go:build windows

package agent

import "golang.zx2c4.com/wireguard/conn"

// newBind is WireGuard's UDP socket. On Windows, wireguard-go's default sends through Registered
// I/O (RIO), which network filter drivers of VPN and security products can break without an
// error: the packets count as sent and never leave (found on canti, 0.56.4, with NordVPN,
// FortiClient and Cisco AnyConnect installed, while a plain socket's packets arrived). The
// standard socket goes through Winsock like any program's.
func newBind() conn.Bind { return conn.NewStdNetBind() }
