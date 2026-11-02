//go:build !windows

package agent

import (
	"context"
	"net"
)

// serveSessions: the person's channel is Windows-only, where the device's key is out of the
// person's reach and no PAM step signs them in (elsewhere they use sudo).
func serveSessions(context.Context, Config) {}

func sessionDial(context.Context) (net.Conn, error) { return nil, ErrNoSessionChannel }
