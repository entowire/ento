package store

import (
	"context"
	"net"
	"time"
)

// dialDB connects to PostgreSQL so that a server that vanishes (powered off, cut off: it neither
// answers nor refuses) is noticed within seconds instead of after TCP's own give-up, about 15
// minutes: keepalives probe idle connections (such as the one waiting for change notifications),
// and on Linux unacknowledged data abandons a connection after dbUserTimeout. Without it, a failover
// of the database left every query of a control node hanging on its connections to the old primary
// until that machine came back.
func dialDB(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{
		Timeout: 5 * time.Second,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     10 * time.Second,
			Interval: 5 * time.Second,
			Count:    3,
		},
		Control: setUserTimeout,
	}
	return d.DialContext(ctx, network, addr)
}

const dbUserTimeout = 15 * time.Second
