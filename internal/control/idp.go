package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"entowire.com/ento/internal/store"
)

// IdentityProviderPort is where control nodes forward the identity provider on their overlay
// address.
const IdentityProviderPort = 443

// Limits of the forward, so that a device cannot hold this node's (and the provider's) connections:
// the first bytes within idpFirstByte, then no silence longer than idpIdle, no connection longer
// than idpTotal, at most idpPerDevice at a time from one device (a browser opens a handful).
// Variables for tests.
var (
	idpFirstByte = 10 * time.Second
	idpIdle      = 10 * time.Minute
	idpTotal     = time.Hour
	idpPerDevice = 32
)

// The identity provider is made reachable on this node's overlay address, port 443, by passing TCP
// connections through to it (TLS stays end to end between the browser and the provider); start443
// in adminui.go listens. Enrolled devices can reach it even when they are not (or no longer)
// approved, since they must be able to sign in to become approved: the identity provider's name
// should resolve to the control nodes' overlay addresses. Holders of enrollment tokens (temporary
// addresses) and suspended devices are refused: they have nothing to sign in for.

func (s *Server) forwardIdentity(ctx context.Context, c net.Conn, targets []string) {
	s.passThrough(ctx, c, targets, "idp_connection", "identity provider", "")
}

// passThrough passes a TCP connection through to the first of targets that answers, as the
// identity provider's forward does (who may connect, limits, one audit line per connection under
// action, what naming the service, name the TLS server name asked for when not the provider).
func (s *Server) passThrough(ctx context.Context, c net.Conn, targets []string, action, what, name string) {
	defer c.Close()
	via := ""
	if name != "" {
		via = name + " "
	}
	start := time.Now()
	// Who is connecting: TLS stays end to end, so the connection's metadata is all this node sees,
	// and the identity provider only sees this node. One audit line per connection ties the two.
	var dev *store.Peer
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		p, err := s.cfg.Store.PeerByAddress(ctx, ap.Addr().Unmap())
		switch {
		case err == nil:
			dev = &p
		case errors.Is(err, store.ErrNotFound):
			dev = &store.Peer{Hostname: "unknown", Address: ap.Addr().Unmap()}
		default:
			// The database did not answer (a failover): nobody is refused as a stranger for it.
			// Still closed, but recorded as a failure, not a denial.
			s.audit(nil, &store.Peer{Hostname: "unknown", Address: ap.Addr().Unmap()}, action,
				via+"device lookup failed (database unavailable)", "failed")
			return
		}
	}
	switch {
	case dev == nil || dev.ID == 0:
		s.audit(nil, dev, action, via+"not an enrolled device: refused", "denied")
		return
	case dev.Suspended:
		s.audit(nil, dev, action, via+"suspended device: refused", "denied")
		return
	case !s.idpAcquire(dev.Address):
		s.audit(nil, dev, action, via+fmt.Sprintf("more than %d connections at once: refused", idpPerDevice), "denied")
		return
	}
	defer s.idpRelease(dev.Address)
	end := start.Add(idpTotal)
	c = &deadlineConn{Conn: c, end: end, first: idpFirstByte}
	state := func(p *store.Peer) string {
		if p == nil || p.ID == 0 {
			return "not enrolled"
		}
		if !p.Approved {
			return "not approved"
		}
		return "approved"
	}
	var up net.Conn
	var err error
	var used string
	for _, t := range targets { // the first is this node's own
		up, err = (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", t)
		if err == nil {
			used = t
			break
		}
	}
	if up == nil {
		s.cfg.Logf("%s unreachable: %v", what, err)
		s.audit(nil, dev, action, fmt.Sprintf("%sdevice %s: %s unreachable", via, state(dev), what), "failed")
		return
	}
	defer up.Close()
	up = &deadlineConn{Conn: up, end: end}
	var in, out int64
	done := make(chan struct{}, 2)
	go func() { in, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { out, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
	// Closing both ends ends the other copy too; wait for it to count its bytes.
	c.Close()
	up.Close()
	<-done
	s.audit(nil, dev, action, fmt.Sprintf("%sdevice %s via %s, %s, %d bytes in, %d bytes out",
		via, state(dev), used, time.Since(start).Round(time.Second), in, out), "ok")
}

func (s *Server) idpAcquire(a netip.Addr) bool {
	s.idpMu.Lock()
	defer s.idpMu.Unlock()
	if s.idpConns == nil {
		s.idpConns = map[netip.Addr]int{}
	}
	if s.idpConns[a] >= idpPerDevice {
		return false
	}
	s.idpConns[a]++
	return true
}

func (s *Server) idpRelease(a netip.Addr) {
	s.idpMu.Lock()
	defer s.idpMu.Unlock()
	if s.idpConns[a]--; s.idpConns[a] <= 0 {
		delete(s.idpConns, a)
	}
}

// deadlineConn ends reads that wait too long: the first within first (when set), each later one
// within idpIdle, none after end.
type deadlineConn struct {
	net.Conn
	end   time.Time
	first time.Duration
	mu    sync.Mutex
}

func (d *deadlineConn) Read(b []byte) (int, error) {
	d.mu.Lock()
	wait := idpIdle
	if d.first > 0 {
		wait = d.first
	}
	d.mu.Unlock()
	t := time.Now().Add(wait)
	if t.After(d.end) {
		t = d.end
	}
	_ = d.Conn.SetReadDeadline(t)
	n, err := d.Conn.Read(b)
	if n > 0 {
		d.mu.Lock()
		d.first = 0
		d.mu.Unlock()
	}
	return n, err
}
