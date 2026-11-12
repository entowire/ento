package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"time"

	entoid "entowire.com/ento/internal/id"
	"entowire.com/ento/internal/store"
)

// The control nodes as the network's own identity provider (package id, 0.57): served under its
// name on their overlay port 443, TLS ending here with its own certificate, for enrolled devices
// that are not suspended, like the forward to an outside provider was. The control nodes sign
// their own devices in with it in process: the ento client is built in (its secret derived from the
// signing key every node shares), with the dashboard's and the apps' redirect addresses and the
// device grant.

// IDConfig makes the control nodes the network's identity provider.
type IDConfig struct {
	Name    string            // its host name, e.g. id.example.com: the issuer https://<Name>, the passkeys' relying party
	Title   string            // the network's name, shown on its pages and to passkey managers
	Cert    string            // TLS certificate (PEM, with chain) for Name, read again when it changes
	CertKey string            // its private key
	Key     *ecdsa.PrivateKey // signs ID tokens: P-256, the same on every control node
	Clients []entoid.Client   // other applications that sign people in (the ento client is built in)
	// Listen, if set, is a host address (host:port) where the provider is served too, with the same
	// certificate: for services beside the control nodes that are no devices of the network (the
	// platform console on entowire's own nodes, over their mesh). Never a public address.
	Listen   string
	Disabled bool // for tests: no listener on the overlay
}

// IDIssuer is the issuer of the provider named name.
func IDIssuer(name string) string { return "https://" + name }

// IDClientSecret is the secret of the built-in client clientID: every control node derives the same
// from the signing key, so nobody keeps or hands it over.
func IDClientSecret(key *ecdsa.PrivateKey, clientID string) string {
	m := hmac.New(sha256.New, key.D.FillBytes(make([]byte, 32)))
	m.Write([]byte("ento-id-client-v1\x00" + clientID))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// startID makes the provider, and the built-in client when the control nodes sign in with it.
func (s *Server) startID() error {
	cfg := s.cfg.ID
	if cfg.Key == nil {
		return errors.New("the identity provider needs a signing key")
	}
	clients := append([]entoid.Client(nil), cfg.Clients...)
	if o := s.cfg.OIDC; o != nil && o.Issuer == IDIssuer(cfg.Name) {
		c := entoid.Client{ID: o.ClientID, Name: "ento", Secret: IDClientSecret(cfg.Key, o.ClientID), DeviceGrant: true}
		if s.cfg.AdminUI != "" {
			c.RedirectURIs = append(c.RedirectURIs, "https://"+s.cfg.AdminUI+uiCallbackPath)
		}
		c.RedirectURIs = append(c.RedirectURIs, o.AppRedirects...)
		clients = append(clients, c)
	}
	idc := entoid.Config{Name: cfg.Name, Title: cfg.Title, Key: cfg.Key, Clients: clients, Store: s.cfg.Store,
		Logf: s.cfg.Logf, Audit: s.idAudit}
	if o := s.cfg.OIDC; o != nil && o.Issuer == IDIssuer(cfg.Name) {
		// The device's own sign-in (here.go): with the built-in client, served by startHere.
		idc.Here, idc.HereOrigin, idc.HereClient = s, hereOrigin(cfg.Name), o.ClientID
	}
	p, err := entoid.New(idc)
	if err != nil {
		return err
	}
	s.id = p
	return nil
}

// idAudit records what the provider did, by the calling device (its overlay address), or by the
// control nodes themselves (calls in process).
func (s *Server) idAudit(r *http.Request, action, target, result string) {
	var by *store.Peer
	if a, ok := caller(r); ok {
		if p, err := s.cfg.Store.PeerByAddress(r.Context(), a.Unmap()); err == nil {
			by = &p
		} else {
			by = &store.Peer{Hostname: "unknown", Address: a.Unmap()}
		}
	} else {
		by = &store.Peer{Hostname: "control:" + s.cfg.Name}
	}
	s.audit(r, by, action, target, result)
}

// inProcess answers HTTP requests with a handler, without a network: the control node's calls to
// its own provider.
type inProcess struct{ h http.Handler }

func (t inProcess) RoundTrip(req *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	r := req.Clone(req.Context())
	r.RemoteAddr = "" // the control node itself: no device
	r.RequestURI = req.URL.RequestURI()
	t.h.ServeHTTP(w, r)
	resp := w.Result()
	resp.Request = req
	return resp, nil
}

// listenID serves the provider on cfg.Listen as well, until ctx ends.
func (s *Server) listenID(ctx context.Context) error {
	certs := &certFiles{cert: s.cfg.ID.Cert, key: s.cfg.ID.CertKey}
	if _, err := certs.get(nil); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.cfg.ID.Listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: s.id.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute,
		BaseContext: func(net.Listener) context.Context { return ctx }}
	tlsConf := &tls.Config{GetCertificate: certs.get, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	go func() {
		if err := srv.Serve(tls.NewListener(ln, tlsConf)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.cfg.Logf("identity provider on %s: %v", s.cfg.ID.Listen, err)
		}
	}()
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	s.cfg.Logf("identity provider also on https://%s (%s)", s.cfg.ID.Name, ln.Addr())
	return nil
}

// serveID hands a connection for the provider's name to its HTTPS server: only enrolled devices that
// are not suspended get there (others never see its certificate), at most idpPerDevice at a time,
// each within the forward's limits.
func (s *Server) serveID(ctx context.Context, c net.Conn, ln *connListener) {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		c.Close()
		return
	}
	p, err := s.cfg.Store.PeerByAddress(ctx, ap.Addr().Unmap())
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.audit(nil, &store.Peer{Hostname: "unknown", Address: ap.Addr().Unmap()}, "id_connection", "not an enrolled device: refused", "denied")
		c.Close()
		return
	case err != nil:
		s.audit(nil, &store.Peer{Hostname: "unknown", Address: ap.Addr().Unmap()}, "id_connection", "device lookup failed (database unavailable)", "failed")
		c.Close()
		return
	case p.Suspended:
		s.audit(nil, &p, "id_connection", "suspended device: refused", "denied")
		c.Close()
		return
	case !s.idpAcquire(p.Address):
		s.audit(nil, &p, "id_connection", "too many connections at once: refused", "denied")
		c.Close()
		return
	}
	conn := &releasingConn{Conn: &deadlineConn{Conn: c, end: time.Now().Add(idpTotal), first: idpFirstByte},
		release: func() { s.idpRelease(p.Address) }}
	if !ln.push(conn) {
		conn.Close()
	}
}

// releasingConn calls release once, when it is closed.
type releasingConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *releasingConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

func isIDName(cfg *IDConfig, name string) bool {
	return cfg != nil && strings.EqualFold(name, cfg.Name)
}
