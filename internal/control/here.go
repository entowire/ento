package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"crypto/tls"

	"entowire.com/ento/internal/api"
	entoid "entowire.com/ento/internal/id"
	"entowire.com/ento/internal/store"
)

// The device's own sign-in (0.57; constitution 2.5). The control nodes serve their identity
// provider a second time, on their overlay addresses at api.SignInPort, and a person who signs in
// there is signed in on the device the browser runs on, as a device code's sign-in would: no code is
// typed, and nothing can be sent to someone else. That the browser runs on the device is the
// device's agent's to keep: it drops everything it forwards to that port (from containers, virtual
// machines, a network behind it), and says so at every check-in (api.CheckInRequest.HereGuard).
// Devices that do not say so, or did not lately, get the page's refusal and sign in as before.
//
// Any person may sign in on any device this way; the one before is signed out (the audit says
// binding=changed). A device invited for an account (invite.go) takes that account only.

const (
	hereGuardLife = 20 * time.Minute // a device's word that it guards its sign-in, renewed at check-ins
	hereDoneLife  = 10 * time.Minute // a sign-in on the device's own page, for the device that waits for it
	uiHereLife    = 2 * time.Minute  // a dashboard session the device's own sign-in opens
	kindHere      = "here"
	hereGuardKey  = "here-guard:"
	hereDoneKey   = "here-done:"
	uiHereKey     = "ui-here:"
	uiHerePath    = "/ui/here"
	thenUI        = "ui" // a sign-in on the device's own page that opens the dashboard
)

type hereKey struct{}

// hereOrigin is the device's own sign-in's origin.
func hereOrigin(name string) string { return "https://" + name + ":" + strconv.Itoa(api.SignInPort) }

// hereOn reports whether devices sign in on their own page: the control nodes sign their devices in
// with their own provider.
func (s *Server) hereOn() bool { return s.id != nil && s.id.HereURL("") != "" }

// noteHereGuard keeps what a device said at its check-in about its sign-in port.
func (s *Server) noteHereGuard(ctx context.Context, p store.Peer, guards bool) {
	if !s.hereOn() {
		return
	}
	key := hereGuardKey + strconv.FormatInt(p.ID, 10)
	now := time.Now()
	st, err := s.cfg.Store.IDState(ctx, key, now)
	switch {
	case guards && (err != nil || st.ExpiresAt.Sub(now) < hereGuardLife/2):
		err = s.cfg.Store.PutIDState(ctx, store.IDState{Key: key, Kind: kindHere, Data: []byte("{}"), ExpiresAt: now.Add(hereGuardLife)})
	case !guards && err == nil:
		_, err = s.cfg.Store.TakeIDState(ctx, key, now)
	default:
		err = nil
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.cfg.Logf("sign-in guard of %s: %v", p.Hostname, err)
	}
}

// hereGuarded reports whether a device said lately that it keeps its sign-in port to itself.
func (s *Server) hereGuarded(ctx context.Context, p store.Peer) bool {
	_, err := s.cfg.Store.IDState(ctx, hereGuardKey+strconv.FormatInt(p.ID, 10), time.Now())
	return err == nil
}

// startHere serves the device's own sign-in on the node's overlay address, api.SignInPort: for
// enrolled devices that are not suspended, as the provider on port 443.
func (s *Server) startHere(ctx context.Context) error {
	certs := &certFiles{cert: s.cfg.ID.Cert, key: s.cfg.ID.CertKey}
	if _, err := certs.get(nil); err != nil {
		return fmt.Errorf("identity provider's certificate: %w", err)
	}
	ln, err := s.wg.net.ListenTCPAddrPort(netip.AddrPortFrom(s.self.Address, api.SignInPort))
	if err != nil {
		return err
	}
	conns := newConnListener(ln.Addr())
	h := s.id.Handler()
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), hereKey{}, true)))
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	tlsConf := &tls.Config{GetCertificate: certs.get, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	go func() {
		if err := srv.Serve(tls.NewListener(conns, tlsConf)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.cfg.Logf("device sign-in: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		srv.Close()
		ln.Close()
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serveID(ctx, c, conns)
		}
	}()
	s.cfg.Logf("device sign-in on %s (%s:%d)", hereOrigin(s.cfg.ID.Name), s.self.Address, api.SignInPort)
	return nil
}

// hereDevice is the device a request on the device's own sign-in comes from, if it may sign in
// there; otherwise why not, for the person.
func (s *Server) hereDevice(r *http.Request) (store.Peer, string) {
	if on, _ := r.Context().Value(hereKey{}).(bool); !on {
		return store.Peer{}, "Devices sign in on their own sign-in page only."
	}
	addr, ok := caller(r)
	if !ok {
		return store.Peer{}, "This browser does not run on a device of the network."
	}
	p, err := s.cfg.Store.PeerByAddress(r.Context(), addr.Unmap())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Peer{}, "This browser does not run on a device of the network."
	case err != nil:
		return store.Peer{}, "Try again in a moment."
	case p.Suspended:
		return store.Peer{}, "This device is suspended."
	case p.Authority != "":
		return store.Peer{}, "Devices admitted through a linked network do not sign in here."
	case !s.hereGuarded(r.Context(), p):
		return store.Peer{}, "ento on this device cannot keep this page to the device itself (an older version, or a system " +
			"where it cannot yet): sign in on it with sudo ento agent login, or its app."
	}
	return p, ""
}

// HereDevice is the device's own sign-in's check (entoid.Here).
func (s *Server) HereDevice(r *http.Request) (string, string) {
	p, why := s.hereDevice(r)
	if why != "" {
		return "", why
	}
	return p.Hostname, ""
}

// HereSignedIn signs the person in on the device the request comes from (entoid.Here), as the end
// of a device code's sign-in does.
func (s *Server) HereSignedIn(r *http.Request, person store.IDPerson, idToken, refreshToken, then string) (string, error) {
	p, why := s.hereDevice(r)
	if why != "" {
		return "", errors.New(why)
	}
	c, err := parseIDToken(idToken)
	if err != nil {
		return "", errors.New("The sign-in could not be applied.")
	}
	if err := s.bindPerson(r.Context(), p, c, refreshToken, "on the device's own sign-in"); err != nil {
		return "", err
	}
	s.hereDone(r.Context(), p, c.name())
	if then != thenUI || s.cfg.AdminUI == "" {
		return "", nil
	}
	// The dashboard opens with the same sign-in: a ticket only this device can use, once.
	ticket := uiRandom()
	b, _ := json.Marshal(map[string]int64{"peer": p.ID})
	if err := s.cfg.Store.PutIDState(r.Context(), store.IDState{Key: uiHereKey + hashToken(ticket), Kind: kindHere, Person: c.Subject,
		Data: b, ExpiresAt: time.Now().Add(uiHereLife)}); err != nil {
		return "https://" + s.cfg.AdminUI + "/", nil // signed in; the dashboard asks again
	}
	return "https://" + s.cfg.AdminUI + uiHerePath + "?t=" + ticket, nil
}

// hereDone tells a device that waits for a sign-in on its own page (handleLoginStatus) that it
// happened, on whichever control node it waits.
func (s *Server) hereDone(ctx context.Context, p store.Peer, user string) {
	b, _ := json.Marshal(map[string]string{"user": user})
	if err := s.cfg.Store.PutIDState(ctx, store.IDState{Key: hereDoneKey + strconv.FormatInt(p.ID, 10), Kind: kindHere,
		Data: b, ExpiresAt: time.Now().Add(hereDoneLife)}); err != nil {
		s.cfg.Logf("device sign-in of %s: %v", p.Hostname, err)
	}
}

// takeHereDone returns who signed in on the device's own page since the device last asked ("": no one).
func (s *Server) takeHereDone(ctx context.Context, peerID int64) string {
	st, err := s.cfg.Store.TakeIDState(ctx, hereDoneKey+strconv.FormatInt(peerID, 10), time.Now())
	if err != nil {
		return ""
	}
	var d struct {
		User string `json:"user"`
	}
	json.Unmarshal(st.Data, &d)
	if d.User == "" {
		d.User = "?"
	}
	return d.User
}

// uiHere opens the dashboard's session that a sign-in on the device's own page asked for.
func (s *Server) uiHere(w http.ResponseWriter, r *http.Request, device store.Peer) {
	st, err := s.cfg.Store.TakeIDState(r.Context(), uiHereKey+hashToken(r.URL.Query().Get("t")), time.Now())
	var d struct {
		Peer int64 `json:"peer"`
	}
	if err == nil {
		err = json.Unmarshal(st.Data, &d)
	}
	if err != nil || d.Peer != device.ID {
		s.audit(r, &device, "admin_ui_signin", "a ticket of the device's own sign-in that is unknown, used, expired or another device's", "denied")
		uiPage(w, http.StatusBadRequest, "This sign-in expired or was for another device: open the admin page again.")
		return
	}
	if !personSignedIn(device, st.Person) {
		uiPage(w, http.StatusForbidden, "Someone else signed in on this device meanwhile: open the admin page again.")
		return
	}
	if !s.personHasRole(device) {
		s.audit(r, &device, "admin_ui_signin", "signed in on the device as "+device.UserName+", who has no role", "denied")
		uiPage(w, http.StatusForbidden, "This device is signed in as "+device.UserName+", who is neither an admin, an operator nor a viewer.")
		return
	}
	s.openUISession(w, r, device, st.Person, device.UserName)
}

var _ entoid.Here = (*Server)(nil)
