package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
)

// The admin web interface. Every control node serves it on its overlay address, port 443, for one
// name (Config.AdminUI), with TLS from a certificate for that name (AdminUICert, AdminUIKey, read
// again when the files change). Connections for any other name go on to the identity provider as
// before: the node only reads the name the browser asks for, then passes the connection through.
//
// The TLS connection ends here, so the node knows the calling device by its overlay address, and
// only approved admin and operator devices get answers. The address proves the device, not the
// program on it, so the interface also needs a session of that device: the page shows a code, and
// the session opens when the device approves that code with a call signed with its key
// (`ento admin ui CODE`, or the app). Nothing secret travels outside the page (a link would, on
// command lines other programs can read), and a program without the key cannot get its own page
// approved. A session ends when idle for uiSessionIdle, after uiSessionLifetime, at sign-out, and as
// soon as the device is no longer an approved admin or operator; it opens administration only, never
// sign-in or credentials for linked networks (keyHolder). It is as safe as the browser holding it:
// a program that reads that browser's cookies or memory can use it from the device while it lasts.
// Browsers also make requests on behalf of other web pages; the interface accepts a change only
// with its own header, from its own origin, for its own name (see adminUIHandler).

//go:embed ui
var uiFiles embed.FS

// uiHeader must accompany every change made through the admin interface: a page of another origin
// cannot send it without a CORS preflight, which is never answered.
const uiHeader = "X-Ento-UI"

// uiAutoHeader marks the page's own periodic refresh, which does not keep a session alive.
const uiAutoHeader = "X-Ento-Refresh"

const (
	uiPendingLifetime = 5 * time.Minute  // a page shows its code this long
	uiSessionLifetime = 8 * time.Hour    // an approved session lasts at most this long,
	uiSessionIdle     = 30 * time.Minute // and ends earlier when unused this long
	uiMaxPending      = 20               // pages of one device waiting for approval
	// uiCookie holds the session: __Host- keeps it to this exact name, over https, for every path.
	uiCookie = "__Host-ento-admin"
)

// start443 listens on the node's overlay address, port 443, and hands each connection to the admin
// interface (its name), a forwarded service (its name, Config.Forwards) or to the identity provider
// (every other name, and all of them when there is neither).
func (s *Server) start443(ctx context.Context, idpTargets []string) error {
	ln, err := s.wg.net.ListenTCPAddrPort(netip.AddrPortFrom(s.self.Address, IdentityProviderPort))
	if err != nil {
		return err
	}
	var ui *connListener
	if s.cfg.AdminUI != "" {
		certs := &certFiles{cert: s.cfg.AdminUICert, key: s.cfg.AdminUIKey}
		if _, err := certs.get(nil); err != nil {
			ln.Close()
			return err
		}
		ui = newConnListener(ln.Addr())
		srv := &http.Server{
			Handler:           s.adminUIHandler(),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
			BaseContext:       func(net.Listener) context.Context { return ctx },
		}
		tlsConf := &tls.Config{GetCertificate: certs.get, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
		go func() {
			if err := srv.Serve(tls.NewListener(ui, tlsConf)); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.cfg.Logf("admin interface: %v", err)
			}
		}()
		go func() {
			<-ctx.Done()
			srv.Close()
		}()
		s.cfg.Logf("admin interface on https://%s (%s:443)", s.cfg.AdminUI, s.self.Address)
	}
	var idLn *connListener
	if s.id != nil && !s.cfg.ID.Disabled {
		certs := &certFiles{cert: s.cfg.ID.Cert, key: s.cfg.ID.CertKey}
		if _, err := certs.get(nil); err != nil {
			ln.Close()
			return fmt.Errorf("identity provider's certificate: %w", err)
		}
		idLn = newConnListener(ln.Addr())
		srv := &http.Server{
			Handler:           s.id.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
			BaseContext:       func(net.Listener) context.Context { return ctx },
		}
		tlsConf := &tls.Config{GetCertificate: certs.get, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
		go func() {
			if err := srv.Serve(tls.NewListener(idLn, tlsConf)); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.cfg.Logf("identity provider: %v", err)
			}
		}()
		go func() {
			<-ctx.Done()
			srv.Close()
		}()
		s.cfg.Logf("identity provider on https://%s (%s:443)", s.cfg.ID.Name, s.self.Address)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.dispatch443(ctx, c, idpTargets, ui, idLn)
		}
	}()
	return nil
}

func (s *Server) dispatch443(ctx context.Context, c net.Conn, idpTargets []string, ui, idLn *connListener) {
	if ui == nil && idLn == nil && len(s.cfg.Forwards) == 0 {
		s.forwardIdentity(ctx, c, idpTargets)
		return
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	name, replay, err := peekServerName(c)
	c.SetReadDeadline(time.Time{})
	targets := s.cfg.Forwards[strings.ToLower(name)]
	switch {
	case err != nil:
		c.Close()
	case ui != nil && strings.EqualFold(name, s.cfg.AdminUI):
		// Other devices do not even get the interface's certificate: their connection ends here,
		// before TLS, so for them it is not there. The device sign-in shares the name and serves
		// every device, so with it they still get the plain 403 of adminUIHandler.
		if s.cfg.SignIn == nil && !s.isAdminAddr(ctx, c.RemoteAddr()) {
			c.Close()
			return
		}
		if !ui.push(replay) {
			c.Close()
		}
	case idLn != nil && isIDName(s.cfg.ID, name):
		s.serveID(ctx, replay, idLn)
	case len(targets) > 0:
		s.passThrough(ctx, replay, targets, "forward_connection", name, name, s.cfg.ForwardPeople[strings.ToLower(name)])
	case len(idpTargets) > 0:
		s.forwardIdentity(ctx, replay, idpTargets)
	default:
		c.Close()
	}
}

var errPeeked = errors.New("server name read")

// peekServerName reads the TLS ClientHello of c for the server name it asks for, and returns a
// connection that replays what was read, so the handshake can still happen (here or upstream).
func peekServerName(c net.Conn) (string, net.Conn, error) {
	var seen bytes.Buffer
	var name string
	hello := false
	err := tls.Server(readOnlyConn{Conn: c, r: io.TeeReader(c, &seen)}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			name, hello = h.ServerName, true
			return nil, errPeeked
		},
	}).Handshake()
	if !hello {
		return "", nil, err
	}
	return name, &replayConn{Conn: c, r: io.MultiReader(&seen, c)}, nil
}

// readOnlyConn lets crypto/tls read a ClientHello without answering it.
type readOnlyConn struct {
	net.Conn
	r io.Reader
}

func (c readOnlyConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c readOnlyConn) Write(p []byte) (int, error) { return len(p), nil }

// replayConn returns what was already read before continuing with the connection.
type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// connListener is a net.Listener fed with connections accepted elsewhere.
type connListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newConnListener(addr net.Addr) *connListener {
	return &connListener{addr: addr, ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *connListener) push(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.done:
		return false
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *connListener) Addr() net.Addr { return l.addr }

// certFiles serves a certificate from files, loading them again when the certificate file changes
// (checked at most once a minute), so a renewal needs no restart.
type certFiles struct {
	cert, key string
	mu        sync.Mutex
	current   *tls.Certificate
	modTime   time.Time
	checked   time.Time
}

func (f *certFiles) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current != nil && time.Since(f.checked) < time.Minute {
		return f.current, nil
	}
	f.checked = time.Now()
	fi, err := os.Stat(f.cert)
	if err != nil {
		if f.current != nil {
			return f.current, nil
		}
		return nil, err
	}
	if f.current != nil && fi.ModTime().Equal(f.modTime) {
		return f.current, nil
	}
	c, err := tls.LoadX509KeyPair(f.cert, f.key)
	if err != nil {
		if f.current != nil {
			return f.current, nil // keep serving the previous one
		}
		return nil, err
	}
	f.current, f.modTime = &c, fi.ModTime()
	return f.current, nil
}

// adminUIHandler serves the interface's files and the admin API, for its own name only, and accepts
// changes only from the interface itself.
func (s *Server) adminUIHandler() http.Handler {
	routes := s.routes()
	files, _ := fs.Sub(uiFiles, "ui")
	static := http.FileServer(http.FS(files))
	origin := "https://" + s.cfg.AdminUI
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		host := r.Host
		if hp, err := netip.ParseAddrPort(host); err == nil {
			host = hp.Addr().String()
		} else if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host[i:], "]") {
			host = host[:i]
		}
		if !strings.EqualFold(host, s.cfg.AdminUI) {
			writeErr(w, http.StatusMisdirectedRequest, "unknown name")
			return
		}
		// The device sign-in provider answers every device (and the identity provider's server): it
		// decides itself whom it vouches for.
		if s.isSignInPath(r.URL.Path) {
			s.serveSignIn(w, r)
			return
		}
		// Only approved admin and operator devices get anything, the page itself included: every
		// enrolled device reaches the control nodes (it must, to sign in), but others have no business
		// here. The API behind it limits operators.
		device, ok := s.adminDevice(r)
		if !ok {
			h.Set("Cache-Control", "no-store")
			h.Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, "This device is not an administrator of this network.\n")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get(uiHeader) != "1" ||
				(r.Header.Get("Origin") != "" && r.Header.Get("Origin") != origin) ||
				(r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin") {
				writeErr(w, http.StatusForbidden, "changes are accepted from the admin interface only")
				return
			}
		}
		if r.URL.Path == uiSignInPath || r.URL.Path == uiCallbackPath || r.URL.Path == uiHerePath {
			h.Set("Cache-Control", "no-store")
			if r.Method != http.MethodGet {
				writeErr(w, http.StatusMethodNotAllowed, "GET")
				return
			}
			switch r.URL.Path {
			case uiSignInPath:
				s.uiSignIn(w, r, device)
			case uiHerePath:
				s.uiHere(w, r, device)
			default:
				s.uiCallback(w, r, device)
			}
			return
		}
		if r.URL.Path == "/ui/session" {
			h.Set("Cache-Control", "no-store")
			switch r.Method {
			case http.MethodGet:
				s.uiSessionState(w, r, device)
			case http.MethodPost:
				s.uiPair(w, r, device)
			case http.MethodDelete:
				s.uiSignOut(w, r, device)
			default:
				writeErr(w, http.StatusMethodNotAllowed, "GET, POST or DELETE")
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			h.Set("Cache-Control", "no-store")
			u, ok := s.uiSession(r, device)
			if !ok {
				writeErr(w, http.StatusUnauthorized, "no session: approve this page from this device (ento admin ui CODE)")
				return
			}
			routes.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), uiSessionKey{}, uiCaller{device: device.ID, person: u.Person})))
			return
		}
		// Browsers ask again every time (an open page from an older control plane kept its old
		// script), and the page carries the version that served it: it tells the person when the
		// control plane runs another one.
		h.Set("Cache-Control", "no-cache")
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			s.serveIndex(w)
			return
		}
		static.ServeHTTP(w, r)
	})
}

// isAdminAddr reports whether a connection comes from a device that may open the interface.
func (s *Server) isAdminAddr(ctx context.Context, a net.Addr) bool {
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return false
	}
	p, err := s.cfg.Store.PeerByAddress(ctx, ap.Addr().Unmap())
	return err == nil && s.mayOpenInterface(p)
}

// mayOpenInterface: devices that may administer, and approved devices in admin or operator, whose
func (s *Server) mayOpenInterface(p store.Peer) bool {
	return s.mayAdminister(p) || (p.Machine.Admin || p.Machine.Operator) && p.Approved && !p.Suspended && !isolated(p)
}

// mayAdminister: approved admin and operator devices, and viewers (read-only).
func (s *Server) mayAdminister(p store.Peer) bool {
	p = s.withRoles(p)
	return (p.Admin || p.Operator) && p.Approved && !isolated(p) || s.isViewer(p)
}

// adminDevice returns the device the request comes from if it may open the interface, known by its
// overlay address (the connection ends here, inside WireGuard).
func (s *Server) adminDevice(r *http.Request) (store.Peer, bool) {
	addr, ok := caller(r)
	if !ok {
		return store.Peer{}, false
	}
	p, err := s.cfg.Store.PeerByAddress(r.Context(), addr.Unmap())
	return p, err == nil && s.mayOpenInterface(p)
}

// uiSecret returns a new random secret and the hash it is stored by.
func uiSecret() (secret, hash string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	secret = base64.RawURLEncoding.EncodeToString(b[:])
	return secret, uiHash(secret), nil
}

func uiHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// uiCodeAlphabet has no letters or digits that are easily confused (0/O, 1/I/L).
const uiCodeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

// newUICode returns a code to show on a page, like "K7QM-4TZP". It identifies the page among the
// device's pending ones; it is no secret (approving it takes the device's key).
func newUICode() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	out := make([]byte, 0, 9)
	for i, c := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, uiCodeAlphabet[int(c)%len(uiCodeAlphabet)])
	}
	return string(out), nil
}

// normalUICode brings a typed code to the shown form: upper case, any separators.
func normalUICode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if strings.ContainsRune(uiCodeAlphabet, r) {
			b.WriteRune(r)
		}
	}
	c := b.String()
	if len(c) != 8 {
		return ""
	}
	return c[:4] + "-" + c[4:]
}

// uiState is what the page learns about its session.
type uiState struct {
	State     string `json:"state"` // "none", "pending" (show Code until ExpiresAt), "open"
	Code      string `json:"code,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	// SignIn: the page can also open its session by signing in (/ui/signin, 0.49); Person, who is
	// signed in on the device in ento (the one who may). Here: that sign-in is the device's own
	// (here.go, 0.57), which signs anyone in on the device first, so Person need not be there.
	SignIn bool   `json:"sign_in,omitempty"`
	Person string `json:"person,omitempty"`
	Here   bool   `json:"here,omitempty"`
}

// uiCurrent returns the session the request's cookie names, if it is this device's and alive.
func (s *Server) uiCurrent(r *http.Request, device store.Peer, now time.Time) (store.UISession, bool) {
	c, err := r.Cookie(uiCookie)
	if err != nil || c.Value == "" {
		return store.UISession{}, false
	}
	u, err := s.cfg.Store.UISession(r.Context(), uiHash(c.Value), now)
	if err != nil || u.PeerID != device.ID || (u.Approved && now.Sub(u.LastUsed) > uiSessionIdle) {
		return store.UISession{}, false
	}
	// Opened by signing in: it lasts only while that person is signed in on the device in ento.
	if u.Person != "" && !personSignedIn(device, u.Person) {
		return store.UISession{}, false
	}
	return u, true
}

func uiStateOf(u store.UISession) uiState {
	if u.Approved {
		return uiState{State: "open"}
	}
	return uiState{State: "pending", Code: u.Code, ExpiresAt: u.ExpiresAt.UTC().Format(time.RFC3339)}
}

// uiPair gives the page a pending session showing a code (or the one it already has): it opens
// when the device approves the code with a call signed with its key (ento admin ui CODE), so no
// program on the device without the key can open one, and no secret ever leaves the page.
func (s *Server) uiPair(w http.ResponseWriter, r *http.Request, device store.Peer) {
	now := time.Now()
	if u, ok := s.uiCurrent(r, device, now); ok {
		writeJSON(w, http.StatusOK, s.withSignIn(uiStateOf(u), device))
		return
	}
	if n, err := s.cfg.Store.PendingUISessions(r.Context(), device.ID, now); err != nil {
		s.respondStoreErr(w, err)
		return
	} else if n >= uiMaxPending {
		writeErr(w, http.StatusTooManyRequests, "too many pages of this device wait for approval: approve or close them")
		return
	}
	secret, hash, err := uiSecret()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	u := store.UISession{Hash: hash, PeerID: device.ID, Browser: browserName(r.UserAgent()), CreatedAt: now,
		ExpiresAt: now.Add(uiPendingLifetime), LastUsed: now}
	for range 3 { // a code already shown on another page of the device: draw again
		if u.Code, err = newUICode(); err != nil {
			break
		}
		if err = s.cfg.Store.CreateUISession(r.Context(), u); !errors.Is(err, store.ErrExists) {
			break
		}
	}
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	// A browser session cookie: gone when the browser closes, never readable by scripts.
	http.SetCookie(w, &http.Cookie{Name: uiCookie, Value: secret, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, s.withSignIn(uiStateOf(u), device))
}

// browserName keeps a User-Agent to printable ASCII, short enough for a terminal line.
func browserName(ua string) string {
	ua = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, ua)
	if len(ua) > 120 {
		ua = ua[:120]
	}
	return ua
}

// uiSessionState tells the page whether its session is pending (and its code) or open.
func (s *Server) uiSessionState(w http.ResponseWriter, r *http.Request, device store.Peer) {
	u, ok := s.uiCurrent(r, device, time.Now())
	if !ok {
		writeJSON(w, http.StatusOK, s.withSignIn(uiState{State: "none"}, device))
		return
	}
	writeJSON(w, http.StatusOK, s.withSignIn(uiStateOf(u), device))
}

// uiSignOut ends the session.
func (s *Server) uiSignOut(w http.ResponseWriter, r *http.Request, device store.Peer) {
	if c, err := r.Cookie(uiCookie); err == nil {
		if err := s.cfg.Store.DeleteUISession(r.Context(), uiHash(c.Value)); err != nil {
			s.respondStoreErr(w, err)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{Name: uiCookie, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
	s.audit(r, &device, "admin_ui_signout", peerLabel(device), "ok")
	w.WriteHeader(http.StatusNoContent)
}

// uiSession reports whether the request carries an open session of the device it comes from, and
// records its use (at most once a minute: the idle limit counts from there). The page's own
// periodic refresh (uiAutoHeader) is not use: an open tab nobody looks at still goes idle.
func (s *Server) uiSession(r *http.Request, device store.Peer) (store.UISession, bool) {
	now := time.Now()
	u, ok := s.uiCurrent(r, device, now)
	if !ok || !u.Approved {
		return u, false
	}
	if r.Header.Get(uiAutoHeader) == "" && now.Sub(u.LastUsed) > time.Minute {
		if err := s.cfg.Store.TouchUISession(r.Context(), u.Hash, now); err != nil {
			s.cfg.Logf("admin interface session: %v", err)
		}
	}
	return u, true
}

// handleAdminUI (signed): the admin interface's address, for the command line and the apps to open.
func (s *Server) handleAdminUI(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.cfg.AdminUI == "" {
		writeErr(w, http.StatusNotFound, "this network has no admin interface")
		return
	}
	writeJSON(w, http.StatusOK, api.AdminUI{URL: "https://" + s.cfg.AdminUI + "/"})
}

// handleApproveAdminUI (signed): opens the session of the admin interface that a browser on the
// calling device shows the code of.
func (s *Server) handleApproveAdminUI(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.cfg.AdminUI == "" {
		writeErr(w, http.StatusNotFound, "this network has no admin interface")
		return
	}
	var req api.ApproveAdminUIRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	code := normalUICode(req.Code)
	if code == "" {
		writeErr(w, http.StatusBadRequest, "the code has 8 letters and digits, like K7QM-4TZP")
		return
	}
	now := time.Now()
	u, err := s.cfg.Store.ApproveUISession(r.Context(), self.ID, code, now, now.Add(uiSessionLifetime))
	if errors.Is(err, store.ErrNotFound) {
		s.audit(r, &self, "admin_ui_session", "code "+code+": no page of this device shows it", "denied")
		writeErr(w, http.StatusNotFound, "no admin page on this device shows this code (each one is valid for 5 minutes)")
		return
	}
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "admin_ui_session", peerLabel(self), "ok")
	writeJSON(w, http.StatusOK, api.ApprovedAdminUI{URL: "https://" + s.cfg.AdminUI + "/",
		OpenedAt: u.CreatedAt.UTC().Format(time.RFC3339), Browser: u.Browser})
}

// noBrowsers keeps browsers away from the plain API (port 80): agents and the command line never
// send these headers, while every browser request carries at least one. Without it, any web page
// open on an admin device could make that device call the admin API.
//
// A page a browser opens by name (someone typed http://net.example.com, or a browser that never
// visited tried http first) is sent to the same address over https instead: a redirect carries
// nothing and calls nothing.
func noBrowsers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.Header.Get("Sec-Fetch-Mode") == "navigate" &&
			r.Header.Get("Origin") == "" && r.Host != "" {
			// Names only: an address has no certificate to match, and nothing odd is echoed back.
			host, _, _ := strings.Cut(r.Host, ":")
			_, isAddr := netip.ParseAddr(strings.Trim(host, "[]"))
			if isAddr != nil && host != "" && !strings.ContainsAny(host, "/\\@[]") {
				http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
				return
			}
		}
		if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" || r.Header.Get("Sec-Fetch-Mode") != "" {
			writeErr(w, http.StatusForbidden, "browsers use the admin interface, not the API")
			return
		}
		// Agents call a control node by its address. A name here is a browser that sends no fetch
		// metadata (an older one) on a page whose name was rebound to this address (DNS rebinding):
		// refused, as is a body that is not JSON (what such a page can send without asking first).
		if !hostIsAddress(r.Host) {
			writeErr(w, http.StatusForbidden, "the API answers on its addresses only")
			return
		}
		if r.ContentLength != 0 {
			if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
				writeErr(w, http.StatusUnsupportedMediaType, "the API takes JSON only")
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		h.ServeHTTP(w, r)
	})
}

// maxRequestBody bounds what one call to the plain API may send (the largest are policy and posture
// check definitions, a few kilobytes).
const maxRequestBody = 1 << 20

// hostIsAddress reports whether a Host header names an IP address (with or without a port).
func hostIsAddress(h string) bool {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	_, err := netip.ParseAddr(strings.Trim(h, "[]"))
	return err == nil
}

// serveIndex serves the page with the control node's version: in a meta tag the script compares with
// the control plane's, and on the script and style sheet, so a new version is fetched anew.
func (s *Server) serveIndex(w http.ResponseWriter) {
	b, err := fs.ReadFile(uiFiles, "ui/index.html")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	v := url.QueryEscape(s.cfg.Version)
	page := strings.NewReplacer(
		`<meta charset="utf-8">`, `<meta charset="utf-8">`+"\n"+`<meta name="ento-version" content="`+html.EscapeString(s.cfg.Version)+`">`,
		`href="app.css"`, `href="app.css?v=`+v+`"`,
		`src="app.js"`, `src="app.js?v=`+v+`"`,
	).Replace(string(b))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, page)
}
