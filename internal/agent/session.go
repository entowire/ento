package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// The person's channel (0.35, Windows): what the person at the device may ask the running agent
// without holding the device's key, which only the service and administrators can read. They sign
// in (the agent runs the device login, the person finishes it in their browser), sign out, and see
// whether their session is open. The CLI uses it when it is not elevated, and the tray program
// always. Each request is one JSON line; the agent answers with one or more JSON lines and closes.
// Nothing here acts on the network beyond what the person could do with an administrator's
// `ento agent login|logout`, and a sign-in still needs the person's own credentials at the
// identity provider.

// SessionRequest asks the agent for one thing: Op is "status", "login" or "logout".
type SessionRequest struct {
	Op string `json:"op"`
}

// SessionReply is one line of the agent's answer. Event says which: "status" (the session as the
// agent knows it), "link" (a sign-in started: open Link, the provider shows Code), "done" (signed
// in as User; Approved: the person's groups approve devices), "logout" (Delivered: the control
// plane was told; otherwise the agent tells it when it can) or "error" (Error says why).
type SessionReply struct {
	Event         string `json:"event"`
	User          string `json:"user,omitempty"`
	UserName      string `json:"user_name,omitempty"`
	SessionActive bool   `json:"session_active,omitempty"`
	LoginRequired bool   `json:"login_required,omitempty"`
	Version       string `json:"version,omitempty"`
	Link          string `json:"link,omitempty"`
	Code          string `json:"code,omitempty"`
	Approved      bool   `json:"approved,omitempty"`
	Delivered     bool   `json:"delivered,omitempty"`
	Error         string `json:"error,omitempty"`
}

// ErrNoSessionChannel: no agent answers on the person's channel here (not Windows, the agent not
// running, or one older than 0.35).
var ErrNoSessionChannel = errors.New("the agent's session channel is not available")

// SessionDo sends op to the running agent and passes each line of its answer to each, until the
// agent closes the channel, each returns an error or ctx ends. A reply with Event "error" ends it
// with that error.
func SessionDo(ctx context.Context, op string, each func(SessionReply) error) error {
	conn, err := sessionDial(ctx)
	if err != nil {
		return err
	}
	return sessionExchange(ctx, conn, op, each)
}

// sessionExchange is SessionDo on a connection already made.
func sessionExchange(ctx context.Context, conn net.Conn, op string, each func(SessionReply) error) error {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := json.NewEncoder(conn).Encode(SessionRequest{Op: op}); err != nil {
		return err
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		var r SessionReply
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return fmt.Errorf("the agent's answer: %w", err)
		}
		if r.Event == "error" {
			return errors.New(Printable(r.Error))
		}
		if err := each(r); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return sc.Err()
}

// SessionStatus asks the running agent whether the person's session is open.
func SessionStatus(ctx context.Context) (SessionReply, error) {
	var st SessionReply
	err := SessionDo(ctx, "status", func(r SessionReply) error {
		if r.Event == "status" {
			st = r
		}
		return nil
	})
	return st, err
}

// LoginViaAgent signs the person in through the running agent, as Login does with the device's
// key: the agent starts the sign-in, this opens the link in the person's browser and waits.
func LoginViaAgent(ctx context.Context, out io.Writer, showQR func(link string)) error {
	return SessionDo(ctx, "login", func(r SessionReply) error {
		switch r.Event {
		case "link":
			link, code := Printable(r.Link), Printable(r.Code)
			switch {
			case !SafeLink(r.Link):
				fmt.Fprintf(out, "The control node sent a sign-in link that is not a plain https link; it was not opened:\n\n    %s\n\nCode: %s", link, code)
			case openBrowser(r.Link):
				fmt.Fprintf(out, "In the browser window that just opened (or at this link), type the code and sign in:\n\n    %s\n\nCode: %s", link, code)
			default:
				fmt.Fprintf(out, "Open this link in a browser, type the code and sign in:\n\n    %s\n\nCode: %s", link, code)
			}
			if showQR != nil && SafeLink(r.Link) {
				showQR(r.Link)
			}
			fmt.Fprint(out, "\n\nWaiting...")
		case "done":
			if r.Approved {
				fmt.Fprintf(out, "\n\nLogged in as %s. This device is approved.\n", Printable(r.User))
			} else {
				fmt.Fprintf(out, "\n\nLogged in as %s, but your groups do not approve devices; ask an administrator.\n", Printable(r.User))
			}
		}
		return nil
	})
}

// LogoutViaAgent signs the person out through the running agent.
func LogoutViaAgent(ctx context.Context) (delivered bool, err error) {
	err = SessionDo(ctx, "logout", func(r SessionReply) error {
		if r.Event == "logout" {
			delivered = r.Delivered
		}
		return nil
	})
	return delivered, err
}

// sessionOps is what the channel's requests do; the agent's are sessionAgent's.
type sessionOps interface {
	status() SessionReply
	// startLogin starts a sign-in: the link to open, the code it shows, and how to wait for it.
	startLogin(ctx context.Context) (link, code string, wait func(context.Context) (LoginResult, error), err error)
	logout(ctx context.Context) (bool, error)
}

// sessionAgent answers the channel with the running agent's state and key.
type sessionAgent struct {
	cfg Config
}

func (s sessionAgent) status() SessionReply {
	r, _ := RunningAgent(s.cfg.StateDir)
	return SessionReply{Event: "status", User: r.User, UserName: r.UserName, Version: r.Version,
		SessionActive: r.User != "" && !r.LoginRequired && r.PersonActive, LoginRequired: r.LoginRequired}
}

func (s sessionAgent) startLogin(ctx context.Context) (string, string, func(context.Context) (LoginResult, error), error) {
	f, err := StartLogin(ctx, s.cfg)
	if err != nil {
		return "", "", nil, err
	}
	return f.Link, f.UserCode, func(ctx context.Context) (LoginResult, error) { return f.Wait(ctx, nil) }, nil
}

func (s sessionAgent) logout(ctx context.Context) (bool, error) {
	return Logout(ctx, s.cfg, 5*time.Second)
}

// sessionServer serves the channel. One sign-in runs at a time: a new one ends the one before
// (its link is no longer of use to anyone once the person asked again).
type sessionServer struct {
	ops  sessionOps
	logf func(string, ...any)

	mu          sync.Mutex
	cancelLogin context.CancelFunc
}

// serve answers one connection from who (as the system names the person, for the log). Only a
// program of the person at the computer's screen may act (sign in or out); others may ask.
func (s *sessionServer) serve(ctx context.Context, conn net.Conn, who string, mayAct bool) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(conn, 4096)).ReadBytes('\n')
	if err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	var req SessionRequest
	enc := json.NewEncoder(conn)
	reply := func(r SessionReply) bool {
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return enc.Encode(r) == nil
	}
	if json.Unmarshal(line, &req) != nil {
		reply(SessionReply{Event: "error", Error: "not a request"})
		return
	}
	// The person closing the window (or the tray program) ends a sign-in it waits for.
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		cancel()
	}()
	if req.Op != "status" && !mayAct {
		s.logf("person's channel: %s refused for %s (not the session at the computer's screen)", Printable(req.Op), who)
		reply(SessionReply{Event: "error", Error: "only the person at this computer's screen can sign in or out here; from a remote session, use ento agent login in an administrator's PowerShell"})
		return
	}
	switch req.Op {
	case "status":
		reply(s.ops.status())
	case "logout":
		s.logf("person's channel: sign-out asked by %s", who)
		delivered, err := s.ops.logout(ctx)
		if err != nil {
			reply(SessionReply{Event: "error", Error: err.Error()})
			return
		}
		reply(SessionReply{Event: "logout", Delivered: delivered})
	case "login":
		s.login(ctx, who, reply)
	default:
		reply(SessionReply{Event: "error", Error: "unknown request " + Printable(req.Op)})
	}
}

func (s *sessionServer) login(ctx context.Context, who string, reply func(SessionReply) bool) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	s.mu.Lock()
	if s.cancelLogin != nil {
		s.cancelLogin()
	}
	s.cancelLogin = cancel
	s.mu.Unlock()
	s.logf("person's channel: sign-in asked by %s", who)
	link, code, wait, err := s.ops.startLogin(ctx)
	if err != nil {
		reply(SessionReply{Event: "error", Error: "the sign-in could not start: " + err.Error()})
		return
	}
	if !reply(SessionReply{Event: "link", Link: link, Code: code}) {
		return
	}
	r, err := wait(ctx)
	switch {
	case err != nil && ctx.Err() != nil:
		reply(SessionReply{Event: "error", Error: "the sign-in was ended (asked again, or the window closed)"})
	case err != nil:
		reply(SessionReply{Event: "error", Error: err.Error()})
	default:
		s.logf("person's channel: signed in as %s (asked by %s)", Printable(r.User), who)
		reply(SessionReply{Event: "done", User: r.User, Approved: r.Approved})
	}
}
