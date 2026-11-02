//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

// sessionPipe is the person's channel: open to interactive users (the console's and remote
// desktops'; the agent then answers only the console's), never to the network (the pipe refuses
// remote clients).
const sessionPipe = `\\.\pipe\ento-session`

// sessionSDDL: SYSTEM and Administrators own and control the pipe, interactive users read and
// write. Writing would also let them add instances of it, so a client trusts an answer only from a
// process in session 0 (a service's; no user's program runs there): see sessionDial.
const sessionSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

// serveSessions answers the person's channel until ctx ends (only the agent that holds the
// device's state: the service, or one an administrator runs in a console).
func serveSessions(ctx context.Context, cfg Config) {
	sd, err := windows.SecurityDescriptorFromString(sessionSDDL)
	if err != nil {
		cfg.Logf("person's channel: %v", err)
		return
	}
	l, err := (&namedpipe.ListenConfig{SecurityDescriptor: sd}).Listen(sessionPipe)
	if err != nil {
		cfg.Logf("person's channel: not served (%v): signing in needs an administrator's `ento agent login`", err)
		return
	}
	context.AfterFunc(ctx, func() { l.Close() })
	s := &sessionServer{ops: sessionAgent{cfg: cfg}, logf: cfg.Logf}
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				cfg.Logf("person's channel: %v", err)
			}
			return
		}
		who, console := sessionClient(conn)
		go s.serve(ctx, conn, who, console)
	}
}

// sessionClient names the program at the other end of conn (account, process, session) and
// reports whether it runs in the session at the computer's console.
func sessionClient(conn net.Conn) (string, bool) {
	h, ok := conn.(interface{ Handle() windows.Handle })
	if !ok {
		return "unknown", false
	}
	var pid, session uint32
	if windows.GetNamedPipeClientProcessId(h.Handle(), &pid) != nil || windows.ProcessIdToSessionId(pid, &session) != nil {
		return "unknown", false
	}
	who := fmt.Sprintf("%s (process %d, session %d)", processAccount(pid), pid, session)
	console := windows.WTSGetActiveConsoleSessionId()
	return who, session != 0 && session == console
}

// processAccount is the account process pid runs as, DOMAIN\name, or "unknown".
func processAccount(pid uint32) string {
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "unknown"
	}
	defer windows.CloseHandle(p)
	var tok windows.Token
	if windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok) != nil {
		return "unknown"
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "unknown"
	}
	name, domain, _, err := u.User.Sid.LookupAccount("")
	if err != nil {
		return u.User.Sid.String()
	}
	return domain + `\` + name
}

// sessionDial connects to the person's channel, trusting only a server in session 0: anyone who
// may use the pipe may also open an instance of it, and a program of the person's own posing as
// the agent would otherwise hand them its own sign-in link.
func sessionDial(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := namedpipe.DialContext(ctx, sessionPipe)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, context.DeadlineExceeded) {
			return nil, ErrNoSessionChannel
		}
		return nil, fmt.Errorf("%w: %v", ErrNoSessionChannel, err)
	}
	h, ok := conn.(interface{ Handle() windows.Handle })
	var pid, session uint32
	if !ok || windows.GetNamedPipeServerProcessId(h.Handle(), &pid) != nil ||
		windows.ProcessIdToSessionId(pid, &session) != nil || session != 0 {
		conn.Close()
		return nil, fmt.Errorf("the program answering on %s (process %d) is not the ento service: not trusted", sessionPipe, pid)
	}
	return conn, nil
}
