package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
)

// OpenBrowser opens link in a browser of the user who ran the command, best effort; false when it
// could not or would not (the caller then prints it). Control nodes choose these links, so only a
// well-formed https link is ever handed to the system's opener (never a file, another scheme or an
// application handler).
func OpenBrowser(link string) bool { return SafeLink(link) && openBrowser(link) }

// SafeLink reports whether a link from a control node may be opened: https, with a host, without
// user information, in printable ASCII only.
func SafeLink(link string) bool {
	for _, r := range link {
		if r <= ' ' || r >= 0x7f {
			return false
		}
	}
	u, err := url.Parse(link)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Opaque == ""
}

// Printable drops what a terminal could act on (control and formatting characters, which can
// rewrite what is shown) from text a control node or identity provider chose, before printing it.
func Printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
}

// AdminUIURL returns the address of the network's admin interface (for admin and operator devices).
func AdminUIURL(ctx context.Context, cfg Config) (string, error) {
	c, err := ownClient(cfg)
	if err != nil {
		return "", err
	}
	var ui api.AdminUI
	if err := c.Do(ctx, "GET", api.PathAdminUI, nil, &ui); err != nil {
		return "", err
	}
	return ui.URL, nil
}

// ApproveAdminUI opens the session of the admin interface whose page, in a browser on this device,
// shows code. Only the holder of the device's key can: other programs on the device cannot.
func ApproveAdminUI(ctx context.Context, cfg Config, code string) error {
	c, err := ownClient(cfg)
	if err != nil {
		return err
	}
	return c.Do(ctx, "POST", api.PathAdminUI, api.ApproveAdminUIRequest{Code: code}, nil)
}

// ownClient calls the control plane as this device, with its key.
func ownClient(cfg Config) (*AdminClient, error) {
	cfg.defaults()
	st, err := LoadState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	return &AdminClient{Controls: st.Controls, Key: wgtypes.Key(st.PrivateKey)}, nil
}

// LoginFlow is an SSO device login in progress: open Link (the code is UserCode), then Wait.
type LoginFlow struct {
	Link     string
	UserCode string
	c        *AdminClient
	stateDir string
	deadline time.Time
}

// LoginResult is how a login ended.
type LoginResult struct {
	User     string
	Approved bool
}

// StartLogin starts an SSO device login.
func StartLogin(ctx context.Context, cfg Config) (*LoginFlow, error) {
	cfg.defaults()
	st, err := LoadState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	c := &AdminClient{Controls: st.Controls, Key: wgtypes.Key(st.PrivateKey)} // any enrolled peer may sign in
	var start api.LoginStart
	if err := c.Do(ctx, "POST", api.PathLogin, nil, &start); err != nil {
		return nil, err
	}
	// The bare address, never a link with the code in it (an older control node still sends one).
	link := start.VerificationURI
	if link == "" {
		link = start.VerificationURIComplete
	}
	return &LoginFlow{Link: link, UserCode: start.UserCode, c: c, stateDir: cfg.StateDir,
		deadline: time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)}, nil
}

// StartAppLogin starts a sign-in for an app on this device that catches redirect (RFC 8252; 0.56):
// where the control node allows that address, Link is an ordinary sign-in with the identity
// provider that ends in the app (UserCode empty: nothing to type), and the app hands what it
// receives to FinishAppLogin. Elsewhere (an older control node, or the address not allowed) it is
// a device sign-in, as StartLogin's.
func StartAppLogin(ctx context.Context, cfg Config, redirect string) (*LoginFlow, error) {
	cfg.defaults()
	st, err := LoadState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	c := &AdminClient{Controls: st.Controls, Key: wgtypes.Key(st.PrivateKey)}
	var start api.LoginStart
	if err := c.Do(ctx, "POST", api.PathLogin, api.LoginStartRequest{Redirect: redirect}, &start); err != nil {
		return nil, err
	}
	link := start.AuthorizationURL
	if link == "" {
		link = start.VerificationURI
	}
	if link == "" {
		link = start.VerificationURIComplete
	}
	return &LoginFlow{Link: link, UserCode: start.UserCode, c: c, stateDir: cfg.StateDir,
		deadline: time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)}, nil
}

// FinishAppLogin hands the control node what the identity provider sent the app: the address it
// opened (redirect?code=...&state=..., or ?error=...). The sign-in's outcome follows as for any
// other (LoginFlow.Wait).
func FinishAppLogin(ctx context.Context, cfg Config, address string) error {
	u, err := url.Parse(address)
	if err != nil {
		return errors.New("not a sign-in's address")
	}
	q := u.Query()
	req := api.LoginCodeRequest{Code: q.Get("code"), State: q.Get("state"), Error: q.Get("error")}
	if req.State == "" || (req.Code == "" && req.Error == "") {
		return errors.New("not a sign-in's address")
	}
	c, err := ownClient(cfg)
	if err != nil {
		return err
	}
	var s api.LoginStatus
	if err := c.Do(ctx, "POST", api.PathLoginCode, req, &s); err != nil {
		return err
	}
	if s.State == "failed" {
		return fmt.Errorf("sign-in failed: %s", Printable(s.Error))
	}
	return nil
}

// Wait polls until the user has completed the login in a browser, calling tick on every poll.
func (f *LoginFlow) Wait(ctx context.Context, tick func(ok bool)) (LoginResult, error) {
	for time.Now().Before(f.deadline) {
		select {
		case <-ctx.Done():
			return LoginResult{}, ctx.Err()
		case <-time.After(3 * time.Second):
		}
		var s api.LoginStatus
		if err := f.c.Do(ctx, "GET", api.PathLogin, nil, &s); err != nil {
			f.refreshKey()
			if tick != nil {
				tick(false)
			}
			continue
		}
		switch s.State {
		case "done":
			return LoginResult{User: s.User, Approved: s.Approved}, nil
		case "failed":
			return LoginResult{}, fmt.Errorf("login failed: %s", Printable(s.Error))
		}
		if tick != nil {
			tick(true)
		}
	}
	return LoginResult{}, fmt.Errorf("login expired")
}

// refreshKey takes the device's key and control nodes from its state again: the agent changes its
// key daily, and a sign-in that spans the change would otherwise sign every poll with the old key,
// be refused, and wait until it expired although the person had signed in.
func (f *LoginFlow) refreshKey() {
	if f.stateDir == "" {
		return
	}
	if st, err := LoadState(f.stateDir); err == nil && st.PrivateKey != (Key{}) {
		f.c.Key, f.c.Controls = wgtypes.Key(st.PrivateKey), st.Controls
	}
}

// Login starts an SSO device login and waits until the user has completed it in a browser. showQR,
// if set, draws the link for a phone to scan, so the sign-in can be finished on another device (one
// that has the person's security key or passkey); it is called only with a safe link.
func Login(ctx context.Context, cfg Config, out io.Writer, showQR func(link string)) error {
	f, err := StartLogin(ctx, cfg)
	if err != nil {
		return err
	}
	link, code := Printable(f.Link), Printable(f.UserCode)
	switch {
	case !SafeLink(f.Link):
		fmt.Fprintf(out, "The control node sent a sign-in link that is not a plain https link; it was not opened:\n\n    %s\n\nCode: %s", link, code)
	case openBrowser(f.Link):
		fmt.Fprintf(out, "In the browser window that just opened (or at this link), type the code and sign in:\n\n    %s\n\nCode: %s", link, code)
	default:
		fmt.Fprintf(out, "Open this link in a browser, type the code and sign in:\n\n    %s\n\nCode: %s", link, code)
	}
	if showQR != nil && SafeLink(f.Link) {
		showQR(f.Link)
	}
	fmt.Fprint(out, "\n\nWaiting")
	r, err := f.Wait(ctx, func(ok bool) {
		if ok {
			fmt.Fprint(out, ".")
		} else {
			fmt.Fprint(out, "?")
		}
	})
	if err != nil {
		return err
	}
	if r.Approved {
		fmt.Fprintf(out, "\n\nLogged in as %s. This device is approved.\n", Printable(r.User))
	} else {
		fmt.Fprintf(out, "\n\nLogged in as %s, but your groups do not approve devices; ask an administrator.\n", Printable(r.User))
	}
	return nil
}
