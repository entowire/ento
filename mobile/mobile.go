// Package mobile is ento's agent for mobile apps (gomobile bind): the app's VPN service creates the
// TUN interface with the device's address and routes and hands its file descriptor to Start. Only
// simple types cross the boundary; structured answers are JSON strings.
//go:build linux

package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"entowire.com/ento/internal/agent"
	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/token"
)

// Version is ento's version, set at build time.
var version = "dev"

// Version returns the version of the agent inside the app.
func Version() string { return version }

func cfg(stateDir, hostname string) agent.Config {
	return agent.Config{Version: version, StateDir: stateDir, Hostname: hostname, Userspace: true, Quiet: true,
		Logf: agentLogf}
}

// Enroll redeems an enrollment token (ento1:...) with a network stack inside the app: no VPN
// permission needed yet. It does nothing if already enrolled.
func Enroll(stateDir, token, hostname string) (err error) {
	defer plain(&err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, err = agent.EnrollInProcess(ctx, cfg(stateDir, hostname), token)
	return err
}

// LookupRecord finds a domain's network record (_ento.<domain>), for enrollment by words, asking
// the phone's DNS servers (comma-separated: Go's resolver cannot find Android's by itself). It
// returns {"record", "fingerprint", "network", "endpoints"}: show the fingerprint, which the
// administrator can confirm, then pass the record to EnrollWords.
func LookupRecord(domain, dnsServers string) (_ string, err error) {
	defer plain(&err)
	var servers []string
	for _, s := range strings.Split(dnsServers, ",") {
		if s = strings.TrimSpace(s); s != "" {
			servers = append(servers, s)
		}
	}
	var r *net.Resolver
	if len(servers) > 0 {
		r = agent.ResolverVia(servers)
	}
	text, err := agent.LookupRecord(context.Background(), domain, r)
	if err != nil {
		return "", err
	}
	rec, err := token.ParseRecord(text)
	if err != nil {
		return "", err
	}
	var eps []string
	for _, c := range rec.Controls {
		eps = append(eps, c.Endpoint)
	}
	b, _ := json.Marshal(map[string]any{"record": text, "fingerprint": rec.Fingerprint(), "network": rec.Network.String(), "endpoints": eps})
	return string(b), nil
}

// ParseJoinCode reads what an enrollment QR code holds (an administrator's admin page or `ento
// admin token --words --qr` shows it): {"domain", "fingerprint", "words"}. Look the domain's record
// up (LookupRecord), refuse it unless its fingerprint is the code's, then EnrollWords.
func ParseJoinCode(text string) (_ string, err error) {
	defer plain(&err)
	j, err := token.ParseJoinCode(text)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]string{"domain": j.Domain, "fingerprint": j.Fingerprint, "words": strings.Join(j.Words, " ")})
	return string(b), nil
}

// EnrollWords enrolls with the words an administrator read out (any case, any separator), in the
// network of record (as LookupRecord returned it). The words are stretched with Argon2id (256 MiB,
// a few seconds on a phone): call it off the main thread.
func EnrollWords(stateDir, record, words, hostname string) (err error) {
	defer plain(&err)
	tok, err := agent.WordsToken(record, words)
	if err != nil {
		return err
	}
	return Enroll(stateDir, tok, hostname)
}

// Network is what the VPN service needs to create the interface: {"address", "prefix_bits",
// "network", "mtu"}, or "" when not enrolled.
func Network(stateDir string) string {
	st, err := agent.LoadState(stateDir)
	if err != nil {
		return ""
	}
	b, _ := json.Marshal(map[string]any{"address": st.Address.String(), "prefix_bits": st.Network.Bits(),
		"network": st.Network.Masked().String(), "mtu": 1380})
	return string(b)
}

var (
	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	lastErr string
)

// SocketProtector exempts a socket from the VPN; Android's VpnService.protect(int) implements it.
type SocketProtector interface {
	Protect(fd int32) bool
}

// Start runs the agent on the TUN interface whose file descriptor fd the VPN service established
// (the agent owns it from now on), until Stop. WireGuard's own sockets are given to p.
func Start(stateDir string, fd int32, hostname string, p SocketProtector) (err error) {
	defer plain(&err)
	mu.Lock()
	defer mu.Unlock()
	if cancel != nil {
		return fmt.Errorf("already running")
	}
	t, _, err := tun.CreateUnmonitoredTUNFromFD(int(fd))
	if err != nil {
		writeLog("agent", "start: "+err.Error())
		return err
	}
	writeLog("agent", "starting on the VPN interface")
	ctx, c := context.WithCancel(context.Background())
	cancel, done, lastErr = c, make(chan struct{}), ""
	go func() {
		defer close(done)
		err := agent.RunOnTUN(ctx, cfg(stateDir, hostname), t, func(fd int) bool { return p.Protect(int32(fd)) })
		switch {
		case err != nil && ctx.Err() == nil:
			writeLog("agent", "stopped: "+err.Error())
			mu.Lock()
			lastErr = err.Error()
			mu.Unlock()
		default:
			writeLog("agent", "stopped")
		}
	}()
	return nil
}

// Stop ends the agent (the VPN service then closes its interface).
func Stop() {
	mu.Lock()
	c, d := cancel, done
	cancel = nil
	mu.Unlock()
	if c != nil {
		c()
		<-d
	}
}

// SetPosture gives the agent what only the app can read about the device, as JSON:
// {"os_version": "14", "sdk": 34, "patch_level": "2026-09-05", "disk_encryption": true,
// "screen_lock": true}. Fields left out stay unknown. The agent reports them with the rest of the
// device's posture.
func SetPosture(facts string) (err error) {
	defer plain(&err)
	var in struct {
		OSVersion      string `json:"os_version"`
		SDK            int    `json:"sdk"`
		PatchLevel     string `json:"patch_level"`
		DiskEncryption *bool  `json:"disk_encryption"`
		ScreenLock     *bool  `json:"screen_lock"`
		MachineID      string `json:"machine_id"` // ANDROID_ID, for the check-ins' fingerprint
	}
	if err := json.Unmarshal([]byte(facts), &in); err != nil {
		return err
	}
	p := api.Posture{OSVersion: in.OSVersion, PatchLevel: in.PatchLevel, DiskEncryption: in.DiskEncryption, ScreenLock: in.ScreenLock}
	if in.SDK > 0 {
		p.Distribution = fmt.Sprintf("SDK %d", in.SDK)
	}
	agent.SetExternalPosture(p)
	if in.MachineID != "" {
		agent.SetAppMachineID(in.MachineID)
	}
	return nil
}

// Attestor attests the phone (Android key attestation): Attest returns, as JSON {"chain": [base64
// DER, leaf first, ...], "signature": base64}, the certificate chain of a key the Keystore made in
// the phone's secure hardware with challenge as its attestation challenge, and that key's
// signature (SHA256withECDSA) of message. The app keeps the key while the challenge is the same.
type Attestor interface {
	Attest(challenge []byte, message []byte) (string, error)
}

// SetAttestor makes the agent's posture reports carry the phone's attestation, which the control
// nodes verify (verified boot, patch levels: what the hardware says, not the app).
func SetAttestor(a Attestor) {
	agent.SetAttestor(func(challenge, message []byte) ([][]byte, []byte, error) {
		out, err := a.Attest(challenge, message)
		if err != nil {
			return nil, nil, err
		}
		var res struct {
			Chain     [][]byte `json:"chain"`
			Signature []byte   `json:"signature"`
		}
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			return nil, nil, fmt.Errorf("attestation unreadable: %v", err)
		}
		if len(res.Chain) == 0 || len(res.Signature) == 0 {
			return nil, nil, fmt.Errorf("attestation without a chain or a signature")
		}
		return res.Chain, res.Signature, nil
	})
}

// Status describes the device and the running agent as JSON: {"enrolled", "address", "running",
// "login_required", "error", "peers": [{"endpoint", "handshake_seconds_ago", "rx", "tx"}]}, and
// once the network map arrived "approved", "groups", "administers" (an admin or operator device),
// "routes" (the networks the VPN routes, 0.0.0.0/0 while an exit is in use), "exits" (offered:
// [{"route", "via", "default", "in_use"}]), "exit" (the one in use, "" for none) and "dns" (the
// DNS server the VPN names, the agent's resolver, "" for none);
// once the agent reported its posture "posture" (a summary), "posture_failing" (the checks the
// device fails: [{"check", "reason"}]) and "attested" (what the control plane found in the
// phone's attestation, api.Attested; absent when it sent none).
func Status(stateDir string) string {
	out := map[string]any{"enrolled": false, "version": version}
	if st, err := agent.LoadState(stateDir); err == nil {
		out["enrolled"] = true
		out["address"] = st.Address.String()
	}
	peers, running, loginRequired := agent.InProcessPeers()
	out["running"] = running
	out["login_required"] = loginRequired
	if self, ok := agent.InProcessSelf(); ok {
		out["approved"] = self.Approved
		out["groups"] = self.Groups
		out["administers"] = self.Approved && (self.Admin || self.Operator)
		out["user"] = self.User // the person the phone is signed in as ("" for none)
		out["routes"] = agent.InProcessRoutes()
		out["exits"] = agent.InProcessExits()
		out["exit"] = agent.InProcessExit()
		out["dns"] = agent.InProcessDNS()
	}
	if facts, _, failing := agent.InProcessPosture(); facts != nil || len(failing) > 0 {
		if facts != nil {
			out["posture"] = agent.PostureSummary(*facts)
			if facts.Attested != nil {
				out["attested"] = facts.Attested
			}
		}
		if failing == nil {
			failing = []api.PostureFailure{}
		}
		out["posture_failing"] = failing
	}
	mu.Lock()
	out["error"] = lastErr
	mu.Unlock()
	var list []map[string]any
	for _, p := range peers {
		ago := -1
		if !p.LastHandshake.IsZero() {
			ago = int(time.Since(p.LastHandshake).Seconds())
		}
		list = append(list, map[string]any{"endpoint": p.Endpoint, "handshake_seconds_ago": ago, "rx": p.RxBytes, "tx": p.TxBytes})
	}
	out["peers"] = list
	b, _ := json.Marshal(out)
	return string(b)
}

var (
	loginMu    sync.Mutex
	loginState = ""
)

// LoginStart starts an SSO sign-in (the agent must be running) and returns {"url", "code"}; the app
// opens the URL in a browser. The outcome is reported by LoginState.
func LoginStart(stateDir string) (_ string, err error) {
	defer plain(&err)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	f, err := agent.StartLogin(ctx, cfg(stateDir, ""))
	if err != nil {
		cancel()
		return "", err
	}
	setLogin("waiting")
	go func() {
		defer cancel()
		r, err := f.Wait(ctx, nil)
		switch {
		case err != nil:
			setLogin("failed: " + err.Error())
		case r.Approved:
			setLogin("done: Signed in as " + r.User + ".")
		default:
			setLogin("done: Signed in as " + r.User + ", but your groups do not give this device access.")
		}
	}()
	b, _ := json.Marshal(map[string]string{"url": f.Link, "code": f.UserCode})
	return string(b), nil
}

// AdminPage returns the address of the network's admin interface, for admin and operator devices.
// The page shows a code, which AdminApprove approves.
func AdminPage(stateDir string) (_ string, err error) {
	defer plain(&err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return agent.AdminUIURL(ctx, cfg(stateDir, ""))
}

// AdminApprove opens the admin page that shows code in a browser on this phone. The request is
// signed with the device's key, which only this app holds: no other app on the phone can.
func AdminApprove(stateDir, code string) (err error) {
	defer plain(&err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return agent.ApproveAdminUI(ctx, cfg(stateDir, ""), code)
}

// LoginState is "" (none), "waiting", "done: <message>" or "failed: <error>".
func LoginState() string {
	loginMu.Lock()
	defer loginMu.Unlock()
	return loginState
}

func setLogin(s string) { loginMu.Lock(); loginState = s; loginMu.Unlock() }

// PendingApprovals returns the sign-ins waiting for this phone's person to approve, as JSON (a list
// of {"id", "device", "user", "service", "choices", "expires_at"}), waiting up to waitSeconds (at
// most 25) for one. The agent must be running (the call goes through the tunnel).
func PendingApprovals(stateDir string, waitSeconds int32) (_ string, err error) {
	defer plain(&err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(waitSeconds+15)*time.Second)
	defer cancel()
	list, err := agent.PendingApprovals(ctx, cfg(stateDir, ""), time.Duration(waitSeconds)*time.Second)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(list)
	return string(b), nil
}

// WaitApprovals waits (at most waitSeconds) until the network map says something else of the
// approvals waiting for this phone's person than (last, supported), and returns it as JSON:
// {"count", "supported", "seen"}. seen: a map arrived; supported: its control node reports the
// count (0.34), else the app asks with PendingApprovals as before. Fetch the approvals with
// PendingApprovals(dir, 0) when the count changes: the phone keeps no poll of its own open.
func WaitApprovals(last int32, supported bool, waitSeconds int32) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(waitSeconds)*time.Second)
	defer cancel()
	count, sup, seen := agent.WaitMapApprovals(ctx, int(last), supported)
	b, _ := json.Marshal(map[string]any{"count": count, "supported": sup, "seen": seen})
	return string(b)
}

// AnswerApproval answers a sign-in approval with the number the person picked (approve false
// refuses it). It returns the approval's state: approved, or denied when the number is not the one
// the device that asks shows. The answer is signed with this phone's key, which only this app holds.
func AnswerApproval(stateDir, id string, number int32, approve bool) (_ string, err error) {
	defer plain(&err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return agent.AnswerApproval(ctx, cfg(stateDir, ""), id, int(number), approve)
}

// SetExit chooses the exit the phone uses: a route's name, "off", or "" for the one used by default
// (if any). The agent applies it within seconds; the VPN is created again with its routes.
func SetExit(stateDir, choice string) (err error) {
	defer plain(&err)
	return agent.SetExitChoice(stateDir, choice)
}

// SetUpstreamDNS gives the agent the DNS servers of the network the phone uses beside the VPN
// (comma-separated IPv4 addresses): it asks them for every name that is neither the network's nor
// an exit's. Given before Start and again when the phone changes networks.
func SetUpstreamDNS(servers string) { agent.SetUpstreamDNS(strings.Split(servers, ",")) }

// plain turns an error going to the app into one gomobile can pass. gomobile keeps the errors it
// hands to Java in a map, so an error of a type that cannot be a map key (agent.httpError holds a
// slice) panicked and ended the whole app; every exported function defers it (0.30.4).
func plain(err *error) {
	if *err != nil {
		*err = errors.New((*err).Error())
	}
}
