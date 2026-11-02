package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/attest"
)

// Device posture: the agent tells its control nodes what it can find out about the device (system
// and version, disk encryption, firewall, secure boot), at start, when that changes, and every 10
// minutes, in a call signed with the device's key. Policies may require checks of those facts; the
// control nodes answer with the checks the device fails, which the agent shows (agent status, the
// log, the mobile app). Collecting runs beside the tunnel, never in its way: fixed commands only,
// each with a short timeout.

const (
	postureReportEvery  = 10 * time.Minute
	postureCollectEvery = time.Minute
	postureRetry        = 30 * time.Second
	commandTimeout      = 10 * time.Second // one command, at most
)

// Collecting takes at most postureTimeout: macOS runs three commands one after the other, each with
// commandTimeout, so the whole leaves them room. Variables for tests.
var (
	postureTimeout = 45 * time.Second
	collect        = collectPlatform
)

// external holds the facts an app provides that the agent cannot read itself (mobile systems).
var external atomic.Pointer[api.Posture]

// SetExternalPosture gives the agent facts only the app around it can read (Android: system
// version, security patch level, storage encryption, screen lock). Set fields replace what the
// agent found.
func SetExternalPosture(p api.Posture) { external.Store(&p) }

// Attestor gives what the device's secure hardware attests, for one report: the certificate chain
// (DER, leaf first) of a key the hardware made for challenge, and that key's signature of message
// (ECDSA P-256, SHA-256, ASN.1). The app around the agent provides it (Android key attestation).
type Attestor func(challenge, message []byte) (chain [][]byte, signature []byte, err error)

var attestor atomic.Pointer[Attestor]

// SetAttestor makes every posture report carry an attestation from f (see package attest).
func SetAttestor(f Attestor) { attestor.Store(&f) }

// attestation makes the attestation of a report: nil without an attestor, or when it fails (the
// report goes without, and checks that need one fail; why is logged when it changes).
func (a *runner) attestation() *api.Attestation {
	f := attestor.Load()
	if f == nil {
		return nil
	}
	pub := a.key().PublicKey()
	at := wallNow().UTC().Format(time.RFC3339)
	chain, sig, err := (*f)(attest.Challenge(pub), attest.Message(pub, at))
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if msg != a.attestErr {
		if msg != "" {
			a.cfg.Logf("posture: no attestation from the secure hardware: %s", msg)
		}
		a.attestErr = msg
	}
	if err != nil {
		return nil
	}
	return &api.Attestation{Format: attest.FormatAndroid, Chain: chain, SignedAt: at, Signature: sig}
}

var postureCache struct {
	sync.Mutex
	at        time.Time // of the latest collection (zero: collect again)
	facts     api.Posture
	collected bool // facts hold a complete collection
}

// currentPosture collects the device's posture, at most once a minute for all networks. When
// collecting does not finish in time, it returns the facts collected last, and false when there are
// none: a slow tool must not make a device report every fact unknown (and fail its checks).
func currentPosture(ctx context.Context, version string) (api.Posture, bool) {
	postureCache.Lock()
	defer postureCache.Unlock()
	if !postureCache.at.IsZero() && time.Since(postureCache.at) < postureCollectEvery-5*time.Second {
		return withExternal(postureCache.facts), true
	}
	cctx, cancel := context.WithTimeout(ctx, postureTimeout)
	defer cancel()
	done := make(chan api.Posture, 1)
	fn := collect
	go func() { done <- fn(cctx) }()
	var p api.Posture
	select {
	case p = <-done:
	case <-cctx.Done(): // something hangs: keep what was found before, if anything
		if postureCache.collected {
			return withExternal(postureCache.facts), true
		}
		p = api.Posture{Format: api.PostureFormat, OS: runtime.GOOS, Agent: version}
		return withExternal(p), false
	}
	p.Format, p.OS, p.Agent = api.PostureFormat, runtime.GOOS, version
	postureCache.at, postureCache.facts, postureCache.collected = time.Now(), p, true
	return withExternal(p), true
}

func withExternal(p api.Posture) api.Posture {
	e := external.Load()
	if e == nil {
		return p
	}
	if e.OSVersion != "" {
		p.OSVersion = e.OSVersion
	}
	if e.Distribution != "" {
		p.Distribution = e.Distribution
	}
	if e.PatchLevel != "" {
		p.PatchLevel = e.PatchLevel
	}
	for _, f := range []struct{ dst, src **bool }{{&p.DiskEncryption, &e.DiskEncryption}, {&p.Firewall, &e.Firewall},
		{&p.SecureBoot, &e.SecureBoot}, {&p.ScreenLock, &e.ScreenLock}, {&p.Antimalware, &e.Antimalware}} {
		if *f.src != nil {
			*f.dst = *f.src
		}
	}
	return p
}

func samePosture(a, b api.Posture) bool {
	eq := func(x, y *bool) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) }
	return a.Format == b.Format && a.OS == b.OS && a.OSVersion == b.OSVersion && a.Distribution == b.Distribution &&
		a.Agent == b.Agent && a.PatchLevel == b.PatchLevel && eq(a.DiskEncryption, b.DiskEncryption) && eq(a.Firewall, b.Firewall) &&
		eq(a.SecureBoot, b.SecureBoot) && eq(a.ScreenLock, b.ScreenLock) && eq(a.Antimalware, b.Antimalware)
}

// runFixed runs one of the system's tools, by its full path and with fixed arguments (nothing from
// outside reaches a command line), and returns what it printed.
func runFixed(ctx context.Context, path string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.Env = append(os.Environ(), "LANG=C", "LC_ALL=C") // messages in English, which the parsers read
	err := cmd.Run()
	return out.String(), err
}

// PostureSummary describes facts for people: "disk encrypted, firewall on, secure boot unknown,
// screen lock unknown, anti-malware unknown; linux 6.8.0 (debian 12)". On Android, secure boot is
// what the control plane found in the attestation: "verified boot attested (tee)", "verified boot
// not attested: <why>", ...; and the system's patch level follows its version.
func PostureSummary(p api.Posture) string {
	fact := func(v *bool, on, off, what string) string {
		switch {
		case v == nil:
			return what + " unknown"
		case *v:
			return on
		}
		return off
	}
	boot := fact(p.SecureBoot, "secure boot on", "secure boot OFF", "secure boot")
	if p.OS == "android" {
		boot = verifiedBootSummary(p.Attested)
	}
	s := strings.Join([]string{
		fact(p.DiskEncryption, "disk encrypted", "disk NOT encrypted", "disk encryption"),
		fact(p.Firewall, "firewall on", "firewall OFF", "firewall"),
		boot,
		fact(p.ScreenLock, "screen lock on", "screen lock OFF", "screen lock"),
		fact(p.Antimalware, "anti-malware on", "anti-malware OFF", "anti-malware"),
	}, ", ")
	sys := strings.TrimSpace(p.OS + " " + p.OSVersion)
	if p.OSVersion == "" {
		sys += " (version unknown)"
	}
	if p.Distribution != "" {
		sys += " (" + p.Distribution + ")"
	}
	if p.PatchLevel != "" {
		sys += ", patch " + p.PatchLevel
	}
	return s + "; " + sys
}

// verifiedBootSummary describes what an Android device's attestation showed (nil: none sent, or
// not answered yet).
func verifiedBootSummary(a *api.Attested) string {
	switch {
	case a == nil:
		return "verified boot not attested"
	case a.Error != "":
		return "verified boot not attested: " + a.Error
	case a.BootState == "verified" && a.Locked:
		return "verified boot attested (" + a.SecurityLevel + ")"
	case !a.Locked:
		return "bootloader UNLOCKED (attested, " + a.BootState + ")"
	}
	return "verified boot " + strings.ToUpper(a.BootState) + " (attested)"
}

// reportPosture reports the device's posture to the network's control nodes until ctx ends.
func (a *runner) reportPosture(ctx context.Context) {
	var sent api.Posture
	var sentAt time.Time
	var notesLogged string
	wait, quiet, force := 2*time.Second, false, false // first report once the tunnel had a moment
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		case <-a.postureWake: // the control plane holds no recent report (after a sleep)
			force = true
		}
		facts, ok := currentPosture(ctx, a.cfg.Version)
		if !ok {
			a.cfg.Logf("posture: collecting took longer than %s; trying again", postureTimeout)
			wait = postureRetry
			continue
		}
		if !postureDue(facts, sent, sentAt, wallNow(), force) {
			wait = postureCollectEvery
			continue
		}
		c := &AdminClient{Controls: a.controls(), Key: a.key(), HTTP: a.env.http}
		var res api.PostureResult
		report := facts
		report.Attestation = a.attestation()
		err := c.Do(ctx, http.MethodPost, api.PathPosture, report, &res)
		var he httpError
		switch {
		case err == nil:
			facts.Attested = res.Attested
			if sentAt.IsZero() || !samePosture(facts, sent) || !sameAttested(facts.Attested, sent.Attested) {
				a.cfg.Logf("posture reported: %s", PostureSummary(facts))
			}
			if n := strings.Join(PostureNotes(), "; "); n != notesLogged {
				if n != "" {
					a.cfg.Logf("posture: %s", n)
				}
				notesLogged = n
			}
			sent, sentAt, wait, quiet, force = facts, wallNow(), postureCollectEvery, false, false
			a.postureReported(facts, sentAt, res.Failing)
		case errors.As(err, &he) && (he.code == http.StatusNotFound || he.code == http.StatusMethodNotAllowed):
			if !quiet {
				a.cfg.Logf("posture: the control plane takes no reports (older than ento 0.13); trying again every 10 minutes")
				quiet = true
			}
			wait = postureReportEvery
		case errors.As(err, &he) && he.code == http.StatusTooManyRequests:
			wait = postureRetry // reported a moment ago (by this device, perhaps before a restart)
		default:
			if ctx.Err() == nil {
				a.cfg.Logf("posture report: %v", err)
			}
			wait = postureRetry
		}
	}
}

func sameAttested(a, b *api.Attested) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

// askReport asks reportPosture for a report now (the control plane holds no recent one).
func (a *runner) askReport() {
	select {
	case a.postureWake <- struct{}{}:
	default:
	}
}

// awaitReport waits until the control plane took a posture report of this runner, but not past
// max after the runner started (nor past ctx).
func (a *runner) awaitReport(ctx context.Context, max time.Duration) {
	for {
		a.mu.Lock()
		done := !a.postureAt.IsZero() || time.Since(a.started) >= max
		a.mu.Unlock()
		if done {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// postureReported records a report the control plane took, and what it said of it.
func (a *runner) postureReported(facts api.Posture, at time.Time, failing []api.PostureFailure) {
	a.mu.Lock()
	a.posture, a.postureAt = &facts, at
	a.mu.Unlock()
	if !a.setFailing(failing) {
		a.announce()
	}
}

// setFailing records the checks the device fails (from a report's answer or the network map) and
// says so when that changes; it reports whether it did.
func (a *runner) setFailing(failing []api.PostureFailure) bool {
	a.mu.Lock()
	changed := !slices.Equal(a.failing, failing)
	if changed {
		a.failing = slices.Clone(failing)
	}
	a.mu.Unlock()
	if !changed {
		return false
	}
	if staleFailure(failing) {
		a.askReport() // report again at once
	}
	if a.failingFile != "" {
		writeFailing(a.failingFile, failing)
	}
	for _, f := range failing {
		a.cfg.Logf("posture: this device fails check %q (%q): the policies requiring it leave it out", f.Check, f.Reason)
	}
	if len(failing) == 0 {
		a.cfg.Logf("posture: this device passes every check its policies require")
	}
	a.announce()
	return true
}

// FailingText describes the checks a device fails, for people: "check laptops: disk not
// encrypted".
func FailingText(f []api.PostureFailure) []string {
	out := make([]string, 0, len(f))
	for _, x := range f {
		out = append(out, fmt.Sprintf("check %s: %s", x.Check, x.Reason))
	}
	return out
}

// InProcessPosture returns the latest report of the agent running in this process (RunOnTUN), when
// it made one, and the checks the device fails.
func InProcessPosture() (*api.Posture, time.Time, []api.PostureFailure) {
	a := current.Load()
	if a == nil {
		return nil, time.Time{}, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.posture, a.postureAt, slices.Clone(a.failing)
}

// CollectPosture finds out the device's posture now, as the agent would report it.
// postureNotes say how a fact was found when that is not the usual way, or why it is unknown (a
// fallback, an error), for the agent's log and `ento agent posture`; set while collecting.
var postureNotes struct {
	sync.Mutex
	m map[string]string
}

func notePosture(fact, note string) {
	postureNotes.Lock()
	defer postureNotes.Unlock()
	if postureNotes.m == nil {
		postureNotes.m = map[string]string{}
	}
	if note == "" {
		delete(postureNotes.m, fact)
	} else {
		postureNotes.m[fact] = note
	}
}

// PostureNotes returns the notes of the last collection, as "fact: note", sorted.
func PostureNotes() []string {
	postureNotes.Lock()
	defer postureNotes.Unlock()
	var out []string
	for f, n := range postureNotes.m {
		out = append(out, f+": "+n)
	}
	sort.Strings(out)
	return out
}

func CollectPosture(ctx context.Context, version string) api.Posture {
	postureCache.Lock()
	postureCache.at = time.Time{}
	postureCache.Unlock()
	p, _ := currentPosture(ctx, version)
	return p
}

// wallNow is the time now without Go's monotonic reading, so that durations measured from it are
// wall-clock time: the monotonic clock stops while the device sleeps, the control plane's clock
// (which judges a report's age) does not.
func wallNow() time.Time { return time.Now().Round(0) }

// postureDue reports whether facts must be reported now: never reported, changed, asked for
// (force: the control plane holds no recent report), or the last report is postureReportEvery old.
func postureDue(facts, sent api.Posture, sentAt, now time.Time, force bool) bool {
	return force || sentAt.IsZero() || !samePosture(facts, sent) || now.Sub(sentAt) >= postureReportEvery
}

// staleFailure reports whether a failure only says the control plane has no recent report (the
// device slept, or the report was lost): reporting again fixes it.
func staleFailure(f []api.PostureFailure) bool {
	return slices.ContainsFunc(f, func(x api.PostureFailure) bool { return strings.HasPrefix(x.Reason, "no report") })
}
