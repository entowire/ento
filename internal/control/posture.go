package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/attest"
	"entowire.com/ento/internal/names"
	"entowire.com/ento/internal/ports"
	"entowire.com/ento/internal/store"
)

// Device posture: devices report facts about themselves (POST /v1/posture, signed with their key),
// administrators define named checks over those facts, and a policy can require checks of its
// source devices. A source device that fails one of them, or whose report is missing or older than
// the check allows, is left out of that policy: fail closed. The evaluation of the checks each
// device must pass is stored, so that every control node builds the same network maps, the version
// changes (and agents learn of it) only when a result does, and each change is audited once.

const (
	// DefaultPostureMaxAge is how old a report may be when a check does not say.
	DefaultPostureMaxAge = 30 * time.Minute
	// Agents report every 10 minutes: a shorter limit would fail devices between two reports.
	minPostureMaxAge = 15 * time.Minute
	maxPostureMaxAge = 30 * 24 * time.Hour
	// postureEvery is how often control nodes evaluate every device (reports age).
	postureEvery   = 10 * time.Second
	maxPostureBody = 32 << 10 // an attestation's certificate chain takes most
	// A patch level names a month: a limit under a month and a half fails phones between two
	// monthly updates.
	minPatchAgeDays = 45
	maxPatchAgeDays = 3650
)

// postureReportGap is the shortest interval between two reports of a device that are accepted,
// whichever control nodes they reach (the store enforces it). Agents collect once a minute.
// postureHoldDown is how long a device that started failing a check over its facts keeps failing
// it, even when it reports facts that pass meanwhile: a device whose root flips a fact on every
// report would otherwise change every network map (and write an audit line) twice a minute.
// Variables for tests.
var (
	postureReportGap = 30 * time.Second
	postureHoldDown  = 2 * time.Minute
)

// outcome sorts a check's result for audit lines: passed, failed over the device's facts, or
// stale (no report, or none recent enough). Lines are written when it changes.
func outcome(why string) string {
	switch {
	case why == "":
		return "passed"
	case staleReason(why):
		return "stale"
	}
	return "failed"
}

// staleReason reports whether a failure is only about the report's age (or its absence), not about
// what the device reported.
func staleReason(why string) bool { return strings.HasPrefix(why, "no report") }

// postureSystems are the systems a check can ask a minimum version of.
var postureSystems = map[string]string{"linux": "Linux", "darwin": "macOS", "windows": "Windows", "android": "Android"}

// versionParts reads the numeric parts of a version: "6.8.0-142-generic" is 6, 8, 0 and
// "10.0.26100.2033" is 10, 0, 26100, 2033. It stops at the first part that is not only digits (after
// taking that part's leading digits). False when it does not start with a digit.
func versionParts(v string) ([]int, bool) {
	var out []int
	for _, part := range strings.Split(strings.TrimSpace(v), ".") {
		n := 0
		for n < len(part) && part[n] >= '0' && part[n] <= '9' {
			n++
		}
		if n == 0 || n > 9 {
			break
		}
		x, _ := strconv.Atoi(part[:n])
		out = append(out, x)
		if n < len(part) {
			break
		}
	}
	return out, len(out) > 0
}

// compareVersions compares two versions numerically, part by part (missing parts are 0): -1 when a
// is older than b, 0 when equal, 1 when newer. False when either is not a version.
func compareVersions(a, b string) (int, bool) {
	pa, ok1 := versionParts(a)
	pb, ok2 := versionParts(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func maxAgeOf(c store.PostureCheck) time.Duration {
	if c.MaxAge <= 0 {
		return DefaultPostureMaxAge
	}
	return c.MaxAge
}

// evaluateCheck returns why a device with this report fails the check, "" when it passes. Reasons
// depend on the report only (never on its exact age), so that they change only when the device's
// state does.
func evaluateCheck(c store.PostureCheck, facts *api.Posture, reportedAt, now time.Time) string {
	if facts == nil {
		return "no report"
	}
	if age := maxAgeOf(c); now.Sub(reportedAt) > age {
		return "no report in " + api.HumanDuration(age)
	}
	var why []string
	need := func(required bool, fact *bool, unknown, off string) {
		switch {
		case !required:
		case fact == nil:
			why = append(why, unknown)
		case !*fact:
			why = append(why, off)
		}
	}
	need(c.DiskEncryption, facts.DiskEncryption, "disk encryption unknown", "disk not encrypted")
	need(c.Firewall, facts.Firewall, "firewall unknown", "firewall off")
	if facts.OS == "android" {
		need(c.SecureBoot, facts.SecureBoot, verifiedBootUnknown(facts.Attested), verifiedBootOff(facts.Attested))
	} else {
		need(c.SecureBoot, facts.SecureBoot, "secure boot unknown", "secure boot off")
	}
	need(c.Antimalware, facts.Antimalware, "anti-malware unknown", "anti-malware off")
	if len(c.MinOS) > 0 {
		name, known := postureSystems[facts.OS]
		if minimum, limited := c.MinOS[facts.OS]; limited {
			switch cmp, ok := compareVersions(facts.OSVersion, minimum); {
			case !ok:
				why = append(why, name+" version unknown")
			case cmp < 0:
				why = append(why, fmt.Sprintf("%s %s is older than %s", name, facts.OSVersion, minimum))
			}
		} else if !known {
			why = append(why, "system unknown")
		}
	}
	if days, limited := c.MaxPatchAge[facts.OS]; limited {
		switch patched, ok := patchDate(facts.PatchLevel); {
		case !ok:
			why = append(why, "security patch level unknown")
		case now.Sub(patched) > time.Duration(days)*24*time.Hour:
			why = append(why, fmt.Sprintf("security patch %s is older than %dd", facts.PatchLevel, days))
		}
	}
	return strings.Join(why, ", ")
}

// verifiedBootUnknown says why an Android device's verified boot is unknown: no attestation, or
// one that does not count.
func verifiedBootUnknown(a *api.Attested) string {
	if a == nil {
		return "verified boot not attested"
	}
	return "verified boot not attested: " + a.Error
}

// verifiedBootOff says what an Android device's hardware attests instead of a verified boot with
// the bootloader locked.
func verifiedBootOff(a *api.Attested) string {
	switch {
	case a == nil:
		return "verified boot off"
	case a.BootState == "self-signed":
		return "verified boot: a system its maker did not sign"
	case a.BootState == "unverified" || !a.Locked && a.BootState == "verified":
		return "verified boot: bootloader unlocked"
	case a.BootState == "failed":
		return "verified boot failed"
	}
	return "verified boot off"
}

// patchDate reads a security patch level, "2026-09-05" or "2026-09" (the 1st of the month).
func patchDate(level string) (time.Time, bool) {
	for _, layout := range []string{time.DateOnly, "2006-01"} {
		if t, err := time.Parse(layout, level); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// oldestPatch is the oldest of the patch levels an attestation names (system, vendor image, boot
// image): a phone is as patched as its least patched part. "" when it names none.
func oldestPatch(a api.Attested) string {
	oldest, at := "", time.Time{}
	for _, level := range []string{a.PatchLevel, a.VendorPatchLevel, a.BootPatchLevel} {
		if t, ok := patchDate(level); ok && (oldest == "" || t.Before(at)) {
			oldest, at = level, t
		}
	}
	return oldest
}

// postureState is what posture decisions need: the checks, and every device's report and stored
// evaluation, at one moment.
type postureState struct {
	now     time.Time
	checks  map[string]store.PostureCheck
	reports map[int64]store.PostureReport
	facts   map[int64]*api.Posture
}

func loadPosture(ctx context.Context, st store.Store, now time.Time) (*postureState, error) {
	checks, err := st.PostureChecks(ctx)
	if err != nil {
		return nil, err
	}
	reports, err := st.PostureReports(ctx)
	if err != nil {
		return nil, err
	}
	ps := &postureState{now: now, checks: map[string]store.PostureCheck{}, reports: map[int64]store.PostureReport{},
		facts: map[int64]*api.Posture{}}
	for _, c := range checks {
		ps.checks[c.Name] = c
	}
	for _, r := range reports {
		ps.reports[r.PeerID] = r
		if r.Facts != nil {
			var f api.Posture
			if json.Unmarshal(r.Facts, &f) == nil {
				ps.facts[r.PeerID] = &f
			}
		}
	}
	return ps, nil
}

// live evaluates a check for a device now.
func (ps *postureState) live(p store.Peer, name string) string {
	c, ok := ps.checks[name]
	if !ok {
		return "no such check"
	}
	return evaluateCheck(c, ps.facts[p.ID], ps.reports[p.ID].ReportedAt, ps.now)
}

// reason is the stored result of a check for a device, or, before the check was first evaluated for
// it (it just became required), its live evaluation.
func (ps *postureState) reason(p store.Peer, name string) string {
	if r, ok := ps.reports[p.ID].Results[name]; ok {
		return r
	}
	return ps.live(p, name)
}

// passes reports whether a device passes every one of the checks.
func (ps *postureState) passes(p store.Peer, checks []string) bool {
	if ps == nil {
		return len(checks) == 0
	}
	for _, name := range checks {
		if ps.reason(p, name) != "" {
			return false
		}
	}
	return true
}

// inGroup reports whether p is in group g ("*": every device). A route ("route:NAME") is no group:
// policies to routes are applied by routeAccess only.
func inGroup(p store.Peer, g string) bool {
	if isRoute(g) {
		return false
	}
	return g == "*" || hasGroup(p.Groups, g)
}

// allowed reports whether a policy lets a and b reach each other. "*" matches every peer. A policy
// that requires posture checks leaves out each of its source devices that fails one of them (also
// where that device is in its destination group too). ps may be nil when no policy requires any.
func allowed(a, b store.Peer, policies []store.Policy, ps *postureState) bool {
	for _, pol := range policies {
		if !(inGroup(a, pol.Source) && inGroup(b, pol.Destination)) && !(inGroup(b, pol.Source) && inGroup(a, pol.Destination)) {
			continue
		}
		if len(pol.Posture) > 0 {
			eligible := func(p store.Peer) bool { return !inGroup(p, pol.Source) || ps.passes(p, pol.Posture) }
			if !eligible(a) || !eligible(b) {
				continue
			}
		}
		return true
	}
	return false
}

// needsPosture reports whether any policy requires posture checks.
func needsPosture(policies []store.Policy) bool {
	return slices.ContainsFunc(policies, func(p store.Policy) bool { return len(p.Posture) > 0 })
}

// requiredChecks lists the checks policies require of a device (those whose source group it is in).
func requiredChecks(p store.Peer, policies []store.Policy) []string {
	var out []string
	for _, pol := range policies {
		if inGroup(p, pol.Source) {
			out = append(out, pol.Posture...)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// failingChecks lists the required checks a device fails, for the device itself.
func failingChecks(p store.Peer, policies []store.Policy, ps *postureState) []api.PostureFailure {
	var out []api.PostureFailure
	for _, name := range requiredChecks(p, policies) {
		if ps == nil {
			out = append(out, api.PostureFailure{Check: name, Reason: "not evaluated"})
		} else if why := ps.reason(p, name); why != "" {
			out = append(out, api.PostureFailure{Check: name, Reason: why})
		}
	}
	return out
}

// evaluatePosture evaluates the checks each device must pass (only one device when only is not 0)
// and stores the results that changed, auditing each check a device starts or stops failing. It
// returns the stored results of the device only.
func (s *Server) evaluatePosture(ctx context.Context, only int64) (map[string]string, error) {
	s.postureMu.Lock()
	defer s.postureMu.Unlock()
	peers, err := s.cfg.Store.Peers(ctx)
	if err != nil {
		return nil, err
	}
	policies, err := s.cfg.Store.Policies(ctx)
	if err != nil {
		return nil, err
	}
	ps, err := loadPosture(ctx, s.cfg.Store, time.Now())
	if err != nil {
		return nil, err
	}
	var mine map[string]string
	for _, p := range peers {
		if only != 0 && p.ID != only {
			continue
		}
		previous := ps.reports[p.ID].Results
		held := ps.now.Sub(ps.reports[p.ID].ResultsAt) < postureHoldDown
		results := map[string]string{}
		for _, name := range requiredChecks(p, policies) {
			why := ps.live(p, name)
			if old := previous[name]; why == "" && old != "" && !staleReason(old) && held {
				why = old // started failing a moment ago: passes again once the hold-down is over
			}
			results[name] = why
		}
		mine = previous
		if store.SameResults(previous, results) {
			continue
		}
		applied, err := s.cfg.Store.SetPostureResults(ctx, p.ID, previous, results)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				s.cfg.Logf("posture of peer %d: %v", p.ID, err)
			}
			continue
		}
		if !applied { // another control node stored a newer evaluation first, and audited it
			continue
		}
		mine = results
		// A device enrolled a moment ago has not reported yet: that is not worth an audit line.
		young := ps.now.Sub(p.CreatedAt) < 2*time.Minute
		for _, name := range slices.Sorted(maps.Keys(results)) {
			now, old := results[name], previous[name]
			if outcome(now) == outcome(old) || young && (now == "no report" || old == "no report" && now == "") {
				continue
			}
			switch outcome(now) {
			case "failed":
				s.audit(nil, &p, "posture_failed", fmt.Sprintf("%s check=%s reason=%s", peerLabel(p), name, now), "denied")
			case "stale": // asleep, or an agent that does not report: not a failing fact
				s.audit(nil, &p, "posture_stale", fmt.Sprintf("%s check=%s reason=%s", peerLabel(p), name, now), "ok")
			default:
				s.audit(nil, &p, "posture_passed", fmt.Sprintf("%s check=%s", peerLabel(p), name), "ok")
			}
		}
	}
	return mine, nil
}

// --- reports ------------------------------------------------------------------------------------

var versionText = regexp.MustCompile(`[^0-9A-Za-z.+_~-]`)

// printable keeps up to n printable ASCII characters of a value the device sent.
func printable(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n]
	}
	return strings.TrimSpace(s)
}

// cleanPosture keeps what a report may contain, in the form it may have: what a device says about
// itself reaches audit lines, terminals and the admin interface.
func cleanPosture(in api.Posture, self store.Peer) api.Posture {
	out := api.Posture{Format: api.PostureFormat, OS: cleanOS(in.OS), DiskEncryption: in.DiskEncryption,
		Firewall: in.Firewall, SecureBoot: in.SecureBoot, ScreenLock: in.ScreenLock, Antimalware: in.Antimalware}
	if out.OS == "" {
		out.OS = self.OS
	}
	out.OSVersion = versionText.ReplaceAllString(printable(in.OSVersion, 64), "")
	out.Distribution = printable(in.Distribution, 64)
	out.Agent = versionText.ReplaceAllString(printable(in.Agent, 64), "")
	if _, ok := patchDate(in.PatchLevel); ok {
		out.PatchLevel = in.PatchLevel
	}
	return out
}

// attestRoots, when set, are trusted instead of Google's attestation roots (tests).
var attestRoots [][]byte

// revocations returns the list of revoked attestation certificates, fetching it from the first
// call on (networks without phones never ask for it); nil when it is not checked.
func (s *Server) revocations() *attest.Revocations {
	if s.rev == nil {
		return nil
	}
	s.revOnce.Do(func() { go s.rev.Run(s.runCtx) })
	return s.rev
}

// attestPosture verifies an Android device's attestation into its facts: whether it counts and
// what it shows (Attested), verified boot (SecureBoot, from it alone: what the device says itself
// is ignored) and the oldest attested patch level instead of the reported one.
func (s *Server) attestPosture(ctx context.Context, facts *api.Posture, a *api.Attestation, self store.Peer, now time.Time) {
	facts.SecureBoot = nil
	if a == nil {
		return
	}
	o := attest.Options{Now: now, Apps: s.cfg.AndroidApps, Roots: attestRoots}
	if rev := s.revocations(); rev != nil {
		rev.Wait(ctx, 20*time.Second) // a report right after the node started
		o.Revoked = rev.Revoked
	}
	att := attest.Verify(a, self.PublicKey, o)
	facts.Attested = &att
	if att.Error != "" {
		return
	}
	on := att.BootState == "verified" && att.Locked
	facts.SecureBoot = &on
	if p := oldestPatch(att); p != "" {
		facts.PatchLevel = p
	}
}

func (s *Server) handlePostureReport(w http.ResponseWriter, r *http.Request, self store.Peer) {
	now := time.Now()
	var req api.Posture
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPostureBody)).Decode(&req); err != nil || req.Format < 1 {
		writeErr(w, http.StatusBadRequest, "invalid posture report")
		return
	}
	facts := cleanPosture(req, self)
	if facts.OS == "android" {
		s.attestPosture(r.Context(), &facts, req.Attestation, self, now)
	}
	b, err := json.Marshal(facts)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	err = s.cfg.Store.SetPostureReport(r.Context(), self.ID, b, now, postureReportGap)
	if errors.Is(err, store.ErrTooSoon) {
		writeErr(w, http.StatusTooManyRequests, "posture reported a moment ago")
		return
	}
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	results, err := s.evaluatePosture(r.Context(), self.ID)
	if err != nil {
		s.cfg.Logf("posture: %v", err)
		writeErr(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}
	res := api.PostureResult{Failing: []api.PostureFailure{}, Attested: facts.Attested}
	for _, name := range slices.Sorted(maps.Keys(results)) {
		if why := results[name]; why != "" {
			res.Failing = append(res.Failing, api.PostureFailure{Check: name, Reason: why})
		}
	}
	s.checkVersion(r.Context()) // agents learn of a changed evaluation at once
	writeJSON(w, http.StatusOK, res)
}

// --- administration -----------------------------------------------------------------------------

func apiPostureCheck(c store.PostureCheck) api.PostureCheck {
	out := api.PostureCheck{Name: c.Name, DiskEncryption: c.DiskEncryption, Firewall: c.Firewall, SecureBoot: c.SecureBoot,
		Antimalware: c.Antimalware, MinOS: c.MinOS, MaxPatchAgeDays: c.MaxPatchAge, MaxAgeSeconds: int(maxAgeOf(c) / time.Second)}
	if !c.CreatedAt.IsZero() {
		out.CreatedAt = c.CreatedAt.UTC().Format(time.RFC3339)
	}
	return out
}

// checkLabel describes a check for audit lines.
func checkLabel(c store.PostureCheck) string {
	var min []string
	for _, k := range slices.Sorted(maps.Keys(c.MinOS)) {
		min = append(min, k+"="+c.MinOS[k])
	}
	var patch []string
	for _, k := range slices.Sorted(maps.Keys(c.MaxPatchAge)) {
		patch = append(patch, fmt.Sprintf("%s=%dd", k, c.MaxPatchAge[k]))
	}
	label := fmt.Sprintf("check %s disk_encryption=%v firewall=%v secure_boot=%v antimalware=%v min_os=%s max_age=%s", c.Name,
		c.DiskEncryption, c.Firewall, c.SecureBoot, c.Antimalware, strings.Join(min, ","), api.HumanDuration(maxAgeOf(c)))
	if len(patch) > 0 {
		label += " max_patch_age=" + strings.Join(patch, ",")
	}
	return label
}

var dottedVersion = regexp.MustCompile(`^[0-9]{1,9}(\.[0-9]{1,9}){0,5}$`)

func (s *Server) handleListPostureChecks(w http.ResponseWriter, r *http.Request, _ store.Peer) {
	checks, err := s.cfg.Store.PostureChecks(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	out := make([]api.PostureCheck, 0, len(checks))
	for _, c := range checks {
		out = append(out, apiPostureCheck(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAddPostureCheck(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.PostureCheck
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := names.Check(req.Name); err != nil {
		writeErr(w, http.StatusBadRequest, "check name: "+err.Error())
		return
	}
	for os, v := range req.MinOS {
		if _, ok := postureSystems[os]; !ok {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("minimum version for %q: systems are linux, darwin, windows and android", os))
			return
		}
		if !dottedVersion.MatchString(v) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("minimum version for %s: numbers and dots, like 6.1 or 10.0.22631", os))
			return
		}
		if parts, _ := versionParts(v); os == "windows" && parts[0] > 10 {
			// Windows 11 calls itself 10.0: "11" would fail every Windows device.
			writeErr(w, http.StatusBadRequest, "minimum version for windows: Windows versions are 10.0.BUILD, also for Windows 11 "+
				"(10.0.22000 and later), e.g. windows=10.0.22631 for Windows 11 23H2")
			return
		}
	}
	for os, days := range req.MaxPatchAgeDays {
		if os != "android" {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("security patch age for %q: only android reports its security patch level", os))
			return
		}
		if days < minPatchAgeDays || days > maxPatchAgeDays {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("security patch age for %s: between %d and %d days (patches come monthly)", os, minPatchAgeDays, maxPatchAgeDays))
			return
		}
	}
	c := store.PostureCheck{Name: req.Name, DiskEncryption: req.DiskEncryption, Firewall: req.Firewall, SecureBoot: req.SecureBoot,
		Antimalware: req.Antimalware, MaxAge: time.Duration(req.MaxAgeSeconds) * time.Second}
	if len(req.MinOS) > 0 {
		c.MinOS = req.MinOS
	}
	if len(req.MaxPatchAgeDays) > 0 {
		c.MaxPatchAge = req.MaxPatchAgeDays
	}
	if c.MaxAge == 0 {
		c.MaxAge = DefaultPostureMaxAge
	}
	if c.MaxAge < minPostureMaxAge || c.MaxAge > maxPostureMaxAge {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("the longest age of a report is between %s and %s (agents report every 10 minutes)",
			api.HumanDuration(minPostureMaxAge), api.HumanDuration(maxPostureMaxAge)))
		return
	}
	c, err := s.cfg.Store.AddPostureCheck(r.Context(), c)
	if errors.Is(err, store.ErrExists) {
		writeErr(w, http.StatusConflict, "a posture check with that name exists")
		return
	}
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "posture_check_added", checkLabel(c), "ok")
	writeJSON(w, http.StatusCreated, apiPostureCheck(c))
}

func (s *Server) handleDeletePostureCheck(w http.ResponseWriter, r *http.Request, self store.Peer) {
	name := r.PathValue("name")
	err := s.cfg.Store.DeletePostureCheck(r.Context(), name)
	var inUse *store.CheckInUseError
	if errors.As(err, &inUse) {
		writeErr(w, http.StatusConflict, err.Error()+": take it off there first")
		return
	}
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "posture_check_deleted", "check "+name, "ok")
	w.WriteHeader(http.StatusNoContent)
}

// postureNames validates the names of a policy's or a link's checks and returns them sorted, once
// each. Whether they exist the store checks, in the transaction that changes the policy or link
// (*store.NoSuchCheckError).
func postureNames(list []string) ([]string, error) {
	if len(list) == 0 {
		return nil, nil
	}
	if len(list) > 32 {
		return nil, errors.New("at most 32 posture checks")
	}
	for _, name := range list {
		if err := names.Check(name); err != nil {
			return nil, fmt.Errorf("posture check name: %v", err)
		}
	}
	out := slices.Clone(list)
	slices.Sort(out)
	return slices.Compact(out), nil
}

// sameGroup reports whether two names can select the same devices: equal, or a plain name and the
// device group of that name (hasGroup lets a plain name match it). Comparing names literally let
// an operator connect `device:laptops` with servers past an admin's checks on `laptops` (2026-11-03
// review, A4).
func sameGroup(g, h string) bool {
	return g == h || !strings.Contains(g, ":") && DevicePrefix+g == h || !strings.Contains(h, ":") && DevicePrefix+h == g
}

// coversGroups reports whether a policy between groups x and y connects devices of groups a and b,
// going by the names ("*" matches every group; a plain name and its device group match).
func coversGroups(x, y, a, b string) bool {
	match := func(g, h string) bool { return g == "*" || h == "*" || sameGroup(g, h) }
	return match(x, a) && match(y, b) || match(x, b) && match(y, a)
}

// bypasses reports whether policy o lets source devices of policy p reach p's destination devices
// without the checks p requires of them: o connects the same groups (in either order, or through
// "*") and does not require all of p's checks of them as its own source devices. A connection
// carries data both ways whichever side opened it, and the first policy that allows a pair wins, so
// such a policy makes p's checks moot even where it goes the other way (rules go one way since
// 0.52; this stays as strict as when they went both).
// Going by group names: devices in several groups can still be connected by others.
func bypasses(o, p store.Policy) bool {
	if isRoute(o.Destination) != isRoute(p.Destination) { // a policy between groups reaches no route
		return false
	}
	if len(p.Posture) == 0 || o.Source == p.Source && o.Destination == p.Destination ||
		!coversGroups(o.Source, o.Destination, p.Source, p.Destination) {
		return false
	}
	checksThem := o.Source == "*" || sameGroup(o.Source, p.Source)
	return !checksThem || slices.ContainsFunc(p.Posture, func(c string) bool { return !slices.Contains(o.Posture, c) })
}

// policyWarnings describes how policy p and the others make posture checks moot.
func policyWarnings(p store.Policy, all []store.Policy) []string {
	var out []string
	for _, o := range all {
		if bypasses(o, p) {
			out = append(out, fmt.Sprintf("policy %d (%s -> %s) connects devices of %s and %s without check %s",
				o.ID, o.Source, o.Destination, p.Source, p.Destination, strings.Join(p.Posture, ",")))
		}
		if bypasses(p, o) {
			out = append(out, fmt.Sprintf("this policy connects devices of %s and %s without check %s, which policy %d requires",
				o.Source, o.Destination, strings.Join(o.Posture, ","), o.ID))
		}
	}
	return out
}

// noSuchCheck answers a policy or link change that names a posture check that does not exist;
// false when err is something else.
func noSuchCheck(w http.ResponseWriter, err error) bool {
	var nc *store.NoSuchCheckError
	if !errors.As(err, &nc) {
		return false
	}
	writeErr(w, http.StatusBadRequest, nc.Error())
	return true
}

// policyLabel describes a policy for audit lines, with the checks it requires.
func policyLabel(p store.Policy) string {
	arrow := "<->"
	if p.OneWay {
		arrow = "->"
	}
	l := fmt.Sprintf("policy %s %s %s", p.Source, arrow, p.Destination)
	if p.ID != 0 {
		l = fmt.Sprintf("policy %d %s %s %s", p.ID, p.Source, arrow, p.Destination)
	}
	if len(p.Ports) > 0 {
		l += " ports=" + strings.Join(p.Ports, ",")
	}
	if len(p.Posture) > 0 {
		l += " posture=" + strings.Join(p.Posture, ",")
	}
	return l
}

func apiPolicy(p store.Policy) api.Policy {
	return api.Policy{ID: p.ID, Source: p.Source, Destination: p.Destination, Posture: p.Posture, OneWay: p.OneWay, Ports: p.Ports}
}

// filteringAgents is the first agent version that enforces a policy's direction and ports.
const filteringAgents = "0.19.0"

// enforcementWarnings names the devices a policy's direction or ports depend on whose agents do not
// enforce them (older than 0.19, or never reported): its source devices (a one-way policy relies on
// them to refuse connections from its destination, a two-way one with ports to limit them) and, when
// it names ports, its destination devices.
func (s *Server) enforcementWarnings(ctx context.Context, p store.Policy) []string {
	if !p.OneWay && len(p.Ports) == 0 {
		return nil
	}
	peers, err := s.cfg.Store.Peers(ctx)
	if err != nil {
		return nil
	}
	ps, err := loadPosture(ctx, s.cfg.Store, time.Now())
	if err != nil {
		return nil
	}
	var old []string
	for _, d := range peers {
		relies := inGroup(d, p.Source) || len(p.Ports) > 0 && inGroup(d, p.Destination)
		if !d.Approved || d.Suspended || !relies {
			continue
		}
		f := ps.facts[d.ID]
		if f == nil {
			old = append(old, d.Hostname+" (no report)")
			continue
		}
		if c, ok := compareVersions(f.Agent, filteringAgents); !ok || c < 0 {
			old = append(old, d.Hostname+" ("+f.Agent+")")
		}
	}
	if len(old) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%d device(s) of this policy run agents older than %s, which enforce neither its direction nor its ports (they accept everything from its other side) until they are updated: %s",
		len(old), filteringAgents, strings.Join(old, ", "))}
}

// policyPorts checks and normalises a policy's port rules: canonical, and empty for everything.
func policyPorts(list []string) ([]string, error) {
	c, err := ports.Canonical(list)
	if err != nil {
		return nil, err
	}
	if len(c) == 0 || slices.Equal(c, []string{"all"}) {
		return nil, nil
	}
	if len(c) > 64 {
		return nil, errors.New("at most 64 port rules")
	}
	return c, nil
}

// acceptFrom is what peer p may open on self: the union of the ports of every policy that lets p
// open connections to self (posture checks as for allowed); empty when none does (p is in self's
// map only to answer self's own connections, through a one-way policy).
func acceptFrom(self, p store.Peer, policies []store.Policy, ps *postureState) []string {
	var lists [][]string
	for _, pol := range policies {
		if len(pol.Posture) > 0 {
			eligible := func(x store.Peer) bool { return !inGroup(x, pol.Source) || ps.passes(x, pol.Posture) }
			if !eligible(self) || !eligible(p) {
				continue
			}
		}
		opens := inGroup(p, pol.Source) && inGroup(self, pol.Destination) ||
			!pol.OneWay && inGroup(p, pol.Destination) && inGroup(self, pol.Source)
		if opens {
			lists = append(lists, pol.Ports)
		}
	}
	if len(lists) == 0 {
		return nil
	}
	return ports.Union(lists...)
}

func (s *Server) handleUpdatePolicy(w http.ResponseWriter, r *http.Request, self store.Peer) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req api.UpdatePolicyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	checks, err := postureNames(req.Posture)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	before, err := s.policyByID(r.Context(), id)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	p, err := s.cfg.Store.SetPolicyPosture(r.Context(), id, checks)
	if noSuchCheck(w, err) {
		return
	}
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	was := strings.Join(before.Posture, ",")
	if was == "" {
		was = "none"
	}
	s.audit(r, &self, "policy_posture", fmt.Sprintf("%s (was %s)", policyLabel(p), was), "ok")
	s.postureChanged(r.Context())
	out := apiPolicy(p)
	if all, err := s.cfg.Store.Policies(r.Context()); err == nil {
		out.Warnings = policyWarnings(p, all)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) policyByID(ctx context.Context, id int64) (store.Policy, error) {
	pols, err := s.cfg.Store.Policies(ctx)
	if err != nil {
		return store.Policy{}, err
	}
	for _, p := range pols {
		if p.ID == id {
			return p, nil
		}
	}
	return store.Policy{}, store.ErrNotFound
}

// postureChanged evaluates every device after a change of what policies require, so that the
// network maps follow at once.
func (s *Server) postureChanged(ctx context.Context) {
	if _, err := s.evaluatePosture(ctx, 0); err != nil {
		s.cfg.Logf("posture: %v", err)
	}
	s.checkVersion(ctx)
}

// devicePosture adds to the administrative view of devices their reports and how they do on every
// check now.
func devicePosture(info []api.PeerInfo, peers []store.Peer, policies []store.Policy, ps *postureState) {
	names := slices.Sorted(maps.Keys(ps.checks))
	for i, p := range peers {
		if f := ps.facts[p.ID]; f != nil {
			info[i].Posture = f
			info[i].PostureReportedAt = ps.reports[p.ID].ReportedAt.UTC().Format(time.RFC3339)
		}
		required := requiredChecks(p, policies)
		for _, name := range names {
			why := ps.live(p, name)
			if slices.Contains(required, name) {
				why = ps.reason(p, name) // what the network map follows
			}
			info[i].PostureChecks = append(info[i].PostureChecks, api.PostureCheckResult{Check: name, Passed: why == "",
				Reason: why, Required: slices.Contains(required, name)})
		}
	}
}
