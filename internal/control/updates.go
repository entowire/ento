package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
	"entowire.com/ento/internal/update"
)

// Updates (0.37): a control node offers the network's devices the release it runs itself. It keeps
// that release's manifest, its two signatures and every file the manifest lists in
// Config.UpdatesDir/<version>, downloaded from Config.Releases and checked with the keys built into
// this binary, and serves them on PathUpdate to enrolled devices, which check them again with their
// own keys: the control node is a cache, never trusted for what it serves. Which devices are
// offered it is the network's update policy (store.UpdatePolicy), minus Config.UpdatesExcept (a
// group updated otherwise: an environment's members, by their deployments).

const releaseCheckInterval = time.Hour

var releaseRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

type releaseCache struct {
	mu        sync.Mutex
	version   string // ready to serve; "" while not
	files     map[string]bool
	offeredAt time.Time
	problem   string // why nothing is offered, for administrators
}

func (s *Server) releaseLoop(ctx context.Context) {
	t := time.NewTicker(releaseCheckInterval)
	defer t.Stop()
	for {
		if err := s.prepareRelease(ctx); err != nil && ctx.Err() == nil {
			s.cfg.Logf("updates: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) setReleaseProblem(p string) {
	s.release.mu.Lock()
	s.release.problem = p
	s.release.mu.Unlock()
}

// prepareRelease makes this node's own release servable: verified on disk, or downloaded.
func (s *Server) prepareRelease(ctx context.Context) error {
	v := s.cfg.Version
	if !releaseRe.MatchString(v) {
		s.setReleaseProblem("this control node runs " + v + ", not a release")
		return nil
	}
	s.release.mu.Lock()
	ready := s.release.version == v
	s.release.mu.Unlock()
	if ready {
		return nil
	}
	dir := filepath.Join(s.cfg.UpdatesDir, v)
	m, err := s.verifyReleaseDir(dir)
	if err != nil {
		if err := s.downloadRelease(ctx, v, dir); err != nil {
			s.setReleaseProblem(err.Error())
			return err
		}
		if m, err = s.verifyReleaseDir(dir); err != nil {
			s.setReleaseProblem(err.Error())
			return err
		}
	}
	at, err := s.cfg.Store.ReleaseOffered(ctx, v, time.Now())
	if err != nil {
		return err
	}
	files := map[string]bool{"manifest.json": true, "manifest.json.sig": true, "manifest.json.p256.sig": true}
	for _, f := range m.Files {
		files[f.Name] = true
	}
	s.release.mu.Lock()
	s.release.version, s.release.files, s.release.offeredAt, s.release.problem = v, files, at, ""
	s.release.mu.Unlock()
	s.cfg.Logf("updates: release %s ready to offer (first offered %s)", v, at.UTC().Format(time.RFC3339))
	// Other versions' files go: only this node's own release is ever served.
	entries, _ := os.ReadDir(s.cfg.UpdatesDir)
	for _, e := range entries {
		if e.IsDir() && e.Name() != v {
			os.RemoveAll(filepath.Join(s.cfg.UpdatesDir, e.Name()))
		}
	}
	return nil
}

// verifyReleaseDir checks a release directory: the manifest with this binary's keys, the version
// this node runs, every file as listed.
func (s *Server) verifyReleaseDir(dir string) (*update.Manifest, error) {
	read := func(n string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, n)) }
	var parts [3][]byte
	for i, n := range []string{"manifest.json", "manifest.json.sig", "manifest.json.p256.sig"} {
		b, err := read(n)
		if err != nil {
			return nil, err
		}
		parts[i] = b
	}
	m, err := update.Verify(parts[0], parts[1], parts[2])
	if err != nil {
		return nil, err
	}
	if m.Version != s.cfg.Version {
		return nil, fmt.Errorf("release %s: the manifest says %s", s.cfg.Version, m.Version)
	}
	for _, f := range m.Files {
		r, err := os.Open(filepath.Join(dir, f.Name))
		if err != nil {
			return nil, err
		}
		_, err = f.Check(r)
		r.Close()
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}

// downloadRelease fetches a release into dir (written beside, renamed when complete): its manifest
// and signatures first, checked, then each file it lists, checked before it is kept.
func (s *Server) downloadRelease(ctx context.Context, v, dir string) error {
	base := strings.TrimRight(s.cfg.Releases, "/") + "/" + v + "/"
	tmp := dir + ".part"
	os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	get := func(name string, limit int64) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", base+name, nil)
		if err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("%s%s: %s", base, name, resp.Status)
		}
		return io.ReadAll(io.LimitReader(resp.Body, limit))
	}
	var parts [3][]byte
	for i, n := range []string{"manifest.json", "manifest.json.sig", "manifest.json.p256.sig"} {
		b, err := get(n, 1<<20)
		if err != nil {
			return err
		}
		parts[i] = b
		if err := os.WriteFile(filepath.Join(tmp, n), b, 0o644); err != nil {
			return err
		}
	}
	m, err := update.Verify(parts[0], parts[1], parts[2])
	if err != nil {
		return err
	}
	if m.Version != v {
		return fmt.Errorf("release %s: the manifest says %s", v, m.Version)
	}
	for _, f := range m.Files {
		raw, err := get(f.Name, f.Size+1)
		if err != nil {
			return err
		}
		b, err := f.Check(strings.NewReader(string(raw)))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(tmp, f.Name), b, 0o644); err != nil {
			return err
		}
	}
	os.RemoveAll(dir)
	return os.Rename(tmp, dir)
}

// offerUpdate is the release a device's map offers it under the network's policy, or nil.
func (s *Server) offerUpdate(ctx context.Context, p store.Peer) *api.Update {
	v, offered, ok := s.offerFor(ctx, p, time.Now())
	if !ok || !offered {
		return nil
	}
	return &api.Update{Version: v}
}

// offerFor reports the release this node offers (ok: one is ready) and whether p is offered it now.
func (s *Server) offerFor(ctx context.Context, p store.Peer, now time.Time) (string, bool, bool) {
	if s.cfg.UpdatesDir == "" {
		return "", false, false
	}
	s.release.mu.Lock()
	v, at := s.release.version, s.release.offeredAt
	s.release.mu.Unlock()
	if v == "" {
		return "", false, false
	}
	if s.cfg.UpdatesExcept != "" && hasGroup(p.Groups, s.cfg.UpdatesExcept) || p.Suspended {
		return v, false, true
	}
	pol, err := s.cfg.Store.UpdatePolicy(ctx)
	if err != nil {
		return v, false, true
	}
	switch pol.Mode {
	case "off":
		return v, false, true
	case "approve":
		if pol.Approved != v {
			return v, false, true
		}
	}
	if pol.FirstGroup != "" && !hasGroup(p.Groups, pol.FirstGroup) &&
		now.Before(at.Add(time.Duration(pol.FirstHours)*time.Hour)) {
		return v, false, true
	}
	return v, true, true
}

// handleUpdateFile serves the offered release's manifest, signatures and files to enrolled devices.
func (s *Server) handleUpdateFile(w http.ResponseWriter, r *http.Request, self store.Peer) {
	v, name := r.PathValue("version"), r.PathValue("name")
	s.release.mu.Lock()
	ok := s.release.version != "" && v == s.release.version && s.release.files[name]
	s.release.mu.Unlock()
	if !ok || self.Suspended {
		writeErr(w, http.StatusNotFound, "not the release this network offers")
		return
	}
	http.ServeFile(w, r, filepath.Join(s.cfg.UpdatesDir, v, name))
}

func (s *Server) handleGetUpdates(w http.ResponseWriter, r *http.Request, self store.Peer) {
	ctx := r.Context()
	pol, err := s.cfg.Store.UpdatePolicy(ctx)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	peers, err := s.cfg.Store.Peers(ctx)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	ps, err := loadPosture(ctx, s.cfg.Store, time.Now())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.release.mu.Lock()
	info := api.UpdatesInfo{Policy: apiUpdatesPolicy(pol), Release: s.release.version, Except: s.cfg.UpdatesExcept,
		Problem: s.release.problem, Devices: []api.DeviceVersion{}}
	if !s.release.offeredAt.IsZero() {
		info.OfferedAt = s.release.offeredAt.UTC().Format(time.RFC3339)
	}
	s.release.mu.Unlock()
	if s.cfg.UpdatesDir == "" {
		info.Problem = "this control node offers no updates (no --updates-dir)"
	}
	now := time.Now()
	for _, p := range peers {
		if p.Authority != "" {
			continue // memberships of other networks' devices: their home network updates them
		}
		d := api.DeviceVersion{ID: p.ID, Name: p.Hostname, OS: p.OS,
			Excluded: s.cfg.UpdatesExcept != "" && hasGroup(p.Groups, s.cfg.UpdatesExcept)}
		if f := ps.facts[p.ID]; f != nil {
			d.Version = f.Agent
			d.OS = f.OS
		}
		_, d.Offered, _ = s.offerFor(ctx, p, now)
		info.Devices = append(info.Devices, d)
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleSetUpdates(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.UpdatesPolicy
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := checkUpdatesPolicy(req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	pol := store.UpdatePolicy{Mode: req.Mode, Approved: req.Approved, FirstGroup: req.FirstGroup, FirstHours: req.FirstHours,
		SetBy: peerLabel(self), SetAt: time.Now()}
	if err := s.cfg.Store.SetUpdatePolicy(r.Context(), pol); err != nil {
		s.respondStoreErr(w, err)
		return
	}
	what := pol.Mode
	if pol.Mode == "approve" {
		what += " " + pol.Approved
	}
	if pol.FirstGroup != "" {
		what += fmt.Sprintf(" first=%s after=%dh", pol.FirstGroup, pol.FirstHours)
	}
	s.audit(r, &self, "updates_policy", what, "ok")
	s.checkVersion(r.Context())
	writeJSON(w, http.StatusOK, apiUpdatesPolicy(pol))
}

func checkUpdatesPolicy(p api.UpdatesPolicy) error {
	switch p.Mode {
	case "auto", "off":
		if p.Approved != "" {
			return errors.New("a version is approved only with mode approve")
		}
	case "approve":
		if !releaseRe.MatchString(p.Approved) {
			return errors.New("approve: the release to offer, X.Y.Z")
		}
	default:
		return errors.New("mode: auto, approve or off")
	}
	if p.FirstGroup != "" {
		if err := checkGroups([]string{p.FirstGroup}, false); err != nil {
			return fmt.Errorf("first group: %w", err)
		}
		if p.FirstHours < 1 || p.FirstHours > 24*30 {
			return errors.New("first group: the others wait 1 to 720 hours")
		}
	} else if p.FirstHours != 0 {
		return errors.New("hours to wait without a first group")
	}
	return nil
}

func apiUpdatesPolicy(p store.UpdatePolicy) api.UpdatesPolicy {
	out := api.UpdatesPolicy{Mode: p.Mode, Approved: p.Approved, FirstGroup: p.FirstGroup, FirstHours: p.FirstHours, SetBy: p.SetBy}
	if !p.SetAt.IsZero() {
		out.SetAt = p.SetAt.UTC().Format(time.RFC3339)
	}
	return out
}
