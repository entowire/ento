package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
)

// People: the administrators manage the people of the network's identity provider from the
// dashboard, through the provider's API with a key the control nodes hold (Config.People), so the
// provider's own administration can stay closed. Only Rauthy is known so far (its API at
// https://HOST/auth/v1, an API key "NAME$SECRET" with read, create, update and delete on Users and
// Groups; entowire's build adds the setup link it returns instead of mailing).

// PeopleConfig names the provider and how to reach it.
type PeopleConfig struct {
	Kind      string   // "rauthy"
	API       string   // its API's base address, e.g. https://id.example.com/auth/v1
	Key       string   // its API key
	ConnectTo []string // host:port to dial instead of the API's host (as OIDCConfig.ConnectTo)
}

// ParsePeopleKind checks a --people value.
func ParsePeopleKind(kind string) error {
	if kind != "rauthy" {
		return fmt.Errorf("unknown people provider %q (known: rauthy)", kind)
	}
	return nil
}

type rauthyPeople struct {
	cfg    PeopleConfig
	client *http.Client
}

func newPeople(cfg PeopleConfig) *rauthyPeople {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if len(cfg.ConnectTo) == 0 {
				return dialer.DialContext(ctx, network, addr)
			}
			var lastErr error
			for _, target := range cfg.ConnectTo {
				c, err := dialer.DialContext(ctx, network, target)
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
		MaxIdleConnsPerHost: 8,
	}
	cfg.API = strings.TrimRight(cfg.API, "/")
	return &rauthyPeople{cfg: cfg, client: &http.Client{Timeout: 15 * time.Second, Transport: transport}}
}

// errProvider is the provider's own refusal, with its status.
type errProvider struct {
	status int
	msg    string
}

func (e *errProvider) Error() string { return e.msg }

func (p *rauthyPeople) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.cfg.API+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "API-Key "+p.cfg.Key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("identity provider: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Message == "" {
			e.Message = strings.TrimSpace(string(b))
		}
		if len(e.Message) > 200 {
			e.Message = e.Message[:200]
		}
		return &errProvider{status: resp.StatusCode, msg: fmt.Sprintf("identity provider: %s (HTTP %d)", e.Message, resp.StatusCode)}
	}
	if out != nil && len(b) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

type rauthyUser struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	GivenName   string   `json:"given_name"`
	FamilyName  string   `json:"family_name"`
	Groups      []string `json:"groups"`
	Enabled     bool     `json:"enabled"`
	CreatedAt   int64    `json:"created_at"`
	LastLogin   int64    `json:"last_login"`
	AccountType string   `json:"account_type"`
}

func unixTime(s int64) string {
	if s <= 0 {
		return ""
	}
	return time.Unix(s, 0).UTC().Format(time.RFC3339)
}

func (u rauthyUser) person() api.Person {
	g := slices.Clone(u.Groups)
	if g == nil {
		g = []string{}
	}
	sort.Strings(g)
	return api.Person{ID: u.ID, Email: u.Email, GivenName: u.GivenName, FamilyName: u.FamilyName, Enabled: u.Enabled,
		Groups: g, Setup: u.AccountType == "new", Account: u.AccountType, CreatedAt: unixTime(u.CreatedAt), LastLogin: unixTime(u.LastLogin)}
}

func (p *rauthyPeople) user(ctx context.Context, id string) (rauthyUser, error) {
	var u rauthyUser
	err := p.do(ctx, "GET", "/users/"+url.PathEscape(id), nil, &u)
	return u, err
}

// list fetches every user: the list holds no groups or state, so each one is fetched too, a few at
// a time.
func (p *rauthyPeople) list(ctx context.Context) ([]api.Person, error) {
	var short []struct {
		ID string `json:"id"`
	}
	if err := p.do(ctx, "GET", "/users", nil, &short); err != nil {
		return nil, err
	}
	out := make([]api.Person, len(short))
	errs := make([]error, len(short))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, s := range short {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			u, err := p.user(ctx, s.ID)
			out[i], errs[i] = u.person(), err
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

func (p *rauthyPeople) groups(ctx context.Context) ([]string, error) {
	var gs []struct {
		Name string `json:"name"`
	}
	if err := p.do(ctx, "GET", "/groups", nil, &gs); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.Name)
	}
	sort.Strings(out)
	return out, nil
}

// ensureGroups makes the groups the provider does not have yet: it drops unknown ones from a user.
func (p *rauthyPeople) ensureGroups(ctx context.Context, want []string) error {
	have, err := p.groups(ctx)
	if err != nil {
		return err
	}
	for _, g := range want {
		if !slices.Contains(have, g) {
			kind := "people"
			if isDeviceGroup(g) {
				kind = "devices"
			}
			if err := p.do(ctx, "POST", "/groups", map[string]any{"group": g, "meta": map[string]string{"kind": kind}}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *rauthyPeople) deleteGroup(ctx context.Context, name string) error {
	var gs []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := p.do(ctx, "GET", "/groups", nil, &gs); err != nil {
		return err
	}
	for _, g := range gs {
		if g.Name == name {
			return p.do(ctx, "DELETE", "/groups/"+url.PathEscape(g.ID), nil, nil)
		}
	}
	return &errProvider{status: http.StatusNotFound, msg: "no group " + name}
}

func (p *rauthyPeople) passkeys(ctx context.Context, id string) ([]api.Passkey, error) {
	var ks []struct {
		Name       string `json:"name"`
		Registered int64  `json:"registered"`
		LastUsed   int64  `json:"last_used"`
	}
	if err := p.do(ctx, "GET", "/users/"+url.PathEscape(id)+"/webauthn", nil, &ks); err != nil {
		return nil, err
	}
	out := []api.Passkey{}
	for _, k := range ks {
		out = append(out, api.Passkey{Name: k.Name, RegisteredAt: unixTime(k.Registered), LastUsedAt: unixTime(k.LastUsed)})
	}
	return out, nil
}

func (p *rauthyPeople) setupLink(ctx context.Context, id string) (api.SetupLink, error) {
	var r struct {
		Link    string `json:"link"`
		Expires int64  `json:"expires"`
	}
	if err := p.do(ctx, "POST", "/users/"+url.PathEscape(id)+"/setup_link", nil, &r); err != nil {
		return api.SetupLink{}, err
	}
	return api.SetupLink{Link: r.Link, ExpiresAt: unixTime(r.Expires)}, nil
}

func (p *rauthyPeople) create(ctx context.Context, req api.NewPersonRequest) (api.Person, error) {
	if err := p.ensureGroups(ctx, req.Groups); err != nil {
		return api.Person{}, err
	}
	body := map[string]any{"email": req.Email, "language": "en", "roles": []string{}, "groups": req.Groups}
	if req.GivenName != "" {
		body["given_name"] = req.GivenName
	}
	if req.FamilyName != "" {
		body["family_name"] = req.FamilyName
	}
	var u rauthyUser
	if err := p.do(ctx, "POST", "/users", body, &u); err != nil {
		return api.Person{}, err
	}
	return u.person(), nil
}

func (p *rauthyPeople) update(ctx context.Context, id string, req api.UpdatePersonRequest) error {
	var put []map[string]any
	if req.Enabled != nil {
		put = append(put, map[string]any{"key": "enabled", "value": *req.Enabled})
	}
	if req.Groups != nil {
		if err := p.ensureGroups(ctx, *req.Groups); err != nil {
			return err
		}
		put = append(put, map[string]any{"key": "groups", "value": *req.Groups})
	}
	if len(put) == 0 {
		return nil
	}
	return p.do(ctx, "PATCH", "/users/"+url.PathEscape(id), map[string]any{"put": put, "del": []string{}}, nil)
}

func (p *rauthyPeople) deletePasskey(ctx context.Context, id, name string) error {
	return p.do(ctx, "DELETE", "/users/"+url.PathEscape(id)+"/webauthn/delete/"+url.PathEscape(name), map[string]any{}, nil)
}

func (p *rauthyPeople) remove(ctx context.Context, id string) error {
	return p.do(ctx, "DELETE", "/users/"+url.PathEscape(id), nil, nil)
}

// --- the admin API ---------------------------------------------------------------------------------

// personGroup is what a person's group may be named: the provider's rule for users' groups.
var personGroup = regexp.MustCompile(`^[a-z0-9\-_/:]{2,64}$`)

func checkPersonGroups(gs []string) error {
	for _, g := range gs {
		if isDeviceGroup(g) {
			return fmt.Errorf("%s is a device group: people are put in people groups", strings.TrimPrefix(g, DevicePrefix))
		}
		if !personGroup.MatchString(g) {
			return fmt.Errorf("group %q: 2 to 64 lowercase letters, digits, - _ / :", g)
		}
	}
	return nil
}

func (s *Server) peopleOff(w http.ResponseWriter) bool {
	if s.people == nil {
		writeErr(w, http.StatusNotFound, "people are not managed here: the control nodes run without --people")
		return true
	}
	return false
}

// respondPeopleErr answers with the provider's refusal (its client errors as they are, the rest as
// a bad gateway).
func respondPeopleErr(w http.ResponseWriter, err error) {
	var pe *errProvider
	if errors.As(err, &pe) && pe.status >= 400 && pe.status < 500 && pe.status != http.StatusUnauthorized && pe.status != http.StatusForbidden {
		writeErr(w, pe.status, pe.msg)
		return
	}
	writeErr(w, http.StatusBadGateway, err.Error())
}

// guardLastAdmin refuses a change that would leave the network without an enabled admin person, or
// that an administrator would make to their own account (they would lock themselves out).
func (s *Server) guardLastAdmin(ctx context.Context, self store.Peer, target rauthyUser, losesAdmin bool) error {
	if !losesAdmin {
		return nil
	}
	if isSelf(self, target) {
		return errors.New("not on your own account: another admin does that")
	}
	if !intersects(target.Groups, s.personAdminGroups()) || !target.Enabled {
		return nil
	}
	people, err := s.people.list(ctx)
	if err != nil {
		return err
	}
	// Another admin who can sign in: enabled, and their account set up (one who never opened their
	// setup link cannot).
	for _, p := range people {
		if p.ID != target.ID && p.Enabled && !p.Setup && intersects(p.Groups, s.personAdminGroups()) {
			return nil
		}
	}
	return errors.New(target.Email + " is the only enabled admin: make another admin first")
}

// keptGroup: a group that is never deleted: the built-in device groups, the people groups that give
// a role or viewing, and those the configuration names for roles, viewing and approval.
func (s *Server) keptGroup(name string) bool {
	kept := append(slices.Clone(builtinDeviceGroups), s.adminGroups()...)
	kept = append(kept, s.operatorGroups()...)
	kept = append(kept, s.personAdminGroups()...)
	kept = append(kept, s.viewerGroups()...)
	kept = append(kept, "admins", "operators", "viewers")
	if s.cfg.OIDC != nil {
		kept = append(kept, s.cfg.OIDC.OperatorGroups...)
		kept = append(kept, s.cfg.OIDC.ApproveGroups...)
	}
	return slices.Contains(kept, name)
}

// isSelf: the caller's own account, by the provider's subject (the e-mail address only for an older
// session without one).
func isSelf(self store.Peer, target rauthyUser) bool {
	if self.User != "" {
		return self.User == target.ID
	}
	return self.UserName != "" && strings.EqualFold(self.UserName, target.Email)
}

// guardPasskey refuses removing a passkey that is someone's way in when that cannot be undone
// safely (I6): one's own (another admin does that), another admin's from a device with nobody
// signed in (whose root would then take the account over with a setup link), and the last one of
// the only admin who can sign in.
func (s *Server) guardPasskey(ctx context.Context, self store.Peer, target rauthyUser) error {
	if isSelf(self, target) {
		return errors.New("not on your own account: another admin does that")
	}
	admin := intersects(target.Groups, s.personAdminGroups())
	if !admin {
		return nil
	}
	if self.User == "" || !self.Person.Active {
		return errors.New("an admin's passkeys are removed by an admin signed in on their device, not by a device alone")
	}
	keys, err := s.people.passkeys(ctx, target.ID)
	if err != nil {
		return err
	}
	if len(keys) > 1 {
		return nil
	}
	return s.guardLastAdmin(ctx, self, target, true)
}

func (s *Server) handleListPeople(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.peopleOff(w) {
		return
	}
	people, err := s.people.list(r.Context())
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	groups, err := s.people.groups(r.Context())
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.PeopleList{Provider: s.people.cfg.Kind, People: people, Groups: groups})
}

func (s *Server) handleGetPerson(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.peopleOff(w) {
		return
	}
	u, err := s.people.user(r.Context(), r.PathValue("id"))
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	p := u.person()
	if p.Passkeys, err = s.people.passkeys(r.Context(), u.ID); err != nil {
		respondPeopleErr(w, err)
		return
	}
	if si, err := s.people.personSignin(r.Context(), u.ID); err == nil {
		p.Signin = &api.PersonSignin{Password: si.Password, Passkeys: si.Passkeys, TOTP: si.TOTP, Methods: si.Methods, Allowed: si.Allowed, Usable: si.Usable}
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleAddPerson(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.peopleOff(w) {
		return
	}
	var req api.NewPersonRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if !strings.Contains(req.Email, "@") || len(req.Email) > 254 {
		writeErr(w, http.StatusBadRequest, "an e-mail address is needed")
		return
	}
	if req.Groups == nil {
		req.Groups = []string{}
	}
	if err := checkPersonGroups(req.Groups); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p, err := s.people.create(r.Context(), req)
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	link, err := s.people.setupLink(r.Context(), p.ID)
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	s.audit(r, &self, "person_added", fmt.Sprintf("person %s groups %s", p.Email, strings.Join(req.Groups, ",")), "ok")
	writeJSON(w, http.StatusOK, api.NewPersonResult{Person: p, Setup: link})
}

func (s *Server) handleUpdatePerson(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.peopleOff(w) {
		return
	}
	var req api.UpdatePersonRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.Groups != nil {
		if err := checkPersonGroups(*req.Groups); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	u, err := s.people.user(r.Context(), r.PathValue("id"))
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	loses := req.Enabled != nil && !*req.Enabled || req.Groups != nil && intersects(u.Groups, s.personAdminGroups()) && !intersects(*req.Groups, s.personAdminGroups())
	if err := s.guardLastAdmin(r.Context(), self, u, loses); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if req.Groups != nil {
		if err := s.checkPersonFits(r.Context(), u, *req.Groups); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
	}
	if err := s.people.update(r.Context(), u.ID, req); err != nil {
		respondPeopleErr(w, err)
		return
	}
	var what []string
	if req.Enabled != nil {
		what = append(what, fmt.Sprintf("enabled %t", *req.Enabled))
	}
	if req.Groups != nil {
		what = append(what, "groups "+strings.Join(*req.Groups, ","))
	}
	s.audit(r, &self, "person_changed", fmt.Sprintf("person %s %s", u.Email, strings.Join(what, " ")), "ok")
	u, err = s.people.user(r.Context(), u.ID)
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, u.person())
}

func (s *Server) handleDeletePerson(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.peopleOff(w) {
		return
	}
	u, err := s.people.user(r.Context(), r.PathValue("id"))
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	if err := s.guardLastAdmin(r.Context(), self, u, true); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err := s.people.remove(r.Context(), u.ID); err != nil {
		respondPeopleErr(w, err)
		return
	}
	s.audit(r, &self, "person_deleted", "person "+u.Email, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeletePasskey(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.peopleOff(w) {
		return
	}
	u, err := s.people.user(r.Context(), r.PathValue("id"))
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	name := r.PathValue("name")
	if err := s.guardPasskey(r.Context(), self, u); err != nil {
		s.audit(r, &self, "person_passkey_deleted", fmt.Sprintf("person %s passkey %q: %v", u.Email, name, err), "denied")
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err := s.people.deletePasskey(r.Context(), u.ID, name); err != nil {
		respondPeopleErr(w, err)
		return
	}
	s.audit(r, &self, "person_passkey_deleted", fmt.Sprintf("person %s passkey %q", u.Email, name), "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePersonSetup(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.peopleOff(w) {
		return
	}
	u, err := s.people.user(r.Context(), r.PathValue("id"))
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	// A setup link sets up an account that has no way to sign in yet, never one that has: whoever
	// opens it would take the account over (I6). A person who lost their passkey gets one once
	// their passkeys are removed and they have neither a password nor an authenticator app.
	si, err := s.people.personSignin(r.Context(), u.ID)
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	if si.Password || si.Passkeys > 0 || si.TOTP {
		s.audit(r, &self, "person_setup_link", "person "+u.Email+": the account has a way to sign in", "denied")
		writeErr(w, http.StatusConflict, u.Email+" can still sign in (a password, a passkey or an authenticator app): a setup link would take the account over")
		return
	}
	link, err := s.people.setupLink(r.Context(), u.ID)
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	s.audit(r, &self, "person_setup_link", "person "+u.Email, "ok")
	writeJSON(w, http.StatusOK, link)
}

// --- groups: one kind, kept in the identity provider --------------------------------------------

// keepGroups makes the groups a device, an invitation or a rule names in the identity provider, so
// that every group of the network is one there (people can be put in it too). Best effort: a
// provider out of reach never stops the change itself, it is logged.
func (s *Server) keepGroups(ctx context.Context, groups []string) {
	if s.people == nil {
		return
	}
	var want []string
	for _, g := range groups {
		if g != "*" && !isRoute(g) && personGroup.MatchString(g) {
			want = append(want, g)
		}
	}
	if len(want) == 0 {
		return
	}
	if err := s.people.ensureGroups(ctx, want); err != nil {
		s.cfg.Logf("groups %s not made in the identity provider: %v", strings.Join(want, ","), err)
	}
}

func (s *Server) handleAddGroup(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.peopleOff(w) {
		return
	}
	var req api.NewGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	name := strings.TrimPrefix(req.Name, DevicePrefix)
	if !personGroup.MatchString(name) || strings.Contains(name, ":") {
		writeErr(w, http.StatusBadRequest, "a group name: 2 to 64 lowercase letters, digits, - _ /")
		return
	}
	if req.Kind == "devices" || isDeviceGroup(req.Name) {
		name = DevicePrefix + name
	}
	req.Name = name
	if err := s.people.ensureGroups(r.Context(), []string{req.Name}); err != nil {
		respondPeopleErr(w, err)
		return
	}
	s.audit(r, &self, "group_added", "group "+req.Name, "ok")
	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteGroup removes a group from the identity provider, unless something still uses it.
func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.peopleOff(w) {
		return
	}
	name := r.PathValue("name")
	ctx := r.Context()
	// The built-in groups and the groups that give roles stay, empty or not (constitution 3.3, A7).
	if s.keptGroup(name) {
		s.audit(r, &self, "group_deleted", "group "+name+": built in", "denied")
		writeErr(w, http.StatusConflict, name+" is built in (a role, isolation or viewing): it is never deleted")
		return
	}
	var users []string
	policies, err := s.cfg.Store.Policies(ctx)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	for _, p := range policies {
		if p.Source == name || p.Destination == name {
			users = append(users, fmt.Sprintf("rule %s to %s", p.Source, p.Destination))
		}
	}
	peers, err := s.cfg.Store.Peers(ctx)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	for _, p := range peers {
		if slices.Contains(p.Groups, name) || slices.Contains(p.Machine.Groups, name) {
			users = append(users, "device "+p.Hostname)
		}
	}
	tokens, err := s.cfg.Store.ActiveTokens(ctx, time.Now())
	if err == nil {
		for _, t := range tokens {
			if slices.Contains(t.Groups, name) {
				users = append(users, fmt.Sprintf("invitation #%d", t.ID))
			}
		}
	}
	links, err := s.cfg.Store.Links(ctx)
	if err == nil {
		for _, l := range links {
			if slices.Contains(l.Groups, name) {
				users = append(users, "link "+l.Name)
			}
		}
	}
	people, err := s.people.list(ctx)
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	for _, p := range people {
		if slices.Contains(p.Groups, name) {
			users = append(users, "person "+p.Email)
		}
	}
	if len(users) > 0 {
		if len(users) > 5 {
			users = append(users[:5], fmt.Sprintf("%d more", len(users)-5))
		}
		writeErr(w, http.StatusConflict, fmt.Sprintf("%s is still used by %s", name, strings.Join(users, ", ")))
		return
	}
	if err := s.people.deleteGroup(ctx, name); err != nil {
		respondPeopleErr(w, err)
		return
	}
	s.audit(r, &self, "group_deleted", "group "+name, "ok")
	go s.syncGroups(context.WithoutCancel(ctx))
	w.WriteHeader(http.StatusNoContent)
}

// checkDeviceGroups refuses, where people are managed here, a device group that only exists as a
// people group (a device is never put in users): the name was meant for people.
func (s *Server) checkDeviceGroups(ctx context.Context, groups []string) error {
	if s.people == nil {
		return nil
	}
	have, err := s.people.groups(ctx)
	if err != nil {
		return nil // the provider out of reach: the change goes on, keepGroups logs it
	}
	for _, g := range groups {
		if !isDeviceGroup(g) || slices.Contains(have, g) || slices.Contains(builtinDeviceGroups, g) {
			continue
		}
		plain := strings.TrimPrefix(g, DevicePrefix)
		if slices.Contains(have, plain) {
			return fmt.Errorf("%s is a people group: devices are put in device groups", plain)
		}
		// Groups come from the identity provider only: make the group first (the Access page).
		return fmt.Errorf("no device group %s: make it first (Access, New group)", plain)
	}
	return nil
}

// resolveRuleGroup gives a rule's group its kind where the name alone does not say it: a name that
// is only a device group means that one; one that is both must be written device:NAME (the
// dashboard always does).
func (s *Server) resolveRuleGroup(ctx context.Context, g string) (string, error) {
	if g == "*" || isRoute(g) || strings.Contains(g, ":") {
		return g, nil
	}
	var device, person bool
	if s.people != nil {
		if have, err := s.people.groups(ctx); err == nil {
			device, person = slices.Contains(have, DevicePrefix+g), slices.Contains(have, g)
		}
	}
	if !device && !person {
		if peers, err := s.cfg.Store.Peers(ctx); err == nil {
			for _, p := range peers {
				if slices.Contains(p.Machine.Groups, DevicePrefix+g) {
					device = true
				}
			}
		}
	}
	switch {
	case s.people != nil && !device && !person:
		return "", fmt.Errorf("no group %s", g)
	case device && person:
		return "", fmt.Errorf("%s is both a people group and a device group: write device:%s for the devices'", g, g)
	case device:
		return DevicePrefix + g, nil
	}
	return g, nil
}

// --- sign-in policies (0.46) ------------------------------------------------------------------------

// SigninMethods are the ways of signing in the identity provider knows (entowire's build of Rauthy):
// a policy allows some of them, for the network (the default) or for a people group.
var SigninMethods = []string{"passkey", "password+passkey", "password+totp"}

type rauthyGroup struct {
	ID   string         `json:"id"`
	Name string         `json:"name"`
	Meta map[string]any `json:"meta"`
}

func (p *rauthyPeople) groupList(ctx context.Context) ([]rauthyGroup, error) {
	var gs []rauthyGroup
	err := p.do(ctx, "GET", "/groups", nil, &gs)
	return gs, err
}

// groupSignin is a group's own policy (nil: the default).
func groupSignin(g rauthyGroup) []string {
	raw, ok := g.Meta["signin"].([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, m := range raw {
		if s, ok := m.(string); ok && slices.Contains(SigninMethods, s) {
			out = append(out, s)
		}
	}
	return out
}

func (p *rauthyPeople) defaultSignin(ctx context.Context) ([]string, error) {
	var r struct {
		Default []string `json:"default"`
	}
	err := p.do(ctx, "GET", "/signin_policy", nil, &r)
	return r.Default, err
}

type personSignin struct {
	Password bool     `json:"password"`
	Passkeys int      `json:"passkeys"`
	TOTP     bool     `json:"totp"`
	Methods  []string `json:"methods"`
	Allowed  []string `json:"allowed"`
	Usable   []string `json:"usable"`
}

func (p *rauthyPeople) personSignin(ctx context.Context, id string) (personSignin, error) {
	var r personSignin
	err := p.do(ctx, "GET", "/users/"+url.PathEscape(id)+"/signin", nil, &r)
	return r, err
}

// effectiveSignin is what a person with these groups may use: what all their people groups allow
// (a group without its own policy allows the default), the default when they have none.
func effectiveSignin(groups []string, byGroup map[string][]string, def []string) []string {
	out := slices.Clone(def)
	seen := false
	for _, g := range groups {
		if isDeviceGroup(g) {
			continue
		}
		pol, ok := byGroup[g]
		if !ok || pol == nil {
			pol = def
		}
		if !seen {
			out, seen = slices.Clone(pol), true
			continue
		}
		out = slices.DeleteFunc(out, func(m string) bool { return !slices.Contains(pol, m) })
	}
	return out
}

func checkMethods(ms []string) error {
	if len(ms) == 0 {
		return errors.New("at least one way of signing in")
	}
	for i, m := range ms {
		if !slices.Contains(SigninMethods, m) || slices.Contains(ms[:i], m) {
			return fmt.Errorf("unknown or repeated way of signing in %q", m)
		}
	}
	return nil
}

// signinState is the default and every group's own policy, as the provider has them.
func (s *Server) signinState(ctx context.Context) (def []string, byGroup map[string][]string, groups []rauthyGroup, err error) {
	if def, err = s.people.defaultSignin(ctx); err != nil {
		return
	}
	if groups, err = s.people.groupList(ctx); err != nil {
		return
	}
	byGroup = map[string][]string{}
	for _, g := range groups {
		if !isDeviceGroup(g.Name) {
			byGroup[g.Name] = groupSignin(g)
		}
	}
	return
}

// leftOut names the people who would have no way in under a changed policy (whatIf gives each
// person's groups, the policies and the default to judge by).
func (s *Server) leftOut(ctx context.Context, people []api.Person, byGroup map[string][]string, def []string, groupsOf func(api.Person) []string) ([]string, error) {
	var out []string
	for _, p := range people {
		allowed := effectiveSignin(groupsOf(p), byGroup, def)
		si, err := s.people.personSignin(ctx, p.ID)
		if err != nil {
			return nil, err
		}
		if len(si.Methods) == 0 { // not set up yet: their setup link offers what is allowed
			continue
		}
		if !slices.ContainsFunc(si.Methods, func(m string) bool { return slices.Contains(allowed, m) }) {
			out = append(out, p.Email)
		}
	}
	return out, nil
}

func (s *Server) handleGetSignin(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.peopleOff(w) {
		return
	}
	def, byGroup, _, err := s.signinState(r.Context())
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	out := api.SigninPolicy{Default: def, Methods: SigninMethods, Groups: map[string][]string{}}
	for g, pol := range byGroup {
		if pol != nil {
			out.Groups[g] = pol
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSetSignin changes the default, or a people group's own policy (Group set; Methods nil: the
// group follows the default again), unless someone would be left without a way in.
func (s *Server) handleSetSignin(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.peopleOff(w) {
		return
	}
	var req api.SetSigninRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.Group == "" || req.Methods != nil {
		if err := checkMethods(req.Methods); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	ctx := r.Context()
	def, byGroup, groups, err := s.signinState(ctx)
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	var target *rauthyGroup
	if req.Group != "" {
		for i := range groups {
			if groups[i].Name == req.Group && !isDeviceGroup(req.Group) {
				target = &groups[i]
			}
		}
		if target == nil {
			writeErr(w, http.StatusNotFound, "no people group "+req.Group)
			return
		}
		byGroup[req.Group] = req.Methods
	} else {
		def = req.Methods
	}
	people, err := s.people.list(ctx)
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	out, err := s.leftOut(ctx, people, byGroup, def, func(p api.Person) []string { return p.Groups })
	if err != nil {
		respondPeopleErr(w, err)
		return
	}
	if len(out) > 0 {
		writeErr(w, http.StatusConflict, "nobody may be left without a way to sign in: "+strings.Join(out, ", ")+" would be")
		return
	}
	if target == nil {
		if err := s.people.do(ctx, "PUT", "/signin_policy", map[string]any{"default": req.Methods}, nil); err != nil {
			respondPeopleErr(w, err)
			return
		}
		s.audit(r, &self, "signin_policy", "default "+strings.Join(req.Methods, ","), "ok")
	} else {
		meta := map[string]any{}
		for k, v := range target.Meta {
			meta[k] = v
		}
		meta["kind"] = "people"
		if req.Methods == nil {
			delete(meta, "signin")
		} else {
			meta["signin"] = req.Methods
		}
		if err := s.people.do(ctx, "PUT", "/groups/"+url.PathEscape(target.ID), map[string]any{"group": target.Name, "meta": meta}, nil); err != nil {
			respondPeopleErr(w, err)
			return
		}
		what := strings.Join(req.Methods, ",")
		if req.Methods == nil {
			what = "the default"
		}
		s.audit(r, &self, "signin_policy", "group "+target.Name+" "+what, "ok")
	}
	w.WriteHeader(http.StatusNoContent)
}

// checkPersonFits refuses new groups for a person whose ways of signing in they would not allow.
func (s *Server) checkPersonFits(ctx context.Context, u rauthyUser, groups []string) error {
	def, byGroup, _, err := s.signinState(ctx)
	if err != nil {
		return err
	}
	out, err := s.leftOut(ctx, []api.Person{u.person()}, byGroup, def, func(api.Person) []string { return groups })
	if err != nil {
		return err
	}
	if len(out) > 0 {
		allowed := effectiveSignin(groups, byGroup, def)
		return fmt.Errorf("%s has no way of signing in these groups allow (%s): add one first (a setup link), or choose other groups", u.Email, strings.Join(allowed, ", "))
	}
	return nil
}
