package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"entowire.com/ento/internal/api"
	entoid "entowire.com/ento/internal/id"
	"entowire.com/ento/internal/store"
)

// Connect providers that people sign in through at the network's own provider (ento id: upstream.go
// there). Kept in the network's database (entoid.SettingUpstreams), each client secret sealed with
// the provider's key; every change is audited (id_provider). Removing one is refused while it is
// someone's only way in (4.5: nobody, and so no admin, is left without one).

// idOff answers that outside providers need the control nodes' own provider.
func (s *Server) idOff(w http.ResponseWriter) bool {
	if s.id == nil || s.people == nil {
		writeErr(w, http.StatusNotFound, "outside providers are set in the network's own sign-in (ento id), which these control nodes do not run")
		return true
	}
	return false
}

// providerRedirects are the addresses a provider's client must have registered: the provider's
// callback on id.<domain>, and on the device's own sign-in where there is one.
func (s *Server) providerRedirects() []string {
	out := []string{s.id.Issuer() + entoid.UpstreamCallback}
	if u := s.id.HereURL(""); u != "" {
		out = append(out, strings.TrimSuffix(u, entoid.HerePath)+entoid.UpstreamCallback)
	}
	return out
}

func (s *Server) handleListProviders(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.idOff(w) {
		return
	}
	ups, err := entoid.Upstreams(r.Context(), s.cfg.Store)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	def, err := entoid.DefaultSignin(r.Context(), s.cfg.Store)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := api.IDProviders{Providers: []api.IDProvider{}, RedirectURIs: s.providerRedirects(),
		Allowed: slices.Contains(def, entoid.MethodProvider)}
	for _, u := range ups {
		out.Providers = append(out.Providers, api.IDProvider{Name: u.Name, Title: u.Title, Issuer: u.Issuer, ClientID: u.ClientID, Domains: u.Domains})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSetProvider adds or changes an outside provider, once its discovery answers as one.
func (s *Server) handleSetProvider(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.idOff(w) {
		return
	}
	var req api.SetIDProviderRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	u := entoid.Upstream{Name: r.PathValue("name"), Title: req.Title, Issuer: req.Issuer, ClientID: req.ClientID, Domains: req.Domains}
	if err := entoid.CheckUpstream(&u); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	ups, err := entoid.Upstreams(ctx, s.cfg.Store)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	i := slices.IndexFunc(ups, func(o entoid.Upstream) bool { return o.Name == u.Name })
	for j, o := range ups {
		if j != i && o.Issuer == u.Issuer {
			writeErr(w, http.StatusConflict, "provider "+o.Name+" has that issuer already")
			return
		}
	}
	switch {
	case req.ClientSecret != "":
		u.Secret = entoid.SealUpstreamSecret(s.cfg.ID.Key, u.Issuer, req.ClientSecret)
	case i >= 0 && ups[i].Issuer == u.Issuer:
		u.Secret = ups[i].Secret
	default:
		writeErr(w, http.StatusBadRequest, "a provider needs its client secret")
		return
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err = s.id.DiscoverUpstream(dctx, u.Issuer)
	cancel()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	what := "added"
	if i >= 0 {
		ups[i], what = u, "changed"
	} else {
		ups = append(ups, u)
	}
	if err := s.cfg.Store.SetSetting(ctx, entoid.SettingUpstreams, entoid.EncodeUpstreams(ups)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	detail := u.Name + " (" + u.Issuer + ", client " + u.ClientID
	if len(u.Domains) > 0 {
		detail += ", domains " + strings.Join(u.Domains, ",")
	}
	if req.ClientSecret != "" {
		detail += ", new secret"
	}
	s.audit(r, &self, "id_provider", detail+") "+what, "ok")
	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteProvider removes an outside provider, unless it is someone's only way in.
func (s *Server) handleDeleteProvider(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.idOff(w) {
		return
	}
	ctx := r.Context()
	ups, err := entoid.Upstreams(ctx, s.cfg.Store)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	name := r.PathValue("name")
	i := slices.IndexFunc(ups, func(o entoid.Upstream) bool { return o.Name == name })
	if i < 0 {
		writeErr(w, http.StatusNotFound, "no provider "+name)
		return
	}
	after := slices.Delete(slices.Clone(ups), i, i+1)
	stuck, err := s.withoutWayIn(ctx, ups, after)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(stuck) > 0 {
		s.audit(r, &self, "id_provider", name+" removed: the only way in of "+strings.Join(stuck, ", "), "denied")
		writeErr(w, http.StatusConflict, "nobody may be left without a way to sign in: "+strings.Join(stuck, ", ")+
			" would be (give them a passkey with a setup link first, or disable them)")
		return
	}
	if err := s.cfg.Store.SetSetting(ctx, entoid.SettingUpstreams, entoid.EncodeUpstreams(after)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, &self, "id_provider", name+" ("+ups[i].Issuer+") removed", "ok")
	w.WriteHeader(http.StatusNoContent)
}

// withoutWayIn are the enabled people who can sign in with the providers before and not with those
// after (their passkeys, password and app counted, and what their groups allow).
func (s *Server) withoutWayIn(ctx context.Context, before, after []entoid.Upstream) ([]string, error) {
	people, err := s.cfg.Store.IDPeople(ctx)
	if err != nil {
		return nil, err
	}
	def, err := entoid.DefaultSignin(ctx, s.cfg.Store)
	if err != nil {
		return nil, err
	}
	gs, err := s.cfg.Store.IDGroups(ctx)
	if err != nil {
		return nil, err
	}
	usable := func(has, allowed []string) bool {
		return slices.ContainsFunc(has, func(m string) bool { return slices.Contains(allowed, m) })
	}
	var out []string
	for _, x := range people {
		if x.Disabled {
			continue
		}
		keys, err := s.cfg.Store.IDPasskeys(ctx, x.ID)
		if err != nil {
			return nil, err
		}
		allowed := entoid.Allowed(x.Groups, gs, def)
		if usable(entoid.Has(x, len(keys), before), allowed) && !usable(entoid.Has(x, len(keys), after), allowed) {
			out = append(out, x.Email)
		}
	}
	return out, nil
}

// linkedProviders are the names of the providers whose account signs a person in.
func (s *Server) linkedProviders(ctx context.Context, personID string) ([]string, error) {
	if s.id == nil {
		return nil, nil
	}
	x, err := s.cfg.Store.IDPerson(ctx, personID)
	if err != nil {
		return nil, err
	}
	ups, err := entoid.Upstreams(ctx, s.cfg.Store)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, u := range ups {
		if x.Links[u.Issuer] != "" {
			out = append(out, u.Name)
		}
	}
	return out, nil
}

// handleUnlinkProvider forgets the account at a provider that signs a person in: their next sign-in
// through it links the account their address then names (an account they lost, or one that is now
// someone else's).
func (s *Server) handleUnlinkProvider(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.idOff(w) {
		return
	}
	ctx := r.Context()
	u, ok := s.upstreamNamed(ctx, r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no provider "+r.PathValue("name"))
		return
	}
	x, err := s.cfg.Store.IDPerson(ctx, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such person")
		return
	}
	if err := s.id.UnlinkUpstream(ctx, x.ID, u.Issuer); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, x.Email+" has no "+u.Name+" account linked")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, &self, "id_provider", x.Email+": "+u.Name+" account unlinked", "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) upstreamNamed(ctx context.Context, name string) (entoid.Upstream, bool) {
	ups, err := entoid.Upstreams(ctx, s.cfg.Store)
	if err != nil {
		return entoid.Upstream{}, false
	}
	for _, u := range ups {
		if u.Name == name {
			return u, true
		}
	}
	return entoid.Upstream{}, false
}
