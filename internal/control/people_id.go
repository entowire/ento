package control

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"entowire.com/ento/internal/api"
	entoid "entowire.com/ento/internal/id"
	"entowire.com/ento/internal/store"
)

// idPeople are the people of the control nodes' own identity provider (Config.ID): kept in the
// network's database, changed in process, so that a change takes effect at once.
type idPeople struct {
	p  *entoid.Provider
	st store.Store
}

// idMethods are the ways of signing in ento's own provider knows.
var idMethods = entoid.Methods

func (b *idPeople) kind() string        { return "ento" }
func (b *idPeople) methods() []string   { return idMethods }
func (b *idPeople) accountPage() string { return b.p.Issuer() + "/account" }

// idErr turns the store's errors into the answers the admin API gives for a provider's refusals.
func idErr(err error, what string) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return &errProvider{status: http.StatusNotFound, msg: "no such " + what}
	case errors.Is(err, store.ErrExists):
		return &errProvider{status: http.StatusConflict, msg: what + " already exists"}
	case errors.Is(err, entoid.ErrSetUp):
		return &errProvider{status: http.StatusConflict, msg: err.Error()}
	}
	return err
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (b *idPeople) record(ctx context.Context, x store.IDPerson) (personRecord, error) {
	keys, err := b.st.IDPasskeys(ctx, x.ID)
	if err != nil {
		return personRecord{}, err
	}
	kind := "set up"
	if len(entoid.Has(x, len(keys))) == 0 {
		kind = "new"
	}
	r := personRecord{ID: x.ID, Email: x.Email, GivenName: x.GivenName, FamilyName: x.FamilyName, Groups: slices.Clone(x.Groups),
		Enabled: !x.Disabled, CreatedAt: x.CreatedAt.Unix(), AccountType: kind}
	if !x.LastSignIn.IsZero() {
		r.LastLogin = x.LastSignIn.Unix()
	}
	return r, nil
}

func (b *idPeople) user(ctx context.Context, personID string) (personRecord, error) {
	x, err := b.st.IDPerson(ctx, personID)
	if err != nil {
		return personRecord{}, idErr(err, "person")
	}
	return b.record(ctx, x)
}

func (b *idPeople) list(ctx context.Context) ([]api.Person, error) {
	all, err := b.st.IDPeople(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]api.Person, 0, len(all))
	for _, x := range all {
		r, err := b.record(ctx, x)
		if err != nil {
			return nil, err
		}
		out = append(out, r.person())
	}
	return out, nil
}

func (b *idPeople) groups(ctx context.Context) ([]string, error) {
	gs, err := b.st.IDGroups(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.Name)
	}
	sort.Strings(out)
	return out, nil
}

func (b *idPeople) ensureGroups(ctx context.Context, want []string) error {
	have, err := b.groups(ctx)
	if err != nil {
		return err
	}
	for _, g := range want {
		if slices.Contains(have, g) {
			continue
		}
		kind := "people"
		if isDeviceGroup(g) {
			kind = "devices"
		}
		if err := b.st.PutIDGroup(ctx, store.IDGroup{Name: g, Kind: kind}); err != nil {
			return err
		}
	}
	return nil
}

func (b *idPeople) deleteGroup(ctx context.Context, name string) error {
	return idErr(b.st.DeleteIDGroup(ctx, name), "group "+name)
}

func (b *idPeople) passkeys(ctx context.Context, personID string) ([]api.Passkey, error) {
	keys, err := b.st.IDPasskeys(ctx, personID)
	if err != nil {
		return nil, err
	}
	out := []api.Passkey{}
	for _, k := range keys {
		out = append(out, api.Passkey{Name: k.Name, RegisteredAt: rfc3339(k.CreatedAt), LastUsedAt: rfc3339(k.LastUsed)})
	}
	return out, nil
}

func (b *idPeople) setupLink(ctx context.Context, personID string) (api.SetupLink, error) {
	link, exp, err := b.p.SetupLink(ctx, personID, 0, "")
	if err != nil {
		return api.SetupLink{}, idErr(err, "person")
	}
	return api.SetupLink{Link: link, ExpiresAt: rfc3339(exp)}, nil
}

func (b *idPeople) create(ctx context.Context, req api.NewPersonRequest) (api.Person, error) {
	if err := b.ensureGroups(ctx, req.Groups); err != nil {
		return api.Person{}, err
	}
	x, err := b.p.NewPerson(ctx, req.Email, req.GivenName, req.FamilyName, req.Groups)
	if err != nil {
		if errors.Is(err, store.ErrExists) {
			return api.Person{}, &errProvider{status: http.StatusConflict, msg: "someone has this e-mail address already"}
		}
		return api.Person{}, &errProvider{status: http.StatusBadRequest, msg: err.Error()}
	}
	r, err := b.record(ctx, x)
	return r.person(), err
}

func (b *idPeople) update(ctx context.Context, personID string, req api.UpdatePersonRequest) error {
	if req.Groups != nil {
		if err := b.ensureGroups(ctx, *req.Groups); err != nil {
			return err
		}
	}
	_, err := b.p.UpdatePerson(ctx, personID, func(x store.IDPerson) (store.IDPerson, error) {
		if req.Enabled != nil {
			x.Disabled = !*req.Enabled
		}
		if req.Groups != nil {
			x.Groups = slices.Clone(*req.Groups)
		}
		return x, nil
	})
	return idErr(err, "person")
}

func (b *idPeople) deletePasskey(ctx context.Context, personID, name string) error {
	keys, err := b.st.IDPasskeys(ctx, personID)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if k.Name == name {
			return idErr(b.p.DeletePasskey(ctx, personID, k.CredentialID), "passkey")
		}
	}
	return &errProvider{status: http.StatusNotFound, msg: "no passkey " + name}
}

func (b *idPeople) remove(ctx context.Context, personID string) error {
	return idErr(b.p.DeletePerson(ctx, personID), "person")
}

func (b *idPeople) defaultSignin(ctx context.Context) ([]string, error) {
	return entoid.DefaultSignin(ctx, b.st)
}

func (b *idPeople) setDefaultSignin(ctx context.Context, methods []string) error {
	return b.st.SetSetting(ctx, entoid.SettingDefaultSignin, strings.Join(methods, ","))
}

func (b *idPeople) groupList(ctx context.Context) ([]peopleGroup, error) {
	gs, err := b.st.IDGroups(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]peopleGroup, 0, len(gs))
	for _, g := range gs {
		meta := map[string]any{"kind": g.Kind}
		if g.Signin != nil {
			s := make([]any, 0, len(g.Signin))
			for _, m := range g.Signin {
				s = append(s, m)
			}
			meta["signin"] = s
		}
		out = append(out, peopleGroup{ID: g.Name, Name: g.Name, Meta: meta})
	}
	return out, nil
}

func (b *idPeople) setGroupSignin(ctx context.Context, g peopleGroup, methods []string) error {
	return b.st.PutIDGroup(ctx, store.IDGroup{Name: g.Name, Kind: "people", Signin: slices.Clone(methods)})
}

// personSignin: what the person has, what their groups allow, and what of it they can use.
func (b *idPeople) personSignin(ctx context.Context, personID string) (personSignin, error) {
	x, err := b.st.IDPerson(ctx, personID)
	if err != nil {
		return personSignin{}, idErr(err, "person")
	}
	keys, err := b.st.IDPasskeys(ctx, personID)
	if err != nil {
		return personSignin{}, err
	}
	def, err := b.defaultSignin(ctx)
	if err != nil {
		return personSignin{}, err
	}
	gs, err := b.st.IDGroups(ctx)
	if err != nil {
		return personSignin{}, err
	}
	out := personSignin{Password: x.Password != "", Passkeys: len(keys), TOTP: x.TOTP != nil,
		Methods: entoid.Has(x, len(keys)), Allowed: entoid.Allowed(x.Groups, gs, def), Usable: []string{}}
	if out.Methods == nil {
		out.Methods = []string{}
	}
	for _, m := range out.Methods {
		if slices.Contains(out.Allowed, m) {
			out.Usable = append(out.Usable, m)
		}
	}
	return out, nil
}
