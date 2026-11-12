package id

import (
	"context"
	"slices"
	"strings"

	"entowire.com/ento/internal/store"
)

// Ways of signing in. A network allows some of them by default, a people group may allow its own,
// and a person may use what all their people groups allow (the default when they are in none).
const (
	MethodPasskey         = "passkey"          // a passkey alone
	MethodPasswordPasskey = "password+passkey" // the password, then a passkey
	MethodPasswordTOTP    = "password+totp"    // the password, then a code from an authenticator app
)

// Methods are the ways of signing in the provider knows.
var Methods = []string{MethodPasskey, MethodPasswordPasskey, MethodPasswordTOTP}

// SettingDefaultSignin is the store setting holding the network's default ways of signing in
// (comma-separated; unset: every way).
const SettingDefaultSignin = "id_signin_default"

// Store is what the provider needs of the network's database.
type Store interface {
	store.IDStore
	Setting(ctx context.Context, key string) (string, bool, error)
}

// DefaultSignin is the network's default.
func DefaultSignin(ctx context.Context, st Store) ([]string, error) {
	v, ok, err := st.Setting(ctx, SettingDefaultSignin)
	if err != nil || !ok || v == "" {
		return slices.Clone(Methods), err
	}
	return strings.Split(v, ","), nil
}

// Allowed is what a person in these groups may use: what all their people groups allow (a group
// without its own policy allows the default; device groups count for nothing), else the default.
func Allowed(groups []string, all []store.IDGroup, def []string) []string {
	byName := map[string]store.IDGroup{}
	for _, g := range all {
		byName[g.Name] = g
	}
	out, seen := slices.Clone(def), false
	for _, name := range groups {
		g, ok := byName[name]
		if ok && g.Kind == "devices" {
			continue
		}
		pol := def
		if ok && g.Signin != nil {
			pol = g.Signin
		}
		if !seen {
			out, seen = slices.Clone(pol), true
			continue
		}
		out = slices.DeleteFunc(out, func(m string) bool { return !slices.Contains(pol, m) })
	}
	return out
}

// Has is what a person can complete: the ways of signing in their credentials make up.
func Has(x store.IDPerson, passkeys int) []string {
	var out []string
	if passkeys > 0 {
		out = append(out, MethodPasskey)
	}
	if x.Password != "" && passkeys > 0 {
		out = append(out, MethodPasswordPasskey)
	}
	if x.Password != "" && x.TOTP != nil {
		out = append(out, MethodPasswordTOTP)
	}
	return out
}

// access is a person's ways in: what they may use, what they have, and their passkeys.
type access struct {
	allowed, has []string
	passkeys     []store.IDPasskey
}

func (a access) can(m string) bool { return slices.Contains(a.allowed, m) && slices.Contains(a.has, m) }

// usable reports whether any way in is both allowed and complete.
func (a access) usable() bool {
	return slices.ContainsFunc(a.has, func(m string) bool { return slices.Contains(a.allowed, m) })
}

func (p *Provider) access(ctx context.Context, x store.IDPerson) (access, error) {
	keys, err := p.cfg.Store.IDPasskeys(ctx, x.ID)
	if err != nil {
		return access{}, err
	}
	def, err := DefaultSignin(ctx, p.cfg.Store)
	if err != nil {
		return access{}, err
	}
	gs, err := p.cfg.Store.IDGroups(ctx)
	if err != nil {
		return access{}, err
	}
	return access{allowed: Allowed(x.Groups, gs, def), has: Has(x, len(keys)), passkeys: keys}, nil
}

// setUp reports whether a person can sign in at all (with what they have, whatever is allowed):
// a setup link is only for those who cannot.
func setUp(x store.IDPerson, passkeys int) bool { return len(Has(x, passkeys)) > 0 }
