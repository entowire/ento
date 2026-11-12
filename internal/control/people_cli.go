package control

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"entowire.com/ento/internal/api"
	entoid "entowire.com/ento/internal/id"
	"entowire.com/ento/internal/store"
)

// InvitePersonID makes a person in the control nodes' own identity provider (in the network's
// database st), in groups, and returns a one-time link to set up their account: `ento control
// person`, for a network's first administrator, before anyone can use the dashboard. A person who
// exists but has not set up their account yet gets a new link (the old one lapsed); one who has is
// refused, so the command never takes over an account. With reset, a person who exists loses every way in first (passkeys, password, app,
// and what they are signed in with): the recovery of an account whose person lost them, from the
// control nodes' command line (constitution 4.6).
func InvitePersonID(ctx context.Context, st store.Store, cfg IDConfig, email string, groups []string, reset, noLink bool) (api.Person, api.SetupLink, bool, error) {
	p, err := entoid.New(entoid.Config{Name: cfg.Name, Title: cfg.Title, Key: cfg.Key, Store: st})
	if err != nil {
		return api.Person{}, api.SetupLink{}, false, err
	}
	if reset {
		if err := p.ResetPerson(ctx, strings.ToLower(strings.TrimSpace(email))); err != nil {
			return api.Person{}, api.SetupLink{}, false, err
		}
	}
	b := &idPeople{p: p, st: st}
	if noLink {
		return invitePersonOnly(ctx, b, email, groups)
	}
	return invitePerson(ctx, b, email, groups)
}

// invitePersonOnly makes the person as invitePerson does, without a setup link: for an invitation
// with a device's words (`ento control token --person`), whose device gets the link itself.
func invitePersonOnly(ctx context.Context, people peopleBackend, email string, groups []string) (api.Person, api.SetupLink, bool, error) {
	email = strings.TrimSpace(email)
	all, err := people.list(ctx)
	if err != nil {
		return api.Person{}, api.SetupLink{}, false, err
	}
	for _, q := range all {
		if strings.EqualFold(q.Email, email) {
			if !q.Setup {
				return q, api.SetupLink{}, false, fmt.Errorf("%s has set up their account already", q.Email)
			}
			return q, api.SetupLink{}, false, nil
		}
	}
	if groups == nil {
		groups = []string{}
	}
	if err := checkPersonGroups(groups); err != nil {
		return api.Person{}, api.SetupLink{}, false, err
	}
	p, err := people.create(ctx, api.NewPersonRequest{Email: email, Groups: groups})
	return p, api.SetupLink{}, err == nil, err
}

func invitePerson(ctx context.Context, people peopleBackend, email string, groups []string) (p api.Person, link api.SetupLink, created bool, err error) {
	email = strings.TrimSpace(email)
	if !strings.Contains(email, "@") || len(email) > 254 {
		return p, link, false, errors.New("an e-mail address is needed")
	}
	if groups == nil {
		groups = []string{}
	}
	if err := checkPersonGroups(groups); err != nil {
		return p, link, false, err
	}
	all, err := people.list(ctx)
	if err != nil {
		return p, link, false, err
	}
	for _, q := range all {
		if !strings.EqualFold(q.Email, email) {
			continue
		}
		if !q.Setup {
			return q, link, false, fmt.Errorf("%s has set up their account already: a new link would take it over (the dashboard's People page removes their passkeys first, if they lost them)", q.Email)
		}
		link, err = people.setupLink(ctx, q.ID)
		return q, link, false, err
	}
	p, err = people.create(ctx, api.NewPersonRequest{Email: email, Groups: groups})
	if err != nil {
		return p, link, false, err
	}
	link, err = people.setupLink(ctx, p.ID)
	return p, link, true, err
}
