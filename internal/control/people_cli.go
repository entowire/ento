package control

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"entowire.com/ento/internal/api"
)

// InvitePerson makes a person at the identity provider, in groups, and returns a one-time link to
// set up their passkey: `ento control person`, for a network's first administrator, before anyone
// can use the dashboard. A person who exists but has not set up their account yet gets a new link
// (the old one lapsed); one who has is refused, so the command never takes over an account.
func InvitePerson(ctx context.Context, cfg PeopleConfig, email string, groups []string) (api.Person, api.SetupLink, bool, error) {
	return invitePerson(ctx, newPeople(cfg), email, groups)
}

func invitePerson(ctx context.Context, people *rauthyPeople, email string, groups []string) (p api.Person, link api.SetupLink, created bool, err error) {
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
