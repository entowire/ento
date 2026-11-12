package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
)

// Invitations of a person with a device's words (0.57): the network's first administrator gets one
// invitation, not two. Their words name their account (`ento control token --person EMAIL`), the
// device that redeems them is invited for that account, and its first sign-in sets the account up:
// the control node answers its sign-in with a setup link of the control nodes' own provider whose
// next step is that very sign-in (an app's authorization request, or a device code), which the
// provider completes once the account is set up. Nothing but the words travels: the setup link
// reaches only the device that redeemed them, in the answer to a call signed with its key, and the
// device is then bound to that account and no other (loginDone refuses another person).
//
// The invitation is kept with the provider's short-lived records: under the token until it is
// redeemed, then under the device for invitedLife.

const (
	invitedLife   = 7 * 24 * time.Hour
	inviteSetup   = 30 * time.Minute // a setup link given to an invited device
	kindInvite    = "invite"
	invitePrefixT = "invite-token:"
	invitePrefixP = "invited-peer:"
)

type invitation struct {
	Person string `json:"person"` // the account's ID at the control nodes' own provider
}

// InviteWithToken makes token t an invitation of the person with that address: the device that
// redeems it is invited for their account. The account must be there, and not set up yet.
func InviteWithToken(ctx context.Context, st store.Store, t store.Token, email string) error {
	x, err := st.IDPersonByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		return fmt.Errorf("no account %s in the network's sign-in (ento control person --id makes it): %w", email, err)
	}
	b, _ := json.Marshal(invitation{Person: x.ID})
	return st.PutIDState(ctx, store.IDState{Key: invitePrefixT + strconv.FormatInt(t.ID, 10), Kind: kindInvite,
		Person: x.ID, Data: b, ExpiresAt: t.ExpiresAt})
}

// takeInvitation moves the invitation of the token a device redeemed to the device.
func (s *Server) takeInvitation(ctx context.Context, tokenID int64, p store.Peer) {
	now := time.Now()
	inv, err := s.cfg.Store.TakeIDState(ctx, invitePrefixT+strconv.FormatInt(tokenID, 10), now)
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	if err == nil {
		inv.Key, inv.ExpiresAt = invitePrefixP+strconv.FormatInt(p.ID, 10), now.Add(invitedLife)
		err = s.cfg.Store.PutIDState(ctx, inv)
	}
	if err != nil {
		s.cfg.Logf("invitation of %s: %v", p.Hostname, err)
		return
	}
	s.audit(nil, &p, "invited", peerLabel(p)+" invited for account "+inv.Person, "ok")
}

// invitedPerson is the account a device is invited for ("": none).
func (s *Server) invitedPerson(ctx context.Context, peerID int64) string {
	inv, err := s.cfg.Store.IDState(ctx, invitePrefixP+strconv.FormatInt(peerID, 10), time.Now())
	if err != nil {
		return ""
	}
	var i invitation
	if json.Unmarshal(inv.Data, &i) != nil {
		return ""
	}
	return i.Person
}

// inviteStart turns the sign-in start of an invited device whose account is not set up yet into a
// setup link that ends in that sign-in. Otherwise start is as it was.
func (s *Server) inviteStart(r *http.Request, self store.Peer, start api.LoginStart) api.LoginStart {
	if s.id == nil || self.User != "" {
		return start
	}
	person := s.invitedPerson(r.Context(), self.ID)
	if person == "" {
		return start
	}
	next := start.AuthorizationURL
	if next == "" && start.UserCode != "" {
		next = s.id.Issuer() + "/device?user_code=" + start.UserCode
	}
	if next == "" {
		return start
	}
	link, _, err := s.id.SetupLink(r.Context(), person, inviteSetup, next)
	if err != nil {
		// Set up already (or gone): an ordinary sign-in, which only that person may complete.
		return start
	}
	if next == s.id.HereURL("") {
		// Set up on the device's own page, which then signs the person in on it.
		link = s.id.OnHere(link)
	}
	s.audit(r, &self, "invited", peerLabel(self)+": a setup link for account "+person+" instead of a sign-in", "ok")
	if start.AuthorizationURL != "" {
		start.AuthorizationURL = link
	} else {
		start.VerificationURI = link
	}
	return start
}
