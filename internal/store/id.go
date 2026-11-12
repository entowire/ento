package store

import (
	"context"
	"time"
)

// What the network's own identity provider keeps (package id): its people, their passkeys, the
// groups it knows, and short-lived state (authorization requests, codes, passkey ceremonies, setup
// links, refresh grants). None of it is part of the map: a change here does not make a new version.

// IDPerson is a person of the network's identity provider. ID is the subject of their sign-ins
// (what devices bound to them name, Peer.User), never reused.
type IDPerson struct {
	ID         string
	Email      string // lower case, unique
	GivenName  string
	FamilyName string
	Groups     []string
	Disabled   bool
	CreatedAt  time.Time
	LastSignIn time.Time // zero: never
	// Password is the password's hash in PHC form ($argon2id$...; "": none).
	Password string
	// TOTP is the authenticator app's secret, sealed by the provider (nil: none); TOTPStep the last
	// time step a code was accepted for (a code works once).
	TOTP     []byte
	TOTPStep int64
}

// IDPasskey is a passkey a person registered. Credential is the verifier's record of it
// (webauthn.Credential as JSON: public key, flags, authenticator, sign count), opaque here.
type IDPasskey struct {
	CredentialID []byte
	PersonID     string
	Name         string
	Credential   []byte
	CreatedAt    time.Time
	LastUsed     time.Time // zero: never
}

// IDGroup is a group the identity provider knows, people's or devices' (Kind), with the ways of
// signing in it allows (none: the network's default).
type IDGroup struct {
	Name   string
	Kind   string
	Signin []string
}

// IDState is a short-lived record of the identity provider under a unique key: Kind says what it is,
// Person (or "") whose it is, so that a person's records can all go at once, Data what it holds.
type IDState struct {
	Key       string
	Kind      string
	Person    string
	Data      []byte
	ExpiresAt time.Time
}

// IDStore is the identity provider's part of a Store.
type IDStore interface {
	IDPeople(ctx context.Context) ([]IDPerson, error)
	IDPerson(ctx context.Context, id string) (IDPerson, error)
	IDPersonByEmail(ctx context.Context, email string) (IDPerson, error)
	// CreateIDPerson adds a person: ErrExists if the ID or the e-mail address is taken.
	CreateIDPerson(ctx context.Context, p IDPerson) error
	// UpdateIDPerson changes a person with fn, in one step (the ID stays): ErrExists if the new
	// e-mail address is another's.
	UpdateIDPerson(ctx context.Context, id string, fn func(IDPerson) (IDPerson, error)) (IDPerson, error)
	// DeleteIDPerson removes a person, their passkeys and their state.
	DeleteIDPerson(ctx context.Context, id string) error

	IDPasskeys(ctx context.Context, personID string) ([]IDPasskey, error)
	IDPasskey(ctx context.Context, credentialID []byte) (IDPasskey, error)
	// AddIDPasskey adds a passkey: ErrExists if its credential ID is known, or the person has one of
	// that name; ErrNotFound if the person is not there.
	AddIDPasskey(ctx context.Context, k IDPasskey) error
	// UseIDPasskey records a sign-in with a passkey: its new record and when.
	UseIDPasskey(ctx context.Context, credentialID, credential []byte, at time.Time) error
	DeleteIDPasskey(ctx context.Context, personID string, credentialID []byte) error

	IDGroups(ctx context.Context) ([]IDGroup, error)
	// PutIDGroup adds a group or replaces what is known of it.
	PutIDGroup(ctx context.Context, g IDGroup) error
	// DeleteIDGroup removes a group, and takes everyone out of it.
	DeleteIDGroup(ctx context.Context, name string) error

	// PutIDState stores s, replacing what was under its key.
	PutIDState(ctx context.Context, s IDState) error
	// IDState returns what is under key, unless it expired by now (ErrNotFound).
	IDState(ctx context.Context, key string, now time.Time) (IDState, error)
	// TakeIDState removes what is under key and returns it, unless it expired by now (ErrNotFound):
	// of several callers, one gets it.
	TakeIDState(ctx context.Context, key string, now time.Time) (IDState, error)
	// DeleteIDStates removes a person's state of a kind ("": every kind).
	DeleteIDStates(ctx context.Context, person, kind string) error
	// ExpireIDStates removes what expired by now.
	ExpireIDStates(ctx context.Context, now time.Time) error
}
