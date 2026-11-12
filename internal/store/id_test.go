package store

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestIDStore(t *testing.T) {
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) { testIDStore(t, open(t)) })
	}
}

func testIDStore(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	ana := IDPerson{ID: "p1", Email: "ana@example.com", GivenName: "Ana", Groups: []string{"admins"}, CreatedAt: now}
	if err := s.CreateIDPerson(ctx, ana); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateIDPerson(ctx, IDPerson{ID: "p2", Email: "ana@example.com", CreatedAt: now}); !errors.Is(err, ErrExists) {
		t.Fatalf("same e-mail address: %v, want ErrExists", err)
	}
	if err := s.CreateIDPerson(ctx, IDPerson{ID: "p2", Email: "bo@example.com", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateIDPerson(ctx, "p2", func(p IDPerson) (IDPerson, error) { p.Email = "ana@example.com"; return p, nil }); !errors.Is(err, ErrExists) {
		t.Fatalf("taking another's address: %v, want ErrExists", err)
	}
	got, err := s.IDPersonByEmail(ctx, "ana@example.com")
	if err != nil || got.ID != "p1" || got.GivenName != "Ana" || !slices.Equal(got.Groups, []string{"admins"}) || !got.LastSignIn.IsZero() {
		t.Fatalf("by e-mail: %+v %v", got, err)
	}
	if got, err := s.UpdateIDPerson(ctx, "p2", func(p IDPerson) (IDPerson, error) {
		p.Password, p.TOTP, p.TOTPStep = "$argon2id$x", []byte{7, 8}, 42
		return p, nil
	}); err != nil || got.Password != "$argon2id$x" {
		t.Fatalf("password and app: %+v %v", got, err)
	}
	if got, _ := s.IDPerson(ctx, "p2"); got.Password != "$argon2id$x" || string(got.TOTP) != "\x07\x08" || got.TOTPStep != 42 {
		t.Fatalf("password and app kept: %+v", got)
	}
	if _, err := s.IDPerson(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown person: %v", err)
	}

	k := IDPasskey{CredentialID: []byte{1, 2, 3}, PersonID: "p1", Name: "phone", Credential: []byte(`{"a":1}`), CreatedAt: now}
	if err := s.AddIDPasskey(ctx, k); err != nil {
		t.Fatal(err)
	}
	if err := s.AddIDPasskey(ctx, IDPasskey{CredentialID: []byte{9}, PersonID: "p1", Name: "phone", Credential: []byte("{}"), CreatedAt: now}); !errors.Is(err, ErrExists) {
		t.Fatalf("same name twice: %v", err)
	}
	if err := s.AddIDPasskey(ctx, IDPasskey{CredentialID: []byte{1, 2, 3}, PersonID: "p2", Name: "x", Credential: []byte("{}"), CreatedAt: now}); !errors.Is(err, ErrExists) {
		t.Fatalf("same credential twice: %v", err)
	}
	if err := s.AddIDPasskey(ctx, IDPasskey{CredentialID: []byte{8}, PersonID: "ghost", Name: "x", Credential: []byte("{}"), CreatedAt: now}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("passkey of nobody: %v", err)
	}
	later := now.Add(time.Minute)
	if err := s.UseIDPasskey(ctx, []byte{1, 2, 3}, []byte(`{"a":2}`), later); err != nil {
		t.Fatal(err)
	}
	pk, err := s.IDPasskey(ctx, []byte{1, 2, 3})
	if err != nil || string(pk.Credential) != `{"a":2}` || !pk.LastUsed.Equal(later) || pk.PersonID != "p1" {
		t.Fatalf("used passkey: %+v %v", pk, err)
	}
	if got, _ := s.IDPerson(ctx, "p1"); !got.LastSignIn.Equal(later) {
		t.Fatalf("last sign-in %v, want %v", got.LastSignIn, later)
	}

	if err := s.PutIDGroup(ctx, IDGroup{Name: "admins", Kind: "people", Signin: []string{"passkey"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutIDGroup(ctx, IDGroup{Name: "laptops", Kind: "devices"}); err != nil {
		t.Fatal(err)
	}
	gs, err := s.IDGroups(ctx)
	if err != nil || len(gs) != 2 || gs[0].Name != "admins" || !slices.Equal(gs[0].Signin, []string{"passkey"}) || gs[1].Signin != nil {
		t.Fatalf("groups: %+v %v", gs, err)
	}
	if err := s.DeleteIDGroup(ctx, "admins"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.IDPerson(ctx, "p1"); len(got.Groups) != 0 {
		t.Fatalf("groups after the group went: %v", got.Groups)
	}

	st := IDState{Key: "code:x", Kind: "code", Person: "p1", Data: []byte("d"), ExpiresAt: now.Add(time.Minute)}
	if err := s.PutIDState(ctx, st); err != nil {
		t.Fatal(err)
	}
	if err := s.PutIDState(ctx, IDState{Key: "old", Kind: "code", Data: []byte("o"), ExpiresAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IDState(ctx, "old", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired state: %v", err)
	}
	if got, err := s.IDState(ctx, "code:x", now); err != nil || string(got.Data) != "d" {
		t.Fatalf("state: %+v %v", got, err)
	}
	if got, err := s.TakeIDState(ctx, "code:x", now); err != nil || got.Person != "p1" {
		t.Fatalf("take: %+v %v", got, err)
	}
	if _, err := s.TakeIDState(ctx, "code:x", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("taken twice: %v", err)
	}
	if err := s.PutIDState(ctx, IDState{Key: "rt:1", Kind: "refresh", Person: "p1", Data: []byte("r"), ExpiresAt: later}); err != nil {
		t.Fatal(err)
	}
	if err := s.ExpireIDStates(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteIDPerson(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IDState(ctx, "rt:1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a deleted person's state: %v", err)
	}
	if _, err := s.IDPasskey(ctx, []byte{1, 2, 3}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a deleted person's passkey: %v", err)
	}
}
