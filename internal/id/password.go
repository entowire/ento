package id

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"entowire.com/ento/internal/store"
)

// Passwords are kept as Argon2id hashes in PHC form ($argon2id$v=19$m=...,t=...,p=...$salt$hash; any
// such hash is taken as it is, whatever its parameters). New ones use argonMemory KiB, argonTime passes,
// argonThreads lanes; at most argonParallel are computed at once on a node.
const (
	argonMemory   = 64 * 1024
	argonTime     = 3
	argonThreads  = 2
	argonKeyLen   = 32
	argonParallel = 2
	minPassword   = 12
	maxPassword   = 256
	// After failLimit wrong passwords or codes in failWindow, an account takes no more passwords
	// until the window has passed, wherever they come from (counted per account, not per address,
	// so spreading guesses over many devices does not help). Its passkeys still sign it in.
	failLimit  = 10
	failWindow = 15 * time.Minute
)

var argonSlots = make(chan struct{}, argonParallel)

// dummyHash is checked against when there is no account, so that answers take as long; made at
// first use (agents never need it).
var dummyHash = sync.OnceValue(func() string { return hashPassword("not a password") })

// CheckNewPassword says what is wrong with a new password ("": nothing).
func CheckNewPassword(pw string) string {
	n := utf8.RuneCountInString(pw)
	switch {
	case !utf8.ValidString(pw):
		return "The password is not valid text."
	case n < minPassword:
		return fmt.Sprintf("A password needs at least %d characters.", minPassword)
	case n > maxPassword:
		return fmt.Sprintf("A password has at most %d characters.", maxPassword)
	}
	return ""
}

func hashPassword(pw string) string {
	return hashPasswordParams(pw, argonMemory, argonTime, argonThreads)
}

func hashPasswordParams(pw string, m uint32, t uint32, p uint8) string {
	argonSlots <- struct{}{}
	defer func() { <-argonSlots }()
	salt := randomBytes(16)
	key := argon2.IDKey([]byte(pw), salt, t, m, p, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, m, t, p, enc.EncodeToString(salt), enc.EncodeToString(key))
}

var errHash = errors.New("not an Argon2id hash")

// verifyPassword checks pw against a PHC Argon2id hash.
func verifyPassword(phc, pw string) (bool, error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return false, errHash
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || m > 1<<20 || t == 0 || t > 20 || p == 0 {
		return false, errHash
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[4])
	want, err2 := enc.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) < 16 || len(want) > 64 {
		return false, errHash
	}
	argonSlots <- struct{}{}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	<-argonSlots
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// failures is a person's count of wrong passwords and codes in the current window.
type failures struct {
	N int `json:"n"`
}

// locked reports whether a person's account takes no more attempts now.
func (p *Provider) locked(ctx context.Context, person string) bool {
	var f failures
	_, err := p.getState(ctx, "fail:"+person, false, &f)
	return err == nil && f.N >= failLimit
}

// failed counts a wrong password or code against a person.
func (p *Provider) failed(ctx context.Context, person string) {
	var f failures
	s, err := p.getState(ctx, "fail:"+person, false, &f)
	life := failWindow
	if err == nil {
		life = s.ExpiresAt.Sub(p.cfg.Now())
	}
	f.N++
	if err := p.putState(ctx, "fail:"+person, kindFail, person, f, life); err != nil {
		p.cfg.Logf("identity provider: counting a failure: %v", err)
	}
}

// checkPassword finds the person of an address and checks their password: the person, or an error
// for the page that says no more than that one of them is wrong (or that the account is locked).
func (p *Provider) checkPassword(ctx context.Context, email, pw string) (store.IDPerson, error) {
	x, err := p.cfg.Store.IDPersonByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if err != nil || x.Disabled || x.Password == "" {
		verifyPassword(dummyHash(), pw)
		return store.IDPerson{}, errWrongPassword
	}
	if p.locked(ctx, x.ID) {
		return x, errLocked
	}
	ok, err := verifyPassword(x.Password, pw)
	if err != nil {
		p.cfg.Logf("identity provider: password of %s: %v", x.Email, err)
	}
	if !ok {
		p.failed(ctx, x.ID)
		return x, errWrongPassword
	}
	return x, nil
}

var (
	errWrongPassword = errors.New("Wrong e-mail address or password.")
	errLocked        = errors.New("Too many failed attempts on this account. Try again in 15 minutes.")
)
