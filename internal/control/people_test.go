package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"entowire.com/ento/internal/api"
	entoid "entowire.com/ento/internal/id"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

// idBackend is the people of a control nodes' own provider on a memory store.
func idBackend(t *testing.T) (*idPeople, *store.Memory) {
	t.Helper()
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p, err := entoid.New(entoid.Config{Name: "id.example.test", Key: k, Store: st})
	if err != nil {
		t.Fatal(err)
	}
	return &idPeople{p: p, st: st}, st
}

// seed adds a person with the given ways in: passkeys (by name), a password, an app.
func seed(t *testing.T, st *store.Memory, id, email string, groups []string, enabled bool, passkeys []string, password, app bool) {
	t.Helper()
	ctx := context.Background()
	x := store.IDPerson{ID: id, Email: email, Groups: groups, Disabled: !enabled, CreatedAt: time.Now()}
	if password {
		x.Password = "$argon2id$v=19$m=16384,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	if app {
		x.TOTP = []byte{1}
	}
	if err := st.CreateIDPerson(ctx, x); err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		st.PutIDGroup(ctx, store.IDGroup{Name: g, Kind: "people"})
	}
	for i, n := range passkeys {
		if err := st.AddIDPasskey(ctx, store.IDPasskey{CredentialID: []byte(id + n + string(rune('a'+i))), PersonID: id, Name: n, Credential: []byte("{}"), CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIDPeople(t *testing.T) {
	p, st := idBackend(t)
	ctx := context.Background()
	got, err := p.create(ctx, api.NewPersonRequest{Email: "Ana@Example.test", GivenName: "Ana", Groups: []string{"staff"}})
	if err != nil || got.Email != "ana@example.test" || !got.Setup || !slices.Equal(got.Groups, []string{"staff"}) {
		t.Fatalf("create: %+v %v", got, err)
	}
	var pe *errProvider
	if _, err := p.create(ctx, api.NewPersonRequest{Email: "ana@example.test"}); !asProvider(err, &pe) || pe.status != http.StatusConflict {
		t.Fatalf("same address twice: %v", err)
	}
	if gs, _ := p.groups(ctx); !slices.Contains(gs, "staff") {
		t.Fatalf("groups %v", gs)
	}
	off := false
	gs := []string{"staff", "ops"}
	if err := p.update(ctx, got.ID, api.UpdatePersonRequest{Enabled: &off, Groups: &gs}); err != nil {
		t.Fatal(err)
	}
	u, _ := p.user(ctx, got.ID)
	if u.Enabled || len(u.Groups) != 2 {
		t.Fatalf("after update: %+v", u)
	}
	link, err := p.setupLink(ctx, got.ID)
	if err != nil || !strings.HasPrefix(link.Link, "https://id.example.test/setup#") {
		t.Fatalf("setup link: %+v %v", link, err)
	}
	seed(t, st, "u9", "bo@example.test", []string{"staff"}, true, []string{"Phone"}, false, false)
	if err := p.deletePasskey(ctx, "u9", "Laptop"); !asProvider(err, &pe) || pe.status != http.StatusNotFound {
		t.Fatalf("a passkey that is not there: %v", err)
	}
	if err := p.deletePasskey(ctx, "u9", "Phone"); err != nil {
		t.Fatal(err)
	}
	if err := p.deleteGroup(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if err := p.deleteGroup(ctx, "ops"); err == nil {
		t.Fatal("deleting a missing group passed")
	}
	if err := p.remove(ctx, got.ID); err != nil {
		t.Fatal(err)
	}
	if err := checkPersonGroups([]string{"ok-group", "Bad Group"}); err == nil {
		t.Fatal("a group with spaces and capitals passed")
	}
}

func asProvider(err error, pe **errProvider) bool {
	e, ok := err.(*errProvider)
	if ok {
		*pe = e
	}
	return ok
}

func TestEffectiveSignin(t *testing.T) {
	def := []string{"passkey", "password+passkey", "password+totp"}
	by := map[string][]string{"admins": {"passkey", "password+passkey"}, "users": nil, "ops": {"password+totp"}}
	for _, c := range []struct {
		groups []string
		want   []string
	}{
		{nil, def},
		{[]string{"users"}, def},
		{[]string{"users", "admins"}, []string{"passkey", "password+passkey"}},
		{[]string{"admins", "ops"}, []string{}},
		{[]string{"device:laptops", "admins"}, []string{"passkey", "password+passkey"}},
	} {
		got := effectiveSignin(c.groups, by, def)
		if !slices.Equal(got, c.want) && !(len(got) == 0 && len(c.want) == 0) {
			t.Errorf("%v: %v, want %v", c.groups, got, c.want)
		}
	}
	if checkMethods(nil, SigninMethods) == nil || checkMethods([]string{"password"}, SigninMethods) == nil || checkMethods([]string{"passkey", "passkey"}, SigninMethods) == nil || checkMethods([]string{"passkey"}, SigninMethods) != nil {
		t.Error("checkMethods")
	}
}

// `ento control person` (a network's first administrator): made with a setup link; again while not
// set up, a new link for the same person; once set up, refused.
func TestInvitePerson(t *testing.T) {
	p, st := idBackend(t)
	seed(t, st, "u1", "maria@example.test", []string{"admins"}, true, []string{"Key"}, false, false)
	ctx := context.Background()
	got, link, created, err := invitePerson(ctx, p, " ana@example.test ", []string{"admins"})
	if err != nil || !created || got.Email != "ana@example.test" || !slices.Equal(got.Groups, []string{"admins"}) || link.Link == "" {
		t.Fatalf("new: %+v %+v %v %v", got, link, created, err)
	}
	again, link, created, err := invitePerson(ctx, p, "ANA@example.test", []string{"admins"})
	if err != nil || created || again.ID != got.ID || link.Link == "" {
		t.Fatalf("again: %+v %+v %v %v", again, link, created, err)
	}
	if _, _, _, err := invitePerson(ctx, p, "maria@example.test", []string{"admins"}); err == nil || !strings.Contains(err.Error(), "set up") {
		t.Fatalf("set up already: %v", err)
	}
	if _, _, _, err := invitePerson(ctx, p, "nobody", nil); err == nil {
		t.Fatal("no address: accepted")
	}
}

// No admin takes another person's account over (I6, constitution 4.5): a setup link only for an
// account with no way to sign in, no admin's passkey removed from a device with nobody signed in,
// none of one's own, and not the last one of the only admin who can sign in.
func TestAccountTakeoverGuards(t *testing.T) {
	p, st := idBackend(t)
	seed(t, st, "u1", "maria@example.test", []string{"admins"}, true, []string{"Key"}, false, false)
	seed(t, st, "u2", "tom@example.test", []string{"admins"}, true, []string{"A", "B"}, false, false)
	seed(t, st, "u3", "eve@example.test", []string{"staff"}, true, nil, true, true)
	seed(t, st, "u4", "new@example.test", []string{"staff"}, true, nil, false, false)
	s := &Server{cfg: Config{Logf: t.Logf, Store: st}, people: p}
	device := store.Peer{Hostname: "admin-laptop"}                                                                               // nobody signed in
	tom := store.Peer{Hostname: "tom-laptop", User: "u2", UserName: "tom@example.test", Person: store.PersonLayer{Active: true}} // an admin signed in
	call := func(self store.Peer, method, id, name string) int {
		r := httptest.NewRequest(method, "/x", nil)
		r.SetPathValue("id", id)
		r.SetPathValue("name", name)
		w := httptest.NewRecorder()
		if method == "DELETE" {
			s.handleDeletePasskey(w, r, self)
		} else {
			s.handlePersonSetup(w, r, self)
		}
		return w.Code
	}
	for _, c := range []struct {
		what       string
		self       store.Peer
		method, id string
		want       int
	}{
		{"a device alone removes an admin's passkey", device, "DELETE", "u1", http.StatusConflict},
		{"a setup link for an account with a password and an app", tom, "POST", "u3", http.StatusConflict},
		{"a setup link for an account with passkeys", tom, "POST", "u1", http.StatusConflict},
		{"an admin removes their own passkey", tom, "DELETE", "u2", http.StatusConflict},
		{"a setup link for an account not set up", tom, "POST", "u4", http.StatusOK},
	} {
		if got := call(c.self, c.method, c.id, "Key"); got != c.want {
			t.Errorf("%s: HTTP %d, want %d", c.what, got, c.want)
		}
	}
	// Maria is the only admin who can sign in once Tom is disabled: her last passkey stays.
	st.UpdateIDPerson(context.Background(), "u2", func(x store.IDPerson) (store.IDPerson, error) { x.Disabled = true; return x, nil })
	if got := call(tom, "DELETE", "u1", "Key"); got != http.StatusConflict {
		t.Errorf("the only admin's last passkey: HTTP %d, want 409", got)
	}
}

// The built-in groups are never deleted, empty or not (A7, constitution 3.3).
func TestBuiltinGroupsStay(t *testing.T) {
	p, st := idBackend(t)
	ctx := context.Background()
	for _, g := range []string{"admins", "operators", "viewers", "device:admin", "device:isolated", "lab"} {
		st.PutIDGroup(ctx, store.IDGroup{Name: g})
	}
	s := &Server{cfg: Config{Logf: t.Logf, Store: st}, people: p}
	for name, want := range map[string]int{"admins": 409, "operators": 409, "viewers": 409, "device:admin": 409,
		"device:operator": 409, "device:isolated": 409, "lab": http.StatusNoContent} {
		r := httptest.NewRequest("DELETE", "/x", nil)
		r.SetPathValue("name", name)
		w := httptest.NewRecorder()
		s.handleDeleteGroup(w, r, store.Peer{Hostname: "admin"})
		if w.Code != want {
			t.Errorf("delete %s: HTTP %d, want %d (%s)", name, w.Code, want, w.Body.String())
		}
	}
}
