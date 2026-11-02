package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"entowire.com/ento/internal/api"
)

// fakeRauthy answers the calls the people API makes, as Rauthy's API does.
type fakeRauthy struct {
	mu       sync.Mutex
	users    map[string]*rauthyUser
	groups   []string
	passkeys map[string][]string
	calls    []string
}

func (f *fakeRauthy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "API-Key ento$secret" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/auth/v1")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case r.Method == "GET" && path == "/users":
		var out []map[string]string
		for id := range f.users {
			out = append(out, map[string]string{"id": id})
		}
		json.NewEncoder(w).Encode(out)
	case r.Method == "GET" && path == "/groups":
		var out []map[string]string
		for _, g := range f.groups {
			out = append(out, map[string]string{"id": "g-" + g, "name": g})
		}
		json.NewEncoder(w).Encode(out)
	case r.Method == "POST" && path == "/groups":
		var b struct{ Group string }
		json.NewDecoder(r.Body).Decode(&b)
		f.groups = append(f.groups, b.Group)
		w.WriteHeader(http.StatusOK)
	case r.Method == "POST" && path == "/users":
		var b struct {
			Email     string   `json:"email"`
			GivenName string   `json:"given_name"`
			Groups    []string `json:"groups"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		var kept []string
		for _, g := range b.Groups { // Rauthy drops groups it does not know
			if slices.Contains(f.groups, g) {
				kept = append(kept, g)
			}
		}
		u := &rauthyUser{ID: "u3", Email: b.Email, GivenName: b.GivenName, Groups: kept, Enabled: true, AccountType: "new", CreatedAt: 1793500000}
		f.users[u.ID] = u
		json.NewEncoder(w).Encode(u)
	case len(parts) == 2 && parts[0] == "groups" && r.Method == "DELETE":
		f.groups = slices.DeleteFunc(f.groups, func(g string) bool { return "g-"+g == parts[1] })
		w.WriteHeader(http.StatusOK)
	case len(parts) == 2 && parts[0] == "users" && r.Method == "GET":
		u, ok := f.users[parts[1]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "NotFound", "message": "no such user"})
			return
		}
		json.NewEncoder(w).Encode(u)
	case len(parts) == 2 && parts[0] == "users" && r.Method == "PATCH":
		var b struct {
			Put []struct {
				Key   string          `json:"key"`
				Value json.RawMessage `json:"value"`
			} `json:"put"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		u := f.users[parts[1]]
		for _, p := range b.Put {
			switch p.Key {
			case "enabled":
				json.Unmarshal(p.Value, &u.Enabled)
			case "groups":
				json.Unmarshal(p.Value, &u.Groups)
			}
		}
		w.WriteHeader(http.StatusOK)
	case len(parts) == 3 && parts[2] == "webauthn" && r.Method == "GET":
		var out []map[string]any
		for _, n := range f.passkeys[parts[1]] {
			out = append(out, map[string]any{"name": n, "registered": 1793400000, "last_used": 1793490000})
		}
		json.NewEncoder(w).Encode(out)
	case len(parts) == 5 && parts[2] == "webauthn" && parts[3] == "delete" && r.Method == "DELETE":
		f.passkeys[parts[1]] = slices.DeleteFunc(f.passkeys[parts[1]], func(n string) bool { return n == parts[4] })
		w.WriteHeader(http.StatusOK)
	case len(parts) == 3 && parts[2] == "setup_link" && r.Method == "POST":
		json.NewEncoder(w).Encode(map[string]any{"link": "https://id.example.test/auth/v1/users/" + parts[1] + "/reset/abc?type=new_user", "expires": 1793600000})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestRauthyPeople(t *testing.T) {
	fake := &fakeRauthy{
		users: map[string]*rauthyUser{
			"u1": {ID: "u1", Email: "maria@example.test", GivenName: "Maria", Groups: []string{"staff", "admins"}, Enabled: true, AccountType: "passkey", LastLogin: 1793490000},
			"u2": {ID: "u2", Email: "tom@example.test", Groups: nil, Enabled: false, AccountType: "passkey"},
		},
		groups:   []string{"admins", "staff"},
		passkeys: map[string][]string{"u1": {"YubiKey", "Laptop"}},
	}
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()
	p := newPeople(PeopleConfig{Kind: "rauthy", API: srv.URL + "/auth/v1/", Key: "ento$secret"})
	p.client = srv.Client()
	ctx := context.Background()

	people, err := p.list(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(people) != 2 || people[0].Email != "maria@example.test" || !slices.Equal(people[0].Groups, []string{"admins", "staff"}) ||
		people[0].LastLogin == "" || people[1].Enabled || people[1].Groups == nil {
		t.Fatalf("list: %+v", people)
	}

	// A new person in a group the provider does not have yet: it is made first, so it is kept.
	created, err := p.create(ctx, api.NewPersonRequest{Email: "elena@example.test", GivenName: "Elena", Groups: []string{"staff", "finance"}})
	if err != nil {
		t.Fatal(err)
	}
	if !created.Setup || !slices.Equal(created.Groups, []string{"finance", "staff"}) || !slices.Contains(fake.groups, "finance") {
		t.Fatalf("created: %+v, groups %v", created, fake.groups)
	}
	link, err := p.setupLink(ctx, created.ID)
	if err != nil || !strings.Contains(link.Link, "/users/u3/reset/") || link.ExpiresAt == "" {
		t.Fatalf("setup link: %+v %v", link, err)
	}

	off := false
	groups := []string{"sales"}
	if err := p.update(ctx, "u1", api.UpdatePersonRequest{Enabled: &off, Groups: &groups}); err != nil {
		t.Fatal(err)
	}
	if u := fake.users["u1"]; u.Enabled || !slices.Equal(u.Groups, groups) || !slices.Contains(fake.groups, "sales") {
		t.Fatalf("after update: %+v", u)
	}

	keys, err := p.passkeys(ctx, "u1")
	if err != nil || len(keys) != 2 || keys[0].RegisteredAt == "" {
		t.Fatalf("passkeys: %+v %v", keys, err)
	}
	if err := p.deletePasskey(ctx, "u1", "YubiKey"); err != nil || !slices.Equal(fake.passkeys["u1"], []string{"Laptop"}) {
		t.Fatalf("delete passkey: %v %v", err, fake.passkeys["u1"])
	}

	// The provider's refusals come back with their status and message.
	_, err = p.user(ctx, "nobody")
	var pe *errProvider
	if !asProvider(err, &pe) || pe.status != http.StatusNotFound || !strings.Contains(pe.msg, "no such user") {
		t.Fatalf("missing user: %v", err)
	}
	rec := httptest.NewRecorder()
	respondPeopleErr(rec, err)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing user answered %d", rec.Code)
	}

	// A wrong key is the provider failing, not the caller's mistake.
	bad := newPeople(PeopleConfig{Kind: "rauthy", API: srv.URL + "/auth/v1", Key: "ento$wrong"})
	bad.client = srv.Client()
	_, err = bad.list(ctx)
	rec = httptest.NewRecorder()
	respondPeopleErr(rec, err)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("wrong key answered %d", rec.Code)
	}

	if err := p.deleteGroup(ctx, "finance"); err != nil || slices.Contains(fake.groups, "finance") {
		t.Fatalf("delete group: %v %v", err, fake.groups)
	}
	if err := p.deleteGroup(ctx, "nope"); err == nil {
		t.Fatal("deleting a missing group passed")
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
	if checkMethods(nil) == nil || checkMethods([]string{"password"}) == nil || checkMethods([]string{"passkey", "passkey"}) == nil || checkMethods([]string{"passkey"}) != nil {
		t.Error("checkMethods")
	}
}
