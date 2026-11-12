package store

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"time"
)

// idMemory is the identity provider's part of Memory, under Memory.mu.
type idMemory struct {
	people   map[string]IDPerson
	passkeys []IDPasskey
	groups   map[string]IDGroup
	states   map[string]IDState
}

func clonePerson(p IDPerson) IDPerson {
	p.Groups = slices.Clone(p.Groups)
	p.TOTP = bytes.Clone(p.TOTP)
	return p
}

func clonePasskey(k IDPasskey) IDPasskey {
	k.CredentialID = bytes.Clone(k.CredentialID)
	k.Credential = bytes.Clone(k.Credential)
	return k
}

func (m *Memory) IDPeople(context.Context) ([]IDPerson, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]IDPerson, 0, len(m.idp.people))
	for _, p := range m.idp.people {
		out = append(out, clonePerson(p))
	}
	slices.SortFunc(out, func(a, b IDPerson) int { return strings.Compare(a.Email, b.Email) })
	return out, nil
}

func (m *Memory) IDPerson(_ context.Context, id string) (IDPerson, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.idp.people[id]
	if !ok {
		return IDPerson{}, ErrNotFound
	}
	return clonePerson(p), nil
}

func (m *Memory) IDPersonByEmail(_ context.Context, email string) (IDPerson, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.idp.people {
		if p.Email == email {
			return clonePerson(p), nil
		}
	}
	return IDPerson{}, ErrNotFound
}

func (m *Memory) emailTaken(email, except string) bool {
	for id, p := range m.idp.people {
		if id != except && p.Email == email {
			return true
		}
	}
	return false
}

func (m *Memory) CreateIDPerson(_ context.Context, p IDPerson) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.idp.people[p.ID]; ok || m.emailTaken(p.Email, "") {
		return ErrExists
	}
	if m.idp.people == nil {
		m.idp.people = map[string]IDPerson{}
	}
	m.idp.people[p.ID] = clonePerson(p)
	return nil
}

func (m *Memory) UpdateIDPerson(_ context.Context, id string, fn func(IDPerson) (IDPerson, error)) (IDPerson, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.idp.people[id]
	if !ok {
		return IDPerson{}, ErrNotFound
	}
	n, err := fn(clonePerson(p))
	if err != nil {
		return IDPerson{}, err
	}
	n.ID = id
	if m.emailTaken(n.Email, id) {
		return IDPerson{}, ErrExists
	}
	m.idp.people[id] = clonePerson(n)
	return clonePerson(n), nil
}

func (m *Memory) DeleteIDPerson(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.idp.people[id]; !ok {
		return ErrNotFound
	}
	delete(m.idp.people, id)
	m.idp.passkeys = slices.DeleteFunc(m.idp.passkeys, func(k IDPasskey) bool { return k.PersonID == id })
	for key, s := range m.idp.states {
		if s.Person == id {
			delete(m.idp.states, key)
		}
	}
	return nil
}

func (m *Memory) IDPasskeys(_ context.Context, personID string) ([]IDPasskey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []IDPasskey
	for _, k := range m.idp.passkeys {
		if k.PersonID == personID {
			out = append(out, clonePasskey(k))
		}
	}
	return out, nil
}

func (m *Memory) IDPasskey(_ context.Context, credentialID []byte) (IDPasskey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.idp.passkeys {
		if bytes.Equal(k.CredentialID, credentialID) {
			return clonePasskey(k), nil
		}
	}
	return IDPasskey{}, ErrNotFound
}

func (m *Memory) AddIDPasskey(_ context.Context, k IDPasskey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.idp.people[k.PersonID]; !ok {
		return ErrNotFound
	}
	for _, o := range m.idp.passkeys {
		if bytes.Equal(o.CredentialID, k.CredentialID) || o.PersonID == k.PersonID && o.Name == k.Name {
			return ErrExists
		}
	}
	m.idp.passkeys = append(m.idp.passkeys, clonePasskey(k))
	return nil
}

func (m *Memory) UseIDPasskey(_ context.Context, credentialID, credential []byte, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, k := range m.idp.passkeys {
		if bytes.Equal(k.CredentialID, credentialID) {
			m.idp.passkeys[i].Credential = bytes.Clone(credential)
			m.idp.passkeys[i].LastUsed = at
			if p, ok := m.idp.people[k.PersonID]; ok {
				p.LastSignIn = at
				m.idp.people[k.PersonID] = p
			}
			return nil
		}
	}
	return ErrNotFound
}

func (m *Memory) DeleteIDPasskey(_ context.Context, personID string, credentialID []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.idp.passkeys)
	m.idp.passkeys = slices.DeleteFunc(m.idp.passkeys, func(k IDPasskey) bool {
		return k.PersonID == personID && bytes.Equal(k.CredentialID, credentialID)
	})
	if len(m.idp.passkeys) == n {
		return ErrNotFound
	}
	return nil
}

func (m *Memory) IDGroups(context.Context) ([]IDGroup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]IDGroup, 0, len(m.idp.groups))
	for _, g := range m.idp.groups {
		g.Signin = slices.Clone(g.Signin)
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b IDGroup) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (m *Memory) PutIDGroup(_ context.Context, g IDGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idp.groups == nil {
		m.idp.groups = map[string]IDGroup{}
	}
	g.Signin = slices.Clone(g.Signin)
	m.idp.groups[g.Name] = g
	return nil
}

func (m *Memory) DeleteIDGroup(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.idp.groups[name]; !ok {
		return ErrNotFound
	}
	delete(m.idp.groups, name)
	for id, p := range m.idp.people {
		if slices.Contains(p.Groups, name) {
			p.Groups = slices.DeleteFunc(slices.Clone(p.Groups), func(g string) bool { return g == name })
			m.idp.people[id] = p
		}
	}
	return nil
}

func (m *Memory) PutIDState(_ context.Context, s IDState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idp.states == nil {
		m.idp.states = map[string]IDState{}
	}
	s.Data = bytes.Clone(s.Data)
	m.idp.states[s.Key] = s
	return nil
}

func (m *Memory) IDState(_ context.Context, key string, now time.Time) (IDState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.idp.states[key]
	if !ok || !now.Before(s.ExpiresAt) {
		return IDState{}, ErrNotFound
	}
	s.Data = bytes.Clone(s.Data)
	return s, nil
}

func (m *Memory) TakeIDState(_ context.Context, key string, now time.Time) (IDState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.idp.states[key]
	if !ok {
		return IDState{}, ErrNotFound
	}
	delete(m.idp.states, key)
	if !now.Before(s.ExpiresAt) {
		return IDState{}, ErrNotFound
	}
	return s, nil
}

func (m *Memory) DeleteIDStates(_ context.Context, person, kind string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, s := range m.idp.states {
		if s.Person == person && (kind == "" || s.Kind == kind) {
			delete(m.idp.states, key)
		}
	}
	return nil
}

func (m *Memory) ExpireIDStates(_ context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, s := range m.idp.states {
		if !now.Before(s.ExpiresAt) {
			delete(m.idp.states, key)
		}
	}
	return nil
}
