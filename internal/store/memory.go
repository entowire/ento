package store

import (
	"cmp"
	"context"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/names"
)

// Memory is an in-memory Store for tests and ephemeral single-node setups.
type Memory struct {
	mu       sync.Mutex
	space    ipam.Space
	version  int64
	controls map[string]ControlNode
	peers    map[int64]Peer
	tokens   map[int64]Token
	policies map[int64]Policy
	auths    map[string]Authority
	links    map[string]Link
	linkKeys map[string]wgtypes.Key // link + "/" + peer ID
	linkPost map[string]string      // link + "/" + peer ID: how the device does on the link's checks
	ui       map[string]UISession
	sso      map[int64]SSOToken
	checks   map[string]PostureCheck
	posture  map[int64]PostureReport
	approval map[string]Approval
	checkIns map[int64]CheckIn
	hwKeys   map[int64]HWKey
	routes   map[string]Route
	dnsNames map[string]DNSRecord
	dnsZones map[string]DNSForward
	updates  *UpdatePolicy
	offers   map[string]time.Time
	signIns  map[string]SignInCode
	signUse  map[int64]SignInCode // PersonSince and, in ExpiresAt, when the device last signed someone in
	settings map[string]string
	audit    []AuditEntry
	nextID   int64
}

// NewMemory returns an empty in-memory store for the given address space.
func NewMemory(space ipam.Space) *Memory {
	return &Memory{
		space: space, version: 1,
		controls: map[string]ControlNode{}, peers: map[int64]Peer{},
		tokens: map[int64]Token{}, policies: map[int64]Policy{},
		auths: map[string]Authority{}, links: map[string]Link{},
		linkKeys: map[string]wgtypes.Key{}, linkPost: map[string]string{}, ui: map[string]UISession{}, sso: map[int64]SSOToken{},
		checks: map[string]PostureCheck{}, posture: map[int64]PostureReport{},
	}
}

func (m *Memory) Close() error { return nil }

func (m *Memory) id() int64 { m.nextID++; return m.nextID }

func (m *Memory) Version(context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.version, nil
}

func (m *Memory) ControlNodeSeen(_ context.Context, name string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.controls[name]; ok {
		c.LastSeen = at
		m.controls[name] = c
	}
	return nil
}

func (m *Memory) RegisterControlNode(_ context.Context, n ControlNode) (ControlNode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, c := range m.controls {
		if name != n.Name && c.PublicKey == n.PublicKey {
			return ControlNode{}, ErrKeyInUse
		}
	}
	for _, p := range m.peers { // a device's or a token's key is never a control node's
		if p.PublicKey == n.PublicKey {
			return ControlNode{}, ErrKeyInUse
		}
	}
	for _, t := range m.tokens {
		if t.PublicKey == n.PublicKey {
			return ControlNode{}, ErrKeyInUse
		}
	}
	if old, ok := m.controls[n.Name]; ok {
		n.Address = old.Address
	} else {
		used := map[netip.Addr]bool{}
		for _, c := range m.controls {
			used[c.Address] = true
		}
		a, err := ipam.FirstFree(m.space.ControlAddresses(), used)
		if err != nil {
			return ControlNode{}, err
		}
		n.Address = a
	}
	if old, ok := m.controls[n.Name]; !ok || old.PublicKey != n.PublicKey || old.Endpoint != n.Endpoint {
		m.version++
	}
	m.controls[n.Name] = n
	return n, nil
}

func (m *Memory) ControlNodes(context.Context) ([]ControlNode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ControlNode, 0, len(m.controls))
	for _, c := range m.controls {
		out = append(out, c)
	}
	sortControls(out)
	return out, nil
}

func sortControls(c []ControlNode) {
	sort.Slice(c, func(i, j int) bool { return c[i].Address.Less(c[j].Address) })
}

func (m *Memory) CreateToken(_ context.Context, t Token) (Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.createToken(t)
}

// nameHolder returns who has or reserves a device name (see Postgres.nameHolder); the caller holds
// m.mu.
func (m *Memory) nameHolder(name string, now time.Time, exceptToken int64) *NameTakenError {
	h := &NameTakenError{Name: name}
	for _, p := range m.peers {
		if p.Hostname == name {
			h.PeerID = p.ID
		}
	}
	for _, t := range m.tokens {
		if t.Name == name && t.Active(now) && t.ID != exceptToken && (h.TokenID == 0 || t.ID < h.TokenID) {
			h.TokenID = t.ID
		}
	}
	if h.PeerID == 0 && h.TokenID == 0 {
		return nil
	}
	return h
}

func (m *Memory) createToken(t Token) (Token, error) {
	now := time.Now()
	if t.Name != "" {
		switch h := m.nameHolder(t.Name, now, 0); {
		case h == nil:
		case h.TokenID != 0:
			return Token{}, &NameTakenError{Name: t.Name, TokenID: h.TokenID}
		case !t.Replace:
			return Token{}, &NameTakenError{Name: t.Name, PeerID: h.PeerID}
		}
	}
	used := map[netip.Addr]bool{}
	for _, o := range m.tokens {
		if o.PublicKey == t.PublicKey {
			return Token{}, ErrKeyInUse
		}
		if o.Active(now) {
			used[o.TempAddress] = true
		}
	}
	a := t.TempAddress
	if a.IsValid() { // asked for (enrollment by words derives it)
		if !m.space.IsEnrollment(a) || used[a] {
			return Token{}, ErrAddressInUse
		}
	} else {
		var err error
		if a, err = ipam.FirstFree(m.space.EnrollmentAddresses(), used); err != nil {
			return Token{}, err
		}
	}
	t.ID, t.TempAddress, t.CreatedAt = m.id(), a, now
	t.Groups = slices.Clone(t.Groups)
	m.tokens[t.ID] = t
	m.version++
	return t, nil
}

func (m *Memory) ActiveTokens(_ context.Context, now time.Time) ([]Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Token
	for _, t := range m.tokens {
		if t.Active(now) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) DeleteToken(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok || !t.RedeemedAt.IsZero() || t.Authority != "" {
		return ErrNotFound
	}
	delete(m.tokens, id)
	m.version++
	return nil
}

func (m *Memory) Redeem(_ context.Context, temp netip.Addr, key wgtypes.Key, hostname, os string, now time.Time, grant *Grant) (Peer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var tok Token
	found := false
	for _, t := range m.tokens {
		if t.TempAddress == temp && t.Active(now) {
			tok, found = t, true
			break
		}
	}
	if !found || (tok.Authority != "") != (grant != nil) || (grant != nil && grant.Authority != tok.Authority) {
		return Peer{}, ErrTokenUnusable
	}
	for _, p := range m.peers {
		if p.PublicKey == key {
			return Peer{}, ErrKeyInUse
		}
	}
	for _, c := range m.controls { // a control node's or a token's key would take its place
		if c.PublicKey == key {
			return Peer{}, ErrKeyInUse
		}
	}
	for _, t := range m.tokens {
		if t.PublicKey == key {
			return Peer{}, ErrKeyInUse
		}
	}
	p := Peer{
		PublicKey: key, ReportedHostname: names.Reported(hostname), OS: os, CreatedAt: now,
		Machine: Rights{Approved: tok.Approve, Admin: tok.Admin, Groups: slices.Clone(tok.Groups)},
	}
	if grant != nil && grant.Hostname != "" {
		p.ReportedHostname = names.Reported(grant.Hostname)
	}
	var replaced *Peer
	if grant != nil {
		// One membership per device of the authority: a new key replaces the previous one.
		n := 0
		for _, o := range m.peers {
			if o.Authority != grant.Authority {
				continue
			}
			if grant.DeviceID != "" && o.AuthorityDevice == grant.DeviceID && replaced == nil {
				if o.Suspended { // excluded by this network's administrators: a new key does not undo it
					return Peer{}, ErrMemberSuspended
				}
				old := o
				replaced = &old
				continue
			}
			n++
		}
		if grant.MaxDevices > 0 && n >= grant.MaxDevices {
			return Peer{}, &AuthorityFullError{Authority: grant.Authority, Max: grant.MaxDevices}
		}
		if replaced != nil {
			delete(m.peers, replaced.ID) // frees its name for the new membership
		}
	}
	if tok.Name != "" {
		switch h := m.nameHolder(tok.Name, now, tok.ID); {
		case h == nil:
		case h.PeerID == 0 || !tok.Replace:
			return Peer{}, h
		default:
			old := m.peers[h.PeerID]
			replaced = &old
		}
		p.Hostname = tok.Name
	} else {
		prefix := names.SelfPrefix
		if grant != nil {
			prefix = grant.Authority + "-"
		}
		p.Hostname, _ = names.Free(prefix, names.Base(p.ReportedHostname), func(n string) (bool, error) {
			return m.nameHolder(n, now, 0) != nil, nil
		})
	}
	if replaced != nil {
		delete(m.peers, replaced.ID)
		m.forgetPeer(replaced.ID)
		p.Address = replaced.Address
	} else {
		used := map[netip.Addr]bool{}
		for _, o := range m.peers {
			used[o.Address] = true
		}
		a, err := m.space.FirstFreePeer(used)
		if err != nil {
			return Peer{}, err
		}
		p.Address = a
	}
	p.ID = m.id()
	if grant != nil {
		p.Machine = Rights{Approved: true, Groups: slices.Clone(grant.Groups)}
		p.Authority, p.UserName, p.ApprovedUntil = grant.Authority, grant.UserName, grant.Until
		p.AuthorityDevice = grant.DeviceID
	} else {
		tok.RedeemedAt = now
		m.tokens[tok.ID] = tok
	}
	p.apply(PeerUpdate{})
	m.peers[p.ID] = p
	m.version++
	return p, nil
}

func (m *Memory) Peers(context.Context) ([]Peer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Peer, 0, len(m.peers))
	for _, p := range m.peers {
		out = append(out, p.cloned())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) PeerByAddress(_ context.Context, a netip.Addr) (Peer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.peers {
		if p.Address == a {
			return p.cloned(), nil
		}
	}
	return Peer{}, ErrNotFound
}

func (m *Memory) PeerByPublicKey(_ context.Context, key wgtypes.Key) (Peer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.peers {
		if p.PublicKey == key {
			return p.cloned(), nil
		}
	}
	return Peer{}, ErrNotFound
}

func (m *Memory) UpdatePeer(_ context.Context, id int64, u PeerUpdate) (Peer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[id]
	if !ok {
		return Peer{}, ErrNotFound
	}
	if u.conflicts(p) {
		return Peer{}, ErrChanged
	}
	if u.Hostname != nil && *u.Hostname != p.Hostname {
		if h := m.nameHolder(*u.Hostname, time.Now(), 0); h != nil {
			return Peer{}, h
		}
	}
	p = p.cloned()
	p.apply(u)
	m.peers[id] = p
	m.version++
	return p.cloned(), nil
}

// cloned copies a peer's slices, so that callers cannot change the stored peer.
func (p Peer) cloned() Peer {
	p.Groups = slices.Clone(p.Groups)
	p.Machine.Groups = slices.Clone(p.Machine.Groups)
	p.Person.Groups = slices.Clone(p.Person.Groups)
	return p
}

func (m *Memory) DeletePeer(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.peers[id]; !ok {
		return ErrNotFound
	}
	delete(m.peers, id)
	m.forgetPeer(id)
	m.version++
	return nil
}

// forgetPeer deletes what belongs to a deleted device; the caller holds m.mu.
func (m *Memory) forgetPeer(id int64) {
	delete(m.sso, id)
	delete(m.signUse, id)
	for h, c := range m.signIns {
		if c.PeerID == id {
			delete(m.signIns, h)
		}
	}
	delete(m.posture, id)
	delete(m.checkIns, id)
	for k := range m.linkKeys {
		if strings.HasSuffix(k, "/"+strconv.FormatInt(id, 10)) {
			delete(m.linkKeys, k)
		}
	}
	for k := range m.linkPost {
		if strings.HasSuffix(k, "/"+strconv.FormatInt(id, 10)) {
			delete(m.linkPost, k)
		}
	}
	for h, u := range m.ui {
		if u.PeerID == id {
			delete(m.ui, h)
		}
	}
}

func (m *Memory) ObservePeer(_ context.Context, key wgtypes.Key, endpoint string, at time.Time) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, p := range m.peers {
		if p.PublicKey == key {
			previous, changed := p.Endpoint, false
			if endpoint != "" && endpoint != p.Endpoint {
				p.Endpoint = endpoint
				if p.Approved { // an unapproved device is in no other device's map
					m.version++
				}
				changed = true
			}
			p.LastSeen = at
			m.peers[id] = p
			return previous, changed, nil
		}
	}
	return "", false, ErrNotFound
}

func (m *Memory) Policies(context.Context) ([]Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Policy, 0, len(m.policies))
	for _, p := range m.policies {
		p.Posture, p.Ports = slices.Clone(p.Posture), slices.Clone(p.Ports)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// missingCheck returns the first of the checks that does not exist; m.mu is held.
func (m *Memory) missingCheck(checks []string) error {
	for _, name := range checks {
		if _, ok := m.checks[name]; !ok {
			return &NoSuchCheckError{Check: name}
		}
	}
	return nil
}

func (m *Memory) AddPolicy(_ context.Context, want Policy) (Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.policies {
		if p.Source == want.Source && p.Destination == want.Destination {
			p.Posture, p.Ports = slices.Clone(p.Posture), slices.Clone(p.Ports)
			return p, nil
		}
	}
	if err := m.missingCheck(want.Posture); err != nil {
		return Policy{}, err
	}
	p := Policy{ID: m.id(), Source: want.Source, Destination: want.Destination, Posture: slices.Clone(want.Posture),
		OneWay: want.OneWay, Ports: slices.Clone(want.Ports)}
	if len(p.Posture) == 0 {
		p.Posture = nil
	}
	if len(p.Ports) == 0 {
		p.Ports = nil
	}
	m.policies[p.ID] = p
	m.version++
	p.Posture, p.Ports = slices.Clone(p.Posture), slices.Clone(p.Ports)
	return p, nil
}

func (m *Memory) SetPolicyRules(_ context.Context, id int64, oneWay bool, ports []string) (Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.policies[id]
	if !ok {
		return Policy{}, ErrNotFound
	}
	if len(ports) == 0 {
		ports = nil
	}
	if p.OneWay != oneWay || !slices.Equal(p.Ports, ports) {
		p.OneWay, p.Ports = oneWay, slices.Clone(ports)
		m.policies[id] = p
		m.version++
	}
	p.Posture, p.Ports = slices.Clone(p.Posture), slices.Clone(p.Ports)
	return p, nil
}

func (m *Memory) SetPolicyPosture(_ context.Context, id int64, posture []string) (Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.policies[id]
	if !ok {
		return Policy{}, ErrNotFound
	}
	if err := m.missingCheck(posture); err != nil {
		return Policy{}, err
	}
	if !slices.Equal(p.Posture, posture) {
		p.Posture = slices.Clone(posture)
		m.policies[id] = p
		m.version++
	}
	p.Posture, p.Ports = slices.Clone(p.Posture), slices.Clone(p.Ports)
	return p, nil
}

func (m *Memory) PostureChecks(context.Context) ([]PostureCheck, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PostureCheck, 0, len(m.checks))
	for _, c := range m.checks {
		c.MinOS, c.MaxPatchAge = maps.Clone(c.MinOS), maps.Clone(c.MaxPatchAge)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) AddPostureCheck(_ context.Context, c PostureCheck) (PostureCheck, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.checks[c.Name]; ok {
		return PostureCheck{}, ErrExists
	}
	c.CreatedAt = time.Now()
	c.MinOS, c.MaxPatchAge = maps.Clone(c.MinOS), maps.Clone(c.MaxPatchAge)
	m.checks[c.Name] = c
	return c, nil
}

func (m *Memory) DeletePostureCheck(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.checks[name]; !ok {
		return ErrNotFound
	}
	var users []int64
	for _, p := range m.policies {
		if slices.Contains(p.Posture, name) {
			users = append(users, p.ID)
		}
	}
	var links []string
	for _, l := range m.links {
		if slices.Contains(l.Posture, name) {
			links = append(links, l.Name)
		}
	}
	if len(users) > 0 || len(links) > 0 {
		slices.Sort(users)
		slices.Sort(links)
		return &CheckInUseError{Check: name, Policies: users, Links: links}
	}
	delete(m.checks, name)
	return nil
}

func (m *Memory) SetPostureReport(_ context.Context, peerID int64, facts []byte, at time.Time, minGap time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.peers[peerID]; !ok {
		return ErrNotFound
	}
	r := m.posture[peerID]
	if minGap > 0 && !r.ReportedAt.IsZero() && at.Sub(r.ReportedAt) < minGap {
		return ErrTooSoon
	}
	r.PeerID, r.Facts, r.ReportedAt = peerID, slices.Clone(facts), at
	m.posture[peerID] = r
	return nil
}

func (m *Memory) PostureReports(context.Context) ([]PostureReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PostureReport, 0, len(m.posture))
	for _, r := range m.posture {
		r.Facts, r.Results = slices.Clone(r.Facts), maps.Clone(r.Results)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PeerID < out[j].PeerID })
	return out, nil
}

func (m *Memory) SetPostureResults(_ context.Context, peerID int64, previous, results map[string]string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.peers[peerID]; !ok {
		return false, ErrNotFound
	}
	r := m.posture[peerID]
	// Conditional on the stored evaluation, "none" (nil) included.
	if (r.Results == nil) != (previous == nil) || !maps.Equal(r.Results, previous) {
		return false, nil
	}
	changed := !maps.Equal(r.Results, results)
	r.PeerID, r.Results = peerID, maps.Clone(results)
	if r.Results == nil {
		r.Results = map[string]string{}
	}
	if changed || r.ResultsAt.IsZero() {
		r.ResultsAt = time.Now()
	}
	m.posture[peerID] = r
	if changed {
		m.version++
	}
	return true, nil
}

func (m *Memory) DeletePolicy(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.policies[id]; !ok {
		return ErrNotFound
	}
	delete(m.policies, id)
	m.version++
	return nil
}

func (m *Memory) ExpirePeers(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, p := range m.peers {
		if p.Machine.Approved && !p.ApprovedUntil.IsZero() && !now.Before(p.ApprovedUntil) {
			p.Machine.Approved = false
			p.apply(PeerUpdate{})
			m.peers[id] = p
			n++
		}
	}
	if n > 0 {
		m.version++
	}
	return n, nil
}

func (m *Memory) EndIdleSessions(_ context.Context, now time.Time, idle, max time.Duration) ([]Peer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Peer
	for id, p := range m.peers {
		if PersonIdle(p, now, idle, max) {
			out = append(out, p.cloned())
			p.Person.Active = false
			p.apply(PeerUpdate{})
			m.peers[id] = p
		}
	}
	if len(out) > 0 {
		m.version++
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) CreateAuthority(_ context.Context, a Authority, t Token) (Authority, Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.auths[a.Name]; ok {
		return Authority{}, Token{}, ErrExists
	}
	t.Authority = a.Name
	t, err := m.createToken(t)
	if err != nil {
		return Authority{}, Token{}, err
	}
	a.TokenID, a.CreatedAt = t.ID, t.CreatedAt
	a.Groups = slices.Clone(a.Groups)
	m.auths[a.Name] = a
	return a, t, nil
}

func (m *Memory) Authorities(context.Context) ([]Authority, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Authority, 0, len(m.auths))
	for _, a := range m.auths {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) Authority(_ context.Context, name string) (Authority, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.auths[name]
	if !ok {
		return Authority{}, ErrNotFound
	}
	return a, nil
}

func (m *Memory) SuspendAuthority(_ context.Context, name string, suspended bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.auths[name]
	if !ok {
		return ErrNotFound
	}
	a.Suspended = suspended
	m.auths[name] = a
	if suspended {
		now := time.Now()
		for id, p := range m.peers {
			if p.Authority == name {
				p.Approved, p.ApprovedUntil = false, now
				m.peers[id] = p
			}
		}
	}
	m.version++
	return nil
}

func (m *Memory) DeleteAuthority(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.auths[name]
	if !ok {
		return ErrNotFound
	}
	delete(m.tokens, a.TokenID)
	for id, p := range m.peers {
		if p.Authority == name {
			delete(m.peers, id)
			m.forgetPeer(id)
		}
	}
	delete(m.auths, name)
	m.version++
	return nil
}

func (m *Memory) CreateLink(_ context.Context, l Link) (Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.links[l.Name]; ok {
		return Link{}, ErrExists
	}
	if err := m.missingCheck(l.Posture); err != nil {
		return Link{}, err
	}
	l.CreatedAt = time.Now()
	l.Posture = nilIfEmpty(slices.Clone(l.Posture))
	m.links[l.Name] = l
	return cloneLink(l), nil
}

// cloneLink copies a link's lists, so that callers cannot change the stored one.
func cloneLink(l Link) Link {
	l.Groups, l.Grant, l.Posture = slices.Clone(l.Groups), slices.Clone(l.Grant), slices.Clone(l.Posture)
	return l
}

func (m *Memory) Links(context.Context) ([]Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Link, 0, len(m.links))
	for _, l := range m.links {
		out = append(out, cloneLink(l))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) Link(_ context.Context, name string) (Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.links[name]
	if !ok {
		return Link{}, ErrNotFound
	}
	return cloneLink(l), nil
}

func (m *Memory) SetLinkPosture(_ context.Context, name string, posture []string) (Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.links[name]
	if !ok {
		return Link{}, ErrNotFound
	}
	if err := m.missingCheck(posture); err != nil {
		return Link{}, err
	}
	if !slices.Equal(l.Posture, nilIfEmpty(posture)) {
		l.Posture = nilIfEmpty(slices.Clone(posture))
		m.links[name] = l
		for k := range m.linkPost {
			if strings.HasPrefix(k, name+"/") {
				delete(m.linkPost, k)
			}
		}
	}
	return cloneLink(l), nil
}

func (m *Memory) SwapLinkPosture(_ context.Context, link string, peerID int64, failing string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.links[link]; !ok {
		return "", ErrNotFound
	}
	if _, ok := m.peers[peerID]; !ok {
		return "", ErrNotFound
	}
	k := link + "/" + strconv.FormatInt(peerID, 10)
	previous := m.linkPost[k]
	if failing == "" {
		delete(m.linkPost, k)
	} else {
		m.linkPost[k] = failing
	}
	return previous, nil
}

func (m *Memory) SetLinkToken(_ context.Context, name, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.links[name]
	if !ok {
		return ErrNotFound
	}
	l.Token = token
	m.links[name] = l
	return nil
}

func (m *Memory) DeleteLink(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.links[name]; !ok {
		return ErrNotFound
	}
	delete(m.links, name)
	for k := range m.linkKeys {
		if strings.HasPrefix(k, name+"/") {
			delete(m.linkKeys, k)
		}
	}
	for k := range m.linkPost {
		if strings.HasPrefix(k, name+"/") {
			delete(m.linkPost, k)
		}
	}
	return nil
}

func (m *Memory) LinkKey(_ context.Context, link string, peerID int64) (wgtypes.Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.linkKeys[link+"/"+strconv.FormatInt(peerID, 10)]
	if !ok {
		return wgtypes.Key{}, ErrNotFound
	}
	return k, nil
}

func (m *Memory) SetLinkKey(_ context.Context, link string, peerID int64, key wgtypes.Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.linkKeys[link+"/"+strconv.FormatInt(peerID, 10)] = key
	return nil
}

func (m *Memory) SetAuthorityLimit(_ context.Context, name string, maxDevices int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.auths[name]
	if !ok {
		return ErrNotFound
	}
	a.MaxDevices = maxDevices
	m.auths[name] = a
	return nil
}

func (m *Memory) RotateAuthorityToken(_ context.Context, name string, t Token) (Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.auths[name]
	if !ok {
		return Token{}, ErrNotFound
	}
	old := a.TokenID
	t.Authority = name
	t, err := m.createToken(t)
	if err != nil {
		return Token{}, err
	}
	delete(m.tokens, old)
	a.TokenID = t.ID
	m.auths[name] = a
	return t, nil
}

func (m *Memory) SetSSOToken(_ context.Context, t SSOToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.peers[t.PeerID]; !ok {
		return ErrNotFound
	}
	if t.Previous != "" && m.sso[t.PeerID].Encrypted != t.Previous {
		return ErrChanged
	}
	t.Previous = ""
	m.sso[t.PeerID] = t
	return nil
}

func (m *Memory) ClaimSSOTokens(_ context.Context, now, next time.Time, limit int) ([]SSOToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var due []SSOToken
	for _, t := range m.sso {
		if !t.NextCheck.After(now) {
			due = append(due, t)
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].NextCheck.Before(due[j].NextCheck) })
	if len(due) > limit {
		due = due[:limit]
	}
	for i := range due {
		t := m.sso[due[i].PeerID]
		t.NextCheck = next
		m.sso[t.PeerID] = t
	}
	return due, nil
}

func (m *Memory) DeleteSSOToken(_ context.Context, peerID int64, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.sso[peerID]
	if token != "" && (!ok || t.Encrypted != token) {
		return ErrChanged
	}
	delete(m.sso, peerID)
	return nil
}

func (m *Memory) ForgetSSOTokens(context.Context) ([]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []int64
	for id := range m.sso {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	m.sso = map[int64]SSOToken{}
	delete(m.settings, SettingSSOTokenCanary)
	return ids, nil
}

func (m *Memory) KeepSetting(_ context.Context, key, value string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.settings == nil {
		m.settings = map[string]string{}
	}
	if v, ok := m.settings[key]; ok {
		return v, nil
	}
	m.settings[key] = value
	return value, nil
}

func (m *Memory) SetSetting(_ context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.settings == nil {
		m.settings = map[string]string{}
	}
	m.settings[key] = value
	m.version++
	return nil
}

func (m *Memory) Setting(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.settings[key]
	return v, ok, nil
}

func (m *Memory) CreateUISession(_ context.Context, u UISession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.ui[u.Hash]; ok {
		return ErrExists
	}
	for _, o := range m.ui {
		if o.PeerID == u.PeerID && !o.Approved && o.Code == u.Code {
			return ErrExists
		}
	}
	m.ui[u.Hash] = u
	return nil
}

func (m *Memory) UISession(_ context.Context, hash string, now time.Time) (UISession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.ui[hash]
	if !ok || !now.Before(u.ExpiresAt) {
		return UISession{}, ErrNotFound
	}
	return u, nil
}

func (m *Memory) PendingUISessions(_ context.Context, peerID int64, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, u := range m.ui {
		if u.PeerID == peerID && !u.Approved && now.Before(u.ExpiresAt) {
			n++
		}
	}
	return n, nil
}

func (m *Memory) ApproveUISession(_ context.Context, peerID int64, code string, now, expires time.Time) (UISession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, u := range m.ui {
		if u.PeerID == peerID && !u.Approved && u.Code == code && now.Before(u.ExpiresAt) {
			u.Approved, u.ExpiresAt, u.LastUsed = true, expires, now
			m.ui[h] = u
			return u, nil
		}
	}
	return UISession{}, ErrNotFound
}

func (m *Memory) TouchUISession(_ context.Context, hash string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.ui[hash]; ok {
		u.LastUsed = now
		m.ui[hash] = u
	}
	return nil
}

func (m *Memory) DeleteUISessionsOf(_ context.Context, peerID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, u := range m.ui {
		if u.PeerID == peerID {
			delete(m.ui, h)
		}
	}
	return nil
}

func (m *Memory) DeleteUISession(_ context.Context, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ui, hash)
	return nil
}

func (m *Memory) CreateSignInCode(_ context.Context, c SignInCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.signIns == nil {
		m.signIns = map[string]SignInCode{}
	}
	if _, ok := m.signIns[c.Hash]; ok {
		return ErrExists
	}
	m.signIns[c.Hash] = c
	return nil
}

func (m *Memory) TakeSignInCode(_ context.Context, hash string, now time.Time) (SignInCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.signIns[hash]
	delete(m.signIns, hash)
	if !ok || !now.Before(c.ExpiresAt) {
		return SignInCode{}, ErrNotFound
	}
	return c, nil
}

func (m *Memory) ExpireSignInCodes(_ context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, c := range m.signIns {
		if !now.Before(c.ExpiresAt) {
			delete(m.signIns, h)
		}
	}
	return nil
}

func (m *Memory) LastSignIn(_ context.Context, peerID int64, since time.Time) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.signUse[peerID]; ok && u.PersonSince.Equal(since) {
		return u.ExpiresAt, nil
	}
	return time.Time{}, nil
}

func (m *Memory) RecordSignIn(_ context.Context, peerID int64, since, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.signUse == nil {
		m.signUse = map[int64]SignInCode{}
	}
	m.signUse[peerID] = SignInCode{PeerID: peerID, PersonSince: since, ExpiresAt: at}
	return nil
}

func (m *Memory) ExpireUISessions(_ context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, u := range m.ui {
		if !now.Before(u.ExpiresAt) {
			delete(m.ui, h)
		}
	}
	return nil
}

func (m *Memory) CreateApproval(_ context.Context, a Approval) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.approval == nil {
		m.approval = map[string]Approval{}
	}
	if _, ok := m.approval[a.ID]; ok {
		return ErrExists
	}
	a.State, a.Choices = ApprovalPending, slices.Clone(a.Choices)
	m.approval[a.ID] = a
	return nil
}

func (m *Memory) Approval(_ context.Context, id string) (Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.approval[id]
	if !ok {
		return Approval{}, ErrNotFound
	}
	return a, nil
}

func (m *Memory) PendingApprovals(_ context.Context, user string, now time.Time) ([]Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Approval
	for _, a := range m.approval {
		if a.User == user && a.State == ApprovalPending && a.ExpiresAt.After(now) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) AnyPendingApproval(_ context.Context, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.approval {
		if a.State == ApprovalPending && a.ExpiresAt.After(now) {
			return true, nil
		}
	}
	return false, nil
}

func (m *Memory) FinishApproval(_ context.Context, id, state string, by int64, at time.Time) (Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.approval[id]
	switch {
	case !ok:
		return Approval{}, ErrNotFound
	case a.State != ApprovalPending:
		return a, ErrChanged
	}
	a.State, a.AnsweredBy, a.AnsweredAt = state, by, at
	m.approval[id] = a
	return a, nil
}

func (m *Memory) CountApprovals(_ context.Context, requester int64, user string, since time.Time) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var r, u int
	for _, a := range m.approval {
		if a.CreatedAt.Before(since) {
			continue
		}
		if a.Requester == requester {
			r++
		}
		if a.User == user {
			u++
		}
	}
	return r, u, nil
}

func (m *Memory) DeleteApprovalsBefore(_ context.Context, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, a := range m.approval {
		if a.ExpiresAt.Before(t) {
			delete(m.approval, id)
		}
	}
	return nil
}

func (m *Memory) UpdateCheckIn(_ context.Context, peerID int64, fn func(c CheckIn, found bool) (CheckIn, error)) (CheckIn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.peers[peerID]; !ok {
		return CheckIn{}, ErrNotFound
	}
	if m.checkIns == nil {
		m.checkIns = map[int64]CheckIn{}
	}
	cur, found := m.checkIns[peerID]
	if !found {
		cur = CheckIn{PeerID: peerID}
	}
	next, err := fn(cur, found)
	if err != nil {
		return CheckIn{}, err
	}
	next.PeerID = peerID
	m.checkIns[peerID] = next
	return next, nil
}

func (m *Memory) UpdateHWKey(_ context.Context, peerID int64, fn func(k HWKey, found bool) (HWKey, error)) (HWKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.peers[peerID]; !ok {
		return HWKey{}, ErrNotFound
	}
	if m.hwKeys == nil {
		m.hwKeys = map[int64]HWKey{}
	}
	cur, found := m.hwKeys[peerID]
	if !found {
		cur = HWKey{PeerID: peerID}
	}
	next, err := fn(cur, found)
	if err != nil {
		return HWKey{}, err
	}
	next.PeerID = peerID
	if next.BoundAt.IsZero() {
		next.BoundAt = time.Now()
	}
	if next.Rotate != cur.Rotate {
		m.version++
	}
	m.hwKeys[peerID] = next
	return next, nil
}

func (m *Memory) HWKey(_ context.Context, peerID int64) (HWKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.hwKeys[peerID]
	if !ok {
		return HWKey{}, ErrNotFound
	}
	return k, nil
}

func (m *Memory) DeleteHWKey(_ context.Context, peerID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.hwKeys[peerID]; !ok {
		return ErrNotFound
	}
	delete(m.hwKeys, peerID)
	return nil
}

func (m *Memory) HWKeys(_ context.Context) ([]HWKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]HWKey, 0, len(m.hwKeys))
	for _, k := range m.hwKeys {
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b HWKey) int { return cmp.Compare(a.PeerID, b.PeerID) })
	return out, nil
}

func (m *Memory) RotatePeerKey(_ context.Context, peerID int64, oldKey, newKey wgtypes.Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[peerID]
	if !ok || p.PublicKey != oldKey {
		return ErrNotFound
	}
	for _, q := range m.peers {
		if q.PublicKey == newKey {
			return ErrExists
		}
	}
	for _, c := range m.controls {
		if c.PublicKey == newKey {
			return ErrExists
		}
	}
	for _, t := range m.tokens {
		if t.PublicKey == newKey {
			return ErrExists
		}
	}
	p.PublicKey = newKey
	m.peers[peerID] = p
	if k, ok := m.hwKeys[peerID]; ok {
		k.Rotate, k.RotatedAt = false, time.Now()
		m.hwKeys[peerID] = k
	}
	m.version++
	return nil
}

func (m *Memory) DeleteCheckIn(_ context.Context, peerID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.checkIns, peerID)
	return nil
}

func (m *Memory) CheckIns(_ context.Context) ([]CheckIn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []CheckIn
	for _, c := range m.checkIns {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PeerID < out[j].PeerID })
	return out, nil
}

func (m *Memory) Routes(_ context.Context) ([]Route, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Route, 0, len(m.routes))
	for _, r := range m.routes {
		r.Networks = slices.Clone(r.Networks)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) AddRoute(_ context.Context, r Route) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.routes == nil {
		m.routes = map[string]Route{}
	}
	if _, ok := m.routes[r.Name]; ok {
		return ErrExists
	}
	r.Networks = slices.Clone(r.Networks)
	m.routes[r.Name] = r
	m.version++
	return nil
}

func (m *Memory) DeleteRoute(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.routes[name]; !ok {
		return ErrNotFound
	}
	delete(m.routes, name)
	m.version++
	return nil
}

func (m *Memory) DNSRecords(_ context.Context) ([]DNSRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]DNSRecord, 0, len(m.dnsNames))
	for _, r := range m.dnsNames {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) AddDNSRecord(_ context.Context, r DNSRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dnsNames == nil {
		m.dnsNames = map[string]DNSRecord{}
	}
	if _, ok := m.dnsNames[r.Name]; ok {
		return ErrExists
	}
	m.dnsNames[r.Name] = r
	m.version++
	return nil
}

func (m *Memory) DeleteDNSRecord(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.dnsNames[name]; !ok {
		return ErrNotFound
	}
	delete(m.dnsNames, name)
	m.version++
	return nil
}

func (m *Memory) DNSForwards(_ context.Context) ([]DNSForward, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]DNSForward, 0, len(m.dnsZones))
	for _, f := range m.dnsZones {
		f.Servers = slices.Clone(f.Servers)
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Zone < out[j].Zone })
	return out, nil
}

func (m *Memory) AddDNSForward(_ context.Context, f DNSForward) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dnsZones == nil {
		m.dnsZones = map[string]DNSForward{}
	}
	if _, ok := m.dnsZones[f.Zone]; ok {
		return ErrExists
	}
	f.Servers = slices.Clone(f.Servers)
	m.dnsZones[f.Zone] = f
	m.version++
	return nil
}

func (m *Memory) DeleteDNSForward(_ context.Context, zone string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.dnsZones[zone]; !ok {
		return ErrNotFound
	}
	delete(m.dnsZones, zone)
	m.version++
	return nil
}

func (m *Memory) UpdatePolicy(_ context.Context) (UpdatePolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updates == nil {
		return UpdatePolicy{Mode: "auto"}, nil
	}
	return *m.updates, nil
}

func (m *Memory) SetUpdatePolicy(_ context.Context, u UpdatePolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updates = &u
	m.version++
	return nil
}

func (m *Memory) ReleaseOffered(_ context.Context, version string, at time.Time) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.offers == nil {
		m.offers = map[string]time.Time{}
	}
	if t, ok := m.offers[version]; ok {
		return t, nil
	}
	m.offers[version] = at
	return at, nil
}

func (m *Memory) RecordPersonActivity(_ context.Context, id int64, at time.Time, reports bool, bootID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[id]
	if !ok {
		return ErrNotFound
	}
	if at.After(p.Person.ActivityAt) {
		p.Person.ActivityAt = at
	}
	p.Person.Reports = p.Person.Reports || reports
	if bootID != "" {
		p.BootID = bootID
	}
	m.peers[id] = p
	return nil
}

// memoryAuditKeep bounds the in-memory audit (tests and single-node trials); the database keeps all.
const memoryAuditKeep = 100000

func (m *Memory) AddAudit(_ context.Context, e AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e.ID = int64(len(m.audit)) + 1
	if n := len(m.audit); n > 0 {
		e.ID = m.audit[n-1].ID + 1
	}
	m.audit = append(m.audit, e)
	if len(m.audit) > memoryAuditKeep {
		m.audit = slices.Clone(m.audit[len(m.audit)-memoryAuditKeep:])
	}
	return nil
}

func (m *Memory) Audit(_ context.Context, q AuditQuery) ([]AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	limit := q.Limit
	if limit <= 0 || limit > MaxAuditPage {
		limit = MaxAuditPage
	}
	text := strings.ToLower(q.Text)
	out := []AuditEntry{}
	for i := len(m.audit) - 1; i >= 0 && len(out) < limit; i-- {
		e := m.audit[i]
		if q.Before > 0 && e.ID >= q.Before || q.Action != "" && e.Action != q.Action || q.Result != "" && e.Result != q.Result {
			continue
		}
		if !q.Since.IsZero() && e.At.Before(q.Since) {
			break
		}
		if text != "" && !strings.Contains(strings.ToLower(strings.Join([]string{e.Node, e.Action, e.Device, e.Person, e.From, e.Target, e.Result}, " ")), text) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}
