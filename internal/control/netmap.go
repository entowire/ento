package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/names"
	"entowire.com/ento/internal/store"
	"entowire.com/ento/internal/token"
)

func apiControls(nodes []store.ControlNode) []api.Control {
	out := make([]api.Control, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, api.Control{Name: n.Name, PublicKey: n.PublicKey.String(), Endpoint: n.Endpoint, Address: n.Address.String()})
	}
	return out
}

// buildNetMap computes what self may see. Unapproved peers only get the control nodes.
func buildNetMap(ctx context.Context, st store.Store, space ipam.Space, self store.Peer, version int64, noGateways []string) (api.NetMap, error) {
	self = withIsolation(self)
	nodes, err := st.ControlNodes(ctx)
	if err != nil {
		return api.NetMap{}, err
	}
	nm := api.NetMap{
		Version: version,
		Network: space.Prefix.String(),
		Self: api.Self{Address: self.Address.String(), Hostname: self.Hostname, Approved: self.Approved,
			Admin: self.Admin, Operator: self.Operator, Groups: self.Groups, Suspended: self.Suspended,
			LoginRequired: loginRequired(self, time.Now())},
		Controls: apiControls(nodes),
		Peers:    []api.Peer{},
	}
	if self.User != "" && self.Authority == "" { // bound to a person by single sign-on
		nm.Self.User, nm.Self.UserName = self.UserLogin, self.UserName
	}
	if !self.Approved {
		// No peers, but a filter all the same (0.57): it admits only the control nodes, and keeps
		// what the device forwards from their sign-in port, so a device waiting for its person's
		// sign-in can sign them in on its own page (here.go).
		nm.Filter = true
		return nm, nil
	}
	peers, err := st.Peers(ctx)
	if err != nil {
		return api.NetMap{}, err
	}
	for i := range peers {
		peers[i] = withIsolation(peers[i])
	}
	policies, err := st.Policies(ctx)
	if err != nil {
		return api.NetMap{}, err
	}
	var ps *postureState
	if needsPosture(policies) {
		if ps, err = loadPosture(ctx, st, time.Now()); err != nil {
			return api.NetMap{}, err
		}
		nm.Self.PostureFailing = failingChecks(self, policies, ps)
	}
	for _, p := range peers {
		if p.ID == self.ID || !p.Approved || !allowed(self, p, policies, ps) {
			continue
		}
		var eps []string
		if p.Endpoint != "" {
			eps = append(eps, p.Endpoint)
		}
		nm.Peers = append(nm.Peers, api.Peer{PublicKey: p.PublicKey.String(), Address: p.Address.String(),
			Hostname: p.Hostname, Endpoints: eps, Accept: acceptFrom(self, p, policies, ps), Quiet: quietOS(p.OS)})
	}
	routes, err := st.Routes(ctx)
	if err != nil {
		return api.NetMap{}, err
	}
	routes = usableRoutes(routes, peers, noGateways)
	addRoutes(&nm, self, peers, routes, policies, ps)
	if self.Person.Active && self.User != "" && self.Authority == "" {
		nm.Self.PersonActive = true
		nm.Self.PersonSince = self.Person.Since.UTC().Format(time.RFC3339Nano)
		addMachineAccess(&nm, self.MachineOnly(), peers, routes, policies, ps)
	}
	nm.Filter = true
	return nm, nil
}

// loginRequired reports whether the person's rights return on a device bound to them only with a
// full sign-in: their layer is closed, and an approved sign-in on the device cannot reopen it (the
// last full sign-in is too old, the identity provider withdrew them, or the machine is not
// approved and so cannot ask).
func loginRequired(p store.Peer, now time.Time) bool {
	if p.User == "" || p.Authority != "" || p.Suspended || p.Person.Active && p.Person.Approved {
		return false
	}
	return !(p.Machine.Approved && p.Reopenable(now))
}

// addMachineAccess tells a device whose person layer is open what its machine layer alone may open
// on each peer, in each network behind a gateway and through each exit: what it sends beyond that
// is its person's traffic, which keeps the layer open.
func addMachineAccess(nm *api.NetMap, machine store.Peer, peers []store.Peer, routes []store.Route, policies []store.Policy, ps *postureState) {
	byKey := map[string]store.Peer{}
	for _, p := range peers {
		byKey[p.PublicKey.String()] = p
	}
	gateways := routeGateways(routes, peers)
	for i := range nm.Peers {
		e := &nm.Peers[i]
		p, ok := byKey[e.PublicKey]
		if !ok {
			continue
		}
		if machine.Approved && allowed(machine, p, policies, ps) {
			e.Machine = acceptFrom(p, machine, policies, ps)
		}
		for _, r := range routes {
			gw, ok := gateways[r.Name]
			if !ok || gw.ID != p.ID || !machine.Approved {
				continue
			}
			rules, ok := routeAccess(machine, r, policies, ps)
			if !ok {
				continue
			}
			if r.Exit {
				for j := range e.Exits {
					if e.Exits[j].Route == r.Name {
						e.Exits[j].Machine = true
					}
				}
				continue
			}
			for _, n := range r.Networks {
				e.RouteMachine = append(e.RouteMachine, api.RouteRule{Network: n.String(), Ports: rules})
			}
		}
	}
}

// TokenOptions describes what an enrollment token pre-authorises.
type TokenOptions struct {
	Groups  []string
	Approve bool
	Admin   bool
	TTL     time.Duration
	// CreatedBy is recorded with the token (who issued it).
	CreatedBy string
	// Name is the enrolled device's name ("": made from its host name); with Replace it takes over
	// from a device that has the name when it enrolls.
	Name    string
	Replace bool
	// Words asks for the token as words (token.WordCount of them) in the network Network, whose
	// record (NetworkRecord) the device reads from DNS. At most a day.
	Words   bool
	Network netip.Prefix
}

// maxWordsTTL limits how long words can be used: what makes guessing them hopeless is their
// entropy against Argon2id, and the time they are good for.
const maxWordsTTL = 24 * time.Hour

// argonSlot lets one Argon2id derivation (256 MiB) run at a time on a control node.
var argonSlot = make(chan struct{}, 1)

// NetworkRecord is the network record of the network (token.Record): its range and the
// registered control nodes.
func NetworkRecord(ctx context.Context, st store.Store, network netip.Prefix) (token.Record, error) {
	nodes, err := st.ControlNodes(ctx)
	if err != nil {
		return token.Record{}, err
	}
	if len(nodes) == 0 {
		return token.Record{}, fmt.Errorf("no control node registered yet")
	}
	r := token.Record{Network: network}
	for _, n := range nodes {
		r.Controls = append(r.Controls, token.Control{PublicKey: n.PublicKey, Endpoint: n.Endpoint, Address: n.Address})
	}
	return r, nil
}

// IssueToken creates an enrollment token. Only derived key material is stored; the returned token
// string (or words, TokenOptions.Words) is the only copy of the secret.
func IssueToken(ctx context.Context, st store.Store, opts TokenOptions) (string, store.Token, error) {
	if opts.TTL <= 0 {
		opts.TTL = time.Hour
	}
	if opts.Words {
		return issueWords(ctx, st, opts)
	}
	if opts.Name != "" {
		if err := names.Check(opts.Name); err != nil {
			return "", store.Token{}, err
		}
	} else if opts.Replace {
		return "", store.Token{}, errors.New("replacing a device needs its name")
	}
	nodes, err := st.ControlNodes(ctx)
	if err != nil {
		return "", store.Token{}, err
	}
	if len(nodes) == 0 {
		return "", store.Token{}, fmt.Errorf("no control node registered yet")
	}
	secret, err := token.NewSecret()
	if err != nil {
		return "", store.Token{}, err
	}
	creds, err := token.Derive(secret)
	if err != nil {
		return "", store.Token{}, err
	}
	t, err := st.CreateToken(ctx, store.Token{
		PublicKey: creds.PublicKey, PresharedKey: creds.PresharedKey, Groups: opts.Groups,
		Approve: opts.Approve, Admin: opts.Admin, ExpiresAt: time.Now().Add(opts.TTL),
		CreatedBy: opts.CreatedBy, Name: opts.Name, Replace: opts.Replace,
	})
	if err != nil {
		return "", store.Token{}, err
	}
	tok := token.Token{Secret: secret, TempAddress: t.TempAddress}
	for _, n := range nodes {
		tok.Controls = append(tok.Controls, token.Control{PublicKey: n.PublicKey, Endpoint: n.Endpoint, Address: n.Address})
	}
	s, err := tok.Encode()
	return s, t, err
}

// issueWords creates a token that stands for words: the secret is stretched from them (see
// token.WordsSecret) and the enrollment address derived from it, so the device needs only the
// words and the network record. New words are drawn while the address is taken.
func issueWords(ctx context.Context, st store.Store, opts TokenOptions) (string, store.Token, error) {
	if opts.TTL > maxWordsTTL {
		return "", store.Token{}, fmt.Errorf("words are good for at most %s", maxWordsTTL)
	}
	if opts.Name != "" {
		if err := names.Check(opts.Name); err != nil {
			return "", store.Token{}, err
		}
	} else if opts.Replace {
		return "", store.Token{}, errors.New("replacing a device needs its name")
	}
	rec, err := NetworkRecord(ctx, st, opts.Network)
	if err != nil {
		return "", store.Token{}, err
	}
	select {
	case argonSlot <- struct{}{}:
		defer func() { <-argonSlot }()
	case <-ctx.Done():
		return "", store.Token{}, ctx.Err()
	}
	for range 16 {
		w, err := token.NewWords()
		if err != nil {
			return "", store.Token{}, err
		}
		tok, err := rec.Token(w)
		if err != nil {
			return "", store.Token{}, err
		}
		creds, err := token.Derive(tok.Secret)
		if err != nil {
			return "", store.Token{}, err
		}
		t, err := st.CreateToken(ctx, store.Token{
			PublicKey: creds.PublicKey, PresharedKey: creds.PresharedKey, TempAddress: tok.TempAddress,
			Groups: opts.Groups, Approve: opts.Approve, Admin: opts.Admin, ExpiresAt: time.Now().Add(opts.TTL),
			CreatedBy: opts.CreatedBy, Name: opts.Name, Replace: opts.Replace,
		})
		if errors.Is(err, store.ErrAddressInUse) {
			continue
		}
		return strings.Join(w, " "), t, err
	}
	return "", store.Token{}, errors.New("no free enrollment address for words: too many tokens in use")
}

// quietOS reports whether devices of a system run on a battery whose radio wakes for every packet
// (phones): their peers send them no keepalives (api.Peer.Quiet).
func quietOS(os string) bool { return os == "android" || os == "ios" }
