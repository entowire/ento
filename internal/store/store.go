// Package store persists the state of an ento deployment.
//
// Every mutation increments a single version counter. Control nodes compare versions to detect
// changes, and agents long-poll the network map with the version they last received.
package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	// ErrNotFound is returned when the requested object does not exist.
	ErrNotFound = errors.New("not found")
	// ErrTokenUnusable is returned when redeeming an expired or already redeemed token.
	ErrTokenUnusable = errors.New("enrollment token expired or already used")
	// ErrKeyInUse is returned when a public key is already registered.
	ErrKeyInUse = errors.New("public key already registered")
	// ErrAddressInUse is returned when a token asks for an enrollment address that another token
	// that can still be used holds, or that is no enrollment address (CreateToken).
	ErrAddressInUse = errors.New("enrollment address in use")
	// ErrExists is returned when creating an object whose name is taken.
	ErrExists = errors.New("already exists")
	// ErrChanged is returned when a conditional change finds its object changed meanwhile
	// (PeerUpdate.IfLoginAt, SSOToken.Previous).
	ErrChanged = errors.New("changed meanwhile")
	// ErrTooSoon is returned when a device reports its posture again too soon (SetPostureReport).
	ErrTooSoon = errors.New("too soon")
	// ErrMemberSuspended is returned when a home device whose membership is suspended joins again
	// with a new key: the suspension stays until an administrator of this network lifts it.
	ErrMemberSuspended = errors.New("this device's membership is suspended in this network")
)

// NoSuchCheckError is returned when a policy is to require a posture check that does not exist.
type NoSuchCheckError struct{ Check string }

func (e *NoSuchCheckError) Error() string { return fmt.Sprintf("no posture check named %q", e.Check) }

// CheckInUseError is returned when deleting a posture check that policies or links still require.
type CheckInUseError struct {
	Check    string
	Policies []int64
	Links    []string
}

func (e *CheckInUseError) Error() string {
	var users []string
	if len(e.Policies) > 0 {
		ids := make([]string, len(e.Policies))
		for i, id := range e.Policies {
			ids[i] = fmt.Sprint(id)
		}
		users = append(users, "policy "+strings.Join(ids, ", "))
	}
	if len(e.Links) > 0 {
		users = append(users, "link "+strings.Join(e.Links, ", "))
	}
	return fmt.Sprintf("posture check %s is required by %s", e.Check, strings.Join(users, " and "))
}

// AuthorityFullError is returned when an authority already has as many devices as it may.
type AuthorityFullError struct {
	Authority string
	Max       int
}

func (e *AuthorityFullError) Error() string {
	return fmt.Sprintf("authority %s already has its maximum of %d devices", e.Authority, e.Max)
}

// NameTakenError reports a device name that another device has, or that an enrollment token
// reserves for the device it will enroll.
type NameTakenError struct {
	Name    string
	PeerID  int64 // the device that has it, or
	TokenID int64 // the token that reserves it
}

func (e *NameTakenError) Error() string {
	if e.PeerID != 0 {
		return fmt.Sprintf("%s is already the name of device %d", e.Name, e.PeerID)
	}
	return fmt.Sprintf("%s is reserved by enrollment token %d", e.Name, e.TokenID)
}

// ControlNode is a node of the control plane.
type ControlNode struct {
	Name      string
	PublicKey wgtypes.Key
	Endpoint  string // public host:port of its WireGuard socket
	Address   netip.Addr
	LastSeen  time.Time
}

// Rights are what a layer of a device's access gives it.
type Rights struct {
	Approved bool
	Admin    bool
	Operator bool
	Groups   []string
}

// PersonLayer is the part of a device's access that comes from the person signed in on it by single
// sign-on (its rights from their groups, kept current by the identity provider), and whether it is
// open now: it opens at a sign-in (or an approved sign-in on the device, within PersonReopen of the
// last sign-in) and ends when the person signs out, the device starts again, or nothing of theirs
// crossed the tunnel for the session idle time.
type PersonLayer struct {
	Rights
	Active bool
	Since  time.Time // when it last opened
	// ActivityAt is when the person's traffic last crossed the tunnel (the device's check-ins say,
	// and the control plane's own record of their administration); Reports: the device's agent
	// reports it (0.27 and later; older agents' sessions are judged by LastSeen, as before).
	ActivityAt time.Time
	Reports    bool
}

// Peer is an enrolled device. Its access has two layers: the machine's (Machine: given by its
// enrollment token or an administrator, untouched by sessions) and the person's (Person). Approved,
// Admin, Operator and Groups are what both give it now (derive): the machine's, and the person's
// while their layer is open.
type Peer struct {
	ID        int64
	PublicKey wgtypes.Key
	Address   netip.Addr
	// Hostname is the device's name in the network (package names): unique, given by an
	// administrator or made from ReportedHostname.
	Hostname string
	// ReportedHostname is the host name the device reported when it enrolled (for a device admitted
	// by an authority: its name at home), kept for display.
	ReportedHostname string
	OS               string
	Approved         bool
	Admin            bool
	// Operator devices administer the network within limits that keep every change reversible:
	// ordinary devices, ordinary tokens and policies, never admins, operators, links or authorities.
	Operator bool
	Groups   []string
	Endpoint string // public endpoint last observed by a control node
	User     string // identity provider subject of the user who logged in on this device, if any
	UserName string // human-readable name of that user (e-mail or username)
	// UserLogin is that user's username at the identity provider (preferred_username), which systems
	// that sign people in with it use as their account name (sign-in approvals).
	UserLogin string
	CreatedAt time.Time
	LastSeen  time.Time

	// Authority is set for devices of a home network admitted through an authority (linked
	// networks). Their approval lasts until ApprovedUntil and is extended by fresh credentials.
	Authority     string
	ApprovedUntil time.Time // zero: no expiry
	// AuthorityDevice identifies the device in its home network (from its credential): it has one
	// membership here, and enrolling again with a new key replaces it.
	AuthorityDevice string

	// LoginAt is when the device's user last signed in with SSO, in full (devices bound to a user
	// only): the person layer reopens without a sign-in only within PersonReopen of it.
	LoginAt time.Time
	// Suspended devices are never approved: neither an administrator's approve nor a sign-in
	// restores them until they are resumed.
	Suspended bool

	Machine Rights
	Person  PersonLayer
	// BootID identifies the device's current boot, as it last reported it: a new one ends the person
	// layer (nothing a person opened survives a restart).
	BootID string
}

// IsolatedGroups are the names of the built-in device group isolated (the second from networks
// older than 0.44, before device groups had their prefix).
var IsolatedGroups = []string{"device:isolated", "isolated"}

// Isolated reports whether the device is in the isolated group: it then has no rights at all,
// whoever is signed in on it (constitution 4.3).
func (p Peer) Isolated() bool {
	return slices.ContainsFunc(p.Machine.Groups, func(g string) bool { return slices.Contains(IsolatedGroups, g) })
}

// derive sets Approved, Admin, Operator and Groups from the layers. Isolation and suspension come
// before both: an isolated device is not approved, has no role and none of its person's groups
// (0.50; before, an open person layer gave them back).
func (p *Peer) derive() {
	m := p.Machine
	p.Approved, p.Admin, p.Operator, p.Groups = m.Approved, m.Admin, m.Operator, slices.Clone(m.Groups)
	if p.Groups == nil {
		p.Groups = []string{}
	}
	if pl := p.Person; pl.Active && pl.Approved {
		p.Approved = true
		p.Admin = p.Admin || pl.Admin
		p.Operator = p.Operator || pl.Operator
		for _, g := range pl.Groups {
			if !slices.Contains(p.Groups, g) {
				p.Groups = append(p.Groups, g)
			}
		}
	}
	if p.Isolated() {
		p.Approved, p.Admin, p.Operator, p.Groups = false, false, false, slices.Clone(m.Groups)
	}
	if p.Admin {
		p.Operator = false
	}
	if p.Suspended {
		p.Approved = false
	}
}

// PersonOnly returns the device as its person layer alone sees it: the person's approval, role and
// groups, without the machine's approval and role (its device groups stay, for isolation and rules).
// A dashboard session opened by signing in acts with these (0.50).
func (p Peer) PersonOnly() Peer {
	p.Machine.Approved, p.Machine.Admin, p.Machine.Operator = false, false, false
	p.derive()
	return p
}

// MachineOnly returns the device as its machine layer alone sees it.
func (p Peer) MachineOnly() Peer {
	p.Person = PersonLayer{}
	p.derive()
	return p
}

// PersonReopen is how long after a person's last full sign-in on a device their layer may open
// again without one (an approved sign-in on the device).
const PersonReopen = 7 * 24 * time.Hour

// Reopenable reports whether the person layer may open again by an approved sign-in at now.
func (p Peer) Reopenable(now time.Time) bool {
	return p.User != "" && p.Authority == "" && !p.Suspended && p.Person.Approved && !p.LoginAt.IsZero() &&
		now.Sub(p.LoginAt) <= PersonReopen
}

// apply changes the layers and fields an update names, then derives the effective rights.
func (p *Peer) apply(u PeerUpdate) {
	if u.Hostname != nil {
		p.Hostname = *u.Hostname
	}
	if u.Approved != nil {
		p.Machine.Approved = *u.Approved
	}
	if u.Admin != nil {
		p.Machine.Admin = *u.Admin
	}
	if u.Operator != nil {
		p.Machine.Operator = *u.Operator
	}
	if u.Groups != nil {
		p.Machine.Groups = slices.Clone(*u.Groups)
		if p.Isolated() { // isolating a device ends its person's session there
			p.Person.Active = false
		}
	}
	if u.PersonApproved != nil {
		p.Person.Approved = *u.PersonApproved
	}
	if u.PersonAdmin != nil {
		p.Person.Admin = *u.PersonAdmin
	}
	if u.PersonOperator != nil {
		p.Person.Operator = *u.PersonOperator
	}
	if u.PersonGroups != nil {
		p.Person.Groups = slices.Clone(*u.PersonGroups)
	}
	if u.PersonActive != nil {
		p.Person.Active = *u.PersonActive
	}
	if u.PersonSince != nil { // a layer opened anew: its activity starts over
		p.Person.Since, p.Person.ActivityAt = *u.PersonSince, time.Time{}
	}
	if u.PersonActivityAt != nil && u.PersonActivityAt.After(p.Person.ActivityAt) {
		p.Person.ActivityAt = *u.PersonActivityAt
	}
	if u.PersonReports != nil {
		p.Person.Reports = *u.PersonReports
	}
	if u.BootID != nil {
		p.BootID = *u.BootID
	}
	if u.User != nil {
		p.User = *u.User
	}
	if u.UserName != nil {
		p.UserName = *u.UserName
	}
	if u.UserLogin != nil {
		p.UserLogin = *u.UserLogin
	}
	if u.ApprovedUntil != nil {
		p.ApprovedUntil = *u.ApprovedUntil
	}
	if u.LoginAt != nil {
		p.LoginAt = *u.LoginAt
	}
	if u.Suspended != nil {
		p.Suspended = *u.Suspended
		if p.Suspended {
			// Suspension withdraws the approval for good: resuming does not bring back the machine's
			// approval nor the person's open layer (an administrator approves, the person signs in).
			p.Machine.Approved, p.Person.Active = false, false
		}
	}
	if u.AuthorityDevice != nil {
		p.AuthorityDevice = *u.AuthorityDevice
	}
	if p.Machine.Groups == nil {
		p.Machine.Groups = []string{}
	}
	if p.Person.Groups == nil {
		p.Person.Groups = []string{}
	}
	p.derive()
}

// Token is a pending or used enrollment token. Only derived key material is stored, never the
// token secret itself.
type Token struct {
	ID           int64
	PublicKey    wgtypes.Key // temporary key derived from the token secret
	PresharedKey wgtypes.Key
	TempAddress  netip.Addr
	Groups       []string // pre-authorised for the enrolled peer
	Approve      bool
	Admin        bool
	CreatedAt    time.Time
	ExpiresAt    time.Time
	RedeemedAt   time.Time // zero while unused

	// Authority, if set, makes this the enrollment key of that authority: it is reused by every
	// device the authority admits, is never consumed, and a redemption must carry a Grant.
	Authority string
	// CreatedBy names who created the token (the admin device), for the record.
	CreatedBy string
	// Name, if set, is the name the enrolled device gets (reserved until then) instead of one made
	// from its host name. With Replace, a device that has the name when the token is redeemed is
	// deleted and the new one takes its place (name and address): re-enrolling a server.
	Name    string
	Replace bool
}

// Active reports whether the token can still be redeemed at now.
func (t Token) Active(now time.Time) bool {
	return t.RedeemedAt.IsZero() && now.Before(t.ExpiresAt)
}

// Policy lets the source group's devices open connections to the destination group's, which answer
// them (OneWay; false: an old policy both ways, which the control nodes split into one-way ones
// since 0.52 unless it requires posture checks). Ports limits
// what may be opened (canonical rules of package ports; empty: everything). Posture names the
// checks its source devices must pass (see PostureCheck).
type Policy struct {
	ID          int64
	Source      string
	Destination string
	Posture     []string
	OneWay      bool
	Ports       []string
}

// PostureCheck is a named set of requirements on a device's posture report: every flag that is set
// must hold, the device's system must be at least the version MinOS gives for it, and its security
// patch level at most MaxPatchAge days old (systems they do not name are not limited). A report
// older than MaxAge fails.
type PostureCheck struct {
	Name           string
	DiskEncryption bool
	Firewall       bool
	SecureBoot     bool
	Antimalware    bool
	MinOS          map[string]string
	MaxPatchAge    map[string]int
	MaxAge         time.Duration
	CreatedAt      time.Time
}

// PostureReport is a device's latest posture report and the result of its latest evaluation.
type PostureReport struct {
	PeerID int64
	// Facts is the report as the device sent it (JSON, cleaned up by the control node); nil: none.
	Facts      []byte
	ReportedAt time.Time
	// Results maps each check policies require of the device to "" (passed) or why it failed, as
	// last evaluated; the network map follows it. Nil: never evaluated.
	Results map[string]string
	// ResultsAt is when Results last changed (zero: never evaluated).
	ResultsAt time.Time
}

// SameResults reports whether two evaluations agree (nil and empty do).
func SameResults(a, b map[string]string) bool { return maps.Equal(a, b) }

// PeerUpdate changes selected fields of a peer; nil fields are left unchanged. Approved, Admin,
// Operator and Groups are the machine layer's; Person* the person layer's.
type PeerUpdate struct {
	Hostname *string // a new name, already checked (names.Check); it must be free
	Approved *bool
	Admin    *bool
	Operator *bool
	Groups   *[]string
	// The person layer: its rights, whether it is open, since when, the person's last traffic (only
	// ever moved forward) and whether the device reports it.
	PersonApproved   *bool
	PersonAdmin      *bool
	PersonOperator   *bool
	PersonGroups     *[]string
	PersonActive     *bool
	PersonSince      *time.Time
	PersonActivityAt *time.Time
	PersonReports    *bool
	BootID           *string
	User             *string
	UserName         *string
	UserLogin        *string
	ApprovedUntil    *time.Time
	LoginAt          *time.Time
	Suspended        *bool // true also withdraws the approval
	// AuthorityDevice records the home device of a membership admitted before credentials named it.
	AuthorityDevice *string
	// IfLoginAt makes the update conditional: it applies only if the peer's LoginAt is still this
	// (nobody signed in on it since), else ErrChanged.
	IfLoginAt *time.Time
	// IfPersonSince likewise: only if the person layer is still the one opened then (zero: closed).
	IfPersonSince *time.Time
}

// conflicts reports whether an update's conditions no longer hold for p.
func (u PeerUpdate) conflicts(p Peer) bool {
	if u.IfLoginAt != nil && !p.LoginAt.Equal(*u.IfLoginAt) {
		return true
	}
	if u.IfPersonSince != nil {
		since := time.Time{}
		if p.Person.Active {
			since = p.Person.Since
		}
		return !since.Equal(*u.IfPersonSince)
	}
	return false
}

// Route is a network behind a gateway device (api.Route).
type Route struct {
	Name     string
	Networks []netip.Prefix
	Via      string // the gateway device's name
	// Exit: all internet traffic of the devices that use it goes through the gateway (Networks is
	// empty); Default: devices allowed use it unless they turn it off.
	Exit      bool
	Default   bool
	CreatedAt time.Time
	CreatedBy string
}

// CheckIn is what the control plane keeps of a device's check-ins, to notice a copied identity:
// the rolling token (hashes only) it expects next and the last one it accepted, and a fingerprint of
// the machine (a salted hash the device reports).
type CheckIn struct {
	PeerID      int64
	Cur         string // hash of the token issued last, not presented yet
	Prev        string // hash of the token accepted last
	Fingerprint string
	Endpoint    string    // the device's endpoint at the last accepted check-in
	At          time.Time // the last accepted check-in
	// Suspected says why the identity was last suspected to be in use on another machine, and when.
	Suspected   string
	SuspectedAt time.Time
}

// HWKey is a device's hardware-held key (0.31): a P-256 key its TPM keeps, which signs its
// check-ins and certifies each new WireGuard key (package hwsig). The first key a device binds stays
// its key until an administrator releases it; another one for the same device is a copy.
type HWKey struct {
	PeerID    int64
	Kind      string // the hardware ("tpm")
	PublicKey string // PKIX DER, base64
	BoundAt   time.Time
	// SeenAt is the last check-in it signed. UnsignedSince is the first check-in without its
	// signature since then (zero: none): a copy that cannot sign, or the device's TPM failing.
	SeenAt        time.Time
	UnsignedSince time.Time
	// Rotate asks the device to change its WireGuard key at its next signed check-in; RotatedAt is
	// when it last did.
	Rotate    bool
	RotatedAt time.Time
}

// Approval is a sign-in approval: a device asks that a person approve, on another of their
// devices, a sign-in on it (a PAM service: the login screen, sudo). The approver picks the number
// the asking device shows among Choices.
type Approval struct {
	ID        string // random, unguessable
	Requester int64  // the asking device
	User      string // the person's identity provider subject
	Login     string // the account name as asked for
	Service   string
	Number    int
	Choices   []int // three numbers, Number among them
	CreatedAt time.Time
	ExpiresAt time.Time
	State     string // ApprovalPending, ApprovalApproved, ApprovalDenied, ApprovalExpired
	// AnsweredBy is the device that answered (zero: none); AnsweredAt when, or when it expired.
	AnsweredBy int64
	AnsweredAt time.Time
	// BootID is the asking device's boot (0.27): an approved sign-in that reopens its person layer
	// opens it for that boot.
	BootID string
}

const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalDenied   = "denied"
	ApprovalExpired  = "expired"
)

// Grant is what a verified authority credential admits a device with.
type Grant struct {
	Authority string
	Groups    []string // already prefixed with the authority's name
	UserName  string
	Hostname  string
	Until     time.Time
	// DeviceID is the device's identity at home (empty from older home networks): a device of the
	// authority with the same one is replaced. MaxDevices is the authority's limit (0: none).
	DeviceID   string
	MaxDevices int
}

// Authority is another network (a home network) allowed to admit its devices into this one with
// signed credentials (see package credential).
type Authority struct {
	Name      string
	PublicKey ed25519.PublicKey
	Groups    []string // groups the authority may assign, without prefix
	MaxTTL    time.Duration
	TokenID   int64 // the authority's reusable enrollment token
	CreatedAt time.Time
	// MaxDevices caps how many devices the authority may have here (0: no limit).
	MaxDevices int
	// Suspended authorities admit no device and renew no credential until resumed; their devices
	// lose their approval when suspended (they stay, and come back with their next credential).
	Suspended bool
}

// Link is a linked network, seen from the home network: the authority key this network signs
// credentials with, and the enrollment token the linked network issued for that authority.
type Link struct {
	Name       string
	PrivateKey ed25519.PrivateKey
	Token      string   // "" until the linked network's token has been imported
	Groups     []string // home groups whose devices may join the linked network
	Grant      []string // groups requested for them in the linked network
	TTL        time.Duration
	CreatedAt  time.Time
	// Posture names the checks a device must pass (with a recent report) to get a credential.
	Posture []string
}

// UISession is a session of the admin interface, kept by the hash of its secret (the browser's
// cookie; the secret itself is never stored). It belongs to one device and works only from it. It
// starts pending, showing Code on the page, and opens when that device approves the code with a
// call signed with its key.
type UISession struct {
	Hash     string
	PeerID   int64
	Code     string
	Browser  string // the page's User-Agent, shown when it is approved
	Approved bool
	// Person, for a session opened by signing in on the page (0.49): the identity provider's subject
	// of the person, who must stay signed in on the device in ento for it to last.
	Person    string
	CreatedAt time.Time
	ExpiresAt time.Time
	LastUsed  time.Time
}

// SSOToken is the refresh token an identity provider issued at a device's sign-in, kept so a control
// node can ask the provider every few minutes whether the user still has access (and with which
// groups). The store holds it encrypted by the control nodes, never in clear. Subject is the user it
// belongs to; NextCheck when it is due. Previous, when set, makes SetSSOToken conditional: the token
// is replaced only if the stored one is still Previous (else ErrChanged), so that a check that took
// a while cannot overwrite the token of a sign-in that happened meanwhile.
// SettingSSOTokenCanary is the setting that holds a value sealed with the control nodes' token key:
// a control node whose key does not open it refuses to start (it could read none of the tokens).
const SettingSSOTokenCanary = "sso_token_canary"

type SSOToken struct {
	PeerID    int64
	Subject   string
	Encrypted string
	NextCheck time.Time
	Previous  string
}

// SignInCode is an authorization code of the device sign-in provider (control/signin.go), kept by
// the hash of the code (the code itself is never stored) so that whichever control node the client
// redeems it at can: it names the device whose person it vouches for, and the person layer it was
// given in (PersonSince), which must still be open when it is redeemed.
type SignInCode struct {
	Hash        string
	PeerID      int64
	PersonSince time.Time
	ClientID    string
	RedirectURI string
	Nonce       string
	Challenge   string // PKCE S256 code challenge
	ExpiresAt   time.Time
}

// Store is implemented by every storage backend.
type Store interface {
	Close() error

	// Version returns the current state version.
	Version(ctx context.Context) (int64, error)

	// RegisterControlNode inserts or updates a control node by name. A new node gets the first free
	// control address; an existing node keeps its address.
	RegisterControlNode(ctx context.Context, n ControlNode) (ControlNode, error)
	// ControlNodeSeen records that a control node is running (its heartbeat): only LastSeen changes,
	// no device is told.
	ControlNodeSeen(ctx context.Context, name string, at time.Time) error
	ControlNodes(ctx context.Context) ([]ControlNode, error)

	// CreateToken stores a token and allocates its temporary address. A token with a name fails
	// with *NameTakenError if another token reserves the name, or a device has it (unless Replace).
	CreateToken(ctx context.Context, t Token) (Token, error)

	// Routes returns every route; AddRoute adds one (ErrExists if the name is taken); DeleteRoute
	// removes one (ErrNotFound). Routes change network maps: they bump the version.
	Routes(ctx context.Context) ([]Route, error)
	AddRoute(ctx context.Context, r Route) error
	DeleteRoute(ctx context.Context, name string) error

	// DNSRecords returns the names administrators gave addresses (internal DNS); AddDNSRecord adds
	// one (ErrExists if the name is taken), DeleteDNSRecord removes one (ErrNotFound). DNSForwards,
	// AddDNSForward and DeleteDNSForward do the same for zones forwarded to name servers. Both change
	// network maps: they bump the version.
	DNSRecords(ctx context.Context) ([]DNSRecord, error)
	AddDNSRecord(ctx context.Context, r DNSRecord) error
	DeleteDNSRecord(ctx context.Context, name string) error
	DNSForwards(ctx context.Context) ([]DNSForward, error)
	AddDNSForward(ctx context.Context, f DNSForward) error
	DeleteDNSForward(ctx context.Context, zone string) error

	// UpdatePolicy is how the network's devices take new releases (0.37); a network that never set
	// one updates automatically (Mode "auto"). SetUpdatePolicy replaces it (maps are sent again).
	UpdatePolicy(ctx context.Context) (UpdatePolicy, error)
	SetUpdatePolicy(ctx context.Context, p UpdatePolicy) error
	// ReleaseOffered records when the network first offered a release (the first call wins) and
	// returns that time: devices outside the policy's first group wait from it.
	ReleaseOffered(ctx context.Context, version string, at time.Time) (time.Time, error)

	// UpdateCheckIn reads a device's check-in record (found false: none yet) and stores what fn
	// returns, atomically with respect to other control nodes; fn's error leaves it unchanged.
	UpdateCheckIn(ctx context.Context, peerID int64, fn func(c CheckIn, found bool) (CheckIn, error)) (CheckIn, error)
	// DeleteCheckIn forgets a device's check-ins (its next one starts over).
	DeleteCheckIn(ctx context.Context, peerID int64) error
	// CheckIns returns every device's record.
	CheckIns(ctx context.Context) ([]CheckIn, error)

	// UpdateHWKey reads a device's hardware key (found false: none bound) and stores what fn
	// returns, atomically with respect to other control nodes; fn's error leaves it unchanged.
	UpdateHWKey(ctx context.Context, peerID int64, fn func(k HWKey, found bool) (HWKey, error)) (HWKey, error)
	// HWKey returns a device's hardware key (ErrNotFound: none bound). UpdateHWKey bumps the version
	// when it changes Rotate (the device's network map says so).
	HWKey(ctx context.Context, peerID int64) (HWKey, error)
	// DeleteHWKey releases a device's hardware key (ErrNotFound: none bound).
	DeleteHWKey(ctx context.Context, peerID int64) error
	// HWKeys returns every bound hardware key.
	HWKeys(ctx context.Context) ([]HWKey, error)
	// RotatePeerKey changes a device's WireGuard key from oldKey to newKey (ErrNotFound: its key is
	// not oldKey; ErrExists: newKey belongs to another device, a control node or a token), and in the
	// same transaction clears its hardware key's Rotate and sets RotatedAt. It changes network maps:
	// it bumps the version.
	RotatePeerKey(ctx context.Context, peerID int64, oldKey, newKey wgtypes.Key) error

	// CreateApproval stores a new pending sign-in approval.
	CreateApproval(ctx context.Context, a Approval) error
	// Approval returns one (ErrNotFound when there is none).
	Approval(ctx context.Context, id string) (Approval, error)
	// PendingApprovals returns the pending approvals of a person that have not expired at now.
	PendingApprovals(ctx context.Context, user string, now time.Time) ([]Approval, error)
	// AnyPendingApproval reports whether any approval is pending and unexpired (a cheap check for
	// waiting approvers).
	AnyPendingApproval(ctx context.Context, now time.Time) (bool, error)
	// FinishApproval ends a pending approval as state (approved, denied or expired), answered by a
	// device (zero for expired), at; ErrChanged when it is no longer pending.
	FinishApproval(ctx context.Context, id, state string, by int64, at time.Time) (Approval, error)
	// CountApprovals counts the approvals asked since a time by a device and for a person.
	CountApprovals(ctx context.Context, requester int64, user string, since time.Time) (byRequester, byUser int, err error)
	// DeleteApprovalsBefore removes approvals that ended or expired before t.
	DeleteApprovalsBefore(ctx context.Context, t time.Time) error
	// ActiveTokens lists tokens that can still be redeemed.
	ActiveTokens(ctx context.Context, now time.Time) ([]Token, error)
	// DeleteToken revokes an unused enrollment token; authorities' tokens go with their authority.
	DeleteToken(ctx context.Context, id int64) error
	// Redeem atomically consumes the active token holding tempAddress and enrolls a peer with key.
	// Authority tokens are not consumed and need a grant for that authority; other tokens must
	// be redeemed without one. The device is named by its token, else after hostname (the grant's
	// for authorities) with names.SelfPrefix (the authority's name) and the first free counter.
	// A grant replaces the authority's device with the same DeviceID (its address is reused), and
	// fails with *AuthorityFullError beyond the authority's MaxDevices.
	Redeem(ctx context.Context, tempAddress netip.Addr, key wgtypes.Key, hostname, os string, now time.Time, grant *Grant) (Peer, error)

	Peers(ctx context.Context) ([]Peer, error)
	PeerByAddress(ctx context.Context, a netip.Addr) (Peer, error)
	PeerByPublicKey(ctx context.Context, key wgtypes.Key) (Peer, error)
	// UpdatePeer fails with *NameTakenError when renaming to a name that is not free.
	UpdatePeer(ctx context.Context, id int64, u PeerUpdate) (Peer, error)
	DeletePeer(ctx context.Context, id int64) error
	// ObservePeer records that a control node saw the peer, possibly at a new endpoint. Only an
	// endpoint change increments the version.
	// It returns the endpoint recorded before, when this call changed it.
	ObservePeer(ctx context.Context, key wgtypes.Key, endpoint string, at time.Time) (previous string, changed bool, err error)

	// ExpirePeers withdraws the approval of peers whose ApprovedUntil has passed and returns how
	// many changed.
	ExpirePeers(ctx context.Context, now time.Time) (int, error)
	// RecordPersonActivity notes, without a new network map version (nothing in maps depends on it),
	// when a device's person last had traffic (moved forward only; zero: unchanged), that the device
	// reports it (reports), and its boot (bootID; "": unchanged).
	RecordPersonActivity(ctx context.Context, id int64, at time.Time, reports bool, bootID string) error
	// EndIdleSessions closes the person layer of devices whose person was idle for longer than idle
	// (PersonIdle), or whose layer opened longer ago than max (a zero duration disables that limit),
	// and returns those devices as they were. Their machine layer and binding stay.
	EndIdleSessions(ctx context.Context, now time.Time, idle, max time.Duration) ([]Peer, error)

	Policies(ctx context.Context) ([]Policy, error)
	// AddPolicy adds pol (its ID is ignored) and returns it with its ID, or the existing policy
	// between the same groups if there is one, unchanged. A posture check it names must exist
	// (*NoSuchCheckError), checked in the same transaction as DeletePostureCheck's use check, so
	// that no policy requires a check that is gone.
	AddPolicy(ctx context.Context, pol Policy) (Policy, error)
	DeletePolicy(ctx context.Context, id int64) error
	// SetPolicyPosture changes the checks a policy requires of its source devices (which must
	// exist, as for AddPolicy).
	SetPolicyPosture(ctx context.Context, id int64, posture []string) (Policy, error)
	// SetPolicyRules changes a policy's direction and ports.
	SetPolicyRules(ctx context.Context, id int64, oneWay bool, ports []string) (Policy, error)

	// Posture checks. AddPostureCheck fails with ErrExists when the name is taken;
	// DeletePostureCheck with *CheckInUseError while a policy or a link requires the check.
	PostureChecks(ctx context.Context) ([]PostureCheck, error)
	AddPostureCheck(ctx context.Context, c PostureCheck) (PostureCheck, error)
	DeletePostureCheck(ctx context.Context, name string) error
	// SetPostureReport records a device's report (ErrNotFound: no such device), unless its previous
	// report is less than minGap older (ErrTooSoon; minGap 0: no limit): the limit holds across
	// control nodes. It does
	// not change the version: only a different evaluation (SetPostureResults) does.
	SetPostureReport(ctx context.Context, peerID int64, facts []byte, at time.Time, minGap time.Duration) error
	// PostureReports returns the reports and evaluations of every device that has either.
	PostureReports(ctx context.Context) ([]PostureReport, error)
	// SetPostureResults records a device's evaluation if the stored one is still previous (nil:
	// none), else it returns false (another control node got there first). The version changes, and
	// ResultsAt is set, when the evaluation does. Deleting a device deletes its report and evaluation.
	SetPostureResults(ctx context.Context, peerID int64, previous, results map[string]string) (bool, error)

	// CreateAuthority stores an authority together with its enrollment token (whose temporary
	// address is allocated here).
	CreateAuthority(ctx context.Context, a Authority, t Token) (Authority, Token, error)
	Authorities(ctx context.Context) ([]Authority, error)
	Authority(ctx context.Context, name string) (Authority, error)
	// DeleteAuthority removes an authority, its enrollment token and every peer it admitted.
	DeleteAuthority(ctx context.Context, name string) error
	// SuspendAuthority suspends (withdrawing the approval of every device it admitted) or resumes it.
	SuspendAuthority(ctx context.Context, name string, suspended bool) error
	// SetAuthorityLimit changes how many devices an authority may have (0: no limit). Devices it
	// already has stay.
	SetAuthorityLimit(ctx context.Context, name string, maxDevices int) error
	// RotateAuthorityToken gives an authority the enrollment token t (its temporary address is
	// allocated here) in place of its current one, which stops working.
	RotateAuthorityToken(ctx context.Context, name string, t Token) (Token, error)

	// CreateLink fails with ErrExists when the name is taken, and with *NoSuchCheckError when a
	// posture check it requires does not exist (checked as for AddPolicy).
	CreateLink(ctx context.Context, l Link) (Link, error)
	Links(ctx context.Context) ([]Link, error)
	Link(ctx context.Context, name string) (Link, error)
	// SetLinkToken changes the token only: a link's other fields stay as they are (also those an
	// older control node does not know).
	SetLinkToken(ctx context.Context, name, token string) error
	// SetLinkPosture changes the checks a link requires (which must exist, as for CreateLink). A
	// change forgets the devices' recorded results for the link (SwapLinkPosture).
	SetLinkPosture(ctx context.Context, name string, posture []string) (Link, error)
	// SwapLinkPosture records how a device does on a link's checks ("": passes, else what it fails,
	// opaque to the store)
	// and returns what was recorded before ("" when nothing was): atomically, whichever control node
	// asks, so that each change is audited once. Recording a failure for a link or a device that is
	// gone fails with ErrNotFound.
	SwapLinkPosture(ctx context.Context, link string, peerID int64, failing string) (previous string, err error)
	// DeleteLink also forgets the devices' keys in that network, and their results for its checks.
	DeleteLink(ctx context.Context, name string) error
	// LinkKey returns the one key a device holds in a linked network (ErrNotFound: none yet);
	// SetLinkKey records it, replacing the previous one.
	LinkKey(ctx context.Context, link string, peerID int64) (wgtypes.Key, error)
	SetLinkKey(ctx context.Context, link string, peerID int64, key wgtypes.Key) error

	// Refresh tokens of signed-in devices. SetSSOToken replaces the device's; ClaimSSOTokens returns
	// up to limit tokens due at now and moves their next check to next in the same step, so that of
	// several control nodes only one checks each device; deleting a device deletes its token.
	SetSSOToken(ctx context.Context, t SSOToken) error
	ClaimSSOTokens(ctx context.Context, now, next time.Time, limit int) ([]SSOToken, error)
	// DeleteSSOToken forgets the device's token; with a token other than "", only if it is still that
	// one (else ErrChanged).
	DeleteSSOToken(ctx context.Context, peerID int64, token string) error
	// ForgetSSOTokens forgets every device's token, and the token key's canary
	// (SettingSSOTokenCanary), and returns the devices whose tokens they were.
	ForgetSSOTokens(ctx context.Context) ([]int64, error)
	// KeepSetting stores value under key unless the key has one, and returns the stored value: the
	// first control node to ask sets it, every later one learns it.
	KeepSetting(ctx context.Context, key, value string) (string, error)

	// Sessions of the admin interface. CreateUISession fails with ErrExists when the hash, or the
	// code among the device's pending sessions, is taken. UISession returns an unexpired session;
	// PendingUISessions counts a device's unexpired pending ones. ApproveUISession opens the
	// device's unexpired pending session showing code until expires (ErrNotFound: none).
	// TouchUISession records its use. Deleting a device also deletes its sessions.
	CreateUISession(ctx context.Context, s UISession) error
	UISession(ctx context.Context, hash string, now time.Time) (UISession, error)
	PendingUISessions(ctx context.Context, peerID int64, now time.Time) (int, error)
	ApproveUISession(ctx context.Context, peerID int64, code string, now, expires time.Time) (UISession, error)
	TouchUISession(ctx context.Context, hash string, now time.Time) error
	DeleteUISession(ctx context.Context, hash string) error
	// DeleteUISessionsOf ends every session of a device (it lost its rights).
	DeleteUISessionsOf(ctx context.Context, peerID int64) error
	ExpireUISessions(ctx context.Context, now time.Time) error

	// The device sign-in provider (control/signin.go). CreateSignInCode stores a code (ErrExists:
	// its hash is taken); TakeSignInCode returns an unexpired code and deletes it, so it is used once
	// (ErrNotFound: unknown, expired or already used). LastSignIn returns when the device's person
	// layer that opened at since last signed someone in (zero: never); RecordSignIn sets it.
	// Deleting a device also deletes its codes and record.
	CreateSignInCode(ctx context.Context, c SignInCode) error
	TakeSignInCode(ctx context.Context, hash string, now time.Time) (SignInCode, error)
	ExpireSignInCodes(ctx context.Context, now time.Time) error
	LastSignIn(ctx context.Context, peerID int64, since time.Time) (time.Time, error)
	RecordSignIn(ctx context.Context, peerID int64, since, at time.Time) error
}

// DNSRecord is a name in the network's domain (relative to it, e.g. "nas.office") and its address.
type DNSRecord struct {
	Name      string
	Address   netip.Addr
	CreatedAt time.Time
	CreatedBy string
}

// DNSForward is a zone (e.g. "corp.example.com") whose names devices ask the zone's name servers.
type DNSForward struct {
	Zone      string
	Servers   []netip.Addr
	CreatedAt time.Time
	CreatedBy string
}

// UpdatePolicy: see api.UpdatesPolicy.
type UpdatePolicy struct {
	Mode       string // auto, approve, off
	Approved   string
	FirstGroup string
	FirstHours int
	SetBy      string
	SetAt      time.Time
}

// PersonIdle reports whether a device's open person layer has ended at now: nothing of the person
// crossed the tunnel for longer than idle (by the device's reports; a device whose agent does not
// report them is judged by when a control node last saw it, as before 0.27), or it opened longer ago
// than max. Zero durations disable a limit.
func PersonIdle(p Peer, now time.Time, idle, max time.Duration) bool {
	if !p.Person.Active || p.User == "" {
		return false
	}
	if max > 0 && now.Sub(p.Person.Since) > max {
		return true
	}
	if idle <= 0 {
		return false
	}
	last := p.Person.Since
	if p.Person.ActivityAt.After(last) {
		last = p.Person.ActivityAt
	}
	if !p.Person.Reports && p.LastSeen.After(last) {
		last = p.LastSeen
	}
	return now.Sub(last) > idle
}
