// Package api defines the JSON messages exchanged between agents, administrators and control
// nodes. All of it travels inside WireGuard; callers are identified by their overlay address, and
// calls that act with a device's rights are also signed with its key (package reqsig).
package api

// Paths of the control API (served on every control node's overlay address, port 80).
const (
	PathRedeem = "/v1/redeem"
	PathNetMap = "/v1/netmap"
	PathTokens = "/v1/admin/tokens"
	// PathApprovals: sign-in approvals. POST asks one (ApprovalRequest → ApprovalResponse); GET
	// lists those waiting for this device's person ([]PendingApproval, ?wait=SECONDS); GET .../{id}
	// is the asking device's view (ApprovalStatus, ?wait=); POST .../{id} answers (ApprovalAnswer).
	PathApprovals = "/v1/approvals"
	// PathRoutes: routes to networks behind gateway devices (Route), admins only.
	PathRoutes = "/v1/admin/routes"
	// PathDNS lists the internal DNS (DNSAdmin); PathDNSRecords and PathDNSForwards add (POST) and
	// delete (DELETE .../NAME) its names and forwarded zones (0.26).
	PathDNS         = "/v1/admin/dns"
	PathDNSRecords  = "/v1/admin/dns/records"
	PathDNSForwards = "/v1/admin/dns/forwards"
	// PathCheckIn: a device's check-in (CheckInRequest → CheckInResponse), signed with its key.
	PathCheckIn = "/v1/checkin"
	// PathLogout: the device's person signs out (LogoutRequest), signed with its key (0.27).
	PathLogout = "/v1/logout"
	// PathLeave: a membership admitted through a linked network leaves it (deleted), signed with its
	// key (0.28).
	PathLeave = "/v1/leave"
	// PathCredentialEnd: a membership admitted through a linked network ends its approval now
	// (no body), signed with its key (0.35.1): its home network refused to renew its credential.
	// A credential renews it again.
	PathCredentialEnd = "/v1/credential/end"
	// PathHWKey binds the device's hardware-held key (HWKeyRequest), signed with its WireGuard key
	// (0.31); PathRotate changes its WireGuard key (RotateRequest), certified by that hardware key.
	PathHWKey  = "/v1/hwkey"
	PathRotate = "/v1/rotate"
	// PathRecord returns the network record to publish at _ento.<domain> (NetworkRecordResponse).
	PathRecord = "/v1/admin/record"
	PathInfo   = "/v1/admin/info"
	PathPeers  = "/v1/admin/peers"
	// PathUserSuspension suspends or resumes every device of a user (SuspendUserRequest).
	PathUserSuspension = "/v1/admin/users/suspension"
	PathPolicies       = "/v1/admin/policies"
	PathLogin          = "/v1/login"
	ControlPort        = 80

	// Linked networks. In the linked network: authorities (admin) and credential renewal (devices
	// admitted by an authority). In the home network: links (admin) and credentials for its
	// devices (PathLinks + "/{name}/credential").
	PathAuthorities = "/v1/admin/authorities"
	PathCredential  = "/v1/credential"
	PathAdminLinks  = "/v1/admin/links"
	PathLinks       = "/v1/links"

	// PathAdminUI: GET describes the admin interface; POST approves a session of it that a
	// browser on the calling device shows the code of (signed calls of admin or operator devices).
	PathAdminUI = "/v1/admin/ui"

	// PathPosture: a device reports its posture (Posture, a call signed with its key) and gets the
	// checks it fails back (PostureResult).
	PathPosture = "/v1/posture"
	// PathPostureChecks: the network's posture checks (GET admins and operators; POST and
	// DELETE PathPostureChecks + "/{name}" admins only).
	PathPostureChecks = "/v1/admin/posture"

	// PathUpdate + "/{version}/{name}": the release a control node offers (NetMap.Update), its
	// manifest, the manifest's two signatures and its files, for enrolled devices (0.37). Devices
	// check them with the keys of their own binary, so the control node is not trusted for them.
	PathUpdate = "/v1/update"
	// PathAdminUpdates: how the network's devices take new releases (GET admins and operators:
	// UpdatesInfo; PUT admins: UpdatesPolicy).
	PathAdminUpdates = "/v1/admin/updates"
	// PathPeople: the people of the network's identity provider, managed through its API (0.40;
	// admins only; control nodes run with --people): GET lists them (PeopleList), POST adds one
	// (NewPersonRequest → NewPersonResult); PathPeople + "/{id}": GET one with its passkeys,
	// PATCH (UpdatePersonRequest), DELETE; + "/{id}/passkeys/{name}": DELETE; + "/{id}/setup":
	// POST makes a new setup link (SetupLink).
	PathPeople = "/v1/admin/people"
	// PathGroups: the network's groups where people are managed here (0.42; admins): POST makes one
	// in the identity provider (NewGroupRequest), DELETE PathGroups + "/{name}" removes one that
	// nothing uses.
	PathGroups = "/v1/admin/groups"
	// PathSignin: the sign-in policies (GET SigninPolicy; PUT SetSigninRequest), 0.46.
	PathSignin = "/v1/admin/signin"

	// RelayPort is the UDP port, on control nodes' and agents' overlay addresses, that carries
	// relayed WireGuard packets between peers that cannot reach each other directly.
	RelayPort = 3479
)

// Relay frames: one version byte, a 32-byte WireGuard public key, then the peer-to-peer WireGuard
// packet (still encrypted end to end). Agents send the destination's key; control nodes deliver
// the frame to the destination with the source's key.
const (
	RelayVersion   = 1
	RelayHeaderLen = 1 + 32
)

// Control describes a control node.
type Control struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Endpoint  string `json:"endpoint"`
	Address   string `json:"address"`
}

// RedeemRequest is sent by an agent, from its temporary address, to exchange a token for a peer.
type RedeemRequest struct {
	PublicKey string `json:"public_key"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	// Credential is required with an authority's token: it is signed by the authority for
	// PublicKey (see package credential).
	Credential string `json:"credential,omitempty"`
}

// RedeemResponse describes the new peer.
type RedeemResponse struct {
	Address  string    `json:"address"`
	Network  string    `json:"network"`
	Approved bool      `json:"approved"`
	Controls []Control `json:"controls"`
}

// NetMap is everything an agent needs to configure its interface.
type NetMap struct {
	Version  int64     `json:"version"`
	Network  string    `json:"network"`
	Self     Self      `json:"self"`
	Controls []Control `json:"controls"`
	Peers    []Peer    `json:"peers"`
	// Filter: each peer carries what it may open on this device (Peer.Accept), and the agent
	// refuses every other new connection from the network; answers to this device's own
	// connections, and the control nodes, always pass. Maps of older control nodes have no
	// filter: everything from a peer passes.
	Filter bool `json:"filter,omitempty"`
	// Hosts are names of the network's services (e.g. its identity provider) with their overlay
	// addresses, for devices that have no DNS for this network (linked networks).
	Hosts []Host `json:"hosts,omitempty"`
	// LinkForwards are services of this network that its devices make reachable inside the
	// namespaces of the networks they are linked to: a connection to Name:Port there is carried
	// by the device, from its own address in this network, to one of Targets.
	LinkForwards []Forward `json:"link_forwards,omitempty"`
	// DNS is the network's internal DNS (0.26), when its control nodes have a domain: the names
	// this device may resolve, and the zones it asks other name servers.
	DNS *DNSConfig `json:"dns,omitempty"`
	// RecordDomain (0.29) is the domain whose network record (TXT _ento.<domain>, the one words
	// enroll with) names the control nodes: a device that reaches none of them looks there for
	// where they moved (new endpoints for the keys it knows; never other keys).
	RecordDomain string `json:"record_domain,omitempty"`
	// Approvals (0.34): Self.PendingApprovals is filled (the request asked with ?approvals=N and
	// the control node knows it); without it the device asks for approvals itself.
	Approvals bool `json:"approvals,omitempty"`
	// Update (0.37) is the release this device should run, when its network's update policy offers
	// it one: the agent fetches it from PathUpdate and installs it only if its own keys verify it
	// and it is newer than itself.
	Update *Update `json:"update,omitempty"`
}

// Update is a release offered to a device.
type Update struct {
	Version string `json:"version"`
}

// UpdatesPolicy is how a network's devices take new releases (0.37): "auto" (each release its
// control nodes run, once they verified it), "approve" (only Approved), "off". FirstGroup's
// devices are offered a release at once, the others FirstHours after the network first offered it.
type UpdatesPolicy struct {
	Mode       string `json:"mode"`
	Approved   string `json:"approved,omitempty"`
	FirstGroup string `json:"first_group,omitempty"`
	FirstHours int    `json:"first_hours,omitempty"`
	SetBy      string `json:"set_by,omitempty"`
	SetAt      string `json:"set_at,omitempty"`
}

// UpdatesInfo is the network's update state: its policy, the release its control node offers
// (none while it is not verified or the node runs a development build), and each device's version.
type UpdatesInfo struct {
	Policy    UpdatesPolicy   `json:"policy"`
	Release   string          `json:"release,omitempty"`
	OfferedAt string          `json:"offered_at,omitempty"`
	Except    string          `json:"except,omitempty"` // the group never offered one (members)
	Problem   string          `json:"problem,omitempty"`
	Devices   []DeviceVersion `json:"devices"`
}

// DeviceVersion is a device's agent version, from its last posture report.
type DeviceVersion struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	OS       string `json:"os,omitempty"`
	Version  string `json:"version,omitempty"`
	Offered  bool   `json:"offered,omitempty"`  // its map offers it the release now
	Excluded bool   `json:"excluded,omitempty"` // in the group never offered one
}

// DNSConfig is a network's internal DNS as a device sees it.
type DNSConfig struct {
	Domain   string       `json:"domain"`             // e.g. "example.internal"; "" for none
	Records  []Host       `json:"records,omitempty"`  // names relative to Domain: devices and administrators' names
	Forwards []DNSForward `json:"forwards,omitempty"` // zones asked of their name servers
	// Fixed (0.30.1) are full names answered with these addresses (one entry per address) by the
	// device's resolver itself, on every enrolled device, approved or not: the identity provider's
	// name and the admin interface's, which the control nodes serve on their overlay addresses. DNS
	// that drops answers pointing at private or shared addresses (rebinding protection: routers,
	// filtering resolvers) would otherwise keep a device from signing in.
	Fixed []Host `json:"fixed,omitempty"`
}

// DNSAdmin is a network's internal DNS as administrators see it ("" domain: none).
type DNSAdmin struct {
	Domain   string       `json:"domain"`
	Records  []DNSRecord  `json:"records"`
	Forwards []DNSForward `json:"forwards"`
}

// DNSRecord is a name administrators gave an address in the network's domain (relative to it).
type DNSRecord struct {
	Name      string   `json:"name"`
	Address   string   `json:"address"`
	CreatedAt string   `json:"created_at,omitempty"`
	CreatedBy string   `json:"created_by,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// DNSForward is a zone whose names devices ask its name servers (IPv4 addresses).
type DNSForward struct {
	Zone      string   `json:"zone"`
	Servers   []string `json:"servers"`
	CreatedAt string   `json:"created_at,omitempty"`
	CreatedBy string   `json:"created_by,omitempty"`
}

// Forward is a service of a network made reachable inside linked networks' namespaces.
type Forward struct {
	Name    string   `json:"name"`
	Port    int      `json:"port"`
	Targets []string `json:"targets"` // address:port in the network, tried in order
}

// Host is a service name of the network and one of its addresses.
type Host struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// Self describes the requesting peer.
type Self struct {
	Address  string   `json:"address"`
	Hostname string   `json:"hostname"`
	Approved bool     `json:"approved"`
	Admin    bool     `json:"admin"`
	Operator bool     `json:"operator,omitempty"`
	Groups   []string `json:"groups"`
	// Routes are the networks this device serves as a gateway (routes whose gateway it is): it
	// forwards to them what its peers may open there (Peer.RouteAccept).
	Routes []string `json:"routes,omitempty"`
	// Exit: this device is an exit (it forwards its peers' internet traffic, and answers their DNS).
	Exit bool `json:"exit,omitempty"`
	// RotateKey asks a device with a bound hardware key to change its WireGuard key now (0.31), as
	// CheckInResponse.RotateKey does: the map reaches the device sooner when a copy of it competes
	// for its WireGuard session.
	RotateKey bool `json:"rotate_key,omitempty"`
	// User is the identity provider's username (preferred_username) of the person the device is
	// bound to by single sign-on, and UserName their readable name (e-mail); empty when none.
	User     string `json:"user,omitempty"`
	UserName string `json:"user_name,omitempty"`
	// LoginRequired: the person's rights on this device return only with `ento agent login` (their
	// layer is closed and an approved sign-in on the device no longer reopens it, or the identity
	// provider withdrew them).
	LoginRequired bool `json:"login_required,omitempty"`
	// PersonActive: the person layer is open (since PersonSince, RFC 3339): the person's rights are
	// part of the device's (0.27). Their traffic keeps it open: the device counts what it sends
	// that its machine layer alone would not (Peer.Machine, Peer.RouteMachine, ExitOffer.Machine)
	// and says when it last did in its check-ins.
	PersonActive bool   `json:"person_active,omitempty"`
	PersonSince  string `json:"person_since,omitempty"`
	// Suspended: an administrator suspended the device; nothing but resuming it restores access.
	Suspended bool `json:"suspended,omitempty"`
	// PostureFailing lists the posture checks that policies require of the device and that it
	// fails: while it does, those policies leave it out.
	PostureFailing []PostureFailure `json:"posture_failing,omitempty"`
	// PendingApprovals (0.34, asked for with ?approvals=N) is how many sign-in approvals wait for
	// this device's person to answer on it; the map is sent early when it differs from N, so a
	// phone needs no poll of its own for them. See NetMap.Approvals.
	PendingApprovals int `json:"pending_approvals,omitempty"`
}

// Peer is another peer the agent may reach.
type Peer struct {
	PublicKey string   `json:"public_key"`
	Address   string   `json:"address"`
	Hostname  string   `json:"hostname"`
	Endpoints []string `json:"endpoints"`
	// Accept is what this peer may open on the device, as port rules (package ports: "all",
	// "tcp/22", "udp/53", "icmp", ...); with NetMap.Filter, empty means nothing (the peer only
	// answers the device's connections).
	Accept []string `json:"accept,omitempty"`
	// Quiet (0.34): the peer runs on a battery whose radio wakes for every packet (a phone): send
	// it no keepalives, and do not take its silence for a failed direct path.
	Quiet bool `json:"quiet,omitempty"`
	// Routes are networks (CIDR) the device reaches through this peer, a gateway (0.24).
	Routes []string `json:"routes,omitempty"`
	// Exits are the exits this peer is the gateway of that the device may use: send all its
	// internet traffic through it (0.25).
	Exits []ExitOffer `json:"exits,omitempty"`
	// With Self.PersonActive: Machine is what the device's machine layer alone may open on this peer
	// (port rules; empty: nothing), RouteMachine the same per network reached through it.
	Machine      []string    `json:"machine,omitempty"`
	RouteMachine []RouteRule `json:"route_machine,omitempty"`
	// RouteAccept is what this peer may open, through the device as its gateway, in the networks
	// the device serves (Self.Routes).
	RouteAccept []RouteRule `json:"route_accept,omitempty"`
}

// CreateTokenRequest asks for a new enrollment token (admin only).
type CreateTokenRequest struct {
	Groups     []string `json:"groups"`
	Approve    bool     `json:"approve"`
	Admin      bool     `json:"admin"`
	TTLSeconds int      `json:"ttl_seconds"`
	// Name, if set, is the enrolled device's name (reserved until then) instead of one made from its
	// host name. Replace lets it take over from a device that has the name when it enrolls.
	Name    string `json:"name,omitempty"`
	Replace bool   `json:"replace,omitempty"`
	// Words asks for the token as words to read out (at most a day): the device joins with them and
	// the network record of a domain (`ento agent install --join DOMAIN`).
	Words bool `json:"words,omitempty"`
	// QRDomain (with Words, 0.30) asks for the words as a QR code too, for phones to scan: the
	// domain whose network record names this network (empty: the control nodes' --record-domain,
	// if they have one).
	QRDomain string `json:"qr_domain,omitempty"`
}

// CreateTokenResponse carries the token, or its words. It is shown once and never stored.
type CreateTokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	// Words (a words token): the words, separated by spaces, and the fingerprint of the network
	// the device's record must show.
	Words       string `json:"words,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// JoinCode (asked with QRDomain, or a record domain) is the domain, the fingerprint and the
	// words as one text (token.JoinCode), and QRSVG the same as a QR code (an SVG image).
	JoinCode string `json:"join_code,omitempty"`
	QRSVG    string `json:"qr_svg,omitempty"`
}

// NetworkRecordResponse is the network record (the TXT record at _ento.<domain> for enrollment
// by words) and its fingerprint.
type NetworkRecordResponse struct {
	Record      string `json:"record"`
	Fingerprint string `json:"fingerprint"`
}

// TokenInfo is the administrative view of an enrollment token that can still be used; the token
// itself is never stored and cannot be shown again.
type TokenInfo struct {
	ID        int64    `json:"id"`
	Groups    []string `json:"groups"`
	Approve   bool     `json:"approve"`
	Admin     bool     `json:"admin"`
	CreatedAt string   `json:"created_at"`
	ExpiresAt string   `json:"expires_at"`
	CreatedBy string   `json:"created_by,omitempty"`
	// Authority is set for an authority's reusable token (revoked by removing the authority).
	Authority string `json:"authority,omitempty"`
	// Name is the name the enrolled device will get; Replace: it takes over from a device with it.
	Name    string `json:"name,omitempty"`
	Replace bool   `json:"replace,omitempty"`
}

// ControlInfo describes a control node for administrators.
type ControlInfo struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	Endpoint string `json:"endpoint"`
	LastSeen string `json:"last_seen"`
}

// AdminInfo is the overview of the network for administrators.
type AdminInfo struct {
	Network  string        `json:"network"`
	Node     string        `json:"node"`    // the control node answering
	Version  string        `json:"version"` // its software version
	Controls []ControlInfo `json:"controls"`
	Self     PeerInfo      `json:"self"` // the calling device
	SSO      bool          `json:"sso"`
	// People: administrators manage the identity provider's people here (PathPeople, 0.40).
	People bool `json:"people,omitempty"`
	// NoGateways: groups whose devices are never gateways (0.41).
	NoGateways []string `json:"no_gateways,omitempty"`
	// Viewer: the calling device may only look (0.43).
	Viewer bool `json:"viewer,omitempty"`
	// PersonRoles: the people groups that give a person each role (0.46.1): admin, operator, viewer.
	PersonRoles map[string][]string `json:"person_roles,omitempty"`
}

// PeerInfo is the administrative view of a peer.
type PeerInfo struct {
	ID        int64  `json:"id"`
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
	// Hostname is the device's name in the network; ReportedHostname the host name it reported.
	Hostname         string `json:"hostname"`
	ReportedHostname string `json:"reported_hostname,omitempty"`
	OS               string `json:"os"`
	Approved         bool   `json:"approved"`
	Admin            bool   `json:"admin"`
	// Operator devices administer within limits: ordinary devices, ordinary tokens, policies.
	Operator  bool     `json:"operator,omitempty"`
	Groups    []string `json:"groups"`
	Endpoint  string   `json:"endpoint"`
	User      string   `json:"user,omitempty"`
	LastSeen  string   `json:"last_seen,omitempty"`
	Authority string   `json:"authority,omitempty"`
	// ApprovedUntil is set for devices admitted by an authority.
	ApprovedUntil string `json:"approved_until,omitempty"`
	Suspended     bool   `json:"suspended,omitempty"`
	// CheckedInAt is the device's last accepted check-in (none: an agent older than 0.23, or not
	// since it was resumed); CloneSuspected says why its identity was last suspected to be in use on
	// another machine, at CloneSuspectedAt.
	CheckedInAt      string `json:"checked_in_at,omitempty"`
	CloneSuspected   string `json:"clone_suspected,omitempty"`
	CloneSuspectedAt string `json:"clone_suspected_at,omitempty"`
	// HardwareKey names the hardware that holds the device's bound key ("tpm"; none: not bound,
	// 0.31), HardwareKeyAt when it last signed a check-in, KeyRotatedAt when the device last changed
	// its WireGuard key.
	HardwareKey   string `json:"hardware_key,omitempty"`
	HardwareKeyAt string `json:"hardware_key_at,omitempty"`
	KeyRotatedAt  string `json:"key_rotated_at,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	LoginAt       string `json:"login_at,omitempty"`
	// The layers (0.27): the machine's (given by its token or an administrator) and the person's
	// (from their sign-in), and whether the person's is open, since when, their last traffic.
	MachineApproved  bool     `json:"machine_approved,omitempty"`
	MachineGroups    []string `json:"machine_groups,omitempty"`
	PersonApproved   bool     `json:"person_approved,omitempty"`
	PersonGroups     []string `json:"person_groups,omitempty"`
	PersonRole       string   `json:"person_role,omitempty"` // admin, operator or ""
	PersonActive     bool     `json:"person_active,omitempty"`
	PersonSince      string   `json:"person_since,omitempty"`
	PersonActivityAt string   `json:"person_activity_at,omitempty"`
	// Posture is the device's latest report (none yet: nil), received at PostureReportedAt.
	Posture           *Posture `json:"posture,omitempty"`
	PostureReportedAt string   `json:"posture_reported_at,omitempty"`
	// PostureChecks is how the device does on every check of the network, now.
	PostureChecks []PostureCheckResult `json:"posture_checks,omitempty"`
}

// UpdatePeerRequest changes selected fields of a peer (admins; operators only on devices that are
// neither admins nor operators, and never Admin or Operator).
type UpdatePeerRequest struct {
	// Hostname renames the device; UseReportedHostname instead names it after the host name it
	// reported (without the prefix of devices that named themselves).
	Hostname            *string   `json:"hostname,omitempty"`
	UseReportedHostname bool      `json:"use_reported_hostname,omitempty"`
	Approved            *bool     `json:"approved,omitempty"`
	Admin               *bool     `json:"admin,omitempty"`
	Operator            *bool     `json:"operator,omitempty"`
	Groups              *[]string `json:"groups,omitempty"`
	// Suspended true withdraws the approval until resumed (false); no sign-in restores it.
	Suspended *bool `json:"suspended,omitempty"`
	// SignOut closes the device's person layer (0.27): its person's rights end until they sign in
	// again; Approved, Admin, Operator and Groups are the machine layer's.
	SignOut bool `json:"sign_out,omitempty"`
	// UnbindHardwareKey releases the device's hardware key binding (0.31; admins only): its next
	// hardware key binds instead, e.g. after its TPM was cleared or replaced.
	UnbindHardwareKey bool `json:"unbind_hardware_key,omitempty"`
}

// SuspendUserRequest suspends (Suspended true) or resumes every device a user signed in on. User is
// their name as devices show it (PeerInfo.UserName) or their identity provider's subject.
type SuspendUserRequest struct {
	User      string `json:"user"`
	Suspended bool   `json:"suspended"`
}

// SuspendUserResult lists the devices changed and those left as they were, with why.
type SuspendUserResult struct {
	User    string          `json:"user"`
	Changed []PeerInfo      `json:"changed"`
	Skipped []SkippedDevice `json:"skipped"`
}

type SkippedDevice struct {
	ID       int64  `json:"id"`
	Hostname string `json:"hostname"`
	Reason   string `json:"reason"`
}

// Policy allows traffic between two groups ("*" matches every approved peer). Posture names checks
// its source devices must pass: one that fails any of them is left out of the policy (admins only
// set them).
type Policy struct {
	ID          int64    `json:"id"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Posture     []string `json:"posture,omitempty"`
	// OneWay: only the source opens connections (the destination answers them). Every policy is
	// one way since 0.52 (asked for or not); false is an old one both ways that requires posture
	// checks, kept until an admin replaces it. Ports limits what may be opened ("tcp/22", "tcp/8000-8100", "udp/53", "icmp"; empty:
	// everything). Enforced by the receiving device's agent (0.19 and later).
	OneWay bool     `json:"one_way,omitempty"`
	Ports  []string `json:"ports,omitempty"`
	// Warnings, in answers to adding or changing a policy: other policies that let some of the
	// same devices through without the checks one of them requires.
	Warnings []string `json:"warnings,omitempty"`
}

// UpdatePolicyRequest changes the posture checks a policy requires (admins only), at PathPolicies +
// "/{id}" (PATCH). An empty list requires none.
type UpdatePolicyRequest struct {
	Posture []string `json:"posture"`
}

// PolicyRulesRequest sets a policy's ports, at PathPolicies + "/{id}/rules" (PUT); the policy is
// one way afterwards, whatever OneWay says (0.52).
type PolicyRulesRequest struct {
	OneWay bool     `json:"one_way"`
	Ports  []string `json:"ports"`
}

// PostureFormat is the version of the Posture document agents send.
const PostureFormat = 1

// Posture is what a device reports about itself. A fact that is nil (or a version that is empty)
// is unknown: the device could not find out, and a check that needs it fails.
type Posture struct {
	Format int    `json:"format"`
	OS     string `json:"os"` // linux, darwin, windows, android
	// OSVersion is what checks compare (numerically, part by part): the kernel release on Linux,
	// the product version on macOS ("14.5"), major.minor.build.revision on Windows
	// ("10.0.26100.2033"), the release on Android ("14").
	OSVersion string `json:"os_version,omitempty"`
	// Distribution describes the system further, for people: "debian 12" (Linux), "SDK 34"
	// (Android).
	Distribution   string `json:"distribution,omitempty"`
	Agent          string `json:"agent,omitempty"`
	DiskEncryption *bool  `json:"disk_encryption,omitempty"`
	Firewall       *bool  `json:"firewall,omitempty"`
	SecureBoot     *bool  `json:"secure_boot,omitempty"`
	ScreenLock     *bool  `json:"screen_lock,omitempty"`
	// Antimalware: real-time anti-malware protection is on (Windows: an antivirus registered with
	// Windows Security, or Microsoft Defender, with real-time protection; macOS: XProtect present;
	// Linux: a known real-time scanner running; unknown when none is found there).
	Antimalware *bool `json:"antimalware,omitempty"`
	// PatchLevel is the system's security patch level, "2026-09-05" or "2026-09" (Android, 0.30).
	// On Android it is the attested one when the attestation counts (see Attested).
	PatchLevel string `json:"patch_level,omitempty"`
	// Attestation is what the device's secure hardware gives about it (Android, 0.30): sent by
	// the device, verified by the control node, never stored.
	Attestation *Attestation `json:"attestation,omitempty"`
	// Attested is what the control node found in the attestation (nil: none sent), never what the
	// device says. On Android, SecureBoot is set from it alone: true when the hardware attests a
	// verified boot (the system its maker signed) with the bootloader locked, false when it attests
	// otherwise, unknown without an attestation that counts.
	Attested *Attested `json:"attested,omitempty"`
}

// Attestation is evidence from a device's secure hardware, sent with a posture report: for
// Android key attestation (Format "android-key"), the certificate chain (DER, leaf first, ending
// with the root) of a key the phone's Keystore made in its secure hardware, for the challenge
// attest.Challenge of the device's WireGuard key, and the key's signature (ECDSA P-256, SHA-256,
// ASN.1) of attest.Message(device key, SignedAt), made for this report.
type Attestation struct {
	Format    string   `json:"format"`
	Chain     [][]byte `json:"chain"`
	SignedAt  string   `json:"signed_at"`
	Signature []byte   `json:"signature"`
}

// Attested is what a device's attestation shows, as the control node verified it. Error says why
// it does not count ("" when it does); nothing else is set then.
type Attested struct {
	Error string `json:"error,omitempty"`
	// SecurityLevel is where the key lives: "tee" (trusted execution environment) or "strongbox".
	SecurityLevel string `json:"security_level,omitempty"`
	// BootState is Android Verified Boot's: "verified" (the system its maker signed), "self-signed"
	// (a system signed with a key its owner set, e.g. a custom OS), "unverified" (bootloader
	// unlocked: anything) or "failed". Locked: the bootloader is locked. BootKey: the verified boot
	// key's digest (hex).
	BootState string `json:"boot_state,omitempty"`
	Locked    bool   `json:"locked,omitempty"`
	BootKey   string `json:"boot_key,omitempty"`
	// OSVersion ("14.0.0") and the patch levels of the system, the vendor image and the boot image
	// ("2026-09" or "2026-09-05"), each when the hardware knows it.
	OSVersion        string `json:"os_version,omitempty"`
	PatchLevel       string `json:"patch_level,omitempty"`
	VendorPatchLevel string `json:"vendor_patch_level,omitempty"`
	BootPatchLevel   string `json:"boot_patch_level,omitempty"`
	// App is the package that asked for the key, AppSigner its signing certificate's SHA-256 (hex).
	App       string `json:"app,omitempty"`
	AppSigner string `json:"app_signer,omitempty"`
}

// PostureResult answers a posture report: the checks the device fails now (see
// Self.PostureFailing).
type PostureResult struct {
	Failing []PostureFailure `json:"failing"`
	// Attested is what the control node found in the report's attestation (0.30; nil: none).
	Attested *Attested `json:"attested,omitempty"`
}

// PostureFailure is a check a device fails, and why ("disk not encrypted", "no report in 30m0s").
type PostureFailure struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

// PostureCheck is a named set of requirements a policy can ask of its source devices. Every
// requirement set must hold; MinOS gives, per system (linux, darwin, windows, android), the oldest
// version accepted (systems it does not name are not limited). SecureBoot on Android is a verified
// boot with the bootloader locked, as the phone's secure hardware attests it. MaxPatchAgeDays gives,
// per system (android), how many days old the security patch level may be: the oldest of the
// attested system, vendor and boot patch levels, else the reported one (0.30). A device's report
// must be younger than MaxAgeSeconds (0: 30 minutes).
type PostureCheck struct {
	Name            string            `json:"name"`
	DiskEncryption  bool              `json:"disk_encryption,omitempty"`
	Firewall        bool              `json:"firewall,omitempty"`
	SecureBoot      bool              `json:"secure_boot,omitempty"`
	Antimalware     bool              `json:"antimalware,omitempty"`
	MinOS           map[string]string `json:"min_os,omitempty"`
	MaxPatchAgeDays map[string]int    `json:"max_patch_age_days,omitempty"`
	MaxAgeSeconds   int               `json:"max_age_seconds,omitempty"`
	CreatedAt       string            `json:"created_at,omitempty"`
}

// PostureCheckResult is how a device does on one check: Required when a policy asks it of the
// device (it is in the policy's source group).
type PostureCheckResult struct {
	Check    string `json:"check"`
	Passed   bool   `json:"passed"`
	Reason   string `json:"reason,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// LoginStart is returned when a device starts an SSO login (OAuth 2.0 device authorization grant).
// The user opens VerificationURI and types UserCode in a browser. VerificationURIComplete (the
// link with the code in it) stays empty since 0.50: control nodes no longer pass it on.
type LoginStart struct {
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	UserCode                string `json:"user_code"`
	ExpiresIn               int    `json:"expires_in"`
}

// LoginStatus reports the progress of a device's SSO login.
type LoginStatus struct {
	State    string `json:"state"` // "none", "pending", "done", "failed"
	User     string `json:"user,omitempty"`
	Approved bool   `json:"approved"`
	Error    string `json:"error,omitempty"`
}

// Error is the body of every non-2xx response. PostureFailing lists, when a link refuses a device
// a credential over its posture, the checks it fails.
type Error struct {
	Error          string           `json:"error"`
	PostureFailing []PostureFailure `json:"posture_failing,omitempty"`
}

// CreateAuthorityRequest registers another network as an authority (admin only, in the linked
// network). Its devices are admitted with the groups their credentials request, limited to Groups
// and prefixed with "<name>:", for at most MaxTTLSeconds per credential.
type CreateAuthorityRequest struct {
	Name          string   `json:"name"`
	PublicKey     string   `json:"public_key"` // "entoa1:..."
	Groups        []string `json:"groups"`
	MaxTTLSeconds int      `json:"max_ttl_seconds"`
	// MaxDevices caps how many devices the authority may have in this network (0: no limit).
	MaxDevices int `json:"max_devices,omitempty"`
}

// CreateAuthorityResponse carries the authority's reusable enrollment token. It is shown once;
// the home network imports it into its link.
type CreateAuthorityResponse struct {
	Token string `json:"token"`
}

// AuthorityInfo is the administrative view of an authority.
type AuthorityInfo struct {
	Name          string   `json:"name"`
	PublicKey     string   `json:"public_key"`
	Groups        []string `json:"groups"`
	MaxTTLSeconds int      `json:"max_ttl_seconds"`
	Devices       int      `json:"devices"`
	CreatedAt     string   `json:"created_at"`
	Suspended     bool     `json:"suspended,omitempty"`
	MaxDevices    int      `json:"max_devices,omitempty"`
}

// UpdateAuthorityRequest suspends an authority (it admits nothing, its devices lose their approval
// until it is resumed) or resumes it.
type UpdateAuthorityRequest struct {
	Suspended *bool `json:"suspended,omitempty"`
}

// AuthorityLimitRequest changes how many devices an authority may have (0: no limit), at
// PathAuthorities + "/{name}/limit" (PUT). A route of its own: control nodes older than 0.11
// answer it with an error instead of reading it as a resume.
type AuthorityLimitRequest struct {
	MaxDevices int `json:"max_devices"`
}

// RotateAuthorityTokenResponse carries an authority's new enrollment token, which replaces the
// previous one (it stops working at once; devices already admitted are not affected). The home
// network imports it into its link.
type RotateAuthorityTokenResponse struct {
	Token string `json:"token"`
}

// RenewCredentialRequest extends the approval of a device admitted by an authority.
type RenewCredentialRequest struct {
	Credential string `json:"credential"`
}

// RenewCredentialResponse reports the new approval.
type RenewCredentialResponse struct {
	ApprovedUntil string   `json:"approved_until"`
	Groups        []string `json:"groups"`
}

// CreateLinkRequest creates a link to another network (admin only, in the home network): an
// authority key is generated and devices in Groups may join the linked network, requesting Grant
// there, with credentials valid for TTLSeconds.
// Posture names checks a device must pass, with a recent report, to get a credential.
type CreateLinkRequest struct {
	Name       string   `json:"name"`
	Groups     []string `json:"groups"`
	Grant      []string `json:"grant"`
	TTLSeconds int      `json:"ttl_seconds"`
	Posture    []string `json:"posture,omitempty"`
}

// UpdateLinkRequest changes a link (admins only), at PathAdminLinks + "/{name}" (PATCH). Posture,
// when set, replaces the checks it requires (empty: none).
type UpdateLinkRequest struct {
	Posture *[]string `json:"posture,omitempty"`
}

// LinkInfo is the administrative view of a link. PublicKey is what the linked network registers.
type LinkInfo struct {
	Name       string   `json:"name"`
	PublicKey  string   `json:"public_key"`
	Groups     []string `json:"groups"`
	Grant      []string `json:"grant"`
	TTLSeconds int      `json:"ttl_seconds"`
	HasToken   bool     `json:"has_token"`
	CreatedAt  string   `json:"created_at"`
	// Network identifies the network the link leads to (links into one network share it), and
	// Controls are that network's control nodes, both from its token.
	Network  string   `json:"network,omitempty"`
	Controls []string `json:"controls,omitempty"`
	// Posture names the checks a device must pass to get a credential.
	Posture []string `json:"posture,omitempty"`
}

// SetLinkTokenRequest imports the enrollment token the linked network issued for this authority.
type SetLinkTokenRequest struct {
	Token string `json:"token"`
}

// LinkCredentialRequest asks the home network for a credential for this device's key in a linked
// network. A device holds one key per linked network: renewals must be for that key, and only
// joining (Join, a fresh membership) replaces it.
type LinkCredentialRequest struct {
	PublicKey string `json:"public_key"`
	Join      bool   `json:"join,omitempty"`
}

// LinkCredentialResponse carries a fresh credential, and to a device joining, the linked network's
// enrollment token.
type LinkCredentialResponse struct {
	Token      string `json:"token,omitempty"`
	Credential string `json:"credential"`
	ExpiresAt  string `json:"expires_at"`
}

// AdminUI describes the network's admin interface.
type AdminUI struct {
	URL string `json:"url"`
}

// ApproveAdminUIRequest opens the session of the admin interface whose page, in a browser on the
// calling device, shows Code.
type ApproveAdminUIRequest struct {
	Code string `json:"code"`
}

// ApprovedAdminUI describes the page whose session opened: when it asked for its code, and the
// browser it said it was (for the person approving to recognise their own).
type ApprovedAdminUI struct {
	URL      string `json:"url"`
	OpenedAt string `json:"opened_at"`
	Browser  string `json:"browser"`
}

// ApprovalRequest asks that a person approve, on another of their devices, a sign-in on this one.
type ApprovalRequest struct {
	// BootID identifies the asking device's current boot (0.27): an approved sign-in that reopens
	// the person layer opens it for this boot.
	BootID         string `json:"boot_id,omitempty"`
	User           string `json:"user"`    // the account name: the identity provider's username or e-mail
	Service        string `json:"service"` // what is being signed in to (a PAM service: gdm-password, sudo)
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// ApprovalResponse is the asking device's: the number to show, which the person picks on the
// approving device.
type ApprovalResponse struct {
	ID        string `json:"id"`
	Number    int    `json:"number"`
	ExpiresAt string `json:"expires_at"`
}

// ApprovalStatus is an approval's state: pending, approved, denied or expired.
type ApprovalStatus struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// PendingApproval is what an approving device shows: who asks to sign in where, and three numbers,
// one of which the asking device shows.
type PendingApproval struct {
	ID        string `json:"id"`
	Device    string `json:"device"`
	User      string `json:"user"`
	Service   string `json:"service"`
	Choices   []int  `json:"choices"`
	ExpiresAt string `json:"expires_at"`
}

// ApprovalAnswer is the approving device's answer: the number picked, and whether the person
// approves.
type ApprovalAnswer struct {
	Number  int  `json:"number"`
	Approve bool `json:"approve"`
}

// CheckInRequest is a device's check-in: the token the previous one handed out ("" the first time)
// and a fingerprint of the machine ("" where it cannot be read).
type CheckInRequest struct {
	Token       string `json:"token"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// PersonIdle is how many seconds ago the device last sent traffic of the person layer (-1: none
	// since its agent started; absent: an agent older than 0.27). BootID identifies the device's
	// current boot: a new one closes the person layer.
	PersonIdle *int64 `json:"person_idle,omitempty"`
	BootID     string `json:"boot_id,omitempty"`
	// HWSignature is the device's hardware key's signature of the check-in (hwsig.CheckInMessage of
	// its WireGuard key, Token and HWTime), from a device with a bound hardware key (0.31).
	HWSignature string `json:"hw_signature,omitempty"`
	HWTime      int64  `json:"hw_time,omitempty"`
	// FilterFailed says why the device's inbound filter could not be applied (0.51; up to 200
	// characters): until it can, its only peers are its control nodes, which audit it
	// (filter_failed) at each check-in.
	FilterFailed string `json:"filter_failed,omitempty"`
}

// HWKeyRequest binds a device's hardware-held key (0.31): its public key (PKIX DER, base64) and
// its signature of hwsig.BindMessage, which proves the device holds it. The first key a device
// binds is its key until an administrator releases it; another one is refused (a copy).
type HWKeyRequest struct {
	Kind      string `json:"kind"`
	PublicKey string `json:"public_key"`
	Time      int64  `json:"time"`
	Signature string `json:"signature"`
}

// RotateRequest changes a device's WireGuard key (0.31) to PublicKey, certified by its bound
// hardware key (hwsig.RotateMessage from its current key to PublicKey, at Time). The device's
// address, name and rights stay; the network maps carry the new key.
type RotateRequest struct {
	PublicKey string `json:"public_key"`
	Time      int64  `json:"time"`
	Signature string `json:"signature"`
}

// LogoutRequest closes the device's person layer, if it is still the one opened at PersonSince
// (RFC 3339; empty: whichever is open).
type LogoutRequest struct {
	PersonSince string `json:"person_since,omitempty"`
}

// CheckInResponse carries the token the next check-in presents; the device saves it first.
type CheckInResponse struct {
	Token string `json:"token"`
	// RotateKey asks a device with a bound hardware key to change its WireGuard key now (0.31): a
	// copy of its identity was noticed, or an administrator asked.
	RotateKey bool `json:"rotate_key,omitempty"`
}

// RouteRule is what a peer may open in one network behind a gateway: port rules (package ports;
// empty or "all": everything).
type RouteRule struct {
	Network string   `json:"network"`
	Ports   []string `json:"ports,omitempty"`
}

// Route is a network behind a gateway device: devices that a policy lets reach "route:NAME" reach
// its networks through that device, which forwards to them.
type Route struct {
	Name     string   `json:"name"`
	Networks []string `json:"networks"`
	Via      string   `json:"via"` // the gateway device's name
	// Exit: all internet traffic of the devices that use it goes through the gateway (no networks);
	// Default: the devices allowed use it unless they turn it off (ento agent exit off).
	Exit      bool   `json:"exit,omitempty"`
	Default   bool   `json:"default,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	CreatedBy string `json:"created_by,omitempty"`
	// Warnings (when created) name what keeps the route from working yet (the gateway's agent).
	Warnings []string `json:"warnings,omitempty"`
}

// ExitOffer is an exit a device may use: the route's name, and whether the device uses it unless
// it turns it off.
type ExitOffer struct {
	Route   string `json:"route"`
	Default bool   `json:"default,omitempty"`
	// Machine: the device's machine layer alone may use it (with Self.PersonActive).
	Machine bool `json:"machine,omitempty"`
}

// Person is someone in the network's identity provider. Groups are theirs there (devices take them
// at every sign-in); Setup is true while they have no credentials yet (invited, or their passkeys
// removed): only a setup link lets them in.
type Person struct {
	ID         string        `json:"id"`
	Email      string        `json:"email"`
	GivenName  string        `json:"given_name,omitempty"`
	FamilyName string        `json:"family_name,omitempty"`
	Enabled    bool          `json:"enabled"`
	Groups     []string      `json:"groups"`
	Setup      bool          `json:"setup,omitempty"`
	Account    string        `json:"account,omitempty"` // the provider's account type (passkey, password, ...)
	CreatedAt  string        `json:"created_at,omitempty"`
	LastLogin  string        `json:"last_login,omitempty"`
	Passkeys   []Passkey     `json:"passkeys,omitempty"` // only for one person
	Signin     *PersonSignin `json:"signin,omitempty"`   // only for one person (0.46)
}

type Passkey struct {
	Name         string `json:"name"`
	RegisteredAt string `json:"registered_at,omitempty"`
	LastUsedAt   string `json:"last_used_at,omitempty"`
}

// PeopleList is every person, and the groups the provider knows.
type PeopleList struct {
	Provider string   `json:"provider"`
	People   []Person `json:"people"`
	Groups   []string `json:"groups"`
}

// SigninPolicy: the ways of signing in the network allows by default, those it knows, and the
// people groups with their own (0.46).
type SigninPolicy struct {
	Default []string            `json:"default"`
	Methods []string            `json:"methods"`
	Groups  map[string][]string `json:"groups"`
}

// SetSigninRequest changes the default (Group empty) or a people group's own policy (Methods null:
// back to the default).
type SetSigninRequest struct {
	Group   string   `json:"group,omitempty"`
	Methods []string `json:"methods"`
}

// PersonSignin: what a person has, may use (their groups' policy) and can use now.
type PersonSignin struct {
	Password bool     `json:"password"`
	Passkeys int      `json:"passkeys"`
	TOTP     bool     `json:"totp"`
	Methods  []string `json:"methods"`
	Allowed  []string `json:"allowed"`
	Usable   []string `json:"usable"`
}

type NewGroupRequest struct {
	Name string `json:"name"`
	// Kind: "people" (default) or "devices" (0.44).
	Kind string `json:"kind,omitempty"`
}

type NewPersonRequest struct {
	Email      string   `json:"email"`
	GivenName  string   `json:"given_name,omitempty"`
	FamilyName string   `json:"family_name,omitempty"`
	Groups     []string `json:"groups"`
}

// UpdatePersonRequest changes what is set: Enabled false cuts the person off (their devices lose
// what their sign-in gives them at the next refresh), Groups replaces their groups.
type UpdatePersonRequest struct {
	Enabled *bool     `json:"enabled,omitempty"`
	Groups  *[]string `json:"groups,omitempty"`
}

// SetupLink lets a person without credentials register a passkey, once, until it expires. It is
// shown to the administrator, who hands it over: the provider sends no mail.
type SetupLink struct {
	Link      string `json:"link"`
	ExpiresAt string `json:"expires_at"`
}

type NewPersonResult struct {
	Person Person    `json:"person"`
	Setup  SetupLink `json:"setup"`
}
