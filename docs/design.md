# ento design

ento is a self-hostable mesh VPN built on WireGuard. It follows the architecture of NetBird
(control plane, agents, peer-to-peer data plane, relay fallback) with one fundamental difference:

> **Everything runs through WireGuard.** The only thing a deployment exposes to the internet is a
> WireGuard UDP port. Enrollment, control, signalling and relaying all happen inside the tunnel.

they are met.

It is a product of its own: it must not depend on anything in any platform that deploys it, and anyone must be
able to deploy it on their own infrastructure.

## Goals

- Zero public attack surface besides WireGuard (which does not answer unauthenticated packets).
- Simple self-hosting: one static binary, one UDP port, SQLite for a single node or PostgreSQL for HA.
- High availability: any number of control nodes, agents fail over between them transparently.
- Default deny: a new device reaches nothing until it is approved and a policy allows it.
- Peer-to-peer data plane with relay fallback; control nodes never see plaintext user traffic.

## Non-goals (for now)

- Layer 2 networking (broadcast, multicast). ento is layer 3, like WireGuard itself.
- Platforms other than Linux for the first releases (macOS, Windows, mobile come later).

## Components

A single binary, `ento`:

| Command | Role |
|---|---|
| `ento control` | Control node. Userspace WireGuard (wireguard-go) with an in-process TCP/IP stack (gVisor netstack): needs no root, no TUN device, no kernel module, only its UDP port. The HTTP API listens on the node's overlay address inside that stack, so it is unreachable except through WireGuard. |
| `ento agent` | Runs on every device. Configures a WireGuard interface (kernel WireGuard on Linux), enrolls with a token, keeps the network map up to date and applies it. |
| `ento admin …` | Administration through the control API, as a peer that has the admin flag. |
| admin web interface | Served by `ento control` itself on port 443 of its overlay address for one name (`--admin-ui`): the node reads the server name of each TLS connection, terminates those for the interface and passes all others through to the identity provider. Authorization is the calling device (admin flag), as for the API; changes need the interface's own header, origin and name (cross-site requests from other pages cannot make them), and the plain API refuses browsers. |
| `ento agent join DOMAIN` | Joins another network besides the first, with its own invitation, on an interface of its own (see "Several networks on one device"). |
| `ento agent link NAME` | Joins a linked network (see "Linked networks") in namespace `ento-NAME`. |
| `ento control token …` | Local bootstrap commands operating directly on the database (first admin token). |

```
                    internet: UDP only
   ┌──────────────┐         ┌───────────────────────────────┐
   │ agent        │◄───────►│ control node 1                │
   │ ento0       │  WG     │  wireguard-go + netstack      │
   │  peer: ctl-1 │         │  API on 100.64.0.1:80 (tunnel)│──┐
   │  peer: ctl-2 │         └───────────────────────────────┘  │   PostgreSQL
   │  peer: B ◄───┼── P2P ──►  agent B                          ├── (or SQLite for a
   └──────────────┘         ┌───────────────────────────────┐  │    single node)
                            │ control node 2 (100.64.0.2)   │──┘
                            └───────────────────────────────┘
```

## Identity and authentication

- A peer is identified by its WireGuard public key.
- The control API identifies callers by **source overlay address**. WireGuard's cryptokey routing
  guarantees that a packet from `100.64.x.y` was sent by the holder of the key that owns that
  address.
- That proves the device, not the program on it: every process, container or app on a device shares
  its address. Calls that act with the device's rights (the admin API, sign-in, credentials for
  linked networks) must also be **signed with the device's key** (package `reqsig`): the key is the
  X25519 agreement between the device's WireGuard key and the control node's (nothing to register),
  through HKDF-SHA256 with both public keys; each request carries HMAC-SHA256 over its method,
  target, time (within 5 minutes), a nonce (accepted once) and the hash of its body. Only the agent,
  root or an administrator reads the key. The network map and credential renewals in a linked network
  (bound to the key by the credential itself) do not need it yet; agents sign them anyway.
- The admin web interface answers in a **session** of the calling device only. The page gets a
  pending session (an `HttpOnly`, `SameSite=Strict` browser-session cookie) showing a short code; the
  session opens when the same device approves that code with a signed call (`ento admin ui CODE`,
  or the app). Nothing secret leaves the page (an earlier design passed a one-time link to the
  browser on a command line, which local programs can read), and a program without the key cannot
  get a page approved. Sessions open administration only (not sign-in or link credentials), last 8
  hours, end after 30 minutes unused or when the device loses its role, are stored by the hash of
  their cookie in the shared database (any control node honours them) and go with the device. A
  program able to read the browser's cookies on the device can use an open session from there.
  With an identity provider, a session also opens when the person signed in on the device in ento
  signs in on the page again (0.49; a fresh sign-in, nonce and `auth_time` checked, 0.50): only for
  a person with a role of their own, and it has what that person has on that device (a role takes
  both layers, 0.54; from 0.50 to 0.53 the person's rights alone), so the provider's open session
  does not count.
- Authorization levels:
  - *enrolling*: a temporary key from an enrollment token; may only call the redeem endpoint;
  - *pending*: enrolled, not approved; receives an empty network map;
  - *approved*: receives the network map allowed by policy;
  - *admin*: may call the admin API.
- Two layers per device (0.27; `store.Peer.Machine`, `store.Peer.Person`): the machine's (approval,
  groups, role from its token or an administrator; columns `approved`, `admin`, `operator`,
  `groups`) and the person's (from their sign-in; `person_*`), with the effective approval and
  groups their union while the person layer is open, and a role only where both have it (0.54:
  admin is the machine's admin and the person's; `Peer.derive`; in SQL `effectiveApproved`). Without
  an identity provider the control node gives the machine's role alone (`Server.withRoles`).
  Sessions and timeouts
  touch only the person layer; suspension clears the machine's approval and closes the person's
  for good. The person layer closes when its person's last traffic (`person_activity_at`, from the
  devices' check-ins: `person_idle` seconds; and their administration, recorded at most once a
  minute) is older than the idle limit (8 hours; for agents that do not report, `last_seen`), on
  logout (`/v1/logout`, conditional on the session the device named), on a new boot ID (check-ins),
  when the identity provider withdraws the person, and after a maximum only if one is set. The
  devices' reports are written without a new map version (nothing in maps depends on them). An
  approved sign-in approval of a desktop service (`--reopen-services`) asked by a bound device of
  its person reopens the layer within 7 days of the last full sign-in (`login_at`), for the boot it
  asked from. With the layer open, the map tells the device what its machine layer alone may open
  per peer (`Peer.Machine`), per network behind a gateway (`RouteMachine`) and through exits
  (`ExitOffer.Machine`); the agent counts the rest (the kernel's nftables chain `person` with
  conntrack, the agent's own WireGuard in its packet path) and everything in linked networks'
  namespaces. The 0.27 schema moved bound devices' rights to the person layer once (column
  `layered`). The sweep runs on every control node.
- Within the session, the identity provider decides (when the control nodes have a token key):
  each sign-in's refresh token is kept encrypted (AES-256-GCM, the device's ID as associated data)
  in the store, and every 2 minutes a control node claims the devices that are due
  (`FOR UPDATE SKIP LOCKED`, so each is checked by one node) and refreshes them. `invalid_grant`
  withdraws the approval; new groups in the ID token apply (ID tokens are verified against the
  provider's published keys, 0.50, and one that fails changes nothing; in any order; an ID token without the
  groups claim, or none at all, leaves them as they are); anything else (unreachable, 5xx, an
  unexpected answer) changes nothing, so an outage of the provider never locks people out. Every
  write is conditional on the token and the sign-in it was decided for (`SSOToken.Previous`,
  `PeerUpdate.IfLoginAt`): a check overtaken by a new sign-in on the device changes nothing. It runs
  while the device is bound, its person layer open or not, and updates only the person layer.
  Refresh tokens are offline ones where the provider offers them, so that a browser sign-out
  elsewhere does not end the VPN. Plain OIDC: no admin API, SCIM or back-channel of the provider is
  needed. Linked-network credentials of checked devices last at most 10 minutes.
- The person's channel (0.35, Windows): signing in is a call signed with the device's key, which
  only the service and administrators can read there, and Windows has no login-screen step that
  reopens the layer. The agent takes `status`, `login` and `logout` on a named pipe open to
  interactive users (`internal/agent/session.go`): it runs the device login with its key and hands
  back only the link and code, so the person gains nothing they could not do with an administrator's
  `ento agent login`, and the sign-in still needs their own credentials at the provider. Acting is
  limited to a program in the console's session; clients trust only a pipe server in session 0,
  because writing to a pipe also allows opening instances of it, so a user's program could
  otherwise answer in the agent's place with its own link. `ento-tray.exe` uses the channel to
  show the session and sign the person in when it has ended.

## Copied identities

A device is its WireGuard key, kept in the agent's state; a copy of that state is the device. Step
1 (0.23, decided on 2026-10-04) detects copies. The agent checks in every 5 minutes (`POST
/v1/checkin`, signed) with the token the last check-in issued and a salted fingerprint of the
machine; the control plane keeps per device (`ento_checkins`, changed under the peer row's lock so
control nodes agree) the hash of the token it issued last (`cur`) and of the one it accepted last
(`prev`): `cur` presented is accepted (it becomes `prev`, a new `cur` is issued); `prev` presented
means the answer was lost (a fresh `cur` replaces the unused one, never the same, so two copies
cannot pass one token around); anything else, a missing token after earlier check-ins, or another
fingerprint means a second holder. Devices bound to a person are then suspended (`auto`), others
reported; resuming deletes the record, so the next check-in starts over. One check-in at a time per
agent (a single loop); linked networks' memberships do not check in yet.

Step 2 (0.31, Linux with a TPM 2.0; the user's request of 2026-10-06): a P-256 key the TPM holds
(created under the owner hierarchy's storage root key, fixedTPM and fixedParent, no PCR policy so
firmware updates keep it; package `tpmkey`, go-tpm) is bound to the device on first use
(`ento_hwkeys`: kind, PKIX public key, bound, last signed check-in, first unsigned one since,
rotation wanted, last rotation). It signs every check-in (`hwsig.CheckInMessage`: label, WireGuard
key, token, time) and certifies each new WireGuard key (`hwsig.RotateMessage`), which the device
changes daily: `RotatePeerKey` swaps the key in the device's row under the version lock, so the
address, name and rights stay and maps carry the new key. Rules: an unsigned check-in from a bound
device is refused (no token issued), marks the device to rotate (the map's `rotate_key`, a new
version, and the next signed check-in's answer; the key change clears it in the same transaction),
and after 15 minutes without a signed one suspends it; the control node answers a rotation before
committing it (the commit wakes WireGuard, which drops the old key's session), and the agent keeps
the old key as its fallback until a control node answers the new one; a signed check-in wins over the token chain (rotate, never suspend);
another hardware key for a bound device is refused (`hwkey_conflict`) and rotates the original; a
rotation resets the expected fingerprint (salted with the key). The agent saves the next key
before asking and, while the answer is unknown, tries both keys in turn. Not yet: macOS's Secure
Enclave and Windows' TPM, phones (the Keystore key signs posture reports only), API calls other than
check-ins signed by the hardware key, and memberships in linked networks. (3) attestation (TPM endorsement key
certificate and quotes for Secure Boot) and a posture check `hardware-bound` that customer links can
require. Android key attestation is built for posture (0.30, Device posture): a Keystore key bound
to the WireGuard key signs each report's time, so a copied identity reports without the phone's
attested facts; it does not sign the other calls yet.

## Sign-in approvals

A device may ask that a person approve a sign-in on it (a PAM service) from another of their
devices (0.21). `POST /v1/approvals` names the account (the identity provider's username or e-mail,
kept from sign-ins as `user_login`/`user_name`) and the service; the control node maps it to one
person (the subject of SSO-bound devices), refuses when none of that person's devices may approve
(bound by SSO, approved, not suspended, passing their policies' posture checks, agent 0.21 or
later, not the asking device), and stores a pending approval (`ento_approvals`: random id, the
number to show (10 to 99), two other numbers, at most 2 minutes). The asking device long-polls its
state; approving devices long-poll the approvals waiting for their person (a phone instead learns
their number from its network map, `?approvals=N` making the map's long poll return when it
changes, 0.34, and fetches them then) and answer with the number picked: the right one approves, another or a refusal denies; one answer only. Every call is signed
with the device's key; rate limits per asking device (10 in 10 minutes) and per person (20); state
is shared through the database (another control node may hold either side; waiting calls look
every second), rows are deleted after a day, the audit lines are the record.

## Sign-in by the device

Control nodes can be an OpenID Connect provider for one client (0.32, `internal/control/signin.go`):
the organisation's identity provider brokers to them, and they sign in the person of the device the
browser runs on. They serve it under the admin interface's name and certificate, at `/device`, on
port 443 of their overlay addresses; the TLS connection ends at the control node inside the tunnel,
so the caller's overlay address names the device, as for the admin interface, and nothing else is
asked. Discovery and the JWKS answer anyone in the network; the authorization endpoint answers any
device and decides itself; the token endpoint answers the client (its secret), from wherever its
server reaches the control nodes.

A device vouches only for its person (`user` of an SSO-bound device), while their person layer is
open and approved, the device is not suspended and was not admitted through a link, and the layer
is recent: the later of its opening and the device's last sign-in through the provider
(`ento_signin_use`, per person layer) is within the idle limit (default 6 hours). Otherwise the
browser goes back with `access_denied`, which an identity provider such as Keycloak turns into its
own sign-in form. So it does when the request asks for a fresh sign-in (`prompt=login`, `max_age=0`,
0.34.2): an application confirming a change wants the person's own factors, and a device vouching
is not one. Authorization codes (`ento_signin_codes`, stored by a salted SHA-256 of the code)
last a minute, are deleted when redeemed, and bind the client, the redirect URI (exact match), a
PKCE S256 challenge (required), the nonce and the person layer (its opening time): redeeming one
re-checks that this layer is still open. ID tokens are ES256 with a key every control node shares
(an environment secret, not the database), five minutes, `sub`/`preferred_username` from the
person's last full sign-in at the same identity provider.

The provider never vouches from anything a device says about itself: only the control plane's
record of the person layer, which opens at a full sign-in or an approved desktop login and closes at
logout, a new boot, idleness, or withdrawal by the identity provider. It adds no way to open that
layer. The identity provider must keep ento's own sign-in off this path (a flow without the
session cookie), or a session the device opened could renew the full sign-in that the device's
vouching rests on.

## Enrollment

A token carries everything needed to reach the control plane:

```
ento1:<base64url( version | secret[32] | n × (control public key[32] | endpoint) )>
```

- The token secret derives, with HKDF-SHA256 and versioned labels, a temporary WireGuard private key
  and a preshared key. Control nodes pre-register the derived public key with a temporary overlay
  address that can only reach the redeem endpoint, until the token expires.
- The agent configures the control peers from the token, handshakes with the temporary key, generates
  a fresh random permanent key and redeems it over the tunnel. The control node identifies the token
  by the source address; the secret is never sent. Redemption is atomic; the temporary key is
  removed from every control node.
- Tokens are one-time and short-lived by default. Fleet tokens (a seed deriving a family of keys) are
  a later extension.
- The token is read from a file, stdin or an environment variable, never from command-line arguments.
- **Words instead of a token** (0.20). A domain publishes the network record, a TXT record at
  `_ento.<domain>`: `ento1 net=<range> c=<key>,<endpoint>,<overlay address> ...`, one `c=` per
  control node. A control node draws five words from the EFF large wordlist (64.6 bits) and stretches
  them with Argon2id (256 MiB, 8 passes; salt: SHA-256 of `ento-words-v1`, the range and the sorted
  control node keys) into a token secret; HKDF derives from it the temporary key and preshared key
  as above, and the temporary address (`enrollment-address`: x.y.255.1 to .254, new words while it is
  taken). It stores what a token stores. The device reads the record, asks for the words and builds
  the same token in memory. A forged record leads nowhere without the preshared key; whoever answers
  the first handshake can test guesses offline against the temporary public key, at an Argon2id per
  guess, until the words expire (a day at most). The record changes when a control node's key does.
- **Words as a QR code** (0.30). For a phone in front of the administrator, the words come with a
  join code, `ENTO1:<domain>:<fingerprint>:<words>` in capitals (QR alphanumeric mode), drawn by the
  admin page (`qr_domain`: its own name without `net.`; else the control nodes' `--record-domain`) or
  `ento admin|control token --words --qr` on a terminal. The app reads it with the camera, looks the
  record up as for typed words and refuses one whose fingerprint is not the code's: the fingerprint
  the person would have compared is compared for them. The person still presses Join, naming the
  domain. The code is the words in another form: single use, short-lived, shown, never sent.
- **The record finds control nodes that moved** (0.29). With `--record-domain`, the network map
  names the record's domain and agents keep it. An agent that has had no network map from any
  control node for 5 minutes looks the record up (every 10 minutes while that lasts; on Android
  through the DNS servers of the phone's network) and takes the endpoints it gives for control
  keys it already holds; keys and overlay addresses come only from the map. A forged record can
  only send handshakes to an address where no one holds a control key. Control nodes check at
  start and hourly that the record names them at their endpoint. The home network only: linked
  memberships are renewed through it.

Enrollment only grants a tunnel to the control plane (L1). Network access (L2) requires approval:
explicit, pre-authorised when the token was created, or through single sign-on — the device logs in
with the OAuth 2.0 device authorization grant and inherits approval, admin rights and groups from
the user's groups at the identity provider.

## Device names

A device's name is what other devices and people see: in the network map (and so in the hosts files
of linked namespaces), audit lines, the admin interface. It used to be whatever host name the device
reported, unchecked, which let a device choose a name that looked like another's (a deployment
could be sent to it) and put control characters into logs and terminals.

Names are now unique within a network, at most 32 characters of `a-z`, `0-9` and dashes (package
`names`), and come from one of three places:

- an administrator: with the enrollment token (`Name`, reserved from the token's creation until it
  is used or expires; with `Replace` the new device takes over name and address from the device
  that has the name when it enrolls, in the same transaction), or later with a rename;
- the device: its reported host name, reduced to name characters, after the prefix `z-`, with the
  first free counter (`-1`, `-2`, ...). Administrators' names cannot start with `z-`, so the two
  never meet;
- an authority: a device admitted into a linked network is named `<authority>-<its name at home>`
  (without a `z-`), just as its groups carry the authority's name.

The reported host name is stored beside the name, reduced to printable ASCII, for display. An
administrator can confirm it (the name becomes the reported host name without `z-`) or rename the
device. The control node computes every name itself, whatever an agent sends, and the database
enforces uniqueness. Names contain no dots, so none can stand for a domain in a hosts file; agents
reduce peer names from older control planes the same way.

## Network map

Each agent keeps a long-poll request open to one control node:

```
GET /v1/netmap?since=<version>
```

The response holds the agent's own address, the list of control nodes and the peers it may reach:
public key, overlay address and endpoint candidates (after policies and their posture checks), and
the posture checks the device fails. The version increases on every relevant change,
so agents only receive updates. Control nodes are stateless between requests; any of them can answer.

## Policies

A policy names a source, a destination group (`*`: every device) and port rules: the
source's devices may open connections to the destination's, which answer them (one way: 0.52,
control node starts, `internal/control/oneway.go`, except one that requires posture checks, kept
both ways until an admin replaces it); port rules are `all`, `tcp`, `udp`, `tcp/N`, `tcp/N-M`, `udp/...` and `icmp` (echo
requests). Two devices are in each other's network map when any policy connects them, in either
direction (one must be able to answer the other). Since 0.19 each peer in a map also carries what
it may open on the receiving device (`accept`: the union of the rules of every policy that lets it,
empty when it may only answer), and the map says the device must enforce that (`filter`).

The receiving device's agent enforces it, never the sender's: a modified agent on the opening side
gains nothing. Answers to the device's own connections and everything from control nodes pass. The
filter is applied before the peers are, and one that cannot be applied leaves the control nodes as
the only peers until it can (0.50; before, it was only logged and every peer reached every port).
Since 0.51 the table is looked for at every application of the map (every few seconds; before,
once a minute, so `nft flush ruleset` left no filter for up to a minute), and a filter that cannot
be applied is said: `ento agent status` shows a WARNING with the reason, and each check-in carries
it to the control plane, which audits `filter_failed` (failed) while it lasts.
With the Linux kernel's WireGuard the agent keeps an nftables table of its own (`inet
ento-filter`: a prerouting chain after conntrack, for answers, and before the system's DNAT, so it
sees the port the peer connected to; re-created if removed; not at the input hook, where it would
count in the firewall fact); with wireguard-go a wrapper around
the TUN device filters what WireGuard delivers (TCP: stateless, only an opening SYN is judged; UDP:
answers to datagrams the device sent in the last 2 minutes; ICMP: only echo requests are judged).
With `--log-drops` (0.29) refused new connections are logged, at most 20 a minute: by nftables log
rules before the chain's final drop (prefix `ento-filter drop: `), or by the wrapper in the same
fields. Agents older than 0.19 ignore the filter and accept everything from their map's peers (fail open,
as before), so control nodes warn about receiving devices with older agents when a policy gets a
direction or ports.

a people group, everyone signed in (`*signed-in`), nobody signed in (`*nobody`) or anyone (`*`), on a
device group or any device. It is kept in the policy's one source column, `engineers on
device:laptops`, so that no schema changes and a control node older than 0.53 reads it as a group
that no device is in: during a rolling update or after a downgrade such a rule lets less through,
never more. Anyone on a device group is the device group alone, and a people group on any device
the people group alone, exactly as policies were written before, so nothing stored changes meaning.
The matching is that of every policy (`inGroup`): a person's groups count while their layer is open
on the device, so a rule of people follows their sign-in; the machine's own access (what the device
may open without its person, which keeps the person layer open when exceeded) has nobody signed in.
Bypass detection compares who and devices apart, conservatively (a people group and everyone signed
in may share devices; nobody signed in and a people group may not).

A forwarded service (`--forward`) is a destination too, `service:NAME`, without ports (0.53). The
control node judges each connection by the device's address, as before, now against the rules
(`serviceAllowed`: the device approved, not isolated or suspended, in a rule's source, passing its
checks; full administration, a person in admins on a device in admin, without a rule), and checks an
open connection again every 15 seconds. No device's map changes: the control nodes are always in
it. Each service, the first time a node of 0.53 forwards it, gets rules for whom it let through
before (`*`, or `--forward-people`'s role groups), once (a `service_rules:NAME` setting): before the
node accepts its first connection, so nobody is refused in between. Isolated devices, which reached
forwarded services before, no longer do (4.3). The identity provider and the dashboard are not
reached by rules yet.

## Audit

Every change and refusal is a journal line of the control node that made it (`audit:`, one line a
SIEM parses) and, since 0.53, an entry in the network's database (`ento_audit`), so that the record
is the network's, not one node's, and the dashboard can show it. Writing it is synchronous and
bounded (3 seconds): an audit line is never lost because the database is slow, it only is not
stored, and a second journal line says so; the journal stays the record of last resort. The table
only grows: a trigger refuses UPDATE, DELETE and TRUNCATE. That stops the control nodes (and any
code path in them) from rewriting history, not the database's owner, who can drop the trigger;
backups and the SIEM's copy of the journal are what show such a change. The control nodes' command
line writes its entries too, with whoever ran it (the user behind sudo). Reading is `GET
/v1/admin/audit` for admins, operators and viewers, by pages of IDs (newest first), filtered by
action, result, text and time, or as CSV (an export is audited). Not yet: retention, the identity
provider's own changes, and refusals that happen before a device is known (unenrolled addresses,
unsigned calls from strangers) beyond what the journal has.

## Routes

A route (0.24) names IPv4 networks behind a gateway device, by its name. A policy whose destination
is `route:NAME` lets its source devices reach those networks on its ports (posture checks as for any
policy; groups never match a route, so no policy between groups reaches one). The control node gives
such a device the gateway as a peer with `Peer.Routes` (its agent puts the networks in that peer's
allowed IPs and routes them into the interface, leaving out networks that overlap one of its own
interfaces), and gives the gateway `Self.Routes` (what it serves) and, per device, `RouteAccept`
(network and port rules). The gateway's filter then judges every packet by its destination: its own
address by the device rules, a served network by the route rules, anything else dropped; a
postrouting masquerade hides the devices behind the gateway's LAN address and a forward chain lets
the LAN only answer. The relay carries a route's traffic like a policy's (`routeLinked`). Later: two
gateways per route, internal DNS.

An exit (0.25) is a route without networks (`exit`, and `use_by_default`). Its gateway gets
`Self.Exit` and `0.0.0.0/0` in the `RouteAccept` of each device the policies let use it; those
devices get the offer on the gateway's peer (`Peer.Exits`: route, default). The device chooses
(`<state dir>/exit`: off, a route's name, or nothing for the one used by default); in use, the
gateway's peer carries `0.0.0.0/0` and the system routes into the tunnel everything the main table
has no more specific route for: on Linux, WireGuard's packets get firewall mark 30835, rule 31770
looks up the main table with `suppress_prefixlength 0`, rule 31771 sends unmarked packets to table
30835 (IPv4 default into the interface, IPv6 default unreachable), and systemd-resolved gets the
gateway as the interface's DNS server with routing domain `~.` (only from the system's network
namespace); on Android the VPN routes `0.0.0.0/0` with the gateway as DNS server. The gateway's
filter accepts from such a device, after its device and route rules: UDP and TCP 53 to its own
address (a forwarder that passes queries to its resolvers, answering only those devices), then
anything to a public address (private, shared and special ranges and `fib daddr type local` are
dropped first), masqueraded on the way out. A device that is an exit uses none. macOS and Windows:
later.

## Internal DNS

With a domain (`--dns-domain`, 0.26), each device's map carries `DNS` (`api.DNSConfig`): the domain,
names relative to it with their addresses, and forwarded zones with their servers. The control node
puts in it the device itself and the devices of its map (by device name, which wins), and the names
administrators added (`dns_records`) and zones they forwarded (`dns_forwards`, servers filtered the
same way) whose address the device reaches: a device of its map, a network one of its peers routes
for it (or it serves), or an address in neither the overlay nor any route. The agent's resolver
(`dns.go`) listens on the device's overlay address, port 53, and answers only the device itself
(and, on an exit, the devices using it, whose queries it passes to the system's resolvers): names
in the domain from the map (A records, TTL 60; other types answered empty; unknown names NXDOMAIN),
forwarded zones (the longest match; a zone inside the domain before the domain) by asking their
servers, other names through the exit's gateway while an exit is in use or the upstream servers a
phone's app gives it, else refused. `DNS.fixed` (0.30.1) names what the control nodes serve on their
overlay addresses, port 443: the identity provider's name when they forward it (`--oidc-connect-to`),
the admin interface's and the services they pass through (`--forward
NAME=HOST:PORT[+...]`, 0.33; reached by rules since 0.53: split by TLS server name like the admin interface, with the identity
provider's rules and one audit line per connection, `forward_connection`), each with every control node's overlay address, in every device's map,
approved or not (then `DNS` has no domain, only these). The resolver answers them first, itself
(several A records; other types empty), and Linux routes them to it like the domain: signing in no
longer depends on the network's DNS passing answers that point at shared addresses (rebinding
protection drops them). `--service-names` (0.30.2) adds the network's other services: each control
node resolves the names with its own DNS (at start, then every 5 minutes; a failed lookup keeps the
last addresses) and adds the IPv4 answers inside the overlay range, never others, after the names it
serves itself. Linux points systemd-resolved at it with routing domains (the
domain, the zones, `~.` with an exit), only from the system's network namespace, told again every 5
minutes and after the interface was repaired. A phone's app cannot listen on port 53: there the
resolver sits in the packet path (`filterTUN`): UDP queries to x.x.0.255 (the end of the control
range, never assigned) are answered by the agent and written back as datagrams from that address;
the VPN names it as its DNS server once the agent can answer every name. Linked networks' namespaces
get the names in their hosts files.

## Device posture

L2 admission can also depend on the state of the device, per policy (NetBird's "posture checks",
done inside the tunnel):

- **Reports.** Agents find out facts about their device (system and version, disk encryption,
  firewall, Secure Boot, screen lock; each may be unknown) with fixed commands and files only, and
  report them as a versioned JSON document (`api.Posture`, `format` 1) in a call signed with the
  device's key (`POST /v1/posture`, package `reqsig`), at start, when they change and every 10
  minutes, to every network the device belongs to. Mobile apps hand the agent what only they can
  read. A control node keeps each device's latest report (cleaned up: values reach audit lines and
  terminals) with the time it received it, never the device's clock. The store refuses a report
  less than 30 seconds after the previous one (so the limit holds across control nodes). Agents
  measure the 10 minutes by the wall clock (the monotonic clock stops while a device sleeps), and
  report at once when their network map says the network holds no recent report.
- **Checks.** Administrators name sets of requirements (`PostureCheck`: disk encryption, firewall,
  Secure Boot, the oldest version per system, the oldest report accepted). A policy may require
  checks of its source devices. For each policy with checks, a source device that fails one of them,
  or whose report is missing or too old, is left out of that policy entirely (also where it is in the
  destination group too); everything else about the network map is unchanged, and policies without
  checks behave as before. Unknown facts fail.
- **Consistency.** Whether a device passes depends on time (reports age), but every control node
  must build the same maps and wake agents only on a change. The checks each device must pass are
  therefore evaluated (on a report, after a policy change, every 10 seconds) and the results stored;
  network maps and the relay follow the stored results (a check that became required a moment ago is
  evaluated on the spot). A result is replaced only if it is still the one the evaluating node read
  (a conditional write), so of several control nodes one records, and audits, each change, and the
  version changes only then. The device learns which checks it fails, and why, in its network map
  (`self.posture_failing`) and in the answer to its report.
- **Damping.** A check a device started failing over its facts stays failed for 2 minutes after
  that result was stored (`results_at`), even if passing facts arrive meanwhile; failures that are
  only about the report's age pass at once. With the 30-second gap between reports, a device that
  flips a fact on every report changes the network maps at most twice per hold-down, not twice a
  minute.
- **Bypass.** Any policy that connects two devices puts them in each other's map, so another
  policy connecting the same groups (either order, or `*`) without the checks makes them moot
  (counted both ways and every port: a connection carries data both ways whichever side opened
  it, and older agents enforce neither).
  Adding or changing a policy reports such pairs as warnings (by group names); operators may not add
  a policy that would bypass a guarded one.
- **Audit.** `posture_failed` (denied) for failing facts, `posture_stale` (ok) for a missing or old
  report, `posture_passed` (ok); one line per change of outcome and check, written by the control
  node whose conditional write stored it.
- **Linked networks.** Checks that policies require do not gate link credentials. A link may require
  checks of its own (`links.posture`): the home control plane evaluates them at every credential
  request (joining and renewal) as for policies (the live evaluation, plus a facts-based failure the
  stored results still hold back for that check), and while the device fails one it issues neither a
  credential nor the linked network's token; the refusal names the failing checks
  (`posture_failing` in the error body), which the agent keeps for `ento agent status`. Issued
  credentials are not revoked by the home network: they expire (renewal at half their lifetime), but
  the device's agent ends them when a renewal is refused (0.35.1: peers dropped at once, the linked
  network asked to withdraw the approval, `/v1/credential/end`, audited `credential_ended`) and
  renews at once when the person's layer opens or ends, so a sign-out ends linked access within
  seconds; a device whose agent does not cooperate keeps it until the credential expires. Whether a device
  passes each link is recorded per link and device (`link_posture`: the outcome, failed or stale, of
  each check it does not pass), swapped atomically, so that one control node audits each change of a
  check's outcome (`link_posture_failed` denied, `link_posture_stale` ok, `link_posture_passed` ok)
  and renewals of a device whose outcomes stay the same write nothing; changing a link's checks
  forgets these records. Agents wait briefly at start for their first report to be taken before
  asking for a link credential, and report at once and ask again within seconds when refused only
  for want of a recent report. Each linked network also requires its own checks of the devices admitted into it, which
  report there too.
- **Trust.** The facts are the device's own statement, signed with its key: they keep honest devices
  in policy and make drift visible (audit, admin interface), but a device whose root user lies passes.
  Attested facts are the layer above, on the same checks: Android's for now (below); TPM quotes later.
- **Android key attestation** (0.30, `internal/attest`). The app's posture reports carry
  `attestation`: the certificate chain (leaf first) of a P-256 key the Keystore made in the phone's
  secure hardware with the challenge SHA-256(`ento-attest-v1` 0x00 WireGuard public key), and the
  key's ECDSA signature of `ento-attest-signed-v1` 0x00 key time (RFC 3339), made for the report.
  The control node that takes the report verifies it and stores the outcome (`attested`) with the
  facts, never the chain: every certificate signed by the next; the last carries one of Google's
  root keys (the key, not the certificate, is the anchor: phones hold the RSA root in certificates
  of 2016, 2019 and 2022, the oldest expired); every other certificate inside its validity; none on
  Google's revocation list (fetched from the first attestation on, every 6 hours; older than 3 days:
  nothing counts); the attestation extension in the leaf and nowhere else (the attested key is the
  app's to use, and a certificate it signs placed in front of the chain would otherwise attest
  anything); attestation security level TEE or StrongBox; the challenge for the reporting device's
  key; origin generated (an imported key was known outside the hardware); the signature valid and
  its time within 10 minutes; optionally (`--android-apps`) the package and signing certificate of
  the app that asked. On Android, Secure Boot is set from it alone (verified boot state `verified`
  and the bootloader locked; the app's own word is dropped) and the patch level is the oldest of the
  attested system, vendor and boot patch levels; checks evaluate those as usual, and a missing or
  invalid attestation is `verified boot not attested: <why>`. The signature binds the attestation to
  the phone holding the hardware key, so a copy of the state elsewhere has none; the challenge binds
  it to the device's key, so another phone's attestation does not count. Not covered: what runs
  after boot, and phones whose hardware keys leaked before Google revoked them.
- **Who.** Only admins add or delete checks and attach them to policies and links; operators list
  them and cannot change or remove a policy that has checks. A check that a policy or link requires
  cannot be deleted.

## Data plane

- **Direct connectivity.** Control nodes observe each agent's public endpoint from WireGuard itself
  (the same socket the mesh uses) and distribute it in the network map, together with endpoints the
  agent reports (local addresses). Both sides receive each other's endpoints at about the same time
  and start handshaking, which opens most NAT mappings.
- **Keepalives.** Agents and control nodes send WireGuard keepalives every 25 s to keep NAT
  mappings open, except to and from phones (`os` android or ios, `quiet` in the map; 0.34), whose
  radio each packet wakes: a phone's map long poll (every 25 s at most) keeps its way to its control
  node open, and its peers handshake afresh when they have something to send.
- **Relay.** When something was sent to a peer and no handshake followed within 20 seconds (or it
  has no known endpoint; an idle peer without a session is not a failure, 0.34), its traffic flows through a control node. The agent binds a local UDP socket per
  relayed peer and points the kernel WireGuard peer at it; packets are wrapped in a relay frame
  (version, 32-byte peer key, payload) and sent over the agent's own tunnel to UDP port 3479 of its
  control node, which checks that both peers are approved and allowed by policy and forwards the
  frame to the destination's overlay address. The payload is the peer-to-peer WireGuard packet, so
  the control node cannot read it. A relayed peer is tried directly again when its published
  endpoint changes.

## Control plane high availability

- Any number of control nodes share one database. Each has its own WireGuard key, public endpoint and
  overlay address; all of them are control peers in every agent's configuration.
- Agents talk to one control node at a time and switch on failure. Data-plane traffic between peers
  does not depend on the control plane being up.
- Changes are propagated between control nodes through the database (PostgreSQL `LISTEN/NOTIFY`,
  polling as a fallback).

## Several networks on one device

A device may be in several networks as equals (0.51, Linux): the first, whose state is the agent's
state directory, and each network joined with `ento agent join DOMAIN`, whose state is
`<state dir>/networks/<domain>/` (`internal/agent/networks.go`). One agent runs them all: one
service, and on the phones, which give a device one VPN interface, the only way it can be done
there later. Each joined network is a runner like the first's on an interface of its own (`ento1`,
`ento2`, ...) in the device's own namespace, with its own key, hardware key (its own TPM key blob),
WireGuard port, control nodes, filter table (`ento-filter-<interface>`), posture reports,
check-ins, person and resolver. The running agent acts on the directories (`network.json` and
`enroll.token` written by `join`, `remove` by `leave`) every few seconds, as it does on linked
networks'.

Every program on the device reaches every network, so what keeps them apart is that no network can

1. **Distinct ranges.** `join` refuses a network whose range (from its record, checked again after
   enrolling) overlaps one of the device's networks, linked ones included, or a route one uses.
2. **Claims.** The agent keeps, per interface, what each network holds in the device's namespace:
   its range, the routes it routes, its record domain and the names its resolver answers. A
   network's routes and names that overlap another's claim are left out, whatever their prefix
   length (a narrower route would otherwise win in the routing table, a narrower zone in
   systemd-resolved). Checking and claiming are one step under one lock, so that two networks
   offering the same route never both take it (nor both drop it): the first keeps it. A network's
   own record domain is always its own, so another network cannot take its sign-in names by
   claiming them first. The joined networks' ranges and domains are claimed before any network of
   a starting agent applies its map.
3. **No forwarding.** Each network's filter table drops, in its forward chain and before anything
   else, what would pass from its interface to another network's or back (counted). A packet from a
   network's peer reaches the device only for the device itself or a network it serves there (the
   prerouting filter); a network it serves that another network routes is dropped there.
4. **What only one network decides.** Exits (the system's default route and `~.` DNS) and releases
   come from the first network alone; a joined network's exits are not used. Its WireGuard packets
   carry the exit's mark, as the first network's do, so they never go through the exit.
5. **Saying which network asks.** Sign-ins, sign-in approvals and `ento agent approvals` name the
   network on a device in several.

Leaving deletes the network's interface, filter table and state on the device; the device stays in
that network's list until an administrator there deletes it (a device leaving by itself is a
linked membership's right only, `POST /v1/leave`). Each network still learns what the device
reports to it (host name, posture facts), which may let two networks that compare notes tell it is
one device.

## Linked networks (access across independent deployments)

An organisation that operates many ento deployments it does not own (a managed service provider
and its customers) needs its people to reach into each of them, while the deployments stay unable to
reach each other or the organisation. ento does this without joining or routing between
networks: a device of the **home network** gets a separate, independent membership in each
**linked network**, and the linked network decides what that membership may reach.

### Isolation guarantees

1. **No shared components.** Every deployment has its own control nodes, database, keys, relays and
   overlay range. Nothing is shared between two linked networks, or between a linked network and the
   home network, except the software.
2. **No transit.** Networks are never peered or routed into each other. No peer, gateway or control
   node forwards packets from one network into another. A compromised peer of one linked network
   gains nothing in another one.
3. **One namespace per linked network on the home device.** The agent creates the WireGuard
   interface of each linked network in the root namespace (so its UDP socket uses the device's normal
   connectivity) and moves it into a network namespace of its own (`ento-<network>`), with its own
   routes and resolver configuration. ento only places the interface; what runs inside the
   namespace is up to the user, with standard tools (`ip netns exec ento-<network> …`). A process
   working on one network cannot reach another, and overlapping overlay ranges are not a problem. The namespace has
   no forwarding and accepts only return traffic: members of a linked network cannot open connections
   to the home device.
4. **Separate keys.** The device uses a different WireGuard key in every linked network; linked
   networks cannot correlate the organisation's devices across each other.

### Trust: the linked network stays in charge

- **Link (home network).** An administrator of the home network creates a link: the control plane
  generates an Ed25519 **authority key** for that linked network only, and records which home groups
  may join it (for example `operators`), which groups they request there, and how long each
  credential lasts, and optionally the posture checks a device must pass to get one (see Device
  posture). The public half (`entoa1:...`) goes to the linked network's administrator.
- **Authority (linked network).** The linked network's administrator registers that key as an
  authority: a name (for example `msp`), the groups the authority may assign and the longest
  approval a single credential may give. The linked network answers with the authority's
  **enrollment token**, which the home network imports into its link. The token's key is reusable
  but grants nothing by itself: every redemption must carry a valid credential.
- **Joining.** When a device joins, its agent generates a new WireGuard key for the linked network
  and asks its home control plane for an **access credential**: a statement signed with the authority
  key naming the device's key, the user, the device, the requested groups and an expiry. The home
  control plane only issues it to approved devices in the link's groups that pass the link's posture
  checks, signed calls only. The agent then enrolls in the linked network with the token and the
  credential.
- **One membership per device.** The home control plane records the one key each device holds in
  each linked network: renewals are for that key only, and only joining again (a fresh membership,
  `join`) replaces it, audited as `link_key_replaced`. The linked network's enrollment token goes to
  a device only when it joins, never with renewals. Each credential carries an identifier (`jti`) and
  the device's identity at home (`did`), recorded by both networks; the linked network keeps one
  membership per home device and authority, so a new key replaces the previous membership (same
  name and address), and it can cap the authority's devices (`max_devices`).
- **Admission.** The linked network's control plane verifies the signature with the registered key,
  checks that the credential names the key being enrolled, and approves the device until the
  credential expires (never beyond the authority's maximum), with the requested groups the authority
  may assign, prefixed with its name (`msp:operators`). Group prefixes keep the authority's devices
  apart from the linked network's own groups.
- **Renewal and expiry.** The agent renews the credential through the home network when half of its
  lifetime has passed and presents it to the linked network over the tunnel. An approval that is not
  renewed lapses: the device falls back to *pending* and sees only the control plane. Revoking a user
  or a device in the home network therefore ends its access everywhere within one credential
  lifetime.
- **Policy.** What admitted devices may reach is the linked network's own policy (for example
  `msp:operators → servers`). The namespace firewall makes it one-way in practice. A later step
  makes access conditional on an approval by the linked network's administrators (time-bound access
  grants), which is where dual control plugs in.
- **Leaving.** The linked network ends the relationship at any time by deleting the authority: the
  enrollment key and every device it admitted are removed at once, and nothing in the linked network
  depends on the home network. It can also replace the authority's enrollment token
  (`ento admin authority token`): the old one stops working, admitted devices stay, and the home
  network imports the new one into its link.

What each side holds: the home network's database holds the authority private keys and the linked
networks' enrollment tokens (neither gives access without the other); the linked network holds only
the authority public key.

### On the device

- Each linked network has a directory under the agent's state (`links/<name>/`); `ento agent link`
  and `ento agent unlink` leave a request there and the running agent acts on it, so joining and
  leaving need no restart.
- The namespace is created by a small systemd template unit (`ento-netns@<name>`), outside the
  agent's sandbox: namespaces created inside the sandbox's private mount namespace would not be
  visible to the rest of the system. The agent needs `CAP_SYS_ADMIN` to enter them.
- The agent writes the linked network's peers, the service names the network publishes in its
  network map (`hosts`, from the control nodes' `--hosts`) and the device's own hostname into
  `/etc/netns/ento-<name>/hosts`, which `ip netns exec` presents as `/etc/hosts`, so peers and
  services can be reached by name without DNS.
- Services of the home network named by its control nodes (`--link-forwards`, `link_forwards` in
  the network map) are carried into every linked namespace by the agent: a listener on a loopback
  address of the namespace (`127.2.X.Y`, derived from the name so it stays put when forwards change, in the hosts file under the service's name) and a TCP
  connection per client from the home side to the service. A forward, not a route: only local
  processes in the namespace can use it, only towards the named services, and forwarded names take
  precedence over names published by the linked network.
- On request (`ento agent link --proxy ADDR NAME`, kept in `links/<name>/proxy`) the agent serves
  an HTTP proxy (CONNECT and plain HTTP) on a loopback address of its own namespace that opens
  connections only to the linked network's addresses, from inside its namespace, resolving names
  only through the namespace's hosts file.
- The namespace firewall (nftables table `inet ento`) accepts loopback, return traffic and relayed
  WireGuard frames from the linked network's control nodes; everything else inbound and all
  forwarding is dropped.

## Addressing

- One overlay range per deployment (default `100.64.0.0/16`, configurable).
- `x.x.0.0/24` is reserved for control nodes, `x.x.255.0/24` for enrollment addresses; peers are
  allocated from the rest.

## Storage

| Table | Contents |
|---|---|
| `control_nodes` | name, public key, public endpoint, overlay address, last seen |
| `peers` | public key, overlay address, hostname, OS, approved, admin, groups, observed endpoint, last seen |
| `enrollment_tokens` | temporary public key and preshared key, temporary address, expiry, redemption, pre-authorised groups/approval/admin |
| `policies` | allow rules between groups, one way (`one_way` false: an old rule both ways with posture checks), port rules, and the posture checks their source devices must pass |
| `posture_checks` | named posture requirements: disk encryption, firewall, Secure Boot, oldest system versions, oldest security patch per system (days), oldest report |
| `posture` | each device's latest report (facts, received at) and the stored results of the checks it must pass (and when they last changed) |
| `authorities` | other networks whose credentials admit their devices: name, public key, groups, maximum lifetime, enrollment token |
| `links` | linked networks this network's devices join: authority private key, imported token, groups, grant, credential lifetime, posture checks; statements change only their own columns, so an older control node keeps the checks it does not know |
| `routes` | networks behind gateway devices: name, networks, the gateway's name, whether it is an exit (no networks) and used by default, who added it and when |
| `dns_records` | internal DNS: names relative to the domain, their IPv4 address, who added them and when |
| `dns_forwards` | internal DNS: zones forwarded to name servers (IPv4), who added them and when |
| `checkins` | per device: the hashes of the check-in token issued last and accepted last, the machine's fingerprint, the endpoint and time of the last accepted check-in, the last suspicion of a copy and when |
| `approvals` | sign-in approvals: asking device, person (subject) and account name, service, the number and the three offered, expiry, state (pending, approved, denied, expired), who answered and when |
| `audit` | the network's audit (0.53): when, control node, action, device, person, overlay address, target, result; only ever added (a trigger refuses changes) |
| `link_posture` | per link and device that failed its checks: each failing check's outcome (failed, stale), and since when (deleted when it passes, when the link's checks change, with the link or the device) |
| `state` | network map version |

## Milestones

1. Control node (userspace WireGuard, API in the tunnel, PostgreSQL), agent for Linux (kernel
   WireGuard), enrollment, approval, network map with direct peer-to-peer connectivity. (done)
2. Policies (groups and rules), admin CLI, multiple control nodes with agent failover. (done;
   directions and ports enforced by the receiving device since 0.19; routes to networks behind a
   gateway since 0.24, exits since 0.25, internal DNS since 0.26)
3. Relay through control nodes (done), NAT traversal improvements (periodic direct probing).
4. Linked networks: multiple networks per agent in separate namespaces, authorities, access
   credentials. (done) Several networks on one device as equals, each joined with its own
   invitation (done on Linux, 0.51; macOS, Windows and the apps to come).
5. SQLite backend, packaging (container image, systemd unit), documentation for self-hosting.
6. More platforms: macOS and Windows (done), Android (done), iOS.
7. Device posture checks on policies and links (done); attested facts: Android (done, 0.30), TPM later.
8. Automatic updates (decided by the user on 2026-10-13: keep every deployment on the latest release,
   with the customer's approval where they want it, without people otherwise). Step 1 in 0.36: a
   signed manifest per release checked with the binary's own keys, never an older version
   (`internal/update`). Step 2 (deployments, not in ento): members through their
   environment's executor (`ento-update`). Step 3 in 0.37: control nodes keep and offer the release
   they run (`--updates-dir`, `--updates-except`), each device's map names it under the network's
   policy (`ento admin updates auto|approve X.Y.Z|off [--first GROUP --after HOURS]`), and Linux and
   macOS agents install it themselves, checked with their own keys, with a rollback after three
   failed starts (`internal/agent/selfupdate.go`). Next: Windows (through the service manager),
   phones by a prompt. The earlier idea, not taken as such (the user, 2026-10-05): self-updates spreading through
   the network. A release installed on one device starts a wave: a peer that sees a newer version
   on any other peer fetches it from that peer and takes it as its own update, if it is signed with
   the pinned release keys. Notes so far: on Linux with kernel WireGuard the tunnel, peers and filter
   live in the kernel, so replacing the binary (written beside, verified, renamed) and restarting the
   agent interrupts no traffic, only the agent's own DNS answers, relayed peers and map updates for
   about a second (none with the sockets handed to the new process, as nginx and HAProxy upgrade);
   in userspace WireGuard a restart costs one handshake. Open: who allows a version to spread
   (the trust model promises customer-approved updates: an admin's switch per network, a group first),
   never to an older version, the previous binary kept with a rollback when the new agent does not
   check in, members left to deployments, phones (an APK is replaced only with the person's consent
   unless the phone is managed), and that a signed-update channel is code reaching every device.

## Platforms

The agent's WireGuard interface is one of two backends behind the same interface (`tunnel`): the
Linux kernel's (netlink, wgctrl), or wireguard-go inside the agent on the system's TUN driver (utun
on macOS, Wintun on Windows, `/dev/net/tun` on Linux). Addresses and routes are set with the
platform's own tools (netlink, `ifconfig`/`route`, the IP Helper API). The in-process device answers
on the standard WireGuard control socket, so status tools work unchanged. Everything above the
interface (enrollment, network map, relay, SSO) is the same code on every platform; linked networks
need network namespaces and are Linux-only.

A kernel interface outlives the agent: stopping or restarting it leaves the interface working with
its last configuration, so restarts and upgrades interrupt nothing, not even connections bound to
the interface (a new interface would break those). While no agent runs, nothing updates it either:
a peer removed in the meantime is dropped by the control nodes and the other agents, not by this
device. `ento agent down` closes it for good: the service is stopped and disabled, and the
device's interfaces (its own and those of linked networks) are deleted, until `ento agent up`. An
in-process interface goes away with the agent.

Mobile systems own the interface: an app asks the system for a VPN (Android's `VpnService`), which
creates the TUN interface with the addresses and routes the app requests and hands over its file
descriptor. The agent then runs in the app's process (`agent.RunOnTUN`, bound with gomobile in
`mobile/`), with wireguard-go on that descriptor; it sets no addresses or routes itself. Two
details matter there:

- WireGuard's UDP sockets are handed to the system to be exempted from the VPN (`protect`), else a
  peer endpoint inside the network's range would be routed into the tunnel it carries;
- the agent's own HTTP connections to the control nodes must go through the tunnel, so the app
  starts the agent only once the system reports the VPN network (earlier sockets escape it).

Enrollment happens before there is an interface: the agent runs WireGuard on an in-process network
stack (as the control nodes do) just for the redeem call (`agent.EnrollInProcess`). SSO sign-in is
split into a start (link and code for the app to open) and a wait (`agent.StartLogin`).
