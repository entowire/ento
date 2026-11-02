# ento manual

Everything ento does and how to run it: installing agents, running control nodes, enrolling devices,
policies, routes, exits, DNS, device posture, the admin web interface, single sign-on, operators and
linked networks. The overview is the [README](../README.md); the architecture and security model,
[design.md](design.md).

## Install

Linux and macOS:

    curl -fsSL https://entowire.com/install.sh | sudo sh

Windows (PowerShell as Administrator; needs the OpenSSH client 8.1+, which Windows 11 has):

    [Net.ServicePointManager]::SecurityProtocol = 'Tls12'; irm https://entowire.com/install.ps1 | iex

Two WireGuard clients on one machine (since 0.38.2): if the agent's UDP port (51830) is taken, by
another network's agent or wg-quick, it takes the next free one and logs it, instead of failing to
start. The port only serves direct connections; peers learn it from the control nodes.

On Linux the installed service gets the TPM's group (`/dev/tpmrm0`, usually `tss`) as a
supplementary group, so its hardware key can open the TPM despite the service's narrow capability
set (0.38.2; before, `ento agent status` showed `hw key: unusable: ... permission denied`). Run
`sudo ento agent install` once to rewrite the unit of an agent installed before.

Help: `ento` alone lists what a device's person and an administrator need most; `ento help` shows
every command, and `ento help agent`, `admin`, `control` or `update` (or `ento agent` alone, and so
on) one part.

Uninstall (Linux and macOS; asks you to type `delete` first):

    curl -fsSL https://entowire.com/uninstall.sh | sudo sh

It runs `ento agent uninstall --purge`, removes what that leaves (the agent's nftables tables, an
exit's routing rules and table, `ento*` interfaces and namespaces), the state and the binary. The
device stays listed in its network until an administrator deletes it (`ento admin peers`, or the
admin page). Windows: `ento.exe agent uninstall --purge` as Administrator, then delete
`C:\Program Files\ento`.

The installers verify each release's SSH signature (`ssh-keygen -Y verify`, namespace
`ento-release`) against the release key pinned in the script (`release-signing.pub`), then its
SHA-256, before installing. Where OpenSSH is older than 8.1 and cannot verify signatures (Debian 10,
for example), `install.sh` checks a second signature with OpenSSL instead (`<file>.p256.sig`,
ECDSA P-256 over SHA-256, key `release-signing-p256.pem`, also pinned in the script); with neither
tool it stops without downloading. Both keys sign every release file. Each release also has a
manifest (`releases/manifest.json`, the current one's): its version, release time and every file's
SHA-256 and size, signed with both keys (namespace `ento-manifest`). `ento update check` (from 0.36)
checks it with the keys built into the installed binary, never with keys fetched beside it, and
never takes an older version as an update (`internal/update`; `ento update keys` prints the keys'
fingerprints). From 0.37 on, control nodes with `--updates-dir` offer their own release to the
network's devices (`ento admin updates`), and Linux and macOS agents install it themselves, checked
the same way, with a rollback if it does not come up. It then installs `/usr/local/bin/ento` (Windows: `C:\Program Files\ento`, with
`wintun.dll` and `ento-tray.exe`, see [Signing in on Windows](#signing-in-on-windows)). With `ENTO_JOIN=<domain>` they also install the agent service and enroll with the
words an administrator reads out (see Enrollment by words); `install.sh` also takes
`ENTO_TOKEN_FILE=/path/to/token`. Then `ento agent install --join <domain>` or, Linux and macOS
only, `ento agent install --token-file <token>` (root or Administrator), and `ento agent login`.
Phones and Windows take words only (0.23.3): they are people's devices, and a token is a file that
lingers; tokens are for Linux and macOS machines that automation enrolls (servers, prepared
images). An enrollment only takes on a device that is not enrolled yet: on an enrolled device
`install` refuses it (0.10.1), and `install --force` forgets the old enrollment (as
`uninstall --purge`) and enrolls anew. State: `/var/lib/ento` (Linux), `/Library/Application Support/ento`
(macOS), `C:\ProgramData\ento` (Windows, SYSTEM and Administrators only). Logs: the journal (Linux,
`journalctl -u ento-agent`), `/Library/Logs/ento-agent.log` (macOS), `C:\ProgramData\ento\agent.log`
(Windows, since 0.32.1, `Get-Content C:\ProgramData\ento\agent.log -Tail 50` as administrator; the
previous 5 MB in `agent.log.1`). Running `ento.exe agent run` by hand on Windows fails at WireGuard's
control pipe (only SYSTEM may own it): read the service's log instead.

`ento agent down` turns the tunnel off: the service stops and stays off, across reboots and
re-installs too, and on Linux the kernel's WireGuard interfaces (the device's own and those of
linked networks) are removed. `ento agent up` turns it on again. Merely stopping or restarting the
service leaves a kernel interface in place, working with its last configuration, so that restarts
and upgrades interrupt no connection; `down` is what closes it (elsewhere the interface lives in
the agent and goes away with it). `ento agent run` runs the agent in the foreground instead of as
a service (`up` with a token does the same, as it always did); `down` stops that one too (Linux,
macOS).

On Linux with NetworkManager (desktops), `ento agent install` writes
`/etc/NetworkManager/conf.d/90-ento.conf` (0.22.1; `uninstall` removes it): interfaces named
`ento*` are left unmanaged, so they are not listed in the desktop's network menu. Before that, its
Disconnect took the interface's address away and the device reached nothing until the agent
restarted. The agent also checks its interface every 5 seconds and puts a removed address back, or
brings it up again, whoever changed it (logged as `... had lost its address ...`).

Android: install `ento-android-<version>.apk` from the release (check its signing certificate
first, see below), join with the domain and the words your administrator reads out (the only way
since 0.23.3), or **Scan the QR code** of both their admin page shows (0.30; the app looks the
domain's record up as for typed words and refuses it unless its fingerprint is the code's, then
shows **Join DOMAIN**), **Connect** (Android asks once to allow the VPN), then **Sign in** if
the deployment uses single sign-on (the button is there only while the device is not approved or
its sign-in has ended; the app shows the device's groups once it is). Only the network's own range goes through
the VPN; the phone's other traffic is untouched. Always-on VPN (Android settings) works too.

## Android app

`android/` is a small Java app: `EntoVpnService` creates the VPN interface with the device's
address and the network's route and hands its file descriptor to the agent; `MainActivity` enrolls
with the domain and the words an administrator reads out, or with the QR code of both
(`ScanActivity`), connects and signs in. Its one library is ZXing's core (0.30, a single jar without
dependencies), which decodes the camera's frames; the camera code is the app's own (Camera2, no
`androidx`), and the camera permission is asked for when someone scans. Every artifact
Gradle downloads, the build plugin included, is checked against the SHA-256 in
`android/gradle/verification-metadata.xml` (after changing a dependency:
`gradle --write-verification-metadata sha256 assembleDebug assembleRelease`, then review the diff). The agent is the same Go code as on the
other platforms, bound with gomobile (`mobile/`, pinned in `go.mod`):

- enrollment runs WireGuard on a network stack inside the agent (no interface needed);
- the running agent drives wireguard-go on the VPN's interface (`agent.RunOnTUN`); WireGuard's own
  sockets are exempted with `VpnService.protect`, so endpoints inside the network's range (carrier
  NAT uses 100.64.0.0/10) never loop into the tunnel;
- the service starts the agent only once Android reports the VPN network: sockets opened before
  would reach the control nodes outside the tunnel;
- while the tunnel is up, the app shows a notification for each sign-in approval waiting for the
  phone's person (`Approvals`, no push service): since 0.34 the network map says how many wait
  (the phone's map long poll returns early when that number changes) and the app fetches them only
  then, so the phone keeps one request open instead of two (against older control nodes it long
  polls the approvals itself);
  `ApprovalActivity` offers the three numbers and confirms with the platform's BiometricPrompt
  (fingerprint, or the screen lock; Android 8 and 9: the screen lock), with no added library;
- every posture report carries the phone's key attestation (`Attest`, 0.30): a key the Keystore
  made in the phone's secure hardware for a challenge derived from the device's WireGuard key,
  its certificate chain, and its signature of the report's time (see Device posture);
- logs (0.30.3): the agent's and the app's lines go to Android's log and to `files/logs/ento.log`
  in the app's storage (rotated at 1 MiB, one older file kept); a Go panic writes its report to
  `crash-go.txt` (`debug.SetCrashOutput`), a Java crash to `crash-java.txt`, and at each start the
  app records why its previous runs ended as Android says (`ApplicationExitInfo`, Android 11 and
  later: crash, native crash, not responding with its trace, low memory, killed) in `exits.txt`.
  **Send logs** shares all of it, with the device's description and the agent's status, as one
  file through Android's share sheet (`LogsProvider`, no library); nothing leaves the phone
  otherwise; the app's version is shown at the bottom of its screen;
- Android fixes a VPN's routes and DNS server when it is created, so the service creates it again
  when the agent wants others (an exit, a route, its resolver as DNS server). Since 0.30.5 it starts
  with the routes and DNS server of this enrollment's last session, so a connection no longer comes
  up, drops and comes up again a few seconds later; only the first one after enrolling, or a real
  change, recreates the VPN;
- battery (0.34): every packet wakes a phone's radio, which then stays on for seconds. Phones are
  quiet: their agent sends no WireGuard keepalives (other devices send one every 25 s to each
  peer), every other agent and the control nodes send them none either (the map marks phones,
  `quiet`), and the map's long poll every 25 s is what keeps the phone's way through its NAT
  to a control node open. An idle peer without a session is not counted as a failed direct path:
  a peer is relayed only when something was sent to it and no handshake followed within 20 s. A
  phone that has not spoken to a peer for a while is reached through a fresh handshake, which costs
  the first packet a round trip, or the relay when its NAT refuses the peer.

Build (toolchain pinned in `scripts/android.env`: JDK 21, Android SDK 36, NDK, Gradle):

    scripts/android-toolchain.sh        # once: ~/opt/android (or $ANDROID_TOOLCHAIN)
    scripts/build-android.sh            # dist/ento-android-<version>.apk

With `ENTO_ANDROID_KEYSTORE_B64` and `ENTO_ANDROID_KEYSTORE_PASSWORD` in the environment the APK is
release-signed (key `ento`, PKCS#12); without them it is debug-signed, for testing only. Android
only accepts updates signed with the same key. The published APK's certificate SHA-256 is in
`android-signing.sha256`; check it before installing:

    apksigner verify --print-certs ento-android-<version>.apk | grep SHA-256

## Build and release

    scripts/build.sh linux/amd64 linux/arm64 darwin/arm64 windows/amd64   # dist/, static and reproducible

Windows builds are zips (`ento.exe`, `wintun.dll` and Wintun's licence); the DLL is the official,
signed build pinned by version and SHA-256 in `scripts/wintun.env`.

Releases are tags `ento-vX.Y.Z` on a clean tree. The entowire repository publishes them with
`scripts/publish-site.sh`, which builds, signs (the key never touches the disk: it is loaded into
ssh-agent from SOPS; the P-256 key only in /dev/shm while signing), checks both signatures with the keys embedded in the installer, and deploys
`https://entowire.com/releases/<version>/`. The release includes the Android APK, signed with the app
key and, like every other file, with the release key (`.sig`) and a `.sha256`.

Upgrade agents (and the Android app) before control nodes, at least across 0.11: agents sign their
calls from 0.11 on and work with older control nodes, but control nodes from 0.11 on refuse
unsigned calls, so an older agent can no longer sign in (once its SSO session ends it loses access)
or renew its linked networks (they lapse within the link's TTL), an older CLI cannot administer,
and each refusal from an admin device is audited as `unsigned_call`. In linked networks, upgrade
the home network's devices before its control nodes; the linked network's control nodes can follow
in any order. Posture checks (0.13) need every control node and agent of a network at 0.13 or later
before a policy requires one (see Device posture). From 0.15 the control nodes' plain API answers
only requests addressed to an IP address with JSON bodies (DNS rebinding), which is how agents
call it.

## Run a control plane

Each control node needs a WireGuard key, a public UDP port and access to a shared PostgreSQL
database. Control nodes run unprivileged (userspace WireGuard, no TUN, no capabilities).

    ento genkey > control.key && chmod 600 control.key
    export ENTO_DATABASE_URL='postgres://ento:...@db1:5432,db2:5432/ento?target_session_attrs=read-write'
    ento control run --name ctl-1 --key-file control.key \
      --listen-port 51821 --endpoint 203.0.113.10:51821 --network 100.64.0.0/16

Run as many nodes as you like against the same database; each gets its own overlay address
(`100.64.0.1`, `100.64.0.2`, ...), and agents fail over between them.

### Control nodes that move

Devices hold the control nodes' keys, endpoints and overlay addresses, and learn changes from the
network map, which only a control node gives. If every control node gets a new public address at
once (rebuilt somewhere else) while a device is away, the device has nowhere to fetch that map
from. So (0.29) give the control nodes the domain that publishes the network record (see
[Enrollment by words](#enrollment-by-words)):

    ento control run ... --record-domain example.com

The network map names the domain, and devices keep it. A device that has reached no control node
for 5 minutes looks up `_ento.<domain>` (then every 10 minutes while that lasts) and takes the
endpoints it gives for the keys the device already trusts. Keys and overlay addresses never change
this way: a forged record only sends the device's handshakes where nobody holds a control node's
key. Moving control nodes is then: start them at their new endpoints, publish the record again
(`ento admin record` or `ento control record` prints it; its fingerprint covers the keys only, so
it stays the same), and devices find them within about 15 minutes. Each control node checks at its
start and every hour that the record names it at its endpoint, and logs when it does not
(`network record _ento.example.com names this node at ..., not ...`). In the Android app the
record is looked up through the DNS servers of the phone's network, as when joining with words.
Not for linked networks: a device's membership in another network is renewed through its home
network instead.

## Enroll the first administrator

The first token is created directly in the database:

    ento control token --admin --approve --groups admins --ttl 15m --out admin.token

Other bootstrap operations work the same way, on a control node with `ENTO_DATABASE_URL`, for
deployments that are set up by automation before any administrator has a device:

    ento control allow servers servers
    ento control allow --one-way --ports tcp/443 msp:operators servers   # direction and ports (0.19.1)
    ento control authority add msp --key entoa1:... --groups operators > msp.token
    ento control admin ops-laptop          # make a device an administrator (--off takes it back)

Each of these (`token`, `allow`, `authority`, `admin`) logs what it changed to the system log, as the
control nodes log theirs (0.35): `audit: action=control_cli by="<user behind sudo> (cli)" from=local
target="ento control ..." result=ok|failed`, so a change made around the control nodes is recorded
too. A device refused a linked network's credential because the person who may join is no longer
signed in on it (their session ended) is logged as such (0.35): `target="link <name>: no person
signed in on this device (their session ended)"`; a device whose groups may never join, as before,
`target="link <name>"`.

On the administrator's machine (root):

    ento agent install --token-file admin.token   # enrolls, then runs as a service

## Add devices

From an enrolled admin peer, as root (on Windows, in a PowerShell run as administrator):

    ento admin token --groups servers --ttl 1h --out server.token
    # on the device:
    ento agent install --token-file server.token

### Enrollment by words

Where a file is awkward to hand over (someone on the phone, a laptop being set up), an
administrator can read out a domain and five words instead (0.20):

    sudo ento admin token --name laptop-7 --words      # five words, single use, 1 h (--ttl up to 24h)
    # on the device (Windows: an administrator's PowerShell, without sudo):
    sudo ento agent install --join example.com         # shows the network and its fingerprint, asks for the words
    curl -fsSL https://entowire.com/install.sh | sudo ENTO_JOIN=example.com sh   # the same, installing ento first

The domain publishes the network's record, the TXT record `_ento.<domain>`, as `ento admin
record` prints it (on a control node: `ento control record`):

    _ento.example.com. TXT "ento1 net=100.64.0.0/16 c=<public key>,<endpoint>,<overlay address> c=..."

It names the overlay range and every control node (public key, public UDP endpoint, overlay
address): what every enrolled device holds already. Publish it again when a control node is added
or its key or endpoint changes; words made before a key changes stop working. With
`--record-domain`, devices that lose their control nodes look for them there
([Control nodes that move](#control-nodes-that-move)). `--record TEXT`
gives the record directly where there is no DNS. The admin page makes words too (**Add a device**, **Five words**).

The control node draws the words from the EFF large wordlist (7,772 words, leaving out the four
with a hyphen: 64.6 bits; the list is embedded unchanged, CC BY 3.0 US, Electronic Frontier
Foundation) and stretches them with Argon2id (256 MiB, 8 passes, about a second; salt: SHA-256 of
the label `ento-words-v1`, the range and the control nodes' keys) into the token secret, from which
the temporary WireGuard key, the preshared key and the enrollment address derive as for any token.
It stores what a token stores, never the words. The device reads the record, asks for the words
(any case, any separator; from the terminal, or a line of stdin; never from the command line),
derives the same secret and enrolls as with a token: the control plane only, approval and groups
come from the token's options or the sign-in. The fingerprint (16 hex digits of the same hash)
lets the person check the record against what the administrator sees.

What protects the words:

- Guessing online is hopeless: each guess costs an Argon2id, and a handshake with a wrong key gets
  no answer at all.
- Offline, only whoever answers the device's first handshake (with a forged record naming their
  server) gets something to test guesses against: the temporary public key in that handshake. Each
  guess still costs a 256 MiB Argon2id, against 2^64.6 words, before the words expire (1 hour by
  default, a day at most).
- A forged or stale record only keeps the device from enrolling: without the preshared key, which
  comes from the words, no other server completes the handshake. Even a device enrolled somewhere
  else would sign in there with passkeys bound to the real identity provider's name, which fail.
- In a DNSSEC-signed zone, a validating resolver refuses a forged record.

In the Android app (0.21.1): **Or join with the words**, the domain, **Find the network** (it shows
the fingerprint), then the words and **Join**. Go cannot find Android's DNS servers by itself, so
the app passes those of the phone's active network (`agent.ResolverVia`); the phone's resolver, not
the app, decides whether DNSSEC is checked, so the fingerprint is the check there.

With the phone in front of the administrator, a QR code saves the typing (0.30): the admin page
shows one beside the words (for its own domain, the page's name without `net.`), and so does

    sudo ento admin token --words --qr [--domain example.com]   # default: the control nodes' --record-domain
    ento control token --words --qr --domain example.com          # on a control node

(the terminal only: never into a file or a pipe). It holds a join code, the domain, the record's
fingerprint and the words in capitals (QR alphanumeric mode, a small code):
`ENTO1:EXAMPLE.COM:8A4D-0034-38BF-6588:ABACUS ZOOM GUMDROP DROPBOX SNOWDROP`. **Scan the QR code**
in the app reads it with the camera, looks the domain's record up as for typed words, and refuses a
record whose fingerprint is not the code's ("do not join"); otherwise it fills in the words and
offers **Join DOMAIN**, so the person sees which network they join. The code is as secret as the
words (single use, an hour by default): shown on a screen to the person holding the phone, never
sent as a picture, which would put the words in writing. Tokens never come as QR codes.

A new device reaches nothing until it is approved and a policy allows it:

    ento admin peers
    ento admin approve 2
    ento admin allow admins servers            # both directions; "*" matches every peer

Control nodes know a device by its overlay address, which proves the device but not the program on
it: every process, container or app there shares the address. Calls that act with the device's
rights (administration, sign-in, credentials for linked networks) are therefore also signed with
the device's key, which only the agent, root or an administrator can read (X25519 between the
device's key and the control node's, HKDF, HMAC-SHA256 over the request; package `reqsig`). An
unsigned call is refused and audited as `unsigned_call` with the device's role. A signed call sent
twice (the same nonce) is refused too and audited as `signed_call_repeated` (0.28.1): it carries the
device's own signature, as when an HTTP client resends a request on a dropped connection, so it is
no program without the key.

Other commands: `ento admin tokens` (tokens that can still be used, with who created them),
`revoke ID` (a token), `suspend ID` / `resume ID` (a suspended device is removed from the control
nodes' WireGuard altogether: it reaches nothing, not even the control plane or the identity
provider, and no approval or sign-in restores it until it is resumed), `groups`, `delete`,
`policies`, `disallow`.

### Direction and ports

A policy lets the devices of its source open connections to the devices of its destination, and
(two-way, the default) the reverse. From 0.19 a policy can be one-way and limited to ports:

    sudo ento admin allow operators servers --one-way --ports tcp/22,tcp/443,icmp
    sudo ento admin policy 3 --one-way --ports tcp/22        # an existing policy
    sudo ento admin policy 3 --two-way --ports all           # back to everything, both ways

Port rules are `all` (the default), `tcp`, `udp`, `tcp/22`, `tcp/8000-8100`, `udp/53` and `icmp`
(echo requests: ping), at most 64 per policy. Several policies between the same devices add up.
Answers always pass: a device that opens a connection gets its answers (TCP: every segment but an
opening SYN; UDP: datagrams from the address and port it sent to, until 2 minutes after its last
one; ICMP other than echo requests: replies and errors). Traffic from the control nodes (the
control plane, relayed packets) always passes.

The device that receives a connection enforces the rule, so a peer whose own agent is modified
gains nothing. The control node sends each device, for every peer in its map, what that peer may
open on it, and the agent drops the rest of what arrives through the tunnel: with Linux kernel
WireGuard in an nftables table of its own, `inet ento-filter` (a prerouting chain that judges only
packets arriving on the ento interface, accepts established connections, and is put back within a
minute if something removes it; it runs before the system's own DNAT, so a port the system
redirects, as a firewall that sends 443 to a proxy's port, is judged as the 443 the peer opened;
since 0.20.1, before that an input chain matching conntrack's original port, whose rules made the
firewall fact unknown); in the agent's own WireGuard (macOS, Windows, Android, Linux with
`--userspace`) in the packet path. The system's firewall still applies to what the filter lets
through. Both devices of a one-way policy are still in each other's map (one has to answer the
other).

What the filter refuses is dropped silently unless the agent runs with `--log-drops` (0.29; `ento
agent install --log-drops` keeps it in the service, and on Linux later installs keep it until
`--log-drops=false`): each new connection refused (TCP: an opening SYN; anything else that is not
an answer) is logged, at most 20 a minute, so a device probing others' ports leaves a trace. With
kernel WireGuard the kernel logs it (two rules before the chain's final drop, `limit rate
20/minute burst 20 packets log prefix "ento-filter drop: " level info`), in the kernel's usual
format:

    ento-filter drop: IN=ento0 OUT= MAC= SRC=100.64.1.5 DST=100.64.1.3 LEN=60 ... PROTO=TCP SPT=40312 DPT=22 ...

(the kernel logs it only from the host's network namespace, unless `net.netfilter.nf_log_all_netns`
is 1); with the agent's own WireGuard, the agent writes the same fields:

    ento-filter drop: IN=ento0 SRC=100.64.1.5 DST=100.64.1.3 PROTO=TCP SPT=40312 DPT=22

Agents older than 0.19 do not enforce direction or ports: they accept everything from the peers in
their map, as before. Adding or changing a policy with a direction or ports answers with a warning
naming the devices that receive connections through it and run an older agent or have never
reported. Control nodes older than 0.19 do not know the rules: they add the policy two-way and for
every port, and `allow` then fails, saying so and how to remove it; `policy ID --ports` changes
nothing and says the control plane is too old. `ento admin policies` shows `->` (one-way) or `<->`
and the ports; in the admin interface, adding a rule has a ports field and a one-way box, and each
rule has **Direction and ports**. Operators may change the direction and ports of a
policy that requires no posture checks; changes are audited as `policy_rules` with what the policy
was, and `policy_added`/`policy_deleted` lines carry the direction and ports.

### Routes (networks behind a gateway)

A route makes a network that has no ento agent on its machines, such as an office LAN, reachable
through one device on it, its gateway (0.24): the classic VPN to the office, with policies.

    # on a Linux machine in the office (a small box or a VM): join like any device
    sudo ento agent install --join example.com
    # an admin, once:
    sudo ento admin route add office 192.168.10.0/24 --via office-gw     # several networks: a,b
    sudo ento admin allow staff route:office --ports tcp/445,tcp/3389    # who, and on which ports
    sudo ento admin routes | route delete office

The devices a policy lets reach `route:NAME` get the gateway as a peer that carries the route's
networks, and their agents route those networks into the tunnel (on Android the VPN is created
again when they change). The gateway forwards what each of them may open there and nothing else,
under its own LAN address (masquerade: the office router needs no route back), and the LAN only
answers: it opens nothing into the network, even with a route to it. Nobody reaches a route without
a policy to it: a policy between groups, `*` included, never does, and a route is never a source.
Ports, posture checks and the admin page (**Routes**, **Allow…** to make the policy) work as for
any policy. A device that is itself on a network overlapping a route (in the office) leaves the
route out and reaches the LAN directly; `ento agent status` shows the routes a device uses
(`routes:`) and those it serves (`gateway of:`).

The gateway runs Linux with the kernel's WireGuard (not `--userspace`); its agent turns on IPv4
forwarding and keeps the forwarding rules in its own nftables table (`inet ento-filter`: a
postrouting masquerade and a forward chain beside its input filter). A firewall on the gateway that
drops forwarded traffic (firewalld does by default) must let traffic from the ento interface out to
the LAN. Routes are for admins; adding and deleting them is audited (`route_added`,
`route_deleted`). Gateways older than 0.24 forward nothing, and routes list a warning until theirs
runs 0.24. A route's networks are IPv4, may not overlap the network's range or another route, and a
route to everything (all traffic through a gateway) is not a route: it comes as an exit.

Groups whose devices must never be gateways (0.41): `ento control run --no-gateways servers`. Then a
route or exit through a device of such a group is refused, a route that already goes through one
(or whose gateway joins such a group later) is never handed to devices, and the dashboard leaves those
devices out of its gateway list. For the operator's own machines enrolled in a network they serve,
such as a provider's infrastructure in a customer's network.

### Exits (all internet traffic through a gateway)

An exit is a route without networks (0.25): the devices a policy lets use it may send all their
internet traffic through its gateway, as OpenVPN's `redirect-gateway` does, for example so that it
leaves from the office's address.

    sudo ento admin route add internet --exit --via office-gw            # --default: used unless turned off
    sudo ento admin allow staff route:internet                           # who (--ports: only those)
    sudo ento agent exit internet      # on a device: use it; off: none; default: the one used by default
    sudo ento agent exit               # the choice, and the exits offered

Each device decides: an exit is offered to the devices the policy names, and used once the device
chooses it (`ento agent exit NAME`, or the button in the Android app), or, for an exit added with
`--default`, unless it turns it off (`ento agent exit off`). In use, everything but the device's
own networks (its LAN stays reachable directly) goes into the tunnel to the gateway, and names are
resolved there: the gateway answers DNS on its overlay address, passing queries to its own resolver
(a firewall on the gateway that drops input must accept TCP and UDP port 53 on the ento interface:
the agent's filter already lets only the exit's devices reach it; otherwise traffic flows through
the exit but no name resolves).
IPv6 is blocked while an exit is in use, since it would leave beside it. A device that is an exit
uses none.

The gateway forwards to public addresses only: never into private, shared or special ranges
(`10/8`, `172.16/12`, `192.168/16`, `100.64/10` (the network itself), `169.254/16` (link-local,
a cloud's metadata endpoint), multicast, ...), nor to its own addresses; a private network takes a
route of its own, with its policy. The gateway's requirements are a route's (Linux, kernel
WireGuard, ento 0.25 or later; a firewall that drops forwarded traffic must let it out); its
traffic leaves masqueraded behind the gateway's address.

On the device: Linux and Android (0.25). Linux marks WireGuard's own packets and adds two routing
rules and a table (`ip rule` priorities 31770 and 31771, table and mark 30835, as wg-quick does,
with other numbers), and points systemd-resolved at the gateway for every name (routing domain `~.`
on the interface; without systemd-resolved, names go where they went before, which the agent logs).
macOS and Windows leave an offered exit unused for now, with a log line. It is no kill switch:
while the agent is stopped or restarting, traffic takes its normal path; a captive portal (a hotel's
sign-in page) needs the exit off. `ento agent status` shows the exits offered (`exit:`, which one is
in use) and, on a gateway, `exit for:`.

### Internal DNS (names for devices and office machines)

With a domain on the control nodes (`ento control run --dns-domain example.internal`, the same on
each; 0.26), devices resolve each other by name, `NAME.example.internal` (their device names), and
the names administrators add:

    sudo ento admin dns add nas.office 192.168.10.5          # nas.office.example.internal
    sudo ento admin dns forward office.example.com 192.168.10.1   # names in a zone: the office's own DNS
    sudo ento admin dns                                      # the domain, names and zones
    sudo ento admin dns delete nas.office | dns unforward office.example.com

Each device resolves what it can reach: itself, the devices in its network map, and an added name
when it reaches the address (a device it reaches, a network behind a route it reaches, or an
address outside the network and its routes); a forwarded zone when it reaches one of its servers
(an office DNS server takes a policy to its route that allows `udp/53`). A device name wins over an
added name. Names under `.internal` (reserved for private use) never collide with public ones.

Every agent answers them itself, on its overlay address, port 53: names in the domain from its
network map, forwarded zones from their servers through the tunnel, the names the control nodes
serve (the identity provider's and the admin interface's, 0.30.1, also before approval and without
a domain), and, while an exit is in use, every other name through the exit's gateway. On Linux, systemd-resolved sends it the domain and the
forwarded zones (routing domains on the interface; every name while an exit is in use); without
systemd-resolved the agent logs what to set. On Android the VPN names the agent as its DNS server
(an address no device gets, x.x.0.255, answered inside the agent, since apps cannot listen on port
53), and the agent asks the DNS servers of the phone's other network for every other name; Private
DNS in strict mode bypasses it. macOS and Windows: not yet. Linked networks get the names in their
namespace's hosts file. `ento agent status` shows `dns:` when the device answers them.

Adding and deleting names and zones is for admins and audited (`dns_record_added`,
`dns_record_deleted`, `dns_forward_added`, `dns_forward_deleted`); the admin page's **Names** page
lists every name devices resolve (devices' names, read-only, then the added ones) and changes them.

### Device posture

A policy can require checks of the devices it comes from: disk encryption, a firewall, Secure Boot
(on phones: an attested verified boot, 0.30), real-time anti-malware (0.17, `--antimalware`), a
minimum system version, a recent security patch (phones, 0.30, `--max-patch-age`), and a recent report. A source device that fails one of them is left out
of that policy until it passes again (fail closed: no report, a report older than the check
allows, or a fact the device could not find out all count as failing). Devices that no such policy
comes from are not affected, and existing policies require nothing.

    sudo ento admin posture add laptops --disk-encryption --firewall \
      --min-os linux=6.1,windows=10.0.22631,darwin=14.0,android=13 --max-age 30m
    sudo ento admin allow laptops servers --posture laptops      # a new policy
    sudo ento admin policy 3 --posture laptops                     # an existing one (none: no checks)
    sudo ento admin posture                                        # list; posture delete NAME

Agents (0.13 and later) report what they find out about the device when they start, when it changes
(they look every minute) and every 10 minutes, in a call signed with the device's key, to every
network the device is in (linked networks too: a network an authority admits devices into can
require checks of them). Collecting never holds up the tunnel; it runs fixed commands only, each
with a timeout:

| Fact | Linux | macOS | Windows | Android |
|---|---|---|---|---|
| system version (`--min-os`) | kernel release (`/proc/sys/kernel/osrelease`), distribution from `os-release` | `sw_vers -productVersion` | 10.0.build.revision (`RtlGetVersion`, registry `UBR`); Windows 11 is 10.0.22000 and later, so `windows=10.0.22631` (23H2), never `windows=11` (refused) | release and SDK level (the app) |
| disk encryption | the file system at `/` is on a device-mapper device that encrypts (`/sys/block/*/dm/uuid` `CRYPT-LUKS1/LUKS2/PLAIN/BITLK/...`), directly or under LVM (found through `mountinfo`); on ostree systems (Fedora Silverblue and Kinoite, CoreOS), where `/` is a composefs overlay, the file system at `/sysroot` (0.19.3); dm-verity and dm-integrity protect integrity only and do not count | `fdesetup status`: FileVault is On | BitLocker protection of the system drive (WMI `Win32_EncryptableVolume`, else `manage-bde -status`) | storage encryption with the user's key (`ACTIVE_PER_USER`, or full-disk `ACTIVE`) |
| firewall | an nftables base chain at the input hook that drops by default, or whose last rule drops or rejects everything (firewalld; iptables-nft and ufw set the policy); else legacy `iptables -S INPUT` read the same way. Rules that drop some packets only (fail2ban's, `ct state invalid drop`) in a chain that accepts the rest do not count, nor do chains at other hooks; a chain google/nftables cannot decode (rules with `ct original`, as firewalld's rich rules with a port) is read with `nft -j` (0.20.1, noted in the agent's log and `ento agent posture`) | `socketfilterfw --getglobalstate` enabled | every profile (domain, private, public) on, group policy first | unknown |
| secure boot | the `SecureBoot` EFI variable; no EFI: off | unknown | registry `UEFISecureBootEnabled` | Android Verified Boot as the phone's secure hardware attests it (0.30, below): on for a verified boot (the system its maker signed) with the bootloader locked; never what the app says |
| security patch (0.30, `--max-patch-age`) | not reported | not reported | not reported | the oldest of the system's, vendor image's and boot image's patch levels the hardware attests; without an attestation that counts, the app's `SECURITY_PATCH` |
| screen lock | unknown | unknown | unknown | a screen lock is set (reported, not checked yet) |
| anti-malware (0.17) | on when a known real-time scanner runs (process names: ClamAV's on-access `clamonacc`, Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Sophos, Trend Micro Deep Security, Bitdefender GravityZone); else unknown (another product may run) | XProtect present (it cannot be turned off without disabling System Integrity Protection) | an antivirus registered with Windows Security has real-time protection on (`root/SecurityCenter2`, client editions); server editions: Microsoft Defender's `AntivirusEnabled` and `RealTimeProtectionEnabled` | unknown |

Versions compare numerically, part by part (`6.10` is newer than `6.9`; `6.8.0-142-generic` is
6.8.0); systems a check does not name are not limited by its `--min-os`. `--max-age` is 15 minutes
to 30 days (default 30 minutes). `ento agent posture` prints what this device reports, collected
now (`--json` as sent); `ento agent status` shows the last report the network took and the checks
the device fails; `ento admin peers` has a posture column (`enc+ fw+ sb? linux 6.8.0-142-generic (2m ago)`)
and one for the checks a device fails (`av` is anti-malware); for a linked network, `ento agent status` lists the checks
the device fails there under the linked networks. The Android app shows the failing checks ("This device needs
attention: disk not encrypted"). In the admin interface, devices show their report and each check
(solid where a policy requires it), the **Access** page's **Device checks** add and delete checks (and shows which
policies and links require each), and policies and links show and set theirs (a link also lists
the devices that would be refused now).

A device left out of a guarded policy can still be connected by another policy, so **any other
policy that connects the same devices without the checks makes them moot**, whoever added it: the
same groups in the other order (`allow servers laptops` beside `allow laptops servers --posture
enc`), or `*` on either side. Adding or changing a policy answers with a warning for each such pair
(the CLI prints it, the admin interface shows it), going by group names: a device that is in
several groups can still be let through by a policy of another of its groups. The warning counts
every policy as two-way and allowing every port (agents older than 0.19 enforce neither).

Checks, and attaching them to policies, are for admins: operators list checks, add and remove
policies without checks, but neither change a policy's checks, nor remove a policy that has some,
nor add a policy that would connect a guarded policy's devices without its checks (refused and
audited as `policy_added ... (would bypass policy N)`, `result=denied`). Operators can still change
the groups of ordinary devices, and so move one into a group an unguarded policy lets through.

Checks that policies require do not cover the device's memberships in linked networks. A **link**
can require checks of its own: the home network then issues or renews a credential for that linked
network (and, to a device joining, its enrollment token) only while the device passes every one of
them, evaluated as for policies (fail closed: no report or one older than the check allows is
refused; where a policy requires the same check, a failure it still holds counts too):

    sudo ento admin link create acme --groups operators --grant operators --posture laptops
    sudo ento admin link update acme --posture laptops,boot        # none: no checks
    sudo ento admin links                                          # POSTURE column

A refused device is told which checks it fails and why; `ento agent status` shows them under its
linked networks (`link acme: FAILS check laptops: disk not encrypted, which this network's link
requires`), and the agent keeps asking (every 30 seconds while joining, every minute while renewing;
within seconds, after reporting at once, when the only reason is a missing or old report). Right
after it starts, the agent waits up to 15 seconds for the home network to take its first report
before asking, so a device that was off longer than its credential lasted is not refused at boot.
Credentials already issued are not withdrawn by the home network: they expire (renewed at half
their lifetime: 10 minutes for devices signed in with SSO, else the link's `--ttl`), and the linked
network then sets the device back to pending. The device does not wait for that (0.35.1): when the
home network refuses a renewal, its agent drops its peers in that linked network at once and asks
the linked network's control nodes to withdraw its approval (`credential_ended` in their audit), and
a renewed credential brings it back. Each change of a check's outcome is audited once, whichever control node
the device asks, as for policies: `link_posture_failed` (`target="peer 7 laptop-1 100.64.1.9
link=acme check=laptops reason=disk not encrypted"`, `result=denied`) when a check starts failing
over the device's facts (also after it failed for want of a report, and for each further check that
starts failing); `link_posture_stale` (`reason=no report in 30m`, `result=ok`) when it fails only
for want of a recent report; `link_posture_passed` when it passes again; `link_posture` when an
admin changes a link's checks (with what they were), `link_created` carries them. Only admins set a
link's checks (like links themselves); a check a link requires cannot be deleted. Links without
checks behave as before. Each linked network can also require its own checks of the devices its authority admits
(agents report there too).

Control nodes evaluate the checks each device must pass when it reports, when policies change and
every 10 seconds (reports age), store the results, and change the network maps only when a result
does. A device reports at most every 30 seconds (later reports are refused with 429, whichever
control node they reach), and a device that starts failing a check over its facts keeps failing it
for at least 2 minutes, even if it reports passing facts meanwhile: a device that flips a fact on
every report cannot make the whole network fetch new maps. An agent whose network map says the
network holds no recent report (after the device slept) reports again at once.

Each change is audited once: `posture_failed` (`target="peer 7 laptop-1 100.64.1.9 check=laptops
reason=disk not encrypted"`, `result=denied`) when a required check starts failing over the
device's facts; `posture_stale` (`reason=no report in 30m`, `result=ok`) when it fails only
because there is no recent report (a laptop asleep, an agent older than 0.13; not for a device
enrolled a moment ago that has yet to report), so that alerts on `posture_failed` are about devices
out of policy; `posture_passed` when it passes again; `posture_check_added`,
`posture_check_deleted`, `policy_posture` (with what it was), and `policy_added`/`policy_deleted`
carry the policy's checks.
Upgrade every control node and agent before requiring checks: an agent older than 0.13 reports
nothing, so its device fails every check, and a control node older than 0.13 ignores checks (it
builds network maps as if policies had none; `ento admin allow --posture` first asks the control
plane whether it knows posture checks, and adds nothing when it does not). The same for links: a
control node older than 0.14 issues link credentials without looking at the link's checks (it keeps
them when it imports the link's token), so upgrade every control node of the home network before
requiring checks of a link; `ento admin link create --posture` says so when the control plane
created the link without them (it first asks whether the control plane can require checks of
links, and creates nothing on an older one), and `link update` is refused by older ones. Until every
home control node runs 0.14, an older one can also delete a check a link requires (it only looks at
policies): the link's devices are then refused with `no such check` until an admin updates the
link. Agents older than 0.14 are refused all the same; they only log why instead of showing it in `ento agent status`. The facts are the device's own word: they keep honest devices from drifting out of policy, and do
not stop a device whose owner (or an attacker with root on it) reports what they like. Phones'
verified boot and patch levels are the exception (below).

#### Attested facts on Android (0.30)

    sudo ento admin posture add phones --secure-boot --max-patch-age android=90d --disk-encryption

Every posture report of the Android app carries a key attestation: the app asks the Keystore for a
P-256 key made in the phone's secure hardware (the trusted execution environment, or StrongBox),
with an attestation challenge derived from the device's WireGuard key (`attest.Challenge`); the
hardware certifies the key with a chain that ends at Google's attestation root and writes into the
certificate the verified boot state, whether the bootloader is locked, the patch levels and the app
that asked. The report also carries the key's signature of the report's time, so the attestation
cannot be copied: a copy of the device's state on another phone has the WireGuard key but not the
hardware key. The app makes the key again for a new enrollment, after a system update and weekly.

The control node that takes the report verifies it (`internal/attest`) and stores what it found
(`attested` in the facts; the chain itself is not kept): each certificate signed by the next, the
last one carrying a key of Google's roots (embedded, as `android.googleapis.com/attestation/root`
lists them), none but the root outside its validity, none on Google's list of revoked attestation
certificates (keys leaked from phones), the attestation only in the leaf (the app's own key could
sign a forged one placed in front), made in secure hardware (not software) for this device's key,
the key generated there (not imported), the signature of a time within 10 minutes, and, with
`--android-apps PACKAGE:SHA256` on the control nodes, made by that app. On Android, Secure Boot is
then on only for `boot_state=verified` with the bootloader locked, and the patch level is the oldest
attested one; what the app says of either is ignored. A report without an attestation, or with one
that does not count, fails a check that needs Secure Boot, with the reason (`verified boot not
attested: certificate 1 is revoked (a leaked or flawed key)`); `self-signed` (a custom OS such as
GrapheneOS, signed with its own key) fails too (`verified boot: a system its maker did not sign`).
`--max-patch-age` takes days, at least 45 (patch levels name a month); systems that do not report a
patch level cannot be limited.

Revocations: control nodes fetch Google's list (`--attestation-revocations`, default
`https://android.googleapis.com/attestation/status`) once the first attestation arrives, then every
6 hours (every 15 minutes while that fails, logged); networks without phones never ask. With no
list fetched in 3 days, no attestation counts. `--attestation-revocations off` checks none, which
leaked keys make unsafe: only for networks that cannot reach Google, knowingly.

What it does not prove: anything about software running on the phone now (the boot state is the
one it started with), or about a phone whose own hardware key leaked before Google revoked it.
Older apps send no attestation; control nodes older than 0.30 drop it (fail closed: Secure Boot
stays unknown on Android). `ento admin posture add --max-patch-age` refuses to leave a check
without its patch age on an older control node.

### Device names

Every device has a unique name in its network, at most 32 characters of `a-z`, `0-9` and dashes:
the name other devices see in their hosts files, audit lines and the admin interface. It is given
in one of three ways:

- **by the token**: `ento admin token --name web-1` reserves `web-1` for the device that enrolls
  with it. For servers and anything else whose destination is known. The token is refused if the
  name is taken, unless `--replace` lets the new device take over the name (and address) of the
  device that has it when it enrolls: re-enrolling a rebuilt server;
- **by the device**: otherwise it is named after the host name it reports, as `z-<host name>`
  (lowercase, first label only, anything but letters and digits turned into dashes, `-1`, `-2`, ...
  on conflicts). Administrators' names never start with `z-`, so no device can make itself look
  like one an administrator named; `z-` also sorts these devices last;
- **by an authority** (linked networks): a device admitted by an authority is named after it and
  its name at home, `<authority>-<name>`, as its groups are.

The host name a device reported is kept next to its name (`ento admin peers`, last column; the
admin interface, under the name). An administrator can confirm it, which drops the `z-` in one
step (`ento admin confirm-name ID`), or choose any other name (`ento admin rename ID NAME`). A
name does not follow later changes of the device's host name. Devices enrolled before 0.9.0 kept
their names, cleaned up and made unique.

### Admin web interface

`ento control run --admin-ui net.example.com --admin-ui-cert FILE --admin-ui-key FILE` serves a web
interface on port 443 of each control node's overlay address, for that name (point it at the
control nodes' overlay addresses in DNS; the certificate is read again when the file changes): the
network's dashboard (0.39, rebuilt from scratch). It has seven pages:

- **Overview**: the control nodes and whether they were heard from lately (each records itself in
  the store every minute, 0.41.2; before, only when it started), counts (devices, people,
  devices waiting for approval, devices failing a check), the devices waiting (approve or remove them
  there), what needs a look (copied identities, failing checks, names to confirm), open invitations.
- **People**: everyone who signed in on a device, from what the devices know (their groups from
  sign-in, their devices and whether they are signed in now); suspend or resume every device of a
  person at once, sign them out of one device. With `--people` (below), everyone in the identity
  provider too: invite a person (the page shows their setup link, to hand over), change their
  groups, see and remove their passkeys (a lost key: remove them all, then a new setup link),
  disable or enable them, delete them.
- **Devices**: every device with its state, checks and last contact, filtered (online, waiting,
  failing a check, suspended, admins) and searched; a device's panel shows its groups, its posture
  report and each check, and does what the admin commands do: approve and unapprove (**Sign out**
  for a device bound to a person, who gets it back by signing in again; **Unapprove** for others),
  suspend and resume, rename or confirm the reported name, groups (picked as tags, with the
  network's groups suggested; groups that come from sign-in or from an authority are marked, since a
  change would last only until the next one), role, release the hardware key, delete. **Add a
  device** (a dialog over the darkened page, from the Overview too) makes an invitation (an enrollment token: **Five words**, with the QR code for phones,
  or a **Token file**), shown once, with only the groups (picked from the network's) and how long
  it lasts: the device joins named after its host name and waits for approval (0.42.1; a name,
  approval at once, admin rights and replacing a device stay with `ento admin token`); open
  invitations are listed and revoked there, authorities' reusable ones too.
- **Groups** (0.45.3, its own page): people groups and device groups, their members, add and
  remove them, a new group, delete one.
- **Access**: the rules between groups
  (policies, written as "Let A reach B on PORTS", one way or both, with the device checks they
  require) and the device checks themselves (posture checks: which rules and links require each,
  how many devices pass).
- **Routes**, **Names** (internal DNS) and **Linked networks** (grouped by the network they lead to,
  with the devices that may join and the checks the link requires; authorities).

Group names are checked wherever they are set: 1 to 64 characters, no commas or control
characters, `*` only in rules. The page carries the version of the control node that served it and
says so when the control plane runs another (reload it then); browsers revalidate its files every
time (0.23.2). It is plain HTML, CSS and JavaScript embedded in `ento` (about 130 KB besides its fonts, no framework,
nothing loaded from anywhere else: its fonts, Archivo and IBM Plex Mono, are embedded with their OFL
licences), follows the system's light or dark mode, and works down to a phone's width. Commands to
run have a copy button, and their `$` prompt is never selected or copied (0.41.1).

Only approved admin and operator devices get answers (operators see only what they may do, see
Operators below), the page itself included, known by their overlay address as for the admin API
(every enrolled device can reach the control nodes): for the others the interface is not there, their
connection ends before TLS, without its certificate (0.40.2; with sign-in by the device, which shares
the name and serves every device, they get a plain 403 instead). Its API answers
only in a session of that same device: the page shows a code (`K7QM-4TZP`, valid five minutes), and
the session opens when the device approves it with a call signed with its key:

    sudo ento admin ui        # opens the page in your browser, then asks for the code it shows
    sudo ento admin ui CODE   # approves a page you opened yourself

(Windows: in a PowerShell run as administrator; Android: **Open the admin page**, then **Approve** with
the code, in the app, for admin and operator devices; opened on an Android phone, the page shows these steps first
and the commands for computers below them. While it waits for the approval it shows only the code.) Nothing secret goes to the browser, so a
program on the device without its key can neither get its own page approved nor race the browser
for one. The session (an `HttpOnly`, `SameSite=Strict` browser-session cookie) opens administration
only, never sign-in or credentials for linked networks, and ends after 8 hours, after 30 minutes
unused, when it is closed (the button beside the device's name), or as soon as the device is no longer an approved admin or operator. It is
as safe as the browser holding it: a program that reads that browser's cookies could use it from
the device while it lasts; for such a device, use the command line (signed) and sign out.
The interface accepts a change only with its own request header, from its own origin
and for its own name, so other web pages open on an admin device cannot act through it; the plain
API on port 80 refuses browsers, except that a page opened by name there (someone typing
`http://net.example.com`, or a browser trying http first) is redirected to the same address over https. Connections to port 443 for any other name still go to
the identity provider (`--oidc-connect-to`), untouched.

People in the identity provider (0.40): `ento control run --people rauthy --people-api
https://id.example.com/auth/v1`, with the provider's API key in `ENTO_PEOPLE_API_KEY` (Rauthy: an
API key `NAME$SECRET` with read, create, update and delete on Users and Groups), lets admins manage
the provider's people from the dashboard's **People** page, so the provider's own administration can
stay closed. The control node calls the provider's API (through `--oidc-connect-to` when its host
is the issuer's) for each request, keeps nothing, and audits every change (`person_added`,
`person_changed`, `person_deleted`, `person_passkey_deleted`, `person_setup_link`). New people and
people without credentials get a setup link the dashboard shows once (the provider sends no mail):
whoever opens it first registers the account's passkey, so hand it over the way you trust. Groups
missing in the provider are made there first (it would drop them). Rauthy needs entowire's build
for the setup link (`POST /users/{id}/setup_link`, tools/rauthy in entowire's repository).

With `--people`, the network's groups are one kind, kept in the identity provider (0.42): a group
named for a device, an invitation or a rule is made there too, and the **Groups** page lists the
provider's groups with their devices and their people, adds and removes either, makes a group (empty,
if need be) and deletes one that nothing uses (no rule, device, invitation, link or person; audited
as `group_added` and `group_deleted`). Inviting a person preselects `users` where the network has it.

### Device groups and people groups (0.44)

Groups are of two kinds, never mixed: **people groups** hold people (their identity provider's
groups, which devices take while their person is signed in) and **device groups** hold devices (a
device's own groups, given by its invitation or an administrator). A device group's name is stored
with the prefix `device:` (in ento's store and in the identity provider, where each group also
carries `meta: {"kind": "devices"|"people"}`); the dashboard and the CLI never show it, so a people
group and a device group can share a name. Invitations and a device's groups take device groups
only (a plain name gets the prefix; a name that is only a people group is refused); a person's
groups take people groups only. A rule can join either kind: from the CLI a plain name means the
device group when only that exists, `device:NAME` names it explicitly where both do, and a rule
written with a plain name matches both. Built-in device groups: `isolated`, `admin` and `operator`
(a device's role; `--admin-groups` and `--operator-groups` name others); people's roles come from
the identity provider's groups (`--oidc-admin-groups`, ...). A control node of 0.44 gives the
devices' own groups of an older network their prefix once, at start; `--no-gateways` takes device
groups.

Where people are managed here, the identity provider is the only source of groups (0.45): the
dashboard lists only its groups, a device group it does not have is refused (make it first: Access,
**New group**), a rule must name one of its groups, and a device group deleted there is taken off
every device within 30 seconds (audited as `groups_synced`; a device left without groups keeps its
approval and reaches only what rules on its person's groups give). The built-in device groups are
made there whenever missing. `ento control groups NAME GROUP...` sets a device's own groups straight
in the database (recovery; out of `isolated` means approved).


A device's own groups decide whether it is in and what role it has; there is no separate approval
or role to set:

- **isolated**: a device in it reaches nothing and nothing reaches it, whoever signs in on it (it
  counts as not approved). A new device whose invitation names no groups lands in it; giving it groups
  (**Let in…** on the dashboard) lets it in, **Isolate** puts it back. `PATCH approved` does the
  same for older clients.
- the device groups **admin** and **operator** (`--admin-groups`, `--operator-groups`) make a device
  an admin or an operator, and nothing else does (0.47): a device's own role is only ever its
  groups. A person's role comes from their people groups, and lasts while they are signed in on the
  device. Only admins put devices in them or take them out; `ento admin role`, `ento control admin`
  and an administrator token or words put the device in that group, even when the token names other
  groups too. A control node of 0.47 puts a device that was an admin or operator by an older flag
  alone in that role's group once, at start (audited as `device_roles_from_groups`).
- **The device leaves admin when an admin signs in on it** (0.47): once a person whose groups make
  them an admin signs in on a device in the admin group (or becomes an admin while signed in), the
  device leaves that group (audited as `device_admin_dropped`); it keeps its other groups and its
  approval. From then on administration on that device is the person's: it ends when they sign out
  or their session closes. This is how a network's first device (enrolled with the first
  administrator's words) hands over to its people. A device that must administer with nobody signed
  in (automation) is put back in admin by an admin, and stays there while no admin person signs in
  on it.
- **viewers** (`--viewer-groups`) open the dashboard and the admin API read-only, for devices and
  for people signed in on them.

Where people are managed here (`--people`), the dashboard refuses to disable, delete or take the
admin group from the only enabled admin, or from your own account, and asks twice (a confirmation,
then the e-mail address typed) before disabling, deleting or suspending every device of a person.
**Made by** on invitations names the person who made it, or the device when nobody was signed in.

### Sign-in policies (0.46)

Where people are managed here (entowire's build of Rauthy), the network allows some ways of signing
in: `passkey` (passkey only), `password+passkey` and `password+totp` (a password, then a passkey or an
authenticator app); a password alone never. The default (all three unless changed) applies to people
groups without their own; a people group may have its own (`admins`: passkey only, say), and someone
in several groups may use only what all of them allow. Kept in Rauthy (the default in its config, a
group's in its meta), enforced by Rauthy at every sign-in. Always consistent: changing a policy is
refused while anyone would be left without a way in (the refusal names them), and so is putting a
person in a group whose policy their ways of signing in do not meet (a setup link adds one; it also
finishes an unfinished setup or replaces a lost second factor). The dashboard edits the default
(Groups) and each people group's methods, and shows a person's: what they have, what they may use
and what they can use now. API: `GET`/`PUT /v1/admin/signin`.

### Single sign-on

With an OpenID Connect provider, access follows identity instead of manual approval. The control
nodes act as a confidential client using the device authorization grant (RFC 8628):

    export ENTO_OIDC_CLIENT_SECRET=...
    ento control run ... --oidc-issuer https://id.example.com/realms/team \
      --oidc-approve-groups staff --oidc-operator-groups engineers --oidc-admin-groups admins

On an enrolled device:

    ento agent login        # opens the sign-in page in your browser (or prints the link and a code)

Run with sudo from a desktop session, the agent opens the page as the user who ran sudo, in that
user's graphical session; without one (SSH, servers) it only prints the link.
On Windows no administrator is needed (0.35, [Signing in on Windows](#signing-in-on-windows)).
`ENTO_NO_BROWSER=1` disables it.
On a terminal it also draws the link as a QR code (0.32.2; `--no-qr` leaves it out): the sign-in can be
finished on a phone, or any device that has the person's security key or passkey, while this one
waits, so a computer without a port for the key, or without a passkey, still signs in. The link
carries the code the device shows, which the identity provider asks to confirm.

A device must reach the identity provider to sign in, before it is approved to reach anything.
Control nodes therefore pass TCP port 443 on their overlay address through to the provider (the
`--oidc-connect-to` addresses; TLS stays end to end): point the provider's name at the control
nodes' overlay addresses. Since 0.30.1 devices do not depend on that DNS record: every device's
network map, approved or not, gives the provider's name (and the admin interface's, `--admin-ui`)
with the control nodes' overlay addresses, and the agent's resolver answers it itself (Linux:
systemd-resolved sends it that name; Android: the VPN names the agent as its DNS server). DNS that
drops answers pointing at private or shared addresses (rebinding protection in home routers and
filtering resolvers) had kept phones from signing in (`DNS_PROBE_FINISHED_NXDOMAIN` for the
provider's name). An identity provider that devices reach directly (no `--oidc-connect-to`) keeps
its own addresses. The same goes for the network's other services whose public names point inside
it (a chat, a SIEM): list them with `--service-names chat.example.com,siem.example.com` (0.30.2) and
the control nodes resolve them with their own DNS every 5 minutes and give every device the
addresses inside the network's range (others are left out: a control node never points a name
anywhere the network itself does not); a name that stops resolving keeps its last addresses. Only enrolled devices get through: holders of enrollment tokens are
refused (audited `idp_connection … result=denied`), and suspended devices reach nothing at all.
A connection must send within 10 seconds, may stay silent for at most 10 minutes and last at most
an hour, and one device may hold 32 at a time (more are refused and audited).

The device is bound to the user; its groups become the user's groups from the ID token, it is
approved if the user is in an approve group, an admin if in an admin group, and an operator if in
an operator group (and not an admin).

The device knows whom it is bound to (0.22): its network map carries the person's username at the
identity provider (`preferred_username`) and readable name, `ento agent status` shows them, and
`ento agent whoami` prints the username for scripts (as root: it reads the running agent's state,
which only root can): exit 0 signed in, 2 when the session ended (the device stays bound to that
person, and the name is still printed), 1 bound to nobody (nothing printed); `--json` gives
`user`, `user_name` and `session_active`. It is the control plane's word, received through the
tunnel, so a device can rely on it for decisions such as who owns it.

Each sign-in is audited with whose device it was (`binding=new` for a device signed in on for the
first time, `changed` for another person's, `same`; 0.18): a new binding that makes an admin device
is what a phished sign-in looks like (someone signing in with a link another device asked for), so
alert on it.

Only devices that need a person's sign-in can sign in (0.15): a device approved without one (by a
token, or by an administrator) keeps the rights of that approval, and one admitted through a linked
network those its authority gave; to bind such a device to a person, an administrator withdraws its
approval first. A device starts at most one sign-in every 5 seconds. The agent opens only plain
https sign-in links (anything else a control node sends is printed, not opened), and strips control
characters from what it prints.

### Services for every device (0.33)

A service that every enrolled device must reach, whatever the policies say (an installer for the
network's endpoint agents, say, on machines whose policies open only what that agent needs), can be
passed through by the control nodes like the identity provider:

    ento control run ... --forward agent.example.com=10.0.0.1:8462+10.0.0.2:8462

A TLS connection to the control nodes' overlay port 443 that names `agent.example.com` goes to the
first of those addresses that answers (TLS stays end to end: the service holds the certificate and
sees the control node as its client), with the identity provider's rules: enrolled devices only,
not suspended, 10 seconds to send, 10 minutes of silence and an hour at most, 32 connections per
device; each connection is audited (`forward_connection`, naming the device and the service). Every
device resolves the name to the control nodes' overlay addresses itself, like the provider's (agents
of 0.30.1 or later), so no DNS record is needed inside the network; one pointing there helps tools
outside it. Several services: comma-separated entries, each name once. The service decides who may
do what: the control nodes only keep devices that are not the network's out.

### Sign-in approvals

A device can ask that a person approve a sign-in on it from another of their devices, typically
their phone (0.21): the login screen, the screen lock or sudo, as a PAM step. The asking device
shows a number; the phone shows the request with three numbers, and the person picks the one shown
and confirms with a fingerprint or the screen lock:

    sudo ento agent approve --user ana --service sudo     # prints "... pick 47", waits up to 60 s
    # in /etc/pam.d/<service>, before the step it may replace (pam_exec passes PAM_USER, PAM_SERVICE):
    auth [success=done default=ignore] pam_exec.so stdout quiet seteuid /usr/local/bin/ento agent approve --timeout 60s

`seteuid` matters: without it pam_exec runs the program as the real user of the calling process,
which for sudo and su is the person asking, who cannot read the device's key; the request then
cannot be signed and the step answers 3 (unavailable).

`ento agent approve` exits 0 approved, 1 denied (declined, or another number picked), 2 expired
(no answer in time), 3 unavailable (nobody of that name, no device of theirs can approve, too many
requests, the control plane unreachable or older than 0.21; it gives up after 5 seconds without an
answer, 0.22.1, so a broken tunnel does not hold up every sudo), 64 usage. Every exit but 0 lets PAM go
on to the next step, so a phone that does not answer leaves the usual sign-in. It belongs in the
auth stack only; who may sign in at all is still the system's own decision (the account phase).

- **Who.** The name is the identity provider's username or e-mail of a person who has signed in on
  a device of the network (ento keeps `preferred_username` from each sign-in; for devices that
  signed in before 0.21, the next SSO refresh adds it within 2 minutes). Approving devices are that
  person's own, bound to them by single sign-on, approved, not suspended, passing the posture checks
  their policies require, with ento 0.21 or later, and never the asking device. A leaver's phone
  stops approving when the SSO refresh withdraws it.
- **Approving.** The Android app shows a notification for each request while its tunnel is up: it
  asks the control plane through the tunnel, so nothing goes through Google's push service; the
  phone needs a screen lock. On a desktop: `ento agent approvals` lists them and
  `ento agent approvals answer ID NUMBER` (`--deny` before ID refuses) answers.
- **Limits.** An approval is good for one answer and at most 2 minutes (default 60 s). A device may
  ask 10 in 10 minutes, and 20 may be asked for one person. Requests and answers are calls signed
  with the devices' keys. Audited as `signin_approval_requested`, `signin_approved`,
  `signin_denied` (with `wrong number` when the person picked another number: possibly a request
  they did not start), `signin_approval_expired`, each naming both devices and the account. Three
  numbers mean that someone who picks at random approves one request in three: the numbers stop
  approval by reflex, not a person who guesses.

### Sign-in by the device

The control nodes can sign a device's person in to your identity provider, so that a browser on a
device whose person is signed in to ento needs no password or key for the applications behind
that provider (0.32). They are then an OpenID Connect provider for one client, your identity
provider, which brokers to them, at `https://<admin-ui>/device` (it needs `--admin-ui`):

    export ENTO_SIGNIN_CLIENT_SECRET=...   # at least 32 characters, the same in the identity provider
    export ENTO_SIGNIN_KEY="$(openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform DER | base64 -w0)"
    ento control run ... --admin-ui net.example.com ... \
      --device-sign-in-client keycloak \
      --device-sign-in-redirect https://id.example.com/realms/team/broker/device/endpoint

The key signs ID tokens (ES256, published at `/device/jwks`); every control node needs the same
one, and the same client secret. Discovery is at `/device/.well-known/openid-configuration`.

- **Whom it signs in.** The browser's connection comes through the tunnel, so its overlay address
  names the device, as for the admin interface. The device's person is signed in when their
  session on it is open (the person layer: a sign-in, or an approved login on the desktop) and
  recent: the device signed them in, or the session opened, within `--device-sign-in-idle` (default
  6 hours; each sign-in through it slides the window). The ID token says who: `sub` and
  `preferred_username` of their last full sign-in at the same identity provider, `email` when the
  name kept is one, `acr` `device`.
- **Whom it does not.** Devices without a person (servers), with their session closed or stale,
  suspended, or admitted through a link (their person belongs to another network). It then sends the
  browser back with `access_denied`, and the identity provider shows its own sign-in.
- **Not a fresh sign-in.** A request with `prompt=login` or `max_age=0` (an application confirming a
  change with the person's own sign-in) is answered `access_denied` from every device, so the
  identity provider asks for its own factors (0.34.2; Keycloak passes `prompt` on to the providers it
  brokers to).
- **Codes.** Single use, one minute, kept in the database (either control node may redeem them),
  bound to the client, its redirect URI and a PKCE challenge (S256, required), and to the person's
  session they were given in, which must still be open when they are redeemed. Unknown clients and
  redirect URIs are refused without a redirect. A device may start 20 sign-ins a minute on each
  node.
- **Audit.** `device_signin` (`ok`, or `denied` with the reason), `device_signin_token` for refused
  redemptions (a failed client authentication is someone else trying to redeem codes).

What it proves is the device, not the program on it: any program of the device's person can sign
them in this way while it lasts, as anything that can use their browser could. Decide in the
identity provider what such a sign-in may reach. With Keycloak: an OIDC identity provider with
signature validation (JWKS URL), PKCE, no user info, hidden on the login page, a first-login flow
that links to the existing account of the same username (`idp-detect-existing-broker-user`,
`idp-auto-link`) and never creates one, and an "Identity Provider Redirector" naming it in the
browser flow of the clients that may use it. Keycloak shows its own sign-in with the provider's
`access_denied`; answers such as `login_required` would be passed on to the application instead,
which is why the provider never sends them. Keep ento's own sign-in on a flow without the
session cookie, or a device could renew the full sign-in it vouches from.

### Copied identities

A device's identity is the key in its agent's state: whoever copies that state to another machine
(as root) has the device. From 0.23 the control plane notices most copies. Every 5 minutes the agent
checks in: it presents the token the previous check-in handed out (kept in `checkin.token` beside
the state, written to disk before it is used) and a fingerprint of the machine (a hash of
`/etc/machine-id`, the Mac's IOPlatformUUID, Windows' MachineGuid or Android's ANDROID_ID, salted
with the device's own key), and gets a new token. Two machines with the same state soon present a
token the other has already spent; a copy also shows another fingerprint. An answer lost on the way
is no copy: the previous token is accepted once more, with a new one; so is no token at all after
only the first check-in, from the same machine (0.28.1: a phone's app restarts its agent moments
after the first network map arrives, which could stop it before it kept the first token, and the
next check-in, without one, suspended the phone).

What follows depends on the device (`ento control run --clone-response`): by default (`auto`) a
device bound to a person by single sign-on is suspended (as an administrator's suspension: it
survives sign-ins), and other devices, such as servers, are reported and keep working (a server
rebuilt with its state but a new machine ID is reported once; its new fingerprint is then the one
expected); `suspend` suspends every device, `report` none. Each suspicion is audited as
`device_clone_suspected` with the reason and both endpoints (reported devices once an hour); `ento
admin peers` shows `suspended:copied?` and `--json` says why, as the admin page does. `ento admin
resume ID` starts the device's check-ins over once you know what happened.

The limit: a quiet move, where the original never runs again and the copy's fingerprint is faked
(root can), goes unnoticed, unless the device's identity is bound to its hardware (below). Agents
older than 0.23 do not check in; the peer list shows them
without a check-in. Two agents on one machine's state would trade its tokens too: from 0.23.1 a
second agent refuses to start while one runs with the same state (Linux, macOS; it tells the
process apart from another that took its PID).

#### Identities bound to the hardware (TPM)

From 0.31 an agent on Linux that finds a TPM 2.0 (`/dev/tpmrm0`) makes the identity uncopyable.
It creates a P-256 signing key inside the TPM, which never hands out the private half (fixedTPM;
`hwkey.json` beside the state holds the TPM's encrypted blob, which no other TPM can load), and
binds it to the device (`POST /v1/hwkey`, audited `hwkey_bound`). The first key a device binds is
its key until an administrator releases it. From then on:

- Every check-in carries that key's signature over the device's WireGuard key, the token and the
  time. A check-in without it comes from a copy (or from the device's own TPM failing): it is
  refused, its token chain left alone, and audited as `device_clone_suspected` with `reason=no
  hardware signature`; the device is asked to change its WireGuard key (in its network map, which
  the original fetches even while a copy competes for its WireGuard session, and at its next
  signed check-in).
  Still unsigned 15 minutes later (the original gone, only a copy left): suspended.
- A signed check-in with a token already spent (a copy checked in first, or state restored from a
  backup on the original machine) is the original: no suspension; it changes its key at once.
- The device changes its WireGuard key every day (`POST /v1/rotate`, audited `key_rotated`): the
  new key is made on the device and certified by the TPM key; the control plane swaps it in the
  device's row (address, name, groups and rights stay) and every map carries it within seconds.
  With kernel WireGuard the change interrupts the device's sessions for about a second. A copy taken
  before a change works for no more than a day, and in practice only until the original's next
  check-in.
- Another hardware key for a bound device (a copy on a machine with a TPM of its own) is refused
  and audited as `hwkey_conflict`; the original changes its key.

Neither a crash nor a lost answer during a change leaves the device with a key nobody knows: the new
key is saved (`next_private_key` in the state) before it is asked for, and while the outcome is
open the agent tries both keys in turn until a control node answers. Clearing or replacing the TPM
loses the key: the device's check-ins then go unsigned, so an administrator releases the binding
(`ento admin unbind ID`, admins only, audited `hwkey_unbound`) and resumes it if it was
suspended; its next key binds. Downgrading a bound device below 0.31 has the same effect.
`ento agent status` shows `hw key: tpm, bound` and when its WireGuard key was made, `ento admin
peers` a `HW KEY` column (`--json`: `hardware_key`, `hardware_key_at`, `key_rotated_at`).
`--hardware-key off` keeps an agent from using its TPM; `--tpm-device` names another one (a socket:
a software TPM, as the tests use).

What this does not cover yet: proof that the key really is a TPM's (its endorsement certificate)
and a posture check `hardware-bound` that policies and links can require (step 3); macOS (Secure
Enclave), Windows (TPM) and phones (the Android Keystore key signs posture reports only, 0.30);
linked networks' memberships; and root on the device itself, which can use the TPM key as the
agent does while it has the machine.

### Operators

An operator device administers the network within limits that keep every change reversible:
it may list everything, approve and unapprove, suspend and resume, rename and regroup devices that
are neither admins nor operators (its own excluded), create ordinary tokens (neither admin nor
replacing a device) and revoke tokens, and add and remove policies (except where posture checks
are involved: see Device posture). Deleting devices, changing
anyone's role (`ento admin role`), links and authorities stay with admins. Operators use the same
commands and the same admin interface, which shows them only what they may do; refused requests
are audited like an admin's (`result=denied`).

A device's access has two layers (0.27). The **machine layer** is what its enrollment token or an
administrator gives it: approval, groups, a role (`ento admin approve|groups|role`, the admin
page's Approve and Groups). No session or timeout touches it: only unapproving, suspending,
deleting or a suspected copy does. A laptop enrolled with `--groups laptops --approve` stays
connected with nobody signed in, and its SIEM agent keeps sending. The **person layer** is what a
sign-in adds: the person's groups and role (from their identity provider groups), on top of the
machine's while it is open. Policies name groups of either layer.

    sudo ento admin token --name laptop-anna --words --groups laptops --approve   # the machine layer
    sudo ento agent login        # on the laptop: the person layer (password and security key)
    sudo ento agent logout       # the person's rights end; the machine's stay
    sudo ento admin groups ID laptops && sudo ento admin approve ID   # an existing device's machine layer

The person layer closes when:

- **the person is idle** for `--session-idle` (8 hours): nothing of theirs crossed the tunnel. The
  agent counts what the device sends that its machine layer alone would not (the network map says
  what that allows, per peer and port; answers and the control plane do not count, everything in a
  linked network's namespace does), and reports in its check-ins (every 5 minutes) how long ago it
  last moved; the control plane adds the person's own administration. A device that is off sends
  nothing, so its person layer closes too. There is no limit on a session's age by default
  (`--session-max`, 0): a session in use is never cut. Agents before 0.27 report nothing: their
  sessions are judged by when a control node last saw the device, as before;
- **they sign out**: `ento agent logout` (also at the end of a desktop session, from PAM), or an
  administrator's Sign out (`ento admin signout ID`). Told to the control plane within 5 seconds,
  or by the agent once it can reach it; a late logout never closes a session opened since;
- **the device starts again**: check-ins carry its boot ID (Linux, Android, macOS; Windows since
  0.32.3, the kernel's boot time without the clock's corrections), and a new one closes the layer, so
  a crash or a flat battery leaves nothing open. On Windows a shutdown with fast startup resumes the
  kernel and is not a new boot; a restart is;
- the identity provider withdraws them (below), or the device is suspended.

It opens again with `ento agent login`, or, within 7 days of their last full sign-in on the device,
when the person approves a sign-in to its desktop from another of their devices (an approved sign-in
approval, service `gdm-password` by default, `--reopen-services`, asked by that device: the PAM
step at the login screen). After 7 days the next login needs `ento agent login`. Sign-in approvals
need the machine's approval, not an open person layer (the login screen asks before anyone is signed
in), and a device approves for its person while bound to them, its layer open or not (a phone that
sat idle overnight approves the morning's login). `ento agent status` shows the session (`session:
open since ...` or closed); `ento agent whoami` exits 2 while it is closed.


Every sign-in should ask for the user's credentials, not reuse a browser session: bind the client
to a login flow without the session cookie at the identity provider. Credentials for linked networks
last only while the person layer is open (they come from the person's groups), so access to other
networks ends with it. Devices without a person (servers) are not affected. Until 0.27, a device
approved without SSO could not sign in, and a session lasted at most 12 hours (an hour unseen);
signing in replaced the device's own groups. The ID token is
fetched by the control node directly from the token endpoint over TLS, which OpenID Connect allows
in place of a signature check. `--oidc-connect-to` dials a different address for the issuer (e.g. a
private one) while TLS still verifies the issuer's name.

Scopes: ento asks for `openid profile email`, the groups claim's scope where the provider lists it
(Rauthy's `groups`, without which it sends no groups: 0.38.3), and `offline_access` where offered
and refresh tokens are kept.

Within a session, the identity provider stays in charge. With `ENTO_OIDC_TOKEN_KEY` (32 random
bytes in base64, the same on every control node: `openssl rand -base64 32`), control nodes keep the
refresh token of each sign-in, encrypted (AES-256-GCM, bound to the device) in the database, and
every `--oidc-refresh-interval` (2 minutes) one of them asks the provider with it for new tokens:

- refused (`invalid_grant`: the user was disabled or deleted, or their session revoked): the person
  layer loses its rights and closes at once (audit `sso_withdrawn`, with the provider's reason); the
  machine's stay. Which answers count as a refusal is `--oidc-refusals` (STATUS:ERROR, comma-separated;
  default `400:invalid_grant`, as RFC 6749 prescribes). Providers that answer otherwise are named
  there: Rauthy needs `400:invalid_grant,401:Disabled,404:NotFound` (401 `Disabled` for a disabled
  user, 404 `NotFound` for a deleted one or an unknown token). Anything else, a wrong client secret
  (401 `invalid_client`) included, counts as the provider failing and cuts nothing (0.38.2);
- the user's groups changed: the person layer's groups and role follow at once, open or not
  (`sso_changed`), and leaving every approve group leaves it nothing;
- the provider unreachable or failing: nothing changes (`sso_refresh_unavailable` when it starts,
  every 10 minutes while it lasts and once when it is over); the idle limit still applies.

The check runs while the device is bound to the person, also with their layer closed, which keeps
the offline token alive for the next time it opens.

This is plain OpenID Connect, so it works with any provider that issues refresh tokens for the device
grant (Keycloak, Microsoft Entra ID, Okta, Google). Where the provider lists `offline_access`,
sign-in asks for it: such a token belongs to the user rather than to their browser session, so
signing out of another application in the browser does not end the VPN (without it, or if the
client may not have one, sign-in uses an ordinary refresh token). On the provider, let an unused
offline token expire well after the reopening window (7 days; Keycloak: the client's Offline
Session Idle): the refresh every 2 minutes keeps it in use while the device is bound.
Credentials for linked networks of a device checked this way last at most 10 minutes, so a user
disabled at home loses their memberships elsewhere within minutes as well. When the person's
session on the device opens or ends (`ento agent logout`, idle, a new boot, withdrawn), the agent
asks for those credentials at once, and a refusal ends its access there at once (0.35.1), so a
sign-out closes the customers' networks as quickly as home's own services.

To cut someone off at once, whatever the provider says (someone leaving, a stolen laptop):

    sudo ento admin suspend --user alice@example.com    # every device they signed in on
    sudo ento admin resume --user alice@example.com

`--user` takes the name `peers` shows (or the provider's subject); devices admitted through a linked
network are not included (suspend their authority, or the device). Operators suspend only ordinary
devices; nobody suspends the device they call from. The admin interface offers the same when
suspending one of the person's devices. Suspended devices stay out until resumed, whatever the
provider says, and their refresh tokens are dropped (audited `user_suspended`).

Control nodes log every change and every decision as one line
`audit: action=<action> by="<who>" from=<address> target="<what>" result=<ok|denied|failed>`
(enrollments, sign-ins, approvals, policies, tokens, links, sessions ended, connections passed to
the identity provider, a device showing up from another public address, unsigned calls, sessions of
the admin interface, what the identity provider's checks changed, posture checks a device starts or
stops failing, or fails for want of a recent report, links refusing or granting credentials again
over a device's posture), for a SIEM to collect.

**Tailscale on the same device.** Tailscale numbers its devices from 100.64.0.0/10 and, by default,
its firewall drops every packet from that range that does not arrive on `tailscale0`. If this
network is in that range (the default 100.64.0.0/16 is), the tunnel comes up and handshakes but
nothing answers: no ping, no sign-in page. `ento agent status` (0.18.2) warns when it finds Tailscale's
rule in force; `sudo tailscale set --netfilter-mode=nodivert` keeps Tailscale but stops that
diversion (the device's own firewall still applies), or stop `tailscaled`. Choosing a network
outside 100.64.0.0/10 (`ento control run --network`) avoids the clash for everyone.

Linked networks (`ento agent link`) put another deployment's network into its own namespace on the
device; the home network can make named services of its own reachable there too (`--link-forwards`,
see [docs/linked-networks.md](linked-networks.md)); a device can also serve a local proxy
into a linked network for programs that need it and the rest of the world at once
(`ento agent link --proxy 127.0.0.1:PORT [--proxy-ports P,P] NAME`).

Credentials for linked networks count the authority's limit (`--max-ttl`) from their issue time
(0.16): presenting the same credential again buys no fresh limit, and one issued in the future
(more than 2 minutes of clock drift) is refused. A membership the linked network's administrators
suspended stays suspended when the home device joins again with a new key.

Tokens are one-time and short-lived. They are read from a file, stdin (`--token-stdin`) or the
`ENTO_TOKEN` environment variable, never from command-line arguments.

### Signing in on Windows

The device's key, which signs a sign-in, is readable only by the service and administrators
(`C:\ProgramData\ento`), and Windows has no step at its login screen that reopens the person
layer. Since 0.35 the agent therefore takes the person's requests on a channel of its own, the
named pipe `\\.\pipe\ento-session` (interactive users may connect, the network may not):

    ento agent login        # in an ordinary PowerShell: no administrator needed
    ento agent logout
    ento agent whoami
    ento agent status       # without an administrator: only who is signed in and the session

The agent runs the sign-in with its key and passes back the link and code; the command opens the
link in the person's browser, where they sign in with their own credentials as anywhere else. Only
a program in the session at the computer's screen may sign in or out (a remote desktop may only
ask whether the session is open; an administrator's `ento agent login` still works from there),
and a program trusts only an answer from a process in session 0, the services' (anyone who may use
the pipe may open an instance of it, so a program of the person's own could otherwise pose as the
agent and hand out its own sign-in link). Each sign-in and sign-out asked this way is in the
agent's log with the account and process that asked. One sign-in runs at a time: asking again ends
the one before.

`ento-tray.exe`, shipped in the release zip and started at every sign-in to Windows for every
account (`HKLM\...\Run`, written by `ento agent install`, removed by `uninstall`), shows the session
as an icon in the notification area (blue: open; grey: closed; amber: the agent does not answer),
tells the person once when it has ended (at each start of Windows, since a restart closes it, and
when 8 idle hours or an administrator close it), and signs them in when they click the
notification or **Sign in...** in its menu; **Sign out** and **Status** are there too. It holds
nothing: it asks the agent every 15 seconds over the same channel. A device nobody ever signed in to
(a shared or new one) shows a grey icon and is not nagged. `install.ps1` starts it for the person
who ran it, through Explorer, so it does not run elevated.

## Linked networks

A device can also belong to other, independent ento deployments, each in a network namespace
of its own, admitted by that deployment with credentials your network signs:

    ento admin link create acme --groups operators --grant operators      # your network
    ento admin authority add msp --key entoa1:... --groups operators --max-devices 10 --out msp.token   # theirs
    ento admin link token acme --token-file msp.token                     # your network
    sudo ento agent link acme                                             # a device
    sudo ip netns exec ento-acme ssh <peer>

A device holds one membership per linked network: joining again (a new key) replaces it there, and
the linked network can cap how many devices an authority has (`--max-devices`, `authority limit`).
A link can require posture checks of the devices that join through it (`link create|update
--posture`, see Device posture).
Where a linked network makes your device one of its administrators, administer it from that device
with `sudo ento admin --link acme ...` (its key there, its namespace): open its admin page in a
browser running inside `ento-acme` and approve its code with `sudo ento admin --link acme ui CODE`.

See [docs/linked-networks.md](linked-networks.md).

## Tests

    go test ./...                                        # unit + userspace integration tests
    ENTO_TEST_POSTGRES=postgres://... go test ./internal/store/
    ENTO_DATABASE_URL=postgres://... test/e2e-netns.sh dist/ento-linux-amd64   # root, kernel WireGuard
    ENTO_TEST_POSTGRES=postgres://.../postgres test/e2e-linked.sh dist/ento-linux-amd64

Both end-to-end tests accept `E2E_BLOCK_DIRECT=1` to force traffic through the relay.

## Independence

ento is a standalone product. It must never import or depend on anything outside this
directory; deployments consume it like any other user (built binaries, documented CLI).
