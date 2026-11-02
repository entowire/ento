# Linked networks: operating other people's networks

This guide is for an organisation that runs its own ento deployment (the **home network**) and
needs access to other, independent ento deployments it operates for someone else (the **linked
networks**), for example a managed service provider and its customers. The design and its guarantees
are in [design.md](design.md#linked-networks-access-across-independent-deployments); in short:

- networks are never joined or routed into each other;
- on your devices, each linked network lives in its own network namespace (`ento-<name>`);
- the linked network decides who gets in and what they reach, and can end it at any time.

The example uses a home network run by `example-msp` and a linked network `acme`.

## 1. Home network: create the link

On an admin device of the home network:

    ento admin link create acme --groups operators --grant operators --ttl 12h

- `--groups`: which of your groups may join `acme` (devices must be approved and in one of them);
- `--grant`: the groups your devices request in `acme` (acme decides which it accepts);
- `--ttl`: how long each access credential lasts. Devices renew them automatically; a user or device
  you revoke loses access to `acme` within this time;
- `--posture CHECK[,CHECK...]` (optional): posture checks of your network (`ento admin posture`)
  that a device must pass, with a recent report, to get a credential for `acme`: neither joining nor
  renewing works while it fails one. Change them later with
  `ento admin link update acme --posture CHECK,...` (`none` for no checks); see "Posture" below.

The command prints the link's authority key, `entoa1:...`. It is a public key: send it to acme's
administrator by any channel where it cannot be swapped (read it out, compare it over a call).

## 2. Linked network: register the authority

On an admin device of the `acme` network:

    ento admin authority add msp --key entoa1:... --groups operators --max-ttl 12h --max-devices 10 --out msp.token
    ento admin allow msp:operators servers

- the name (`msp`) becomes the prefix of every group the authority assigns: its devices appear as
  `msp:operators`, never in acme's own groups;
- `--groups`: the only groups the authority may assign;
- `--max-ttl`: the longest approval one credential can give, whatever the home network asks for;
- `--max-devices`: how many of the authority's devices may be in acme at a time (0, the default:
  no limit); change it later with `ento admin authority limit msp N`. Each device of the home
  network has one membership: when it joins again with a new key, its previous membership is
  replaced (same name and address), so the count is of devices, not of keys;
- the policy decides what the authority's devices reach, like any other policy.

`msp.token` is the authority's enrollment token. It is a secret, but a limited one: it lets a device
reach acme's control plane, and nothing more unless the device also presents a credential signed with
the registered key. Hand it to the home network's administrator over a secure channel and delete it
afterwards.

## 3. Home network: import the token

    ento admin link token acme --token-file msp.token
    ento admin links

## 4. Devices: join and work

On a device of the home network (approved, in `operators`):

    sudo ento agent link acme

The agent creates the namespace `ento-acme`, enrolls in acme with a new key and a credential from
the home network, and keeps both up to date. Only the agent can ask the home network for
credentials (its calls are signed with the device's key), for one key per linked network: renewals
are for that key, and joining again replaces it. Work inside the namespace:

    sudo ip netns exec ento-acme ping <peer>
    sudo ip netns exec ento-acme sudo -u "$USER" ssh admin@<peer>

Peers of acme resolve by name inside the namespace (the agent maintains
`/etc/netns/ento-acme/hosts`), and so do the names acme publishes for its services (`--hosts` of
its control nodes, e.g. its identity provider and dashboards) and the device's own hostname (which
`sudo` looks up). There is no DNS inside the namespace. Outside it, acme does not exist: no routes, no addresses. Inside it,
nothing but acme exists: no internet, no home network, no other linked network. Members of acme
cannot open connections to the device.

### Services of the home network inside the namespace

Some services of the home network are needed while working in a linked network, typically the
home identity provider when the linked network's applications let the home network's people sign
in through it (with a flow where only the browser talks to both sides, e.g. SAML with redirect and
POST bindings). The home network's control nodes name them:

    ento control run ... --link-forwards "id.example.com:443=100.64.0.1:443+100.64.0.2:443"

(`NAME:PORT=TARGET[+TARGET...]`, entries separated by commas, targets inside the home network.)
Every device then gives each name a loopback address inside each linked namespace (`127.2.X.Y` from a hash of the name, so it never moves when other forwards change,
written into its hosts file) and carries connections to `NAME:PORT` from its own address in the
home network to the first target that answers. TLS stays end to end, so names and certificates are
the service's own. Nothing is routed between the networks: only processes inside the namespace on
that device can use it, the linked network cannot (its connections to the device are dropped),
and a name the linked network publishes itself never overrides a forwarded one. The agent needs
`CAP_NET_BIND_SERVICE` for ports below 1024 (the installed unit has it).

A browser run inside the namespace then reaches both the linked network's applications and the
home identity provider. Give it its own profile, so it does not hand the page to a browser already
running outside. Create the directory first, and not a hidden one: Firefox quits on a `--profile`
that does not exist, and a snap-packaged Firefox cannot read hidden directories. Turn off Firefox's
offline detection in that profile: the namespace has no default route, which Firefox takes for no
network at all (every page then fails with `NS_ERROR_OFFLINE`):

    mkdir -p ~/ento/acme && echo 'user_pref("network.manage-offline-status", false);' >> ~/ento/acme/user.js
    sudo ip netns exec ento-acme sudo -u "$USER" firefox --no-remote --profile ~/ento/acme

### A proxy into the linked network

Programs that need the linked network and everything else at once, and cannot run inside the
namespace (a metrics collector scraping several networks, a provisioning tool that also talks to
the internet), can use a proxy the agent serves on a loopback address of the device's own
namespace:

    sudo ento agent link --proxy 127.0.0.1:9180 --proxy-ports 443,9199 acme     # --proxy off stops it

It accepts `CONNECT` and plain `http://` requests (e.g. Prometheus-style `proxy_url`, `curl -x`,
`HTTPS_PROXY`), resolves names only through the namespace's hosts file, and opens connections only
to addresses of the linked network, from inside its namespace, and with `--proxy-ports` (0.16) only
to those ports (refusals are logged, once a minute per port). Anything that can reach the loopback
address can use it, so give it only on devices whose local programs may reach the linked network
(servers, not shared workstations), and limit it to the ports its users need.

For devices that only need part of the linked network, the linked network's administrator
registers a separate authority for them (e.g. `msp-mon` allowed to assign `monitoring`) and a
policy for that group only; the home network makes a separate link for it (`link create acme-mon
--groups servers --grant monitoring`), which the devices join under that name.

    ento agent status          # shows linked networks, addresses and approval expiry
    sudo ento agent unlink acme

Leaving (0.28) deletes the membership in the linked network too: the device tells its control
plane (`/v1/leave`, signed with the membership's key; audited `link_left` there), so it no longer
counts against the authority's devices (`--max-devices`). A linked network nothing was sent to for
a week is left by itself (the agent's `--link-idle`, 7 days; 0 never): a device used for many
customers does not keep a membership in each. `ento agent link acme` joins again (it does nothing
for a network the device is a member of, so scripts can run it before every use). A device that
was off or offline when it left is deleted by the network's administrators, as before.

### Posture

A link that requires posture checks (`--posture`) gets the same evaluation from the home network as
a policy that requires them: the device's latest report must be recent enough for each check and
show what it requires (no report, an old one or an unknown fact fail), and where a policy of the
home network requires the same check of the device, a failure it still holds back counts too. The
home control plane decides at every credential request (joining and each renewal):

- a device that fails gets no credential and, joining, no token; the answer names the checks and
  why (`enc (disk not encrypted)`), and `ento agent status` shows them:

      link acme: FAILS check enc: disk not encrypted, which this network's link requires: no credential for acme until it passes

  The agent keeps asking (every 30 seconds while joining, every minute while renewing) and gets its
  credential as soon as the device passes again. A refusal only for want of a recent report makes
  it report at once and ask again within seconds; right after it starts, it waits up to 15 seconds
  for its first report to be taken before asking.
- a credential already issued is not withdrawn by home (the two networks never talk); the device
  ends it itself (0.35.1): when home refuses a renewal, for posture or because the person's
  session there ended or their groups may no longer join, the agent drops its peers in acme at once
  and asks acme's control nodes to withdraw its approval (`/v1/credential/end`, signed with the
  membership's key, audited `credential_ended` there); a renewed credential approves it again. It
  renews at once when the person's session at home opens or ends, so a sign-out ends the access
  within seconds. What does not rest on the device's own agent: acme sets the device back to
  pending when the credential lapses (within the link's `--ttl`, at most 10 minutes for devices
  signed in with SSO), and acme's control nodes older than 0.35.1 wait for that too. Choose the TTL
  with that in mind.
- each change of a check's outcome is audited once, whichever control node the device asks, as for
  policies: `link_posture_failed` (`result=denied`, `check=` and `reason=`) when a check fails over
  the device's facts, `link_posture_stale` (`result=ok`) when it fails only for want of a recent
  report, `link_posture_passed`; changes of a link's checks as `link_posture`.

These are the home network's checks, about its own devices; acme can require its own checks of the
devices it admits (agents report their posture to every network they are in), and decides with its
own policy what they reach.

## Revoking

| Who | What | Effect |
|---|---|---|
| Linked network | `ento admin authority suspend msp` | its devices lose their access at once and none joins or renews until `authority resume msp` (the registration and devices stay; on the admin page: Suspend, also on the authority's invitation under Devices, Open invitations) |
| Linked network | `ento admin authority delete msp` | every device of the authority is removed at once |
| Linked network | `ento admin delete ID` | that device is removed (it can join again while the authority exists) |
| Linked network | `ento admin authority token msp --out F` | the authority's enrollment token is replaced: the old one stops working, admitted devices stay; the home network imports the new one (`ento admin link token`) |
| Linked network | `ento admin authority limit msp N` | at most N devices of the authority (0: no limit); devices already in stay |
| Home network | remove a user or device, or its group | its credentials are no longer renewed; access ends within the link's TTL |
| Home network | `ento admin link update acme --posture CHECK,...` | devices that fail a check get no more credentials for acme; their access ends within the TTL, and comes back when they pass |
| Home network | `ento admin link delete acme` | no more credentials for acme; access ends within the TTL |

## Requirements

- Linux with kernel WireGuard and nftables, running the agent as the systemd service installed by
  `ento agent install` (it installs the `ento-netns@` unit the namespaces are created with).
- Both networks running ento with linked network support (0.2.0 or later); device limits,
  token replacement and the one-membership rule need 0.11.0 on the linked network's control nodes,
  signed credential requests 0.11.0 on the home network's control nodes and devices. Posture checks
  on links need 0.14.0 on **every** control node of the home network before a link requires any (an
  older one issues credentials without looking at them, and can delete a check a link requires:
  devices are then refused with `no such check` until the link is updated), and devices reporting their posture (0.13.0
  or later; 0.14.0 shows a refusal in `ento agent status`).

## Administering a linked network

Where acme makes your device one of its administrators (`ento control admin` on one of its nodes,
or on its admin page), administer acme from that device as its membership there, with its key and
in its namespace:

    sudo ento admin --link acme peers
    sudo ento admin --link acme ui CODE     # approves acme's admin page showing CODE

Open acme's admin page in a browser running inside `ento-acme`; it shows the code to approve.
