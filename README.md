# ento

A self-hostable WireGuard mesh VPN whose control plane is **only reachable through WireGuard**.

A deployment exposes one UDP port per control node and nothing else: no VPN portal, sign-in page
or admin console on the internet. Enrollment, control, sign-in and administration all happen inside
the tunnel. One binary, `ento`, is the control node, the agent and the administration CLI.

## What it does

- **A mesh of your devices**: direct WireGuard connections between peers, relayed through the
  control nodes when no direct path exists.
- **Enrollment** with a token file or five words read out over the phone; devices wait for approval
  or are approved by their groups.
- **Policies** between device and people groups, one way or both, limited to ports.
- **Single sign-on** with any OpenID Connect provider: access follows the person, and someone
  disabled there loses access within minutes.
- **Device posture**: disk encryption, firewall, OS version and more, checked before a rule applies.
- **Routes and exits**: reach networks behind a gateway, or send all traffic through one.
- **Internal DNS** for devices and office machines.
- **An admin web interface** served by the control nodes, reachable only by admin devices through
  the tunnel.
- **High availability**: as many control nodes as you like on one PostgreSQL database; agents fail
  over between them, and find them again through a DNS record if they all move.
- **Several networks on one device**: a laptop in its company's network and a personal one at
  once, each joined with its own invitation and kept apart from the others (Linux).
- **Linked networks**: give the people of one network access to another, independent one, which
  stays in charge (Linux).

## Platforms

| Platform | WireGuard | Runs as |
|---|---|---|
| Linux | the kernel's (5.6+), or inside the agent | systemd service |
| macOS | inside the agent (`utunN`) | launchd service |
| Windows | inside the agent (Wintun) | Windows service |
| Android 8+ | inside the app (Android's VPN service) | the app |

macOS, Windows and Android are newer and tested less than Linux; iOS is next.

## Quick start

Install the agent. Linux and macOS:

    curl -fsSL https://entowire.com/install.sh | sudo sh

Windows (PowerShell as Administrator):

    [Net.ServicePointManager]::SecurityProtocol = 'Tls12'; irm https://entowire.com/install.ps1 | iex

Join a network with the domain that publishes its record and the five words an administrator gives
you:

    sudo ento agent install --join example.com

Run your own control plane: a WireGuard key, a public UDP port and a PostgreSQL database per node.

    ento genkey > control.key && chmod 600 control.key
    export ENTO_DATABASE_URL='postgres://ento:...@db1:5432,db2:5432/ento?target_session_attrs=read-write'
    ento control run --name ctl-1 --key-file control.key \
      --listen-port 51821 --endpoint 203.0.113.10:51821 --network 100.64.0.0/16

Then enroll the first administrator and add devices: [the manual](docs/manual.md#enroll-the-first-administrator).

## Documentation

  administration, a new network, plain WireGuard peers)
- [docs/manual.md](docs/manual.md): everything ento does and how to run it
- [docs/design.md](docs/design.md): architecture and security model
- [docs/linked-networks.md](docs/linked-networks.md): operating other people's networks from yours

## Build

Go, no cgo; static builds with the toolchain `go.mod` pins, and flags for reproducible ones (no
second build is compared yet):

    scripts/build.sh linux/amd64 linux/arm64 darwin/arm64 windows/amd64   # dist/
    go test ./...                                                          # PostgreSQL tests with ENTO_TEST_POSTGRES

The Android app: [the manual](docs/manual.md#android-app).

## License

Apache License 2.0 with the Commons Clause ([LICENSE](LICENSE)): you may use, change and share ento,
but not sell it, nor a product or service (hosting included) whose value derives entirely or
substantially from it. Third-party material and its licenses: [NOTICE](NOTICE).
