package main

import (
	"fmt"
	"io"
	"strings"
)

// shortUsage is what `ento` prints without arguments: what a person needs on their own device, and
// the administrators' two most used commands. Everything else is in `ento help` (usage).
const shortUsage = `ento: a private WireGuard network.

This device:
  ento agent install --join DOMAIN   join a network (asks for the words an administrator reads out)
  ento agent join DOMAIN             join another network too (Linux; leave DOMAIN forgets it)
  ento agent status                  the connection, peers and this device's checks
  ento agent login | logout          sign in or out as yourself
  ento agent up | down               turn the tunnel on or off
  ento agent exit [NAME|off]         send internet traffic through an exit, or stop
  ento agent uninstall [--purge]     remove the service (--purge also forgets the network)

Administrators:
  ento admin ui                      open the admin page
  ento admin token --words           words for a new device to join with

  ento version                       this ento's version
  ento update check                  whether a newer release is out

Everything: ento help    One part: ento help agent | admin | control | update
`

const usageHeader = `ento: WireGuard mesh VPN whose control plane is only reachable through WireGuard.

`

const usageControl = `Control node:
  ento control run      run a control node
  ento control token    create an enrollment token directly in the database (bootstrap; --words)
  ento control record   print the network record to publish at _ento.<domain> (enrollment by words)
  ento control authority add NAME --key KEY --groups G   register an authority (bootstrap)
                         [--max-devices N]; authority token NAME gives it a new enrollment token
  ento control allow SOURCE DESTINATION                  add a policy (bootstrap)
  ento control admin [--off] NAME                        make a device an administrator (bootstrap)

`

const usageAgent = `Agent:
  ento agent install    install as a service and start it (first time: --join DOMAIN, the domain's
                         network record and the words an administrator reads out, typed when asked;
                         or, Linux and macOS, a token; --force with either replaces an enrollment)
  ento agent uninstall  stop and remove the service (--purge also forgets the enrollment)
  ento agent down       turn the tunnel off: the service stops and stays off, across reboots too
  ento agent up         turn it on again
  ento agent run        enroll (if needed) and keep the interface in sync, in the foreground
  ento agent login      log in with SSO: binds this device to your identity (approval, groups)
  ento agent status     show the local state, posture, WireGuard peers and linked networks
  ento agent posture    show what this device reports about itself (--json), as collected now
  ento agent approve    ask the person to approve a sign-in on this device from another of their
                         devices (a PAM step: pam_exec stdout); --user (default $PAM_USER), --service
                         (default $PAM_SERVICE), --timeout 60s; prints the number to pick, exits 0
                         approved, 1 denied, 2 expired, 3 unavailable, 64 usage
  ento agent whoami     the identity provider's username of the person this device is signed in as
                         (the control plane's word; root): exit 0, 2 when their session (the person
                         layer) is closed (still printed), 1 when nobody (prints nothing); --json adds
                         the readable name and session_active
  ento agent logout     the person signs out: their rights on this device end (the machine's stay)
                         until they sign in again or approve a sign-in on it; told to the control plane
                         within --timeout (default 5s), else by the agent later
  ento agent exit [NAME|off|default]
                         send all internet traffic through exit NAME (a gateway administrators
                         offer; status lists those offered), through none (off), or through the one
                         used by default; without an argument shows the choice (Linux; Android: the app)
  ento agent approvals  sign-ins waiting for your approval on this device; approvals answer [--deny]
                         ID NUMBER answers one (the person's own devices, bound by sign-in)
  ento agent join DOMAIN
                         join another network besides the first, with the words an administrator
                         there reads out (Linux): its own interface (ento1, ...), key and rights,
                         reached by every program; status, login, logout, whoami, approve and
                         approvals then take --network DOMAIN (default: the first network), and
                         ento admin --network DOMAIN administers it; exits and releases stay the
                         first network's
  ento agent leave DOMAIN
                         forget a network joined so (that network keeps the device until an
                         administrator there deletes it)
  ento agent link NAME  join linked network NAME (in network namespace ento-NAME)
                         --proxy 127.0.0.1:PORT also serves an HTTP proxy into it (before NAME),
                         --proxy-ports P,P only to those ports
  ento agent unlink NAME
                         (leaves it, there too: the membership is deleted; a linked network unused for
                         --link-idle, 7 days, is left by itself)

`

const usageAdmin = `Administration (from an enrolled admin or operator peer, as root or administrator: calls are signed
with the device's key; ENTO_STATE_DIR selects the agent state, --link NAME first administers linked
network NAME as this device's membership there, --network DOMAIN first a network joined with ento
agent join; operators: ordinary devices, tokens and policies only):
  ento admin ui [CODE]  open the admin interface in a browser of this device: the page shows a code,
                         which this approves (typed in, or given as CODE); --no-browser
  ento admin token      create an enrollment token; --name NAME names the device it enrolls (else
                         z-<its host name>), --replace lets it take over from a device with the name;
                         --words: as words to read out (the device runs ento agent install --join DOMAIN);
                         --qr with them: also a QR code of the domain (--domain, else the control
                         nodes' --record-domain), the network's fingerprint and the words, which the
                         phone app scans
  ento admin record     print the network record to publish at _ento.<domain> for --join
  ento admin peers      list peers (--json for machine-readable output)
  ento admin tokens | revoke ID
  ento admin approve ID | unapprove ID | suspend ID | resume ID | delete ID
                         approve and unapprove are the machine's: a device bound to a person keeps
                         their rights while they are signed in; signout ID ends that (0.27)
  ento admin unbind ID  release a device's hardware key (0.31, admins only), e.g. after its TPM
                         was cleared or replaced: its next one binds (peers shows HW KEY)
  ento admin suspend --user USER | resume --user USER
                         every device USER signed in on (their name as peers shows it), e.g. when
                         they leave: no sign-in restores the access until resumed
  ento admin rename ID NAME
  ento admin confirm-name ID   name a device after the host name it reported (drops "z-")
  ento admin groups ID GROUP[,GROUP...]
  ento admin role ID admin|operator|none   (admins only)
  ento admin policies   list policies
  ento admin allow SOURCE DESTINATION [--one-way] [--ports RULE[,RULE...]] [--posture CHECK[,CHECK...]] | disallow ID
                         --one-way: only SOURCE opens connections (DESTINATION answers them)
                         --ports: what may be opened: tcp/22, tcp/8000-8100, udp/53, tcp, udp, icmp (default: all)
                         --posture: SOURCE devices must pass these checks (admins only)
  ento admin policy ID --posture CHECK[,CHECK...]|none   change the checks a policy requires (admins)
  ento admin route add NAME NETWORK[,NETWORK...] --via DEVICE   a network behind a gateway device (admins);
                         devices reach it once a policy lets them: allow GROUP route:NAME [--ports ...]
  ento admin route add NAME --exit --via DEVICE [--default]   an exit (admins): devices a policy lets
                         use it (allow GROUP route:NAME) may send all their internet traffic through
                         DEVICE, to public addresses; --default: they do unless they turn it off
  ento admin routes | route delete NAME
  ento admin dns        the network's internal DNS (control nodes' --dns-domain): names and forwarded zones
  ento admin dns add NAME ADDRESS | dns delete NAME     a name in the domain (e.g. nas.office) for an
                         address; devices resolve it when they reach the address (admins)
  ento admin dns forward ZONE SERVER[,SERVER...] | dns unforward ZONE   names in ZONE are asked of
                         its name servers, e.g. an office's own DNS through its route (admins)
  ento admin policy ID [--one-way|--two-way] [--ports RULE[,RULE...]|all]   change its direction and ports

Device posture (checks: admins add and delete them, operators list them):
  ento admin posture    list posture checks
  ento admin posture add NAME [--disk-encryption] [--firewall] [--secure-boot] [--antimalware]
                         [--min-os linux=6.1,windows=10.0.22631,darwin=14.0,android=13] [--max-age 30m]
                         [--max-patch-age android=90d]
                         --secure-boot on Android: verified boot with the bootloader locked, as the
                         phone's secure hardware attests it (key attestation, verified by the
                         control nodes); --max-patch-age: how old its security patch may be
  ento admin posture delete NAME

Linked networks, in the home network (whose devices join others):
  ento admin link create NAME --groups G --grant G   create a link; prints its authority key
                         [--ttl 12h] [--posture CHECK[,CHECK...]: devices get credentials only while
                         they pass these checks (admins)]
  ento admin link update NAME --posture CHECK[,CHECK...]|none   change the checks a link requires
  ento admin link token NAME --token-file F          import the token the linked network issued
  ento admin links | link delete NAME

Linked networks, in the linked network (which admits another network's devices):
  ento admin authority add NAME --key KEY --groups G --out F   register an authority
                         [--max-devices N: at most N of its devices at a time]
  ento admin authority limit NAME N    change that limit (0: none)
  ento admin authority token NAME --out F   a new enrollment token for it (the old one stops)
  ento admin authorities | authority suspend NAME | resume NAME | delete NAME

`

const usageOther = `Other:
  ento version          print the version
  ento update check [--short]  whether a newer release is signed and published (exit 10: yes)
  ento update install --version V [--dir DIR]  replace this binary with signed release V (never older;
                         the previous one kept: ento update rollback)
  ento update verify DIR  check a release directory's manifest and files (publishing)
  ento update keys      the release keys built into this binary
  ento admin updates [auto | approve VERSION | off] [--first GROUP --after HOURS]
                         how the network's devices take new releases (none: show it and every device's version)
  ento genkey           print a new WireGuard private key
  ento pubkey           read a private key on stdin, print its public key

`

const usageFooter = `Secrets are never taken from command-line arguments: the database URL comes from
ENTO_DATABASE_URL, tokens from a file, stdin or ENTO_TOKEN, words from the terminal or stdin.
`

// usage is the whole of it (`ento help`).
const usage = usageHeader + usageControl + usageAgent + usageAdmin + usageOther + usageFooter

// helpTopics are the parts `ento help TOPIC` prints, also printed by `ento TOPIC` without a command.
var helpTopics = map[string]string{
	"control": usageControl,
	"agent":   usageAgent,
	"admin":   usageAdmin,
	"update":  usageOther,
}

// printHelp writes `ento help [TOPIC]`: everything, or one part.
func printHelp(w io.Writer, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(w, usage)
		return nil
	}
	t, ok := helpTopics[args[0]]
	if !ok {
		return fmt.Errorf("no help for %q: ento help agent | admin | control | update", args[0])
	}
	fmt.Fprint(w, usageHeader+strings.TrimRight(t, "\n")+"\n")
	return nil
}

// isHelp reports whether args ask for help instead of a command: none, or only help, -h or --help.
func isHelp(args []string) bool {
	return len(args) == 0 || len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help")
}
