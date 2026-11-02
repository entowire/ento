#!/usr/bin/env bash
# End-to-end test on one Linux host: a control node (unprivileged, userspace WireGuard, PostgreSQL)
# and two agents in separate network namespaces using kernel WireGuard.
#
#   admin (ns ento-a) ──┐                ┌── control node (host netns, 10.200.0.1:51821)
#                        ├── host routes ─┤
#   peer  (ns ento-b) ──┘                └── PostgreSQL (ENTO_DATABASE_URL)
#
# Checks: bootstrap token, enrollment (B by words and the network record), admin API, device names (named after the host name, counter,
# confirm, rename), pending peer isolation, approval, policy, direct peer-to-peer traffic, a one-way
# policy limited to ports (enforced by the receiving agent's nftables table, put back when removed),
# `ento agent down` (agent stopped, kernel interface removed), device posture (agents report,
# a policy requiring a firewall leaves a device without one out until it has one), refused
# connections logged (--log-drops), a hardware-bound identity (with swtpm: B's key in a software
# TPM, check-ins signed, its WireGuard key changed on schedule, a copy on a machine with another TPM
# refused and shut out), and with kernel
# WireGuard a route (B the gateway of a LAN namespace) and an exit (B forwards A's internet traffic
# into a namespace standing for the internet, and answers its DNS), and internal DNS (each agent's
# resolver: device names, a name in the LAN, a zone forwarded to the LAN's name server), and a
# control node that moves (B finds its new endpoint in the network record).
# Needs root (sudo), the wireguard kernel module and a PostgreSQL database the test may wipe
# (ENTO_DATABASE_URL).
#
# With E2E_BLOCK_DIRECT=1, UDP between the two agents is dropped, so they must fall back to the
# relay through the control node. With E2E_PSQL (a psql command for ENTO_DATABASE_URL's database,
# e.g. `docker exec -i <container> psql -U postgres -d e2e`), sign-in approvals are tested too; the
# binary must then report 0.21 or later (go build -ldflags "-X main.version=0.21.0").
#
# Usage: ENTO_DATABASE_URL=postgres://... [E2E_BLOCK_DIRECT=1] [E2E_USERSPACE=1] test/e2e-netns.sh path/to/ento
set -euo pipefail

bin="$(realpath "${1:?usage: $0 path/to/ento}")"
: "${ENTO_DATABASE_URL:?set ENTO_DATABASE_URL to a disposable database}"
work="$(mktemp -d)"
ctl_pid=""
made_netns_conf=""

cleanup() {
  set +e
  sudo pkill -f "$work/" 2>/dev/null
  [[ -n "$ctl_pid" ]] && kill "$ctl_pid" 2>/dev/null
  for ns in a b c lan inet; do sudo ip netns del "ento-$ns" 2>/dev/null; sudo ip link del "ento-v$ns" 2>/dev/null; done
  [[ -n "$made_netns_conf" ]] && sudo rm -rf /etc/netns/ento-b
  sudo ip addr del 10.200.0.1/32 dev lo 2>/dev/null
  sudo ip addr del 10.200.0.9/32 dev lo 2>/dev/null
  [[ -n "${nf_log_all_netns:-}" ]] && sudo sysctl -qw "net.netfilter.nf_log_all_netns=$nf_log_all_netns"
  [[ -n "${moved_rule:-}" ]] && sudo iptables -D INPUT -d 10.200.0.1 -p udp --dport 51821 -j DROP 2>/dev/null
  sudo iptables -D FORWARD -s 10.200.0.0/16 -d 10.200.0.0/16 -j ACCEPT 2>/dev/null
  sudo iptables -D FORWARD -s 10.200.2.0/24 -d 10.200.3.0/24 -p udp -j DROP 2>/dev/null
  sudo iptables -D FORWARD -s 10.200.3.0/24 -d 10.200.2.0/24 -p udp -j DROP 2>/dev/null
  if [[ -n "${KEEP:-}" ]]; then echo "kept $work"; else sudo rm -rf "$work"; fi
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
fail() {
  echo "FAIL: $*" >&2
  for ns in a b; do
    echo "--- ns $ns: wg"; sudo ip netns exec "ento-$ns" wg show 2>&1 | sed 's/^/    /'
    echo "--- ns $ns: routes"; sudo ip netns exec "ento-$ns" ip route 2>&1 | sed 's/^/    /'
    echo "--- ns $ns: netmap"; sudo ip netns exec "ento-$ns" curl -s --max-time 3 "http://100.64.0.1/v1/netmap" | head -c 900; echo
  done
  exit 1
}

step "network namespaces"
sudo sysctl -qw net.ipv4.ip_forward=1
# The kernel logs netfilter's log rules from other namespaces than the host's only with this on.
nf_log_all_netns="$(cat /proc/sys/net/netfilter/nf_log_all_netns 2>/dev/null || echo 0)"
sudo sysctl -qw net.netfilter.nf_log_all_netns=1
sudo iptables -I FORWARD -s 10.200.0.0/16 -d 10.200.0.0/16 -j ACCEPT
if [[ -n "${E2E_BLOCK_DIRECT:-}" ]]; then
  echo "blocking direct UDP between the agents"
  sudo iptables -I FORWARD -s 10.200.2.0/24 -d 10.200.3.0/24 -p udp -j DROP
  sudo iptables -I FORWARD -s 10.200.3.0/24 -d 10.200.2.0/24 -p udp -j DROP
fi
sudo ip addr add 10.200.0.1/32 dev lo
i=1
for ns in a b; do
  i=$((i + 1))
  sudo ip netns add "ento-$ns"
  sudo ip link add "ento-v$ns" type veth peer name eth0 netns "ento-$ns"
  sudo ip addr add "10.200.$i.1/24" dev "ento-v$ns"
  sudo ip link set "ento-v$ns" up
  sudo ip netns exec "ento-$ns" ip addr add "10.200.$i.2/24" dev eth0
  sudo ip netns exec "ento-$ns" ip link set eth0 up
  sudo ip netns exec "ento-$ns" ip link set lo up
  sudo ip netns exec "ento-$ns" ip route add default via "10.200.$i.1"
done
# B's resolver is the internet namespace's (the exit step): processes started in ento-b read it.
if [[ ! -e /etc/netns/ento-b ]]; then
  sudo mkdir -p /etc/netns/ento-b
  echo "nameserver 203.0.113.2" | sudo tee /etc/netns/ento-b/resolv.conf >/dev/null
  made_netns_conf=1
fi

step "database reset"
psql_reset() {
  docker run --rm --network host postgres:18-alpine psql "$ENTO_DATABASE_URL" -qc \
    "DROP TABLE IF EXISTS ento_settings, ento_state, ento_control_nodes, ento_peers, ento_tokens, ento_policies,
     ento_authorities, ento_links, ento_link_keys, ento_admin_sessions, ento_sso_tokens, ento_posture,
     ento_posture_checks, ento_link_posture, ento_ui_sessions, ento_approvals, ento_checkins, ento_hwkeys, ento_routes, ento_dns_records, ento_dns_forwards CASCADE" >/dev/null
}
psql_reset

step "control node"
"$bin" genkey > "$work/control.key"
chmod 600 "$work/control.key"
"$bin" control run --name ctl-1 --key-file "$work/control.key" --listen-port 51821 \
  --endpoint 10.200.0.1:51821 --dns-domain e2e.internal --record-domain e2e.test > "$work/control.log" 2>&1 &
ctl_pid=$!
for _ in $(seq 1 50); do grep -q "control node ctl-1 up" "$work/control.log" && break; sleep 0.2; done
grep -q "control node ctl-1 up" "$work/control.log" || { cat "$work/control.log"; fail "control node did not start"; }

step "bootstrap admin token (directly in the database)"
"$bin" control token --admin --approve --groups admins --out "$work/admin.token" 2>/dev/null

agent() { # agent <ns> <args...>
  local ns="$1"; shift
  sudo ENTO_STATE_DIR="$work/state-$ns" ip netns exec "ento-$ns" "$bin" "$@"
}

# E2E_USERSPACE=1: both agents run WireGuard inside themselves (as on macOS and Windows), and
# their inbound filter is the one in the packet path instead of nftables.
# B's interface then has another name: the UAPI sockets of userspace WireGuard live in
# /var/run/wireguard (not per namespace), and two agents named ento0 would share one.
userspace=() userspace_b=() ifb=ento0
[[ -n "${E2E_USERSPACE:-}" ]] && userspace=(--userspace) userspace_b=(--userspace --interface ento1) ifb=ento1

step "agent A enrolls as admin"
sudo ip netns exec ento-a "$bin" agent up --state-dir "$work/state-a" --token-file "$work/admin.token" "${userspace[@]}" \
  > "$work/agent-a.log" 2>&1 &
for _ in $(seq 1 100); do sudo test -f "$work/state-a/state.json" && break; sleep 0.2; done
sudo test -f "$work/state-a/state.json" || { cat "$work/agent-a.log" "$work/control.log"; fail "agent A did not enroll"; }
sleep 2

step "admin issues words for B (enrollment by words: B gets the network record and five words)"
words="$(agent a admin token --groups servers --ttl 10m --words 2>/dev/null)"
record="$(agent a admin record 2>/dev/null)"
[[ "$(wc -w <<<"$words")" == 5 && "$record" == "ento1 net=100.64.0.0/16 c="* ]] || fail "words ($words) or record ($record)"

step "agent B enrolls with the words (pending approval)"
printf '%s\n' "$words" | sudo ip netns exec ento-b "$bin" agent run --state-dir "$work/state-b" --record "$record" "${userspace_b[@]}" \
  > "$work/agent-b.log" 2>&1 &
for _ in $(seq 1 100); do sudo test -f "$work/state-b/state.json" && break; sleep 0.2; done
sudo test -f "$work/state-b/state.json" || { cat "$work/agent-b.log" "$work/control.log"; fail "agent B did not enroll"; }
sleep 2

addr_a="$(sudo cat "$work/state-a/state.json" | python3 -c 'import json,sys;print(json.load(sys.stdin)["address"])')"
addr_b="$(sudo cat "$work/state-b/state.json" | python3 -c 'import json,sys;print(json.load(sys.stdin)["address"])')"
echo "A = $addr_a, B = $addr_b"

step "B cannot reach A before approval"
if sudo ip netns exec ento-b ping -c1 -W1 "$addr_a" >/dev/null 2>&1; then fail "pending peer reached another peer"; fi
if agent b admin peers >/dev/null 2>&1; then fail "non-admin peer used the admin API"; fi

step "names: both devices report this host's name, so B gets a counter; confirm and rename"
host="$(hostname | cut -d. -f1 | tr 'A-Z' 'a-z' | sed -E 's/[^a-z0-9]+/-/g; s/^-+|-+$//g')"
id_b="$(agent a admin peers | awk -v a="$addr_b" '$3 == a {print $1}')"
[[ "$(agent a admin peers | awk 'NR > 1 {print $2}' | sort | tr '\n' ' ')" == "z-$host z-$host-1 " ]] ||
  { agent a admin peers; fail "devices are not named z-$host and z-$host-1"; }
agent a admin confirm-name "$id_b" | grep -q "is now $host\$" || fail "confirm-name"
if agent a admin rename "$id_b" "z-other" 2>/dev/null; then fail "an administrator gave a z- name"; fi
agent a admin rename "$id_b" peer-b | grep -q "is now peer-b" || fail "rename"

step "admin approves B and allows admins <-> servers"
agent a admin peers
agent a admin approve "$id_b"
agent a admin allow admins servers >/dev/null

step "A <-> B traffic through the mesh"
for _ in $(seq 1 60); do sudo ip netns exec ento-a ping -c1 -W1 "$addr_b" >/dev/null 2>&1 && break; sleep 1; done
sudo ip netns exec ento-a ping -c3 -W2 "$addr_b" || { cat "$work/agent-a.log" "$work/agent-b.log"; fail "A cannot reach B"; }
sudo ip netns exec ento-b ping -c3 -W2 "$addr_a" || fail "B cannot reach A"

agent a agent status --state-dir "$work/state-a"
if [[ -n "${E2E_BLOCK_DIRECT:-}" ]]; then
  step "the path is relayed (B's endpoint is the local relay socket)"
  agent a agent status --state-dir "$work/state-a" | grep -q "peer.*127.0.0.1:" || fail "B is not relayed"
else
  step "the path is direct (B's endpoint is B's own address, not the control node)"
  agent a agent status --state-dir "$work/state-a" | grep -q "peer.*10.200.3.2:51830" || fail "no direct endpoint for B"
fi

step "another program takes B's address away and the interface down (NetworkManager's Disconnect): the agent puts both back"
sudo ip netns exec ento-b ip addr flush dev "$ifb"
sudo ip netns exec ento-b ip link set "$ifb" down
for _ in $(seq 1 20); do sudo ip netns exec ento-a ping -c1 -W1 "$addr_b" >/dev/null 2>&1 && break; sleep 1; done
sudo ip netns exec ento-b ip -4 addr show dev "$ifb" | grep -q "$addr_b" || fail "B's address was not put back"
sudo ip netns exec ento-a ping -c1 -W2 "$addr_b" >/dev/null || fail "A cannot reach B after the repair"
grep -q "had lost its address" "$work/agent-b.log" || fail "B's agent did not say it repaired its interface"

step "control API is not reachable outside the tunnel"
ctl_addr="$(sudo cat "$work/state-a/state.json" | python3 -c 'import json,sys;print(json.load(sys.stdin)["controls"][0]["address"])')"
if curl -s --max-time 2 "http://10.200.0.1/v1/netmap" >/dev/null; then fail "API reachable on the public address"; fi
echo "control API only on $ctl_addr inside WireGuard"

step "ento agent down: B's agent stops and its kernel interface goes away"
agent b agent down --state-dir "$work/state-b"
if sudo ip netns exec ento-b ip link show "$ifb" >/dev/null 2>&1; then fail "$ifb still exists after down"; fi
if sudo ip netns exec ento-a ping -c1 -W1 "$addr_b" >/dev/null 2>&1; then fail "B still answers after down"; fi
agent b agent status --state-dir "$work/state-b" | grep -q "^agent: *down" || fail "status does not say down"

step "B runs again (logging refused connections from here on): reachable, no longer marked down"
sudo ip netns exec ento-b "$bin" agent run --state-dir "$work/state-b" --log-drops "${userspace_b[@]}" >> "$work/agent-b.log" 2>&1 &
for _ in $(seq 1 60); do sudo ip netns exec ento-a ping -c1 -W1 "$addr_b" >/dev/null 2>&1 && break; sleep 1; done
sudo ip netns exec ento-a ping -c2 -W2 "$addr_b" >/dev/null || { cat "$work/agent-b.log"; fail "A cannot reach B again"; }
if agent b agent status --state-dir "$work/state-b" | grep -q "^agent: *down"; then fail "B still marked down"; fi

step "one-way policy with ports: A (admins) opens tcp/8080 on B (servers), nothing else; B opens nothing on A"
pol="$(agent a admin policies | awk '$2 == "admins" && $4 == "servers" {print $1}')"
mkdir -p "$work/www" && echo ok > "$work/www/index.html"
for p in 8080 8081; do
  sudo ip netns exec ento-b python3 -m http.server "$p" --bind "$addr_b" --directory "$work/www" > "$work/http-b-$p.log" 2>&1 &
done
sudo ip netns exec ento-a python3 -m http.server 9090 --bind "$addr_a" --directory "$work/www" > "$work/http-a.log" 2>&1 &
opens() { sudo ip netns exec "ento-$1" timeout 3 bash -c "</dev/tcp/$2/$3" 2>/dev/null; }
posture_of() { # posture_of <address> <field>
  agent a admin peers --json | python3 -c 'import json,sys
for p in json.load(sys.stdin):
    if p["address"] == sys.argv[1]:
        print(json.dumps((p.get("posture") or {}).get(sys.argv[2])))' "$1" "$2"
}
for _ in $(seq 1 20); do opens a "$addr_b" 8081 && break; sleep 1; done
opens a "$addr_b" 8081 || fail "A cannot open B:8081 before the policy changes"
agent a admin policy "$pol" --one-way --ports tcp/8080 >/dev/null
agent a admin policies | grep -q "admins *-> *servers *tcp/8080" || fail "the policy does not show its direction and ports"
for _ in $(seq 1 20); do opens a "$addr_b" 8081 || break; sleep 1; done
opens a "$addr_b" 8080 || { sudo ip netns exec ento-b nft list ruleset; fail "A cannot open B:8080"; }
if opens a "$addr_b" 8081; then fail "A opened B:8081, which the policy does not allow"; fi
# The refused attempt is logged (B runs with --log-drops): by the kernel, or by the agent itself.
drop_line="ento-filter drop: IN=$ifb .*SRC=$addr_a DST=$addr_b .*PROTO=TCP SPT=[0-9]* DPT=8081"
if [[ -n "${E2E_USERSPACE:-}" ]]; then
  grep -q "$drop_line" "$work/agent-b.log" || fail "B's agent did not log the refused connection"
else
  [[ "$(sudo ip netns exec ento-b nft list table inet ento-filter)" == *'log prefix "ento-filter drop: "'* ]] ||
    fail "B's filter has no log rule"
  grep -q "$drop_line" <<<"$(sudo dmesg)" || { sudo dmesg | tail -5; fail "the kernel did not log the refused connection"; }
fi
if opens b "$addr_a" 9090; then fail "B opened a connection to A through a one-way policy"; fi
if sudo ip netns exec ento-a ping -c1 -W1 "$addr_b" >/dev/null 2>&1; then fail "A pinged B without icmp in the policy"; fi
if [[ -z "${E2E_USERSPACE:-}" ]]; then
  # Whole, then matched: grep -q stopping early would make nft fail on a closed pipe (pipefail).
  [[ "$(sudo ip netns exec ento-b nft list table inet ento-filter)" == *'tcp dport 8080 accept'* ]] || fail "B's filter does not show the rule"
  echo "removing B's filter table: the agent puts it back within a minute"
  sudo ip netns exec ento-b nft delete table inet ento-filter
  for _ in $(seq 1 75); do sudo ip netns exec ento-b nft list table inet ento-filter >/dev/null 2>&1 && break; sleep 1; done
  sudo ip netns exec ento-b nft list table inet ento-filter >/dev/null 2>&1 || fail "B's agent did not put its filter back"
  if opens a "$addr_b" 8081; then fail "A opened B:8081 after the filter was put back"; fi
  # B's own filter (port rules in it) leaves its firewall fact known: no firewall here, so false.
  [[ "$(posture_of "$addr_b" firewall)" == "false" ]] || fail "B's firewall fact is $(posture_of "$addr_b" firewall) with its filter in place"
fi
echo "a port B's system redirects (as members send 443 to their proxy): the filter judges the port A connected to"
sudo ip netns exec ento-b nft add table ip e2e-nat
sudo ip netns exec ento-b nft add chain ip e2e-nat pre '{ type nat hook prerouting priority dstnat; }'
sudo ip netns exec ento-b nft add rule ip e2e-nat pre tcp dport 8443 redirect to :8081
agent a admin policy "$pol" --ports tcp/8080,tcp/8443 >/dev/null
for _ in $(seq 1 20); do opens a "$addr_b" 8443 && break; sleep 1; done
opens a "$addr_b" 8443 || { sudo ip netns exec ento-b nft list ruleset; fail "A cannot open B:8443, which B redirects to 8081"; }
if opens a "$addr_b" 8081; then fail "A opened B:8081 directly"; fi
sudo ip netns exec ento-b nft delete table ip e2e-nat
agent a admin policy "$pol" --ports tcp/8080,icmp >/dev/null
for _ in $(seq 1 20); do sudo ip netns exec ento-a ping -c1 -W1 "$addr_b" >/dev/null 2>&1 && break; sleep 1; done
sudo ip netns exec ento-a ping -c1 -W1 "$addr_b" >/dev/null || fail "A cannot ping B with icmp in the policy"
agent a admin policy "$pol" --two-way --ports all >/dev/null
for _ in $(seq 1 20); do opens b "$addr_a" 9090 && break; sleep 1; done
opens b "$addr_a" 9090 || fail "B cannot open A:9090 once the policy is two-way again"
opens a "$addr_b" 8081 || fail "A cannot open B:8081 once the policy allows every port again"

if [[ -n "${E2E_PSQL:-}" ]]; then
  step "sign-in approval: A asks for tester, B (tester's other device) picks the number A shows"
  # Single sign-on binds a device to its person; this test has no identity provider, so it binds
  # both devices in the database. B's agent must report 0.21 or later (build the binary so).
  $E2E_PSQL -qc "UPDATE ento_peers SET user_id = 'sub-tester', user_login = 'tester', user_name = 'tester@example.com',
    login_at = now(), person_approved = true, person_active = true, person_since = now(), person_activity_at = now()
    WHERE address IN ('$addr_a', '$addr_b')" -c "UPDATE ento_state SET version = version + 1 WHERE id = 1" \
    -c "SELECT pg_notify('ento_changes', '')" >/dev/null
  # The device's own idea of its person, from its network map.
  for _ in $(seq 1 30); do [[ "$(agent b agent whoami --state-dir "$work/state-b" 2>/dev/null)" == "tester" ]] && break; sleep 1; done
  [[ "$(agent b agent whoami --state-dir "$work/state-b")" == "tester" ]] || fail "whoami does not name the person B is bound to"
  st_out="$(agent b agent status --state-dir "$work/state-b" 2>&1)"
  grep -q "^user: *tester (tester@example.com)" <<<"$st_out" || { echo "$st_out"; sudo cat "$work/state-b/agent.json"; echo; fail "status does not show the person"; }
  ask() { # ask <expected exit> <timeout>; B answers with the number A shows (+1 when <expected exit> is 1)
    local out="$work/approve.out" rc=0
    : > "$out"
    agent a agent approve --state-dir "$work/state-a" --user tester --service sudo --timeout "$2" > "$out" 2>&1 & local pid=$!
    for _ in $(seq 1 40); do grep -q 'pick [0-9]' "$out" && break; sleep 0.25; done
    local n id
    n="$(grep -o 'pick [0-9]*' "$out" | awk '{print $2}')"
    [[ -n "$n" ]] || { cat "$out"; fail "approve printed no number"; }
    if [[ "$1" != 2 ]]; then
      id="$(agent b agent approvals --state-dir "$work/state-b" | awk 'NR == 1 {print $1}')"
      [[ "$1" == 1 ]] && n=$((n == 99 ? 10 : n + 1))
      agent b agent approvals answer --state-dir "$work/state-b" "$id" "$n" >/dev/null
    fi
    wait "$pid" || rc=$?
    [[ "$rc" == "$1" ]] || { cat "$out"; fail "approve exited $rc, expected $1"; }
  }
  ask 0 30s
  ask 1 30s
  ask 2 10s
  rc=0; agent a agent approve --state-dir "$work/state-a" --user nobody --service sudo >/dev/null 2>&1 || rc=$?
  [[ "$rc" == 3 ]] || fail "approve for an unknown person exited $rc, expected 3"
  $E2E_PSQL -qc "UPDATE ento_peers SET user_id = '', user_login = '', user_name = '', login_at = NULL, person_approved = false,
    person_active = false, person_groups = '{}'" \
    -c "UPDATE ento_state SET version = version + 1 WHERE id = 1" -c "SELECT pg_notify('ento_changes', '')" >/dev/null
  for _ in $(seq 1 30); do agent b agent whoami --state-dir "$work/state-b" >/dev/null 2>&1 || break; sleep 1; done
  rc=0; agent b agent whoami --state-dir "$work/state-b" >/dev/null 2>&1 || rc=$?
  [[ "$rc" == 1 ]] || fail "whoami of a device bound to nobody exited $rc, expected 1"
fi

step "internal DNS: A's resolver answers B's name (domain e2e.internal)"
cat > "$work/resolve.py" <<'PY'
import socket, struct, sys
server, name = sys.argv[1], sys.argv[2]
q = struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
q += b"".join(bytes([len(l)]) + l.encode() for l in name.rstrip(".").split(".")) + b"\0" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(q, (server, 53))
r, _ = s.recvfrom(4096)
rcode, ancount = r[3] & 15, struct.unpack(">H", r[6:8])[0]
i = len(q)
for _ in range(ancount):
    if r[i] & 0xC0 == 0xC0:
        i += 2
    else:
        while r[i]:
            i += r[i] + 1
        i += 1
    typ, _, _, rdlen = struct.unpack(">HHIH", r[i:i + 10])
    i += 10
    if typ == 1:
        print(socket.inet_ntoa(r[i:i + 4]))
        sys.exit(0)
    i += rdlen
print("rcode", rcode)
PY
resolve_a() { sudo ip netns exec ento-a python3 "$work/resolve.py" "$addr_a" "$1" 2>&1; }
for _ in $(seq 1 20); do [[ "$(resolve_a peer-b.e2e.internal)" == "$addr_b" ]] && break; sleep 1; done
[[ "$(resolve_a peer-b.e2e.internal)" == "$addr_b" ]] || { resolve_a peer-b.e2e.internal; tail -5 "$work/agent-a.log"; fail "A's resolver does not answer B's name"; }
[[ "$(resolve_a nobody.e2e.internal)" == "rcode 3" ]] || fail "A's resolver invents a name"
[[ "$(agent a agent status --state-dir "$work/state-a")" == *"dns:        e2e.internal, answered by $addr_a"* ]] || fail "status does not show the DNS"
if sudo ip netns exec ento-b python3 "$work/resolve.py" "$addr_a" peer-b.e2e.internal >/dev/null 2>&1; then fail "A's resolver answered another device"; fi

if [[ -n "${E2E_PSQL:-}" && -z "${E2E_USERSPACE:-}" ]]; then # the kernel's table counts (the agent's own WireGuard is unit-tested)
  step "person layer: what A sends beyond its machine's policy is its person's traffic; logout closes the layer, the machine keeps its own"
  pol="$(agent a admin policies | awk '$2 == "admins" && $4 == "servers" {print $1}')"
  agent a admin policy "$pol" --one-way --ports tcp/8080 >/dev/null # the machine's (A is in admins by its token)
  agent a admin allow operators servers --one-way --ports tcp/8081 >/dev/null # the person's
  $E2E_PSQL -qc "UPDATE ento_peers SET user_id = 'sub-tester', user_login = 'tester', user_name = 'tester@example.com', login_at = now(),
    person_approved = true, person_groups = '{operators}', person_active = true, person_since = now(), person_activity_at = now()
    WHERE address = '$addr_a'" -c "UPDATE ento_state SET version = version + 1 WHERE id = 1" -c "SELECT pg_notify('ento_changes', '')" >/dev/null
  counted() { sudo ip netns exec ento-a nft list chain inet ento-filter person 2>/dev/null |
    awk '{for (i = 1; i < NF; i++) if ($i == "bytes") s += $(i + 1)} END {print s + 0}'; }
  for _ in $(seq 1 20); do sudo ip netns exec ento-a nft list chain inet ento-filter person >/dev/null 2>&1 && break; sleep 1; done
  sudo ip netns exec ento-a nft list chain inet ento-filter person >/dev/null 2>&1 || fail "no person chain on A with its person layer open"
  for _ in $(seq 1 10); do opens a "$addr_b" 8081 && break; sleep 1; done
  before="$(counted)"
  opens a "$addr_b" 8080 || fail "A cannot open B:8080 (its machine's)"
  [[ "$(counted)" == "$before" ]] || fail "the machine's traffic counted as the person's ($before, then $(counted))"
  opens a "$addr_b" 8081 || fail "A cannot open B:8081 (its person's)"
  (( "$(counted)" > before )) || fail "the person's traffic is not counted"
  st_out="$(agent a agent status --state-dir "$work/state-a")"
  [[ "$st_out" == *"session:    open since"* ]] || { echo "$st_out"; fail "status does not show the open session"; }
  [[ "$(agent a agent logout --state-dir "$work/state-a")" == "signed out"* ]] || fail "logout did not say it signed out"
  [[ "$($E2E_PSQL -tAc "SELECT person_active FROM ento_peers WHERE address = '$addr_a'")" == "f" ]] || fail "logout did not close the person layer"
  for _ in $(seq 1 20); do opens a "$addr_b" 8081 || break; sleep 1; done
  if opens a "$addr_b" 8081; then fail "A still opens its person's port after logout"; fi
  opens a "$addr_b" 8080 || fail "A lost its machine's port at logout"
  [[ "$(agent a agent logout --state-dir "$work/state-a")" == "signed out"* ]] || fail "a second logout"
  agent a admin disallow "$(agent a admin policies | awk '$2 == "operators" {print $1}')" >/dev/null
  agent a admin policy "$pol" --two-way --ports all >/dev/null
  $E2E_PSQL -qc "UPDATE ento_peers SET user_id = '', user_login = '', user_name = '', login_at = NULL, person_approved = false,
    person_active = false, person_groups = '{}'" -c "UPDATE ento_state SET version = version + 1 WHERE id = 1" \
    -c "SELECT pg_notify('ento_changes', '')" >/dev/null
  for _ in $(seq 1 20); do opens b "$addr_a" 9090 && break; sleep 1; done
fi

step "a second agent on B's state refuses to start (it would trade B's check-in tokens)"
out="$(sudo ip netns exec ento-b timeout 10 "$bin" agent run --state-dir "$work/state-b" "${userspace_b[@]}" 2>&1)" && fail "a second agent started on B's state"
grep -q "another agent" <<<"$out" || fail "the second agent did not say why: $out"

step "check-ins: both agents checked in and keep their next token"
checked_in() { agent a admin peers --json | python3 -c 'import json,sys
print(sum(1 for p in json.load(sys.stdin) if p.get("checked_in_at")))'; }
for _ in $(seq 1 20); do [[ "$(checked_in)" == 2 ]] && break; sleep 1; done
[[ "$(checked_in)" == 2 ]] || fail "not both agents checked in"
sudo test -s "$work/state-b/checkin.token" || fail "B keeps no check-in token"

if [[ -z "${E2E_USERSPACE:-}" ]]; then # a gateway forwards with the kernel's WireGuard
  step "route: B is the gateway of a LAN (namespace ento-lan); A reaches it on the policy's port only"
  sudo ip netns add ento-lan
  sudo ip link add ento-lanb netns ento-b type veth peer name eth0 netns ento-lan
  sudo ip netns exec ento-b ip addr add 10.210.0.1/24 dev ento-lanb
  sudo ip netns exec ento-b ip link set ento-lanb up
  sudo ip netns exec ento-lan ip addr add 10.210.0.2/24 dev eth0
  sudo ip netns exec ento-lan ip link set eth0 up
  sudo ip netns exec ento-lan ip link set lo up
  for p in 8080 8081; do
    sudo ip netns exec ento-lan python3 -m http.server "$p" --bind 10.210.0.2 --directory "$work/www" > "$work/http-lan-$p.log" 2>&1 &
  done
  cat > "$work/dns-lan.py" <<'PY'
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.210.0.2", 53))
while True:  # every name is 10.210.0.77
    q, a = s.recvfrom(4096)
    end = 12
    while q[end]:
        end += q[end] + 1
    end += 5
    r = q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x01\x00\x00\x00\x00" + q[12:end]
    r += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("10.210.0.77")
    s.sendto(r, a)
PY
  agent a admin route add lab 10.210.0.0/24 --via peer-b >/dev/null
  if opens a 10.210.0.2 8080; then fail "A reached the LAN without a policy to the route"; fi
  agent a admin allow admins route:lab --ports tcp/8080,udp/53 >/dev/null
  for _ in $(seq 1 20); do opens a 10.210.0.2 8080 && break; sleep 1; done
  opens a 10.210.0.2 8080 || { sudo ip netns exec ento-b nft list ruleset; sudo ip netns exec ento-a ip route; fail "A cannot reach the LAN through the route"; }
  if opens a 10.210.0.2 8081; then fail "A reached a LAN port the policy does not allow"; fi
  if opens a 10.210.0.1 22; then fail "A reached the gateway's own LAN address through the route"; fi
  sudo ip netns exec ento-a curl -s -o /dev/null --max-time 5 http://10.210.0.2:8080/ || fail "no HTTP answer through the route"
  grep -q '10.210.0.1 ' "$work/http-lan-8080.log" || fail "the LAN saw another address than the gateway's: $(tail -2 "$work/http-lan-8080.log")"
  # Names in the LAN: one given by an admin, and a zone forwarded to the LAN's own name server.
  sudo ip netns exec ento-lan python3 "$work/dns-lan.py" > "$work/dns-lan.log" 2>&1 &
  agent a admin dns add nas.lab 10.210.0.2 >/dev/null
  agent a admin dns forward office.test 10.210.0.2 >/dev/null
  for _ in $(seq 1 20); do [[ "$(resolve_a nas.lab.e2e.internal)" == "10.210.0.2" ]] && break; sleep 1; done
  [[ "$(resolve_a nas.lab.e2e.internal)" == "10.210.0.2" ]] || fail "A does not resolve the name given to the LAN's machine"
  for _ in $(seq 1 10); do [[ "$(resolve_a printer.office.test)" == "10.210.0.77" ]] && break; sleep 1; done
  [[ "$(resolve_a printer.office.test)" == "10.210.0.77" ]] || { resolve_a printer.office.test; fail "A's resolver does not ask the forwarded zone's server through the route"; }
  agent a admin dns delete nas.lab
  agent a admin dns unforward office.test
  # The LAN only answers: with a route to the network through the gateway, it still opens nothing.
  sudo ip netns exec ento-lan ip route add 100.64.0.0/16 via 10.210.0.1
  if sudo ip netns exec ento-lan timeout 3 bash -c "</dev/tcp/$addr_a/9090" 2>/dev/null; then fail "the LAN opened a connection into the network"; fi
  pol="$(agent a admin policies | awk '$4 == "route:lab" {print $1}')"
  agent a admin disallow "$pol" >/dev/null
  for _ in $(seq 1 20); do opens a 10.210.0.2 8080 || break; sleep 1; done
  if opens a 10.210.0.2 8080; then fail "A still reaches the LAN once the policy is gone"; fi
  agent a admin route delete lab
  sudo ip netns del ento-lan

  status_a() { agent a agent status --state-dir "$work/state-a"; } # whole, not cut short by grep -q (pipefail)
  step "exit: B is an exit into namespace ento-inet (the internet); A sends its internet traffic through it"
  sudo ip netns add ento-inet
  sudo ip link add ento-inetb netns ento-b type veth peer name eth0 netns ento-inet
  sudo ip netns exec ento-b ip addr add 203.0.113.1/24 dev ento-inetb
  sudo ip netns exec ento-b ip link set ento-inetb up
  sudo ip netns exec ento-inet ip addr add 203.0.113.2/24 dev eth0
  sudo ip netns exec ento-inet ip addr add 10.220.0.2/32 dev eth0 # a private address beyond the exit
  sudo ip netns exec ento-inet ip link set eth0 up
  sudo ip netns exec ento-inet ip link set lo up
  sudo ip netns exec ento-inet ip route add default via 203.0.113.1
  sudo ip netns exec ento-b ip route add 10.220.0.0/24 via 203.0.113.2
  sudo ip netns exec ento-inet python3 -m http.server 80 --directory "$work/www" > "$work/http-inet.log" 2>&1 &
  sudo ip netns exec ento-b python3 -m http.server 8090 --bind 203.0.113.1 --directory "$work/www" > "$work/http-gw.log" 2>&1 &
  cat > "$work/dns.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 53))
while True:
    q, a = s.recvfrom(4096)
    r = bytearray(q)
    r[2] |= 0x80  # an answer (no records: enough to show it came back)
    s.sendto(bytes(r), a)
PY
  cat > "$work/ask.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
q = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
s.sendto(q, (sys.argv[1], 53))
r, _ = s.recvfrom(4096)
sys.exit(0 if r[:2] == q[:2] and r[2] & 0x80 else 1)
PY
  sudo ip netns exec ento-inet python3 "$work/dns.py" 203.0.113.2 > "$work/dns-inet.log" 2>&1 &
  for _ in $(seq 1 20); do opens b 203.0.113.2 80 && break; sleep 0.5; done
  opens b 203.0.113.2 80 || fail "the internet namespace does not answer B"
  opens b 10.220.0.2 80 || fail "the private address beyond the exit does not answer B"
  if opens a 203.0.113.2 80; then fail "A reaches the internet namespace without the exit"; fi
  agent a admin route add internet --exit --via peer-b >/dev/null
  [[ "$(agent a admin routes)" == *$'\n'"internet  exit"* ]] || fail "the exit is not listed"
  agent a admin allow admins route:internet >/dev/null
  exits_a() { agent a agent exit --state-dir "$work/state-a"; }
  for _ in $(seq 1 20); do [[ "$(exits_a)" == *"internet through peer-b"* ]] && break; sleep 1; done
  [[ "$(exits_a)" == *"internet through peer-b: offered"* ]] || { exits_a; fail "A is not offered the exit"; }
  [[ "$(agent a agent exit --state-dir "$work/state-a" internet)" == *"IN USE"* ]] || { tail -5 "$work/agent-a.log"; fail "A did not start using the exit"; }
  for _ in $(seq 1 20); do opens a 203.0.113.2 80 && break; sleep 1; done
  opens a 203.0.113.2 80 || { sudo ip netns exec ento-a ip rule; sudo ip netns exec ento-a ip route show table all | grep -v local;
    sudo ip netns exec ento-b nft list table inet ento-filter; fail "A cannot reach the internet through the exit"; }
  sudo ip netns exec ento-a curl -s -o /dev/null --max-time 5 http://203.0.113.2/ || fail "no HTTP answer through the exit"
  grep -q '203.0.113.1 ' "$work/http-inet.log" || fail "the internet saw another address than the exit's: $(tail -2 "$work/http-inet.log")"
  sudo ip netns exec ento-a ping -c1 -W2 "$addr_b" >/dev/null || fail "A lost B while using the exit (WireGuard's packets must bypass it)"
  if opens a 10.220.0.2 80; then fail "the exit forwarded to a private address"; fi
  if opens a 203.0.113.1 8090; then fail "the exit let A open a service on the gateway's own address"; fi
  opens inet 203.0.113.1 8090 || fail "the gateway's service does not answer its own network (the check above proves nothing)"
  sudo ip netns exec ento-a python3 "$work/ask.py" "$addr_b" || fail "the exit does not answer A's DNS"
  [[ "$(resolve_a example.com)" == "rcode 0" ]] || { resolve_a example.com; fail "A's resolver does not ask the exit for other names"; }
  [[ "$(sudo ip netns exec ento-a ip -6 route show table all)" == *"unreachable default"* ]] || fail "IPv6 is not blocked beside the exit"
  [[ "$(status_a)" == *"exit:       internet through peer-b: IN USE"* ]] || { status_a; fail "status does not show the exit in use"; }
  [[ "$(agent b agent status --state-dir "$work/state-b")" == *"exit for:   other devices"* ]] || fail "B's status does not say it is an exit"
  [[ "$(agent a agent exit --state-dir "$work/state-a" off)" == *"no exit"* ]] || fail "A did not stop using the exit"
  if opens a 203.0.113.2 80; then fail "A still reaches the internet namespace with the exit off"; fi
  [[ "$(resolve_a example.com)" == "rcode 5" ]] || fail "A's resolver answers other names without an exit"
  if [[ "$(sudo ip netns exec ento-a ip rule)" == *"3177"[01]":"* ]]; then fail "the exit's routing rules stay"; fi
  [[ -z "$(sudo ip netns exec ento-a ip route show table 30835; sudo ip netns exec ento-a ip -6 route show table 30835)" ]] ||
    fail "the exit's routing table stays"
  # Used by default: A uses it without choosing it (its choice back to the default), until it turns it off.
  pol="$(agent a admin policies | awk '$4 == "route:internet" {print $1}')"
  agent a admin disallow "$pol" >/dev/null
  agent a admin route delete internet
  agent a admin route add internet --exit --default --via peer-b >/dev/null
  agent a admin allow admins route:internet >/dev/null
  agent a agent exit --state-dir "$work/state-a" default >/dev/null
  for _ in $(seq 1 20); do [[ "$(exits_a)" == *"IN USE"* ]] && break; sleep 1; done
  [[ "$(exits_a)" == *"IN USE"* ]] || { exits_a; fail "A does not use the exit used by default"; }
  for _ in $(seq 1 20); do opens a 203.0.113.2 80 && break; sleep 1; done
  opens a 203.0.113.2 80 || fail "A cannot reach the internet through the exit used by default"
  agent a agent exit --state-dir "$work/state-a" off >/dev/null
  pol="$(agent a admin policies | awk '$4 == "route:internet" {print $1}')"
  agent a admin disallow "$pol" >/dev/null
  agent a admin route delete internet
  agent a agent exit --state-dir "$work/state-a" default >/dev/null
  sudo ip netns del ento-inet
fi

step "posture: both agents reported (the namespaces have no firewall)"
for _ in $(seq 1 30); do [[ "$(posture_of "$addr_b" firewall)" == "false" ]] && break; sleep 1; done
for addr in "$addr_a" "$addr_b"; do
  [[ "$(posture_of "$addr" os)" == '"linux"' && "$(posture_of "$addr" firewall)" == "false" ]] ||
    { agent a admin peers --json; fail "no posture report from $addr"; }
done
[[ "$(posture_of "$addr_a" os_version)" == "\"$(uname -r)\"" ]] || fail "kernel release not reported"
agent a admin peers

step "posture: a policy requiring a firewall leaves A (its source) out"
agent a admin posture add fw --firewall
agent a admin posture | grep -q "^fw " || fail "check not listed"
pol="$(agent a admin policies | awk '$2 == "admins" && $4 == "servers" {print $1}')"
agent a admin policy "$pol" --posture fw >/dev/null
agent a admin policies | grep -q "admins *<-> *servers *all *fw" || fail "policy does not show its check"
for _ in $(seq 1 30); do sudo ip netns exec ento-a ping -c1 -W1 "$addr_b" >/dev/null 2>&1 || break; sleep 1; done
if sudo ip netns exec ento-a ping -c1 -W1 "$addr_b" >/dev/null 2>&1; then fail "A reaches B without a firewall"; fi
status_a() { agent a agent status --state-dir "$work/state-a"; } # whole, not cut short by grep -q (pipefail)
for _ in $(seq 1 10); do [[ "$(status_a)" == *"FAILS check fw: firewall off"* ]] && break; sleep 1; done
[[ "$(status_a)" == *"FAILS check fw: firewall off"* ]] || { status_a; fail "status does not show the failing check"; }
grep -q 'action=posture_failed .*check=fw reason=firewall off' "$work/control.log" || fail "failure not audited"
if agent b admin posture add x 2>/dev/null; then fail "a non-admin added a check"; fi

step "posture: a chain that drops some packets only is no firewall"
sudo ip netns exec ento-a nft -f - <<'NFT'
table inet e2e {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 9 drop
  }
}
NFT
[[ "$(agent a agent posture --json | python3 -c 'import json,sys; print(json.load(sys.stdin).get("firewall"))')" == "False" ]] ||
  fail "a chain dropping one port counts as a firewall"

step "posture: A gets a firewall (an input chain ending in drop), reports it, and is let in again (after the 2-minute hold-down)"
sudo ip netns exec ento-a nft delete table inet e2e
sudo ip netns exec ento-a nft -f - <<'NFT'
table inet e2e {
  chain input {
    type filter hook input priority 0; policy accept;
    ct state established,related accept
    iifname "lo" accept
    meta l4proto udp accept
    iifname "ento0" accept
    drop
  }
}
NFT
for _ in $(seq 1 240); do sudo ip netns exec ento-a ping -c1 -W1 "$addr_b" >/dev/null 2>&1 && break; sleep 1; done
sudo ip netns exec ento-a ping -c2 -W2 "$addr_b" >/dev/null || { cat "$work/agent-a.log"; fail "A does not reach B with a firewall"; }
[[ "$(posture_of "$addr_a" firewall)" == "true" ]] || fail "firewall not reported"
grep -q 'action=posture_passed .*check=fw' "$work/control.log" || fail "pass not audited"
for _ in $(seq 1 10); do [[ "$(status_a)" != *FAILS* ]] && break; sleep 1; done
if [[ "$(status_a)" == *FAILS* ]]; then fail "status still shows a failing check"; fi

if command -v swtpm >/dev/null; then
  step "hardware key: B binds a key its (software) TPM holds, signs its check-ins and changes its WireGuard key on schedule; a copy of B's state on a machine with another TPM is refused, and B's next key change shuts it out"
  start_swtpm() { # start_swtpm NAME: a software TPM on $work/NAME.sock
    mkdir -p "$work/$1-state"
    swtpm socket --tpm2 --tpmstate dir="$work/$1-state" --server type=unixio,path="$work/$1.sock" \
      --ctrl type=unixio,path="$work/$1.ctrl" --flags startup-clear,not-need-init --daemon
  }
  wait_for() { # wait_for SECONDS FILE PATTERN
    for _ in $(seq 1 "$1"); do grep -q -- "$3" "$2" && return 0; sleep 1; done
    return 1
  }
  pub_of() { sudo python3 -c 'import json,sys,base64,subprocess; print(json.load(open(sys.argv[1]))["private_key"])' "$1/state.json" | "$bin" pubkey; }
  start_swtpm tpm-b
  start_swtpm tpm-c
  agent b agent down --state-dir "$work/state-b" >/dev/null
  sudo ENTO_CHECKIN_EVERY=5s ENTO_KEY_ROTATE_EVERY=25s ip netns exec ento-b "$bin" agent run --state-dir "$work/state-b" --log-drops \
    --tpm-device "$work/tpm-b.sock" "${userspace_b[@]}" >> "$work/agent-b.log" 2>&1 &
  wait_for 60 "$work/agent-b.log" "hardware key (tpm) bound" || { tail -20 "$work/agent-b.log"; fail "B did not bind its hardware key"; }
  grep -q "action=hwkey_bound" "$work/control.log" || fail "the binding is not audited"
  [[ "$(agent a admin peers --json | python3 -c 'import json,sys,os; print([p.get("hardware_key","") for p in json.load(sys.stdin) if p["address"] == sys.argv[1]][0])' "$addr_b")" == tpm ]] ||
    fail "peers does not show B's hardware key"
  [[ "$(agent b agent status --state-dir "$work/state-b")" == *"hw key:     tpm, bound"* ]] || fail "status does not show the bound key"
  key_b0="$(pub_of "$work/state-b")"
  wait_for 90 "$work/agent-b.log" "WireGuard key changed (daily)" || { tail -20 "$work/agent-b.log"; fail "B did not change its key on schedule"; }
  wait_for 30 "$work/agent-b.log" "key change settled" || { tail -20 "$work/agent-b.log"; fail "the control plane does not answer B's new key"; }
  [[ "$(pub_of "$work/state-b")" != "$key_b0" ]] || fail "B's state keeps the old key"
  grep -q "action=key_rotated .*result=ok" "$work/control.log" || fail "the key change is not audited"
  for _ in $(seq 1 30); do sudo ip netns exec ento-a ping -c1 -W1 "$addr_b" >/dev/null 2>&1 && break; sleep 1; done
  sudo ip netns exec ento-a ping -c2 -W2 "$addr_b" >/dev/null || fail "A does not reach B after its key changed"

  # A copy of B's whole state (key, token, TPM blob) on machine C, which has another TPM.
  sudo ip netns add ento-c
  sudo ip link add ento-vc type veth peer name eth0 netns ento-c
  sudo ip addr add 10.200.4.1/24 dev ento-vc
  sudo ip link set ento-vc up
  sudo ip netns exec ento-c ip addr add 10.200.4.2/24 dev eth0
  sudo ip netns exec ento-c ip link set eth0 up
  sudo ip netns exec ento-c ip link set lo up
  sudo ip netns exec ento-c ip route add default via 10.200.4.1
  sudo cp -a "$work/state-b" "$work/state-c"
  sudo rm -f "$work/state-c/agent.json"
  key_b1="$(pub_of "$work/state-b")"
  sudo ENTO_CHECKIN_EVERY=5s ip netns exec ento-c "$bin" agent run --state-dir "$work/state-c" --interface ento2 \
    --tpm-device "$work/tpm-c.sock" "${userspace[@]}" > "$work/agent-c.log" 2>&1 &
  c_pid=$!
  wait_for 60 "$work/control.log" "no hardware signature" || { tail -10 "$work/agent-c.log"; fail "the copy's check-in was not refused"; }
  grep -q "the TPM does not take the key" "$work/agent-c.log" || fail "the copy used B's TPM key on another TPM"
  wait_for 120 "$work/agent-b.log" "WireGuard key changed (asked by the control plane)" || { tail -20 "$work/agent-b.log"; fail "B did not change its key after the copy"; }
  [[ "$(pub_of "$work/state-b")" != "$key_b1" ]] || fail "B kept the key the copy holds"
  sleep 5
  if sudo ip netns exec ento-c curl -sf -o /dev/null --max-time 5 "http://$ctl_addr/v1/netmap"; then fail "the copy still reaches the control plane"; fi
  for _ in $(seq 1 30); do sudo ip netns exec ento-a ping -c1 -W1 "$addr_b" >/dev/null 2>&1 && break; sleep 1; done
  sudo ip netns exec ento-a ping -c2 -W2 "$addr_b" >/dev/null || fail "A does not reach B after the copy was shut out"
  if grep -q "suspended" <(agent a admin peers | awk -v a="$addr_b" '$3 == a'); then fail "B was suspended"; fi
  sudo kill "$c_pid" 2>/dev/null; wait "$c_pid" 2>/dev/null || true
  sudo ip netns del ento-c

  # An administrator releases the binding (e.g. a cleared TPM): B binds again at its next check-in.
  agent a admin unbind "$id_b" >/dev/null || fail "unbind"
  grep -q "action=hwkey_unbound" "$work/control.log" || fail "the release is not audited"
fi

step "moved control node: it serves another endpoint, the old one is unreachable; B finds the new one in the network record"
# The record as it will be published, with the new endpoint, served for _ento.e2e.test on the
# host, which B's resolver asks from now on.
echo "${record//10.200.0.1:51821/10.200.0.9:51821}" > "$work/record-moved"
cat > "$work/dns-record.py" <<'PY'
import socket, struct, sys
rec = open(sys.argv[2]).read().strip().encode()
txt = b"".join(bytes([len(rec[i:i + 255])]) + rec[i:i + 255] for i in range(0, len(rec), 255))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 53))
while True:  # a TXT question for any name gets the record; others no answer
    q, a = s.recvfrom(4096)
    end = 12
    while q[end]:
        end += q[end] + 1
    qtype = struct.unpack(">H", q[end + 1:end + 3])[0]
    end += 5
    answers = 1 if qtype == 16 else 0
    r = q[:2] + b"\x81\x80" + q[4:6] + struct.pack(">HHH", answers, 0, 0) + q[12:end]
    if answers:
        r += b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, len(txt)) + txt
    s.sendto(r, a)
PY
sudo python3 "$work/dns-record.py" 10.200.0.1 "$work/record-moved" > "$work/dns-record.log" 2>&1 &
if [[ -n "$made_netns_conf" ]]; then
  echo "nameserver 10.200.0.1" | sudo tee /etc/netns/ento-b/resolv.conf >/dev/null
fi
agent b agent down --state-dir "$work/state-b"
kill "$ctl_pid"; wait "$ctl_pid" 2>/dev/null || true
sudo ip addr add 10.200.0.9/32 dev lo
# The old endpoint is gone; the control node's packets to B now leave from the new address (a
# server with a new public address); and B is as if behind NAT: only answers to what it sent come
# in (here, without NAT, the control node would otherwise take up the session from its side,
# which WireGuard allows, and B would never miss it).
sudo iptables -I INPUT -d 10.200.0.1 -p udp --dport 51821 -j DROP
moved_rule=1
sudo ip route replace 10.200.3.0/24 dev ento-vb src 10.200.0.9
sudo ip netns exec ento-b iptables -I INPUT -p udp -s 10.200.0.0/24 -m conntrack --ctstate NEW -j DROP
"$bin" control run --name ctl-1 --key-file "$work/control.key" --listen-port 51821 \
  --endpoint 10.200.0.9:51821 --dns-domain e2e.internal --record-domain e2e.test >> "$work/control.log" 2>&1 &
ctl_pid=$!
for _ in $(seq 1 50); do [[ "$(grep -c "control node ctl-1 up" "$work/control.log")" == 2 ]] && break; sleep 0.2; done
[[ "$(grep -c "control node ctl-1 up" "$work/control.log")" == 2 ]] || { tail -5 "$work/control.log"; fail "the control node did not start again"; }
# B knows the record's domain from its last network map; it starts with the old endpoint only.
sudo python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); sys.exit(0 if s.get("record_domain") == "e2e.test" else 1)' "$work/state-b/state.json" ||
  fail "B did not keep the record domain"
sudo ENTO_MOVED_AFTER=10s ip netns exec ento-b "$bin" agent run --state-dir "$work/state-b" "${userspace_b[@]}" >> "$work/agent-b.log" 2>&1 &
for _ in $(seq 1 120); do grep -q 'control nodes moved, says the network record _ento.e2e.test: "ctl-1" from 10.200.0.1:51821 to 10.200.0.9:51821' "$work/agent-b.log" && break; sleep 1; done
grep -q 'control nodes moved' "$work/agent-b.log" || { tail -20 "$work/agent-b.log"; fail "B did not look up where the control node went"; }
for _ in $(seq 1 30); do sudo ip netns exec ento-b curl -sf -o /dev/null --max-time 3 "http://$ctl_addr/v1/netmap" && break; sleep 1; done
sudo ip netns exec ento-b curl -sf -o /dev/null --max-time 3 "http://$ctl_addr/v1/netmap" || { sudo ip netns exec ento-b wg show; fail "B does not reach the control node at its new endpoint"; }
sudo python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); sys.exit(0 if s["controls"][0]["endpoint"] == "10.200.0.9:51821" else 1)' "$work/state-b/state.json" ||
  fail "B's state does not keep the new endpoint"

printf '\nPASS\n'
