#!/usr/bin/env bash
# End-to-end test of linked networks on one Linux host: three independent ento deployments
# (home, acme, beta), each with its own control node and database, and one device per network in
# network namespaces, using kernel WireGuard.
#
#   op    (ns en-op,   home network)  links to acme and beta: namespaces ento-acme, ento-beta
#   srv-a (ns en-srva, acme network)
#   srv-b (ns en-srvb, beta network)
#   control nodes home/acme/beta: host namespace, 10.200.0.1:5192{1,2,3}
#
# Checks: link and authority setup, joining with credentials, groups and names prefixed with the authority,
# reachability only from the linked network's own namespace, no inbound connections from a linked
# network, no path between linked networks, hosts file, a home service forwarded into a linked
# namespace (which the linked network cannot take over), the proxy into a linked network, unlinking,
# `ento agent down` (the home and linked interfaces go away; the next start rejoins), and
# revocation by the linked network. Needs root (sudo), the wireguard kernel module, nsenter/unshare and a PostgreSQL server
# the test may create databases on (ENTO_TEST_POSTGRES, a DSN of its maintenance database).
#
# With E2E_BLOCK_DIRECT=1, UDP between op and srv-a is dropped, so acme traffic must be relayed
# through acme's control node.
#
# Usage: ENTO_TEST_POSTGRES=postgres://user:pass@host:port/postgres [E2E_BLOCK_DIRECT=1] [E2E_USERSPACE=1] test/e2e-linked.sh path/to/ento
set -euo pipefail

bin="$(realpath "${1:?usage: $0 path/to/ento}")"
: "${ENTO_TEST_POSTGRES:?set ENTO_TEST_POSTGRES to a PostgreSQL maintenance DSN}"
work="$(mktemp -d)"
pids=()
namespaces=(en-op en-srva en-srvb)

cleanup() {
  set +e
  sudo pkill -f "$work/" 2>/dev/null
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
  for ns in "${namespaces[@]}" ento-acme ento-beta; do sudo ip netns del "$ns" 2>/dev/null; done
  for v in op srva srvb; do sudo ip link del "en-v$v" 2>/dev/null; done
  sudo rm -rf /etc/netns/ento-acme /etc/netns/ento-beta
  sudo ip addr del 10.200.0.1/32 dev lo 2>/dev/null
  sudo iptables -D FORWARD -s 10.200.0.0/16 -d 10.200.0.0/16 -j ACCEPT 2>/dev/null
  sudo iptables -D FORWARD -s 10.200.2.0/24 -d 10.200.3.0/24 -p udp -j DROP 2>/dev/null
  sudo iptables -D FORWARD -s 10.200.3.0/24 -d 10.200.2.0/24 -p udp -j DROP 2>/dev/null
  if [[ -n "${KEEP:-}" ]]; then echo "kept $work"; else sudo rm -rf "$work"; fi
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
fail() {
  echo "FAIL: $*" >&2
  for f in "$work"/*.log; do echo "--- $f"; tail -n 30 "$f"; done
  exit 1
}

# in <ns> <cmd...>: run in a device's network namespace only (the mount namespace stays the
# host's, so namespaces created by the agent are visible to everyone, as under systemd).
inns() { local ns="$1"; shift; sudo nsenter --net="/run/netns/$ns" "$@"; }
# as <ns> <hostname> <cmd...>: same, with its own hostname (what agents report).
as() { local ns="$1" host="$2"; shift 2; sudo nsenter --net="/run/netns/$ns" unshare --uts sh -c 'hostname "$0"; exec "$@"' "$host" "$@"; }
admin() { local ns="$1" state="$2"; shift 2; inns "$ns" env ENTO_STATE_DIR="$state" "$bin" admin "$@"; }
addr_of() { sudo python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["address"])' "$1"; }
wait_for() { # wait_for <seconds> <cmd...>
  local t="$1"; shift
  for _ in $(seq 1 "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

step "network namespaces"
sudo sysctl -qw net.ipv4.ip_forward=1
sudo iptables -I FORWARD -s 10.200.0.0/16 -d 10.200.0.0/16 -j ACCEPT
if [[ -n "${E2E_BLOCK_DIRECT:-}" ]]; then
  echo "blocking direct UDP between op and srv-a"
  sudo iptables -I FORWARD -s 10.200.2.0/24 -d 10.200.3.0/24 -p udp -j DROP
  sudo iptables -I FORWARD -s 10.200.3.0/24 -d 10.200.2.0/24 -p udp -j DROP
fi
sudo ip addr add 10.200.0.1/32 dev lo
i=1
for v in op srva srvb; do
  i=$((i + 1))
  sudo ip netns add "en-$v"
  sudo ip link add "en-v$v" type veth peer name eth0 netns "en-$v"
  sudo ip addr add "10.200.$i.1/24" dev "en-v$v"
  sudo ip link set "en-v$v" up
  sudo ip netns exec "en-$v" ip addr add "10.200.$i.2/24" dev eth0
  sudo ip netns exec "en-$v" ip link set eth0 up
  sudo ip netns exec "en-$v" ip link set lo up
  sudo ip netns exec "en-$v" ip route add default via "10.200.$i.1"
done

step "databases"
base="${ENTO_TEST_POSTGRES%/*}"
for db in home acme beta; do
  docker run --rm --network host postgres:18-alpine psql "$ENTO_TEST_POSTGRES" -qc "DROP DATABASE IF EXISTS ento_e2e_$db" >/dev/null
  docker run --rm --network host postgres:18-alpine psql "$ENTO_TEST_POSTGRES" -qc "CREATE DATABASE ento_e2e_$db" >/dev/null
done

step "control nodes"
port=51920
for net in home:100.80.0.0/16 acme:100.81.0.0/16 beta:100.82.0.0/16; do
  name="${net%%:*}" prefix="${net#*:}"
  port=$((port + 1))
  "$bin" genkey > "$work/$name.key"
  chmod 600 "$work/$name.key"
  # home forwards a service (on op's own address, the first in home) into linked namespaces;
  # acme tries to publish the same name for its own address, which op's agent must ignore.
  extra=()
  [[ $name == home ]] && extra=(--link-forwards "svc.home.test:8080=100.80.1.1:8080")
  [[ $name == acme ]] && extra=(--hosts "svc.home.test=100.81.0.1")
  ENTO_DATABASE_URL="$base/ento_e2e_$name" "$bin" control run --name "$name-1" --key-file "$work/$name.key" \
    --listen-port "$port" --endpoint "10.200.0.1:$port" --network "$prefix" "${extra[@]}" > "$work/control-$name.log" 2>&1 &
  pids+=($!)
  wait_for 10 grep -q "control node $name-1 up" "$work/control-$name.log" || fail "control node $name did not start"
  # The servers get their names from their tokens; op names itself after its host name.
  device=()
  [[ $name == acme ]] && device=(--name srv-a)
  [[ $name == beta ]] && device=(--name srv-b)
  ENTO_DATABASE_URL="$base/ento_e2e_$name" "$bin" control token --network "$prefix" --admin --approve \
    --groups "$([[ $name == home ]] && echo admins,operators || echo servers)" "${device[@]}" --out "$work/$name.token" 2>/dev/null
done

# E2E_USERSPACE=1: every device runs WireGuard inside the agent (as on macOS and Windows) instead
# of the kernel's; linked networks stay on kernel interfaces in their namespaces.
userspace=()
[[ -n "${E2E_USERSPACE:-}" ]] && userspace=(--userspace)

step "one device per network: op (home), srv-a (acme), srv-b (beta)"
start_agent() { # start_agent <ns> <hostname> <state> <token>
  as "$1" "$2" "$bin" agent up --state-dir "$3" --token-file "$4" "${userspace[@]}" > "$work/agent-$2.log" 2>&1 &
  pids+=($!)
  wait_for 20 sudo test -f "$3/state.json" || fail "$2 did not enroll"
}
start_agent en-op op "$work/state-op" "$work/home.token"
start_agent en-srva srv-a "$work/state-a" "$work/acme.token"
start_agent en-srvb srv-b "$work/state-b" "$work/beta.token"
if [[ -n "${E2E_USERSPACE:-}" ]]; then
  inns en-op ip -d link show ento0 | grep -qw tun || fail "op's ento0 is not a TUN interface (userspace WireGuard)"
  inns en-op wg show ento0 >/dev/null || fail "the in-process device does not answer on the WireGuard control socket"
fi
srv_a="$(addr_of "$work/state-a/state.json")"
srv_b="$(addr_of "$work/state-b/state.json")"
echo "srv-a = $srv_a (acme), srv-b = $srv_b (beta)"

step "home creates the links; acme and beta register home as an authority"
for net in acme:en-srva:state-a beta:en-srvb:state-b; do
  IFS=: read -r name ns state <<<"$net"
  # acme's credentials last 30 s, so the test sees them renewed.
  ttl=1h; [[ $name == acme ]] && ttl=30s
  key="$(admin en-op "$work/state-op" link create "$name" --groups operators --grant operators,admins --ttl "$ttl" 2>/dev/null)"
  [[ "$key" == entoa1:* ]] || fail "no authority key for $name: $key"
  admin "$ns" "$work/$state" authority add home --key "$key" --groups operators --max-ttl 1h --out "$work/$name-authority.token" 2>/dev/null
  sudo chown "$(id -u)" "$work/$name-authority.token"
  admin "$ns" "$work/$state" allow home:operators servers >/dev/null
  admin en-op "$work/state-op" link token "$name" --token-file "$work/$name-authority.token"
done
admin en-op "$work/state-op" links

step "op joins acme"
inns en-op "$bin" agent link --state-dir "$work/state-op" acme || fail "joining acme"
admin en-srva "$work/state-a" peers
admin en-srva "$work/state-a" peers | grep -q "home:operators" || fail "op not admitted with home:operators"
admin en-srva "$work/state-a" peers | grep "home:op" | grep -q "admins" && fail "op got a group the authority may not assign"
admin en-srva "$work/state-a" peers | awk '$2 == "home-op"' | grep -q . || fail "op is not named home-op in acme (authority + its name at home)"
admin en-op "$work/state-op" peers | awk '$2 == "z-op"' | grep -q . || fail "op is not named z-op at home"

step "acme is reachable from namespace ento-acme, by address and by name"
wait_for 60 sudo ip netns exec ento-acme ping -c1 -W1 "$srv_a" || fail "ento-acme cannot reach srv-a"
sudo ip netns exec ento-acme ping -c2 -W2 srv-a || fail "srv-a does not resolve in ento-acme"

if [[ -n "${E2E_BLOCK_DIRECT:-}" ]]; then
  step "the acme path is relayed"
  sudo ip netns exec ento-acme wg show enl-acme endpoints | grep -q "127.0.0.1:" || fail "srv-a is not relayed"
fi

op_in_acme_pre="$(sudo python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["address"])' "$work/state-op/links/acme/state.json")"
step "home's forwarded service is reachable inside ento-acme, under its name only from home"
op_home="$(addr_of "$work/state-op/state.json")"
[[ "$op_home" == 100.80.1.1 ]] || fail "op got $op_home in home, the forward expects 100.80.1.1"
mkdir -p "$work/www" && echo forwarded > "$work/www/index.html"
inns en-op python3 -m http.server 8080 --bind "$op_home" --directory "$work/www" > "$work/http.log" 2>&1 &
pids+=($!)
wait_for 20 grep -qP "^127\.2\.\d+\.\d+\tsvc\.home\.test$" /etc/netns/ento-acme/hosts || fail "svc.home.test not in ento-acme's hosts"
grep -q "100.81.0.1.svc.home.test" /etc/netns/ento-acme/hosts && fail "acme overrode a forwarded name"
wait_for 20 sudo ip netns exec ento-acme curl -sf http://svc.home.test:8080/ || fail "forwarded service unreachable in ento-acme"
[[ "$(sudo ip netns exec ento-acme curl -sf http://svc.home.test:8080/)" == forwarded ]] || fail "wrong answer through the forward"
if inns en-srva curl -sf -m 3 "http://$op_in_acme_pre:8080/" >/dev/null 2>&1; then fail "acme reached the forward"; fi

step "a proxy into acme on op's loopback reaches acme, and nothing else"
inns en-op "$bin" agent link --state-dir "$work/state-op" --proxy 127.0.0.1:18080 acme >/dev/null
mkdir -p "$work/www-a" && echo acme > "$work/www-a/index.html"
inns en-srva python3 -m http.server 8081 --bind "$srv_a" --directory "$work/www-a" > "$work/http-a.log" 2>&1 &
pids+=($!)
wait_for 20 inns en-op curl -sf -x http://127.0.0.1:18080 "http://$srv_a:8081/" || fail "proxy does not reach srv-a"
[[ "$(inns en-op curl -sf -x http://127.0.0.1:18080 http://srv-a:8081/)" == acme ]] || fail "proxy does not resolve acme's names"
inns en-op curl -sf -p -x http://127.0.0.1:18080 "http://$srv_a:8081/" >/dev/null || fail "CONNECT through the proxy fails"
if inns en-op curl -sf -m 5 -x http://127.0.0.1:18080 "http://10.200.0.1:8081/" >/dev/null 2>&1; then fail "proxy reached an address outside acme"; fi
step "the proxy limited to port 8081 refuses every other port"
inns en-srva python3 -m http.server 8082 --bind "$srv_a" --directory "$work/www-a" > "$work/http-a2.log" 2>&1 &
pids+=($!)
wait_for 20 inns en-op curl -sf -x http://127.0.0.1:18080 "http://$srv_a:8082/" || fail "proxy does not reach srv-a:8082 before the limit"
inns en-op "$bin" agent link --state-dir "$work/state-op" --proxy 127.0.0.1:18080 --proxy-ports 8081 acme >/dev/null
for _ in $(seq 1 10); do inns en-op curl -sf -m 2 -x http://127.0.0.1:18080 "http://$srv_a:8082/" >/dev/null 2>&1 || break; sleep 1; done
if inns en-op curl -sf -m 2 -x http://127.0.0.1:18080 "http://$srv_a:8082/" >/dev/null 2>&1; then fail "the limited proxy reached port 8082"; fi
if inns en-op curl -sf -m 2 -p -x http://127.0.0.1:18080 "http://$srv_a:8082/" >/dev/null 2>&1; then fail "the limited proxy tunnelled to port 8082"; fi
wait_for 20 inns en-op curl -sf -x http://127.0.0.1:18080 "http://$srv_a:8081/" || fail "the limited proxy does not reach port 8081"
inns en-op "$bin" agent link --state-dir "$work/state-op" --proxy off acme >/dev/null
for _ in $(seq 1 10); do inns en-op curl -sf -m 2 -x http://127.0.0.1:18080 "http://$srv_a:8081/" >/dev/null 2>&1 || break; sleep 1; done
if inns en-op curl -sf -m 2 -x http://127.0.0.1:18080 "http://$srv_a:8081/" >/dev/null 2>&1; then fail "proxy still serves after --proxy off"; fi

step "acme is not reachable from op's own namespace"
if inns en-op ping -c1 -W1 "$srv_a" >/dev/null 2>&1; then fail "op reached acme outside ento-acme"; fi

step "acme cannot open connections to op"
op_in_acme="$(sudo python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["address"])' "$work/state-op/links/acme/state.json")"
if inns en-srva ping -c2 -W1 "$op_in_acme" >/dev/null 2>&1; then fail "srv-a reached op in acme"; fi

step "op's credential for acme is renewed before it expires"
until_of() { sudo python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["approved_until"])' "$work/state-op/links/acme/state.json"; }
first="$(until_of)"
sleep 35
[[ "$(until_of)" > "$first" ]] || fail "credential not renewed (approved until $(until_of))"
sudo ip netns exec ento-acme ping -c1 -W2 "$srv_a" >/dev/null || fail "acme unreachable after the first credential expired"
echo "approved until $first, then $(until_of)"

step "op joins beta; acme and beta stay apart"
inns en-op "$bin" agent link --state-dir "$work/state-op" beta || fail "joining beta"
wait_for 60 sudo ip netns exec ento-beta ping -c1 -W1 "$srv_b" || fail "ento-beta cannot reach srv-b"
if sudo ip netns exec ento-acme ping -c1 -W1 "$srv_b" >/dev/null 2>&1; then fail "beta reached from ento-acme"; fi
if sudo ip netns exec ento-beta ping -c1 -W1 "$srv_a" >/dev/null 2>&1; then fail "acme reached from ento-beta"; fi
if inns en-srva ping -c1 -W1 "$srv_b" >/dev/null 2>&1; then fail "srv-a reached srv-b"; fi
inns en-op "$bin" agent status --state-dir "$work/state-op"

step "op leaves beta"
inns en-op "$bin" agent unlink --state-dir "$work/state-op" beta || fail "unlink"
if sudo ip netns list | grep -qw ento-beta; then fail "namespace ento-beta still exists"; fi

step "op goes down: its agent stops, its interfaces (home and acme) go away"
inns en-op "$bin" agent down --state-dir "$work/state-op" || fail "down"
if inns en-op ip link show ento0 >/dev/null 2>&1; then fail "op's ento0 still exists after down"; fi
if sudo ip netns exec ento-acme ip link show enl-acme >/dev/null 2>&1; then fail "enl-acme still exists after down"; fi
if sudo ip netns exec ento-acme ping -c1 -W1 "$srv_a" >/dev/null 2>&1; then fail "acme still reachable after down"; fi

step "op runs again and rejoins acme by itself"
as en-op op "$bin" agent run --state-dir "$work/state-op" "${userspace[@]}" >> "$work/agent-op.log" 2>&1 &
pids+=($!)
wait_for 60 sudo ip netns exec ento-acme ping -c1 -W1 "$srv_a" || fail "acme unreachable after op came back"

step "acme deletes the authority: op loses access"
admin en-srva "$work/state-a" authority delete home
for _ in $(seq 1 20); do sudo ip netns exec ento-acme ping -c1 -W1 "$srv_a" >/dev/null 2>&1 || break; sleep 1; done
if sudo ip netns exec ento-acme ping -c2 -W1 "$srv_a" >/dev/null 2>&1; then fail "op still reaches acme after revocation"; fi

printf '\nPASS\n'
