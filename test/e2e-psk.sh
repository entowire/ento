#!/usr/bin/env bash
# End-to-end test of the preshared keys between devices and their control nodes (Constitution 9.1,
# 9.2) on one Linux host, with kernel WireGuard: one control node, and two devices in network
# namespaces of their own.
#
#   a  (ns ep-a)  joins with a key from its first handshake, changes it (every 40 s here, daily
#                 otherwise) without losing its tunnel, and finds its way back after a reset; reaches
#                 b through a tunnel with a pair key, which changes without a ping lost
#   b  (ns ep-b)  joins, then has its key taken out of its state, as a device that joined before
#                 ento had them: it gets one without joining again
#   control node: host namespace, 10.201.0.1:51941
#
# Checks: the key in the agent's state is the one on its interface; changes keep the tunnel (the
# control API answers right after each); after a restore (the control node stopped, `ento control
# psk-reset`, started again) a running device, whose key the control nodes no longer have, reaches
# them without one and agrees on a new one; a device without a key gets one at its first check-in.
# Needs root (sudo), the wireguard kernel module, nsenter/unshare, wg and a PostgreSQL server the
# test may create a database on (ENTO_TEST_POSTGRES, a DSN of its maintenance database).
#
# Usage: ENTO_TEST_POSTGRES=postgres://user:pass@host:port/postgres test/e2e-psk.sh path/to/ento
set -euo pipefail

bin="$(realpath "${1:?usage: $0 path/to/ento}")"
: "${ENTO_TEST_POSTGRES:?set ENTO_TEST_POSTGRES to a PostgreSQL maintenance DSN}"
work="$(mktemp -d)"
pids=()
namespaces=(ep-a ep-b)
net=100.82.0.0/16

cleanup() {
  set +e
  sudo pkill -f "$work/" 2>/dev/null
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
  for ns in "${namespaces[@]}"; do sudo ip netns del "$ns" 2>/dev/null; done
  for v in a b; do sudo ip link del "ep-v$v" 2>/dev/null; done
  sudo ip addr del 10.201.0.1/32 dev lo 2>/dev/null
  if [[ -n "${KEEP:-}" ]]; then echo "kept $work"; else sudo rm -rf "$work"; fi
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
fail() {
  echo "FAIL: $*" >&2
  for f in "$work"/*.log; do echo "--- $f"; tail -n 40 "$f"; done
  exit 1
}
inns() { local ns="$1"; shift; sudo nsenter --net="/run/netns/$ns" "$@"; }
wait_for() { # wait_for <seconds> <cmd...>
  local t="$1"; shift
  for _ in $(seq 1 "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
state() { sudo python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get(sys.argv[2]) or "")' "$1" "$2"; }
ctl_key() { sudo python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["controls"][0]["public_key"])' "$1"; }
# iface_psk <ns> <state>: the preshared key the device's interface has for its control node.
iface_psk() { inns "$1" wg show ento0 preshared-keys | awk -v k="$(ctl_key "$2/state.json")" '$1 == k {print $2}'; }
# same_psk <ns> <state>: the agent's state and its interface agree, on a key.
same_psk() {
  local s i
  s="$(state "$2/state.json" preshared_key)" i="$(iface_psk "$1" "$2")"
  [[ -n "$s" && "$s" == "$i" ]]
}
db="ento_e2e_psk"
dburl="${ENTO_TEST_POSTGRES%/*}/$db"
peers() { ENTO_DATABASE_URL="$dburl" "$bin" control "$@" --network "$net"; }

step "network namespaces"
sudo sysctl -qw net.ipv4.ip_forward=1
sudo ip addr add 10.201.0.1/32 dev lo
i=1
for v in a b; do
  i=$((i + 1))
  sudo ip netns add "ep-$v"
  sudo ip link add "ep-v$v" type veth peer name eth0 netns "ep-$v"
  sudo ip addr add "10.201.$i.1/24" dev "ep-v$v"
  sudo ip link set "ep-v$v" up
  sudo ip netns exec "ep-$v" ip addr add "10.201.$i.2/24" dev eth0
  sudo ip netns exec "ep-$v" ip link set eth0 up
  sudo ip netns exec "ep-$v" ip link set lo up
  sudo ip netns exec "ep-$v" ip route add default via "10.201.$i.1"
done

step "database and control node"
docker run --rm --network host postgres:18-alpine psql "$ENTO_TEST_POSTGRES" -qc "DROP DATABASE IF EXISTS $db" >/dev/null
docker run --rm --network host postgres:18-alpine psql "$ENTO_TEST_POSTGRES" -qc "CREATE DATABASE $db" >/dev/null
"$bin" genkey > "$work/control.key"
chmod 600 "$work/control.key"
start_control() {
  ENTO_PSK_EVERY=40s ENTO_DATABASE_URL="$dburl" "$bin" control run --name psk-1 --key-file "$work/control.key" \
    --listen-port 51941 --endpoint 10.201.0.1:51941 --network "$net" >> "$work/control.log" 2>&1 &
  control_pid=$!
  pids+=("$control_pid")
  wait_for 10 sh -c "grep -c 'control node psk-1 up' '$work/control.log' | grep -qx '$1'" || fail "the control node did not start"
}
start_control 1
peers token --admin --approve --groups laptops --out "$work/a.token" 2>/dev/null
peers token --approve --groups servers --name b --out "$work/b.token" 2>/dev/null

start_agent() { # start_agent <ns> <name> [--token-file FILE]
  local ns="$1" name="$2"; shift 2
  sudo ENTO_CHECKIN_EVERY=5s ENTO_PSK_EVERY=40s nsenter --net="/run/netns/$ns" \
    "$bin" agent run --state-dir "$work/state-$name" "$@" >> "$work/agent-$name.log" 2>&1 &
  last=$!
  pids+=("$last")
}

step "a and b join: a preshared key from the first handshake"
start_agent ep-a a --token-file "$work/a.token"
start_agent ep-b b --token-file "$work/b.token"
b_pid=$last
wait_for 30 sudo test -f "$work/state-a/state.json" || fail "a did not join"
wait_for 30 sudo test -f "$work/state-b/state.json" || fail "b did not join"
wait_for 20 same_psk ep-a "$work/state-a" || fail "a's state and interface do not have the same preshared key"
wait_for 20 same_psk ep-b "$work/state-b" || fail "b's state and interface do not have the same preshared key"
inns ep-a env ENTO_STATE_DIR="$work/state-a" "$bin" admin peers >/dev/null || fail "a does not reach the control API"
wait_for 20 sh -c "sudo nsenter --net=/run/netns/ep-a '$bin' agent status --state-dir '$work/state-a' | grep -q '^psk: *from '" ||
  fail "status shows no preshared key"
first="$(state "$work/state-a/state.json" preshared_key)"
map_errors="$(grep -c 'network map from' "$work/agent-a.log" || true)"

step "a's key changes twice (every 40 s here), the tunnel stays"
wait_for 90 sh -c "[ \"\$(sudo python3 -c 'import json;print(json.load(open(\"$work/state-a/state.json\")).get(\"preshared_key\"))')\" != '$first' ]" ||
  fail "a's key did not change"
wait_for 20 same_psk ep-a "$work/state-a" || fail "after the change, a's state and interface disagree"
inns ep-a env ENTO_STATE_DIR="$work/state-a" "$bin" admin peers >/dev/null || fail "a lost the control API after the change"
second="$(state "$work/state-a/state.json" preshared_key)"
wait_for 90 sh -c "[ \"\$(sudo python3 -c 'import json;print(json.load(open(\"$work/state-a/state.json\")).get(\"preshared_key\"))')\" != '$second' ]" ||
  fail "a's key did not change again"
inns ep-a env ENTO_STATE_DIR="$work/state-a" "$bin" admin peers >/dev/null || fail "a lost the control API after the second change"
[[ "$(grep -c 'preshared key with the control nodes changed' "$work/agent-a.log")" -ge 2 ]] || fail "a did not log its changes"
[[ "$(grep -c 'network map from' "$work/agent-a.log" || true)" == "$map_errors" ]] ||
  fail "a's map failed while its key changed: $(grep 'network map from' "$work/agent-a.log" | tail -3)"

step "a and b: a pair key on both ends, which changes without a ping lost"
inns ep-a env ENTO_STATE_DIR="$work/state-a" "$bin" admin allow laptops servers >/dev/null || fail "a rule for a to reach b"
a_pub="$(inns ep-a wg show ento0 public-key)" b_pub="$(inns ep-b wg show ento0 public-key)"
b_addr="$(state "$work/state-b/state.json" address)"
pair_psk() { inns "$1" wg show ento0 preshared-keys | awk -v k="$2" '$1 == k {print $2}'; }
# same_pair [OLD]: both ends have the same key (other than OLD).
same_pair() {
  local x y
  x="$(pair_psk ep-a "$b_pub")" y="$(pair_psk ep-b "$a_pub")"
  [[ -n "$x" && "$x" != "(none)" && "$x" == "$y" && "$x" != "${1:-}" ]]
}
wait_for 200 same_pair || fail "a and b have no pair key in common: $(pair_psk ep-a "$b_pub") / $(pair_psk ep-b "$a_pub")"
wait_for 30 inns ep-a ping -c1 -W1 "$b_addr" || fail "a does not reach b with the pair key"
pair_first="$(pair_psk ep-a "$b_pub")"
sudo nsenter --net=/run/netns/ep-a ping -i 0.2 -O "$b_addr" > "$work/ping.log" 2>&1 &
ping_pid=$!
wait_for 300 same_pair "$pair_first" || fail "the pair key did not change on both ends"
sleep 10
sudo kill -INT "$ping_pid"
wait "$ping_pid" 2>/dev/null || true
lost="$(grep -c 'no answer yet' "$work/ping.log" || true)"
echo "pings unanswered while the pair key changed: $lost of $(grep -c 'icmp_seq=' "$work/ping.log" || true)"
[[ "$lost" -le 5 ]] || fail "pings lost while the pair key changed: $lost"

step "b loses its key as a device that joined before; the database is restored (psk-reset)"
sudo kill "$b_pid"
wait "$b_pid" 2>/dev/null || true
sudo python3 - "$work/state-b/state.json" <<'EOF'
import json, sys
p = sys.argv[1]
s = json.load(open(p))
for k in ("preshared_key", "psk_at", "psk_for", "next_preshared_key", "next_psk_tag"):
    s.pop(k, None)
json.dump(s, open(p, "w"))
EOF
# A restore: the control node stops (its sessions with it), its database comes back with keys
# older than the devices', so they are forgotten, and it starts again.
kill "$control_pid"
wait "$control_pid" 2>/dev/null || true
peers psk-reset | grep -q "preshared keys forgotten: 2" || fail "psk-reset did not forget both keys"
start_control 2

step "b, without a key, gets one at its first check-in"
start_agent ep-b b
wait_for 150 grep -q "preshared key with the control nodes changed (none yet)" "$work/agent-b.log" || fail "b got no key"
wait_for 20 same_psk ep-b "$work/state-b" || fail "b's state and interface disagree"

step "a, whose key the control nodes forgot, reaches them without one, then agrees on a new one (minutes)"
wait_for 480 grep -q "the control nodes have no preshared key for this device (reset)" "$work/agent-a.log" ||
  fail "a did not find its way back"
wait_for 60 sh -c "grep -A100 'no preshared key for this device (reset)' '$work/agent-a.log' | grep -q 'preshared key with the control nodes changed (none yet)'" ||
  fail "a agreed on no new key after the reset"
wait_for 20 same_psk ep-a "$work/state-a" || fail "a's state and interface disagree after the reset"
inns ep-a env ENTO_STATE_DIR="$work/state-a" "$bin" admin peers >/dev/null || fail "a does not reach the control API after the reset"

printf '\nPASS\n'
