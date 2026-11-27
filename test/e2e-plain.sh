#!/usr/bin/env bash
# End-to-end test of a plain WireGuard peer (Constitution 6) on one Linux host: a control node, a
# gateway and a laptop with the agent (kernel WireGuard), and a device with plain WireGuard only,
# set up from the configuration ento gives (`wg setconf`, as wg-quick does), in network namespaces.
#
#   gw     (ns pl-gw)   servers: carries the plain peer
#   laptop (ns pl-lap)  laptops, admin: adds it, reaches it
#   dev    (ns pl-dev)  printers: no agent, plain WireGuard
#   control node: host namespace, 10.202.0.1:51951
#
# Checks: the configuration (one peer, the gateway, with a preshared key) brings up a tunnel, and
# the gateway's reports make it online in peers; the
# laptop reaches the plain peer by a rule, the plain peer reaches the laptop and the gateway only by
# rules of its own (the receiving side filters what it opens, the gateway what others open on it);
# it reaches its control nodes; deleted, it reaches nothing.
# Needs root (sudo), the wireguard kernel module, wg, nsenter, nft and a PostgreSQL server the test
# may create a database on (ENTO_TEST_POSTGRES, a DSN of its maintenance database).
#
# Usage: ENTO_TEST_POSTGRES=postgres://user:pass@host:port/postgres test/e2e-plain.sh path/to/ento
set -euo pipefail

bin="$(realpath "${1:?usage: $0 path/to/ento}")"
: "${ENTO_TEST_POSTGRES:?set ENTO_TEST_POSTGRES to a PostgreSQL maintenance DSN}"
work="$(mktemp -d)"
pids=()
namespaces=(pl-gw pl-lap pl-dev)
net=100.83.0.0/16

cleanup() {
  set +e
  sudo pkill -f "$work/" 2>/dev/null
  for p in "${pids[@]}"; do sudo kill "$p" 2>/dev/null; done
  for ns in "${namespaces[@]}"; do sudo ip netns del "$ns" 2>/dev/null; done
  for v in gw lap dev; do sudo ip link del "pl-v$v" 2>/dev/null; done
  sudo ip addr del 10.202.0.1/32 dev lo 2>/dev/null
  sudo iptables -D FORWARD -s 10.202.0.0/16 -d 10.202.0.0/16 -j ACCEPT 2>/dev/null
  if [[ -n "${KEEP:-}" ]]; then echo "kept $work"; else sudo rm -rf "$work"; fi
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
fail() {
  echo "FAIL: $*" >&2
  for f in "$work"/*.log; do echo "--- $f"; sudo tail -n 30 "$f"; done
  for ns in pl-gw pl-dev; do echo "--- wg in $ns"; inns "$ns" wg show 2>&1 | sed 's/^/    /'; done
  exit 1
}
inns() { local ns="$1"; shift; sudo nsenter --net="/run/netns/$ns" "$@"; }
wait_for() { # wait_for <seconds> <cmd...>
  local t="$1"; shift
  for _ in $(seq 1 "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
state() { sudo python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get(sys.argv[2]) or "")' "$1" "$2"; }
admin() { inns pl-lap env ENTO_STATE_DIR="$work/state-lap" "$bin" admin "$@"; }
reaches() { inns "$1" ping -c1 -W1 "$2"; }
# tcp <ns> <address> <port>: a TCP connection opens.
tcp() { inns "$1" timeout 3 bash -c "exec 3<>/dev/tcp/$2/$3"; }
db="ento_e2e_plain"
dburl="${ENTO_TEST_POSTGRES%/*}/$db"

step "network namespaces"
sudo sysctl -qw net.ipv4.ip_forward=1
sudo iptables -I FORWARD -s 10.202.0.0/16 -d 10.202.0.0/16 -j ACCEPT
sudo ip addr add 10.202.0.1/32 dev lo
i=1
for v in gw lap dev; do
  i=$((i + 1))
  sudo ip netns add "pl-$v"
  sudo ip link add "pl-v$v" type veth peer name eth0 netns "pl-$v"
  sudo ip addr add "10.202.$i.1/24" dev "pl-v$v"
  sudo ip link set "pl-v$v" up
  sudo ip netns exec "pl-$v" ip addr add "10.202.$i.2/24" dev eth0
  sudo ip netns exec "pl-$v" ip link set eth0 up
  sudo ip netns exec "pl-$v" ip link set lo up
  sudo ip netns exec "pl-$v" ip route add default via "10.202.$i.1"
done

step "database and control node"
docker run --rm --network host postgres:18-alpine psql "$ENTO_TEST_POSTGRES" -qc "DROP DATABASE IF EXISTS $db" >/dev/null
docker run --rm --network host postgres:18-alpine psql "$ENTO_TEST_POSTGRES" -qc "CREATE DATABASE $db" >/dev/null
"$bin" genkey > "$work/control.key"
chmod 600 "$work/control.key"
ENTO_DATABASE_URL="$dburl" "$bin" control run --name pl-1 --key-file "$work/control.key" \
  --listen-port 51951 --endpoint 10.202.0.1:51951 --network "$net" > "$work/control.log" 2>&1 &
pids+=($!)
wait_for 10 grep -q "control node pl-1 up" "$work/control.log" || fail "the control node did not start"
ENTO_DATABASE_URL="$dburl" "$bin" control token --network "$net" --approve --groups servers --name gw --out "$work/gw.token" 2>/dev/null
ENTO_DATABASE_URL="$dburl" "$bin" control token --network "$net" --admin --approve --groups laptops --name laptop --out "$work/lap.token" 2>/dev/null
control_addr="$(ENTO_DATABASE_URL="$dburl" "$bin" control record --network "$net" 2>/dev/null | grep -o 'c=[^ ]*' | head -1 | awk -F, '{print $3}')"

step "the gateway and the laptop join"
for n in gw:pl-gw lap:pl-lap; do
  name="${n%%:*}" ns="${n#*:}"
  sudo ENTO_PLAIN_SEEN_EVERY=5s nsenter --net="/run/netns/$ns" "$bin" agent run --state-dir "$work/state-$name" --token-file "$work/$name.token" \
    > "$work/agent-$name.log" 2>&1 &
  pids+=($!)
  wait_for 30 sudo test -f "$work/state-$name/state.json" || fail "$name did not join"
done
lap_addr="$(state "$work/state-lap/state.json" address)" gw_addr="$(state "$work/state-gw/state.json" address)"
wait_for 30 sh -c "sudo nsenter --net=/run/netns/pl-lap env ENTO_STATE_DIR='$work/state-lap' '$bin' admin peers | grep -q '^.*gw .*10.202.2.2:'" ||
  fail "the control node has not seen the gateway's endpoint"
[[ -n "$control_addr" ]] || control_addr="${net%.0.0/16}.0.1"

step "the laptop adds a plain WireGuard peer through the gateway"
admin plain add printer --via gw --groups printers --out "$work/printer.conf" 2> "$work/plain-add.txt" || { cat "$work/plain-add.txt"; fail "plain add"; }
cat "$work/plain-add.txt"
sudo sed 's/PrivateKey = .*/PrivateKey = (hidden)/' "$work/printer.conf"
sudo grep -q "^PresharedKey = " "$work/printer.conf" || fail "the configuration has no preshared key"
dev_addr="$(sudo sed -n 's#^Address = \(.*\)/32#\1#p' "$work/printer.conf")"
admin allow laptops printers >/dev/null || fail "a rule for laptops to reach printers"
admin peers | grep -E "^[0-9]+ +printer " | grep -q "via gw" || fail "peers does not show the plain peer through its gateway"

step "dev brings it up with plain WireGuard"
inns pl-dev ip link add wg0 type wireguard
sudo grep -v '^Address = ' "$work/printer.conf" | sudo tee "$work/printer.wg" >/dev/null
inns pl-dev wg setconf wg0 "$work/printer.wg"
inns pl-dev ip addr add "$dev_addr/32" dev wg0
inns pl-dev ip link set wg0 up
inns pl-dev ip route add "$net" dev wg0
wait_for 30 sh -c "sudo nsenter --net=/run/netns/pl-dev wg show wg0 latest-handshakes | awk '{exit !(\$2 > 0)}'" || fail "no handshake with the gateway"

step "its gateway reports it seen: online in peers (it has no tunnel with the control nodes)"
seen_recently() {
  admin peers --json | python3 -c '
import json, sys, datetime
p = [p for p in json.load(sys.stdin) if p["hostname"] == "printer"][0]
at = datetime.datetime.fromisoformat(p.get("last_seen", "1970-01-01T00:00:00+00:00").replace("Z", "+00:00"))
sys.exit(0 if (datetime.datetime.now(datetime.timezone.utc) - at).total_seconds() < 180 else 1)'
}
wait_for 60 seen_recently || fail "the plain peer is not seen: $(admin peers | grep printer)"

step "the laptop reaches it by its rule; it reaches nothing of its own yet"
wait_for 60 reaches pl-lap "$dev_addr" || fail "the laptop does not reach the plain peer"
reaches pl-dev "$lap_addr" && fail "the plain peer reaches the laptop without a rule"
reaches pl-dev "$gw_addr" && fail "the plain peer reaches its gateway without a rule"
reaches pl-gw "$dev_addr" && fail "the gateway reaches the plain peer without a rule"
inns pl-dev ping -c1 -W1 "$lap_addr" >/dev/null 2>&1 || true

step "rules of its own: printers reach the laptop (icmp) and the gateway (tcp/22 only)"
admin allow printers laptops --ports icmp >/dev/null || fail "a rule for printers"
admin allow printers servers --ports tcp/22 >/dev/null || fail "a rule for printers to servers"
wait_for 60 reaches pl-dev "$lap_addr" || fail "the plain peer does not reach the laptop by its rule"
reaches pl-dev "$gw_addr" && fail "the plain peer pings the gateway, which its rule does not let"
inns pl-gw sh -c "timeout 20 nc -l -p 22 -s $gw_addr >/dev/null 2>&1 &" || true
sleep 1
wait_for 20 tcp pl-dev "$gw_addr" 22 || fail "the plain peer does not reach the gateway's port 22 by its rule"

step "it reaches its control nodes"
tcp pl-dev "$control_addr" 80 || fail "the plain peer does not reach the control node $control_addr"

step "deleted, it reaches nothing"
dev_id="$(admin peers --json | python3 -c 'import json,sys;print([p["id"] for p in json.load(sys.stdin) if p["hostname"]=="printer"][0])')"
admin delete "$dev_id" >/dev/null || fail "delete"
wait_for 30 sh -c "! sudo nsenter --net=/run/netns/pl-gw wg show ento0 peers | grep -q \"\$(sudo nsenter --net=/run/netns/pl-dev wg show wg0 public-key)\"" ||
  fail "the gateway still has the deleted plain peer"
reaches pl-lap "$dev_addr" && fail "the laptop still reaches a deleted plain peer"
reaches pl-dev "$lap_addr" && fail "a deleted plain peer still reaches the laptop"

printf '\nPASS\n'
