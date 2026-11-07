#!/usr/bin/env bash
# End-to-end test of several networks on one device, on one Linux host: two independent ento
# networks (home and md), each with its own control node and database, a server in each, and one
# device (op) in both, using kernel WireGuard.
#
#   op    (ns en-op)  home first (ento0), then joins md by words (ento1), both in its own namespace
#   srv-h (ns en-srvh, home)    gateway of home's route lan (10.84.0.0/16)
#   srv-m (ns en-srvm, md)      gateway of md's route lan2 (10.84.1.0/24: inside home's)
#   control nodes home/md: host namespace, 10.200.0.1:5193{1,2}
#
# Checks: joining a second network by words (a range overlapping one of the device's is refused
# before the words are asked for), both networks reached from the device's own namespace, by
# address, status of both, administering the second (ento admin --network), a route of md inside
# home's left out (home keeps 10.84.1.0/24, whichever is more specific), md's internal domain taken
# by home left out, nothing forwarded between the two networks even where op is md's gateway into
# a network home routes (the forward drop counts it), `ento agent down` (both interfaces go away;
# the next start brings both back), and leaving md (its interface, filter table and state go).
# Needs root (sudo), the wireguard kernel module, nsenter/unshare, nft and a PostgreSQL server the
# test may create databases on (ENTO_TEST_POSTGRES, a DSN of its maintenance database).
#
# Usage: ENTO_TEST_POSTGRES=postgres://user:pass@host:port/postgres test/e2e-networks.sh path/to/ento
set -euo pipefail

bin="$(realpath "${1:?usage: $0 path/to/ento}")"
: "${ENTO_TEST_POSTGRES:?set ENTO_TEST_POSTGRES to a PostgreSQL maintenance DSN}"
work="$(mktemp -d)"
pids=()
namespaces=(en-op en-srvh en-srvm)

cleanup() {
  set +e
  sudo pkill -f "$work/" 2>/dev/null
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
  for ns in "${namespaces[@]}"; do sudo ip netns del "$ns" 2>/dev/null; done
  for v in op srvh srvm; do sudo ip link del "en-v$v" 2>/dev/null; done
  sudo ip addr del 10.200.0.1/32 dev lo 2>/dev/null
  sudo iptables -D FORWARD -s 10.200.0.0/16 -d 10.200.0.0/16 -j ACCEPT 2>/dev/null
  if [[ -n "${KEEP:-}" ]]; then echo "kept $work"; else sudo rm -rf "$work"; fi
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
fail() {
  echo "FAIL: $*" >&2
  for f in "$work"/*.log; do echo "--- $f"; tail -n 30 "$f"; done
  echo "--- op: links, routes, wg"
  inns en-op ip -br addr 2>&1 | sed 's/^/    /'
  inns en-op ip route 2>&1 | sed 's/^/    /'
  inns en-op wg show 2>&1 | sed 's/^/    /'
  exit 1
}

inns() { local ns="$1"; shift; sudo nsenter --net="/run/netns/$ns" "$@"; }
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
sudo ip addr add 10.200.0.1/32 dev lo
i=1
for v in op srvh srvm; do
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
# Forwarding is on in op's namespace (it is md's gateway): only the agent's own rules keep the two
# networks apart.
inns en-op sysctl -qw net.ipv4.ip_forward=1

step "databases"
base="${ENTO_TEST_POSTGRES%/*}"
for db in home md; do
  docker run --rm --network host postgres:18-alpine psql "$ENTO_TEST_POSTGRES" -qc "DROP DATABASE IF EXISTS ento_e2e_net_$db" >/dev/null
  docker run --rm --network host postgres:18-alpine psql "$ENTO_TEST_POSTGRES" -qc "CREATE DATABASE ento_e2e_net_$db" >/dev/null
done

step "control nodes: home (100.80.0.0/16, internal domain home.internal) and md (100.81.0.0/16, also home.internal)"
port=51930
for net in home:100.80.0.0/16 md:100.81.0.0/16; do
  name="${net%%:*}" prefix="${net#*:}"
  port=$((port + 1))
  "$bin" genkey > "$work/$name.key"
  chmod 600 "$work/$name.key"
  ENTO_DATABASE_URL="$base/ento_e2e_net_$name" "$bin" control run --name "$name-1" --key-file "$work/$name.key" \
    --listen-port "$port" --endpoint "10.200.0.1:$port" --network "$prefix" \
    --record-domain "$name.test" --dns-domain home.internal > "$work/control-$name.log" 2>&1 &
  pids+=($!)
  wait_for 10 grep -q "control node $name-1 up" "$work/control-$name.log" || fail "control node $name did not start"
done
db() { echo "$base/ento_e2e_net_$1"; }
ENTO_DATABASE_URL="$(db home)" "$bin" control token --network 100.80.0.0/16 --admin --approve --groups laptops --out "$work/op-home.token" 2>/dev/null
ENTO_DATABASE_URL="$(db home)" "$bin" control token --network 100.80.0.0/16 --approve --groups servers --name srv-h --out "$work/srv-h.token" 2>/dev/null
ENTO_DATABASE_URL="$(db md)" "$bin" control token --network 100.81.0.0/16 --approve --groups servers --name srv-m --out "$work/srv-m.token" 2>/dev/null

step "op (home), srv-h (home), srv-m (md)"
start_agent() { # start_agent <ns> <hostname> <state> <token>
  as "$1" "$2" "$bin" agent run --state-dir "$3" --token-file "$4" > "$work/agent-$2.log" 2>&1 &
  pids+=($!)
  wait_for 20 sudo test -f "$3/state.json" || fail "$2 did not enroll"
}
start_agent en-op op "$work/state-op" "$work/op-home.token"
start_agent en-srvh srv-h "$work/state-h" "$work/srv-h.token"
start_agent en-srvm srv-m "$work/state-m" "$work/srv-m.token"
srv_h="$(addr_of "$work/state-h/state.json")"
srv_m="$(addr_of "$work/state-m/state.json")"
echo "srv-h = $srv_h (home), srv-m = $srv_m (md)"

step "home: laptops reach servers and the route lan (10.84.0.0/16 through srv-h)"
admin en-op "$work/state-op" allow laptops servers >/dev/null
admin en-op "$work/state-op" route add lan 10.84.0.0/16 --via srv-h >/dev/null
admin en-op "$work/state-op" allow laptops route:lan >/dev/null
wait_for 60 inns en-op ping -c1 -W1 "$srv_h" || fail "op cannot reach srv-h in home"
wait_for 30 sh -c "sudo nsenter --net=/run/netns/en-op ip route get 10.84.1.5 | grep -q 'dev ento0'" || fail "home's route lan is not routed into ento0"

step "a network whose range overlaps one of op's is refused before the words"
record_md="$(ENTO_DATABASE_URL="$(db md)" "$bin" control record --network 100.81.0.0/16 2>/dev/null)"
dup="${record_md//100.81./100.80.}" # md's record as another network on home's range
if out="$(echo "x y z w v" | inns en-op "$bin" agent join --state-dir "$work/state-op" --record "$dup" dup.test 2>&1)"; then fail "joined a network overlapping home"; fi
grep -q "overlaps 100.80.0.0/16 of home.test" <<<"$out" || fail "the refusal does not say why: $out"

step "op joins md with the words an administrator of md reads out"
words="$(ENTO_DATABASE_URL="$(db md)" "$bin" control token --network 100.81.0.0/16 --admin --approve --groups laptops --words --ttl 10m 2>/dev/null | head -1)"
[[ "$(wc -w <<<"$words")" == 5 ]] || fail "no words: $words"
printf '%s\n' "$words" | inns en-op "$bin" agent join --state-dir "$work/state-op" --record "$record_md" md.test || fail "joining md"
sudo test -f "$work/state-op/networks/md.test/state.json" || fail "no state for md"
op_md="$(addr_of "$work/state-op/networks/md.test/state.json")"
inns en-op ip -br addr show ento1 | grep -q "$op_md" || fail "ento1 does not carry op's md address $op_md"
sudo nft list table inet ento-filter-ento1 >/dev/null 2>&1 && fail "md's filter table is in the host's namespace"
inns en-op wg show ento1 fwmark | grep -q 0x7873 || fail "md's WireGuard packets are not marked (they would take an exit of home)"

step "md, administered from op (--network md.test): laptops reach servers, the route lan2 (10.84.1.0/24 through srv-m)"
admin en-op "$work/state-op" --network md.test allow laptops servers >/dev/null || fail "administering md with --network"
admin en-op "$work/state-op" --network md.test route add lan2 10.84.1.0/24 --via srv-m >/dev/null
admin en-op "$work/state-op" --network md.test allow laptops route:lan2 >/dev/null
admin en-op "$work/state-op" --network md.test peers | grep -q srv-m || fail "md's peers not listed through --network"

step "op reaches both networks from its own namespace"
wait_for 60 inns en-op ping -c1 -W1 "$srv_m" || fail "op cannot reach srv-m in md"
inns en-op ping -c1 -W2 "$srv_h" >/dev/null || fail "op lost home after joining md"
inns en-op "$bin" agent status --state-dir "$work/state-op" > "$work/status.txt" || fail "status"
cat "$work/status.txt"
grep -q "^network: *home.test" "$work/status.txt" || fail "status does not name the network it shows"
grep -qE "^md.test +ento1 +$op_md +up" "$work/status.txt" || fail "status does not list md as up"
inns en-op "$bin" agent status --state-dir "$work/state-op" --network md.test > "$work/status-md.txt" 2>&1 || { cat "$work/status-md.txt"; fail "status --network md.test"; }
grep -q "address: *$op_md" "$work/status-md.txt" || { cat "$work/status-md.txt"; fail "status --network md.test shows another network"; }

step "md's route inside home's is left out: 10.84.1.0/24 stays home's"
wait_for 30 grep -q "route 10.84.1.0/24 through \"srv-m\" left out: it overlaps another network" "$work/agent-op.log" || fail "md's route was not left out"
inns en-op ip route get 10.84.1.5 | grep -q "dev ento0" || fail "10.84.1.0/24 goes elsewhere than home: $(inns en-op ip route get 10.84.1.5)"
inns en-op wg show ento1 allowed-ips | grep -q "10.84.1.0/24" && fail "md's route is in ento1's allowed IPs"

step "md's internal domain, home's already, is left out"
wait_for 30 grep -q "network md.test: DNS: home.internal left out: another network of this device holds it" "$work/agent-op.log" || fail "md's domain was not left out"

step "nothing passes between the networks: op is md's gateway into 10.84.0.0/24, which home routes"
op_id="$(admin en-op "$work/state-op" --network md.test peers --json | python3 -c 'import json,sys;print([p["id"] for p in json.load(sys.stdin) if p["hostname"]=="z-op"][0])')"
admin en-op "$work/state-op" --network md.test confirm-name "$op_id" >/dev/null || fail "confirming op's name in md"
admin en-op "$work/state-op" --network md.test route add tohome 10.84.0.0/24 --via op >/dev/null || fail "op as md's gateway"
admin en-op "$work/state-op" --network md.test allow servers route:tohome >/dev/null
wait_for 60 sh -c "sudo nsenter --net=/run/netns/en-srvm ip route get 10.84.0.7 | grep -q 'dev ento0'" || fail "srv-m has no route to tohome"
wait_for 30 sudo nsenter --net=/run/netns/en-op nft list table inet ento-filter-ento1 >/dev/null || fail "no filter table for ento1"
inns en-srvm ping -c3 -W1 10.84.0.7 >/dev/null 2>&1 || true
# Both networks' tables drop it (the first to see it counts it).
{ inns en-op nft list table inet ento-filter-ento1; inns en-op nft list table inet ento-filter; } > "$work/nft.txt"
grep -E 'iifname "ento1" oifname "ento0" counter packets [1-9]' "$work/nft.txt" >/dev/null || { cat "$work/nft.txt"; fail "md's packets for home were not dropped by an isolation rule"; }
inns en-op nft list table inet ento-filter-ento1 > "$work/nft-md.txt"
grep 'iifname "ento0" oifname "ento1"' "$work/nft-md.txt" >/dev/null || fail "md's table has no isolation rule the other way"
# The first network's table follows at its next check (every 5 s); md's drops both ways meanwhile.
wait_for 15 sh -c "sudo nsenter --net=/run/netns/en-op nft list table inet ento-filter > $work/nft-home.txt && grep 'iifname \"ento0\" oifname \"ento1\"' $work/nft-home.txt" ||
  { cat "$work/nft-home.txt"; fail "home's table does not keep md apart"; }

step "down: both interfaces go away; the next start brings both back"
inns en-op "$bin" agent down --state-dir "$work/state-op" || fail "down"
if inns en-op ip link show ento1 >/dev/null 2>&1; then fail "ento1 still exists after down"; fi
if inns en-op ip link show ento0 >/dev/null 2>&1; then fail "ento0 still exists after down"; fi
as en-op op "$bin" agent run --state-dir "$work/state-op" >> "$work/agent-op.log" 2>&1 &
pids+=($!)
wait_for 60 inns en-op ping -c1 -W1 "$srv_m" || fail "md unreachable after op came back"
wait_for 30 inns en-op ping -c1 -W1 "$srv_h" || fail "home unreachable after op came back"

step "op leaves md: its interface, filter table and state go; home stays"
inns en-op "$bin" agent leave --state-dir "$work/state-op" md.test || fail "leave"
if inns en-op ip link show ento1 >/dev/null 2>&1; then fail "ento1 still exists after leave"; fi
if inns en-op nft list table inet ento-filter-ento1 >/dev/null 2>&1; then fail "ento1's filter table still exists after leave"; fi
sudo test -e "$work/state-op/networks/md.test" && fail "md's state still exists after leave"
inns en-op ping -c1 -W2 "$srv_h" >/dev/null || fail "home lost after leaving md"
wait_for 20 sh -c "sudo nsenter --net=/run/netns/en-op nft list table inet ento-filter > $work/nft-after.txt && ! grep 'oifname \"ento1\"' $work/nft-after.txt" || fail "home's table still names ento1"

printf '\nPASS\n'
