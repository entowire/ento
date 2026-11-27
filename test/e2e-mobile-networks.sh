#!/usr/bin/env bash
# End-to-end test of a phone in several networks (0.60), on one Linux host: the agent of package
# mobile, as the Android app runs it, played by test/mobilehost on a TUN interface it configures as
# Android's VpnService would (one interface for every network). Two independent ento networks (home
# and md), each with its own control node and database and a server; the phone joins home by words,
# then md by words while connected.
#
#   phone (ns en-ph)   mobilehost: home first, then md, one tun0
#   srv-h (ns en-srvh, home)   administers home
#   srv-m (ns en-srvm, md)     administers md; gateway of md's route lan2 (10.85.1.0/24, its 10.85.1.1)
#   control nodes home/md: host namespace, 10.200.0.1:5196{1,2}
#
# Checks: both networks reached through the one interface by address, md's route through its
# gateway, each network's names from the one DNS server the VPN names (the first network's
# resolver hands md's names to md's), status of each network, a network overlapping one of the
# phone's refused, md's exit (srv-m, into namespace en-inet) used by the phone (0.61: any network's
# exit, with that network's resolver as the VPN's DNS server), leaving md (home stays, md's
# addresses go), and, md joined again, leaving home, the first network: md takes its place.
# Needs root (sudo), nsenter, docker (psql) and a PostgreSQL server the test may create databases
# on (ENTO_TEST_POSTGRES, a DSN of its maintenance database).
#
# Usage: ENTO_TEST_POSTGRES=postgres://user:pass@host:port/postgres test/e2e-mobile-networks.sh path/to/ento
set -euo pipefail

bin="$(realpath "${1:?usage: $0 path/to/ento}")"
: "${ENTO_TEST_POSTGRES:?set ENTO_TEST_POSTGRES to a PostgreSQL maintenance DSN}"
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
pids=()
namespaces=(en-ph en-srvh en-srvm en-inet)

cleanup() {
  set +e
  sudo pkill -f "$work/" 2>/dev/null
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
  for ns in "${namespaces[@]}"; do sudo ip netns del "$ns" 2>/dev/null; done
  for v in ph srvh srvm; do sudo ip link del "en-v$v" 2>/dev/null; done
  sudo ip addr del 10.200.0.1/32 dev lo 2>/dev/null
  sudo iptables -D FORWARD -s 10.200.0.0/16 -d 10.200.0.0/16 -j ACCEPT 2>/dev/null
  if [[ -n "${KEEP:-}" ]]; then echo "kept $work"; else sudo rm -rf "$work"; fi
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
fail() {
  echo "FAIL: $*" >&2
  for f in "$work"/*.log; do echo "--- $f"; tail -n 40 "$f"; done
  echo "--- phone: links, routes"
  inns en-ph ip -br addr 2>&1 | sed 's/^/    /'
  inns en-ph ip route 2>&1 | sed 's/^/    /'
  exit 1
}

inns() { local ns="$1"; shift; sudo nsenter --net="/run/netns/$ns" "$@"; }
as() { local ns="$1" host="$2"; shift 2; sudo nsenter --net="/run/netns/$ns" unshare --uts sh -c 'hostname "$0"; exec "$@"' "$host" "$@"; }
admin() { local ns="$1" state="$2"; shift 2; inns "$ns" env ENTO_STATE_DIR="$state" "$bin" admin "$@"; }
addr_of() { sudo python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["address"])' "$1"; }
phone() { inns en-ph "$work/mobilehost" "$@"; }
field() { python3 -c 'import json,sys;v=json.load(sys.stdin).get(sys.argv[1]);print("" if v is None else v)' "$1"; }
wait_for() { # wait_for <seconds> <cmd...>
  local t="$1"; shift
  for _ in $(seq 1 "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

step "the phone's app (mobilehost)"
(cd "$here/.." && go build -o "$work/mobilehost" ./test/mobilehost) || fail "building mobilehost"

step "network namespaces"
sudo sysctl -qw net.ipv4.ip_forward=1
sudo iptables -I FORWARD -s 10.200.0.0/16 -d 10.200.0.0/16 -j ACCEPT
sudo ip addr add 10.200.0.1/32 dev lo
i=1
for v in ph srvh srvm; do
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
# srv-m's LAN: one address of it on srv-m itself, which answers for it.
inns en-srvm ip addr add 10.85.1.1/32 dev lo
inns en-srvm sysctl -qw net.ipv4.ip_forward=1

step "databases"
base="${ENTO_TEST_POSTGRES%/*}"
for db in home md; do
  docker run --rm --network host postgres:18-alpine psql "$ENTO_TEST_POSTGRES" -qc "DROP DATABASE IF EXISTS ento_e2e_mob_$db" >/dev/null
  docker run --rm --network host postgres:18-alpine psql "$ENTO_TEST_POSTGRES" -qc "CREATE DATABASE ento_e2e_mob_$db" >/dev/null
done
db() { echo "$base/ento_e2e_mob_$1"; }

step "control nodes: home (100.80.0.0/16, home.internal) and md (100.81.0.0/16, md.internal)"
port=51960
for net in home:100.80.0.0/16 md:100.81.0.0/16; do
  name="${net%%:*}" prefix="${net#*:}"
  port=$((port + 1))
  "$bin" genkey > "$work/$name.key"
  chmod 600 "$work/$name.key"
  ENTO_DATABASE_URL="$(db "$name")" "$bin" control run --name "$name-1" --key-file "$work/$name.key" \
    --listen-port "$port" --endpoint "10.200.0.1:$port" --network "$prefix" \
    --record-domain "$name.test" --dns-domain "$name.internal" > "$work/control-$name.log" 2>&1 &
  pids+=($!)
  wait_for 10 grep -q "control node $name-1 up" "$work/control-$name.log" || fail "control node $name did not start"
done
ENTO_DATABASE_URL="$(db home)" "$bin" control token --network 100.80.0.0/16 --admin --approve --groups servers --name srv-h --out "$work/srv-h.token" 2>/dev/null
ENTO_DATABASE_URL="$(db md)" "$bin" control token --network 100.81.0.0/16 --admin --approve --groups servers --name srv-m --out "$work/srv-m.token" 2>/dev/null

step "srv-h (home), srv-m (md)"
start_agent() { # start_agent <ns> <hostname> <state> <token>
  as "$1" "$2" "$bin" agent run --state-dir "$3" --token-file "$4" > "$work/agent-$2.log" 2>&1 &
  pids+=($!)
  wait_for 20 sudo test -f "$3/state.json" || fail "$2 did not enroll"
}
start_agent en-srvh srv-h "$work/state-h" "$work/srv-h.token"
start_agent en-srvm srv-m "$work/state-m" "$work/srv-m.token"
srv_h="$(addr_of "$work/state-h/state.json")"
srv_m="$(addr_of "$work/state-m/state.json")"
echo "srv-h = $srv_h (home), srv-m = $srv_m (md)"
admin en-srvh "$work/state-h" allow mobiles servers >/dev/null || fail "home's rule"
admin en-srvm "$work/state-m" allow mobiles servers >/dev/null || fail "md's rule"
admin en-srvm "$work/state-m" route add lan2 10.85.1.0/24 --via srv-m >/dev/null || fail "md's route"
admin en-srvm "$work/state-m" allow mobiles route:lan2 >/dev/null || fail "md's route rule"

step "the phone joins home by words and connects"
record_home="$(ENTO_DATABASE_URL="$(db home)" "$bin" control record --network 100.80.0.0/16 2>/dev/null)"
record_md="$(ENTO_DATABASE_URL="$(db md)" "$bin" control record --network 100.81.0.0/16 2>/dev/null)"
words() { ENTO_DATABASE_URL="$(db "$1")" "$bin" control token --network "$2" --approve --groups mobiles --words --ttl 10m 2>/dev/null | head -1; }
phone enroll "$work/phone" "$record_home" "$(words home 100.80.0.0/16)" || fail "enrolling in home"
start_phone() {
  inns en-ph "$work/mobilehost" run "$work/phone" >> "$work/phone.log" 2>&1 &
  phone_pid=$!
  pids+=($phone_pid)
}
start_phone
wait_for 60 inns en-ph ping -c1 -W1 "$srv_h" || fail "the phone cannot reach srv-h in home"

step "a network overlapping home is refused"
dup="${record_md//100.81./100.80.}"
if out="$(phone join "$work/phone" dup.test "$dup" "a b c d e" 2>&1)"; then fail "joined a network overlapping home"; fi
grep -q "overlaps" <<<"$out" || fail "the refusal does not say why: $out"

step "the phone joins md by words while connected: the VPN is created again with md's address"
phone join "$work/phone" md.test "$record_md" "$(words md 100.81.0.0/16)" || fail "joining md"
phone networks "$work/phone" | grep -q '"md.test"' || fail "md is not among the phone's networks"
wait_for 30 grep -q "creating the VPN again" "$work/phone.log" || fail "the VPN was not created again"
wait_for 15 phone status "$work/phone" md.test || fail "no status of md"
ph_md="$(phone status "$work/phone" md.test | field address)"
wait_for 30 sh -c "sudo nsenter --net=/run/netns/en-ph ip -br addr show tun0 | grep -q $ph_md" || fail "tun0 does not carry md's address $ph_md"

step "the phone reaches both networks, and md's route, through its one interface"
wait_for 60 inns en-ph ping -c1 -W1 "$srv_m" || fail "the phone cannot reach srv-m in md"
inns en-ph ping -c1 -W2 "$srv_h" >/dev/null || fail "the phone lost home after joining md"
wait_for 30 sh -c "sudo nsenter --net=/run/netns/en-ph ip route get 10.85.1.1 | grep -q 'dev tun0'" || fail "md's route lan2 is not in the VPN"
wait_for 30 inns en-ph ping -c1 -W1 10.85.1.1 || fail "the phone cannot reach md's route lan2"
echo "10.85.1.1 from: $(inns en-ph ip route get 10.85.1.1 | grep -o 'src [0-9.]*')"
running() { phone status "$work/phone" "$@" | grep -q '"running":true'; }
wait_for 15 running md.test || fail "md's status: not running"
wait_for 15 running || fail "home's status: not running"

step "names of both networks from the one DNS server the VPN names"
dns="$(phone status "$work/phone" | field dns)"
[[ -n "$dns" ]] || fail "the VPN names no DNS server"
wait_for 30 sh -c "sudo nsenter --net=/run/netns/en-ph $work/mobilehost resolve $dns srv-h.home.internal | grep -qx $srv_h" || fail "home's name from $dns"
wait_for 30 sh -c "sudo nsenter --net=/run/netns/en-ph $work/mobilehost resolve $dns srv-m.md.internal | grep -qx $srv_m" || fail "md's name from $dns (the first network's resolver)"

step "md's exit: srv-m into namespace en-inet (203.0.113.0/24); the phone uses it"
sudo ip netns add en-inet
sudo ip link add en-inetm netns en-srvm type veth peer name eth0 netns en-inet
inns en-srvm ip addr add 203.0.113.1/24 dev en-inetm
inns en-srvm ip link set en-inetm up
inns en-inet ip addr add 203.0.113.2/24 dev eth0
inns en-inet ip link set eth0 up
inns en-inet ip link set lo up
inns en-inet ip route add default via 203.0.113.1
mkdir -p "$work/www" && echo inet > "$work/www/index.html"
inns en-inet python3 -m http.server 80 --directory "$work/www" > "$work/http-inet.log" 2>&1 &
pids+=($!)
# The phone's WireGuard packets keep their path once 0.0.0.0/0 goes into the VPN (Android protects
# its sockets; mobilehost has no protector).
inns en-ph ip route add 10.200.0.0/16 via 10.200.2.1
admin en-srvm "$work/state-m" route add internet --exit --via srv-m >/dev/null || fail "md's exit"
admin en-srvm "$work/state-m" allow mobiles route:internet >/dev/null || fail "md's exit rule"
offered() { phone status "$work/phone" md.test | grep -q '"route":"internet"'; }
wait_for 30 offered || fail "md does not offer its exit to the phone"
phone exit "$work/phone" md.test internet || fail "choosing md's exit"
exit_in() { [[ "$(phone status "$work/phone" | field exit_network)" == "$1" ]]; }
wait_for 30 exit_in md.test || fail "md's exit not in use"
wait_for 30 sh -c "sudo nsenter --net=/run/netns/en-ph ip route get 203.0.113.2 | grep -q 'dev tun0'" || fail "0.0.0.0/0 is not in the VPN"
wait_for 30 inns en-ph curl -s -o /dev/null --max-time 3 http://203.0.113.2/ || fail "the phone does not reach en-inet through md's exit"
inns en-ph ping -c1 -W2 "$srv_h" >/dev/null || fail "home lost while md's exit is in use"
dns="$(phone status "$work/phone" | field dns)"
[[ "$dns" == 100.81.* ]] || fail "the VPN's DNS server is $dns, not md's resolver (md's exit is in use)"
wait_for 30 sh -c "sudo nsenter --net=/run/netns/en-ph $work/mobilehost resolve $dns srv-h.home.internal | grep -qx $srv_h" || fail "home's name from md's resolver"
phone exit "$work/phone" md.test off || fail "stopping md's exit"
wait_for 30 exit_in "" || fail "md's exit still in use"
wait_for 30 sh -c "! sudo nsenter --net=/run/netns/en-ph curl -s -o /dev/null --max-time 2 http://203.0.113.2/" || fail "en-inet still reached with the exit off"

step "the phone leaves md: home stays, md's address goes"
phone leave "$work/phone" md.test || fail "leave"
phone networks "$work/phone" | grep -q '"md.test"' && fail "md is still among the phone's networks"
wait_for 30 sh -c "! sudo nsenter --net=/run/netns/en-ph ip -br addr show tun0 | grep -q $ph_md" || fail "tun0 still carries md's address"
wait_for 30 inns en-ph ping -c1 -W1 "$srv_h" || fail "home lost after leaving md"
if inns en-ph ping -c1 -W2 "$srv_m" >/dev/null 2>&1; then fail "md still reached after leaving it"; fi

step "md joined again; the phone leaves home, its first network (disconnected): md takes its place"
phone join "$work/phone" md.test "$record_md" "$(words md 100.81.0.0/16)" || fail "joining md again"
wait_for 60 inns en-ph ping -c1 -W1 "$srv_m" || fail "the phone cannot reach srv-m after joining md again"
sudo kill "$phone_pid"
wait_for 15 sh -c "! sudo kill -0 $phone_pid 2>/dev/null" || fail "the phone did not disconnect"
phone leave "$work/phone" "" || fail "leaving home"
[[ "$(phone networks "$work/phone")" == '[{"domain":"md.test","first":true}]' ]] || fail "networks after leaving home: $(phone networks "$work/phone")"
start_phone
wait_for 60 inns en-ph ping -c1 -W1 "$srv_m" || fail "md, now first, not reached"
if inns en-ph ping -c1 -W2 "$srv_h" >/dev/null 2>&1; then fail "home still reached after leaving it"; fi
dns_is() { [[ "$(phone status "$work/phone" | field dns)" == $1 ]]; }
wait_for 30 dns_is '100.81.*' || fail "the VPN's DNS server is $(phone status "$work/phone" | field dns), not md's resolver"
dns="$(phone status "$work/phone" | field dns)"
wait_for 30 sh -c "sudo nsenter --net=/run/netns/en-ph $work/mobilehost resolve $dns srv-m.md.internal | grep -qx $srv_m" || fail "md's name from $dns after leaving home"

printf '\nPASS\n'
