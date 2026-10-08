#!/usr/bin/env bash
# Backhaul end-to-end integration test (spec §11) using Linux network namespaces.
#
#   bh-client (10.100.1.2) ──┐
#                            ├── bh-inet (router; IP-echo + DNS on 10.100.3.1)
#   bh-exit   (10.100.2.2) ──┘
#
# Asserts: the client's egress IP equals the exit node's; `doctor` reports no
# leaks; the kill-switch blocks traffic while the transport is cut and the
# tunnel auto-recovers; teardown restores routes/firewall/DNS exactly.
#
# Requires: root, iproute2, nftables, python3, curl, Go; dnsmasq optional.
# Usage:    sudo -E bash test/integration/netns.sh   [WSTUNNEL=/path/to/wstunnel]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d /tmp/backhaul-it.XXXXXX)"
BIN="$WORK/bin"
PIDS=()
EXIT_IP=10.100.2.2
CLIENT_IP=10.100.1.2
ECHO=http://10.100.3.1:8080/

log()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
fail() { printf '\n\033[31mFAIL: %s\033[0m\n' "$*"; exit 1; }
nsx()  { local ns=$1; shift; ip netns exec "$ns" "$@"; }

cleanup() {
  set +e
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  sleep 2
  for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null; done
  for ns in bh-client bh-exit bh-inet; do ip netns del "$ns" 2>/dev/null; done
  rm -rf /etc/netns/bh-client /etc/netns/bh-exit
  echo "logs kept in $WORK"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || fail "run as root"

log "build backhaul"
mkdir -p "$BIN"
(cd "$ROOT" && go build -o "$BIN/backhaul" ./cmd/backhaul)
if [ -n "${WSTUNNEL:-}" ]; then
  cp "$WSTUNNEL" "$BIN/wstunnel"   # found next to the backhaul binary
fi                                 # else backhaul downloads the pinned release

log "create namespaces"
for ns in bh-inet bh-exit bh-client; do ip netns add "$ns"; nsx "$ns" ip link set lo up; done
ip link add veth-c type veth peer name veth-ci
ip link add veth-e type veth peer name veth-ei
ip link set veth-c netns bh-client; ip link set veth-ci netns bh-inet
ip link set veth-e netns bh-exit;   ip link set veth-ei netns bh-inet
nsx bh-inet ip addr add 10.100.1.1/24 dev veth-ci
nsx bh-inet ip addr add 10.100.2.1/24 dev veth-ei
nsx bh-inet ip addr add 10.100.3.1/32 dev lo
nsx bh-inet ip link set veth-ci up; nsx bh-inet ip link set veth-ei up
nsx bh-inet sysctl -qw net.ipv4.ip_forward=1
nsx bh-client ip addr add $CLIENT_IP/24 dev veth-c; nsx bh-client ip link set veth-c up
nsx bh-client ip route add default via 10.100.1.1
nsx bh-exit ip addr add $EXIT_IP/24 dev veth-e;     nsx bh-exit ip link set veth-e up
nsx bh-exit ip route add default via 10.100.2.1
# Per-namespace resolv.conf so nothing touches the host's.
for ns in bh-client bh-exit; do
  mkdir -p /etc/netns/$ns; echo "nameserver 10.100.3.1" > /etc/netns/$ns/resolv.conf
done

log "start 'internet' services (IP echo, DNS)"
cat > "$WORK/echo.py" <<'EOF'
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = (self.client_address[0] + "\n").encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("10.100.3.1", 8080), H).serve_forever()
EOF
nsx bh-inet python3 "$WORK/echo.py" & PIDS+=($!)
HAVE_DNS=0
if command -v dnsmasq >/dev/null; then
  nsx bh-inet dnsmasq --no-daemon --no-resolv --no-hosts --listen-address=10.100.3.1 --bind-interfaces \
    --address=/whoami.test/10.100.9.9 >"$WORK/dnsmasq.log" 2>&1 & PIDS+=($!)
  HAVE_DNS=1
fi
sleep 1
[ "$(nsx bh-client curl -s --max-time 5 $ECHO)" = "$CLIENT_IP" ] || fail "baseline: client cannot reach echo service"

tune() { # tune <config> : point probes at the fake internet, speed up health checks
  sed -i \
    -e "s|^ip_check_url = .*|ip_check_url = \"$ECHO\"|" \
    -e 's|^ipv6_check_url = .*|ipv6_check_url = "http://[fd00:dead::1]:8080/"|' \
    -e 's|^dns_leak_name = .*|dns_leak_name = "whoami.test"|' \
    -e 's|^dns_upstream = .*|dns_upstream = "10.100.3.1:53"|' \
    -e 's|^dns_method = .*|dns_method = "resolv.conf"|' \
    -e 's|^interval = "10s"|interval = "2s"|' \
    -e 's|^handshake_timeout = .*|handshake_timeout = "20s"|' \
    -e 's|^startup_grace = .*|startup_grace = "5s"|' \
    -e 's|^probe_timeout = .*|probe_timeout = "4s"|' "$1"
}

log "setup: exit node, then client import"
export BACKHAUL_CONFIG_DIR="$WORK/exit"
"$BIN/backhaul" setup --yes --role serve --endpoint $EXIT_IP --port 443 --subnet6 "" > "$WORK/setup.log"
tune "$WORK/exit/config.toml"
export BACKHAUL_CONFIG_DIR="$WORK/client"
"$BIN/backhaul" setup --import "@$WORK/exit/pairing.txt" >> "$WORK/setup.log"
tune "$WORK/client/config.toml"
# Both namespaces share /var/run/wireguard; use distinct interface names.
sed -i 's|^interface = "wg0"|interface = "bhc0"|' "$WORK/client/config.toml"

snapshot() { # snapshot <ns>
  { nsx "$1" ip -4 route; nsx "$1" ip -6 route; nsx "$1" nft list ruleset; cat /etc/netns/$1/resolv.conf
    nsx "$1" sysctl -n net.ipv4.ip_forward net.ipv6.conf.all.disable_ipv6; } 2>/dev/null
}
snapshot bh-client > "$WORK/client.before"
snapshot bh-exit > "$WORK/exit.before"

log "backhaul serve (exit node)"
BACKHAUL_CONFIG_DIR="$WORK/exit" nsx bh-exit "$BIN/backhaul" serve -v > "$WORK/serve.log" 2>&1 & SERVE=$!; PIDS+=($SERVE)
for i in $(seq 30); do grep -q "exit node ready" "$WORK/serve.log" && break; sleep 1; done
grep -q "exit node ready" "$WORK/serve.log" || { cat "$WORK/serve.log"; fail "serve did not come up"; }

log "backhaul connect (client)"
BACKHAUL_CONFIG_DIR="$WORK/client" nsx bh-client "$BIN/backhaul" connect -v > "$WORK/connect.log" 2>&1 & CONNECT=$!; PIDS+=($CONNECT)
for i in $(seq 45); do
  [ "$(nsx bh-client curl -s --max-time 3 $ECHO || true)" = "$EXIT_IP" ] && break; sleep 1
done

log "assert: egress IP is the exit node's"
GOT="$(nsx bh-client curl -s --max-time 5 $ECHO || true)"
[ "$GOT" = "$EXIT_IP" ] || { tail -50 "$WORK/connect.log"; fail "egress IP '$GOT', want $EXIT_IP"; }
echo "egress = $GOT ✓"

log "assert: doctor reports no leaks"
if ! BACKHAUL_CONFIG_DIR="$WORK/client" nsx bh-client "$BIN/backhaul" doctor | tee "$WORK/doctor.log"; then
  if [ $HAVE_DNS = 0 ] && ! grep -v "DNS leak" "$WORK/doctor.log" | grep -q FAIL; then
    echo "(only the DNS check failed, and dnsmasq is not installed — tolerated)"
  else
    fail "doctor reported problems"
  fi
fi
BACKHAUL_CONFIG_DIR="$WORK/client" nsx bh-client "$BIN/backhaul" status --no-ip

log "assert: kill-switch — cut the transport, nothing may leak"
nsx bh-inet nft add table inet cut
nsx bh-inet nft add chain inet cut fwd '{ type filter hook forward priority 0; }'
nsx bh-inet nft add rule inet cut fwd ip daddr $EXIT_IP tcp dport 443 drop
nsx bh-client pkill -f "wstunnel client" || true   # drop the live TCP session too
for i in 1 2 3 4 5; do
  GOT="$(nsx bh-client curl -s --max-time 2 $ECHO || true)"
  [ "$GOT" = "$CLIENT_IP" ] && fail "LEAK: traffic left with the real IP while the tunnel was down"
  sleep 1
done
echo "no leak while tunnel down ✓"

log "assert: auto-reconnect after the transport is restored"
nsx bh-inet nft delete table inet cut
for i in $(seq 90); do
  [ "$(nsx bh-client curl -s --max-time 2 $ECHO || true)" = "$EXIT_IP" ] && break; sleep 1
done
[ "$(nsx bh-client curl -s --max-time 5 $ECHO || true)" = "$EXIT_IP" ] || { tail -50 "$WORK/connect.log"; fail "did not recover"; }
echo "recovered ✓"

log "assert: clean teardown restores the machines exactly"
kill -TERM $CONNECT; wait $CONNECT || true                               # signal path
BACKHAUL_CONFIG_DIR="$WORK/exit" nsx bh-exit "$BIN/backhaul" disconnect \
  || fail "backhaul disconnect failed"                                    # stop-request path
wait $SERVE || true
snapshot bh-client > "$WORK/client.after"
snapshot bh-exit > "$WORK/exit.after"
diff -u "$WORK/client.before" "$WORK/client.after" || fail "client not restored"
diff -u "$WORK/exit.before" "$WORK/exit.after" || fail "exit node not restored"
echo "restored ✓"

log "PASS"
