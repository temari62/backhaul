# Backhaul — Build Specification

A self-hosted, two-machine personal VPN that lets **Laptop 1** (the *client*, e.g. on a
restricted/foreign network) route its internet traffic through **Laptop 2** (the *exit node*,
e.g. at home) so it appears on the internet with Laptop 2's residential IP address.

This document is the authoritative spec. Build the project described here. Where this spec is
silent, prefer the simplest robust option and leave a `TODO(spec)` comment.

---

## 1. Goal & success criteria

Build a single cross-platform program, `backhaul`, that runs in one of two modes:

- `backhaul serve`   — run on **Laptop 2** (exit node). Terminates the tunnel, NATs traffic to the internet.
- `backhaul connect` — run on **Laptop 1** (client). Routes all local traffic through the tunnel.

**Done =** On Laptop 1, after `backhaul connect`, visiting an "what is my IP" service returns
**Laptop 2's public IP**, DNS resolves through the tunnel (no leaks), and the connection survives
on a network that blocks or throttles plain WireGuard UDP.

### Explicit non-goals
- Do **not** implement tunnel encryption yourself. Use WireGuard for the data plane.
- Do **not** implement a custom obfuscation protocol. Use `wstunnel` (WebSocket Secure) as the
  transport wrapper.
- Not a multi-user/commercial VPN. Exactly two peers, both owned by the same person.

---

## 2. Why this architecture (read before designing)

The naive design (plain WireGuard, UDP, peer-to-peer) fails in two common real-world ways:

1. **Reachability** — Laptop 2 sits behind a home router (NAT). Laptop 1 cannot open a connection
   to it without help.
2. **Deep packet inspection** — Some networks fingerprint and throttle/drop WireGuard's UDP
   handshake. Traffic needs to look like normal HTTPS.

Backhaul solves both by stacking proven components:

```
Laptop 1 (client)                                   Laptop 2 (exit node)
┌─────────────────────────┐                         ┌──────────────────────────┐
│ apps / browser          │                         │   wstunnel server :443    │
│   │ (all traffic)       │                         │     (TLS / WebSocket)     │
│   ▼                     │                         │        │                  │
│ WireGuard iface wg0     │                         │        ▼                  │
│ AllowedIPs=0.0.0.0/0    │                         │   WireGuard iface wg0     │
│ Endpoint=127.0.0.1:PORT │                         │        │                  │
│   │                     │                         │        ▼                  │
│   ▼                     │   WSS over TCP/443       │   IP forward + NAT        │
│ wstunnel client ───────────────────────────────▶ │        │                  │
│ (wraps WG UDP in TLS)   │   (looks like HTTPS)     │        ▼                  │
└─────────────────────────┘                         │   physical NIC → internet │
                                                     └──────────────────────────┘
```

- **WireGuard** gives modern, audited encryption and the `0.0.0.0/0` "route everything" behavior.
- **wstunnel** carries WireGuard's UDP inside a TLS WebSocket on port 443, so on the wire it is
  indistinguishable from HTTPS. This is what gets through restrictive networks.
- Because the exit is Laptop 2 (a residential connection), the public IP is a residential IP,
  which is far less likely to be blocklisted than a datacenter/VPS IP.

---

## 3. Reachability (NAT traversal) — pick a mode at setup

Laptop 2 must be reachable from Laptop 1. Support three modes, selectable in config
(`reachability.mode`). Implement **A** first; **B** and **C** can be later milestones.

**A. Port forward (default, no third party, free).**
User forwards TCP **443** on the home router to Laptop 2. Because home IPs change, support
**Dynamic DNS**: config takes a hostname (e.g. `myhome.duckdns.org`); the `serve` side can
optionally run a DDNS updater loop (pluggable: DuckDNS, Cloudflare). Client uses the hostname.

**B. Relay via cheap VPS (fallback when no port forward is possible).**
A tiny always-on box with a public IP runs `wstunnel server` and relays to Laptop 2, which holds
a persistent outbound WSS connection to the VPS (so Laptop 2 needs no inbound port). Traffic still
exits via Laptop 2. Document this but it is optional for v1.

**C. Rendezvous/hole-punching.** Out of scope for v1. Leave an interface stub.

Detect and clearly report the common failure: "cannot reach exit node on :443 — is the port
forwarded / DDNS pointing correctly?"

---

## 4. Tech stack

- **Language: Go** (single static binary, easy cross-compile for Linux/macOS/Windows).
- **WireGuard:** embed userspace **`wireguard-go`** plus a TUN device so the app does not depend on
  a kernel module; configure peers with the `wgctrl` library
  (`golang.zx2c4.com/wireguard/wgctrl`). Fall back to invoking system `wg-quick` if present and
  preferred (`engine.wireguard = "embedded" | "wg-quick"`).
- **Obfuscation transport:** bundle the **`wstunnel`** binary (Rust) and manage it as a child
  process. Abstract it behind a `Transport` interface so it can be swapped later
  (e.g. for `udp2raw` or a native Go WS implementation).
- **TLS certs for wstunnel:** support (a) self-signed generated at setup, or (b) a real cert via
  the hostname. Self-signed is fine since both ends are ours; pin the cert fingerprint in client
  config to prevent MITM.
- **Config:** TOML at `~/.config/backhaul/config.toml`. Secrets (private keys) in a sibling file
  with `0600` perms.
- **CLI:** `cobra`. **Logging:** structured (`slog`), `--verbose` for debug.
- **Optional GUI (later milestone):** system-tray app (`fyne` or `systray`) with Connect/Disconnect
  and a status dot. Ship CLI first.

Privilege note: creating a TUN device and editing routes needs admin/root. The app must detect
missing privileges and print the exact command to re-run (don't silently fail).

---

## 5. Component breakdown

Build these packages:

- `cmd/backhaul` — CLI entrypoints (`serve`, `connect`, `setup`, `status`, `keys`, `doctor`).
- `internal/config` — load/validate/generate TOML; key storage with strict perms.
- `internal/keys` — WireGuard keypair + preshared key generation.
- `internal/wg` — bring up/down the WireGuard interface, apply peer config, set routes & DNS.
  Two backends: `embedded` (wireguard-go + wgctrl) and `wgquick`.
- `internal/transport` — `Transport` interface; `wstunnel` implementation (spawn, supervise,
  restart with backoff, parse readiness from stdout).
- `internal/route` — OS-specific routing + DNS override + kill-switch (see §7). Linux/macOS/Windows
  implementations behind one interface.
- `internal/nat` — exit-node side: enable IP forwarding + NAT/masquerade. Linux (`nftables`/
  `iptables`), macOS (`pf`), Windows (ICS or `netsh`/`New-NetNat`).
- `internal/ddns` — optional dynamic-DNS updaters (DuckDNS, Cloudflare).
- `internal/health` — connectivity probe, IP-leak check, auto-reconnect loop.
- `internal/doctor` — pre-flight diagnostics (privileges, port reachability, DNS, cert, leaks).

---

## 6. Setup & run flows

### 6.1 `backhaul setup` (run once, ideally on an unrestricted network)
Interactive wizard that:
1. Asks which machine this is (exit node vs client).
2. Generates WireGuard keypairs + a preshared key.
3. For the exit node: picks a WireGuard subnet (default `10.9.0.0/24`, server `.1`, client `.2`),
   a wstunnel listen setup on `:443`, generates a self-signed TLS cert, prints its SHA-256
   fingerprint, and writes `serve` config.
4. Produces a **pairing blob** (base64 TOML) containing everything the *other* machine needs:
   peer public keys, PSK, subnet, endpoint hostname/port, TLS fingerprint. Print it and also write
   `pairing.txt`. The other machine runs `backhaul setup --import <blob>`.
5. Validates the result and prints next steps (router port-forward reminder, DDNS, etc.).

Do the key exchange here, while the network is open — re-pairing from a restricted network is the
most fragile step, so make the blob easy to move (QR code output is a nice-to-have).

### 6.2 `backhaul serve` (Laptop 2 / exit node)
1. Pre-flight (`doctor` subset): root? forwarding allowed? :443 free?
2. Bring up WireGuard `wg0` with the client as the sole peer.
3. Enable IP forwarding + NAT from `wg0` to the default internet interface.
4. Start wstunnel server on `:443`, forwarding to the local WireGuard UDP port.
5. Start DDNS updater if configured.
6. Supervise children; on crash, restart with exponential backoff; log health.
7. On `SIGINT`/`SIGTERM`: tear down NAT rules and interface cleanly (leave the machine as found).

### 6.3 `backhaul connect` (Laptop 1 / client)
1. Pre-flight: root? can resolve + TCP-connect to `endpoint:443`?
2. Start wstunnel client → local UDP listener; it dials `wss://endpoint:443`, pinning the cert
   fingerprint.
3. Bring up WireGuard `wg0`: `Endpoint = 127.0.0.1:<wstunnel-local-port>`,
   `AllowedIPs = 0.0.0.0/0, ::/0`, `PersistentKeepalive = 25`.
4. Install routing so all traffic uses `wg0`, **except** the route to the real exit endpoint IP,
   which must stay on the physical interface (avoid the classic routing loop). Override system DNS
   to a resolver reached through the tunnel.
5. Enable **kill-switch** (default on): if the tunnel drops, block non-tunnel traffic so the real
   IP never leaks. `--no-killswitch` to disable.
6. Run health loop (§8). On `SIGINT`/`SIGTERM`: restore original routes/DNS/firewall exactly.

---

## 7. Routing, DNS, kill-switch (the leak-prevention details)

Implement carefully per-OS; this is where hand-rolled VPNs leak:

- **Default-route split:** add `0.0.0.0/1` and `128.0.0.1/1` via `wg0` (beats the existing default
  without deleting it), or use the OS's standard full-tunnel method. Add an explicit host route for
  the exit endpoint IP via the original gateway.
- **DNS:** route DNS through the tunnel; set resolver to the WireGuard server IP or a public
  resolver reached via the tunnel. On Linux prefer `resolvectl`/`systemd-resolved`; handle plain
  `/etc/resolv.conf` fallback; macOS `scutil`; Windows `Set-DnsClientServerAddress`. Restore on exit.
- **Kill-switch:** firewall rules allowing only (a) traffic on `wg0` and (b) the single
  endpoint:443 connection; drop everything else. Linux `nftables`, macOS `pf`, Windows WFP/`netsh`.
- **IPv6:** either fully tunnel it or disable it for the session to prevent v6 leaks. Pick one and
  document it; default to tunneling `::/0` and, if that fails setup, disabling v6 with a warning.

---

## 8. Health, resilience, diagnostics

- **`backhaul status`** — tunnel up/down, handshake age, current egress IP, bytes in/out, transport
  state.
- **`backhaul doctor`** — runs: privilege check; endpoint DNS + TCP:443 reachability; TLS
  fingerprint match; WireGuard handshake success; **IP-leak test** (fetch external IP, assert it
  equals the exit's); **DNS-leak test**; IPv6-leak test. Print pass/fail with remedies.
- **Auto-reconnect:** detect dead tunnel (no handshake within N s) and restart transport + WG with
  backoff. Keep kill-switch engaged during reconnect so nothing leaks.
- **Transport fallback hook:** `Transport` interface should make it easy to add a second
  obfuscation method later and switch if the primary is blocked. v1 ships wstunnel only.

---

## 9. Config file shape (reference)

```toml
# ~/.config/backhaul/config.toml
mode = "connect"            # "serve" or "connect"

[wireguard]
engine     = "embedded"     # "embedded" | "wg-quick"
subnet     = "10.9.0.0/24"
self_ip    = "10.9.0.2/32"  # server uses 10.9.0.1/32
keepalive  = 25

[peer]
public_key = "BASE64..."    # the other machine's WG public key
# serve mode only: client's allowed IP. connect mode only: endpoint below.

[transport]
kind        = "wstunnel"
endpoint    = "myhome.duckdns.org"   # connect mode
port        = 443
tls_sha256  = "AB:CD:...:EF"         # pinned cert fingerprint

[reachability]
mode = "port-forward"       # "port-forward" | "relay"
# [reachability.relay] host = "vps.example.com"  # mode = relay

[ddns]                      # serve mode, optional
provider = "duckdns"        # "duckdns" | "cloudflare" | ""
# token/domain in the secrets file, not here

[client]
killswitch = true
tunnel_ipv6 = true
dns = "10.9.0.1"
```

Private keys, PSK, and DDNS tokens live in `~/.config/backhaul/secrets.toml` (`0600`).

---

## 10. Milestones (build in this order)

1. **M1 — CLI skeleton + config/keys.** `setup`, `keys`, config load/validate, pairing blob
   round-trip. No networking yet.
2. **M2 — Plain WireGuard tunnel (no obfuscation).** `serve` brings up WG + NAT on Linux; `connect`
   full-tunnels on Linux. Verify egress IP changes. (This proves routing/NAT before adding TLS.)
3. **M3 — wstunnel transport.** Wrap WG UDP in WSS:443 with cert pinning; supervise the child
   process. Verify it still works and now rides port 443.
4. **M4 — Leak prevention.** DNS override, kill-switch, IPv6 handling, `doctor` leak tests.
5. **M5 — Resilience.** Auto-reconnect, backoff, `status`, clean teardown on signals.
6. **M6 — Cross-platform.** macOS (`pf`, `scutil`) then Windows (WFP, `New-NetNat`). Linux is the
   reference.
7. **M7 — DDNS + relay mode (B).** Optional reachability helpers.
8. **M8 — Tray GUI.** Connect/Disconnect, status indicator.

Each milestone must build, run, and have at least a smoke test. Don't start a milestone before the
previous one works end-to-end.

---

## 11. Testing

- **Unit:** config validation, pairing blob encode/decode, key generation, fingerprint pinning.
- **Integration (Linux, in CI with network namespaces or two containers):** stand up `serve` and
  `connect` on a virtual network; assert the client's egress IP equals the server's and that
  `doctor` reports no leaks.
- **Manual acceptance checklist** (put in `README`): fresh pair on open network → port-forward →
  connect from a second network → confirm IP, DNS, and v6 all exit via the server → kill the
  transport mid-session and confirm no leak + auto-reconnect.

---

## 12. Deliverables

- `backhaul` binary (Go), building for linux/amd64, linux/arm64, darwin/arm64, windows/amd64.
- Bundled or auto-downloaded `wstunnel` binary per platform (verify checksum).
- `README.md`: install, the one-time setup walkthrough, router/DDNS instructions, the acceptance
  checklist, and a troubleshooting section keyed to `doctor` failures.
- `Makefile` / `goreleaser` config for cross-builds.
- `LICENSE` (MIT unless told otherwise).

---

## 13. Constraints & guidance for the implementer

- Favor correctness of teardown over features: the app must **always** restore the machine's
  original routing/DNS/firewall on exit, including on crash (use deferred cleanup + a recovery pass
  on next start).
- Never log private keys or tokens. Redact in verbose output.
- All timeouts, ports, subnets, and resolver IPs configurable; no magic numbers in code.
- Prefer invoking well-maintained libraries/binaries over bespoke protocol code. The value of this
  project is the *orchestration*, not reinventing crypto or obfuscation.
- Keep a `TODO(spec)` marker anywhere you had to guess, so gaps are easy to find.
