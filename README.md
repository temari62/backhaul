# Backhaul

A self-hosted, two-machine personal VPN. **Laptop 1** (the *client*, e.g. on a restricted or
foreign network) routes all its traffic through **Laptop 2** (the *exit node*, e.g. at home), so
it appears on the internet with Laptop 2's residential IP.

```
Laptop 1 (client)                                    Laptop 2 (exit node)
apps ─▶ WireGuard wg0 (0.0.0.0/0, ::/0)              wstunnel server :443 (TLS/WebSocket)
          │ Endpoint = 127.0.0.1:51821                        │
          ▼                                                   ▼
        wstunnel client ─▶ pinned-TLS proxy ══ WSS/443 ══▶ WireGuard wg0 ─▶ NAT ─▶ internet
                                    (looks like HTTPS)
```

- **WireGuard** (embedded userspace `wireguard-go`, or system `wg-quick`) does the encryption.
- **wstunnel** wraps WireGuard's UDP in a TLS WebSocket on port 443, so it gets through networks
  that block or throttle plain WireGuard.
- The exit node's self-signed certificate is **pinned** by SHA-256 on the client. wstunnel itself
  can't pin certificates, so backhaul's client runs wstunnel against a tiny loopback proxy that
  makes the real TLS connection and refuses any certificate except the pinned one.
- An unknown HTTP upgrade path is rejected by the server (`transport.path_prefix`, a random token
  generated at setup), so port scanners just see a TLS server that says no.

Backhaul only orchestrates these components. It doesn't implement any crypto or obfuscation itself.

---

## Install

Download a release binary for your platform, or build from source (Go 1.26+):

```sh
make build            # → bin/backhaul        (or: go build -o backhaul ./cmd/backhaul)
make cross            # → dist/ for linux/amd64, linux/arm64, darwin/arm64, windows/amd64
```

On first `serve`/`connect`, backhaul downloads **wstunnel v10.7.1** and checks its SHA-256 against
a value pinned in the source (`internal/transport/install.go`). On Windows it also downloads
**wintun.dll** (pinned SHA-256) and puts it next to `backhaul.exe`. To use your own copies instead,
put `wstunnel` next to the backhaul binary, put it on `PATH`, or set `transport.wstunnel_path`.

`serve` and `connect` need root/Administrator, because they create a TUN device and change routes
and the firewall. If you run them without it, backhaul prints the exact command to re-run.

---

## Windows app (all-in-one)

`Backhaul.exe` is a single file. It has a modern interface with two tabs:

- **Share**: use this PC as the exit node.
- **Connect**: send this PC's traffic through one of your exit nodes. Every pairing code you save
  is added to a list. Click an exit node to choose it, then click **Connect**. You can rename or
  remove entries. Saving a new code for an exit node that's already in the list updates it.

wstunnel and the Wintun driver are built in, so there's nothing else to install.

1. **On the exit node PC (Laptop 2):** open Backhaul and choose **Share**. Click **Detect** to
   fill in the public IP (or type your DDNS hostname), then click **Set up exit node**. Backhaul
   shows a **pairing code** with a QR code. Copy it.
2. **On the other PC (Laptop 1):** open Backhaul, choose **Connect**, paste the pairing code and
   click **Save pairing**.
3. Click **Start sharing** on Laptop 2, then **Connect** on Laptop 1. The status turns green, and
   the app shows the handshake, traffic and your new public IP.

Other things to know:
- **Admin prompt.** Backhaul asks for administrator rights once when it starts (UAC), because
  connecting changes routes, DNS and the firewall.
- **Closing the window.** Backhaul keeps running in the tray, still sharing or connected.
  - Click the tray icon to open the window again.
  - Right-click it → **Quit** to stop, restore your network and exit.
  - The icon's colour shows the status.
- **Stealth mode** (⚙ Settings). Hides the tray icon while Backhaul keeps running.
  - To reopen the window, start `Backhaul.exe` again.
  - To exit, use **Quit Backhaul** in Settings.
- **Start with Windows** (⚙ Settings). Backhaul starts in the tray when you sign in and starts
  sharing by itself.
  - It's a scheduled task named "Backhaul" that runs with administrator rights, so there's no
    permission prompt at every sign-in.
  - It starts at **sign-in**. For an exit node that should come back after a restart without
    anyone signing in, turn on automatic sign-in for that PC: run `netplwiz`, then clear "Users
    must enter a user name and password".
- **Profiles.** One PC can hold both roles. The exit node profile and each saved exit node (in
  `nodes\`) are stored under `%USERPROFILE%\.config\backhaul`. An exit-node or client config
  created earlier with the CLI is picked up automatically.
- **App files.** Logs, the unpacked components and WebView2 data live in
  `%LOCALAPPDATA%\Backhaul`.
- **Requirements.** The Microsoft Edge **WebView2 Runtime**, which is built into Windows 11 and
  current Windows 10. If it's missing, Backhaul says so and links to the installer.

To build it:

```powershell
powershell -ExecutionPolicy Bypass -File .\build-app.ps1     # → dist\Backhaul.exe
```

The build fetches the pinned wstunnel and Wintun releases, verifies their SHA-256, and embeds
them along with the icon and the administrator manifest.

---

## One-time setup

Do this while both machines are on an open network. Re-pairing from a restricted network is the
most fragile step.

### 1. Exit node (Laptop 2, at home)

```sh
backhaul setup
```

The wizard asks for:
- **Public hostname**: a DDNS name such as `myhome.duckdns.org`. Your current public IP is offered
  as the default, which is fine for testing, but home IPs change.
- **Port**: 443 by default.
- **Tunnel subnets**: `10.9.0.0/24` (server `.1`, client `.2`) and `fd09:b4c0::/64` for IPv6.
- **DDNS provider** (optional): DuckDNS or Cloudflare.

It then:
- generates both WireGuard keypairs, a preshared key and a self-signed TLS certificate;
- writes `~/.config/backhaul/config.toml` and `secrets.toml` (mode 0600);
- prints the certificate fingerprint and a **pairing blob**, also saved to
  `~/.config/backhaul/pairing.txt`.

You can also run it non-interactively:

```sh
backhaul setup --yes --role serve --endpoint myhome.duckdns.org \
  --ddns-provider duckdns --ddns-domain myhome.duckdns.org --ddns-token <token>
```

### 2. Client (Laptop 1)

Move the blob over a trusted channel (USB stick, Signal, `scp`). **It contains the client's
private key.** `backhaul setup --qr` (or later `backhaul pairing --qr`) also prints it as a QR
code. Scanning it with a phone is an easy way to carry the blob to the other laptop, but anyone
who can see the screen can copy the key. Then run:

```sh
backhaul setup --import <blob>          # or: --import @pairing.txt
```

Afterwards, delete `pairing.txt` and every copy of the blob.

### 3. Router port-forward

In your home router's admin page (usually under *NAT*, *Virtual servers* or *Port forwarding*):

1. Give Laptop 2 a fixed LAN IP with a **DHCP reservation**. `setup` prints the LAN IP it detected.
2. Forward **TCP 443** (or your chosen port) to that LAN IP on the same port. WireGuard's own UDP
   port does **not** need forwarding, because it stays on the exit node's loopback.
3. If 443 is already in use on your public IP, pick another port in `setup` (`--port 8443`).
   443 is the hardest to block, though.

### 4. Dynamic DNS

Home IPs change, so the client dials a hostname.

- **DuckDNS** (free): create a subdomain at duckdns.org and copy your token. Set
  `ddns.provider = "duckdns"` and `ddns.domain = "myhome.duckdns.org"`, and put the token in
  `secrets.toml` as `ddns_token`.
- **Cloudflare**: create an API token with *Zone:DNS:Edit*. Set `ddns.provider = "cloudflare"`,
  `ddns.domain` and `ddns.zone_id`. backhaul creates or updates the A record (TTL 60, not proxied).

`backhaul serve` runs the updater every `ddns.interval` (5 minutes by default). On the exit node,
`backhaul doctor` checks that the hostname resolves to the machine's current public IP.

### 5. Run it

```sh
# Laptop 2
sudo backhaul serve
# Laptop 1
sudo backhaul connect          # --no-killswitch to disable the kill-switch for this session
backhaul status
backhaul doctor
```

On Windows, run the same commands from an elevated terminal ("Run as administrator").

Press Ctrl+C (or send SIGTERM, or run `backhaul disconnect` from another terminal) to stop. backhaul then restores routes, DNS, firewall and NAT
exactly as it found them. If backhaul crashes or loses power, the next `serve`/`connect` replays a
persisted undo journal first. You can also run `sudo backhaul doctor --recover` yourself.

---

## Exit node on an Ubuntu VPS

A rented Linux server (VPS) can be the exit node instead of a home PC. It's always on and needs no
router setup.

**What you need:**
- Ubuntu 22.04 or 24.04 with a public IPv4 address.
- Inbound TCP 443 allowed in the provider's firewall.

From China, use the Cloudflare disguise with your own domain, because connecting straight to a VPS
address tends to get that address blocked. The same guide is in the Windows app under **?**.

1. **Copy the Linux program to the VPS.** Use `backhaul_linux_arm64` instead if `uname -m` on the
   VPS prints `aarch64`.

   ```sh
   scp backhaul_linux_amd64 root@VPS_IP:/usr/local/bin/backhaul
   ```

2. **Prepare the VPS** (as root):

   ```sh
   chmod +x /usr/local/bin/backhaul
   apt update && apt install -y nftables
   ufw status | grep -q active && ufw allow 443/tcp
   ```

3. **Set it up.** Pick one of the two commands. Both print the pairing code.

   ```sh
   # Cloudflare (API token as described above)
   backhaul setup --role serve --transport cloudflare --endpoint vps.yourdomain.com --cloudflare-token YOUR_TOKEN --yes
   # or REALITY
   backhaul setup --role serve --transport reality --endpoint VPS_IP --yes
   ```

4. **Run it as a service.** This starts it at boot and restarts it if it stops.

   ```sh
   cat > /etc/systemd/system/backhaul.service <<'EOF'
   [Unit]
   Description=Backhaul exit node
   After=network-online.target
   Wants=network-online.target

   [Service]
   ExecStart=/usr/local/bin/backhaul serve
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   EOF
   systemctl daemon-reload && systemctl enable --now backhaul
   ```

5. **Pair.** `backhaul pairing` prints the code again. On the client, go to **Connect → + Add**, paste
   it, then click **Connect**.

**Checking on it:** `backhaul status` shows the tunnel state, and `journalctl -u backhaul -f`
follows the log.

**Changing the disguise later:** run `setup` again with `--force`, then
`systemctl restart backhaul`, and pair again.

A machine with its own public address skips the home-router step automatically: no UPnP and no
port forward.

---

## Commands

| Command | What it does |
|---|---|
| `setup` | Interactive wizard. `--import <blob>` on the client. `--yes` for non-interactive use. |
| `serve` | Exit node: WireGuard, forwarding and NAT, a DNS forwarder on the tunnel IP, the wstunnel server, and the DDNS updater. |
| `connect` | Client: wstunnel client, WireGuard, full-tunnel routes, DNS override, kill-switch, auto-reconnect. |
| `disconnect` | Stop a running `serve`/`connect` from another terminal, a service or the tray, and wait until the network is restored. |
| `pairing [--qr]` | Re-print the exit node's pairing blob, optionally as a terminal QR code. |
| `status` | Up/down, handshake age, egress IP, bytes in/out, transport state (`--json`). |
| `doctor` | Pre-flight and live diagnostics with remedies (`--recover` to undo a crashed run). |
| `keys show` / `keys generate` | Public keys of both sides, or a fresh keypair and PSK for manual setups. |

Global flags: `--config-dir` (or `$BACKHAUL_CONFIG_DIR`) and `-v/--verbose` for debug logs.
Secrets are never logged.

### Tray app

`backhaul-tray` puts a status dot in the system tray:

| Dot | Meaning |
|---|---|
| ● green | Connected and healthy |
| ◐ amber | Connecting or reconnecting (the kill-switch is blocking traffic meanwhile) |
| ○ grey | Disconnected |
| ✕ red | The last connect attempt failed |

The menu has **Connect / Disconnect** (labelled *Start / Stop exit node* on the exit node),
**Open log** and **Quit**.

- The tray itself runs **unprivileged**. Connect and Disconnect run `backhaul connect` /
  `backhaul disconnect` through your OS's normal admin prompt: UAC on Windows, the password
  dialog on macOS, `pkexec` on Linux.
- Their output goes to `~/.config/backhaul/tray.log`.
- The tunnel runs on its own, so quitting the tray leaves the VPN up. Use Disconnect first if you
  want it down.

Put `backhaul-tray` next to the `backhaul` binary (or put `backhaul` on `PATH`). On Linux it needs
a desktop with StatusNotifier/AppIndicator support and polkit. Release binaries cover Windows and
Linux. On macOS, build it on a Mac with `make tray`, because the macOS tray needs cgo (Cocoa).

---

## How leaks are prevented

| Concern | Linux | macOS | Windows |
|---|---|---|---|
| Full tunnel | `0.0.0.0/1` + `128.0.0.0/1` (and `::/1` + `8000::/1`) via the tunnel. The existing default route is left in place. | same, via `route` | same, via `netsh` |
| Routing loop | `/32` host route to the exit endpoint via the original gateway | same | same (`Find-NetRoute`) |
| DNS | `resolvectl` (`~.` routing domain), or a rewritten `/etc/resolv.conf` (backed up) | `networksetup -setdnsservers` on every service | NRPT rule for `.` plus the adapter's DNS server |
| Kill-switch | nftables `inet backhaul_ks` output policy drop (iptables fallback) | pf anchor `com.apple/250.backhaul` | Windows Filtering Platform filters in a dynamic session (adapted from WireGuard for Windows): removed automatically when Backhaul exits |
| IPv6 | **Tunnelled** (`::/0`). If that fails, IPv6 is **disabled for the session** with a warning. | same (`networksetup -setv6off`) | same (`ms_tcpip6` unbound) |

The kill-switch only allows traffic on the tunnel interface, loopback, the single
`endpoint:443` TCP connection, and DHCP/neighbour discovery so the physical link keeps working.
It stays engaged during reconnects.

**On Windows**, "the single endpoint connection" means Backhaul's own program (and Xray for
REALITY), so every Cloudflare address in the pool is allowed. The local network (router,
printers) and Windows' connectivity check (the Network Location Awareness service) are also
allowed. Blocking that check makes Windows mark the real adapter "No Internet".

If the exit node stops answering while the kill switch is on, Backhaul lifts the kill switch and
tries again. If the exit node then answers, the kill switch stays off for that session and the
log explains why.

An earlier version used Windows Firewall rules. On some PCs they began blocking the exit node about
a minute after connecting, which looked like a drop every minute. The filters now live in a
*dynamic* WFP session, so Windows deletes them by itself if Backhaul exits or crashes.

After connecting, two self-tests check the kill switch:
- the exit node must still be reachable;
- another program's DNS lookup through the tunnel must work.

If either fails, or the filters can't be installed, the kill switch is turned off for that
session, and the log says so.

**IPv6 decision:** backhaul tunnels IPv6 by default and NATs it out of the exit node (nftables/pf).
If the exit node has no IPv6, client IPv6 traffic simply dies in the tunnel, which is safe. Set
`client.tunnel_ipv6 = false` to disable IPv6 on the client for the session instead.

---

## Disguise (transport): Cloudflare, REALITY or wstunnel

Three disguises are available. You choose one when you set up the exit node, and the pairing code
carries it to the client. You can switch at any time by setting the exit node up again.

### Cloudflare (most robust in China)

The client connects to **Cloudflare's** addresses using your own hostname (for example
`vpn.yourdomain.com`). Cloudflare then forwards the traffic to your exit node.

- **Why it's hard to block:** a censor sees an ordinary HTTPS visit to a site on Cloudflare. It
  can't block Cloudflare's addresses without breaking a large part of the web.
- **Why your home IP is safe:** that IP is never contacted by the client directly, so it can't be
  blocked the way REALITY and wstunnel connections to it were.

**One-time setup, with a domain registered at Namecheap:**

1. Create a free account at <https://dash.cloudflare.com>, click **Add a site**, enter your domain
   and pick the **Free** plan. Cloudflare shows two **nameservers**.
2. At Namecheap, go to **Domain List → Manage → Nameservers**, choose **Custom DNS**, enter the two
   Cloudflare nameservers, and save. Wait until Cloudflare marks the site **Active**. This usually
   takes minutes, but can take a few hours.
3. In Cloudflare, go to **My Profile → API Tokens → Create Token → Custom token** and grant:
   - **Zone · Zone · Read**
   - **Zone · DNS · Edit**
   - **Zone · Zone Settings · Edit**

   Under *Zone Resources*, choose *Include → Specific zone → your domain*. Copy the token.
4. **Exit node:** Share → Reset…, choose **Disguise: Cloudflare**, enter a hostname such as
   `vpn.yourdomain.com`, paste the token, keep port **443**, and click **Set up exit node**.
   Backhaul then:
   - creates the DNS record, proxied (orange cloud) and pointed at your home IP, and keeps it
     updated if that IP changes;
   - sets the zone's **SSL/TLS** mode to **Full** if needed, so Cloudflare accepts the exit node's
     own certificate.
5. Click **Start sharing**. The router must still forward TCP 443 to the exit node (UPnP usually
   does this automatically), because Cloudflare connects to it there.
6. **Client:** Connect → Reset…, paste the new pairing code, then click **Connect**.

**Troubleshooting:** `doctor` on the client checks Cloudflare's certificate, then asks Cloudflare
to reach the exit node:
- **522 / 521:** Cloudflare can't reach the exit node. Check it's Sharing and port 443 is
  forwarded.
- **525 / 526:** wrong SSL mode.

**Automatic address switching:** China's firewall sometimes blocks the Cloudflare address in use,
for this client only, for a few minutes. The client therefore keeps a pool of about 14 Cloudflare
addresses:
- your hostname's own addresses;
- other addresses in the same blocks;
- addresses from Cloudflare's other ranges.

When a connection is cut or an address stops answering, it moves to the next address within
seconds. The log shows this as "switching to another Cloudflare address". Every address must
present a valid certificate for your hostname, so a wrong one is simply skipped.

Traffic to these few addresses goes outside the tunnel. A website that happens to use one of them
is reached directly, not through your home connection.

To use only addresses you choose, set `transport.edge_ips = ["104.16.1.2", "172.64.3.4"]` (or the
single `transport.edge_ip`) on the client.

**Hostname tip:** the hostname is visible to the network (as the TLS server name), so choose a dull
one such as `cdn.` or `static.` rather than `vpn.`.

Cloudflare's free plan is fine for personal use. Speed from China varies by time of day.

### Cloudflare Tunnel (no router setup)

This is the Cloudflare disguise without a port forward. The exit node runs Cloudflare's
`cloudflared`, which keeps an **outgoing** connection to Cloudflare, and Cloudflare sends the
clients' traffic down it.

**What's different from plain Cloudflare mode:**
- **Router:** no port forwarding and no UPnP. A router reboot or a change of home IP doesn't matter.
- **Several exit nodes:** any number can share one home connection.
- **Client:** sees an ordinary Cloudflare exit node on port 443; nothing changes on its side.

**Setting it up:**
- **API token:** needs one more permission, **Account · Cloudflare Tunnel · Edit**.
- **In the app:** choose **Disguise: Cloudflare Tunnel**.
- **From the command line:**
  `backhaul setup --role serve --transport cloudflare-tunnel --endpoint home.yourdomain.com --cloudflare-token …`

**What setup does:**
- creates (or reuses) the tunnel `backhaul-<hostname>`;
- routes the hostname to wstunnel on `127.0.0.1:47443`, which isn't reachable from the network;
- points the hostname's DNS at the tunnel (a proxied CNAME, replacing an earlier A record);
- stores the tunnel's token.

`serve` downloads the pinned cloudflared (Windows and Linux) the first time and supervises it. The
Share tab and `backhaul status` show whether it's connected and, if not, cloudflared's reason.

### REALITY and wstunnel

| Disguise | What a censor sees | Use when |
|---|---|---|
| **REALITY** (VLESS + REALITY via Xray) | An ordinary HTTPS connection to a real website (default `www.amazon.com`). If the censor probes your exit node, it gets Amazon's **genuine** certificate and page. Only your client, holding the exit node's REALITY public key and VLESS ID from the pairing code, gets the tunnel. | **China** and other networks that actively detect VPNs. It's the default in the Windows app. |
| **wstunnel** (WebSocket over TLS) | A TLS server with its own self-signed certificate. The client pins that certificate. | Networks that only block plain WireGuard. Firewalls that hunt for VPNs (like the Great Firewall) detect it within minutes. |

The WireGuard encryption inside is the same either way. The disguise only decides what the
traffic looks like on the wire.

- **Change the impersonated site** with `transport.reality.server_name` and
  `transport.reality.target` on the exit node, then set it up again. Pick a large HTTPS site
  reachable from the client's country that supports TLS 1.3. Xray warns against Apple/iCloud.
- **Command line:** `backhaul setup --transport reality`. Xray v26.3.27 is downloaded with a
  pinned checksum. The Windows app has it built in.
- **Tests:** the REALITY end-to-end test needs Linux or a normal Windows PC (it runs in CI). On
  Windows hosts with third-party Winsock layered providers, Xray's REALITY server stalls after the
  handshake.

## Exit-node NAT modes

`serve.nat_mode` controls how tunnel traffic reaches the internet from the exit node:

| Mode | How it works | Needs |
|---|---|---|
| `system` | Kernel forwarding and masquerade (nftables/iptables, pf, WinNAT). Fastest. | root/Administrator. On Windows, WinNAT, which only exists with the Hyper-V/Containers networking stack. |
| `userspace` | WireGuard feeds an in-process TCP/IP stack (gVisor). backhaul re-opens every TCP connection and UDP flow from its own process, and answers DNS to the tunnel IP by relaying it upstream. | Nothing. No admin rights, no NAT feature, no TUN driver. ICMP (ping) isn't forwarded. |
| `auto` (default) | `system` where available. **Windows 10/11 desktops without WinNAT get `userspace`.** | — |

On Windows, when `serve` runs elevated, it also adds a Windows Firewall rule allowing inbound
TCP on the wstunnel port, and removes it on exit. Without that rule the client can't connect.
If `serve` isn't elevated, allow `wstunnel.exe` when Windows asks.

backhaul's WireGuard socket is bound to **127.0.0.1** only, because it only ever talks to the
local wstunnel. Its UDP port is never exposed on the network.

## Reachability modes

- **A. Port forward + DDNS** (default): described above.
- **B. Relay via a VPS**: use this when you can't forward a port, for example behind CGNAT. The VPS
  runs plain `wstunnel server --restrict-http-upgrade-path-prefix <prefix> wss://0.0.0.0:443`.
  The exit node keeps an outbound reverse tunnel open to it (`wstunnel client -R udp://…`), and
  the client dials the VPS. Traffic still **exits via Laptop 2**. Configure it with
  `backhaul setup --reach relay --relay-host vps.example.com --relay-fingerprint <VPS cert SHA-256>`.
  Get the VPS fingerprint with
  `openssl s_client -connect vps:443 </dev/null | openssl x509 -noout -fingerprint -sha256`.
  This mode is less exercised than mode A.
- **C. Rendezvous / hole punching**: not implemented in v1 (interface stub in `internal/reach`).

---

## Configuration reference

`~/.config/backhaul/config.toml` (see `internal/config/config.go` for every key and default):

```toml
mode = "connect"                 # "serve" | "connect"

[wireguard]
engine = "embedded"              # "embedded" | "wg-quick"
interface = "wg0"                # macOS always uses utunN
subnet = "10.9.0.0/24"
self_ip = "10.9.0.2/32"          # server: 10.9.0.1/32
subnet6 = "fd09:b4c0::/64"
self_ip6 = "fd09:b4c0::2/128"
listen_port = 51820              # serve: WireGuard UDP port (loopback target of wstunnel)
mtu = 1280
keepalive = 25

[peer]
public_key = "BASE64..."
allowed_ips = ["10.9.0.2/32"]    # serve only

[transport]
kind = "wstunnel"
endpoint = "myhome.duckdns.org"  # connect
port = 443
tls_sha256 = "AB:CD:...:EF"
path_prefix = "random-token"
local_udp_port = 51821           # connect: wstunnel's local UDP listener
remote_udp_port = 51820          # connect: the exit node's WireGuard port
dial_timeout = "10s"
backoff_min = "1s"
backoff_max = "1m0s"

[reachability]
mode = "port-forward"            # "port-forward" | "relay"

[ddns]
provider = ""                    # "duckdns" | "cloudflare" | ""
domain = ""
interval = "5m0s"

[client]
killswitch = true
tunnel_ipv6 = true
dns = "10.9.0.1, fd09:b4c0::1"
dns_method = "auto"              # linux: "auto" | "resolved" | "resolv.conf"

[serve]
dns_forwarder = true             # relay DNS on the tunnel IP to dns_upstream
dns_upstream = "1.1.1.1:53"

[health]
interval = "10s"
handshake_timeout = "3m0s"       # no handshake for this long → reconnect
ip_check_url = "https://api.ipify.org"
```

`secrets.toml` (0600) holds `private_key`, `preshared_key` and `ddns_token`. backhaul refuses to
load it if group or others can read it.

---

## Manual acceptance checklist

1. [ ] **Fresh pair on an open network.** Run `backhaul setup` on Laptop 2, then
   `backhaul setup --import` on Laptop 1. Delete `pairing.txt`.
2. [ ] **Port-forward.** Router forwards TCP 443 to Laptop 2. Start `sudo backhaul serve`.
   `backhaul doctor` on Laptop 2 shows *DDNS / endpoint points here: PASS*.
3. [ ] **Connect from a second network** (phone hotspot, café). On Laptop 1, `backhaul doctor`
   shows endpoint DNS, TCP reachability and TLS fingerprint all PASS. Then run
   `sudo backhaul connect`.
4. [ ] **Confirm IP.** A "what is my IP" site shows **Laptop 2's public IP**. `backhaul doctor`
   shows *IP leak test: PASS*.
5. [ ] **Confirm DNS.** `backhaul doctor` shows *DNS leak test: PASS*. A DNS leak test site shows
   only the exit node's resolver.
6. [ ] **Confirm IPv6.** `backhaul doctor` shows *IPv6 leak test: PASS*. An IPv6 test site shows
   no IPv6, or the exit node's.
7. [ ] **Kill the transport mid-session.** Kill the `wstunnel` client process, or block TCP 443
   on Laptop 1's network. Pages stop loading and nothing leaks: `curl https://api.ipify.org` fails
   instead of printing the real IP.
8. [ ] **Auto-reconnect.** Restore the network. Within `health.handshake_timeout` and the
   backoff, traffic flows again through the exit node (`backhaul status` shows reconnects ≥ 1).
9. [ ] **Clean teardown.** Ctrl+C both sides. Routes (`ip route` / `netstat -rn` /
   `route print`), DNS and firewall rules match the state before connecting.

The Linux part of this checklist is automated in `test/integration/netns.sh`, which uses network
namespaces. Run it with `make integration` (root) or in CI.

There's also an end-to-end test that runs on **any OS without privileges** and changes nothing on
the host. It runs the real exit node in userspace mode against an in-process client
(wireguard-go on its own TCP/IP stack, the real wstunnel, and certificate pinning). It then
fetches a public IP-echo service through the tunnel, resolving DNS through the tunnel too.

```sh
BACKHAUL_E2E=1 BACKHAUL_TEST_WSTUNNEL=/path/to/wstunnel go test ./internal/app -run E2E -v
```

---

## Troubleshooting (keyed to `backhaul doctor`)

| `doctor` result | Meaning | Fix |
|---|---|---|
| **privileges: WARN** | Not running as root/Administrator | Re-run the printed command (`sudo …` / elevated terminal). |
| **other VPN: FAIL** | Another full-tunnel VPN (Astrill, OpenVPN, …) is connected on the client | Disconnect it before connecting Backhaul. Two VPNs fight over the routing table and both break, typically after a minute when the other VPN resets its adapter. Backhaul already disguises its traffic as HTTPS. If you deliberately want Backhaul inside the other VPN, set `client.allow_other_vpn = true`. While connected, Backhaul's route guard re-pins the path to the exit node if anything changes it, such as switching Wi-Fi networks. |
| **endpoint DNS: FAIL** | The client can't resolve the exit hostname | Check `transport.endpoint`. Make sure the DDNS updater is running on the exit node (`ddns updated` in its logs). |
| **endpoint TCP reachability: FAIL** — *cannot reach exit node on :443 — is the port forwarded / DDNS pointing correctly?* | Nothing is answering on the public IP:port | Check that `serve` is running, the router forwards TCP 443 to Laptop 2's **current** LAN IP, and Laptop 2's own firewall allows inbound 443. Some ISPs block inbound 443 (try `--port 8443`). Behind CGNAT, use relay mode. |
| **TLS fingerprint: FAIL** (mismatch) | The server presents a different certificate | If you re-ran setup on the exit node, re-pair. Otherwise **don't connect**: something is intercepting TLS. |
| **TLS fingerprint: FAIL** (handshake error) | Something other than wstunnel is on that port | Free the port on the exit node or change it on both sides. |
| **listen port free: FAIL** | Another service (a web server?) holds :443 on the exit node | Stop it or change `transport.port` (re-pair). |
| **DDNS / endpoint points here: FAIL** | The hostname resolves to an old IP | Enable `[ddns]` or update the A record yourself. |
| **WireGuard handshake: FAIL** | The transport is up but WireGuard can't complete a handshake | Keys don't match (re-pair), or the transport isn't ready: check `backhaul status` → *transport* and the exit node's logs. |
| **IP leak test: FAIL** | Egress IP is your real IP, or not the exit's | Restart `connect` and read its logs. If the exit node's public IP differs from its endpoint IP (multi-WAN, relay mode), set `client.expected_exit_ip`. |
| **DNS leak test: FAIL** | System DNS bypasses the tunnel resolver | Make sure `serve.dns_forwarder = true` on the exit node and keep the kill-switch on. On Linux, try `client.dns_method = "resolv.conf"`. |
| **IPv6 leak test: FAIL** | IPv6 leaves from your own address | Set `client.tunnel_ipv6 = false` (disables IPv6 for the session) and reconnect. |
| Anything left over after a crash | The undo journal wasn't replayed | `sudo backhaul doctor --recover`. |

Other notes:
- **Windows, "create TUN … wintun.dll"**: wintun.dll must sit next to `backhaul.exe`. backhaul
  downloads it automatically, but that needs internet access.
- **Windows exit node, `New-NetNat : Invalid class`**: this edition has no WinNAT. Use
  `serve.nat_mode = "auto"` (the default) or `"userspace"`. WinNAT also allows only one NAT
  network per host, so a Docker or Hyper-V NAT can conflict with it (`Get-NetNat`); `userspace`
  avoids that too.
- **Windows, `wsasendmsg: An invalid argument was supplied`**: a third-party Winsock layered
  provider (some VPN, proxy or antivirus products install one) is breaking wireguard-go's default
  sockets. backhaul uses its own plain loopback socket to avoid this, so update to the current
  build.
- **Slow or stalling sites through the tunnel**: lower `wireguard.mtu` on both sides
  (try 1200).

---

## Layout

```
cmd/backhaul        CLI (cobra): setup, pairing, serve, connect, disconnect, status, keys, doctor
cmd/backhaul-tray   system-tray GUI (status dot, Connect/Disconnect)
internal/tray       tray status model, generated icons, per-OS elevated launchers
internal/app        serve/connect orchestration, setup logic, teardown
internal/config     TOML config + secrets (0600), defaults, validation
internal/keys       WireGuard keypair / PSK generation (wgctrl)
internal/pairing    pairing blob (base64 TOML) encode/decode
internal/wg         embedded (wireguard-go + UAPI) and wg-quick engines; Wintun installer
internal/transport  Transport interface; supervised wstunnel; checksum-verified installer
internal/tlspin     self-signed cert, fingerprint pinning, pinned-TLS loopback proxy
internal/route      per-OS full-tunnel routes, DNS override, kill-switch
internal/nat        per-OS forwarding + masquerade (nftables/iptables, pf, WinNAT)
internal/undo       persisted undo journal → exact teardown and crash recovery
internal/health     reconnect loop + egress/DNS/IPv6 leak probes
internal/doctor     diagnostics with remedies
internal/ddns       DuckDNS / Cloudflare updaters
internal/dnsfwd     exit-node DNS relay on the tunnel IP
internal/reach      reachability mode C stub
test/integration    Linux netns end-to-end test
```

Places where the spec was silent and a choice was made are marked `TODO(spec)` in the source
(`grep -rn "TODO(spec)"`).

## Not yet implemented

- Reachability mode C (rendezvous / hole punching). It's out of scope for v1, and there's an
  interface stub in `internal/reach`.
