<!-- Raw research fact sheet produced by a research agent on 2026-09-25 for docs/literature-review.md. Kept as source material; not edited. -->

# Managed Tunnel Services — Fact Sheet (verified as of 2026-09-25)

**Methodology note:** All facts below were gathered by 8 parallel research passes against official vendor docs, GitHub source/LICENSE files, and pricing/ToS pages (WebSearch + WebFetch), not from training memory. Where official WebSearch quotas were exhausted mid-research, agents fell back to direct WebFetch of primary sources (docs/GitHub/source code) rather than secondary blogs — in several cases this is noted as *stronger* sourcing (e.g., reading actual client source for port numbers). Fields that could not be verified are marked **unknown/not documented** rather than guessed. Several findings **correct the task brief's assumptions** — flagged inline where relevant (Cloudflare's port is confirmed as 7844 with no 443 fallback; tunnel.pyjam.as is WireGuard-based, not SSH; srv.us is not built on `sish`; Expose/beyondcode is *not* dormant; Pangolin *does* have an official hosted offering; serveo.net's suspected instability is confirmed).

---

## 1. Cloudflare Tunnel (cloudflared) & TryCloudflare Quick Tunnels

Same `cloudflared` binary; TryCloudflare (`cloudflared tunnel --url`) is the account-less, ephemeral mode.

- **Exposes:** Named Tunnel: HTTP(S) public hostname + arbitrary TCP (SSH/RDP via `cloudflared access`); with WARP Routing, also UDP and ICMP — a de facto VPN-replacement architecture ([README](https://github.com/cloudflare/cloudflared/blob/master/README.md), [CHANGES.md](https://github.com/cloudflare/cloudflared/blob/master/CHANGES.md)). Quick Tunnel: **HTTP(S) only**, single origin, no TCP/UDP routing ([TryCloudflare docs](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/)).
- **Client:** Go, **Apache-2.0** ([LICENSE](https://github.com/cloudflare/cloudflared/blob/master/LICENSE)), open source: [github.com/cloudflare/cloudflared](https://github.com/cloudflare/cloudflared).
- **Server/control plane:** Closed source, **not self-hostable** — client is hardcoded to Cloudflare-owned SNI hosts (`h2.cftunnel.com`, `quic.cftunnel.com`), no independent-relay option ([protocol.go](https://github.com/cloudflare/cloudflared/blob/master/connection/protocol.go)).
- **Transport & port:** **Confirmed exactly: port 7844**, either QUIC/HTTP3 (UDP) or HTTP/2-over-TLS (TCP), default mode `auto` (tries QUIC, falls back to HTTP/2 — both still on 7844) ([docs](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-with-firewall/), corroborated in source: [prechecks/probes.go](https://github.com/cloudflare/cloudflared/blob/master/prechecks/probes.go)). **No fallback to port 443** for the tunnel data connection — 443 is used only for auxiliary functions (update checks, Access token validation).
- **UDP-blocked fallback:** Falls back from QUIC to **HTTP/2 over TCP, same port 7844** (not 443). If UDP payload-proxying (WARP Routing) was in use, that sub-feature stops (“UDP proxying only works for quic” — [CHANGES.md](https://github.com/cloudflare/cloudflared/blob/master/CHANGES.md)), but the core tunnel keeps working over TCP/7844. If *both* TCP and UDP to 7844 are blocked, it fails entirely — no other port exists to fall back to.
- **Outbound HTTP CONNECT proxy:** **No**, verified directly in source (`net.Dialer{}` with no proxy awareness for the edge leg; QUIC dialer opens a raw UDP socket) ([dial.go](https://github.com/cloudflare/cloudflared/blob/master/edgediscovery/dial.go), [quic.go](https://github.com/cloudflare/cloudflared/blob/master/connection/quic.go)). An unmerged PR proposing `HTTP_PROXY` support exists but has not shipped ([PR #1514](https://github.com/cloudflare/cloudflared/pull/1514)) — any claim that this already works is incorrect. PAC/NTLM/Kerberos: no.
- **TLS termination:** **Cloudflare's edge terminates TLS** — operator can read plaintext ([Keyless SSL + Tunnel docs](https://developers.cloudflare.com/ssl/keyless-ssl/configuration/cloudflare-tunnel/)).
- **Free tier:** Quick Tunnel: no signup, random `*.trycloudflare.com`, no custom domain, **200 in-flight-request cap** (HTTP 429 beyond), explicitly "testing and development only," no SLA ([docs](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/)). Named Tunnel: Cloudflare account required, custom domain is the norm; exact Zero Trust free-plan numeric caps **unverified** (pricing page is client-rendered, didn't yield hard numbers).
- **ToS/AUP gotcha:** Named tunnels fall under the Cloudflare Self-Serve Subscription Agreement, §2.2.1(j), which **explicitly bans "us[ing] the Services to provide a virtual private network or other similar proxy services"** ([terms](https://www.cloudflare.com/terms/)). Quick tunnels fall under the separate Online Services Terms of Use instead, with an explicit "no uptime guarantee" disclaimer printed at CLI startup ([source](https://github.com/cloudflare/cloudflared/blob/master/cmd/cloudflared/tunnel/quick_tunnel.go), [terms](https://www.cloudflare.com/website-terms/)).
- **Corporate networks:** Extensively documented — allow TCP+UDP 7844 to Cloudflare IP ranges or by FQDN (`cftunnel.com`, `h2.cftunnel.com`, `quic.cftunnel.com`); `--protocol http2` flag forces the TCP-only path; built-in `cloudflared tunnel diag` distinguishes "QUIC blocked" vs "HTTP2 blocked" vs "both blocked" ([connectivity-prechecks](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/troubleshoot-tunnels/connectivity-prechecks/)).
- **Status:** **Active.** Latest release **2026.9.3** (2026-09-24), multiple releases/month ([releases](https://github.com/cloudflare/cloudflared/releases)).

---

## 2. ngrok (agent + service)

- **Exposes:** HTTP(S) reverse-proxy, raw TCP (any protocol), TLS/SNI endpoints. No UDP endpoint type exists ([protocols](https://ngrok.com/docs/gateway/endpoints/protocols)). Not a VPN product (its "Site-to-Site Connectivity" still just opens an outbound TLS:443 connection, no WireGuard/IPsec documented).
- **Client:** Go. **Closed source, proprietary, no SPDX** — ngrok's own FAQ: *"There are no open source versions of the ngrok Agent and the source code is not available"* ([FAQ](https://ngrok.com/docs/faq/)). (Historical v1, 2013–2016, was Apache-2.0 but is archived/dead — do not confuse with the current product.) ngrok's embeddable SDKs (ngrok-go, ngrok-rust, etc.) are separately open source (Apache-2.0/MIT).
- **Server/control plane:** **Closed, not self-hostable** — "a multi-tenant application with services shared across the customer base"; an undocumented "private edition" exists for enterprise contact-sales only ([docs](https://ngrok.com/docs/gateway/site-to-site-connectivity/faq)).
- **Transport & port:** **TLS, and 443 is the *only* documented port** — *"All connections to ngrok servers are made on port 443"* ([docs](https://ngrok.com/docs/agent)) to `connect.ngrok-agent.com:443`. This is not a "fallback," it's the sole transport, by design, for firewall-friendliness. A secondary plain HTTP (port 80) connection to a CRL endpoint is also used by default (skippable via `crl_noverify`).
- **UDP-blocked fallback:** N/A — never uses UDP for transport or for user endpoints.
- **Outbound HTTP CONNECT proxy:** **Yes for `http_proxy`** (lowercase, standard Unix var) and config-file `proxy_url` (HTTP or **SOCKS5**) ([docs](https://ngrok.com/docs/using-ngrok-with/outboundProxy), [agent config](https://ngrok.com/docs/agent/config/v3/)). Uppercase `HTTPS_PROXY` specifically: not documented under that name. PAC files: no. NTLM/Kerberos: no.
- **TLS termination:** **ngrok's cloud terminates TLS by default for `https` endpoints** — *"All HTTPS endpoints terminate TLS at ngrok's cloud service"* ([docs](https://ngrok.com/docs/universal-gateway/tls-termination)). True end-to-end ("zero-knowledge") is only possible via TCP/TLS endpoint types with TLS terminated at the agent/origin instead.
- **Free tier:** $0, **1 GB/month** bandwidth, **3 concurrent online endpoints**, ~20,000 HTTP requests/mo, ~5,000 TCP connections/mo, no session timeout (per current docs — a widely-repeated "2-hour cap" claim on third-party blogs could **not** be verified officially and contradicts current docs), no custom domains, **account required** (no anonymous use), **interstitial page shown on free tier** (bypassable via cookie/header), random subdomains only ([free-plan-limits](https://ngrok.com/docs/pricing-limits/free-plan-limits)).
- **ToS/AUP gotcha:** Full-text search of the [ToS](https://ngrok.com/tos) found **zero mentions** of VPN, proxying, torrenting, or P2P — no explicit ban on personal remote-access use, unlike Cloudflare.
- **Corporate networks:** Dedicated official page, **explicitly acknowledges "ngrok may be blocked on Fortinet firewalls,"** documents exact allowlist entries and a `connect_url` override + `ngrok diagnose` CLI tool ([docs](https://ngrok.com/docs/gateway/running-behind-firewalls)).
- **Status:** **Active.** Latest agent **v3.39.11** (2026-08-12) ([changelog](https://ngrok.com/docs/agent/changelog)).

---

## 3. Microsoft Dev Tunnels (`devtunnel`) & VS Code Remote Tunnels (`code tunnel`)

**Confirmed: same underlying relay.** VS Code tunnels connect to the identical `*.rel.tunnels.api.visualstudio.com` domain family as the `devtunnel` CLI, and Microsoft's own Group Policy docs list both under one shared ADMX policy set ([policies](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/policies)).

**Dev Tunnels (devtunnel CLI):**
- **Exposes:** HTTP(S) web-forwarding (auto-upgraded to HTTPS/WSS) plus raw **TCP and UDP** port forwarding (`TunnelProtocol` enum: `tcp, udp, rdp, http, https`) ([source](https://github.com/microsoft/dev-tunnels/blob/main/cs/src/Contracts/TunnelProtocol.cs)).
- **Client:** Implementation language of the closed `devtunnel` binary **not documented**. **Not open source** — maintainers explicitly declined ([issue #258](https://github.com/microsoft/dev-tunnels/issues/258)). Separate MIT-licensed SDKs exist but contain no CLI/server code.
- **Server:** Closed, Microsoft-operated only, **not self-hostable**; EULA scopes use to Microsoft products.
- **How a port becomes an https:// URL:** *"TLS termination is done at service ingress using service certificates, issued by a Microsoft CA. After TLS termination, header rewriting takes place"* — i.e. **Microsoft's edge is a TLS-terminating reverse proxy** ([security docs](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/security)).
- **Transport & port:** **WSS (WebSocket-over-TLS)**, real CLI output shows `wss://usw2-data.rel.tunnels.api.visualstudio.com/...` — defaults to port 443; no numeric port stated but no alternate transport exists either ([get-started](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/get-started)).
- **UDP-blocked fallback:** Not documented; moot since client↔relay is always TCP/WSS.
- **Proxy support:** HTTP_PROXY/HTTPS_PROXY — appears proxy-aware per an open GitHub issue (user reports it still uses system proxy even after clearing the env vars) but no official doc confirms the mechanism ([issue #536](https://github.com/microsoft/dev-tunnels/issues/536)). PAC/NTLM: not documented.
- **Free tier:** Signup required (no anonymous *hosting*; anonymous *visiting* possible via `--allow-anonymous`); **interstitial anti-phishing page** on first visit; tunnels auto-expire after **30 days inactivity** (configurable 1h–30d); no custom domains; no published bandwidth cap.
- **ToS gotcha:** EULA scopes use to "develop and test your applications... with Microsoft Visual Studio," bans standalone/third-party redistribution; liability capped at **US $5**.
- **Corporate networks:** Explicit outbound-domain allowlist (no inbound needed); downloadable **Group Policy ADMX templates** to fully disable Dev Tunnels org-wide ([policies](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/policies)).
- **Status:** Active but still labeled **"public preview," "not recommended for production"** as of docs last updated Feb–Apr 2026 ([overview](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview)).

**VS Code Remote Tunnels (code tunnel):**
- **Exposes:** Full remote-dev-machine session (terminal/extensions/commands), not just one port; a separate Port Forwarding feature can also expose individual ports as URLs.
- **Client:** **Rust** (confirmed via `reqwest` crate debug output in an official bug thread — [issue #169333](https://github.com/microsoft/vscode/issues/169333)). Source **MIT** ([LICENSE](https://github.com/microsoft/vscode/blob/main/LICENSE.txt)), but the prebuilt official binary is governed by a separate proprietary-style **"VS Code Server License Terms"** ([license](https://code.visualstudio.com/license/server)) — open source code, closed-license official binary.
- **Server:** Same Microsoft relay as Dev Tunnels — closed, not self-hostable.
- **Transport & port:** TLS WebSocket, confirmed **port 443** (`ss -tp` output in official thread shows connection to `<relay-ip>:https`).
- **Proxy support:** **Yes, confirmed** — `HTTPS_PROXY`/`HTTP_PROXY` honored since ~VS Code 1.77 (March 2023), but the **proxy must support WebSocket upgrades** (plain Squid fails; WS-capable proxies like mitmproxy work) ([issue #169333](https://github.com/microsoft/vscode/issues/169333)). PAC/NTLM: documented for the desktop Electron app generally, **not confirmed** for the standalone `code tunnel` CLI specifically.
- **TLS termination:** **End-to-end for the core session** — *"an SSH connection is created over the tunnel in order to provide end-to-end encryption"* (AES-256-CTR) ([docs](https://code.visualstudio.com/docs/remote/tunnels)); Microsoft's relay only forwards opaque SSH bytes here. (The separate web-forwarding-URL feature above still has Microsoft terminating TLS.)
- **Free tier:** GitHub/Microsoft account **mandatory**, no anonymous mode; **capped at 10 concurrent tunnels per account** (oldest unused one auto-deleted past the cap); no numeric bandwidth cap published; fixed URL format `vscode.dev/tunnel/<machine>/<folder>`, no custom domains.
- **Status:** Active, **GA** (not "preview"), built into VS Code core. Latest VS Code **1.139.1** (2026-09-23/25).

---

## 4. Tailscale Funnel, Tailscale Serve, and DERP

- **Exposes:** **Serve** = HTTP(S)/TCP/TLS-terminated-TCP forwarding to **other devices on your own tailnet only** — not public. **Funnel** = the same three modes exposed to the **public internet**, restricted to exactly **ports 443, 8443, 10000**; "UDP and direct HTTP are not supported; only TLS-encrypted connections work" ([Funnel docs](https://tailscale.com/kb/1223/funnel)). **DERP** is the packet-relay substrate underneath, not a share feature itself.
- **Client:** Go, **BSD-3-Clause**, open source: [github.com/tailscale/tailscale](https://github.com/tailscale/tailscale) (includes DERP client/server code).
- **Server/control plane:** Coordination/control plane (`login.tailscale.com`) is **closed, not self-hostable** by Tailscale. **DERP relay servers are open source and officially self-hostable** (same repo, `cmd/derper`), though Tailscale calls self-hosting DERP "an advanced operation" with feature gaps ([kb/1232](https://tailscale.com/kb/1232/derp-servers)). Funnel's public-edge relay servers are closed/vendor-run. ("Headscale" is a **third-party, unofficial** open-source control-plane reimplementation — explicitly not Tailscale software.)
- **Transport & ports (all confirmed, no guesses):** Control-plane: TCP **:80**, falling back to HTTPS/TLS **:443**. DERP relay data: HTTPS/TLS **:443** (its only documented port). Direct WireGuard P2P: UDP, default source port **:41641**. STUN: UDP **:3478**. Source: *"Connections to the coordination server... and data connections to the DERP relays use HTTPS on port 443... Direct WireGuard tunnels use UDP with a source port that defaults to 41641"* ([firewall-ports FAQ](https://tailscale.com/docs/reference/faq/firewall-ports)).
- **UDP-blocked fallback:** **Explicitly documented and clean** — if UDP (41641/3478) is blocked, Tailscale automatically relays still-WireGuard-encrypted traffic through a DERP server over **TCP/TLS port 443** rather than failing ([connection-types docs](https://tailscale.com/docs/reference/connection-types)).
- **Outbound HTTP CONNECT proxy:** Not officially documented as supported; a community GitHub issue reports `tailscaled` **not honoring** `HTTP_PROXY`/`HTTPS_PROXY` for control-plane connections ([issue #10235](https://github.com/tailscale/tailscale/issues/10235)) — treat as **partial/unreliable**, not "yes." PAC/NTLM: unknown, undocumented. (Tailscale's own `--outbound-http-proxy-listen` flag is the *opposite* direction — tailscaled acting as a proxy for local apps — not relevant here.)
- **TLS termination:** **End-to-end — Tailscale cannot read plaintext.** *"Funnel relay servers do not decrypt the traffic between public devices and your device"* ([Funnel docs](https://tailscale.com/docs/features/tailscale-funnel)); the TLS cert/key lives on the user's own device.
- **Free tier:** Account **required**; Funnel/Serve both available free; Funnel bandwidth subject to **"non-configurable bandwidth limits," no published number**; no documented forced session timeout (tailnet key-expiry default 180 days is separate/general); **no custom domains** (`*.ts.net` only); no interstitial page found documented; hostnames are stable/predictable, not randomized per session.
- **ToS/AUP gotcha:** Generic AUP bans illegal activity/malware/IP infringement/"undue burden on the Tailscale Solution" — **no explicit ban found** on personal VPN-style use, unlike Cloudflare.
- **Corporate networks:** Dedicated FAQ with concrete firewall rules (outbound UDP :41641, UDP :3478 to DERP only, TCP :443) and a recommendation to **allowlist by domain, not IP**, "since the set of DERP servers expands over time" ([FAQ](https://tailscale.com/docs/reference/faq/firewall-ports)).
- **Status:** **Active.** Latest `tailscale/tailscale` **v1.102.4** (2026-09-10), changelog activity through 2026-09-24.

---

## 5. localhost.run

- **Exposes:** HTTP(S) share (default) + a "TLS passthru" mode for TLS-wrapped non-HTTP protocols on 443. No raw arbitrary TCP or UDP mode.
- **Client:** **Stock OpenSSH** (`ssh -R`) — not vendor software. OpenSSH: C, mixed BSD-2/3/ISC/public-domain (no single SPDX, no GPL), open source.
- **Server:** **Closed source**, run commercially by Disseminate Consulting Ltd. **Not self-hostable.**
- **Transport & port:** SSH/TCP, implied **default port 22** (no `-p` flag in any documented example). **No documented 443 fallback for the SSH control connection itself** (443 in their docs refers only to the inbound TLS-passthru feature).
- **UDP-blocked fallback:** N/A — TCP/SSH only.
- **Outbound proxy:** No native `HTTP_PROXY`/PAC/NTLM support (stock OpenSSH); manual `ProxyCommand` workaround possible, not vendor-documented.
- **TLS termination:** Default mode: **localhost.run's edge terminates TLS**, operator can read plaintext — *"takes care of certificates and decryption for you"* ([security docs](https://localhost.run/docs/security/)). Opt-in TLS-passthru mode: genuinely end-to-end.
- **Free tier:** No signup for short-lived tunnels; **random subdomain that rotates every few hours** (stable name requires signing up with an SSH key); "a speed limit" exists, no published number; no documented session timeout (idle keepalive recommended); **no custom domain free** ($9/mo paid).
- **ToS/AUP:** **No dedicated ToS/AUP page found.** Only informal signal: domains rotate "to prevent phishing sites from establishing themselves."
- **Corporate networks:** **Not documented** — no port-22-blocked guidance, no 443-SSH workaround (unlike serveo.net below).
- **Status:** **Active**, commercial SaaS, live and current as of 2026-09-25.

---

## 6. serveo.net

- **Exposes (per mirrored docs — see status caveat):** HTTP(S) share, raw public TCP forwarding (arbitrary/random port), and "lightweight VPN-like" private SSH-forwarding access.
- **Client:** Stock OpenSSH (same facts as localhost.run). Unofficial third-party convenience wrappers exist but are unaffiliated.
- **Server:** **Closed, never published**; `github.com/serveo` is an unrelated account. **Not self-hostable** as serveo.net (the similarly-conceived open-source `sish` project is unrelated).
- **Transport & port:** SSH/TCP, **ports 22 AND 443** — an **explicit, documented fallback**: `ssh -p 443 -R 80:localhost:8888 serveo.net`, specifically "for environments blocking outbound port 22."
- **UDP-blocked fallback:** N/A — TCP/SSH only.
- **Outbound proxy:** Same generic OpenSSH-only behavior as localhost.run; no serveo-specific documentation.
- **TLS termination:** Edge terminates TLS for default HTTP(S) mode, analogous to localhost.run (lower-confidence sourcing — see status note).
- **Free tier:** No signup at all; **user-choosable subdomains**; **custom domains supported for free** via DNS CNAME + TXT-record key-fingerprint auth (notably more generous than localhost.run here); bandwidth/session limits not documented.
- **ToS/AUP:** **None found** — official site was unreachable during this research (see below), no cached ToS content located.
- **Corporate networks:** The explicit `-p 443` fallback is the one officially-documented item.
- **Status: contested/degraded — could not confirm cleanly alive.** Live checks on 2026-09-25 found `http://serveo.net/` 307-redirecting through what a middlebox labeled a "landpage" on an unrelated IP, and `https://serveo.net/` **failing the TLS handshake outright** ("wrong version number") — a pattern typical of a parked/hijacked domain, while control domains (github.com, localhost.run, etc.) on the same network path responded normally. The **Serveo Help Google Group** shows a troubled but not-dead user base: "Serveo is down" (Aug 16, 2026), a brief restoration report (Aug 27, 2026), continued connection problems reported as recently as **Sep 8, 2026**, with no clean "confirmed working" report after that date. This is a well-documented, years-long (2019–2026) pattern of intermittent outages. **Treat as unstable/possibly down, not cleanly active or dead** — this substantially confirms the task brief's suspicion.

---

## 7. Pinggy

- **Exposes:** HTTP(S) (default), raw TCP, TLS-passthrough, and **UDP tunnels (beta, CLI-only)** — [docs](https://pinggy.io/docs/udp_tunnels/).
- **Client:** Two paths — (1) stock OpenSSH (no Pinggy code), or (2) a dedicated CLI, **TypeScript/Node.js, Apache-2.0**, open source: [github.com/Pinggy-io/cli-js](https://github.com/Pinggy-io/cli-js) (v0.6.0, 2026-09-25). Pinggy also publishes open-source SDKs (Go/MIT, Python/Apache-2.0, C++/Apache-2.0).
- **Server:** **Closed** — no server repo published anywhere; **not self-hostable** (Enterprise offers vendor-run "on-premise" deployment, not public self-hosting).
- **Transport & port:** SSH or WebSocket+HTTPS, **port 443 explicitly, by design**: *"Pinggy servers listen on 443 to overcome firewall restrictions in some networks"* ([docs](https://pinggy.io/docs/usages/)).
- **UDP-blocked fallback:** N/A for the control/transport channel (always TCP-based). For the UDP-tunnel *feature* itself, docs are silent on visitor-side UDP blocking.
- **Outbound proxy:** **Partial/manual** — SSH mode supports proxying via SSH's own `ProxyCommand` (documented recipes for HTTP proxies and SSL-inspecting firewalls) — [dedicated page](https://pinggy.io/docs/client_behind_proxy/). No automatic env-var detection, no PAC, no NTLM/Kerberos.
- **TLS termination:** Explicit passthrough (**no** operator access) for `tls`/`tlstcp` modes — *"Pinggy does not terminate the SSL/TLS, instead it forward[s] as it is"* ([docs](https://pinggy.io/docs/tls_tunnels/)). Default `http` mode: likely terminated at Pinggy's edge (inferred from live request-inspection features), not explicitly stated.
- **Free tier:** **Unlimited bandwidth**; **no signup required** ("no signup, no config"); **60-minute tunnel timeout** then reconnect; random subdomain that changes every reconnect; visitors see a one-time **"Browser Screening" interstitial** (bypassable via header/User-Agent, auto-skipped for curl/webhooks).
- **ToS/AUP:** Bans resale/transfer, "competing" uses, malware/phishing/adult content — **no explicit VPN/proxy/torrent ban found**.
- **Corporate networks:** Explicitly documented — dedicated "Client Behind Proxy" page with concrete `ProxyCommand` recipes, plus the port-443-by-design rationale.
- **Status:** **Active.** `cli-js` v0.6.0 released 2026-09-25 (day of research).

---

## 8. Expose (beyondcode / now exposedev)

- **Exposes:** HTTP(S) site sharing + raw TCP port sharing (random public port). **No UDP.** Custom PHP protocol, not SSH-based, not a VPN.
- **Client:** **PHP**, PHAR/Composer/Docker distribution, **MIT**, open source: [github.com/exposedev/expose](https://github.com/exposedev/expose) (org renamed from `beyondcode`).
- **Server:** **Open source (MIT), genuinely self-hostable independent of the vendor** — one of the few services here where this is true. The vendor also runs a managed instance (expose.dev, backed by default host `sharedwithexpose.com`).
- **Transport & port:** Custom TCP protocol, **port 443 by default** — the shipped config literally comments: *"If you want to bypass firewalls and have proper SSL encrypted tunnels, make sure to use port 443... The free default server is already running on port 443"* ([config docs](https://github.com/exposedev/expose/blob/master/docs/client/configuration.md)).
- **UDP-blocked fallback:** N/A — TCP-only protocol throughout.
- **Outbound proxy:** **No** — no `HTTP_PROXY`/PAC/NTLM mentioned anywhere in the full client config docs.
- **TLS termination:** For **self-hosted** servers, the Expose process itself speaks plain non-TLS TCP; a fronting reverse proxy (nginx/Caddy/etc.) must terminate TLS — meaning **whoever runs that fronting proxy can read plaintext**, including on the vendor's own hosted instance (same documented architecture, inferred to apply there too).
- **Free tier ("Hobby," $0):** TLS included, **signup required even for free tier** (*"You will need a free Beyond Code account"*), random URLs only (persistent/custom needs Pro), single EU server, session time limit exists but **exact duration not published**.
- **ToS/AUP:** Only a broad unlawful-content clause found — **no explicit VPN/proxy/torrent restriction**.
- **Corporate networks:** The port-443-by-default config comment is the one documented item.
- **Status: Active** — **contradicts** the "historically low activity" premise in the task brief. Latest release **3.2.4** (2026-09-17), steady 2026 release cadence throughout the year.

---

## 9. playit.gg

- **Exposes:** **Raw TCP and UDP are the core product** (game-server presets: Minecraft, Terraria, Valheim, etc., plus arbitrary custom TCP/UDP). A separate HTTPS tunnel mode is TLS-*passthrough*, Premium-only, not a terminated reverse proxy.
- **Client:** Rust, **BSD-2-Clause**, open source: [github.com/playit-cloud/playit-agent](https://github.com/playit-cloud/playit-agent).
- **Server:** **Closed, not self-hostable** — the playit-cloud org's public repos are client-side tools only, no relay code published.
- **Transport & port:** Two channels: HTTPS to `api.playit.gg` (**:443**) for auth/config, plus a **persistent custom binary control protocol over UDP** to a dynamically-issued control-server address (community-observed as `control.ply.gg:5530`, **not officially documented**). **No documented 443 fallback** for the UDP control channel, including on their own dedicated troubleshooting page.
- **UDP-blocked fallback:** **Not documented** — architecturally, since the control channel is UDP, a UDP-blocking network likely breaks the agent, but this isn't officially confirmed.
- **Outbound proxy:** **Not documented**, and structurally unlikely since HTTP CONNECT proxies only tunnel TCP while the control channel is UDP.
- **TLS termination:** *"Playit does not terminate SSL, so you need to install a program to do that for you"* ([docs](https://playit.gg/support/https-tunnel/)) — default TCP/UDP tunnels carry **no TLS at all** unless the user adds it themselves.
- **Free tier:** Auto-generated "guest account" (low friction, not fully anonymous); **4 concurrent ports** (vs. 16 Premium); no custom domain free; bandwidth/session limits not officially stated.
- **ToS/AUP gotcha — notable contrast with Cloudflare:** playit's prohibited-uses page **explicitly allows** "VPN server to access your network" for personal device management, while banning C2/beaconing patterns and remote control of machines you don't own, plus commercial resale/white-labeling ([terms](https://playit.gg/terms/), [prohibited-uses](https://playit.gg/support/prohibited-uses/)).
- **Corporate networks: not documented** — only troubleshooting page covers ping/DNS, no port/protocol guidance ([is-playit-blocked](https://playit.gg/support/is-playit-blocked/)).
- **Status:** **Active.** Latest stable v1.0.10 (2026-06-08), preview v1.0.11-preview1 (2026-08-19).

---

## 10. localtunnel hosted service (loca.lt)

- **Exposes:** **HTTP(S) only** — confirmed from source, the whole protocol is HTTP-request based. No TCP/UDP/SSH/VPN.
- **Client:** JavaScript/Node.js, **MIT**, open source: [github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel).
- **Server:** **Open source (MIT) and self-hostable** — [github.com/localtunnel/localtunnel-server](https://github.com/localtunnel/localtunnel-server) (needs its own fronting reverse proxy for TLS).
- **Transport & port:** Two-step, confirmed from source: HTTPS handshake to `localtunnel.me` (**:443**) returns a JSON-assigned `ip:port`, then the client opens a **plain, unencrypted raw TCP socket directly to that arbitrary high port** (server accepts any non-root port >1000) ([source](https://raw.githubusercontent.com/localtunnel/localtunnel/master/lib/TunnelCluster.js)). **No fallback-to-443 for the data connection** — it's never 443.
- **UDP-blocked fallback:** N/A, never uses UDP.
- **Outbound proxy:** **Partial/no** — the handshake (via `axios`) may respect `HTTP_PROXY`/`HTTPS_PROXY` by default, but the actual **data-plane `net.connect()` has zero proxy support**, so the tunnel itself won't traverse an HTTP-CONNECT-only proxy.
- **TLS termination:** **Vendor terminates TLS, and the data plane is unencrypted raw TCP besides** — the least private option in this whole list among still-encrypted-in-part services.
- **Free tier:** **No signup at all**; random subdomain or first-come `--subdomain` request (not reserved); no documented bandwidth/session caps; **interstitial "tunnel consent" page** that, since 2023, requires visitors to type the tunnel's public IP as a "password" (anti-phishing measure) — a programmatic-bypass request from Jan 2026 remains open ([issue #727](https://github.com/localtunnel/localtunnel/issues/727)).
- **ToS/AUP:** **None found** anywhere.
- **Corporate networks: not documented anywhere.**
- **Status: nominally active but strained.** Latest npm release **v2.0.2 is from Sept 18, 2021** (5+ years stale); latest GitHub commit Aug 2025; an unanswered **"Is LocalTunnel Down??" issue from Sep 17, 2026** (8 days before this research) plus recurring 2024/2025 outage reports — treat as **lightly-maintained/unreliable**, not formally dead.

---

## 11. tunnel.pyjam.as

**Correction to task brief: this is NOT SSH-based — it uses WireGuard.** Verified directly against the live server and source.

- **Exposes:** **HTTP(S) share only** — an ephemeral Caddy reverse proxy to one local HTTP port, even though the underlying transport mechanism is WireGuard.
- **Client:** Standard WireGuard tooling (`wg-quick`), not vendor code; wireguard-tools is C, **GPLv2**, open source.
- **Server:** **Open source (GPL-3.0-or-later)** by Carl Bordum Hansen, **genuinely self-hostable** (documented systemd unit, Python/Poetry/Caddy requirements) — [GitLab source](https://gitlab.com/pyjam.as/tunnel).
- **Transport & port:** WireGuard, **UDP only** — **live-verified this session: port 55555** (`curl https://tunnel.pyjam.as/8080` returned `Endpoint = tunnel.pyjam.as:55555`), which differs from the published source's compiled-in default of 54321 — the live production deployment overrides it via env var; 55555 is authoritative. Config-fetch itself is over HTTPS **:443** (Caddy).
- **UDP-blocked fallback: fails entirely, no fallback exists or is documented** — WireGuard has no TCP mode, and this service offers no alternate transport.
- **Outbound proxy:** The config-fetch `curl` step can go through a proxy (standard curl behavior); the **WireGuard data plane itself cannot be proxied at all** via HTTP CONNECT.
- **TLS termination:** **Caddy (vendor edge) terminates TLS**, then relays **plain HTTP** to the user's backend over the WireGuard tunnel — operator can read plaintext.
- **Free tier:** Entirely free, **no signup** (a bare `curl` immediately returns a working config); random subdomain slug per tunnel; **no published bandwidth/session/concurrency limits** (small hobby project).
- **ToS/AUP: none found at all** — individual hobby project (response header literally reads "Asbjørn's garage").
- **Corporate networks: not documented at all** — and since it's UDP/WireGuard-only, it is inherently poorly suited to UDP-blocking corporate networks, though the vendor never addresses this.
- **Status: Active**, live-verified 2026-09-25 (fresh Let's Encrypt cert, working config issuance), but **underlying source code unchanged since May 2022** — a small, stable, unattended hobby project rather than one under active development.

---

## 12. pico.sh "tuns"

- **Exposes:** HTTP(S), raw TCP, and WSS tunnels, **plus genuine IP/Ethernet-layer SSH tun/tap VPN modes** ("point-to-point" and "ethernet," both requiring local root) — [docs](https://pico.sh/tuns).
- **Client:** Stock OpenSSH, zero install, no vendor client.
- **Server:** **Open source (MIT, Go), self-hostable** — part of the [picosh/pico](https://github.com/picosh/pico) monorepo with a documented `SELFHOST.md`. Originally built on the separately-maintained open-source **`sish`** project ([announcement](https://blog.pico.sh/ann-006-tuns)).
- **Transport & port:** SSH/TCP, **port 22 inferred** from current docs (no `-p` flag in any example) — note the original 2022 launch announcement stated **port 2222** at that time, suggesting this changed. **No 443 fallback documented.**
- **UDP-blocked fallback: not documented** — no stated behavior for the tun/tap modes if UDP is blocked.
- **Outbound proxy:** Not documented by pico.sh; as stock OpenSSH, only generic `ProxyCommand`/`ProxyJump` would apply, unendorsed.
- **TLS termination:** Standard HTTP(S)/WSS tunnels get **"Automatic HTTPS"** — vendor terminates, operator can read plaintext. The underlying `sish` engine separately supports a **true end-to-end TLS/SNI-passthrough "TCP alias" mode**.
- **Free tier: none for tuns specifically** — it's a **paid pico+ service, $2/month billed yearly** ([pico.sh/plus](https://pico.sh/plus)); pico.sh's free "starter" tier covers other services only. Account is SSH-key-based, no password. Platform-wide "no bandwidth limitations" claimed (per FAQ, ~1.5TB/mo against a self-imposed 10TB threshold). Custom domains supported via CNAME+TXT; subdomains are user-chosen and account-namespaced.
- **ToS/AUP:** Bans copyright infringement, illegal/explicit content, harassment, spam — **does not address VPN use, proxying, or torrenting at all**, a notable silence given the tun/tap VPN primitive exists.
- **Corporate networks: not documented.**
- **Status:** **Active** — monorepo commits as recently as 2026-09-15 (10 days before this research); the underlying `sish` engine last updated 2026-06-25.

---

## 13. srv.us

**Correction to task brief: confirmed NOT built on `sish`** — an independent, purpose-built Go server by the "xmit dev team," unrelated to the antoniomika/sish project.

- **Exposes:** Primarily HTTP(S) via stable URLs; other TCP protocols also ride the same SSH remote-forward mechanism, exposed as a TLS-wrapped TCP endpoint a visitor unwraps with `stunnel`. No UDP.
- **Client:** Stock OpenSSH only — **no dedicated client software exists.**
- **Server:** **Open source, Go, ISC license** ([LICENSE](https://github.com/xmit-co/srv.us/blob/main/LICENSE)), **self-hostable** (systemd service + Let's Encrypt + Cloudflare DNS).
- **Transport & port:** Plain SSH/TCP, **default port 22** (no `-p` flag in any documented example). **No documented 443 fallback** for the SSH control leg (the one ":443" reference in their docs is for a visitor-side `stunnel` config, unrelated).
- **UDP-blocked fallback:** N/A, SSH/TCP only.
- **Outbound proxy: not documented** at all; generic OpenSSH `ProxyCommand` would technically work but is never mentioned by srv.us.
- **TLS termination:** **srv.us's own edge terminates TLS** (Let's Encrypt certs on their systemd service) — operator can read plaintext HTTP relayed over the SSH tunnel.
- **Free tier:** **Entire service is free, no accounts at all** — *"Stable URLs derived from your SSH key. No accounts."* URLs are deterministic per SSH key (optionally prettified via linked GitHub/GitLab username). No published bandwidth/concurrency cap; informal soft-throttling possible if "sponsorships don't cover operating costs." Session lasts exactly as long as the SSH connection (no fixed timeout).
- **ToS/AUP: no dedicated ToS/AUP page found anywhere.** Only privacy note: *"We do not record any of your traffic"* but logs IPs/ports/usernames/keys/byte-counts for up to 1 day.
- **Corporate networks: not documented.**
- **Status:** **Active.** Most recent commit 2026-07-10; no numbered releases published.

---

## 14. zrok hosted (zrok.io) and Pangolin's hosted offering

**zrok (zrok.io, by NetFoundry, built on OpenZiti):**
- **Exposes:** HTTP(S), raw TCP, UDP, and file/directory sharing; public and private peer-to-peer shares. No general "join this network" VPN mode.
- **Client:** Go, **Apache-2.0**, open source: [github.com/openziti/zrok](https://github.com/openziti/zrok).
- **Server:** **Open source (Apache-2.0), explicitly self-hostable** — "designed to scale down to support extremely small deployments," same codebase as zrok.io.
- **Transport & port:** OpenZiti's TLS-based edge protocol. OpenZiti's own docs document **port 443 with ALPN multiplexing** specifically because "from some customer networks other ports are blocked" — but this is general OpenZiti guidance; **zrok.io's exact production port could not be independently confirmed** this session (docs site rendered mostly empty via fetch) — treat as **likely 443 but not confirmed**.
- **UDP-blocked fallback:** No explicit fallback language; architecturally the client-relay transport is TLS/TCP-based by design, so UDP blocking shouldn't affect tunnel establishment (inference, not a doc statement).
- **Outbound proxy: not documented.**
- **TLS termination — nuanced:** zrok's README states *"All traffic is encrypted, even from zrok servers"* (the OpenZiti mTLS fabric is unreadable by routers in between), **but** the vendor-operated "frontend" component is itself an endpoint, and it must inject the anti-phishing interstitial into HTTP responses for unverified free accounts — meaning **NetFoundry's frontend does see plaintext for public zrok.io HTTP(S) shares**, even though the transport fabric is protected from third parties.
- **Free tier:** **5 GB/day bandwidth** (rolling 24h window; shares disabled if exceeded), up to 25 environments / 50 share backends / 50 private frontends, **no credit card required**, account required (myzrok.io), **anti-phishing interstitial for unverified accounts, removable by adding a (still free) verified card**, no custom domains.
- **ToS/AUP:** NetFoundry's Self-Service Agreement bans resale/transfer, unauthorized access, unlawful content, competitive benchmarking — **no explicit VPN/personal-use ban found**.
- **Corporate networks:** OpenZiti-level docs document the port-443-with-ALPN pattern for blocked-port networks, though not phrased as zrok-specific guidance.
- **Status:** **Active.** Latest release **v2.0.4** (2026-05-18).

**Pangolin (fosrl/pangolin, by Fossorial) — hosted offering question:**
- **Answer: yes, an official hosted SaaS exists** — **"Pangolin Cloud"** at app.pangolin.net, run by Fossorial Inc., offered alongside (not instead of) self-hosted Community/Enterprise editions ([pricing](https://pangolin.net/pricing)).
- **Exposes:** Full WireGuard-based VPN (site-to-site/remote access), HTTP(S) reverse-proxy shares, raw TCP, in-browser SSH/RDP/VNC.
- **Client (Newt):** Go, **AGPL-3.0** (dual-licensed with a proprietary Fossorial Commercial License), open source: [github.com/fosrl/newt](https://github.com/fosrl/newt).
- **Server:** Community Edition **open source (AGPL-3.0), self-hostable** (primary deployment path — Docker/K8s/Helm guides); Enterprise Edition is open-core with closed add-ons.
- **Transport & port:** Newt↔Gerbil over WireGuard, default **UDP 51820** (direct); relay fallback through Gerbil on **UDP 21820** when hole-punching fails; web dashboard/public HTTP(S) resources use TCP 80/443. **No documented TCP/443 fallback for the tunnel data path itself** — both the direct and relay paths are UDP.
- **UDP-blocked fallback:** A relay fallback exists for restrictive NAT (Gerbil, UDP 21820), but **that fallback is itself UDP** — if outbound UDP is fully blocked, there is no documented path through.
- **Outbound proxy: not documented.**
- **TLS termination:** The Pangolin node explicitly *"terminates TLS, routes HTTP(S)... and forwards authenticated requests into the tunnel fabric"* — the node operator (self-hoster, or Fossorial on Pangolin Cloud) can read plaintext at ingress.
- **Free tier ("Basic" on Pangolin Cloud):** Up to 5 users / 5 "Sites," **custom domains included even free**, all resource types, 3-day log retention, no credit card required; **restricted to non-commercial use only**; bandwidth/session limits not published.
- **ToS/AUP gotcha:** Free tier is non-commercial only; prohibits disguising location via IP proxying and automated data extraction; general internet proxying/VPN-for-everything is not the intended use case (scoped to "securely access and share internal... applications"), though personal remote access to one's own services is explicitly supported.
- **Corporate networks:** Officially documented that hole-punching can fail behind restrictive/symmetric NAT or UDP-blocking firewalls, with automatic (but still-UDP) relay fallback.
- **Status:** **Active.** Latest self-hosted release **v1.23.0** (2026-09-16, 9 days before this research).

---

## 15. Telebit, Loophole, Packetriot (brief, per task instructions)

**Telebit (telebit.cloud):** **Likely dead/abandoned.** Direct fetch of telebit.cloud failed with a TLS handshake error; the npm `telebit` package's last publish is roughly 3 years stale with no releases in the past 12 months. Historically: JS/Node client, self-hostable relay ("telebit-relay.js"), marketed as a "poor man's VPN." All other fields **unknown**, not re-verified given the brief-research instruction for dead services.

**Loophole (loophole.cloud):** **Appears to still be operating** (no incidents on either loopholelabs.statuspage.io or status.loophole.com) but **recent 2026 development activity was not confirmed**. Exposes **HTTP/HTTPS only** — their own FAQ: *"Currently, Loophole supports http/https only"* (TCP described as "a few releases away," date of that claim unpinned). Client: Go, **MIT**, open source at [github.com/loophole/cli](https://github.com/loophole/cli). Server: **closed/SaaS-only today** — their FAQ frames self-hosting as a future goal, implying it's not currently possible. Free tier: FAQ states *"We do not enforce any limitations on concurrent connections, number of requests or bandwidth"*; custom subdomains supported; custom-domain redirect "not currently possible." Transport ports, proxy support, TLS termination, ToS, corporate-network docs: **unknown**, not verified within the brief-research budget.

**Packetriot (packetriot.com):** **Active** — site/docs/pricing load normally, third-party 2026 reviews describe it as functioning. Exposes HTTP/HTTPS and raw TCP via "secure TLS reverse tunnels"; no UDP found. Client (`pktriot`): **closed source/binary only** — no source repo published. Server ("Spokes"): **no public source found (proprietary)**, but **self-hostable in practice on the Enterprise tier** (deployable Docker/K8s/RPM/DEB packages "in your environment," not available on the free/personal tier). Transport ports: **not disclosed** in reachable docs. TLS termination: *"Our edge-servers use HTTP vhosts and TLS-SNI parsing to route requests"* — suggests termination for HTTP(S) vhosts specifically, not fully disentangled from SNI-passthrough for raw TCP within the research budget. Free tier: **1 GB/month bandwidth, 1 tunnel, 10 reserved subdomains, no port allocations, account required**. Proxy support, ToS gotchas, corporate-network docs: **unknown**.

---

## Comparison Table

| # | Service | Transport + Port | 443-only network OK? | Outbound proxy support | Open server (self-hostable)? | TLS terminated by operator? | Free-tier catch |
|---|---------|------------------|----------------------|------------------------|-------------------------------|------------------------------|------------------|
| 1 | Cloudflare Tunnel / TryCloudflare | QUIC(UDP) or HTTP/2(TCP), **:7844** (auto) | **No** — 7844 only, no 443 fallback | No | No | Yes | Quick: no SLA/200-req cap; Named: ToS bans "VPN or similar proxy" use |
| 2 | ngrok | TLS, **:443 only** | **Yes** | Partial (env var/SOCKS5; no PAC/NTLM) | No | Yes (`https` type only) | 1GB/mo, 3 endpoints, account required, interstitial |
| 3 | MS Dev Tunnels / VS Code Tunnels | WSS/TLS, **:443** | Likely yes | Partial (WS-capable proxy needed) | No | Yes (web URL); No/E2E (SSH session) | Account required, interstitial, 10-tunnel cap, "public preview" |
| 4 | Tailscale Funnel/Serve + DERP | WireGuard UDP :41641 direct; DERP TLS **:443**; control :80→443 | **Yes** (explicit fallback) | Partial/unreliable | Partial (DERP only) | **No** (end-to-end) | Bandwidth cap undisclosed, `*.ts.net` only, Funnel = 3 ports only |
| 5 | localhost.run | SSH/TCP **:22** | Likely no | No (manual only) | No | Yes (default); No (opt-in passthru) | Rotating random subdomain, speed-capped |
| 6 | serveo.net | SSH/TCP :22 or **:443** | **Yes** (explicit) | No (manual only) | No | Yes (lower confidence) | Service reliability itself — possibly down Sept 2026 |
| 7 | Pinggy | SSH or WS/HTTPS, **:443** (default) | **Yes** (explicit) | Partial (manual ProxyCommand) | No | No (tls modes); Yes-inferred (http mode) | 60-min timeout, random subdomain, screening page |
| 8 | Expose (beyondcode) | Custom TCP, **:443** (default) | **Yes** (default) | No | **Yes** | Yes (fronting proxy required) | Signup required even free, random URL only |
| 9 | playit.gg | HTTPS :443 (API) + custom **UDP** control (port unconfirmed) | **No** | No | No | No by default; explicitly not terminated for HTTPS add-on | 4 concurrent ports, no free custom domain |
| 10 | localtunnel (loca.lt) | HTTPS :443 handshake + **unencrypted raw TCP** (arbitrary port) data | **No** (data ≠ 443) | Partial/No | **Yes** | Yes (+ plaintext data plane) | Stale (2021 last release), recurring outages |
| 11 | tunnel.pyjam.as | WireGuard, **UDP :55555** | **No** (UDP-only, no fallback) | No (only config-fetch step) | **Yes** | Yes (Caddy edge) | Hobby project: no published limits, zero ToS |
| 12 | pico.sh tuns | SSH/TCP **:22** (inferred) | **No** (no 443 alt) | No (manual only) | **Yes** | Yes (HTTP/WSS); passthrough mode available | **No free tier** — $2/mo only |
| 13 | srv.us | SSH/TCP **:22** (default) | Not documented | Not documented | **Yes** | Yes (Let's Encrypt at edge) | Free/no account, but zero ToS + no published limits |
| 14a | zrok hosted (zrok.io) | OpenZiti/TLS, **:443** (likely, unconfirmed) | Likely yes | Not documented | **Yes** | Nuanced: fabric E2E, vendor frontend sees plaintext | 5GB/day rolling cap, interstitial unless card added |
| 14b | Pangolin (+ Pangolin Cloud) | WireGuard **UDP :51820** direct / **:21820** relay | **No** (UDP-only fallback) | Not documented | **Yes** (CE + Cloud hosted option exists) | Yes (Traefik/node terminates) | Free "Basic": non-commercial only, limits undisclosed |
| 15a | Telebit | Unknown | Unknown | Unknown | Unknown | Unknown | Effectively dead/abandoned |
| 15b | Loophole | Unknown (HTTP/HTTPS only) | Unknown | Unknown | No (SaaS-only today) | Unknown | No enforced limits per FAQ; 2026 activity unconfirmed |
| 15c | Packetriot | Unknown (undisclosed ports) | Unknown | Unknown | No client; server closed (self-host = Enterprise only) | Likely yes for HTTP(S) vhosts | 1GB/mo, 1 tunnel, 10 subdomains |

---

### Notable cross-cutting findings
- **Only three services are fully open source top-to-bottom AND self-hostable independent of the vendor:** Expose (beyondcode/exposedev, MIT), localtunnel (MIT), tunnel.pyjam.as (GPL-3.0-or-later), plus srv.us (ISC), pico.sh tuns (MIT), zrok (Apache-2.0), and Pangolin Community Edition (AGPL-3.0). Everything else (Cloudflare, ngrok, MS Dev Tunnels/VS Code, Tailscale's control plane, localhost.run, serveo.net, Pinggy, playit.gg, Packetriot, Loophole) keeps its relay/control-plane closed.
- **Explicit "no VPN/proxy" ToS clauses exist only at Cloudflare** among the services checked in detail; **playit.gg explicitly allows** personal VPN-style use in writing — a direct contrast worth highlighting in a literature review.
- **True end-to-end encryption (operator cannot read plaintext) is confirmed only for:** Tailscale Funnel/Serve, Pinggy's TLS/TLS-TCP modes, playit.gg's raw TCP/UDP tunnels (no TLS involved at all unless self-added), MS/VS Code's SSH-based `devtunnel connect`/core tunnel session, and (partially/nuanced) zrok's transport fabric. Every plain "HTTP(S) share" product (Cloudflare, ngrok's `https` type, localhost.run/serveo/Pinggy's default modes, Expose, localtunnel, tunnel.pyjam.as, pico.sh tuns, Pangolin) terminates TLS at the vendor/operator edge by default.
- **Corrections this research made to the original task assumptions:** Cloudflare's port is confirmed exactly as **7844** (not 443, no 443 fallback for tunnel data); tunnel.pyjam.as is **WireGuard-based, not SSH**; srv.us is **not** built on `sish`; Expose (beyondcode) is **actively maintained in 2026**, not dormant; Pangolin **does** have an official hosted SaaS ("Pangolin Cloud"); serveo.net's suspected instability is **substantiated** by direct technical checks and community reports.

