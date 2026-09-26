<!-- Raw research fact sheet produced by a research agent on 2026-09-25 for docs/literature-review.md. Kept as source material; not edited. -->


# Fact Sheet: Self-Hosted, Open-Source Reverse Tunnels ("ngrok alternatives")

**Compiled:** 2026-09-25. **Methodology:** GitHub REST API (`api.github.com`, via authenticated `gh`) for stars/license/release/commit data; raw README/LICENSE files fetched directly from each repo; official docs sites via WebFetch where they rendered; items 1-2 (frp, rathole) were researched in depth by a parallel sub-agent using the same live-verification methodology, with extensive GitHub-issue citations — that section is reproduced near-verbatim. **Constraints encountered:** the session's WebSearch quota was exhausted partway through (shared across my sub-agents), and a few JS-rendered docs sites (zrok, some others) returned empty content to WebFetch — in those specific spots I mark fields "unknown" rather than guess, per instructions. Everything else was independently verified live today, not recalled from training data. Legend for the summary table: **Y**=yes, **N**=no, **P**=partial, **Unk**=unknown/unconfirmed.

---

## 1. frp (fatedier/frp)
- **Language:** Go. **License:** Apache-2.0. No AGPL/BSL/SSPL; no commercial edition (community/sponsor-funded).
- **Stars:** ~109,620. **Last release:** v0.71.0 (2026-08-14). **Last commit:** 2026-09-15 (dev branch). **Maintenance: Active** (weekly-ish merges, 52 open issues).
- **Transport:** TCP+TLS by default since v0.50.0; optional `kcp` (UDP), `quic`, `websocket`, `wss`.
- **443+proxy:** (a) Yes, `wss` runs as normal HTTPS. (b) **Yes, explicit**: `transport.proxyURL="http://user:pass@host:port"` (also socks5/ntlm) or `HTTP_PROXY` env var — but only when `protocol=tcp` (doesn't combine with kcp/quic/websocket). Source: `conf/frpc_full_example.toml`.
- **HTTPS shares:** Subdomain routing yes; custom domains yes; **ACME: No** — you must supply your own cert (self-signed or externally obtained); open feature request issue #2799 "autocert support" still unresolved.
- **TCP/UDP:** Yes/Yes (v0.71.0 added a dedicated UDP binary codec).
- **Auth:** Shared token (default) or OIDC (Client Credentials Grant); native multi-user needs the companion `gofrp/fp-multiuser` plugin (implies core has none).
- **Multi-tenant:** No (core); plugin-based.
- **Encryption:** Relay-terminated by default (frps reads/routes vhost traffic); an off-by-default per-proxy `transport.useEncryption` adds a second E2E-ish layer for tcp/udp/stcp/xtcp types.
- **P2P:** Yes for XTCP mode (falls back to relayed STCP if hole-punch fails); STCP itself is always relayed.
- **Architecture:** Classic client(frpc)/relay(frps) with a highly configurable per-proxy transport/encryption/plugin system; alpha TUN-based L3 "VirtualNet" mode; SSH Tunnel Gateway lets plain `ssh -R` register without frpc.
- **Notable limitations:** No built-in ACME (#2799); no cert hot-reload (#2946); XTCP lacks UPnP help (#4112) and has stability gaps (#5087); no native multi-tenant.
- **Sources:** github.com/fatedier/frp, gofrp.org/en/docs, github.com/fatedier/frp/issues/{2799,2946,4112,5087}

## 2. rathole (rapiz1/rathole → **transferred to rathole-org/rathole**)
- **Language:** Rust. **License:** Apache-2.0. No commercial edition.
- **Stars:** ~14,255. **Last release: v0.5.0 (2023-10-01) — over 3 years stale.** **Last commit:** 2026-08-23 (isolated merge; prior commits Jul-2025, Jun-2025, Jun-2024…). **Maintenance: Sporadic** — no versioned release in 3 years, year-long gaps between commits, repo transferred from solo maintainer to an org (consistent with the original author stepping back).
- **Transport:** Raw TCP, **unencrypted by default**; optional `tls`, `noise` (Noise_NK_25519_ChaChaPoly_BLAKE2s), or `websocket` (since v0.5.0). No QUIC (open issue #65).
- **443+proxy:** (a) Partial — TLS/WS could bind 443 but no documented turnkey mode. (b) **Yes**: client `proxy = "socks5://user:pass@host:port"` config, README states "`http` and `socks5` is supported."
- **HTTPS shares: Not supported at all** — pure L4 TCP/UDP forwarder, no vhosting/subdomain/ACME/custom-domain concept.
- **TCP/UDP:** Yes/Yes, but with rough edges (issue #171 latency/jitter for Minecraft; #162 one service can't forward both TCP+UDP simultaneously).
- **Auth:** Per-service shared pre-shared token only. No OIDC/identity.
- **Multi-tenant:** No.
- **Encryption:** Relay-terminated, plaintext by default; even with TLS/Noise, the server holds the key so the relay operator can still read traffic.
- **P2P:** No.
- **Architecture:** Minimal async-Rust client/server; one data-channel TCP connection per incoming connection (not multiplexed like frp); deliberately leaner than frp (no HTTP vhosting, no plugins, no P2P).
- **Notable limitations:** No HTTP layer (#213); no QUIC (#65); connection-stability bug #401; no Prometheus metrics (#119); very stale formal release despite a live `dev-latest` build.
- **Sources:** github.com/rathole-org/rathole, github.com/rathole-org/rathole/issues/{401,171,162,213,65,119}

## 3. bore (ekzhang/bore)
- **Language:** Rust. **License:** MIT.
- **Stars:** ~11,508. **Last release:** v0.6.0 (2025-06-09). **Last commit:** 2026-02-04 (~7.5 months ago). **Maintenance: Sporadic** (no release in 15+ months, no commit in ~7.5 months, but not dead).
- **Transport:** Raw TCP only — no TLS/WS/QUIC option at all.
- **443+proxy:** (a) The control port and each forwarded port are separate TCP listeners on the server, not multiplexed inside one 443 connection — poorly suited to "outbound-443-only" scenarios by design. (b) No CONNECT/SOCKS proxy flag found in the CLI (`--local-host`, `--to`, `--port`, `--secret` only).
- **HTTPS shares:** None at all — no subdomain routing, no ACME, no custom domains; it's a pure random-remote-TCP-port allocator with zero HTTP awareness.
- **TCP:** Yes. **UDP: No.**
- **Auth:** Single shared `--secret` (HMAC challenge-response), not per-user.
- **Multi-tenant:** No.
- **Encryption:** **Not E2E and not encrypted at all by default** — direct quote: "no further traffic is encrypted by default." Relay sees 100% plaintext of the proxied stream unless the tunneled app itself uses TLS.
- **P2P:** No.
- **Architecture:** ~400 lines of async Rust, deliberately minimal ("that's all it does: no more, and no less"); control port 7835 issues per-connection UUIDs.
- **Notable limitations:** No subdomains/HTTP routing, no UDP, no proxy support, no encryption, single shared secret only — all self-documented in the README rather than found via issue-tracker digging (not separately verified against the issues tab for this item).
- **Sources:** github.com/ekzhang/bore (README)

## 4. tunnelto (agrinman/tunnelto)
- **Language:** Rust. **License:** MIT.
- **Stars:** ~7,080. **Last release:** 0.1.18 (2021-05-16). **Last commit:** 2022-09-24 — **over 4 years ago. Maintenance: Unmaintained.**
- **Transport:** WebSocket control channel + TCP data channel; TLS on by default in production (local testing disables via `CTRL_TLS_OFF=1`).
- **443+proxy:** No proxy flag/env var found in the README.
- **HTTPS shares:** Subdomain via `-s` flag: yes. ACME: not documented for self-hosting. Custom domain: not evident.
- **TCP:** Yes (implicit). **UDP: No** (not mentioned).
- **Auth:** API key (`--key` / `set-auth`), single key per tunnel.
- **Multi-tenant:** Unclear/likely minimal (`ALLOWED_HOSTS` env var only).
- **Encryption:** Relay-terminated.
- **P2P:** No.
- **Architecture:** Rust/tokio; originally named "wormhole" (crate `wormhole-tunnel`, Docker image `agrinman/wormhole`) before rename.
- **Notable limitations:** Self-documented: "does not support multiple running servers (i.e. centralized coordination)" — no built-in clustering; effectively abandoned since 2022.
- **Sources:** github.com/agrinman/tunnelto (README)

## 5. wstunnel (erebe/wstunnel)
- **Language:** Rust. **License:** BSD-3-Clause.
- **Stars:** ~7,056. **Last release:** v11.0.0 (**2026-09-19**, 6 days old). **Last commit:** 2026-09-20. **Maintenance: Active.**
- **Transport:** WebSocket (default, most performant), HTTP/2, or HTTP/3 WebTransport (QUIC); carries TCP, UDP, SOCKS5, HTTP-proxy, transparent-proxy, Unix-socket, or stdio payloads.
- **443+proxy:** (a) Yes, `wss://` is normal 443 TLS. (b) **Yes, explicit `--http-proxy` flag** ("Support for using http proxy (when behind one) as gateway") — but explicitly **not** supported in WebTransport/HTTP3 mode.
- **HTTPS shares:** **None** — this is a generic L4/L7 firewall-bypass tunnel (VPN-like port mapper), not an ngrok-style multi-app subdomain sharer. No subdomain routing, no ACME, no custom-domain concept.
- **TCP/UDP:** Yes/Yes (explicit `udp://host:port` syntax with configurable timeout).
- **Auth:** Pre-shared token/password (`-P` flag); no OIDC/per-user system.
- **Multi-tenant:** No.
- **Encryption:** TLS-wrapped client↔relay (wss/https), so **relay-terminated**, not E2E to the backend.
- **P2P:** No.
- **Architecture:** Single static binary; 3 selectable transport encodings chosen specifically to blend with ordinary web traffic and defeat DPI/firewalls; static and dynamic (SOCKS5/HTTP-proxy) modes.
- **Notable limitations (from README's own warnings):** HTTP/2 mode breaks behind buffering reverse proxies/CDNs (must expose wstunnel directly); WebTransport mode needs true E2E UDP reachability and can't combine with `--http-proxy`/SNI options.
- **Sources:** github.com/erebe/wstunnel (README)

## 6. chisel (jpillora/chisel)
- **Language:** Go. **License:** MIT.
- **Stars:** ~16,578. **Last release:** v1.12.0 (2026-08-29). **Last commit:** 2026-09-01. **Maintenance: Active.**
- **Transport:** SSH (crypto/ssh) tunneled inside an HTTP-upgraded WebSocket.
- **443+proxy:** (a) Yes, `wss://` over 443; `--tls-domain` forces port 443 for built-in ACME. (b) **Yes, explicit**: `--proxy` flag, "An optional HTTP CONNECT or SOCKS5 proxy which will be used to reach the chisel server" (DNS always resolved by the proxy).
- **HTTPS shares:** No built-in multi-app vhost router (server optionally proxies to one single default backend). **ACME: Yes, built-in** — `--tls-domain` gets a free Let's Encrypt cert (HTTP-01-style; "requires port 443"). Custom domain: yes via that flag.
- **TCP/UDP:** Yes/Yes (explicit `1.1.1.1:53/udp` example).
- **Auth:** `--authfile` (user:pass with per-user allowed-remote ACL patterns, wildcards supported) or SSH-keypair fingerprint pinning; SOCKS5 gated by its own ACL token.
- **Multi-tenant:** Yes, in a limited sense — authfile supports multiple named users scoped to specific remotes.
- **Encryption:** Relay-terminated (server is the SSH/TLS endpoint and actively routes streams).
- **P2P:** No.
- **Architecture:** Single Go binary (client+server); SSH-over-WebSocket-over-HTTPS specifically to look like ordinary web traffic to firewalls/proxies.
- **Notable limitations:** Single-backend reverse-proxy fallback only (not multi-app vhosting); 245 open issues (largest backlog of the SSH-based tools here); recent DoS-hardening changelog entries (`CHISEL_WS_READ_LIMIT`) suggest past abuse-resistance gaps.
- **Sources:** github.com/jpillora/chisel (README)

## 7. sish (antoniomika/sish)
- **Language:** Go. **License:** MIT.
- **Stars:** ~4,737. **Last release:** v2.23.0 (2026-06-05). **Last commit:** 2026-06-25. **Maintenance: Active.**
- **Transport:** Literally the SSH protocol (`ssh -R`) — no custom client needed.
- **443+proxy:** (a) HTTPS data plane listens on a configurable `--https-address` (typically 443), but the **SSH control connection is a separate listener/port** — a strict outbound-443-TCP-only network cannot open the `ssh -R` session unless that SSH port is also somehow exposed on 443. (b) No sish-native proxy-env-var support found; standard OpenSSH `ProxyCommand`/`ProxyJump` could be layered on manually since it's just SSH, but that's not a sish feature per se.
- **HTTPS shares:** Subdomain routing yes; custom domain yes (`--domain`); **ACME strongly implied** by `--https-certificate-directory` flag (Go autocert/certmagic-style pattern) but the exact challenge type isn't spelled out in the README — treat as inferred, not fully confirmed.
- **TCP:** Yes (plus private "TCP alias" SSH-jump targets). **UDP: No** (SSH `-R` is TCP-only by protocol design).
- **Auth:** SSH public-key (authorized_keys-style, dynamic reloading) and password auth.
- **Multi-tenant:** **Yes, explicitly** — "Restrictive binding policies for safer multi-tenant setups."
- **Encryption:** Relay-terminated for normal HTTP(S)/subdomain mode; **but** sish also has a distinct **SNI-passthrough mode** ("Route TLS traffic by SNI to multiple backends without terminating TLS") which is effectively E2E for that specific mode.
- **P2P:** No.
- **Architecture:** An SSH daemon repurposing stock `ssh -R` as the tunnel-setup protocol; adds HTTP vhosting, raw TCP, SNI-passthrough, and private TCP aliases on top.
- **Notable limitations:** No UDP; SSH control port and HTTPS data port are separate listeners (a real constraint for 443-only networks); exact ACME mechanics undocumented.
- **Sources:** github.com/antoniomika/sish (README), docs.ssi.sh

## 8. inlets (open-source) vs inlets-pro
- **inlets (OSS core): does not currently exist as a public repo.** `api.github.com/repos/inlets/inlets` returns 404, and listing all repos under the `inlets` GitHub org (`inlets-operator`, `inlets-pro`, `inletsctl`, `inlets.dev`, `cloud-provision`, `inlets-svc`, `docs.inlets.dev`, `mixctl`, `agent-skills`, …) shows **no free/open "inlets" core repo remains.** I could not confirm the exact narrative/date of this deprecation (WebSearch quota ran out before I could locate an announcement) — this is a directly-observed GitHub fact, not a guess, but the *history* behind it is unverified.
- **inlets-pro (the only currently distributed product):**
  - **Language:** Unknown — the public repo `inlets/inlets-pro` is ~99% "Mustache" (docs/site templates); actual source is **not published**, only compiled binaries/container images are distributed.
  - **License: NONE (proprietary).** GitHub reports `license: null`. README states explicitly: *"A valid license key or Gumroad subscription is required to launch or deploy inlets... you agree... bound by the terms of the End User License Agreement (EULA)."* **This is closed-source, subscription-gated commercial software sitting in a public GitHub repo — flag prominently: not open source at all**, despite topics like "open-source"-adjacent framing in search results.
  - **Stars:** ~574. **Last release:** 0.11.16 (2026-09-08, reads like a running changelog). **Last commit (docs repo):** 2026-09-08. **Maintenance: Active** (frequent releases; paying customer base).
  - **Transport/443+proxy/auth/multi-tenant/encryption:** **Unknown** — closed source, and the docs I could fetch don't specify wire-protocol or proxy-traversal details.
  - **HTTPS shares:** Marketed yes ("Expose as many HTTPS websites as you like," "Use your own DNS"), exact ACME mechanics unconfirmed.
  - **TCP:** Yes (core feature). **UDP:** Marketed/topic-tagged as supported in Pro's L4 mode, not independently verified.
  - **P2P:** No (not marketed as such).
  - **Architecture:** Single binary, client+server roles, Kubernetes/cloud-native oriented (inlets-operator, Helm charts); explicitly "not a VPN."
  - **Notable limitation for this literature review:** this is arguably the clearest "open-core bait" case surveyed — discoverable via "open source ngrok alternative" searches, living in a public repo with stars/issues/topics that read as OSS, but 100% commercial/EULA-bound with no free tier and no public source.
- **Sources:** github.com/inlets/inlets-pro, api.github.com/orgs/inlets/repos, inlets.dev

## 9. Pangolin (fosrl/pangolin + newt + gerbil)
- **Language:** TypeScript (Pangolin control plane), Go (Newt client, Gerbil gateway).
- **License:** **Dual-licensed per-file**: AGPL-3.0 by default for unmarked files, or the proprietary **"Fossorial Commercial License"** for headers/customers that specify it (confirmed by reading the LICENSE file directly). Textbook open-core, confirmed by the README's own framing: *"Self-Host: Community Edition - Free, open-source, AGPL-3"* vs *"Self-Host: Enterprise Edition - Open-core, Fossorial Commercial License (free for personal/hobbyist use and businesses <$100K USD gross annual revenue)"* vs fully-hosted **Pangolin Cloud**. Newt and Gerbil are individually AGPL-3.0, same dual-license clause.
- **Stars:** pangolin ~22,918; newt ~909; gerbil ~334 (very fast growth — created Sept 2024). **Last release:** pangolin 1.23.0 (2026-09-16), newt 1.17.0 (2026-09-15), gerbil 1.5.2 (2026-09-18). **Last commit:** all three within the last 2 days of check. **Maintenance: Active** (releases every 1-2 weeks across all three).
- **Transport:** Control/session = HTTPS + WebSocket. **Data plane = WireGuard** (Newt is a fully userspace WireGuard client via netstack; Gerbil manages the WireGuard interface/peers and listens on **UDP 21820** for NAT hole-punch). Gerbil also runs an SNI-based TLS-routing proxy (port 8443, or 443 directly in single-node deployments).
- **443+proxy:** Control WebSocket is 443/proxy-friendly. **But the actual tunnel data plane is WireGuard/UDP — no documented TCP-only fallback was found**, so a network that blocks all outbound UDP (even with TCP 443 open) will likely be unable to pass real tunnel traffic even though the control channel connects. `HTTP_PROXY` support for Newt: not found/unknown.
- **HTTPS shares:** Subdomain routing yes; automatic SSL certificates yes ("Pangolin handles routing, load balancing, health checking, and automatic SSL certificates"); custom domains yes; exact ACME challenge type unspecified.
- **TCP/UDP:** Yes/Yes (Newt is explicitly "a WireGuard tunnel client and TCP/UDP proxy").
- **Auth:** Full identity system — SSO/OIDC, RBAC, in-browser SSH/RDP/VNC privileged access management (PAM).
- **Multi-tenant:** **Yes**, explicitly org/RBAC-based ("sites, reverse proxy, client access, RBAC... share one identity and policy model").
- **Encryption:** Nuanced. The Newt↔Gerbil hop is always WireGuard-encrypted. Gerbil's SNI proxy can route HTTPS by inspecting only the SNI field without itself terminating TLS in some configurations; but Pangolin's control plane also provisions/manages TLS certs directly for exposed resources, implying termination happens somewhere in the self-hoster's own stack for at least some resource types. Net effect: **not readable by any third party** (you run all the relay infrastructure yourself) but **not a strict SNI-passthrough-only guarantee** either — closer to "terminated within your own self-hosted stack" than to OpenZiti/zrok's stronger "not even our servers can read it" claim.
- **P2P:** **Yes** — "Peer-to-peer with intelligent NAT traversal," via Gerbil's UDP hole-punch orchestration, falling back to relay through Gerbil if hole-punch fails.
- **Architecture:** Three cooperating components positioned as a full self-hostable "SASE platform" (zero-trust VPN + reverse proxy + PAM + AI-gateway), not just a tunnel — notably broader scope than any other item on this list.
- **Notable limitations:** WireGuard/UDP dependency may struggle on strict TCP-443-only networks; Enterprise features gated above $100K revenue; young project (Sept 2024) with limited long-term track record.
- **Sources:** github.com/fosrl/{pangolin,newt,gerbil} (README + LICENSE files read directly)

## 10. zrok (openziti/zrok) and its dependency OpenZiti (openziti/ziti)
**zrok:**
- **Language:** Go. **License:** Apache-2.0.
- **Stars:** ~4,721. **Last release:** v2.0.4 (2026-05-18). **Last commit:** 2026-09-24. **Maintenance: Active.**
- **Transport:** Inherits OpenZiti's own application-layer overlay (mTLS identity auth + libsodium E2E encryption) rather than a conventional single transport.
- **443+proxy:** OpenZiti routers are commonly configured on 443/TLS, so outbound-443-only generally works; explicit `HTTP_PROXY` support **not independently confirmed** (zrok's docs site returned empty content to WebFetch — JS-rendered, could not verify live).
- **HTTPS shares:** Yes (HTTP/HTTPS, TCP, UDP, file sharing all supported); **self-hosting is explicitly documented as supported** ("Self-Hostable: Run your own zrok service instance," with a linked guide) — but exact ACME challenge type: **unknown**, could not independently verify.
- **TCP/UDP:** Yes/Yes ("Share TCP/UDP services securely with other zrok users").
- **Auth:** Identity-based (OpenZiti PKI), with zrok layering its own invite/account UX on top.
- **Multi-tenant:** Yes.
- **Encryption: Explicitly and strongly E2E** — direct README quotes: *"End-to-end encryption with zero-trust architecture"* and **"All traffic is encrypted, even from zrok servers"** — a materially stronger claim than almost every relay-based tool in this survey.
- **P2P:** Yes when possible ("Direct connections between users when possible"), falling back to the OpenZiti fabric otherwise.
- **Architecture:** A user-facing sharing/UX layer (CLI + self-hostable controller/frontend) built entirely on top of OpenZiti as the data-plane/identity substrate — nearly all of zrok's transport/security/P2P properties are inherited OpenZiti properties.
- **Notable limitations:** Self-hosting requires standing up (or reusing) an OpenZiti network first — materially higher setup complexity than a single binary like frp/chisel.

**OpenZiti (dependency, itself a self-hostable project):**
- **Language:** Go. **License:** Apache-2.0. **Stars:** ~4,406. **Last release:** v2.0.6 (2026-09-17). **Last commit:** 2026-09-25 (today). **Maintenance: Active.**
- **Transport:** Its own zero-trust overlay — mTLS identity auth, libsodium E2E data encryption, carried over a self-hostable mesh "fabric" of routers using **"smart routing"** (latency/throughput/cost-aware path selection), not simply TCP or WireGuard.
- **Auth:** Strong per-identity cryptographic model for every connection (user/service/device/workload) — explicitly not a shared-token model.
- **Multi-tenant:** Yes, policy/identity-based, core to the design.
- **Encryption:** Explicitly E2E by design — direct quote: *"traffic is encrypted from the sending application to the receiving application using libsodium... Even if routers or intermediate networks are compromised, traffic cannot be decrypted or tampered with."* A secondary "tunneler" mode (for apps that can't embed the SDK) only guarantees tunneler-to-tunneler encryption — still strong, slightly narrower.
- **P2P: Not classic NAT hole-punch** between two end-user machines — architecturally it's a self-hostable **mesh of routers** with intelligent shortest-path routing; encryption stays E2E regardless of hop count, but this is a different model from WireGuard/iroh/holesail-style direct hole-punching.
- **Architecture:** Full zero-trust network-as-a-service platform (controller + routers + edge SDKs); "dark" services (no exposed listening ports at all) is the core philosophy.
- **Notable limitations:** Significant operational complexity vs. a single tunnel binary — overkill for "just share one dev server," which is exactly the gap zrok fills on top of it.
- **Sources:** github.com/openziti/{zrok,ziti} (README), zrok.io, openziti.io

## 11. boringproxy
- **Language:** Go. **License:** MIT.
- **Stars:** ~1,385. **Last release:** v0.10.0 (2023-01-04). **Last commit:** 2024-07-06 — **over 2 years ago. Maintenance: Unmaintained** — independently corroborated: its own marketing site **boringproxy.io now returns NXDOMAIN** (domain no longer resolves) as of 2026-09-25, a strong signal beyond just GitHub inactivity.
- **Transport:** Token-based tunnel; server source includes `tls_proxy.go` and `sni.go`, indicating a built-in TLS-terminating/SNI-routing proxy. Exact wire protocol not fully detailed in the (thin) README.
- **443+proxy:** Not documented.
- **HTTPS shares:** Automatic HTTPS was the headline feature (GitHub description: *"Simple tunneling reverse proxy with a fast web UI and auto HTTPS. Designed for self-hosters"*); originally integrated with TakingNames.io for one-click custom domains (that integration's own promotional site is referenced in the README, status unconfirmed); subdomain-per-client routing supported.
- **TCP:** Plausible via the SNI/TLS proxy path but not confirmed in detail. **UDP: No / not found** — no `udp_proxy.go`-equivalent file in the repo listing.
- **Auth:** Shared per-client token (`-token` flag).
- **Multi-tenant:** Partial — named clients/users (`-client-name`, `-user`) but no documented RBAC.
- **Encryption:** Relay-terminated (server does TLS/SNI proxying).
- **P2P:** No.
- **Architecture:** Single Go binary + WebUI, built specifically so self-hosters get automatic HTTPS without manually running Certbot/nginx.
- **Notable limitations:** Project appears abandoned (dead marketing site, 2+ years no commits, 60 open issues with no visible recent triage).
- **Sources:** github.com/boringproxy/boringproxy (README + repo file listing); DNS lookup performed directly on 2026-09-25

## 12. nps (ehang-io/nps)
- **Language:** Go. **License:** GPL-3.0.
- **Stars: ~34,238 — the highest of any item except frp.** **Last release:** v0.26.10 (**2021-04-08**). **Last commit:** 2024-05-30 — **over 2 years ago. Maintenance: Unmaintained** — one of the starkest "stars ≠ maintained" cases surveyed: massive historical popularity, no release in 5+ years, no commits in 2+ years, 527 open issues with apparently little ongoing triage.
- **Transport:** Raw TCP control/bridge channel (default port 8024); tunneled service types include tcp, udp, http(s), socks5, and "p2p."
- **443+proxy:** No documented `HTTP_PROXY`/SOCKS5 upstream support for the client-to-server bridge itself (NPS can *expose* an http-proxy/socks5 *service type* to end users, which is a different thing).
- **HTTPS shares:** Yes — "Https integration... support to convert backend proxy and web services to https, and support multiple certificates" — reads as **manual/multi-cert configuration, not automated ACME**; subdomain/host routing and custom domains supported (custom headers, host modification, URL routing, wildcard "pan-resolution").
- **TCP/UDP:** Yes/Yes.
- **Auth:** Web-UI username/password login (default `admin`/`123`, must be changed) **plus "Multi-user and user registration support on server"** — a real account system, not just a shared token.
- **Multi-tenant: Yes**, explicitly.
- **Encryption:** Relay-terminated (full-featured proxy that inspects/routes/rewrites HTTP(S) traffic).
- **P2P:** Listed as a supported protocol type; no further technical detail on the hole-punch mechanism found.
- **Architecture:** Server (`nps`) + client (`npc`) with a full web admin console; heavy feature set (traffic accounting, port reuse, caching, compression, rate limiting) — closer to a complete "intranet-penetration platform" than a minimal tunnel.
- **Notable limitations:** Effectively unmaintained since mid-2024 despite huge popularity; 527 open issues; ACME automation unclear/likely absent.
- **Sources:** github.com/ehang-io/nps (README, confirmed as still the live canonical repo via `gh search`)

## 13. piko (andydunstall/piko)
- **Language:** Go. **License:** MIT.
- **Stars:** ~2,193. **Last release:** v0.10.0 (2026-05-08). **Last commit:** 2026-09-22. **Maintenance: Active.**
- **Transport:** Standard HTTPS reverse-proxy semantics; raw TCP requires a separate companion process ("Piko forward").
- **443+proxy:** (a) Yes, standard HTTPS reverse proxy. (b) Not documented/unknown.
- **HTTPS shares:** Subdomain routing yes (wildcard domain, Host-header first segment); also offers an `x-piko-endpoint` header as an alternative to wildcard DNS/certs entirely — a distinctive design choice. ACME: not documented.
- **TCP:** Yes, but only via the separate "Piko forward" helper (raw TCP has no Host header to route by, so you can't connect directly to the Piko server). **UDP: No / not found.**
- **Auth:** Endpoint-level auth for Piko-forward connections (TLS + auth), specifics not fully detailed.
- **Multi-tenant:** Not addressed in the README; unknown.
- **Encryption:** Relay-terminated (explicitly reads/routes by Host header).
- **P2P:** No.
- **Architecture:** Deliberately built to **"serve production traffic"** as a fault-tolerant, horizontally-scaled cluster of Piko nodes with gossip-style routing propagation — a notably more "production infra" design goal than most other items, aimed at Kubernetes hosting.
- **Notable limitations:** Raw TCP needs an extra hop/component; no UDP; young/small project (3 open issues) so little issue-tracker history to mine for limitations.
- **Sources:** github.com/andydunstall/piko (README)

## 14. portr (amalshaji/portr)
- **Language:** Go. **License:** AGPL-3.0 (single-tier; no separate commercial edition found).
- **Stars:** ~3,192. **Last release:** v1.0.18 (2026-08-12). **Last commit:** 2026-09-13. **Maintenance: Active.**
- **Transport:** SSH remote port forwarding under the hood.
- **443+proxy:** Not documented as a first-class feature (standard SSH `ProxyCommand` could be layered on manually, as with sish).
- **HTTPS shares:** Automatic public HTTPS URL, subdomain pinning (`--subdomain`); ACME type and custom-domain support not specified.
- **TCP:** Yes. **UDP: No / not found** (feature list explicitly says "HTTP, TCP, and WebSocket" only).
- **Auth:** Account-based via an admin dashboard for "team, user, and connection management" (exact mechanism — password/OIDC — not detailed).
- **Multi-tenant: Yes**, explicitly — built for small teams, with team/user/connection management.
- **Encryption:** Relay-terminated — has a built-in local request/response **inspector** (`localhost:7777`) that captures and replays HTTP and WebSocket traffic, which is only meaningful if plaintext is visible somewhere on the path.
- **P2P:** No.
- **Architecture:** SSH-remote-port-forward tunnel with an unusually strong DX layer: local SQLite-backed request logging, a local web inspector, a `portr logs` CLI query interface — explicitly positioned for small-team dev use, "not recommended for use alongside production servers."
- **Notable limitations:** Self-documented as not production-grade; no UDP.
- **Sources:** github.com/amalshaji/portr (README), portr.dev

## 15. localtunnel server (localtunnel/server)
- **Language:** JavaScript/Node.js. **License:** MIT.
- **Stars:** ~3,320 (server); companion CLI client `localtunnel/localtunnel` has ~22,489 stars separately.
- **Last release:** None via GitHub Releases API (404 — never used GitHub Releases, npm-published only). **Last commit:** 2024-03-20 (server, **over 2 years ago**); client repo pushed 2025-08-29 (~1 year ago, marginally less stale). **Maintenance: Unmaintained** (server).
- **Transport:** Raw TCP control channel; no TLS/WS/QUIC in the tunnel protocol itself.
- **443+proxy:** (a) Server explicitly does **not** terminate HTTPS itself — README says you must front it with your own reverse proxy (their companion `localtunnel-nginx`) to handle 80/443. (b) Client's `host` option only repoints to a different localtunnel *server*, not an HTTP CONNECT proxy — **No.**
- **HTTPS shares:** Subdomain routing: core feature. **ACME: No** — entirely the operator's responsibility via an external reverse proxy. Custom domain: yes (`--domain` server flag).
- **TCP/UDP: No/No** — this is an HTTP(S)-request tunnel only, not a general L4 port forwarder.
- **Auth:** **None built in** — no token/password mechanism in either repo.
- **Multi-tenant:** No.
- **Encryption:** Relay-terminated (by design, once you add the recommended nginx TLS front-end).
- **P2P:** No.
- **Architecture:** The original, simplest "ngrok-clone" reference design (created 2012/2013) — client requests a subdomain, server proxies public HTTP(S) requests back down the same persistent connection; deliberately leaves TLS to the operator.
- **Notable limitations:** Effectively unmaintained; no built-in HTTPS/ACME; no auth; no raw TCP/UDP; README points to third-party client reimplementations (Go's `gotunnelme`, `go-localtunnel`, a .NET client, Rust's `rlt`) — a sign the ecosystem has moved past the original JS client.
- **Sources:** github.com/localtunnel/{server,localtunnel} (README)

## 16. pagekite
- **Language:** Python (reference implementation, `pagekite/PyPagekite`; a separate C implementation also exists, `pagekite/libpagekite`, not the primary item here). **License:** AGPL-3.0.
- **Stars:** ~751. **Last release (GitHub):** v1.5.1.200424 "The Go-Faster-Please Release" (**2020-04-25, over 6 years old**). **Last commit:** 2026-01-13 (~8 months ago — some activity despite the very stale release tag). **Maintenance: Sporadic** — maintenance-mode; one of the oldest tools surveyed (created 2010), a pioneer of "tunnel over 443 to beat firewalls," a technique most later tools (chisel, wstunnel, frp) also adopted.
- **Transport:** Works with any HTTP/HTTPS/SSH backend "and a few other TCP-based protocols" over a custom persistent multiplexed front-end/back-end relay protocol.
- **443+proxy:** The project's entire original value proposition is 80/443 firewall traversal; explicit `HTTP_PROXY`/CONNECT support **not independently confirmed** — the technical docs pages I tried 404'd, only the marketing site rendered. **Unknown, moderate historical confidence it works given the project's stated purpose.**
- **HTTPS shares:** Yes — "Automatic https:// security," "Stable DNS names," "Unlimited sub-domains"; **notably offers a choice** between "end-to-end" TLS (not relay-terminated) and "wild-card TLS encryption" (relay-terminated, shared wildcard cert) per its own marketing copy — an unusual dual-mode option among the tools surveyed. Exact ACME automation unconfirmed.
- **TCP:** Yes (SSH + "other TCP-based protocols"). **UDP: No / not found.**
- **Auth:** Unknown (marketing pages only; technical docs unreachable).
- **Multi-tenant:** Unknown.
- **Encryption:** Genuinely dual — "end-to-end" or "wild-card TLS" (relay-terminated) depending on configuration, per pagekite.net's own copy.
- **P2P:** No (relay/front-end based, no hole-punching).
- **Architecture:** One of the very first "expose localhost via a public relay over 443" tools (2010); "front-end" (public relay) / "back-end" (your machine) terminology.
- **Notable limitations:** Documentation today is thin/marketing-only, making several technical details hard to verify live; for balance — a third party (opentunnel's own README, see ADDED section below) claims **"PageKite does not support clustering, allows unencrypted traffic"** — a competitor's characterization, not independently verified by me.
- **Sources:** github.com/pagekite/PyPagekite, pagekite.net

## 17. gost (go-gost/gost)
- **Language:** Go. **License:** MIT.
- **Stars:** ~7,534. **Last release:** v3.3.0 (2026-08-30). **Last commit:** 2026-09-22. **Maintenance: Active.**
- **Transport:** Extremely broad — confirmed protocol list from official docs: `tcp, mtcp, udp, tls, dtls, mtls, ws, mws, wss, mwss, h2, h2c, grpc, pht, ssh, sshd, kcp, quic, h3, wt (WebTransport), ohttp, otls, icmp, icmp6, ftcp`. **No WireGuard, no Noise protocol.**
- **443+proxy:** (a) Yes trivially (wss/https/h2 all run on 443). (b) **Yes** — gost is fundamentally a "proxy chain" tool; you can chain an upstream HTTP/SOCKS5 proxy hop before the gost tunnel hop in its forwarding-chain config, core to its design.
- **HTTPS shares:** Primarily a generic L4/L7 proxy/tunnel swiss-army-knife, not an ngrok-style subdomain sharer; can reverse-proxy to a Host-routed backend, but **built-in ACME automation was not found** in the docs fetched.
- **TCP/UDP:** Yes/Yes (both first-class: port forwarding and transparent proxying for each).
- **Auth:** Username:password on proxy-chain node URLs (e.g. `socks5://user:pass@host:port`) — basic per-node credentials, not full OIDC/identity.
- **Multi-tenant:** Partial — multiple named chain nodes, no built-in user/org management UI (a separate `go-gost/gost-ui` WebUI project exists).
- **Encryption:** Relay-terminated for TLS/WS/H2 transports (gost node terminates and re-forwards); not marketed as E2E.
- **P2P:** No.
- **Architecture:** Everything-is-a-chain-of-connectors/dialers/listeners design — the same binary can be forward proxy, reverse tunnel, transparent proxy, TUN/TAP-based device, or DNS proxy — closer to a protocol-translator Swiss army knife than a purpose-built ngrok clone.
- **Notable limitations:** Documentation is Chinese-first (English docs thinner); no built-in ACME found; no native multi-tenant/billing layer.
- **Sources:** github.com/go-gost/gost, gost.run/en/tutorials/protocols/overview/

## 18. tunnelmole (robbie-cahill/tunnelmole-client + tunnelmole-service)
- **Language:** TypeScript/Node.js. **License: split** — client = MIT, **self-hostable server (`tunnelmole-service`) = AGPL-3.0.**
- **Stars:** client ~1,894; service ~416. **Last release:** none via GitHub Releases (npm-published only). **Last commit:** both repos 2026-04-13 (~5+ months ago). **Maintenance: Sporadic** (small solo-maintainer project, quiet but not clearly abandoned).
- **Transport:** WebSocket control/data channel.
- **443+proxy:** Not documented.
- **HTTPS shares:** Subdomain support yes; custom subdomains require a paid subscription **on the hosted SaaS**, but are **free/unrestricted when self-hosting** (you just edit your own `apiKeys.json`) — a notable business-model contrast. **ACME: No** — self-hosting README explicitly says you need your own Let's Encrypt cert + your own nginx reverse proxy (same pattern as localtunnel).
- **TCP/UDP: No/No** — appears to be HTTP-tunnel-only; no raw port-forwarding features found.
- **Auth:** API-key based for custom subdomains; otherwise open/anonymous random-subdomain use.
- **Multi-tenant:** No built-in team/user system; single shared `apiKeys.json`.
- **Encryption:** Relay-terminated.
- **P2P:** No.
- **Architecture:** Classic split ngrok-clone: permissively-licensed client (usable against the author's paid SaaS by default) + copyleft self-hostable server.
- **Notable limitations:** No ACME automation; no TCP/UDP; the MIT-client/AGPL-server license split is a subtlety worth flagging for anyone building commercially on the self-hosted server.
- **Sources:** github.com/robbie-cahill/tunnelmole-{client,service} (README)

## 19. holesail (holesail/holesail)
- **Language:** JavaScript/Node.js. **License:** AGPL-3.0.
- **Stars:** ~346. **Last release:** 2.4.1 (2025-11-17, ~10 months ago). **Last commit:** 2026-09-19 (6 days ago). **Maintenance: Active** (recent commits despite an older release tag).
- **Transport:** Built on the **Holepunch/Pear ecosystem** (formerly Hypercore Protocol/"Dat") — a DHT-based P2P stack using Noise-protocol-secured connections and UDP hole-punching; explicitly inspired by `holepunch.to` and Bitfinex's `hypertele`.
- **443+proxy:** Fundamentally P2P/hole-punch-first (DHT rendezvous, no fixed TCP host:port to dial) — **architecturally incompatible with strict outbound-TCP-443-only-via-CONNECT-proxy networks**; no HTTP_PROXY support found or expected.
- **HTTPS shares:** Not applicable in the ngrok sense — shares a raw TCP/UDP port P2P via a connection string/key (`hs://...`); no subdomain routing, no public-CA TLS certs (uses the Holepunch stack's own Noise encryption instead of Web PKI).
- **TCP/UDP:** Yes/Yes (both explicit; "Force UDP usage" is an advanced override, implying TCP-style framing is the default path).
- **Auth:** Possession-based (whoever holds the `hs://` key can connect); "secure" mode toggles Noise-protocol auth+encryption for that key; no account system.
- **Multi-tenant:** No.
- **Encryption:** Genuinely P2P — the DHT/relay is only used for peer discovery, not data-carrying; once connected, traffic flows directly between peers, encrypted in "secure" mode with keys neither a relay nor third party holds. **Note: `secure` defaults to `false`** in the JS API example shown in the README, so E2E encryption may need to be explicitly enabled.
- **P2P: Yes** — this is holesail's core design principle ("truly peer-to-peer... No port forwarding, servers or configuration required").
- **Architecture:** Thin CLI/library wrapper around the Holepunch/Pear DHT + hole-punching stack, positioned as a P2P-first alternative to relay-based tunnels.
- **Notable limitations:** Not usable for classic "stable public HTTPS website" use cases; will generally fail on symmetric-NAT/strict-proxy corporate networks (architectural consequence of the design, not tied to a specific GitHub issue); encryption appears opt-in rather than default.
- **Sources:** github.com/holesail/holesail (README), holesail.io, docs.holesail.io

## 20. iroh-based tunnels: dumbpipe (n0-computer/dumbpipe) + community projects
**dumbpipe:**
- **Language:** Rust. **License: MIT OR Apache-2.0** (dual-licensed, standard Rust-ecosystem pattern — confirmed by reading both `LICENSE-MIT` and `LICENSE-APACHE` directly; GitHub's detector shows "NOASSERTION" only because of the two-file setup, not because there's no license).
- **Stars:** ~783. **Last release:** v0.39.0 (2026-06-15). **Last commit:** 2026-09-25 (today). **Maintenance: Active.**
- **Transport:** QUIC via the `iroh` Rust crate — automatic NAT hole-punching, falling back to a relay if hole-punching fails; connections identified by 256-bit "endpoint IDs" (public keys), not IP addresses; TLS 1.3-native (QUIC).
- **443+proxy:** No HTTP_PROXY/CONNECT support found, and architecturally unusual for a QUIC/UDP-first hole-punching tool (though iroh's relay fallback can run over HTTPS-compatible ports per iroh's own general docs — **not independently re-verified for dumbpipe specifically here**).
- **HTTPS shares:** Not applicable — dumbpipe is framed as "netcat over iroh," a generic point-to-point utility, not an HTTP-vhost/ACME product.
- **TCP:** Yes (`listen-tcp`/`connect-tcp`, plus Unix sockets via `listen-unix`/`connect-unix`). **UDP: no explicit raw-UDP-port-forwarding subcommand found** (the transport itself is UDP-based QUIC, but that's distinct from forwarding an arbitrary external UDP service).
- **Auth:** Identity/ticket-based — the listener prints a ticket (256-bit public endpoint ID + relay/address hints); anyone holding it can connect. No password/account layer.
- **Multi-tenant:** No — point-to-point pipe tool.
- **Encryption: Explicitly E2E** — the README favorably contrasts itself with `tty-share`'s public server, noting that server "is not end-to-end encrypted" (implying dumbpipe's connections are); matches iroh's general architecture where relay nodes (used only when hole-punching fails) forward already-encrypted QUIC packets they cannot decrypt.
- **P2P: Yes** — core design: direct hole-punched QUIC whenever possible, relay fallback only when needed.
- **Architecture:** A deliberately "dumb"/minimal CLI example wrapping the `iroh` crate to forward TCP ports, Unix sockets, or raw stdio over a hole-punched/relay-assisted QUIC connection between two endpoint identities; demoed use cases include ffmpeg video streaming and tty-share terminal sharing.
- **Notable limitations:** No HTTP-vhost/subdomain/ACME layer (out of scope by design); no explicit UDP-service forwarding; being an "example" project first, has less production tooling (no web UI, no multi-tenant auth) than purpose-built products.

**Community iroh-tunnel projects found** (as item 20 specifically requested):
- **naicoi92/iroh-tunnel** — Rust, Apache-2.0, ~3 stars, pushed 2026-09-16, described as **"P2P port-forwarding tunnel (TCP/UDP) via Iroh"** — notably claims explicit UDP forwarding (unlike dumbpipe's TCP/Unix-socket-only subcommands), but given its tiny (3-star) footprint this claim was only checked at the repo-description level, not deep-dived.
- **datum-cloud/app** — Rust, AGPL-3.0, ~15 stars, backed by a company (Datum Cloud), **"A desktop app for safely exposing local services on the Internet via Iroh tunnels using QUIC"** — a productized/GUI take on the same iroh hole-punching approach, pushed 2026-09-14.
- No other iroh-based tunnel/port-forward projects with meaningful independent traction were found (remaining search hits were single-digit-star forks, Sandstorm-specific tools, or Homebrew taps).
- **Sources:** github.com/n0-computer/dumbpipe (README, LICENSE-MIT, LICENSE-APACHE), github.com/naicoi92/iroh-tunnel, github.com/datum-cloud/app

---

## ADDED (bonus, discovered organically via `gh search repos` while resolving other items — not from the required list)

**ADDED 1 — opentunnel (slopus/opentunnel).** TypeScript/Node.js, MIT, ~60 stars, last push 2026-02-05. Distinctive 3-tier architecture: a registration server (issues NaCl/TweetNaCl-based auth tokens), a public-facing frontend server (TLS, typically 443), and a backend server (accepts your local tunnel connection) — all coordinated via a **NATS message bus** for shortest-path routing. Automatic Let's Encrypt cert issuance on tunnel start; explicitly claims end-to-end encryption; its own README directly (and pointedly) compares itself to ngrok ("closed source"), PageKite ("does not support clustering, allows unencrypted traffic" — their claim, unverified by me), and frp ("works only for exposing something... having server that connected directly to the internet" — also their claim). Single-tier MIT, no commercial edition. Notable limitation: self-hosting requires operating a NATS cluster — materially higher ops complexity than a single binary. Source: github.com/slopus/opentunnel.

**ADDED 2 — underpass (cjdenio/underpass).** Go, **license: NONE (no LICENSE file at all — GitHub reports `license: null`)**, ~78 stars, last push 2022-05-03 (**unmaintained, 4+ years**). Minimal self-hostable ngrok-style subdomain tunnel; self-documented limitation: "No WebSocket support." Worth flagging for this review specifically because of the license gap: a public, star-collecting GitHub repo with **zero license file** means all rights are legally reserved by default, despite looking like an open-source project — a trap distinct from (but related to) the AGPL/open-core patterns seen elsewhere in this survey. Source: github.com/cjdenio/underpass.

**ADDED 3 — MekongTunnel (MuyleangIng/MekongTunnel).** Go, MIT, ~37 stars, last push 2026-04-24 (~5 months ago, the freshest of these three). SSH-remote-port-forwarding based (same family as sish/portr), "One command to get a public HTTPS URL for your local app." Small/sporadic but properly licensed and actively touched. Source: github.com/MuyleangIng/MekongTunnel.

---

## Comparison Table

| # | Item | Lang | License | Transport | 443+proxy OK? | HTTPS subdomain+ACME? | TCP/UDP? | E2E encrypted? | P2P? | Maintained? |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | frp | Go | Apache-2.0 | TCP+TLS/KCP/QUIC/WS | Y (proxyURL, tcp-mode only) | Y subdomain / N ACME (BYO cert) | Y/Y | N (relay-term; opt-in extra layer) | Y (XTCP) | **Active** |
| 2 | rathole | Rust | Apache-2.0 | TCP(plain)/TLS/Noise/WS | P (443 possible) / Y (proxy=) | N (no HTTP layer at all) | Y/Y | N (plaintext by default) | N | **Sporadic** (no release since 2023) |
| 3 | bore | Rust | MIT | TCP only | P (separate ports) / N | N/N | Y/N | **N — unencrypted by default** | N | **Sporadic** |
| 4 | tunnelto | Rust | MIT | WS+TCP, TLS default | Unk | Y subdomain / Unk ACME | Y/N | N (relay-term) | N | **Unmaintained** (since 2022) |
| 5 | wstunnel | Rust | BSD-3-Clause | WS/HTTP2/HTTP3-WebTransport | Y / **Y (`--http-proxy`)** | N (not an HTTP-vhost tool) | Y/Y | N (relay-term) | N | **Active** |
| 6 | chisel | Go | MIT | SSH-over-WS/HTTP | Y / **Y (CONNECT or SOCKS5)** | P (single backend) / **Y ACME (LE, `--tls-domain`)** | Y/Y | N (relay-term) | N | **Active** |
| 7 | sish | Go | MIT | SSH | P (separate SSH port) / N | Y subdomain / Y ACME (inferred) | Y/N | P (SNI-passthrough mode only) | N | **Active** |
| 8a | inlets (OSS) | — | **repo gone (404)** | — | — | — | — | — | — | **Discontinued** |
| 8b | inlets-pro | Unk (source private) | **None/EULA — closed-source commercial** | Unk | Unk | Y marketed / Unk ACME | Y/Reported | Unk | N | **Active (commercial)** |
| 9 | Pangolin+newt+gerbil | TS+Go | **AGPL-3.0 / Fossorial Commercial (open-core)** | WSS(control)+WireGuard(data) | P (control only, UDP data plane) / Unk | Y subdomain / Y auto-SSL | Y/Y | P (own-stack only, not 3rd-party-blind) | **Y** | **Active** |
| 10a | zrok | Go | Apache-2.0 | OpenZiti overlay | P (routers on 443 common) / Unk | Y / Unk ACME | Y/Y | **Y — even zrok's own servers can't read it** | Y (when possible) | **Active** |
| 10b | OpenZiti | Go | Apache-2.0 | Own zero-trust mesh overlay | P | N/A (lower-level than HTTP) | Y/Y | **Y (libsodium, by design)** | P (mesh routing, not classic hole-punch) | **Active** |
| 11 | boringproxy | Go | MIT | TLS/SNI proxy (token auth) | Unk | Y auto-HTTPS (marketed) / Unk type | P/N | N (relay-term) | N | **Unmaintained** (site DNS dead) |
| 12 | nps | Go | GPL-3.0 | TCP | N (not found) | Y subdomain / N ACME (manual certs) | Y/Y | N (relay-term) | P (listed, undetailed) | **Unmaintained** (despite 34k★) |
| 13 | piko | Go | MIT | HTTPS reverse proxy | Y / Unk | Y (+header-based alt to wildcard) / Unk | P (needs "Piko forward")/N | N (relay-term) | N | **Active** |
| 14 | portr | Go | AGPL-3.0 | SSH | Unk | Y auto-HTTPS / Unk ACME | Y/N | N (relay-term, has inspector) | N | **Active** |
| 15 | localtunnel server | JS | MIT | TCP | N / N | Y subdomain / **N ACME (BYO nginx)** | N/N | N (relay-term) | N | **Unmaintained** |
| 16 | pagekite | Python | AGPL-3.0 | Custom multiplexed relay | Unk (historically yes) | Y subdomain / dual "E2E or wildcard TLS" mode | Y/N | **Dual (configurable)** | N | **Sporadic** |
| 17 | gost | Go | MIT | tcp/tls/ws/h2/quic/kcp/ssh/grpc/… (huge list) | Y / **Y (proxy-chain)** | P (not ACME-automated) | Y/Y | N (relay-term) | N | **Active** |
| 18 | tunnelmole | TS | client MIT / **server AGPL-3.0** | WS | Unk | Y subdomain / **N ACME (BYO nginx)** | N/N | N (relay-term) | N | **Sporadic** |
| 19 | holesail | JS | AGPL-3.0 | Holepunch/Pear DHT (Noise) | **N (P2P-first, architecturally incompatible)** | N (not HTTP-vhost) | Y/Y | **Y (P2P, opt-in "secure" mode)** | **Y** | **Active** |
| 20a | dumbpipe | Rust | MIT OR Apache-2.0 | QUIC (iroh) | N (UDP-first) | N | Y (TCP+Unix)/N (no UDP fwd cmd) | **Y (relay-blind)** | **Y** | **Active** |
| 20b | naicoi92/iroh-tunnel (community) | Rust | Apache-2.0 | QUIC (iroh) | N | N | Y/Y (claimed) | Y (iroh-inherited) | Y | Active (tiny, 3★) |
| ADD1 | opentunnel | TS | MIT | TLS, NATS-coordinated | Unk | Y / **Y ACME (LE)** | Y/N | Y (claimed) | N | Sporadic |
| ADD2 | underpass | Go | **None (no LICENSE file)** | TCP/subdomain | Unk | Y subdomain / Unk | Unk | N (relay-term) | N | **Unmaintained** |
| ADD3 | MekongTunnel | Go | MIT | SSH | Unk | Y auto-HTTPS / Unk | Unk | N (relay-term) | N | Sporadic |

---

### Key cross-cutting observations for the literature review
1. **Open-core/commercial traps:** inlets-pro (fully closed, EULA-gated, the free "inlets" core is simply gone) and Pangolin (AGPL-3.0 + proprietary "Fossorial Commercial License" per-file) are the two clearest open-core cases; tunnelmole splits license by component (MIT client / AGPL server).
2. **"Stars ≠ maintained" is dramatic here:** nps (~34k★, no commit since May 2024) and boringproxy (dead marketing domain) are the starkest examples; rathole (~14k★) hasn't tagged a release since October 2023.
3. **Only two items make a strong, specific "relay cannot read your traffic" claim backed by their own docs:** OpenZiti/zrok (libsodium E2E, explicitly "even zrok servers" can't read it) and the iroh-based tools (dumbpipe, community iroh-tunnel) via relay-blind QUIC. Everything else in the classic reverse-proxy family (frp, rathole, bore, tunnelto, wstunnel, chisel, piko, portr, localtunnel, tunnelmole, nps, gost) is relay-terminated by default.
4. **P2P/hole-punch tools (holesail, dumbpipe/iroh) are architecturally the worst fit for the "outbound TCP 443 + HTTP CONNECT proxy only" constraint**, since they're UDP/DHT-rendezvous-first by design — the opposite profile from chisel/wstunnel/frp/gost, which were explicitly built to disguise themselves as ordinary HTTPS traffic through corporate proxies.
5. **Built-in ACME automation is rarer than expected:** only chisel (confirmed, Let's Encrypt HTTP-01-style via `--tls-domain`) and arguably sish/opentunnel (inferred/claimed) clearly automate certificates; frp, localtunnel, and tunnelmole all explicitly require you to bring your own certificate/reverse proxy.

**Known gaps (marked "unknown" rather than guessed, per instructions):** exact ACME challenge type for most items; explicit HTTP_PROXY support for sish/portr/piko/nps/pagekite/zrok; the historical "why" behind inlets OSS's disappearance; boringproxy's UDP support. These were unverifiable within this session's WebFetch/WebSearch results (WebSearch quota was exhausted mid-task; a few docs sites — zrok, gost's auth pages, boringproxy.io — either 404'd or returned empty/JS-only content to WebFetch).


