<!-- Raw research fact sheet produced by a research agent on 2026-09-25 for docs/literature-review.md. Kept as source material; not edited. -->


# Fact Sheet: Overlay Networks, Mesh VPNs, and P2P Connectivity Substrates
Verified 2026-09-25. Research method: one sub-agent (Tailscale/Headscale) ran independently and exhausted this session's shared WebSearch quota (200 calls) almost immediately; every other item below was verified by me directly via WebFetch on official docs/GitHub/crates.io pages, the GitHub CLI (`gh`, authenticated, used to pull exact `tag_name`/`published_at` from the Releases API and raw LICENSE file bytes), and the crates.io JSON API. Where a WebFetch AI-summary and a direct `gh api`/`gh release view` call disagreed on a date, I trusted the direct API call (this caught at least two summarizer errors, on OpenZiti's and Netmaker's release years). Every "unknown" or hedged claim below is genuinely unverified, not a guess.

---

## 1. Tailscale and Headscale

### Tailscale
- **Language / license / closed parts**: Go. Client and CLI (`tailscaled`, `tailscale`) and the DERP server binary (`cmd/derper`) are **BSD-3-Clause** (https://github.com/tailscale/tailscale/blob/main/LICENSE). Closed: the hosted coordination/control server, the admin console/web dashboard, and operation of the hosted DERP fleet as a managed service (https://tailscale.com/opensource). Windows/macOS GUI wrappers are also closed; Linux/Android GUI and tailscaled/CLI are open.
- **Control plane**: Not open source, not self-hostable (confirmed on Tailscale's own open-source page). Headscale exists specifically to fill this gap.
- **Data plane**: WireGuard.
- **Relay (DERP)**: "Designated Encrypted Relay for Packets." Protocol switches inside TLS from HTTP to a custom bidirectional binary protocol, never decrypting inner WireGuard traffic (https://github.com/tailscale/tailscale/blob/main/cmd/derper/README.md). Transport/port: **HTTPS on TCP 443** (also 80), plus UDP 3478 for STUN (direct-path discovery only, not the relay path).
- **443 + HTTP proxy**: Yes by design. `tailscale.com/net/tshttpproxy` wraps `http.ProxyFromEnvironment` plus OS proxy lookups; the control protocol (TS2021) explicitly falls back from port 80 to **HTTPS on 443 "for proxy compatibility"** (https://pkg.go.dev/tailscale.com/control/controlhttp). Proxy env vars must be set in the daemon's own environment, not the user's shell (GitHub issue #10235, closed as working as intended). One open gap: exit-node data traffic on Windows does not fully respect the configured proxy (issue #17698, open).
- **NAT traversal**: STUN plus a custom, non-IETF-compliant ICE-like negotiation, plus UPnP/NAT-PMP/PCP via the `portmapper` package. Published birthday-paradox hard-NAT numbers (one side hard NAT, ~100 probes/sec): 174 probes to 50% success, 256 to 64%, 1024 to 98%, 2048 to 99.9%; when **both** sides are hard NAT, success falls to about 0.01% after 20 seconds (https://tailscale.com/blog/how-nat-traversal-works).
- **Public https publish**: Yes, **Funnel**. Dedicated georeplicated Funnel relay/ingress nodes (separate from DERP), TCP proxy to the device, ports limited to 443/8443/10000, `https://<device>.<tailnet>.ts.net` (https://tailscale.com/kb/1223/funnel).
- **Rust**: Official experimental `tailscale-rs`, published as the `tailscale` crate on crates.io (v0.6.1, 2026-09-18, BSD-3-Clause, GitHub Trusted Publishing verified), explicitly preview-quality with incomplete NAT traversal (https://crates.io/crates/tailscale). Unofficial third-party crates also exist (`libtailscale`, `tailscale-localapi`).
- **Self-host effort**: Not fully self-hostable (closed control plane); substitute is Headscale, optionally with a self-hosted `derper`.
- **Maintenance**: Active. Latest **v1.102.4, 2026-09-10** (https://github.com/tailscale/tailscale/releases).

### Headscale
- **Language / license**: Go, **BSD-3-Clause**, no closed parts found (https://github.com/juanfont/headscale/blob/main/LICENSE).
- **Control plane**: Yes, fully open and self-hostable (it IS the control plane).
- **Self-host components**: headscale binary, a database (SQLite is the supported default; "using Postgres is highly discouraged... only supported for legacy reasons," per `config-example.yaml`), optional TLS/reverse proxy, optional embedded DERP server. No official web admin UI (community projects fill this gap) (https://headscale.net/stable/about/faq/).
- **Relay**: Ships its own embedded, self-hostable DERP server (same wire protocol as Tailscale's, disabled by default) or can point at Tailscale's/custom DERP maps (https://headscale.net/stable/ref/derp/).
- **Public https publish**: No. Funnel is explicitly not implemented; a feature request (issue #1040) was closed "not planned" (https://github.com/juanfont/headscale/issues/1040).
- **Rust**: None, Go only.
- **Maintenance**: Active. Latest **v0.29.4, 2026-09-23** (https://github.com/juanfont/headscale/releases).

---

## 2. NetBird
- **Language**: Go.
- **License**: Split. **BSD-3-Clause** for most of the repo; **AGPL-3.0-only** specifically for the `management/`, `signal/`, `relay/`, and `combined/` directories (verified byte-for-byte via the raw LICENSE file: https://github.com/netbirdio/netbird/blob/main/LICENSE).
- **Control plane**: Open source and self-hostable (management + signal + relay + dashboard); NetBird also sells a hosted cloud version.
- **Data plane**: WireGuard.
- **Relay**: Two generations. Modern relay (`*.relay.netbird.io`, clients v0.36.0+) uses **WebSocket over TCP/443 and QUIC over UDP/443 simultaneously**, taking whichever succeeds first (UDP is an optimization; falls back to WS-over-TCP/443). Legacy relay (`turn.netbird.io`, pre-v0.29.0 clients) is a standard **coturn**-based TURN server on UDP 80/443 and TCP 443 to 65535 (https://docs.netbird.io/about-netbird/ports-and-firewalls).
- **443 + HTTP proxy**: Not explicitly documented either way. The modern relay's WebSocket-over-TCP/443 design is architecturally proxy-friendly, but no NetBird doc or issue confirming HTTP CONNECT proxy support was found.
- **NAT traversal**: ICE via `pion/ice` plus STUN (`stun.netbird.io`, UDP 80/443/3478/5555) (https://docs.netbird.io/about-netbird/how-netbird-works). No published success-rate numbers found.
- **Public https publish**: Partial. Docs reference a self-hosted "Reverse Proxy" feature with auto-TLS; exact mechanism/relation to the relay infrastructure not fully documented in what I could fetch.
- **Rust**: None, pure Go.
- **Self-host effort**: management server + signal server + relay server (or legacy coturn) + dashboard, commonly deployed via Docker Compose.
- **Maintenance**: Active. Latest **v0.79.0, 2026-09-18** (https://github.com/netbirdio/netbird/releases).

---

## 3. Firezone
- **Language**: connlib, gateway, and clients are **Rust**; the portal is **Elixir/Phoenix**; mobile clients also use Swift (iOS/macOS) and Kotlin (Android).
- **License**: Split, confirmed via raw LICENSE bytes. Root of repo (including the Rust data plane) is **Apache-2.0**. The `elixir/` directory (the portal/control plane) is **Elastic License 2.0**, a source-available license that is NOT OSI-approved open source (it restricts, among other things, offering the software as a competing hosted service) (https://github.com/firezone/firezone/blob/main/LICENSE, https://raw.githubusercontent.com/firezone/firezone/main/elixir/LICENSE). This is an open-core-like split worth flagging even though it isn't AGPL or BSL by name.
- **Control plane**: Source-visible and self-hostable for your own use, but under a non-OSI, field-of-use-restricted license (Elastic License 2.0), not a permissive/copyleft license.
- **Data plane**: WireGuard, via connlib.
- **Relay**: STUN assists direct Client-to-Gateway connection; when that fails, the Relay implements the **TURN** protocol (RFC 8656-style) as a middleman that cannot decrypt the WireGuard payload. "34 relay clusters worldwide," hosted on Microsoft Azure by Firezone (https://www.firezone.dev/kb/architecture/core-components, https://www.firezone.dev/kb/architecture/tech-stack). Exact listening port was not confirmed in the docs I could fetch (standard TURN commonly uses 3478, with TURNS-over-443 possible; not confirmed for Firezone specifically).
- **443 + HTTP proxy**: Not documented either way in what I could fetch.
- **NAT traversal**: ICE + STUN via connlib's `snownet` component; connections "typically ready in 200ms or less" (a latency figure, not a success-rate percentage). No numeric success rate found.
- **Public https publish**: No equivalent found. Firezone is resource-access-control oriented (authorized clients to specific resources), not a general public-web-publishing tool.
- **Rust reusability**: connlib is Rust but I could not confirm it is published as a standalone crate on crates.io in this session (the `connlib-client-shared` crates.io page did not return usable content); architecturally it looks like an internal workspace crate consumed via FFI/UniFFI bindings by the mobile/desktop clients rather than a public reusable library.
- **Self-host effort**: portal (Elixir) + gateway (Rust) + relay (Rust, or rely on Firezone's hosted relays) + database.
- **Maintenance**: Very active, per-component release trains. Latest as of today: **gateway-1.6.2, gui-client-1.5.18, headless-client-1.5.13, android-client-1.5.15, apple-client-1.5.21, all 2026-09-24** (https://github.com/firezone/firezone/releases).

---

## 4. Defguard (Rust)
- **Language**: Rust.
- **License**: Open-core. **AGPL-3.0** for the core (explicitly excluding `crates/defguard_core/src/enterprise`), a separate proprietary **Enterprise License** for the enterprise directory (https://github.com/DefGuard/defguard, per repo README).
- **Control plane**: Core is open source and self-hostable; enterprise features (e.g. real-time SIEM streaming) are a closed add-on.
- **Data plane**: WireGuard.
- **Relay / NAT traversal**: No relay or DERP/TURN-style fallback found; architecture emphasizes an "Isolated Control Plane" with no direct internet exposure by default, and connectivity relies on direct WireGuard through gateways rather than a relay network.
- **443 + HTTP proxy**: Not found/documented.
- **Public https publish**: Partial, via the separate **Edge** component, described as a "public-facing entry point exposing selected services" (self-hosted by the operator, not a vendor-hosted Funnel-equivalent). Underlying transport not confirmed in detail.
- **Rust reusability**: Whole project is Rust; no standalone published crates.io library components were confirmed in this session (appears to be application code: core, gateway, edge, each a separate repo/binary).
- **Self-host effort**: core + optional gateway(s) + optional Edge + database.
- **Maintenance**: Active. Latest **v2.1.0, 2026-09-04** (https://github.com/DefGuard/defguard/releases).

---

## 5. Nebula (originally Slack)
- **Language**: Go.
- **License**: **MIT** (https://github.com/slackhq/nebula, LICENSE file confirmed).
- **Control plane**: "Lighthouse" nodes handle discovery/coordination, and there is no vendor-hosted component at all: Nebula is fully self-hosted by design, unlike Tailscale/NetBird/Firezone which offer a hosted option.
- **Data plane**: A custom, certificate-based encrypted tunnel protocol (not WireGuard). I could not independently re-confirm the exact handshake framework in this session (FAQ.md returned 404, and the README excerpt I could fetch didn't cover it); it is commonly described elsewhere as Noise-based, but treat that specific claim as unverified here.
- **Relay**: `relay_manager.go` exists in the codebase, and lighthouses "optionally use UDP hole punching." Whether relay nodes forward full encrypted tunnel traffic (not just handshake/discovery assistance) was ambiguous in what I could verify: a GitHub issue (#1489) characterization suggested relaying "does not proxy full traffic," which is at odds with how Nebula's relay feature is commonly described elsewhere. I was not able to resolve this conflict with a primary source in this session, so treat the exact relay traffic-forwarding behavior as unconfirmed. What is confirmed: relay, like the rest of Nebula, is **UDP**, with no TCP or port-443 fallback found anywhere (README, GitHub issues #1014 and #1489 all point to UDP-only).
- **443 + HTTP proxy**: No evidence of support. Feature requests for TCP/port-forwarding-style connectivity are open, unresolved issues, not shipped features (issue #1014).
- **NAT traversal**: UDP hole punching, lighthouse-assisted. No published success-rate numbers found.
- **Public https publish**: No evidence of any such feature.
- **Rust**: None, pure Go.
- **Self-host effort**: Minimal: your own lighthouse node(s) plus the participating nodes; no database or web UI required.
- **Maintenance**: Active. Latest **v1.11.2, 2026-09-22** (https://github.com/slackhq/nebula/releases).

---

## 6. ZeroTier
- **Language**: C++ (core agent).
- **License, corrected from the "BSL" premise**: Not literally a Business Source License (no change-date/sunset clause). It's a **split license**, confirmed by reading both license files directly:
  - The **"ZeroTier Agent"** (the actual client most users run: `node/`, `osdep/`, `service/`) is **MPL-2.0**, genuinely OSI-approved open source (https://github.com/zerotier/ZeroTierOne/blob/dev/LICENSE.txt).
  - The **"Controller" and other components** under `nonfree/` are licensed under a proprietary **"ZeroTier SOURCE-AVAILABLE LICENSE, Version 1.0, Copyright 2025"**: source-visible but restricted to non-commercial use (personal, academic, or ≤30-day evaluation) without a separate paid commercial license. "Commercial Use" is defined broadly (any for-profit, government, or even non-profit organizational use, or "offering paid or unpaid services powered by the Software") (https://github.com/zerotier/ZeroTierOne/blob/dev/nonfree/LICENSE.md). This is a real 2025 relicensing event restricting the self-hosted network Controller, just not technically "BSL."
- **Control plane**: Partially open. Agent is open; self-hosting your own network Controller (to avoid ZeroTier Central / my.zerotier.com) requires accepting the non-commercial restriction or buying a commercial license.
- **Data plane**: Custom protocol (not WireGuard), default port UDP/9993.
- **Relay**: Root servers provide "free (but slow) relaying" when P2P fails; **moons** are user-deployable federated roots and are technically self-hostable, but current docs carry an explicit warning that "private moons are no longer recommended for deployment and are not supported under the ZeroTier Service Level Agreement (SLA)" (https://docs.zerotier.com/roots/), which is a notable and somewhat surprising finding.
- **TCP fallback on 443**: **Unconfirmed.** Despite dedicated searching of docs.zerotier.com (`/roots/`, `/faq/`, troubleshooting index) and the ZeroTierOne source tree, I could not find or confirm the commonly-cited claim that ZeroTier disguises a TCP fallback as HTTPS on port 443 when UDP is blocked. This may still be true (it has circulated in community/support content historically) but I am flagging it explicitly as not verified via the primary sources I could reach in this session, rather than asserting it.
- **NAT traversal**: Own UDP hole-punching implementation plus root/moon relay fallback. No published success-rate numbers found this session.
- **Public https publish**: No evidence of a Funnel-equivalent feature.
- **Rust**: None, C++ core.
- **Self-host effort**: Agent is trivial to self-host; a fully independent self-hosted network (Controller + roots) is legally and operationally discouraged by ZeroTier's own current guidance.
- **Maintenance**: Latest **1.16.2, 2026-05-28** (https://github.com/zerotier/ZeroTierOne/releases), about four months old as of today, a noticeably slower cadence than most other projects in this sheet.

---

## 7. innernet (Rust, Tonari)
- **Language**: Rust.
- **License**: **MIT** (https://github.com/tonarino/innernet).
- **Control plane**: `innernet-server`, open source, self-hosted by design; there is no vendor-hosted alternative at all.
- **Data plane**: WireGuard.
- **Relay**: None found. The README describes direct WireGuard peer connections only; no TURN/relay fallback is documented.
- **443 + HTTP proxy**: Not applicable, since there is no relay path to tunnel through a proxy; it's raw WireGuard UDP.
- **NAT traversal**: Endpoints are exchanged via the coordination server; no dedicated hole-punching or relay system beyond what WireGuard itself provides. No success-rate numbers (not applicable, no traversal-assist system).
- **Public https publish**: No evidence of any such feature.
- **Rust reusability**: Project is Rust throughout, but structured as CLI + server binaries; I found no evidence it's published as reusable library crates on crates.io.
- **Self-host effort**: Just `innernet-server` plus WireGuard tooling; no database or extra services documented.
- **Maintenance**: Contrary to an initial assumption that this project might be abandoned, it is **actively maintained**: README carries an "Actively Maintained" badge, and the latest release is **v2.0.0, 2026-07-02** (https://github.com/tonarino/innernet/releases), about 400 commits, 81 open issues.

---

## 8. Netmaker
- **Language**: Go.
- **License**: **Apache-2.0** for the core; a separate license applies to the `pro/` directory (open-core split). I could not fetch the exact text of the pro-tier license in this session (https://github.com/gravitl/netmaker).
- **Control plane**: Core is open source and self-hostable; "Pro"/enterprise tiers are separately licensed.
- **Data plane**: WireGuard.
- **Relay / restrictive-network features**: STUN and TURN servers (added v0.18.0) assist NAT traversal. A dedicated **"TCP Proxy / WSS Uplink"** feature for restrictive network environments was introduced in the official v1.7.0 release notes (https://github.com/gravitl/netmaker/releases/tag/v1.7.0), which strongly suggests WebSocket-Secure-over-443 connectivity for hard networks, though I could not reach a dedicated docs page (docs.netmaker.io is mid-migration to learn.netmaker.io and several guessed URLs 404'd) to confirm the exact port/proxy behavior beyond the release note itself. As of v0.90.0, the older separate "Relay" and "Remote Access" features were merged into a single **"Gateways"** feature.
- **443 + HTTP proxy**: Not independently confirmed beyond the "TCP Proxy / WSS Uplink" release-note mention above.
- **NAT traversal**: STUN/TURN (`pion`-family libraries commonly used in this space; not independently confirmed for Netmaker specifically). No published success-rate numbers found.
- **Public https publish**: Plausible via "Remote Access Gateways and Clients" plus documented wildcard-DNS-subdomain setup for HTTPS exposure, but I could not confirm whether this means unauthenticated public access (Funnel-style) or authenticated-Netmaker-client-only access.
- **Rust**: None, Go.
- **Self-host effort**: server + message broker/queue + STUN/TURN + DNS configuration + dashboard.
- **Maintenance**: Active. Latest **v1.7.0, 2026-08-31** (https://github.com/gravitl/netmaker/releases), confirmed via the GitHub API directly (an earlier AI-summarized fetch of the same page misread this as 2024; the API date is authoritative).

---

## 9. OpenZiti
- **Language**: Primarily Go. Official SDKs exist for Go, C, Java/Kotlin, Swift, Node.js, C#, and Python; **no official Rust SDK was found**.
- **License**: **Apache-2.0** (https://github.com/openziti/ziti, "Licensed under Apache 2.0" in the README).
- **Control plane**: Controller, open source, fully self-hostable. NetFoundry (the commercial company behind OpenZiti, whose domain now hosts the docs at netfoundry.io/docs/openziti/) offers a hosted/managed alternative, but the OSS controller itself is not restricted.
- **Data plane**: A full overlay "fabric" of routers rather than a classic client-to-client WireGuard tunnel. Confirmed: mutual TLS (mTLS) for identity/authentication and libsodium for the data path. I could not confirm the specific named wire protocol (sometimes referred to elsewhere as a "Ziti Transport Wire Protocol") or explicit QUIC support for router transport via the docs I could fetch this session; treat those specifics as unconfirmed.
- **Relay**: Not a bolt-on relay concept: routing/relaying is inherent to the mesh fabric design itself. Routers can be public (internet-reachable) or "dark" (private, outbound-only connections), which lets a fully outbound-only deployment participate in the fabric.
- **443 + HTTP proxy**: Not confirmed in the docs I could fetch this session (the netfoundry.io-hosted docs pages I tried either redirected to generic landing content or returned empty).
- **NAT traversal**: The architecture largely sidesteps classic STUN/ICE-style hole punching by using outbound-only "dark" routers to join the fabric, rather than dynamically punching through a NAT. No numeric success-rate figures found.
- **Public https publish**: OpenZiti is known elsewhere for a browser-based, client-less access feature ("BrowZer") that would answer this affirmatively, but I was not able to independently verify it via the docs fetched in this session, so treat it as unconfirmed rather than a firm yes.
- **Rust**: None found; no official Rust SDK or crate.
- **Self-host effort**: Controller + at least one router (public or edge) + PKI setup.
- **Maintenance**: Active. Latest **v2.0.6, 2026-09-17** (confirmed via `gh api repos/openziti/ziti/releases/latest`; an earlier WebFetch summary of the HTML releases page had misread this as 2023, the API result is authoritative).

---

## 10. wush (Coder)
- **Language**: Go.
- **License**: **CC0-1.0** (public domain dedication), confirmed via the raw LICENSE file (https://github.com/coder/wush) — an unusual choice for a full application, worth flagging.
- **Control plane**: No persistent coordination server. Wush runs "an in-memory control server on each CLI" and uses Tailscale's `tsnet` package under the hood; peer auth uses x25519 keys exchanged out-of-band via a generated auth code that encodes the server's public key and the sender's private key.
- **Data plane**: WireGuard, via `tsnet`.
- **Relay**: Uses **Tailscale's DERP** relay infrastructure as a fallback for "hard NAT" cases where direct UDP hole punching fails, by way of `tsnet` (this is the same DERP mechanism documented under Tailscale above, not a separate wush-specific relay network).
- **443 + HTTP proxy**: Not independently re-tested for wush; architecturally inherits `tsnet`'s DERP-over-HTTPS/443 behavior since it depends on the same Go library Tailscale itself uses.
- **NAT traversal**: UDP hole punch (via `tsnet`/`wireguard-go`) with DERP fallback. No wush-specific published success-rate numbers found.
- **Public https publish**: No evidence of any such feature (it's a P2P file-transfer/shell tool, not a publishing tool).
- **Rust**: None, Go.
- **Self-host effort**: None required for basic use (rides on Tailscale's public DERP infrastructure by default); could point at a self-hosted DERP map if desired.
- **Maintenance**: Latest **v0.4.1, 2025-01-07** (https://github.com/coder/wush/releases), over a year and a half old as of today, the staleness confirmed by two independent checks in this session; treat as low/no recent active maintenance.

---

## 11. Yggdrasil
- **Language**: Go (requires Go 1.22+).
- **License**: **LGPL-3.0**, with an explicit exception permitting distribution of statically/dynamically linked binaries without requiring "Minimal Corresponding Source" of the linking application (https://github.com/yggdrasil-network/yggdrasil-go).
- **Control plane**: None by design. Fully decentralized, self-arranging encrypted IPv6 overlay; routing/addressing is derived cryptographically, with no coordination server.
- **Data plane**: A custom protocol. I could not independently re-confirm the exact crypto primitives in this session (commonly described elsewhere as NaCl/Curve25519-box-based); treat that specific claim as unverified here.
- **Relay / peering**: No separate "relay server" concept; every peer routes packets for the mesh, more like a small internet than a hub-and-spoke relay. Confirmed supported peering URI schemes, straight from the configuration docs: **`tcp://`, `tls://` (TCP+TLS), `quic://`, and `socks://proxyhost:proxyport/hostname:port`** (SOCKS proxy chaining) (https://yggdrasil-network.github.io/configuration.html). No `ws://`/`wss://` scheme was documented.
- **443 + HTTP proxy**: Nuanced. Yggdrasil explicitly supports peering **through a SOCKS proxy**, which is a proxy mechanism but not literally HTTP CONNECT. A `tls://host:443` peering would look like ordinary TLS traffic to a network observer, but I found no explicit documentation confirming it traverses an HTTP CONNECT proxy specifically.
- **NAT traversal**: Relies on peering with a reachable node (from the public peer list or your own) rather than classic dynamic hole punching. No published success-rate numbers found.
- **Public https publish**: No evidence of any Funnel-equivalent feature.
- **Rust**: None, Go.
- **Self-host effort**: You need at least one publicly reachable peer to join the mesh (use the public peer list, or self-host your own public peer); otherwise the network is fully self-organizing.
- **Maintenance**: Active. Latest **v0.5.14, 2026-06-19** (https://github.com/yggdrasil-network/yggdrasil-go/releases).

---

## 12. iroh (n0-computer)
- **Language**: Rust.
- **License**: Dual **MIT OR Apache-2.0** (https://github.com/n0-computer/iroh; confirmed again via crates.io metadata).
- **Version / 1.0 status**: **iroh 1.0 shipped 2026-06-15** ("Dial Keys, not IPs," https://www.iroh.computer/blog/v1). Current latest is **v1.2.0, released 2026-09-11** (https://github.com/n0-computer/iroh/releases; crates.io shows the same version, indexed 2026-09-09, a normal small propagation lag).
- **Control plane**: Decentralized by default, with a self-hostable centralized option. Node discovery is via **DNS** (a signed record published over HTTPS PUT to a DNS server, by default one operated by n0/"number0," but self-hostable via the `iroh-dns-server` crate) **or** the **Mainline DHT** (BEP 44) for a fully peer-to-peer mode with zero infrastructure (https://docs.iroh.computer/what-is-iroh).
- **Data plane**: QUIC, natively.
- **Relay protocol, in detail**: As of **v0.91.0 (2026-08-01)**, iroh's relay protocol runs **exclusively over WebSocket**: "you can now only communicate to the relay servers using WebSockets," described by n0 as the "last relay wire-level breaking change" (https://www.iroh.computer/blog/iroh-0-91-0-the-last-relay-break). This directly confirms the "WebSocket over HTTPS" premise in the research brief. I could not independently re-confirm the exact default port in the docs fetched this session (commonly expected to be 443 for the hosted relay fleet, since it's WebSocket-over-HTTPS, but I'm flagging the port number itself as not explicitly re-verified live here).
- **443 + HTTP proxy**: Not found. No blog post, doc page, or issue confirming or denying HTTP CONNECT proxy compatibility turned up despite dedicated searching.
- **Hole-punching approach**: Since v0.90, iroh uses **QUIC Address Discovery (QAD)**, replacing STUN. Reflexive addresses arrive as `OBSERVED_ADDRESS` frames inside the normal QUIC handshake/connection (an IETF QUIC extension), rather than via a separate STUN round-trip, and updates are event-driven off QUIC's connection-migration mechanism (https://www.iroh.computer/blog/qad). Reliability work continued in **v0.98.0** ("Getting back to traversing NATs," 2026-04-17), which improved retry/probe handling for off-path validation during multipath NAT traversal (https://www.iroh.computer/blog/iroh-0-98-0-getting-back-to-traversing-nats).
- **Published success-rate numbers**: **None found.** I checked the QAD post and the two NAT-traversal-focused release posts specifically for numeric hole-punch/direct-connection success rates; none is published in any of them.
- **Public https publish**: **No.** iroh is explicitly peer-to-peer only, "a lightweight native library meant to be embedded directly into your application"; it does not expose services to arbitrary web browsers via a public https URL the way Tailscale Funnel does (https://docs.iroh.computer/what-is-iroh).
- **Rust crates**: Extensive and genuinely designed for reuse: `iroh` (core), `iroh-relay`, `iroh-base`, `iroh-dns-server`, plus ecosystem crates `iroh-blobs`, `iroh-gossip`, `iroh-docs`, all published on crates.io.
- **Self-host effort**: Fully optional infrastructure: self-host your own `iroh-relay` and/or `iroh-dns-server`, or run pure DHT-based P2P with none at all. n0 also sells a paid "Iroh Services Pro" plan for a hosted, authenticated relay (https://www.iroh.computer/blog/shared-relays, 2026-09-08).
- **Maintenance**: Very active, close to monthly releases.

---

## 13. rust-libp2p
This is a networking **library**, not a full VPN product, so some fields below are adapted accordingly.
- **Language**: Rust. **License: MIT** (https://github.com/libp2p/rust-libp2p).
- **Circuit relay v2**: Implemented, in the `libp2p-relay` crate.
- **DCUtR (hole punching)**: Implemented, in the `libp2p-dcutr` crate.
- **Transports**: WebSocket (`libp2p-websocket`), WebTransport (`libp2p-webtransport`), and QUIC (`libp2p-quic`) all exist as separate, maintained crates.
- **Maturity**: Used in production by major systems, per the repo's own listed users: **Forest** (Filecoin), **Lighthouse** (Ethereum consensus client), **rust-ipfs**, and **Substrate** (Polkadot).
- **"Control plane" (adapted)**: No built-in centralized service; any relay-v2 or rendezvous-protocol server you deploy is self-hostable by construction, since you write/run it yourself from the library.
- **Data plane**: Noise for encryption (`libp2p-noise`), over TCP, QUIC, WebSocket, or WebTransport depending on configuration.
- **Relay transport + port (adapted)**: Circuit relay v2 runs over whichever transport you configure; a WebSocket-based relay on TCP 443 is architecturally supported but is a deployment choice, not a fixed default the way DERP or NetBird's relay is.
- **443 + HTTP proxy**: Architecturally plausible via the WebSocket transport crate; no documented default or issue thread confirming real-world HTTP CONNECT proxy compatibility was found.
- **Rust reusability**: This is definitionally a Rust crate ecosystem, `libp2p` plus each protocol/transport as its own sub-crate.
- **Self-host effort (adapted)**: Deploy your own circuit-relay-v2 node and/or rendezvous server using the library; there's no packaged "product" to install.
- **Maintenance**: Very active. Latest **v0.57.0**, updated on crates.io **2026-09-11** (https://crates.io/crates/libp2p).

---

## 14. Hoppy Network
Identified after several failed search attempts (DuckDuckGo blocked automated queries with a CAPTCHA both times I tried it, Bing returned unrelated results, and a GitHub repository/org search for "hoppy network" turned up only an unrelated aviation ACARS plugin). A direct guess at `hoppy.network` succeeded:
- **What it is**: A commercial service that assigns devices a **static public IPv4/IPv6 address**, aimed at bypassing CGNAT and other ISP restrictions so people can self-host services or keep a stable address while roaming. It markets itself around "static addresses bind to your device no matter the location" and continuously refreshed routing, explicitly for self-hosting scenarios (https://hoppy.network).
- **Data plane**: **WireGuard** ("ChaCha20 and Poly1305"), per the marketing site. The docs site also separately mentions **Yggdrasil** (covered as item 11) in the context of self-hosting guides, suggesting Hoppy supports or documents both, though the exact relationship between the two was not clear from what I could fetch (https://hoppy.network/docs).
- **License / openness**: **Not disclosed** on the site. It reads as a commercial SaaS product (you run their client to reach their service), not an open-source project; I found "self-hosting guides" for using Hoppy with your own self-hosted apps, not for self-hosting Hoppy's own infrastructure. Mark license, control plane, relay port/protocol, NAT traversal technique, Rust involvement, and maintenance status all as **unknown**: this was explicitly scoped as a brief item and I did not find primary technical documentation (only a marketing site and a shallow docs landing page).

---

## 15. Twingate and Enclave (brief, closed-source; transport/port facts only)

### Twingate
- **License**: Closed-source, proprietary.
- **Architecture**: Confirmed four components: Controller, Clients, Connectors, and Twingate's own Relay infrastructure. The Connector is explicitly described as enabling "direct connections with protected resources without requiring inbound ports" (https://www.twingate.com/docs/architecture), i.e. outbound-only by design.
- **Data plane protocol**: Commonly reported (in Twingate's own past materials and third-party write-ups) to be **WireGuard-based**, but I could not independently confirm this from the docs pages I could fetch in this session (the dedicated network-requirements page returned a 404, and the architecture overview page I could fetch didn't specify the tunnel protocol).
- **443 + HTTP proxy**: Not independently confirmed this session. The outbound-only, no-inbound-ports Connector design is suggestive of proxy-friendliness, but I did not find a docs page explicitly stating HTTP CONNECT proxy support on TCP 443 only egress.

### Enclave (enclave.io)
- **License**: Closed-source, proprietary.
- **Data plane / NAT traversal**: Confirmed from their docs: "Enclave prefers a UDP substrate to build tunnels" but **falls back to TCP** if needed, attempting both simultaneously and using whichever succeeds first. When direct P2P fails (particularly under symmetric NAT), Enclave selects a relay "based on geographic proximity," and both peers connect **outbound to the relay's public TCP endpoint**, authenticated with a 128-bit randomly generated code; the relay cannot decrypt traffic (end-to-end encrypted) (https://docs.enclave.io/concepts/nat-traversal/). Underlying tunnel protocol (WireGuard-based, per general reputation) was not explicitly confirmed in the page I could fetch.
- **443 + HTTP proxy**: Not explicitly confirmed. The relay's "public TCP endpoint" fallback is consistent with the general shape of a 443-friendly design, but no page I fetched stated the exact port or HTTP CONNECT proxy compatibility outright.

---

## Comparison Table

| Item | License | Control plane open? | Data plane | Relay transport + port | 443 + proxy OK? | Public https publish? | Rust? |
|---|---|---|---|---|---|---|---|
| Tailscale | BSD-3-Clause (client); coordination server/admin console/DERP fleet operation closed | No | WireGuard | DERP: custom binary protocol inside TLS, TCP 443 (+80) | Yes by design (one Windows exit-node gap open) | Yes (Funnel, ports 443/8443/10000) | Official experimental crate on crates.io |
| Headscale | BSD-3-Clause | Yes (fully) | WireGuard | Embedded/self-hosted DERP, same protocol, TCP 443 | Inherits client-side behavior above | No (Funnel not implemented) | No |
| NetBird | BSD-3-Clause + AGPL-3.0 (mgmt/signal/relay) | Yes | WireGuard | WebSocket/TCP 443 + QUIC/UDP 443 (modern); coturn TURN (legacy) | Not documented | Partial (self-hosted reverse proxy) | No |
| Firezone | Apache-2.0 (Rust parts) + Elastic License 2.0 (Elixir portal) | Partial (source-available, non-OSI) | WireGuard | STUN + TURN (RFC 8656 style), port not confirmed | Not documented | No evidence found | Yes (connlib, gateway, clients); not confirmed published to crates.io |
| Defguard | AGPL-3.0 (core) + proprietary Enterprise | Yes (core) | WireGuard | None found (direct only) | Not documented | Partial (self-hosted "Edge") | Yes (whole app); no published crates confirmed |
| Nebula | MIT | Yes (always, no vendor option) | Custom (crypto framework unconfirmed) | UDP only, no TCP/443 fallback found; relay traffic-forwarding scope disputed in sources | No evidence | No | No |
| ZeroTier | MPL-2.0 (Agent) + proprietary Source-Available License v1.0/2025 (Controller) | Partial (restricted) | Custom, UDP/9993 default | Root/moon relay; TCP-443-disguise fallback unconfirmed this session | Unconfirmed | No evidence | No |
| innernet | MIT | Yes (always, no vendor option) | WireGuard | None (direct only) | N/A | No evidence | Yes (CLI/server); no published library crates confirmed |
| Netmaker | Apache-2.0 (core) + separate pro/ license | Yes (core) | WireGuard | STUN/TURN; "TCP Proxy / WSS Uplink" mentioned in release notes, details unconfirmed | Partially suggested, not confirmed | Plausible, not confirmed as public-unauthenticated | No |
| OpenZiti | Apache-2.0 | Yes | Mesh fabric, mTLS + libsodium | Inherent to fabric routing; port/proxy unconfirmed | Unconfirmed | Unconfirmed (BrowZer reputed, not verified) | No official SDK |
| wush | CC0-1.0 | N/A (no persistent server; uses tsnet) | WireGuard (via tsnet) | Tailscale's DERP (inherited) | Inherits Tailscale/tsnet behavior, not independently tested | No evidence | No |
| Yggdrasil | LGPL-3.0 (+ linking exception) | N/A (no control plane by design) | Custom (crypto primitives unconfirmed) | No relay concept; mesh routes for itself. Peering over tcp/tls/quic/socks-proxy | SOCKS proxy chaining documented; HTTP CONNECT not confirmed | No | No |
| iroh | MIT OR Apache-2.0 | Yes (decentralized: DNS or DHT), self-hostable | QUIC | WebSocket (confirmed, "relay-only" as of v0.91.0), port not re-confirmed | Not found either way | No (peer-to-peer only) | Yes, extensively (iroh, iroh-relay, iroh-base, iroh-dns-server, +ecosystem) |
| rust-libp2p | MIT | N/A (library; self-deployed) | Noise over TCP/QUIC/WebSocket/WebTransport | Circuit relay v2, transport-dependent (WebSocket/443 possible, not default) | Architecturally plausible, unconfirmed | N/A | Yes (this is the crate ecosystem) |
| Hoppy Network | Unknown (undisclosed, appears commercial) | Unknown | WireGuard (marketing claim); Yggdrasil also mentioned | Unknown | Unknown | Unknown | Unknown |
| Twingate | Closed-source, proprietary | No | Reputed WireGuard, not confirmed this session | Twingate-operated Relay; outbound-only Connector | Not confirmed this session | No evidence (zero-trust access model, not public publishing) | No |
| Enclave | Closed-source, proprietary | No | Not confirmed (UDP-preferred, TCP fallback confirmed) | Relay's "public TCP endpoint," geographic selection | Not confirmed this session | No evidence | No |

---

### Key corrections to the research brief's premises, worth flagging for the lit review
1. **ZeroTier is not on a Business Source License.** The client ("Agent") is MPL-2.0, fully open. Only the Controller and a few other components are under a bespoke, non-sunsetting "Source-Available License v1.0" (2025) that bars commercial use without payment. Functionally open-core, but not BSL by name or mechanism (no future conversion date).
2. **Firezone's Rust data plane (connlib/gateway/clients) is Apache-2.0, but its Elixir control plane/portal is Elastic License 2.0**, a different, non-OSI source-available license. The brief only mentioned checking whether the license "changed"; the more important nuance is that the two halves of Firezone are under two different license families today.
3. **innernet appears actively maintained** (v2.0.0, 2026-07-02, "Actively Maintained" badge), not stale or archived as one might assume for a smaller Tonari-originated project.
4. **wush (CC0-1.0) does look stale**: last release 2025-01-07, confirmed via two independent lookups.
5. Two dates from AI-summarized WebFetch calls were wrong and corrected via direct `gh api`/`gh release view` calls: **OpenZiti's latest release is 2026-09-17, not 2023**, and **Netmaker's v1.7.0 is dated 2026-08-31, not 2024**. This is a good illustration of why the raw API/CLI was used as the tiebreaker throughout this sheet.


