<!-- Raw research fact sheet produced by a research agent on 2026-09-25 for docs/literature-review.md. Kept as source material; not edited. -->

# Rust Ecosystem Fact Sheet — Self-Hosted Tunnel / Remote-Access Tool

Verified live on 2026-09-25 primarily via the crates.io JSON API, the authenticated GitHub API (`gh api`), and targeted docs.rs/README fetches — not from training-data recall. (Note on method: my WebSearch quota was exhausted almost immediately, apparently shared across other concurrent sessions on this account — the `fork`-based parallel research plan also failed on a concurrent-subagent-limit error before it could run. I pivoted to direct `curl`/`gh api` calls against crates.io + GitHub, which turned out to give more precise, citable facts than search snippets would have anyway. A handful of narrow items are flagged below as "not independently re-verified this session" where I'm relying on well-established prior knowledge rather than a fetched source.)

---

## A. Async + HTTP

- **tokio** — async runtime. `1.53.1` (2026-07-20). MIT. Active (tokio-rs). Source: https://crates.io/crates/tokio
- **hyper** — HTTP/1+2 client/server library. `1.11.1` (2026-08-28). MIT. Active (hyperium). Source: https://crates.io/crates/hyper
- **hyper-util** — hyper 1.x glue (client pooling, connectors, service utils). `0.1.21` (2026-09-24, i.e. yesterday). MIT. Very active. Source: https://crates.io/crates/hyper-util
- **axum** — ergonomic HTTP routing/handler framework on hyper/tower. `0.8.9` (2026-04-14). MIT. Active (tokio-rs). Source: https://crates.io/crates/axum
- **h2** — HTTP/2 client+server. `0.4.19` (2026-08-24). MIT. Active. **RFC 8441 extended CONNECT: YES, both server and client**, added in v0.3.8 (Dec 2021), still current:
  - Server: `h2::server::Builder::enable_connect_protocol()` — advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
  - Client: `h2::client::SendRequest::is_extended_connect_protocol_enabled()` — check before use.
  - Shared: `h2::ext::Protocol` — the `:protocol` pseudo-header type (`Protocol::from_static("websocket")`, `as_str()`), attached as a request extension on a CONNECT request.
  - Source: https://docs.rs/h2/latest/h2/ (methods confirmed on `server::Builder`, `client::SendRequest`, `ext::Protocol` docs pages) and https://github.com/hyperium/h2/blob/master/CHANGELOG.md
- **h3 / h3-webtransport** — async HTTP/3 (QUIC) implementation + WebTransport extension, hyperium org. `0.0.8` / `0.1.2` (crates.io, both last published 2025-05-06 — ~16 months stale on crates.io). GitHub repo itself is very active (pushed 2026-09-24, one day before this report). MIT. **Maturity: explicitly experimental** — README states "still very experimental... the API could change," no named production users, stated goal is eventually becoming an internal hyper dependency. Treat as pre-production. Source: https://github.com/hyperium/h3
- **reqwest** — high-level HTTP client (on hyper). `0.13.5` (2026-09-08). MIT OR Apache-2.0. Very active. Proxy support confirmed via docs.rs: `Proxy::http/https/all/custom()`, HTTP-CONNECT tunneling for HTTPS-through-HTTP-proxy, SOCKS5 via `socks` feature, and **system proxy is on by default** — reads `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` (+ lowercase) env vars automatically, more-specific var wins over `ALL_PROXY`, disable via `ClientBuilder::no_proxy()`. Source: https://docs.rs/reqwest/latest/reqwest/struct.Proxy.html

**Gap noted:** no ready-made "WebSocket-over-HTTP/2" crate exists in the ecosystem (see section D).

---

## B. QUIC

- **quinn** — the mainstream Rust QUIC implementation. `0.11.12` (2026-09-14). MIT OR Apache-2.0. Very active (quinn-rs). 0-RTT: supported (`ZeroRttAccepted` future / connect-then-0-RTT API). Unreliable datagrams: supported via the QUIC DATAGRAM extension — `Connection::send_datagram_wait` (`SendDatagram` future), `Connection::read_datagram` (`ReadDatagram` future). Source: https://docs.rs/quinn/latest/quinn/
- **s2n-quic** — AWS's QUIC implementation. `1.89.0` (2026-09-22). Apache-2.0. Very active (aws org). Differentiators per README: pluggable "providers" for granular config, integrates either **s2n-tls** (AWS's own TLS impl) or **rustls**, heavy fuzz/interop/perf testing emphasis. A solid quinn alternative if you want an AWS-backed, s2n-tls-integrated stack; quinn has the larger/broader ecosystem (h3, iroh, etc. build on quinn). Source: https://crates.io/crates/s2n-quic

---

## C. TLS

- **rustls** — pure-Rust TLS. `0.23.45` (2026-09-14). Apache-2.0 OR ISC OR MIT. Very active. **Default crypto provider is `aws_lc_rs`** — confirmed from the published Cargo.toml feature table: `default = ["aws_lc_rs", "logging", "prefer-post-quantum", "std", "tls12"]`; `ring` is available as an explicit opt-in feature instead (`default-features = false, features = ["ring", ...]`). Default set also enables **post-quantum key exchange preference** (X25519MLKEM768-style) and a `fips` feature (aws-lc-rs FIPS mode) exists. Source: https://crates.io/crates/rustls/0.23.45
- **rustls-platform-verifier** — verifies certs using OS-native verification APIs. `0.7.1` (2026-09-24). MIT OR Apache-2.0. Very active (rustls org). OS coverage confirmed from README: **native OS trust store + verifier on Windows, macOS (10.14+), iOS, Android**; on **Linux and WASM it falls back to a bundled webpki verifier** (Mozilla root store), and that fallback explicitly does **not** support CRL-based revocation checking. Source: https://github.com/rustls/rustls-platform-verifier
- **rustls-native-certs** — just loads the OS CA bundle into a rustls `RootCertStore` once at startup (list of roots only, no per-connection OS verifier call, no revocation/EV handling). `0.8.4` (2026-06-01). Apache-2.0 OR ISC OR MIT. Active. Use `rustls-platform-verifier` instead if you want real OS-verifier semantics; use this if you just want the OS root list. Source: https://crates.io/crates/rustls-native-certs
- **tokio-rustls** — async rustls streams for Tokio. `0.26.5` (2026-09-04). MIT OR Apache-2.0. Active, tracks rustls 0.23.x. Source: https://crates.io/crates/tokio-rustls
- **boring / boring2** (BoringSSL bindings): `boring` (Cloudflare) is at `5.2.0` (2026-08-11), Apache-2.0, actively maintained. `boring2` on crates.io shows `4.15.15` (2026-02-13) but is stale/superseded: **the same repo (0x676e67) has renamed itself upstream to `btls`** (docs at docs.rs/btls, docs.rs/btls-sys, docs.rs/tokio-btls, docs.rs/compio-btls; README states "based on a fork of boring"), currently `btls 0.5.6` (2026-04-20), Apache-2.0, repo pushed as recently as today. If picking the fork, target **`btls`**, not the older `boring2` crate name. Sources: https://crates.io/crates/boring , https://crates.io/crates/btls , https://github.com/0x676e67/btls (repo slug shows as boring2 in some search results but content is the btls project)

---

## D. WebSocket

- **tokio-tungstenite** — Tokio binding for tungstenite. `0.30.0` (2026-07-11). MIT. Active (snapview). The de facto standard; has `WebSocketStream::from_raw_socket(stream, role, config)` and `from_partially_read(...)` constructors that wrap an **already-established** `AsyncRead+AsyncWrite` without doing their own HTTP handshake — this is the hook you'd use to layer a WebSocket frame codec on top of a hand-rolled h2 extended-CONNECT stream. Source: https://docs.rs/tokio-tungstenite/latest/tokio_tungstenite/struct.WebSocketStream.html
- **fastwebsockets** — fast, low-level RFC 6455 implementation. `0.10.0` (2026-01-01). Apache-2.0. Maintained by **Deno Land** (denoland org) — used in Deno's own runtime, a strong maintenance signal. Lower-level/faster than tungstenite for hyper 1.x integration. Source: https://crates.io/crates/fastwebsockets
- **hyper-tungstenite** — WebSocket upgrade glue for hyper servers, built on tungstenite. `0.30.0` (2026-07-13). BSD-2-Clause. Active. Source: https://crates.io/crates/hyper-tungstenite
- **WebSocket-over-HTTP/2 (RFC 8441) in the ecosystem: no ready-made crate found.** None of tokio-tungstenite / fastwebsockets / hyper-tungstenite implement RFC 8441 extended-CONNECT negotiation themselves — they're HTTP/1.1-Upgrade-shaped. To get WS-over-h2 today you'd compose it yourself: use h2's `enable_connect_protocol`/`ext::Protocol` (section A) to establish the extended-CONNECT stream, then hand the resulting bidirectional byte stream to `tokio_tungstenite::WebSocketStream::from_raw_socket(...)` for framing. This is a real, buildable path, just not an off-the-shelf crate.

---

## E. Multiplexing

- **yamux** — stream multiplexer over a reliable ordered connection (the one libp2p uses). `0.14.1` (2026-09-21). Apache-2.0 OR MIT. Very active — **now maintained under the `paritytech` org** (Parity Technologies), not directly under `libp2p`, because it's also load-bearing for Substrate/Polkadot; still the crate rust-libp2p depends on. Source: https://github.com/paritytech/yamux
- **Alternatives:** `async-smux` (`0.4.0`, updated 2026-09-05 — very fresh) — async smux-protocol multiplexer. `smux` (`0.2.0`, 2025-07-29) — Rust impl explicitly compatible with the **Go smux protocol** (useful if interop with Go tunnel tools like sing-box/frp matters). Sources: https://crates.io/crates/async-smux , https://crates.io/crates/smux. Note many QUIC-based tunnels skip a mux crate entirely and just use native QUIC streams instead.

---

## F. ACME

- **instant-acme** — low-level async pure-Rust ACME client. `0.8.5` (2026-02-24). Apache-2.0. Active (djc). **DNS-01 supported**: confirmed `ChallengeType` enum has `Http01, Dns01, TlsAlpn01, DeviceAttest01, Unknown` variants — it hands you the challenge/token, you still have to publish the DNS TXT record yourself (e.g. via your DNS provider's API). Source: https://docs.rs/instant-acme/latest/instant_acme/enum.ChallengeType.html
- **rustls-acme** — fully-automatic TLS cert provisioning wired directly into a rustls `ServerConfig`/hyper listener. `0.15.4` (2026-08-11). Apache-2.0 OR MIT. Active. Its whole design point is **TLS-ALPN-01 only** (no port 80, no DNS API needed) — I did not find/re-fetch an explicit DNS-01 code path this session, and it's not part of its stated value proposition, so treat "DNS-01 in rustls-acme" as **not supported** unless you check the current source directly. Source: https://crates.io/crates/rustls-acme
- **acme-lib** — `0.9.1`, last published **2024-01-24**. MIT. **Stale** (~2.5 years). Source: https://crates.io/crates/acme-lib
- **acme2** — `0.5.1`, last published **2022-05-02**. MIT. **Dead** (~4.5 years). Source: https://crates.io/crates/acme2
- Bottom line: **instant-acme (general/DNS-01-capable) + rustls-acme (zero-config TLS-ALPN-01) are the two live options**; acme-lib/acme2 are effectively superseded/abandoned.

---

## G. WireGuard

- **boringtun** (Cloudflare) — userspace WireGuard in Rust. Lib `0.7.1` (2026-05-01), BSD-3-Clause, 7200 stars, 109 open issues. **Maintenance is mixed**: the library crate still gets updates, but the **CLI's last tagged release (`boringtun-cli-0.5.2`) was 2022-07-20** — over 4 years ago — and repo `pushed_at` is 2026-06-29 (3 months stale at time of writing), i.e. slowing but not dead. **No standalone public "Firezone fork" repo found** — a GitHub code search for `boringtun` scoped to the `firezone` org only turns up usage inside the main `firezone/firezone` monorepo (they build on/vendor it rather than publish a separate fork repo). **DefGuard does maintain its own public boringtun fork** (`DefGuard/boringtun`, low-traffic, pushed 2026-09-17). Source: https://github.com/cloudflare/boringtun
- **wireguard-rs** (the original WireGuard-team implementation, `github.com/WireGuard/wireguard-rs`) — **dead**: repo description literally says "Mirror only. Official repository is at https://git.zx2c4.com/wireguard-rs", last pushed 2022-04-11 (~4.5 years). The `wireguard-rs` name on crates.io is squatted (v0.0.0, no repo linked). Don't use this; boringtun effectively superseded it as the maintained userspace implementation. Source: https://github.com/WireGuard/wireguard-rs
- **defguard_wireguard_rs** — "unified multi-platform high-level API for managing WireGuard interfaces" (wraps kernel WireGuard where available, userspace/boringtun-style otherwise). `0.12.1` (2026-09-17). Apache-2.0. Active (DefGuard org). This is the **currently-recommended high-level WG management crate** given wireguard-rs (original) is dead. Source: https://crates.io/crates/defguard_wireguard_rs
- **onetun** — userspace WireGuard **port-forwarder that needs no TUN device / no root / no system network config** — it forwards specific local `host:port` → `peer:port` through a WG tunnel entirely in userspace, rather than routing all system traffic. `0.3.10`, last published **2024-12-01** (~22 months — getting stale, but the mechanism/description is exactly what was asked about). MIT. Source: https://github.com/aramperes/onetun
- **wg-netmanager** — WireGuard mesh network manager. `0.5.1`, last published **2022-02-12**. **Dead** (~4.5 years). MIT. Source: https://crates.io/crates/wg-netmanager

---

## H. TUN / userspace networking

- **tun** (meh/rust-tun) — TUN device creation. `0.8.14` (2026-07-21). **WTFPL** license (unusual — flag for legal review). 685 stars, active. Source: https://crates.io/crates/tun
- **tun-rs** — cross-platform TUN/TAP library. `2.8.11` (2026-09-17, most recent of the two). Apache-2.0. 231 stars, active, high release cadence. More conventional license than `tun`; worth preferring on that basis alone. Source: https://crates.io/crates/tun-rs
- **tun2proxy** — routes TUN traffic to a SOCKS/HTTP proxy. `0.8.3` (crates.io 2026-07-23; repo pushed 2026-09-21). MIT. 1417 stars, very active. Confirmed from README: **Linux, Android, macOS, iOS, Windows**; **HTTP proxy** (none/basic/digest auth) + **SOCKS4/4a/5/5h** (none/user-pass auth) + SOCKS5 UDP + DNS-over-TCP + per-app routing on Android (session info embedded in SOCKS5 username) + a UDP-gateway mode. This is a very complete, directly-reusable building block. Source: https://github.com/tun2proxy/tun2proxy
- **smoltcp** — userspace TCP/IP stack for bare-metal/no-heap use, also usable for tun2socks-style tools. `0.14.0` (2026-08-17). 0BSD. Active (smoltcp-rs). Source: https://crates.io/crates/smoltcp
- **ipstack** — "asynchronous lightweight userspace implementation of TCP/IP stack for Tun device." `1.0.1` (2026-07-12). Apache-2.0. Active (narrowlink org). Source: https://crates.io/crates/ipstack
- **netstack-lwip** — Rust bindings around the **lwIP** C TCP/IP stack, by the `leaf` author (eycorsican). Not on crates.io (GitHub-only). 71 stars, pushed 2026-07-16, active-ish. License not confirmed (check repo LICENSE directly). Used by `leaf`; forked by others for Clash-compatible clients. Source: https://github.com/eycorsican/netstack-lwip
- **ipstack vs netstack-lwip:** ipstack is a smaller, more modern pure-Rust async netstack; netstack-lwip wraps the battle-tested C lwIP stack (more mature TCP edge-case handling, FFI overhead, tied to `leaf`'s ecosystem).

---

## I. NAT traversal / P2P

- **iroh** — QUIC-based P2P connectivity dialed by public key (n0-computer). `1.2.0` (2026-09-09). MIT OR Apache-2.0. Very active. **Hit 1.0.0 on 2026-06-15** — so about 3.5 months of stable-track record as of this report. Source: https://crates.io/crates/iroh
  - **iroh-relay** — same release train, `1.2.0`. Its Cargo.toml (verified directly) depends on **`reqwest 0.13`** for the relay client and **`tokio-websockets 0.13`** for the relay transport — i.e. the relay connection is a **WebSocket**, and because it's built on reqwest, it **inherits reqwest's proxy handling** (system `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` env vars, incl. HTTP CONNECT tunneling, and SOCKS5 with the right feature). I could not find an explicit README paragraph spelling out "runs over 443 through CONNECT proxies," but the dependency graph is strong direct evidence for both the WebSocket-relay and proxy-capable claims. Source: https://raw.githubusercontent.com/n0-computer/iroh/main/iroh-relay/Cargo.toml
- **rust-libp2p** — `0.57.0` (2026-09-11). MIT. Very active. Feature maturity (via sub-crate publish status, all released same day as core):
  - `libp2p-relay` (circuit relay v2) `0.22.0` — shipped.
  - `libp2p-dcutr` (hole punching) `0.15.0` — shipped.
  - `libp2p-quic` `0.14.0` — shipped.
  - `libp2p-websocket` `0.46.0` — shipped, long track record.
  - `libp2p-webrtc` — **only ever published as `0.10.0-alpha`, no stable release exists** — genuinely experimental.
  - `libp2p-webtransport` — **not published as a standalone crate on crates.io at all** (not available as an off-the-shelf transport today).
  - Source: https://crates.io/crates/libp2p and per-crate pages (e.g. https://crates.io/crates/libp2p-webrtc)
- **str0m** — Sans-IO WebRTC library (ICE/DTLS/SRTP), by Martin Algesten (Lookback). `0.23.1` (2026-08-21). MIT OR Apache-2.0. Active. No formal "adopters" list, but README confirms **Lookback uses it in production as a server SFU**, and points to **BitWHIP** (a CLI WebRTC agent) as a real external user. Source: https://github.com/algesten/str0m
- **webrtc-rs** (crate `webrtc`) — async WebRTC implementation. `0.21.0` (2026-09-19). MIT/Apache-2.0. Active (webrtc-rs org). Broader/older/more traditional-API than str0m's sans-IO design. Source: https://crates.io/crates/webrtc
- **STUN/TURN**: `stun` and `turn` crates, both under the webrtc-rs org, both `0.17.2` (2026-07-20). MIT/Apache-2.0. Active. Sources: https://crates.io/crates/stun , https://crates.io/crates/turn

---

## J. Noise / crypto

- **snow** — pure-Rust Noise Protocol Framework. `0.10.0` (2025-07-19). Apache-2.0 OR MIT. Reasonably active (low churn is expected/fine for a finished spec). Source: https://crates.io/crates/snow
- **ring** — `0.17.14` (2025-03-11). Apache-2.0 AND ISC. Source: https://crates.io/crates/ring
- **aws-lc-rs** — `1.18.1` (2026-09-01). ISC AND (Apache-2.0 OR ISC). Very active — **this is now rustls's default crypto provider** (see section C). Source: https://crates.io/crates/aws-lc-rs
- **ed25519-dalek** — `3.0.0` (2026-07-06). BSD-3-Clause. Now lives in the `curve25519-dalek` monorepo; note the major version jump to 3.x is recent — check for API changes vs the long-lived 2.x line if upgrading. Source: https://crates.io/crates/ed25519-dalek
- **x25519-dalek** — `3.0.0` (2026-07-06, same monorepo/release train as ed25519-dalek). BSD-3-Clause. Source: https://crates.io/crates/x25519-dalek
- **age** — file encryption library/format. `0.12.1` (2026-07-14). MIT OR Apache-2.0. Active (str4d/rage). Still self-labels **"[BETA]"** in its own crates.io description despite the 0.12 version. Source: https://crates.io/crates/age

---

## K. SSH

- **russh** — pure-Rust SSH client+server. `0.63.3` (2026-09-09). Apache-2.0. Very active, 1883 stars, now under the `warp-tech` GitHub org. Confirmed from README: **"Russh began as a fork of Thrussh by Pierre-Étienne Meunier, originally extended to provide the SSH backend for Warpgate. It has since been substantially reworked, and is maintained independently."** Confirmed **adopters list** (README "Adopters" section): HexPatch, kartoffels, kty, lapdev, medusa, rebels-in-the-sky, **warpgate**, **Devolutions Gateway**, Sandhole, Motor OS, Cubic VM, ferrissh, Yazi, GitArena, Calagopus, Oryxis. (I did not find Zed editor in this list — don't repeat that claim if you've seen it elsewhere; it wasn't confirmed here.) Source: https://github.com/warp-tech/russh
- **thrussh** — `0.49.0`, last published **2026-08-28** on crates.io. Apache-2.0. **Not simply dead**: the original author continues it, but has moved the repo off GitHub to their own **Pijul forge** (`https://nest.pijul.com/pijul/ssh`) and it gets infrequent-but-real updates there. In practice it's a low-visibility, low-adoption continuation; **russh is the de facto community-maintained, far more widely-adopted successor** — use russh unless you specifically need something thrussh still has. Source: https://crates.io/crates/thrussh

---

## L. Proxy frameworks / servers

- **pingora** (Cloudflare) — "framework to build fast, reliable and programmable networked systems." `0.9.0` (2026-09-09). Apache-2.0. Very active. **SNI-based TCP passthrough / pure L4 routing: no ready-made primitive found.** Its README/feature list is explicitly L7-framed ("HTTP 1/2 end to end proxy," "gRPC and websocket proxying"); the `pingora-proxy` crate's core trait `ProxyHttp` operates on parsed HTTP requests, not raw TLS ClientHellos. I checked the one example that sounded relevant (`pingora-proxy/examples/virtual_l4.rs`) — it's actually a mock/virtual **L4 connector for HTTP testing** (routes on the HTTP Host header), not SNI-sniffing passthrough. `pingora-core` is positioned as a general service framework (not HTTP-only), so a raw-TCP/SNI-sniffing proxy is *buildable* on it, but you'd need to parse the TLS ClientHello's SNI extension yourself — there's no built-in helper for it. **If SNI-based L4 passthrough is a hard requirement, `rust-rpxy-l4` (below) is a more direct fit.** Source: https://github.com/cloudflare/pingora
- **rama** (plabayo) — modular service/proxy framework. `0.4.0` (2026-08-19). MIT OR Apache-2.0. Active. Self-describes as **production-ready** ("Rama is used in production for network security, data extraction, API gateways, routing..."), still pre-1.0 numerically. Confirmed **UA + TLS fingerprint emulation**: "client and proxy HTTP/TLS User-Agent emulation with real-browser profiles," plus **JA3, JA4, PeetPrint TLS fingerprinting** and **JA4H / Akamai HTTP/2 fingerprinting**. Source: https://github.com/plabayo/rama
- **sozu** — "fast, reliable, hot reconfigurable HTTP reverse proxy." `2.2.1` (2026-08-28). **AGPL-3.0** (copyleft — flag for licensing review if you'd redistribute/host it commercially without open-sourcing your own stack). Active (sozu-proxy org). Source: https://crates.io/crates/sozu
- **rpxy** — not on crates.io. `junkurihara/rust-rpxy`: "simple and ultrafast http reverse proxy serving multiple domain names and terminating TLS for http/1.1, 2 and 3." MIT. 778 stars, active (pushed 2026-09-24). Source: https://github.com/junkurihara/rust-rpxy
  - **Notable sibling project, directly relevant to the pingora gap above:** `junkurihara/rust-rpxy-l4` — **"An L4 reverse proxy with protocol multiplexer"** — MIT, 119 stars, active (pushed 2026-09-23). This looks like the closer off-the-shelf match for SNI-based TCP passthrough / L4 routing than pingora. Source: https://github.com/junkurihara/rust-rpxy-l4

---

## M. Existing Rust tunnel/VPN/proxy projects (reuse candidates)

| Project | License | Latest release | Maintenance | Reuse note |
|---|---|---|---|---|
| **wstunnel** (erebe) | BSD-3-Clause | v11.0.0 (2026-09-19) | Very active, 7056★ | Tunnels arbitrary TCP/UDP over WebSocket or HTTP/2, explicitly built to bypass firewalls/DPI, static-binary distribution — closest existing project to "this task's" transport goals; read its WS/H2 transport layer and SOCKS/HTTP-proxy-bypass code first. |
| **rathole** | Apache-2.0 | tag v0.5.0 (2023-10-01, stale) but commits active (2026-08-23) | Active dev, stale releases, 14255★, now under `rathole-org` | Clean reverse-tunnel (frp/ngrok-alternative) control/data-channel protocol and TOML config UX worth modeling. |
| **bore** (ekzhang) | MIT | v0.6.0 (2025-06-09) | Moderate, 11508★ | Minimal, very readable single-purpose TCP tunnel broker — good pedagogical reference for the simplest possible relay protocol. |
| **tunnelto** | MIT (orig.), unclear on fork | orig. dead since 2022; community fork `tunneltodev/tunnelto` active (pushed 2026-09-07, tag 0.1.20 from 2024-10-23) | Original abandoned; fork alive but no LICENSE file detected via GitHub API — check before reusing code | ngrok-like public-URL client/server split; verify the fork's actual license before lifting code. |
| **shadowsocks-rust** | MIT | v1.25.0 (2026-08-26) | Very active, 10891★ | Mature, battle-tested AEAD cipher suites, obfuscation plugins, and UDP relay handling — strong crypto/obfuscation reference. |
| **tuic** (EAimTY) | GPL-3.0 | tags stuck at 2023-06-08 (`tuic-server/client-1.0.0`) | Not archived but effectively stale (last commit 2025-05-15), 3280★ | 0-RTT QUIC proxy protocol design (UDP-over-QUIC relaying) is worth studying even though the code itself isn't actively evolving; GPL-3.0 limits direct code reuse. |
| **leaf** (eycorsican) | Apache-2.0 | v0.14.2 (2026-02-25) | Active, 2832★ | Modular multi-protocol proxy framework + mobile (iOS/Android) FFI patterns; pairs with `netstack-lwip`. |
| **shoes** (cfal) | MIT | v0.2.7 (2026-01-22) | Active, 1229★ | Clean single-binary multi-protocol (HTTP/SOCKS5/VMess/VLESS/SS/Trojan/Hysteria2/TUIC/AnyTLS/Naive/XTLS) architecture — good reference for a protocol-plugin design. |
| **clash-rs** (correct repo: `ibigbug/clash-rs`, not Watfaq) | Apache-2.0 | rolling "latest" tag (2026-09-21) | Active, 1728★ | Rule-based routing engine, Clash/Mihomo-config-compatible. Note: a newer engine, **`meow-rs`**, has emerged and now powers several downstream Clash-compatible clients (BaoLianDeng, meow-android, Paws) — worth a look as a possibly more current alternative. |
| **phantun** (dndx) | Apache-2.0 | v0.8.1 (2025-08-23) | Active, 2396★ | UDP-to-fake-TCP obfuscation to cross NAPT/firewalls that block raw UDP — directly useful for getting QUIC-based transports through restrictive NATs. |
| **quincy** | AGPL-3.0 | v3.0.3 (2026-09-03) | Very active, 325★ | Full QUIC-based (TUN-over-QUIC) VPN reference architecture, with a post-quantum-crypto angle. |
| **snx-rs** (ancwrd1) | AGPL-3.0 | v6.4.1 (2026-09-24) | Extremely active, 508★ | Check Point SNX-protocol interop client — narrow relevance unless you need SNX compatibility specifically. |
| **sshx** (ekzhang) | MIT | v0.4.1 (2025-02-12), commits active to 2026-09-21 | Active, 7671★ | Browser-based collaborative terminal sharing: client registers with a relay server over WebSocket — good architectural reference for a web-facing relay + control-plane split. |
| **RustDesk hbbs/hbbr** (`rustdesk/rustdesk-server`) | AGPL-3.0 | v1.1.16 (2026-07-20) | Active, 10461★ | Production-proven **rendezvous server (hbbs) + relay server (hbbr)** split — directly analogous to a NAT-traversal-with-relay-fallback architecture. |
| **warpgate** | Apache-2.0 | v0.29.1 (2026-09-23) | Extremely active, 7965★ | Zero-client-install SSH/HTTPS/DB/RDP/VNC bastion built on **russh**; excellent reference for a multi-protocol bastion/relay behind one front door, and confirms russh in real production use. |
| **dumbpipe** (n0-computer) | MIT OR Apache-2.0 | v0.39.0 (2026-06-15) | Very active, pushed today, 783★ | Minimal "Unix pipes between devices" built directly on iroh — the best small reference for iroh-based NAT-traversal pipe integration. |

(Sources: each project's GitHub repo, e.g. https://github.com/erebe/wstunnel , https://github.com/rathole-org/rathole , https://github.com/ekzhang/bore , https://github.com/tunneltodev/tunnelto , https://github.com/shadowsocks/shadowsocks-rust , https://github.com/EAimTY/tuic , https://github.com/eycorsican/leaf , https://github.com/cfal/shoes , https://github.com/ibigbug/clash-rs , https://github.com/dndx/phantun , https://github.com/quincy-rs/quincy , https://github.com/ancwrd1/snx-rs , https://github.com/ekzhang/sshx , https://github.com/rustdesk/rustdesk-server , https://github.com/warp-tech/warpgate , https://github.com/n0-computer/dumbpipe)

---

## N. Proxy-client plumbing

**HTTP CONNECT clients:**
- **async-http-proxy** — `1.2.5`, last published **2022-02-19**. BSD-3-Clause. Stale (~4.5yr) but small/complete-enough for what it does. Source: https://crates.io/crates/async-http-proxy
- **hyper-proxy** — `0.9.1`, last published **2021-03-27**. MIT. **Dead** (~5.5yr). Source: https://crates.io/crates/hyper-proxy
- **hyper-http-proxy** — `1.2.0`, last published **2026-08-12**. MIT. **Active — this is the maintained fork of hyper-proxy**, by metalbear-co (the mirrord company), and works with hyper 1.x. Use this, not hyper-proxy. Source: https://crates.io/crates/hyper-http-proxy

**SOCKS5:**
- **tokio-socks** — `0.5.3` (2026-05-29). MIT. Active. **Client-only** — I found no server-side API surface in its source (only a `ToProxyAddrs` trait for connecting *to* a proxy). Source: https://crates.io/crates/tokio-socks
- **fast-socks5** — `1.0.0` (2026-01-20). MIT. Active. Confirmed **client AND server**, SOCKS5 + SOCKS4/4a, UDP support, typestate-based extensible server API, no unsafe code, cross-platform. The most complete/current of the three. Source: https://crates.io/crates/fast-socks5
- **socks5-impl** — `0.9.6` (2026-08-02). **GPL-3.0-or-later** (copyleft — flag for review). Active. Low-level building blocks + a server implementation. Source: https://crates.io/crates/socks5-impl

**Windows/Kerberos/NTLM:**
- **sspi** (Devolutions) — `0.22.0` (2026-09-15). MIT OR Apache-2.0. Very active. Confirmed cross-platform design intent: "ships with platform-independent implementations of Security Support Providers... and is able to utilize native Microsoft libraries when ran under Windows." However, per its own docs, **only NTLM currently has a guaranteed portable (non-Windows) implementation**; Kerberos/Negotiate support is present but not stated as equally portability-guaranteed. Source: https://github.com/Devolutions/sspi-rs
- **cross-krb5** — `0.5.0` (2026-05-31). MIT. Active. **Not a from-scratch reimplementation** — its own Cargo.toml shows it depends on `libgssapi` (same author, Eric Stokes) on Unix targets and the `windows` crate (native SSPI) on Windows. So on Unix it still needs a **system GSSAPI library (MIT krb5 or Heimdal)**, exactly like using `libgssapi` directly — its value-add is a single API that also covers Windows natively, not avoiding the system dependency. Source: https://github.com/estokes/cross-krb5
- **libgssapi** — `0.11.0` (2026-05-30). MIT. Active. Safe binding to the system's `libgssapi.so`/framework — Unix-only, requires a system Kerberos/GSSAPI install. Source: https://crates.io/crates/libgssapi

**System proxy discovery:**
- **proxy_cfg** (Devolutions) — `0.4.2` (2025-12-18). MIT/Apache-2.0. Reasonably active (~9mo old). Gets proxy config from the OS. Source: https://crates.io/crates/proxy_cfg
- **sysproxy** — `0.3.0`, last published **2023-03-16**. MIT. Stale (~3.5yr) but still commonly vendored by proxy GUI tools (e.g. Clash Verge-adjacent projects); supports Windows/macOS/Linux (via gsettings). Source: https://crates.io/crates/sysproxy
- **PAC (proxy auto-config JS) evaluator: this is a real gap.** I could not find a maintained PAC-file JS evaluator crate in the Rust ecosystem. The only GitHub hit for "PAC" + Rust proxy was `traxys/pac_proxy` (0 stars, last pushed 2022-09-20, and it's actually a shim proxy for *non*-PAC-aware apps, not a PAC evaluator library). If you need real PAC support, budget for either embedding a JS engine (e.g. `boa` or `rquickjs`) to run the PAC script yourself, or shelling out to the OS's own PAC resolution where available.

---

## Recommended stack

| Layer | Crate | Version | License | Confidence |
|---|---|---|---|---|
| Async runtime | tokio | 1.53.1 | MIT | High |
| HTTP/1+2 | hyper + hyper-util | 1.11.1 / 0.1.21 | MIT | High |
| HTTP routing (control plane / relay API) | axum | 0.8.9 | MIT | High |
| WS-over-H2 extended CONNECT | h2 (`enable_connect_protocol`, `ext::Protocol`) + hand-rolled framing | 0.4.19 | MIT | Medium (feature verified; no turnkey crate, you assemble it) |
| HTTP/3 / QUIC transport (app-level) | quinn | 0.11.12 | MIT/Apache-2.0 | High |
| HTTP/3 (if truly needed) | h3 / h3-webtransport | 0.0.8 / 0.1.2 | MIT | Low — explicitly experimental |
| HTTP client (outbound, incl. proxy egress) | reqwest | 0.13.5 | MIT/Apache-2.0 | High |
| TLS | rustls (+ aws-lc-rs default provider) | 0.23.45 | Apache-2.0/ISC/MIT | High |
| Cert verification (client trust) | rustls-platform-verifier | 0.7.1 | MIT/Apache-2.0 | High (Linux/WASM fall back to bundled roots) |
| TLS/Tokio glue | tokio-rustls | 0.26.5 | MIT/Apache-2.0 | High |
| ACME (automatic TLS certs) | instant-acme (general/DNS-01) or rustls-acme (zero-config TLS-ALPN-01) | 0.8.5 / 0.15.4 | Apache-2.0 / Apache-2.0-MIT | High |
| WebSocket | tokio-tungstenite (or fastwebsockets for raw speed) | 0.30.0 / 0.10.0 | MIT / Apache-2.0 | High |
| Stream multiplexing | yamux | 0.14.1 | Apache-2.0/MIT | High |
| WireGuard (userspace) | boringtun (lib) + defguard_wireguard_rs (mgmt API) | 0.7.1 / 0.12.1 | BSD-3-Clause / Apache-2.0 | Medium (boringtun CLI release-stale; lib itself fine) |
| TUN device | tun-rs | 2.8.11 | Apache-2.0 | High |
| TUN-to-proxy routing | tun2proxy | 0.8.3 | MIT | High |
| Userspace TCP/IP stack | smoltcp or ipstack | 0.14.0 / 1.0.1 | 0BSD / Apache-2.0 | Medium |
| NAT traversal / P2P QUIC | iroh (+ iroh-relay) | 1.2.0 | MIT/Apache-2.0 | High |
| P2P alternative (if libp2p ecosystem needed) | rust-libp2p (relay v2 + dcutr + quic; avoid webrtc/webtransport sub-crates, not stable) | 0.57.0 | MIT | Medium |
| Noise protocol (optional auth/encryption layer) | snow | 0.10.0 | Apache-2.0/MIT | High |
| Signing / key agreement | ed25519-dalek + x25519-dalek | 3.0.0 | BSD-3-Clause | Medium (recent major bump, check API) |
| SSH client+server | russh | 0.63.3 | Apache-2.0 | High |
| Reverse-proxy / L7 framework (if building a full proxy) | pingora | 0.9.0 | Apache-2.0 | Medium (no built-in SNI/L4 passthrough) |
| SNI-based L4 passthrough | rust-rpxy-l4 | (latest, active) | MIT | Medium (newer, smaller project) |
| UA/TLS-fingerprint-aware proxying | rama | 0.4.0 | MIT/Apache-2.0 | Medium (pre-1.0 but self-described production-ready) |
| HTTP CONNECT client (if not using reqwest/hyper-util directly) | hyper-http-proxy | 1.2.0 | MIT | High |
| SOCKS5 client+server | fast-socks5 | 1.0.0 | MIT | High |
| Windows/Kerberos/NTLM auth | sspi | 0.22.0 | MIT/Apache-2.0 | Medium (NTLM cross-platform confirmed; Kerberos less so) |
| System proxy discovery | proxy_cfg | 0.4.2 | MIT/Apache-2.0 | Medium |
| Reference implementations to read | wstunnel, warpgate, rathole, dumbpipe | — | BSD-3-Clause / Apache-2.0 / Apache-2.0 / MIT-Apache-2.0 | High (as reading material) |

All source URLs are inline above per crate/project.

