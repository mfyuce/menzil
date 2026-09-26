# menzil: a unified, self hosted tunnel in Rust. Literature review and plan

Status: draft for discussion. Compiled 2026-09-25 from six parallel research passes over vendor documentation, GitHub repositories, LICENSE files, crates.io and RFCs. Every non obvious fact carries a source in the section that states it. Fields that could not be verified are marked unknown rather than guessed.

## 0. Summary

- Nothing today combines "expose a port to a public https URL", "reach my own machine from anywhere" and "route my traffic through a machine I own" in one self hostable, permissively licensed tool, in any language. Tailscale comes closest and keeps its control plane closed; zrok comes closest in open source and needs an OpenZiti network underneath, in Go.
- The two products the user named are not equivalent on a locked down network. cloudflared talks to Cloudflare on port 7844 only, has no HTTP proxy support (verified in its source), and Cloudflare's terms forbid using named tunnels as a VPN. The VS Code tunnel does the right things on the wire (WebSocket on 443, end to end SSH inside, proxy aware, client written in Rust) and is limited only by Microsoft's account, relay, quotas and license.
- On an office network the mandatory baseline is: TCP 443, through the HTTP CONNECT proxy, TLS verified against the OS trust store (never pinned, so TLS inspection does not break it), an ordinary WebSocket, and a second end to end encryption layer inside so the relay and any inspecting proxy see ciphertext. Everything UDP based (QUIC, MASQUE, WebTransport, hole punching) is an optional accelerator.
- The Rust ecosystem has every layer: tokio, hyper, h2 (with RFC 8441), rustls plus rustls-platform-verifier, instant-acme, yamux, snow, quinn, tun2proxy, russh, and iroh 1.x for a later direct path. The two gaps are a PAC evaluator and a turnkey WebSocket over HTTP/2 crate; both are small.
- Fit with an enterprise SASE (section 10): the crates double as a SASE edge's ZTNA connector, 443 client transport and relay when built with an organization profile. The concrete assessment against a private codebase is in the private notes.
- Recommendation: build it. One binary with relay, node and client roles; one primitive (authenticated, end to end encrypted, multiplexed streams between key identified nodes); public shares served through a blind SNI passthrough relay with the certificate on the user's device (Tailscale Funnel's property); editors composed through SSH ProxyCommand; SOCKS egress first, TUN later; direct P2P path later behind a narrow trait. Section 8 phases it; section 9 lists what to decide first.

## 1. Scope: three problems that are one problem

The user's request names two products and three behaviors. Naming the behaviors precisely matters because the industry sells them separately.

- S1 expose. A local port becomes a public https URL. cloudflared --url, ngrok http, devtunnel host, tailscale funnel.
- S2 reach. From any network, open a stream to a port on a machine of mine that sits behind NAT. The VS Code tunnel, cloudflared access ssh, Tailscale, a bastion.
- S3 egress. Route my own traffic through a machine I control, so that the network I am on sees only one TLS connection to my own domain. An exit node, ssh -D, a VPN.

All three reduce to one primitive: an authenticated, end to end encrypted, multiplexed byte stream between two nodes, where the target of a stream is a (node, service) pair, plus a public ingress that maps a hostname to such a pair. S1 is ingress plus stream, S2 is stream, S3 is a stream whose far end is a SOCKS executor. This is the observation the design in section 6 is built on.

The constraints that the request adds:

- Self hosted and free of strings: no account, no vendor relay, no telemetry, no quotas, no terms that forbid the use, permissive license.
- Works from networks that allow only HTTPS egress, typically through an authenticated corporate proxy, often with TLS inspection.
- Rust.

## 2. How to read the landscape

Section 3 surveys about sixty projects in four families: managed services, self hosted reverse tunnels, overlay networks, and remote development tools. Section 4 covers the transport question on its own, because it decides the architecture. Section 5 states what "free" costs across the survey and derives the project's definition of "no strings". Sections 6 to 9 are the proposal. Section 10 (added 2026-09-26) summarizes the fit with an enterprise SASE edge; the concrete assessment is in the private notes.

## 3. The landscape

### 3.1 Managed services (the vendor runs the relay)

These are the products the project wants to replace. The table records what each one actually does on the wire, verified against vendor docs and, where possible, client source code.

| Service | Exposes | Client | Relay | Client to relay transport | TCP 443 only network | HTTP CONNECT proxy | Operator sees plaintext | Free tier catch | Status (2026-09) |
|---|---|---|---|---|---|---|---|---|---|
| Cloudflare Tunnel, TryCloudflare | HTTP(S), TCP via cloudflared access, UDP and ICMP with WARP routing; quick tunnels HTTP only | Go, Apache-2.0 | Closed, SNI hosts hardcoded in source | QUIC (UDP) or HTTP/2 (TCP), both on port 7844, mode auto | No. 7844 only, 443 used just for update checks and Access tokens | No (raw net.Dialer in source; PR 1514 unmerged) | Yes, edge terminates TLS | Quick tunnel: 200 in flight requests, no SLA. Named: Self-Serve Agreement 2.2.1(j) bans using the service "to provide a virtual private network or other similar proxy services" | 2026.9.3, 2026-09-24 |
| ngrok | HTTP(S), TCP, TLS endpoints; no UDP | Go, closed ("no open source versions of the ngrok Agent") | Closed | TLS on 443 only, by design | Yes | http_proxy env and proxy_url (HTTP, SOCKS5); no PAC, NTLM | Yes for https endpoints; only TCP and TLS endpoint types are end to end | 1 GB per month, 3 endpoints, account, interstitial page, no custom domain. Docs admit "ngrok may be blocked on Fortinet firewalls" | agent 3.39.11, 2026-08-12 |
| Microsoft Dev Tunnels (devtunnel) | HTTP(S), TCP, UDP port forwarding | Closed binary, maintainers declined to open it (issue 258) | Closed, Microsoft only | WebSocket over TLS on 443 | Yes | Appears to use system proxy (issue 536), undocumented | Yes, "TLS termination is done at service ingress" | Account, anti phishing interstitial, 30 day inactivity expiry, still "public preview, not recommended for production" | docs updated 2026 |
| VS Code Remote Tunnels (code tunnel) | Whole dev session plus per port forwarding URLs | Rust (confirmed via reqwest debug output), MIT source, proprietary "VS Code Server License Terms" binary | Same Microsoft relay | WebSocket over TLS on 443 | Yes | HTTPS_PROXY honored since 1.77 but the proxy must allow WebSocket upgrades | No for the session (SSH inside the tunnel, end to end); yes for forwarded port URLs | GitHub or Microsoft account mandatory, 10 tunnels per account | VS Code 1.139, 2026-09 |
| Tailscale Funnel and Serve | HTTPS, TCP, TLS terminated TCP; Funnel only on 443, 8443, 10000 | Go, BSD-3-Clause | Control plane closed; DERP relay open and self hostable; Funnel ingress closed | WireGuard UDP 41641 direct, DERP over TLS 443, control 80 then 443 | Yes, explicit fallback | Partial, env vars for control and DERP only | No: "Funnel relay servers do not decrypt", the certificate lives on the device | Undisclosed bandwidth limit, ts.net names only | v1.102.4, 2026-09-10 |
| localhost.run | HTTP(S), TLS passthrough | stock OpenSSH | Closed | SSH on 22 | Not documented | No | Yes by default, no in passthrough | Rotating subdomain, speed limit, custom domain 9 USD per month | active |
| serveo.net | HTTP(S), TCP | stock OpenSSH | Closed | SSH on 22 or 443 | Yes | No | Yes | Service itself: down in August 2026, still flaky in September 2026 | unstable |
| Pinggy | HTTP(S), TCP, TLS, UDP beta | OpenSSH or TypeScript CLI (Apache-2.0) | Closed | SSH or WebSocket on 443 "to overcome firewall restrictions" | Yes | Manual ProxyCommand recipes, documented for SSL inspecting firewalls | No in tls modes, yes in http mode | 60 minute tunnel timeout, screening interstitial | cli 0.6.0, 2026-09-25 |
| Expose (exposedev) | HTTP(S), TCP | PHP, MIT | Open, MIT, self hostable | Custom TCP on 443 by default | Yes | No | Yes (fronting proxy terminates) | Signup even for free, random URLs | 3.2.4, 2026-09-17 |
| playit.gg | TCP and UDP (game servers) | Rust, BSD-2-Clause | Closed | HTTPS 443 for API, custom UDP control channel | No | No | No TLS at all unless you add it | 4 ports free. Terms explicitly allow a "VPN server to access your network" | 1.0.10, 2026-06 |
| localtunnel (loca.lt) | HTTP(S) | Node, MIT | Open, MIT | HTTPS handshake then unencrypted raw TCP to a random high port | No | No on the data plane | Yes, and the data plane is plaintext | Last release 2021, outage report 2026-09-17 | strained |
| tunnel.pyjam.as | HTTP(S) | wg-quick | Open, GPL-3.0-or-later, self hostable | WireGuard UDP 55555 (live verified) | No, no fallback | No | Yes, Caddy edge | Hobby project, code unchanged since 2022 | live |
| pico.sh tuns | HTTP(S), TCP, WSS, SSH tun/tap VPN | stock OpenSSH | Open, MIT (sish based) | SSH on 22 | No | No | Yes for HTTP; sish has SNI passthrough | Paid only, 2 USD per month | active |
| srv.us | HTTP(S), TLS wrapped TCP | stock OpenSSH | Open, Go, ISC | SSH on 22 | Not documented | No | Yes | Free, no accounts, no terms page | active |
| zrok.io (NetFoundry) | HTTP(S), TCP, UDP, files; public and private shares | Go, Apache-2.0 | Open, Apache-2.0, same code as zrok.io | OpenZiti TLS edge, 443 with ALPN likely | Likely yes | Not documented | Fabric is end to end, but the vendor frontend injects an interstitial so it sees public HTTP shares | 5 GB per day, interstitial unless a card is on file | v2.0.4, 2026-05 |
| Pangolin Cloud (Fossorial) | WireGuard sites, HTTP(S) resources, TCP, browser SSH, RDP, VNC | Newt: Go, AGPL-3.0 dual licensed | Community edition AGPL-3.0, self hostable; Enterprise open core | WireGuard UDP 51820 direct, UDP 21820 relay | No, both paths are UDP | Not documented | Yes, "terminates TLS, routes HTTP(S)" | Free tier non commercial only | v1.23.0, 2026-09-16 |
| Telebit, Loophole, Packetriot | | | | | | | | Telebit dead; Loophole HTTP only, closed relay; Packetriot closed client, 1 GB per month | |

What the table says.

- The two tools the user named behave differently on a locked down network. cloudflared needs port 7844 and cannot use a proxy, so it is the wrong reference point for "works everywhere". The VS Code tunnel is the right reference point: WebSocket on 443, proxy aware, end to end encrypted session, and its client is already Rust. Its problem is purely the strings: Microsoft account, Microsoft relay, ten tunnel cap, proprietary binary license.
- "Free" is paid for in one of four ways: an account (ngrok, Microsoft, Tailscale, zrok, Expose, Pangolin Cloud), plaintext visibility at the vendor's edge (every default HTTP share except Tailscale Funnel and Pinggy's TLS modes), quotas and interstitial pages (ngrok, zrok, Pinggy, Dev Tunnels), or terms that forbid the intended use (Cloudflare's VPN clause). Only playit.gg's terms say personal VPN use is fine.
- The self hostable subset that is also 443 friendly is small: Expose (PHP, custom TCP on 443), zrok (Go, OpenZiti, heavy), and the SSH based services only if you run them on 443 yourself.
- End to end encrypted public HTTPS with the certificate on the user's device exists in exactly one mainstream product, Tailscale Funnel. That is the property to replicate.

### 3.2 Self hosted reverse tunnels (you run the relay)

| Project | Language, license | Maintenance (2026-09) | Transport | TCP 443 plus HTTP proxy | HTTPS subdomain shares, ACME | TCP, UDP | End to end | P2P |
|---|---|---|---|---|---|---|---|---|
| frp | Go, Apache-2.0, about 110k stars | Active, v0.71.0 2026-08 | TCP plus TLS, kcp, quic, websocket, wss | Yes; proxyURL supports http, socks5, ntlm, but only in tcp mode | Subdomains and custom domains yes; ACME no (issue 2799 open for years) | Yes, yes | No by default; opt in extra layer | XTCP with relay fallback |
| rathole | Rust, Apache-2.0, about 14k stars | Sporadic: last release v0.5.0 2023-10, isolated commits to 2026-08, moved to rathole-org | Raw TCP plaintext by default; tls, noise, websocket options | Partial; proxy = http or socks5 supported | None, pure L4 | Yes, yes | No; server holds the keys | No |
| bore | Rust, MIT, about 11.5k stars | Sporadic: v0.6.0 2025-06, last commit 2026-02 | Raw TCP, separate control and data ports | No | None | Yes, no | No, "no further traffic is encrypted by default" | No |
| tunnelto | Rust, MIT, about 7k stars | Unmaintained since 2022 (community fork exists) | WebSocket control plus TCP data, TLS | No | Subdomains yes; ACME undocumented | Yes, no | No | No |
| wstunnel | Rust, BSD-3-Clause, about 7k stars | Active, v11.0.0 2026-09-19 | WebSocket, HTTP/2, or WebTransport carrying TCP, UDP, SOCKS5, HTTP proxy, unix, stdio | Yes, explicit --http-proxy (not in WebTransport mode) | None, not a vhost tool | Yes, yes | No, relay terminated | No |
| chisel | Go, MIT, about 16.5k stars | Active, v1.12.0 2026-08 | SSH inside WebSocket inside HTTPS | Yes, --proxy takes HTTP CONNECT or SOCKS5 | Single backend only; ACME yes via --tls-domain | Yes, yes | No | No |
| sish | Go, MIT, about 4.7k stars | Active, v2.23.0 2026-06 | Plain SSH (ssh -R) | Partial: the SSH port is a separate listener, so it must itself be moved to 443 | Subdomains, custom domains, ACME inferred | Yes, no | SNI passthrough mode is end to end | No |
| inlets | The open source repo is gone (404); inlets-pro is closed, EULA and license key required | Commercial | unknown | unknown | Marketed | Yes | unknown | No |
| Pangolin (pangolin, newt, gerbil) | TypeScript plus Go, AGPL-3.0 dual licensed with the Fossorial Commercial License, about 23k stars, created 2024-09 | Very active, releases every one to two weeks | HTTPS and WebSocket control; WireGuard data plane, UDP 21820 relay | Control yes; data plane UDP only, no TCP fallback found | Yes, automatic certificates | Yes, yes | Terminated inside your own stack | Yes, with UDP relay fallback |
| zrok, on OpenZiti | Go, Apache-2.0, about 4.7k plus 4.4k stars | Active, zrok v2.0.4 2026-05, ziti v2.0.6 2026-09 | OpenZiti overlay: mTLS identity, libsodium end to end | Routers commonly on 443; proxy support unconfirmed | Yes; ACME type unknown | Yes, yes | Yes, "even from zrok servers" | Direct when possible |
| boringproxy | Go, MIT | Unmaintained; last commit 2024-07, boringproxy.io no longer resolves | TLS and SNI proxy, token auth | unknown | Auto HTTPS was the headline | Partial, no | No | No |
| nps | Go, GPL-3.0, about 34k stars | Unmaintained: last release 2021, last commit 2024-05, 527 open issues | Raw TCP bridge | No | Subdomains yes, manual certificates | Yes, yes | No | Listed |
| piko | Go, MIT, about 2.2k stars | Active, v0.10.0 2026-05 | HTTPS reverse proxy, clustered | Yes; proxy unknown | Subdomains yes plus header based routing; ACME undocumented | TCP via a helper, no UDP | No | No |
| portr | Go, AGPL-3.0, about 3.2k stars | Active, v1.0.18 2026-08 | SSH remote forwarding | Not documented | Auto HTTPS | Yes, no | No, has a request inspector | No |
| localtunnel server | Node, MIT | Unmaintained, last commit 2024-03 | Raw TCP | No | Subdomains; bring your own nginx and certificates | No, no | No | No |
| pagekite | Python, AGPL-3.0, since 2010 | Sporadic, last release 2020, commits 2026-01 | Custom multiplexed relay on 80 and 443 | Historically its whole point; unconfirmed today | Yes; offers end to end or wildcard TLS modes | Yes, no | Configurable | No |
| gost | Go, MIT, about 7.5k stars | Active, v3.3.0 2026-08 | tcp, tls, ws, wss, h2, grpc, quic, h3, WebTransport, ssh, kcp and more | Yes, proxy chains are the core design | Not ACME automated | Yes, yes | No | No |
| tunnelmole | TypeScript, client MIT, server AGPL-3.0 | Sporadic, commits 2026-04 | WebSocket | Not documented | Subdomains; bring your own certificates | No, no | No | No |
| holesail | Node, AGPL-3.0 | Active | Holepunch DHT, Noise, UDP hole punching | No, architecturally | Not applicable | Yes, yes | Yes when "secure" is enabled (off by default in the example) | Yes |
| dumbpipe (n0) | Rust, MIT or Apache-2.0 | Active, v0.39.0 2026-06 | QUIC via iroh, relay fallback | Not documented for dumbpipe | Not applicable | TCP and unix sockets | Yes, relay blind | Yes |
| iroh-tunnel (naicoi92), datum-cloud/app | Rust, Apache-2.0 and AGPL-3.0 | Tiny, 2026-09 | QUIC via iroh | No | No | Claimed TCP and UDP | Yes | Yes |
| opentunnel, underpass, MekongTunnel (found while searching) | TypeScript MIT; Go with no license file; Go MIT | Sporadic; unmaintained; sporadic | TLS plus NATS; TCP; SSH | unknown | ACME yes; unknown; auto HTTPS | | | |

Observations.

- Two families exist. The "looks like HTTPS" family (wstunnel, chisel, frp in wss mode, gost, pagekite) was built for exactly the office network problem and does proxies well, but has no or weak public share features and is relay terminated. The "share a port" family (tunnelto, sish, portr, piko, localtunnel, tunnelmole, boringproxy) does subdomains but rarely ACME, rarely proxies, and never end to end.
- Nothing in Rust combines the two. wstunnel is the transport half, tunnelto (dead) was the sharing half, rathole and bore are L4 only.
- Only two self hosted designs make a documented "the relay cannot read your traffic" claim: OpenZiti and zrok, and the iroh based tools. Pangolin terminates inside your stack; that is fine when you host alone, not when a friend hosts.
- Built in ACME is rarer than expected: chisel (confirmed), Pangolin, zrok and sish (inferred). frp, localtunnel and tunnelmole tell you to bring nginx.
- Stars say nothing about maintenance: nps (34k) is dead, rathole (14k) has not tagged a release since 2023, boringproxy's domain is gone, inlets deleted its open source repository and sells the successor.
- License traps: AGPL servers behind MIT clients (tunnelmole, NetBird), per file dual licenses (Pangolin), repositories with no license file at all (underpass).

### 3.3 Overlay networks and P2P substrates (the "reach" and "egress" families)

These solve S2 and S3 (reach my machine, exit through it) but not S1 (public https URL), with the single exception of Tailscale Funnel. They matter here for two reasons: their relay designs are the proven answer to UDP-blocked networks, and their licensing shows what "free" tends to cost.

| Project | Language, license | Control plane | Relay when UDP fails | TCP 443 plus HTTP proxy | Public https | Version, date |
|---|---|---|---|---|---|---|
| Tailscale | Go, BSD-3-Clause client and derper; coordination server, admin console and DERP fleet closed | Closed, not self-hostable | DERP: custom binary protocol inside TLS on TCP 443 (plus 80); inner WireGuard never decrypted | Yes by design: proxy env vars honored for control and DERP, control protocol falls back from 80 to 443 "for proxy compatibility" (one open Windows exit node gap, issue 17698) | Yes, Funnel, ports 443, 8443, 10000 only | v1.102.4, 2026-09-10 |
| Headscale | Go, BSD-3-Clause | Open, this is the control plane; embedded DERP available | Same DERP protocol | Inherits client behavior | No, Funnel closed as "not planned" (issue 1040) | v0.29.4, 2026-09-23 |
| NetBird | Go, BSD-3-Clause plus AGPL-3.0 for management, signal, relay | Open, self-hostable | Modern relay: WebSocket on TCP 443 and QUIC on UDP 443 raced, first wins | Architecturally friendly, HTTP CONNECT not documented | Partial (self-hosted reverse proxy feature) | v0.79.0, 2026-09-18 |
| Firezone | Rust data plane (connlib, gateway, clients), Elixir portal; Apache-2.0 for Rust, Elastic License 2.0 (not OSI) for the portal | Source available, self-hostable under field of use limits | TURN relay, cannot decrypt WireGuard; port not confirmed | Not documented | No | gateway 1.6.2, 2026-09-24 |
| Defguard | Rust, AGPL-3.0 core plus proprietary enterprise directory | Open core | None found, direct WireGuard through gateways | Not documented | Partial via self-hosted "Edge" | v2.1.0, 2026-09-04 |
| Nebula | Go, MIT | Open, lighthouses only, no vendor | UDP only, no TCP or 443 fallback (issues 1014, 1489) | No | No | v1.11.2, 2026-09-22 |
| ZeroTier | C++, MPL-2.0 agent; controller under a 2025 "Source Available License v1.0" barring commercial use | Partial | Root and moon relays; private moons "no longer recommended"; TCP 443 fallback unconfirmed | Unconfirmed | No | 1.16.2, 2026-05-28 |
| innernet | Rust, MIT | Open, own server | None, direct WireGuard only | n/a | No | v2.0.0, 2026-07-02, actively maintained |
| Netmaker | Go, Apache-2.0 core plus pro directory | Open core | STUN and TURN; v1.7.0 adds a "TCP Proxy / WSS Uplink" for restrictive networks | Suggested by release notes, not confirmed | Unclear | v1.7.0, 2026-08-31 |
| OpenZiti | Go, Apache-2.0 | Open | Routing is inherent to the fabric; outbound only "dark" routers | Unconfirmed | Reputed via BrowZer, unverified | v2.0.6, 2026-09-17 |
| wush (Coder) | Go, CC0-1.0 | None, uses tsnet in memory | Tailscale DERP | Inherits tsnet | No | v0.4.1, 2025-01-07, stale |
| Yggdrasil | Go, LGPL-3.0 with linking exception | None, decentralized | Every peer routes; peering over tcp, tls, quic and socks schemes | SOCKS chaining documented, HTTP CONNECT not | No | v0.5.14, 2026-06-19 |
| iroh (n0) | Rust, MIT or Apache-2.0 | Decentralized: DNS discovery (n0 runs the default server, self-hostable as iroh-dns-server) or Mainline DHT | Relay protocol is WebSocket only since v0.91.0 (2026-08-01); inner QUIC never decrypted | Not documented either way (Cargo.toml shows reqwest, which does CONNECT) | No, peer to peer only | 1.0.0 on 2026-06-15, v1.2.0 on 2026-09-11 |
| rust-libp2p | Rust, MIT | Library, you deploy | Circuit relay v2 over any configured transport, WebSocket possible | Plausible, unconfirmed | n/a | v0.57.0, 2026-09-11 |

Observations.

- The relay design converged: Tailscale DERP, NetBird's modern relay, iroh's relay and Enclave's relay all put an end-to-end encrypted datagram protocol (WireGuard or QUIC) inside a TLS connection on TCP 443, with the relay unable to read anything. This is the shape to copy.
- Only Tailscale ships all three capabilities (Funnel for S1, the mesh for S2, exit nodes for S3), and only with a closed control plane; Headscale restores the control plane but explicitly will not implement Funnel.
- iroh is the only Rust substrate with relay, hole punching (QUIC Address Discovery replaced STUN in v0.90) and a stable 1.x API. Its defaults point at n0's relays and DNS server; self-hosting both is supported and n0 now sells a paid relay plan (September 2026), which is exactly the kind of string the project wants to avoid by default.
- Licensing drift is the norm: NetBird's server parts are AGPL, Firezone's portal is Elastic, ZeroTier's controller went source-available in 2025, Defguard and Netmaker are open core. Client code is almost always permissive; the control plane is where vendors keep leverage.
- Tailscale's own numbers on hard NAT: 174 probes for 50%, 1024 for 98%, and about 0.01% when both sides are hard NAT. A relay is not optional even on friendly networks.

### 3.4 Remote development tunnels, and the tools that claim to unify

The VS Code tunnel is the product the user wants to replace for daily work, so it is worth being precise about what it is.

- code tunnel connects outbound over WebSocket on 443 to Microsoft's Dev Tunnels relay and runs an SSH session inside it (AES-256-CTR), so the relay cannot read the session. Forwarded ports get https URLs terminated at Microsoft's ingress, private by default or public by choice.
- Documented quotas per account: 10 tunnels, 5 GB per user per month, 10 ports per tunnel, 1,000 connections per port, 20 MB/s per tunnel. Unused tunnels are deleted after 30 days.
- Licensing has three layers: the Code OSS source is MIT, the product build is proprietary, and the server and CLI component that tunnels deploy is under the separate "Visual Studio Code Server License Terms": single user only, cannot be hosted as a service, requires a licensed VS Code. The same component is deployed by Remote-SSH, Dev Containers and Codespaces.
- VS Code's network docs list the CLI among the features that "don't yet fully support proxy networking".

The composition insight. VS Code Remote-SSH documents ProxyCommand in ssh_config, JetBrains Gateway's primary provider is SSH, and Zed's remote server talks plain SSH through a control master. Any transport that can carry an SSH handshake replaces the Microsoft relay for all three editors without touching them. cloudflared documents exactly this pattern (`ProxyCommand cloudflared access ssh --hostname %h`) and Tailscale SSH works as plain ssh. So the project needs a `stdio` mode that speaks a stream to a peer's port 22; the editor experience comes free.

| Tool | Transport and ports | Open | License | Rides plain SSH |
|---|---|---|---|---|
| VS Code Remote Tunnels | WebSocket 443 plus inner SSH | Relay closed | MIT source, proprietary server terms | It is the tunnel |
| Dev Tunnels CLI | WebSocket 443 | Relay closed, binary closed | SDK MIT, CLI EULA | It is the tunnel |
| VS Code Remote-SSH | SSH, any port via ssh_config | Server component proprietary | Server terms | Yes, ProxyCommand documented |
| JetBrains Gateway | SSH | No | Proprietary, paid backend IDE | Yes |
| Zed remote | SSH, server pushed over SSH if needed | Yes | GPL-3.0-or-later remote crates | Yes |
| code-server, openvscode-server | HTTP(S) on localhost, exposed via SSH forward or reverse proxy | Yes | MIT, Open VSX marketplace | Yes (ssh -L) |
| DevPod | SSH over a provider channel | Client yes | MPL-2.0 | Yes, writes ssh_config |
| Coder | WireGuard plus its own DERP compatible relay on HTTPS 443 | Core yes | AGPL-3.0 plus enterprise license | Yes, coder ssh |
| Codespaces | Proprietary | No | Closed | Not verified |
| Gitpod | Renamed Ona, joined OpenAI June 2026; control plane SaaS only, runners self hostable | Partial | Proprietary | Not verified |
| sshx (Rust) | gRPC over HTTP/2 plus WebSocket, port 8051 | Source yes, "self hosted deployments are not supported" | MIT | No |
| upterm | SSH reverse tunnel to uptermd, SSH over WebSocket option | Yes, self hostable | Apache-2.0 | Yes |
| tmate | SSH, tmate-ssh-server plus tmate-websocket | Yes | Messy, per file, no LICENSE files | Yes |
| ShellHub | WebSocket agents, SSH facing gateway | Community edition | Apache-2.0 | Yes |
| Apache Guacamole | Browser to guacd (4822) to RDP, VNC, SSH | Yes | Apache-2.0 | Partial |
| RustDesk | hbbs 21115 to 21118, hbbr 21117 and 21119 | Core yes, Pro closed | AGPL-3.0 | No |
| mosh, Eternal Terminal | SSH handshake then UDP 60000 to 61000; SSH then TCP 2022 | Yes | GPL-3.0-or-later; Apache-2.0 | Handshake only |
| Teleport | Agents dial out to the proxy, moving to single port multiplexing | Community yes | AGPL-3.0 since 2023-12 (was Apache-2.0), enterprise in a private submodule | Yes, tsh proxy |

The unified attempts, scored against the three capabilities:

| Tool | Public https share | Private reach in | Egress | TCP 443 plus proxy | License, language |
|---|---|---|---|---|---|
| Tailscale (Funnel, Serve, exit nodes, SSH) | Yes, three ports | Yes | Yes | Yes | BSD-3 client, closed control plane; Go |
| zrok | Yes | Yes | SOCKS5 backend mode yes; TUN vpn mode removed in v1.1.11 for dependency reasons | Likely | Apache-2.0; Go on OpenZiti |
| Pangolin | Yes via Traefik | Yes, identity gated plus client mesh | Not found | Control only, data plane UDP | AGPL-3.0 dual; TypeScript and Go |
| NetBird | No | Yes | Yes, exit nodes | Relay on WebSocket 443 | BSD-3 plus AGPL server; Go |
| Firezone | No | Yes | Yes, "Internet Resource", paid plans | Unconfirmed | Apache-2.0 plus Elastic portal; Rust and Elixir |
| Teleport | No | Yes | No | Yes | AGPL-3.0; Go |
| inlets | Yes | Partial | No, "not a VPN" | Yes | Commercial EULA; Go |
| boringproxy | Yes | No | No | Unknown | MIT; Go, dormant |

Only Tailscale covers all three, and its control plane is the closed part. zrok is the closest open source shape (public shares, private shares, SOCKS egress, end to end encryption, self hostable) at the price of running an OpenZiti controller and routers, in Go.

### 3.5 Gap analysis

Scoring the strongest candidates against the project's requirements (three capabilities, TCP 443 through a proxy, relay blind, self hostable without an account, permissive license, Rust):

| Candidate | S1 expose | S2 reach | S3 egress | 443 plus proxy | Relay blind | No account, permissive | Rust |
|---|---|---|---|---|---|---|---|
| cloudflared | Yes | Yes | Yes with WARP | No (7844, no proxy) | No | No; terms ban VPN use | No |
| VS Code tunnel | Ports only | Yes | No | Yes | Session yes, ports no | No | Client yes |
| Tailscale plus Headscale | Funnel only with Tailscale's control plane | Yes | Yes | Yes | Yes | Headscale yes, no Funnel | No |
| zrok | Yes | Yes | SOCKS | Likely | Yes | Yes, Apache-2.0, heavy | No |
| Pangolin | Yes | Yes | No | No (UDP) | Own stack | AGPL dual | No |
| wstunnel | No | Yes (ports) | Yes (SOCKS) | Yes, best in class | No | Yes, BSD-3 | Yes |
| chisel | Single backend | Yes | Yes (SOCKS) | Yes | No | Yes, MIT | No |
| rathole, bore | No | Ports | No | Partial, no | No | Yes | Yes |
| iroh, dumbpipe | No | Yes | No | Relay is WebSocket; proxy unverified | Yes | Yes, but defaults use n0 infrastructure | Yes |

No project fills the row. The unified tool would be assembled from four proven ideas: wstunnel's transport pragmatism (WebSocket or HTTP/2 on 443 through a CONNECT proxy), Tailscale's relay model (end to end encrypted packets through a blind relay, direct path as an upgrade), Tailscale Funnel's certificate on the device, and zrok's product shape (public shares, private shares, SOCKS shares from one identity). Section 6 does that in Rust.

## 4. Getting through the office network: transports on port 443

This section is the engineering core. The threat model is a managed network that allows only outbound TCP 443, usually through an explicit HTTP proxy (PAC or WPAD discovered, Basic, NTLM or Negotiate authenticated), with UDP blocked and, on many corporate laptops, TLS inspection by a proxy holding a CA the machine trusts.

### 4.1 Two different adversaries, often confused

Circumvention literature (Tor pluggable transports, Xray REALITY, Trojan, naiveproxy) targets a network censor that cannot forge certificates the client trusts. An enterprise TLS-inspecting proxy is a stronger adversary: it terminates TLS with a CA the endpoint trusts and sees plaintext no matter how browser-like the handshake looks. The only design that works against both is an outer TLS session the proxy is allowed to inspect, with a second, independently authenticated encryption layer inside it (Noise, WireGuard or QUIC with our own keys). This is how Tailscale (WireGuard inside DERP), iroh (QUIC inside the relay) and rathole (Noise) already behave. Sources: Durumeric et al., NDSS 2017; CISA alert TA17-075A; rustls-platform-verifier README.

Consequence: never pin the relay certificate. Verify the outer TLS against the operating system trust store (rustls-platform-verifier, maintained by the rustls project, used by 1Password, Bitwarden, Signal, rustup) so an injected corporate root does not hard-fail the connection. Authenticity of the peer comes from the inner layer.

### 4.2 Carrier candidates, ranked by compatibility

| Carrier | Works with TCP 443 only, via HTTP CONNECT | Survives TLS inspection | Needs UDP | Status | Rust |
|---|---|---|---|---|---|
| WebSocket over TLS (RFC 6455) | Yes; RFC 6455 section 4.1 specifies CONNECT traversal | Mostly | No | Ubiquitous, HTTP/1.1 semantics almost everywhere | tokio-tungstenite, fastwebsockets |
| HTTP/2 extended CONNECT (RFC 8441) | Yes; the forward proxy only sees a plain CONNECT | Partial (depends on the inspecting proxy speaking H2 to the origin) | No | Firefox, Chromium, HAProxy, nghttpx; not nginx, not Caddy | h2 crate since 0.3.8 (Dec 2021) |
| Plain HTTP/1.1 request/response streaming (XHTTP style) | Yes | Yes, but the proxy sees the shape | No | Project specific | hyper |
| HTTP/3, MASQUE CONNECT-UDP (RFC 9298), CONNECT-IP (RFC 9484) | No as primary | No; Palo Alto, Fortinet, Zscaler, Cisco document blocking QUIC to force inspectable TLS | Yes | Deployed at scale by Cloudflare WARP (MASQUE is now WARP's default) and Apple Private Relay, which itself falls back to HTTP/2 when QUIC is blocked | quinn, h3, hopf-masque |
| WebTransport | No as primary (H2 mapping is still a draft) | No | Yes | W3C Candidate Recommendation July 2026, Baseline in browsers since March 2026 | wtransport, web-transport-quinn |
| WebSocket over HTTP/3 (RFC 9220) | No | n/a | Yes | Standardized, essentially unimplemented | none |

Reading of the table: WebSocket over TLS on 443 is the mandatory baseline. HTTP/2 extended CONNECT is an optional optimization that removes per-stream handshakes when talking to our own relay (h2 has the primitive). Everything QUIC based is an opportunistic fast path with mandatory fallback. Sources: RFC 6455, RFC 8441, RFC 9298, RFC 9484, Cloudflare "Zero Trust WARP tunneling with a MASQUE", Palo Alto KB "Block QUIC", W3C WebTransport CR, websocket.org "Future of WebSockets".

Operational details that bite: reverse proxies and load balancers drop idle WebSocket connections at 60 s by default (nginx proxy_read_timeout, AWS ALB) and Cloudflare at 100 s, so the tunnel needs an application-level ping every 25 to 30 s. Reverse proxies also buffer responses by default, which matters only if someone fronts the relay with nginx.

### 4.3 The corporate HTTP proxy is three separate problems

1. Discovery: HTTPS_PROXY, ALL_PROXY and NO_PROXY environment variables are the de facto convention, but they express neither PAC evaluation nor WPAD (DHCP option 252, wpad DNS name).
2. PAC evaluation: needs a JavaScript evaluator, or on Windows the WinHTTP API which evaluates PAC natively.
3. Authentication: Basic is trivial; NTLM and Negotiate (SPNEGO, Kerberos with NTLM fallback) are multi round-trip 407 challenges. Open source tunnel clients rarely implement them; users chain a local helper proxy (px, cntlm) instead.

How the incumbents fare: ngrok documents proxy_url and honors http_proxy (HTTP and SOCKS5). Teleport's tsh honors HTTPS_PROXY with inline credentials since 8.3.5. Tailscale honors the variables only for its control and DERP connections. cloudflared has an open issue since 2020 about ignoring the proxy variable for its edge connection. The VS Code tunnel CLI is reported to ignore proxy settings, and VS Code's own docs mark that layer as incomplete. Sources: ngrok outbound proxy docs; Teleport networking reference; Tailscale issues 11053 and 10235; cloudflared issue 170; vscode-remote-release issue 8209.

Design consequence: a client that does all three natively (env vars, OS proxy settings plus PAC, NTLM and Negotiate) would be better at this than every incumbent except possibly ngrok. In Rust: the sspi crate (Devolutions) for NTLM and Kerberos on Windows, cross-krb5 or libgssapi elsewhere, and WinHTTP bindings for PAC on Windows.

### 4.4 Do not stack TCP inside TCP

Running a reliable protocol inside a reliable protocol (TCP inside TCP, or a full QUIC stack inside TCP) creates two competing congestion control loops and stalls under loss (Titz 2001, Honda et al. 2005). WireGuard's known-limitations page refuses TCP transport for this reason. Fake-TCP wrappers such as udp2raw (C++) and phantun (Rust) satisfy stateful firewalls without implementing TCP reliability, but they explicitly do not pass an L7 proxy that re-terminates TCP and TLS. When the relay path is a real WebSocket through a real proxy, the right shape is: byte streams carried as framed multiplexed streams with no inner retransmission (yamux over the WebSocket), and UDP payloads carried as discrete framed datagrams. wstunnel (Rust, BSD-3-Clause, actively maintained) is the reference implementation of exactly this shape and has a documented WireGuard-over-wstunnel mode. Sources: wireguard.com/known-limitations; dndx/phantun README; erebe/wstunnel README.

### 4.5 What the network sees, and how far to go

Four independent control points exist in real deployments, run by different products: URL categorization, NGFW application signatures, TLS and HTTP/2 client fingerprinting, and TLS inspection content analysis.

- Categorization: vendors keep a "proxy avoidance and anonymizers" category (Palo Alto, Zscaler, Fortinet, Cisco Umbrella). FortiGuard lists ngrok under category Proxy with risk 5 of 5, and WireGuard with risk 3 of 5 (signature updated August 2026). Ephemeral subdomains under trusted parents (trycloudflare.com, devtunnels.ms, ts.net) are the documented blind spot that threat intelligence reports (Proofpoint, GuidePoint, CSO Online, 2024 to 2026) describe being abused. A personal domain is simply "uncategorized", and vendors differ on whether that is allowed by default.
- Application signatures: Palo Alto App-ID and FortiGuard ship signatures for well known tunnel binaries and for generic SSH port forwarding. Reusing ngrok's or WireGuard's wire protocol unchanged on 443 does not help.
- Fingerprinting: a default rustls plus h2 stack has a JA4 and HTTP/2 fingerprint that is passively distinguishable from a browser. Open source answers exist (Go uTLS; Rust wreq on cloudflare/boring, rama), but they are an arms race and sit outside the core of a remote access tool.
- Prior art in "look like a website": Tor WebTunnel (an ordinary HTTPS WebSocket upgrade to what is externally a normal website, aimed at allow-list networks) and Trojan (a real website on the same port, proxy traffic distinguished only by a secret) are the two clean designs. Domain fronting has been dead on major CDNs since April 2018, and ECH (RFC 9849, March 2026) is not a replacement: managed endpoints disable it by policy or strip the DNS record.

Position for this project: the relay path should be an ordinary TLS 1.3 connection to a personal domain carrying an ordinary WebSocket, ideally with a real, boring website answering non-tunnel requests (the WebTunnel and Trojan pattern). That is the honest engineering baseline that every mainstream product uses, and it is enough for networks that merely block known vendors. Active fingerprint mimicry is out of scope for the core and, on a managed device with TLS inspection, would not help anyway (section 4.1).

### 4.6 The direct path is a bonus, never the base

STUN, ICE, hole punching and libp2p's DCUtR are all UDP. Tailscale reports direct connections "well north of 90%" of the time, iroh about 90% first-attempt success, and an independent 2025 measurement of 4.4 million attempts across 85,000 networks found 70% (plus or minus 7) success for the DCUtR punch stage (arXiv 2510.27500). On the office network none of that machinery is reachable, so the architecture must be Tailscale's: connect through the relay first, silently try to upgrade to a direct path, fall back transparently. Sources: Tailscale "How NAT traversal works"; iroh NAT traversal docs; arXiv 2510.27500.

## 5. What "free" costs, and what "no strings" has to mean

Across the sixty odd projects surveyed, the price of a free tunnel is paid in one of these currencies:

1. An account and an identity. ngrok, Microsoft, Tailscale, zrok, Expose and Pangolin Cloud all require one. It ties every tunnel to a person and lets the vendor revoke or rate limit.
2. Plaintext at the vendor's edge. Every default HTTP share except Tailscale Funnel and Pinggy's TLS modes terminates TLS at the operator. The operator can read, log and inject (zrok and ngrok inject interstitial pages, which is only possible because they see the HTTP).
3. Quotas and interstitials. 1 GB per month (ngrok, Packetriot), 5 GB per day (zrok), 60 minute sessions (Pinggy), 200 in flight requests (TryCloudflare), 10 tunnels (VS Code), consent pages (localtunnel, ngrok, zrok, Dev Tunnels).
4. Terms of service. Cloudflare's Self-Serve Subscription Agreement forbids using named tunnels "to provide a virtual private network or other similar proxy services". Pangolin Cloud's free tier is non commercial only. Only playit.gg's terms explicitly permit a personal VPN.
5. Ports that corporate firewalls do not open. cloudflared (7844), Pangolin (UDP), Nebula (UDP), tunnel.pyjam.as (UDP), localtunnel (random high port), playit (UDP control).
6. License drift on the server side. Client code is almost always permissive; the control plane is AGPL (NetBird, Pangolin, Defguard), Elastic (Firezone), source available (ZeroTier controller) or simply closed (everyone hosted).

"No strings attached" therefore has a precise definition for this project:

- No accounts, no e-mail, no telemetry, no update pings, no vendor relay in the default configuration. Identity is a key pair generated on the device.
- The relay is blind. It sees ciphertext for every private stream and, in the default public share mode, also for HTTPS shares (section 6.4). A relay run by a friend is therefore low trust.
- Permissive license (Apache-2.0 or MIT), no contributor license agreement, no open core split, single static binary.
- The only cost of independence is a domain name and a small VPS, or a friend who has one.

A note on policy. The same features that make this work from a café or a client site make it work from an office that blocks vendor tunnels. Whether that is allowed is a matter between the user and their employer's acceptable use policy; the design below does not add active evasion features (section 4.5), it behaves like every mainstream product on the list, on the user's own domain.

## 6. Proposed architecture

### 6.1 One primitive, three products

S1, S2 and S3 reduce to a single primitive: an authenticated, end to end encrypted, multiplexed byte stream between two nodes, where the target of each stream is a (node, service) pair, plus a public ingress that maps a hostname to a (node, service).

- S1 expose: ingress plus a stream to the node that owns the service.
- S2 reach: a stream from one of my nodes to (node, port). SSH, VS Code Remote-SSH, JetBrains Gateway, Zed remote, database clients and port forwards all compose on top through a ProxyCommand or a local listener.
- S3 egress: a stream to (node, "dial anything"), that is a SOCKS executor on the far end. A full VPN is the same thing with a TUN device in front.

### 6.2 Roles: one binary, three modes

- relay: a public VPS. Listens on 443 (and 80 for ACME and redirects). Routes (a) node sessions, authenticated by node public key; (b) public HTTP(S) for names under its domain to (node, service) by Host or SNI; (c) SNI passthrough for blind shares; (d) optional raw TCP ports.
- node: any machine. Keeps one or more outbound long lived sessions to relays, advertises services, accepts stream requests from authorized peers, and can act as an egress executor.
- client: a node in ephemeral mode, for example the laptop in the office. Same binary, same keys.

A node may connect to several relays (a personal one plus a friend's); public names live under whichever relay's domain serves them.

### 6.3 Transport stack for the relay path

Outer to inner:

1. TCP 443, optionally through an HTTP CONNECT proxy discovered from environment variables, OS settings, PAC or WPAD, authenticated with Basic, NTLM or Negotiate.
2. TLS 1.3 to the relay with a public CA certificate, verified against the OS trust store (rustls-platform-verifier, plus rustls-native-certs on Linux). Never pinned, so TLS inspection does not hard fail.
3. HTTP/1.1 WebSocket upgrade as the baseline; HTTP/2 extended CONNECT when the relay is reached directly; HTTP/3 only when UDP works. Application level ping every 25 to 30 s.
4. Inner end to end encryption between the two nodes, so the relay and any inspecting proxy see ciphertext: either Noise IK over the WebSocket with yamux multiplexing, or QUIC over the WebSocket (the iroh shape). See 6.6 for the choice.
5. Streams and datagrams on top: reliable streams for TCP style services, framed datagrams for UDP and VPN packets, never a second TCP inside TCP.

The relay should also serve an ordinary, boring website on the same port for requests that are not tunnel sessions (the WebTunnel and Trojan pattern), so the domain looks like what it is: a personal web server.

### 6.4 Public HTTPS shares: blind by default

Mode A, relay terminated (what everyone does): the relay holds a wildcard certificate (DNS-01) or per host certificates (HTTP-01, TLS-ALPN-01), routes by Host, and can apply relay side auth. The relay sees plaintext HTTP.

Mode B, blind relay: the relay reads only the ClientHello SNI and forwards the raw TLS bytes as a stream to the node; the node terminates TLS with its own certificate. ACME works through the relay: HTTP-01 by forwarding /.well-known/acme-challenge on port 80 to the node, TLS-ALPN-01 naturally through the SNI router, DNS-01 if the node holds DNS credentials. Browsers see a normal certificate; the relay sees nothing. Auth gated shares are done at the node (password or OIDC middleware). This matches Tailscale Funnel's property and is something Cloudflare, ngrok, Pangolin and zrok cannot offer with their terminated designs. rust-rpxy-l4 shows an SNI multiplexer in Rust; the node side is rustls plus instant-acme.

Default: mode B. Mode A stays available for the cases that need relay side features.

Raw TCP exposure to the public: the relay allocates a port, or multiplexes on 443 by SNI ("ssh.app.example"). For the owner's own clients, S2 covers this without any public port.

### 6.5 Egress ("VPN myself")

- Level 1, no admin rights: a local SOCKS5 and HTTP CONNECT listener on 127.0.0.1. Each connection becomes a stream to the chosen exit node, which dials the target; DNS is resolved remotely (socks5h). Browsers and tools point at it. This covers most of "browse through home".
- Level 2, admin rights: a TUN device. Either tun2proxy style (TUN to a userspace stack to streams; tun2proxy is already a complete Rust component for Linux, Android, macOS, iOS and Windows), or WireGuard inside the tunnel (boringtun packets as framed datagrams, kernel WireGuard on the exit for speed). Datagram framing avoids TCP in TCP.
- The exit can be the relay itself or any node the user owns.

### 6.6 Build versus adopt: the QUIC question

Two viable designs for layer 4 of section 6.3.

Option 1, own transport: Noise (snow) plus yamux over the WebSocket for the relay path; a separate quinn based direct path added later behind one Stream trait. Simple, efficient over TCP relays (no inner retransmission), fully under project control. Cost: two stream implementations, and connection migration between relay and direct paths has to be done at the application level (re dial).

Option 2, QUIC everywhere on iroh: iroh 1.x gives public key addressed QUIC connections, hole punching (QUIC Address Discovery since 0.90), a self hostable relay (iroh-relay, WebSocket only since 0.91, reqwest based so it inherits CONNECT proxy handling), DNS or DHT discovery, and one connection object that migrates between relay and direct paths. Cost: QUIC inside TCP on the relay path (extra encapsulation and a reliability loop that mostly idles because the outer TCP never loses), a dependency on n0's roadmap and defaults (their relays and DNS server must be replaced by the user's own), no public HTTPS ingress (that stays our code either way), and no verification yet that the relay client honors NTLM or PAC.

Recommendation: start with option 1 for the relay path, because the office network is the case that must work and it is the case where iroh's advantages (hole punching, migration) are unusable. Keep the Stream trait narrow so that the direct path can be quinn hole punching of our own or an iroh endpoint later. Revisit after the MVP with a measurement, not an opinion.

Alternatives considered and rejected as the base: Pangolin (Go, AGPL, UDP only, terminates TLS), zrok (Go, Apache-2.0, needs an OpenZiti controller and routers, vendor frontend model), wstunnel (Rust, BSD-3, the right transport but single user, no identity, no public shares; read its code, do not fork it), rathole and bore (Rust, right shape, no HTTP ingress, no proxy support, no identity), Headscale plus derper (Go, no Funnel, WireGuard needs a TUN and admin rights on the client).

## 7. Rust building blocks (verified on crates.io and GitHub, 2026-09-25)

The ecosystem covers every layer of the design. The two real gaps are a PAC evaluator and a turnkey WebSocket-over-HTTP/2 crate; both are buildable.

| Layer | Crate | Version (date) | License | Notes |
|---|---|---|---|---|
| Runtime | tokio | 1.53.1 (2026-07) | MIT | |
| HTTP/1 and HTTP/2 | hyper, hyper-util | 1.11.1, 0.1.21 (2026-08/09) | MIT | |
| Control plane HTTP | axum | 0.8.9 | MIT | Relay admin API, ACME callbacks |
| HTTP/2 extended CONNECT | h2 | 0.4.19 | MIT | Server: `enable_connect_protocol()`; client: `is_extended_connect_protocol_enabled()`; `h2::ext::Protocol` for the `:protocol` pseudo header. Present since 0.3.8 |
| WebSocket | tokio-tungstenite, fastwebsockets, hyper-tungstenite | 0.30.0, 0.10.0, 0.30.0 | MIT, Apache-2.0, BSD-2 | `WebSocketStream::from_raw_socket` wraps any established byte stream, which is how WebSocket framing can sit on an h2 CONNECT stream. No off the shelf RFC 8441 WebSocket crate exists |
| QUIC | quinn | 0.11.12 (2026-09) | MIT or Apache-2.0 | 0-RTT and DATAGRAM extension supported. s2n-quic 1.89 is the AWS alternative |
| HTTP/3, WebTransport | h3, h3-webtransport, wtransport, web-transport-quinn | 0.0.8, 0.1.2 | MIT | h3 is self described experimental; treat as optional |
| TLS | rustls, tokio-rustls | 0.23.45, 0.26.5 | Apache-2.0 or ISC or MIT | Default provider aws-lc-rs, post quantum key exchange preferred by default |
| Trust store | rustls-platform-verifier | 0.7.1 (2026-09) | MIT or Apache-2.0 | Native verifier on Windows, macOS, iOS, Android. On Linux it falls back to bundled Mozilla roots, so add rustls-native-certs for the system bundle there |
| ACME | instant-acme, rustls-acme | 0.8.5, 0.15.4 | Apache-2.0 | instant-acme supports HTTP-01, DNS-01, TLS-ALPN-01 (you publish the record). rustls-acme is zero config TLS-ALPN-01 only. acme-lib and acme2 are abandoned |
| Multiplexing | yamux | 0.14.1 (2026-09) | Apache-2.0 or MIT | Maintained by Parity, used by rust-libp2p. async-smux and smux (Go smux compatible) are alternatives |
| E2E crypto | snow, ed25519-dalek, x25519-dalek | 0.10.0, 3.0.0, 3.0.0 | Apache-2.0 or MIT, BSD-3 | Noise framework; note the recent dalek 3.0 major bump |
| WireGuard | boringtun (lib), defguard_wireguard_rs | 0.7.1, 0.12.1 | BSD-3, Apache-2.0 | boringtun library still updated, its CLI last released 2022. WireGuard/wireguard-rs is dead. onetun (userspace port forward without root) last published 2024-12 |
| TUN and userspace IP | tun-rs, tun2proxy, smoltcp, ipstack | 2.8.11, 0.8.3, 0.14.0, 1.0.1 | Apache-2.0, MIT, 0BSD, Apache-2.0 | tun2proxy: Linux, Android, macOS, iOS, Windows; HTTP and SOCKS4/5 upstream, UDP, DNS over TCP. Prefer tun-rs over the WTFPL licensed tun crate |
| P2P and relay | iroh, iroh-relay | 1.2.0 (2026-09), 1.0.0 released 2026-06-15 | MIT or Apache-2.0 | Public key addressed QUIC with relay fallback and hole punching. The relay client depends on reqwest 0.13 and tokio-websockets 0.13, so the relay path is WebSocket over HTTPS and inherits reqwest's HTTP CONNECT and env var proxy support (inferred from Cargo.toml, not from a README statement) |
| P2P alternative | rust-libp2p | 0.57.0 | MIT | relay v2, dcutr, quic, websocket shipped; webrtc only alpha; webtransport not published |
| WebRTC, STUN, TURN | str0m, webrtc, stun, turn | 0.23.1, 0.21.0, 0.17.2 | MIT or Apache-2.0 | Only needed for a browser client or Snowflake style relays |
| SSH | russh | 0.63.3 (2026-09) | Apache-2.0 | Client and server; used by warpgate, Devolutions Gateway, Sandhole |
| Proxy frameworks | pingora, rama, rust-rpxy, rust-rpxy-l4 | 0.9.0, 0.4.0, git | Apache-2.0, MIT | pingora has no built in SNI passthrough. rust-rpxy-l4 is an L4 proxy with protocol multiplexer (SNI routing). rama has JA3, JA4, JA4H and Akamai H2 fingerprinting plus browser emulation. sozu is AGPL |
| HTTP CONNECT client | hyper-http-proxy | 1.2.0 (2026-08) | MIT | Maintained fork of hyper-proxy by metalbear (mirrord) |
| SOCKS5 | fast-socks5 | 1.0.0 (2026-01) | MIT | Client and server, SOCKS4/4a/5, UDP. tokio-socks is client only; socks5-impl is GPL-3.0 |
| Proxy auth | sspi (Devolutions), cross-krb5, libgssapi | 0.22.0, 0.5.0, 0.11.0 | MIT or Apache-2.0, MIT | sspi has a portable NTLM and native Windows SSPI; Kerberos off Windows needs the system GSSAPI library |
| System proxy discovery | proxy_cfg (Devolutions) | 0.4.2 (2025-12) | MIT or Apache-2.0 | Reads OS proxy settings. No maintained PAC evaluator crate exists: embed boa or rquickjs, or call WinHTTP on Windows |

Reference implementations worth reading before writing code:

| Project | License | Latest | Why |
|---|---|---|---|
| wstunnel (erebe) | BSD-3-Clause | v11.0.0, 2026-09-19, about 7,000 stars | Arbitrary TCP, UDP, SOCKS and reverse tunnels over WebSocket or HTTP/2 with HTTP proxy support and TLS. The closest existing Rust code to the relay path of this design |
| rathole | Apache-2.0 | commits 2026-08, last tag v0.5.0 (2023) | Clean control channel plus data channel protocol with Noise, TOML config, about 14,000 stars |
| bore (ekzhang) | MIT | v0.6.0, 2025-06 | The smallest readable relay protocol, TCP only |
| tunnelto | MIT (original), fork license unverified | original dead since 2022, community fork tunneltodev active 2026-09 | ngrok style subdomain HTTP tunnels in Rust |
| dumbpipe (n0) | MIT or Apache-2.0 | v0.39.0, 2026-06 | Minimal pipe between devices on iroh; the reference for iroh integration |
| sshx (ekzhang) | MIT | v0.4.1, commits 2026-09 | Browser terminal sharing with a WebSocket relay; relay and control plane split |
| RustDesk hbbs and hbbr | AGPL-3.0 | v1.1.16, 2026-07 | Production rendezvous plus relay split |
| warpgate | Apache-2.0 | v0.29.1, 2026-09 | SSH, HTTPS, database and RDP bastion on russh |
| shadowsocks-rust | MIT | v1.25.0, 2026-08 | Mature AEAD and UDP relay code |
| leaf, shoes, clash-rs | Apache-2.0, MIT, Apache-2.0 | 2026 | Multi protocol proxy cores and mobile FFI patterns; shoes is a clean single binary protocol plugin design |
| quincy | AGPL-3.0 | v3.0.3, 2026-09 | TUN over QUIC VPN reference (copyleft) |
| phantun | Apache-2.0 | v0.8.1, 2025-08 | UDP as fake TCP for L3/L4 firewalls only |

## 8. Phased plan

| Phase | Weeks | Deliverable |
|---|---|---|
| 0 Spec | 1 | Wire protocol document, threat model, name, workspace layout (proto, relay, node, cli crates), decision record for 6.6 |
| 1 MVP | 3 to 5 | relay and node in one binary; WebSocket over TLS 443 with HTTPS_PROXY and Basic auth; Noise inner; yamux; `expose` in mode A with ACME; `forward` and `stdio` (SSH ProxyCommand, which gives VS Code Remote-SSH, JetBrains and Zed for free); key based auth and invites; Linux, macOS, Windows builds via cargo-dist |
| 2 Office grade | 3 to 4 | HTTP/2 extended CONNECT with fallback; mode B blind shares with node side ACME; `proxy` (local SOCKS5 and HTTP CONNECT egress); OS proxy discovery, PAC, NTLM and Negotiate; reconnection and stream resumption; ACLs; boring website on the relay |
| 3 Direct and VPN | 4 to 8 | quinn hole punching or iroh endpoint behind the Stream trait; TUN mode via tun2proxy or WireGuard in tunnel; UDP forwarding; Android build |
| 4 Comfort | ongoing | `code` helper (Remote-SSH or code-server through the tunnel), terminal sharing in the sshx style, packaging (Nix, Homebrew, deb), documentation |

## 9. Questions to settle before phase 0

1. Priority among the three products. My guess is reach (S2, replaces the VS Code tunnel) first, expose (S1) second, egress (S3) third. Correct?
2. Blind relay (mode B) as the default for public shares, accepting that the node then runs its own ACME client?
3. Personal relay only, or design for shared "friends" relays from day one (multi tenant names, per key quotas)?
4. Own transport first (recommended) or iroh from the start?
5. Full VPN (TUN, admin rights, mobile) in scope for the first year, or user space SOCKS only?
6. Scope on the office network: standard TLS plus WebSocket on a personal domain, no fingerprint mimicry in the core. Agreed?
7. A name. Decided 2026-09-26: **menzil** (Ottoman relay station on a courier route; also "reach" in modern Turkish). Crates: menzil-proto, menzil-carrier, menzil-relay, menzil-node; personal binary `menzil`; ng_sdwan's agent keeps the name ngsd and links the crates.

## 10. Fit with an enterprise SASE edge

The same crates can serve an enterprise SASE edge as its ZTNA application connector, its client transport on 443 through corporate proxies, and its authenticated relay, when built with an organization profile: SVID or mTLS inner authentication, a central policy source, terminated and inspected egress. Public shares, blind egress and invite tokens stay out of that profile. This is not a bend of SASE: Gartner's service initiated ZTNA is exactly a lightweight connector making an outbound connection to a broker, and Zscaler, Palo Alto, Netskope and Cloudflare all ship one. The concrete assessment against a specific private codebase, and the analysis of why its coverage checklist missed the connector, live in the private notes (`docs/private/ng-sdwan-fit.md`, not published).
