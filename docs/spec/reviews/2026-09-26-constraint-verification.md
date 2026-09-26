# Constraint verification of the phase 0 spec against the literature review

Produced 2026-09-26 by a verification agent (checklist job, read only). Input: literature review sections 4, 5, 6, 8 and the three spec drafts at commit 1765b4b. Kept unedited as review provenance; the resulting changes are recorded in the spec's changelog.

Legend for spec pointers: P = docs/spec/protocol.md, T = docs/spec/threat-model.md, D = docs/spec/decisions/0001-relay-path-transport.md.

## Checklist

| id | constraint | source quote | status | spec pointer / gap |
|---|---|---|---|---|
| R4.1 | Two-layer design: inspectable outer TLS + independent inner auth encryption | "outer TLS session the proxy is allowed to inspect, with a second, independently authenticated encryption layer" | SATISFIED | P layering table L1/L3/L4; §1 "Nothing above L1 trusts L1...L4 authenticates peers" |
| R4.2 | Never pin the relay certificate | "never pin the relay certificate" | SATISFIED | P L1; §3.1.3 "Pinning is forbidden" |
| R4.3 | Outer TLS verified against OS trust store | "Verify the outer TLS against the operating system trust store" | SATISFIED | P §3.1.3 "platform verifier...system CA bundle...on Linux" |
| R4.5 | WebSocket/TLS 443 is mandatory baseline | "WebSocket over TLS on 443 is the mandatory baseline" | SATISFIED | P L2, §3.1.4 |
| R4.6 | HTTP/2 ext-CONNECT = optional, direct-to-relay only | "optional optimization...talking to our own relay" | SATISFIED | P §3.1.5, marked "Later", barred through forward proxy |
| R4.7 | QUIC = opportunistic fast path, mandatory fallback | "opportunistic fast path with mandatory fallback" | SATISFIED | D e2e_proto tag scheme; base path never needs QUIC |
| R4.8 | App-level ping every 25-30s | "application-level ping every 25 to 30 s" | SATISFIED | P §3.3 "ping every 25 seconds" (fixed, low end of range) |
| R4.9 | Client natively does proxy discovery + NTLM/Negotiate | "a client that does all three natively...better than every incumbent" | SATISFIED | P §3.1.1-2, SSPI/GSSAPI |
| R4.10 | No TCP inside TCP / no QUIC-in-TCP | "Do not stack TCP inside TCP" | SATISFIED | P §1 "No reliable protocol...stacked inside another" |
| R4.11 | Byte streams as muxed frames, no inner retransmit (yamux/WS) | "framed multiplexed streams with no inner retransmission (yamux over the WebSocket)" | SATISFIED | P §5.3 |
| R4.12 | UDP as discrete framed datagrams | "UDP payloads carried as discrete framed datagrams" | SATISFIED | P §5.4 DGRAM |
| R4.13 | Ordinary-looking relay path; boring website fronting | "a real, boring website answering non-tunnel requests" | SATISFIED | P §3.1.4, §11 static site dir |
| R4.14 / R5.11 | No active evasion/fingerprint mimicry; behaves like mainstream products | "Active fingerprint mimicry is out of scope for the core"; "does not add active evasion features" | SATISFIED | T §2.2, §4 non-goals |
| R4.15 | Relay-first, silent opportunistic direct upgrade, transparent fallback | "connect through the relay first, silently try to upgrade...fall back transparently" | PARTIAL | P PEER_STATE.direct empty in phase1 (§4.2); no upgrade/fallback message defined; deferred to phase 3 (T §2.8) |
| R5.1 | No accounts / no e-mail | "No accounts, no e-mail...default configuration" | SATISFIED | P §2.1 keypair-only identity |
| R5.2 | No telemetry | "no telemetry" | MISSING | Not addressed in P, T or D |
| R5.3 | No update pings | "no update pings" | MISSING | Not addressed in P, T or D |
| R5.4 | No vendor relay in default config | "no vendor relay in the default configuration" | SATISFIED | P §11: relays are user-supplied connection strings, no built-in default |
| R5.5 | Identity = on-device keypair | "Identity is a key pair generated on the device" | SATISFIED | P §2.1 |
| R5.6 | Relay blind to private streams | "sees ciphertext for every private stream" | SATISFIED | T §2.3, §3 table (L4 row) |
| R5.7 | Relay blind to default-mode HTTPS shares | "in the default public share mode, also for HTTPS shares" | SATISFIED | P §6.1 "(default)"; T §3 (Blind share row) |
| R5.8 | Friend-run relay = low trust | "A relay run by a friend is therefore low trust" | SATISFIED | T §2.3 whole "malicious/compromised relay" model |
| R5.9 | Permissive license, no CLA, no open-core split | "Permissive license (Apache-2.0 or MIT)..." | MISSING | Governance/licensing not addressed in P, T or D (out of scope for these docs) |
| R5.10 | Single static binary, one binary/three modes | "single static binary" | SATISFIED | P §11 one `menzil` binary, subcommands; terms line 3 |
| R6.1 | Single primitive: e2e stream keyed to (node,service); ingress hostname→(node,service); S1 = ingress+stream to owning node | "a...multiplexed byte stream between two nodes...plus a public ingress" | SATISFIED | P §2.3 ServiceId, §4.3 ADVERTISE, §6 |
| R6.2/R8.10 | S2 reach / `stdio` composes via ProxyCommand or local listener | "SSH...compose...through a ProxyCommand or a local listener"; "`stdio` (SSH ProxyCommand...)" | PARTIAL | P §11 lists `reach`/`stdio`; "exact flags are not part of this protocol" - composition mechanics unspecified |
| R6.3 | S3 egress = stream to (node,"dial anything"); full VPN = +TUN | "A full VPN is the same thing with a TUN device in front" | PARTIAL | SOCKS exec done (P §8); TUN mode only a "Later" one-liner |
| R6.4 | Relay listens 443 and 80 (ACME + redirects) | "Listens on 443 (and 80 for ACME and redirects)" | PARTIAL | P §6.1 covers port 80 for ACME only; plain-HTTP redirect unaddressed |
| R6.5 | Relay routes node sessions authenticated by node public key | "authenticated by node public key" | SATISFIED | P §4.1 HELLO/WELCOME via NodeCert |
| R6.7 | SNI passthrough for blind shares | "SNI passthrough for blind shares" | SATISFIED | P §6.1 |
| R6.8 | Optional raw TCP ports | "optional raw TCP ports" | SATISFIED | P §6.3, operator opt-in, off by default |
| R6.9 | Node: long-lived sessions, advertises, accepts peer streams, egress executor; may hold several relays | "Keeps one or more outbound long lived sessions to relays...egress executor" | SATISFIED | P §3, §4.3, §8; multi-relay implied by plural "relays" in §11, not elaborated |
| R6.10 | Client = node in ephemeral mode, same binary/keys | "Same binary, same keys" | SATISFIED | P terms, line 3 |
| R6.12 | Outer transport: TCP443 via discovered CONNECT proxy, Basic/NTLM/Negotiate | "TCP 443, optionally through an HTTP CONNECT proxy discovered from...PAC or WPAD" | SATISFIED | P §3.1.1-2 |
| R6.13 | TLS1.3 public CA, OS store (+native-certs on Linux), never pinned | "Never pinned, so TLS inspection does not hard fail" | SATISFIED | P §3.1.3 |
| R6.15 | App ping 25-30s (restated) | "Application level ping every 25 to 30 s" | SATISFIED | P §3.3 |
| R6.16 | Inner E2E: Noise IK+yamux OR QUIC-over-WS; relay sees ciphertext only | "either Noise IK...with yamux, or QUIC over the WebSocket" | SATISFIED | P §5 implements Noise+yamux; QUIC alt reserved as e2e_proto 0x02 (D) |
| R6.17 | Reliable streams for TCP-style, framed datagrams for UDP/VPN, never 2nd TCP-in-TCP | "never a second TCP inside TCP" | SATISFIED | P §5.2-5.4 |
| R6.18 | Relay serves boring website on same port | "an ordinary, boring website on the same port" | SATISFIED | P §3.1.4, §11 |
| R6.19 | Mode A/terminated: relay cert, name routing, optional relay auth, sees plaintext | "the relay holds a wildcard certificate...can apply relay side auth" | SATISFIED | P §6.2 (Host vs SNI routing key not explicit) |
| R6.20 | Mode B/blind: relay forwards raw TLS by SNI only; node terminates | "reads only the ClientHello SNI and forwards the raw TLS bytes" | SATISFIED | P §6.1 |
| R6.21 | ACME via relay in Mode B: HTTP-01 fwd / TLS-ALPN-01 via SNI / DNS-01 at node | "HTTP-01 by forwarding...TLS-ALPN-01 naturally...DNS-01 if the node holds DNS credentials" | SATISFIED | P §6.1, `acme-http` ServiceId (§2.3) |
| R6.22 | Browsers see normal cert; relay sees nothing (Mode B) | "the relay sees nothing" | SATISFIED | P §6.1; T §3 |
| R6.23 | Auth-gated shares done at node (password/OIDC), Mode B | "done at the node (password or OIDC middleware)" | PARTIAL | Terminated-mode auth assigned to relay instead (P §6.2, "later addition"); blind-mode node-side auth not explicitly described |
| R6.24 | Default = Mode B; Mode A available for relay-side-feature cases | "Default: mode B. Mode A stays available" | SATISFIED | P §6.1 "(default)" vs §6.2 |
| R6.25 | Public raw TCP via port or SNI-mux; S2 needs no public port | "S2 covers this without any public port" | SATISFIED | P §6.3 |
| R6.26/R6.28 | Egress L1: local SOCKS5+CONNECT, remote DNS; exit = relay or any owned node | "DNS is resolved remotely"; review: "exit can be the relay itself or any node" | SATISFIED | P §8; relay-as-exit possible since "Relays are nodes too" (§2.1) but not stated explicitly |
| R6.27 | Egress L2: TUN (tun2proxy or WG-in-tunnel), datagram framing avoids TCP-in-TCP | "Datagram framing avoids TCP in TCP" | PARTIAL | P §8 "Later: a TUN mode..."; no tun2proxy-vs-WireGuard choice made |
| R6.29/R6.30 | Decision: Option1 (Noise+yamux) for phase1; keep swap point narrow for future direct path | "Build option 1 for phase 1, with one structural rule that keeps option 2 open" | SATISFIED | D "Decision"; e2e_proto tag substitutes for a code-level Stream trait |
| R6.31 | Revisit iroh-vs-own after MVP via measurement not opinion | "Revisit after the MVP with a measurement, not an opinion" | SATISFIED | D "Revisit criteria", concrete metrics + adoption test |
| R8.1 | Phase0 deliverable: wire protocol document | "Wire protocol document" | SATISFIED | P exists |
| R8.2 | Phase0 deliverable: threat model | "threat model" | SATISFIED | T exists |
| R8.3 | Phase0 deliverable: name | "name" | SATISFIED | "menzil" used consistently in P, T |
| R8.4 | Phase0 deliverable: workspace layout (proto/relay/node/cli crates) | "workspace layout (proto, relay, node, cli crates)" | MISSING | No crate/workspace structure in P, T or D |
| R8.5 | Phase0 deliverable: decision record for §6.6 | "decision record for 6.6" | SATISFIED | D exists, cross-refs review §6.6 |
| R8.6 | Phase1: relay+node in one binary | "relay and node in one binary" | SATISFIED | P §11, one `menzil` binary |
| R8.7 | Phase1: WS/TLS443 + HTTPS_PROXY + Basic auth | "WebSocket over TLS 443 with HTTPS_PROXY and Basic auth" | SATISFIED | P §3.1 (also adds NTLM/Negotiate/PAC beyond this line - see R8.15) |
| R8.8 | Phase1: Noise inner; yamux | "Noise inner; yamux" | SATISFIED | P §5, §5.3; D |
| R8.9 | Phase1: `expose` in mode A with ACME | "`expose` in mode A with ACME" | SATISFIED | P §6.2 |
| R8.11 | Phase1: key based auth and invites | "key based auth and invites" | SATISFIED | P §7, §7.2 |
| R8.13 | Phase2 item: mode B blind shares w/ node-side ACME | "mode B blind shares with node side ACME" (phase-2 row) | CONTRADICTED | P states "normative for phase 1 unless marked \"later\""; §6.1 Blind mode "(default)" has no "later" tag - spec makes it phase-1 |
| R8.14 | Phase2 item: boring website on the relay | "boring website on the relay" (phase-2 row) | CONTRADICTED | P §3.1.4's boring-website line is unmarked (contrast: adjacent §3.1.5 IS "Later:") - phase-1 in spec |
| R8.15 | Phase2 item: OS proxy discovery, PAC, NTLM and Negotiate | "OS proxy discovery, PAC, NTLM and Negotiate" (phase-2 row) | CONTRADICTED | P §3.1.1-2 give these unmarked (phase-1), vs phase-1 row's own "...and Basic auth" only |
| R8.16 | Phase2 item: ACLs | "ACLs" (phase-2 row) | CONTRADICTED | P §2.2 Policy/grants default-deny model is unmarked (phase-1) |
| R8.17 | Phase2 item: reconnection and stream resumption | "reconnection and stream resumption" (phase-2 row) | PARTIAL | Carrier reconnect is phase-1 (P §3.3); true L4 "stream resumption" explicitly NOT phase-1 (D: "Relay reconnects tear down L4 sessions in phase 1") - correctly deferred, self-declared gap |

Dropped as not independently checkable / out of scope for the 3 spec files: R5's "domain + VPS is the only cost" (descriptive, not a spec requirement); wstunnel/rathole/zrok "rejected as base" rationale (development-process note, not a spec content requirement); cargo-dist cross-platform builds (packaging, not addressed by a wire-protocol/threat-model/ADR set and adds no signal beyond R5.9/R8.4's "governance/tooling not covered" finding).

## New commitments in the spec (not present in review §4/5/6/8)

1. One-session-per-NodeId-per-relay uniqueness, with supersede-and-GOAWAY on a new HELLO (P §4.2, §10). The review only says a node "may connect to several relays" - it never states a per-relay session-uniqueness rule.
2. A large set of concrete numeric parameters absent from the review: NodeCert validity ≤400 days, MemberCert 90 days, L3 rekey at 2^32 msgs/24h, L4 rekey at 2^60/2^30 records or 2h, 2048-record replay window, 64 KiB record cap, 256 KiB yamux window, 65,467-byte datagram cap, 30-day label lease, 20 labels/NodeId, 10 HELLO/min/IP, 1-60s full-jitter reconnect backoff, 10s stream-open timeout, 35s pong-less idle cutoff.
3. CBOR (via `ciborium`, per D's dependency list) as the universal control-message encoding. Review §7's crate table names no serialization format at all.
4. A concrete PKI/policy wire schema: self-signed NodeCert binding X25519↔NodeId, owner-signed MemberCert, one whole-document Policy with monotonic `seq`, default-deny `grants`, per-node `egress` allow/deny lists (P §2.2). Review discusses roles and grants conceptually but never proposes a document format.
5. A relay-mediated invite-redemption sub-protocol (INVITE_REDEEM/INVITE_RESULT, owner-online requirement, `owner_offline` retry-with-backoff) (P §7.2). Review's phase list only says "key based auth and invites."
6. Systematic promotion of four review phase-2 "Office grade" deliverables into phase-1-normative spec text: blind/Mode-B shares + node ACME, the boring website, OS proxy discovery/PAC/NTLM/Negotiate, and ACLs (see R8.13-R8.16). This is a schedule commitment the review never made for phase 1.
7. `acme-http` as a first-class `ServiceId` kind alongside tcp/udp/http/tls/egress (P §2.3). Review never enumerates a typed service-kind schema.

## Summary

64 items extracted from review §4, §5, §6 and §8; status counts: 50 SATISFIED, 7 PARTIAL, 3 MISSING, 4 CONTRADICTED.
PARTIAL/MISSING items cluster around explicitly-deferred phase-3 work (direct-path upgrade mechanics, TUN/VPN design) and matters genuinely outside a protocol/threat-model/ADR's scope (telemetry, update checks, licensing/governance, workspace layout, CLI flag semantics).
All 4 CONTRADICTED items are the same kind of conflict, not a security or wire-format one: protocol.md declares itself normative for phase 1 unless a clause is marked "later," and four items the review's phase table placed in phase 2 (Mode B/ACME, boring website, OS-proxy/PAC/NTLM/Negotiate, ACLs) carry no "later" tag.
