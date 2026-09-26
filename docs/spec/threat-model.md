# menzil threat model (spec v0.2, 2026-09-26)

Status: v0.2 after the red team review of v0.1. Companion to `protocol.md` v0.2; section references point there.

## 1. What we protect

| Asset | Why it matters |
|---|---|
| Contents of every private stream and datagram (S2 reach, S3 egress) | The core promise: only the two endpoints read them |
| Contents of blind public shares (S1, default once shipped) | The relay operator must not be able to read a share it hosts by observing it |
| Node identities and the ability to act as one | A stolen or forged identity opens every service granted to it |
| Membership and policy: who may reach what | Wrong grants are the most likely real world failure |
| Grants, device names and egress rules (the Policy) | Hidden from relays; the Roster the relay sees holds ids only |
| Service existence and topology (which nodes exist, which shares exist) | Node ids and share names are visible to the relay and, for shares, to the public (certificate transparency) |
| Relay availability | A personal relay is a single point of failure; abuse must not take it down |

## 2. Adversaries and what each can do

### 2.1 Passive network observer (ISP, campus, wifi)

Sees: TLS connections from the node to the relay's domain on 443, their timing and sizes, DNS lookups of the relay name unless DoH is used. Cannot see anything inside. Not a goal: hiding that the relay domain is contacted or that a long lived WebSocket exists; traffic analysis resistance is out of scope. Version 1 key agreement is X25519 without a post quantum component, so an observer who records traffic today could decrypt it with a future quantum computer; a hybrid is a version 2 change.

### 2.2 Inspecting corporate proxy (TLS interception with a trusted enterprise CA)

Sees: the HTTP upgrade request, the WebSocket framing, the L3 records as ciphertext, record sizes and timing, the relay host name and the CONNECT target. Because L3 is a Noise session keyed to the relay's identity, the proxy cannot read control records or forwarded payloads, impersonate the relay, or inject records. It can block, delay, throttle or drop. It can record a HELLO and replay it; the ATTACH rule and the monotonic timestamp make a replayed HELLO harmless (section 4.1). Requirement met by design: the outer TLS is verified against the OS trust store and never pinned, so interception does not hard fail. Not a goal: passing as browser traffic under fingerprinting (review section 4.5).

### 2.3 Malicious or compromised relay

Sees: node identities and NodeCerts, the Rosters of the networks it serves (ids, revocations, minimum serials, label claims, stewards), which nodes are online, who sends to whom and when, record sizes, advertised names, and for terminated mode shares the full HTTP plaintext, by design. Does not see: Policies (grants, device names, egress rules travel end to end only), or any L4 payload.

Cannot: read or forge L4 records (authenticated encryption with contiguous counters, so a dropped, duplicated or reordered reliable record ends the session instead of corrupting a stream); impersonate a member to another member (the L4 handshake binds dialed NodeId, RECV source and prologue to the NodeCert); mint members or alter documents (owner and steward signatures; the admission tag is keyed with a secret the relay never sees); freeze revocation indefinitely (documents expire within 14 days and peers exchange sequence numbers end to end); open arbitrary streams to a node (the relay principal may open only share streams for names it accepted); disconnect a node by replaying its HELLO.

Can: drop or delay traffic, refuse service, lie about peer presence, and observe the metadata above. An operator who also controls the DNS of the share domain can obtain certificates for blind names and terminate them; this is detectable through certificate transparency and preventable for custom domains with CAA `accounturi`. Blind therefore means blind against a passive relay. Mitigation available to users: run your own relay, attach to several, use a custom domain with CAA.

### 2.4 Malicious member

Can: open L4 sessions to members of the same network and attempt any stream; send datagrams up to its token bucket; initiate handshakes up to the per peer limit. Stopped by: default deny grants scoped to that network and enforced at the target node, grant re evaluation on policy change, egress deny lists at the exit, per channel token buckets, per peer handshake limits, L3 credit so that one slow or hostile peer cannot stall others, and revocation. Cannot: read traffic between other members (pairwise keys), impersonate the owner or steward, escalate through roles of another network (principals are scoped), or reach services not granted. Residual risk: a member with an egress grant uses the exit's address for its traffic, bounded by the exit's rules and by revocation.

### 2.5 Stolen node key

The holder is that node until revoked. Mitigations: key files restricted to the user (mode 0600, Windows ACL), revocation through Roster and Policy applied by relays and peers on receipt, `min_serial` raising so stale NodeCerts die immediately, document expiry of 14 days as the upper bound for a relay that withholds updates, one attached session per NodeId so the legitimate node notices displacement. Not in phase 1: hardware backed keys, device attestation.

### 2.6 Stolen owner key

Unrecoverable for that network: the attacker can sign documents and admit members. Remedy is a new network and re admission of devices. Mitigations: the owner key stays offline; the always online admission device holds a steward key limited to admit and renew with a lifetime of at most 90 days; one writer issues sequence numbers.

### 2.7 Internet attacker against the relay

Attempts: connection floods, HELLO floods (an office behind one proxy shares one address, so per address limits are generous and per NodeId limits apply after the Diffie Hellman), SNI probing, abuse of terminated shares as an open proxy, ACME abuse, admission request floods. Controls: rate limits, one attached session per NodeId, 65,535 byte records, bounded queues, per name connection limits, label claims signed by owners with quotas and quarantine, unknown SNI receives the static site, ACME routing only for known names, Host must match SNI (421 otherwise), pending admissions capped. Public shares are the one surface accepting unauthenticated connections; everything else requires a Noise handshake with a listed identity. Share names are public knowledge through certificate transparency; the static site fallback prevents casual probing, not enumeration.

### 2.8 Wrong policy

The owner is trusted; mistakes are the realistic risk (`to_node: "*"` with `services: ["*:*"]`). The CLI prints every grant in words, default templates are narrow, and the default egress deny list is written into the Policy so that what is enforced is what was signed.

### 2.9 Malicious peer over a direct path (phase 3)

The direct path will most likely be QUIC with its own reliability; L4 version 1 records are defined for the relay path, where the reliable class requires contiguity and only datagrams tolerate loss. Whatever the direct path is, it must add no trust: same identities, same network scoping, same grants.

## 3. Guarantees by layer

| Layer | Confidentiality against | Authenticity | Notes |
|---|---|---|---|
| L1 outer TLS | passive observer | relay domain unless intercepted | OS trust store, never pinned, 1.2 accepted |
| L3 relay session | observer, inspecting proxy | node and relay, mutually (Noise IK or XX anchored in the relay NodeId) | Control plane; the relay sees Rosters and metadata by design |
| L4 end to end | observer, proxy, relay | peers, bound to dialed id, source and network | Reliable class contiguous; datagram class windowed |
| L5 streams | inherited from L4 | authorization at the target node, re evaluated on policy change; exit rules for egress | OPEN before any byte |
| Blind share | observer, proxy, passive relay | the node's certificate to the browser | Active operator with DNS control can misissue; CT and CAA |
| Terminated share | observer, proxy | relay certificate to the browser; node to relay via L4 | The relay reads HTTP by design; opt in; the only mode in phase 1 |

## 4. Explicit non goals

- Anonymity of nodes toward relays, or of relays toward the network.
- Resistance to traffic analysis and fingerprinting by the local network operator.
- Protection against a malicious owner, or recovery from a stolen owner key.
- Hiding share names; they are public through certificate transparency.
- Availability under a determined denial of service against a personal relay.
- Post quantum confidentiality in version 1.
- Hiding that menzil is in use: ordinary TLS carrying an ordinary WebSocket to a personal domain, nothing more.

## 5. Security requirements the implementation must test

1. A relay that drops, duplicates or reorders one reliable L4 record causes the receiver to end the session; no stream ever delivers a hole or reordered bytes. Datagram records inside the window are accepted, outside it dropped.
2. An admission request replayed by the relay with a different NodeCert is rejected by the steward (tag mismatch); a request with the correct tag succeeds exactly `uses` times across any number of relays.
3. A member of network N2 cannot use a role of N2 to reach a service granted to that role name in N1 on a node that belongs to both.
4. A revoked node is refused by relays and peers on receipt of the new documents; a peer that cannot obtain documents newer than `expires` refuses new L4 sessions.
5. A responder NodeCert whose `node_id` differs from the dialed NodeId, or an initiator whose `node_id` differs from the RECV source, aborts the L4 handshake. A NodeCert with a serial below `min_serial` or below the highest seen is rejected at L3 and L4.
6. The relay principal cannot open `tcp:`, `udp:` or `egress:*` streams, nor share streams for names it did not accept; `meta` from a member is ignored.
7. A replayed HELLO does not supersede an attached session and is rejected by the timestamp rule; a new session becomes routable only after ATTACH.
8. With one slow destination, other destinations of the same source keep flowing; a reliable SEND beyond credit closes the sending session; droppable records are dropped first under pressure.
9. Two `menzil stdio` processes for one user share one agent and one relay session, and both SSH sessions stay up.
10. Egress: a name resolving to a denied address is refused before any dial; `0.0.0.0`, IPv4 mapped loopback, `100.64.0.0/10` and the exit's own addresses are denied by the default list; a UDP channel never sends to an address other than the OPEN target.
11. A request to a terminated share with a `Host` that differs from the SNI receives 421; client supplied `X-Forwarded-For` never reaches the node; a request for a blind name over a connection terminated for the wildcard zone receives 421.
12. With a TLS intercepting proxy in the harness, the node connects, the proxy sees only ciphertext after the upgrade, and an injected record is rejected.
13. Unknown SNI, no SNI, quarantined names and a fragmented ClientHello up to 16 KiB behave as specified; a peek that exceeds the deadline is closed.
14. Relay static key rotation: nodes with the old key still connect for 30 days, receive the new NodeCert, and afterwards reject a lower relay serial.

## 6. Open questions after v0.2

1. Should relays be allowed to cache Policies encrypted to members for availability when no member with newer documents is online?
2. Is a 14 day document expiry the right trade between revocation latency under a withholding relay and steward availability requirements?
