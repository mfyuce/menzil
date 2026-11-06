# menzil threat model (spec v0.3, 2026-11-06)

Status: v0.3 adds the hostile tenant of a shared relay (2.10, with a non goal in 4 and tests 15 to 19 in 5) to v0.2, which followed the red team review of v0.1. Companion to `protocol.md` v0.3; section references point there.

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

The holder is that node until revoked. Mitigations: key files restricted to the user (mode 0600, Windows ACL), revocation through Roster and Policy applied by relays and peers on receipt, `min_serial` raising so stale NodeCerts die immediately, document expiry of 14 days as the upper bound for a relay that withholds updates from a verifier that holds no steward signed renewal (a steward renews from the base it holds, so a revocation that never reaches the steward lasts until the steward's `not_after`, at most 90 days; this is accepted: a steward key is trusted for its whole `not_after`, and a stolen steward key is a risk of up to 90 days, so keep stewards short lived and on devices that are online), one attached session per NodeId so the legitimate node notices displacement. Not in phase 1: hardware backed keys, device attestation.

### 2.6 Stolen owner key

Unrecoverable for that network: the attacker can sign documents and admit members. Remedy is a new network and re admission of devices. Mitigations: the owner key stays offline; the always online admission device holds a steward key limited to admit and renew with a lifetime of at most 90 days; one writer issues sequence numbers. A steward signed document must travel with its owner signed base and may only renew or append members with no roles, a unique name and a `min_serial` no higher than their own certificate's serial (protocol.md 2.3), so a stolen steward key cannot unrevoke, grant, claim labels or change stewards; a verifier that holds the steward's earlier admissions refuses a document that drops them, and a steward that may only admit cannot keep renewing what it admitted. A stolen steward key can still take the network down at once: it can sign a pair at the owner base `seq` plus 2^20 with a short `expires`, which every verifier then holds, and only the owner recovers the network (by signing a higher `seq`, which takes the steward out); it cannot outrank the owner.

### 2.7 Internet attacker against the relay

Attempts: connection floods, HELLO floods (an office behind one proxy shares one address, so per address limits are generous and per NodeId limits apply after the Diffie Hellman), SNI probing, abuse of terminated shares as an open proxy, ACME abuse, admission request floods. Controls: rate limits, one attached session per NodeId, 65,535 byte records, bounded queues, per name connection limits, label claims signed by owners with quotas and quarantine, unknown SNI receives the static site, ACME routing only for known names, Host must match SNI (421 otherwise), pending admissions capped. Public shares are the one surface accepting unauthenticated connections; everything else requires a Noise handshake with a listed identity. Share names are public knowledge through certificate transparency; the static site fallback prevents casual probing, not enumeration.

### 2.8 Wrong policy

The owner is trusted; mistakes are the realistic risk (`to_node: "*"` with `services: ["*:*"]`). The CLI prints every grant in words, default templates are narrow, and the default egress deny list is written into the Policy so that what is enforced is what was signed.

### 2.9 Malicious peer over a direct path (phase 3)

The direct path will most likely be QUIC with its own reliability; L4 version 1 records are defined for the relay path, where the reliable class requires contiguity and only datagrams tolerate loss. Whatever the direct path is, it must add no trust: same identities, same network scoping, same grants.

### 2.10 Hostile tenant on a shared relay

A relay may serve several unrelated tenants, each a group of networks its operator assigned (protocol.md 10). Every tenant trusts the operator exactly as 2.3 says; tenancy protects tenants from each other, not from the operator. The attackers: the owner of a tenant's network, who can sign any Roster for it (any members, any labels, any `seq`, up to its size figure) and run any number of devices; a member device of some tenant; and a stranger with a key it just generated, listed in no Roster. Their goals against a victim tenant: learn its networks, members, labels or which of its nodes are online; reach its nodes; take its share names; starve it of relay memory, CPU, bandwidth, sessions, handshake slots or log lines.

Controls (protocol.md section in brackets):

- Nothing names another tenant's networks. WELCOME lists only the networks the HELLO claimed and passed, and nothing in XX [4.1]; a network the relay does not serve is refused `not_member` like one that does not list the node, at the same cost [4.1]; DOC for a network the session did not claim, or the relay does not serve, gets no answer [4.3]; a HELLO with more than 32 networks is refused before any lookup [4.1]; WELCOME `session` numbers do not count other connections [4.1].
- Nothing reaches another tenant's node. Forwarding needs a network claimed by both sessions, so an owner who lists a victim's NodeId in its own Roster can send nothing to it; every case after authorization answers the same `peer_offline`, so the answer is no presence oracle [4.2]. A Roster's `min_serial` and `revoked` count only for the networks a node claimed, so one owner cannot lock a node out of another's network.
- Names live in one zone per tenant. A tenant can produce no name in another's zone, so there is nothing to race for and `label_taken` exists only inside one tenant; flat names exclude every slug; a released flat name and a removed tenant's slug are quarantined for 180 days, so links, bookmarks and certificate history of the old holder never land on a new tenant [4.4, 11].
- Every resource a tenant can use is bounded per tenant or per session: sessions attached and waiting, pairs, destinations per sender, queued droppable bytes, bandwidth and volume, Roster size and adoptions, names [10]; and per source address and per NodeId before any tenant is known: connection rate, handshakes in flight, sessions waiting to attach, the ATTACH deadline, write timeouts, the replay history bound [10]. A tenant over its bandwidth delays only its own CREDIT [4.2].
- No lock that other tenants need is held across a signature check or an ADVERTISE decision; the log lines a peer can cause are throttled per peer, so that no peer floods the operator's log or hides another's first warning.

Residual risks, accepted:

- Until the share domain is on the Public Suffix List and browsers carry the listing, a blind share of one tenant can set cookies for the share domain that browsers send to other tenants' shares (cookie tossing). One tenant's abuse, phishing on a share for example, can get the share domain blocklisted for every tenant; the operator's remedy is to remove that tenant.
- A session counts against the tenant of every network it claims and is refused while any of them is at a session figure. A device that joined a hostile owner's network as well as the victim's can therefore be kept off the victim's network too, for as long as the hostile owner keeps its own tenant full. Listing the device in a Roster is not enough for this: a device claims only the networks it joined, and one that leaves the hostile network out of its HELLO is unaffected.
- The default tenant has no tenant figures and flat names. A friend's network belongs in a named tenant; a network left in the default tenant is limited only by the global limits.
- ERROR `over_quota` for a new pair names no destination, so a refused node cannot tell which peer it was; the figures are meant to be reached only by abuse. A relay restart begins a new volume period; only the operator can cause one.
- Inside one tenant there is no isolation beyond fair sharing of delayed CREDIT: its members share its figures, and one of them can use them up for the others. The tenant's owner admitted that member.

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
- Isolation of tenants from the relay operator: on a shared relay the operator sees every tenant's Rosters, NodeIds, traffic metadata, label claims and terminated shares, as 2.3 says; tenancy isolates tenants from each other only (2.10).

## 5. Security requirements the implementation must test

1. A relay that drops, duplicates or reorders one reliable L4 record causes the receiver to end the session; no stream ever delivers a hole or reordered bytes. Datagram records inside the window are accepted, outside it dropped.
2. An admission request replayed by the relay with a different NodeCert is rejected by the steward (tag mismatch); a request with the correct tag succeeds exactly `uses` times across any number of relays.
3. A member of network N2 cannot use a role of N2 to reach a service granted to that role name in N1 on a node that belongs to both.
4. A revoked node is refused by relays and peers on receipt of the new Roster, and its existing relay and L4 sessions are ended then; a peer that cannot obtain documents newer than `expires` refuses new full L4 sessions and serves nothing but `menzil:docs` on the ones it has; it still completes docs only sessions, so that newer documents can reach it.
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
15. WELCOME `rosters`: a stranger with a fresh key sees no network, in IK and in XX; an IK member sees exactly the networks it claimed, not every network that lists it; an XX member sees none, and its Roster upload is adopted or dropped as equal.
16. A HELLO that claims a network gets a byte identical ERROR whether the relay does not serve that network or serves it without listing the node; a HELLO that claims no network is refused; a DOC for an unserved network, for a served network the session did not claim, and a forged one all get no record back.
17. An owner who lists another tenant's node in its own Roster gets the same `peer_offline` whether that node is online, offline, or closed to peers, and the node receives nothing; members of a network both sides claimed still reach each other; every refused reliable SEND is reimbursed.
18. A tenant never gets a name in another tenant's zone, and the answer to its ADVERTISE does not depend on what another tenant holds; a released flat name and a removed tenant's slug stay quarantined across a relay restart.
19. One tenant at its figures does not take a second tenant's sessions, pairs or throughput: the 65th attached node of a tenant is refused while another tenant's first is accepted, a new pair over the figure is refused while existing pairs work, and the second tenant's transfer rate is not reduced by the first tenant's stalled credit. At the default floor a 16 MiB transfer completes and no session ends.

## 6. Open questions after v0.2

1. Should relays be allowed to cache Policies encrypted to members for availability when no member with newer documents is online?
2. Is a 14 day document expiry the right trade between revocation latency under a withholding relay and steward availability requirements?
