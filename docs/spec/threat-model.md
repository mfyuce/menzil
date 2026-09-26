# menzil threat model (phase 0 draft, 2026-09-26)

Status: draft for red team review. Companion to `protocol.md`.

## 1. What we protect

| Asset | Why it matters |
|---|---|
| Contents of every private stream and datagram (S2 reach, S3 egress) | The core promise: nobody but the two endpoints reads them |
| Contents of blind public shares (S1, default mode) | The relay operator must not be able to read a share it hosts |
| Node identities and the ability to act as one | A stolen or forged identity opens every service granted to it |
| The policy: who may reach what | Wrong grants are the most likely real world failure |
| Service existence and topology (which nodes exist, which services they run) | Metadata; protected against outsiders, exposed to the relay by design |
| Relay availability | A personal relay is a single point of failure; abuse must not take it down |

## 2. Adversaries and what each can do

### 2.1 Passive network observer (ISP, campus network, wifi)

Sees: TLS 1.3 connections from the node to the relay's domain on 443, their timing and sizes, DNS lookups of the relay name unless DoH is used. Cannot see: anything inside, including which peers talk or which services exist. Not a goal: hiding that the relay domain is being contacted or that a long lived WebSocket exists. Traffic analysis resistance is out of scope.

### 2.2 Inspecting corporate proxy (TLS interception with a trusted enterprise CA)

Sees: the HTTP upgrade request, the WebSocket framing, and the L3 records as ciphertext. Because L3 is a Noise IK session keyed to the relay's static key, the proxy cannot read control records or forward payloads, cannot impersonate the relay to the node, and cannot inject records. It can block, delay, throttle, or drop the connection, and it can observe record sizes and timing. It sees the relay's host name and the proxy CONNECT target. Requirement met by design: the outer TLS is verified against the OS trust store and never pinned, so interception does not hard fail; confidentiality does not depend on L1. Not a goal: passing as browser traffic under fingerprinting (review section 4.5). Reason: on a managed device with interception, fingerprint mimicry would buy nothing.

### 2.3 Malicious or compromised relay

Sees: node identities and membership certificates, which nodes are online, which node sends to which and when, record sizes, advertised public names, and for terminated mode shares the full HTTP plaintext (by design, that mode exists for relay side features). Cannot: read L4 payloads (Noise between the peers, keys never leave the nodes), forge L4 records (authenticated encryption), impersonate a member to another member (L4 handshake verifies NodeCert and MemberCert against the owner key, which the relay does not hold), mint members or change policy (owner signatures), or read blind shares (TLS terminates at the node). Can: drop or delay traffic, refuse service, replay old L3 records (harmless: L3 is a fresh Noise session per connection), and lie about peer presence. Residual risk accepted: metadata exposure to the relay. Mitigation available to users: run your own relay, or attach to several.

### 2.4 Malicious member (a device that is legitimately in the network)

Can: open L4 sessions to other members and attempt any stream. Stopped by: default deny grants enforced at the target node, egress deny lists at the exit, and revocation. Cannot: read traffic between other members (pairwise Noise keys), impersonate the owner, or reach services not granted. Residual risk: a member with an `egress` grant can use the exit's IP address for its traffic; that is the feature, bounded by the exit's allow and deny lists and by revocation.

### 2.5 Stolen node key

An attacker holding a node's Ed25519 key and X25519 key is that node until revoked. Mitigations: keys stored with mode 0600, revocation through a Policy update that relays apply at the next session and peers apply on receipt, MemberCert expiry of 90 days, NodeCert rotation of the X25519 key without changing identity. Not in phase 1: hardware backed keys, device attestation, short lived certificates under one day.

### 2.6 Internet attacker against the relay

Attempts: connection floods, HELLO floods, SNI probing to enumerate shares, abuse of terminated mode shares as an open proxy, ACME abuse. Controls: HELLO rate limits per source IP, one session per NodeId, 64 KiB record cap, per name connection limits, label leasing with ownership proof, blind shares only route to advertised names (unknown SNI gets the operator's static site), ACME challenges only for names the relay knows. Public shares are the one surface where menzil accepts unauthenticated connections; everything else requires a Noise handshake with a member certificate.

### 2.7 Malicious owner or wrong policy

The owner is trusted; there is no protection against the owner. Mistakes are the realistic risk: a grant with `to_node: "*"` and `services: ["*"]`. The CLI must make broad grants explicit and visible (`menzil policy show` prints every grant in words) and default templates must be narrow.

### 2.8 Malicious peer over a direct path (later, phase 3)

When a direct UDP path exists, L4 records travel without the relay. L4 authentication and explicit counters with a replay window were designed so that the direct path adds no new trust: same keys, same records, unordered delivery tolerated.

## 3. Guarantees by layer

| Layer | Confidentiality against | Authenticity | Notes |
|---|---|---|---|
| L1 outer TLS | passive observer only | relay domain, unless intercepted | Verified by the OS trust store, never pinned |
| L3 relay session | observer, inspecting proxy | node to relay and relay to node (Noise IK, relay static key from connection info) | Control plane; relay sees plaintext here by design |
| L4 end to end | observer, proxy, relay | peer to peer (NodeCert plus MemberCert of a common network) | Relay forwards ciphertext with explicit counters |
| L5 streams | inherited from L4 | authorization at the target node (grants), at the exit (egress rules) | OPEN is checked before any byte flows |
| Blind share | observer, proxy, relay | the node's own certificate to the browser | Relay routes on SNI only |
| Terminated share | observer, proxy | relay certificate to the browser; node to relay via L4 | Relay reads HTTP by design |

## 4. Explicit non goals

- Anonymity of nodes toward the relay, or of the relay toward the network.
- Resistance to traffic analysis and fingerprinting by the local network operator.
- Protection against a malicious owner.
- Availability under a determined denial of service against a personal relay.
- Hiding that menzil is in use. The design mimics nothing; it is ordinary TLS carrying an ordinary WebSocket to a personal domain.

## 5. Security requirements that the implementation must test

1. A relay given a modified SEND payload cannot make the destination accept it (L4 AEAD failure closes the session).
2. A node presenting a MemberCert from a different network cannot reach a member of this network through the relay (relay refuses) and cannot complete an L4 handshake with it (peer refuses).
3. A revoked node is disconnected by the relay within one Policy delivery and refused by peers on their next Policy.
4. A stream OPEN for a service without a grant returns `ok: false` and no bytes of the local target are ever read or written.
5. Egress to a denied destination fails before any connection is dialed at the exit.
6. With an interception proxy in the test harness (a TLS terminating proxy with a test CA trusted by the client), the node connects, the proxy sees only ciphertext after the upgrade, and a record injected by the proxy is rejected.
7. Unknown SNI on the relay's 443 receives the static site, not a routing error that reveals share names.
8. The relay's own Noise static key rotation does not let an attacker holding the old key impersonate the relay after nodes have received new connection information.

## 6. Open questions for the red team

1. Should L3 additionally authenticate the relay with its Ed25519 key (a signature in WELCOME) so that connection information can carry only the NodeId, not the X25519 key?
2. Is exposing membership certificates to the relay acceptable, or should the relay learn only a per network pseudonym? (Trade: the relay needs membership to enforce forwarding; pseudonyms would need owner cooperation per relay.)
3. Terminated mode adds relay side features at the cost of plaintext at the relay. Should it be off unless the relay operator and the node owner are the same key?
