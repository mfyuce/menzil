# menzil protocol, version 1 (spec v0.2, 2026-09-26)

Status: v0.2 after the red team review of v0.1 (`reviews/2026-09-26-red-team.md`) and the constraint verification (`reviews/2026-09-26-constraint-verification.md`). Normative for protocol version 1. Which parts ship in which implementation phase is stated in section 13, not by omission.

Terms: node = any menzil process holding an identity; agent = the one per user process that owns the identity and all sessions (section 12); relay = a node role that is publicly reachable and forwards for others; peer = the node at the other end of an end to end session; owner = the key that defines a network; steward = a key the owner delegates for day to day admission and renewal.

## Changes in v0.2 (red team finding numbers in brackets)

- Reliable L4 records must be contiguous; only datagrams get a replay window. Abnormal L4 end resets local sockets [1].
- Admission no longer sends the invite secret anywhere; a keyed tag binds the request to the device's NodeCert; the relay stores and forwards [2].
- Every authorization is scoped to one network, named in the L4 handshake and prologue [3].
- MemberCert is gone. A relay visible Roster and an end to end Policy, both owner signed with an expiry, are the single source of truth; peers exchange sequence numbers and fetch newer documents end to end [4, 23].
- Peer identity is bound: dialed NodeId, RECV source and prologue must agree; NodeCert has a serial and the Roster carries a minimum serial per member [5].
- The relay principal may open only share streams for names it accepted [6].
- A new relay session becomes routable only after ATTACH; HELLO carries a monotonic timestamp [7].
- L3 credit flow control, bounded per destination queues, droppable datagrams [8].
- WireGuard style L4 header with receiver index; in session rekey; simultaneous open rule [9].
- One agent per user owns the relay sessions; CLI processes attach over local IPC [10].
- Egress resolves once, vets every address, ships a complete default deny list [11].
- Blind mode is blind against a passive relay only; no relay certificate may cover a blind name; 421 for foreign authorities [12].
- Relay identity anchored in its Ed25519 NodeId, XX fallback when the static key is unknown, rotation rule [13].
- Corrected size limits, chunked documents, L3 PING/PONG and REKEY, TLS 1.2 accepted at L1, proxy authentication details [14, 15, 22].
- Terminated mode header hygiene, label claims and quotas, SNI router rules, flood limits, grant re-evaluation, signed object encoding, owner key delegation [16 to 24].
- Phase mapping section, consistency fixes, low findings [25, 26].

## 1. Layering

```
L5  streams and datagrams        yamux streams; datagram channels; OPEN authorization      (A <-> B)
L4  end to end session           Noise IK, indexed records, contiguous reliable class      (A <-> B, opaque to the relay)
L3  relay session                Noise IK or XX node <-> relay, control records, SEND/RECV, credit
L2  carrier                      WebSocket binary messages over HTTP/1.1 upgrade (later: HTTP/2 extended CONNECT)
L1  outer TLS                    TLS 1.2 or 1.3 to the relay's public CA certificate, OS trust store, never pinned
L0  network                      TCP 443 to the relay, optionally through an HTTP CONNECT proxy
```

Rules that hold everywhere:

- Nothing above L1 trusts L1 for confidentiality or peer authenticity. L3 authenticates node and relay to each other; L4 authenticates peers to each other.
- The relay forwards L4 records without interpreting them. A one byte `e2e_proto` tag identifies the L4 protocol so that another one (QUIC, later) can ride the same relays.
- No reliable protocol is stacked inside another reliable protocol: L5 streams ride yamux over a contiguous L4 record sequence; L5 datagrams are length delimited messages outside yamux; nothing retransmits inside the outer TCP.
- Signatures cover exact transmitted bytes with domain separation (section 2.1). Signed bodies are decoded strictly; unsigned control messages ignore unknown keys.
- Post quantum key agreement is a version 1 non goal; all key agreement is X25519. A hybrid will be a version 2 change to the handshakes.

## 2. Identities and documents

### 2.1 Encoding of signed objects

```
Signed(type) = CBOR array [ bstr body, bstr sig ]
sig          = Ed25519( "menzil.v1." || type || 0x00 || body )
```

`type` is one of `nodecert`, `roster`, `policy`, `invite`, `steward`, `release`. `body` is a CBOR map decoded strictly: no duplicate keys, no unknown keys, definite lengths only. A verifier keeps and forwards the signed bytes verbatim; it never re encodes them. Hashes are BLAKE2s-256 unless stated.

### 2.2 Node identity

Each node holds an Ed25519 key pair; `NodeId` is the 32 byte public key, displayed as lowercase hex (prompts show the full id or a fingerprint of at least 80 bits). On Unix the key file has mode 0600; on Windows it carries an ACL for the owning user only.

The X25519 static key used for Noise is bound to the NodeId by a self signed certificate:

```
NodeCert = Signed("nodecert"){ v: 1, node_id: bytes32, x25519_pub: bytes32, serial: u32, not_before: u64, not_after: u64 }
```

`serial` increases by one on every rotation. Every verifier remembers the highest serial it has accepted for a NodeId and rejects lower serials. Validity is at most 400 days. A relay is a node and has a NodeCert too.

### 2.3 Networks, roster, policy

A network is identified by its owner's Ed25519 public key, `NetworkId`. Two owner signed documents describe it, always issued together with the same `seq`:

```
Roster = Signed("roster"){ v: 1, network_id, seq: u64, issued: u64, expires: u64,
    members: [ { node_id, min_serial: u32 } ],
    revoked: [ { node_id, since: u64 } ],
    stewards: [ Steward ],
    labels:  [ { name: str, node_id } ] }

Policy = Signed("policy"){ v: 1, network_id, seq: u64, issued: u64, expires: u64,
    members: [ { node_id, name: str, roles: [str] } ],
    certs:   [ NodeCert ],
    grants:  [ { from: Principal, to_node: node_id | "*", services: [ServicePattern], expires: u64 | null } ],
    egress:  [ { node_id, allow: [HostPortPattern], deny: [HostPortPattern] } ],
    accept:  [ { node_id, peers: bool } ] }
```

The Roster is what a relay needs and may see. The Policy is delivered end to end between members and never to a relay. `expires` is at most `issued` plus 14 days; a steward re issues both documents automatically before expiry. Once `expires` has passed, relays stop forwarding for that network and peers refuse new L4 sessions of it (fail closed). A node keeps the newest Roster and Policy it has verified; it never accepts a lower `seq`, and a reinstalled node accepts the first `seq` it verifies.

`Principal` is `{ network_id, node_id }` or `{ network_id, role }`. Roles and grants exist only inside one network. Membership, roles, grants, egress and label ownership for a session between A and B come only from the Policy and Roster of the network named in that session's handshake.

```
Steward = Signed("steward"){ v: 1, network_id, steward_pub: bytes32, may: ["admit", "renew"], not_after: u64 }
```

A steward may sign Roster and Policy re issues and admissions on the owner's behalf; verifiers accept a Roster or Policy signed by the owner or by a steward listed in the previous accepted Roster. There is exactly one active steward; the owner rotates it by issuing a new Roster. Only one writer issues sequence numbers; two devices holding the owner key must not both issue.

### 2.4 Services

```
ServiceId  = kind ":" label
kind       = "tcp" | "udp" | "http" | "tls" | "egress" | "acme-http" | "menzil"
```

`tcp:ssh`, `udp:wg`, `http:app`, `tls:app`, `egress:*`, `acme-http:app`, `menzil:docs` (reserved, section 5.5). A label never maps implicitly to a port on localhost; every service is configured explicitly. `ServicePattern` allows `*` in the label position only. Share services are limited to `http`, `tls` and `tcp`.

## 3. Carrier (L0 to L2)

### 3.1 Reaching the relay

1. Proxy resolution: explicit `--proxy`; else `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` in either case; else the operating system proxy settings; else PAC or WPAD when configured or discovered. `--no-proxy` disables discovery. PAC scripts run in a sandbox with no network access, a 2 second time limit and a 64 MiB memory limit.
2. `CONNECT relay-host:443 HTTP/1.1`. Authentication: Basic; NTLM and Negotiate through the platform SSPI on Windows, Negotiate through GSSAPI elsewhere when a system library exists. All 407 legs of one authentication run on one kept alive connection with response bodies drained. The Kerberos service principal is the proxy's fully qualified host name. Credentials are offered to a WPAD discovered proxy only when the operating system's automatic logon policy allows it for that proxy. A 407 with no supported scheme is a hard error with a clear message. Direct connection is attempted only when `NO_PROXY` or the PAC says DIRECT.
3. TLS to the relay, versions 1.2 and 1.3 accepted (L1 is untrusted; some interception appliances speak 1.2 only). ALPN `http/1.1`. Certificate verification uses the platform verifier plus the system bundle on Linux. Pinning is forbidden.
4. `GET <path> HTTP/1.1` with `Upgrade: websocket`, `Sec-WebSocket-Protocol: menzil.v1`. Default path `/_menzil/v1`, operator configurable, carried in the connection information. Any other path returns the operator's ordinary website. The offered and selected subprotocol strings are bound into the L3 prologue (section 4.1).
5. Later: HTTP/2 extended CONNECT with `:protocol = menzil.v1` when the relay is reached without a forward proxy.

### 3.2 Connection information

```
menzil://relay.example:443/_menzil/v1?id=<relay NodeId hex>[&key=<relay x25519 hex>]
```

`id` is the anchor. `key` is a cache that enables the one round trip IK handshake; when it is absent or stale the node uses XX (section 4.1). Connection information is exchanged out of band (typed, pasted, QR), never fetched through the L1 path it protects.

### 3.3 WebSocket usage

- Binary messages only; one message is one L3 record; payload at most 65,535 bytes (the Noise message limit). No compression extensions.
- Liveness is measured at L3 (PING and PONG records, section 4.2), not with WebSocket control frames, because proxies may answer or swallow those. A link is dead when no authenticated record has arrived for two ping intervals (interval 25 s, so 50 s). Control records take priority over SEND on the sender's queue; implementations set `TCP_NOTSENT_LOWAT` or equivalent where available.
- Reconnection: exponential backoff 1 s to 60 s with full jitter, reset after a connection older than 60 s; `retry_after_ms` from GOAWAY is honored and spread.

## 4. Relay session (L3)

### 4.1 Handshake

Pattern `Noise_IK_25519_ChaChaPoly_BLAKE2s` when the relay's static key is known, `Noise_XX_25519_ChaChaPoly_BLAKE2s` otherwise. Prologue: `"menzil.v1.relay" || 0x00 || offered_subprotocols || 0x00 || selected_subprotocol || 0x00 || pattern_name`.

```
HELLO   (node -> relay)   final handshake message from the node carries
        CBOR{ v: 1, node_cert: NodeCert, networks: [NetworkId], timestamp: bytes12 (TAI64N),
              roster_seq: { NetworkId: u64 }, caps: [str], e2e_protos: [u8] }
WELCOME (relay -> node)   final handshake message from the relay carries
        CBOR{ v: 1, relay_cert: NodeCert, session: u32, time: u64,
              limits: { max_record: u32, max_peers: u32, credit: u32 }, rosters: { NetworkId: u64 } }
```

In IK the node's payload rides message 1 and the relay's rides message 2; in XX the node's payload rides message 3 and the relay's message 2. The node verifies `relay_cert.node_id` equals the `id` of its connection information and `relay_cert.x25519_pub` equals the relay static key of the handshake, and remembers the highest relay serial. During rotation a relay accepts handshakes to both its old and new static key for 30 days and always returns the newest NodeCert. WELCOME `time` is informational and never extends any validity.

The relay verifies the NodeCert and rejects a serial lower than the highest it has seen or lower than any Roster's `min_serial` for that node, rejects a `timestamp` not greater than the last accepted for that NodeId, and checks each claimed network against its Rosters: unknown network, unlisted node or revoked node fails with ERROR. A node may claim no network; it may then only redeem an invite.

After WELCOME all records are Noise transport messages. The new session is not routable and does not supersede an existing one until the node's first transport record, ATTACH, is decrypted. Then the previous session for that NodeId receives GOAWAY `superseded`. Noise `Rekey()` runs in both directions on REKEY (section 4.2) every hour; there is no forced daily reconnect.

### 4.2 Records

```
u8 type | body
```

| type | name | direction | body |
|---|---|---|---|
| 0x00 | ATTACH | node to relay | empty; makes the session routable |
| 0x01 | SEND | node to relay | `bytes32 dst \| u8 e2e_proto \| u8 flags \| payload` |
| 0x02 | RECV | relay to node | `bytes32 src \| u8 e2e_proto \| u8 flags \| payload` |
| 0x03 | ADVERTISE | node to relay | CBOR (4.4) |
| 0x04 | ADVERTISE_ACK | relay to node | CBOR `{ accepted: [str], rejected: [{ name, reason }] }` |
| 0x05 | DOC | both | `u8 doc_type \| bytes16 doc_id \| u16 index \| u16 count \| chunk`; chunked Roster (relay and node) or Policy (node only, never to a relay); whole document at most 1 MiB |
| 0x06 | PEER_STATE | relay to node | CBOR `{ node_id, online: bool, direct: [Addr] }` (direct empty in phase 1) |
| 0x07 | CREDIT | relay to node | CBOR `{ peer: node_id, bytes: u32 }` |
| 0x08 | PING | both | `bytes8 nonce` |
| 0x09 | PONG | both | `bytes8 nonce` |
| 0x0a | REKEY | both | empty; the sender rekeys its sending state after this record, the receiver rekeys its receiving state on receipt |
| 0x0b | ADMIT_REQUEST | node to relay | CBOR (7.2) |
| 0x0c | ADMIT_PENDING | relay to steward node | CBOR (7.2) |
| 0x0d | ADMIT_RESULT | relay to node | CBOR (7.2) |
| 0x0e | ERROR | both | CBOR `{ code: u16, msg: str }` |
| 0x0f | GOAWAY | relay to node | CBOR `{ reason: str, retry_after_ms: u32 }` |

`e2e_proto`: `0x01` menzil Noise (section 5), `0x02` reserved for QUIC. Others are rejected with ERROR `unknown_e2e`. `flags` bit 0 = droppable (datagram class). SEND payload is at most 65,535 minus 35 bytes.

Forwarding rule: the relay forwards a SEND as a RECV to `dst` only if `src` and `dst` are both listed and unrevoked in one common, unexpired Roster the relay holds, `dst` is online and attached, and `dst` has not set `accept_peers: false` in its ADVERTISE. Otherwise ERROR `forbidden` or `peer_offline` goes back to the sender. The relay never inspects payloads.

Flow control and queues: the relay keeps one bounded queue per (source session, destination session), default 4 MiB. It never stops reading one session because another destination is slow. Reliable SENDs consume credit granted by CREDIT records for that peer (initial credit `limits.credit`, default 1 MiB, replenished as bytes are written to the destination socket); a reliable SEND beyond credit is a protocol violation and closes the session. Droppable SENDs are not credited, pass through a token bucket per (source, destination) and are the first records dropped when a queue is full. Senders order their output: control records, then reliable SEND, then droppable SEND.

Error codes are a registry in `menzil-proto`; version 1 defines at least `bad_cert`, `stale_serial`, `stale_timestamp`, `unknown_network`, `not_member`, `revoked`, `roster_expired`, `forbidden`, `peer_offline`, `unknown_e2e`, `credit_exceeded`, `too_large`, `rate_limited`, `label_taken`, `label_unclaimed`, `owner_offline`, `bad_invite`, `bad_tag`.

### 4.3 Documents

A node sends DOC(roster) to a relay when it holds a newer Roster than the relay's WELCOME `rosters` shows; a relay sends DOC(roster) to attached members of that network when it receives a newer one. Policies travel only end to end (section 5.5). Relays keep the newest Roster per network they are configured to serve (by NetworkId) and refuse Rosters of other networks.

### 4.4 Advertising public names

```
ADVERTISE = CBOR{ v: 1, shares: [ { name: str, mode: "blind" | "terminated", service: ServiceId, alpn: [str] } ], accept_peers: bool }
```

A relay accepts a `name` only if the Roster of one of the node's networks lists that name for this NodeId in `labels`. Labels under the relay's share domain are one LDH label each (letters, digits, hyphen, 1 to 63 characters, not starting or ending with a hyphen), not in the relay's reserved list (`www`, `mail`, `admin`, `api`, `relay`, `t`, the operator's own names). Custom domains are fully qualified names whose DNS TXT record `_menzil.<domain>` equals the NetworkId hex, checked at ADVERTISE and daily, exact match only. Quotas per network per relay: 20 names, and at most 5 new names per week. A name is released by an owner signed Roster that drops it, or after 90 days without a session; a released name is quarantined for 180 days before another network may claim it. Operators of multi tenant relays put the share domain on the Public Suffix List so tenants are not same site.

## 5. End to end session (L4)

### 5.1 Handshake

A and B run `Noise_IK_25519_ChaChaPoly_BLAKE2s`, A as initiator, in the network A chooses. Prologue: `"menzil.v1.e2e" || network_id || initiator_node_id || responder_node_id`. A knows B's current NodeCert from the Policy `certs`.

```
init  = u8 0x01 | u32 sender_index | bytes32 network_id | noise msg1
resp  = u8 0x02 | u32 sender_index | u32 receiver_index | noise msg2
data  = u8 0x03 | u32 receiver_index | u64 counter | ciphertext
```

Handshake payloads: `CBOR{ v: 1, node_cert: NodeCert, roster_seq: u64, policy_seq: u64, e2e_protos: [u8] }`. There is no application data in message 1.

Checks. The initiator verifies the responder's `node_cert.node_id` equals the NodeId it dialed and `x25519_pub` equals the handshake static key. The responder verifies the initiator's `node_id` equals the RECV `src` and its static key matches, that both are unrevoked members of `network_id` in an unexpired Roster and Policy, and that the initiator's serial is not below `min_serial`. The responder then decides whether any grant exists for the initiator on this node; if none, it answers with a data record of kind CLOSE `no_grant` and the initiator learns nothing further. Handshakes are rate limited per peer (10 per minute) because each costs four Diffie Hellman operations and two signature checks.

Simultaneous open: if both sides initiate to each other, the session initiated by the lower NodeId (byte wise) is kept. A responder keeps its current session with a peer until a data record on the new session decrypts. A session is pinned to the relay path its initiation used; if that relay session ends, the L4 session ends (phase 1 consequence, decision 0001).

### 5.2 Records and counters

The 64 bit counter has two classes by its top bit. Class 0 (reliable) carries kinds MUX, CLOSE, KEEP, REKEY and must arrive contiguous: a receiver accepts only `counter == last + 1`; any gap, duplicate or reordering ends the session and resets every stream. Class 1 (datagram) carries kind DGRAM and uses a 2048 record replay window. Both classes count from zero per session and per direction.

Rekey: every 2^20 records or every hour a sender emits REKEY (class 0) and applies Noise `Rekey()` to its sending state; the receiver applies it on receipt. A full new handshake with new indices happens every 24 hours; the old session stays valid until the first data record of the new one is received.

Plaintext of a data record:

```
u8 kind | body
0x01 MUX     one yamux frame
0x02 DGRAM   u16 channel | datagram bytes
0x03 CLOSE   CBOR{ code: u16, msg: str }
0x04 KEEP    empty, every 20 s when idle
0x05 REKEY   empty
```

When an L4 session ends abnormally, the node closes the local sockets of its streams with a reset where the platform allows, never with a clean end of file, so that truncation is visible to applications.

### 5.3 Streams

yamux (spec version 0) inside MUX records, initial receive window 256 KiB, receiver tuned upward to 16 MiB within a per session budget. The stream initiator writes an OPEN header first:

```
OPEN     = u16 len | CBOR{ v: 1, service: ServiceId, target: { host: str, port: u16 } | null, meta: { client_ip: str | null, sni: str | null } }
OPEN_ACK = u16 len | CBOR{ ok: bool, code: u16, msg: str, channel: u16 | null }
```

`target` must be null unless `service` is `egress:*`. `meta` is honored only from the relay principal (section 6). The target node evaluates the grant for `(network, initiator)` on `(this node, service)` and, for egress, the rules of section 8. On `ok` the stream is a byte pipe to the configured local target or the vetted egress address. OPEN times out after 10 seconds. Grants are re evaluated whenever a Policy changes or a grant's `expires` passes; streams and channels whose grant disappeared are closed with CLOSE `grant_removed`.

### 5.4 Datagram channels

A channel is opened by a yamux stream whose OPEN names a `udp:` service or `egress:*` with a UDP target; OPEN_ACK returns `channel`. The session initiator allocates even channel ids, the responder odd ones. Datagrams travel as DGRAM records outside yamux flow control, at most 65,458 bytes each, through a token bucket per channel (default 20 Mbit/s, 256 KiB burst, operator and owner configurable). A channel closes with its stream. UDP datagrams of a channel always go to the OPEN target; the far end never redirects them.

### 5.5 Documents end to end

Handshake payloads carry each side's `roster_seq` and `policy_seq`. The side with the older documents opens a stream `menzil:docs` and receives the newer signed Roster and Policy, verifies them and adopts them. This is how a revocation reaches peers even when a relay withholds it. A steward node pushes new documents to every online member through the same stream and expects an acknowledgment.

## 6. Public shares (S1)

### 6.1 The relay as a principal

A relay is never a member. For share traffic it acts as the relay principal `{ relay: relay_node_id }` and may open streams to a node only for `tls:`, `http:` and `acme-http:` services whose names it accepted in ADVERTISE_ACK for that node, always with `target` null. The node accepts such OPENs only over the L3 session it has with that relay's NodeId. Relays refuse member traffic to nodes with `accept_peers: false`.

### 6.2 Blind mode (default)

The relay reads the ClientHello on 443 without terminating TLS: it reassembles up to 16 KiB across TLS records and TCP segments with a 10 second deadline and a cap on concurrent peeks. SNI equal to the relay's own host name is handled as section 3. SNI matching an advertised blind name opens `tls:<name>` to the owning node with `meta.sni` and pipes the bytes, ClientHello included. No SNI, an unknown name, or a name in quarantine receives the operator's static site. TLS 1.2 and 1.3 clients route the same way. Encrypted Client Hello is not supported for share names in version 1: the relay publishes no ECH configuration for them.

The node terminates TLS with its own certificate. HTTP-01 challenges arrive through the relay's port 80 listener, which forwards `/.well-known/acme-challenge/` requests for a blind name to `acme-http:<name>` and redirects every other port 80 request to https. TLS-ALPN-01 challenges route through the SNI router like any other ClientHello for the name. DNS-01 is the node's own affair.

What blind means: the relay cannot read a blind share as long as it behaves passively. An operator who controls the DNS of the share domain can obtain a certificate for a blind name (DNS-01) and terminate the share itself; this is detectable through certificate transparency and preventable for custom domains with CAA `accounturi` (RFC 8657). The threat model states this explicitly. To avoid connection coalescing leaks, a relay never holds a certificate whose names cover a blind name: terminated shares live under a separate zone (`<label>.t.<domain>` with a wildcard for `*.t.<domain>`), and the relay answers HTTP 421 for any authority it does not terminate.

### 6.3 Terminated mode

Shares advertised as `terminated` are served under the terminated zone with the relay's certificate (wildcard by DNS-01 or per name by HTTP-01 or TLS-ALPN-01 from the relay's own ACME account). The relay terminates TLS and HTTP and opens one `http:<name>` stream per client connection carrying HTTP/1.1. It parses every request, requires `Host` to equal the SNI name (421 otherwise), removes any `Forwarded`, `X-Forwarded-*` and `X-Real-IP` headers, sets fresh `X-Forwarded-For` and `X-Forwarded-Proto`, translates HTTP/2 to HTTP/1.1 rejecting CR, LF and NUL in field values and requests with both `Content-Length` and `Transfer-Encoding`, and passes `Upgrade` (WebSocket) through. Relay side access control (a password page, OIDC) is a later addition to this mode only. Terminated mode requires opt in per share by the node and per network by the operator; the CLI warns that the relay reads these shares.

### 6.4 Raw TCP

A `tcp:` share is reachable by SNI on 443 as a blind share whose node side speaks any protocol inside the TLS it terminates. Dedicated public ports are an operator option, off by default.

## 7. Admission, invites, renewal, revocation

### 7.1 Admission by the owner or steward

`menzil admit <node-id> [--role ...] [--name ...]` on a device holding the owner or steward key issues Roster and Policy with `seq + 1`, listing the new member and its current NodeCert, and pushes them to relays (DOC roster) and members (section 5.5). The new member receives both when it next connects, or as a pasted token.

### 7.2 Invites

```
Invite = Signed("invite"){ v: 1, network_id, invite_id: bytes16, secret_hash: bytes32, roles: [str], expires: u64, uses: u8 }
```

The owner or steward hands the device the Invite plus a 32 byte secret in one URL. The secret never leaves the device. The device connects to the relay with its NodeCert, no network claim, and sends

```
ADMIT_REQUEST = CBOR{ invite: Invite, node_cert: NodeCert,
                      tag: BLAKE2s-256-keyed(key = secret, data = "menzil.v1.admit" || invite_id || node_cert_bytes) }
```

The relay checks the Invite signature against the network's owner or steward and stores at most 100 pending requests per network. When the steward node is attached, the relay delivers ADMIT_PENDING with the request. The steward verifies `secret_hash == BLAKE2s(secret)` for the secret it issued, the tag, `expires`, and its own use counter (use counts are enforced by the steward, never by relays). It then issues Roster and Policy `seq + 1` and pushes them; the relay answers the device with ADMIT_RESULT `{ roster: Roster, policy: Policy }` or `{ pending: true }`. A relay cannot mint membership: nothing it holds lets it forge the tag or sign documents.

### 7.3 Renewal and revocation

Roster and Policy are re issued by the steward before `expires`; a member within 24 hours of expiry that has not received new documents requests them over `menzil:docs` from the steward node or any member with newer documents. Revocation is a Roster and Policy update: relays end the revoked node's session and refuse its HELLO on receipt; peers close its L4 sessions on receipt and refuse new ones. A node whose key is compromised gets `min_serial` raised in the Roster so that its stale NodeCerts die even before revocation propagates.

A stolen owner key is unrecoverable for that network; the remedy is a new network. Owners keep the owner key offline and give the always online admission device a steward key with `may: ["admit", "renew"]` and a lifetime of at most 90 days.

## 8. Egress (S3)

A node with an `egress` entry in the Policy accepts `egress:*` streams and channels. Client side, the agent runs a local listener (SOCKS5 with CONNECT and UDP ASSOCIATE, and HTTP CONNECT) on 127.0.0.1; each connection becomes an OPEN with the requested target; names are sent as names and resolved at the exit.

Exit rules, in order: canonicalize the target (IPv4 mapped IPv6 to IPv4, no leading zeros); match `deny` then `allow` against the name; resolve the name once; check every returned address against `deny` then `allow`; dial only addresses that passed, and never re resolve. UDP channels are fixed to the OPEN target. The default `deny` list is written into the Policy at network creation so that what is enforced is exactly what is signed:

```
0.0.0.0/8  10.0.0.0/8  100.64.0.0/10  127.0.0.0/8  169.254.0.0/16  172.16.0.0/12  192.168.0.0/16  198.18.0.0/15  224.0.0.0/4  240.0.0.0/4
::/128  ::1/128  fc00::/7  fe80::/10  ff00::/8  64:ff9b::/96  64:ff9b:1::/48  2002::/16  and every address of the exit itself
```

Later: a TUN mode feeding the same streams and channels.

## 9. Versioning and negotiation

The subprotocol `menzil.v1`, both Noise prologues, and every CBOR body's `v` carry the version; the offered and selected subprotocols are bound into the L3 prologue and the supported `e2e_proto` tags into both handshake payloads, so downgrade is detected. Unknown L3 record types produce ERROR `unknown_type` without closing the session; unknown L4 kinds close the L4 session. New `e2e_proto` tags introduce a different L4 without touching relays.

## 10. Limits and abuse controls (relay defaults)

| Item | Default |
|---|---|
| HELLO per source IP | 60 per minute (offices share one proxy address), then HTTP 429 |
| HELLO per NodeId after a successful Diffie Hellman | 10 per minute |
| Sessions per NodeId | 1 attached |
| L3 record | 65,535 bytes payload |
| Per destination queue | 4 MiB |
| Initial credit per peer | 1 MiB |
| Datagram token bucket per (source, destination) | 20 Mbit/s, 256 KiB burst |
| Pending admissions per network | 100 |
| Names per network, new names per week | 20, 5 |
| Concurrent ClientHello peeks | 1,024 |
| Session idle without any record | 60 s |

## 11. Configuration surface (informative)

Node: identity path, relays (connection information), networks, services, shares, egress listener. Relay: listen addresses, domains for blind and terminated zones, ACME account, the NetworkIds it serves, WebSocket path, limits, static site directory, reserved names. Phase 1 commands: `menzil init`, `agent`, `admit`, `invite`, `relay`, `node`, `expose`, `reach`, `proxy`, `stdio`. Their flags are not part of this protocol.

## 12. The agent and local IPC

Exactly one process per user, the agent, holds the identity and owns every L3 and L4 session. CLI commands (`reach`, `stdio`, `proxy`, `expose`) attach to it over a local socket restricted to that user: a Unix domain socket under the user's runtime directory with mode 0600, or a Windows named pipe with an ACL for the user only. The agent starts on first use and exits when idle, unless run as a service. `menzil stdio <node>/<service>` bridges its standard input and output to one L5 stream through the agent, which is what an SSH `ProxyCommand` needs; several such processes share one agent and one relay session.

## 13. Phase mapping

| Section | Phase 1 | Phase 2 | Phase 3 |
|---|---|---|---|
| 3.1 proxy: environment variables, Basic | yes | | |
| 3.1 proxy: OS settings, PAC, WPAD, NTLM, Negotiate | | yes | |
| 3.1 step 5 HTTP/2 extended CONNECT | | yes | |
| 3.3 relay static site for non tunnel paths | minimal 404 page | full static site | |
| 4 relay session incl. ATTACH, credit, PING, REKEY, DOC | yes | | |
| 4.4 label claims and quotas | claims in Roster | quotas, custom domains, quarantine | |
| 5 end to end session, reliable class, streams | yes | | |
| 5.4 datagram channels | | yes | |
| 6.2 blind shares with node side ACME | | yes (becomes the default when it ships) | |
| 6.3 terminated shares with relay ACME | yes (the only share mode in phase 1; the relay reads shares in phase 1) | header hygiene complete | |
| 7 admission by pasted token; invites through relay | pasted token | invites | |
| 8 egress SOCKS and HTTP CONNECT listener | | yes | |
| 8 TUN mode | | | yes |
| 12 agent and IPC, stdio, reach | yes | | |
| PEER_STATE direct addresses, QUIC e2e_proto | | | yes |

## 14. Open items after v0.2

1. Whether the relay should be allowed to cache Policies encrypted to members (availability when the steward is offline) or documents must always come from members.
2. yamux receive window auto tuning policy once credits exist (answer 5 of the red team: about 14 Mbit/s per stream at 150 ms with 256 KiB).
3. A short checksummed display form for NodeIds.
