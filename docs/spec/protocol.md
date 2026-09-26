# menzil protocol, version 1 (phase 0 draft, 2026-09-26)

Status: draft for red team review. Everything here is normative for phase 1 unless marked "later". Terms: node = any menzil process holding an identity (the CLI in client mode is a node too); relay = a node role that is publicly reachable and forwards for others; peer = the node at the other end of an end to end session; owner = the key that admits members and signs policy for a network.

## 1. Layering

```
L5  streams and datagrams        yamux streams; datagram channels        (A <-> B, end to end)
L4  end to end session           Noise IK handshake, explicit nonce records, opaque to the relay
L3  relay session                Noise IK node <-> relay, control records, SEND/RECV forwarding
L2  carrier                      WebSocket binary messages over HTTP/1.1 upgrade (later: HTTP/2 extended CONNECT, HTTP/3)
L1  outer TLS                    TLS 1.3 to the relay's public CA certificate, verified against the OS trust store, never pinned
L0  network                      TCP 443 to the relay, optionally through an HTTP CONNECT proxy
```

Design rules that follow from the review (sections 4 and 6):

- L1 may be terminated and re-encrypted by a corporate proxy. Nothing above L1 trusts L1 for confidentiality or peer authenticity. L3 authenticates the relay to the node and the node to the relay; L4 authenticates peers to each other.
- The relay forwards L4 records without interpreting them. The L4 protocol is identified by a one byte tag so that a different end to end protocol (QUIC, later) can ride the same relay unchanged.
- No reliable protocol is stacked inside another reliable protocol by design: L5 streams are yamux over the ordered L3 path, and L5 datagrams are length delimited messages, never a second TCP.
- Every message that a party signs is signed over the exact byte string transmitted. No canonicalization.

## 2. Identities and objects

### 2.1 Keys

Each node holds one Ed25519 signing key pair generated on first run and stored with mode 0600. `NodeId` is the 32 byte Ed25519 public key. Display form is lowercase hex for version 1 (a shorter checksummed form is a later addition).

For key agreement each node holds an X25519 static key pair. It is bound to the NodeId by a self signed `NodeCert`:

```
NodeCert = Signed{ body = CBOR{ v: 1, node_id: bytes32, x25519_pub: bytes32, not_before: u64, not_after: u64 }, sig: ed25519(body) }
```

`not_after` is at most 400 days after `not_before`. Rotating the X25519 key is a new NodeCert with the same NodeId.

Relays are nodes too. The relay's NodeId and X25519 public key are published in its connection information (section 3.2).

### 2.2 Networks, members, policy

A `Network` is identified by the owner's Ed25519 public key (`NetworkId`). A node is a member when it holds a `MemberCert` signed by the owner:

```
MemberCert = Signed{ body = CBOR{ v: 1, network_id: bytes32, node_id: bytes32, roles: [str], not_before: u64, not_after: u64 }, sig: ed25519_owner(body) }
```

Roles are free strings; version 1 defines `member`, `relay`, `exit`. A member certificate is valid for at most 90 days and renewed by the owner (section 7).

The `Policy` is one owner signed document, replaced whole, with a strictly increasing `seq`:

```
Policy = Signed{ body = CBOR{
    v: 1, network_id: bytes32, seq: u64, issued: u64,
    members: [ { node_id: bytes32, name: str, roles: [str] } ],
    grants:  [ { from: Principal, to_node: bytes32 | "*", services: [ServicePattern], expires: u64 | null } ],
    revoked: [ { node_id: bytes32, since: u64 } ],
    egress:  [ { node_id: bytes32, allow: [HostPortPattern], deny: [HostPortPattern] } ]
}, sig: ed25519_owner(body) }
```

`Principal` is a NodeId or a role name. `ServicePattern` is a `ServiceId` with `*` allowed in the label position. Grants are default deny. A node enforces the policy for streams addressed to itself, always, regardless of what the relay did. The relay enforces only membership: it forwards L4 records between two nodes only if both hold a valid MemberCert of the same network and neither is revoked at the relay's latest known policy.

The organization profile (review section 10, decision record 0002 later) replaces MemberCert and Policy with an external `PolicySource` and replaces L4 authentication with mTLS certificates. The wire layout of L3 and L5 does not change; only the L4 handshake payload and the authorization calls do.

### 2.3 Services

```
ServiceId  = kind ":" label
kind       = "tcp" | "udp" | "http" | "tls" | "egress" | "acme-http"
```

Examples: `tcp:ssh` (a named TCP service the node maps to 127.0.0.1:22), `tcp:5432` (label may be a port for convenience), `http:app` (a public HTTP share named app), `tls:app` (a public share where the node terminates TLS itself), `egress` (dial anything, subject to the egress rules), `acme-http:app` (ACME HTTP-01 challenges for the share app).

The node's service registry maps a ServiceId to a local dial target and, for shares, to a public name under a relay's domain. Registration is local configuration; the relay learns about public names through ADVERTISE (section 4.3).

## 3. Carrier (L0 to L2)

### 3.1 Reaching the relay

1. Resolve the proxy: `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` (upper and lower case), then the operating system proxy settings, then PAC or WPAD when a PAC URL is configured or discovered. Explicit `--proxy` overrides everything; `--no-proxy` disables discovery.
2. If a proxy applies: `CONNECT relay-host:443 HTTP/1.1` with `Proxy-Authorization` as needed. Authentication schemes in version 1: Basic; NTLM and Negotiate on Windows through the platform SSPI; Negotiate elsewhere through GSSAPI when a system library is present. A 407 that offers no supported scheme is a hard error with a clear message. If the proxy refuses, fall back to a direct connection only if `NO_PROXY` or the PAC says DIRECT for the host.
3. TLS 1.3 to the relay. ALPN `http/1.1` (later also `h2`). SNI is the relay host name. Certificate verification uses the platform verifier; on Linux the system CA bundle is added. Pinning is forbidden.
4. HTTP/1.1 `GET <path> HTTP/1.1` with `Upgrade: websocket`, `Sec-WebSocket-Protocol: menzil.v1`, standard key and version headers. The default path is `/_menzil/v1`; the relay operator may change it, and the client learns it from the connection information. The relay answers 101 with the protocol echoed. Any other path on the relay returns the operator's ordinary website, so the domain looks like the personal web server it is.
5. Later: when the relay is reached directly and both sides speak HTTP/2, an extended CONNECT stream with `:protocol = menzil.v1` may replace step 4. Never through a forward proxy (RFC 8441 scopes extended CONNECT to origin servers).

### 3.2 Connection information

A relay is described by a small text blob that the operator hands out (also encoded as a URL and a QR code):

```
menzil://relay.example:443/_menzil/v1?id=<relay NodeId hex>&key=<relay x25519 hex>
```

The `key` lets the node run Noise IK against a known static key even when a corporate proxy has replaced the relay's L1 certificate.

### 3.3 WebSocket usage

- Binary messages only. One message is one L3 record. Maximum message size 64 KiB plus headers; a relay closes connections that exceed it.
- The client sends a WebSocket ping every 25 seconds and treats a missing pong within 10 seconds as a dead connection. The relay sends no unsolicited pings.
- Compression extensions are not negotiated.
- Reconnection: exponential backoff from 1 s to 60 s with full jitter, reset after a connection that lived longer than 60 s.

## 4. Relay session (L3)

### 4.1 Handshake

Immediately after the 101, the node sends Noise message 1 and the relay answers with Noise message 2. Pattern `Noise_IK_25519_ChaChaPoly_BLAKE2s`, prologue `menzil.v1.relay`. The node is the initiator and knows the relay's static key from the connection information.

```
HELLO   (node -> relay)  noise msg 1, payload = CBOR{ v: 1, node_cert: NodeCert, member_certs: [MemberCert], caps: [str], policy_seq: { network_id: u64 } }
WELCOME (relay -> node)  noise msg 2, payload = CBOR{ v: 1, relay_id: bytes32, time: u64, session_id: bytes16, policies: [Policy], limits: { max_record: u32, max_peers: u32 } }
```

The relay verifies: NodeCert signature and validity; each MemberCert signature against an owner key the relay is configured to serve; that the NodeId in the Noise static key's NodeCert matches the Noise static key presented; that the node is not revoked. On failure the relay sends `ERROR` and closes. A node may present zero member certificates; such a node can only use the relay for what the relay operator allows unauthenticated nodes to do (version 1: nothing except redeeming an invite, section 7).

All records after WELCOME are Noise transport messages. Because the WebSocket path is ordered and reliable, Noise's implicit nonces are used at this layer. Rekey every 2^32 messages or 24 hours by a fresh handshake on a new connection.

### 4.2 Record format

Inside each decrypted L3 record:

```
u8 type | body
```

| type | name | direction | body |
|---|---|---|---|
| 0x01 | SEND | node to relay | `bytes32 dst_node_id \| u8 e2e_proto \| payload` |
| 0x02 | RECV | relay to node | `bytes32 src_node_id \| u8 e2e_proto \| payload` |
| 0x03 | ADVERTISE | node to relay | CBOR (4.3) |
| 0x04 | ADVERTISE_ACK | relay to node | CBOR `{ accepted: [str], rejected: [{ name: str, reason: str }] }` |
| 0x05 | POLICY | both | a Policy object; a node sends it when it is the owner or carries a newer seq; the relay sends the newest it knows |
| 0x06 | PEER_STATE | relay to node | CBOR `{ node_id: bytes32, online: bool, direct: [Addr] }` (direct is empty in phase 1) |
| 0x07 | INVITE_REDEEM | node to relay | CBOR (7.2) |
| 0x08 | INVITE_RESULT | relay to node | CBOR (7.2) |
| 0x0e | ERROR | both | CBOR `{ code: u16, msg: str }` |
| 0x0f | GOAWAY | relay to node | CBOR `{ reason: str, retry_after_ms: u32 }` |

`e2e_proto` values: `0x01` menzil Noise (section 5), `0x02` reserved for QUIC, others rejected. The relay forwards a SEND as a RECV to the destination node's current session, unmodified, if the membership rule of 2.2 holds and the destination is online; otherwise it answers ERROR `peer_offline` or `forbidden` to the sender. The relay never buffers SEND payloads beyond the socket send buffer, and it never inspects them.

One active session per NodeId per relay. A new HELLO from the same NodeId replaces the old session, which receives GOAWAY `superseded`.

### 4.3 Advertising public names

```
ADVERTISE = CBOR{ v: 1, shares: [ { name: str, mode: "blind" | "terminated", service: ServiceId, alpn: [str] } ], accept_peers: bool }
```

`name` is a label under the relay's domain (`app` for `app.relay.example`) or a fully qualified custom domain the node claims. The relay accepts a label if it is free or already owned by the same NodeId; labels are leased for 30 days after the last session and released afterwards. Custom domains require a DNS TXT record `_menzil.<domain>` equal to the NodeId hex; the relay checks it at ADVERTISE time and once a day.

`accept_peers: false` means the node wants no L4 sessions from anyone, only its shares (an unattended kiosk).

## 5. End to end session (L4)

### 5.1 Handshake

Two nodes A and B run `Noise_IK_25519_ChaChaPoly_BLAKE2s` with prologue `menzil.v1.e2e`, A as initiator. A knows B's X25519 static key from B's NodeCert, obtained from the Policy (the owner includes the members' current NodeCerts in a `certs` field) or from a direct exchange. The handshake messages travel as SEND payloads with `e2e_proto = 0x01`.

Handshake payloads carry the initiator's and responder's NodeCert and MemberCert. Each side verifies the other is a member of a common network, not revoked, and that the Noise static key matches the NodeCert. B then decides whether it is willing to talk to A at all (policy grants exist for A on B); if not, B answers with an L4 CLOSE and A learns nothing about B's services.

### 5.2 Records

L4 transport records are:

```
u64 counter (little endian) | ciphertext
```

The counter is the explicit Noise nonce. Receivers keep a 2048 record replay window and accept out of order records inside it. This makes L4 indifferent to the path: over the relay the path is ordered, over a later direct UDP path it is not. Rekey by a fresh handshake after 2^60 records, 2^30 records, or 2 hours, whichever comes first, using a new session id so that in flight records on the old session still decrypt.

Plaintext of each record:

```
u8 kind | body
kind 0x01 MUX      body = one yamux frame
kind 0x02 DGRAM    body = u16 channel | datagram bytes
kind 0x03 CLOSE    body = CBOR{ code: u16, msg: str }
kind 0x04 KEEP     body = empty
```

Over the relay path, a lost record (a relay reconnect on either side) breaks the yamux state. Version 1 handles this by tearing the L4 session down and letting applications re-dial; `menzil` client commands reconnect their listeners automatically. A later QUIC based L4 removes this limitation; the relay does not change for it.

### 5.3 Streams

yamux (spec version 0) runs inside kind 0x01 records with a window of 256 KiB. The initiator of a stream writes an OPEN header as the first bytes of the stream:

```
OPEN     = u16 len | CBOR{ v: 1, service: ServiceId, target: { host: str, port: u16 } | null, meta: { client_ip: str | null, sni: str | null } }
OPEN_ACK = u16 len | CBOR{ ok: bool, code: u16, msg: str }
```

The target node checks the policy grant for (initiator principal, this node, service) and, for `egress`, the egress allow and deny lists against `target`. On `ok` the stream is a transparent byte pipe to the mapped local target (or to the dialed egress destination). On failure the target node writes OPEN_ACK with `ok: false` and closes the stream. Stream open timeout is 10 seconds.

### 5.4 Datagrams

A datagram channel is opened as a yamux stream whose OPEN has `service` of kind `udp` or the special label `egress` with a UDP target; the OPEN_ACK returns `channel: u16`. Datagrams then travel as kind 0x02 records tagged with that channel, at most 65,467 bytes each, outside yamux flow control. A channel closes when its yamux stream closes. Later profiles carry WireGuard packets this way for an SD-WAN fallback; the design deliberately keeps them out of the reliable stream so that no second congestion control loop runs inside the outer TCP.

## 6. Public shares (S1) on the relay

### 6.1 Blind mode (default)

The relay accepts TCP on 443 and reads the ClientHello without terminating TLS. If the SNI equals the relay's own host name, the connection is handled as section 3. If the SNI matches an advertised blind share, the relay opens an L4 stream to the owning node with `service = "tls:<name>"` and `meta.sni`, writes the already read ClientHello bytes, and pipes both directions. The node terminates TLS with its own certificate and speaks to the local application. The relay sees only TLS.

Certificates for blind shares belong to the node: HTTP-01 challenges arrive through the relay's port 80 listener, which forwards requests for `/.well-known/acme-challenge/` on a share's name to the node as an `acme-http:<name>` stream; TLS-ALPN-01 challenges arrive naturally through the SNI router because the ACME server's ClientHello carries the share's name; DNS-01 is the node's own affair.

### 6.2 Terminated mode

For shares advertised as `terminated`, the relay holds the certificate (a wildcard for its domain via DNS-01, or per name via HTTP-01 or TLS-ALPN-01 using the relay's own ACME account), terminates TLS and HTTP, and opens one L4 stream per client connection with `service = "http:<name>"` and `meta.client_ip`. The stream carries the HTTP/1.1 bytes of that connection; the relay adds `X-Forwarded-For` and `X-Forwarded-Proto` headers and nothing else. Relay side access control (a password page, OIDC) is a later addition to this mode only.

### 6.3 Raw TCP

A share of kind `tcp` on the relay is reachable by SNI on 443: clients that can set an SNI (`openssl s_client`, stunnel, a menzil client) connect with `SNI = <name>.<relay-domain>`; the relay treats it as a blind share whose node side speaks whatever protocol it wants inside the TLS it terminates. Allocating a dedicated public port is an operator option, off by default.

## 7. Admission, invites, revocation

### 7.1 Admission by the owner

The owner runs `menzil admit <node-id> [--role ...] [--name ...]`, which produces a MemberCert and a new Policy with `seq + 1` and pushes both to every relay the owner is connected to (POLICY record). The relay stores the newest Policy per network and delivers it to members on WELCOME and on change. The joining node receives its MemberCert inside the Policy's `certs` field on its next HELLO, or out of band as a pasted token.

### 7.2 Invites

An invite lets a device join without the owner typing its NodeId:

```
Invite = Signed{ body = CBOR{ v: 1, network_id: bytes32, invite_id: bytes16, secret_hash: bytes32, roles: [str], expires: u64, uses: u8 }, sig: ed25519_owner(body) }
```

The owner gives the device the invite plus the 32 byte secret (one URL). The device connects to the relay with a NodeCert and no MemberCert and sends `INVITE_REDEEM { invite: Invite, secret: bytes32, node_cert: NodeCert }`. The relay checks the signature, the hash and the use count, then forwards the request to the owner's online node as a RECV with a reserved `e2e_proto = 0x00` control envelope. The owner node signs the MemberCert and answers; the relay returns `INVITE_RESULT { member_cert, policy }`. If the owner is offline the relay answers `owner_offline` and the device retries with backoff. Relays do not hold owner keys and cannot mint membership.

### 7.3 Revocation and expiry

Revocation is a Policy update listing the NodeId in `revoked`. Relays terminate the revoked node's session at the next Policy and refuse its HELLO; peers refuse L4 handshakes from it and close open L4 sessions on the next Policy they receive. MemberCerts expire in 90 days and are renewed by the owner's periodic Policy re-issue; a node whose certificate is within 7 days of expiry asks the owner through the relay (`renew` control envelope).

## 8. Egress (S3)

A node with the `exit` role and an `egress` rule set accepts `service = "egress"` streams. The client side runs a local listener: SOCKS5 (CONNECT and UDP ASSOCIATE) and HTTP CONNECT on 127.0.0.1. Each accepted connection becomes an L4 stream OPEN with the target; hostnames are sent as names and resolved at the exit (SOCKS5h semantics), so DNS leaves through the exit as well. The exit applies the egress deny list before the allow list; the default deny list contains the private ranges (RFC 1918, link local, loopback, ULA) unless the owner grants otherwise. Later: a TUN mode feeding the same streams and datagram channels.

## 9. Versioning and extensibility

- The WebSocket subprotocol `menzil.v1`, the Noise prologues, and every CBOR body's `v` field carry the version. A receiver rejects unknown major versions at the handshake and ignores unknown CBOR keys elsewhere.
- Unknown L3 record types produce ERROR `unknown_type` and do not close the session. Unknown L4 kinds close the L4 session.
- New `e2e_proto` tags are how a different L4 (QUIC) is introduced without touching relays.

## 10. Limits and abuse controls (relay)

| Item | Default |
|---|---|
| HELLO attempts per source IP | 10 per minute, then 429 at the HTTP layer |
| Sessions per NodeId | 1 |
| Record size | 64 KiB |
| SEND rate per session | operator configurable, unlimited by default for personal relays |
| Blind share connections per name | operator configurable |
| Labels per NodeId | 20 |
| Session idle without WebSocket pong | 35 s |

## 11. Configuration surface (informative)

Node configuration (TOML) declares identity path, relays (connection information strings), services, shares, egress rules. Relay configuration declares listen addresses, domain, ACME account for terminated mode, the owner keys it serves, the WebSocket path, limits, and the static site directory. `menzil init`, `menzil admit`, `menzil invite`, `menzil relay`, `menzil node`, `menzil expose`, `menzil reach`, `menzil proxy`, `menzil stdio` are the phase 1 commands; their exact flags are not part of this protocol.

## 12. Open items for the red team

1. Is one Noise IK session between node and relay enough, or should the relay additionally sign WELCOME with its Ed25519 key so that relay identity survives an X25519 key rotation?
2. Explicit counters at L4 with implicit nonces at L3: is the asymmetry justified (L3 is always ordered, L4 may later be unordered)?
3. Invite redemption through the relay to an online owner node versus pre signed MemberCerts only: is the added relay control envelope worth it in phase 1?
4. Label leasing on the relay (30 days) versus first come first served with owner signatures: abuse versus simplicity.
5. yamux window 256 KiB over a relay with intercontinental RTT: expected throughput ceiling, and whether the window should be negotiated in the OPEN.
