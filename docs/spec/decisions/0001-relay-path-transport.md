# 0001. Relay path transport: own stack (WebSocket, Noise, yamux) first, QUIC later behind an opaque relay

Date: 2026-09-26. Status: accepted for phase 1, amended the same day after the red team review (spec v0.2), to be revisited after phase 1 with measurements.

## Context

The relay path is the one path that must work everywhere, because the office network allows only TCP 443 through an HTTP proxy and blocks UDP (review section 4). Two designs were on the table for what runs inside the WebSocket.

Option 1, own stack: Noise IK for the node to relay session and for the end to end session, yamux for streams, length delimited datagrams. Simple, efficient over TCP (no inner retransmission), fully under project control. Costs: a relay reconnect resets end to end sessions and their streams; connection migration between relay and a future direct path must be handled at the application level (re dial); two stream implementations if the direct path later uses QUIC.

Option 2, QUIC everywhere via iroh: public key addressed QUIC connections, hole punching (QUIC Address Discovery), a self hostable relay whose protocol is WebSocket only since iroh 0.91 (August 2026), DNS or DHT discovery, one connection object that migrates between relay and direct paths, and a stable 1.x API since June 2026. Costs: QUIC inside TCP on the relay path (double reliability, extra framing, head of line blocking anyway), a dependency on n0's roadmap and defaults (their relays and DNS server must be replaced by the user's own), no verification that the relay client honors NTLM or PAC proxies, and no public HTTPS ingress in either case (that is our code regardless).

## Decision

Build option 1 for phase 1, with one structural rule that keeps option 2 open at zero cost to relays: the relay forwards SEND payloads tagged with a one byte `e2e_proto` and never interprets them. Tag 0x01 is the Noise based L4 of `protocol.md`; tag 0x02 is reserved for QUIC packets. A future L4 based on quinn (own hole punching) or on an iroh endpoint would run over the same relays and the same L3 records.

Two consequences are accepted knowingly:

1. Relay reconnects tear down L4 sessions in phase 1. Client commands (`reach`, `stdio`, `proxy`) re establish their listeners automatically; applications see a dropped connection, as they do with ngrok and cloudflared today.
2. The direct path in phase 3 will most likely be QUIC, which means the L4 stream layer changes at that point (yamux to QUIC streams). L4 version 1 is therefore defined for the relay path: its reliable record class requires contiguous counters (a gap ends the session rather than corrupting a yamux stream), and only the datagram class tolerates loss and reordering. The L5 OPEN and OPEN_ACK headers and the service model are defined independently of the mux so that the QUIC change stays below them.

## Why not option 2 now

The office network is the case that must work and it is exactly the case where iroh's advantages (hole punching, migration) are unusable. Starting with option 1 keeps the phase 1 dependency set small (tokio, hyper, rustls, tokio-tungstenite, snow, yamux, ciborium, blake2, ed25519-dalek, x25519-dalek) and every byte on the wire specified in this repository.

## Revisit criteria (after phase 1)

Measure on a real relay with an intercontinental client: throughput per stream at 256 KiB yamux window, connection setup time through a CONNECT proxy, behavior on relay restart. Then estimate the phase 3 effort for own quinn hole punching versus an iroh endpoint, and check whether iroh's relay client passes an authenticated CONNECT proxy in a test harness. If iroh passes the proxy test and the migration behavior matters to users, adopt it as `e2e_proto 0x02` and keep the relay unchanged.

## Related

`protocol.md` sections 1, 4.2, 5.1, 5.2, 9 and 13. Review sections 4.2, 4.4, 6.3, 6.6. Red team findings 1, 9 and 25 (`reviews/2026-09-26-red-team.md`).
