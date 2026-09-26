# Closure check of the red team findings against spec v0.2

Produced 2026-09-26 by a verification agent (read only) against commit ef3c238. The four partial items it lists were fixed in the commit that adds this file.

## Findings 1–26 and Answers 1–7 vs protocol.md / threat-model.md v0.2

| # | Severity | Status | v0.2 pointer or gap |
|---|---|---|---|
| 1 | Critical | CLOSED | §5.2: reliable class "accept only counter == last + 1; any gap, duplicate or reordering ends the session and resets every stream"; datagram class gets the 2048 window. Abnormal end resets sockets, "never with a clean end of file" (§5.2). TM §5.1 adds the drop/dup/reorder test. |
| 2 | Critical | CLOSED | §7.2: secret never leaves device; `ADMIT_REQUEST{invite, node_cert, tag=keyed BLAKE2s(...)}`; steward verifies tag/expiry/use-count; relay "only checks the invite signature" and holds via ADMIT_PENDING/`{pending:true}`; renewal over `menzil:docs` (§5.5/7.3). `e2e_proto 0x00` and the "control envelope" are gone (only 0x01/0x02 defined, §4.2). |
| 3 | High | CLOSED | §5.1 init carries `network_id`; prologue includes it. §2.3: "Principal is {network_id, node_id} or {network_id, role}... come only from the Policy and Roster of the network named in that session's handshake." |
| 4 | High | CLOSED | MemberCert removed; §2.3 Roster/Policy, `expires` ≤ issued+14d, fail-closed after. §5.1 carries `roster_seq`/`policy_seq`; §5.5 has the older side fetch documents end-to-end. `certs` added to the Policy schema (§2.3). |
| 5 | High | CLOSED | §5.1: initiator checks responder `node_cert.node_id` == dialed id; responder checks initiator `node_id` == RECV `src`. §2.2 `serial`/highest-seen-wins; §2.3 `min_serial` per member, raised on compromise (§7.3). |
| 6 | High | CLOSED | §6.1: relay principal is `{relay: relay_node_id}` (never a role), may open only `tls:`/`http:`/`acme-http:` accepted names, `target` null; `accept_peers:false` refused. §5.3: "`meta` is honored only from the relay principal." |
| 7 | High | CLOSED | §4.1: new session "not routable and does not supersede an existing one until... ATTACH is decrypted"; HELLO carries a TAI64N timestamp, relay "rejects a timestamp not greater than the last accepted." |
| 8 | High | CLOSED | §4.2: bounded per-(source,destination) queues (4 MiB default), "never stops reading one session because another destination is slow," CREDIT records, droppable flag, send-priority order (control, reliable, droppable). |
| 9 | High | CLOSED | §5.1/5.2: WireGuard-style `sender_index`/`receiver_index`/`counter`; responder keeps current session until a new-session data record decrypts; simultaneous-open keeps the lower NodeId; session pinned to its relay; in-session `REKEY` every 2^20 records/hourly; "no application data in message 1." |
| 10 | High | CLOSED | §12: one agent per user owns all L3/L4 sessions; CLI attaches over local IPC; TM §5.9 test. |
| 11 | High | CLOSED (all sub-items) | §8: canonicalize → match name vs deny/allow → resolve once → check every address vs deny/allow → dial only vetted, never re-resolve. Default list is address-for-address identical to the finding's list (0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.168/16, 198.18/15, 224/4, 240/4, ::/128, ::1, fc00::/7, fe80::/10, ff00::/8, 64:ff9b::/96, 64:ff9b:1::/48, 2002::/16, exit's own addresses); `::ffff:127.0.0.1` handled via the canonicalization step. No "unless owner grants otherwise" override remains. UDP fixed to OPEN target. |
| 12 | High | CLOSED | TM §2.3: "Blind therefore means blind against a passive relay... preventable for custom domains with CAA `accounturi`." §6.2: relay "never holds a certificate whose names cover a blind name" (separate `.t.` zone), 421 for any authority it doesn't terminate. |
| 13 | Medium | CLOSED | §4.1: rotation accepts both old/new static keys 30 days, returns newest NodeCert (TM §5.14 test). §3.2: connection info exchanged out of band, "never fetched through the L1 path it protects." |
| 14 | Medium | CLOSED | §3.3 WS payload ≤65,535; §5.4 DGRAM ≤65,458 (matches corrected figure exactly); WELCOME now carries only `rosters:{NetworkId:u64}`, not full documents; §4.2 `DOC` record chunks Roster/Policy. |
| 15 | Medium | CLOSED | §3.3/4.1: L3 PING/PONG, dead link = no record for two intervals (50s), in-band `REKEY` hourly, "no forced daily reconnect"; §10 idle = 60s; `TCP_NOTSENT_LOWAT`, control-record priority. |
| 16 | Medium | CLOSED | §6.3 matches the fix almost clause-for-clause: parses every request, Host==SNI or 421, strips Forwarded/X-Forwarded-*/X-Real-IP and sets fresh ones, HTTP/2→1.1 translation rejecting CR/LF/NUL and conflicting Content-Length/Transfer-Encoding, Upgrade passed through. |
| 17 | Medium | CLOSED | §4.4 matches Answer 4 (claims via Roster, quotas 20/5-per-week, release by owner-signed drop or 90d idle, 180d quarantine, PSL for multi-tenant). §2.4 "Share services are limited to `http`, `tls` and `tcp`" blocks ADVERTISE→egress mapping. |
| 18 | Medium | CLOSED | §6.2: 16 KiB/10s reassembly with peek cap (§10: 1,024 concurrent); TLS 1.2/1.3 routed identically; ECH "not supported for share names in version 1"; HTTP-01/TLS-ALPN-01 routed per §6.2/6.3. TM §2.7: "Share names are public knowledge through certificate transparency." |
| 19 | Medium | CLOSED | §5.4 token bucket per channel; §5.1 handshake rate limit (10/min per peer); even/odd channel-id split by opener; `OPEN_ACK.channel` field added. |
| 20 | Medium | CLOSED | §5.3: "Grants are re evaluated whenever a Policy changes or a grant's `expires` passes; streams and channels whose grant disappeared are closed with CLOSE `grant_removed`." |
| 21 | Medium | CLOSED | §2.1: domain separation (`"menzil.v1."\|\|type\|\|0x00\|\|body`), strict decode ("no duplicate keys, no unknown keys, definite lengths only"), `Signed = [bstr body, bstr sig]` defined, `secret_hash` named as BLAKE2s (§7.2). |
| 22 | Medium | CLOSED (all 5 sub-items) | §3.1: 407 legs on one kept-alive connection with bodies drained; Kerberos SPN = proxy FQDN; credentials gated on "the operating system's automatic logon policy"; PAC sandboxed (2s/64MiB); TLS 1.2 accepted at L1; §10 HELLO-per-IP=60/min, per-NodeId=10/min post-DH, `retry_after_ms` "honored and spread." |
| 23 | Medium | CLOSED | §2.3: "The Roster is what a relay needs and may see. The Policy is delivered end to end... and never to a relay." TM §1 asset table and §2.3 restate this. |
| 24 | Medium | CLOSED | TM §2.6 new "Stolen owner key" entry. §7.3: owner key stays offline, steward key `may:["admit","renew"]` ≤90 days, "one writer issues sequence numbers." §4.1: "WELCOME `time`... never extends any validity." |
| 25 | Medium | PARTIAL | Most listed contradictions resolved (§13 phase table added; `e2e_proto 0x00` gone; TM §2.5/§7.3 both now say "on receipt"; label wildcard vs TM §2.7 resolved via exact-match-only labels; "stream resumption" language removed). **New/surviving mismatch**: §11 lists `invite` and `proxy` under "Phase 1 commands," but §13 maps "invites through relay" and "8 egress SOCKS and HTTP CONNECT listener" (what `proxy` implements) to Phase 2 only — the same species of cross-section phase inconsistency the finding targeted. |
| 26 | Low/Nit | PARTIAL | 7 of 9 nits closed outright: version negotiation in prologue/payloads (§9), PQ non-goal stated (TM §2.1/§4, protocol §1), `target` null outside egress + no implicit localhost mapping (§5.3/2.4), NodeId fingerprint ≥80 bits (§2.2), Windows ACL (§2.2), 4.1's check now correctly says `x25519_pub` (§4.1), `egress` grammar consistent (always `egress:*`), yamux window explicitly "initial... tuned upward" (§5.3). `session_id`→`session:u32`, `max_peers`, KEEP cadence (20s), `revoked.since:u64`, and an error-code registry are now typed/defined. **Still thin**: `caps:[str]` (§4.1 HELLO) and `alpn:[str]` (§4.4 ADVERTISE) are declared fields with no defined vocabulary or negotiation semantics. |
| A1 (12.1) | — | CLOSED | §3.2 `key` as IK cache, XX fallback; §4.1 node checks `relay_cert.node_id`/`x25519_pub`, remembers highest relay serial; dual-key 30-day rotation; TM §5.14. |
| A2 (12.2) | — | CLOSED | §5.1/5.2: explicit L4 counters, contiguity required for reliable, window only for datagram class. (L3 nonces are implicit via standard Noise transport mode, §4.1 — not restated separately, which is adequate since the pattern is adopted by reference.) |
| A3 (12.3) | — | PARTIAL | MAC-bound `ADMIT_REQUEST` stored/forwarded by relay (§7.2) and phase-1 minimum = pasted token (§13) are both done. **Gap**: answer says admission "also removes `owner_offline`," but §4.2's error-code registry still lists `owner_offline` alongside `peer_offline`. |
| A4 (12.4) | — | PARTIAL | §4.4 implements claims/quotas/release-quarantine exactly. **Gap**: "On a personal relay, configure labels statically" has no corresponding text anywhere in protocol.md. |
| A5 (12.5) | — | DEFERRED | §5.3 adopts the ceiling logic (256 KiB initial, auto-tuned to 16 MiB, no window field in OPEN). But protocol.md §14 "Open items after v0.2," item 2, explicitly defers the "yamux receive window auto tuning policy once credits exist (answer 5 of the red team...)" — named as still open. |
| A6 (TM 6.2) | — | CLOSED | TM §2.3 (relay sees ids/online-state, not grants/names/egress) and TM §4 non-goal "Anonymity of nodes toward relays." |
| A7 (TM 6.3) | — | CLOSED | §6.3: opt-in per share by node, per network by operator, CLI warning. TM §3 guarantees table and §2.3 state the relay reads shares by design in phase 1. |

## Sub-items still missing (all instances found)
- **Finding 25**: §11's "Phase 1 commands" list still includes `invite` (contradicts §13, which puts "invites through relay" in Phase 2 — only pasted-token admission is Phase 1) and `proxy` (contradicts §13, which puts the egress SOCKS/CONNECT listener in Phase 2).
- **Finding 26 / nits list**: `caps` (§4.1 HELLO body) — typed `[str]` but no defined vocabulary. `alpn` (§4.4 ADVERTISE) — typed `[str]` but negotiation/semantics for shares unspecified.
- **Answer 3**: `owner_offline` error code not removed from the §4.2 registry, despite the answer's explicit "removes owner_offline."
- **Answer 4**: "on a personal relay, configure labels statically" is absent from protocol.md.
- **Answer 5**: the yamux auto-tuning *policy* itself (as opposed to the initial value and ceiling) is explicitly left as open item §14.2, not specified in the normative text.

No finding or answer was found fully OPEN (unaddressed), and finding 11's address list and finding 22's carrier bullets check out completely with no missing sub-items.

## Counts per status
- **Findings (1–26)**: CLOSED 24, PARTIAL 2 (25, 26), DEFERRED 0, OPEN 0.
- **Answers (1–7)**: CLOSED 4 (1, 2, 6, 7), PARTIAL 2 (3, 4), DEFERRED 1 (5), OPEN 0.
- **Combined (33 items)**: CLOSED 28, PARTIAL 4, DEFERRED 1, OPEN 0.

Files read: `docs/spec/reviews/2026-09-26-red-team.md`, `docs/spec/protocol.md` (v0.2, 366 lines), `docs/spec/threat-model.md` (v0.2, 100 lines), `docs/spec/decisions/0001-relay-path-transport.md`. No files were edited; no commits made.
