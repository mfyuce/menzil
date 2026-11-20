# menzil throughput and latency over a relay (2026-11-20, first round)

Status: first measurements and a root-cause reading. Nothing fixed yet; the fix needs a design (see
"What follows"). Lab: `docs/private/tools/bench/` (menzil-prv): a loopback relay and two nodes, a TCP
forwarder that adds a one-way delay and a per connection rate cap between the nodes and the relay, a
random byte server (not a company service), and a client that measures request latency and bulk
rates. Release build of this tree (f85da24), one machine, so CPU is shared (load about 5).

## Measurements (57 ms one way to the relay, so 115 ms to the relay and 230 ms node to node)

| case | result |
|---|---|
| small request, same connection | 230 ms (= node to node RTT, nothing to save) |
| small request, new connection | 461 ms (two RTTs: OPEN/OPEN_ACK, then request/answer) |
| bulk, 1 stream | 30 Mbit/s |
| bulk, 4 streams | 50 Mbit/s total (about 12.5 each) |
| bulk, 16 streams | 64 Mbit/s total (about 4.5 each) |
| small request while 2 bulk streams run, no rate cap | 1034 ms new, 472 ms warm |
| the same with a 15 Mbit/s cap per connection (the laptop line) | 1265 ms new, 1860 ms warm (max 2235 ms) |

Parallel streams do scale on a clean link in the lab (30 to 64 Mbit/s), so the owner's "4 streams total
4.2 Mbit/s" is not a protocol ceiling: it is the line (15.9 Mbit/s) plus the standing queues below.

## Root cause of the "pending" requests: ordered standing queues, sized for a fast long path

One L4 session carries every stream as one ordered, counted record sequence (Noise counters: a record
cannot be reordered or dropped once encrypted). Bytes wait in series at: the node's send budget
(`L4_SEND_BUDGET_PER_DST` 1 MiB, `outbound.rs`), the relay's per pair credit and queue (credit 1 MiB,
`relay_cmd.rs`, queue 4 MiB, `forward.rs`; credit is returned when the record is handed to the
destination socket, so the kernel's send buffer toward a slow client adds to it), and yamux windows of up
to 16 MiB per stream. Every small record (an OPEN, an ACK, a window update, a small request) waits behind
all of that. At a 16 Mbit/s line 1 MiB is 0.5 s, 2 MiB 1 s, plus kernel buffers and wifi: the 3.7 to 12.6 s
the owner saw. Fairness between streams exists (yamux round robin) but only before the queue; there is no
priority lane after it.

Experiment: credit and node budget both cut to 256 KiB. With the 15 Mbit/s cap the warm small request fell
from 1860 to 1151 ms, but uncapped throughput fell from 50 to 16 Mbit/s (4 streams): the in flight limit
must be at least the bandwidth delay product (100 Mbit/s x 230 ms = 2.9 MB), so no fixed constant serves
both the slow wifi line and a fast long path. Credit returns when the relay writes the RECV, so the credit loop is node to relay (115 ms): the ceiling
for one (source, destination) pair is 1 MiB / 0.115 s = about 73 Mbit/s (an earlier draft said 36, wrong).
Lab caveat: `delayproxy.py` buffers without limit, so TCP never pushes back and the slow laptop leg is not
reproduced faithfully; fix first (design note slice 0).

## Other findings from the owner's log (reading of the code)

- `no OPEN_ACK within 10s` (`l5_stream.rs` OPEN_TIMEOUT 10 s): the OPEN waits in the same queue; under a
  standing queue of seconds plus a reconnect it expires. Streams open during a reconnect are lost (the L4
  session belongs to one L3 epoch).
- `this node is not connected to the relay (yet)`: the reach agent refuses while the node is detached; a
  reconnect storm (below) makes it frequent. Seen in the lab too in the first seconds after start.
- `link idle too long, presumed dead` (`session.rs`, 50 s of silence = two 25 s ping intervals): the
  `recv` loop that answers PING and ticks also awaits `carrier.send` for replies, so a blocked socket
  write (bufferbloat on a bad wifi link) can starve the loop; to be checked with a test.
- `dropped an L3 event nobody was reading ... no available capacity`: cosmetic. `Node::take_events` has
  a reader only for expose/admission; the CLI node never takes it, so the 256 slot channel fills with
  Attached/Detached copies and every later event logs a warning (rate limited to one a second). A reader
  that does not exist should not be warned about.
- A new connection costs two RTTs (OPEN/OPEN_ACK before the first byte): the request could ride with the
  OPEN (saves one RTT, about 115 to 230 ms on this path).

## What follows (TODO.md)

1. Adaptive in flight limit instead of fixed 1 MiB (design first, opus): size the node send budget and
   the relay credit from the measured delivery rate (credit return rate) times a target queue delay
   (about 200 ms), never below a floor and never above the BDP need; or a priority lane for small and
   control records ahead of bulk (needs counters assigned after prioritising, so before encryption).
2. Quiet the passthrough warning when nobody takes the events.
3. A test that a blocked carrier write does not stall PING answering or the dead link tick.
4. OPEN carrying the first bytes; OPEN_ACK timeout and streams across a reconnect (TBD 96).
5. Nearer relay or a direct path (RTT), the owner's priority 1.
