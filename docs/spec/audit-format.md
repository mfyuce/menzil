# menzil audit file, format v1

An optional file that a relay or a node appends to while it runs (`menzil relay run
--audit-file PATH`, `[audit] file` in a node's config.toml). Off unless asked for.

One JSON object per line, UTF-8, `\n` terminated. Every line has:

| key | type | meaning |
|---|---|---|
| `v` | integer | format version, `1` |
| `ts` | integer | Unix seconds when the event happened |
| `by` | string | `relay` or `node` |
| `ev` | string | event name |

and the flat fields of its event: strings (at most 255 characters), integers, numbers with a fraction, booleans, and lists of strings (at most 64 items); no nesting. A consumer must
ignore keys and events it does not know. A new key never changes the meaning of an old one; `v`
changes only for a breaking change.

Privacy: no payload bytes are ever recorded. The relay records no client address. A node records the
address an egress stream reached only when the operator turned that on (`include_ips = true`). Host names that a node reached for
a member (egress) are recorded, as they are in the exit's own close line.

## Events (v1)

Relay (`by` = `relay`):

- `session_attach`: `node_id` (hex), `session` (integer), `networks` (the claimed network ids,
  hex, as a list). The peer address is not recorded.
- `session_superseded`: `node_id`, `session`: a newer session of the same NodeId replaced it.
- `session_evicted`: `node_id`, `session`, `reason` (the protocol.md 4.2 name of the ERROR code sent to the node, such as `not_member`). An eviction can also happen before any attach (a session that is refused while it attaches), so a `session_evicted` line may have no `session_attach` before it.
- `share_accepted`: `node_id`, `session`, `name`: the relay accepted this name from an ADVERTISE (one line per name, every ADVERTISE).
- `share_rejected`: `node_id`, `session`, `name`, `reason` (the relay's free text, as sent in ADVERTISE_ACK).
- Tenant changes, written by the process that makes them (`menzil relay <command>` with `MENZIL_RELAY_AUDIT_FILE` set, or `menzil-relay-admin --audit-file`), which may append to the same file as the running relay, with `by` = `relay`: `network_added` (`network`, `seq`, `tenant` unless the default tenant), `network_removed` (`network`, `tenant` if one listed it), `tenant_removed` (`tenant`, `networks` list), `tenant_suspended` and `tenant_resumed` (`tenant`; nothing is written when the state did not change), `tenant_updated` (`tenant`, `class` now in force). A line is written after the change succeeded; lines of several processes interleave whole, each ending in a newline.

Node (`by` = `node`):

- `egress_stream`: one line for every egress stream this node served as an exit, when it ended:
  `peer` (initiator NodeId, hex), `host` (an address literal is written as `<ip>` unless `include_ips` is on), `port`, `outcome` (the close line's outcome word),
  `up` and `down` (bytes toward and from the target), `secs` (duration, number),
  `ip` (the target address, only with `include_ips`).

There is no session end event: the absence of a `session_superseded` or `session_evicted` line does not mean a session is still attached. A relay's `session_attach` lines are a persistent record of when each NodeId was online in each network (metadata the relay sees by design, threat-model.md); keep the file as private as the relay's own state. `include_ips` without `file` does nothing. The file must be on a local disk (a write blocks the writing task), is a regular file (anything else is refused), and is opened append only with mode 0600 when it is created (an existing file keeps its mode, with a warning if group or others can reach it). A write error is logged and counted, never fatal.
There is no rotation: rotate by stopping the process, moving the file, starting it again.
