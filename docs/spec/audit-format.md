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

and the flat fields of its event (strings, integers, booleans; no nesting). A consumer must
ignore keys and events it does not know. A new key never changes the meaning of an old one; `v`
changes only for a breaking change.

Privacy: no payload bytes are ever recorded. The relay records no client address. A node records the
address an egress stream reached only when the operator turned that on (`include_ips = true`). Host names that a node reached for
a member (egress) are recorded, as they are in the exit's own close line.

## Events (v1)

Relay (`by` = `relay`):

- `session_attach`: `node_id` (hex), `session` (integer), `networks` (the claimed network ids,
  hex, as one comma separated string). The peer address is not recorded.
- `session_superseded`: `node_id`, `session`: a newer session of the same NodeId replaced it.
- `session_evicted`: `node_id`, `session`, `reason` (the name of the ERROR code sent to the node, as the relay's log prints it).

Node (`by` = `node`):

- `egress_stream`: one line for every egress stream this node served as an exit, when it ended:
  `peer` (initiator NodeId, hex), `host`, `port`, `outcome` (the close line's outcome word),
  `up` and `down` (bytes toward and from the target), `secs` (duration, number),
  `ip` (the target address, only with `include_ips`).

The file is opened append only with mode 0600. A write error is logged and counted, never fatal.
There is no rotation: rotate by stopping the process, moving the file, starting it again.
