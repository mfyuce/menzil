# menzil-relay-admin

A thin gRPC agent (`TenantAdmin`, `proto/menzil_admin.proto`, v3.1) for menzil-ui. It runs on the
relay machine and changes the relay's tenant files through `menzil_cli::relay_cmd::tenants`
(under `lock_relay`, one change at a time in this process). It never touches keys, rosters of its
own or the relay process. A reply means "the file is written"; the running relay applies it
within 15 seconds.

* Mutual TLS 1.3 only, no plaintext listener. The client certificate is required and verified
  against the `--client-ca` file alone (not the system roots). A refused handshake never reaches a
  handler. The server key file must not be readable by group or other.
* Limits: 4 MiB per message, 64 KiB per roster token, 15 s per request, 32 RPCs at once.
* Status messages hold no path, token or key text; the log holds the RPC name, the slug and the
  outcome.
* `menzil-relay-admin gen-certs --out DIR --server-name NAME [--client-name NAME]` makes a private
  CA (5 years), a server certificate (SAN: the name and 127.0.0.1) and a client certificate (1
  year each), refusing to overwrite. Move `ca.key` offline.

See `docs/private/ui-agent-howto.md` for the commands.

## Build notes

* `protoc` is the vendored one from the `protoc-bin-vendored` crate (build dependency); no system
  install is needed. `/usr/local/bin/protoc` is not used.
* The generated client is behind the `client` feature (used by the tests); the agent is a server
  only.
