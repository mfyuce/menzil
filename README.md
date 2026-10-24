# menzil

A menzil was the relay station on an Ottoman courier route. In modern Turkish the word also means reach.

menzil is a self hosted tunnel written in Rust. One binary and one identity do three things:

- expose a local port as a public https URL,
- reach your own machines from anywhere, including through SSH for VS Code, JetBrains and Zed,
- route your own traffic through a machine you own.

It is built for networks that allow only HTTPS through a corporate proxy, with a relay that cannot read your traffic. No accounts, no vendor relay, no telemetry, no quotas. You need a domain name and a small server, or a friend who has one.

## Status

Early implementation, not ready for use (2026-10-25). The protocol (WebSocket, Noise and yamux, one key identity), the relay, the node and a first slice of the command line are built and tested: `init`, `network create`, `admit`, `grant`, `renew`, `join`, `token`, `status`, `relay`, `node`, `stdio` (an SSH `ProxyCommand`) and `reach` (a local listener), all for a private network of your own machines. Steward signed documents, which keep a network alive without the owner key on every machine, are being added. Not built yet: `expose` (a public https URL), egress through a machine you own (SOCKS5, TUN), certificate rotation, `revoke`, starting the agent on demand, Windows named pipes and packaging.

The protocol is in [docs/spec/protocol.md](docs/spec/protocol.md) and the threat model in [docs/spec/threat-model.md](docs/spec/threat-model.md); design decisions are under [docs/spec/decisions/](docs/spec/decisions/). The literature review of about sixty tunnels, overlays and zero trust tools and the transport analysis are in [docs/literature-review.md](docs/literature-review.md), with the raw research fact sheets and their sources in [docs/research/](docs/research/).

Some code comments cite item ids such as "TODO.md L4g" or "DONE.md". Those working notes (task list, history, open decisions) are kept in a separate private repository; the comments say what the code does without them, and the ids only point at the reasoning behind a fix.

## License

Apache-2.0 OR MIT, at your option. No contributor license agreement.
