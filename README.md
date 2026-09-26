# menzil

A menzil was the relay station on an Ottoman courier route. In modern Turkish the word also means reach.

menzil is a self hosted tunnel written in Rust. One binary and one identity do three things:

- expose a local port as a public https URL,
- reach your own machines from anywhere, including through SSH for VS Code, JetBrains and Zed,
- route your own traffic through a machine you own.

It is built for networks that allow only HTTPS through a corporate proxy, with a relay that cannot read your traffic. No accounts, no vendor relay, no telemetry, no quotas. You need a domain name and a small server, or a friend who has one.

## Status

Design phase, no code yet (2026-09-26). The literature review of about sixty tunnels, overlays and zero trust tools, the transport analysis and the plan are in [docs/literature-review.md](docs/literature-review.md). The raw research fact sheets with their sources are in [docs/research/](docs/research/). Protocol and threat model documents will appear under docs/spec/.

## License

Apache-2.0 OR MIT, at your option. No contributor license agreement.
