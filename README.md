# menzil

A menzil was the relay station on an Ottoman courier route. In modern Turkish the word also means reach.

menzil is a self hosted tunnel written in Rust. One binary and one identity do three things:

- expose a local port as a public https URL,
- reach your own machines from anywhere, including through SSH for VS Code, JetBrains and Zed,
- route your own traffic through a machine you own.

It is built for networks that allow only HTTPS through a corporate proxy, with a relay that cannot read your traffic. No accounts, no vendor relay, no telemetry, and no quota unless the operator of a shared relay sets one for its tenants. You need a domain name and a small server, or a friend who has one.

Project domain: `menzil.dev` (registered 2026-11-06; no site or public relay runs there yet).

## Status

Early implementation, not ready for use (2026-11-06). The protocol (WebSocket, Noise and yamux, one key identity), the relay, the node and a first slice of the command line are built and tested: `init` (also `--new-identity`), `network create`, `admit` (also `--replace`), `grant`, `revoke`, `renew`, `cert` (show, renew, request, accept), `join`, `token`, `status`, `relay`, `node`, `stdio` (an SSH `ProxyCommand`) and `reach` (a local listener), all for a private network of your own machines. Steward signed documents, which keep a network alive without the owner key on every machine, and certificate rotation (a node renews its own certificate before it expires) are built. A relay can serve several unrelated tenants, each with its own quotas and name zone. Public shares are built too: `expose` (blind and `tcp` shares, and terminated `http:` shares served by the relay under its own certificate), and egress through a machine you own, as a local SOCKS5 or HTTP CONNECT proxy (`proxy`). Not built yet: UDP through the proxy, a TUN device, starting the agent on demand, Windows named pipes and packaging.

The protocol is in [docs/spec/protocol.md](docs/spec/protocol.md) and the threat model in [docs/spec/threat-model.md](docs/spec/threat-model.md); design decisions are under [docs/spec/decisions/](docs/spec/decisions/). The literature review of about sixty tunnels, overlays and zero trust tools and the transport analysis are in [docs/literature-review.md](docs/literature-review.md), with the raw research fact sheets and their sources in [docs/research/](docs/research/).

Some code comments cite item ids such as "TODO.md L4g" or "DONE.md". Those working notes (task list, history, open decisions) are kept in a separate private repository; the comments say what the code does without them, and the ids only point at the reasoning behind a fix.

## What is public

Everything published here stays public under the licence below: the protocol and its specification, the relay (including multi tenancy, quotas, public shares and certificate handling), the node, the command line and the admin API. Anything a person needs to run menzil for themselves or for friends belongs in this repository. A hosted service, its web interface, billing and similar commercial products built on menzil are separate and are not part of it. Features that mainly serve companies (for example single sign-on in front of shares, durable metering, multi region operation, audit export) may be developed outside this repository; the core then only offers extension points and does not depend on them. Nothing already published is ever moved out.

## License

Apache-2.0 OR MIT, at your option. No contributor license agreement.

## Trademark

The licence covers the code, not the name. "menzil", "menzil.dev" and the logo are the author's marks (no registration is claimed yet). You may say that your service is built on or compatible with menzil; please do not present a modified version or a hosted service as the official menzil or as run by its author.
