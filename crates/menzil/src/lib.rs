//! The `menzil` command line as a library: what the subcommands do, so that it can be tested
//! without starting processes. `main.rs` only parses arguments and prints.
//!
//! * [`home`]: where a user's identity, keys, documents and configuration live, and how files
//!   are written (secrets readable by their owner only, every write atomic).
//! * [`token`]: the strings people paste between machines, a join request and a membership
//!   token (TOBEDECIDED 14: phase 1 has no invites, admission is by hand).
//! * [`local`]: the operations on those files: `init`, `network create`, `admit`, `grant`,
//!   `join`, `renew`, `cert` and `status`. Every one takes the clock as a parameter.
//! * [`cert_renew`] and [`cert_node`]: certificate rotation. The first is the pure rules (when a
//!   node renews, when a network is warned about, which pushed renewals a steward lists); the
//!   second renews a running node's certificate and reports it through the agent socket.

#![forbid(unsafe_code)]

pub mod agent;
pub mod cert_node;
pub mod cert_renew;
pub mod config;
pub mod home;
pub mod local;
pub mod node_cmd;
pub mod persist;
pub mod reach;
pub mod relay_cmd;
pub mod signals;
pub mod stdio;
pub mod steward_loop;
pub mod text;
pub mod token;
