//! The `menzil` command line as a library: what the subcommands do, so that it can be tested
//! without starting processes. `main.rs` only parses arguments and prints.
//!
//! * [`home`]: where a user's identity, keys, documents and configuration live, and how files
//!   are written (secrets readable by their owner only, every write atomic).
//! * [`token`]: the strings people paste between machines, a join request and a membership
//!   token (TOBEDECIDED 14: phase 1 has no invites, admission is by hand).
//! * [`local`]: the operations on those files: `init`, `network create`, `admit`, `grant`,
//!   `join`, `renew` and `status`. Every one takes the clock as a parameter.

#![forbid(unsafe_code)]

pub mod agent;
pub mod config;
pub mod home;
pub mod local;
pub mod node_cmd;
pub mod relay_cmd;
pub mod token;
