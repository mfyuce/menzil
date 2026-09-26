//! Command line entry point for menzil: relay, node, and client roles for
//! a self hosted tunnel that runs over WebSocket on TLS 443.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

/// Self hosted tunnel: relay, node, and client roles over WebSocket on TLS 443.
#[derive(Parser)]
#[command(name = "menzil", about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the relay role.
    Relay,
    /// Run the node role.
    Node,
    /// Expose a local port through a node.
    Expose {
        /// Local port to expose.
        port: u16,
    },
    /// Reach a service published by a node.
    Reach {
        /// Address of the service to reach, as node/service.
        target: String,
    },
    /// Run a local SOCKS proxy that exits through a node.
    Proxy {
        /// Node to use as the SOCKS exit.
        exit: String,
    },
    /// Run in SSH stdio mode against a target.
    Stdio {
        /// Address of the target, as node/service.
        target: String,
    },
    /// Print the menzil version.
    Version,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Relay => not_implemented("relay"),
        Command::Node => not_implemented("node"),
        Command::Expose { .. } => not_implemented("expose"),
        Command::Reach { .. } => not_implemented("reach"),
        Command::Proxy { .. } => not_implemented("proxy"),
        Command::Stdio { .. } => not_implemented("stdio"),
        Command::Version => println!("menzil {}", env!("CARGO_PKG_VERSION")),
    }
}

/// Prints a one line "not implemented" message for `subcommand` to stderr,
/// then exits the process with status 2.
fn not_implemented(subcommand: &str) -> ! {
    eprintln!("{subcommand}: not implemented in phase 0");
    std::process::exit(2);
}
