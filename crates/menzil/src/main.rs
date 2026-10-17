//! Command line entry point for menzil: relay, node, and client roles for
//! a self hosted tunnel that runs over WebSocket on TLS 443.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use menzil_cli::agent::{self, End};
use menzil_cli::config::Config;
use menzil_cli::home::Home;
use menzil_cli::local::{self, Joined};
use menzil_cli::stdio::ClosingStdout;
use menzil_cli::{node_cmd, reach, relay_cmd, signals, text, token};
use menzil_proto::ServiceId;
use tracing_subscriber::EnvFilter;

/// Self hosted tunnel: relay, node, and client roles over WebSocket on TLS 443.
#[derive(Parser)]
#[command(name = "menzil", about, long_about = None)]
struct Cli {
    /// Where menzil keeps its files [default: $MENZIL_HOME, else ~/.config/menzil].
    #[arg(long, global = true, value_name = "DIR")]
    home: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make this device's identity and print the join request to give to a network owner.
    Init,
    /// Print this device's join request again.
    JoinRequest,
    /// Create and manage networks this device owns.
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    /// Admit the device a join request names to a network this device owns.
    Admit {
        /// The join request (`menzil1-join:...`) the new member's `menzil init` printed; `-`
        /// reads it from standard input.
        join_request: String,
        /// The name the member is addressed by (letters, digits, '-', '_' and '.').
        #[arg(long)]
        name: String,
        /// A role for the member; may be repeated.
        #[arg(long = "role", value_name = "ROLE")]
        roles: Vec<String>,
        /// The network, when this device is in more than one.
        #[arg(long, value_name = "ID")]
        network: Option<String>,
    },
    /// Let a member use services on another (owner only).
    Grant {
        /// Who may use them: a member's name, or `role:<role>`.
        from: String,
        /// Whose services: a member's name, or `*` for every node.
        to: String,
        /// The services, such as `tcp:ssh`.
        #[arg(required = true)]
        services: Vec<ServiceId>,
        /// The grant ends at this Unix time.
        #[arg(long, value_name = "UNIX_SECONDS")]
        expires: Option<u64>,
        /// The network, when this device is in more than one.
        #[arg(long, value_name = "ID")]
        network: Option<String>,
    },
    /// Re-issue a network's documents with a fresh lifetime (owner only; needed every 14 days).
    Renew {
        /// The network, when this device is in more than one.
        #[arg(long, value_name = "ID")]
        network: Option<String>,
    },
    /// Install the documents in a membership token an owner gave this device.
    Join {
        /// The token (`menzil1-docs:...`); `-` reads it from standard input, which keeps it out
        /// of `ps` output and shell history.
        token: String,
    },
    /// Print the membership token for the documents this device holds.
    Token {
        /// The network, when this device is in more than one.
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        /// Print the token for a relay instead: the Roster alone, without the Policy (who may
        /// use what, and the members' device names), which is hidden from relays.
        #[arg(long)]
        for_relay: bool,
    },
    /// Show this device's identity, networks and members.
    Status,
    /// Run a relay, or tell it which networks it serves.
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
    /// Run the node: attach to the relay, serve the configured services and answer the agent
    /// socket that `stdio` and `reach` use.
    Node,
    /// Expose a local port through a node.
    Expose {
        /// Local port to expose.
        port: u16,
    },
    /// Listen on a local port and carry each connection to a service of another member. A
    /// connection that does not end cleanly (the service failed, the agent refused, this
    /// command is stopped) is reset, never closed as if it had finished.
    Reach {
        /// The service, as `<member>/<service>`, for example `laptop/ssh`.
        target: String,
        /// Where to listen.
        #[arg(long, default_value = "127.0.0.1:2222")]
        listen: SocketAddr,
    },
    /// Run a local SOCKS proxy that exits through a node.
    Proxy {
        /// Node to use as the SOCKS exit.
        exit: String,
    },
    /// Carry standard input and output to a service of another member: what an SSH
    /// `ProxyCommand` runs (`ssh -o ProxyCommand="menzil stdio %h/ssh" laptop`). Both directions
    /// run to their end: when the service finishes, standard output is closed and standard
    /// input is carried on until it ends too; a reset ends it at once with status 1.
    Stdio {
        /// The service, as `<member>/<service>`, for example `laptop/ssh`.
        target: String,
    },
    /// Print the menzil version.
    Version,
}

#[derive(Subcommand)]
enum RelayCommand {
    /// Serve a network: keep the Roster in a relay token the network's owner gave you.
    AddNetwork {
        /// The token (`menzil1-roster:...`) from `menzil token --for-relay` on the owner's
        /// device; `-` reads it from standard input. A full membership token is refused: it
        /// carries the Policy, which a relay must not get.
        token: String,
    },
    /// Run the relay until interrupted and print the connection information for nodes.
    Run {
        /// Where to listen.
        #[arg(long, default_value = "0.0.0.0:443")]
        listen: SocketAddr,
        /// The TLS certificate chain, PEM (such as certbot's fullchain.pem).
        #[arg(long, value_name = "FILE")]
        tls_cert: PathBuf,
        /// The TLS private key, PEM.
        #[arg(long, value_name = "FILE")]
        tls_key: PathBuf,
        /// The public name of this relay, for the connection information that is printed.
        #[arg(long)]
        host: Option<String>,
        /// The WebSocket path to answer on.
        #[arg(long, default_value = relay_cmd::DEFAULT_PATH)]
        path: String,
    },
}

#[derive(Subcommand)]
enum NetworkCommand {
    /// Create a network owned by this device, with this device as its first member.
    Create {
        /// The name this device is addressed by in the network.
        #[arg(long, default_value = "owner")]
        name: String,
    },
}

/// A token given on the command line, or `-` for one read from standard input.
fn token_argument(value: String) -> Result<String> {
    if value != "-" {
        return Ok(value);
    }
    token::read_token(std::io::stdin())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() {
    // Warnings from everything and progress from menzil itself, unless RUST_LOG says otherwise.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("warn,menzil=info,menzil_cli=info,menzil_node=info,menzil_relay=info")
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    if let Err(error) = run(cli).await {
        eprintln!("menzil: {error:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let home = || -> Result<Home> {
        match &cli.home {
            Some(dir) => Ok(Home::new(dir)),
            None => Home::locate(),
        }
    };
    match cli.command {
        Command::Init => {
            let home = home()?;
            let made = local::init(&home, now())?;
            println!("created the identity of this device: {}", made.node_id);
            println!("files are in {}", home.root().display());
            println!();
            println!(
                "the join request to give to a network owner (`menzil admit <request> --name <name>`):"
            );
            println!("{}", made.join_request);
        }
        Command::JoinRequest => println!("{}", local::join_request(&home()?)?),
        Command::Network {
            command: NetworkCommand::Create { name },
        } => {
            let home = home()?;
            let id = local::network_create(&home, &name, now())?;
            println!("created network {id}");
            println!("the owner key is {}", home.owner_key_path(&id).display());
            println!("keep it private and backed up: nobody can change the network without it");
            println!(
                "next: `menzil admit <join request> --name <name>` for each device, then `menzil grant`"
            );
        }
        Command::Admit {
            join_request,
            name,
            roles,
            network,
        } => {
            let join_request = token_argument(join_request)?;
            let issued = local::admit(
                &home()?,
                network.as_deref(),
                &join_request,
                &name,
                &roles,
                now(),
            )?;
            println!(
                "admitted {} as {name:?}: the network's documents are now #{}",
                issued.member.map(|m| m.to_string()).unwrap_or_default(),
                issued.seq
            );
            println!("give this token to the new member, who runs `menzil join <token>`:");
            println!("{}", issued.token);
        }
        Command::Grant {
            from,
            to,
            services,
            expires,
            network,
        } => {
            let issued = local::grant(
                &home()?,
                network.as_deref(),
                &from,
                &to,
                &services,
                expires,
                now(),
            )?;
            println!("granted: the network's documents are now #{}", issued.seq);
            println!("every member needs the new documents (`menzil join <token>`):");
            println!("{}", issued.token);
        }
        Command::Renew { network } => {
            let issued = local::renew(&home()?, network.as_deref(), now())?;
            println!("renewed: the network's documents are now #{}", issued.seq);
            println!("every member needs the new documents (`menzil join <token>`):");
            println!("{}", issued.token);
        }
        Command::Join { token } => match local::join(&home()?, &token_argument(token)?, now())? {
            Joined::New { network_id, seq } => {
                println!("joined network {network_id} (documents #{seq})")
            }
            Joined::Updated {
                network_id,
                from_seq,
                seq,
            } => println!("updated network {network_id}: documents #{from_seq} -> #{seq}"),
            Joined::AlreadyCurrent {
                network_id,
                held_seq,
            } => println!(
                "nothing to do: this device holds documents #{held_seq} of network {network_id} already"
            ),
        },
        Command::Token { network, for_relay } => {
            let home = home()?;
            println!(
                "{}",
                if for_relay {
                    local::token_for_relay(&home, network.as_deref())?
                } else {
                    local::token(&home, network.as_deref())?
                }
            );
        }
        Command::Status => print!("{}", local::status(&home()?)?.render(now())),
        Command::Relay {
            command: RelayCommand::AddNetwork { token },
        } => {
            let (network_id, seq) =
                relay_cmd::add_network(&home()?, &token_argument(token)?, now())?;
            println!("this relay serves network {network_id} (Roster #{seq})");
        }
        Command::Relay {
            command:
                RelayCommand::Run {
                    listen,
                    tls_cert,
                    tls_key,
                    host,
                    path,
                },
        } => {
            let mut relay = relay_cmd::start(
                &home()?,
                &relay_cmd::RunOptions {
                    listen,
                    tls_cert,
                    tls_key,
                    path,
                    host,
                    reload_every: relay_cmd::DEFAULT_RELOAD_EVERY,
                },
            )
            .await?;
            eprintln!("relay listening on {}", relay.addr);
            eprintln!("it serves {} network(s)", relay.networks.len());
            eprintln!("put this in `relay = ` in the config.toml of every node that uses it:");
            println!("{}", relay.connection_info);
            tokio::select! {
                _ = relay.wait() => {}
                why = signals::shutdown() => eprintln!("stopping ({})", why?),
            }
        }
        Command::Node => node_cmd::run(&home()?).await?,
        Command::Stdio { target } => {
            let home = home()?;
            let socket = node_cmd::agent_socket_path(&home, &Config::load(&home)?);
            let mut input = tokio::io::stdin();
            let mut output = ClosingStdout::new();
            let end = agent::connect_and_bridge(&socket, &target, &mut input, &mut output).await?;
            // Out at once, whatever standard input is doing: tokio reads it on a thread that a
            // finished program would otherwise wait for.
            match end {
                End::Clean => std::process::exit(0),
                End::Reset(why) => {
                    eprintln!(
                        "menzil: the connection was reset: {}",
                        text::one_line(&why, 300)
                    );
                    std::process::exit(1);
                }
            }
        }
        Command::Reach { target, listen } => {
            let home = home()?;
            let socket = node_cmd::agent_socket_path(&home, &Config::load(&home)?);
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("listening on {listen}"))?;
            eprintln!(
                "carrying connections to {} to {target}; ctrl-c stops and resets what is open",
                listener.local_addr()?
            );
            reach::run(&socket, &target, listener, async {
                match signals::shutdown().await {
                    Ok(why) => eprintln!("stopping ({why})"),
                    Err(error) => eprintln!("menzil: cannot wait for a signal: {error}"),
                }
            })
            .await?;
        }
        Command::Expose { .. } => not_implemented("expose"),
        Command::Proxy { .. } => not_implemented("proxy"),
        Command::Version => println!("menzil {}", env!("CARGO_PKG_VERSION")),
    }
    Ok(())
}

/// Prints a one line "not implemented" message for `subcommand` to stderr,
/// then exits the process with status 2.
fn not_implemented(subcommand: &str) -> ! {
    eprintln!("{subcommand}: not implemented yet");
    std::process::exit(2);
}
