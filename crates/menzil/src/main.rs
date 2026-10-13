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
use menzil_cli::{node_cmd, relay_cmd};
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
        /// The join request (`menzil1-join:...`) the new member's `menzil init` printed.
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
        /// The token (`menzil1-docs:...`).
        token: String,
    },
    /// Print the membership token for the documents this device holds.
    Token {
        /// The network, when this device is in more than one.
        #[arg(long, value_name = "ID")]
        network: Option<String>,
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
    /// Listen on a local port and carry each connection to a service of another member.
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
    /// `ProxyCommand` runs (`ssh -o ProxyCommand="menzil stdio %h/ssh" laptop`).
    Stdio {
        /// The service, as `<member>/<service>`, for example `laptop/ssh`.
        target: String,
    },
    /// Print the menzil version.
    Version,
}

#[derive(Subcommand)]
enum RelayCommand {
    /// Serve a network: keep the Roster in a membership token the network's owner gave you.
    AddNetwork {
        /// The token (`menzil1-docs:...`) from `menzil token` on the owner's device.
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
        Command::Join { token } => match local::join(&home()?, &token, now())? {
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
        Command::Token { network } => println!("{}", local::token(&home()?, network.as_deref())?),
        Command::Status => print!("{}", local::status(&home()?)?.render(now())),
        Command::Relay {
            command: RelayCommand::AddNetwork { token },
        } => {
            let (network_id, seq) = relay_cmd::add_network(&home()?, &token, now())?;
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
                _ = tokio::signal::ctrl_c() => eprintln!("stopping"),
            }
        }
        Command::Node => node_cmd::run(&home()?).await?,
        Command::Stdio { target } => {
            let home = home()?;
            let socket = node_cmd::agent_socket_path(&home, &Config::load(&home)?);
            let end = agent::connect_and_bridge(
                &socket,
                &target,
                tokio::io::stdin(),
                tokio::io::stdout(),
            )
            .await?;
            if let End::Reset(why) = end {
                eprintln!("menzil: the connection was reset: {why}");
                std::process::exit(1);
            }
        }
        Command::Reach { target, listen } => {
            let home = home()?;
            let socket = node_cmd::agent_socket_path(&home, &Config::load(&home)?);
            reach(&socket, &target, listen).await?;
        }
        Command::Expose { .. } => not_implemented("expose"),
        Command::Proxy { .. } => not_implemented("proxy"),
        Command::Version => println!("menzil {}", env!("CARGO_PKG_VERSION")),
    }
    Ok(())
}

/// `menzil reach`: a local listener whose every connection is carried to `target` through the
/// agent. A stream that ends in a reset resets the local connection (a TCP RST), so that a
/// program reading it cannot take a truncated answer for a whole one.
async fn reach(socket: &std::path::Path, target: &str, listen: SocketAddr) -> Result<()> {
    use std::os::fd::AsFd;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("listening on {listen}"))?;
    eprintln!(
        "carrying connections to {} to {target}; ctrl-c stops",
        listener.local_addr()?
    );
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(128));
    loop {
        let (connection, peer) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = tokio::signal::ctrl_c() => return Ok(()),
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            eprintln!("menzil: too many connections, refusing one from {peer}");
            continue;
        };
        let (socket, target) = (socket.to_path_buf(), target.to_string());
        tokio::spawn(async move {
            // Kept to be able to make the connection end in a reset after the halves are gone.
            let keep = connection.as_fd().try_clone_to_owned().ok();
            let _ = connection.set_nodelay(true);
            let (read, write) = connection.into_split();
            match agent::connect_and_bridge(&socket, &target, read, write).await {
                Ok(End::Clean) => {}
                Ok(End::Reset(why)) => {
                    eprintln!("menzil: a connection from {peer} was reset: {why}");
                    if let Some(fd) = &keep {
                        let _ =
                            socket2::SockRef::from(fd).set_linger(Some(std::time::Duration::ZERO));
                    }
                }
                Err(error) => eprintln!("menzil: {error:#}"),
            }
            drop(keep);
            drop(permit);
        });
    }
}

/// Prints a one line "not implemented" message for `subcommand` to stderr,
/// then exits the process with status 2.
fn not_implemented(subcommand: &str) -> ! {
    eprintln!("{subcommand}: not implemented yet");
    std::process::exit(2);
}
