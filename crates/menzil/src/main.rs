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
use menzil_cli::expose::{self, ExposeMode, ExposeSpec};
use menzil_cli::home::Home;
use menzil_cli::local::{self, Joined};
use menzil_cli::stdio::{ClosingStdout, reset_message};
use menzil_cli::{node_cmd, proxy, reach, relay_cmd, signals, text, token};
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
    Init {
        /// Put this device's identity aside in `<home>/retired/` and make another, for a device
        /// whose identity may be compromised or lost its place: each owner then moves the old
        /// node's place to the new one (`menzil admit --replace`). Refused while a node runs.
        #[arg(long)]
        new_identity: bool,
    },
    /// Print this device's join request again.
    JoinRequest,
    /// Create and manage networks this device owns.
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    /// Admit the device a join request names to a network this device owns, or is a steward of.
    Admit {
        /// The join request (`menzil1-join:...`) the new member's `menzil init` printed; `-`
        /// reads it from standard input.
        join_request: String,
        /// The name the member is addressed by (letters, digits, '-', '_' and '.').
        #[arg(long, required_unless_present = "replace", conflicts_with = "replace")]
        name: Option<String>,
        /// A role for the member; may be repeated. A steward admits without roles.
        #[arg(long = "role", value_name = "ROLE", conflicts_with = "replace")]
        roles: Vec<String>,
        /// Owner only: instead of a new member, move the place of this member (its name, roles,
        /// grants, egress and accept entries and labels) to the device the join request names,
        /// and revoke the old device, in one update. The member is a name, the start of a node
        /// id (8 or more hex digits), or a whole node id; `menzil init --new-identity` prints
        /// the line.
        #[arg(long, value_name = "MEMBER")]
        replace: Option<String>,
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
    /// Take grants back (owner only): the services named, or with none named every grant from
    /// `from` to `to`.
    Ungrant {
        /// Whose grants: a member's name, or `role:<role>`.
        from: String,
        /// On whose services: a member's name, or `*`.
        to: String,
        /// The services to take out, such as `tcp:ssh`; none means every grant from `from` to `to`.
        services: Vec<ServiceId>,
        /// The network, when this device is in more than one.
        #[arg(long, value_name = "ID")]
        network: Option<String>,
    },
    /// Give a member a public share name, take it back, or list them (owner only, except `list`).
    ///
    /// A relay accepts `menzil expose --name <name>` from a node only if the network's Roster
    /// lists that name for that node. `add` and `remove` change the Roster, so the relay (and
    /// every member) needs the new documents afterwards: a running `menzil node` on this device
    /// hands them over, and `menzil token --for-relay` prints the Roster for `menzil relay
    /// add-network`.
    Label {
        #[command(subcommand)]
        command: LabelCommand,
    },
    /// Revoke a member for good (owner only): it is cut off, and a revoked device joins again
    /// only under a new identity.
    Revoke {
        /// The member's name, the start of its node id (8 or more hex digits), or a whole node id.
        member: String,
        /// The network, when this device is in more than one.
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        /// Allow revoking this device's own node.
        #[arg(long = "self")]
        allow_self: bool,
    },
    /// Re-issue a network's documents with a fresh lifetime (owner or steward; needed every 14
    /// days).
    Renew {
        /// The network, when this device is in more than one.
        #[arg(long, value_name = "ID")]
        network: Option<String>,
    },
    /// Hand admitting and renewing to a steward, a device with a key of its own that signs for
    /// the owner for a while (owner: `add`, `remove`; steward device: `request`).
    Steward {
        #[command(subcommand)]
        command: StewardCommand,
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
    /// This device's certificate: show it (the default), renew it, print the token for it, or
    /// (owner or steward) list a member's renewed one.
    Cert {
        #[command(subcommand)]
        command: Option<CertCommand>,
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
    /// Make a local port reachable under a public name (`https://<name>.<the relay's domain>`),
    /// or list or remove such shares.
    ///
    /// The node serves the port and advertises the name to its relay, which routes visitors to
    /// this node by the name in their TLS hello without reading their traffic (blind mode). The
    /// local program must speak TLS itself, with a certificate for the public name: menzil does
    /// not make one. A running node picks the change up at once; with no node running only
    /// config.toml is changed and `menzil node` advertises the share when it starts.
    #[command(
        args_conflicts_with_subcommands = true,
        subcommand_negates_reqs = true,
        after_help = "Examples:\n  menzil expose 8443 --name myapp          expose a local HTTPS server\n  menzil expose 22 --name box --mode tcp  reach sshd by name (TLS in front of it)\n  menzil expose list                      what is exposed and what the relay says\n  menzil expose remove myapp                take it away"
    )]
    Expose(ExposeArgs),
    /// Listen on a local port (or a Unix socket) and carry each connection to a service of
    /// another member.
    ///
    /// On a TCP port, a connection that does not end cleanly (the service failed, the agent
    /// refused, this command is stopped) is reset, never closed as if it had finished. The port
    /// is open to every user of this machine, and each of them gets this user's grants (as with
    /// `ssh -L`); on a shared machine use `--unix`.
    ///
    /// A Unix socket (`--unix`) is private to this user: mode 0600, nothing on the way to it
    /// that other users can change (the whole path is checked, links included), and the user of
    /// every connection is checked. It cannot be relied on to carry a reset, though: a program
    /// on it is in general not told whether the stream ended cleanly or not, so a program that
    /// must tell a truncated answer from a whole one needs the TCP form.
    Reach {
        /// The service, as `<member>/<service>`, for example `laptop/ssh`.
        target: String,
        /// Where to listen, as a TCP address.
        #[arg(long, default_value = "127.0.0.1:2222", conflicts_with = "unix")]
        listen: SocketAddr,
        /// Listen on a Unix socket at this path instead. Missing directories are made (0700); a
        /// socket left by a `reach` that died is replaced; the socket and the lock file
        /// `<PATH>.lock` next to it are removed when this stops.
        #[arg(long, value_name = "PATH")]
        unix: Option<PathBuf>,
    },
    /// Run a local SOCKS5 proxy whose connections leave through another member's node.
    ///
    /// Point the application at it with a `socks5h://` URL, for example
    /// `curl --proxy socks5h://127.0.0.1:1080 https://example.org/`. The `h` matters: the proxy
    /// resolves no name, it sends the name to the exit, which resolves it. With `socks5://` the
    /// application looks the name up itself, first, on this machine: that leaks the lookup and
    /// takes from the exit the choice of what the name means.
    ///
    /// Only CONNECT, without authentication, is supported. The proxy listens on loopback only
    /// (127.0.0.1 or ::1; `0.0.0.0`, `::` and any other address are refused before it binds)
    /// and, like `reach` on a TCP port, is open to every user of this machine, each of whom
    /// gets this user's grants. At most 128 connections at once.
    ///
    /// The exit must be a member whose node runs with `[egress] enabled = true` in its
    /// config.toml, to which this device holds an `egress:*` grant and for which the Policy has
    /// an `egress` entry (an egress rule); the exit refuses loopback, link local, its own
    /// addresses and other private ranges whatever the rules say. A refusal reaches the
    /// application as a SOCKS error.
    Proxy {
        /// The node to use as the exit: a member's name, or the start of its node id.
        exit: String,
        /// Where to listen, as a loopback TCP address (or `localhost:PORT`).
        #[arg(long, default_value = "127.0.0.1:1080", value_name = "ADDR")]
        listen: String,
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

/// What `menzil expose` takes.
#[derive(clap::Args)]
struct ExposeArgs {
    #[command(subcommand)]
    command: Option<ExposeCommand>,
    /// The local port to expose (1 to 65535).
    #[arg(required = true, value_parser = clap::value_parser!(u16).range(1..))]
    port: Option<u16>,
    /// The public label: one lowercase name of letters, digits and hyphens, so the share is
    /// `<label>.<the relay's share domain>` (the relay adds your tenant's label if it has one).
    #[arg(long, required = true, value_name = "LABEL")]
    name: Option<String>,
    /// blind: the relay forwards the encrypted bytes and the local target speaks TLS itself (the
    /// default); tcp: the same by name, for any protocol inside the TLS (`tcp:` service);
    /// terminated: the relay terminates TLS and sends the target plain HTTP/1.1, so it reads the
    /// share (the tenant must have `terminated` on; no --alpn).
    #[arg(long, default_value = "blind", value_name = "MODE", value_parser = ["blind", "tcp", "terminated"])]
    mode: String,
    /// The host of the local target. Anything but this machine's loopback shows the target to
    /// whoever reaches the public name; a warning says so.
    #[arg(long, default_value = "127.0.0.1", value_name = "HOST")]
    host: String,
    /// An ALPN identifier the target terminates (h2, http/1.1, acme-tls/1); may be repeated or
    /// comma separated. Without any, every ALPN is routed to it except acme-tls/1, which must be
    /// listed by name.
    #[arg(long = "alpn", value_name = "ID", value_delimiter = ',')]
    alpn: Vec<String>,
    /// Change a share (or a service) that exists already instead of refusing.
    #[arg(long)]
    replace: bool,
}

#[derive(Subcommand)]
enum ExposeCommand {
    /// What is exposed, what the relay answered for each (accepted, or rejected with its reason),
    /// and the public address.
    List,
    /// Take a share away: it stops being advertised and served at once.
    Remove {
        /// The label of the share.
        label: String,
    },
}

#[derive(Subcommand)]
enum LabelCommand {
    /// Let a member use a public name (owner only).
    Add {
        /// The name: one lowercase label of letters, digits and hyphens (1 to 63, not starting
        /// or ending with a hyphen), not one a relay reserves (`www`, `mail`, `admin`, `api`,
        /// `relay`, `t`, `app`, `dashboard`, `console`, `status`, `docs`, `login`, `static`).
        name: String,
        /// The member: its name, the start of its node id (8 or more hex digits), or a whole
        /// node id.
        member: String,
        /// Move the name from the member that has it to this one. Without it a name that
        /// belongs to another member is refused.
        #[arg(long)]
        replace: bool,
        /// The network, when this device is in more than one.
        #[arg(long, value_name = "ID")]
        network: Option<String>,
    },
    /// Take a name back (owner only): from the member that has it, or with no member named
    /// from whoever lists it.
    Remove {
        /// The name.
        name: String,
        /// Only if this member has it.
        member: Option<String>,
        /// The network, when this device is in more than one.
        #[arg(long, value_name = "ID")]
        network: Option<String>,
    },
    /// List the names the Roster this device holds gives out.
    List {
        /// The network, when this device is in more than one.
        #[arg(long, value_name = "ID")]
        network: Option<String>,
    },
}

// `Run` has many options and the enum is parsed once at start, so the size gap costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum RelayCommand {
    /// Serve a network: keep the Roster in a relay token the network's owner gave you.
    AddNetwork {
        /// The token (`menzil1-roster:...`) from `menzil token --for-relay` on the owner's
        /// device; `-` reads it from standard input. A full membership token is refused: it
        /// carries the Policy, which a relay must not get.
        token: String,
        /// Put the network in this tenant (made if it is new), whose shares will be named
        /// under its own zone and counted against its own allowance. Without it a new network
        /// belongs to the default tenant, and one the relay already serves for a tenant stays
        /// there. The tenant name is 3 to 32 lowercase letters, digits or hyphens.
        #[arg(long, value_name = "NAME")]
        tenant: Option<String>,
    },
    /// Stop serving a network: delete its Roster here and take it out of its tenant. A running
    /// relay drops it at its next reload and ends the sessions of its members.
    RemoveNetwork {
        /// The network id (64 hex digits).
        network: String,
    },
    /// Stop serving a tenant: remove it and all its networks. Its name cannot be given to
    /// another tenant for 180 days.
    RemoveTenant {
        /// The tenant name.
        name: String,
    },
    /// Stop serving a tenant's networks without removing it: the tenant file, its name, its
    /// figures and its Roster files stay. A running relay drops the networks at its next reload
    /// and ends their sessions; they are not served as the default tenant's.
    SuspendTenant {
        /// The tenant name.
        name: String,
    },
    /// Serve a suspended tenant's networks again (from the Roster files kept here).
    ResumeTenant {
        /// The tenant name.
        name: String,
    },
    /// List the tenants of this relay, their networks and what the relay makes of their files.
    Tenants,
    /// Show what the running relay counts per tenant (devices attached, live pairs, bytes in the
    /// volume period, names), from the status file it writes every 10 seconds. Fails when the
    /// relay is not running here or its file is more than 60 seconds old.
    Status {
        /// Print the status document as JSON (version 1; the default tenant is `_default`).
        #[arg(long)]
        json: bool,
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
        /// The share domain: serve public shares by SNI on the TLS port (`<name>.<domain>`,
        /// `<name>.<tenant>.<domain>`), piped blind to the node that holds the name. Needs
        /// `--host`, the name this relay's own certificate and nodes use, which may not lie under
        /// the domain. Off unless given. The relay needs file descriptors for it: up to 7,168
        /// (1,024 ClientHello reads, as many more on port 80, 1,024 refusals and 4,096 piped
        /// connections) on top of its sessions. It raises its soft limit to the hard one at
        /// start and warns if that is too low; set `LimitNOFILE` (systemd) or `ulimit -n` to
        /// cover the sum, 16384 is comfortable.
        #[arg(long, value_name = "DOMAIN", requires = "host")]
        share_domain: Option<String>,
        /// Also serve plain HTTP here, for ACME HTTP-01 challenges of shares and the redirect
        /// of every other request to https (usually 0.0.0.0:80). Needs `--share-domain`. Off
        /// unless given.
        #[arg(long, value_name = "ADDR", requires = "share_domain")]
        http_listen: Option<SocketAddr>,
        /// Keep certificates by ACME TLS-ALPN-01 for `--host` and for the names of terminated
        /// shares (`<name>.t.<domain>`), from the CA whose RFC 8555 directory is at this https
        /// URL. Not set by default and no CA is assumed: name it yourself (for a trial the CA's
        /// staging directory, such as Let's Encrypt's `https://acme-staging-v02.api.letsencrypt.org/directory`).
        /// The certificate files given stay the answer until the first one is issued. Needs
        /// `--share-domain`.
        #[arg(long, value_name = "URL", requires = "share_domain")]
        acme_directory: Option<String>,
        /// The contact for the CA's notices (`mailto:ops@example.org`). Needs `--acme-directory`.
        #[arg(long, value_name = "URI", requires = "acme_directory")]
        acme_contact: Option<String>,
        /// A static HTML file (at most 64 KiB, read once at start) to answer a plain HTTPS
        /// request to this relay's own host name with, such as a browser opening
        /// `https://<host>/`: `GET` and `HEAD` of `/` get the page, other paths 404, other
        /// methods 405. Without it such a request gets no answer at all. Connections that ask
        /// for the WebSocket upgrade are not affected.
        #[arg(long, value_name = "FILE")]
        fallback_page: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum CertCommand {
    /// Show this device's certificate and what each network lists for it.
    Show,
    /// Renew this device's certificate: the same keys, a higher serial, valid for 400 days. A
    /// running `menzil node` does it and switches at once; with none running the file is
    /// written here. Prints the token for the owner of an owner-only network.
    Renew,
    /// Print the token for this device's current certificate, changing nothing.
    Request,
    /// On the owner's or a steward's device: list the renewed certificate a member's `menzil
    /// cert renew` or `menzil cert request` printed.
    Accept {
        /// The token (`menzil1-cert:...`); `-` reads it from standard input.
        token: String,
        /// The network, when this device is in more than one.
        #[arg(long, value_name = "ID")]
        network: Option<String>,
    },
}

#[derive(Subcommand)]
enum StewardCommand {
    /// On the device that will be the steward: make its steward key for a network and print the
    /// request to give to the owner. The secret key stays on this device; asking again prints
    /// the same request.
    Request {
        /// The network, when this device is in more than one.
        #[arg(long, value_name = "ID")]
        network: Option<String>,
    },
    /// On the owner's device: list the steward a request names (replaces any other).
    Add {
        /// The request (`menzil1-steward:...`) from `menzil steward request`; `-` reads it from
        /// standard input.
        request: String,
        /// What the steward may do: `admit`, `renew`; may be repeated [default: both].
        #[arg(long = "may", value_name = "RIGHT")]
        may: Vec<String>,
        /// How long the steward is listed for, 1 to 90 days.
        #[arg(long, default_value_t = 30, value_name = "DAYS")]
        days: u64,
        /// The network, when this device owns more than one.
        #[arg(long, value_name = "ID")]
        network: Option<String>,
    },
    /// On the owner's device: remove the steward. Whatever the steward signed from its last
    /// documents is outranked; members it admitted stay until revoked.
    Remove {
        /// The network, when this device owns more than one.
        #[arg(long, value_name = "ID")]
        network: Option<String>,
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

/// What `ungrant` and `revoke` end with: like `grant`, plus that a running node pushes.
fn print_new_documents(token: &str) {
    println!(
        "a `menzil node` running on this device sends them to the members within 15 seconds; otherwise every member needs the new documents (`menzil join <token>`):"
    );
    println!("{token}");
}

fn print_new_label_documents(token: &str) {
    println!(
        "a relay accepts the name only from a Roster that lists it: a `menzil node` running on this device hands the new documents over within 15 seconds; otherwise give every member the token (`menzil join <token>`) and the relay the Roster (`menzil token --for-relay`, then `menzil relay add-network`):"
    );
    println!("{token}");
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
        Command::Init { new_identity } => {
            let home = home()?;
            if new_identity {
                let renewed = local::new_identity(&home, now())?;
                println!("put the identity {} aside:", renewed.old);
                println!("  {}", renewed.retired.key.display());
                println!("  {}", renewed.retired.cert.display());
                println!(
                    "it is kept so that a mistake can be undone before an owner revokes it; once the owners have replaced it, delete the files with `rm`"
                );
                println!();
                println!(
                    "created the identity of this device: {}",
                    renewed.made.node_id
                );
                println!("files are in {}", home.root().display());
                println!();
                println!("the join request of the new identity:");
                println!("{}", renewed.made.join_request);
                if renewed.networks.is_empty() {
                    println!();
                    println!(
                        "the old identity was a member of none of the networks this device holds"
                    );
                }
                for (network_id, name) in &renewed.networks {
                    println!();
                    println!(
                        "network {network_id}: the old node was {name:?}; its owner moves the place to the new node with:"
                    );
                    println!(
                        "  menzil admit --network {network_id} --replace {name} {}",
                        renewed.made.join_request
                    );
                }
            } else {
                let made = local::init(&home, now())?;
                println!("created the identity of this device: {}", made.node_id);
                println!("files are in {}", home.root().display());
                println!();
                println!(
                    "the join request to give to a network owner (`menzil admit <request> --name <name>`):"
                );
                println!("{}", made.join_request);
            }
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
            replace,
            network,
        } => {
            let join_request = token_argument(join_request)?;
            if let Some(member) = replace {
                let replaced =
                    local::replace(&home()?, network.as_deref(), &member, &join_request, now())?;
                println!(
                    "{} now has the place of {} ({:?}), which is revoked: the network's documents are now #{}",
                    replaced
                        .issued
                        .member
                        .map(|m| m.to_string())
                        .unwrap_or_default(),
                    replaced.old,
                    replaced.name,
                    replaced.issued.seq
                );
                println!("give this token to the new member, who runs `menzil join <token>`;");
                println!("the other members and relays need the new documents too:");
                println!("{}", replaced.issued.token);
                return Ok(());
            }
            let name = name.context("`--name` is required")?;
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
        Command::Ungrant {
            from,
            to,
            services,
            network,
        } => {
            let issued =
                local::ungrant(&home()?, network.as_deref(), &from, &to, &services, now())?;
            println!(
                "took the grants back: the network's documents are now #{}",
                issued.seq
            );
            print_new_documents(&issued.token);
        }
        Command::Label { command } => match command {
            LabelCommand::Add {
                name,
                member,
                replace,
                network,
            } => {
                let added =
                    local::label_add(&home()?, network.as_deref(), &name, &member, replace, now())?;
                println!(
                    "label {} now belongs to {}: the network's documents are now #{}",
                    text::one_line(&name, 80),
                    text::one_line(&added.member_name, 80),
                    added.issued.seq
                );
                if let Some(from) = &added.moved_from {
                    println!("it was moved from {}", text::one_line(from, 80));
                }
                print_new_label_documents(&added.issued.token);
            }
            LabelCommand::Remove {
                name,
                member,
                network,
            } => {
                let issued = local::label_remove(
                    &home()?,
                    network.as_deref(),
                    &name,
                    member.as_deref(),
                    now(),
                )?;
                println!(
                    "took label {} back: the network's documents are now #{}",
                    text::one_line(&name, 80),
                    issued.seq
                );
                print_new_label_documents(&issued.token);
            }
            LabelCommand::List { network } => {
                let (_, entries) = local::label_list(&home()?, network.as_deref())?;
                if entries.is_empty() {
                    println!("no labels");
                }
                for entry in entries {
                    let who = match &entry.member {
                        Some(name) => text::one_line(name, 80),
                        None => entry.node_id.to_string(),
                    };
                    println!("{}  {who}", text::one_line(&entry.name, 80));
                }
            }
        },
        Command::Revoke {
            member,
            network,
            allow_self,
        } => {
            let revoked = local::revoke(&home()?, network.as_deref(), &member, allow_self, now())?;
            let node = revoked
                .issued
                .member
                .map(|m| m.to_string())
                .unwrap_or_default();
            match &revoked.name {
                Some(name) => println!(
                    "revoked {name:?} ({node}): the network's documents are now #{}",
                    revoked.issued.seq
                ),
                None => println!(
                    "revoked {node}: the network's documents are now #{}",
                    revoked.issued.seq
                ),
            }
            if !revoked.was_member {
                println!("(it was not a member of the documents this device held)");
            }
            if revoked.steward_listed {
                println!(
                    "a steward is listed, and revoking its device does not remove its key: if this node hosted the steward, run `menzil steward remove`"
                );
            }
            print_new_documents(&revoked.issued.token);
        }
        Command::Renew { network } => {
            let issued = local::renew(&home()?, network.as_deref(), now())?;
            println!("renewed: the network's documents are now #{}", issued.seq);
            println!("every member needs the new documents (`menzil join <token>`):");
            println!("{}", issued.token);
        }
        Command::Steward { command } => match command {
            StewardCommand::Request { network } => {
                let request = local::steward_request(&home()?, network.as_deref())?;
                if request.created {
                    println!(
                        "made this device's steward key for network {}",
                        request.network_id
                    );
                } else {
                    println!(
                        "this device has a steward key for network {} already (left as it was)",
                        request.network_id
                    );
                }
                println!(
                    "give this request to the owner, who runs `menzil steward add <request>`:"
                );
                println!("{}", request.token);
            }
            StewardCommand::Add {
                request,
                may,
                days,
                network,
            } => {
                let may = if may.is_empty() {
                    vec!["admit".to_string(), "renew".to_string()]
                } else {
                    may
                };
                let added = local::steward_add(
                    &home()?,
                    network.as_deref(),
                    &token_argument(request)?,
                    &may,
                    days,
                    now(),
                )?;
                println!(
                    "listed steward {} for {days} day(s): the network's documents are now #{}",
                    added.steward.to_hex(),
                    added.issued.seq
                );
                println!(
                    "every member and the steward need the new documents (`menzil join <token>`):"
                );
                println!("{}", added.issued.token);
            }
            StewardCommand::Remove { network } => {
                let issued = local::steward_remove(&home()?, network.as_deref(), now())?;
                println!(
                    "removed the steward: the network's documents are now #{}",
                    issued.seq
                );
                println!("every member needs the new documents (`menzil join <token>`):");
                println!("{}", issued.token);
            }
        },
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
        Command::Cert { command } => match command.unwrap_or(CertCommand::Show) {
            CertCommand::Show => {
                print!("{}", local::cert_show(&home()?)?.render(now()));
            }
            CertCommand::Request => println!("{}", local::cert_request(&home()?)?),
            CertCommand::Renew => {
                let home = home()?;
                // A running node does it (it holds the identity and switches at once); only
                // when none answers is the file written here, under the node lock.
                let socket = node_cmd::agent_socket_path(&home, &Config::load(&home)?);
                match agent::renew_cert(&socket).await {
                    Ok(renewed) => {
                        println!(
                            "the running node renewed this device's certificate: serial {}, valid until {}",
                            renewed.serial,
                            local::relative(renewed.not_after, now())
                        );
                        println!(
                            "it uses the new one from now on and offers it to the network's steward by itself; an owner-only network needs this token given to its owner (`menzil cert accept`):"
                        );
                        println!("{}", renewed.token);
                    }
                    Err(agent::RenewError::Failed(error)) => return Err(error),
                    Err(agent::RenewError::NoAgent) => {
                        let renewed = local::cert_renew(&home, now())?;
                        println!(
                            "renewed this device's certificate: serial {}, valid until {}",
                            renewed.serial,
                            local::relative(renewed.not_after, now())
                        );
                        println!(
                            "no node is running; the next `menzil node` uses it. Give this token to the owner of each owner-only network (`menzil cert accept`); a steward lists it once the node reaches it:"
                        );
                        println!("{}", renewed.token);
                    }
                }
            }
            CertCommand::Accept { token, network } => {
                let token = token_argument(token)?;
                let issued = local::cert_accept(&home()?, network.as_deref(), &token, now())?;
                println!(
                    "listed the renewed certificate of {}: the network's documents are now #{}",
                    issued.member.map(|m| m.to_string()).unwrap_or_default(),
                    issued.seq
                );
                print_new_documents(&issued.token);
            }
        },
        Command::Status => {
            let home = home()?;
            print!("{}", local::status(&home)?.render(now()));
            // A running node knows what the files do not: whether the relay has it attached,
            // and why it turned it away, and which certificate it uses. No node, or one that
            // says nothing, adds nothing.
            if let Ok(config) = Config::load(&home) {
                let socket = node_cmd::agent_socket_path(&home, &config);
                if let Ok(status) = agent::query_node_status(&socket).await {
                    print!("{}", status.relay.render(now()));
                    if let Some(cert) = status.cert {
                        print!("{}", cert.render(now()));
                    }
                    let domain = config
                        .share_domain()
                        .ok()
                        .flatten()
                        .or_else(|| status.relay.usable_share_domain().map(str::to_string));
                    print!(
                        "{}",
                        expose::render_status(&status.shares, domain.as_deref())
                    );
                }
            }
        }
        Command::Relay {
            command: RelayCommand::AddNetwork { token, tenant },
        } => {
            let added = relay_cmd::tenants::add_network_to(
                &home()?,
                &token_argument(token)?,
                now(),
                tenant.as_deref(),
            )?;
            match &added.tenant {
                Some(tenant) => println!(
                    "this relay serves network {} (Roster #{}) for tenant {tenant}",
                    added.network_id, added.seq
                ),
                None => println!(
                    "this relay serves network {} (Roster #{})",
                    added.network_id, added.seq
                ),
            }
            for warning in &added.warnings {
                eprintln!("warning: {warning}");
            }
        }
        Command::Relay {
            command: RelayCommand::RemoveNetwork { network },
        } => {
            let removed = relay_cmd::tenants::remove_network(&home()?, &network)?;
            println!("this relay no longer serves network {}", removed.network_id);
            for warning in &removed.warnings {
                eprintln!("warning: {warning}");
            }
            eprintln!("a running relay drops it at its next reload");
        }
        Command::Relay {
            command: RelayCommand::RemoveTenant { name },
        } => {
            let networks = relay_cmd::tenants::remove_tenant(&home()?, &name, now())?;
            println!(
                "removed tenant {name} and its {} network(s); the name is kept back for 180 days",
                networks.len()
            );
            eprintln!("a running relay drops them at its next reload");
        }
        Command::Relay {
            command: RelayCommand::SuspendTenant { name },
        } => {
            let info = relay_cmd::tenants::set_suspended(&home()?, &name, true)?;
            println!(
                "suspended tenant {name}: its {} network(s) are not served",
                info.network_ids.len()
            );
            eprintln!("a running relay drops them at its next reload");
        }
        Command::Relay {
            command: RelayCommand::ResumeTenant { name },
        } => {
            let info = relay_cmd::tenants::set_suspended(&home()?, &name, false)?;
            println!(
                "resumed tenant {name}: its {} network(s) are served again",
                info.network_ids.len()
            );
            eprintln!("a running relay serves them at its next reload");
        }
        Command::Relay {
            command: RelayCommand::Tenants,
        } => print!("{}", relay_cmd::tenants::render_tenants(&home()?, now())?),
        Command::Relay {
            command: RelayCommand::Status { json },
        } => {
            let at = now();
            let doc = relay_cmd::status::read(&home()?, at)?;
            if json {
                print!("{}", doc.render());
            } else {
                print!("{}", doc.render_human(at));
            }
        }
        Command::Relay {
            command:
                RelayCommand::Run {
                    listen,
                    tls_cert,
                    tls_key,
                    host,
                    path,
                    share_domain,
                    http_listen,
                    acme_directory,
                    acme_contact,
                    fallback_page,
                },
        } => {
            let front = share_domain.map(|share_domain| relay_cmd::FrontDoorOptions {
                share_domain,
                http_listen,
                acme: acme_directory.map(|directory_url| relay_cmd::AcmeOptions {
                    directory_url,
                    contact: acme_contact,
                }),
            });
            let mut relay = relay_cmd::start_with(
                &home()?,
                &relay_cmd::RunOptions {
                    listen,
                    tls_cert,
                    tls_key,
                    path,
                    host,
                    reload_every: relay_cmd::DEFAULT_RELOAD_EVERY,
                    fallback_page,
                },
                front.as_ref(),
            )
            .await?;
            eprintln!("relay listening on {}", relay.addr);
            eprintln!("it serves {} network(s)", relay.networks.len());
            if let Some(front) = &front {
                eprintln!("public shares: <name>.{}", front.share_domain);
                if let Some(http) = relay.http_addr {
                    eprintln!("plain HTTP (ACME HTTP-01, redirect to https) on {http}");
                }
            }
            eprintln!("put this in `relay = ` in the config.toml of every node that uses it:");
            println!("{}", relay.connection_info);
            // Until a signal; the last Roster adopted over DOC is flushed to disk before the
            // process goes.
            if let Some(why) = relay_cmd::run_until(&mut relay, signals::shutdown()).await? {
                eprintln!("stopping ({})", why?);
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
                    eprintln!("menzil: {}", reset_message(&why));
                    std::process::exit(1);
                }
            }
        }
        Command::Reach {
            target,
            listen,
            unix,
        } => {
            let home = home()?;
            let socket = node_cmd::agent_socket_path(&home, &Config::load(&home)?);
            let stop = async {
                match signals::shutdown().await {
                    Ok(why) => eprintln!("stopping ({why})"),
                    Err(error) => eprintln!("menzil: cannot wait for a signal: {error}"),
                }
            };
            match unix {
                Some(path) => {
                    let bound = reach::bind_unix(&path).await?;
                    eprintln!(
                        "carrying connections to {} to {target}; ctrl-c stops and ends what is open",
                        bound.path().display()
                    );
                    reach::run_unix(&socket, &target, bound, stop).await?;
                }
                None => {
                    let listener = tokio::net::TcpListener::bind(listen)
                        .await
                        .with_context(|| format!("listening on {listen}"))?;
                    eprintln!(
                        "carrying connections to {} to {target}; ctrl-c stops and resets what is open",
                        listener.local_addr()?
                    );
                    reach::run(&socket, &target, listener, stop).await?;
                }
            }
        }
        Command::Expose(args) => {
            let home = home()?;
            let out = match args.command {
                Some(ExposeCommand::List) => expose::run_list(&home).await?,
                Some(ExposeCommand::Remove { label }) => {
                    expose::run_unexpose(&home, &label).await?
                }
                None => {
                    let spec = ExposeSpec {
                        label: args.name.context("`--name` is required")?,
                        mode: ExposeMode::parse(&args.mode).map_err(anyhow::Error::msg)?,
                        host: args.host,
                        port: args.port.context("the port to expose is required")?,
                        alpn: args.alpn,
                        replace: args.replace,
                    };
                    expose::run_expose(&home, spec).await?
                }
            };
            print!("{out}");
        }
        Command::Proxy { exit, listen } => {
            let home = home()?;
            let socket = node_cmd::agent_socket_path(&home, &Config::load(&home)?);
            // Refused before anything is bound unless it is loopback.
            let listener = proxy::bind(&listen).await?;
            let stop = async {
                match signals::shutdown().await {
                    Ok(why) => eprintln!("stopping ({why})"),
                    Err(error) => eprintln!("menzil: cannot wait for a signal: {error}"),
                }
            };
            eprintln!(
                "SOCKS5 proxy on {} through {exit}; use socks5h:// so that names are resolved at the exit; ctrl-c stops and resets what is open",
                listener.local_addr()?
            );
            proxy::run(&socket, &exit, listener, stop).await?;
        }
        Command::Version => println!("menzil {}", env!("CARGO_PKG_VERSION")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("menzil").chain(args.iter().copied()))
    }

    #[test]
    fn proxy_takes_the_exit_and_listens_on_loopback_1080_by_default() {
        let proxy = |args: &[&str]| match parse(args)?.command {
            Command::Proxy { exit, listen } => Ok((exit, listen)),
            _ => panic!("not proxy"),
        };
        let got: Result<(String, String), clap::Error> = proxy(&["proxy", "laptop"]);
        assert_eq!(
            got.unwrap(),
            ("laptop".to_string(), "127.0.0.1:1080".to_string())
        );
        let got: Result<(String, String), clap::Error> =
            proxy(&["proxy", "laptop", "--listen", "[::1]:9050"]);
        assert_eq!(got.unwrap().1, "[::1]:9050");
        // The exit is required; the address is checked (and refused unless loopback) when the
        // command runs, before it binds.
        assert!(parse(&["proxy"]).is_err());
        assert!(menzil_cli::proxy::parse_listen("0.0.0.0:1080").is_err());
        // The help says what an application must do.
        let help = <Cli as clap::CommandFactory>::command()
            .find_subcommand_mut("proxy")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.contains("socks5h://"), "{help}");
        assert!(help.contains("[egress] enabled = true"), "{help}");
        assert!(help.contains("egress:*"), "{help}");
        assert!(help.contains("loopback"), "{help}");
    }

    fn label_command(args: &[&str]) -> Result<LabelCommand, clap::Error> {
        match parse(args)?.command {
            Command::Label { command } => Ok(command),
            _ => panic!("not label"),
        }
    }

    #[test]
    fn label_add_remove_and_list_parse_with_their_options() {
        let Ok(LabelCommand::Add {
            name,
            member,
            replace,
            network,
        }) = label_command(&["label", "add", "myapp", "phone"])
        else {
            panic!("add");
        };
        assert_eq!((name.as_str(), member.as_str()), ("myapp", "phone"));
        assert!(!replace && network.is_none());
        let Ok(LabelCommand::Add {
            replace, network, ..
        }) = label_command(&[
            "label",
            "add",
            "myapp",
            "phone",
            "--replace",
            "--network",
            "ab",
        ])
        else {
            panic!("add");
        };
        assert!(replace);
        assert_eq!(network.as_deref(), Some("ab"));

        // The member is optional for `remove`, and absent for `list`.
        let Ok(LabelCommand::Remove { name, member, .. }) =
            label_command(&["label", "remove", "myapp"])
        else {
            panic!("remove");
        };
        assert_eq!((name.as_str(), member), ("myapp", None));
        let Ok(LabelCommand::Remove { member, .. }) =
            label_command(&["label", "remove", "myapp", "phone"])
        else {
            panic!("remove");
        };
        assert_eq!(member.as_deref(), Some("phone"));
        let Ok(LabelCommand::List { network }) =
            label_command(&["label", "list", "--network", "cd"])
        else {
            panic!("list");
        };
        assert_eq!(network.as_deref(), Some("cd"));

        for bad in [
            &["label"][..],
            &["label", "add"],
            &["label", "add", "myapp"],
            &["label", "add", "myapp", "phone", "extra"],
            &["label", "remove"],
            &["label", "list", "myapp"],
            &["label", "remove", "myapp", "phone", "--replace"],
            &["label", "list", "--replace"],
        ] {
            assert!(label_command(bad).is_err(), "{bad:?}");
        }
    }

    fn expose_args(args: &[&str]) -> Result<ExposeArgs, clap::Error> {
        match parse(args)?.command {
            Command::Expose(args) => Ok(args),
            _ => panic!("not expose"),
        }
    }

    #[test]
    fn expose_takes_a_port_a_name_and_the_options_with_their_defaults() {
        let args = expose_args(&["expose", "8443", "--name", "myapp"]).unwrap();
        assert!(args.command.is_none());
        assert_eq!(args.port, Some(8443));
        assert_eq!(args.name.as_deref(), Some("myapp"));
        assert_eq!(args.mode, "blind");
        assert_eq!(args.host, "127.0.0.1");
        assert!(args.alpn.is_empty() && !args.replace);
        // Options before the port, a mode, a host, ALPN repeated and comma separated.
        let args = expose_args(&[
            "expose",
            "--name",
            "box",
            "--mode",
            "tcp",
            "--host",
            "::1",
            "--alpn",
            "h2,http/1.1",
            "--alpn",
            "acme-tls/1",
            "--replace",
            "22",
        ])
        .unwrap();
        assert_eq!(args.port, Some(22));
        assert_eq!(args.mode, "tcp");
        assert_eq!(args.host, "::1");
        assert_eq!(args.alpn, ["h2", "http/1.1", "acme-tls/1"]);
        assert!(args.replace);
        // Terminated parses; anything else is clap's.
        assert_eq!(
            expose_args(&["expose", "1", "--name", "a", "--mode", "terminated"])
                .unwrap()
                .mode,
            "terminated"
        );
        assert!(expose_args(&["expose", "1", "--name", "a", "--mode", "udp"]).is_err());
    }

    #[test]
    fn expose_needs_a_port_in_range_and_a_name() {
        for bad in [
            &["expose"][..],
            &["expose", "8443"],
            &["expose", "--name", "myapp"],
            &["expose", "0", "--name", "myapp"],
            &["expose", "65536", "--name", "myapp"],
            &["expose", "http", "--name", "myapp"],
            &["expose", "-1", "--name", "myapp"],
        ] {
            assert!(expose_args(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            expose_args(&["expose", "65535", "--name", "a"])
                .unwrap()
                .port,
            Some(65535)
        );
        assert_eq!(
            expose_args(&["expose", "1", "--name", "a"]).unwrap().port,
            Some(1)
        );
    }

    #[test]
    fn expose_list_and_remove_are_subcommands_that_take_no_port() {
        let args = expose_args(&["expose", "list"]).unwrap();
        assert!(matches!(args.command, Some(ExposeCommand::List)));
        let args = expose_args(&["expose", "remove", "myapp"]).unwrap();
        assert!(
            matches!(args.command, Some(ExposeCommand::Remove { ref label }) if label == "myapp")
        );
        assert!(expose_args(&["expose", "remove"]).is_err());
        // A port together with a subcommand is a mistake, not a guess.
        assert!(expose_args(&["expose", "8443", "list"]).is_err());
        assert!(expose_args(&["expose", "list", "--name", "myapp"]).is_err());
    }

    #[test]
    fn the_help_says_the_target_speaks_its_own_tls() {
        let help = parse(&["expose", "--help"]).err().unwrap().to_string();
        assert!(help.contains("must speak TLS itself"), "{help}");
        assert!(help.contains("reads the share"), "{help}");
    }
}
