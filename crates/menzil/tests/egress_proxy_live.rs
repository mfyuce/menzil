//! `menzil proxy` against a real exit: three homes and a relay with real TLS, three running nodes
//! (the exit `laptop` with `[egress] enabled = true`, `tablet` that is granted and has a rule but
//! never turned egress on, and `phone` that runs the proxies), and a raw SOCKS5 client.
//!
//! What this proves is the production behaviour of the whole chain and its refusals: the floor
//! (loopback is never dialled, even with an `allow` of everything), the names that resolve only
//! to refused addresses, the exit that has egress off, and the listener's refusal of a SOCKS4
//! client. A positive path (bytes flowing to a destination) is NOT here: the production floor
//! refuses loopback, so a loopback echo cannot be dialled through it, and the narrowed floor of
//! `menzil-node`'s own tests is `#[cfg(test)]` there and not reachable from this crate. That path
//! is covered by the executor's tests in `menzil-node` and, from this side, by the parser and
//! bridge tests of `proxy.rs` with a fake exit and the agent tests (`connect` through a real
//! agent to a stream that echoes).
//!
//! One `#[tokio::test]` for the same reason `menzil-node`'s live tests have exactly one:
//! `SSL_CERT_FILE` is process-global, and it must be set before anything dials.

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use menzil_admin::Documents;
use menzil_cli::config::Config;
use menzil_cli::home::Home;
use menzil_cli::local::{self, admit, grant, init, join, network_create};
use menzil_cli::node_cmd;
use menzil_cli::proxy;
use menzil_cli::relay_cmd::{self, DEFAULT_PATH, RunOptions};
use menzil_cli::token::encode_documents;
use menzil_proto::{EgressRule, HostPortPattern, Policy, Roster, ServiceId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(60);

fn service(s: &str) -> ServiceId {
    s.parse().unwrap()
}

/// What the owner does not have a command for yet: the next pair of documents with an `egress`
/// entry for each of `nodes`, allowing any target (the floor still applies), signed by the owner.
fn add_egress_rules(home: &Home, nodes: &[menzil_proto::NodeId]) -> Documents {
    let network_id = local::resolve_network(home, None).unwrap();
    let owner = local::load_owner(home, &network_id).unwrap();
    let current = local::load_documents(home, &network_id).unwrap();
    let (mut roster, mut policy) = (current.roster_body().clone(), current.policy_body().clone());
    roster.seq += 1;
    policy.seq += 1;
    for node in nodes {
        policy.egress.push(EgressRule {
            node_id: *node,
            allow: vec![HostPortPattern("*".to_string())],
            deny: vec![],
        });
    }
    let next = Documents::from_signed(
        Roster::sign(owner.signing_key(), &roster).unwrap(),
        Policy::sign(owner.signing_key(), &policy).unwrap(),
    )
    .unwrap();
    local::save_documents(home, &next).unwrap();
    next
}

/// What the destination of a CONNECT looks like on the wire.
enum Dest<'a> {
    Name(&'a str),
    V4([u8; 4]),
    V6([u8; 16]),
}

/// The reply code of a SOCKS5 CONNECT to `dest`:`port` through the proxy at `proxy`.
async fn connect_code(proxy: SocketAddr, dest: Dest<'_>, port: u16) -> u8 {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(&[5, 1, 0]);
    match dest {
        Dest::Name(name) => {
            request.push(3);
            request.push(name.len() as u8);
            request.extend_from_slice(name.as_bytes());
        }
        Dest::V4(octets) => {
            request.push(1);
            request.extend_from_slice(&octets);
        }
        Dest::V6(octets) => {
            request.push(4);
            request.extend_from_slice(&octets);
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut answer = [0u8; 12];
    timeout(WAIT, client.read_exact(&mut answer))
        .await
        .expect("the proxy answers")
        .unwrap();
    assert_eq!(&answer[..2], &[5, 0], "method selection");
    assert_eq!(&answer[2..2 + 2], &[5, answer[3]][..], "reply header");
    assert_eq!(&answer[4..], &[0, 1, 0, 0, 0, 0, 0, 0], "bound address");
    // After a failure reply the proxy closes in order: nothing more, then the end.
    let mut rest = Vec::new();
    timeout(WAIT, client.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert!(rest.is_empty(), "bytes after the reply: {rest:?}");
    answer[3]
}

#[tokio::test]
async fn the_proxy_carries_a_connect_to_an_exit_and_the_exit_refuses_what_it_must() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // --- the relay's certificate, trusted by every dial in this process ---
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = root.join("fullchain.pem");
    let key_pem = root.join("privkey.pem");
    std::fs::write(&cert_pem, certified.cert.pem()).unwrap();
    std::fs::write(&key_pem, certified.signing_key.serialize_pem()).unwrap();
    // SAFETY: the first thing the only test in this binary does, before any dial or other thread
    // that could read the environment.
    unsafe { std::env::set_var("SSL_CERT_FILE", &cert_pem) };

    // --- a loopback service that counts every connection it is offered ---
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    {
        let accepts = accepts.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = echo.accept().await else {
                    return;
                };
                accepts.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];
                    while let Ok(n) = socket.read(&mut buffer).await {
                        if n == 0 || socket.write_all(&buffer[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
    }

    // --- the commands, as a person runs them ---
    let relay_home = Home::new(root.join("relay"));
    let laptop_home = Home::new(root.join("laptop"));
    let tablet_home = Home::new(root.join("tablet"));
    let phone_home = Home::new(root.join("phone"));
    init(&relay_home, now).unwrap();
    init(&laptop_home, now).unwrap();
    let network_id = network_create(&laptop_home, "laptop", now).unwrap();
    for (home, name) in [(&phone_home, "phone"), (&tablet_home, "tablet")] {
        let request = init(home, now).unwrap().join_request;
        let admitted = admit(&laptop_home, None, &request, name, &[], now).unwrap();
        join(home, &admitted.token, now).unwrap();
    }
    // The phone may use egress on both exits.
    for exit in ["laptop", "tablet"] {
        grant(
            &laptop_home,
            None,
            "phone",
            exit,
            &[service("egress:*")],
            None,
            now,
        )
        .unwrap();
    }
    // Both exits have an egress entry in the Policy (allowing any target: the floor is what
    // refuses); only the laptop will turn egress on in its own configuration.
    let node_id = |home: &Home| local::load_identity(home).unwrap().0.node_id();
    let docs = add_egress_rules(
        &laptop_home,
        &[node_id(&laptop_home), node_id(&tablet_home)],
    );
    let token = encode_documents(&docs);
    join(&phone_home, &token, now).unwrap();
    join(&tablet_home, &token, now).unwrap();
    relay_cmd::add_network(
        &relay_home,
        &local::token_for_relay(&laptop_home, None).unwrap(),
        now,
    )
    .unwrap();

    let relay = relay_cmd::start(
        &relay_home,
        &RunOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            tls_cert: cert_pem.clone(),
            tls_key: key_pem.clone(),
            path: DEFAULT_PATH.to_string(),
            host: Some("localhost".to_string()),
            reload_every: relay_cmd::DEFAULT_RELOAD_EVERY,
            fallback_page: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(relay.networks, vec![network_id]);

    // --- three nodes, configured by files ---
    let write_config = |home: &Home, extra: &str| {
        std::fs::create_dir_all(home.root()).unwrap();
        std::fs::write(
            home.config_path(),
            format!(
                "relay = \"{}\"\nproxy = \"direct\"\n{extra}",
                relay.connection_info
            ),
        )
        .unwrap();
    };
    write_config(&laptop_home, "[egress]\nenabled = true\n");
    write_config(&tablet_home, "");
    write_config(&phone_home, "");
    let start = |home: &Home, socket: &str| {
        let (home, socket) = (home.clone(), root.join(socket));
        async move {
            node_cmd::start(&home, &Config::load(&home).unwrap(), &socket)
                .await
                .unwrap()
        }
    };
    let laptop = start(&laptop_home, "laptop.sock").await;
    let tablet = start(&tablet_home, "tablet.sock").await;
    let phone = start(&phone_home, "phone.sock").await;
    for node in [&laptop.node, &tablet.node, &phone.node] {
        node.wait_attached(WAIT).await.expect("a node must attach");
    }

    // --- the proxies, on the phone: one through each exit ---
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut proxies = Vec::new();
    let mut addresses = Vec::new();
    for exit in ["laptop", "tablet"] {
        let listener = proxy::bind("127.0.0.1:0").await.unwrap();
        addresses.push(listener.local_addr().unwrap());
        let (socket, mut stop) = (phone.socket.clone(), stop_rx.clone());
        proxies.push(tokio::spawn(async move {
            proxy::run(&socket, exit, listener, async move {
                let _ = stop.wait_for(|stopped| *stopped).await;
            })
            .await
        }));
    }
    let (through_laptop, through_tablet) = (addresses[0], addresses[1]);

    // (a) A literal loopback address, however it is written, is the floor: 0x02, and the
    // listener on that very port is never offered a connection.
    assert_eq!(
        connect_code(through_laptop, Dest::V4([127, 0, 0, 1]), echo_port).await,
        0x02
    );
    assert_eq!(
        connect_code(
            through_laptop,
            Dest::V6("::1".parse::<std::net::Ipv6Addr>().unwrap().octets()),
            echo_port
        )
        .await,
        0x02
    );
    assert_eq!(
        connect_code(
            through_laptop,
            Dest::V6(
                "::ffff:127.0.0.1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
            ),
            echo_port
        )
        .await,
        0x02
    );
    assert_eq!(
        connect_code(through_laptop, Dest::V4([169, 254, 169, 254]), 80).await,
        0x02
    );
    assert_eq!(
        connect_code(through_laptop, Dest::V4([0, 0, 0, 0]), echo_port).await,
        0x02
    );
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "the floor was not applied"
    );

    // (b) A name that resolves only to a refused address is `target_unreachable` (0x04), the
    // same answer as a name that does not exist, and the listener still sees nothing. The
    // upper case spelling is folded by the proxy, so it reaches the same refusal and not
    // `invalid_target`.
    assert_eq!(
        connect_code(through_laptop, Dest::Name("localhost"), echo_port).await,
        0x04
    );
    assert_eq!(
        connect_code(through_laptop, Dest::Name("LocalHost"), echo_port).await,
        0x04
    );
    assert_eq!(accepts.load(Ordering::SeqCst), 0, "a name reached loopback");

    // A name the exit cannot take as one (`127.1` would be read as an address by a resolver) is
    // `invalid_target`, 0x08; port 0 is refused by the proxy itself with 0x01.
    assert_eq!(
        connect_code(through_laptop, Dest::Name("127.1"), echo_port).await,
        0x08
    );
    assert_eq!(
        connect_code(through_laptop, Dest::Name("example.org"), 0).await,
        0x01
    );
    assert_eq!(accepts.load(Ordering::SeqCst), 0);

    // (c) The tablet is granted and has a rule but did not turn egress on: it answers
    // `unknown_service`, which the proxy reports as the general failure (0x01).
    assert_eq!(
        connect_code(through_tablet, Dest::Name("example.org"), 443).await,
        0x01
    );
    assert_eq!(
        connect_code(through_tablet, Dest::V4([127, 0, 0, 1]), echo_port).await,
        0x01
    );
    assert_eq!(accepts.load(Ordering::SeqCst), 0);

    // (d) The listener does not take a SOCKS4 client: closed, no answer.
    let mut socks4 = TcpStream::connect(through_laptop).await.unwrap();
    socks4
        .write_all(&[4, 1, 0, 80, 93, 184, 216, 34, 0])
        .await
        .unwrap();
    let mut answer = Vec::new();
    let _ = timeout(WAIT, socks4.read_to_end(&mut answer))
        .await
        .unwrap();
    assert!(answer.is_empty(), "a SOCKS4 client got {answer:?}");

    // The codes above could be mistaken for each other (`no_grant` is 0x02 too), so ask the agent
    // itself, which carries the exit's own code name: the grant and the rule were accepted and
    // the refusals are the executor's.
    let said = |host: &'static str, who: &'static str| {
        let socket = phone.socket.clone();
        async move {
            let error = menzil_cli::agent::open_connect(&socket, who, host, echo_port)
                .await
                .err()
                .expect("refused");
            format!("{error:#}")
        }
    };
    let text = said("127.0.0.1", "laptop").await;
    assert!(
        text.starts_with("refused by the other end: forbidden"),
        "{text}"
    );
    let text = said("localhost", "laptop").await;
    assert!(
        text.starts_with("refused by the other end: target_unreachable"),
        "{text}"
    );
    let text = said("127.1", "laptop").await;
    assert!(
        text.starts_with("refused by the other end: invalid_target"),
        "{text}"
    );
    let text = said("example.org", "tablet").await;
    assert!(
        text.starts_with("refused by the other end: unknown_service"),
        "{text}"
    );
    assert_eq!(accepts.load(Ordering::SeqCst), 0);

    // The proxy goes on after all those refusals: one more of the same.
    assert_eq!(
        connect_code(through_laptop, Dest::V4([127, 0, 0, 1]), echo_port).await,
        0x02
    );
    assert_eq!(accepts.load(Ordering::SeqCst), 0);

    stop_tx.send(true).unwrap();
    for proxy in proxies {
        timeout(WAIT, proxy).await.unwrap().unwrap().unwrap();
    }
    drop(phone);
    drop(tablet);
    drop(laptop);
    relay.stop();
}
