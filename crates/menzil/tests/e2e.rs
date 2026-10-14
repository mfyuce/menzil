//! The whole thing, driven the way a person drives it: three homes (a relay, a laptop that owns a
//! network and serves, a phone that is admitted), the commands that make them, a real relay with
//! real TLS, two running nodes, and a client going through the phone's agent socket to a service
//! on the laptop, which is a real TCP server on loopback.
//!
//! One `#[tokio::test]` for the same reason `menzil-node`'s live tests have exactly one:
//! `SSL_CERT_FILE` is process-global, and it must be set before anything dials.

#![cfg(target_os = "linux")]

use std::io;
use std::path::Path;
use std::time::Duration;

use menzil_cli::agent::{End, connect_and_bridge};
use menzil_cli::config::Config;
use menzil_cli::home::Home;
use menzil_cli::local::{admit, grant, init, join, network_create};
use menzil_cli::node_cmd;
use menzil_cli::relay_cmd::{self, DEFAULT_PATH, RunOptions};
use menzil_proto::ServiceId;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(60);

fn service(s: &str) -> ServiceId {
    s.parse().unwrap()
}

/// Echoes until the client's end of file, then closes: a service that finishes cleanly.
async fn echo_server(listener: TcpListener) {
    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            loop {
                match socket.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if socket.write_all(&buffer[..n]).await.is_err() {
                            return;
                        }
                    }
                }
            }
            let _ = socket.shutdown().await;
        });
    }
}

/// Answers a byte with `partial` and then fails the connection: a service that dies mid-answer.
async fn failing_server(listener: TcpListener) {
    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let mut one = [0u8; 1];
            let _ = socket.read_exact(&mut one).await;
            let _ = socket.write_all(b"partial").await;
            tokio::time::sleep(Duration::from_millis(150)).await;
            socket2::SockRef::from(&socket)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
            drop(socket);
        });
    }
}

async fn run_through(socket: &Path, target: &str, input: &[u8]) -> anyhow::Result<(Vec<u8>, End)> {
    let (mut feed, mut stdin) = duplex(64 * 1024);
    let (mut stdout, mut collect) = duplex(1 << 20);
    let input = input.to_vec();
    tokio::spawn(async move {
        let _ = feed.write_all(&input).await;
        let _ = feed.shutdown().await;
    });
    let end = timeout(
        WAIT,
        connect_and_bridge(socket, target, &mut stdin, &mut stdout),
    )
    .await
    .expect("the client must finish")?;
    drop(stdout);
    let mut output = Vec::new();
    collect.read_to_end(&mut output).await.unwrap();
    Ok((output, end))
}

#[tokio::test]
async fn a_phone_reaches_a_service_on_a_laptop_through_a_relay() {
    // The real clock: nodes and the relay check certificates and documents against it.
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

    // --- the services behind the laptop ---
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(echo_server(echo));
    let failing = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let failing_port = failing.local_addr().unwrap().port();
    tokio::spawn(failing_server(failing));
    let dead_port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };

    // --- the commands, as a person runs them ---
    let relay_home = Home::new(root.join("relay"));
    let laptop_home = Home::new(root.join("laptop"));
    let phone_home = Home::new(root.join("phone"));
    init(&relay_home, now).unwrap();
    init(&laptop_home, now).unwrap();
    let network_id = network_create(&laptop_home, "laptop", now).unwrap();
    let request = init(&phone_home, now).unwrap().join_request;
    let admitted = admit(&laptop_home, None, &request, "phone", &[], now).unwrap();
    join(&phone_home, &admitted.token, now).unwrap();
    let services = [
        service("tcp:echo"),
        service("tcp:failing"),
        service("tcp:dead"),
        service("tcp:unserved"),
    ];
    let granted = grant(&laptop_home, None, "phone", "laptop", &services, None, now).unwrap();
    join(&phone_home, &granted.token, now).unwrap();
    relay_cmd::add_network(
        &relay_home,
        &menzil_cli::local::token_for_relay(&laptop_home, None).unwrap(),
        now,
    )
    .unwrap();

    // The relay.
    let relay = relay_cmd::start(
        &relay_home,
        &RunOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            tls_cert: cert_pem.clone(),
            tls_key: key_pem.clone(),
            path: DEFAULT_PATH.to_string(),
            host: Some("localhost".to_string()),
            reload_every: relay_cmd::DEFAULT_RELOAD_EVERY,
        },
    )
    .await
    .unwrap();
    assert_eq!(relay.networks, vec![network_id]);

    // --- two nodes, configured by files ---
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
    write_config(
        &laptop_home,
        &format!(
            "[services]\n\"tcp:echo\" = \"127.0.0.1:{echo_port}\"\n\"tcp:failing\" = \"127.0.0.1:{failing_port}\"\n\"tcp:dead\" = \"127.0.0.1:{dead_port}\"\n"
        ),
    );
    write_config(&phone_home, "");
    let laptop_socket = root.join("laptop.sock");
    let phone_socket = root.join("phone.sock");
    let laptop = node_cmd::start(
        &laptop_home,
        &Config::load(&laptop_home).unwrap(),
        &laptop_socket,
    )
    .await
    .unwrap();
    let phone = node_cmd::start(
        &phone_home,
        &Config::load(&phone_home).unwrap(),
        &phone_socket,
    )
    .await
    .unwrap();
    laptop
        .node
        .wait_attached(WAIT)
        .await
        .expect("the laptop must attach");
    phone
        .node
        .wait_attached(WAIT)
        .await
        .expect("the phone must attach");

    // --- bytes both ways through the relay, and a clean end ---
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let (output, end) = run_through(&phone_socket, "laptop/echo", &data)
        .await
        .unwrap();
    assert_eq!(end, End::Clean);
    assert_eq!(output, data);
    // The shorthand and the long form name the same service.
    let (output, end) = run_through(&phone_socket, "laptop/tcp:echo", b"again")
        .await
        .unwrap();
    assert_eq!((output.as_slice(), end), (&b"again"[..], End::Clean));

    // --- a service that dies mid-answer is a reset at the far end ---
    let (output, end) = run_through(&phone_socket, "laptop/failing", b"x")
        .await
        .unwrap();
    assert_eq!(output, b"partial");
    assert!(matches!(end, End::Reset(_)), "{end:?}");

    // --- what is refused, in words ---
    let message = |result: anyhow::Result<(Vec<u8>, End)>| format!("{:#}", result.unwrap_err());
    let error = message(run_through(&phone_socket, "nobody/echo", b"").await);
    assert!(
        error.contains("no member called") && error.contains("laptop"),
        "{error}"
    );
    let error = message(run_through(&phone_socket, "laptop/dead", b"").await);
    assert!(error.contains("target_unreachable"), "{error}");
    let error = message(run_through(&phone_socket, "laptop/unserved", b"").await);
    assert!(error.contains("unknown_service"), "{error}");
    let error = message(run_through(&phone_socket, "laptop/notgranted", b"").await);
    assert!(error.contains("no_grant"), "{error}");
    let error = message(run_through(&phone_socket, "laptop", b"").await);
    assert!(error.contains("<who>/<service>"), "{error}");

    // --- and the laptop can reach nothing on the phone: it holds no grant for that ---
    let error = message(run_through(&laptop_socket, "phone/echo", b"").await);
    assert!(
        error.contains("no_grant") || error.contains("refused"),
        "{error}"
    );

    // --- the agent socket is private ---
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&phone_socket)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    drop(phone);
    drop(laptop);
    relay.stop();
    let _ = (TcpStream::connect("127.0.0.1:1").await.map(|_| ()) as io::Result<()>).ok();
}
