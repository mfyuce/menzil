//! What the local target of a served stream sees when the serving `menzil node` process is
//! stopped (the third red-team round, M4). Every signal that stops a process has to end the
//! stream with a reset: `systemctl stop`, `docker stop` and `kill` send SIGTERM and a closing
//! terminal SIGHUP, and a process that handled only SIGINT was killed by them with its sockets
//! open, which the kernel closes with a FIN, so the target saw a clean end of file where the
//! stream had been cut off.
//!
//! The laptop is the real binary as a child process, the relay and the phone run in this
//! process. One `#[tokio::test]`: `SSL_CERT_FILE` is process-global and must be set before
//! anything dials.

#![cfg(target_os = "linux")]

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use menzil_cli::agent::connect_and_bridge;
use menzil_cli::config::Config;
use menzil_cli::home::Home;
use menzil_cli::local::{admit, grant, init, join, network_create};
use menzil_cli::node_cmd;
use menzil_cli::relay_cmd::{self, DEFAULT_PATH, RunOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(60);

/// Kills the child when the test ends one way or another.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Accepts connections; reports each one's data, then how it ended.
async fn sink(listener: TcpListener, tx: mpsc::UnboundedSender<(u32, String)>) {
    let mut next = 0u32;
    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        next += 1;
        let (id, tx) = (next, tx.clone());
        tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            loop {
                match socket.read(&mut buffer).await {
                    Ok(0) => {
                        let _ = tx.send((id, "clean end of file".to_string()));
                        return;
                    }
                    Ok(n) => {
                        let _ = tx.send((
                            id,
                            format!("data {}", String::from_utf8_lossy(&buffer[..n])),
                        ));
                    }
                    Err(error) => {
                        let _ = tx.send((id, format!("error {:?}", error.kind())));
                        return;
                    }
                }
            }
        });
    }
}

#[tokio::test]
async fn every_signal_that_stops_a_node_resets_the_connections_it_serves() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // A short path: Unix socket paths are limited to about 100 bytes.
    let dir = tempfile::Builder::new()
        .prefix("ns")
        .tempdir_in("/tmp")
        .unwrap();
    let root = dir.path();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = root.join("fullchain.pem");
    let key_pem = root.join("privkey.pem");
    std::fs::write(&cert_pem, certified.cert.pem()).unwrap();
    std::fs::write(&key_pem, certified.signing_key.serialize_pem()).unwrap();
    // SAFETY: the first thing the only test in this binary does, before any dial or other thread
    // that could read the environment.
    unsafe { std::env::set_var("SSL_CERT_FILE", &cert_pem) };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_port = listener.local_addr().unwrap().port();
    let (tx, mut seen) = mpsc::unbounded_channel();
    tokio::spawn(sink(listener, tx));

    let relay_home = Home::new(root.join("relay"));
    let laptop_home = Home::new(root.join("laptop"));
    let phone_home = Home::new(root.join("phone"));
    init(&relay_home, now).unwrap();
    init(&laptop_home, now).unwrap();
    network_create(&laptop_home, "laptop", now).unwrap();
    let request = init(&phone_home, now).unwrap().join_request;
    let admitted = admit(&laptop_home, None, &request, "phone", &[], now).unwrap();
    join(&phone_home, &admitted.token, now).unwrap();
    let granted = grant(
        &laptop_home,
        None,
        "phone",
        "laptop",
        &["tcp:sink".parse().unwrap()],
        None,
        now,
    )
    .unwrap();
    join(&phone_home, &granted.token, now).unwrap();
    relay_cmd::add_network(
        &relay_home,
        &menzil_cli::local::token_for_relay(&laptop_home, None).unwrap(),
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
        },
    )
    .await
    .unwrap();
    std::fs::write(
        laptop_home.config_path(),
        format!(
            "relay = \"{}\"\nproxy = \"direct\"\nagent_socket = \"{}\"\n[services]\n\"tcp:sink\" = \"127.0.0.1:{sink_port}\"\n",
            relay.connection_info,
            root.join("l.sock").display()
        ),
    )
    .unwrap();
    std::fs::write(
        phone_home.config_path(),
        format!(
            "relay = \"{}\"\nproxy = \"direct\"\n",
            relay.connection_info
        ),
    )
    .unwrap();

    for signal in ["INT", "TERM", "HUP"] {
        // A fresh phone node each round: the previous laptop process is gone, and a session to
        // it would only be given up on after the liveness timeout.
        let phone_socket = root.join(format!("p-{signal}.sock"));
        let phone = node_cmd::start(
            &phone_home,
            &Config::load(&phone_home).unwrap(),
            &phone_socket,
        )
        .await
        .unwrap();
        phone
            .node
            .wait_attached(WAIT)
            .await
            .expect("the phone attaches");
        let laptop = Guard(
            Command::new(env!("CARGO_BIN_EXE_menzil"))
                .arg("node")
                .env("MENZIL_HOME", laptop_home.root())
                .env("SSL_CERT_FILE", &cert_pem)
                .env("RUST_LOG", "error")
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );

        // Open a stream to the laptop's sink, trying again until the laptop is up.
        let payload = format!("hello-{signal}");
        let (mut feed, client) = 'attempts: {
            for _ in 0..100 {
                let (feed, mut stdin) = duplex(64 * 1024);
                let (mut stdout, _collect) = duplex(1 << 20);
                let socket = phone_socket.clone();
                let mut client = tokio::spawn(async move {
                    connect_and_bridge(&socket, "laptop/sink", &mut stdin, &mut stdout).await
                });
                match timeout(Duration::from_secs(3), &mut client).await {
                    // Refused or failed at once (the laptop is not up yet): again.
                    Ok(_) => tokio::time::sleep(Duration::from_millis(300)).await,
                    // Still running: the stream is open.
                    Err(_) => break 'attempts (feed, client),
                }
            }
            panic!("the laptop never served a stream");
        };
        feed.write_all(payload.as_bytes()).await.unwrap();
        let connection = loop {
            let (id, event) = timeout(WAIT, seen.recv()).await.unwrap().unwrap();
            if event.contains(&payload) {
                break id;
            }
        };
        tokio::time::sleep(Duration::from_millis(300)).await;

        let status = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(laptop.0.id().to_string())
            .status()
            .unwrap();
        assert!(status.success());
        let ended = loop {
            let (id, event) = timeout(Duration::from_secs(20), seen.recv())
                .await
                .unwrap_or_else(|_| panic!("[{signal}] the target heard nothing after the signal"))
                .unwrap();
            if id == connection {
                break event;
            }
        };
        assert_eq!(
            ended, "error ConnectionReset",
            "[{signal}] a node stopped by a signal must reset the connections it serves"
        );
        client.abort();
        drop(feed);
        drop(laptop);
        drop(phone);
        let _ = std::fs::remove_file(root.join("l.sock"));
    }
}
