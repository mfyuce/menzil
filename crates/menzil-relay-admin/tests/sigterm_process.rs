//! `menzil-relay-admin` as a process: SIGTERM ends it cleanly. The binary's own signal handling
//! (`main.rs`: stop accepting, give open requests `GRACE` to finish, exit 0) cannot be seen from
//! the library tests, which stop the server through a channel.
//!
//! The agent is the real binary on an ephemeral loopback port with certificates from its own
//! `gen-certs`; the client is the mTLS test client. A change made before the signal (a created
//! tenant) is still on disk after the exit, the exit status is 0 well inside the grace, nothing
//! panicked, and the port no longer answers.

#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::{Owner, connect};
use menzil_relay_admin::pb::CreateTenantRequest;

/// Well inside the agent's 10 s grace: an idle or just served connection must not use it.
const EXIT_BOUND: Duration = Duration::from_secs(6);

struct Guard(Option<Child>);

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_menzil-relay-admin"));
    command.env("NO_COLOR", "1").env("RUST_LOG", "info");
    command
}

/// Sends SIGTERM to the child's own pid (never by name).
fn terminate(child: &Child) {
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(status.success());
}

fn wait_for_exit(child: &mut Child) -> std::process::ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            started.elapsed() < EXIT_BOUND,
            "the agent did not exit within {EXIT_BOUND:?} of SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Starts the agent and returns it with the address it listens on and a reader of everything it
/// writes (the tracing output goes to standard output).
fn start(
    home: &Path,
    certs: &menzil_relay_admin::certs::Generated,
) -> (Guard, SocketAddr, mpsc::Receiver<String>) {
    let mut child = binary()
        .arg("--home")
        .arg(home)
        .args(["--listen", "127.0.0.1:0"])
        .arg("--cert")
        .arg(&certs.server_cert)
        .arg("--key")
        .arg(&certs.server_key)
        .arg("--client-ca")
        .arg(&certs.ca_cert)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, lines) = mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    let out_tx = tx.clone();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = out_tx.send(line);
        }
    });
    let mut stderr = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        for line in text.lines() {
            let _ = tx.send(format!("stderr: {line}"));
        }
    });
    let guard = Guard(Some(child));
    let started = Instant::now();
    loop {
        let line = lines
            .recv_timeout(Duration::from_secs(20))
            .expect("the agent says where it listens");
        if let Some(rest) = line.split("listen=").nth(1) {
            let address = rest.split_whitespace().next().unwrap();
            return (guard, address.parse().unwrap(), lines);
        }
        assert!(started.elapsed() < Duration::from_secs(20));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sigterm_ends_the_agent_cleanly_and_what_it_served_is_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("relay-home");
    let certs =
        menzil_relay_admin::certs::generate(&dir.path().join("certs"), "localhost", "menzil-ui")
            .unwrap();
    let (mut agent, address, lines) = start(&home, &certs);

    let owner = Owner::new();
    let mut client = connect(
        address,
        &certs.ca_cert,
        Some((&certs.client_cert, &certs.client_key)),
    )
    .await
    .expect("connect to the agent process");
    client
        .create_tenant(CreateTenantRequest {
            slug: "alpha".into(),
            tokens: vec![owner.token()],
            class: String::new(),
            idempotency_key: String::new(),
        })
        .await
        .expect("a request before the signal is answered");
    let tenant_file = home.join("relay").join("tenants").join("alpha.toml");
    assert!(tenant_file.is_file());

    // The client keeps its connection open, idle, across the signal.
    let child = agent.0.as_mut().unwrap();
    let signalled = Instant::now();
    terminate(child);
    let status = wait_for_exit(child);
    let took = signalled.elapsed();
    assert!(status.success(), "exit status {status:?} after SIGTERM");
    assert!(took < EXIT_BOUND, "took {took:?}");
    agent.0 = None;

    // Let the readers drain, then look at what was printed.
    std::thread::sleep(Duration::from_millis(200));
    let output: Vec<String> = lines.try_iter().collect();
    let all = output.join("\n");
    assert!(!all.contains("panicked"), "{all}");
    assert!(!all.contains("ERROR"), "{all}");
    assert!(
        !all.contains("did not finish in time"),
        "an idle connection must not use the grace: {all}"
    );

    assert!(tenant_file.is_file(), "the tenant the agent served is kept");
    drop(client);
    assert!(
        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_err(),
        "the port still answers after the exit"
    );
}
