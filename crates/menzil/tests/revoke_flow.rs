//! Revocation and grant removal, driven on the command line the way an owner does it (L4k K6):
//! a laptop that owns a network and runs `menzil node`, a phone and a tablet that are admitted and
//! run `menzil node` too, a relay with real TLS, and `menzil stdio` on the phone and the tablet
//! carrying streams to services on the laptop. Then the owner runs `menzil ungrant` and `menzil revoke` on the laptop
//! while its node runs, and the test watches what the phone's `stdio` processes and the phone's
//! node see:
//!
//! - `menzil ungrant phone laptop tcp:other` ends the stream to `tcp:other` (the phone's `stdio`
//!   exits with status 1 and says why), leaves the stream to `tcp:echo` running, and
//!   `menzil status` on both devices goes on working;
//! - `menzil revoke phone` ends the other stream the same way, the relay holds the new Roster, the
//!   relay ends the phone's session (the phone's node logs the GOAWAY `revoked`), and the phone
//!   cannot reach the laptop again; `menzil status` counts the revoked node;
//! - none of that touches the tablet: its stream goes on, it can open another, and the laptop's
//!   node sends it the new documents (its `menzil status` counts the revoked node too).
//!
//! The relay runs in this process, both nodes and every command are the real binary as child
//! processes. One `#[tokio::test]` like the other live tests of this crate, although nothing here
//! sets `SSL_CERT_FILE` in this process: the children get it in their environment.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use menzil_cli::home::Home;
use menzil_cli::local::{admit, grant, init, join, network_create};
use menzil_cli::relay_cmd::{self, DEFAULT_PATH, RunOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const WAIT: Duration = Duration::from_secs(60);

/// Kills the child when the test ends one way or another.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// What a finished `menzil` command printed.
struct Output {
    ok: bool,
    stdout: String,
    stderr: String,
}

/// Runs `menzil --home <home> <args>` to its end, off the async threads.
async fn menzil(home: &Path, args: &[&str]) -> Output {
    let home = home.to_path_buf();
    let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        let out = Command::new(env!("CARGO_BIN_EXE_menzil"))
            .arg("--home")
            .arg(&home)
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        Output {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    })
    .await
    .unwrap()
}

/// A `menzil stdio` process of a member's home, with its standard input held open.
struct MemberStdio {
    child: Guard,
    stdin: Option<ChildStdin>,
    out: mpsc::Receiver<Vec<u8>>,
    err: mpsc::Receiver<Vec<u8>>,
    seen: Vec<u8>,
}

impl MemberStdio {
    fn spawn(home: &Path, target: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_menzil"))
            .arg("--home")
            .arg(home)
            .arg("stdio")
            .arg(target)
            .env("RUST_LOG", "error")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let (out_tx, out) = mpsc::channel();
        let mut stdout = child.stdout.take().unwrap();
        thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buffer) {
                if n == 0 || out_tx.send(buffer[..n].to_vec()).is_err() {
                    return;
                }
            }
        });
        let (err_tx, err) = mpsc::channel();
        let mut stderr = child.stderr.take().unwrap();
        thread::spawn(move || {
            let mut all = Vec::new();
            let _ = stderr.read_to_end(&mut all);
            let _ = err_tx.send(all);
        });
        Self {
            child: Guard(child),
            stdin,
            out,
            err,
            seen: Vec::new(),
        }
    }

    /// Sends `bytes` and waits until as many have come back (the service echoes).
    async fn echoes(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("standard input is open");
        stdin.write_all(bytes).unwrap();
        stdin.flush().unwrap();
        let started = Instant::now();
        let mut got = Vec::new();
        while got.len() < bytes.len() {
            assert!(
                started.elapsed() < WAIT,
                "no echo of {bytes:?}, got {got:?}"
            );
            match self.out.try_recv() {
                Ok(chunk) => got.extend_from_slice(&chunk),
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        assert_eq!(got, bytes);
        self.seen.extend_from_slice(&got);
    }

    /// Waits for the process to end, `within` at most; its status and what it wrote to standard
    /// error.
    async fn ends(&mut self, within: Duration) -> Option<(ExitStatus, String)> {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.0.try_wait().unwrap() {
                let mut text = Vec::new();
                let waited = Instant::now();
                loop {
                    match self.err.try_recv() {
                        Ok(more) => {
                            text.extend_from_slice(&more);
                            break;
                        }
                        Err(_) if waited.elapsed() < Duration::from_secs(5) => {
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                        Err(_) => break,
                    }
                }
                return Some((status, String::from_utf8_lossy(&text).into_owned()));
            }
            if started.elapsed() >= within {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// An echo service: a connection ends with its client's end of file.
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

fn node(home: &Path, cert: &Path, log: &Path) -> Guard {
    Guard(
        Command::new(env!("CARGO_BIN_EXE_menzil"))
            .arg("--home")
            .arg(home)
            .arg("node")
            .env("SSL_CERT_FILE", cert)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(log).unwrap())
            .spawn()
            .unwrap(),
    )
}

fn write_config(home: &Home, relay: &str, socket: &Path, services: &str) {
    std::fs::create_dir_all(home.root()).unwrap();
    std::fs::write(
        home.config_path(),
        format!(
            "relay = \"{relay}\"\nproxy = \"direct\"\nagent_socket = \"{}\"\n{services}",
            socket.display()
        ),
    )
    .unwrap();
}

#[tokio::test]
async fn ungrant_and_revoke_cut_a_running_phone_off_and_the_status_goes_on_working() {
    // The real clock: nodes and the relay check certificates and documents against it.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // A short path: Unix socket paths are limited to about 100 bytes.
    let dir = tempfile::Builder::new()
        .prefix("rv")
        .tempdir_in("/tmp")
        .unwrap();
    let root: PathBuf = dir.path().to_path_buf();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = root.join("fullchain.pem");
    let key_pem = root.join("privkey.pem");
    std::fs::write(&cert_pem, certified.cert.pem()).unwrap();
    std::fs::write(&key_pem, certified.signing_key.serialize_pem()).unwrap();

    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(echo_server(echo));

    // --- the homes, made with the library functions the commands call ---
    let relay_home = Home::new(root.join("relay"));
    let laptop_home = Home::new(root.join("laptop"));
    let phone_home = Home::new(root.join("phone"));
    let tablet_home = Home::new(root.join("tablet"));
    init(&relay_home, now).unwrap();
    init(&laptop_home, now).unwrap();
    let network_id = network_create(&laptop_home, "laptop", now).unwrap();
    let request = init(&phone_home, now).unwrap().join_request;
    admit(&laptop_home, None, &request, "phone", &[], now).unwrap();
    grant(
        &laptop_home,
        None,
        "phone",
        "laptop",
        &["tcp:echo".parse().unwrap(), "tcp:other".parse().unwrap()],
        None,
        now,
    )
    .unwrap();
    let request = init(&tablet_home, now).unwrap().join_request;
    admit(&laptop_home, None, &request, "tablet", &[], now).unwrap();
    let granted = grant(
        &laptop_home,
        None,
        "tablet",
        "laptop",
        &["tcp:echo".parse().unwrap()],
        None,
        now,
    )
    .unwrap();
    // Documents #5 for both.
    assert_eq!(granted.seq, 5);
    join(&phone_home, &granted.token, now).unwrap();
    join(&tablet_home, &granted.token, now).unwrap();
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
    write_config(
        &laptop_home,
        &relay.connection_info,
        &root.join("l.sock"),
        &format!(
            "[services]\n\"tcp:echo\" = \"127.0.0.1:{echo_port}\"\n\"tcp:other\" = \"127.0.0.1:{echo_port}\"\n"
        ),
    );
    write_config(
        &phone_home,
        &relay.connection_info,
        &root.join("p.sock"),
        "",
    );
    write_config(
        &tablet_home,
        &relay.connection_info,
        &root.join("t.sock"),
        "",
    );

    // --- two running nodes, and a stream to each service ---
    let phone_log = root.join("phone.log");
    let _laptop_node = node(laptop_home.root(), &cert_pem, &root.join("laptop.log"));
    let _phone_node = node(phone_home.root(), &cert_pem, &phone_log);
    let _tablet_node = node(tablet_home.root(), &cert_pem, &root.join("tablet.log"));
    let started = Instant::now();
    let (mut echo_stream, mut other_stream) = loop {
        assert!(
            started.elapsed() < WAIT,
            "the phone never reached the laptop"
        );
        let mut probe = MemberStdio::spawn(phone_home.root(), "laptop/echo");
        if tokio::time::timeout(Duration::from_secs(20), probe.echoes(b"ready"))
            .await
            .is_ok()
        {
            let other = MemberStdio::spawn(phone_home.root(), "laptop/other");
            break (probe, other);
        }
        drop(probe);
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    echo_stream.echoes(b"first").await;
    other_stream.echoes(b"first").await;
    let mut tablet_stream = loop {
        assert!(
            started.elapsed() < WAIT,
            "the tablet never reached the laptop"
        );
        let mut probe = MemberStdio::spawn(tablet_home.root(), "laptop/echo");
        if tokio::time::timeout(Duration::from_secs(20), probe.echoes(b"first"))
            .await
            .is_ok()
        {
            break probe;
        }
        drop(probe);
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    // --- `menzil ungrant`: one service goes, the stream to it is reset, the other goes on ---
    let ungranted = menzil(
        laptop_home.root(),
        &["ungrant", "phone", "laptop", "tcp:other"],
    )
    .await;
    assert!(ungranted.ok, "{}", ungranted.stderr);
    assert!(
        ungranted.stdout.contains("took the grants back")
            && ungranted.stdout.contains("documents are now #6")
            && ungranted.stdout.contains("within 15 seconds"),
        "{}",
        ungranted.stdout
    );
    let (status, message) = other_stream
        .ends(WAIT)
        .await
        .expect("the stream to the service that was taken back must end");
    assert_eq!(status.code(), Some(1), "{message}");
    assert!(
        message.contains("the connection was reset")
            && message.contains("taken back")
            && message.contains("grant_removed"),
        "{message}"
    );
    // The stream to the service that was not taken back is untouched.
    echo_stream.echoes(b"after ungrant").await;
    // A new stream to the service that was taken back is refused, in words.
    let mut again = MemberStdio::spawn(phone_home.root(), "laptop/other");
    let (status, message) = again
        .ends(WAIT)
        .await
        .expect("a stream to a service without a grant is refused");
    assert_eq!(status.code(), Some(1), "{message}");
    assert!(
        message.contains("no_grant") && message.contains("menzil ungrant"),
        "{message}"
    );
    tablet_stream.echoes(b"after ungrant").await;
    // The status works on both devices, with the grants that are left.
    let status = menzil(laptop_home.root(), &["status"]).await;
    assert!(status.ok, "{}", status.stderr);
    assert!(
        status.stdout.contains("owned by this device")
            && status.stdout.contains("documents #6")
            && status.stdout.contains("2 grants")
            && !status.stdout.contains("revoked"),
        "{}",
        status.stdout
    );
    let status = menzil(phone_home.root(), &["status"]).await;
    assert!(
        status.ok && status.stdout.contains("laptop"),
        "{}",
        status.stderr
    );

    // --- `menzil revoke`: the phone is cut off and stays cut off ---
    let revoked_at = Instant::now();
    let revoked = menzil(laptop_home.root(), &["revoke", "phone"]).await;
    assert!(revoked.ok, "{}", revoked.stderr);
    assert!(
        revoked.stdout.contains("revoked \"phone\"")
            && revoked.stdout.contains("documents are now #7")
            && revoked.stdout.contains("within 15 seconds"),
        "{}",
        revoked.stdout
    );
    let (status, message) = echo_stream
        .ends(WAIT)
        .await
        .expect("the stream of a revoked member must end");
    assert_eq!(status.code(), Some(1), "{message}");
    assert!(
        message.contains("the connection was reset") && message.contains("revoked"),
        "{message}"
    );
    // The laptop's node reloads its files every 15 s; the end follows at once.
    assert!(
        revoked_at.elapsed() < Duration::from_secs(45),
        "the revocation took {:?}",
        revoked_at.elapsed()
    );
    // The relay holds the Roster that revokes the phone (the laptop's node pushed it) ...
    let until = Instant::now();
    while relay.roster_seq(&network_id) != Some(7) {
        assert!(until.elapsed() < WAIT, "the relay never got the revocation");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // ... and ended the phone's session: the phone's node was sent GOAWAY `revoked`.
    let until = Instant::now();
    loop {
        let log = std::fs::read_to_string(&phone_log).unwrap_or_default();
        if log.contains("GOAWAY") && log.contains("revoked") {
            break;
        }
        assert!(
            until.elapsed() < WAIT,
            "the phone's node was never told it was revoked: {log}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // The phone's node remembers why, and `menzil status` on the phone (which asks the running
    // node) and a refused `stdio` say it in words, not only as a list of possible causes.
    let until = Instant::now();
    loop {
        let status = menzil(phone_home.root(), &["status"]).await;
        assert!(status.ok, "{}", status.stderr);
        if status.stdout.contains("the relay turned this device away")
            && status.stdout.contains("this device is revoked")
            && status.stdout.contains("GOAWAY revoked")
        {
            assert!(status.stdout.contains("relay: "), "{}", status.stdout);
            break;
        }
        assert!(
            until.elapsed() < WAIT,
            "the phone's status never gave the relay's reason: {}",
            status.stdout
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // The phone cannot reach the laptop again. (Whether its node still counts itself as not
    // attached, or has reattached without the network and fails its own standing check, depends
    // on how long ago the relay ended its session; both say why.)
    let mut retry = MemberStdio::spawn(phone_home.root(), "laptop/echo");
    let (status, message) = retry
        .ends(Duration::from_secs(120))
        .await
        .expect("a revoked phone gets an answer, an error, in the end");
    assert_eq!(status.code(), Some(1), "{message}");
    assert!(
        message.starts_with("menzil: ")
            && (message.contains("not connected to the relay")
                || message.contains("not a member in good standing"))
            && message.contains("the relay turned this device away")
            && message.contains("revoked"),
        "{message}"
    );
    // The tablet is not touched: its stream goes on, it can open another, and it was sent the
    // documents that revoke the phone.
    tablet_stream.echoes(b"after revoke").await;
    let mut another = MemberStdio::spawn(tablet_home.root(), "laptop/echo");
    another.echoes(b"another").await;
    let until = Instant::now();
    loop {
        let status = menzil(tablet_home.root(), &["status"]).await;
        assert!(status.ok, "{}", status.stderr);
        if status.stdout.contains("1 revoked") && status.stdout.contains("documents #7") {
            assert!(!status.stdout.contains("phone"), "{}", status.stdout);
            break;
        }
        assert!(
            until.elapsed() < WAIT,
            "the tablet never got the revocation: {}",
            status.stdout
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // The owner's status counts the revoked node and no longer lists it.
    let status = menzil(laptop_home.root(), &["status"]).await;
    assert!(status.ok, "{}", status.stderr);
    assert!(
        status.stdout.contains("documents #7") && status.stdout.contains("1 revoked"),
        "{}",
        status.stdout
    );
    assert!(!status.stdout.contains("phone"), "{}", status.stdout);

    relay.stop();
}
