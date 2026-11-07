//! `gen-certs`: the files, their modes, and what the certificates say.

use std::os::unix::fs::PermissionsExt;

use menzil_relay_admin::certs::generate;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

fn der(path: &std::path::Path) -> Vec<u8> {
    CertificateDer::from_pem_file(path).unwrap().to_vec()
}

fn has(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
/// basicConstraints, critical, cA FALSE (the empty SEQUENCE).
const NOT_A_CA: &[u8] = &[0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00];
/// cA TRUE with pathLen 0.
const A_CA: &[u8] = &[0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00];

/// The two UTCTime values (notBefore, notAfter) of a certificate as days since 1970.
fn validity_days(der: &[u8]) -> (i64, i64) {
    let mut times = Vec::new();
    for i in 0..der.len().saturating_sub(15) {
        if der[i] == 0x17 && der[i + 1] == 0x0d && der[i + 14] == b'Z' {
            let t = &der[i + 2..i + 14];
            if t.iter().all(u8::is_ascii_digit) {
                let n = |a: usize| i64::from((t[a] - b'0') * 10 + (t[a + 1] - b'0'));
                let date = time::Date::from_calendar_date(
                    2000 + n(0) as i32,
                    time::Month::try_from(n(2) as u8).unwrap(),
                    n(4) as u8,
                )
                .unwrap();
                times.push(i64::from(date.to_julian_day()));
            }
        }
    }
    assert_eq!(times.len(), 2, "notBefore and notAfter");
    (times[0], times[1])
}

#[test]
fn writes_six_files_with_private_keys() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("new").join("certs");
    let g = generate(&out, "relay.example", "menzil-ui").unwrap();
    for key in [&g.ca_key, &g.server_key, &g.client_key] {
        assert_eq!(
            std::fs::metadata(key).unwrap().permissions().mode() & 0o777,
            0o600,
            "{key:?}"
        );
    }
    for cert in [&g.ca_cert, &g.server_cert, &g.client_cert] {
        assert!(cert.is_file());
    }
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn refuses_to_overwrite_and_writes_nothing_then() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("certs");
    std::fs::create_dir_all(&out).unwrap();
    // One existing file of the six stops everything.
    std::fs::write(out.join("client.key"), "mine").unwrap();
    let e = generate(&out, "relay.example", "menzil-ui").unwrap_err();
    assert!(e.contains("refusing to overwrite"), "{e}");
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1);
    assert_eq!(
        std::fs::read_to_string(out.join("client.key")).unwrap(),
        "mine"
    );
    // A second run in a clean directory, then again over it.
    let out2 = dir.path().join("certs2");
    generate(&out2, "relay.example", "menzil-ui").unwrap();
    let before = std::fs::read(out2.join("ca.key")).unwrap();
    assert!(generate(&out2, "relay.example", "menzil-ui").is_err());
    assert_eq!(std::fs::read(out2.join("ca.key")).unwrap(), before);
    // A symlink in the way is not followed.
    let out3 = dir.path().join("certs3");
    std::fs::create_dir_all(&out3).unwrap();
    std::os::unix::fs::symlink(dir.path().join("elsewhere"), out3.join("ca.pem")).unwrap();
    assert!(generate(&out3, "relay.example", "menzil-ui").is_err());
    assert!(!dir.path().join("elsewhere").exists());
}

#[test]
fn leaves_are_not_cas_and_carry_their_one_usage() {
    let dir = tempfile::tempdir().unwrap();
    let g = generate(dir.path(), "relay.example", "menzil-ui").unwrap();
    let (ca, server, client) = (der(&g.ca_cert), der(&g.server_cert), der(&g.client_cert));
    assert!(has(&ca, A_CA) && !has(&ca, NOT_A_CA));
    for leaf in [&server, &client] {
        assert!(has(leaf, NOT_A_CA), "basicConstraints CA:FALSE");
        assert!(!has(leaf, A_CA));
    }
    assert!(has(&server, SERVER_AUTH) && !has(&server, CLIENT_AUTH));
    assert!(has(&client, CLIENT_AUTH) && !has(&client, SERVER_AUTH));
}

#[test]
fn the_server_certificate_names_the_host_and_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let g = generate(dir.path(), "relay.example", "menzil-ui").unwrap();
    let server = der(&g.server_cert);
    assert!(has(&server, b"relay.example"));
    assert!(
        has(&server, &[0x87, 0x04, 127, 0, 0, 1]),
        "IP SAN 127.0.0.1"
    );
    // An IP as the name is an IP SAN and is not doubled.
    let dir = tempfile::tempdir().unwrap();
    let g = generate(dir.path(), "127.0.0.1", "c").unwrap();
    let server = der(&g.server_cert);
    assert_eq!(
        server
            .windows(6)
            .filter(|w| *w == [0x87, 0x04, 127, 0, 0, 1])
            .count(),
        1
    );
}

#[test]
fn validity_is_a_year_for_leaves_and_five_for_the_ca() {
    let dir = tempfile::tempdir().unwrap();
    let g = generate(dir.path(), "relay.example", "menzil-ui").unwrap();
    let (s0, s1) = validity_days(&der(&g.server_cert));
    let (c0, c1) = validity_days(&der(&g.client_cert));
    let (a0, a1) = validity_days(&der(&g.ca_cert));
    assert!((365..=367).contains(&(s1 - s0)), "{}", s1 - s0);
    assert!((365..=367).contains(&(c1 - c0)), "{}", c1 - c0);
    assert!((5 * 365..=5 * 365 + 3).contains(&(a1 - a0)), "{}", a1 - a0);
}

#[test]
fn empty_names_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    assert!(generate(dir.path(), "", "c").is_err());
    assert!(generate(dir.path(), "s", "").is_err());
}
