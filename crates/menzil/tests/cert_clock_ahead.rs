//! A renewal made while the clock ran ahead leaves a certificate that does not start yet; once
//! the clock is right again the node sees it is due (cert rotation round C, L2), and the
//! renewal that follows is valid now and not due again.

use menzil_cli::{cert_renew, home::Home, local};

const DAY: u64 = 24 * 60 * 60;

#[test]
fn a_certificate_made_under_a_clock_ahead_is_renewed_when_the_clock_is_right() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path().join("home"));
    let real = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    local::init(&home, real).unwrap();
    let file_cert = || local::load_identity(&home).unwrap().1.decode().unwrap();
    let first = file_cert();
    assert!(!cert_renew::renew_due(
        first.not_before,
        first.not_after,
        real
    ));

    // The clock jumps 345 days ahead: the 400 day certificate looks due (55 days left).
    let ahead = real + 345 * DAY;
    assert!(cert_renew::renew_due(
        first.not_before,
        first.not_after,
        ahead
    ));
    local::cert_renew(&home, ahead).unwrap();

    // The clock is right again: the only certificate on disk starts in about 344 days.
    let stale = file_cert();
    assert_eq!(stale.serial, 2);
    assert!(!stale.is_valid_at(real));
    assert!(
        cert_renew::renew_due(stale.not_before, stale.not_after, real),
        "the only certificate on disk is not valid now and nothing renews it"
    );
    let report = local::cert_show(&home).unwrap().render(real);
    assert!(
        report.contains("NOT YET VALID: it starts in 344 days"),
        "{report}"
    );
    assert!(report.contains("due for renewal"), "{report}");

    // The renewal is valid now, and is not due again.
    local::cert_renew(&home, real).unwrap();
    let fixed = file_cert();
    assert_eq!(fixed.serial, 3);
    assert!(fixed.is_valid_at(real));
    assert!(!cert_renew::renew_due(
        fixed.not_before,
        fixed.not_after,
        real
    ));
    let report = local::cert_show(&home).unwrap().render(real);
    assert!(!report.contains("NOT YET VALID"), "{report}");
}
