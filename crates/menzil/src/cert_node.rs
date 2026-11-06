//! The running node's side of certificate rotation (cert-rotation design Q9): renewing its own
//! certificate, on request (`menzil cert renew` through the agent socket) and by itself (a check
//! at start and every six hours), and saying where the networks stand.
//!
//! The rules are in [`crate::cert_renew`]; this is the I/O around them. A renewal reads the
//! secret keys from `identity.key` only for the moment of signing, writes `identity.cert`
//! atomically (the key file is never rewritten), switches the node to the new certificate at once
//! ([`Node::renew_identity`]) and has it offered to the peers of the live sessions
//! ([`Node::announce_renewed_cert`]); sessions that come up later offer it by themselves.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use menzil_node::{Node, PolicyStore};
use menzil_proto::NetworkId;

use crate::agent::{CertStatus, RenewedCert, UnlistedCert};
use crate::cert_renew::{self, CHECK_EVERY_SECS};
use crate::home::Home;
use crate::local::load_identity;
use crate::token::encode_cert_request;

/// Renews the certificate of a running node.
pub struct CertRenewer {
    home: Home,
    node: Arc<Node>,
    policies: Arc<PolicyStore>,
    /// One renewal at a time: the agent's request and the timer both come through here, so two
    /// of them cannot both read the same serial and write the same next one.
    busy: tokio::sync::Mutex<()>,
}

/// What the periodic check remembers: when each network was last warned about.
#[derive(Debug, Default)]
pub struct CheckState {
    last_warning: HashMap<NetworkId, u64>,
}

/// What one periodic check did.
#[derive(Debug, Default)]
pub struct Checked {
    /// A renewal that was due: the new serial, or why it failed.
    pub renewal: Option<Result<u32, String>>,
    /// The networks warned about this time, with the days the listed certificate has left.
    pub warnings: Vec<(NetworkId, u64)>,
}

impl CertRenewer {
    /// A renewer for `node`, which holds `policies`, on `home`.
    pub fn new(home: Home, node: Arc<Node>, policies: Arc<PolicyStore>) -> Self {
        Self {
            home,
            node,
            policies,
            busy: tokio::sync::Mutex::new(()),
        }
    }

    /// The highest serial of this node that any Policy the node holds lists.
    fn listed_max(&self, me: &menzil_proto::NodeId) -> Option<u32> {
        let networks = self.home.networks().unwrap_or_default();
        let bodies: Vec<_> = networks
            .iter()
            .filter_map(|network| self.policies.body(network))
            .collect();
        cert_renew::listed_max_serial(bodies.iter().map(|body| &**body), me)
    }

    /// Renews the certificate at `now`: the same keys, a serial above the one in use, the file's
    /// and every serial a held Policy lists, `not_before` a day ago, 400 days. The file is
    /// written before the node switches, so a crash in between leaves a file that is ahead of
    /// the node, never behind it (the next start uses the new certificate).
    pub async fn renew(&self, now: u64) -> Result<RenewedCert, String> {
        let _one_at_a_time = self.busy.lock().await;
        let current = self.node.own_cert();
        let me = current.decode().map_err(|e| e.to_string())?.node_id;
        let listed_max = self.listed_max(&me);
        let home = self.home.clone();
        let next = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            let (keys, in_file) = load_identity(&home)?;
            let floor = listed_max.max(Some(in_file.decode()?.serial));
            let next = keys.next_cert(&current, floor, now)?;
            home.write_public(&home.identity_cert_path(), &next.encode())?;
            Ok(next)
        })
        .await
        .map_err(|e| format!("the renewal task failed: {e}"))?
        .map_err(|e| format!("{e:#}"))?;
        self.node
            .renew_identity(next.clone())
            .map_err(|e| format!("the node did not take the new certificate: {e}"))?;
        self.node.announce_renewed_cert();
        let body = next.decode().map_err(|e| e.to_string())?;
        Ok(RenewedCert {
            serial: body.serial,
            not_after: body.not_after,
            token: encode_cert_request(&next),
        })
    }

    /// The certificate in use and the networks that do not list it yet.
    pub fn status(&self, now: u64) -> Option<CertStatus> {
        let own = self.node.own_cert().decode().ok()?;
        let mut unlisted = Vec::new();
        for network in self.home.networks().unwrap_or_default() {
            let Some(policy) = self.policies.body(&network) else {
                continue;
            };
            let listed = cert_renew::listed_cert(&policy, &own.node_id);
            if let Some(days) = cert_renew::unlisted_days(listed, own.serial, now) {
                unlisted.push(UnlistedCert { network, days });
            }
        }
        Some(CertStatus {
            serial: own.serial,
            not_after: own.not_after,
            unlisted,
        })
    }

    /// The check every [`CHECK_EVERY_SECS`]: renews when the certificate expires within 60 days
    /// or does not start yet, offers the certificate again to the peers of the live sessions
    /// while a network does not list it, and warns (once a day per network) about a network
    /// whose listed certificate of this node expires within 30 days without the current one being
    /// listed.
    pub async fn check(&self, state: &mut CheckState, now: u64) -> Checked {
        let mut checked = Checked::default();
        let Ok(own) = self.node.own_cert().decode() else {
            return checked;
        };
        if cert_renew::renew_due(own.not_before, own.not_after, now) {
            checked.renewal = Some(self.renew(now).await.map(|renewed| renewed.serial));
        }
        let Some(status) = self.status(now) else {
            return checked;
        };
        // Round C M1: a network that does not list the current certificate gets it offered
        // again over the sessions that are live now, every check. Nothing else does: a renewal
        // is announced once, and a Policy that stopped listing it, a steward that dropped its
        // candidates or a push no steward answered would leave it unlisted until the next
        // session, which may be after the listed certificate ran out. (Not after a renewal made
        // just now, which announced itself.)
        if !status.unlisted.is_empty() && !matches!(checked.renewal, Some(Ok(_))) {
            self.node.announce_renewed_cert();
        }
        for network in self.home.networks().unwrap_or_default() {
            let Some(policy) = self.policies.body(&network) else {
                continue;
            };
            let listed = cert_renew::listed_cert(&policy, &own.node_id);
            let Some(days) = cert_renew::warn_due(listed, status.serial, now) else {
                state.last_warning.remove(&network);
                continue;
            };
            if crate::steward_loop::warn_due(state.last_warning.get(&network).copied(), now) {
                state.last_warning.insert(network, now);
                checked.warnings.push((network, days));
            }
        }
        checked
    }
}

/// The sentence for the log and the terminal when a network does not list the current
/// certificate yet and the one it lists runs out soon.
pub fn warning_text(network: &NetworkId, days: u64) -> String {
    format!(
        "network {network}: it lists an older certificate of this device, which runs out in {days} day(s); the owner or the steward has to list the current one (`menzil cert request` prints the token for the owner's `menzil cert accept`)"
    )
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The task: a check at start, then one every six hours.
pub async fn run(renewer: Arc<CertRenewer>) {
    let mut state = CheckState::default();
    loop {
        let checked = renewer.check(&mut state, unix_now()).await;
        match checked.renewal {
            Some(Ok(serial)) => {
                tracing::info!(serial, "renewed this device's certificate");
                eprintln!("menzil: renewed this device's certificate (serial {serial})");
            }
            Some(Err(error)) => {
                tracing::warn!(%error, "the certificate renewal failed; trying again in six hours");
                eprintln!("warning: the certificate renewal failed: {error}");
            }
            None => {}
        }
        for (network, days) in checked.warnings {
            let text = warning_text(&network, days);
            tracing::warn!(network = %network, "{text}");
            eprintln!("warning: {text}");
        }
        let every = cert_renew::test_knob("CHECK_EVERY").unwrap_or(CHECK_EVERY_SECS);
        tokio::time::sleep(Duration::from_secs(every.max(1))).await;
    }
}

#[cfg(test)]
mod tests;
