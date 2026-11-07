//! Node side ACME TLS-ALPN-01 through the relay (protocol.md 6.2, expose design S-E8).
//!
//! A node that holds a blind share (`tls:<label>`, or `tcp:`) terminates TLS for the share's name
//! itself, so it also obtains and renews that name's certificate itself. The CA's validation
//! connection reaches the relay's front door like any client, with ALPN `acme-tls/1` and the
//! share name as SNI, and the relay (which routes it only to a node whose share lists
//! `acme-tls/1`) opens a blind `tls:` stream with the bytes, ClientHello included. The generic
//! pieces (ChallengeBook, the RFC 8555 client, the certificate store, the renewal loop, the
//! answer to a ClientHello) are in `menzil-acme` and re-exported here; this module is the node's
//! half:
//!
//! * [`AcmeHandler`]: wraps [`LocalServices`] and, for a relay stream whose SNI has a pending
//!   order, reads the ClientHello (16 KiB, 5 s) and answers it with the challenge certificate
//!   if, and only if, its ALPN list is exactly `acme-tls/1` and its SNI is the pending name. A
//!   stream without a pending order is not read at all; any other stream with one is handed to
//!   the local target with the bytes already read written first. Every failure on the way
//!   (garbage, a slow client, no certificate for the name) is a closed stream, never a
//!   certificate.
//! * [`wanted`]: whether a share is one the node asks a CA for (accepted, blind, `acme-tls/1`).
//!
//! * [`spawn_renewals`] (module `supervisor`): the renewal tasks. They are started and stopped
//!   from the relay's ADVERTISE_ACK, which names the share domain `H` and the full names it
//!   accepted, so the operator keeps no second setting; `menzil node` starts them when
//!   config.toml has an `[acme]` table (protocol.md 11, 12).
//!
//! What this module does not do: hand the issued certificate to the service behind the share. It
//! is written to `<home>/acme/certs/<domain>/{fullchain,privkey}.pem` and the service reads it
//! from there; the node signals nobody and runs no command (protocol.md 12).

use std::pin::Pin;

use menzil_proto::ServiceKind;
use menzil_stream::{OpenRefusal, OpenRequest, ServiceHandler, Stream};

pub use menzil_acme::{
    AccountKey, AcmeClient, AcmeJob, AcmeTransport, CertStore, FailureKind, HttpRequest,
    HttpResponse, HttpsTransport, Issued, Method, Progress, Timing, renewal_time,
};
pub use menzil_acme::{
    AcmeError, ChallengeBook, MAX_PENDING, PENDING_TTL, PendingOrder, check_domain, client, http,
    renew,
};
use menzil_acme::{Served, answer_or_pass};

mod supervisor;

pub use supervisor::{
    AcmeSetup, AcmeStatus, CertState, DomainMismatch, MAX_JOBS, Plan, candidate_jobs, plan,
    spawn_renewals,
};

use crate::serve::{LocalServices, OpenedTarget, TokioStream};
pub use crate::shares::ACME_ALPN;
use crate::shares::{ShareBook, lists_acme_alpn};

/// Whether `share` is one the relay accepted in this attachment and lists `acme-tls/1`: the only
/// state in which the node asks a CA for anything or answers a validation.
pub fn wanted(shares: &ShareBook, share: &str) -> bool {
    shares
        .accepted()
        .iter()
        .any(|accepted| accepted.name == share && lists_acme_alpn(accepted))
}

/// Keeps a certificate for `job.domain` fresh (see [`menzil_acme::run_renewals`]) for as long as
/// the share is [`wanted`].
pub async fn run_renewals<T: AcmeTransport>(
    client: AcmeClient<T>,
    store: CertStore,
    shares: ShareBook,
    book: ChallengeBook,
    job: AcmeJob,
) {
    let share = job.share.clone();
    menzil_acme::run_renewals(client, store, move || wanted(&shares, &share), book, job).await
}

/// [`LocalServices`] that also answers TLS-ALPN-01 validation connections for the names of a
/// [`ChallengeBook`]. See the module docs; hand it to the node in place of the plain
/// [`LocalServices`].
///
/// Only the relay principal sets `meta.sni` (the node scrubs it from every member's OPEN), so a
/// member can never reach the responder; without a pending order for the stream's SNI the stream
/// is not read.
#[derive(Debug, Clone)]
pub struct AcmeHandler {
    services: LocalServices,
    book: ChallengeBook,
}

impl AcmeHandler {
    /// `services` with the validation answers of `book`.
    pub fn new(services: LocalServices, book: ChallengeBook) -> Self {
        Self { services, book }
    }
}

impl ServiceHandler<Stream> for AcmeHandler {
    type Opened = OpenedTarget;
    type Handling = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

    async fn open(&self, request: &OpenRequest) -> Result<OpenedTarget, OpenRefusal> {
        self.services.open(request).await
    }

    async fn open_with_own_limits(
        &self,
        request: &OpenRequest,
    ) -> Result<OpenedTarget, OpenRefusal> {
        self.services.open_with_own_limits(request).await
    }

    fn handle(&self, stream: Stream, request: OpenRequest, opened: OpenedTarget) -> Self::Handling {
        let sni = request
            .meta
            .sni
            .as_deref()
            .map(str::to_ascii_lowercase)
            .filter(|_| matches!(request.service.kind, ServiceKind::Tls | ServiceKind::Tcp))
            .filter(|sni| self.book.is_pending(sni));
        let Some(sni) = sni else {
            return self
                .services
                .handle_with_prefix(stream, request, opened, Vec::new());
        };
        let services = self.services.clone();
        let book = self.book.clone();
        Box::pin(async move {
            let mut remote = TokioStream(stream);
            match answer_or_pass(&mut remote, &sni, &book).await {
                Served::Answered => {
                    // The connection the open made is of no use for a validation; dropping it
                    // resets it.
                    drop(opened);
                }
                Served::PassOn(read) => {
                    services
                        .handle_with_prefix(remote.0, request, opened, read)
                        .await;
                }
                // A slow or broken stream: nothing was served, nothing is passed on.
                Served::Failed => remote.0.reset(),
            }
        })
    }
}

#[cfg(test)]
mod supervisor_tests;
#[cfg(test)]
mod tests;
