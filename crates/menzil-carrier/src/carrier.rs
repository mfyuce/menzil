//! The dial abstraction (protocol.md 3): composes proxy resolution,
//! CONNECT, TLS, and the WebSocket upgrade into one established
//! binary-message transport, plus a backoff-driven retry helper for the
//! initial dial.
//!
//! Staying connected long-term, noticing a drop, and redialing with
//! [`Backoff::note_connection_uptime`] is the job of whoever owns the
//! session (the L3 layer, not built yet); this crate stops at one
//! established connection and its byte-level send/receive.

use std::collections::HashMap;
use std::future::Future;

use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use crate::backoff::Backoff;
use crate::connection_info::ConnectionInfo;
use crate::error::CarrierError;
use crate::proxy::{self, ProxyOverride, ProxyResolution};
use crate::{connect, socket_tuning, tls, websocket};

/// The Noise message size limit (protocol.md 3.3): one WebSocket binary
/// message is one L3 record, at most this many bytes.
pub const MAX_MESSAGE_BYTES: usize = 65_535;

/// Configuration for one dial; cheap to clone and reuse across reconnects.
#[derive(Debug, Clone)]
pub struct DialConfig {
    /// The relay to reach.
    pub connection_info: ConnectionInfo,
    /// An explicit proxy decision, bypassing environment discovery.
    /// `None` resolves from the environment (protocol.md 3.1 step 1).
    pub proxy_override: Option<ProxyOverride>,
}

/// An established carrier connection: binary-message send/receive over
/// WebSocket-on-TLS, plus the subprotocol strings the L3 Noise prologue
/// needs (protocol.md 4.1).
pub struct Carrier {
    ws: WebSocketStream<TlsStream<TcpStream>>,
    /// What we offered: always [`websocket::SUBPROTOCOL`].
    pub offered_subprotocol: String,
    /// What the relay selected.
    pub selected_subprotocol: Option<String>,
}

impl Carrier {
    /// Resolves the proxy, opens the TCP connection (direct or via
    /// CONNECT), establishes TLS, and performs the WebSocket upgrade.
    pub async fn dial(
        config: &DialConfig,
        env: &HashMap<String, String>,
    ) -> Result<Self, CarrierError> {
        let info = &config.connection_info;
        let resolution = proxy::resolve(&info.host, env, config.proxy_override.as_ref())
            .map_err(CarrierError::ConnectionInfo)?;

        let tcp = match &resolution {
            ProxyResolution::Direct => connect::dial_tcp(None, &info.host, info.port).await?,
            ProxyResolution::Via(target) => {
                connect::dial_tcp(
                    Some((&target.host, target.port, target.credentials.as_ref())),
                    &info.host,
                    info.port,
                )
                .await?
            }
        };
        socket_tuning::apply(&tcp);

        let client_config = tls::client_config()?;
        let connector = TlsConnector::from(client_config);
        let server_name = ServerName::try_from(info.host.clone())
            .map_err(|e| CarrierError::TlsSetup(e.to_string()))?;
        let tls_stream = connector.connect(server_name, tcp).await?;

        let (ws, outcome) = websocket::upgrade(tls_stream, &info.host, &info.path).await?;

        Ok(Self {
            ws,
            offered_subprotocol: outcome.offered_subprotocol,
            selected_subprotocol: outcome.selected_subprotocol,
        })
    }

    /// Sends one binary L3 record (protocol.md 3.3: "one message is one
    /// L3 record"). Errors if `payload` exceeds [`MAX_MESSAGE_BYTES`]
    /// without sending anything.
    pub async fn send(&mut self, payload: Vec<u8>) -> Result<(), CarrierError> {
        if payload.len() > MAX_MESSAGE_BYTES {
            return Err(CarrierError::PayloadTooLarge {
                len: payload.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }
        self.ws.send(Message::Binary(payload.into())).await?;
        Ok(())
    }

    /// Receives the next binary L3 record, transparently skipping
    /// WebSocket-level ping/pong control frames (liveness is measured at
    /// L3, not with these, per protocol.md 3.3). Errors on a text message
    /// (protocol.md 3.3: "binary messages only") or a closed connection.
    pub async fn recv(&mut self) -> Result<Vec<u8>, CarrierError> {
        loop {
            let msg = self.ws.next().await.ok_or(CarrierError::Closed)??;
            match msg {
                Message::Binary(bytes) => return Ok(bytes.to_vec()),
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(_) => return Err(CarrierError::Closed),
                Message::Text(_) => return Err(CarrierError::UnexpectedMessageType),
                Message::Frame(_) => return Err(CarrierError::UnexpectedMessageType),
            }
        }
    }
}

/// Retries `dial_fn` with [`Backoff`]'s schedule until it succeeds. This
/// covers only the initial dial; a caller that stays connected and wants
/// to redial after a drop tracks its own [`Backoff`] (feeding it uptime
/// via [`Backoff::note_connection_uptime`]) rather than calling this in a
/// loop, so it doesn't lose the schedule's state across attempts.
/// Callers that need cancellation should race this future with their own
/// signal (e.g. `tokio::select!`).
pub async fn dial_with_backoff<F, Fut>(mut dial_fn: F) -> Carrier
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Carrier, CarrierError>>,
{
    let mut backoff = Backoff::new();
    loop {
        match dial_fn().await {
            Ok(carrier) => return carrier,
            Err(err) => {
                let delay = backoff.next_delay();
                tracing::warn!(error = %err, delay_ms = delay.as_millis(), "carrier dial failed, retrying");
                tokio::time::sleep(delay).await;
            }
        }
    }
}
