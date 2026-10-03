//! The L5 OPEN/OPEN_ACK exchange (`src/open.rs`, TODO.md L4g) run over a
//! real connected `yamux::Stream` pair, not the hand-built byte buffers
//! `src/open.rs`'s own unit tests use — the same reason
//! `tests/live_connection.rs` exists alongside `src/record_io.rs`'s unit
//! tests: this is what actually matters end to end. `connected_pair`
//! duplicates `tests/live_connection.rs`'s own helper of the same name
//! rather than sharing it, matching that file's existing choice not to
//! factor a common `tests/` module out for one small helper.

use futures_util::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use menzil_proto::{
    ErrorCode, NetworkId, NodeId, OpenAckBody, OpenBody, OpenMeta, OpenTarget, ServiceId,
    ServiceKind,
};
use menzil_stream::{
    Authorizer, Inbound, Mode, OpenDecision, OpenRefusal, OpenRequest, OutboundFrames, Responded,
    ServiceHandler, Stream, StreamMux, initiate_open, respond_to_open,
};
use std::future::Future;
use std::pin::Pin;

async fn pump(mut from: OutboundFrames, to: StreamMux) {
    while let Some(frame) = from.next_frame().await {
        if to.feed_inbound(frame).is_err() {
            return;
        }
    }
}

fn connected_pair(max_record: u32) -> (StreamMux, Inbound, StreamMux, Inbound) {
    let (mux_a, inbound_a, outbound_a, driver_a) = menzil_stream::new(Mode::Client, max_record);
    let (mux_b, inbound_b, outbound_b, driver_b) = menzil_stream::new(Mode::Server, max_record);

    tokio::spawn(driver_a);
    tokio::spawn(driver_b);
    tokio::spawn(pump(outbound_a, mux_b.clone()));
    tokio::spawn(pump(outbound_b, mux_a.clone()));

    (mux_a, inbound_a, mux_b, inbound_b)
}

struct Allow;
impl Authorizer for Allow {
    fn authorize(&self, _request: &OpenRequest) -> OpenDecision {
        OpenDecision::Allow
    }
}

struct Deny(OpenRefusal);
impl Authorizer for Deny {
    fn authorize(&self, _request: &OpenRequest) -> OpenDecision {
        OpenDecision::Deny(self.0.clone())
    }
}

/// Accepts everything, and on [`ServiceHandler::handle`] echoes
/// everything the stream sends back to it (so the test can confirm the
/// accepted stream still works as an ordinary byte pipe after the OPEN
/// header), while also reporting the exact [`OpenRequest`] it was handed
/// through `seen_tx`.
struct EchoHandler {
    seen_tx: std::sync::Mutex<Option<futures_channel::oneshot::Sender<OpenRequest>>>,
}

impl EchoHandler {
    fn new() -> (Self, futures_channel::oneshot::Receiver<OpenRequest>) {
        let (tx, rx) = futures_channel::oneshot::channel();
        (
            Self {
                seen_tx: std::sync::Mutex::new(Some(tx)),
            },
            rx,
        )
    }
}

impl ServiceHandler<Stream> for EchoHandler {
    type Handling = Pin<Box<dyn Future<Output = ()> + Send>>;

    fn accepts(&self, _request: &OpenRequest) -> Result<(), OpenRefusal> {
        Ok(())
    }

    fn handle(&self, mut stream: Stream, request: OpenRequest) -> Self::Handling {
        if let Some(tx) = self.seen_tx.lock().unwrap().take() {
            let _ = tx.send(request);
        }
        Box::pin(async move {
            let mut buf = Vec::new();
            if stream.read_to_end(&mut buf).await.is_ok() {
                let _ = stream.write_all(&buf).await;
                let _ = stream.close().await;
            }
        })
    }
}

struct DecliningHandler(OpenRefusal);
impl ServiceHandler<Stream> for DecliningHandler {
    type Handling = std::future::Ready<()>;

    fn accepts(&self, _request: &OpenRequest) -> Result<(), OpenRefusal> {
        Err(self.0.clone())
    }

    fn handle(&self, _stream: Stream, _request: OpenRequest) -> Self::Handling {
        panic!("accepts() refused this request; handle() must never run")
    }
}

#[tokio::test]
async fn an_allowed_open_is_acked_and_the_accepted_stream_still_works_as_a_byte_pipe() {
    let (mux_a, _inbound_a, _mux_b, mut inbound_b) = connected_pair(65_535);
    let (handler, seen_rx) = EchoHandler::new();
    let network_id = NetworkId::from([5u8; 32]);
    let initiator = NodeId::from([6u8; 32]);

    let mut stream_a = mux_a.open().await.unwrap();
    let open = OpenBody {
        v: menzil_proto::PROTOCOL_VERSION,
        service: ServiceId::new(ServiceKind::Egress, "*"),
        target: Some(OpenTarget {
            host: "example.com".to_string(),
            port: 443,
        }),
        meta: OpenMeta {
            client_ip: Some("203.0.113.5".to_string()),
            sni: Some("example.com".to_string()),
        },
    };

    let responder = tokio::spawn(async move {
        let stream_b = inbound_b.accept().await.unwrap();
        respond_to_open(stream_b, network_id, initiator, &Allow, &handler).await
    });

    let ack = initiate_open(&mut stream_a, &open).await.unwrap();
    assert!(ack.ok);

    let request = seen_rx.await.unwrap();
    assert_eq!(request.network_id, network_id);
    assert_eq!(request.initiator, initiator);
    assert_eq!(request.service, open.service);
    assert_eq!(request.target, open.target);
    assert_eq!(request.meta, open.meta);

    let responded = responder.await.unwrap().unwrap();
    let Responded::Accepted(handling) = responded else {
        panic!("Allow + EchoHandler::accepts == Ok must be Accepted");
    };
    tokio::spawn(handling);

    stream_a.write_all(b"hello").await.unwrap();
    stream_a.close().await.unwrap();
    let mut echoed = Vec::new();
    stream_a.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"hello");
}

#[tokio::test]
async fn an_authorizer_denial_is_acked_as_refused_before_the_handler_ever_sees_it() {
    let (mux_a, _inbound_a, _mux_b, mut inbound_b) = connected_pair(65_535);
    let (handler, seen_rx) = EchoHandler::new();
    let refusal = OpenRefusal {
        code: ErrorCode::NoGrant,
        msg: "no grant for this service".to_string(),
    };
    let authorizer = Deny(refusal.clone());

    let mut stream_a = mux_a.open().await.unwrap();
    let open = OpenBody {
        v: menzil_proto::PROTOCOL_VERSION,
        service: ServiceId::new(ServiceKind::Tcp, "ssh"),
        target: None,
        meta: OpenMeta::default(),
    };

    let responder = tokio::spawn(async move {
        let stream_b = inbound_b.accept().await.unwrap();
        respond_to_open(
            stream_b,
            NetworkId::from([1u8; 32]),
            NodeId::from([2u8; 32]),
            &authorizer,
            &handler,
        )
        .await
    });

    let ack = initiate_open(&mut stream_a, &open).await.unwrap();
    assert!(!ack.ok);
    assert_eq!(ack.code, refusal.code);
    assert_eq!(ack.msg, refusal.msg);

    match responder.await.unwrap().unwrap() {
        Responded::Refused(r) => {
            assert_eq!(r.code, refusal.code);
            assert_eq!(r.msg, refusal.msg);
        }
        Responded::Accepted(_) => panic!("a denied request must never be Accepted"),
    }
    assert!(
        seen_rx.await.is_err(),
        "the handler must never have been asked to handle a denied OPEN"
    );
}

/// Never actually takes a stream: for tests where both gates refuse, so
/// only the type, not the behavior, of a `ServiceHandler` matters.
struct NeverHandles;
impl<S> ServiceHandler<S> for NeverHandles {
    type Handling = std::future::Ready<()>;

    fn accepts(&self, _request: &OpenRequest) -> Result<(), OpenRefusal> {
        Ok(())
    }

    fn handle(&self, _stream: S, _request: OpenRequest) -> Self::Handling {
        panic!("every test using this handler refuses before handle() could run")
    }
}

/// A server-speaks-first service (SSH-like): writes a banner the moment
/// it owns the stream, then echoes back the first 5 bytes it reads.
struct BannerThenEcho;
impl ServiceHandler<Stream> for BannerThenEcho {
    type Handling = Pin<Box<dyn Future<Output = ()> + Send>>;

    fn accepts(&self, _request: &OpenRequest) -> Result<(), OpenRefusal> {
        Ok(())
    }

    fn handle(&self, mut stream: Stream, _request: OpenRequest) -> Self::Handling {
        Box::pin(async move {
            let _ = stream.write_all(b"BANNER").await;
            let mut first = [0u8; 5];
            if stream.read_exact(&mut first).await.is_ok() {
                let _ = stream.write_all(&first).await;
            }
            let _ = stream.close().await;
        })
    }
}

#[tokio::test]
async fn bytes_pipelined_behind_either_header_reach_the_other_side_intact() {
    // Neither side waits its turn here: the initiator sends application
    // bytes in the same write as its OPEN header (the way a relay
    // forwarding an HTTP request might), and the handler writes its banner
    // the instant it owns the stream. Each header read must stop exactly
    // at its own header's end, or these bytes vanish into it.
    let (mux_a, _inbound_a, _mux_b, mut inbound_b) = connected_pair(65_535);
    tokio::spawn(async move {
        let stream_b = inbound_b.accept().await.unwrap();
        let responded = respond_to_open(
            stream_b,
            NetworkId::from([1u8; 32]),
            NodeId::from([2u8; 32]),
            &Allow,
            &BannerThenEcho,
        )
        .await
        .unwrap();
        if let Responded::Accepted(handling) = responded {
            handling.await;
        }
    });

    let mut stream_a = mux_a.open().await.unwrap();
    let open = OpenBody {
        v: menzil_proto::PROTOCOL_VERSION,
        service: ServiceId::new(ServiceKind::Tcp, "ssh"),
        target: None,
        meta: OpenMeta::default(),
    };
    let mut pipelined = open.encode().unwrap();
    pipelined.extend_from_slice(b"early");
    stream_a.write_all(&pipelined).await.unwrap();

    // Read the OPEN_ACK by hand (initiate_open would write a second OPEN).
    let mut len = [0u8; 2];
    stream_a.read_exact(&mut len).await.unwrap();
    let mut ack = len.to_vec();
    ack.resize(2 + usize::from(u16::from_be_bytes(len)), 0);
    stream_a.read_exact(&mut ack[2..]).await.unwrap();
    assert!(OpenAckBody::decode(&ack).unwrap().ok);

    let mut rest = Vec::new();
    stream_a.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, b"BANNERearly");
}

#[tokio::test]
async fn a_server_speaks_first_banner_stays_unread_behind_initiate_opens_ack() {
    let (mux_a, _inbound_a, _mux_b, mut inbound_b) = connected_pair(65_535);
    tokio::spawn(async move {
        let stream_b = inbound_b.accept().await.unwrap();
        let responded = respond_to_open(
            stream_b,
            NetworkId::from([1u8; 32]),
            NodeId::from([2u8; 32]),
            &Allow,
            &BannerThenEcho,
        )
        .await
        .unwrap();
        if let Responded::Accepted(handling) = responded {
            handling.await;
        }
    });

    let mut stream_a = mux_a.open().await.unwrap();
    let open = OpenBody {
        v: menzil_proto::PROTOCOL_VERSION,
        service: ServiceId::new(ServiceKind::Tcp, "ssh"),
        target: None,
        meta: OpenMeta::default(),
    };
    assert!(initiate_open(&mut stream_a, &open).await.unwrap().ok);
    let mut banner = [0u8; 6];
    stream_a.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"BANNER");
    stream_a.write_all(b"hello").await.unwrap();
    let mut echoed = Vec::new();
    stream_a.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"hello");
}

#[tokio::test]
async fn a_refusal_through_a_buffering_writer_still_reaches_the_initiator() {
    // `respond_to_open` is generic over any stream on purpose (decision
    // 0001); one that buffers writes until flushed used to lose the
    // refusal with the dropped stream, the initiator seeing only EOF.
    let (mux_a, _inbound_a, _mux_b, mut inbound_b) = connected_pair(65_535);
    let refusal = OpenRefusal {
        code: ErrorCode::NoGrant,
        msg: "no grant for this service".to_string(),
    };
    let authorizer = Deny(refusal.clone());
    let responder = tokio::spawn(async move {
        let stream_b = inbound_b.accept().await.unwrap();
        respond_to_open(
            BufWriter::new(stream_b),
            NetworkId::from([1u8; 32]),
            NodeId::from([2u8; 32]),
            &authorizer,
            &NeverHandles,
        )
        .await
    });

    let mut stream_a = mux_a.open().await.unwrap();
    let open = OpenBody {
        v: menzil_proto::PROTOCOL_VERSION,
        service: ServiceId::new(ServiceKind::Tcp, "ssh"),
        target: None,
        meta: OpenMeta::default(),
    };
    let ack = initiate_open(&mut stream_a, &open).await.unwrap();
    assert!(!ack.ok);
    assert_eq!(ack.code, refusal.code);
    assert!(matches!(
        responder.await.unwrap().unwrap(),
        Responded::Refused(_)
    ));
}

#[tokio::test]
async fn a_handler_decline_after_authorization_is_acked_as_refused() {
    let (mux_a, _inbound_a, _mux_b, mut inbound_b) = connected_pair(65_535);
    let refusal = OpenRefusal {
        code: ErrorCode::Forbidden,
        msg: "no local target configured for this service".to_string(),
    };
    let handler = DecliningHandler(refusal.clone());

    let mut stream_a = mux_a.open().await.unwrap();
    let open = OpenBody {
        v: menzil_proto::PROTOCOL_VERSION,
        service: ServiceId::new(ServiceKind::Http, "app"),
        target: None,
        meta: OpenMeta::default(),
    };

    let responder = tokio::spawn(async move {
        let stream_b = inbound_b.accept().await.unwrap();
        respond_to_open(
            stream_b,
            NetworkId::from([3u8; 32]),
            NodeId::from([4u8; 32]),
            &Allow,
            &handler,
        )
        .await
    });

    let ack = initiate_open(&mut stream_a, &open).await.unwrap();
    assert!(!ack.ok);
    assert_eq!(ack.code, refusal.code);
    assert_eq!(ack.msg, refusal.msg);

    match responder.await.unwrap().unwrap() {
        Responded::Refused(r) => {
            assert_eq!(r.code, refusal.code);
            assert_eq!(r.msg, refusal.msg);
        }
        Responded::Accepted(_) => panic!("a declined request must never be Accepted"),
    }
}
