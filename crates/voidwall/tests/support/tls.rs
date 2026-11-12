//! A test CA and an HTTPS upstream for the upstream TLS tests.
//!
//! Included with `#[path = "support/tls.rs"] mod tls;`, so every test crate
//! that needs it compiles its own copy; a test uses part of it.
#![allow(dead_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// The host every test upstream listens on and its certificates name.
pub const HOST: &str = "127.0.0.1";

/// A CA that signs server certificates for the test upstreams.
pub struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    /// The CA certificate, PEM-encoded.
    pub pem: String,
}

impl TestCa {
    pub fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();
        Self {
            issuer: Issuer::new(params, key),
            pem,
        }
    }

    /// Write the CA certificate to `dir` and return its path.
    pub fn write_pem(&self, dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, &self.pem).unwrap();
        path
    }

    /// A server config whose certificate this CA signs for `name`, offering
    /// `alpn` in its order of preference.
    pub fn server_config(&self, name: &str, alpn: &[&[u8]]) -> ServerConfig {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .signed_by(&key, &self.issuer)
            .unwrap();
        let chain = vec![CertificateDer::from(cert.der().to_vec())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        config
    }
}

/// ALPN offering HTTP/2 first, then HTTP/1.1.
pub const H2_AND_H1: &[&[u8]] = &[b"h2", b"http/1.1"];
/// ALPN offering HTTP/1.1 only.
pub const H1_ONLY: &[&[u8]] = &[b"http/1.1"];

/// What a test upstream answers.
#[derive(Clone, Copy)]
pub enum Reply {
    /// `text/plain` naming the request's HTTP version, such as `HTTP/2.0`.
    Version,
    /// A `text/event-stream` Chat Completions stream whose one delta is the
    /// text given, then `[DONE]`.
    ChatStream(&'static str),
}

/// Start an HTTPS upstream on `HOST` with `config`. It speaks the protocol
/// that ALPN selected: HTTP/2 for `h2`, else HTTP/1.1.
pub async fn https_upstream(config: ServerConfig, reply: Reply) -> SocketAddr {
    let listener = TcpListener::bind((HOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                // A client that rejects the certificate ends the handshake.
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                let io = TokioIo::new(tls);
                let service = service_fn(move |req| answer(req, reply));
                if h2 {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                }
            });
        }
    });
    addr
}

/// Start a plain HTTP/1.1 upstream on `HOST`, without TLS.
pub async fn http_upstream(reply: Reply) -> SocketAddr {
    let listener = TcpListener::bind((HOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let service = service_fn(move |req| answer(req, reply));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service)
                    .await;
            });
        }
    });
    addr
}

async fn answer(req: Request<Incoming>, reply: Reply) -> Result<Response<Full<Bytes>>, Infallible> {
    let version = format!("{:?}", req.version());
    let _ = req.into_body().collect().await;
    let (content_type, body) = match reply {
        Reply::Version => ("text/plain", version),
        Reply::ChatStream(text) => ("text/event-stream", chat_stream(text)),
    };
    Ok(Response::builder()
        .header("content-type", content_type)
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

fn chat_stream(text: &str) -> String {
    let chunk = serde_json::json!({
        "id": "chatcmpl-1",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "test-model",
        "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": null}],
    });
    format!("data: {chunk}\n\ndata: [DONE]\n\n")
}
