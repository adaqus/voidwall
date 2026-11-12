//! The reverse proxy in front of an HTTPS upstream: one test per scenario of
//! the `The proxy originates TLS to an https upstream` requirement that runs
//! in process. The system-root scenarios set `SSL_CERT_FILE`, so they spawn the
//! binary and live in `startup_integration.rs`.
//!
//! Every upstream is a local server whose certificate a fresh test CA signs.
//! That CA is in no system store, so a route reaches it only through its
//! `upstream_ca_path`.
//!
//! `voidwall_errors_total` carries no route label, so every test that asserts
//! it holds [`METRICS`] and the change it asserts is exact.

#[path = "support/tls.rs"]
mod tls;

use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use voidwall::config::AppConfig;
use voidwall::engine::Engine;
use voidwall::metrics::ERRORS_TOTAL;
use voidwall::reverse_proxy::{self, UpstreamClients};
use voidwall_ml::fixtures::runtime;

use tls::{H1_ONLY, H2_AND_H1, HOST, Reply, TestCa};

static METRICS: Mutex<()> = Mutex::const_new(());

/// A running reverse proxy. Dropping it stops the proxy.
struct Proxy {
    addr: SocketAddr,
    cancel: CancellationToken,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl Proxy {
    /// Start the proxy with one route, `/`, to `upstream`, with the PII guard
    /// on. `route` holds more lines of the route table.
    async fn start(upstream: &str, route: &str) -> Self {
        let toml = format!(
            "[builtin_guards.pii]\nscanner_threads = 1\n\n\
             [reverse_proxy]\nenabled = true\n\n\
             [[reverse_proxy.routes]]\npath_prefix = \"/\"\nupstream = \"{upstream}\"\n{route}\n"
        );
        let config: AppConfig = toml::from_str(&toml).unwrap();
        config.validate().unwrap();

        let engine = Arc::new(Engine::from_config(runtime(), &config).unwrap());
        let clients = UpstreamClients::build(&config).unwrap();
        let listener = TcpListener::bind((HOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let serve_cancel = cancel.clone();
        tokio::spawn(async move {
            reverse_proxy::serve_on(listener, &config, engine, clients, serve_cancel)
                .await
                .unwrap();
        });
        Proxy { addr, cancel }
    }

    async fn get(&self, path: &str) -> (u16, String) {
        let resp = reqwest::get(format!("http://{}{path}", self.addr))
            .await
            .unwrap();
        (resp.status().as_u16(), resp.text().await.unwrap())
    }

    async fn post_json(&self, path: &str, body: serde_json::Value) -> (u16, String) {
        let resp = reqwest::Client::new()
            .post(format!("http://{}{path}", self.addr))
            .json(&body)
            .send()
            .await
            .unwrap();
        (resp.status().as_u16(), resp.text().await.unwrap())
    }
}

fn upstream_errors() -> u64 {
    ERRORS_TOTAL
        .with_label_values(&["blocked", "upstream_error"])
        .get()
}

/// A route line naming `ca` as its bundle.
fn bundle(ca: &std::path::Path) -> String {
    format!("upstream_ca_path = {:?}", ca.display().to_string())
}

#[tokio::test]
async fn the_upstream_certificate_chains_to_the_route_bundle() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let pem = ca.write_pem(dir.path(), "ca.pem");
    let upstream = tls::https_upstream(ca.server_config(HOST, H2_AND_H1), Reply::Version).await;

    let proxy = Proxy::start(&format!("https://{upstream}"), &bundle(&pem)).await;
    let (status, body) = proxy.get("/version").await;

    assert_eq!(status, 200, "got: {body}");
    assert!(body.starts_with("HTTP/"), "the upstream answered: {body}");
}

#[tokio::test]
async fn the_upstream_certificate_chains_to_no_trusted_ca() {
    let _metrics = METRICS.lock().await;
    let ca = TestCa::new();
    let upstream = tls::https_upstream(ca.server_config(HOST, H2_AND_H1), Reply::Version).await;

    let proxy = Proxy::start(&format!("https://{upstream}"), "").await;
    let before = upstream_errors();
    let (status, body) = proxy.get("/version").await;

    assert_eq!(status, 502);
    assert_eq!(body, r#"{"error":"upstream error"}"#);
    assert_eq!(upstream_errors(), before + 1);
}

#[tokio::test]
async fn the_upstream_certificate_names_another_host() {
    let _metrics = METRICS.lock().await;
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let pem = ca.write_pem(dir.path(), "ca.pem");
    let upstream = tls::https_upstream(
        ca.server_config("other.example.com", H2_AND_H1),
        Reply::Version,
    )
    .await;

    let proxy = Proxy::start(&format!("https://{upstream}"), &bundle(&pem)).await;
    let before = upstream_errors();
    let (status, body) = proxy.get("/version").await;

    assert_eq!(status, 502);
    assert_eq!(body, r#"{"error":"upstream error"}"#);
    assert_eq!(upstream_errors(), before + 1);
}

#[tokio::test]
async fn the_upstream_selects_http2() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let pem = ca.write_pem(dir.path(), "ca.pem");
    let upstream = tls::https_upstream(ca.server_config(HOST, H2_AND_H1), Reply::Version).await;

    let proxy = Proxy::start(&format!("https://{upstream}"), &bundle(&pem)).await;

    assert_eq!(proxy.get("/version").await, (200, "HTTP/2.0".to_string()));
}

#[tokio::test]
async fn the_upstream_selects_http1() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let pem = ca.write_pem(dir.path(), "ca.pem");
    let upstream = tls::https_upstream(ca.server_config(HOST, H1_ONLY), Reply::Version).await;

    let proxy = Proxy::start(&format!("https://{upstream}"), &bundle(&pem)).await;

    assert_eq!(proxy.get("/version").await, (200, "HTTP/1.1".to_string()));
}

#[tokio::test]
async fn a_plain_http_upstream_gets_http1() {
    let upstream = tls::http_upstream(Reply::Version).await;

    let proxy = Proxy::start(&format!("http://{upstream}"), "").await;

    assert_eq!(proxy.get("/version").await, (200, "HTTP/1.1".to_string()));
}

/// An `openai-chat` route scans a stream that arrives over HTTP/2 as it scans
/// one over HTTP/1.1: a clean stream passes, one with an e-mail is blocked.
#[tokio::test]
async fn an_openai_chat_stream_over_http2_is_scanned() {
    const PLACEHOLDER: &str = "jane.doe@example.com";

    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let pem = ca.write_pem(dir.path(), "ca.pem");
    let request = json!({
        "model": "test-model",
        "messages": [{"role": "user", "content": "Say hello."}],
        "stream": true,
    });
    let route = format!("{}\nformat = \"openai-chat\"", bundle(&pem));

    let clean = tls::https_upstream(
        ca.server_config(HOST, H2_AND_H1),
        Reply::ChatStream("Hello there."),
    )
    .await;
    let proxy = Proxy::start(&format!("https://{clean}"), &route).await;
    let (status, body) = proxy
        .post_json("/v1/chat/completions", request.clone())
        .await;
    assert_eq!(status, 200, "got: {body}");
    assert!(body.contains("Hello there."), "got: {body}");
    assert!(body.contains("data: [DONE]"), "got: {body}");

    let leaking = tls::https_upstream(
        ca.server_config(HOST, H2_AND_H1),
        Reply::ChatStream("Write to jane.doe@example.com today."),
    )
    .await;
    let proxy = Proxy::start(&format!("https://{leaking}"), &route).await;
    let (status, body) = proxy.post_json("/v1/chat/completions", request).await;
    assert_eq!(status, 400, "got: {body}");
    assert!(body.contains("content_filter"), "got: {body}");
    assert!(body.contains("EMAIL"), "got: {body}");
    assert!(
        !body.contains(PLACEHOLDER),
        "the value never reaches the client"
    );
}
