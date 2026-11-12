//! Content coding on the reverse proxy: the `Accept-Encoding` the upstream
//! receives, and the answer to a compressed upstream body.

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use test_case::test_case;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use voidwall::config::{AppConfig, BuiltinGuards, PiiGuardConfig};
use voidwall::engine::Engine;
use voidwall::reverse_proxy;

/// Serialises every test: the metric families are shared by the binary.
static METRICS: Mutex<()> = Mutex::const_new(());

static ENGINE: LazyLock<Arc<Engine>> = LazyLock::new(|| {
    let pii = PiiGuardConfig {
        scanner_threads: Some(1),
        ..PiiGuardConfig::default()
    };
    Arc::new(Engine::new(&BuiltinGuards::with_pii(pii)).unwrap())
});

/// Stands in for a compressed body: the gzip magic, then bytes that are not
/// JSON. The proxy never decompresses, so what follows the magic is moot.
const COMPRESSED: &[u8] = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03compressed";

/// A clean JSON body.
const CLEAN_JSON: &str = r#"{"status":"clean"}"#;

const CHAT: &str = "/v1/chat/completions";

// ---------------------------------------------------------------------------
// Upstream
// ---------------------------------------------------------------------------

/// An upstream whose answer is named by a segment of the request path, so a
/// route's upstream URL can pick it on both formats.
async fn start_upstream() -> SocketAddr {
    let app = Router::new().fallback(answer);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    wait_for_port(addr).await;
    addr
}

async fn answer(req: Request) -> Response {
    let path = req.uri().path().to_string();
    let kind = path
        .split('/')
        .find(|segment| {
            [
                "accept-encoding",
                "gzip-json",
                "br-json",
                "identity-json",
                "gzip-png",
                "gzip-204",
                "gzip-sse",
            ]
            .contains(segment)
        })
        .unwrap_or_default();
    match kind {
        // The `Accept-Encoding` values the upstream received, in order.
        "accept-encoding" => {
            let values: Vec<&str> = req
                .headers()
                .get_all("accept-encoding")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect();
            (
                [("content-type", "application/json")],
                json!({ "accept_encoding": values }).to_string(),
            )
                .into_response()
        }
        "gzip-json" => compressed("application/json", "gzip"),
        "br-json" => compressed("application/json", "br"),
        "gzip-png" => compressed("image/png", "gzip"),
        "gzip-sse" => compressed("text/event-stream", "gzip"),
        "identity-json" => (
            [
                ("content-type", "application/json"),
                ("content-encoding", "identity"),
            ],
            CLEAN_JSON,
        )
            .into_response(),
        "gzip-204" => (StatusCode::NO_CONTENT, [("content-encoding", "gzip")]).into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

fn compressed(content_type: &'static str, coding: &'static str) -> Response {
    (
        [("content-type", content_type), ("content-encoding", coding)],
        COMPRESSED,
    )
        .into_response()
}

async fn wait_for_port(addr: SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("server did not start on {addr}");
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

/// The route a test sends its request through.
#[derive(Clone, Copy)]
enum Via {
    /// A route without `format`.
    Generic,
    /// A route with `format = "openai-chat"`.
    OpenAiChat,
    /// A route without `format` and with `guards = []`.
    OptedOut,
    /// A route with `format = "openai-chat"` and `guards = []`.
    OptedOutChat,
}

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
    /// A proxy whose three routes all reach `upstream`; `answer` is the path
    /// segment that picks the upstream's answer on the `openai-chat` route.
    async fn start(
        upstream: SocketAddr,
        on_error: &str,
        response_scan: bool,
        answer: &str,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let toml = format!(
            "on_error = \"{on_error}\"\n\
             [builtin_guards.pii]\nscanner_threads = 1\n\
             [reverse_proxy]\nenabled = true\nlisten = \"{addr}\"\n\
             [reverse_proxy.response]\nscan = {response_scan}\n\
             [[reverse_proxy.routes]]\npath_prefix = \"/\"\nupstream = \"http://{upstream}\"\n\
             [[reverse_proxy.routes]]\npath_prefix = \"/opted-out/\"\nupstream = \"http://{upstream}\"\nguards = []\n\
             [[reverse_proxy.routes]]\npath_prefix = \"{CHAT}\"\nupstream = \"http://{upstream}/{answer}\"\nformat = \"openai-chat\"\n\
             [[reverse_proxy.routes]]\npath_prefix = \"/opted-out{CHAT}\"\nupstream = \"http://{upstream}/{answer}\"\nformat = \"openai-chat\"\nguards = []\n"
        );
        let config: AppConfig = toml::from_str(&toml).unwrap();
        config.validate().unwrap();

        let cancel = CancellationToken::new();
        let serve_cancel = cancel.clone();
        let engine = ENGINE.clone();
        tokio::spawn(async move {
            reverse_proxy::serve(&config, engine, serve_cancel)
                .await
                .unwrap();
        });
        wait_for_port(addr).await;
        Proxy { addr, cancel }
    }

    /// Sends one request through `via` for the upstream answer `answer`, with
    /// `accept_encoding` when it is set.
    async fn send(
        &self,
        via: Via,
        answer: &str,
        accept_encoding: Option<&str>,
    ) -> reqwest::Response {
        let client = reqwest::Client::new();
        let request = match via {
            Via::Generic => client.get(format!("http://{}/{answer}", self.addr)),
            Via::OptedOut => client.get(format!("http://{}/opted-out/{answer}", self.addr)),
            Via::OpenAiChat | Via::OptedOutChat => client
                .post(match via {
                    Via::OptedOutChat => format!("http://{}/opted-out{CHAT}", self.addr),
                    _ => format!("http://{}{CHAT}", self.addr),
                })
                .header("content-type", "application/json")
                .body(
                    json!({"model": "m", "messages": [{"role": "user", "content": "Hello"}]})
                        .to_string(),
                ),
        };
        let request = match accept_encoding {
            Some(value) => request.header("accept-encoding", value),
            None => request,
        };
        request.send().await.unwrap()
    }
}

/// The current `voidwall_errors_total` count for one outcome and reason.
fn errors_total(outcome: &str, reason: &str) -> u64 {
    prometheus::default_registry()
        .gather()
        .iter()
        .find(|m| m.get_name() == "voidwall_errors_total")
        .map(|family| {
            family
                .get_metric()
                .iter()
                .filter(|m| {
                    let labels = m.get_label();
                    labels
                        .iter()
                        .any(|l| l.get_name() == "outcome" && l.get_value() == outcome)
                        && labels
                            .iter()
                            .any(|l| l.get_name() == "reason" && l.get_value() == reason)
                })
                .map(|m| m.get_counter().get_value() as u64)
                .sum()
        })
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Accept-Encoding on the forwarded request
// ---------------------------------------------------------------------------

#[test_case(true, Via::Generic, Some("gzip, deflate, br"), &["identity"] ; "scan on replaces the client's value")]
#[test_case(true, Via::Generic, None, &["identity"] ; "scan on adds the header")]
#[test_case(true, Via::OpenAiChat, Some("gzip"), &["identity"] ; "an openai-chat route")]
#[test_case(true, Via::OptedOut, Some("gzip"), &["identity"] ; "a route that selects no guard")]
#[test_case(false, Via::Generic, Some("gzip"), &["gzip"] ; "scan off keeps the client's value")]
#[test_case(false, Via::Generic, None, &[] ; "scan off adds nothing")]
#[tokio::test]
async fn the_upstream_receives_the_accept_encoding_response_scan_allows(
    response_scan: bool,
    via: Via,
    sent: Option<&str>,
    expected: &[&str],
) {
    let _guard = METRICS.lock().await;
    let upstream = start_upstream().await;
    let proxy = Proxy::start(upstream, "fail_close", response_scan, "accept-encoding").await;

    let resp = proxy.send(via, "accept-encoding", sent).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["accept_encoding"], json!(expected));
}

// ---------------------------------------------------------------------------
// A compressed response body is unscannable content
// ---------------------------------------------------------------------------

#[tokio::test]
async fn compressed_json_on_a_generic_route_answers_422_under_fail_close() {
    let _guard = METRICS.lock().await;
    let upstream = start_upstream().await;
    let proxy = Proxy::start(upstream, "fail_close", true, "gzip-json").await;
    let before = errors_total("blocked", "unscannable_content");

    let resp = proxy.send(Via::Generic, "gzip-json", None).await;

    assert_eq!(resp.status(), 422);
    assert_eq!(
        resp.text().await.unwrap(),
        r#"{"error":"unscannable content"}"#
    );
    assert_eq!(errors_total("blocked", "unscannable_content"), before + 1);
}

#[tokio::test]
async fn compressed_json_on_a_generic_route_passes_unscanned_under_fail_open() {
    let _guard = METRICS.lock().await;
    let upstream = start_upstream().await;
    let proxy = Proxy::start(upstream, "fail_open", true, "gzip-json").await;
    let before = errors_total("passed", "unscannable_content");

    let resp = proxy.send(Via::Generic, "gzip-json", None).await;

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "application/json");
    assert_eq!(resp.headers()["content-encoding"], "gzip");
    assert_eq!(&resp.bytes().await.unwrap()[..], COMPRESSED);
    assert_eq!(errors_total("passed", "unscannable_content"), before + 1);
}

#[tokio::test]
async fn compressed_json_on_an_openai_chat_route_answers_422_under_fail_close() {
    let _guard = METRICS.lock().await;
    let upstream = start_upstream().await;
    let proxy = Proxy::start(upstream, "fail_close", true, "br-json").await;
    let before = errors_total("blocked", "unscannable_content");

    let resp = proxy.send(Via::OpenAiChat, "br-json", None).await;

    assert_eq!(resp.status(), 422);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "unscannable_content");
    assert_eq!(errors_total("blocked", "unscannable_content"), before + 1);
}

#[tokio::test]
async fn compressed_json_on_an_openai_chat_route_passes_unscanned_under_fail_open() {
    let _guard = METRICS.lock().await;
    let upstream = start_upstream().await;
    let proxy = Proxy::start(upstream, "fail_open", true, "br-json").await;
    let before = errors_total("passed", "unscannable_content");

    let resp = proxy.send(Via::OpenAiChat, "br-json", None).await;

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-encoding"], "br");
    assert_eq!(&resp.bytes().await.unwrap()[..], COMPRESSED);
    assert_eq!(errors_total("passed", "unscannable_content"), before + 1);
}

/// A body the route does not scan, or that is not compressed, or that does
/// not exist, is forwarded under `fail_close`, and counts no unscannable
/// content.
#[test_case(Via::Generic, "identity-json", 200, CLEAN_JSON.as_bytes() ; "identity is not compressed")]
#[test_case(Via::OptedOut, "gzip-json", 200, COMPRESSED ; "a route that selects no guard")]
#[test_case(Via::OptedOutChat, "gzip-json", 200, COMPRESSED ; "an openai-chat route that selects no guard")]
#[test_case(Via::OptedOutChat, "gzip-sse", 200, COMPRESSED ; "a stream on an openai-chat route that selects no guard")]
#[test_case(Via::Generic, "gzip-png", 200, COMPRESSED ; "a type not in content_types")]
#[test_case(Via::Generic, "gzip-204", 204, b"" ; "a response without a body")]
#[tokio::test]
async fn a_body_the_route_does_not_need_to_decompress_is_forwarded(
    via: Via,
    answer: &str,
    status: u16,
    body: &[u8],
) {
    let _guard = METRICS.lock().await;
    let upstream = start_upstream().await;
    let proxy = Proxy::start(upstream, "fail_close", true, answer).await;
    let before = (
        errors_total("blocked", "unscannable_content"),
        errors_total("passed", "unscannable_content"),
    );

    let resp = proxy.send(via, answer, None).await;

    assert_eq!(resp.status(), status);
    assert_eq!(&resp.bytes().await.unwrap()[..], body);
    let after = (
        errors_total("blocked", "unscannable_content"),
        errors_total("passed", "unscannable_content"),
    );
    assert_eq!(after, before, "no unscannable_content sample");
}
