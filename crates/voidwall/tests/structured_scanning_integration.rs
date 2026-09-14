//! Integration tests for Phase 7.6 structured-body scanning.
//!
//! Spins up an echo upstream and a real reverse-proxy listener configured
//! with request scanning on, then exercises the structured-scanning
//! paths for JSON, CSV, and TSV bodies. Also covers the `on_error` policy
//! when the body fails to parse, and the CSV-without-headers fallback.

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::any;
use http_body_util::BodyExt;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use voidwall::config::{
    AppConfig, DirectionConfig, OnError, PiiConfig, ReverseProxyConfig,
    Route, ScanConfig,
};
use voidwall::engine::Engine;
use voidwall::reverse_proxy;

// ---------------------------------------------------------------------------
// Echo upstream
// ---------------------------------------------------------------------------

async fn start_echo_upstream() -> SocketAddr {
    let app = Router::new().route("/{*rest}", any(echo_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    wait_for_port(addr).await;
    addr
}

async fn echo_handler(req: Request) -> impl IntoResponse {
    let ct = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("text/plain")
        .to_string();
    let body = req.into_body().collect().await.unwrap().to_bytes();
    (StatusCode::OK, [("content-type", ct)], body)
}

async fn wait_for_port(addr: SocketAddr) {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("server did not start on {addr}");
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

fn pii_config() -> PiiConfig {
    PiiConfig {
        countries: vec![],
        languages: vec![],
        scanner_threads: Some(1),
        detect: None,
        ignore: None,
        custom: Vec::new(),
    }
}

static SHARED_ENGINE: LazyLock<Arc<Engine>> =
    LazyLock::new(|| Arc::new(Engine::new(&pii_config()).unwrap()));

fn scan_on() -> DirectionConfig {
    DirectionConfig { scan: true }
}

fn scan_off() -> DirectionConfig {
    DirectionConfig { scan: false }
}

struct TestProxy {
    addr: SocketAddr,
    cancel: CancellationToken,
    _engine: Arc<Engine>,
}

impl TestProxy {
    async fn start(upstream: SocketAddr, scan: ScanConfig, request: DirectionConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        drop(listener);

        let config = AppConfig {
            pii: pii_config(),
            scan,
            reverse_proxy: ReverseProxyConfig {
                enabled: true,
                listen: proxy_addr.to_string(),
                request,
                response: scan_off(),
                routes: vec![Route {
                    path_prefix: "/".into(),
                    upstream: format!("http://{upstream}"),
                    scan: None,
                }],
                ..Default::default()
            },
            forward_proxy: Default::default(),
            http_api: Default::default(),
            admin: Default::default(),
            shutdown_timeout_secs: 30,
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let engine = SHARED_ENGINE.clone();
        let engine_clone = engine.clone();

        tokio::spawn(async move {
            reverse_proxy::serve(&config, engine_clone, cancel_clone)
                .await
                .unwrap();
        });

        wait_for_port(proxy_addr).await;
        TestProxy {
            addr: proxy_addr,
            cancel,
            _engine: engine,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

impl Drop for TestProxy {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// A blocked response: 403, the expected kinds named in the body, and none of
/// the matched values echoed back.
fn assert_blocked(body: &str, expect_kinds: &[&str], never: &[&str]) {
    let json: serde_json::Value =
        serde_json::from_str(body).unwrap_or_else(|e| panic!("block body is JSON: {e}, got {body}"));
    let kinds: Vec<&str> = json["kinds"]
        .as_array()
        .expect("kinds array")
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    for kind in expect_kinds {
        assert!(kinds.contains(kind), "expected {kind} in kinds, got {kinds:?}");
    }
    for value in never {
        assert!(!body.contains(value), "matched value leaked: {body}");
    }
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

/// Nested JSON: PII in a deeply-nested string value is detected via the
/// flattened key path. This is the only coverage that a nested JSON key path
/// reaches the scanner as context, so the input matters more than the outcome.
#[tokio::test]
async fn nested_json_body_pii_detected_and_blocked() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(upstream, ScanConfig::default(), scan_on()).await;

    let payload =
        r#"{"user":{"contact":{"phone_number":"555-123-4567","email":"jane@example.com"}}}"#;
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();

    // Both values sit in deeply-nested string fields and are found only
    // because the flattened key path reaches the scanner as context.
    assert_blocked(
        &body,
        &["US_PHONE_NUMBER", "EMAIL"],
        &["555-123-4567", "jane@example.com"],
    );
}

/// JSON path where the PII keyword sits at the **head** of the path
/// (`phone_number.primary`). The structured detector iterates prefixes
/// from full → first segment, so this resolves on iteration 2 after
/// dropping the trailing `primary` segment.
#[tokio::test]
async fn json_keyword_at_head_of_path() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(upstream, ScanConfig::default(), scan_on()).await;

    let payload = r#"{"phone_number":{"primary":"555-123-4567","secondary":"555-987-6543"}}"#;
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();

    assert_blocked(
        &body,
        &["US_PHONE_NUMBER"],
        &["555-123-4567", "555-987-6543"],
    );
}

/// JSON path where the keyword sits in the **middle**
/// (`user.phone_number.value`). Resolves on iteration 2 after `value` is
/// dropped, exposing `phone_number` adjacent to the synthesized `:`.
#[tokio::test]
async fn json_keyword_in_middle_of_path() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(upstream, ScanConfig::default(), scan_on()).await;

    let payload = r#"{"user":{"phone_number":{"value":"555-123-4567","verified":true}}}"#;
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();

    assert_blocked(&body, &["US_PHONE_NUMBER"], &["555-123-4567"]);
}

/// JSON keyword at the head **inside an array element**: array indices in
/// the path (e.g. `phone_numbers[0].primary`) are stripped before keyword
/// matching, so the keyword still resolves.
#[tokio::test]
async fn json_keyword_at_head_inside_array() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(upstream, ScanConfig::default(), scan_on()).await;

    let payload = r#"{"phone_number":[{"primary":"555-123-4567"},{"primary":"555-987-6543"}]}"#;
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();

    assert_blocked(
        &body,
        &["US_PHONE_NUMBER"],
        &["555-123-4567", "555-987-6543"],
    );
}

/// Malformed JSON with `on_error = fail_open`: the proxy degrades to plain-
/// text scanning rather than failing the request. PII inside the malformed
/// text is still detected via flat scanning.
#[tokio::test]
async fn json_parse_failure_fail_open_falls_back_to_plain_text() {
    let upstream = start_echo_upstream().await;
    let scan = ScanConfig {
        on_error: OnError::FailOpen,
        ..ScanConfig::default()
    };
    let proxy = TestProxy::start(upstream, scan, scan_on()).await;

    // Trailing garbage makes this not parse as JSON, but the email is still
    // present as plain text and should be found by the fallback path.
    let payload = r#"{"email":"jane@example.com" not closed properly"#;
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();

    // The body did not parse as JSON, so it was scanned as flat text. The
    // email is still found, which is what fail_open promises.
    assert_blocked(&body, &["EMAIL"], &["jane@example.com"]);
}

/// Same malformed body but `on_error = fail_close`: the proxy refuses to
/// forward the request and answers 400. The client declared the content type
/// and sent bytes that do not match it, so the fault is the client's.
#[tokio::test]
async fn json_parse_failure_fail_close_blocks_request() {
    let upstream = start_echo_upstream().await;
    let scan = ScanConfig {
        on_error: OnError::FailClose,
        ..ScanConfig::default()
    };
    let proxy = TestProxy::start(upstream, scan, scan_on()).await;

    let payload = r#"{not json"#;
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "expected 400 on parse failure with fail_close, got {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// CSV / TSV
// ---------------------------------------------------------------------------

/// CSV with a header row: the column name supplies keyword context for cell
/// values, so a phone in the `phone_number` column is detected on it alone.
/// The header row and delimiter structure must survive intact.
#[tokio::test]
async fn csv_body_with_headers_detected_via_column_context() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(upstream, ScanConfig::default(), scan_on()).await;

    let payload = "name,phone_number\nAda,555-123-4567\nBob,555-987-6543";
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "text/csv")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();

    // Neither cell carries a keyword; the `phone_number` column header is the
    // only context that makes them detectable.
    assert_blocked(
        &body,
        &["US_PHONE_NUMBER"],
        &["555-123-4567", "555-987-6543"],
    );
}

/// TSV with a header row: tab delimiter, otherwise identical to CSV behavior.
#[tokio::test]
async fn tsv_body_with_headers_detected_via_column_context() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(upstream, ScanConfig::default(), scan_on()).await;

    let payload = "name\tphone_number\nAda\t555-123-4567";
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "text/tab-separated-values")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();

    assert_blocked(&body, &["US_PHONE_NUMBER"], &["555-123-4567"]);
}

/// CSV whose first row is all numeric: header detection fails, body falls
/// back to flat-text scanning. PII patterns that don't depend on a column
/// keyword (e.g. SSN-shaped strings) are still detected.
#[tokio::test]
async fn csv_without_headers_falls_back_to_plain_text() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(upstream, ScanConfig::default(), scan_on()).await;

    // First row is purely numeric → no headers, plain-text fallback.
    // The body contains an SSN-shaped value detected via pattern alone.
    let payload = "1,2\n3,4\nSSN: 123-45-6789";
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "text/csv")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();

    // No header row, so the body is scanned as flat text and the SSN is found
    // on its own shape rather than on column context.
    assert_blocked(&body, &["US_SSN"], &["123-45-6789"]);
}
