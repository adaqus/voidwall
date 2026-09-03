//! Integration tests for Phase 7.6 structured-body scanning.
//!
//! Spins up an echo upstream and a real reverse-proxy listener configured
//! with redact-on-request actions, then exercises the structured-scanning
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
    Action, AppConfig, DirectionConfig, OnError, PiiConfig, RedactStrategy, ReverseProxyConfig,
    Route, ScanConfig,
};
use voidwall::reverse_proxy;
use voidwall::scanner::ScannerPool;

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

static SHARED_SCANNER: LazyLock<Arc<ScannerPool>> =
    LazyLock::new(|| Arc::new(ScannerPool::new(&pii_config()).unwrap()));

fn redact_request() -> DirectionConfig {
    DirectionConfig {
        actions: vec![Action::Redact],
        redact_strategy: Some(RedactStrategy::TypeLabel),
        mask_char: None,
        block_status: 403,
        block_body: None,
        block_headers: vec![],
    }
}

fn empty_direction() -> DirectionConfig {
    DirectionConfig {
        actions: vec![],
        redact_strategy: None,
        mask_char: None,
        block_status: 403,
        block_body: None,
        block_headers: vec![],
    }
}

struct TestProxy {
    addr: SocketAddr,
    cancel: CancellationToken,
    _scanner: Arc<ScannerPool>,
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
                response: empty_direction(),
                routes: vec![Route {
                    path_prefix: "/".into(),
                    upstream: format!("http://{upstream}"),
                    scan: None,
                    specialization: None,
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
        let scanner = SHARED_SCANNER.clone();
        let scanner_clone = scanner.clone();

        tokio::spawn(async move {
            reverse_proxy::serve(&config, scanner_clone, cancel_clone)
                .await
                .unwrap();
        });

        wait_for_port(proxy_addr).await;
        TestProxy {
            addr: proxy_addr,
            cancel,
            _scanner: scanner,
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

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

/// Nested JSON: PII in a deeply-nested string value is detected via the
/// flattened key path and redacted in-place. The redacted body must remain
/// valid JSON so downstream consumers can still parse it.
#[tokio::test]
async fn nested_json_body_pii_detected_and_redacted() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(upstream, ScanConfig::default(), redact_request()).await;

    let payload =
        r#"{"user":{"contact":{"phone_number":"555-123-4567","email":"jane@example.com"}}}"#;
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    assert!(!body.contains("555-123-4567"), "phone leaked: {body}");
    assert!(!body.contains("jane@example.com"), "email leaked: {body}");
    assert!(body.contains("[US_PHONE_NUMBER]"));
    assert!(body.contains("[EMAIL]"));

    // Surviving JSON structure: must still parse.
    let v: serde_json::Value = serde_json::from_str(&body).expect("redacted body is valid JSON");
    assert_eq!(v["user"]["contact"]["phone_number"], "[US_PHONE_NUMBER]");
    assert_eq!(v["user"]["contact"]["email"], "[EMAIL]");
}

/// JSON path where the PII keyword sits at the **head** of the path
/// (`phone_number.primary`). The structured detector iterates prefixes
/// from full → first segment, so this resolves on iteration 2 after
/// dropping the trailing `primary` segment.
#[tokio::test]
async fn json_keyword_at_head_of_path() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(upstream, ScanConfig::default(), redact_request()).await;

    let payload = r#"{"phone_number":{"primary":"555-123-4567","secondary":"555-987-6543"}}"#;
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    assert!(
        !body.contains("555-123-4567"),
        "primary phone leaked: {body}"
    );
    assert!(
        !body.contains("555-987-6543"),
        "secondary phone leaked: {body}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["phone_number"]["primary"], "[US_PHONE_NUMBER]");
    assert_eq!(v["phone_number"]["secondary"], "[US_PHONE_NUMBER]");
}

/// JSON path where the keyword sits in the **middle**
/// (`user.phone_number.value`). Resolves on iteration 2 after `value` is
/// dropped, exposing `phone_number` adjacent to the synthesized `:`.
#[tokio::test]
async fn json_keyword_in_middle_of_path() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(upstream, ScanConfig::default(), redact_request()).await;

    let payload = r#"{"user":{"phone_number":{"value":"555-123-4567","verified":true}}}"#;
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    assert!(!body.contains("555-123-4567"), "phone leaked: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["user"]["phone_number"]["value"], "[US_PHONE_NUMBER]");
    // `verified` is non-PII boolean — must pass through unchanged.
    assert_eq!(v["user"]["phone_number"]["verified"], true);
}

/// JSON keyword at the head **inside an array element**: array indices in
/// the path (e.g. `phone_numbers[0].primary`) are stripped before keyword
/// matching, so the keyword still resolves.
#[tokio::test]
async fn json_keyword_at_head_inside_array() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(upstream, ScanConfig::default(), redact_request()).await;

    let payload = r#"{"phone_number":[{"primary":"555-123-4567"},{"primary":"555-987-6543"}]}"#;
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    assert!(!body.contains("555-123-4567"), "phone leaked: {body}");
    assert!(!body.contains("555-987-6543"), "phone leaked: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["phone_number"][0]["primary"], "[US_PHONE_NUMBER]");
    assert_eq!(v["phone_number"][1]["primary"], "[US_PHONE_NUMBER]");
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
    let proxy = TestProxy::start(upstream, scan, redact_request()).await;

    // Trailing garbage makes this not parse as JSON, but the email is still
    // present as plain text and should be redacted by the fallback path.
    let payload = r#"{"email":"jane@example.com" not closed properly"#;
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    assert!(!body.contains("jane@example.com"), "email leaked: {body}");
    assert!(body.contains("[EMAIL]"));
}

/// Same malformed body but `on_error = fail_close`: the proxy refuses to
/// forward the request and returns a 502 (scanner-error mapping).
#[tokio::test]
async fn json_parse_failure_fail_close_blocks_request() {
    let upstream = start_echo_upstream().await;
    let scan = ScanConfig {
        on_error: OnError::FailClose,
        ..ScanConfig::default()
    };
    let proxy = TestProxy::start(upstream, scan, redact_request()).await;

    let payload = r#"{not json"#;
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_server_error() || resp.status().is_client_error(),
        "expected error status on parse failure with fail_close, got {}",
        resp.status()
    );
    assert_ne!(resp.status(), 200);
}

// ---------------------------------------------------------------------------
// CSV / TSV
// ---------------------------------------------------------------------------

/// CSV with a header row: the column name supplies keyword context for cell
/// values, so a phone in the `phone_number` column is detected and redacted.
/// The header row and delimiter structure must survive intact.
#[tokio::test]
async fn csv_body_with_headers_redacts_via_column_context() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(upstream, ScanConfig::default(), redact_request()).await;

    let payload = "name,phone_number\nAda,555-123-4567\nBob,555-987-6543";
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "text/csv")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    assert!(!body.contains("555-123-4567"), "phone leaked: {body}");
    assert!(!body.contains("555-987-6543"), "phone leaked: {body}");
    assert!(body.contains("[US_PHONE_NUMBER]"));
    // Header row preserved verbatim, delimiter structure intact, names unchanged.
    assert!(body.starts_with("name,phone_number\n"));
    assert!(body.contains("\nAda,"));
    assert!(body.contains("\nBob,"));
}

/// TSV with a header row: tab delimiter, otherwise identical to CSV behavior.
#[tokio::test]
async fn tsv_body_with_headers_redacts_via_column_context() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(upstream, ScanConfig::default(), redact_request()).await;

    let payload = "name\tphone_number\nAda\t555-123-4567";
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "text/tab-separated-values")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    assert!(!body.contains("555-123-4567"), "phone leaked: {body}");
    assert!(body.contains("[US_PHONE_NUMBER]"));
    assert!(body.starts_with("name\tphone_number\n"));
    assert!(body.contains("\nAda\t"));
}

/// CSV whose first row is all numeric: header detection fails, body falls
/// back to flat-text scanning. PII patterns that don't depend on a column
/// keyword (e.g. SSN-shaped strings) are still detected.
#[tokio::test]
async fn csv_without_headers_falls_back_to_plain_text() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(upstream, ScanConfig::default(), redact_request()).await;

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
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    assert!(!body.contains("123-45-6789"), "SSN leaked: {body}");
    assert!(body.contains("[US_SSN]"));
}
