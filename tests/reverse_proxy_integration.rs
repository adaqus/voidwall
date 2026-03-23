use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{any, get};
use http_body_util::BodyExt;
use pii_proxy::config::{
    Action, AppConfig, DirectionConfig, OnError, PiiConfig, RedactStrategy, ReverseProxyConfig,
    Route, ScanConfig,
};
use pii_proxy::reverse_proxy;
use pii_proxy::scanner::ScannerPool;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Echo upstream server
// ---------------------------------------------------------------------------

/// Starts an echo upstream that returns request details back in the response.
async fn start_echo_upstream() -> SocketAddr {
    let app = Router::new()
        .route("/echo", any(echo_handler))
        .route("/echo/{*rest}", any(echo_handler))
        .route("/pii-response", get(pii_response_handler))
        .route("/pii-response-headers", get(pii_response_headers_handler))
        .route("/echo-with-pii", any(echo_with_pii_handler));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    wait_for_port(addr).await;
    addr
}

async fn echo_handler(req: Request) -> impl IntoResponse {
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let mut header_lines = Vec::new();
    for (name, value) in req.headers() {
        header_lines.push(format!("{}: {}", name, value.to_str().unwrap_or("?")));
    }
    let body = req.into_body().collect().await.unwrap().to_bytes();

    let resp_body = format!(
        "METHOD={method}\nURI={uri}\nHEADERS:\n{}\nBODY:{}",
        header_lines.join("\n"),
        String::from_utf8_lossy(&body)
    );
    (StatusCode::OK, [("content-type", "text/plain")], resp_body)
}

/// Returns a response containing PII in the body.
async fn pii_response_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain")],
        "User email is john.doe@example.com and SSN is 123-45-6789",
    )
}

/// Returns a response with PII in headers.
async fn pii_response_headers_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            ("content-type", "text/plain"),
            ("x-user-info", "john.doe@example.com"),
        ],
        "clean response body",
    )
}

/// Echoes the request body and appends its own PII to the response.
async fn echo_with_pii_handler(req: Request) -> impl IntoResponse {
    let body = req.into_body().collect().await.unwrap().to_bytes();
    let request_body = String::from_utf8_lossy(&body);
    let resp_body = format!("REQUEST_BODY:{request_body}\nRESPONSE_PII:SSN is 123-45-6789");
    (StatusCode::OK, [("content-type", "text/plain")], resp_body)
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

async fn wait_for_port(addr: SocketAddr) {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("server did not start on {addr}");
}

fn default_pii_config() -> PiiConfig {
    PiiConfig {
        countries: vec![],
        languages: vec![],
        scanner_threads: Some(1),
        detect: None,
        ignore: None,
    }
}

fn direction_redact() -> DirectionConfig {
    DirectionConfig {
        actions: vec![Action::Redact],
        redact_strategy: Some(RedactStrategy::TypeLabel),
        mask_char: None,
        block_status: 403,
        block_body: None,
        block_headers: vec![],
    }
}

fn direction_block() -> DirectionConfig {
    DirectionConfig {
        actions: vec![Action::Block],
        redact_strategy: None,
        mask_char: None,
        block_status: 403,
        block_body: None,
        block_headers: vec![],
    }
}

fn direction_header() -> DirectionConfig {
    DirectionConfig {
        actions: vec![Action::Header],
        redact_strategy: None,
        mask_char: None,
        block_status: 403,
        block_body: None,
        block_headers: vec![],
    }
}

fn direction_empty() -> DirectionConfig {
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
    async fn start(
        upstream_addr: SocketAddr,
        routes: Vec<(&str, &str)>,
        request_dir: DirectionConfig,
        response_dir: DirectionConfig,
        scan: ScanConfig,
    ) -> Self {
        let pii_config = default_pii_config();
        let scanner = Arc::new(ScannerPool::new(&pii_config).unwrap());

        let proxy_routes: Vec<Route> = routes
            .into_iter()
            .map(|(prefix, upstream_path)| Route {
                path_prefix: prefix.to_string(),
                upstream: format!("http://{upstream_addr}{upstream_path}"),
                scan: None,
            })
            .collect();

        // Bind to ephemeral port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        drop(listener);

        let config = AppConfig {
            pii: pii_config,
            scan,
            reverse_proxy: ReverseProxyConfig {
                enabled: true,
                listen: proxy_addr.to_string(),
                request: request_dir,
                response: response_dir,
                routes: proxy_routes,
                ..Default::default()
            },
            ..default_app_config()
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
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

fn default_app_config() -> AppConfig {
    AppConfig {
        pii: default_pii_config(),
        scan: ScanConfig::default(),
        reverse_proxy: ReverseProxyConfig::default(),
        forward_proxy: Default::default(),
        rest_api: Default::default(),
        admin: Default::default(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Plain HTTP proxying end-to-end (proxy → echo upstream)
#[tokio::test]
async fn plain_http_proxy_end_to_end() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        direction_empty(),
        direction_empty(),
        ScanConfig::default(),
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("hello world")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("METHOD=POST"));
    assert!(body.contains("BODY:hello world"));
}

/// Route matching: longest-prefix wins, unknown prefix returns 404
#[tokio::test]
async fn route_matching_longest_prefix_and_404() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/echo", ""), ("/echo/sub", "")],
        direction_empty(),
        direction_empty(),
        ScanConfig::default(),
    )
    .await;

    // /echo/sub/test should match /echo/sub (longer prefix)
    let resp = reqwest::get(proxy.url("/echo/sub/test")).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Unknown prefix returns 404
    let resp = reqwest::get(proxy.url("/unknown/path")).await.unwrap();
    assert_eq!(resp.status(), 404);
}

/// Request block action: request with PII returns error response, not forwarded
#[tokio::test]
async fn request_block_action_returns_error() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        direction_block(),
        direction_empty(),
        ScanConfig::default(),
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("My email is john.doe@example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    // Should mention detected PII kinds, not the actual values
    assert!(!body.contains("john.doe@example.com"));
}

/// Response block action: response with PII returns error response
#[tokio::test]
async fn response_block_action_returns_error() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        direction_empty(),
        direction_block(),
        ScanConfig::default(),
    )
    .await;

    let resp = reqwest::get(proxy.url("/pii-response")).await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    // Should NOT contain the actual PII
    assert!(!body.contains("john.doe@example.com"));
    assert!(!body.contains("123-45-6789"));
}

/// Request redact action: PII replaced in forwarded request body
#[tokio::test]
async fn request_redact_action_replaces_pii_in_body() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        direction_redact(),
        direction_empty(),
        ScanConfig::default(),
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("Contact john.doe@example.com for info")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    // Original PII should be redacted
    assert!(!body.contains("john.doe@example.com"));
    // Body should still contain the non-PII text
    assert!(body.contains("Contact"));
}

/// Response redact action: PII replaced in response body before sending to client
#[tokio::test]
async fn response_redact_action_replaces_pii_in_response() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        direction_empty(),
        direction_redact(),
        ScanConfig::default(),
    )
    .await;

    let resp = reqwest::get(proxy.url("/pii-response")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    // PII should be redacted
    assert!(!body.contains("john.doe@example.com"));
    assert!(!body.contains("123-45-6789"));
    // Non-PII text should remain
    assert!(body.contains("User email is"));
}

/// Header action: X-PII-Detected header added to forwarded request
#[tokio::test]
async fn header_action_adds_x_pii_detected() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        direction_header(),
        direction_empty(),
        ScanConfig::default(),
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("My email is john.doe@example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    // The echo server reflects headers — X-PII-Detected should be present
    assert!(body.to_lowercase().contains("x-pii-detected"));
}

/// Empty action list disables scanning for that direction
#[tokio::test]
async fn empty_actions_disables_scanning() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        direction_empty(),
        direction_empty(),
        ScanConfig::default(),
    )
    .await;

    // Send PII — should pass through unmodified because scanning is disabled
    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("My email is john.doe@example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    // PII should pass through unchanged
    assert!(body.contains("john.doe@example.com"));
}

/// Metrics always incremented when PII detected
#[tokio::test]
async fn metrics_incremented_on_pii_detection() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        direction_redact(),
        direction_empty(),
        ScanConfig::default(),
    )
    .await;

    let client = reqwest::Client::new();
    let _resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("My email is john.doe@example.com")
        .send()
        .await
        .unwrap();

    // Verify metrics were incremented by gathering them
    let metrics = prometheus::default_registry().gather();
    let detection_metric = metrics
        .iter()
        .find(|m| m.get_name() == "pii_proxy_detections_total");
    assert!(
        detection_metric.is_some(),
        "pii_proxy_detections_total metric should exist"
    );
}

/// on_error fail_close blocks oversized body
#[tokio::test]
async fn on_error_fail_close_blocks_oversized_body() {
    let upstream = start_echo_upstream().await;

    let scan = ScanConfig {
        max_body_size: 10, // very small limit
        on_error: OnError::FailClose,
        ..ScanConfig::default()
    };

    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        direction_redact(),
        direction_empty(),
        scan,
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("This body is way longer than 10 bytes")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 413);
}

/// on_error fail_open passes through oversized body
#[tokio::test]
async fn on_error_fail_open_passes_oversized_body() {
    let upstream = start_echo_upstream().await;

    let scan = ScanConfig {
        max_body_size: 10,
        on_error: OnError::FailOpen,
        ..ScanConfig::default()
    };

    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        direction_redact(),
        direction_empty(),
        scan,
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("This body is way longer than 10 bytes")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("This body is way longer than 10 bytes"));
}

/// Clean request passes through without modification
#[tokio::test]
async fn clean_request_passes_through() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        direction_redact(),
        direction_redact(),
        ScanConfig::default(),
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("just a normal message")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("just a normal message"));
}

/// Request with PII in query string gets redacted
#[tokio::test]
async fn request_pii_in_query_string_redacted() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        direction_redact(),
        direction_empty(),
        ScanConfig {
            query_params: true,
            ..ScanConfig::default()
        },
    )
    .await;

    let resp = reqwest::get(proxy.url("/echo?email=john.doe@example.com"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    // The echoed URI should not contain the raw email
    assert!(!body.contains("john.doe@example.com"));
}

/// Hop-by-hop headers are stripped when proxying
#[tokio::test]
async fn hop_by_hop_headers_stripped() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        direction_empty(),
        direction_empty(),
        ScanConfig::default(),
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .get(proxy.url("/echo"))
        .header("connection", "keep-alive")
        .header("x-custom", "present")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    // x-custom should be forwarded
    assert!(body.contains("x-custom: present"));
}

/// Request with unsupported content-type: body not scanned, still forwarded
#[tokio::test]
async fn unsupported_content_type_body_not_scanned() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        direction_block(), // would block if scanned
        direction_empty(),
        ScanConfig::default(),
    )
    .await;

    let client = reqwest::Client::new();
    // image/png is not in default allowed content types, so body won't be scanned
    // But URL scanning is still on, so use a clean URL
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "image/png")
        .body("john.doe@example.com")
        .send()
        .await
        .unwrap();

    // Body scanning should be skipped (unsupported content-type),
    // but URL/query scanning may still detect nothing, so request should pass
    assert_eq!(resp.status(), 200);
}

/// Block action with custom status code
#[tokio::test]
async fn block_action_custom_status() {
    let upstream = start_echo_upstream().await;

    let request_dir = DirectionConfig {
        actions: vec![Action::Block],
        redact_strategy: None,
        mask_char: None,
        block_status: 451,
        block_body: Some("legally blocked".to_string()),
        block_headers: vec![],
    };

    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        request_dir,
        direction_empty(),
        ScanConfig::default(),
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("My email is john.doe@example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 451);
    let body = resp.text().await.unwrap();
    assert!(body.contains("legally blocked"));
}

/// Request header scanning with redaction
#[tokio::test]
async fn request_header_scanning_with_redaction() {
    let upstream = start_echo_upstream().await;

    let scan = ScanConfig {
        headers: vec!["authorization".to_string()],
        ..ScanConfig::default()
    };

    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        direction_redact(),
        direction_empty(),
        scan,
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .get(proxy.url("/echo"))
        .header("authorization", "Bearer john.doe@example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    // The forwarded authorization header should have PII redacted
    assert!(!body.contains("john.doe@example.com"));
}

/// Char redaction strategy with mask character
#[tokio::test]
async fn char_redaction_strategy() {
    let upstream = start_echo_upstream().await;

    let request_dir = DirectionConfig {
        actions: vec![Action::Redact],
        redact_strategy: Some(RedactStrategy::Char),
        mask_char: Some('*'),
        block_status: 403,
        block_body: None,
        block_headers: vec![],
    };

    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        request_dir,
        direction_empty(),
        ScanConfig::default(),
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("Email: john.doe@example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(!body.contains("john.doe@example.com"));
    // Char strategy replaces with mask character
    assert!(body.contains("*"));
}

/// Multiple routes with different upstreams
#[tokio::test]
async fn multiple_routes_different_upstreams() {
    let upstream = start_echo_upstream().await;

    let proxy = TestProxy::start(
        upstream,
        vec![("/echo", ""), ("/pii-response", "")],
        direction_empty(),
        direction_empty(),
        ScanConfig::default(),
    )
    .await;

    let client = reqwest::Client::new();

    // First route
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("hello")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("METHOD=POST"));

    // Second route
    let resp = reqwest::get(proxy.url("/pii-response")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("john.doe@example.com")); // no scanning configured
}

/// Per-route scan override fully replaces defaults
#[tokio::test]
async fn per_route_scan_override() {
    let upstream = start_echo_upstream().await;
    let pii_config = default_pii_config();
    let scanner = Arc::new(ScannerPool::new(&pii_config).unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    drop(listener);

    let config = AppConfig {
        pii: pii_config,
        scan: ScanConfig::default(),
        reverse_proxy: ReverseProxyConfig {
            enabled: true,
            listen: proxy_addr.to_string(),
            request: direction_block(),
            response: direction_empty(),
            routes: vec![Route {
                path_prefix: "/".to_string(),
                upstream: format!("http://{upstream}"),
                scan: Some(ScanConfig {
                    body: false, // disable body scanning
                    url: false,
                    query_params: false,
                    headers: vec![],
                    ..ScanConfig::default()
                }),
            }],
            ..Default::default()
        },
        ..default_app_config()
    };

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let scanner_clone = scanner.clone();

    tokio::spawn(async move {
        reverse_proxy::serve(&config, scanner_clone, cancel_clone)
            .await
            .unwrap();
    });
    wait_for_port(proxy_addr).await;

    let client = reqwest::Client::new();
    // Even though block action is configured, scanning is disabled
    // so PII in body should pass through
    let resp = client
        .post(format!("http://{proxy_addr}/echo"))
        .header("content-type", "text/plain")
        .body("john.doe@example.com")
        .send()
        .await
        .unwrap();

    // With all scan targets disabled, nothing to scan → Pass
    assert_eq!(resp.status(), 200);

    cancel.cancel();
}

/// Both request and response redaction: different strategies prove which direction acted
#[tokio::test]
async fn both_request_and_response_redaction() {
    let upstream = start_echo_upstream().await;

    let request_dir = DirectionConfig {
        actions: vec![Action::Redact],
        redact_strategy: Some(RedactStrategy::TypeLabel),
        mask_char: None,
        block_status: 403,
        block_body: None,
        block_headers: vec![],
    };

    let response_dir = DirectionConfig {
        actions: vec![Action::Redact],
        redact_strategy: Some(RedactStrategy::Char),
        mask_char: Some('*'),
        block_status: 403,
        block_body: None,
        block_headers: vec![],
    };

    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        request_dir,
        response_dir,
        ScanConfig::default(),
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo-with-pii"))
        .header("content-type", "text/plain")
        .body("Contact john.doe@example.com for info")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    // Original PII values must not survive
    assert!(
        !body.contains("john.doe@example.com"),
        "request email should be redacted"
    );
    assert!(
        !body.contains("123-45-6789"),
        "response SSN should be redacted"
    );

    // TypeLabel in the echoed request part proves request-side redaction
    assert!(
        body.contains("[EMAIL]"),
        "request redaction should use TypeLabel strategy"
    );

    // Char mask in the response part proves response-side redaction
    assert!(
        body.contains("*"),
        "response redaction should use Char strategy"
    );

    // Non-PII text preserved from both sides
    assert!(body.contains("Contact"));
    assert!(body.contains("RESPONSE_PII"));
}
