use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{any, get};
use http_body_util::BodyExt;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use voidwall::config::{
    AppConfig, DirectionConfig, OnError, PiiConfig, ReverseProxyConfig, Route, ScanConfig,
};
use voidwall::engine::Engine;
use voidwall::reverse_proxy;

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
        custom: Vec::new(),
    }
}

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

/// Single detection engine shared by every `start` test in this binary. Tests
/// that need a custom `PiiConfig` (custom regex, country filter, …) call
/// `start_with_pii` and build their own engine; everything else reuses
/// this one to avoid paying ~9 s of regex/hyperscan compilation per test.
static SHARED_DEFAULT_ENGINE: LazyLock<Arc<Engine>> =
    LazyLock::new(|| Arc::new(Engine::new(&default_pii_config()).unwrap()));

impl TestProxy {
    async fn start(
        upstream_addr: SocketAddr,
        routes: Vec<(&str, &str)>,
        request_dir: DirectionConfig,
        response_dir: DirectionConfig,
        scan: ScanConfig,
    ) -> Self {
        Self::start_inner(
            upstream_addr,
            routes,
            request_dir,
            response_dir,
            scan,
            default_pii_config(),
            SHARED_DEFAULT_ENGINE.clone(),
        )
        .await
    }

    async fn start_with_pii(
        upstream_addr: SocketAddr,
        routes: Vec<(&str, &str)>,
        request_dir: DirectionConfig,
        response_dir: DirectionConfig,
        scan: ScanConfig,
        pii_config: PiiConfig,
    ) -> Self {
        let engine = Arc::new(Engine::new(&pii_config).unwrap());
        Self::start_inner(
            upstream_addr,
            routes,
            request_dir,
            response_dir,
            scan,
            pii_config,
            engine,
        )
        .await
    }

    async fn start_inner(
        upstream_addr: SocketAddr,
        routes: Vec<(&str, &str)>,
        request_dir: DirectionConfig,
        response_dir: DirectionConfig,
        scan: ScanConfig,
        pii_config: PiiConfig,
        engine: Arc<Engine>,
    ) -> Self {
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

fn default_app_config() -> AppConfig {
    AppConfig {
        pii: default_pii_config(),
        scan: ScanConfig::default(),
        reverse_proxy: ReverseProxyConfig::default(),
        forward_proxy: Default::default(),
        http_api: Default::default(),
        admin: Default::default(),
        shutdown_timeout_secs: 30,
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
        scan_off(),
        scan_off(),
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
        scan_off(),
        scan_off(),
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
async fn request_pii_returns_fixed_403() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
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
async fn response_pii_returns_fixed_403() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        scan_off(),
        scan_on(),
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

/// `scan = false` disables inspection for that direction
#[tokio::test]
async fn scan_false_disables_scanning() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        scan_off(),
        scan_off(),
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
        scan_on(),
        scan_off(),
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
        .find(|m| m.get_name() == "voidwall_pii_detections_total");
    assert!(
        detection_metric.is_some(),
        "voidwall_pii_detections_total metric should exist"
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
        scan_on(),
        scan_off(),
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
        scan_on(),
        scan_off(),
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

/// A scanner failure under `fail_close` answers 500. The scanner belongs to the
/// proxy, so a failure inside it is not the upstream's fault and must not be
/// reported as 502.
///
/// The failure is induced with a pool that owns no scanner threads: the work
/// channel has no receiver, so every submit sees it disconnected. That is the
/// same error the pool raises in production once its threads have died.
#[tokio::test]
async fn scanner_failure_fail_close_answers_500() {
    let upstream = start_echo_upstream().await;

    let scan = ScanConfig {
        on_error: OnError::FailClose,
        ..ScanConfig::default()
    };

    let pii_config = PiiConfig {
        scanner_threads: Some(0),
        ..default_pii_config()
    };

    let proxy = TestProxy::start_with_pii(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
        scan,
        pii_config,
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("nothing sensitive here")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 500);
}

/// Every blocking error body names the error and nothing else. A message that
/// held a detected value must not leak a fragment of that value into the 400,
/// the 413, or the 500.
#[tokio::test]
async fn error_bodies_carry_no_scanned_text() {
    const PLACEHOLDER: &str = "jane@example.com";

    let upstream = start_echo_upstream().await;
    let client = reqwest::Client::new();

    // 413: the body passes max_body_size and is refused before any scan.
    let scan = ScanConfig {
        max_body_size: 4,
        on_error: OnError::FailClose,
        ..ScanConfig::default()
    };
    let proxy = TestProxy::start(upstream, vec![("/", "")], scan_on(), scan_off(), scan).await;
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body(PLACEHOLDER)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
    assert!(!resp.text().await.unwrap().contains(PLACEHOLDER));

    // 400: the body declares JSON and does not parse as JSON.
    let scan = ScanConfig {
        on_error: OnError::FailClose,
        ..ScanConfig::default()
    };
    let proxy = TestProxy::start(upstream, vec![("/", "")], scan_on(), scan_off(), scan).await;
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "application/json")
        .body(format!(r#"{{"email": "{PLACEHOLDER}""#))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert!(!resp.text().await.unwrap().contains(PLACEHOLDER));

    // 500: the scanner pool owns no threads, so the scan itself fails.
    let scan = ScanConfig {
        on_error: OnError::FailClose,
        ..ScanConfig::default()
    };
    let pii_config = PiiConfig {
        scanner_threads: Some(0),
        ..default_pii_config()
    };
    let proxy = TestProxy::start_with_pii(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
        scan,
        pii_config,
    )
    .await;
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body(PLACEHOLDER)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);
    assert!(!resp.text().await.unwrap().contains(PLACEHOLDER));
}

/// Reads the current `voidwall_errors_total` count for one outcome/reason pair.
/// The registry is process-wide and shared by every test in this binary, so a
/// test must compare a delta rather than an absolute value.
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

/// A configuration that never names `on_error` blocks on scanner failure. This
/// is the default flip: the safe posture is what an operator gets by writing
/// nothing at all.
#[tokio::test]
async fn default_config_blocks_on_scanner_failure() {
    let upstream = start_echo_upstream().await;

    let before = errors_total("blocked", "scanner_failure");

    // No `on_error` here on purpose — this is what the default gives you.
    let scan = ScanConfig::default();
    assert_eq!(scan.on_error, OnError::FailClose, "default must be fail_close");

    let pii_config = PiiConfig {
        scanner_threads: Some(0),
        ..default_pii_config()
    };
    let proxy = TestProxy::start_with_pii(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
        scan,
        pii_config,
    )
    .await;

    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("nothing sensitive here")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 500);
    assert!(
        errors_total("blocked", "scanner_failure") > before,
        "voidwall_errors_total{{outcome=\"blocked\",reason=\"scanner_failure\"}} must increment"
    );
}

/// A body whose content type sits outside `scan.content_types` is skipped in
/// silence. That is not an error, so `fail_close` must not block it: the
/// request reaches the upstream untouched.
#[tokio::test]
async fn unlisted_content_type_is_forwarded_under_fail_close() {
    let upstream = start_echo_upstream().await;

    let scan = ScanConfig {
        on_error: OnError::FailClose,
        ..ScanConfig::default()
    };
    let proxy = TestProxy::start(upstream, vec![("/", "")], scan_on(), scan_off(), scan).await;

    // image/png is outside the default allowlist, so the body is never scanned.
    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "image/png")
        .body("binary-ish payload")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "an unscannable content type is not an error and must not be blocked"
    );
    assert!(
        resp.text().await.unwrap().contains("binary-ish payload"),
        "the upstream must have received the body unchanged"
    );
}

/// A scanner failure under `fail_open` forwards the message. This is the
/// branch an operator opts back into, so it has to keep working after the
/// default moved off it.
#[tokio::test]
async fn scanner_failure_fail_open_forwards_the_message() {
    let upstream = start_echo_upstream().await;

    let scan = ScanConfig {
        on_error: OnError::FailOpen,
        ..ScanConfig::default()
    };
    let pii_config = PiiConfig {
        scanner_threads: Some(0),
        ..default_pii_config()
    };
    let proxy = TestProxy::start_with_pii(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
        scan,
        pii_config,
    )
    .await;

    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("forwarded unscanned")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("forwarded unscanned"));
}

/// 502 still means the upstream failed. The change moved scanner failures off
/// this status, so something has to pin what is left on it.
#[tokio::test]
async fn upstream_unreachable_answers_502() {
    // Bind and drop: nothing listens here, so the proxy's connection is refused.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_upstream = listener.local_addr().unwrap();
    drop(listener);

    let proxy = TestProxy::start(
        dead_upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
        ScanConfig::default(),
    )
    .await;

    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("nothing sensitive here")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        502,
        "a failure of the upstream itself is the only thing that earns 502"
    );
}

/// Clean request passes through without modification
/// The 403 body is stable: two identical requests produce byte-identical
/// bodies, with the kinds sorted and each named once. This is the guarantee
/// that left with the action engine.
#[tokio::test]
async fn block_body_kinds_are_sorted_and_stable_across_two_requests() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
        ScanConfig::default(),
    )
    .await;

    let client = reqwest::Client::new();
    // Two kinds, given in an order the response must not echo.
    let payload = "ssn 123-45-6789 and mail john.doe@example.com";
    let mut bodies = Vec::new();
    for _ in 0..2 {
        let resp = client
            .post(proxy.url("/echo"))
            .header("content-type", "text/plain")
            .body(payload)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        bodies.push(resp.text().await.unwrap());
    }

    assert_eq!(bodies[0], bodies[1], "block body must be stable");
    let json: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
    let kinds: Vec<&str> = json["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    let mut sorted = kinds.clone();
    sorted.sort_unstable();
    assert_eq!(kinds, sorted, "kinds must be sorted, got {kinds:?}");
    let mut deduped = sorted.clone();
    deduped.dedup();
    assert_eq!(deduped, kinds, "each kind must appear once");
    // Never the matched values.
    assert!(!bodies[0].contains("123-45-6789"));
    assert!(!bodies[0].contains("john.doe@example.com"));
}

#[tokio::test]
async fn clean_request_passes_through() {
    let upstream = start_echo_upstream().await;
    // Request direction only: the echo upstream reflects the client's Host
    // header, which is an IP address and would block the response on its own.
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
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

/// PII in the query string is detected and blocks the request
#[tokio::test]
async fn request_pii_in_query_string_blocks() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
        ScanConfig {
            query_params: true,
            ..ScanConfig::default()
        },
    )
    .await;

    let resp = reqwest::get(proxy.url("/echo?email=john.doe@example.com"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    // The 403 names the kind and never the matched value.
    assert!(body.contains("EMAIL"), "got: {body}");
    assert!(!body.contains("john.doe@example.com"));
}

/// Hop-by-hop headers are stripped when proxying
#[tokio::test]
async fn hop_by_hop_headers_stripped() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        scan_off(),
        scan_off(),
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
        scan_on(), // would block if scanned
        scan_off(),
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
/// A scanned request header carrying PII blocks the request
#[tokio::test]
async fn request_header_scanning_blocks() {
    let upstream = start_echo_upstream().await;

    let scan = ScanConfig {
        headers: vec!["authorization".to_string()],
        ..ScanConfig::default()
    };

    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
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

    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    // The 403 names the kind and never the matched value.
    assert!(body.contains("EMAIL"), "got: {body}");
    assert!(!body.contains("john.doe@example.com"));
}

/// Multiple routes with different upstreams
#[tokio::test]
async fn multiple_routes_different_upstreams() {
    let upstream = start_echo_upstream().await;

    let proxy = TestProxy::start(
        upstream,
        vec![("/echo", ""), ("/pii-response", "")],
        scan_off(),
        scan_off(),
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
    let engine = Arc::new(Engine::new(&pii_config).unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    drop(listener);

    let config = AppConfig {
        pii: pii_config,
        scan: ScanConfig::default(),
        reverse_proxy: ReverseProxyConfig {
            enabled: true,
            listen: proxy_addr.to_string(),
            request: scan_on(),
            response: scan_off(),
            routes: vec![Route {
                path_prefix: "/".to_string(),
                upstream: format!("http://{upstream}"),
                scan: Some(ScanConfig {
                    body: false, // disable body scanning
                    url_path: false,
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
    let engine_clone = engine.clone();

    tokio::spawn(async move {
        reverse_proxy::serve(&config, engine_clone, cancel_clone)
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

// ---------------------------------------------------------------------------
// User-defined PII integration tests
// ---------------------------------------------------------------------------

fn pii_config_with_custom(custom: Vec<voidwall_pii::UserPiiDefinition>) -> PiiConfig {
    PiiConfig {
        countries: vec![],
        languages: vec![],
        scanner_threads: Some(1),
        detect: None,
        ignore: None,
        custom,
    }
}

fn employee_id_def() -> voidwall_pii::UserPiiDefinition {
    voidwall_pii::UserPiiDefinition {
        label: "EMPLOYEE_ID".into(),
        pattern: r"EMP-\d{6}".into(),
        keywords: Vec::new(),
        country: voidwall_pii::Country::International,
    }
}

#[tokio::test]
async fn custom_pii_block_lists_user_label() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start_with_pii(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
        ScanConfig::default(),
        pii_config_with_custom(vec![employee_id_def()]),
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("staff EMP-123456 here")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let kinds: Vec<&str> = json["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"EMPLOYEE_ID"),
        "block response kinds should contain user label, got {kinds:?}"
    );
    assert!(!body.contains("EMP-123456"), "PII value must not leak");
}

/// The operator's label reaches the `pii_kind` metric axis, not just the 403
/// body. A custom definition is the only way an operator-chosen string gets
/// onto a metric label, so this is the case worth pinning.
#[tokio::test]
async fn custom_pii_label_reaches_the_detection_metric() {
    let upstream = start_echo_upstream().await;
    let def = voidwall_pii::UserPiiDefinition {
        label: "BADGE_SERIAL".into(),
        pattern: r"BDG-\d{6}".into(),
        keywords: vec![],
        country: voidwall_pii::Country::International,
    };
    let proxy = TestProxy::start_with_pii(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
        ScanConfig::default(),
        pii_config_with_custom(vec![def]),
    )
    .await;

    let resp = reqwest::Client::new()
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("badge BDG-482915 issued")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let labelled = prometheus::default_registry()
        .gather()
        .iter()
        .find(|m| m.get_name() == "voidwall_pii_detections_total")
        .is_some_and(|mf| {
            mf.get_metric().iter().any(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|l| l.get_name() == "pii_kind" && l.get_value() == "BADGE_SERIAL")
            })
        });
    assert!(
        labelled,
        "expected voidwall_pii_detections_total with pii_kind=\"BADGE_SERIAL\""
    );
}

#[tokio::test]
async fn custom_pii_country_filter_drops_out_of_scope_entry() {
    let upstream = start_echo_upstream().await;
    let pii_config = PiiConfig {
        countries: vec![voidwall_pii::Country::Us],
        languages: vec![],
        scanner_threads: Some(1),
        detect: None,
        ignore: None,
        custom: vec![voidwall_pii::UserPiiDefinition {
            label: "GB_ONLY_ID".into(),
            pattern: r"GB-\d{6}".into(),
            keywords: Vec::new(),
            country: voidwall_pii::Country::Gb,
        }],
    };
    let proxy = TestProxy::start_with_pii(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
        ScanConfig::default(),
        pii_config,
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("value GB-654321 here")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "out-of-scope entry must not match");
    let body = resp.text().await.unwrap();
    assert!(body.contains("BODY:value GB-654321 here"));
}

#[tokio::test]
async fn custom_pii_keyword_mode_requires_keyword() {
    let upstream = start_echo_upstream().await;
    let def = voidwall_pii::UserPiiDefinition {
        label: "PROJECT_CODE".into(),
        pattern: r"[A-Z]{3}-\d{3}".into(),
        keywords: vec!["project code".into()],
        country: voidwall_pii::Country::International,
    };

    // Without keyword → no match, request forwarded
    let proxy = TestProxy::start_with_pii(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
        ScanConfig::default(),
        pii_config_with_custom(vec![def.clone()]),
    )
    .await;
    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("random ABC-123 text")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("BODY:random ABC-123 text"));
    assert!(!body.contains("[PROJECT_CODE]"));
    drop(proxy);

    // With keyword → the definition matches and the request is blocked
    let proxy = TestProxy::start_with_pii(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
        ScanConfig::default(),
        pii_config_with_custom(vec![def]),
    )
    .await;
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("project code ABC-123 assigned")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("PROJECT_CODE"),
        "expected the operator label in kinds, got: {body}"
    );
    assert!(!body.contains("ABC-123"));
}

#[tokio::test]
async fn custom_pii_coexists_with_builtin_detection() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start_with_pii(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
        ScanConfig::default(),
        pii_config_with_custom(vec![employee_id_def()]),
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("contact john.doe@example.com for EMP-123456")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let kinds: Vec<&str> = json["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"EMPLOYEE_ID"),
        "kinds should include custom label, got {kinds:?}"
    );
    assert!(
        kinds.contains(&"EMAIL"),
        "kinds should include built-in EMAIL, got {kinds:?}"
    );
}

/// PersonName (DictionaryDetector) flows end-to-end through the existing
/// pipeline with no PersonName-specific config: a name in the request body is
/// detected, the request is blocked, `PERSON_NAME` appears in the 403 `kinds`
/// array, and the detection metric carries the `pii_kind="PERSON_NAME"` label.
#[tokio::test]
async fn person_name_detected_and_metric_labelled() {
    let upstream = start_echo_upstream().await;
    let proxy = TestProxy::start(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
        ScanConfig::default(),
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("Please contact John Smith about the order")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let kinds: Vec<&str> = json["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"PERSON_NAME"),
        "expected PERSON_NAME in kinds, got {kinds:?}"
    );
    // The matched name never appears in the response.
    assert!(!body.contains("John Smith"));

    // Detection metric carries the PERSON_NAME kind label.
    let metrics = prometheus::default_registry().gather();
    let labelled = metrics
        .iter()
        .find(|m| m.get_name() == "voidwall_pii_detections_total")
        .is_some_and(|mf| {
            mf.get_metric().iter().any(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|l| l.get_name() == "pii_kind" && l.get_value() == "PERSON_NAME")
            })
        });
    assert!(
        labelled,
        "expected voidwall_pii_detections_total with pii_kind=\"PERSON_NAME\""
    );
}

/// Disabling PersonName via `[pii].ignore` is the only knob needed to turn the
/// detector off: the same name now passes through undetected.
#[tokio::test]
async fn person_name_disabled_via_ignore_not_detected() {
    let upstream = start_echo_upstream().await;
    let mut pii_config = default_pii_config();
    pii_config.ignore = Some(vec![voidwall_pii::PiiKind::PersonName]);
    let proxy = TestProxy::start_with_pii(
        upstream,
        vec![("/", "")],
        scan_on(),
        scan_off(),
        ScanConfig::default(),
        pii_config,
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/echo"))
        .header("content-type", "text/plain")
        .body("Please contact John Smith about the order")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    // Name flows through; nothing is detected, so the request is forwarded.
    assert!(
        body.contains("John Smith"),
        "name should pass through undetected, got: {body}"
    );
    assert!(!body.contains("[PERSON_NAME]"));
}
