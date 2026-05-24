//! Integration test parity for the GA4 specialization (Phase 16.3 deferred
//! parity port). Mirrors `ga4_integration.rs` but configures the route with
//! `specialization = "ga4"` so the request goes through `Ga4Specialization`
//! end-to-end. The same scenarios must still detect the same PII kinds, and
//! redaction labels in form-encoded outputs must be properly percent-encoded
//! (`%5BEMAIL%5D` rather than `[EMAIL]`).

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::any;
use http_body_util::BodyExt;
use pii_proxy::config::{
    Action, AppConfig, DirectionConfig, PiiConfig, RedactStrategy, ReverseProxyConfig, Route,
    ScanConfig,
};
use pii_proxy::reverse_proxy;
use pii_proxy::scanner::ScannerPool;
use serde_json::{Value, json};
use test_case::test_case;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Mock GA4 upstream
// ---------------------------------------------------------------------------

async fn start_ga4_upstream() -> SocketAddr {
    let app = Router::new()
        .route("/g/collect", any(echo_handler))
        .route("/mp/collect", any(echo_handler))
        .route("/debug/mp/collect", any(echo_handler))
        .route("/batch", any(echo_handler));

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

// A 1x1 transparent GIF — the canonical real-world GA4/Matomo tracker
// response. Used to exercise the response-side specialization fallback:
// the spec sees `image/gif`, returns `UnsupportedContentType`, and the
// proxy must pass the body through silently (no log, no error counter).
const ONE_PX_GIF: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x21, 0xF9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3B,
];

async fn start_ga4_gif_upstream() -> SocketAddr {
    async fn gif_handler() -> impl IntoResponse {
        (StatusCode::OK, [("content-type", "image/gif")], ONE_PX_GIF)
    }
    let app = Router::new()
        .route("/g/collect", any(gif_handler))
        .route("/mp/collect", any(gif_handler))
        .route("/debug/mp/collect", any(gif_handler))
        .route("/batch", any(gif_handler));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    wait_for_port(addr).await;
    addr
}

// ---------------------------------------------------------------------------
// Test scaffolding
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

fn all_countries_pii_config() -> PiiConfig {
    PiiConfig {
        countries: pii::Country::all().to_vec(),
        languages: pii::Language::all().to_vec(),
        scanner_threads: Some(1),
        detect: None,
        ignore: None,
        custom: Vec::new(),
    }
}

fn direction(actions: Vec<Action>, strategy: Option<RedactStrategy>) -> DirectionConfig {
    DirectionConfig {
        actions,
        redact_strategy: strategy,
        mask_char: None,
        block_status: 403,
        block_body: None,
        block_headers: vec![],
    }
}

fn redact_request() -> DirectionConfig {
    direction(vec![Action::Redact], Some(RedactStrategy::TypeLabel))
}

fn block_request() -> DirectionConfig {
    direction(vec![Action::Block], None)
}

fn header_request() -> DirectionConfig {
    direction(vec![Action::Header], None)
}

fn redact_response() -> DirectionConfig {
    direction(vec![Action::Redact], Some(RedactStrategy::TypeLabel))
}

fn empty_dir() -> DirectionConfig {
    direction(vec![], None)
}

static SHARED_SCANNER: LazyLock<Arc<ScannerPool>> =
    LazyLock::new(|| Arc::new(ScannerPool::new(&all_countries_pii_config()).unwrap()));

struct TestProxy {
    addr: SocketAddr,
    cancel: CancellationToken,
    _scanner: Arc<ScannerPool>,
}

impl TestProxy {
    async fn start(
        upstream_addr: SocketAddr,
        request_dir: DirectionConfig,
        response_dir: DirectionConfig,
    ) -> Self {
        let scanner = SHARED_SCANNER.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        drop(listener);

        let config = AppConfig {
            pii: all_countries_pii_config(),
            scan: ScanConfig::default(),
            reverse_proxy: ReverseProxyConfig {
                enabled: true,
                listen: proxy_addr.to_string(),
                request: request_dir,
                response: response_dir,
                routes: vec![Route {
                    path_prefix: "/".to_string(),
                    upstream: format!("http://{upstream_addr}"),
                    scan: None,
                    specialization: Some("ga4".to_string()),
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

async fn post_mp_collect(proxy: &TestProxy, payload: Value) -> (StatusCode, String) {
    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/mp/collect?api_secret=fake_secret&measurement_id=G-XXXXXXXXXX"))
        .header("content-type", "application/json")
        .body(payload.to_string())
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    (status, body)
}

async fn get_g_collect(proxy: &TestProxy, query: &str) -> (StatusCode, String) {
    let resp = reqwest::get(proxy.url(&format!("/g/collect?{query}")))
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    (status, body)
}

async fn post_g_collect_form(proxy: &TestProxy, query: &str, body: &str) -> (StatusCode, String) {
    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url(&format!("/g/collect?{query}")))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    (status, body)
}

// ---------------------------------------------------------------------------
// PII-kind sweep against `/mp/collect` `notes` event param. Mirrors the same
// list of fixtures used by `ga4_integration::ga4_mp_redacts_pii_in_event_param`
// but with `specialization = "ga4"` driving the per-field scan.
// ---------------------------------------------------------------------------

#[test_case("contact us at user@example.com for info", "user@example.com" ; "Email")]
#[test_case("SSN: 123-45-6789", "123-45-6789" ; "UsSsn")]
#[test_case("card: 4111 1111 1111 1111", "4111 1111 1111 1111" ; "CreditCard")]
#[test_case("IBAN: GB29 NWBK 6016 1331 9268 19", "GB29 NWBK 6016 1331 9268 19" ; "Iban")]
#[test_case("IP: 10.0.0.255 ok", "10.0.0.255" ; "IpAddress")]
#[test_case("phone: 5551234567", "5551234567" ; "UsPhoneNumber")]
#[test_case("NINO: AB123456C", "AB123456C" ; "GbNino")]
#[test_case("key: AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE" ; "AwsAccessKey")]
#[tokio::test]
async fn ga4_mp_redacts_pii_in_event_param(input: &str, expected_match: &str) {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "ga-cid-A.B",
        "events": [{
            "name": "page_view",
            "params": { "notes": input }
        }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(
        !body.contains(expected_match),
        "PII `{expected_match}` leaked. Body:\n{body}"
    );
}

// Same on `/g/collect` query string. Form-encoded output must contain the
// percent-encoded redaction label, never the raw bracket form.
#[test_case("contact us at user@example.com for info", "user@example.com" ; "Email")]
#[test_case("SSN: 123-45-6789", "123-45-6789" ; "UsSsn")]
#[test_case("phone: 5551234567", "5551234567" ; "UsPhoneNumber")]
#[tokio::test]
async fn ga4_g_collect_redacts_pii_in_ep_query(input: &str, expected_match: &str) {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let encoded = urlencoding(input);
    let query =
        format!("v=2&tid=G-XXXXXXXXXX&en=page_view&cid=1234567890.1234567890&ep.notes={encoded}");
    let (status, body) = get_g_collect(&proxy, &query).await;
    assert_eq!(status, 200);
    assert!(
        !body.contains(expected_match),
        "PII `{expected_match}` leaked. Body:\n{body}"
    );
    // Form-encoded query must carry the percent-encoded redaction label.
    assert!(
        !body.contains("[EMAIL]")
            && !body.contains("[US_SSN]")
            && !body.contains("[US_PHONE_NUMBER]"),
        "raw bracket redaction label leaked into form-encoded query. Body:\n{body}"
    );
}

// ---------------------------------------------------------------------------
// GA4 field-shape tests #1–#29 plus pass-through.
// ---------------------------------------------------------------------------

// #1 — PII in `dl` (page_location) query string
#[tokio::test]
async fn g_collect_pii_in_page_location_query() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let dl = "https://shop.example.com/order/confirmed?email=jane.doe@example.com";
    let q = format!(
        "v=2&tid=G-X&cid=1.1&en=page_view&dl={}&dt=Order%20confirmed",
        urlencoding(dl)
    );
    let (status, body) = get_g_collect(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
    // dl is a recursive-URL field — redaction labels end up doubly-encoded.
    assert!(
        body.contains("%255BEMAIL%255D") || body.contains("%5BEMAIL%5D"),
        "expected percent-encoded EMAIL label in body:\n{body}"
    );
}

// #2 — PII in `dt` (page_title)
#[tokio::test]
async fn g_collect_pii_in_page_title() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let dt = "Order confirmation for jane.doe@example.com";
    let q = format!(
        "v=2&tid=G-X&cid=1.1&en=page_view&dl=https%3A%2F%2Fshop%2Eexample%2Ecom%2F&dt={}",
        urlencoding(dt)
    );
    let (status, body) = get_g_collect(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
}

// #3 — PII in `dr` (page_referrer)
#[tokio::test]
async fn g_collect_pii_in_page_referrer() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let dr = "https://shop.example.com/checkout?email=jane.doe@example.com&card=4111111111111111";
    let q = format!(
        "v=2&tid=G-X&cid=1.1&en=page_view&dl=https%3A%2F%2Fshop%2Eexample%2Ecom%2Fthanks&dr={}",
        urlencoding(dr)
    );
    let (status, body) = get_g_collect(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
    assert!(!body.contains("4111111111111111"));
}

// #4 — Raw email in `uid` is an operator-acknowledged channel: it must
// round-trip verbatim, since redacting the deliberate user identifier
// would break cross-device join in GA4.
#[tokio::test]
async fn g_collect_uid_email_passes_through() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = "v=2&tid=G-X&cid=1.1&en=login&uid=jane.doe%40example.com";
    let (status, body) = get_g_collect(&proxy, q).await;
    assert_eq!(status, 200);
    assert!(
        body.contains("uid=jane.doe%40example.com"),
        "uid must pass through unredacted: {body}"
    );
}

// #5 — PII in `ep.<custom>` event param
#[tokio::test]
async fn g_collect_pii_in_custom_event_param() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = "v=2&tid=G-X&cid=1.1&en=cart_view&ep.user_email=jane.doe%40example.com&ep.note=hello";
    let (status, body) = get_g_collect(&proxy, q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
    assert!(body.contains("ep.note=hello"));
}

// #6 — PII in `up.<custom>` user property
#[tokio::test]
async fn g_collect_pii_in_user_property() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = "v=2&tid=G-X&cid=1.1&en=page_view&up.contact_phone=phone%3A%205551234567";
    let (status, body) = get_g_collect(&proxy, q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("5551234567"));
}

// #7 — PII in form-encoded POST body of `/g/collect`. Body redaction label
// must be percent-encoded.
#[tokio::test]
async fn g_collect_post_form_body_pii() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let body = "ep.email=jane.doe%40example.com&ep.note=ok";
    let (status, echoed) = post_g_collect_form(&proxy, "v=2&tid=G-X&cid=1.1&en=signup", body).await;
    assert_eq!(status, 200);
    assert!(!echoed.contains("jane.doe@example.com"));
    assert!(!echoed.contains("jane.doe%40example.com"));
    assert!(
        !echoed.contains("[EMAIL]"),
        "form body must have percent-encoded redaction label, not raw brackets. Body:\n{echoed}"
    );
}

// #8 — `mp/collect` with raw email in `user_id`: operator-acknowledged
// channel, passes through verbatim (see g_collect_uid_email_passes_through).
#[tokio::test]
async fn mp_collect_user_id_email_passes_through() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "user_id": "jane.doe@example.com",
        "events": [{ "name": "login", "params": { "method": "email" } }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(
        body.contains("jane.doe@example.com"),
        "user_id must pass through unredacted: {body}"
    );
}

// #9 — `user_data.email_address` plaintext
#[tokio::test]
async fn mp_collect_plaintext_user_data_email() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "user_data": { "email_address": "jane.doe@example.com" },
        "events": [{ "name": "purchase", "params": {} }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
}

// #10 — `user_data.phone_number` plaintext
#[tokio::test]
async fn mp_collect_plaintext_user_data_phone() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "user_data": { "phone_number": "phone: +1 555 123 4567" },
        "events": [{ "name": "sign_up", "params": {} }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("+1 555 123 4567"));
}

// #11 — Custom `user_properties` value contains PII
#[tokio::test]
async fn mp_collect_pii_in_user_properties() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "user_properties": {
            "favourite_account": { "value": "IBAN: GB29 NWBK 6016 1331 9268 19" }
        },
        "events": [{ "name": "page_view", "params": {} }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("GB29 NWBK 6016 1331 9268 19"));
}

// #12 — `search_term` with email
#[tokio::test]
async fn mp_collect_pii_in_search_term() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "events": [{
            "name": "view_search_results",
            "params": { "search_term": "looking for jane.doe@example.com" }
        }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
}

// #13 — `transaction_id` constructed from email
#[tokio::test]
async fn mp_collect_pii_in_transaction_id() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "events": [{
            "name": "purchase",
            "params": {
                "transaction_id": "order-jane.doe@example.com-2026-05-01",
                "value": 42.0,
                "currency": "USD"
            }
        }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
}

// #14 — `items[].item_name` with customer reference
#[tokio::test]
async fn mp_collect_pii_in_item_name() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "events": [{
            "name": "purchase",
            "params": {
                "transaction_id": "T-12345",
                "value": 99.0,
                "currency": "EUR",
                "items": [{
                    "item_id": "SKU-1",
                    "item_name": "Custom engraving — Vorname: Hans",
                    "price": 99.0,
                    "quantity": 1
                }]
            }
        }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("Hans"));
}

// #15 — `exception.description` with multi-line stack trace
#[tokio::test]
async fn mp_collect_pii_in_exception_description() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let stack = "AuthError at /login\n  email=jane.doe@example.com\n  src IP: 10.0.0.255 ok\n  key: AKIAIOSFODNN7EXAMPLE";
    let payload = json!({
        "client_id": "1.1",
        "events": [{
            "name": "exception",
            "params": { "fatal": false, "description": stack }
        }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
    assert!(!body.contains("10.0.0.255"));
    assert!(!body.contains("AKIAIOSFODNN7EXAMPLE"));
}

// #16 — `ip_override` is an operator-acknowledged IP-override channel and
// passes through verbatim.
#[tokio::test]
async fn mp_collect_ip_override_passes_through() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "ip_override": "10.0.0.255",
        "events": [{ "name": "page_view", "params": {} }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(
        body.contains("10.0.0.255"),
        "ip_override must pass through unredacted: {body}"
    );
}

// #17 — `user_location.city` carrying a PERSON_NAME
#[tokio::test]
async fn mp_collect_person_name_in_user_location() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "user_location": { "city": "Vorname: Hans" },
        "events": [{ "name": "page_view", "params": {} }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("Vorname: Hans"));
}

// #18 — `mp/collect` with multiple events
#[tokio::test]
async fn mp_collect_multiple_events_partial_pii() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "events": [
            { "name": "page_view", "params": { "page_title": "Pricing" } },
            { "name": "view_search_results",
              "params": { "search_term": "phone: 5551234567 please" } }
        ]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("5551234567"));
    assert!(body.contains("Pricing"));
}

// #19 — Block action with PII in `coupon`
#[tokio::test]
async fn mp_collect_block_on_purchase_with_pii_in_coupon() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, block_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "events": [{
            "name": "purchase",
            "params": {
                "transaction_id": "T-1",
                "value": 50.0,
                "currency": "USD",
                "coupon": "promo for jane.doe@example.com"
            }
        }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 403);
    assert!(!body.contains("jane.doe@example.com"));
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let kinds: Vec<&str> = parsed["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"EMAIL"),
        "kinds should list EMAIL: {kinds:?}"
    );
}

// #20 — Header action: `X-PII-Detected` reflected upstream
#[tokio::test]
async fn g_collect_header_action_adds_x_pii_detected() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, header_request(), empty_dir()).await;

    let q = "v=2&tid=G-X&cid=1.1&en=page_view&dt=hi%20jane.doe%40example.com";
    let (status, body) = get_g_collect(&proxy, q).await;
    assert_eq!(status, 200);
    assert!(body.to_lowercase().contains("x-pii-detected"));
    assert!(body.to_lowercase().contains("email"));
}

// #21 — PII embedded in URL *path* via dl
#[tokio::test]
async fn g_collect_pii_in_url_path_via_dl() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let dl = "https://app.example.com/users/user@example.com/profile";
    let q = format!("v=2&tid=G-X&cid=1.1&en=page_view&dl={}", urlencoding(dl));
    let (status, body) = get_g_collect(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
    assert!(!body.contains("user%40example.com"));
}

// #22 — Form GET submission leaking email into URL
#[tokio::test]
async fn g_collect_form_get_submission_in_dl() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let dl = "https://app.example.com/login?email=user@example.com&password=hunter2";
    let q = format!("v=2&tid=G-X&cid=1.1&en=page_view&dl={}", urlencoding(dl));
    let (status, body) = get_g_collect(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
}

// #23 — Password reset URL leak
#[tokio::test]
async fn g_collect_password_reset_url_leak() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let dl = "https://app.example.com/reset?token=gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12&email=user@example.com";
    let q = format!("v=2&tid=G-X&cid=1.1&en=page_view&dl={}", urlencoding(dl));
    let (status, body) = get_g_collect(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
    assert!(!body.contains("gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12"));
}

// #24 — Referrer-chain leak via dr
#[tokio::test]
async fn g_collect_referrer_chain_leak_via_dr() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let dl = "https://blog.example.com/article";
    let dr = "https://app.example.com/reset?token=gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12&email=user@example.com";
    let q = format!(
        "v=2&tid=G-X&cid=1.1&en=page_view&dl={}&dr={}",
        urlencoding(dl),
        urlencoding(dr)
    );
    let (status, body) = get_g_collect(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
    assert!(!body.contains("gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12"));
}

// #25 — `link_url` event param contains redirect with PII
#[tokio::test]
async fn mp_collect_pii_in_link_url() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "events": [{
            "name": "click",
            "params": {
                "link_url": "https://partner.example.com/redir?email=user@example.com",
                "link_text": "click here"
            }
        }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
}

// #26 — `form_destination` carrying PII
#[tokio::test]
async fn mp_collect_pii_in_form_destination() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "events": [{
            "name": "form_submit",
            "params": {
                "form_id": "checkout",
                "form_destination": "https://app.example.com/checkout?email=user@example.com",
                "form_submit_text": "Pay now"
            }
        }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
}

// #27 — Custom event param literally named "email"
#[tokio::test]
async fn mp_collect_custom_param_named_email() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "events": [{
            "name": "newsletter_signup",
            "params": { "email": "user@example.com", "source": "footer" }
        }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
}

// #28 — Blind spots: phone, credit card, SSN
#[tokio::test]
async fn mp_collect_catches_ga4_redaction_blind_spots() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "events": [{
            "name": "page_view",
            "params": {
                "page_location": "https://app.example.com/p?phone=phone%3A%205551234567",
                "payment_method": "card: 4111 1111 1111 1111",
                "tax_id_note": "SSN: 123-45-6789"
            }
        }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("5551234567"));
    assert!(!body.contains("4111 1111 1111 1111"));
    assert!(!body.contains("123-45-6789"));
}

// #29 — Batch endpoint
#[tokio::test]
async fn mp_batch_endpoint_redacts_pii_across_events() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "events": [
            { "name": "page_view", "params": { "page_title": "Home" } },
            { "name": "purchase",
              "params": { "transaction_id": "T-2", "value": 9.0, "currency": "USD",
                          "coupon": "code for user@example.com" } },
            { "name": "exception", "params": { "description": "SSN: 123-45-6789 in log" } }
        ]
    });
    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/batch?api_secret=fake&measurement_id=G-XXX"))
        .header("content-type", "application/json")
        .body(payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(!body.contains("user@example.com"));
    assert!(!body.contains("123-45-6789"));
    assert!(body.contains("Home"));
}

// ---------------------------------------------------------------------------
// Negative / clean pass-through tests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn clean_g_collect_passes_through_unchanged() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = "v=2&tid=G-X&cid=1234567890.1234567890&en=page_view&dl=https%3A%2F%2Fshop%2Eexample%2Ecom%2Fpricing&dt=Pricing";
    let (status, body) = get_g_collect(&proxy, q).await;
    assert_eq!(status, 200);
    assert!(body.contains("dt=Pricing"));
}

#[tokio::test]
async fn clean_mp_collect_passes_through_unchanged() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1234567890.1234567890",
        "events": [{
            "name": "page_view",
            "params": { "page_title": "Pricing", "page_location": "https://shop.example.com/pricing" }
        }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(body.contains("\"page_title\":\"Pricing\""));
    assert!(body.contains("https://shop.example.com/pricing"));
}

// Auto-generated `cid` (UUID-ish dotted decimal) must not match any PII
// detector — confirms there is no false positive on the identifier shapes
// that GA4 itself emits.
#[tokio::test]
async fn auto_generated_cid_does_not_trigger_pii() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, header_request(), empty_dir()).await;

    let q = "v=2&tid=G-XXXXXXXXXX&cid=1234567890.9876543210&en=page_view&_s=1&_et=42";
    let (status, body) = get_g_collect(&proxy, q).await;
    assert_eq!(status, 200);
    assert!(!body.to_lowercase().contains("x-pii-detected"));
}

// ---------------------------------------------------------------------------
// Phase 16.7 — focused reverse-proxy wiring tests
// ---------------------------------------------------------------------------

/// 16.7 request-side wiring: a route configured with `specialization = "ga4"`
/// must run the JSON body through the GA4 spec, detect PII in scanned leaves,
/// and redact the forwarded body. `user_data.email_address` is the explicit
/// PII envelope and stays scanned regardless of policy. Adds a belt-and-braces
/// check on the spec error counter — the success path must leave it untouched
/// (proves we went down the spec path, not a fallback).
#[tokio::test]
async fn ga4_route_redacts_user_data_email_via_specialization() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let before_errors = pii_proxy::metrics::SPECIALIZATION_ERRORS_TOTAL
        .with_label_values(&["ga4", "decode"])
        .get();

    let payload = json!({
        "client_id": "1.1",
        "user_data": { "email_address": "jane.doe@example.com" },
        "events": [{ "name": "login", "params": {} }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
    assert!(
        body.contains("[EMAIL]"),
        "expected redaction label in forwarded body: {body}"
    );

    let after_errors = pii_proxy::metrics::SPECIALIZATION_ERRORS_TOTAL
        .with_label_values(&["ga4", "decode"])
        .get();
    assert_eq!(
        before_errors, after_errors,
        "successful spec processing must not increment the error counter"
    );
}

/// 16.7 response-side wiring: when a route has response actions and the
/// upstream returns `image/gif` (the canonical GA4 tracking-pixel response),
/// the GA4 spec returns `UnsupportedContentType`. That fallback must be
/// silent — no log, no `pii_proxy_specialization_errors_total` increment —
/// because trackers responding with a 1x1 gif is the expected common case
/// on the response path, not an error condition.
#[tokio::test]
async fn ga4_response_gif_silently_falls_back() {
    let upstream = start_ga4_gif_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), redact_response()).await;

    let before_unsupported = pii_proxy::metrics::SPECIALIZATION_ERRORS_TOTAL
        .with_label_values(&["ga4", "unsupported_content_type"])
        .get();
    let before_decode = pii_proxy::metrics::SPECIALIZATION_ERRORS_TOTAL
        .with_label_values(&["ga4", "decode"])
        .get();

    // A clean payload — no request-side PII to muddy the response check.
    let payload = json!({
        "client_id": "1234567890.9876543210",
        "events": [{ "name": "page_view", "params": { "page_title": "Pricing" } }]
    });
    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/mp/collect?api_secret=fake&measurement_id=G-XXX"))
        .header("content-type", "application/json")
        .body(payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap()),
        Some("image/gif"),
        "upstream gif response should pass through unchanged"
    );
    let body = resp.bytes().await.unwrap();
    assert_eq!(
        body.as_ref(),
        ONE_PX_GIF,
        "gif bytes must round-trip intact"
    );

    let after_unsupported = pii_proxy::metrics::SPECIALIZATION_ERRORS_TOTAL
        .with_label_values(&["ga4", "unsupported_content_type"])
        .get();
    let after_decode = pii_proxy::metrics::SPECIALIZATION_ERRORS_TOTAL
        .with_label_values(&["ga4", "decode"])
        .get();
    assert_eq!(
        before_unsupported, after_unsupported,
        "response-side UnsupportedContentType must NOT increment the spec error counter"
    );
    assert_eq!(
        before_decode, after_decode,
        "response-side fallback must not surface as a decode error either"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
