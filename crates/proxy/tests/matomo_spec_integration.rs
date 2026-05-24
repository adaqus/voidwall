//! Integration test parity for the Matomo specialization (Phase 16.4 deferred
//! parity port). Mirrors `matomo_integration.rs` but configures the route with
//! `specialization = "matomo"` so the request goes through `MatomoSpecialization`
//! end-to-end. Same scenarios must still detect the same PII kinds, and
//! redaction labels in form-encoded outputs must be properly percent-encoded
//! (`%5BEMAIL%5D`, `%255BEMAIL%255D` for values nested inside `url=`).

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
// Mock Matomo upstream
// ---------------------------------------------------------------------------

async fn start_matomo_upstream() -> SocketAddr {
    let app = Router::new()
        .route("/matomo.php", any(echo_handler))
        .route("/piwik.php", any(echo_handler));

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

// A 1x1 transparent GIF — Matomo trackers reply with this for `matomo.php`
// hits. Used to exercise the response-side specialization fallback: the
// spec sees `image/gif`, returns `UnsupportedContentType`, and the proxy
// must pass the body through silently (no log, no error counter).
const ONE_PX_GIF: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x21, 0xF9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3B,
];

async fn start_matomo_gif_upstream() -> SocketAddr {
    async fn gif_handler() -> impl IntoResponse {
        (StatusCode::OK, [("content-type", "image/gif")], ONE_PX_GIF)
    }
    let app = Router::new()
        .route("/matomo.php", any(gif_handler))
        .route("/piwik.php", any(gif_handler));

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
                    specialization: Some("matomo".to_string()),
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

async fn get_matomo(proxy: &TestProxy, query: &str) -> (StatusCode, String) {
    let resp = reqwest::get(proxy.url(&format!("/matomo.php?{query}")))
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    (status, body)
}

async fn post_matomo_form(proxy: &TestProxy, body: &str) -> (StatusCode, String) {
    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/matomo.php"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    (status, body)
}

async fn post_matomo_bulk(proxy: &TestProxy, payload: Value) -> (StatusCode, String) {
    let client = reqwest::Client::new();
    let resp = client
        .post(proxy.url("/matomo.php"))
        .header("content-type", "application/json")
        .body(payload.to_string())
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    (status, body)
}

// ---------------------------------------------------------------------------
// PII-kind sweep against bulk `action_name`.
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
async fn matomo_bulk_redacts_pii_in_action_name(input: &str, expected_match: &str) {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let request_qs = format!(
        "?idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url={}&action_name={}",
        urlencoding("https://shop.example.com/article"),
        urlencoding(input)
    );
    let payload = json!({
        "requests": [request_qs],
        "token_auth": "33dc3f2536d3025974cccb4b4d2d98f4",
    });
    let (status, body) = post_matomo_bulk(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(
        !body.contains(expected_match),
        "PII `{expected_match}` leaked. Body:\n{body}"
    );
}

#[test_case("contact us at user@example.com for info", "user@example.com" ; "Email")]
#[test_case("SSN: 123-45-6789", "123-45-6789" ; "UsSsn")]
#[test_case("card: 4111 1111 1111 1111", "4111 1111 1111 1111" ; "CreditCard")]
#[test_case("phone: 5551234567", "5551234567" ; "UsPhoneNumber")]
#[test_case("IBAN: GB29 NWBK 6016 1331 9268 19", "GB29 NWBK 6016 1331 9268 19" ; "Iban")]
#[tokio::test]
async fn matomo_get_redacts_pii_in_action_name_query(input: &str, expected_match: &str) {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url={}&action_name={}",
        urlencoding("https://shop.example.com/article"),
        urlencoding(input)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(
        !body.contains(expected_match),
        "PII `{expected_match}` leaked. Body:\n{body}"
    );
    // Form-encoded output must use percent-encoded redaction labels at the
    // outer layer.
    assert!(
        !body.contains("[EMAIL]")
            && !body.contains("[US_SSN]")
            && !body.contains("[US_PHONE_NUMBER]")
            && !body.contains("[CREDIT_CARD]")
            && !body.contains("[IBAN]"),
        "raw bracket redaction label leaked into form-encoded output. Body:\n{body}"
    );
}

// ---------------------------------------------------------------------------
// Field-shape tests #1–#29 plus pass-through.
// ---------------------------------------------------------------------------

// #1 — PII in `url` query string. Output must be valid form-encoded data
// with redaction label properly percent-encoded (canonical user bug).
#[tokio::test]
async fn get_pii_in_page_url() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let url = "https://shop.example.com/order/confirmed?email=jane.doe@example.com";
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url={}&action_name=Order%20confirmed",
        urlencoding(url)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
    // url is a recursive-URL field — redaction labels end up doubly-encoded.
    assert!(
        body.contains("%255BEMAIL%255D") || body.contains("%5BEMAIL%5D"),
        "expected percent-encoded EMAIL label in body:\n{body}"
    );
}

// #2 — PII in `action_name`
#[tokio::test]
async fn get_pii_in_action_name() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let title = "Order confirmation for jane.doe@example.com";
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fshop.example.com%2F&action_name={}",
        urlencoding(title)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
}

// #3 — PII in `urlref`
#[tokio::test]
async fn get_pii_in_urlref() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let urlref =
        "https://shop.example.com/checkout?email=jane.doe@example.com&card=4111111111111111";
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fshop.example.com%2Fthanks&urlref={}",
        urlencoding(urlref)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
    assert!(!body.contains("4111111111111111"));
}

// #4 — Raw email in `uid` is an operator-acknowledged channel: it must
// round-trip verbatim, since redacting the deliberate user identifier
// would break Matomo's cross-visit join.
#[tokio::test]
async fn get_uid_email_passes_through() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2F&action_name=Login&uid=jane.doe%40example.com";
    let (status, body) = get_matomo(&proxy, q).await;
    assert_eq!(status, 200);
    assert!(
        body.contains("uid=jane.doe%40example.com"),
        "uid must pass through unredacted: {body}"
    );
}

// #5 — PII in `_cvar`
#[tokio::test]
async fn get_pii_in_visit_scope_cvar() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let cvar = r#"{"1":["customer","jane.doe@example.com"],"2":["plan","gold"]}"#;
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2F&_cvar={}",
        urlencoding(cvar)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
}

// #6 — PII in page-scope `cvar`
#[tokio::test]
async fn get_pii_in_page_scope_cvar() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let cvar = r#"{"1":["tax_id","SSN: 123-45-6789"]}"#;
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2F&cvar={}",
        urlencoding(cvar)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("123-45-6789"));
}

// #7 — PII in custom dimensions
#[tokio::test]
async fn get_pii_in_custom_dimension() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2F&dimension1={}&dimension2={}",
        urlencoding("phone: 5551234567"),
        urlencoding("plan-gold")
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("5551234567"));
    assert!(body.contains("plan-gold"));
}

// #8 — PII in event name `e_n`
#[tokio::test]
async fn get_pii_in_event_name() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2F&e_c=newsletter&e_a=submit&e_n={}&e_v=1",
        urlencoding("user@example.com")
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
    assert!(!body.contains("user%40example.com"));
}

// #9 — PII in `search`
#[tokio::test]
async fn get_pii_in_search_keyword() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2Fsearch&search={}&search_count=3",
        urlencoding("looking for jane.doe@example.com")
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
}

// #10 — PII in `search_cat`
#[tokio::test]
async fn get_pii_in_search_category() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2Fsearch&search=results&search_cat={}",
        urlencoding("user@example.com")
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
}

// #11 — PII in `link`
#[tokio::test]
async fn get_pii_in_outlink() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let link = "https://partner.example.com/redir?email=user@example.com&utm_source=mat";
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fshop.example.com%2F&link={}",
        urlencoding(link)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
}

// #12 — PII in `download`
#[tokio::test]
async fn get_pii_in_download_url() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let download = "https://shop.example.com/invoices/INV-1.pdf?for=user@example.com&token=gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12";
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fshop.example.com%2Faccount&download={}",
        urlencoding(download)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
    assert!(!body.contains("gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12"));
}

// #13 — PII in ecommerce order ID `ec_id`
#[tokio::test]
async fn get_pii_in_ecommerce_order_id() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fshop.example.com%2Fthanks&idgoal=0&ec_id={}&revenue=42.00",
        urlencoding("order-jane.doe@example.com-2026-05-01")
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
}

// #14 — PII in `ec_items` JSON
#[tokio::test]
async fn get_pii_in_ecommerce_items() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let items = r#"[["SKU-1","Custom engraving — Vorname: Hans","gifts",99.0,1]]"#;
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fshop.example.com%2Fthanks&idgoal=0&ec_id=T-12345&revenue=99.00&ec_items={}",
        urlencoding(items)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("Hans"));
}

// #15 — PII in URL path via `url`
#[tokio::test]
async fn get_pii_in_url_path_via_url() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let url = "https://app.example.com/users/user@example.com/profile";
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url={}",
        urlencoding(url)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
    assert!(!body.contains("user%40example.com"));
}

// #16 — Form GET submission leaking email into URL
#[tokio::test]
async fn get_form_get_submission_in_url() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let url = "https://app.example.com/login?email=user@example.com&password=hunter2";
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url={}",
        urlencoding(url)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
}

// #17 — Password-reset URL leak
#[tokio::test]
async fn get_password_reset_url_leak() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let url = "https://app.example.com/reset?token=gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12&email=user@example.com";
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url={}",
        urlencoding(url)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
    assert!(!body.contains("gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12"));
}

// #18 — Referrer-chain leak via urlref
#[tokio::test]
async fn get_referrer_chain_leak() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let url = "https://blog.example.com/article";
    let urlref = "https://app.example.com/reset?token=gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12&email=user@example.com";
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url={}&urlref={}",
        urlencoding(url),
        urlencoding(urlref)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
    assert!(!body.contains("gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12"));
}

// #19 — POST form-encoded body. Body redaction must be percent-encoded.
#[tokio::test]
async fn post_form_body_pii_in_action_name() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let body = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2F&action_name={}",
        urlencoding("Order confirmation for jane.doe@example.com")
    );
    let (status, echoed) = post_matomo_form(&proxy, &body).await;
    assert_eq!(status, 200);
    assert!(!echoed.contains("jane.doe@example.com"));
    assert!(!echoed.contains("jane.doe%40example.com"));
    assert!(
        !echoed.contains("[EMAIL]"),
        "form body must have percent-encoded redaction label. Body:\n{echoed}"
    );
}

// #20 — Bulk endpoint with PII spread across multiple requests
#[tokio::test]
async fn bulk_redacts_pii_across_multiple_requests() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "requests": [
            "?idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fshop.example.com%2F&action_name=Home",
            "?idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fshop.example.com%2Fthanks&idgoal=0&ec_id=order-user%40example.com&revenue=9",
            "?idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fshop.example.com%2Flogs&action_name=SSN%3A%20123-45-6789%20found",
        ],
        "token_auth": "33dc3f2536d3025974cccb4b4d2d98f4",
    });
    let (status, body) = post_matomo_bulk(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
    assert!(!body.contains("user%40example.com"));
    assert!(!body.contains("123-45-6789"));
    assert!(body.contains("Home"));
}

// #21 — Crash analytics `cra`
#[tokio::test]
async fn get_pii_in_crash_message() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2F&cra={}",
        urlencoding("AuthError for user user@example.com — token expired")
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
}

// #22 — Crash analytics stack trace `cra_st`
#[tokio::test]
async fn get_pii_in_crash_stack_trace() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let stack = "AuthError at /login\n  email=jane.doe@example.com\n  src IP: 10.0.0.255 ok\n  key: AKIAIOSFODNN7EXAMPLE";
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2F&cra=AuthError&cra_st={}",
        urlencoding(stack)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
    assert!(!body.contains("10.0.0.255"));
    assert!(!body.contains("AKIAIOSFODNN7EXAMPLE"));
}

// #23 — Crash analytics source-file URI `cra_ru`
#[tokio::test]
async fn get_pii_in_crash_source_uri() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let cra_ru = "https://cdn.example.com/app.js?token=gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12";
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2F&cra=Boom&cra_ru={}&cra_rl=42",
        urlencoding(cra_ru)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12"));
}

// #24 — Block action on event name with PII
#[tokio::test]
async fn block_on_event_with_pii_in_event_name() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, block_request(), empty_dir()).await;

    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2F&e_c=newsletter&e_a=signup&e_n={}",
        urlencoding("user@example.com")
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 403);
    assert!(!body.contains("user@example.com"));
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

// #25 — Header action adds X-PII-Detected
#[tokio::test]
async fn header_action_adds_x_pii_detected() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, header_request(), empty_dir()).await;

    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2F&action_name={}",
        urlencoding("hi user@example.com")
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(body.to_lowercase().contains("x-pii-detected"));
    assert!(body.to_lowercase().contains("email"));
}

// #26 — Heatmap content-piece leak (`c_p`)
#[tokio::test]
async fn get_pii_in_content_piece() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2Fcontact&c_n=ContactForm&c_p={}&c_i=keystroke",
        urlencoding("phone: 5551234567")
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("5551234567"));
}

// #27 — Dimension filled from a form field
#[tokio::test]
async fn get_dimension_filled_from_form_field() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2F&dimension5={}",
        urlencoding("user@example.com")
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
    assert!(!body.contains("user%40example.com"));
}

// #28 — Mixed kinds in a single `url` parameter
#[tokio::test]
async fn get_catches_multiple_kinds_in_url() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let url =
        "https://app.example.com/p?phone=5551234567&card=4111 1111 1111 1111&id=SSN: 123-45-6789";
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url={}",
        urlencoding(url)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("5551234567"));
    assert!(!body.contains("4111 1111 1111 1111"));
    assert!(!body.contains("123-45-6789"));
}

// #29 — Legacy /piwik.php alias (operator routes both paths to the same
// specialization; the spec itself is path-agnostic).
#[tokio::test]
async fn legacy_piwik_php_alias_is_scanned() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let client = reqwest::Client::new();
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2F&action_name={}",
        urlencoding("hello user@example.com")
    );
    let resp = client
        .get(proxy.url(&format!("/piwik.php?{q}")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(!body.contains("user@example.com"));
}

// ---------------------------------------------------------------------------
// Negative / clean pass-through tests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn clean_get_passes_through_unchanged() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fshop.example.com%2Fpricing&action_name=Pricing&res=1920x1080&h=14&m=22&s=09";
    let (status, body) = get_matomo(&proxy, q).await;
    assert_eq!(status, 200);
    assert!(body.contains("action_name=Pricing"));
    assert!(body.contains("https%3A%2F%2Fshop.example.com%2Fpricing"));
}

#[tokio::test]
async fn clean_bulk_passes_through_unchanged() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "requests": [
            "?idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fshop.example.com%2Fpricing&action_name=Pricing"
        ],
        "token_auth": "33dc3f2536d3025974cccb4b4d2d98f4",
    });
    let (status, body) = post_matomo_bulk(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(body.contains("action_name=Pricing"));
    assert!(body.contains("33dc3f2536d3025974cccb4b4d2d98f4"));
}

#[tokio::test]
async fn auto_generated_visitor_id_does_not_trigger_pii() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, header_request(), empty_dir()).await;

    let q = "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&rand=987654321&url=https%3A%2F%2Fshop.example.com%2Fpricing&action_name=Pricing&res=1920x1080";
    let (status, body) = get_matomo(&proxy, q).await;
    assert_eq!(status, 200);
    assert!(!body.to_lowercase().contains("x-pii-detected"));
}

// ---------------------------------------------------------------------------
// Phase 16.7 — focused reverse-proxy wiring tests
// ---------------------------------------------------------------------------

/// 16.7 request-side wiring: a route configured with `specialization = "matomo"`
/// must run a doubly-encoded `url=` value through the Matomo spec, detect the
/// PII inside the inner URL's query, and re-encode the redaction label at both
/// layers (`%255BEMAIL%255D`). Mirrors the bullet in TASKS.md.
#[tokio::test]
async fn matomo_route_redacts_doubly_encoded_url_via_specialization() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let before_errors = pii_proxy::metrics::SPECIALIZATION_ERRORS_TOTAL
        .with_label_values(&["matomo", "decode"])
        .get();

    let inner = "https://shop.example.com/order?email=jane.doe@example.com";
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url={}&action_name=Order",
        urlencoding(inner)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
    // Doubly-encoded because url= is a recursive-URL field.
    assert!(
        body.contains("%255BEMAIL%255D"),
        "expected doubly-encoded EMAIL label in body:\n{body}"
    );

    let after_errors = pii_proxy::metrics::SPECIALIZATION_ERRORS_TOTAL
        .with_label_values(&["matomo", "decode"])
        .get();
    assert_eq!(
        before_errors, after_errors,
        "successful spec processing must not increment the error counter"
    );
}

/// 16.7 response-side wiring: when a route has response actions and the
/// upstream returns `image/gif` (the canonical Matomo tracking-pixel
/// response), the Matomo spec returns `UnsupportedContentType`. That
/// fallback must be silent — no log, no `pii_proxy_specialization_errors_total`
/// increment — because trackers responding with a 1x1 gif is the expected
/// common case on the response path.
#[tokio::test]
async fn matomo_response_gif_silently_falls_back() {
    let upstream = start_matomo_gif_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), redact_response()).await;

    let before_unsupported = pii_proxy::metrics::SPECIALIZATION_ERRORS_TOTAL
        .with_label_values(&["matomo", "unsupported_content_type"])
        .get();
    let before_decode = pii_proxy::metrics::SPECIALIZATION_ERRORS_TOTAL
        .with_label_values(&["matomo", "decode"])
        .get();

    let q = "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fshop.example.com%2Fpricing&action_name=Pricing";
    let resp = reqwest::get(proxy.url(&format!("/matomo.php?{q}")))
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
        .with_label_values(&["matomo", "unsupported_content_type"])
        .get();
    let after_decode = pii_proxy::metrics::SPECIALIZATION_ERRORS_TOTAL
        .with_label_values(&["matomo", "decode"])
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
