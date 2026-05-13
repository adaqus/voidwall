//! Integration tests for Matomo (formerly Piwik) traffic shapes.
//!
//! Matomo is not a special case in the proxy — these tests assert that
//! realistic Matomo Tracking HTTP API requests, with PII placed in the
//! integrator-controlled fields where leaks happen in the wild, are caught by
//! the standard reverse-proxy scanner. Auto-generated Matomo fields (`_id` /
//! `cid`, `rand`, `apiv`, `rec`, `res`, `h`/`m`/`s`, etc.) are explicitly
//! excluded.
//!
//! Three Matomo wire shapes are exercised:
//!   * `/matomo.php` GET — the canonical browser endpoint. Parameters are
//!     URL-encoded query string (`url`, `action_name`, `urlref`, `_cvar`,
//!     `dimension1`, `e_c`, `e_a`, …).
//!   * `/matomo.php` POST `application/x-www-form-urlencoded` — same parameter
//!     set carried in the body (used by SDKs and some GTM containers).
//!   * `/matomo.php` POST JSON bulk — `{"requests": ["?…", …], "token_auth":
//!     "…"}` envelope used for server-side and offline batch tracking.
//!
//! The `/piwik.php` legacy alias is also exercised to confirm the proxy
//! treats it the same as `/matomo.php`.

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

fn empty_dir() -> DirectionConfig {
    direction(vec![], None)
}

/// Single ScannerPool shared by every test in this binary.
///
/// Building a `pii::Scanner` with all countries + all languages compiles a
/// large set of regex / hyperscan patterns and takes several seconds in
/// debug builds. Sharing one pool across the whole test binary turns that
/// from a per-test cost (×128) into a one-time cost.
///
/// The pool is owned by this `LazyLock`, so its `Arc` refcount never drops
/// to zero while tests are running and `ScannerPool::shutdown` is not
/// invoked between tests. Each `TestProxy` clones the `Arc`.
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

/// Send a Matomo `/matomo.php` GET (browser tracker style) with the supplied
/// query string (already percent-encoded by the caller).
async fn get_matomo(proxy: &TestProxy, query: &str) -> (StatusCode, String) {
    let resp = reqwest::get(proxy.url(&format!("/matomo.php?{query}")))
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    (status, body)
}

/// Send a Matomo `/matomo.php` POST with a form-encoded body (gtag/SDK-style
/// where the JS tracker promotes long URLs to POST).
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

/// Send a Matomo bulk-tracking POST (JSON envelope with `requests` array and
/// optional `token_auth`).
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
// PII-kind sweep — every PiiKind in `pii::PiiKind::all()` placed into a
// Matomo bulk request's `action_name`, asserted to be redacted.
//
// Sample inputs are taken from the pii crate's positive `#[test_case]`
// fixtures so the detector is guaranteed to match. Most kinds are
// keyword-gated, so the keyword (`SSN:`, `NINO:`, etc.) is part of the input.
//
// The fixture is placed RAW inside the bulk JSON envelope (no inner URL
// encoding of the `action_name` value). This matches what the body scanner
// sees from JSON-bodied SDKs and avoids the pii crate's percent-decoder
// limitation: `decode_for_detection` only converts `%XX` sequences whose
// byte falls in printable ASCII (0x20..=0x7e), so the URL-encoded form of
// non-ASCII keyword characters (`%C3%A9` for `é`, `%C3%A7` for `ç`,
// `%C2%B0` for `°`) is not restored before keyword matching. Sending the
// fixture raw side-steps that and exercises the JSON-body path the same way
// the GA4 `/mp/collect` sweep does.
// ---------------------------------------------------------------------------

#[test_case("phone: +43 1 2345678", "+43 1 2345678" ; "AtPhoneNumber")]
#[test_case("PLZ: 1010", "1010" ; "AtPostalCode")]
#[test_case("SVNR: 1238150185", "1238150185" ; "AtSvnr")]
#[test_case("ABN: 51 824 753 556", "51 824 753 556" ; "AuAbn")]
#[test_case("BSB: 012-345", "012-345" ; "AuBankAccount")]
#[test_case("tas licence: A12345", "A12345" ; "AuDriversLicense")]
#[test_case("Medicare: 2123 45670 1", "2123 45670 1" ; "AuMedicare")]
#[test_case("passport number: B7654321", "B7654321" ; "AuPassportNumber")]
#[test_case("phone: 04 1234 5678", "04 1234 5678" ; "AuPhoneNumber")]
#[test_case("TFN: 123456782", "123456782" ; "AuTfn")]
#[test_case("key: AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE" ; "AwsAccessKey")]
#[test_case(
    "secret_access_key: abcdefghijklmnopqrstuvwxyz0123456789ABCD",
    "abcdefghijklmnopqrstuvwxyz0123456789ABCD" ; "AwsSecretKey"
)]
#[test_case(
    "send to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf Na",
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf" ; "BitcoinAddress"
)]
#[test_case("chequing account: 1234567890", "1234567890" ; "CaBankAccount")]
#[test_case("OHIP: 1234567897", "1234567897" ; "CaOhip")]
#[test_case("passport number: XY987654", "XY987654" ; "CaPassportNumber")]
#[test_case("postal code: K1A0B1", "K1A0B1" ; "CaPostalCode")]
#[test_case("SIN: 130-692-544", "130-692-544" ; "CaSin")]
#[test_case("OASI: 756.3026.0705.92", "756.3026.0705.92" ; "ChAhv")]
#[test_case("phone: +41 44 668 18 00", "+41 44 668 18 00" ; "ChPhoneNumber")]
#[test_case("PLZ: 8001", "8001" ; "ChPostalCode")]
#[test_case("card: 36227206271667", "36227206271667" ; "CreditCard")]
#[test_case("dob: 1990-03-15", "1990-03-15" ; "DateOfBirth")]
#[test_case("Wohnadresse: Bundesplatz 3, 3003 Bern", "Bundesplatz 3, 3003 Bern" ; "DeAtChAddress")]
#[test_case("PF: 56, 4020 Linz", "56, 4020 Linz" ; "DeAtChPostfach")]
#[test_case("Postfiliale: 502, 10115 Berlin", "502, 10115 Berlin" ; "DePackstation")]
#[test_case("Pass-Nr.: C01X00T47", "C01X00T47" ; "DePassportNumber")]
#[test_case("Ausweisnummer: T220001293", "T220001293" ; "DePersonalausweis")]
#[test_case("Festnetz: 030 12345678", "030 12345678" ; "DePhoneNumber")]
#[test_case("PLZ: 80331", "80331" ; "DePostalCode")]
#[test_case("IdNr: 26954371827", "26954371827" ; "DeSteuerId")]
#[test_case("contact us at user@example.com for info", "user@example.com" ; "Email")]
#[test_case(
    "wallet: 0x1234567890abcdef1234567890abcdef12345678",
    "0x1234567890abcdef1234567890abcdef12345678" ; "EthereumAddress"
)]
#[test_case(
    "adresse: 86 quai Perrache, 69002 Lyon",
    "86 quai Perrache, 69002 Lyon" ; "FrChAddress"
)]
#[test_case("CP: 440, 1211 Genève", "440, 1211 Genève" ; "FrChBoitePostale")]
#[test_case("carte d'identité: 123456789012", "123456789012" ; "FrCni")]
#[test_case("permis de conduire: 123456789012", "123456789012" ; "FrDriversLicense")]
#[test_case("numéro fiscal: 0123456789012", "0123456789012" ; "FrNif")]
#[test_case("n° sécu: 175012A00403288", "175012A00403288" ; "FrNir")]
#[test_case("passeport français: 05AB12345", "05AB12345" ; "FrPassportNumber")]
#[test_case("fixe: 01 23 45 67 89", "01 23 45 67 89" ; "FrPhoneNumber")]
#[test_case("CP: 13001", "13001" ; "FrPostalCode")]
#[test_case("SIREN: 732829320", "732829320" ; "FrSiren")]
#[test_case("SIRET: 73282932000074", "73282932000074" ; "FrSiret")]
#[test_case(
    "billing address: 30 St Mary Axe, London EC3A 8BF",
    "30 St Mary Axe, London EC3A 8BF" ; "GbAddress"
)]
#[test_case("DL: JONES901157A99Y1", "JONES901157A99Y1" ; "GbDrivingLicence")]
#[test_case("NHS: 943 476 5919", "943 476 5919" ; "GbNhsNumber")]
#[test_case("NINO: AB123456C", "AB123456C" ; "GbNino")]
#[test_case("phone: 07700 900123", "07700 900123" ; "GbPhoneNumber")]
#[test_case("postcode: M1 1AE", "M1 1AE" ; "GbPostcode")]
#[test_case("Sort code: 200000", "200000" ; "GbSortCode")]
#[test_case("UTR: 5555555555", "5555555555" ; "GbUtr")]
#[test_case("uk passport: 987654321", "987654321" ; "GbZaPassportNumber")]
#[test_case(
    "token: gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12",
    "gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12" ; "GithubToken"
)]
#[test_case("IBAN: GB29 NWBK 6016 1331 9268 19", "GB29 NWBK 6016 1331 9268 19" ; "Iban")]
#[test_case("driverNumber=123456789", "123456789" ; "IeDriverNumber")]
#[test_case("Eircode D02X285", "D02X285" ; "IeEircode")]
#[test_case("irish passport: AB1234567", "AB1234567" ; "IePassportNumber")]
#[test_case("phone: 01 234 5678", "01 234 5678" ; "IePhoneNumber")]
#[test_case("PPSN: 1234567T", "1234567T" ; "IePpsn")]
#[test_case("IMEI: 490154203237518", "490154203237518" ; "Imei")]
#[test_case("IP: 10.0.0.255 ok", "10.0.0.255" ; "IpAddress")]
#[test_case("MAC: 001A.2B3C.4D5E", "001A.2B3C.4D5E" ; "MacAddress")]
#[test_case("licence number: AB123456", "AB123456" ; "NzDriverLicence")]
#[test_case("IRD: 49091857", "49091857" ; "NzIrdNumber")]
#[test_case("NHI: DAB8745", "DAB8745" ; "NzNhiNumber")]
#[test_case("nz passport: L1234567", "L1234567" ; "NzPassportNumber")]
#[test_case("phone: 02 123 4567", "02 123 4567" ; "NzPhoneNumber")]
#[test_case("passport: 987654321", "987654321" ; "PassportNumber")]
#[test_case("Vorname: Hans", "Hans" ; "PersonName")]
#[test_case("Standort: 48.1351,11.5820", "48.1351,11.5820" ; "PreciseGeolocation")]
#[test_case("SWIFT: DEUTDEFF", "DEUTDEFF" ; "SwiftBic")]
#[test_case("ach routing: 111000025", "111000025" ; "UsAbaRouting")]
#[test_case("alienNumber=A012345678", "A012345678" ; "UsAlienNumber")]
#[test_case("DL: B1234568", "B1234568" ; "UsDriversLicense")]
#[test_case("EIN: 12-3456789", "12-3456789" ; "UsEin")]
#[test_case("ITIN: 912-70-1234", "912-70-1234" ; "UsItin")]
#[test_case("Passport: A12345678", "A12345678" ; "UsPassportNew")]
#[test_case("phone: 5551234567", "5551234567" ; "UsPhoneNumber")]
#[test_case("SSN: 123-45-6789", "123-45-6789" ; "UsSsn")]
#[test_case("uscis_receipt SRC2190000001", "SRC2190000001" ; "UsUscisReceiptNumber")]
#[test_case("zip: 90210", "90210" ; "UsZaPostalCode")]
#[test_case("VIN: 1HGBH41JXMN109186", "1HGBH41JXMN109186" ; "Vin")]
#[test_case("driver's licence: 8001015009087", "8001015009087" ; "ZaDriversLicense")]
#[test_case("SA ID: 8001015009087", "8001015009087" ; "ZaId")]
#[test_case("phone: 071 123 4567", "071 123 4567" ; "ZaPhoneNumber")]
#[test_case("SARS: 9876543210" , "9876543210" ; "ZaTaxReference")]
#[tokio::test]
async fn matomo_bulk_redacts_pii_in_action_name(input: &str, expected_match: &str) {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    // One bulk request whose `action_name` carries the PII fixture. The
    // visitor id `_id` is a 16-char hex string that no detector should match.
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
    assert_eq!(status, 200, "expected 200 redact-and-forward");
    assert!(
        !body.contains(expected_match),
        "PII value `{expected_match}` leaked through Matomo bulk.\nForwarded body:\n{body}"
    );
}

// Same sweep against the GET `/matomo.php` endpoint. Runs against a
// representative subset of kinds to verify the URL-encoded query path scans.
#[test_case("contact us at user@example.com for info", "user@example.com" ; "Email")]
#[test_case("SSN: 123-45-6789", "123-45-6789" ; "UsSsn")]
#[test_case("card: 4111 1111 1111 1111", "4111 1111 1111 1111" ; "CreditCard")]
#[test_case("IBAN: GB29 NWBK 6016 1331 9268 19", "GB29 NWBK 6016 1331 9268 19" ; "Iban")]
#[test_case("IP: 10.0.0.255 ok", "10.0.0.255" ; "IpAddress")]
#[test_case("MAC: 001A.2B3C.4D5E", "001A.2B3C.4D5E" ; "MacAddress")]
#[test_case("NINO: AB123456C", "AB123456C" ; "GbNino")]
#[test_case("key: AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE" ; "AwsAccessKey")]
#[test_case(
    "wallet: 0x1234567890abcdef1234567890abcdef12345678",
    "0x1234567890abcdef1234567890abcdef12345678" ; "EthereumAddress"
)]
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
        "PII value `{expected_match}` leaked through /matomo.php.\nForwarded body:\n{body}"
    );
}

// ---------------------------------------------------------------------------
// Field-shape tests — explicit coverage of fields named in real-world Matomo
// pitfalls. The Matomo team's own PII guide flags page URLs, page titles,
// referrer URLs, custom variables, custom dimensions, ecommerce order IDs
// and the user ID as the highest-risk fields:
// https://matomo.org/blog/2018/04/how-to-not-process-any-personal-data-with-matomo-and-what-it-means-for-you/
// ---------------------------------------------------------------------------

// #1 — PII in `url` query string (e-commerce confirmation URL).
//      WooCommerce/Magento order-confirmation pages frequently echo the
//      customer's email back into the page URL.
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
    assert!(body.contains("[EMAIL]"));
}

// #2 — PII in `action_name` (page title). The canonical "Order confirmation
//      for jane@example.com" pattern emitted by templating engines that
//      interpolate the customer's email into <title>.
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

// #3 — PII in `urlref` (referrer). The previous page's URL had the email;
//      the browser sends it as Referer and Matomo records it verbatim.
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

// #4 — Raw email in `uid` (User ID). Matomo's own PII guide explicitly calls
//      out using the email as a User ID as a violation: the User ID needs to
//      be a non-identifying surrogate.
#[tokio::test]
async fn get_raw_email_in_uid() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2F&action_name=Login&uid=jane.doe%40example.com";
    let (status, body) = get_matomo(&proxy, q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
    assert!(!body.contains("jane.doe%40example.com"));
}

// #5 — PII in a visit-scope custom variable `_cvar`. The Matomo doc warns
//      that custom variables are a frequent vector for inadvertent personal
//      data because integrators wire the wrong field into them.
#[tokio::test]
async fn get_pii_in_visit_scope_cvar() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    // _cvar is a JSON object indexed by slot number: {"1":["key","value"], …}
    let cvar = r#"{"1":["customer","jane.doe@example.com"],"2":["plan","gold"]}"#;
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fapp.example.com%2F&_cvar={}",
        urlencoding(cvar)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
}

// #6 — PII in a page-scope custom variable `cvar`. Same shape, different
//      scope; covers the case where the leak is attached to a single page
//      view rather than the whole visit.
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

// #7 — PII in a custom dimension. `dimension1`..`dimension999` are
//      free-form integrator-defined slots.
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
    // Non-PII dimension survives.
    assert!(body.contains("plan-gold"));
}

// #8 — PII in event params. `e_c` (category), `e_a` (action), `e_n` (name),
//      `e_v` (value). The classic GTM mistake is binding `e_n` to a form
//      field's value rather than its label.
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

// #9 — PII in `search` (site search keyword). Users routinely paste their own
//      email or order number into search boxes; Matomo records the literal
//      query.
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

// #10 — PII in `search_cat` (search category). Same shape as `search` but
//       a different leak vector — usually populated from a dropdown that
//       was prefilled with user data.
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

// #11 — PII in `link` (outlink). When a user clicks a partner-redirect URL
//       that already contains their email as a query parameter, Matomo's
//       outlink tracker records the destination URL verbatim.
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

// #12 — PII in `download`. A "download invoice" link that signs the URL with
//       the customer's email and an HMAC token (GitHub-style PAT).
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

// #13 — PII in ecommerce order ID `ec_id`. Matomo's PII guide flags order
//       IDs as a known PII vector when the ID is constructed from customer
//       data rather than a surrogate key.
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

// #14 — PII in ecommerce items `ec_items` JSON. Custom-engraved items leak
//       customer names into product names (PERSON_NAME).
#[tokio::test]
async fn get_pii_in_ecommerce_items() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    // ec_items is a JSON array: [[sku, name, category, price, quantity], …]
    let items = r#"[["SKU-1","Custom engraving — Vorname: Hans","gifts",99.0,1]]"#;
    let q = format!(
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fshop.example.com%2Fthanks&idgoal=0&ec_id=T-12345&revenue=99.00&ec_items={}",
        urlencoding(items)
    );
    let (status, body) = get_matomo(&proxy, &q).await;
    assert_eq!(status, 200);
    // Raw German "Hans" must not survive; PERSON_NAME redaction marker should.
    assert!(!body.contains("Hans"));
}

// #15 — PII in URL path segment via `url`. SPA routing pattern that puts
//       the email into the path itself (`/users/<email>`) rather than a
//       query parameter.
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

// #16 — Form GET submission that leaked email + password into the URL the
//       user landed on after submit. Common with `<form method="get">`.
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

// #17 — Password-reset URL leak: the reset link has an email + GitHub-style
//       token in the query string, which the JS tracker then sends to
//       Matomo as the page URL.
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

// #18 — Referrer-chain leak: the current page URL is clean but the prior
//       page (sent in `urlref`) had the email + token.
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

// #19 — POST form-encoded body. The Matomo JS tracker promotes long
//       requests (>2KB on most browsers) from GET to POST with the same
//       parameters in `application/x-www-form-urlencoded` body.
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
}

// #20 — Bulk endpoint: multiple events in one POST, PII spread across them.
//       Confirms the proxy scans the whole body, not just the first request.
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
    // Clean parts survive.
    assert!(body.contains("Home"));
}

// #21 — Crash analytics `cra` (error message) carries an email.
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

// #22 — Crash analytics stack trace `cra_st` carries multiple PII kinds.
//       Real stack traces from prod often capture request headers and env
//       in their breadcrumbs.
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

// #23 — Crash analytics source-file URI `cra_ru` carries a token. Source
//       maps fetched from a signed CDN URL include the token in `cra_ru`.
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

// #24 — Block action on an event that carries PII in the event name. Must
//       return 403 with the detected kind list, and must not leak the value.
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

// #25 — Header action: `X-PII-Detected` is forwarded with the detected kind
//       names so the upstream can log/quarantine.
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

// #26 — Heatmap / form-input leak. Matomo's heatmap tracker streams form
//       field values into the standard tracker as content interactions
//       (`c_n` / `c_p` / `c_t` / `c_i`). When a heatmap accidentally
//       captures a non-masked input, the value lands in `c_p` (content
//       piece).
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

// #27 — Custom dimension literally named with the form field's name. A
//       common GTM mistake: a Matomo tag pulls `{{Form Field - email}}`
//       directly into `dimension5`, sending the raw value rather than a
//       hash.
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

// #28 — Mixed kinds in a single `url` parameter — the proxy must catch
//       phone, credit card, and SSN simultaneously even though the Matomo
//       core has no built-in redaction for any of them.
#[tokio::test]
async fn get_catches_multiple_kinds_in_url() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    // Use raw colons/spaces in the inner URL so a single round of
    // percent-encoding by `urlencoding()` produces the wire-form `%3A`/`%20`
    // exactly once. Double-encoding would leave the proxy looking at
    // `%253A`, which the percent decoder cannot recover.
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

// #29 — Legacy `/piwik.php` alias. Matomo was renamed from Piwik in 2018
//       and many deployed JS trackers still post to the old path.
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
// Negative tests — clean Matomo traffic must pass through untouched, and
// auto-generated identifier shapes must not trigger any detector.
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

// Auto-generated `_id` (16-char hex) and `rand` must not match any PII
// detector — confirms there is no false positive on the identifier shapes
// that Matomo itself emits.
#[tokio::test]
async fn auto_generated_visitor_id_does_not_trigger_pii() {
    let upstream = start_matomo_upstream().await;
    let proxy = TestProxy::start(upstream, header_request(), empty_dir()).await;

    let q = "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&rand=987654321&url=https%3A%2F%2Fshop.example.com%2Fpricing&action_name=Pricing&res=1920x1080";
    let (status, body) = get_matomo(&proxy, q).await;
    assert_eq!(status, 200);
    // Header action only adds X-PII-Detected when something matched.
    assert!(!body.to_lowercase().contains("x-pii-detected"));
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal application/x-www-form-urlencoded percent-encoder for the chars
/// that matter in test inputs (avoids pulling in `url` as a dev-dep).
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
