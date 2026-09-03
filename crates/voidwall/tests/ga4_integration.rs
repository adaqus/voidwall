//! Integration tests for GA4 (Google Analytics 4) traffic shapes.
//!
//! GA4 itself is not a special case in the proxy — these tests assert that
//! realistic GA4 collection requests, with PII placed in the integrator-
//! controlled fields where leaks happen in the wild, are caught by the
//! standard reverse-proxy scanner. Auto-generated GA4 fields (cid, sid, _et,
//! tid, api_secret, …) are explicitly excluded.
//!
//! Two GA4 wire formats are exercised:
//!   * `/g/collect` — `gtag.js` browser endpoint. Short keys (`dl`, `dt`,
//!     `dr`, `en`, `ep.foo`, `up.bar`) carried in URL query string and/or
//!     `application/x-www-form-urlencoded` body.
//!   * `/mp/collect` — server-side Measurement Protocol. JSON body with
//!     `events`, `user_properties`, `user_data`, `items` schema.

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::any;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use test_case::test_case;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use voidwall::config::{
    Action, AppConfig, DirectionConfig, PiiConfig, RedactStrategy, ReverseProxyConfig, Route,
    ScanConfig,
};
use voidwall::reverse_proxy;
use voidwall::scanner::ScannerPool;

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
        countries: voidwall_pii::Country::all().to_vec(),
        languages: voidwall_pii::Language::all().to_vec(),
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
/// Building a `voidwall_pii::Scanner` with all countries + all languages compiles a
/// large set of regex / hyperscan patterns and takes several seconds in
/// debug builds. Sharing one pool across the whole test binary turns that
/// from a per-test cost (×~100) into a one-time cost.
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

/// Send a GA4 `/mp/collect` request with the given JSON payload and return
/// the echoed body the upstream received (for assertion of redacted form).
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

/// Send a GA4 `/g/collect` GET (gtag.js style) with the supplied query string
/// (already percent-encoded by the caller).
async fn get_g_collect(proxy: &TestProxy, query: &str) -> (StatusCode, String) {
    let resp = reqwest::get(proxy.url(&format!("/g/collect?{query}")))
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    (status, body)
}

/// Send a GA4 `/g/collect` POST with a form-encoded body (newer gtag).
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
// PII-kind sweep — every PiiKind in `voidwall_pii::PiiKind::all()` placed in a single
// MP event-param `notes`, asserted to be redacted.
//
// Sample inputs are taken straight from the pii crate's own positive
// `#[test_case]` fixtures so the detector is guaranteed to match. Most kinds
// are keyword-gated, so the keyword (`SSN:`, `NINO:`, etc.) is part of the
// input string.
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
async fn ga4_mp_redacts_pii_in_event_param(input: &str, expected_match: &str) {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        // Placeholder client_id chosen with letters so digit-run fixtures
        // (e.g. CaBankAccount = "1234567890") cannot accidentally collide
        // with the JSON envelope.
        "client_id": "ga-cid-A.B",
        "events": [{
            "name": "page_view",
            "params": { "notes": input }
        }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200, "expected 200 redact-and-forward");
    assert!(
        !body.contains(expected_match),
        "PII value `{expected_match}` leaked through proxy.\nForwarded body:\n{body}"
    );
}

// Same sweep against the gtag.js `/g/collect` endpoint. Runs against a
// representative subset of kinds to verify the URL-encoded query path scans.
// The full sweep above already exercises the JSON body path.
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
        "PII value `{expected_match}` leaked through g/collect.\nForwarded body:\n{body}"
    );
}

// ---------------------------------------------------------------------------
// GA4 field-shape tests — explicit coverage of fields named in real-world
// pitfalls: `dl`, `dt`, `dr`, `uid`, `ep.*`, `up.*`, `user_data`, `items`,
// `exception.description`, `link_url`, `form_destination`, batch endpoint,
// URL-path PII, GET form submissions, password reset URLs, referrer chain.
// ---------------------------------------------------------------------------

// #1 — PII in `dl` (page_location) query string
#[tokio::test]
async fn g_collect_pii_in_page_location_query() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    // Confirmation page leaking the customer email back into the URL.
    let dl = "https://shop.example.com/order/confirmed?email=jane.doe@example.com";
    let q = format!(
        "v=2&tid=G-X&cid=1.1&en=page_view&dl={}&dt=Order%20confirmed",
        urlencoding(dl)
    );
    let (status, body) = get_g_collect(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
    assert!(body.contains("[EMAIL]"));
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

    // Previous page had the email in its query — referrer captures it.
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

// #4 — Raw email in `uid`
#[tokio::test]
async fn g_collect_raw_email_in_uid() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = "v=2&tid=G-X&cid=1.1&en=login&uid=jane.doe%40example.com";
    let (status, body) = get_g_collect(&proxy, q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
    assert!(!body.contains("jane.doe%40example.com"));
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

// #7 — PII in form-encoded POST body of `/g/collect`
#[tokio::test]
async fn g_collect_post_form_body_pii() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    // gtag.js can split params between query and body for batched events.
    let body = "ep.email=jane.doe%40example.com&ep.note=ok";
    let (status, echoed) = post_g_collect_form(&proxy, "v=2&tid=G-X&cid=1.1&en=signup", body).await;
    assert_eq!(status, 200);
    assert!(!echoed.contains("jane.doe@example.com"));
    assert!(!echoed.contains("jane.doe%40example.com"));
}

// #8 — `mp/collect` with raw email in `user_id`
#[tokio::test]
async fn mp_collect_raw_email_in_user_id() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "user_id": "jane.doe@example.com",
        "events": [{ "name": "login", "params": { "method": "email" } }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
}

// #9 — `user_data.email_address` plaintext (devs forget to SHA-256)
#[tokio::test]
async fn mp_collect_plaintext_user_data_email() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "user_data": {
            "email_address": "jane.doe@example.com"
        },
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
        "user_data": {
            "phone_number": "phone: +1 555 123 4567"
        },
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

// #12 — `search_term` with email (the most common search-box leak)
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

// #14 — `items[].item_name` with customer reference (PERSON_NAME)
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
    // PERSON_NAME label should appear; raw "Hans" should not.
    assert!(!body.contains("Hans"));
}

// #15 — `exception.description` with multi-line stack trace containing
//       email, IP, and an AWS access key.
#[tokio::test]
async fn mp_collect_pii_in_exception_description() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let stack = "AuthError at /login\n  email=jane.doe@example.com\n  src IP: 10.0.0.255 ok\n  key: AKIAIOSFODNN7EXAMPLE";
    let payload = json!({
        "client_id": "1.1",
        "events": [{
            "name": "exception",
            "params": {
                "fatal": false,
                "description": stack
            }
        }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("jane.doe@example.com"));
    assert!(!body.contains("10.0.0.255"));
    assert!(!body.contains("AKIAIOSFODNN7EXAMPLE"));
}

// #16 — `ip_override` field carrying a raw client IP
#[tokio::test]
async fn mp_collect_pii_in_ip_override() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "ip_override": "IP: 10.0.0.255 ok",
        "events": [{ "name": "page_view", "params": {} }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("10.0.0.255"));
}

// #17 — `user_location.city` carrying a PERSON_NAME (mistake when the
//       integrator wires the wrong field into the location payload)
#[tokio::test]
async fn mp_collect_person_name_in_user_location() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "user_location": {
            "city": "Vorname: Hans"
        },
        "events": [{ "name": "page_view", "params": {} }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("Vorname: Hans"));
}

// #18 — `mp/collect` with multiple events; PII in one, clean in the other.
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

// #19 — Block action on a `purchase` event with PII in `coupon`. Must return
//       403 with the detected kind list, and must not leak the value.
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

// #20 — Header action: `X-PII-Detected` reflected in the forwarded request.
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

// #21 — PII embedded in URL *path* (SPA routing pattern)
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

// #22 — Form GET submission that put email + a PII-shaped token into URL
#[tokio::test]
async fn g_collect_form_get_submission_in_dl() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    // <form method="get" action="/login"> → URL gets ?email=…&password=…
    // The proxy detects EMAIL; the password field is opaque text.
    let dl = "https://app.example.com/login?email=user@example.com&password=hunter2";
    let q = format!("v=2&tid=G-X&cid=1.1&en=page_view&dl={}", urlencoding(dl));
    let (status, body) = get_g_collect(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
}

// #23 — Password reset URL leak (token + email in dl)
#[tokio::test]
async fn g_collect_password_reset_url_leak() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    // GitHub-style token plus an email — both should be redacted.
    let dl = "https://app.example.com/reset?token=gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12&email=user@example.com";
    let q = format!("v=2&tid=G-X&cid=1.1&en=page_view&dl={}", urlencoding(dl));
    let (status, body) = get_g_collect(&proxy, &q).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
    assert!(!body.contains("gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12"));
}

// #24 — Referrer chain leak: clean current page, prior page leaks via dr.
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

// #26 — `form_destination` carries PII (form action URL with embedded value)
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

// #27 — Custom event param literally named "email" (the canonical GTM
//       mistake of pulling a form input value into a same-named param).
#[tokio::test]
async fn mp_collect_custom_param_named_email() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let payload = json!({
        "client_id": "1.1",
        "events": [{
            "name": "newsletter_signup",
            "params": {
                "email": "user@example.com",
                "source": "footer"
            }
        }]
    });
    let (status, body) = post_mp_collect(&proxy, payload).await;
    assert_eq!(status, 200);
    assert!(!body.contains("user@example.com"));
    // Non-PII key name preserved
    assert!(body.contains("email") || body.contains("[EMAIL]"));
}

// #28 — GA4's own redaction blind spots: phone, credit card, SSN. The
//       proxy should catch all three even though native GA4 redaction
//       targets only emails and a small URL-param allowlist.
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

// #29 — Batch endpoint (`/batch`) carrying multiple events; the request goes
//       through the proxy as one body.
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
// Negative tests — clean GA4 traffic must pass through untouched.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn clean_g_collect_passes_through_unchanged() {
    let upstream = start_ga4_upstream().await;
    let proxy = TestProxy::start(upstream, redact_request(), empty_dir()).await;

    let q = "v=2&tid=G-X&cid=1234567890.1234567890&en=page_view&dl=https%3A%2F%2Fshop%2Eexample%2Ecom%2Fpricing&dt=Pricing";
    let (status, body) = get_g_collect(&proxy, q).await;
    assert_eq!(status, 200);
    // The page title and clean URL pieces must survive verbatim.
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
