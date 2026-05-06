use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use pii_proxy::config::{AppConfig, HttpApiConfig, OnError, PiiConfig, RedactStrategy, ScanConfig};
use pii_proxy::http_api;
use pii_proxy::scanner::ScannerPool;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Shared scanner & helpers
// ---------------------------------------------------------------------------

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

static SHARED_SCANNER: LazyLock<Arc<ScannerPool>> =
    LazyLock::new(|| Arc::new(ScannerPool::new(&default_pii_config()).unwrap()));

async fn wait_for_port(addr: SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("server did not start on {addr}");
}

struct TestApi {
    addr: SocketAddr,
    cancel: CancellationToken,
}

impl TestApi {
    async fn start() -> Self {
        Self::start_with(ScanConfig::default(), Some(RedactStrategy::TypeLabel), None).await
    }

    async fn start_with(
        scan: ScanConfig,
        redact_strategy: Option<RedactStrategy>,
        mask_char: Option<char>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let config = AppConfig {
            pii: default_pii_config(),
            scan,
            reverse_proxy: Default::default(),
            forward_proxy: Default::default(),
            http_api: HttpApiConfig {
                enabled: true,
                listen: addr.to_string(),
                redact_strategy,
                mask_char,
            },
            admin: Default::default(),
            shutdown_timeout_secs: 30,
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let scanner = SHARED_SCANNER.clone();

        tokio::spawn(async move {
            http_api::serve(&config, scanner, cancel_clone)
                .await
                .unwrap();
        });

        wait_for_port(addr).await;

        TestApi { addr, cancel }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

impl Drop for TestApi {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

// ---------------------------------------------------------------------------
// /v1/scan tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_text_plain_detects_email() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(api.url("/v1/scan"))
        .header("content-type", "text/plain")
        .body("contact me at user@example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["detected"], true);
    assert!(json["matches_count"].as_u64().unwrap() >= 1);
    let kinds: Vec<String> = json["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(kinds.contains(&"EMAIL".to_string()));
}

#[tokio::test]
async fn scan_text_plain_no_pii() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(api.url("/v1/scan"))
        .header("content-type", "text/plain")
        .body("nothing sensitive here")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["detected"], false);
    assert_eq!(json["matches_count"], 0);
    assert!(json["kinds"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn scan_application_json_nested_keys_and_arrays() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let body = r#"{"user":{"phone_number":"555-123-4567"},"emails":["a@b.com","x@y.com"]}"#;
    let resp = client
        .post(api.url("/v1/scan"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["detected"], true);
    let kinds: Vec<String> = json["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(kinds.contains(&"EMAIL".to_string()));
    assert!(kinds.contains(&"US_PHONE_NUMBER".to_string()));
}

#[tokio::test]
async fn scan_text_csv_with_headers() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let body = "name,phone_number\nAda,555-123-4567";
    let resp = client
        .post(api.url("/v1/scan"))
        .header("content-type", "text/csv")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["detected"], true);
    let kinds: Vec<String> = json["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(kinds.contains(&"US_PHONE_NUMBER".to_string()));
}

#[tokio::test]
async fn scan_text_tsv_with_headers() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let body = "name\tphone_number\nAda\t555-123-4567";
    let resp = client
        .post(api.url("/v1/scan"))
        .header("content-type", "text/tab-separated-values")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["detected"], true);
    let kinds: Vec<String> = json["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(kinds.contains(&"US_PHONE_NUMBER".to_string()));
}

// ---------------------------------------------------------------------------
// /v1/redact tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn redact_text_plain_replaces_pii() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(api.url("/v1/redact"))
        .header("content-type", "text/plain")
        .body("contact user@example.com today")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-type").unwrap(), "text/plain");
    let detected = resp
        .headers()
        .get("x-pii-detected")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(detected.contains("EMAIL"));
    let count: u64 = resp
        .headers()
        .get("x-pii-redacted-count")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(count >= 1);

    let body = resp.text().await.unwrap();
    assert!(body.contains("[EMAIL]"));
    assert!(!body.contains("user@example.com"));
}

#[tokio::test]
async fn redact_application_json_preserves_valid_json() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let body = r#"{"user":{"phone_number":"555-123-4567"}}"#;
    let resp = client
        .post(api.url("/v1/redact"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/json"
    );
    assert!(
        resp.headers()
            .get("x-pii-detected")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("US_PHONE_NUMBER")
    );

    let body_bytes = resp.bytes().await.unwrap();
    // Must still be valid JSON.
    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(parsed["user"]["phone_number"], "[US_PHONE_NUMBER]");
}

#[tokio::test]
async fn redact_text_csv_preserves_delimiter_structure() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let body = "name,phone_number\nAda,555-123-4567";
    let resp = client
        .post(api.url("/v1/redact"))
        .header("content-type", "text/csv")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-type").unwrap(), "text/csv");

    let text = resp.text().await.unwrap();
    // Header row preserved verbatim, data row contains the redaction.
    assert!(text.starts_with("name,phone_number\nAda,"));
    assert!(text.contains("[US_PHONE_NUMBER]"));
    assert!(!text.contains("555-123-4567"));
}

#[tokio::test]
async fn redact_text_tsv_preserves_tabs() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let body = "name\tphone_number\nAda\t555-123-4567";
    let resp = client
        .post(api.url("/v1/redact"))
        .header("content-type", "text/tab-separated-values")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/tab-separated-values"
    );

    let text = resp.text().await.unwrap();
    assert!(text.starts_with("name\tphone_number\nAda\t"));
    assert!(text.contains("[US_PHONE_NUMBER]"));
    assert!(!text.contains("555-123-4567"));
}

#[tokio::test]
async fn redact_no_pii_omits_x_pii_detected() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(api.url("/v1/redact"))
        .header("content-type", "text/plain")
        .body("nothing sensitive here")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("x-pii-detected").is_none());
    let count = resp
        .headers()
        .get("x-pii-redacted-count")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(count, "0");

    let body = resp.text().await.unwrap();
    assert_eq!(body, "nothing sensitive here");
}

// ---------------------------------------------------------------------------
// Error / fallback paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unsupported_content_type_returns_415() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(api.url("/v1/scan"))
        .header("content-type", "image/png")
        .body("ignored")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 415);
}

#[tokio::test]
async fn oversized_body_returns_413() {
    let scan = ScanConfig {
        max_body_size: 64,
        ..ScanConfig::default()
    };
    let api = TestApi::start_with(scan, Some(RedactStrategy::TypeLabel), None).await;

    let big = "x".repeat(1024);
    let client = reqwest::Client::new();
    let resp = client
        .post(api.url("/v1/scan"))
        .header("content-type", "text/plain")
        .body(big)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 413);
}

#[tokio::test]
async fn malformed_json_returns_400() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(api.url("/v1/scan"))
        .header("content-type", "application/json")
        .body("{not valid json")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn malformed_json_on_redact_returns_400() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(api.url("/v1/redact"))
        .header("content-type", "application/json")
        .body("{not valid json")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn malformed_json_with_fail_open_still_returns_400() {
    // The HTTP API rejects malformed structured bodies regardless of on_error
    // (the caller declared the type, so silently degrading would mask a bug).
    let scan = ScanConfig {
        on_error: OnError::FailOpen,
        ..ScanConfig::default()
    };
    let api = TestApi::start_with(scan, Some(RedactStrategy::TypeLabel), None).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(api.url("/v1/scan"))
        .header("content-type", "application/json")
        .body("{not valid json")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn csv_without_headers_falls_back_to_plain_text() {
    // The body has no header row (all fields numeric), so structured CSV
    // parsing falls back to plain text. An email (pattern-only, no keyword
    // context required) embedded in the body should still be detected via
    // flat-text scanning.
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    // First row is purely numeric → header detection fails, falls back to flat text.
    let body = "1,2\n3,user@example.com";
    let resp = client
        .post(api.url("/v1/scan"))
        .header("content-type", "text/csv")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    let kinds: Vec<String> = json["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(
        kinds.contains(&"EMAIL".to_string()),
        "expected EMAIL in kinds, got {kinds:?}"
    );
}

// ---------------------------------------------------------------------------
// /openapi.json tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn openapi_json_returns_valid_spec() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let resp = client.get(api.url("/openapi.json")).send().await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json"
    );

    let spec: serde_json::Value = resp.json().await.unwrap();

    // Top-level OpenAPI shape.
    assert!(spec["openapi"].as_str().unwrap().starts_with("3."));
    assert_eq!(spec["info"]["title"], "PII Proxy HTTP API");
    assert!(spec["info"]["version"].is_string());

    // Both endpoints are present.
    let scan = &spec["paths"]["/v1/scan"]["post"];
    let redact = &spec["paths"]["/v1/redact"]["post"];
    assert!(scan.is_object(), "/v1/scan POST must be present");
    assert!(redact.is_object(), "/v1/redact POST must be present");

    // Request bodies advertise all four supported content types — driven by
    // `scanner::SUPPORTED_BODY_CONTENT_TYPES` so the spec stays in sync with
    // the parser dispatch.
    for path in ["/v1/scan", "/v1/redact"] {
        let req_content = &spec["paths"][path]["post"]["requestBody"]["content"];
        for ct in [
            "text/plain",
            "application/json",
            "text/csv",
            "text/tab-separated-values",
        ] {
            assert!(
                req_content.get(ct).is_some(),
                "{path}: requestBody.content missing {ct}"
            );
        }
    }

    // /v1/redact 200 mirrors the same content types and documents both
    // X-PII-* response headers.
    let redact_200 = &redact["responses"]["200"];
    let redact_200_content = &redact_200["content"];
    for ct in [
        "text/plain",
        "application/json",
        "text/csv",
        "text/tab-separated-values",
    ] {
        assert!(
            redact_200_content.get(ct).is_some(),
            "/v1/redact: 200.content missing {ct}"
        );
    }
    let headers = &redact_200["headers"];
    assert!(
        headers.get("X-PII-Detected").is_some(),
        "/v1/redact: 200 missing X-PII-Detected header"
    );
    assert!(
        headers.get("X-PII-Redacted-Count").is_some(),
        "/v1/redact: 200 missing X-PII-Redacted-Count header"
    );

    // Documented error status codes are present on both endpoints.
    for path in ["/v1/scan", "/v1/redact"] {
        let responses = &spec["paths"][path]["post"]["responses"];
        for status in ["400", "413", "415", "500"] {
            assert!(
                responses.get(status).is_some(),
                "{path}: missing {status} response"
            );
        }
    }
}

#[tokio::test]
async fn content_type_with_charset_param_accepted() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(api.url("/v1/scan"))
        .header("content-type", "application/json; charset=utf-8")
        .body(r#"{"email":"user@example.com"}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["detected"], true);
}
