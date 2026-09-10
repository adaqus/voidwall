use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use test_case::test_case;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use voidwall::config::{AppConfig, HttpApiConfig, OnError, PiiConfig, ScanConfig};
use voidwall::engine::Engine;
use voidwall::http_api;

// ---------------------------------------------------------------------------
// Shared engine & helpers
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

static SHARED_ENGINE: LazyLock<Arc<Engine>> =
    LazyLock::new(|| Arc::new(Engine::new(&default_pii_config()).unwrap()));

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
        Self::start_with(ScanConfig::default()).await
    }

    async fn start_with(scan: ScanConfig) -> Self {
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
            },
            admin: Default::default(),
            shutdown_timeout_secs: 30,
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let engine = SHARED_ENGINE.clone();

        tokio::spawn(async move {
            http_api::serve(&config, engine, cancel_clone)
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

/// The body holding two kinds, reused by the ordering tests below.
const TWO_KIND_BODY: &str = r#"{"user":{"phone_number":"555-123-4567"},"email":"a@b.com"}"#;

async fn post_json(api: &TestApi, path: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(api.url(path))
        .header("content-type", "application/json")
        .body(TWO_KIND_BODY)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn scan_kinds_are_sorted_and_stable_across_two_posts() {
    let api = TestApi::start().await;

    let read_kinds = async |api: &TestApi| -> Vec<String> {
        let resp = post_json(api, "/v1/scan").await;
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.unwrap();
        json["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    };

    let first = read_kinds(&api).await;
    let second = read_kinds(&api).await;

    assert!(first.len() > 1, "expected several kinds, got {first:?}");
    let mut sorted = first.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        first, sorted,
        "kinds must be sorted and hold each kind once"
    );
    assert_eq!(
        first, second,
        "two scans of one body must agree on the order"
    );
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
// Retired route
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Error / fallback paths
// ---------------------------------------------------------------------------

/// The listener serves exactly the four documented routes and nothing else.
/// It briefly did serve more: a Fly-only build feature mounted a static-file
/// catch-all to host the marketing page off the same listener, which
/// contradicted the requirement unspecced. The page now lives in its own repo
/// behind nginx, so an unrouted path must 404 again.
#[test_case("/" ; "root")]
#[test_case("/index.html" ; "landing index")]
#[test_case("/assets/app.js" ; "landing asset")]
#[test_case("/healthz" ; "health probe")]
#[test_case("/readyz" ; "readiness probe")]
#[test_case("/metrics" ; "admin metrics")]
#[test_case("/config" ; "config endpoint")]
#[tokio::test]
async fn unrouted_path_returns_404(path: &str) {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let resp = client.get(api.url(path)).send().await.unwrap();

    assert_eq!(
        resp.status(),
        404,
        "the API listener must not serve {path} — probes and the admin surface \
         live on the admin listener, or nowhere"
    );
}

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
    let api = TestApi::start_with(scan).await;

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
async fn malformed_json_with_fail_open_still_returns_400() {
    // The HTTP API rejects malformed structured bodies regardless of on_error
    // (the caller declared the type, so silently degrading would mask a bug).
    let scan = ScanConfig {
        on_error: OnError::FailOpen,
        ..ScanConfig::default()
    };
    let api = TestApi::start_with(scan).await;

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
async fn info_endpoint_returns_kinds_and_languages() {
    let api = TestApi::start().await;
    let client = reqwest::Client::new();
    let resp = client.get(api.url("/v1/info")).send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let info: serde_json::Value = resp.json().await.unwrap();

    assert!(!info["version"].as_str().unwrap().is_empty());

    let langs = info["languages"].as_array().unwrap();
    let lang_strs: Vec<&str> = langs.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(lang_strs.contains(&"en"));
    assert!(lang_strs.contains(&"fr"));
    assert!(lang_strs.contains(&"de"));

    let kinds = info["kinds"].as_array().unwrap();
    let kind_strs: Vec<&str> = kinds.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(kind_strs.contains(&"EMAIL"));
    assert!(kind_strs.contains(&"US_SSN"));
    // The Custom marker is filtered — its label comes from operator config.
    assert!(!kind_strs.contains(&"CUSTOM"));
}

/// The retired redaction route is gone from the router, not merely undocumented.
#[tokio::test]
async fn retired_redact_route_returns_404() {
    let api = TestApi::start().await;
    let resp = reqwest::Client::new()
        .post(api.url("/v1/redact"))
        .header("content-type", "text/plain")
        .body("contact me at user@example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

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
    assert_eq!(spec["info"]["title"], "Voidwall HTTP API");
    assert!(spec["info"]["version"].is_string());

    // The scan endpoint is present; the retired redaction route is not.
    let scan = &spec["paths"]["/v1/scan"]["post"];
    assert!(scan.is_object(), "/v1/scan POST must be present");
    assert!(
        spec["paths"].get("/v1/redact").is_none(),
        "/v1/redact must not appear in the spec"
    );

    // The request body advertises all four supported content types — driven by
    // `scanner::SUPPORTED_BODY_CONTENT_TYPES` so the spec stays in sync with
    // the parser dispatch.
    let req_content = &scan["requestBody"]["content"];
    for ct in [
        "text/plain",
        "application/json",
        "text/csv",
        "text/tab-separated-values",
    ] {
        assert!(
            req_content.get(ct).is_some(),
            "/v1/scan: requestBody.content missing {ct}"
        );
    }

    // Documented error status codes are present.
    {
        let responses = &scan["responses"];
        for status in ["400", "413", "415", "500"] {
            assert!(
                responses.get(status).is_some(),
                "/v1/scan: missing {status} response"
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
