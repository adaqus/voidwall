use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use test_case::test_case;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use voidwall::config::{AppConfig, BuiltinGuards, HttpApiConfig, OnError, PiiGuardConfig};
use voidwall::engine::Engine;
use voidwall::http_api;

// ---------------------------------------------------------------------------
// Shared engine & helpers
// ---------------------------------------------------------------------------

fn default_pii_config() -> PiiGuardConfig {
    PiiGuardConfig {
        scanner_threads: Some(1),
        ..PiiGuardConfig::default()
    }
}

/// The ingest settings a test varies. Configuration splits what the old
/// `[scan]` table held: these are deployment-wide, while the scan surface
/// belongs to the guard.
#[derive(Clone)]
struct Ingest {
    max_body_size: usize,
    on_error: OnError,
}

impl Default for Ingest {
    fn default() -> Self {
        Self {
            max_body_size: 1_048_576,
            on_error: OnError::FailClose,
        }
    }
}

static SHARED_ENGINE: LazyLock<Arc<Engine>> = LazyLock::new(|| {
    Arc::new(Engine::new(&BuiltinGuards::with_pii(default_pii_config())).unwrap())
});

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
        Self::start_with(Ingest::default()).await
    }

    async fn start_with(ingest: Ingest) -> Self {
        Self::start_inner(ingest, default_pii_config(), SHARED_ENGINE.clone()).await
    }

    /// Builds a dedicated engine from `pii_config` instead of reusing the
    /// shared one. A test that needs a failing scanner pool must own it.
    async fn start_with_pii(ingest: Ingest, pii_config: PiiGuardConfig) -> Self {
        let engine = Arc::new(Engine::new(&BuiltinGuards::with_pii(pii_config.clone())).unwrap());
        Self::start_inner(ingest, pii_config, engine).await
    }

    async fn start_inner(ingest: Ingest, pii_config: PiiGuardConfig, engine: Arc<Engine>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let config = AppConfig {
            max_body_size: ingest.max_body_size,
            on_error: ingest.on_error,
            builtin_guards: BuiltinGuards::with_pii(pii_config),
            http_api: HttpApiConfig {
                enabled: true,
                listen: addr.to_string(),
            },
            ..AppConfig::default()
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

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
    let ingest = Ingest {
        max_body_size: 64,
        ..Ingest::default()
    };
    let api = TestApi::start_with(ingest).await;

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
    let ingest = Ingest {
        on_error: OnError::FailOpen,
        ..Ingest::default()
    };
    let api = TestApi::start_with(ingest).await;

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

/// A pool that owns no scanner threads: the work channel has no receiver, so
/// every submit sees it disconnected. That is the same error the pool raises
/// once its threads have died.
fn broken_pool_pii_config() -> PiiGuardConfig {
    PiiGuardConfig {
        scanner_threads: Some(0),
        ..default_pii_config()
    }
}

/// A scanner failure under `fail_close` answers 500. `fail_close` is the
/// default, so this is what `/v1/scan` does for an operator who wrote no
/// `on_error` at all.
#[tokio::test]
async fn scanner_failure_fail_close_returns_500() {
    let ingest = Ingest::default();
    assert_eq!(
        AppConfig::default().on_error,
        OnError::FailClose,
        "this test is about the default, which must be fail_close"
    );

    let api = TestApi::start_with_pii(ingest, broken_pool_pii_config()).await;
    let resp = reqwest::Client::new()
        .post(api.url("/v1/scan"))
        .header("content-type", "text/plain")
        .body("nothing sensitive here")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 500);
}

/// The same failure under `fail_open` answers 200 and reports nothing found.
/// The caller cannot tell this apart from a clean scan, which is the reason
/// `fail_open` is no longer the default.
#[tokio::test]
async fn scanner_failure_fail_open_answers_200_detecting_nothing() {
    let ingest = Ingest {
        on_error: OnError::FailOpen,
        ..Ingest::default()
    };

    let api = TestApi::start_with_pii(ingest, broken_pool_pii_config()).await;
    let resp = reqwest::Client::new()
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

/// The retired detection-surface route is gone from the router. The built-in
/// kind labels live in the `kinds` property description of `docs/openapi.json`.
#[tokio::test]
async fn retired_info_route_returns_404() {
    let api = TestApi::start().await;
    let resp = reqwest::Client::new()
        .get(api.url("/v1/info"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// The specification is a checked-in repository file, not a served route.
#[tokio::test]
async fn retired_openapi_route_returns_404() {
    let api = TestApi::start().await;
    let resp = reqwest::Client::new()
        .get(api.url("/openapi.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// The listener sends no CORS header. A wildcard `Access-Control-Allow-Origin`
/// on an unauthenticated listener let any page on the internet post bodies to
/// it; cross-origin access belongs to the gateway that supplies the
/// authentication (openspec/specs/security/spec.md).
#[tokio::test]
async fn scan_response_carries_no_cors_header() {
    let api = TestApi::start().await;
    let resp = reqwest::Client::new()
        .post(api.url("/v1/scan"))
        .header("content-type", "text/plain")
        .header("origin", "https://elsewhere.example")
        .body("contact me at user@example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "the API listener must send no CORS header"
    );
}

/// A browser preflight gets no CORS permission either. The route takes POST
/// only, so `OPTIONS` falls to axum's 405 and carries no `access-control-*`
/// header (openspec/specs/security/spec.md).
#[tokio::test]
async fn preflight_gets_no_cors_permission() {
    let api = TestApi::start().await;
    let resp = reqwest::Client::new()
        .request(reqwest::Method::OPTIONS, api.url("/v1/scan"))
        .header("origin", "https://elsewhere.example")
        .header("access-control-request-method", "POST")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 405);
    let cors: Vec<&str> = resp
        .headers()
        .keys()
        .map(|k| k.as_str())
        .filter(|k| k.starts_with("access-control-"))
        .collect();
    assert!(
        cors.is_empty(),
        "the API listener must answer a preflight with no CORS header, got {cors:?}"
    );
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
