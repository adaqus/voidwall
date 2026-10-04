use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use bytes::Bytes;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use utoipa::ToSchema;

use crate::config::{AppConfig, OnError};
use crate::engine::{BlockPolicy, Engine, GuardSelection, ScanResult, Units};
use crate::error::{Error, INTERNAL_ERROR};
use crate::metrics;
use crate::scanner::{SCANNER_ERROR_LIMITER, classify_body};

const MODE: &str = "http_api";
const ROUTE: &str = "global";

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ApiState {
    engine: Arc<Engine>,
    /// Every enabled guard. The API has no route to attach a selection to, so
    /// it carries none of its own.
    selection: Arc<GuardSelection>,
    content_types: Arc<Vec<String>>,
    max_body_size: usize,
    on_error: OnError,
}

// ---------------------------------------------------------------------------
// Router & server
// ---------------------------------------------------------------------------

pub fn build_state(config: &AppConfig, engine: Arc<Engine>) -> ApiState {
    let selection = Arc::new(engine.select(None));
    ApiState {
        engine,
        selection,
        content_types: Arc::new(config.content_types.clone()),
        max_body_size: config.max_body_size,
        on_error: config.on_error,
    }
}

pub fn router(state: ApiState) -> Router {
    let max_body = state.max_body_size;
    Router::new()
        .route("/v1/scan", post(scan_handler))
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(state)
}

pub async fn serve(
    config: &AppConfig,
    engine: Arc<Engine>,
    cancel: CancellationToken,
) -> Result<(), Error> {
    let state = build_state(config, engine);
    let app = router(state);
    let listener = TcpListener::bind(&config.http_api.listen).await?;
    tracing::info!(listen = %config.http_api.listen, "HTTP API started");

    axum::serve(listener, app)
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await
        .map_err(Error::Io)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
#[schema(example = json!({
    "detected": true,
    "matches_count": 2,
    "kinds": ["EMAIL", "US_SSN"],
}))]
struct ScanResponse {
    /// Whether any PII was detected in the body.
    detected: bool,
    /// Total number of PII matches.
    matches_count: usize,
    /// Distinct PII kinds detected (e.g. `EMAIL`, `US_SSN`). Operator-defined
    /// custom labels surface here using their configured `label`. The full
    /// list of built-in labels is appended to this description at
    /// spec-generation time.
    kinds: Vec<String>,
}

#[derive(Serialize, ToSchema)]
#[schema(example = json!({
    "error": "malformed body for declared content type",
}))]
struct ErrorResponse {
    /// Human-readable error description. Never contains matched PII values.
    error: String,
}

// utoipa is a procedural macro and its arguments must be string literals
// (it cannot expand `const` references), so the macros below use a single
// `text/plain` placeholder for the body Content-Type. At spec-generation
// time `expand_supported_content_types` rewrites the placeholder into one
// entry per `SUPPORTED_BODY_CONTENT_TYPES` element so the documented set
// stays in sync with the parser dispatch in `scanner::classify_body`.

/// Scan a request body for PII
///
/// Inspects the body for PII according to the configured detector set and
/// returns the kinds detected along with per-kind match counts. The body
/// itself is never echoed back.
#[utoipa::path(
    post,
    path = "/v1/scan",
    tag = "pii",
    operation_id = "scanBody",
    request_body(
        description = "Raw body content to scan for PII. The `Content-Type` \
            header determines how the body is parsed and scanned.",
        content_type = "text/plain",
        content = String,
    ),
    responses(
        (
            status = 200,
            description = "Scan completed",
            body = ScanResponse,
            content_type = "application/json",
        ),
        (status = 400, description = "Body could not be parsed for the declared `Content-Type`", body = ErrorResponse, content_type = "application/json"),
        (status = 413, description = "Body exceeds configured `max_body_size`", body = ErrorResponse, content_type = "application/json"),
        (status = 415, description = "`Content-Type` is not in the configured allowlist", body = ErrorResponse, content_type = "application/json"),
        (status = 500, description = "Scanner failed and `on_error = fail_close`", body = ErrorResponse, content_type = "application/json"),
    ),
)]
async fn scan_handler(State(state): State<ApiState>, headers: HeaderMap, body: Bytes) -> Response {
    process(state, headers, body).await
}

// The OpenAPI document is a checked-in repository artefact
// (`docs/openapi.json`), not a served route, so the generator below is reached
// only from the freshness test that keeps the file in step with the handler.
#[cfg(test)]
use utoipa::OpenApi;

#[cfg(test)]
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Voidwall HTTP API",
        description = "Detect PII in arbitrary text, JSON, CSV, and TSV \
            bodies with `POST /v1/scan`, the one route this listener serves. \
            The body itself is the content to scan — there is no JSON \
            envelope. The `Content-Type` header drives parsing.",
        version = env!("CARGO_PKG_VERSION"),
    ),
    paths(scan_handler),
    components(schemas(ScanResponse, ErrorResponse)),
    tags(
        (name = "pii", description = "PII detection endpoints"),
    ),
)]
struct ApiDoc;

/// Render the OpenAPI document as a pretty-printed JSON string, expanding the
/// `text/plain` placeholder used in the `#[utoipa::path]` annotations into one
/// entry per `SUPPORTED_BODY_CONTENT_TYPES` element. This keeps the documented
/// content types in sync with the parser dispatch in `scanner::classify_body`
/// without duplicating the list at every annotation site.
#[cfg(test)]
fn build_openapi_spec() -> String {
    let mut value = serde_json::to_value(ApiDoc::openapi())
        .unwrap_or_else(|_| serde_json::Value::Object(Default::default()));
    expand_supported_content_types(&mut value);
    inject_known_pii_kinds(&mut value);
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

/// Append the full list of built-in PII kind labels to the description of
/// `ScanResponse.kinds`, sourced from `voidwall_pii::PiiKind::all()`. Doing this at
/// spec-generation time keeps the documented set in sync with the upstream
/// crate without duplicating the list at the annotation site. The `Custom`
/// marker is filtered out because its user-facing label comes from operator
/// config, not the enum.
#[cfg(test)]
fn inject_known_pii_kinds(spec: &mut serde_json::Value) {
    let labels_md = voidwall_pii::PiiKind::all()
        .iter()
        .filter(|k| !matches!(k, voidwall_pii::PiiKind::Custom))
        .map(|k| k.label().to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let pointer = "/components/schemas/ScanResponse/properties/kinds/description";
    if let Some(desc) = spec.pointer_mut(pointer)
        && let Some(s) = desc.as_str().map(str::to_owned)
    {
        let new_desc = format!("{s}\n\nBuilt-in labels: {labels_md}.");
        *desc = serde_json::Value::String(new_desc);
    }
}

/// Walk the spec's `/v1/scan` POST operation and replace the single
/// placeholder body Content-Type with one entry per
/// `SUPPORTED_BODY_CONTENT_TYPES` element. The replacement clones the schema
/// from the placeholder, so all entries share the same shape.
#[cfg(test)]
fn expand_supported_content_types(spec: &mut serde_json::Value) {
    let pointer = format!("/paths/{}/post", encode_pointer_segment("/v1/scan"));
    let Some(post) = spec.pointer_mut(&pointer) else {
        return;
    };

    if let Some(content) = post
        .pointer_mut("/requestBody/content")
        .and_then(serde_json::Value::as_object_mut)
    {
        expand_content_map(content);
    }
}

#[cfg(test)]
fn expand_content_map(content: &mut serde_json::Map<String, serde_json::Value>) {
    let Some(template) = content.values().next().cloned() else {
        return;
    };
    content.clear();
    for ct in crate::scanner::SUPPORTED_BODY_CONTENT_TYPES {
        content.insert((*ct).to_string(), template.clone());
    }
}

/// JSON Pointer (RFC 6901) escape: `~` → `~0`, `/` → `~1`. We need this
/// because path templates contain `/` which is the segment separator.
#[cfg(test)]
fn encode_pointer_segment(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

async fn process(state: ApiState, headers: HeaderMap, body: Bytes) -> Response {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if !is_content_type_allowed(&content_type, &state.content_types) {
        let resp = (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            [("content-type", "application/json")],
            r#"{"error":"unsupported content type"}"#,
        )
            .into_response();
        record_request(resp.status());
        return resp;
    }

    // Parse the body according to its declared content type. Malformed
    // structured bodies are always rejected with 400 — the caller declared the
    // type, so silently falling back to flat-text would mask their bug
    // (openspec/specs/http-api/spec.md). This rule overrides on_error.
    let body_format = match classify_body(body.clone(), &content_type) {
        Ok(bf) => bf,
        Err(_) => {
            metrics::inc_error("blocked", "body_parse_failed");
            let resp = (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                r#"{"error":"malformed body for declared content type"}"#,
            )
                .into_response();
            record_request(resp.status());
            return resp;
        }
    };

    // The API scans the body and nothing else, so the message is one unit —
    // there is no URL path, query, or header to attach a surface to. Every
    // enabled guard runs, and each sees the body only if its own surface
    // admits one. The route reports rather than blocks, so the engine never
    // short-circuits.
    let mut units = Units::new();
    units.push_body(body_format);
    let units = units.into_shared();

    let mut scan_result = state
        .engine
        .guard(
            Arc::clone(&units),
            &state.selection,
            BlockPolicy::Never,
            state.on_error,
        )
        .await;

    let kinds = scan_result.kinds();

    // Always increment detection metrics when PII is detected — also when a
    // guard error turns the answer into a 500.
    for kind in &kinds {
        metrics::inc_detection(kind, MODE, ROUTE, "request");
    }

    // A guard error does not discard the findings of the guards that
    // succeeded: fail_open reports them, fail_close answers 500.
    if let Some(e) = scan_result.take_error() {
        if let Some(dropped) = SCANNER_ERROR_LIMITER.should_log() {
            warn!(dropped, error = %e, "scanner error in http api");
        }
        if let Some(resp) = handle_scanner_failure(state.on_error) {
            return resp;
        }
    }

    let resp = build_scan_response(&scan_result, &kinds);

    record_request(resp.status());
    resp
}

fn build_scan_response(scan_result: &ScanResult, kinds: &[String]) -> Response {
    let payload = ScanResponse {
        detected: scan_result.detected(),
        matches_count: scan_result.matches_count(),
        kinds: kinds.to_vec(),
    };
    let body = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    (StatusCode::OK, [("content-type", "application/json")], body).into_response()
}

/// On scanner failure, follow the configured `on_error` policy.
///
/// `fail_open`: count the error and return `None`, so the caller reports the
/// findings of the guards that succeeded. `fail_close`: return the fixed 500.
fn handle_scanner_failure(on_error: OnError) -> Option<Response> {
    match on_error {
        OnError::FailOpen => {
            metrics::inc_error("passed", "scanner_failure");
            None
        }
        OnError::FailClose => {
            metrics::inc_error("blocked", "scanner_failure");
            let body = serde_json::json!({ "error": INTERNAL_ERROR }).to_string();
            let resp = (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("content-type", "application/json")],
                body,
            )
                .into_response();
            record_request(resp.status());
            Some(resp)
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_content_type_allowed(content_type: &str, allowed: &[String]) -> bool {
    if content_type.is_empty() {
        return false;
    }
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    allowed.iter().any(|a| a.eq_ignore_ascii_case(media_type))
}

fn record_request(status: StatusCode) {
    metrics::inc_request(MODE, ROUTE, "POST", &status.as_u16().to_string());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case("application/json", &["application/json".to_string()], true)]
    #[test_case("application/json; charset=utf-8", &["application/json".to_string()], true)]
    #[test_case("text/csv", &["text/csv".to_string(), "application/json".to_string()], true)]
    #[test_case("image/png", &["application/json".to_string()], false)]
    #[test_case("", &["application/json".to_string()], false)]
    #[test_case("APPLICATION/JSON", &["application/json".to_string()], true ; "case insensitive")]
    fn content_type_allowlist(ct: &str, allowed: &[String], expected: bool) {
        assert_eq!(is_content_type_allowed(ct, allowed), expected);
    }

    /// The checked-in `docs/openapi.json` is the published contract. It is
    /// generated, so it cannot drift from the handler — provided somebody
    /// regenerates it. This test is that gate: there is no CI pipeline, so the
    /// failure has to carry the command that fixes it.
    #[test]
    fn openapi_document_file_is_fresh() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/openapi.json");
        let generated = build_openapi_spec();

        if std::env::var_os("UPDATE_OPENAPI").is_some() {
            std::fs::write(&path, format!("{generated}\n"))
                .unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
            return;
        }

        const REGEN: &str = "UPDATE_OPENAPI=1 cargo test -p voidwall --lib openapi";
        let checked_in = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "reading {}: {e}\n\nregenerate it with: {REGEN}",
                path.display()
            )
        });

        // Parsed values, not strings: whitespace, trailing newline, and key
        // order must not fail the test.
        let generated: serde_json::Value = serde_json::from_str(&generated).unwrap();
        let checked_in: serde_json::Value = serde_json::from_str(&checked_in)
            .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()));

        assert_eq!(
            checked_in, generated,
            "docs/openapi.json is stale — regenerate it with: {REGEN}"
        );
    }

    #[test]
    fn openapi_spec_contains_examples_and_kind_labels() {
        let spec: serde_json::Value = serde_json::from_str(&build_openapi_spec()).unwrap();

        let scan_schema = &spec["components"]["schemas"]["ScanResponse"];
        assert_eq!(scan_schema["example"]["detected"], true);
        assert_eq!(scan_schema["example"]["matches_count"], 2);
        assert_eq!(
            scan_schema["example"]["kinds"],
            serde_json::json!(["EMAIL", "US_SSN"])
        );

        let kinds_desc = scan_schema["properties"]["kinds"]["description"]
            .as_str()
            .unwrap();
        assert!(kinds_desc.contains("Built-in labels:"));
        assert!(kinds_desc.contains("`EMAIL`"));
        assert!(kinds_desc.contains("`US_SSN`"));
        // The `Custom` marker is filtered — its label comes from operator config.
        assert!(!kinds_desc.contains("`CUSTOM`"));

        let err_schema = &spec["components"]["schemas"]["ErrorResponse"];
        assert!(err_schema["example"]["error"].is_string());
    }

    // --- A guard error does not discard the other guards' findings ---

    use crate::engine::test_guard::TestGuard;
    use crate::metrics::{DETECTIONS_TOTAL, ERRORS_TOTAL};
    use http_body_util::BodyExt;

    /// Post one plain-text body to `/v1/scan` over a failing guard and a guard
    /// that reports `kind`.
    async fn scan_with_a_failing_guard(on_error: OnError, kind: &'static str) -> Response {
        let engine = Arc::new(Engine::with_guards(vec![
            Box::new(TestGuard::new("failing", "API_UNUSED").failing()),
            Box::new(TestGuard::new("detecting", kind)),
        ]));
        let config = AppConfig {
            on_error,
            ..AppConfig::default()
        };
        let state = build_state(&config, engine);
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/plain".parse().unwrap());
        process(state, headers, Bytes::from_static(b"content")).await
    }

    fn detections(kind: &str) -> u64 {
        DETECTIONS_TOTAL
            .with_label_values(&[kind, MODE, ROUTE, "request"])
            .get()
    }

    fn scanner_failures(outcome: &str) -> u64 {
        ERRORS_TOTAL
            .with_label_values(&[outcome, "scanner_failure"])
            .get()
    }

    #[tokio::test]
    async fn fail_open_reports_the_findings_of_the_guards_that_succeeded() {
        let errors_before = scanner_failures("passed");

        let resp = scan_with_a_failing_guard(OnError::FailOpen, "API_FAIL_OPEN_KIND").await;

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["detected"], true);
        assert_eq!(body["kinds"], serde_json::json!(["API_FAIL_OPEN_KIND"]));
        // Other tests can count the same labels at the same time, so the
        // check is a lower bound.
        assert!(scanner_failures("passed") > errors_before);
    }

    #[tokio::test]
    async fn fail_close_answers_500_and_counts_the_detections() {
        let resp = scan_with_a_failing_guard(OnError::FailClose, "API_FAIL_CLOSE_KIND").await;

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], br#"{"error":"internal error"}"#);
        // The kind label is unique to this test, so the count is exact.
        assert_eq!(detections("API_FAIL_CLOSE_KIND"), 1);
    }
}
