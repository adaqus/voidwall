use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};
use tracing::warn;
use utoipa::{OpenApi, ToSchema};

use crate::config::{AppConfig, HttpApiConfig, OnError, ScanConfig};
use crate::error::Error;
use crate::metrics;
use crate::scanner::{
    RedactWith, SCANNER_ERROR_LIMITER, SUPPORTED_BODY_CONTENT_TYPES, ScanRequest, ScannerPool,
    classify_body, to_redact_with,
};

const MODE: &str = "http_api";
const ROUTE: &str = "global";

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ApiState {
    scanner: Arc<ScannerPool>,
    scan: ScanConfig,
    redact_strategy: Option<RedactWith>,
    max_body_size: usize,
    openapi_spec: Arc<String>,
}

// ---------------------------------------------------------------------------
// Router & server
// ---------------------------------------------------------------------------

pub fn build_state(config: &AppConfig, scanner: Arc<ScannerPool>) -> ApiState {
    let api: &HttpApiConfig = &config.http_api;
    let redact_strategy = api
        .redact_strategy
        .map(|s| to_redact_with(s, api.mask_char));

    let openapi_spec = build_openapi_spec();

    ApiState {
        scanner,
        scan: config.scan.clone(),
        redact_strategy,
        max_body_size: config.scan.max_body_size,
        openapi_spec: Arc::new(openapi_spec),
    }
}

pub fn router(state: ApiState) -> Router {
    let max_body = state.max_body_size;
    // Permissive CORS so the bundled Swagger UI (served from a different
    // origin in docker/docker-compose.yml) can fetch /openapi.json and
    // exercise /v1/scan and /v1/redact via "Try it out". The HTTP API has no
    // built-in auth — it is expected to sit behind a gateway or NetworkPolicy
    // (DESIGN.md § HTTP API · Authentication), so allowing any origin here
    // does not weaken the deployed posture.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers(Any);
    Router::new()
        .route("/v1/scan", post(scan_handler))
        .route("/v1/redact", post(redact_handler))
        .route("/openapi.json", get(openapi_handler))
        .layer(DefaultBodyLimit::max(max_body))
        .layer(cors)
        .with_state(state)
}

pub async fn serve(
    config: &AppConfig,
    scanner: Arc<ScannerPool>,
    cancel: CancellationToken,
) -> Result<(), Error> {
    let state = build_state(config, scanner);
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
        (status = 200, description = "Scan completed", body = ScanResponse, content_type = "application/json"),
        (status = 400, description = "Body could not be parsed for the declared `Content-Type`", body = ErrorResponse, content_type = "application/json"),
        (status = 413, description = "Body exceeds configured `max_body_size`", body = ErrorResponse, content_type = "application/json"),
        (status = 415, description = "`Content-Type` is not in the configured allowlist", body = ErrorResponse, content_type = "application/json"),
        (status = 500, description = "Scanner failed and `on_error = fail_close`", body = ErrorResponse, content_type = "application/json"),
    ),
)]
async fn scan_handler(State(state): State<ApiState>, headers: HeaderMap, body: Bytes) -> Response {
    process(state, headers, body, Mode::Scan).await
}

/// Redact PII in a request body
///
/// Scans the body and replaces detected PII spans in-place. The response
/// `Content-Type` mirrors the request so the redacted body remains valid
/// JSON / CSV / TSV / plain text. Detection metadata is returned via the
/// `X-PII-Detected` and `X-PII-Redacted-Count` response headers.
#[utoipa::path(
    post,
    path = "/v1/redact",
    tag = "pii",
    operation_id = "redactBody",
    request_body(
        description = "Raw body content to scan and redact. Content-Type \
            routing matches `/v1/scan`. The response `Content-Type` mirrors \
            the request so the redacted body remains valid JSON / CSV / TSV / \
            plain text.",
        content_type = "text/plain",
        content = String,
    ),
    responses(
        (
            status = 200,
            description = "Redacted body. The response `Content-Type` mirrors the request.",
            body = String,
            content_type = "text/plain",
            headers(
                ("X-PII-Detected" = String, description = "Comma-separated list of detected PII kinds. Omitted when none detected."),
                ("X-PII-Redacted-Count" = u32, description = "Total redactions performed. `0` when none."),
            ),
        ),
        (status = 400, description = "Body could not be parsed for the declared `Content-Type`", body = ErrorResponse, content_type = "application/json"),
        (status = 413, description = "Body exceeds configured `max_body_size`", body = ErrorResponse, content_type = "application/json"),
        (status = 415, description = "`Content-Type` is not in the configured allowlist", body = ErrorResponse, content_type = "application/json"),
        (status = 500, description = "Scanner failed and `on_error = fail_close`", body = ErrorResponse, content_type = "application/json"),
    ),
)]
async fn redact_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    process(state, headers, body, Mode::Redact).await
}

async fn openapi_handler(State(state): State<ApiState>) -> Response {
    record_request(StatusCode::OK);
    let mut response = Response::new(Body::from(state.openapi_spec.as_bytes().to_vec()));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Veilflow HTTP API",
        description = "Detect and redact PII in arbitrary text, JSON, CSV, and \
            TSV bodies. The body itself is the content to scan — there is no \
            JSON envelope. The `Content-Type` header drives parsing.",
        version = env!("CARGO_PKG_VERSION"),
    ),
    paths(scan_handler, redact_handler),
    components(schemas(ScanResponse, ErrorResponse)),
    tags(
        (name = "pii", description = "PII detection and redaction endpoints"),
    ),
)]
struct ApiDoc;

/// Render the OpenAPI document as a pretty-printed JSON string, expanding the
/// `text/plain` placeholder used in the `#[utoipa::path]` annotations into one
/// entry per `SUPPORTED_BODY_CONTENT_TYPES` element. This keeps the documented
/// content types in sync with the parser dispatch in `scanner::classify_body`
/// without duplicating the list at every annotation site.
fn build_openapi_spec() -> String {
    let mut value = serde_json::to_value(ApiDoc::openapi())
        .unwrap_or_else(|_| serde_json::Value::Object(Default::default()));
    expand_supported_content_types(&mut value);
    inject_known_pii_kinds(&mut value);
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

/// Append the full list of built-in PII kind labels to the description of
/// `ScanResponse.kinds`, sourced from `pii::PiiKind::all()`. Doing this at
/// spec-generation time keeps the documented set in sync with the upstream
/// crate without duplicating the list at the annotation site. The `Custom`
/// marker is filtered out because its user-facing label comes from operator
/// config, not the enum.
fn inject_known_pii_kinds(spec: &mut serde_json::Value) {
    let labels_md = pii::PiiKind::all()
        .iter()
        .filter(|k| !matches!(k, pii::PiiKind::Custom))
        .map(|k| format!("{}", k.label()))
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

/// Walk the spec's `/v1/scan` and `/v1/redact` POST operations and replace the
/// single placeholder body Content-Type with one entry per
/// `SUPPORTED_BODY_CONTENT_TYPES` element. The replacement clones the schema
/// from the placeholder, so all entries share the same shape.
fn expand_supported_content_types(spec: &mut serde_json::Value) {
    for path in ["/v1/scan", "/v1/redact"] {
        let pointer = format!("/paths/{}/post", encode_pointer_segment(path));
        let Some(post) = spec.pointer_mut(&pointer) else {
            continue;
        };

        if let Some(content) = post
            .pointer_mut("/requestBody/content")
            .and_then(serde_json::Value::as_object_mut)
        {
            expand_content_map(content);
        }

        if path == "/v1/redact"
            && let Some(content) = post
                .pointer_mut("/responses/200/content")
                .and_then(serde_json::Value::as_object_mut)
        {
            expand_content_map(content);
        }
    }
}

fn expand_content_map(content: &mut serde_json::Map<String, serde_json::Value>) {
    let Some(template) = content.values().next().cloned() else {
        return;
    };
    content.clear();
    for ct in SUPPORTED_BODY_CONTENT_TYPES {
        content.insert((*ct).to_string(), template.clone());
    }
}

/// JSON Pointer (RFC 6901) escape: `~` → `~0`, `/` → `~1`. We need this
/// because path templates contain `/` which is the segment separator.
fn encode_pointer_segment(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

#[derive(Clone, Copy)]
enum Mode {
    Scan,
    Redact,
}

async fn process(state: ApiState, headers: HeaderMap, body: Bytes, mode: Mode) -> Response {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if !is_content_type_allowed(&content_type, &state.scan.content_types) {
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
    // (DESIGN.md § HTTP API). This rule overrides on_error.
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

    let want_redact = matches!(mode, Mode::Redact) && state.redact_strategy.is_some();
    let scan_req = ScanRequest {
        body: Some(body_format),
        path: None,
        query: None,
        headers: None,
        redact: want_redact,
        redact_strategy: state.redact_strategy.clone(),
    };

    let scan_result = match state.scanner.process(scan_req, state.scan.on_error).await {
        Ok(r) => r,
        Err(e) => {
            if let Some(dropped) = SCANNER_ERROR_LIMITER.should_log() {
                warn!(dropped, error = %e, "scanner error in http api");
            }
            return handle_scanner_failure(state.scan.on_error, &content_type, body, mode);
        }
    };

    // Always increment detection metrics when PII is detected.
    if scan_result.detected {
        for kind in &scan_result.kinds {
            metrics::inc_detection(kind, MODE, ROUTE, "request");
        }
    }

    let resp = match mode {
        Mode::Scan => build_scan_response(&scan_result),
        Mode::Redact => {
            // Increment redaction metrics for kinds we replaced.
            if want_redact && scan_result.redacted_body.is_some() {
                for kind in &scan_result.kinds {
                    metrics::inc_redacted(kind, MODE, ROUTE, "request");
                }
            }
            build_redact_response(&scan_result, &content_type, body)
        }
    };

    record_request(resp.status());
    resp
}

fn build_scan_response(scan_result: &crate::scanner::ScanResult) -> Response {
    let payload = ScanResponse {
        detected: scan_result.detected,
        matches_count: scan_result.matches_count,
        kinds: scan_result.kinds.clone(),
    };
    let body = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    (StatusCode::OK, [("content-type", "application/json")], body).into_response()
}

fn build_redact_response(
    scan_result: &crate::scanner::ScanResult,
    content_type: &str,
    original_body: Bytes,
) -> Response {
    let body = scan_result.redacted_body.clone().unwrap_or(original_body);
    let count = if scan_result.redacted_body.is_some() {
        scan_result.matches_count
    } else {
        0
    };

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;

    let response_headers = response.headers_mut();
    if let Ok(v) = HeaderValue::from_str(content_type) {
        response_headers.insert(axum::http::header::CONTENT_TYPE, v);
    }
    if !scan_result.kinds.is_empty()
        && let Ok(v) = HeaderValue::from_str(&scan_result.kinds.join(","))
    {
        response_headers.insert(HeaderName::from_static("x-pii-detected"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&count.to_string()) {
        response_headers.insert(HeaderName::from_static("x-pii-redacted-count"), v);
    }

    response
}

/// On scanner failure, follow the configured `on_error` policy.
///
/// `fail_open`: return the body unredacted with `X-PII-Redacted-Count: 0`
/// (and the original `Content-Type`); for `/v1/scan` return an empty result.
/// `fail_close`: return 500.
fn handle_scanner_failure(
    on_error: OnError,
    content_type: &str,
    original_body: Bytes,
    mode: Mode,
) -> Response {
    match on_error {
        OnError::FailOpen => {
            metrics::inc_error("passed", "scanner_failure");
            let resp = match mode {
                Mode::Scan => {
                    let payload = ScanResponse {
                        detected: false,
                        matches_count: 0,
                        kinds: Vec::new(),
                    };
                    let body = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
                    (StatusCode::OK, [("content-type", "application/json")], body).into_response()
                }
                Mode::Redact => {
                    let mut response = Response::new(Body::from(original_body));
                    *response.status_mut() = StatusCode::OK;
                    let h = response.headers_mut();
                    if let Ok(v) = HeaderValue::from_str(content_type) {
                        h.insert(axum::http::header::CONTENT_TYPE, v);
                    }
                    h.insert(
                        HeaderName::from_static("x-pii-redacted-count"),
                        HeaderValue::from_static("0"),
                    );
                    response
                }
            };
            record_request(resp.status());
            resp
        }
        OnError::FailClose => {
            metrics::inc_error("blocked", "scanner_failure");
            let resp = (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("content-type", "application/json")],
                r#"{"error":"scanner failure"}"#,
            )
                .into_response();
            record_request(resp.status());
            resp
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
}
