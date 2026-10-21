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
use crate::engine::{BlockPolicy, Engine, GuardSelection, ScanResult, UnitContent, Units};
use crate::error::Error;
use crate::metrics::{self, PiiGuards, UnscannedReason};
use crate::scanner::{SCANNER_ERROR_LIMITER, classify_body, is_json_content_type};
use crate::structured::litellm::{self, GuardrailRequest};

const MODE: &str = "http_api";
const ROUTE: &str = "global";

const SCAN_PATH: &str = "/v1/scan";
const LITELLM_PATH: &str = "/beta/litellm_basic_guardrail_api";

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ApiState {
    engine: Arc<Engine>,
    /// Every enabled guard. The API has no route to attach a selection to, so
    /// it carries none of its own.
    selection: Arc<GuardSelection>,
    pii_guards: Arc<PiiGuards>,
    content_types: Arc<Vec<String>>,
    max_body_size: usize,
    on_error: OnError,
    scan_route: bool,
    litellm_route: bool,
}

// ---------------------------------------------------------------------------
// Router & server
// ---------------------------------------------------------------------------

pub fn build_state(config: &AppConfig, engine: Arc<Engine>) -> ApiState {
    let selection = Arc::new(engine.select(None));
    ApiState {
        engine,
        selection,
        pii_guards: Arc::new(PiiGuards::from_config(config)),
        content_types: Arc::new(config.content_types.clone()),
        max_body_size: config.max_body_size,
        on_error: config.on_error,
        scan_route: config.http_api.scan.enabled,
        litellm_route: config.http_api.litellm.enabled,
    }
}

/// A route whose switch is off is not added, so axum's fallback answers it
/// with 404 like any other unknown path.
pub fn router(state: ApiState) -> Router {
    let max_body = state.max_body_size;
    let mut router = Router::new();
    if state.scan_route {
        router = router.route(SCAN_PATH, post(scan_handler));
    }
    if state.litellm_route {
        router = router.route(LITELLM_PATH, post(litellm_handler));
    }
    router
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

/// The answer to LiteLLM. There is no `GUARDRAIL_INTERVENED` variant, because
/// Voidwall never rewrites a message.
#[derive(Serialize, ToSchema)]
#[serde(tag = "action", rename_all = "SCREAMING_SNAKE_CASE")]
#[schema(example = json!({
    "action": "BLOCKED",
    "blocked_reason": "Voidwall blocked the message. Kinds: EMAIL, US_SSN",
}))]
enum GuardrailResponse {
    /// No guard reported a finding.
    None,
    /// A guard reported a finding.
    Blocked {
        /// `Voidwall blocked the message. Kinds: ` and the sorted kinds,
        /// joined by `, `. Never contains a detected value.
        blocked_reason: String,
    },
}

const BLOCKED_REASON: &str = "Voidwall blocked the message. Kinds: ";

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
        (status = 413, description = "Body exceeds configured `max_body_size`, or, with `on_error = fail_close`, a model guard needs more windows than its limit", body = ErrorResponse, content_type = "application/json"),
        (status = 415, description = "`Content-Type` is not in the configured allowlist", body = ErrorResponse, content_type = "application/json"),
        (status = 500, description = "A guard failed (scanner or model inference) and `on_error = fail_close`", body = ErrorResponse, content_type = "application/json"),
    ),
)]
async fn scan_handler(State(state): State<ApiState>, headers: HeaderMap, body: Bytes) -> Response {
    process(state, headers, body).await
}

/// LiteLLM Generic Guardrail API
///
/// Scans one LiteLLM guardrail payload and answers `NONE` or `BLOCKED`. On the
/// request side it reads `structured_messages`, `tools`, and `tool_calls`, and
/// `texts` only when `structured_messages` is missing. On the response side it
/// reads `texts` and `tool_calls`. It never reads `request_data` or
/// `request_headers`, and never scans base64 data.
#[utoipa::path(
    post,
    path = "/beta/litellm_basic_guardrail_api",
    tag = "litellm",
    operation_id = "litellmGuardrail",
    request_body(
        description = "A LiteLLM Generic Guardrail API payload.",
        content_type = "application/json",
        content = GuardrailRequest,
    ),
    responses(
        (
            status = 200,
            description = "Scan completed: `NONE`, or `BLOCKED` with the kinds found",
            body = GuardrailResponse,
            content_type = "application/json",
        ),
        (status = 400, description = "Body is not a JSON object with an `input_type` of `request` or `response`", body = ErrorResponse, content_type = "application/json"),
        (status = 413, description = "Body exceeds configured `max_body_size`, or, with `on_error = fail_close`, a model guard needs more windows than its limit", body = ErrorResponse, content_type = "application/json"),
        (status = 415, description = "`Content-Type` is not JSON", body = ErrorResponse, content_type = "application/json"),
        (status = 422, description = "A content part has a type Voidwall cannot scan and `on_error = fail_close`", body = ErrorResponse, content_type = "application/json"),
        (status = 500, description = "A guard failed (scanner or model inference) and `on_error = fail_close`", body = ErrorResponse, content_type = "application/json"),
    ),
)]
async fn litellm_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    process_litellm(state, headers, body).await
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
            bodies with `POST /v1/scan`. The body itself is the content to \
            scan — there is no JSON envelope. The `Content-Type` header \
            drives parsing. `POST /beta/litellm_basic_guardrail_api` serves \
            LiteLLM's Generic Guardrail API. `http_api.scan.enabled` and \
            `http_api.litellm.enabled` turn each route on or off.",
        version = env!("CARGO_PKG_VERSION"),
    ),
    paths(scan_handler, litellm_handler),
    components(schemas(ScanResponse, ErrorResponse, GuardrailRequest, GuardrailResponse)),
    tags(
        (name = "pii", description = "PII detection endpoints"),
        (name = "litellm", description = "LiteLLM Generic Guardrail API"),
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
    let pointer = format!("/paths/{}/post", encode_pointer_segment(SCAN_PATH));
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
        return unsupported_content_type();
    }

    // Parse the body according to its declared content type. Malformed
    // structured bodies are always rejected with 400 — the caller declared the
    // type, so silently falling back to flat-text would mask their bug
    // (openspec/specs/http-api/spec.md). This rule overrides on_error.
    let body_format = match classify_body(body.clone(), &content_type) {
        Ok(bf) => bf,
        Err(_) => return malformed_body(),
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

    record_detections(&scan_result, &state.pii_guards, "request");
    if let Some(resp) = handle_guard_error(&mut scan_result, state.on_error) {
        return resp;
    }

    let resp = build_scan_response(&scan_result, &kinds);

    record_request(resp.status());
    resp
}

async fn process_litellm(state: ApiState, headers: HeaderMap, body: Bytes) -> Response {
    // JSON only: the `content_types` allowlist governs `/v1/scan`, not this
    // route, whose payload is JSON by definition.
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !is_json_content_type(content_type) {
        return unsupported_content_type();
    }

    // A payload that does not decode is the caller's fault, whatever
    // `on_error` says, as on `/v1/scan`.
    let (input_type, decoded) = match litellm::decode(&body) {
        Ok(decoded) => decoded,
        Err(Error::BodyParse) => return malformed_body(),
        // The decoder could not pair its decisions with the fragments: a
        // scanner failure. fail_open scans nothing, so it reports no finding.
        Err(e) => {
            warn!(error = %e, "litellm payload decode failed");
            return handle_scanner_failure(e, state.on_error)
                .unwrap_or_else(|| guardrail_response(&GuardrailResponse::None));
        }
    };
    drop(body);
    let direction = input_type.direction();

    // An unknown content part is unscannable: fail_close answers 422 before
    // any guard runs, fail_open scans the rest. The decoder never put the
    // part into a unit.
    if decoded.unknown_parts > 0
        && let Some(resp) = handle_scanner_failure(Error::UnscannableContent, state.on_error)
    {
        return resp;
    }

    // Counted only once the payload goes on to be scanned, so a 400 or a 422
    // counts nothing as skipped.
    if decoded.encoded_values > 0 {
        metrics::inc_unscanned(
            MODE,
            ROUTE,
            direction,
            UnscannedReason::EncodedData,
            decoded.encoded_values as u64,
        );
    }

    // One body unit per top-level entry. The route reports rather than
    // blocks, so the engine never short-circuits.
    let mut units = Units::new();
    for fragments in decoded.units {
        units.push_body(UnitContent::Structured { fragments });
    }
    let mut scan_result = state
        .engine
        .guard(
            units.into_shared(),
            &state.selection,
            BlockPolicy::Never,
            state.on_error,
        )
        .await;

    record_detections(&scan_result, &state.pii_guards, direction);
    if let Some(resp) = handle_guard_error(&mut scan_result, state.on_error) {
        return resp;
    }

    let payload = if scan_result.detected() {
        GuardrailResponse::Blocked {
            blocked_reason: format!("{BLOCKED_REASON}{}", scan_result.kinds().join(", ")),
        }
    } else {
        GuardrailResponse::None
    };
    guardrail_response(&payload)
}

/// A 200 carrying the LiteLLM verdict.
fn guardrail_response(payload: &GuardrailResponse) -> Response {
    let body = serde_json::to_vec(payload).unwrap_or_else(|_| b"{}".to_vec());
    let resp = (StatusCode::OK, [("content-type", "application/json")], body).into_response();
    record_request(resp.status());
    resp
}

/// Increment the detection families. This runs also when a guard error turns
/// the answer into a 500. The PII family counts the PII guards' kinds only.
fn record_detections(scan_result: &ScanResult, pii_guards: &PiiGuards, direction: &str) {
    for kind in &pii_guards.kinds(scan_result) {
        metrics::inc_detection(kind, MODE, ROUTE, direction);
    }
    for guard in scan_result.guards() {
        metrics::inc_guard_detection(&guard, MODE, ROUTE, direction);
    }
}

/// A guard error does not discard the findings of the guards that succeeded:
/// `fail_open` reports them and this returns `None`, `fail_close` answers the
/// error's fixed response.
fn handle_guard_error(scan_result: &mut ScanResult, on_error: OnError) -> Option<Response> {
    let e = scan_result.take_error()?;
    if let Some(dropped) = SCANNER_ERROR_LIMITER.should_log() {
        warn!(dropped, error = %e, "scanner error in http api");
    }
    handle_scanner_failure(e, on_error)
}

fn unsupported_content_type() -> Response {
    let resp = (
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        [("content-type", "application/json")],
        r#"{"error":"unsupported content type"}"#,
    )
        .into_response();
    record_request(resp.status());
    resp
}

/// A body that does not parse as its declared type is always 400 — the caller
/// declared the type, so silently falling back would mask their bug
/// (openspec/specs/http-api/spec.md). This rule overrides `on_error`.
fn malformed_body() -> Response {
    metrics::inc_error("blocked", "body_parse_failed");
    let resp = (
        StatusCode::BAD_REQUEST,
        [("content-type", "application/json")],
        r#"{"error":"malformed body for declared content type"}"#,
    )
        .into_response();
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

/// On a guard error, follow the configured `on_error` policy. The error names
/// its own reason, status, and fixed body.
///
/// `fail_open`: count the error and return `None`, so the caller reports the
/// findings of the guards that succeeded. `fail_close`: return the error's
/// fixed response — 500 for a failure, 413 for a window limit.
fn handle_scanner_failure(err: Error, on_error: OnError) -> Option<Response> {
    match on_error {
        OnError::FailOpen => {
            metrics::inc_error("passed", err.scan_reason());
            None
        }
        OnError::FailClose => {
            metrics::inc_error("blocked", err.scan_reason());
            let resp = err.into_response();
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

    #[test]
    fn openapi_spec_describes_the_litellm_route() {
        let spec: serde_json::Value = serde_json::from_str(&build_openapi_spec()).unwrap();

        let post = &spec["paths"][LITELLM_PATH]["post"];
        assert!(post.is_object(), "the document has no LiteLLM route");
        let request = &post["requestBody"]["content"]["application/json"]["schema"]["$ref"];
        assert_eq!(request, "#/components/schemas/GuardrailRequest");
        for status in ["200", "400", "413", "415", "422", "500"] {
            assert!(post["responses"][status].is_object(), "no {status}");
        }

        let actions: Vec<&serde_json::Value> =
            spec["components"]["schemas"]["GuardrailResponse"]["oneOf"]
                .as_array()
                .unwrap()
                .iter()
                .map(|shape| &shape["properties"]["action"]["enum"][0])
                .collect();
        assert_eq!(actions, ["NONE", "BLOCKED"]);
    }

    // --- A guard error does not discard the other guards' findings ---

    use crate::config::BUILTIN_PII_GUARD_NAME;
    use crate::engine::test_guard::TestGuard;
    use crate::metrics::{DETECTIONS_TOTAL, ERRORS_TOTAL};
    use http_body_util::BodyExt;

    /// Post one plain-text body to `/v1/scan` over a failing guard and the
    /// `pii` guard reporting `kind`.
    async fn scan_with_a_failing_guard(on_error: OnError, kind: &'static str) -> Response {
        let engine = Arc::new(Engine::with_guards(vec![
            Box::new(TestGuard::new("failing", "API_UNUSED").failing()),
            // Each test passes a kind no other test uses, so the PII
            // detection count for it is exact.
            Box::new(TestGuard::new(BUILTIN_PII_GUARD_NAME, kind)),
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
        // The kind label is unique to this test, so the count is exact. Other
        // tests count the `pii` guard too, so its check is a lower bound.
        assert_eq!(detections("API_FAIL_CLOSE_KIND"), 1);
        assert!(guard_detections(BUILTIN_PII_GUARD_NAME) >= 1);
        assert_eq!(guard_detections("failing"), 0);
        assert_eq!(api_blocks(), 0, "a 500 on /v1/scan is not a block");
    }

    /// metrics, "A PII model guard detects": the PII family counts a kind a
    /// guard with `class = "pii"` reports, and not one a classless guard
    /// reports.
    #[tokio::test]
    async fn the_pii_family_counts_a_pii_model_guard_and_not_a_classless_one() {
        let config: AppConfig = toml::from_str(
            r#"
[guards.api_pii_ml]
adapter = "token_classifier"
model_path = "/m"
tokenizer_path = "/t"
config_path = "/c"
max_tokens = 512
labels = ["API_PII_ML_KIND"]
class = "pii"
"#,
        )
        .expect("the test config parses");
        let engine = Arc::new(Engine::with_guards(vec![
            Box::new(TestGuard::new("api_pii_ml", "API_PII_ML_KIND")),
            Box::new(TestGuard::new("api_classless", "API_CLASSLESS_KIND")),
        ]));
        let state = build_state(&config, engine);
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/plain".parse().unwrap());

        let resp = process(state, headers, Bytes::from_static(b"content")).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(detections("API_PII_ML_KIND"), 1);
        assert_eq!(detections("API_CLASSLESS_KIND"), 0);
    }

    // --- A model guard error names its own status and reason ---

    use crate::engine::test_guard::TestFailure;

    /// Post one plain-text body to `/v1/scan` over a guard failing with
    /// `failure` and a guard that reports `kind`.
    async fn scan_with_a_model_failure(
        failure: TestFailure,
        on_error: OnError,
        kind: &'static str,
    ) -> Response {
        let engine = Arc::new(Engine::with_guards(vec![
            Box::new(TestGuard::new("model", "API_UNUSED").failing_with(failure)),
            Box::new(TestGuard::new(kind, kind)),
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

    fn errors(outcome: &str, reason: &str) -> u64 {
        ERRORS_TOTAL.with_label_values(&[outcome, reason]).get()
    }

    #[test_case(TestFailure::Inference, StatusCode::INTERNAL_SERVER_ERROR, br#"{"error":"internal error"}"#, "inference_failure" ; "inference")]
    #[test_case(TestFailure::WindowLimit, StatusCode::PAYLOAD_TOO_LARGE, br#"{"error":"tokenized content too long to scan"}"#, "window_limit" ; "window limit")]
    #[tokio::test]
    async fn a_model_guard_error_under_fail_close_answers_its_fixed_response(
        failure: TestFailure,
        status: StatusCode,
        body: &[u8],
        reason: &str,
    ) {
        let before = errors("blocked", reason);

        let resp = scan_with_a_model_failure(failure, OnError::FailClose, "API_MODEL_FC").await;

        assert_eq!(resp.status(), status);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], body);
        assert!(errors("blocked", reason) > before);
    }

    #[test_case(TestFailure::Inference, "inference_failure", "API_MODEL_FO_INF" ; "inference")]
    #[test_case(TestFailure::WindowLimit, "window_limit", "API_MODEL_FO_WL" ; "window limit")]
    #[tokio::test]
    async fn a_model_guard_error_under_fail_open_reports_the_other_guards(
        failure: TestFailure,
        reason: &str,
        kind: &'static str,
    ) {
        let before = errors("passed", reason);

        let resp = scan_with_a_model_failure(failure, OnError::FailOpen, kind).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["kinds"], serde_json::json!([kind]));
        assert!(errors("passed", reason) > before);
    }

    // --- Guard detections and blocks ---

    use crate::metrics::{GUARD_DETECTIONS_TOTAL, MESSAGES_BLOCKED_TOTAL};

    fn guard_detections(guard: &str) -> u64 {
        GUARD_DETECTIONS_TOTAL
            .with_label_values(&[guard, MODE, ROUTE, "request"])
            .get()
    }

    fn api_blocks() -> u64 {
        MESSAGES_BLOCKED_TOTAL
            .with_label_values(&[MODE, ROUTE, "request"])
            .get()
    }

    #[tokio::test]
    async fn each_guard_with_findings_counts_once_and_nothing_is_blocked() {
        let engine = Arc::new(Engine::with_guards(vec![
            Box::new(TestGuard::new("api_gm_a", "API_GM_KIND_A")),
            Box::new(TestGuard::new("api_gm_b", "API_GM_KIND_B")),
            Box::new(TestGuard::new("api_gm_quiet", "API_UNUSED").silent()),
        ]));
        let state = build_state(&AppConfig::default(), engine);
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/plain".parse().unwrap());

        let resp = process(state.clone(), headers, Bytes::from_static(b"content")).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let mut json = HeaderMap::new();
        json.insert("content-type", "application/json".parse().unwrap());
        let malformed = process(state, json, Bytes::from_static(b"{not json")).await;
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);

        assert_eq!(guard_detections("api_gm_a"), 1);
        assert_eq!(guard_detections("api_gm_b"), 1);
        assert_eq!(guard_detections("api_gm_quiet"), 0);
        assert_eq!(api_blocks(), 0, "/v1/scan reports and blocks nothing");
    }

    // --- The LiteLLM route ---

    use crate::config::{HttpApiConfig, RouteSwitch};
    use crate::engine::test_guard::GuardProbe;

    fn json_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers
    }

    fn litellm_state(guards: Vec<Box<dyn crate::engine::Guard>>, on_error: OnError) -> ApiState {
        let config = AppConfig {
            on_error,
            ..AppConfig::default()
        };
        build_state(&config, Arc::new(Engine::with_guards(guards)))
    }

    async fn post_litellm(state: ApiState, payload: serde_json::Value) -> Response {
        let body = Bytes::from(serde_json::to_vec(&payload).unwrap());
        process_litellm(state, json_headers(), body).await
    }

    async fn body_of(resp: Response) -> Vec<u8> {
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    fn user_text(text: &str) -> serde_json::Value {
        serde_json::json!({
            "input_type": "request",
            "structured_messages": [{"role": "user", "content": text}],
        })
    }

    #[tokio::test]
    async fn litellm_answers_none_when_no_guard_finds_anything() {
        let state = litellm_state(
            vec![Box::new(TestGuard::new("lt_quiet", "LT_UNUSED").silent())],
            OnError::FailClose,
        );
        let resp = post_litellm(state, user_text("hello")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_of(resp).await, br#"{"action":"NONE"}"#);
    }

    #[tokio::test]
    async fn litellm_answers_blocked_with_the_sorted_kinds() {
        let state = litellm_state(
            vec![
                Box::new(TestGuard::new("lt_b", "LT_KIND_B")),
                Box::new(TestGuard::new("lt_a", "LT_KIND_A")),
            ],
            OnError::FailClose,
        );
        let resp = post_litellm(state, user_text("hello")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(&body_of(resp).await).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "action": "BLOCKED",
                "blocked_reason": "Voidwall blocked the message. Kinds: LT_KIND_A, LT_KIND_B",
            })
        );
    }

    #[tokio::test]
    async fn litellm_rejects_a_non_json_content_type_even_when_the_allowlist_has_it() {
        let config = AppConfig {
            content_types: vec!["text/plain".into()],
            ..AppConfig::default()
        };
        let state = build_state(&config, Arc::new(Engine::with_guards(vec![])));
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/plain".parse().unwrap());
        let resp = process_litellm(state, headers, Bytes::from_static(b"{}")).await;
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            body_of(resp).await,
            br#"{"error":"unsupported content type"}"#
        );
    }

    #[test_case(OnError::FailClose ; "fail close")]
    #[test_case(OnError::FailOpen ; "fail open")]
    #[tokio::test]
    async fn litellm_answers_400_to_a_payload_without_input_type(on_error: OnError) {
        let state = litellm_state(vec![], on_error);
        let resp = post_litellm(state, serde_json::json!({"texts": ["hello"]})).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_of(resp).await,
            br#"{"error":"malformed body for declared content type"}"#
        );
    }

    fn hologram_payload() -> serde_json::Value {
        serde_json::json!({
            "input_type": "request",
            "structured_messages": [{"role": "user", "content": [
                {"type": "hologram", "data": "?"},
                {"type": "text", "text": "hello"},
            ]}],
        })
    }

    fn probed(name: &str, kind: &'static str) -> (Box<dyn crate::engine::Guard>, GuardProbe) {
        let guard = TestGuard::new(name, kind);
        let probe = guard.probe();
        (Box::new(guard), probe)
    }

    #[tokio::test]
    async fn litellm_answers_422_to_an_unknown_part_under_fail_close_and_runs_no_guard() {
        let before = errors("blocked", "unscannable_content");
        let (guard, probe) = probed("lt_422", "LT_422");
        let state = litellm_state(vec![guard], OnError::FailClose);

        let resp = post_litellm(state, hologram_payload()).await;

        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = body_of(resp).await;
        assert_eq!(body, br#"{"error":"unscannable content"}"#);
        assert_eq!(probe.calls(), 0, "no guard runs");
        assert!(errors("blocked", "unscannable_content") > before);
    }

    #[tokio::test]
    async fn litellm_skips_an_unknown_part_under_fail_open_and_scans_the_rest() {
        let before = errors("passed", "unscannable_content");
        let (guard, probe) = probed("lt_skip", "LT_SKIP");
        let state = litellm_state(vec![guard], OnError::FailOpen);

        let resp = post_litellm(state, hologram_payload()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(&body_of(resp).await).unwrap();
        assert_eq!(body["action"], "BLOCKED");
        // One unit: the message, holding the text part only.
        assert_eq!(probe.seen().len(), 1);
        assert!(errors("passed", "unscannable_content") > before);
    }

    #[tokio::test]
    async fn litellm_guard_failure_under_fail_close_answers_500() {
        let state = litellm_state(
            vec![
                Box::new(TestGuard::new("lt_fail", "LT_UNUSED").failing()),
                Box::new(TestGuard::new("lt_fc", "LT_FC")),
            ],
            OnError::FailClose,
        );
        let resp = post_litellm(state, user_text("hello")).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body_of(resp).await, br#"{"error":"internal error"}"#);
    }

    #[test_case(false, serde_json::json!({"action": "NONE"}) ; "no other finding")]
    #[test_case(true, serde_json::json!({"action": "BLOCKED", "blocked_reason": "Voidwall blocked the message. Kinds: LT_FO"}) ; "another finding")]
    #[tokio::test]
    async fn litellm_guard_failure_under_fail_open_answers_from_the_other_guards(
        finds: bool,
        expected: serde_json::Value,
    ) {
        let other = TestGuard::new("lt_fo", "LT_FO");
        let other = if finds { other } else { other.silent() };
        let state = litellm_state(
            vec![
                Box::new(TestGuard::new("lt_fail", "LT_UNUSED").failing()),
                Box::new(other),
            ],
            OnError::FailOpen,
        );
        let resp = post_litellm(state, user_text("hello")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(&body_of(resp).await).unwrap();
        assert_eq!(body, expected);
    }

    #[tokio::test]
    async fn litellm_counts_detections_under_the_response_direction_and_blocks_nothing() {
        let state = litellm_state(
            vec![Box::new(TestGuard::new("lt_resp", "LT_RESP"))],
            OnError::FailClose,
        );
        let blocked_before = MESSAGES_BLOCKED_TOTAL
            .with_label_values(&[MODE, ROUTE, "response"])
            .get();
        let payload = serde_json::json!({"input_type": "response", "texts": ["hello"]});

        let resp = post_litellm(state, payload).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let detections = GUARD_DETECTIONS_TOTAL
            .with_label_values(&["lt_resp", MODE, ROUTE, "response"])
            .get();
        assert_eq!(detections, 1);
        assert_eq!(
            MESSAGES_BLOCKED_TOTAL
                .with_label_values(&[MODE, ROUTE, "response"])
                .get(),
            blocked_before,
            "BLOCKED is not a block"
        );
    }

    // --- Route switches ---

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn switched_router(scan: bool, litellm: bool) -> Router {
        let config = AppConfig {
            http_api: HttpApiConfig {
                enabled: true,
                scan: RouteSwitch { enabled: scan },
                litellm: RouteSwitch { enabled: litellm },
                ..HttpApiConfig::default()
            },
            ..AppConfig::default()
        };
        let engine = Arc::new(Engine::with_guards(vec![Box::new(
            TestGuard::new("lt_switch", "LT_SWITCH").silent(),
        )]));
        router(build_state(&config, engine))
    }

    async fn status_of(
        router: &Router,
        path: &str,
        content_type: &str,
        body: &'static str,
    ) -> StatusCode {
        let request = Request::post(path)
            .header("content-type", content_type)
            .body(Body::from(body))
            .unwrap();
        router.clone().oneshot(request).await.unwrap().status()
    }

    const LITELLM_BODY: &str = r#"{"input_type":"request","texts":["hello"]}"#;

    #[tokio::test]
    async fn the_litellm_route_is_absent_when_its_switch_is_off() {
        let router = switched_router(true, false);
        assert_eq!(
            status_of(&router, LITELLM_PATH, "application/json", LITELLM_BODY).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status_of(&router, SCAN_PATH, "text/plain", "hello").await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn the_scan_route_is_absent_when_its_switch_is_off() {
        let router = switched_router(false, true);
        assert_eq!(
            status_of(&router, SCAN_PATH, "text/plain", "hello").await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status_of(&router, LITELLM_PATH, "application/json", LITELLM_BODY).await,
            StatusCode::OK
        );
    }
}
