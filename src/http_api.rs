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
use tracing::warn;

use crate::config::{AppConfig, HttpApiConfig, OnError, ScanConfig};
use crate::error::Error;
use crate::metrics;
use crate::scanner::{
    RedactWith, SCANNER_ERROR_LIMITER, ScanRequest, ScannerPool, classify_body, to_redact_with,
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
}

// ---------------------------------------------------------------------------
// Router & server
// ---------------------------------------------------------------------------

pub fn build_state(config: &AppConfig, scanner: Arc<ScannerPool>) -> ApiState {
    let api: &HttpApiConfig = &config.http_api;
    let redact_strategy = api
        .redact_strategy
        .map(|s| to_redact_with(s, api.mask_char));

    ApiState {
        scanner,
        scan: config.scan.clone(),
        redact_strategy,
        max_body_size: config.scan.max_body_size,
    }
}

pub fn router(state: ApiState) -> Router {
    let max_body = state.max_body_size;
    Router::new()
        .route("/v1/scan", post(scan_handler))
        .route("/v1/redact", post(redact_handler))
        .route("/openapi.json", get(openapi_handler))
        .layer(DefaultBodyLimit::max(max_body))
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

#[derive(Serialize)]
struct ScanResponse {
    detected: bool,
    matches_count: usize,
    kinds: Vec<String>,
}

async fn scan_handler(State(state): State<ApiState>, headers: HeaderMap, body: Bytes) -> Response {
    process(state, headers, body, Mode::Scan).await
}

async fn redact_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    process(state, headers, body, Mode::Redact).await
}

async fn openapi_handler() -> Response {
    // OpenAPI spec generation is implemented in Phase 8.2. Until then, return
    // a stable 501 so callers don't think the route is missing.
    record_request(StatusCode::NOT_IMPLEMENTED);
    (
        StatusCode::NOT_IMPLEMENTED,
        [("content-type", "application/json")],
        r#"{"error":"OpenAPI spec generation not yet implemented"}"#,
    )
        .into_response()
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
}
