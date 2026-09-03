use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

use crate::action::{self, ActionContext, ActionOutcome, ActionSet};
use crate::config::{AppConfig, OnError, ScanConfig};
use crate::error::Error;
use crate::metrics;
use crate::scanner::SCANNER_ERROR_LIMITER;
use crate::scanner::{BodyFormat, ScanRequest, ScanResult, ScannerPool, classify_body};
use crate::specialization::{
    self, ScanHandle, SpecDirection, Specialization, merge_with_default_scan,
};

// ---------------------------------------------------------------------------
// Hop-by-hop headers to strip when proxying
// ---------------------------------------------------------------------------

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP_HEADERS
        .iter()
        .any(|h| name.as_str().eq_ignore_ascii_case(h))
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Per-route resolved configuration.
struct ResolvedRoute {
    path_prefix: String,
    upstream: String,
    scan: ScanConfig,
    /// Optional specialization that owns query+body decoding for this route.
    /// Wired up by config in `docs/history/tasks-phases-1-20.md` § 16.5; always
    /// `None` at this stage so existing behaviour is unchanged.
    specialization: Option<&'static dyn Specialization>,
}

/// Shared state for the reverse proxy handlers.
#[derive(Clone)]
pub struct ReverseProxyState {
    routes: Arc<Vec<ResolvedRoute>>,
    clients: Arc<HashMap<String, Client<hyper_util::client::legacy::connect::HttpConnector, Body>>>,
    scanner: Arc<ScannerPool>,
    request_actions: ActionSet,
    response_actions: ActionSet,
    request_redact_strategy: Option<crate::scanner::RedactWith>,
    response_redact_strategy: Option<crate::scanner::RedactWith>,
}

// ---------------------------------------------------------------------------
// Router & server
// ---------------------------------------------------------------------------

/// Build the reverse proxy state from configuration.
pub fn build_state(config: &AppConfig, scanner: Arc<ScannerPool>) -> ReverseProxyState {
    let rp = &config.reverse_proxy;

    let request_actions = ActionSet::from_direction_config(&rp.request);
    let response_actions = ActionSet::from_direction_config(&rp.response);

    let request_redact_strategy = if request_actions.redact {
        rp.request
            .redact_strategy
            .map(|s| crate::scanner::to_redact_with(s, rp.request.mask_char))
    } else {
        None
    };
    let response_redact_strategy = if response_actions.redact {
        rp.response
            .redact_strategy
            .map(|s| crate::scanner::to_redact_with(s, rp.response.mask_char))
    } else {
        None
    };

    // Build one pooling client per unique upstream.
    let mut clients = HashMap::new();
    for route in &rp.routes {
        if !clients.contains_key(&route.upstream) {
            let client = Client::builder(TokioExecutor::new())
                .pool_idle_timeout(std::time::Duration::from_secs(30))
                .build_http();
            clients.insert(route.upstream.clone(), client);
        }
    }

    // Resolve per-route scan config (route override fully replaces defaults)
    // and look up any configured specialization. Unknown names are rejected
    // by `AppConfig::validate()` at config load, so `lookup` returns `Some`
    // for every name that reaches here.
    let routes: Vec<ResolvedRoute> = rp
        .routes
        .iter()
        .map(|r| ResolvedRoute {
            path_prefix: r.path_prefix.clone(),
            upstream: r.upstream.clone(),
            scan: r.scan.clone().unwrap_or_else(|| config.scan.clone()),
            specialization: r.specialization.as_deref().and_then(specialization::lookup),
        })
        .collect();

    ReverseProxyState {
        routes: Arc::new(routes),
        clients: Arc::new(clients),
        scanner,
        request_actions,
        response_actions,
        request_redact_strategy,
        response_redact_strategy,
    }
}

/// Build the axum router for the reverse proxy.
pub fn router(state: ReverseProxyState) -> Router {
    Router::new().fallback(proxy_handler).with_state(state)
}

/// Start the reverse proxy server.
pub async fn serve(
    config: &AppConfig,
    scanner: Arc<ScannerPool>,
    cancel: CancellationToken,
) -> Result<(), Error> {
    let state = build_state(config, scanner);
    let app = router(state);
    let listener = TcpListener::bind(&config.reverse_proxy.listen).await?;
    tracing::info!(listen = %config.reverse_proxy.listen, "reverse proxy started");

    axum::serve(listener, app)
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await
        .map_err(Error::Io)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Request handler
// ---------------------------------------------------------------------------

async fn proxy_handler(State(state): State<ReverseProxyState>, req: Request) -> Response {
    let start = std::time::Instant::now();
    let method = req.method().clone();

    // Route matching — longest prefix wins.
    let path = req.uri().path().to_string();
    let matched = match_route(&state.routes, &path);

    let Some(route) = matched else {
        metrics::inc_request("reverse_proxy", "", method.as_str(), "404");
        return (StatusCode::NOT_FOUND, "no matching route").into_response();
    };

    let route_label = route.path_prefix.clone();

    let response = handle_proxied_request(&state, req, route).await;

    let status = response.status();
    let elapsed = start.elapsed().as_secs_f64();
    metrics::inc_request(
        "reverse_proxy",
        &route_label,
        method.as_str(),
        &status.as_u16().to_string(),
    );
    metrics::observe_duration("reverse_proxy", &route_label, elapsed);

    response
}

/// Match the longest path_prefix that is a prefix of `path`.
fn match_route<'a>(routes: &'a [ResolvedRoute], path: &str) -> Option<&'a ResolvedRoute> {
    routes
        .iter()
        .filter(|r| path.starts_with(&r.path_prefix))
        .max_by_key(|r| r.path_prefix.len())
}

// ---------------------------------------------------------------------------
// Core pipeline
// ---------------------------------------------------------------------------

async fn handle_proxied_request(
    state: &ReverseProxyState,
    req: Request,
    route: &ResolvedRoute,
) -> Response {
    let scan_config = &route.scan;
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Buffer the request body.
    let body_bytes = match buffer_body(req, scan_config.max_body_size, scan_config.on_error).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let mut forward_body = body_bytes.clone();
    let mut forward_headers = headers.clone();
    let mut forward_uri = uri.clone();

    // --- Request scanning ---
    if !state.request_actions.is_empty() {
        let ctx = ActionContext {
            mode: "reverse_proxy",
            route: &route.path_prefix,
            direction: "request",
            specialization: route.specialization.map(|s| s.name()).unwrap_or("none"),
        };

        // Check content-type for body scanning.
        let should_scan_body = scan_config.body
            && !body_bytes.is_empty()
            && is_content_type_allowed(&headers, &scan_config.content_types);

        match scan_and_act(
            &state.scanner,
            scan_config,
            &state.request_actions,
            state.request_redact_strategy.clone(),
            &ctx,
            &uri,
            &headers,
            if should_scan_body {
                Some(&body_bytes)
            } else {
                None
            },
            route.specialization,
        )
        .await
        {
            PipelineResult::Block(resp) => return resp,
            PipelineResult::Forward {
                body,
                extra_headers,
                redacted_path,
                redacted_query,
                redacted_headers,
            } => {
                if let Some(b) = body {
                    forward_body = b;
                }
                for (name, value) in extra_headers.iter() {
                    forward_headers.insert(name.clone(), value.clone());
                }
                if let Some(rh) = redacted_headers {
                    apply_redacted_headers(&mut forward_headers, &rh);
                }
                if redacted_path.is_some() || redacted_query.is_some() {
                    forward_uri =
                        rebuild_uri(&uri, redacted_path.as_deref(), redacted_query.as_deref());
                }
            }
            PipelineResult::Pass => {}
            PipelineResult::Error(resp) => return resp,
        }
    }

    // --- Build & send upstream request ---
    let upstream_uri = build_upstream_uri(&route.upstream, &forward_uri);
    let client = match state.clients.get(&route.upstream) {
        Some(c) => c,
        None => {
            error!(upstream = %route.upstream, "no client for upstream");
            return Error::Proxy("no client for upstream".into()).into_response();
        }
    };

    // Strip hop-by-hop headers, host, and content-length. Content-length must
    // be removed because body redaction may change the body size; hyper will
    // recompute it from the actual body when sending the upstream request.
    let mut upstream_headers = HeaderMap::new();
    for (name, value) in forward_headers.iter() {
        if !is_hop_by_hop(name) && name != "host" && name != "content-length" {
            upstream_headers.insert(name.clone(), value.clone());
        }
    }

    let upstream_req = match hyper::Request::builder()
        .method(method)
        .uri(&upstream_uri)
        .body(Body::from(forward_body))
    {
        Ok(mut r) => {
            *r.headers_mut() = upstream_headers;
            r
        }
        Err(e) => {
            error!(error = %e, "failed to build upstream request");
            return Error::Proxy(format!("failed to build upstream request: {e}")).into_response();
        }
    };

    let upstream_resp = match client.request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, upstream = %route.upstream, "upstream request failed");
            return Error::Proxy(format!("upstream error: {e}")).into_response();
        }
    };

    let resp_status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    // --- Response scanning ---
    if !state.response_actions.is_empty() {
        let resp_body = match upstream_resp.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                error!(error = %e, "failed to read upstream response body");
                return Error::Proxy(format!("failed to read upstream response: {e}"))
                    .into_response();
            }
        };

        let ctx = ActionContext {
            mode: "reverse_proxy",
            route: &route.path_prefix,
            direction: "response",
            specialization: route.specialization.map(|s| s.name()).unwrap_or("none"),
        };

        let should_scan_body = scan_config.body
            && !resp_body.is_empty()
            && is_content_type_allowed(&resp_headers, &scan_config.content_types);

        match scan_and_act_response(
            &state.scanner,
            scan_config,
            &state.response_actions,
            state.response_redact_strategy.clone(),
            &ctx,
            &resp_headers,
            if should_scan_body {
                Some(&resp_body)
            } else {
                None
            },
            route.specialization,
        )
        .await
        {
            PipelineResult::Block(resp) => return resp,
            PipelineResult::Forward {
                body,
                extra_headers,
                redacted_headers,
                ..
            } => {
                let final_body = body.unwrap_or(resp_body);
                let mut final_headers = strip_hop_by_hop(&resp_headers);
                // Remove stale content-length; body redaction may have changed
                // the size, and hyper will set the correct value from the body.
                final_headers.remove("content-length");
                if let Some(rh) = redacted_headers {
                    apply_redacted_headers(&mut final_headers, &rh);
                }
                for (name, value) in extra_headers.iter() {
                    final_headers.insert(name.clone(), value.clone());
                }
                return build_response(resp_status, final_headers, final_body);
            }
            PipelineResult::Pass => {
                let final_headers = strip_hop_by_hop(&resp_headers);
                return build_response(resp_status, final_headers, resp_body);
            }
            PipelineResult::Error(resp) => return resp,
        }
    }

    // No response scanning — stream through, stripping hop-by-hop.
    let final_headers = strip_hop_by_hop(&resp_headers);
    let mut resp = upstream_resp.map(Body::new);
    *resp.headers_mut() = final_headers;
    resp
}

// ---------------------------------------------------------------------------
// Pipeline result
// ---------------------------------------------------------------------------

enum PipelineResult {
    Block(Response),
    Forward {
        body: Option<Bytes>,
        extra_headers: HeaderMap,
        redacted_path: Option<String>,
        redacted_query: Option<String>,
        redacted_headers: Option<Vec<(String, String)>>,
    },
    Pass,
    Error(Response),
}

// ---------------------------------------------------------------------------
// Scan + action helpers
// ---------------------------------------------------------------------------

/// Scan request direction and execute actions.
#[allow(clippy::too_many_arguments)]
async fn scan_and_act(
    scanner: &ScannerPool,
    scan_config: &ScanConfig,
    action_set: &ActionSet,
    redact_strategy: Option<crate::scanner::RedactWith>,
    ctx: &ActionContext<'_>,
    uri: &Uri,
    headers: &HeaderMap,
    body: Option<&Bytes>,
    spec: Option<&'static dyn Specialization>,
) -> PipelineResult {
    // Specialization path: it owns query+body decoding for this request.
    // URL path and request headers still go through the default scan path
    // (their detections are merged into the final ScanResult).
    if let Some(spec) = spec {
        let handle = ScanHandle::new(
            scanner,
            action_set.redact,
            redact_strategy.clone(),
            scan_config.on_error,
        );
        let content_type = headers.get("content-type").and_then(|v| v.to_str().ok());
        let query_str = uri.query();
        let body_slice = body.map(|b| b.as_ref());

        let dispatch_result = specialization::dispatch(
            spec,
            SpecDirection::Request,
            query_str,
            body_slice,
            content_type,
            &handle,
        )
        .await;

        if let Ok(processed) = dispatch_result {
            let ph_result = match run_path_headers_scan(
                scanner,
                scan_config,
                action_set,
                redact_strategy,
                Some(uri),
                headers,
            )
            .await
            {
                Ok(r) => r,
                Err(pr) => return pr,
            };
            let redact_enabled = handle.redact_enabled();
            let merged = merge_with_default_scan(processed, ph_result, redact_enabled);
            return pipeline_result_from_outcome(action::execute(merged, action_set, ctx));
        }
        // Spec errored — fall through to the default scan path. The
        // dispatch() helper already recorded the metric + rate-limited warn
        // when appropriate.
    }

    let scan_body = match classify_scan_body(body, headers, scan_config.on_error) {
        Ok(b) => b,
        Err(resp) => return *resp,
    };

    // URL path and query are scanned separately (not merged into one string)
    // because: (1) each can be independently enabled via config, (2) redaction
    // rewrites offsets within each string — a combined string would require
    // tracking the `?` boundary to split back into path and query for URI
    // reconstruction, and (3) these strings are tiny so the extra scan call
    // has negligible cost compared to body scanning.
    let scan_path = if scan_config.url_path {
        Some(uri.path().to_string())
    } else {
        None
    };

    let scan_query = if scan_config.query_params {
        uri.query().map(|q| q.to_string())
    } else {
        None
    };

    let scan_headers = collect_scan_headers(scan_config, headers);

    if scan_body.is_none() && scan_path.is_none() && scan_query.is_none() && scan_headers.is_none()
    {
        return PipelineResult::Pass;
    }

    let scan_req = ScanRequest {
        body: scan_body,
        path: scan_path,
        query: scan_query,
        headers: scan_headers,
        redact: action_set.redact,
        redact_strategy,
    };

    let scan_result = match scanner.process(scan_req, scan_config.on_error).await {
        Ok(r) => r,
        Err(e) => {
            if let Some(dropped) = SCANNER_ERROR_LIMITER.should_log() {
                warn!(dropped, error = %e, "scanner error");
            }
            return handle_scan_error(e, scan_config.on_error);
        }
    };

    pipeline_result_from_outcome(action::execute(scan_result, action_set, ctx))
}

/// Scan response direction and execute actions.
#[allow(clippy::too_many_arguments)]
async fn scan_and_act_response(
    scanner: &ScannerPool,
    scan_config: &ScanConfig,
    action_set: &ActionSet,
    redact_strategy: Option<crate::scanner::RedactWith>,
    ctx: &ActionContext<'_>,
    headers: &HeaderMap,
    body: Option<&Bytes>,
    spec: Option<&'static dyn Specialization>,
) -> PipelineResult {
    // Specialization path: response receives the body only (no query). For
    // tracker endpoints the upstream typically replies with a 1x1 gif or
    // 204, so UnsupportedContentType is the common case — dispatch() keeps
    // that silent and the proxy falls through to the default scan path
    // (where the response Content-Type allowlist filters it out).
    if let Some(spec) = spec {
        let handle = ScanHandle::new(
            scanner,
            action_set.redact,
            redact_strategy.clone(),
            scan_config.on_error,
        );
        let content_type = headers.get("content-type").and_then(|v| v.to_str().ok());
        let body_slice = body.map(|b| b.as_ref());

        let dispatch_result = specialization::dispatch(
            spec,
            SpecDirection::Response,
            None,
            body_slice,
            content_type,
            &handle,
        )
        .await;

        if let Ok(processed) = dispatch_result {
            let ph_result = match run_path_headers_scan(
                scanner,
                scan_config,
                action_set,
                redact_strategy,
                None,
                headers,
            )
            .await
            {
                Ok(r) => r,
                Err(pr) => return pr,
            };
            let redact_enabled = handle.redact_enabled();
            let merged = merge_with_default_scan(processed, ph_result, redact_enabled);
            return pipeline_result_from_outcome(action::execute(merged, action_set, ctx));
        }
    }

    let scan_body = match classify_scan_body(body, headers, scan_config.on_error) {
        Ok(b) => b,
        Err(resp) => return *resp,
    };
    let scan_headers = collect_scan_headers(scan_config, headers);

    if scan_body.is_none() && scan_headers.is_none() {
        return PipelineResult::Pass;
    }

    let scan_req = ScanRequest {
        body: scan_body,
        path: None,
        query: None,
        headers: scan_headers,
        redact: action_set.redact,
        redact_strategy,
    };

    let scan_result = match scanner.process(scan_req, scan_config.on_error).await {
        Ok(r) => r,
        Err(e) => {
            if let Some(dropped) = SCANNER_ERROR_LIMITER.should_log() {
                warn!(dropped, error = %e, "scanner error on response");
            }
            return handle_scan_error(e, scan_config.on_error);
        }
    };

    pipeline_result_from_outcome(action::execute(scan_result, action_set, ctx))
}

/// Run the default scan path covering only the URL path (when `uri` is
/// `Some`) and configured request headers. Used by the specialization
/// branch: spec owns query+body, the proxy still scans path+headers and
/// merges results. Returns an empty `ScanResult` when both are disabled
/// (avoids a round-trip through the scanner pool).
#[allow(clippy::too_many_arguments)]
async fn run_path_headers_scan(
    scanner: &ScannerPool,
    scan_config: &ScanConfig,
    action_set: &ActionSet,
    redact_strategy: Option<crate::scanner::RedactWith>,
    uri: Option<&Uri>,
    headers: &HeaderMap,
) -> Result<ScanResult, PipelineResult> {
    let scan_path = match uri {
        Some(u) if scan_config.url_path => Some(u.path().to_string()),
        _ => None,
    };
    let scan_headers = collect_scan_headers(scan_config, headers);

    if scan_path.is_none() && scan_headers.is_none() {
        return Ok(empty_scan_result());
    }

    let req = ScanRequest {
        body: None,
        path: scan_path,
        query: None,
        headers: scan_headers,
        redact: action_set.redact,
        redact_strategy,
    };

    scanner
        .process(req, scan_config.on_error)
        .await
        .map_err(|e| {
            if let Some(dropped) = SCANNER_ERROR_LIMITER.should_log() {
                warn!(dropped, error = %e, "scanner error during path/headers scan");
            }
            handle_scan_error(e, scan_config.on_error)
        })
}

fn empty_scan_result() -> ScanResult {
    ScanResult {
        detected: false,
        kinds: Vec::new(),
        matches_count: 0,
        redacted_body: None,
        redacted_path: None,
        redacted_query: None,
        redacted_headers: None,
    }
}

/// Classify the body bytes into a `BodyFormat` based on Content-Type, applying
/// the `on_error` policy on parse failure: `fail_open` falls back to plain text
/// scanning, `fail_close` short-circuits with a `PipelineResult::Error` block
/// response. Returns `Ok(None)` when there is no body to scan.
///
/// `Err` is boxed so the `Result` stays small on the stack; the error path
/// only fires on parse failure under `fail_close`, so the heap allocation is
/// off the hot path while the success path pays no extra size.
fn classify_scan_body(
    body: Option<&Bytes>,
    headers: &HeaderMap,
    on_error: OnError,
) -> Result<Option<BodyFormat>, Box<PipelineResult>> {
    let Some(bytes) = body else {
        return Ok(None);
    };
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match classify_body(bytes.clone(), content_type) {
        Ok(format) => Ok(Some(format)),
        Err(_) => match on_error {
            OnError::FailOpen => {
                metrics::inc_error("passed", "body_parse_failed");
                Ok(Some(BodyFormat::PlainText(bytes.clone())))
            }
            OnError::FailClose => {
                metrics::inc_error("blocked", "body_parse_failed");
                Err(Box::new(PipelineResult::Error(
                    Error::Scanner("body parse failed".into()).into_response(),
                )))
            }
        },
    }
}

fn collect_scan_headers(
    scan_config: &ScanConfig,
    headers: &HeaderMap,
) -> Option<Vec<(String, String)>> {
    if scan_config.headers.is_empty() {
        return None;
    }
    let mut h = Vec::new();
    for header_name in &scan_config.headers {
        if let Ok(name) = header_name.parse::<HeaderName>()
            && let Some(value) = headers.get(&name)
            && let Ok(v) = value.to_str()
        {
            h.push((header_name.clone(), v.to_string()));
        }
    }
    if h.is_empty() { None } else { Some(h) }
}

fn pipeline_result_from_outcome(outcome: ActionOutcome) -> PipelineResult {
    match outcome {
        ActionOutcome::Block {
            status,
            body,
            headers,
        } => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
            let mut resp = Response::new(Body::from(body));
            *resp.status_mut() = status;
            *resp.headers_mut() = headers;
            PipelineResult::Block(resp)
        }
        ActionOutcome::Forward {
            body,
            extra_headers,
            scan_result,
        } => PipelineResult::Forward {
            body,
            extra_headers,
            redacted_path: scan_result.redacted_path,
            redacted_query: scan_result.redacted_query,
            redacted_headers: scan_result.redacted_headers,
        },
        ActionOutcome::Pass => PipelineResult::Pass,
    }
}

fn handle_scan_error(err: Error, on_error: OnError) -> PipelineResult {
    match on_error {
        OnError::FailOpen => {
            metrics::inc_error("passed", "scanner_failure");
            PipelineResult::Pass
        }
        OnError::FailClose => {
            metrics::inc_error("blocked", "scanner_failure");
            PipelineResult::Error(err.into_response())
        }
    }
}

// ---------------------------------------------------------------------------
// Body buffering
// ---------------------------------------------------------------------------

async fn buffer_body(req: Request, max_size: usize, on_error: OnError) -> Result<Bytes, Response> {
    let collected =
        req.into_body().collect().await.map_err(|e| {
            Error::Proxy(format!("failed to read request body: {e}")).into_response()
        })?;
    let bytes = collected.to_bytes();

    if bytes.len() > max_size {
        match on_error {
            OnError::FailOpen => {
                metrics::inc_error("passed", "body_too_large");
                Ok(bytes)
            }
            OnError::FailClose => {
                metrics::inc_error("blocked", "body_too_large");
                Err(Error::BodyTooLarge.into_response())
            }
        }
    } else {
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// Header / URI helpers
// ---------------------------------------------------------------------------

fn is_content_type_allowed(headers: &HeaderMap, allowed: &[String]) -> bool {
    let Some(ct) = headers.get("content-type") else {
        // No content-type header — don't scan body.
        return false;
    };
    let Ok(ct_str) = ct.to_str() else {
        return false;
    };
    // Match the media type portion (before any parameters like charset).
    let media_type = ct_str.split(';').next().unwrap_or(ct_str).trim();
    allowed.iter().any(|a| a.eq_ignore_ascii_case(media_type))
}

fn strip_hop_by_hop(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers.iter() {
        if !is_hop_by_hop(name) {
            out.insert(name.clone(), value.clone());
        }
    }
    out
}

fn apply_redacted_headers(headers: &mut HeaderMap, redacted: &[(String, String)]) {
    for (name, value) in redacted {
        if let (Ok(n), Ok(v)) = (name.parse::<HeaderName>(), value.parse::<HeaderValue>()) {
            headers.insert(n, v);
        }
    }
}

/// Rebuild a URI with optionally redacted path and/or query.
fn rebuild_uri(original: &Uri, redacted_path: Option<&str>, redacted_query: Option<&str>) -> Uri {
    let path = redacted_path.unwrap_or_else(|| original.path());
    let query = redacted_query.or_else(|| original.query());
    let pq = match query {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    };
    Uri::builder()
        .path_and_query(pq)
        .build()
        .unwrap_or_else(|_| original.clone())
}

fn build_upstream_uri(upstream: &str, original: &Uri) -> String {
    let upstream = upstream.trim_end_matches('/');
    let path = original.path();
    let query = original
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    format!("{upstream}{path}{query}")
}

fn build_response(status: StatusCode, headers: HeaderMap, body: Bytes) -> Response {
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    resp
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    // --- Route matching ---

    fn routes(prefixes: &[&str]) -> Vec<ResolvedRoute> {
        prefixes
            .iter()
            .map(|p| ResolvedRoute {
                path_prefix: p.to_string(),
                upstream: format!("http://upstream{p}"),
                scan: ScanConfig::default(),
                specialization: None,
            })
            .collect()
    }

    #[test_case(&["/api", "/api/v2", "/"], "/api/v2/users", "/api/v2" ; "longest prefix wins")]
    #[test_case(&["/api", "/payments"], "/api/orders", "/api" ; "simple match")]
    #[test_case(&["/"], "/anything", "/" ; "root catches all")]
    fn route_matching(prefixes: &[&str], path: &str, expected_prefix: &str) {
        let rs = routes(prefixes);
        let matched = match_route(&rs, path).unwrap();
        assert_eq!(matched.path_prefix, expected_prefix);
    }

    #[test]
    fn route_matching_no_match() {
        let rs = routes(&["/api", "/payments"]);
        assert!(match_route(&rs, "/other").is_none());
    }

    // --- build_state specialization resolution ---

    #[test]
    fn build_state_resolves_route_specialization() {
        use crate::config::{AppConfig, PiiConfig, ReverseProxyConfig, Route};
        let config = AppConfig {
            pii: PiiConfig {
                countries: vec![voidwall_pii::Country::International],
                languages: vec![voidwall_pii::Language::En],
                scanner_threads: Some(1),
                detect: None,
                ignore: None,
                custom: Vec::new(),
            },
            scan: ScanConfig::default(),
            reverse_proxy: ReverseProxyConfig {
                enabled: true,
                listen: "127.0.0.1:0".into(),
                routes: vec![
                    Route {
                        path_prefix: "/g/collect".into(),
                        upstream: "http://example.com".into(),
                        scan: None,
                        specialization: Some("ga4".into()),
                    },
                    Route {
                        path_prefix: "/matomo.php".into(),
                        upstream: "http://example.com".into(),
                        scan: None,
                        specialization: Some("matomo".into()),
                    },
                    Route {
                        path_prefix: "/plain".into(),
                        upstream: "http://example.com".into(),
                        scan: None,
                        specialization: None,
                    },
                ],
                ..Default::default()
            },
            forward_proxy: Default::default(),
            http_api: Default::default(),
            admin: Default::default(),
            shutdown_timeout_secs: 30,
        };
        let scanner = Arc::new(ScannerPool::new(&config.pii).expect("pool starts"));
        let state = build_state(&config, scanner);

        let ga4_route = state
            .routes
            .iter()
            .find(|r| r.path_prefix == "/g/collect")
            .unwrap();
        assert_eq!(ga4_route.specialization.map(|s| s.name()), Some("ga4"));

        let matomo_route = state
            .routes
            .iter()
            .find(|r| r.path_prefix == "/matomo.php")
            .unwrap();
        assert_eq!(
            matomo_route.specialization.map(|s| s.name()),
            Some("matomo")
        );

        let plain_route = state
            .routes
            .iter()
            .find(|r| r.path_prefix == "/plain")
            .unwrap();
        assert!(plain_route.specialization.is_none());
    }

    // --- URI building ---

    #[test_case("http://backend:8080", "/api/users", "http://backend:8080/api/users" ; "simple path")]
    #[test_case("http://backend:8080/", "/api/users", "http://backend:8080/api/users" ; "trailing slash")]
    #[test_case("http://backend:8080", "/api?q=1", "http://backend:8080/api?q=1" ; "with query")]
    fn upstream_uri(upstream: &str, original: &str, expected: &str) {
        let uri: Uri = original.parse().unwrap();
        assert_eq!(build_upstream_uri(upstream, &uri), expected);
    }

    // --- Hop-by-hop ---

    #[test_case("connection", true ; "connection")]
    #[test_case("keep-alive", true ; "keep-alive")]
    #[test_case("transfer-encoding", true ; "transfer-encoding")]
    #[test_case("content-type", false ; "content-type")]
    #[test_case("x-custom", false ; "custom header")]
    fn hop_by_hop_detection(name: &str, expected: bool) {
        let header_name: HeaderName = name.parse().unwrap();
        assert_eq!(is_hop_by_hop(&header_name), expected);
    }

    // --- Content-type checking ---

    #[test]
    fn content_type_allowed_json() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        let allowed = vec!["application/json".into(), "text/plain".into()];
        assert!(is_content_type_allowed(&headers, &allowed));
    }

    #[test]
    fn content_type_allowed_with_charset() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            "application/json; charset=utf-8".parse().unwrap(),
        );
        let allowed = vec!["application/json".into()];
        assert!(is_content_type_allowed(&headers, &allowed));
    }

    #[test]
    fn content_type_not_allowed() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "image/png".parse().unwrap());
        let allowed = vec!["application/json".into()];
        assert!(!is_content_type_allowed(&headers, &allowed));
    }

    #[test]
    fn content_type_missing() {
        let headers = HeaderMap::new();
        let allowed = vec!["application/json".into()];
        assert!(!is_content_type_allowed(&headers, &allowed));
    }

    // --- Body buffering ---

    #[tokio::test]
    async fn buffer_body_within_limit() {
        let req = Request::builder().body(Body::from("hello")).unwrap();
        let result = buffer_body(req, 1024, OnError::FailClose).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from("hello"));
    }

    #[tokio::test]
    async fn buffer_body_exceeds_limit_fail_close() {
        let req = Request::builder().body(Body::from("hello world")).unwrap();
        let result = buffer_body(req, 5, OnError::FailClose).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn buffer_body_exceeds_limit_fail_open() {
        let req = Request::builder().body(Body::from("hello world")).unwrap();
        let result = buffer_body(req, 5, OnError::FailOpen).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from("hello world"));
    }

    // --- Pipeline result from outcome ---

    #[test]
    fn pipeline_pass() {
        let result = pipeline_result_from_outcome(ActionOutcome::Pass);
        assert!(matches!(result, PipelineResult::Pass));
    }

    #[test]
    fn pipeline_block() {
        let result = pipeline_result_from_outcome(ActionOutcome::Block {
            status: 403,
            body: Bytes::from("blocked"),
            headers: HeaderMap::new(),
        });
        assert!(matches!(result, PipelineResult::Block(_)));
    }

    #[test]
    fn pipeline_forward() {
        use crate::scanner::ScanResult;
        let result = pipeline_result_from_outcome(ActionOutcome::Forward {
            body: Some(Bytes::from("redacted")),
            extra_headers: HeaderMap::new(),
            scan_result: ScanResult {
                detected: true,
                kinds: vec!["EMAIL".into()],
                matches_count: 1,
                redacted_body: Some(Bytes::from("redacted")),
                redacted_path: None,
                redacted_query: None,
                redacted_headers: None,
            },
        });
        assert!(matches!(result, PipelineResult::Forward { .. }));
    }

    // --- Header helpers ---

    #[test]
    fn strip_hop_by_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "keep-alive".parse().unwrap());
        headers.insert("content-type", "text/plain".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("x-custom", "value".parse().unwrap());

        let stripped = strip_hop_by_hop(&headers);
        assert!(stripped.get("connection").is_none());
        assert!(stripped.get("transfer-encoding").is_none());
        assert_eq!(stripped.get("content-type").unwrap(), "text/plain");
        assert_eq!(stripped.get("x-custom").unwrap(), "value");
    }

    #[test]
    fn apply_redacted_headers_replaces() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer secret".parse().unwrap());

        apply_redacted_headers(
            &mut headers,
            &[("authorization".into(), "Bearer [REDACTED]".into())],
        );
        assert_eq!(headers.get("authorization").unwrap(), "Bearer [REDACTED]");
    }

    // --- Scan header collection ---

    #[test]
    fn collect_scan_headers_picks_configured() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer token".parse().unwrap());
        headers.insert("x-safe", "clean".parse().unwrap());

        let scan_config = ScanConfig {
            headers: vec!["Authorization".into()],
            ..ScanConfig::default()
        };

        let collected = collect_scan_headers(&scan_config, &headers);
        let collected = collected.unwrap();
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].0, "Authorization");
        assert_eq!(collected[0].1, "Bearer token");
    }

    #[test]
    fn collect_scan_headers_empty_config() {
        let headers = HeaderMap::new();
        let scan_config = ScanConfig::default();
        assert!(collect_scan_headers(&scan_config, &headers).is_none());
    }

    // --- Specialization pipeline integration (16.2) ---

    use crate::config::PiiConfig;
    use crate::specialization::{
        AggregatedScan, ProcessFuture, ProcessedPart, ProcessedRequest, ScanHandle,
        SpecializationError,
    };
    use bytes::Bytes;

    fn pool_for_tests() -> ScannerPool {
        ScannerPool::new(&PiiConfig {
            countries: vec![voidwall_pii::Country::International],
            languages: vec![voidwall_pii::Language::En],
            scanner_threads: Some(1),
            detect: None,
            ignore: None,
            custom: Vec::new(),
        })
        .expect("pool starts")
    }

    /// Mock spec that returns a re-encoded query + body plus one EMAIL kind,
    /// regardless of input. Lets us verify the merge path: the proxy still
    /// runs path/headers default scanning, and the final ScanResult contains
    /// both the spec's EMAIL and any additional kinds from the path/header
    /// scan.
    struct PipelineOkSpec;
    impl Specialization for PipelineOkSpec {
        fn name(&self) -> &'static str {
            "pipeline_ok"
        }
        fn process<'a>(
            &'a self,
            _query: Option<&'a str>,
            _body: Option<&'a [u8]>,
            _ct: Option<&'a str>,
            _scan: &'a ScanHandle<'a>,
        ) -> ProcessFuture<'a> {
            Box::pin(async move {
                Ok(ProcessedRequest {
                    query: Some(ProcessedPart {
                        bytes: Bytes::from_static(b"redacted=query"),
                        content_type: None,
                    }),
                    body: Some(ProcessedPart {
                        bytes: Bytes::from_static(b"redacted-body"),
                        content_type: Some("text/plain".into()),
                    }),
                    scan_result: AggregatedScan {
                        kinds: vec!["EMAIL".into()],
                        matches_count: 1,
                    },
                })
            })
        }
    }

    struct PipelineDecodeSpec;
    impl Specialization for PipelineDecodeSpec {
        fn name(&self) -> &'static str {
            "pipeline_decode"
        }
        fn process<'a>(
            &'a self,
            _query: Option<&'a str>,
            _body: Option<&'a [u8]>,
            _ct: Option<&'a str>,
            _scan: &'a ScanHandle<'a>,
        ) -> ProcessFuture<'a> {
            Box::pin(async move {
                Err(SpecializationError::Decode {
                    reason: "invalid".into(),
                })
            })
        }
    }

    struct PipelineUnsupportedSpec;
    impl Specialization for PipelineUnsupportedSpec {
        fn name(&self) -> &'static str {
            "pipeline_unsupported"
        }
        fn process<'a>(
            &'a self,
            _query: Option<&'a str>,
            _body: Option<&'a [u8]>,
            _ct: Option<&'a str>,
            _scan: &'a ScanHandle<'a>,
        ) -> ProcessFuture<'a> {
            Box::pin(async move { Err(SpecializationError::UnsupportedContentType) })
        }
    }

    fn header_action_ctx() -> ActionContext<'static> {
        ActionContext {
            mode: "reverse_proxy",
            route: "/pipeline-test",
            direction: "request",
            specialization: "none",
        }
    }

    fn header_action_set() -> ActionSet {
        ActionSet {
            block: false,
            redact: true,
            header: true,
            block_status: 403,
            block_body: None,
            block_headers: vec![],
        }
    }

    #[tokio::test]
    async fn scan_and_act_runs_spec_then_merges_path_and_headers() {
        let pool = pool_for_tests();
        let scan_config = ScanConfig {
            // We want URL-path scanning to pick up the EMAIL embedded in the
            // path so we can confirm path/header detections still merge into
            // the final ScanResult.
            url_path: true,
            query_params: true,
            headers: vec!["X-Custom".into()],
            ..ScanConfig::default()
        };

        let uri: Uri = "/api/v1/users/user@example.com?cid=123".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        // PII in a configured request header.
        headers.insert("x-custom", "contact me at hr@example.com".parse().unwrap());

        let body = Bytes::from(r#"{"raw":"shouldn't matter — spec replaces"}"#);

        let static_spec: &'static dyn Specialization = &PipelineOkSpec;
        let outcome = scan_and_act(
            &pool,
            &scan_config,
            &header_action_set(),
            Some(crate::scanner::RedactWith::TypeLabel),
            &header_action_ctx(),
            &uri,
            &headers,
            Some(&body),
            Some(static_spec),
        )
        .await;

        match outcome {
            PipelineResult::Forward {
                body,
                redacted_path,
                redacted_query,
                redacted_headers,
                extra_headers,
            } => {
                // Spec re-encoded body wins (redact_enabled propagates the
                // bytes onto the action layer as the new forward body).
                assert_eq!(body.as_deref(), Some(b"redacted-body".as_ref()));
                // Spec re-encoded query string wins.
                assert_eq!(redacted_query.as_deref(), Some("redacted=query"));
                // Default URL-path scan still ran — the EMAIL embedded in
                // the path was detected and redacted in place.
                let rp = redacted_path.expect("path scanned by default path");
                assert!(rp.contains("[EMAIL]"), "expected [EMAIL] in path: {rp}");
                // Default header scan still ran — the EMAIL in X-Custom was
                // detected and redacted.
                let rh = redacted_headers.expect("headers scanned by default path");
                let custom = rh
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case("X-Custom"))
                    .expect("X-Custom present");
                assert!(custom.1.contains("[EMAIL]"));
                // header action populated X-PII-Detected with the merged
                // kinds (just EMAIL here since spec + path/header all hit
                // EMAIL — dedup must apply).
                let val = extra_headers
                    .get("x-pii-detected")
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert_eq!(val, "EMAIL");
            }
            _ => panic!("expected Forward outcome"),
        }
    }

    #[tokio::test]
    async fn scan_and_act_decode_failure_falls_back_and_records_metric() {
        let pool = pool_for_tests();
        let scan_config = ScanConfig {
            url_path: false,
            query_params: false,
            headers: Vec::new(),
            body: true,
            content_types: vec!["text/plain".into()],
            ..ScanConfig::default()
        };
        let uri: Uri = "/api".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/plain".parse().unwrap());

        // PII in the raw body; default scan path must still catch it after
        // the spec falls back.
        let body = Bytes::from("contact user@example.com");

        let before = crate::metrics::SPECIALIZATION_ERRORS_TOTAL
            .with_label_values(&["pipeline_decode", "decode"])
            .get();

        let static_spec: &'static dyn Specialization = &PipelineDecodeSpec;
        let outcome = scan_and_act(
            &pool,
            &scan_config,
            &header_action_set(),
            Some(crate::scanner::RedactWith::TypeLabel),
            &ActionContext {
                mode: "reverse_proxy",
                route: "/pipeline-test",
                direction: "request",
                specialization: "none",
            },
            &uri,
            &headers,
            Some(&body),
            Some(static_spec),
        )
        .await;

        match outcome {
            PipelineResult::Forward { body: out, .. } => {
                // Fallback path scanned the body normally — EMAIL must be
                // redacted in the forwarded body.
                let bytes = out.expect("fallback redacted body");
                let text = std::str::from_utf8(&bytes).unwrap();
                assert!(text.contains("[EMAIL]"), "got: {text}");
            }
            _ => panic!("expected Forward on fallback"),
        }

        let after = crate::metrics::SPECIALIZATION_ERRORS_TOTAL
            .with_label_values(&["pipeline_decode", "decode"])
            .get();
        assert_eq!(
            after,
            before + 1,
            "spec decode failure must record an error counter on the request side"
        );
    }

    #[tokio::test]
    async fn scan_and_act_response_unsupported_content_type_is_silent() {
        let pool = pool_for_tests();
        let scan_config = ScanConfig {
            url_path: false,
            query_params: false,
            headers: Vec::new(),
            body: true,
            // The default content-type allowlist would skip image/gif anyway
            // — this exercises the silent-fallback path for the spec.
            content_types: vec!["text/plain".into()],
            ..ScanConfig::default()
        };
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "image/gif".parse().unwrap());

        let body = Bytes::from_static(&[0x47, 0x49, 0x46]); // "GIF" magic.

        let before = crate::metrics::SPECIALIZATION_ERRORS_TOTAL
            .with_label_values(&["pipeline_unsupported", "unsupported_content_type"])
            .get();

        let static_spec: &'static dyn Specialization = &PipelineUnsupportedSpec;
        let outcome = scan_and_act_response(
            &pool,
            &scan_config,
            &ActionSet {
                block: false,
                redact: true,
                header: false,
                block_status: 403,
                block_body: None,
                block_headers: vec![],
            },
            Some(crate::scanner::RedactWith::TypeLabel),
            &ActionContext {
                mode: "reverse_proxy",
                route: "/pipeline-test",
                direction: "response",
                specialization: "none",
            },
            &headers,
            Some(&body),
            Some(static_spec),
        )
        .await;

        // Spec returned UnsupportedContentType → silent fallback → default
        // scan path runs but the body's image/gif content-type is not in the
        // allowlist, so no scanning happens and the outcome is Pass.
        assert!(matches!(outcome, PipelineResult::Pass));

        let after = crate::metrics::SPECIALIZATION_ERRORS_TOTAL
            .with_label_values(&["pipeline_unsupported", "unsupported_content_type"])
            .get();
        assert_eq!(
            after, before,
            "response-side UnsupportedContentType must NOT increment the error counter"
        );
    }
}
