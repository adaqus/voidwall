use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

use crate::config::{AppConfig, OnError};
use crate::engine::{BlockPolicy, Engine, GuardSelection, UnitContent, UnitKind, Units};
use crate::error::Error;
use crate::metrics;
use crate::scanner::SCANNER_ERROR_LIMITER;
use crate::scanner::classify_body;

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
    /// The guards that run for this route, resolved once at startup. It also
    /// carries the union of their surfaces, which is what decides the units
    /// this route's messages are decoded into.
    selection: GuardSelection,
    /// The header names this route exposes to detection, in both directions.
    /// A header not named here is never decoded into a unit.
    headers: Vec<String>,
}

/// How a message is admitted and decoded, before any guard sees it. Shared by
/// every route and every direction.
struct Ingest {
    max_body_size: usize,
    content_types: Vec<String>,
    on_error: OnError,
}

/// The `mode` metric label for every counter this module writes.
const MODE: &str = "reverse_proxy";

/// Shared state for the reverse proxy handlers.
#[derive(Clone)]
pub struct ReverseProxyState {
    routes: Arc<Vec<ResolvedRoute>>,
    clients: Arc<HashMap<String, Client<hyper_util::client::legacy::connect::HttpConnector, Body>>>,
    engine: Arc<Engine>,
    ingest: Arc<Ingest>,
    request_scan: bool,
    response_scan: bool,
}

// ---------------------------------------------------------------------------
// Router & server
// ---------------------------------------------------------------------------

/// Build the reverse proxy state from configuration.
pub fn build_state(config: &AppConfig, engine: Arc<Engine>) -> ReverseProxyState {
    let rp = &config.reverse_proxy;

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

    // Resolve each route's guard set once. A route that names no guard takes
    // every enabled one; one that names an empty list takes none.
    let enabled = config.builtin_guards.enabled_names();
    let routes: Vec<ResolvedRoute> = rp
        .routes
        .iter()
        .map(|r| ResolvedRoute {
            path_prefix: r.path_prefix.clone(),
            upstream: r.upstream.clone(),
            selection: match &r.guards {
                Some(_) => engine.select(Some(&r.selected_guards(&enabled))),
                None => engine.select(None),
            },
            headers: r.headers.clone(),
        })
        .collect();

    ReverseProxyState {
        routes: Arc::new(routes),
        clients: Arc::new(clients),
        engine,
        ingest: Arc::new(Ingest {
            max_body_size: config.max_body_size,
            content_types: config.content_types.clone(),
            on_error: config.on_error,
        }),
        request_scan: rp.request.scan,
        response_scan: rp.response.scan,
    }
}

/// Build the axum router for the reverse proxy.
pub fn router(state: ReverseProxyState) -> Router {
    Router::new().fallback(proxy_handler).with_state(state)
}

/// Start the reverse proxy server.
pub async fn serve(
    config: &AppConfig,
    engine: Arc<Engine>,
    cancel: CancellationToken,
) -> Result<(), Error> {
    let state = build_state(config, engine);
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
    let ingest = &state.ingest;
    let selection = &route.selection;
    let plan = ScanPlan {
        engine: &state.engine,
        ingest,
        selection,
        headers: &route.headers,
    };
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Buffer the request body.
    let body_bytes = match buffer_body(
        req,
        ingest.max_body_size,
        ingest.on_error,
        &route.path_prefix,
    )
    .await
    {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    // --- Request scanning ---
    if state.request_scan {
        let ctx = MetricContext {
            route: &route.path_prefix,
            direction: "request",
        };

        // The body is decoded only when a guard selected for this route wants
        // it, its content type is admitted, and there is something to read.
        let should_scan_body = selection.wants(UnitKind::Body)
            && !body_bytes.is_empty()
            && is_content_type_allowed(&headers, &ingest.content_types);

        match scan_and_act(
            &plan,
            &ctx,
            &uri,
            &headers,
            if should_scan_body {
                Some(&body_bytes)
            } else {
                None
            },
        )
        .await
        {
            PipelineResult::Block(resp) | PipelineResult::Error(resp) => {
                metrics::inc_message_blocked(MODE, ctx.route, ctx.direction);
                return resp;
            }
            PipelineResult::Pass => {}
        }
    }

    // --- Build & send upstream request ---
    let upstream_uri = build_upstream_uri(&route.upstream, &uri);
    let client = match state.clients.get(&route.upstream) {
        Some(c) => c,
        None => {
            error!(upstream = %route.upstream, "no client for upstream");
            return Error::Proxy("no client for upstream".into()).into_response();
        }
    };

    // Strip hop-by-hop headers, the host, and content-length. Hyper recomputes
    // the length from the body it actually sends.
    let mut upstream_headers = HeaderMap::new();
    for (name, value) in headers.iter() {
        if !is_hop_by_hop(name) && name != "host" && name != "content-length" {
            upstream_headers.insert(name.clone(), value.clone());
        }
    }

    let upstream_req = match hyper::Request::builder()
        .method(method)
        .uri(&upstream_uri)
        .body(Body::from(body_bytes))
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
    if state.response_scan {
        let resp_body = match upstream_resp.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                error!(error = %e, "failed to read upstream response body");
                return Error::Proxy(format!("failed to read upstream response: {e}"))
                    .into_response();
            }
        };

        let ctx = MetricContext {
            route: &route.path_prefix,
            direction: "response",
        };

        let should_scan_body = selection.wants(UnitKind::Body)
            && !resp_body.is_empty()
            && is_content_type_allowed(&resp_headers, &ingest.content_types);

        match scan_and_act_response(
            &plan,
            &ctx,
            &resp_headers,
            if should_scan_body {
                Some(&resp_body)
            } else {
                None
            },
        )
        .await
        {
            PipelineResult::Block(resp) | PipelineResult::Error(resp) => {
                metrics::inc_message_blocked(MODE, ctx.route, ctx.direction);
                return resp;
            }
            PipelineResult::Pass => {
                let final_headers = strip_hop_by_hop(&resp_headers);
                return build_response(resp_status, final_headers, resp_body);
            }
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
    /// A detection stopped the message: the fixed 403.
    Block(Response),
    Pass,
    /// A `fail_close` error stopped the message. Only a stopped message is
    /// built here — it is counted as blocked — so a 502 never is.
    Error(Response),
}

/// The metric labels for one scanned direction. The mode is fixed, so only the
/// route and the direction vary.
struct MetricContext<'a> {
    route: &'a str,
    direction: &'a str,
}

/// Everything detection needs for one message: the engine, the shared ingest
/// settings, and the two things the matched route decides — which guards run,
/// and which headers become units.
struct ScanPlan<'a> {
    engine: &'a Engine,
    ingest: &'a Ingest,
    selection: &'a GuardSelection,
    headers: &'a [String],
}

// ---------------------------------------------------------------------------
// Scan + action helpers
// ---------------------------------------------------------------------------

/// Scan the request direction and decide what happens to it.
async fn scan_and_act(
    plan: &ScanPlan<'_>,
    ctx: &MetricContext<'_>,
    uri: &Uri,
    headers: &HeaderMap,
    body: Option<&Bytes>,
) -> PipelineResult {
    let scan_body = match classify_scan_body(body, headers, plan.ingest.on_error) {
        Ok(b) => b,
        Err(resp) => return *resp,
    };

    let mut units = Units::new();
    if let Some(content) = scan_body {
        units.push_body(content);
    }

    // URL path and query become separate units rather than one merged string:
    // each is admitted by a guard's surface on its own, and a finding's span
    // then names which of the two it sits in. They are tiny, so the extra unit
    // costs nothing next to body scanning.
    if plan.selection.wants(UnitKind::UrlPath) {
        units.push_path(uri.path().to_string());
    }
    if plan.selection.wants(UnitKind::QueryString)
        && let Some(query) = uri.query()
    {
        units.push_query(query.to_string());
    }
    if plan.selection.wants(UnitKind::HeaderValue) {
        push_scan_headers(&mut units, plan.headers, headers);
    }

    if units.is_empty() {
        return PipelineResult::Pass;
    }

    run_engine(plan, units, ctx, "scanner error").await
}

/// Scan the response direction and decide what happens to it.
async fn scan_and_act_response(
    plan: &ScanPlan<'_>,
    ctx: &MetricContext<'_>,
    headers: &HeaderMap,
    body: Option<&Bytes>,
) -> PipelineResult {
    let scan_body = match classify_scan_body(body, headers, plan.ingest.on_error) {
        Ok(b) => b,
        Err(resp) => return *resp,
    };

    let mut units = Units::new();
    if let Some(content) = scan_body {
        units.push_body(content);
    }
    if plan.selection.wants(UnitKind::HeaderValue) {
        push_scan_headers(&mut units, plan.headers, headers);
    }

    if units.is_empty() {
        return PipelineResult::Pass;
    }

    run_engine(plan, units, ctx, "scanner error on response").await
}

/// Hand the units to the engine and decide what happens to the message.
/// Shared by both directions — they differ only in which units they build and
/// how a scanner failure is logged.
///
/// A detection blocks, so the engine may stop as soon as one finding arrives:
/// the message is not going anywhere and the rest cannot change that.
async fn run_engine(
    plan: &ScanPlan<'_>,
    units: Units,
    ctx: &MetricContext<'_>,
    error_message: &'static str,
) -> PipelineResult {
    let units = units.into_shared();

    let mut scan_result = plan
        .engine
        .guard(
            Arc::clone(&units),
            plan.selection,
            BlockPolicy::AnyFinding,
            plan.ingest.on_error,
        )
        .await;

    // A block from another guard wins over a guard error, whatever on_error
    // says. The error is still logged and counted, as blocked.
    let error = scan_result.take_error();
    if let Some(e) = &error
        && let Some(dropped) = SCANNER_ERROR_LIMITER.should_log()
    {
        warn!(dropped, error = %e, "{error_message}");
    }

    if !scan_result.detected() {
        return match error {
            Some(e) => handle_scan_error(e, plan.ingest.on_error),
            None => PipelineResult::Pass,
        };
    }
    if error.is_some() {
        metrics::inc_error("blocked", "scanner_failure");
    }

    // The kind list is sorted and holds each kind once, so the counter moves
    // once per kind and the block body lists them in a stable order.
    let kinds = scan_result.kinds();
    for kind in &kinds {
        metrics::inc_detection(kind, MODE, ctx.route, ctx.direction);
    }
    // Once per guard that reported, however many findings it reported. A
    // guard the block abandoned returned nothing, so it is not counted.
    for guard in scan_result.guards() {
        metrics::inc_guard_detection(&guard, MODE, ctx.route, ctx.direction);
    }
    // The PII family counts the 403 only. The engine-wide family counts every
    // stopped message and moves where the pipeline result is known.
    metrics::inc_blocked(MODE, ctx.route, ctx.direction);

    PipelineResult::Block(block_response(&kinds))
}

/// The fixed response a detection produces: 403, JSON, and the kind names that
/// were found. It never carries matched text — see
/// `openspec/specs/security/spec.md`.
fn block_response(kinds: &[String]) -> Response {
    let payload = serde_json::json!({ "error": "PII detected", "kinds": kinds });
    let body = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    (
        StatusCode::FORBIDDEN,
        [("content-type", "application/json")],
        body,
    )
        .into_response()
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
) -> Result<Option<UnitContent>, Box<PipelineResult>> {
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
                Ok(Some(UnitContent::PlainText(bytes.clone())))
            }
            OnError::FailClose => {
                metrics::inc_error("blocked", "body_parse_failed");
                Err(Box::new(PipelineResult::Error(
                    Error::BodyParse.into_response(),
                )))
            }
        },
    }
}

/// Append one unit per header the route names, when it is present and
/// readable. A header the route does not name is never decoded, so no guard
/// can see it whatever its surface says.
fn push_scan_headers(units: &mut Units, scanned_headers: &[String], headers: &HeaderMap) {
    for header_name in scanned_headers {
        if let Ok(name) = header_name.parse::<HeaderName>()
            && let Some(value) = headers.get(&name)
            && let Ok(v) = value.to_str()
        {
            units.push_header(v.to_string());
        }
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

/// Read the request body whole. An oversize body under `fail_close` stops the
/// message, so it is counted as blocked on `route`; a read failure is a 502 and
/// is not.
async fn buffer_body(
    req: Request,
    max_size: usize,
    on_error: OnError,
    route: &str,
) -> Result<Bytes, Response> {
    let collected = req.into_body().collect().await.map_err(|e| {
        error!(error = %e, "failed to read request body");
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
                metrics::inc_message_blocked(MODE, route, "request");
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
    use crate::config::GuardSurface;
    use crate::engine::Interest;
    use test_case::test_case;

    /// A selection carrying the default surface: the path, the query, and the
    /// body, and no header.
    fn default_selection() -> GuardSelection {
        GuardSelection::for_test(Interest::from_surface(&GuardSurface::default()))
    }

    // --- Route matching ---

    fn routes(prefixes: &[&str]) -> Vec<ResolvedRoute> {
        prefixes
            .iter()
            .map(|p| ResolvedRoute {
                path_prefix: p.to_string(),
                upstream: format!("http://upstream{p}"),
                selection: default_selection(),
                headers: Vec::new(),
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
        let result = buffer_body(req, 1024, OnError::FailClose, "/buffer-body-test").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from("hello"));
    }

    #[tokio::test]
    async fn buffer_body_exceeds_limit_fail_close() {
        let req = Request::builder().body(Body::from("hello world")).unwrap();
        let result = buffer_body(req, 5, OnError::FailClose, "/buffer-body-test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn buffer_body_exceeds_limit_fail_open() {
        let req = Request::builder().body(Body::from("hello world")).unwrap();
        let result = buffer_body(req, 5, OnError::FailOpen, "/buffer-body-test").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from("hello world"));
    }

    // --- Block response ---

    #[test]
    fn block_response_is_a_fixed_403_naming_the_kinds() {
        let resp = block_response(&["EMAIL".to_string(), "US_SSN".to_string()]);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn block_body_lists_the_kinds_sorted_and_carries_no_value() {
        // Deliberately unsorted input: the body must not echo arrival order,
        // and must never carry matched text.
        let kinds = ["US_SSN".to_string(), "EMAIL".to_string()];
        let body = read_body(block_response(&kinds)).await;
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["error"], "PII detected");
        assert_eq!(json["kinds"], serde_json::json!(["US_SSN", "EMAIL"]));
        assert!(!String::from_utf8_lossy(&body).contains("@"));
    }

    #[tokio::test]
    async fn the_same_kinds_produce_a_byte_identical_body() {
        let kinds = ["EMAIL".to_string(), "IBAN_CODE".to_string()];
        let first = read_body(block_response(&kinds)).await;
        let second = read_body(block_response(&kinds)).await;
        assert_eq!(first, second);
    }

    async fn read_body(resp: Response) -> Bytes {
        use http_body_util::BodyExt;
        resp.into_body().collect().await.unwrap().to_bytes()
    }

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

    // --- Scan header collection ---

    #[test]
    fn push_scan_headers_picks_the_ones_the_route_named() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer token".parse().unwrap());
        headers.insert("x-safe", "clean".parse().unwrap());

        let mut units = Units::new();
        push_scan_headers(&mut units, &["Authorization".to_string()], &headers);
        let units = units.into_shared();

        assert_eq!(units.len(), 1, "the named header, and not the other one");
        assert_eq!(units[0].kind, UnitKind::HeaderValue);
    }

    /// The route names no header, so no header unit is built — whatever the
    /// message carries, and whatever the guards would accept.
    #[test]
    fn no_header_unit_is_built_when_the_route_names_none() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer token".parse().unwrap());

        let mut units = Units::new();
        push_scan_headers(&mut units, &[], &headers);
        assert!(units.is_empty());
    }

    /// A unit no selected guard wants is never constructed, so a selection that
    /// admits only the body leaves the path and the query undecoded.
    #[test]
    fn only_the_units_the_selection_admits_are_built() {
        let body_only = GuardSurface {
            url_path: false,
            query_params: false,
            ..GuardSurface::default()
        };
        let selection = GuardSelection::for_test(Interest::from_surface(&body_only));

        assert!(selection.wants(UnitKind::Body));
        assert!(!selection.wants(UnitKind::UrlPath));
        assert!(!selection.wants(UnitKind::QueryString));
    }

    /// The same rule reaches headers, which is why the call that collects them
    /// is gated like the path and the query. A route may name a header while
    /// no selected guard wants one: the value is then never copied into a unit.
    #[test]
    fn a_selection_that_declines_headers_builds_no_header_unit() {
        let no_headers = GuardSurface {
            headers: false,
            ..GuardSurface::default()
        };
        let selection = GuardSelection::for_test(Interest::from_surface(&no_headers));
        assert!(!selection.wants(UnitKind::HeaderValue));

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer token".parse().unwrap());

        let mut units = Units::new();
        if selection.wants(UnitKind::HeaderValue) {
            push_scan_headers(&mut units, &["Authorization".to_string()], &headers);
        }
        assert!(units.is_empty(), "no selected guard admits the kind");
    }

    // --- A block from another guard wins over a guard error ---

    use crate::engine::test_guard::TestGuard;
    use crate::engine::{Engine, UnitContent};
    use crate::metrics::ERRORS_TOTAL;

    /// Run one request body through `run_engine` with the given guards.
    async fn run_guards(guards: Vec<TestGuard>, on_error: OnError) -> PipelineResult {
        run_guards_on(guards, on_error, "/guard-error-test", 1).await
    }

    /// Run `unit_count` request bodies through `run_engine` on `route`. A test
    /// that reads a counter passes a route no other test uses, so its count is
    /// exact.
    async fn run_guards_on(
        guards: Vec<TestGuard>,
        on_error: OnError,
        route: &str,
        unit_count: usize,
    ) -> PipelineResult {
        let engine = Engine::with_guards(guards.into_iter().map(|g| Box::new(g) as _).collect());
        let selection = engine.select(None);
        let ingest = Ingest {
            max_body_size: 1024,
            content_types: Vec::new(),
            on_error,
        };
        let plan = ScanPlan {
            engine: &engine,
            ingest: &ingest,
            selection: &selection,
            headers: &[],
        };
        let ctx = MetricContext {
            route,
            direction: "request",
        };
        let mut units = Units::new();
        for _ in 0..unit_count {
            units.push_body(UnitContent::PlainText(Bytes::from_static(b"content")));
        }
        run_engine(&plan, units, &ctx, "scanner error").await
    }

    fn blocked_scanner_failures() -> u64 {
        ERRORS_TOTAL
            .with_label_values(&["blocked", "scanner_failure"])
            .get()
    }

    #[test_case(OnError::FailOpen ; "fail_open")]
    #[test_case(OnError::FailClose ; "fail_close")]
    #[tokio::test]
    async fn a_block_from_another_guard_wins_over_a_guard_error(on_error: OnError) {
        let before = blocked_scanner_failures();

        let result = run_guards(
            vec![
                TestGuard::new("failing", "RP_UNUSED").failing(),
                TestGuard::new("detecting", "RP_GUARD_ERROR_KIND")
                    .with_delay(std::time::Duration::from_millis(50)),
            ],
            on_error,
        )
        .await;

        let PipelineResult::Block(resp) = result else {
            panic!("expected a 403 block");
        };
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value = serde_json::from_slice(&read_body(resp).await).unwrap();
        assert_eq!(body["kinds"], serde_json::json!(["RP_GUARD_ERROR_KIND"]));
        // Other tests can count the same labels at the same time, so the
        // check is a lower bound.
        assert!(
            blocked_scanner_failures() > before,
            "the error is counted as blocked"
        );
    }

    #[tokio::test]
    async fn a_guard_error_alone_under_fail_open_passes() {
        let result = run_guards(
            vec![TestGuard::new("failing", "RP_UNUSED").failing()],
            OnError::FailOpen,
        )
        .await;
        assert!(matches!(result, PipelineResult::Pass));
    }

    #[tokio::test]
    async fn a_guard_error_alone_under_fail_close_answers_the_fixed_500() {
        let result = run_guards(
            vec![
                TestGuard::new("failing", "RP_UNUSED").failing(),
                TestGuard::new("quiet", "RP_UNUSED").silent(),
            ],
            OnError::FailClose,
        )
        .await;

        let PipelineResult::Error(resp) = result else {
            panic!("expected a 500");
        };
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(&read_body(resp).await[..], br#"{"error":"internal error"}"#);
    }

    // --- Guard detections count once per guard per message ---

    use crate::metrics::GUARD_DETECTIONS_TOTAL;

    fn guard_detections(guard: &str, route: &str) -> u64 {
        GUARD_DETECTIONS_TOTAL
            .with_label_values(&[guard, MODE, route, "request"])
            .get()
    }

    #[tokio::test]
    async fn each_guard_with_findings_counts_once_per_message() {
        let route = "/guard-metrics-two-guards";

        // Four units, so each guard reports four findings.
        let result = run_guards_on(
            vec![
                TestGuard::new("gm_two_a", "RP_GM_KIND_A"),
                TestGuard::new("gm_two_b", "RP_GM_KIND_B"),
            ],
            OnError::FailClose,
            route,
            4,
        )
        .await;

        // The first guard to report blocks, so the other may be abandoned. A
        // guard counts only when its findings came back.
        let PipelineResult::Block(resp) = result else {
            panic!("expected a 403 block");
        };
        let body: serde_json::Value = serde_json::from_slice(&read_body(resp).await).unwrap();
        let kinds = body["kinds"].as_array().unwrap();
        let counted = |guard: &str, kind: &str| {
            let expected = u64::from(kinds.iter().any(|k| k == kind));
            assert_eq!(guard_detections(guard, route), expected, "{guard}");
        };
        counted("gm_two_a", "RP_GM_KIND_A");
        counted("gm_two_b", "RP_GM_KIND_B");
    }

    #[tokio::test]
    async fn one_guard_with_many_findings_counts_once() {
        let route = "/guard-metrics-many-findings";

        let result = run_guards_on(
            vec![TestGuard::new("gm_many", "RP_GM_MANY_KIND")],
            OnError::FailClose,
            route,
            4,
        )
        .await;

        assert!(matches!(result, PipelineResult::Block(_)));
        assert_eq!(guard_detections("gm_many", route), 1);
    }

    #[tokio::test]
    async fn an_abandoned_guard_is_not_counted() {
        let route = "/guard-metrics-abandoned";

        let result = run_guards_on(
            vec![
                TestGuard::new("gm_fast", "RP_GM_FAST_KIND"),
                TestGuard::new("gm_slow", "RP_GM_SLOW_KIND")
                    .with_delay(std::time::Duration::from_secs(5)),
            ],
            OnError::FailClose,
            route,
            1,
        )
        .await;

        assert!(matches!(result, PipelineResult::Block(_)));
        assert_eq!(guard_detections("gm_fast", route), 1);
        assert_eq!(guard_detections("gm_slow", route), 0);
    }

    #[tokio::test]
    async fn a_guard_without_findings_is_not_counted() {
        let route = "/guard-metrics-clean";

        let result = run_guards_on(
            vec![TestGuard::new("gm_quiet", "RP_UNUSED").silent()],
            OnError::FailClose,
            route,
            1,
        )
        .await;

        assert!(matches!(result, PipelineResult::Pass));
        assert_eq!(guard_detections("gm_quiet", route), 0);
    }

    // --- A stopped message counts once in voidwall_blocked_total ---

    use crate::config::{ReverseProxyConfig, Route};
    use crate::metrics::MESSAGES_BLOCKED_TOTAL;

    /// Send one plain-text request through the whole handler, over the given
    /// guards. Request scanning blocks it before the upstream, so nothing
    /// listens there.
    async fn block_through_the_handler(guards: Vec<TestGuard>, route: &str) -> Response {
        let engine = Arc::new(Engine::with_guards(
            guards.into_iter().map(|g| Box::new(g) as _).collect(),
        ));
        let config = AppConfig {
            reverse_proxy: ReverseProxyConfig {
                routes: vec![Route {
                    path_prefix: route.to_string(),
                    upstream: "http://127.0.0.1:9".to_string(),
                    guards: None,
                    headers: Vec::new(),
                }],
                ..ReverseProxyConfig::default()
            },
            ..AppConfig::default()
        };
        let state = build_state(&config, engine);
        let req = Request::builder()
            .method("POST")
            .uri(route)
            .header("content-type", "text/plain")
            .body(Body::from("content"))
            .unwrap();
        proxy_handler(State(state), req).await
    }

    fn blocked(route: &str) -> u64 {
        MESSAGES_BLOCKED_TOTAL
            .with_label_values(&[MODE, route, "request"])
            .get()
    }

    #[test_case(
        vec![
            TestGuard::new("gm_block_a", "RP_GM_BLOCK_A"),
            TestGuard::new("gm_block_b", "RP_GM_BLOCK_B"),
        ],
        "/guard-metrics-two-guards-blocked" ;
        "two guards report findings"
    )]
    #[test_case(
        vec![
            TestGuard::new("gm_block_failing", "RP_UNUSED").failing(),
            TestGuard::new("gm_block_detecting", "RP_GM_BLOCK_DETECT")
                .with_delay(std::time::Duration::from_millis(50)),
        ],
        "/guard-metrics-error-and-detection" ;
        "a guard error and a detection"
    )]
    #[tokio::test]
    async fn a_stopped_message_counts_once_as_blocked(guards: Vec<TestGuard>, route: &str) {
        let resp = block_through_the_handler(guards, route).await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(blocked(route), 1);
    }
}
