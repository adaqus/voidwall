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

use crate::config::{AppConfig, OnError, ScanConfig};
use crate::engine::{BlockPolicy, Engine, UnitContent, Units};
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
    scan: ScanConfig,
}

/// The `mode` metric label for every counter this module writes.
const MODE: &str = "reverse_proxy";

/// Shared state for the reverse proxy handlers.
#[derive(Clone)]
pub struct ReverseProxyState {
    routes: Arc<Vec<ResolvedRoute>>,
    clients: Arc<HashMap<String, Client<hyper_util::client::legacy::connect::HttpConnector, Body>>>,
    engine: Arc<Engine>,
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

    // Resolve per-route scan config (route override fully replaces defaults).
    let routes: Vec<ResolvedRoute> = rp
        .routes
        .iter()
        .map(|r| ResolvedRoute {
            path_prefix: r.path_prefix.clone(),
            upstream: r.upstream.clone(),
            scan: r.scan.clone().unwrap_or_else(|| config.scan.clone()),
        })
        .collect();

    ReverseProxyState {
        routes: Arc::new(routes),
        clients: Arc::new(clients),
        engine,
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
    let scan_config = &route.scan;
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Buffer the request body.
    let body_bytes = match buffer_body(req, scan_config.max_body_size, scan_config.on_error).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    // --- Request scanning ---
    if state.request_scan {
        let ctx = MetricContext {
            route: &route.path_prefix,
            direction: "request",
        };

        // Check content-type for body scanning.
        let should_scan_body = scan_config.body
            && !body_bytes.is_empty()
            && is_content_type_allowed(&headers, &scan_config.content_types);

        match scan_and_act(
            &state.engine,
            scan_config,
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
            PipelineResult::Block(resp) => return resp,
            PipelineResult::Pass => {}
            PipelineResult::Error(resp) => return resp,
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

        let should_scan_body = scan_config.body
            && !resp_body.is_empty()
            && is_content_type_allowed(&resp_headers, &scan_config.content_types);

        match scan_and_act_response(
            &state.engine,
            scan_config,
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
            PipelineResult::Block(resp) => return resp,
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
    Pass,
    Error(Response),
}

/// The metric labels for one scanned direction. The mode is fixed, so only the
/// route and the direction vary.
struct MetricContext<'a> {
    route: &'a str,
    direction: &'a str,
}

// ---------------------------------------------------------------------------
// Scan + action helpers
// ---------------------------------------------------------------------------

/// Scan the request direction and decide what happens to it.
async fn scan_and_act(
    engine: &Engine,
    scan_config: &ScanConfig,
    ctx: &MetricContext<'_>,
    uri: &Uri,
    headers: &HeaderMap,
    body: Option<&Bytes>,
) -> PipelineResult {
    let scan_body = match classify_scan_body(body, headers, scan_config.on_error) {
        Ok(b) => b,
        Err(resp) => return *resp,
    };

    let mut units = Units::new();
    if let Some(content) = scan_body {
        units.push_body(content);
    }

    // URL path and query become separate units rather than one merged string:
    // each can be independently enabled via config, and a finding's span then
    // names which of the two it sits in. They are tiny, so the extra unit costs
    // nothing next to body scanning.
    if scan_config.url_path {
        units.push_path(uri.path().to_string());
    }
    if scan_config.query_params
        && let Some(query) = uri.query()
    {
        units.push_query(query.to_string());
    }
    push_scan_headers(&mut units, scan_config, headers);

    if units.is_empty() {
        return PipelineResult::Pass;
    }

    run_engine(engine, units, scan_config, ctx, "scanner error").await
}

/// Scan the response direction and decide what happens to it.
async fn scan_and_act_response(
    engine: &Engine,
    scan_config: &ScanConfig,
    ctx: &MetricContext<'_>,
    headers: &HeaderMap,
    body: Option<&Bytes>,
) -> PipelineResult {
    let scan_body = match classify_scan_body(body, headers, scan_config.on_error) {
        Ok(b) => b,
        Err(resp) => return *resp,
    };

    let mut units = Units::new();
    if let Some(content) = scan_body {
        units.push_body(content);
    }
    push_scan_headers(&mut units, scan_config, headers);

    if units.is_empty() {
        return PipelineResult::Pass;
    }

    run_engine(engine, units, scan_config, ctx, "scanner error on response").await
}

/// Hand the units to the engine and decide what happens to the message.
/// Shared by both directions — they differ only in which units they build and
/// how a scanner failure is logged.
///
/// A detection blocks, so the engine may stop as soon as one finding arrives:
/// the message is not going anywhere and the rest cannot change that.
async fn run_engine(
    engine: &Engine,
    units: Units,
    scan_config: &ScanConfig,
    ctx: &MetricContext<'_>,
    error_message: &'static str,
) -> PipelineResult {
    let units = units.into_shared();

    let scan_result = match engine
        .guard(
            Arc::clone(&units),
            BlockPolicy::AnyFinding,
            scan_config.on_error,
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            if let Some(dropped) = SCANNER_ERROR_LIMITER.should_log() {
                warn!(dropped, error = %e, "{error_message}");
            }
            return handle_scan_error(e, scan_config.on_error);
        }
    };

    if !scan_result.detected() {
        return PipelineResult::Pass;
    }

    // The kind list is sorted and holds each kind once, so the counter moves
    // once per kind and the block body lists them in a stable order.
    let kinds = scan_result.kinds();
    for kind in &kinds {
        metrics::inc_detection(kind, MODE, ctx.route, ctx.direction);
    }
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

/// Append one unit per configured header that is present and readable.
fn push_scan_headers(units: &mut Units, scan_config: &ScanConfig, headers: &HeaderMap) {
    for header_name in &scan_config.headers {
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
    use crate::engine::UnitKind;
    use test_case::test_case;

    // --- Route matching ---

    fn routes(prefixes: &[&str]) -> Vec<ResolvedRoute> {
        prefixes
            .iter()
            .map(|p| ResolvedRoute {
                path_prefix: p.to_string(),
                upstream: format!("http://upstream{p}"),
                scan: ScanConfig::default(),
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
    fn push_scan_headers_picks_configured() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer token".parse().unwrap());
        headers.insert("x-safe", "clean".parse().unwrap());

        let scan_config = ScanConfig {
            headers: vec!["Authorization".into()],
            ..ScanConfig::default()
        };

        let mut units = Units::new();
        push_scan_headers(&mut units, &scan_config, &headers);
        let units = units.into_shared();

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].kind, UnitKind::HeaderValue);
    }

    #[test]
    fn push_scan_headers_empty_config() {
        let headers = HeaderMap::new();
        let scan_config = ScanConfig::default();
        let mut units = Units::new();
        push_scan_headers(&mut units, &scan_config, &headers);
        assert!(units.is_empty());
    }
}
