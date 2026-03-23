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
use crate::scanner::{ScanRequest, ScannerPool};

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

/// Shared state for the reverse proxy handlers.
#[derive(Clone)]
pub struct ReverseProxyState {
    routes: Arc<Vec<ResolvedRoute>>,
    clients: Arc<HashMap<String, Client<hyper_util::client::legacy::connect::HttpConnector, Body>>>,
    scanner: Arc<ScannerPool>,
    request_actions: ActionSet,
    response_actions: ActionSet,
    request_redact_strategy: Option<pii::RedactWith>,
    response_redact_strategy: Option<pii::RedactWith>,
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
        )
        .await
        {
            PipelineResult::Block(resp) => return resp,
            PipelineResult::Forward {
                body,
                extra_headers,
                redacted_url,
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
                if redacted_url.is_some() || redacted_query.is_some() {
                    forward_uri =
                        rebuild_uri(&uri, redacted_url.as_deref(), redacted_query.as_deref());
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
        redacted_url: Option<String>,
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
    redact_strategy: Option<pii::RedactWith>,
    ctx: &ActionContext<'_>,
    uri: &Uri,
    headers: &HeaderMap,
    body: Option<&Bytes>,
) -> PipelineResult {
    let scan_body = body.cloned();

    let scan_url = if scan_config.url {
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

    if scan_body.is_none() && scan_url.is_none() && scan_query.is_none() && scan_headers.is_none() {
        return PipelineResult::Pass;
    }

    let scan_req = ScanRequest {
        body: scan_body,
        url: scan_url,
        query: scan_query,
        headers: scan_headers,
        redact: action_set.redact,
        redact_strategy,
    };

    let scan_result = match scanner.process(scan_req, scan_config.on_error).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "scanner error");
            return handle_scan_error(e, scan_config.on_error);
        }
    };

    pipeline_result_from_outcome(action::execute(scan_result, action_set, ctx))
}

/// Scan response direction and execute actions.
async fn scan_and_act_response(
    scanner: &ScannerPool,
    scan_config: &ScanConfig,
    action_set: &ActionSet,
    redact_strategy: Option<pii::RedactWith>,
    ctx: &ActionContext<'_>,
    headers: &HeaderMap,
    body: Option<&Bytes>,
) -> PipelineResult {
    let scan_body = body.cloned();
    let scan_headers = collect_scan_headers(scan_config, headers);

    if scan_body.is_none() && scan_headers.is_none() {
        return PipelineResult::Pass;
    }

    let scan_req = ScanRequest {
        body: scan_body,
        url: None,
        query: None,
        headers: scan_headers,
        redact: action_set.redact,
        redact_strategy,
    };

    let scan_result = match scanner.process(scan_req, scan_config.on_error).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "scanner error on response");
            return handle_scan_error(e, scan_config.on_error);
        }
    };

    pipeline_result_from_outcome(action::execute(scan_result, action_set, ctx))
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
            redacted_url: scan_result.redacted_url,
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
                redacted_url: None,
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
}
