use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

use crate::config::{AppConfig, BUILTIN_PII_GUARD_NAME, OnError, RouteFormat};
use crate::engine::{BlockPolicy, Engine, GuardSelection, UnitContent, UnitKind, Units};
use crate::error::{Error, INVALID_REQUEST};
use crate::metrics::{self, UnscannedReason};
use crate::scanner::SCANNER_ERROR_LIMITER;
use crate::scanner::{classify_body, is_json_content_type};
use crate::structured::chat_completions::Decoded;
use crate::structured::openai_chat;

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
    /// How the route's bodies are decoded and its answers shaped.
    format: RouteFormat,
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
    /// The limit on one upstream exchange: the wait for the response headers,
    /// and the body read when response scan buffers the body.
    upstream_timeout: Duration,
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
            format: r.format,
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
        upstream_timeout: config.upstream_timeout_secs.as_duration(),
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
    let shape = AnswerShape::from(route.format);
    let plan = ScanPlan {
        engine: &state.engine,
        ingest,
        selection,
        headers: &route.headers,
        shape,
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
        shape,
    )
    .await
    {
        Ok(b) => b,
        Err(resp) => return *resp,
    };

    // --- Request scanning ---
    if state.request_scan {
        let ctx = MetricContext {
            route: &route.path_prefix,
            direction: "request",
        };

        // The body is decoded only when a guard selected for this route wants
        // it and there is something to read. A generic route also needs an
        // admitted content type; an `openai-chat` route admits JSON only.
        let body = if selection.wants(UnitKind::Body) && !body_bytes.is_empty() {
            match route.format {
                RouteFormat::Generic
                    if is_content_type_allowed(&headers, &ingest.content_types) =>
                {
                    classify_scan_body(&body_bytes, &headers, ingest.on_error, shape)
                        .map(|content| vec![content])
                }
                RouteFormat::Generic => Ok(Vec::new()),
                RouteFormat::OpenAiChat => {
                    decode_openai_request(&plan, &ctx, &headers, &body_bytes, state.response_scan)
                }
            }
        } else {
            Ok(Vec::new())
        };

        let result = match body {
            Ok(body) => scan_and_act(&plan, &ctx, &uri, &headers, body).await,
            Err(stop) => *stop,
        };
        match result {
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
            return answer(shape, Error::Proxy("no client for upstream".into()));
        }
    };

    // Strip hop-by-hop headers, the host, and content-length. Hyper recomputes
    // the length from the body it actually sends.
    let mut upstream_headers = HeaderMap::new();
    for (name, value) in headers.iter() {
        if !is_hop_by_hop(name) && name != "host" && name != "content-length" {
            upstream_headers.append(name.clone(), value.clone());
        }
    }

    let upstream_req = match hyper::Request::builder()
        .method(method.clone())
        .uri(&upstream_uri)
        .body(Body::from(body_bytes))
    {
        Ok(mut r) => {
            *r.headers_mut() = upstream_headers;
            r
        }
        Err(e) => {
            error!(error = %e, "failed to build upstream request");
            return answer(
                shape,
                Error::Proxy(format!("failed to build upstream request: {e}")),
            );
        }
    };

    // One deadline bounds the whole exchange: the headers here, and the body
    // read below when response scan buffers it.
    let deadline = tokio::time::Instant::now() + state.upstream_timeout;
    let upstream_resp = match tokio::time::timeout_at(deadline, client.request(upstream_req)).await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            error!(error = %e, upstream = %route.upstream, "upstream request failed");
            return answer(shape, Error::Proxy(format!("upstream error: {e}")));
        }
        Err(_) => return answer(shape, upstream_timeout(&route.upstream)),
    };

    let resp_status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    // --- Response scanning ---
    if state.response_scan {
        let ctx = MetricContext {
            route: &route.path_prefix,
            direction: "response",
        };

        // An `openai-chat` route reads the content type before the body, so a
        // stream it cannot scan is never buffered. A message that passes
        // under `fail_open` streams through as with response scan off; its
        // headers are still scanned.
        let unscannable = match route.format {
            RouteFormat::Generic => None,
            RouteFormat::OpenAiChat => unscannable_response(&method, resp_status, &resp_headers),
        };
        if let Some(err) = unscannable {
            let result = match handle_scan_error(err, ingest.on_error, shape) {
                PipelineResult::Pass => {
                    scan_and_act_response(&plan, &ctx, &resp_headers, Vec::new()).await
                }
                stop => stop,
            };
            return match result {
                PipelineResult::Block(resp) | PipelineResult::Error(resp) => {
                    metrics::inc_message_blocked(MODE, ctx.route, ctx.direction);
                    resp
                }
                PipelineResult::Pass => stream_through(upstream_resp),
            };
        }

        let limited = Limited::new(upstream_resp.into_body(), ingest.max_body_size);
        let resp_body = match tokio::time::timeout_at(deadline, limited.collect()).await {
            Ok(Ok(collected)) => collected.to_bytes(),
            Ok(Err(e)) if e.is::<LengthLimitError>() => {
                error!(
                    upstream = %route.upstream,
                    limit = ingest.max_body_size,
                    "upstream response body too large"
                );
                metrics::inc_error("blocked", "response_too_large");
                return answer(shape, Error::ResponseTooLarge);
            }
            Ok(Err(e)) => {
                error!(error = %e, "failed to read upstream response body");
                return answer(
                    shape,
                    Error::Proxy(format!("failed to read upstream response: {e}")),
                );
            }
            Err(_) => return answer(shape, upstream_timeout(&route.upstream)),
        };

        let body = if selection.wants(UnitKind::Body) && !resp_body.is_empty() {
            match route.format {
                RouteFormat::Generic
                    if is_content_type_allowed(&resp_headers, &ingest.content_types) =>
                {
                    classify_scan_body(&resp_body, &resp_headers, ingest.on_error, shape)
                        .map(|content| vec![content])
                }
                RouteFormat::Generic => Ok(Vec::new()),
                RouteFormat::OpenAiChat => decode_openai_response(&plan, &ctx, &resp_body),
            }
        } else {
            Ok(Vec::new())
        };

        let result = match body {
            Ok(body) => scan_and_act_response(&plan, &ctx, &resp_headers, body).await,
            Err(stop) => *stop,
        };
        match result {
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
    stream_through(upstream_resp)
}

/// Forward the upstream response unread, stripping hop-by-hop headers.
fn stream_through(upstream_resp: hyper::Response<hyper::body::Incoming>) -> Response {
    let final_headers = strip_hop_by_hop(upstream_resp.headers());
    let mut resp = upstream_resp.map(Body::new);
    *resp.headers_mut() = final_headers;
    resp
}

// ---------------------------------------------------------------------------
// Answer shape
// ---------------------------------------------------------------------------

/// The shape of every answer Voidwall makes on a matched route, decided once
/// from the route's format. The 404 for an unmatched path is outside every
/// route and stays plain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnswerShape {
    /// The flat `{"error": ...}` body, and the fixed 403 for a block.
    Plain,
    /// The OpenAI error shape, and the 400 for a block.
    OpenAi,
}

impl From<RouteFormat> for AnswerShape {
    fn from(format: RouteFormat) -> Self {
        match format {
            RouteFormat::Generic => AnswerShape::Plain,
            RouteFormat::OpenAiChat => AnswerShape::OpenAi,
        }
    }
}

/// The answer to `err` in the route's shape.
fn answer(shape: AnswerShape, err: Error) -> Response {
    match shape {
        AnswerShape::Plain => err.into_response(),
        AnswerShape::OpenAi => err.into_openai_response(),
    }
}

/// The answer to a detection in the route's shape.
fn block(shape: AnswerShape, kinds: &[String]) -> Response {
    match shape {
        AnswerShape::Plain => block_response(kinds),
        AnswerShape::OpenAi => openai_block_response(kinds),
    }
}

// ---------------------------------------------------------------------------
// Pipeline result
// ---------------------------------------------------------------------------

enum PipelineResult {
    /// A detection stopped the message: the route's block.
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
/// settings, and what the matched route decides — which guards run, which
/// headers become units, and the shape of its answers.
struct ScanPlan<'a> {
    engine: &'a Engine,
    ingest: &'a Ingest,
    selection: &'a GuardSelection,
    headers: &'a [String],
    shape: AnswerShape,
}

// ---------------------------------------------------------------------------
// Scan + action helpers
// ---------------------------------------------------------------------------

/// Scan the request direction, with its decoded body units, and decide what
/// happens to it.
async fn scan_and_act(
    plan: &ScanPlan<'_>,
    ctx: &MetricContext<'_>,
    uri: &Uri,
    headers: &HeaderMap,
    body: Vec<UnitContent>,
) -> PipelineResult {
    let mut units = Units::new();
    for content in body {
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

/// Scan the response direction, with its decoded body units, and decide what
/// happens to it.
async fn scan_and_act_response(
    plan: &ScanPlan<'_>,
    ctx: &MetricContext<'_>,
    headers: &HeaderMap,
    body: Vec<UnitContent>,
) -> PipelineResult {
    let mut units = Units::new();
    for content in body {
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
            Some(e) => handle_scan_error(e, plan.ingest.on_error, plan.shape),
            None => PipelineResult::Pass,
        };
    }
    if let Some(e) = &error {
        metrics::inc_error("blocked", e.scan_reason());
    }

    // The kind lists are sorted and hold each kind once, so the counter moves
    // once per kind and the block body lists them in a stable order. The PII
    // families count the `pii` guard's findings only.
    let kinds = scan_result.kinds();
    let pii_kinds = scan_result.kinds_of(BUILTIN_PII_GUARD_NAME);
    for kind in &pii_kinds {
        metrics::inc_detection(kind, MODE, ctx.route, ctx.direction);
    }
    // Once per guard that reported, however many findings it reported. A
    // guard the block abandoned returned nothing, so it is not counted.
    for guard in scan_result.guards() {
        metrics::inc_guard_detection(&guard, MODE, ctx.route, ctx.direction);
    }
    // The PII family counts only a block the `pii` guard took part in. The
    // engine-wide family counts every stopped message and moves where the
    // pipeline result is known.
    if !pii_kinds.is_empty() {
        metrics::inc_blocked(MODE, ctx.route, ctx.direction);
    }

    PipelineResult::Block(block(plan.shape, &kinds))
}

/// The fixed response a detection produces: 403, JSON, and the kind names that
/// were found. The `error` text names no class of finding, because any guard
/// can cause the block. It never carries matched text — see
/// `openspec/specs/security/spec.md`.
fn block_response(kinds: &[String]) -> Response {
    let payload = serde_json::json!({ "error": BLOCKED, "kinds": kinds });
    json_response(StatusCode::FORBIDDEN, &payload)
}

/// The fixed text of a block. It names no class of finding.
const BLOCKED: &str = "content blocked";

/// The block on a route with `format = "openai-chat"`: 400 in the OpenAI error
/// shape, so an OpenAI client handles it without a change. `code` names the
/// real cause. Like the 403, it lists kinds and never matched text.
fn openai_block_response(kinds: &[String]) -> Response {
    let payload = serde_json::json!({
        "error": {
            "message": format!("{BLOCKED}. Kinds: {}", kinds.join(", ")),
            "type": INVALID_REQUEST,
            "param": null,
            "code": "content_filter",
            "kinds": kinds,
        }
    });
    json_response(StatusCode::BAD_REQUEST, &payload)
}

fn json_response(status: StatusCode, payload: &serde_json::Value) -> Response {
    let body = serde_json::to_vec(payload).unwrap_or_else(|_| b"{}".to_vec());
    (status, [("content-type", "application/json")], body).into_response()
}

/// Classify the body bytes into a `BodyFormat` based on Content-Type. A body
/// that does not parse follows [`parse_failure`].
///
/// `Err` is boxed so the `Result` stays small on the stack; the error path
/// only fires on parse failure under `fail_close`, so the heap allocation is
/// off the hot path while the success path pays no extra size.
fn classify_scan_body(
    bytes: &Bytes,
    headers: &HeaderMap,
    on_error: OnError,
    shape: AnswerShape,
) -> Result<UnitContent, Box<PipelineResult>> {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    classify_body(bytes.clone(), content_type).or_else(|_| parse_failure(bytes, on_error, shape))
}

/// The `on_error` rule for a body that does not parse as its declared type:
/// `fail_open` falls back to plain text scanning, `fail_close` short-circuits
/// with a `PipelineResult::Error` 400.
fn parse_failure(
    bytes: &Bytes,
    on_error: OnError,
    shape: AnswerShape,
) -> Result<UnitContent, Box<PipelineResult>> {
    match on_error {
        OnError::FailOpen => {
            metrics::inc_error("passed", "body_parse_failed");
            Ok(UnitContent::PlainText(bytes.clone()))
        }
        OnError::FailClose => {
            metrics::inc_error("blocked", "body_parse_failed");
            Err(Box::new(PipelineResult::Error(answer(
                shape,
                Error::BodyParse,
            ))))
        }
    }
}

/// Decode a request body on an `openai-chat` route into its body units, in
/// this order:
///
/// 1. a body that is not a JSON Chat Completions request answers 400 under
///    both `on_error` settings;
/// 2. a `stream: true` request with response scan on is stopped with 422
///    under `fail_close` before any guard runs; under `fail_open` the
///    response side counts it;
/// 3. unknown content parts and base64 data, as [`decoded_units`] states.
fn decode_openai_request(
    plan: &ScanPlan<'_>,
    ctx: &MetricContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    response_scan: bool,
) -> Result<Vec<UnitContent>, Box<PipelineResult>> {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let decoded = if is_json_content_type(content_type) {
        openai_chat::decode_request(body)
    } else {
        Err(Error::BodyParse)
    };
    let request = match decoded {
        Ok(request) => request,
        Err(Error::BodyParse) => {
            metrics::inc_error("blocked", "body_parse_failed");
            return Err(Box::new(PipelineResult::Error(answer(
                plan.shape,
                Error::BodyParse,
            ))));
        }
        Err(e) => return decode_failure(plan, e),
    };

    if request.stream && response_scan && plan.ingest.on_error == OnError::FailClose {
        return Err(Box::new(handle_scan_error(
            Error::UnscannableStream,
            OnError::FailClose,
            plan.shape,
        )));
    }

    decoded_units(plan, ctx, request.decoded)
}

/// Decode a JSON response body on an `openai-chat` route into its body units.
/// A body that does not parse follows the parse-failure rule of the generic
/// scan.
fn decode_openai_response(
    plan: &ScanPlan<'_>,
    ctx: &MetricContext<'_>,
    body: &Bytes,
) -> Result<Vec<UnitContent>, Box<PipelineResult>> {
    match openai_chat::decode_response(body) {
        Ok(decoded) => decoded_units(plan, ctx, decoded),
        Err(Error::BodyParse) => {
            parse_failure(body, plan.ingest.on_error, plan.shape).map(|content| vec![content])
        }
        Err(e) => decode_failure(plan, e),
    }
}

/// Apply `on_error` to a decoder that could not pair its decisions with the
/// fragments. `fail_open` scans the message without its body.
fn decode_failure(
    plan: &ScanPlan<'_>,
    err: Error,
) -> Result<Vec<UnitContent>, Box<PipelineResult>> {
    if let Some(dropped) = SCANNER_ERROR_LIMITER.should_log() {
        warn!(dropped, error = %err, "openai-chat body decode failed");
    }
    match handle_scan_error(err, plan.ingest.on_error, plan.shape) {
        PipelineResult::Pass => Ok(Vec::new()),
        stop => Err(Box::new(stop)),
    }
}

/// The body units of a decoded `openai-chat` body. An unknown content part
/// follows `on_error`: `fail_close` stops the message with 422 before any
/// guard runs, `fail_open` scans the rest. Base64 values are counted only for
/// a message that goes on to be scanned.
fn decoded_units(
    plan: &ScanPlan<'_>,
    ctx: &MetricContext<'_>,
    decoded: Decoded,
) -> Result<Vec<UnitContent>, Box<PipelineResult>> {
    if decoded.unknown_parts > 0 {
        match handle_scan_error(Error::UnscannableContent, plan.ingest.on_error, plan.shape) {
            PipelineResult::Pass => {}
            stop => return Err(Box::new(stop)),
        }
    }
    if decoded.encoded_values > 0 {
        metrics::inc_unscanned(
            MODE,
            ctx.route,
            ctx.direction,
            UnscannedReason::EncodedData,
            decoded.encoded_values as u64,
        );
    }
    Ok(decoded
        .units
        .into_iter()
        .map(|fragments| UnitContent::Structured { fragments })
        .collect())
}

/// Why an upstream response on an `openai-chat` route cannot be scanned,
/// read from its headers before the body: a `text/event-stream` is a stream,
/// and any other type that is not JSON is unscannable content when the
/// response has a body. `None` when the response can be scanned.
fn unscannable_response(method: &Method, status: StatusCode, headers: &HeaderMap) -> Option<Error> {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let media_type = content_type.split(';').next().unwrap_or("").trim();
    if media_type.eq_ignore_ascii_case("text/event-stream") {
        Some(Error::UnscannableStream)
    } else if is_json_content_type(content_type) || has_no_body(method, status, headers) {
        None
    } else {
        Some(Error::UnscannableContent)
    }
}

/// True when the response headers say there is no body: a 204 or 304, an
/// answer to `HEAD`, or `Content-Length: 0`.
fn has_no_body(method: &Method, status: StatusCode, headers: &HeaderMap) -> bool {
    status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
        || method == Method::HEAD
        || headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim() == "0")
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

/// Apply `on_error` to a guard error no detection overruled. The error names
/// its own reason and, under `fail_close`, its own status and fixed body in
/// the route's shape.
fn handle_scan_error(err: Error, on_error: OnError, shape: AnswerShape) -> PipelineResult {
    match on_error {
        OnError::FailOpen => {
            metrics::inc_error("passed", err.scan_reason());
            PipelineResult::Pass
        }
        OnError::FailClose => {
            metrics::inc_error("blocked", err.scan_reason());
            PipelineResult::Error(answer(shape, err))
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
    shape: AnswerShape,
) -> Result<Bytes, Box<Response>> {
    let collected = req.into_body().collect().await.map_err(|e| {
        error!(error = %e, "failed to read request body");
        Box::new(answer(
            shape,
            Error::Proxy(format!("failed to read request body: {e}")),
        ))
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
                Err(Box::new(answer(shape, Error::BodyTooLarge)))
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

/// The error for an upstream exchange that outlived `upstream_timeout_secs`,
/// logged and counted.
fn upstream_timeout(upstream: &str) -> Error {
    error!(upstream = %upstream, "upstream exchange timed out");
    metrics::inc_error("blocked", "upstream_timeout");
    Error::UpstreamTimeout
}

fn strip_hop_by_hop(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers.iter() {
        if !is_hop_by_hop(name) {
            out.append(name.clone(), value.clone());
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
                format: RouteFormat::Generic,
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
        let result = buffer_body(
            req,
            1024,
            OnError::FailClose,
            "/buffer-body-test",
            AnswerShape::Plain,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from("hello"));
    }

    #[tokio::test]
    async fn buffer_body_exceeds_limit_fail_close() {
        let req = Request::builder().body(Body::from("hello world")).unwrap();
        let result = buffer_body(
            req,
            5,
            OnError::FailClose,
            "/buffer-body-test",
            AnswerShape::Plain,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn buffer_body_exceeds_limit_fail_open() {
        let req = Request::builder().body(Body::from("hello world")).unwrap();
        let result = buffer_body(
            req,
            5,
            OnError::FailOpen,
            "/buffer-body-test",
            AnswerShape::Plain,
        )
        .await;
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
        assert_eq!(json["error"], "content blocked");
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

    #[tokio::test]
    async fn the_openai_block_is_a_400_naming_the_kinds() {
        let kinds = ["EMAIL".to_string(), "IBAN_CODE".to_string()];
        let resp = openai_block_response(&kinds);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
        let body = read_body(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"error": {
                "message": "content blocked. Kinds: EMAIL, IBAN_CODE",
                "type": "invalid_request_error",
                "param": null,
                "code": "content_filter",
                "kinds": ["EMAIL", "IBAN_CODE"],
            }})
        );
        assert!(!String::from_utf8_lossy(&body).contains("@"));
    }

    #[tokio::test]
    async fn the_same_kinds_produce_a_byte_identical_openai_block() {
        let kinds = ["EMAIL".to_string(), "IBAN_CODE".to_string()];
        let first = read_body(openai_block_response(&kinds)).await;
        let second = read_body(openai_block_response(&kinds)).await;
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

    #[test]
    fn strip_hop_by_hop_keeps_every_value_of_a_repeated_header() {
        let mut headers = HeaderMap::new();
        headers.append("set-cookie", "a=1".parse().unwrap());
        headers.append("set-cookie", "b=2".parse().unwrap());
        headers.insert("connection", "close".parse().unwrap());

        let stripped = strip_hop_by_hop(&headers);
        let cookies: Vec<_> = stripped.get_all("set-cookie").iter().collect();
        assert_eq!(cookies, ["a=1", "b=2"]);
        assert!(stripped.get("connection").is_none());
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
            shape: AnswerShape::Plain,
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

    // --- A model guard error names its own status and reason ---

    use crate::engine::test_guard::TestFailure;

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

        let result = run_guards(
            vec![TestGuard::new("model", "RP_UNUSED").failing_with(failure)],
            OnError::FailClose,
        )
        .await;

        let PipelineResult::Error(resp) = result else {
            panic!("expected an error response");
        };
        assert_eq!(resp.status(), status);
        assert_eq!(&read_body(resp).await[..], body);
        assert!(errors("blocked", reason) > before);
    }

    #[test_case(TestFailure::Inference, "inference_failure" ; "inference")]
    #[test_case(TestFailure::WindowLimit, "window_limit" ; "window limit")]
    #[tokio::test]
    async fn a_model_guard_error_under_fail_open_passes_and_counts_its_reason(
        failure: TestFailure,
        reason: &str,
    ) {
        let before = errors("passed", reason);

        let result = run_guards(
            vec![TestGuard::new("model", "RP_UNUSED").failing_with(failure)],
            OnError::FailOpen,
        )
        .await;

        assert!(matches!(result, PipelineResult::Pass));
        assert!(errors("passed", reason) > before);
    }

    #[tokio::test]
    async fn a_block_counts_an_earlier_window_limit_with_its_own_reason() {
        let before = errors("blocked", "window_limit");

        let result = run_guards(
            vec![
                TestGuard::new("model", "RP_UNUSED").failing_with(TestFailure::WindowLimit),
                TestGuard::new("detecting", "RP_WINDOW_LIMIT_KIND")
                    .with_delay(std::time::Duration::from_millis(50)),
            ],
            OnError::FailOpen,
        )
        .await;

        let PipelineResult::Block(resp) = result else {
            panic!("expected a 403 block");
        };
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(errors("blocked", "window_limit") > before);
    }

    // --- The PII families count the `pii` guard's findings only ---

    use crate::metrics::{BLOCKED_TOTAL, DETECTIONS_TOTAL};

    fn pii_detections(kind: &str, route: &str) -> u64 {
        DETECTIONS_TOTAL
            .with_label_values(&[kind, MODE, route, "request"])
            .get()
    }

    fn pii_blocks(route: &str) -> u64 {
        BLOCKED_TOTAL
            .with_label_values(&[MODE, route, "request"])
            .get()
    }

    #[tokio::test]
    async fn a_block_by_a_model_guard_alone_leaves_the_pii_families_alone() {
        let route = "/pii-metrics-model-only";

        let result = run_guards_on(
            vec![TestGuard::new("rp_model_only", "PROMPT_INJECTION")],
            OnError::FailClose,
            route,
            1,
        )
        .await;

        let PipelineResult::Block(resp) = result else {
            panic!("expected a 403 block");
        };
        let body: serde_json::Value = serde_json::from_slice(&read_body(resp).await).unwrap();
        assert_eq!(body["kinds"], serde_json::json!(["PROMPT_INJECTION"]));
        assert_eq!(guard_detections("rp_model_only", route), 1);
        assert_eq!(pii_detections("PROMPT_INJECTION", route), 0);
        assert_eq!(pii_blocks(route), 0);
    }

    #[tokio::test]
    async fn a_kind_the_pii_guard_and_a_model_guard_both_report_counts_once() {
        let route = "/pii-metrics-shared-kind";

        let result = run_guards_on(
            vec![
                TestGuard::new(crate::config::BUILTIN_PII_GUARD_NAME, "RP_SHARED_KIND"),
                TestGuard::new("rp_model_shared", "RP_SHARED_KIND"),
            ],
            OnError::FailClose,
            route,
            1,
        )
        .await;

        assert!(matches!(result, PipelineResult::Block(_)));
        // The first guard to report blocks and the other may be abandoned;
        // either way the kind is counted once, and only for the `pii` guard.
        let pii_reported = guard_detections(crate::config::BUILTIN_PII_GUARD_NAME, route) == 1;
        assert_eq!(
            pii_detections("RP_SHARED_KIND", route),
            u64::from(pii_reported)
        );
        assert_eq!(pii_blocks(route), u64::from(pii_reported));
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
                    format: RouteFormat::Generic,
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

    // --- The openai-chat route ---

    use crate::config::{DirectionConfig, UpstreamTimeout};
    use crate::metrics::UNSCANNED_TOTAL;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Serialises the tests that assert no change of the route-less
    /// `unscannable_stream` error samples.
    static STREAM_ERRORS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// An upstream that answers every request with `status`, `content_type`
    /// (none when empty), and `body`, and counts the requests it got.
    async fn stub_upstream(
        status: u16,
        content_type: &'static str,
        body: &'static str,
    ) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let app = Router::new().fallback(move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut resp = Response::new(Body::from(body));
                *resp.status_mut() = StatusCode::from_u16(status).unwrap();
                if !content_type.is_empty() {
                    resp.headers_mut()
                        .insert("content-type", content_type.parse().unwrap());
                }
                resp
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), hits)
    }

    /// An upstream that reads a request and never answers.
    async fn silent_upstream() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    drop(socket);
                });
            }
        });
        format!("http://{addr}")
    }

    /// One route with `format = "openai-chat"` and the settings a test varies.
    struct Chat {
        route: &'static str,
        upstream: String,
        request_scan: bool,
        response_scan: bool,
        on_error: OnError,
        max_body_size: usize,
        content_types: Vec<String>,
        timeout_secs: u64,
    }

    impl Chat {
        fn new(route: &'static str, upstream: &str) -> Self {
            Self {
                route,
                upstream: upstream.to_string(),
                request_scan: true,
                response_scan: true,
                on_error: OnError::FailClose,
                max_body_size: 1024,
                content_types: vec!["application/json".to_string()],
                timeout_secs: 30,
            }
        }

        async fn send(&self, guards: Vec<TestGuard>, req: Request) -> Response {
            let engine = Arc::new(Engine::with_guards(
                guards.into_iter().map(|g| Box::new(g) as _).collect(),
            ));
            let config = AppConfig {
                max_body_size: self.max_body_size,
                on_error: self.on_error,
                content_types: self.content_types.clone(),
                upstream_timeout_secs: UpstreamTimeout::try_from(self.timeout_secs).unwrap(),
                reverse_proxy: ReverseProxyConfig {
                    request: DirectionConfig {
                        scan: self.request_scan,
                    },
                    response: DirectionConfig {
                        scan: self.response_scan,
                    },
                    routes: vec![Route {
                        path_prefix: self.route.to_string(),
                        upstream: self.upstream.clone(),
                        guards: None,
                        headers: Vec::new(),
                        format: RouteFormat::OpenAiChat,
                    }],
                    ..ReverseProxyConfig::default()
                },
                ..AppConfig::default()
            };
            proxy_handler(State(build_state(&config, engine)), req).await
        }

        async fn post(&self, guards: Vec<TestGuard>, body: serde_json::Value) -> Response {
            let req = Request::builder()
                .method("POST")
                .uri(self.route)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            self.send(guards, req).await
        }
    }

    fn chat_request() -> serde_json::Value {
        serde_json::json!({"model": "m", "messages": [{"role": "user", "content": "hello"}]})
    }

    fn quiet() -> Vec<TestGuard> {
        vec![TestGuard::new("chat_quiet", "RP_UNUSED").silent()]
    }

    /// The OpenAI `error` object of `resp`, asserting its status.
    async fn openai_error(resp: Response, status: StatusCode) -> serde_json::Value {
        assert_eq!(resp.status(), status);
        let body: serde_json::Value = serde_json::from_slice(&read_body(resp).await).unwrap();
        body["error"].clone()
    }

    fn stopped(route: &str, direction: &str) -> u64 {
        MESSAGES_BLOCKED_TOTAL
            .with_label_values(&[MODE, route, direction])
            .get()
    }

    const CLEAN_JSON: &str = r#"{"choices":[{"message":{"role":"assistant","content":"ok"}}]}"#;

    // 4.1 — every answer of the route is in the OpenAI shape

    #[tokio::test]
    async fn an_oversize_request_answers_413_in_the_openai_shape() {
        let chat = Chat {
            max_body_size: 8,
            ..Chat::new("/chat-413", "http://127.0.0.1:9")
        };
        let error = openai_error(
            chat.post(quiet(), chat_request()).await,
            StatusCode::PAYLOAD_TOO_LARGE,
        )
        .await;
        assert_eq!(error["code"], "body_too_large");
    }

    #[tokio::test]
    async fn a_scanner_failure_answers_500_in_the_openai_shape() {
        let chat = Chat::new("/chat-500", "http://127.0.0.1:9");
        let guards = vec![TestGuard::new("chat_failing", "RP_UNUSED").failing()];
        let error = openai_error(
            chat.post(guards, chat_request()).await,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await;
        assert_eq!(
            error,
            serde_json::json!({"message": "internal error", "type": "server_error", "param": null, "code": "internal_error"})
        );
    }

    #[tokio::test]
    async fn an_unreachable_upstream_answers_502_in_the_openai_shape() {
        let chat = Chat::new("/chat-502", "http://127.0.0.1:9");
        let error = openai_error(
            chat.post(quiet(), chat_request()).await,
            StatusCode::BAD_GATEWAY,
        )
        .await;
        assert_eq!(error["code"], "upstream_error");
    }

    #[tokio::test]
    async fn an_upstream_timeout_answers_504_in_the_openai_shape() {
        let chat = Chat {
            timeout_secs: 1,
            ..Chat::new("/chat-504", &silent_upstream().await)
        };
        let error = openai_error(
            chat.post(quiet(), chat_request()).await,
            StatusCode::GATEWAY_TIMEOUT,
        )
        .await;
        assert_eq!(error["code"], "upstream_timeout");
    }

    #[tokio::test]
    async fn a_detection_answers_the_openai_400_block() {
        let chat = Chat::new("/chat-block", "http://127.0.0.1:9");
        let guards = vec![TestGuard::new("chat_detecting", "RP_CHAT_KIND")];
        let error = openai_error(
            chat.post(guards, chat_request()).await,
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(error["code"], "content_filter");
        assert_eq!(error["kinds"], serde_json::json!(["RP_CHAT_KIND"]));
        assert_eq!(stopped("/chat-block", "request"), 1);
    }

    // 4.2 — the request side, in the D6 order

    #[test_case(OnError::FailOpen ; "fail_open")]
    #[test_case(OnError::FailClose ; "fail_close")]
    #[tokio::test]
    async fn a_body_that_is_not_json_answers_400_under_both_policies(on_error: OnError) {
        let (upstream, hits) = stub_upstream(200, "application/json", CLEAN_JSON).await;
        let chat = Chat {
            on_error,
            ..Chat::new("/chat-not-json", &upstream)
        };
        let req = Request::builder()
            .method("POST")
            .uri(chat.route)
            .header("content-type", "text/plain")
            .body(Body::from("hello"))
            .unwrap();
        let error = openai_error(chat.send(quiet(), req).await, StatusCode::BAD_REQUEST).await;
        assert_eq!(error["code"], "malformed_body");
        assert_eq!(hits.load(Ordering::SeqCst), 0, "not forwarded");
    }

    #[tokio::test]
    async fn a_request_without_messages_answers_400() {
        let chat = Chat::new("/chat-no-messages", "http://127.0.0.1:9");
        let body = serde_json::json!({"model": "m", "input": "hello"});
        let error = openai_error(chat.post(quiet(), body).await, StatusCode::BAD_REQUEST).await;
        assert_eq!(error["code"], "malformed_body");
    }

    #[tokio::test]
    async fn a_stream_under_fail_close_answers_422_and_runs_no_guard() {
        let _lock = STREAM_ERRORS.lock().await;
        let before = errors("blocked", "unscannable_stream");
        let (upstream, hits) = stub_upstream(200, "application/json", CLEAN_JSON).await;
        let chat = Chat::new("/chat-stream-close", &upstream);
        let guard = TestGuard::new("chat_stream_probe", "RP_UNUSED").silent();
        let probe = guard.probe();
        let mut body = chat_request();
        body["stream"] = serde_json::json!(true);

        let error = openai_error(
            chat.post(vec![guard], body).await,
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
        assert_eq!(error["code"], "unscannable_content");
        assert_eq!(probe.calls(), 0, "no guard ran");
        assert_eq!(hits.load(Ordering::SeqCst), 0, "not forwarded");
        assert_eq!(errors("blocked", "unscannable_stream"), before + 1);
        assert_eq!(stopped("/chat-stream-close", "request"), 1);
    }

    #[test_case(OnError::FailOpen, true ; "fail_open")]
    #[test_case(OnError::FailClose, false ; "response scan off")]
    #[tokio::test]
    async fn a_stream_is_forwarded_and_not_counted_on_the_request_side(
        on_error: OnError,
        response_scan: bool,
    ) {
        let _lock = STREAM_ERRORS.lock().await;
        let before = (
            errors("passed", "unscannable_stream"),
            errors("blocked", "unscannable_stream"),
        );
        let (upstream, hits) = stub_upstream(200, "application/json", CLEAN_JSON).await;
        let chat = Chat {
            on_error,
            response_scan,
            ..Chat::new("/chat-stream-forwarded", &upstream)
        };
        let mut body = chat_request();
        body["stream"] = serde_json::json!(true);

        let resp = chat.post(quiet(), body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            (
                errors("passed", "unscannable_stream"),
                errors("blocked", "unscannable_stream")
            ),
            before
        );
    }

    fn hologram_request() -> serde_json::Value {
        serde_json::json!({"messages": [{"role": "user", "content": [
            {"type": "hologram"},
            {"type": "text", "text": "hello"},
        ]}]})
    }

    #[tokio::test]
    async fn an_unknown_part_under_fail_close_answers_422_and_runs_no_guard() {
        let chat = Chat::new("/chat-hologram-close", "http://127.0.0.1:9");
        let guard = TestGuard::new("chat_hologram_probe", "RP_UNUSED").silent();
        let probe = guard.probe();
        let error = openai_error(
            chat.post(vec![guard], hologram_request()).await,
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
        assert_eq!(error["code"], "unscannable_content");
        assert_eq!(probe.calls(), 0);
    }

    #[tokio::test]
    async fn an_unknown_part_under_fail_open_scans_the_rest() {
        let chat = Chat {
            on_error: OnError::FailOpen,
            ..Chat::new("/chat-hologram-open", "http://127.0.0.1:9")
        };
        let guards = vec![TestGuard::new("chat_hologram_detect", "RP_HOLOGRAM_KIND")];
        let error = openai_error(
            chat.post(guards, hologram_request()).await,
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(error["kinds"], serde_json::json!(["RP_HOLOGRAM_KIND"]));
    }

    #[tokio::test]
    async fn the_route_ignores_the_content_type_allowlist() {
        let chat = Chat {
            content_types: vec!["text/plain".to_string()],
            ..Chat::new("/chat-allowlist", "http://127.0.0.1:9")
        };
        // Body units only, so a block proves the body was decoded.
        let guards = vec![
            TestGuard::new("chat_body_only", "RP_BODY_KIND")
                .with_interest(Interest::in_kinds([UnitKind::Body])),
        ];
        let error = openai_error(
            chat.post(guards, chat_request()).await,
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(error["kinds"], serde_json::json!(["RP_BODY_KIND"]));
    }

    #[tokio::test]
    async fn an_empty_get_is_forwarded() {
        let (upstream, hits) = stub_upstream(200, "application/json", CLEAN_JSON).await;
        let chat = Chat::new("/chat-get", &upstream);
        let req = Request::builder()
            .uri(chat.route)
            .body(Body::empty())
            .unwrap();
        assert_eq!(chat.send(quiet(), req).await.status(), StatusCode::OK);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    // 4.3 — the response side reads the content type first

    #[tokio::test]
    async fn an_event_stream_under_fail_close_answers_422() {
        let _lock = STREAM_ERRORS.lock().await;
        let before = errors("blocked", "unscannable_stream");
        let (upstream, _) = stub_upstream(200, "text/event-stream", "data: hello\n\n").await;
        let chat = Chat::new("/chat-sse-close", &upstream);
        let error = openai_error(
            chat.post(quiet(), chat_request()).await,
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
        assert_eq!(error["code"], "unscannable_content");
        assert_eq!(errors("blocked", "unscannable_stream"), before + 1);
        assert_eq!(stopped("/chat-sse-close", "response"), 1);
    }

    #[tokio::test]
    async fn an_event_stream_under_fail_open_streams_through() {
        let _lock = STREAM_ERRORS.lock().await;
        let before = errors("passed", "unscannable_stream");
        let (upstream, _) = stub_upstream(200, "text/event-stream", "data: hello\n\n").await;
        let chat = Chat {
            on_error: OnError::FailOpen,
            max_body_size: 4,
            ..Chat::new("/chat-sse-open", &upstream)
        };
        let resp = chat.post(quiet(), chat_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            &read_body(resp).await[..],
            b"data: hello\n\n",
            "no size limit"
        );
        assert_eq!(errors("passed", "unscannable_stream"), before + 1);
    }

    #[test_case(OnError::FailClose, StatusCode::UNPROCESSABLE_ENTITY, "blocked" ; "fail_close")]
    #[test_case(OnError::FailOpen, StatusCode::BAD_GATEWAY, "passed" ; "fail_open")]
    #[tokio::test]
    async fn an_html_page_follows_on_error(on_error: OnError, status: StatusCode, outcome: &str) {
        let before = errors(outcome, "unscannable_content");
        let (upstream, _) = stub_upstream(502, "text/html", "<html>bad gateway</html>").await;
        let chat = Chat {
            on_error,
            ..Chat::new("/chat-html", &upstream)
        };
        let resp = chat.post(quiet(), chat_request()).await;
        assert_eq!(resp.status(), status);
        if on_error == OnError::FailOpen {
            assert_eq!(&read_body(resp).await[..], b"<html>bad gateway</html>");
        }
        assert!(errors(outcome, "unscannable_content") > before);
    }

    #[tokio::test]
    async fn an_empty_html_204_is_forwarded() {
        let (upstream, _) = stub_upstream(204, "text/html", "").await;
        let chat = Chat::new("/chat-204", &upstream);
        let resp = chat.post(quiet(), chat_request()).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn a_detection_in_a_json_response_answers_400() {
        let route = "/chat-response-block";
        let (upstream, _) = stub_upstream(200, "application/json", CLEAN_JSON).await;
        let chat = Chat {
            request_scan: false,
            ..Chat::new(route, &upstream)
        };
        let guards = vec![TestGuard::new("chat_response_detect", "RP_RESPONSE_KIND")];
        let error = openai_error(
            chat.post(guards, chat_request()).await,
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(error["code"], "content_filter");
        assert_eq!(stopped(route, "response"), 1);
    }

    // A decoder that cannot pair its decisions with the fragments follows
    // on_error as a scanner failure.

    fn decode_failure_with(on_error: OnError) -> Result<Vec<UnitContent>, Box<PipelineResult>> {
        let engine = Engine::with_guards(Vec::new());
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
            shape: AnswerShape::OpenAi,
        };
        let mismatch = Error::Scanner("classified 2 string leaves, the flattener found 1".into());
        decode_failure(&plan, mismatch)
    }

    #[tokio::test]
    async fn a_leaf_count_mismatch_under_fail_close_answers_500_in_the_openai_shape() {
        let before = blocked_scanner_failures();
        let Err(stop) = decode_failure_with(OnError::FailClose) else {
            panic!("expected the message to stop");
        };
        let PipelineResult::Error(resp) = *stop else {
            panic!("expected an error answer");
        };
        let error = openai_error(resp, StatusCode::INTERNAL_SERVER_ERROR).await;
        assert_eq!(error["code"], "internal_error");
        assert!(blocked_scanner_failures() > before);
    }

    #[test]
    fn a_leaf_count_mismatch_under_fail_open_scans_without_the_body() {
        let before = errors("passed", "scanner_failure");
        let Ok(units) = decode_failure_with(OnError::FailOpen) else {
            panic!("expected the message to pass");
        };
        assert!(units.is_empty(), "no body unit");
        assert!(errors("passed", "scanner_failure") > before);
    }

    // 4.4 — base64 data is counted with the route and the direction

    fn encoded(route: &str, direction: &str) -> u64 {
        UNSCANNED_TOTAL
            .with_label_values(&[MODE, route, direction, "encoded_data"])
            .get()
    }

    #[tokio::test]
    async fn an_inline_image_in_a_request_is_counted_once() {
        let route = "/chat-encoded-request";
        let (upstream, _) = stub_upstream(200, "application/json", CLEAN_JSON).await;
        let chat = Chat::new(route, &upstream);
        let body = serde_json::json!({"messages": [{"role": "user", "content": [
            {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
            {"type": "text", "text": "hello"},
        ]}]});
        assert_eq!(chat.post(quiet(), body).await.status(), StatusCode::OK);
        assert_eq!(encoded(route, "request"), 1);
        assert_eq!(encoded(route, "response"), 0);
    }

    #[tokio::test]
    async fn audio_data_in_a_response_is_counted_once() {
        let route = "/chat-encoded-response";
        let (upstream, _) = stub_upstream(
            200,
            "application/json",
            r#"{"choices":[{"message":{"role":"assistant","audio":{"id":"a","data":"AAAA"}}}]}"#,
        )
        .await;
        let chat = Chat::new(route, &upstream);
        assert_eq!(
            chat.post(quiet(), chat_request()).await.status(),
            StatusCode::OK
        );
        assert_eq!(encoded(route, "response"), 1);
        assert_eq!(encoded(route, "request"), 0);
    }

    #[tokio::test]
    async fn a_stopped_request_counts_no_encoded_data() {
        let route = "/chat-encoded-stopped";
        let chat = Chat::new(route, "http://127.0.0.1:9");
        let body = serde_json::json!({"messages": [{"role": "user", "content": [
            {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
            {"type": "hologram"},
        ]}]});
        let resp = chat.post(quiet(), body).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(encoded(route, "request"), 0);
    }
}
