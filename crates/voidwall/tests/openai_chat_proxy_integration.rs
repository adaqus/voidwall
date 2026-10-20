//! A reverse proxy route with `format = "openai-chat"` end to end: a real
//! reverse proxy and a real admin server in front of a stub upstream that
//! answers JSON, `text/event-stream`, or `text/html`.
//!
//! One test per scenario of `specs/openai-chat-proxy/spec.md` and of
//! `specs/openai-chat-streaming/spec.md`, then the scenarios of the
//! `reverse-proxy` and `metrics` deltas they do not cover. A stream test
//! serves the recorded stream, edited, or a scripted one that waits between
//! reads.
//! Requests are hand-written from the `openai-python` 3.5.0 types; responses
//! were recorded from LM Studio 0.4.26 and are served with their recorded
//! status and content type. The fixtures hold no PII: a test inserts a
//! placeholder by editing the loaded fixture.
//!
//! Metrics are read from the admin `/metrics` endpoint. `voidwall_errors_total`
//! carries no route label, so every test holds [`METRICS`] and a change it
//! asserts is exact.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use bytes::Bytes;
use serde_json::{Value, json};
use test_case::test_case;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use voidwall::admin::{self, AdminState};
use voidwall::config::AppConfig;
use voidwall::engine::Engine;
use voidwall::reverse_proxy;
use voidwall_ml::fixtures::{Fixture, TRIGGER, TRIGGER_ID, TokenizerFixture};

const ROUTE: &str = "/v1/chat/completions";

const REQUEST_FULL: &str =
    include_str!("fixtures/openai-chat/openai-python-3.5.0-request-full.json");
const RESPONSE: &str = include_str!("fixtures/openai-chat/lmstudio-0.4.26-response.json");
const RESPONSE_TOOL_CALL: &str =
    include_str!("fixtures/openai-chat/lmstudio-0.4.26-response-tool-call.json");
const ERROR_FLAT: &str = include_str!("fixtures/openai-chat/lmstudio-0.4.26-error-flat.json");
const ERROR_OBJECT: &str = include_str!("fixtures/openai-chat/lmstudio-0.4.26-error-object.json");
const STREAM: &str = include_str!("fixtures/openai-chat/lmstudio-0.4.26-stream.txt");

/// The content types LM Studio 0.4.26 sent with the recordings.
const LMSTUDIO_JSON: &str = "application/json; charset=utf-8";
const LMSTUDIO_STREAM: &str = "text/event-stream";

const EMAIL: &str = "jane.doe@example.com";
const IBAN: &str = "GB82WEST12345698765432";

/// Serialises every test: the metric families are shared by the binary.
static METRICS: Mutex<()> = Mutex::const_new(());

const PII: &str = "[builtin_guards.pii]\nscanner_threads = 1\n";

static SHARED_ENGINE: LazyLock<Arc<Engine>> = LazyLock::new(|| {
    let config = Setup::default().config("http://127.0.0.1:9", PII);
    Arc::new(Engine::from_config(&config).unwrap())
});

// ---------------------------------------------------------------------------
// Stub upstream
// ---------------------------------------------------------------------------

/// An upstream that answers every request with one fixed response, and
/// counts the requests it got.
struct Upstream {
    url: String,
    hits: Arc<AtomicUsize>,
}

impl Upstream {
    async fn start(status: u16, content_type: &'static str, body: impl Into<String>) -> Self {
        let body = body.into();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let app = Router::new().fallback(move || {
            let (counter, body) = (Arc::clone(&counter), body.clone());
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut resp = Response::new(Body::from(body));
                *resp.status_mut() = StatusCode::from_u16(status).unwrap();
                resp.headers_mut()
                    .insert("content-type", content_type.parse().unwrap());
                resp
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        wait_for_port(addr).await;
        Upstream {
            url: format!("http://{addr}"),
            hits,
        }
    }

    /// A recorded JSON response, edited by `edit`.
    async fn json(status: u16, raw: &str, edit: impl FnOnce(&mut Value)) -> Self {
        let mut body: Value = serde_json::from_str(raw).unwrap();
        edit(&mut body);
        Self::start(status, LMSTUDIO_JSON, body.to_string()).await
    }

    /// The recorded plain answer, unedited.
    async fn clean() -> Self {
        Self::start(200, LMSTUDIO_JSON, RESPONSE).await
    }

    /// An upstream that answers `text/event-stream` with `steps`, and with
    /// the header `header` when it is set.
    async fn stream(steps: Vec<Step>, header: Option<(&'static str, &'static str)>) -> Self {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let app = Router::new().fallback(move || {
            let (counter, steps) = (Arc::clone(&counter), steps.clone());
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let body =
                    futures_util::stream::unfold(steps.into_iter(), |mut steps| async move {
                        loop {
                            match steps.next()? {
                                Step::Send(s) => return Some((Ok(Bytes::from(s)), steps)),
                                Step::Wait(d) => tokio::time::sleep(d).await,
                                Step::Fail => {
                                    return Some((Err(std::io::Error::other("cut")), steps));
                                }
                            }
                        }
                    });
                let mut resp = Response::new(Body::from_stream(body));
                resp.headers_mut()
                    .insert("content-type", LMSTUDIO_STREAM.parse().unwrap());
                if let Some((name, value)) = header {
                    resp.headers_mut().insert(name, value.parse().unwrap());
                }
                resp
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        wait_for_port(addr).await;
        Upstream {
            url: format!("http://{addr}"),
            hits,
        }
    }

    /// An upstream that sends `body` in one read.
    async fn sse(body: String) -> Self {
        Self::stream(vec![Step::Send(body)], None).await
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// One step of a scripted stream upstream.
#[derive(Clone)]
enum Step {
    Send(String),
    Wait(Duration),
    /// Cut the connection before the body ends.
    Fail,
}

/// An upstream that reads a request and never answers.
async fn silent_upstream() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            });
        }
    });
    format!("http://{addr}")
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

async fn wait_for_port(addr: SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("server did not start on {addr}");
}

/// The settings a test varies.
struct Setup {
    /// Top-level config keys, such as `on_error`.
    top: &'static str,
    request_scan: bool,
    response_scan: bool,
    /// False for a route without `format`.
    openai_chat: bool,
    /// More keys of the route, such as `stream`.
    route: &'static str,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            top: "",
            request_scan: true,
            response_scan: true,
            openai_chat: true,
            route: "",
        }
    }
}

impl Setup {
    fn top(top: &'static str) -> Self {
        Self {
            top,
            ..Self::default()
        }
    }

    /// A validated config with one route to `upstream`. The listen addresses
    /// are set by [`Proxy`].
    fn config(&self, upstream: &str, guards: &str) -> AppConfig {
        let format = if self.openai_chat {
            "format = \"openai-chat\""
        } else {
            ""
        };
        let toml = format!(
            "{top}\n{guards}\n[reverse_proxy]\nenabled = true\n\
             [reverse_proxy.request]\nscan = {request}\n\
             [reverse_proxy.response]\nscan = {response}\n\
             [[reverse_proxy.routes]]\npath_prefix = \"{ROUTE}\"\nupstream = \"{upstream}\"\n{format}\n{route}\n",
            top = self.top,
            request = self.request_scan,
            response = self.response_scan,
            route = self.route,
        );
        let config: AppConfig = toml::from_str(&toml).unwrap();
        config.validate().unwrap();
        config
    }
}

struct Proxy {
    addr: SocketAddr,
    admin: SocketAddr,
    cancel: CancellationToken,
}

impl Proxy {
    /// The PII guard on the shared engine.
    async fn start(setup: Setup, upstream: &str) -> Self {
        Self::start_with(setup.config(upstream, PII), SHARED_ENGINE.clone()).await
    }

    /// An engine of its own, built from `guards`.
    async fn start_owning(setup: Setup, upstream: &str, guards: &str) -> Self {
        let config = setup.config(upstream, guards);
        let engine = Arc::new(Engine::from_config(&config).unwrap());
        Self::start_with(config, engine).await
    }

    /// A PII guard whose pool owns no scanner threads, so every submit
    /// fails. Validation rejects that value, so it is set after validation.
    async fn start_broken(setup: Setup, upstream: &str) -> Self {
        let mut config = setup.config(upstream, PII);
        config.builtin_guards.pii.as_mut().unwrap().scanner_threads = Some(0);
        let engine = Arc::new(Engine::from_config(&config).unwrap());
        Self::start_with(config, engine).await
    }

    async fn start_with(mut config: AppConfig, engine: Arc<Engine>) -> Self {
        let (addr, admin) = (free_addr().await, free_addr().await);
        config.reverse_proxy.listen = addr.to_string();
        config.admin.listen = admin.to_string();
        let cancel = CancellationToken::new();

        let (proxy_cancel, admin_cancel) = (cancel.clone(), cancel.clone());
        let admin_config = config.admin.clone();
        tokio::spawn(async move {
            reverse_proxy::serve(&config, engine, proxy_cancel)
                .await
                .unwrap();
        });
        tokio::spawn(async move {
            let state = AdminState {
                ready: Arc::new(true.into()),
            };
            admin::serve(&admin_config, state, admin_cancel)
                .await
                .unwrap();
        });
        wait_for_port(addr).await;
        wait_for_port(admin).await;
        Proxy {
            addr,
            admin,
            cancel,
        }
    }

    async fn post_raw(
        &self,
        content_type: &str,
        body: impl Into<reqwest::Body>,
    ) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("http://{}{ROUTE}", self.addr))
            .header("content-type", content_type)
            .body(body)
            .send()
            .await
            .unwrap()
    }

    async fn post(&self, request: &Value) -> reqwest::Response {
        self.post_raw("application/json", request.to_string()).await
    }

    /// One sample of the admin `/metrics` endpoint: the line of `family`
    /// carrying every label in `labels`. An absent sample reads 0.
    async fn metric(&self, family: &str, labels: &[(&str, &str)]) -> f64 {
        let text = reqwest::get(format!("http://{}/metrics", self.admin))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        text.lines()
            .filter(|l| l.starts_with(&format!("{family}{{")))
            .find(|l| {
                labels
                    .iter()
                    .all(|(k, v)| l.contains(&format!("{k}=\"{v}\"")))
            })
            .and_then(|l| l.rsplit(' ').next())
            .map_or(0.0, |v| v.parse().unwrap())
    }

    async fn errors(&self, outcome: &str, reason: &str) -> f64 {
        self.metric(
            "voidwall_errors_total",
            &[("outcome", outcome), ("reason", reason)],
        )
        .await
    }

    async fn stopped(&self, direction: &str) -> f64 {
        self.metric(
            "voidwall_blocked_total",
            &[
                ("mode", "reverse_proxy"),
                ("route", ROUTE),
                ("direction", direction),
            ],
        )
        .await
    }

    async fn encoded(&self, direction: &str) -> f64 {
        self.metric(
            "voidwall_unscanned_total",
            &[
                ("mode", "reverse_proxy"),
                ("route", ROUTE),
                ("direction", direction),
                ("reason", "encoded_data"),
            ],
        )
        .await
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

// ---------------------------------------------------------------------------
// Payloads and answers
// ---------------------------------------------------------------------------

/// The full request fixture with `edit` applied.
fn request(edit: impl FnOnce(&mut Value)) -> Value {
    let mut payload: Value = serde_json::from_str(REQUEST_FULL).unwrap();
    edit(&mut payload);
    payload
}

/// A clean request with one user message.
fn clean_request() -> Value {
    json!({"model": "m", "messages": [{"role": "user", "content": "Where is my order 4471?"}]})
}

fn message<'a>(payload: &'a mut Value, role: &str) -> &'a mut Value {
    payload["messages"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|m| m["role"] == role)
        .unwrap()
}

/// The `error` object of an OpenAI-shaped answer, asserting its status.
async fn openai_error(resp: reqwest::Response, status: u16) -> Value {
    assert_eq!(resp.status(), status);
    let body: Value = resp.json().await.unwrap();
    body["error"].clone()
}

/// Assert the 400 block naming `kinds`, and return the raw body.
async fn assert_block(resp: reqwest::Response, kinds: &[&str]) -> String {
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.headers()["content-type"], "application/json");
    let text = resp.text().await.unwrap();
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["error"]["code"], "content_filter", "{text}");
    assert_eq!(body["error"]["kinds"], json!(kinds), "{text}");
    text
}

// ---------------------------------------------------------------------------
// A route opts in with format openai-chat
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_route_with_the_format() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    let payload = request(|p| message(p, "user")["content"][0]["text"] = json!(EMAIL));
    assert_block(proxy.post(&payload).await, &["EMAIL"]).await;
    assert_eq!(upstream.hits(), 0);
}

#[tokio::test]
async fn a_route_without_the_format() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let setup = Setup {
        openai_chat: false,
        ..Setup::default()
    };
    let proxy = Proxy::start(setup, &upstream.url).await;

    let resp = proxy.post(&json!({"note": EMAIL})).await;
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body,
        json!({"error": "content blocked", "kinds": ["EMAIL"]})
    );
}

#[tokio::test]
async fn an_empty_request_body() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    let resp = reqwest::get(format!("http://{}{ROUTE}", proxy.addr))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(upstream.hits(), 1);
}

// ---------------------------------------------------------------------------
// The request body must be a Chat Completions request
// ---------------------------------------------------------------------------

#[tokio::test]
async fn json_is_admitted_although_content_types_omits_it() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start(
        Setup::top(r#"content_types = ["text/plain"]"#),
        &upstream.url,
    )
    .await;

    let payload = request(|p| message(p, "user")["content"][0]["text"] = json!(EMAIL));
    assert_block(proxy.post(&payload).await, &["EMAIL"]).await;
}

#[tokio::test]
async fn a_body_that_is_not_json() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start(Setup::top(r#"on_error = "fail_open""#), &upstream.url).await;
    let before = proxy.errors("blocked", "body_parse_failed").await;

    let resp = proxy.post_raw("text/plain", "hello").await;
    let error = openai_error(resp, 400).await;
    assert_eq!(error["code"], "malformed_body");
    assert_eq!(upstream.hits(), 0);
    assert_eq!(
        proxy.errors("blocked", "body_parse_failed").await,
        before + 1.0
    );
}

#[tokio::test]
async fn messages_is_missing() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    let resp = proxy.post(&json!({"model": "m", "input": "hello"})).await;
    assert_eq!(openai_error(resp, 400).await["code"], "malformed_body");
    assert_eq!(upstream.hits(), 0);
}

// ---------------------------------------------------------------------------
// The request is read from messages, tools, and the free-text fields
// ---------------------------------------------------------------------------

#[test_case(|p: &mut Value| message(p, "system")["content"][0]["text"] = json!(format!("Contact {EMAIL}")) ; "a system message")]
#[test_case(|p: &mut Value| message(p, "assistant")["tool_calls"][0]["function"]["arguments"] = json!(format!("{{\"email\":\"{EMAIL}\"}}")) ; "a replayed tool call")]
#[test_case(|p: &mut Value| p["tools"][0]["function"]["parameters"]["properties"]["order_id"]["description"] = json!(format!("Ask {EMAIL}")) ; "a tool parameter schema")]
#[test_case(|p: &mut Value| p["metadata"]["owner"] = json!(EMAIL) ; "metadata")]
#[test_case(|p: &mut Value| p["safety_identifier"] = json!(EMAIL) ; "safety_identifier")]
#[test_case(|p: &mut Value| p["response_format"]["json_schema"]["schema"]["description"] = json!(format!("Reply to {EMAIL}")) ; "a response format schema")]
#[tokio::test]
async fn a_request_field_is_scanned(edit: fn(&mut Value)) {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    assert_block(proxy.post(&request(edit)).await, &["EMAIL"]).await;
    assert_eq!(upstream.hits(), 0);
}

#[tokio::test]
async fn the_model_name_is_not_scanned() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    let resp = proxy.post(&request(|p| p["model"] = json!(EMAIL))).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(upstream.hits(), 1);
}

// ---------------------------------------------------------------------------
// An unknown key or role is scanned generically
// ---------------------------------------------------------------------------

#[test_case(|p: &mut Value| p["chat_template_kwargs"] = json!({"note": EMAIL}) ; "a vendor extension at the top level")]
#[test_case(|p: &mut Value| message(p, "assistant")["reasoning_content"] = json!(format!("The user is {EMAIL}")) ; "a reasoning trace on an assistant message")]
#[test_case(|p: &mut Value| p["messages"].as_array_mut().unwrap().push(json!({"role": "narrator", "content": EMAIL})) ; "an unknown role")]
#[tokio::test]
async fn an_unknown_key_or_role_is_scanned(edit: fn(&mut Value)) {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    assert_block(proxy.post(&request(edit)).await, &["EMAIL"]).await;
}

// ---------------------------------------------------------------------------
// The response is read from choices
// ---------------------------------------------------------------------------

#[test_case(200, RESPONSE, |r: &mut Value| r["choices"][0]["message"]["content"] = json!(format!("Your email is {EMAIL}")) ; "model output")]
#[test_case(200, RESPONSE_TOOL_CALL, |r: &mut Value| r["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = json!(format!("{{\"email\":\"{EMAIL}\"}}")) ; "model tool call")]
#[test_case(400, ERROR_OBJECT, |r: &mut Value| r["error"]["message"] = json!(format!("Unknown user {EMAIL}")) ; "an upstream error that echoes input")]
#[test_case(400, ERROR_FLAT, |r: &mut Value| *r = json!({"error": format!("Got '{EMAIL}'")}) ; "an upstream error as a flat string")]
#[test_case(200, RESPONSE, |r: &mut Value| r["choices"][0]["message"]["reasoning_content"] = json!(format!("The user is {EMAIL}")) ; "a reasoning trace in the response")]
#[tokio::test]
async fn a_response_field_is_scanned(status: u16, raw: &str, edit: fn(&mut Value)) {
    let _m = METRICS.lock().await;
    let upstream = Upstream::json(status, raw, edit).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    let body = assert_block(proxy.post(&clean_request()).await, &["EMAIL"]).await;
    assert!(!body.contains(EMAIL), "{body}");
    assert!(
        !body.contains("chatcmpl"),
        "the upstream body reached the client"
    );
}

#[tokio::test]
async fn logprobs_are_not_scanned() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::json(200, RESPONSE, |r| {
        r["choices"][0]["logprobs"] =
            json!({"content": [{"token": EMAIL, "logprob": -0.1, "top_logprobs": []}]});
    })
    .await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    let resp = proxy.post(&clean_request()).await;
    assert_eq!(resp.status(), 200);
}

// ---------------------------------------------------------------------------
// Encoded data is skipped and counted
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_inline_image() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;
    let before = proxy.encoded("request").await;

    let payload = json!({"model": "m", "messages": [{"role": "user", "content": [
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}},
        {"type": "text", "text": "What is on the label?"},
    ]}]});
    assert_eq!(proxy.post(&payload).await.status(), 200);
    assert_eq!(proxy.encoded("request").await, before + 1.0);
}

#[tokio::test]
async fn audio_output() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::json(200, RESPONSE, |r| {
        r["choices"][0]["message"]["audio"] =
            json!({"id": "audio_1", "expires_at": 1792254850, "data": "UklGRg==", "transcript": "Order 4471 shipped."});
    })
    .await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;
    let before = proxy.encoded("response").await;

    assert_eq!(proxy.post(&clean_request()).await.status(), 200);
    assert_eq!(proxy.encoded("response").await, before + 1.0);
}

// ---------------------------------------------------------------------------
// An unknown content part type follows on_error
// ---------------------------------------------------------------------------

fn hologram(text: &str) -> Value {
    json!({"model": "m", "messages": [{"role": "user", "content": [
        {"type": "hologram", "hologram": {"id": "h1"}},
        {"type": "text", "text": text},
    ]}]})
}

#[tokio::test]
async fn unknown_part_under_fail_close() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;
    let before = proxy.errors("blocked", "unscannable_content").await;

    let error = openai_error(proxy.post(&hologram("hello")).await, 422).await;
    assert_eq!(error["code"], "unscannable_content");
    assert_eq!(upstream.hits(), 0);
    assert_eq!(
        proxy.errors("blocked", "unscannable_content").await,
        before + 1.0
    );
}

#[tokio::test]
async fn unknown_part_under_fail_open() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start(Setup::top(r#"on_error = "fail_open""#), &upstream.url).await;
    let before = proxy.errors("passed", "unscannable_content").await;

    assert_block(proxy.post(&hologram(EMAIL)).await, &["EMAIL"]).await;
    assert_eq!(
        proxy.errors("passed", "unscannable_content").await,
        before + 1.0
    );
}

// ---------------------------------------------------------------------------
// Streams: shared helpers
// ---------------------------------------------------------------------------

fn stream_request() -> Value {
    let mut payload = clean_request();
    payload["stream"] = json!(true);
    payload
}

const DONE: &str = "data: [DONE]\n\n";

/// A small window, so the recorded stream releases events before it ends.
const SMALL_WINDOW: &str = "stream_holdback_bytes = 32\nstream_scan_bytes = 8\n";

/// The events of the recorded stream, each with its blank line. The last one
/// is `[DONE]`.
fn recorded_events() -> Vec<String> {
    STREAM.split_inclusive("\n\n").map(str::to_string).collect()
}

/// The recorded events without `[DONE]`.
fn recorded_text_events() -> Vec<String> {
    let mut events = recorded_events();
    assert_eq!(events.pop().as_deref(), Some(DONE));
    events
}

/// A chunk shaped like the recorded ones, with `choices`.
fn chunk_with(choices: Value) -> String {
    let first = &recorded_events()[1];
    let mut chunk: Value =
        serde_json::from_str(first.strip_prefix("data: ").unwrap().trim_end()).unwrap();
    chunk["choices"] = choices;
    format!("data: {chunk}\n\n")
}

/// A chunk of choice 0 with `delta`.
fn delta(delta: Value) -> String {
    chunk_with(json!([{"index": 0, "delta": delta, "logprobs": null, "finish_reason": null}]))
}

fn content(text: &str) -> String {
    delta(json!({"content": text}))
}

/// The recorded stream with `events` inserted before `[DONE]`.
fn recorded_with(events: &[String]) -> String {
    let mut all = recorded_text_events();
    all.extend(events.iter().cloned());
    all.push(DONE.to_string());
    all.concat()
}

/// The parts of [`EMAIL`] in three chunks.
fn email_parts() -> [&'static str; 3] {
    ["jane.d", "oe@exam", "ple.com"]
}

/// The `error` object of the last event of a stream body.
fn last_event_error(body: &str) -> Value {
    let last = body.trim_end().rsplit("\n\n").next().unwrap();
    let data: Value = serde_json::from_str(last.strip_prefix("data: ").unwrap()).unwrap();
    data["error"].clone()
}

/// Read a stream that went out and was stopped after its first byte: the
/// status is the upstream's, the body starts with recorded events, and its
/// last event is the error. Return that error.
async fn assert_cut(resp: reqwest::Response) -> Value {
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.starts_with(&recorded_events()[0]),
        "some events reached the client: {body}"
    );
    assert!(!body.contains("[DONE]"), "{body}");
    last_event_error(&body)
}

/// The error code of a stopped stream, before or after its first byte.
async fn stop_code(resp: reqwest::Response) -> Value {
    if resp.status() == 200 {
        last_event_error(&resp.text().await.unwrap())["code"].clone()
    } else {
        resp.json::<Value>().await.unwrap()["error"]["code"].clone()
    }
}

/// A model guard section over `fixture`, for the tests that need a guard
/// whose findings have no span. The model scores high on a window holding
/// the word [`TRIGGER`].
fn model_guard(dir: &std::path::Path, fixture: Fixture) -> String {
    format!(
        r#"
[guards.injection]
adapter = "text_classifier"
model_path = "{model}"
tokenizer_path = "{tokenizer}"
max_tokens = 16
labels = ["PROMPT_INJECTION"]
threads = 1

[guards.injection.thresholds]
PROMPT_INJECTION = 0.90
"#,
        model = fixture.write(dir).display(),
        tokenizer = TokenizerFixture::default().write(dir).display(),
    )
}

impl Proxy {
    async fn cuts(&self, reason: &str) -> f64 {
        self.metric(
            "voidwall_streams_cut_total",
            &[
                ("mode", "reverse_proxy"),
                ("route", ROUTE),
                ("reason", reason),
            ],
        )
        .await
    }

    async fn all_cuts(&self) -> f64 {
        let mut total = 0.0;
        for reason in [
            "detection",
            "scan_error",
            "idle_timeout",
            "too_large",
            "upstream_error",
            "malformed_body",
            "unscannable_content",
        ] {
            total += self.cuts(reason).await;
        }
        total
    }
}

// ---------------------------------------------------------------------------
// A stream on an openai-chat route is scanned
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_clean_stream_in_hold_back_mode() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::start(200, LMSTUDIO_STREAM, STREAM).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], LMSTUDIO_STREAM);
    let body = resp.text().await.unwrap();
    assert_eq!(body, STREAM);
    assert!(body.ends_with(DONE));
}

#[tokio::test]
async fn a_stream_without_stream_true_in_the_request() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::sse(recorded_with(&[content(&format!("Mail {EMAIL}"))])).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    assert_block(proxy.post(&clean_request()).await, &["EMAIL"]).await;
}

#[tokio::test]
async fn a_detection_in_a_response_header() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::stream(
        vec![Step::Send(STREAM.to_string())],
        Some(("x-note", EMAIL)),
    )
    .await;
    let setup = Setup {
        route: r#"headers = ["x-note"]"#,
        ..Setup::default()
    };
    let proxy = Proxy::start(setup, &upstream.url).await;

    let body = assert_block(proxy.post(&stream_request()).await, &["EMAIL"]).await;
    assert!(!body.contains("chatcmpl"), "a body byte reached the client");
}

#[tokio::test]
async fn response_scan_off_passes_a_stream() {
    let _m = METRICS.lock().await;
    let stream = recorded_with(&[content(EMAIL)]);
    let upstream = Upstream::sse(stream.clone()).await;
    let setup = Setup {
        response_scan: false,
        ..Setup::default()
    };
    let proxy = Proxy::start(setup, &upstream.url).await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), stream);
}

// ---------------------------------------------------------------------------
// Stream text is read by the response field rules
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_value_split_across_chunks() {
    let _m = METRICS.lock().await;
    let parts = email_parts().map(content);
    let upstream = Upstream::sse(recorded_with(&parts)).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    assert_block(proxy.post(&stream_request()).await, &["EMAIL"]).await;
}

#[tokio::test]
async fn tool_call_arguments() {
    let _m = METRICS.lock().await;
    let call = |arguments: &str| {
        delta(json!({"tool_calls": [{"index": 0, "function": {"arguments": arguments}}]}))
    };
    let mut events = vec![delta(json!({"tool_calls": [{
        "index": 0, "id": "call_1", "type": "function",
        "function": {"name": "lookup_order", "arguments": "{\"email\": \""},
    }]}))];
    events.extend(email_parts().map(call));
    events.push(call("\"}"));
    let upstream = Upstream::sse(recorded_with(&events)).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    assert_block(proxy.post(&stream_request()).await, &["EMAIL"]).await;
}

#[tokio::test]
async fn a_reasoning_trace() {
    let _m = METRICS.lock().await;
    // The recorded reasoning, with the placeholder in three of its chunks.
    let mut events = recorded_events();
    for (i, part) in email_parts().into_iter().enumerate() {
        let event = &mut events[10 + i];
        let mut chunk: Value =
            serde_json::from_str(event.strip_prefix("data: ").unwrap().trim_end()).unwrap();
        chunk["choices"][0]["delta"]["reasoning_content"] = json!(part);
        *event = format!("data: {chunk}\n\n");
    }
    let upstream = Upstream::sse(events.concat()).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    assert_block(proxy.post(&stream_request()).await, &["EMAIL"]).await;
}

#[tokio::test]
async fn two_choices_interleaved() {
    let _m = METRICS.lock().await;
    let choice = |index: u64, text: &str| {
        chunk_with(json!([{"index": index, "delta": {"content": text}, "finish_reason": null}]))
    };
    let mut events = Vec::new();
    for part in email_parts() {
        events.push(choice(0, "Your order "));
        events.push(choice(1, part));
    }
    let upstream = Upstream::sse(recorded_with(&events)).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    assert_block(proxy.post(&stream_request()).await, &["EMAIL"]).await;
}

#[tokio::test]
async fn an_upstream_error_event() {
    let _m = METRICS.lock().await;
    let error =
        json!({"error": {"message": format!("Unknown user {EMAIL}"), "type": "invalid_request"}});
    let upstream = Upstream::sse(recorded_with(&[format!("data: {error}\n\n")])).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    assert_block(proxy.post(&stream_request()).await, &["EMAIL"]).await;
}

#[tokio::test]
async fn logprobs_are_not_scanned_in_a_stream() {
    let _m = METRICS.lock().await;
    let event = chunk_with(json!([{
        "index": 0, "delta": {"content": "ok"}, "finish_reason": null,
        "logprobs": {"content": [{"token": EMAIL, "logprob": -0.1, "top_logprobs": []}]},
    }]));
    let stream = recorded_with(&[event]);
    let upstream = Upstream::sse(stream.clone()).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), stream);
}

// ---------------------------------------------------------------------------
// A payload that does not parse follows the parse-failure rule
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_bad_payload_under_fail_close() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::sse(recorded_with(&["data: {not json\n\n".to_string()])).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    assert_eq!(
        stop_code(proxy.post(&stream_request()).await).await,
        "malformed_body"
    );
}

#[tokio::test]
async fn a_bad_payload_under_fail_open() {
    let _m = METRICS.lock().await;
    let stream = recorded_with(&["data: {not json\n\n".to_string()]);
    let upstream = Upstream::sse(stream.clone()).await;
    let proxy = Proxy::start(Setup::top(r#"on_error = "fail_open""#), &upstream.url).await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), stream);
}

// ---------------------------------------------------------------------------
// Hold-back mode forwards an event only after a scan clears it
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_short_reply() {
    let _m = METRICS.lock().await;
    // The recorded stream's last text event carries `finish_reason`.
    let mut events = recorded_text_events();
    let finish = events.pop().unwrap();
    assert!(finish.contains(r#""finish_reason":"length""#));
    let mut steps: Vec<Step> = events.into_iter().map(Step::Send).collect();
    steps.push(Step::Wait(Duration::from_millis(300)));
    steps.push(Step::Send(finish + DONE));
    let upstream = Upstream::stream(steps, None).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    let started = Instant::now();
    let resp = proxy.post(&stream_request()).await;
    assert!(
        started.elapsed() >= Duration::from_millis(300),
        "no byte before the choice finished"
    );
    assert_eq!(resp.text().await.unwrap(), STREAM);
}

#[tokio::test]
async fn a_value_inside_the_hold_back() {
    let _m = METRICS.lock().await;
    let parts = email_parts().map(content);
    let upstream = Upstream::sse(recorded_with(&parts)).await;
    let proxy = Proxy::start(Setup::top(SMALL_WINDOW), &upstream.url).await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.starts_with(&recorded_events()[0]),
        "the client has some events"
    );
    for part in email_parts() {
        assert!(!body.contains(part), "a byte of the placeholder: {body}");
    }
    assert_eq!(last_event_error(&body)["code"], "content_filter");
}

#[tokio::test]
async fn a_keyword_before_the_value() {
    let _m = METRICS.lock().await;
    // The keyword and 40 spaces, then, in a later read, the value.
    let mut first = vec![content("passport:")];
    first.extend((0..8).map(|_| content("     ")));
    let steps = vec![
        Step::Send(first.concat()),
        Step::Wait(Duration::from_millis(200)),
        Step::Send(content("987654321") + DONE),
    ];
    let upstream = Upstream::stream(steps, None).await;
    let proxy = Proxy::start(Setup::top(SMALL_WINDOW), &upstream.url).await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.starts_with(&first[0]),
        "the keyword is released: {body}"
    );
    let error = last_event_error(&body);
    assert_eq!(error["kinds"], json!(["PASSPORT_NUMBER"]));
}

// ---------------------------------------------------------------------------
// A finding at the end of the received text waits
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_value_that_is_not_complete_yet() {
    let _m = METRICS.lock().await;
    // The first read ends in a US SSN; the next digit makes it no kind.
    let steps = vec![
        Step::Send(content("my number is 123-45-6789")),
        Step::Wait(Duration::from_millis(200)),
        Step::Send(content("0, not a social security number") + DONE),
    ];
    let upstream = Upstream::stream(steps, None).await;
    let proxy = Proxy::start(
        Setup::top("stream_holdback_bytes = 8\nstream_scan_bytes = 8\n"),
        &upstream.url,
    )
    .await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.ends_with(DONE), "{body}");
}

#[tokio::test]
async fn a_value_at_the_end_of_the_stream() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::sse(recorded_with(&[content(&format!(" {EMAIL}"))])).await;
    let proxy = Proxy::start(Setup::top(SMALL_WINDOW), &upstream.url).await;

    let error = assert_cut(proxy.post(&stream_request()).await).await;
    assert_eq!(error["code"], "content_filter");
}

// ---------------------------------------------------------------------------
// A finding without a span waits for the next scan
// ---------------------------------------------------------------------------

/// The text `first`, then in a later read `second`, each scanned on its own.
async fn model_stream(first: &str, second: &str) -> (Upstream, tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture {
        trigger: true,
        ..Fixture::default()
    };
    let guards = model_guard(dir.path(), fixture);
    let steps = vec![
        Step::Send(content(first)),
        Step::Wait(Duration::from_millis(200)),
        Step::Send(content(second)),
        Step::Wait(Duration::from_millis(200)),
        Step::Send(DONE.to_string()),
    ];
    (Upstream::stream(steps, None).await, dir, guards)
}

#[tokio::test]
async fn the_finding_comes_back() {
    let _m = METRICS.lock().await;
    let (upstream, _dir, guards) =
        model_stream(&format!("we pull the {TRIGGER}"), " now and then").await;
    let setup = Setup::top("stream_holdback_bytes = 64\nstream_scan_bytes = 4\n");
    let proxy = Proxy::start_owning(setup, &upstream.url, &guards).await;

    assert_block(proxy.post(&stream_request()).await, &["PROMPT_INJECTION"]).await;
}

#[tokio::test]
async fn the_finding_does_not_come_back() {
    let _m = METRICS.lock().await;
    // The word grows into one the model does not know.
    let (upstream, _dir, guards) =
        model_stream(&format!("we pull the {TRIGGER}"), "ed nothing").await;
    let setup = Setup::top("stream_holdback_bytes = 64\nstream_scan_bytes = 4\n");
    let proxy = Proxy::start_owning(setup, &upstream.url, &guards).await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().ends_with(DONE));
}

// ---------------------------------------------------------------------------
// A text of a choice closes when the choice moves on
// ---------------------------------------------------------------------------

/// How long the upstream waits before it ends the stream.
const PAUSE: Duration = Duration::from_millis(500);

fn reasoning(text: &str) -> String {
    delta(json!({"reasoning_content": text}))
}

/// A stream that sends `first`, waits [`PAUSE`], then sends `rest` and
/// `[DONE]`.
async fn paused_stream(first: &[String], rest: &[String]) -> Upstream {
    let steps = vec![
        Step::Send(first.concat()),
        Step::Wait(PAUSE),
        Step::Send(rest.concat() + DONE),
    ];
    Upstream::stream(steps, None).await
}

/// Post a stream request and read the body until it holds `event`. Return
/// whether that came before the upstream's pause ended.
async fn arrives_before_the_pause(proxy: &Proxy, event: &str) -> bool {
    let started = Instant::now();
    let mut resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    let mut body = String::new();
    while !body.contains(event) {
        let chunk = resp.chunk().await.unwrap().expect("the body ended first");
        body.push_str(&String::from_utf8_lossy(&chunk));
    }
    started.elapsed() < PAUSE
}

/// Ten bytes of clean text.
const DOTS: &str = "..........";

#[tokio::test]
async fn content_after_a_reasoning_trace() {
    let _m = METRICS.lock().await;
    // Each event differs, so the last one is found only when it arrives.
    let trace: Vec<String> = (0..5)
        .map(|i| reasoning(&format!("{i}{}", &DOTS[1..])))
        .collect();
    let mut first = trace.clone();
    first.extend((0..5).map(|_| content(DOTS)));
    let upstream = paused_stream(&first, &[content(DOTS)]).await;
    let proxy = Proxy::start(Setup::top(SMALL_WINDOW), &upstream.url).await;

    let last = trace.last().unwrap();
    assert!(arrives_before_the_pause(&proxy, last).await);
}

#[tokio::test]
async fn tool_call_arguments_after_the_name() {
    let _m = METRICS.lock().await;
    let call = |function: Value| delta(json!({"tool_calls": [{"index": 0, "function": function}]}));
    let name = call(json!({"name": "lookup"}));
    let mut first = vec![name.clone()];
    first.extend((0..5).map(|_| call(json!({"arguments": DOTS}))));
    let upstream = paused_stream(&first, &[call(json!({"arguments": DOTS}))]).await;
    let proxy = Proxy::start(Setup::top(SMALL_WINDOW), &upstream.url).await;

    assert!(arrives_before_the_pause(&proxy, &name).await);
}

#[tokio::test]
async fn a_choice_that_finishes() {
    let _m = METRICS.lock().await;
    let of = |index: u64, text: &str| {
        chunk_with(json!([{"index": index, "delta": {"content": text}, "finish_reason": null}]))
    };
    let finish = chunk_with(json!([{"index": 0, "delta": {}, "finish_reason": "stop"}]));
    let mut first = vec![of(0, DOTS), finish.clone()];
    first.extend((0..5).map(|_| of(1, DOTS)));
    let upstream = paused_stream(&first, &[of(1, DOTS)]).await;
    let proxy = Proxy::start(Setup::top(SMALL_WINDOW), &upstream.url).await;

    assert!(arrives_before_the_pause(&proxy, &finish).await);
}

#[tokio::test]
async fn a_value_at_the_switch() {
    let _m = METRICS.lock().await;
    let mut events = vec![reasoning(&format!("Mail {EMAIL}"))];
    events.extend((0..5).map(|_| content(DOTS)));
    let upstream = Upstream::sse(recorded_with(&events)).await;
    let proxy = Proxy::start(Setup::top(SMALL_WINDOW), &upstream.url).await;

    assert_eq!(
        stop_code(proxy.post(&stream_request()).await).await,
        "content_filter"
    );
}

#[tokio::test]
async fn a_text_that_opens_again() {
    let _m = METRICS.lock().await;
    let mut events: Vec<String> = (0..5).map(|_| reasoning(DOTS)).collect();
    events.extend((0..5).map(|_| content(DOTS)));
    events.push(reasoning(&format!(" mail {EMAIL} now")));
    events.extend((0..5).map(|_| content(DOTS)));
    let upstream = Upstream::sse(recorded_with(&events)).await;
    let proxy = Proxy::start(Setup::top(SMALL_WINDOW), &upstream.url).await;

    let error = assert_cut(proxy.post(&stream_request()).await).await;
    assert_eq!(error["code"], "content_filter");
}

#[tokio::test]
async fn a_finding_without_a_span_that_does_not_come_back_at_the_close() {
    let _m = METRICS.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture {
        trigger: true,
        ..Fixture::default()
    };
    let guards = model_guard(dir.path(), fixture);
    let steps = vec![
        Step::Send(reasoning(&format!("we pull the {TRIGGER}"))),
        Step::Wait(Duration::from_millis(200)),
        // Below the scan step: only the close scans the grown word.
        Step::Send(reasoning("ed")),
        Step::Send(content(DOTS)),
        Step::Send(DONE.to_string()),
    ];
    let upstream = Upstream::stream(steps, None).await;
    let setup = Setup::top("stream_holdback_bytes = 64\nstream_scan_bytes = 4\n");
    let proxy = Proxy::start_owning(setup, &upstream.url, &guards).await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().ends_with(DONE));
}

#[tokio::test]
async fn a_finding_without_a_span_that_does_not_come_back_at_a_close_with_the_end() {
    let _m = METRICS.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture {
        trigger: true,
        ..Fixture::default()
    };
    let guards = model_guard(dir.path(), fixture);
    let finish = chunk_with(json!([{"index": 0, "delta": {}, "finish_reason": "stop"}]));
    let steps = vec![
        Step::Send(content(&format!("we pull the {TRIGGER}"))),
        Step::Wait(Duration::from_millis(200)),
        // One read closes the text and ends the stream.
        Step::Send([content("ed"), finish, DONE.to_string()].concat()),
    ];
    let upstream = Upstream::stream(steps, None).await;
    let setup = Setup::top("stream_holdback_bytes = 64\nstream_scan_bytes = 4\n");
    let proxy = Proxy::start_owning(setup, &upstream.url, &guards).await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().ends_with(DONE));
}

// ---------------------------------------------------------------------------
// Before the first byte a stop answers as a buffered response
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_detection_in_the_first_text() {
    let _m = METRICS.lock().await;
    let mut events = vec![content(EMAIL)];
    events.extend(recorded_events());
    let upstream = Upstream::sse(events.concat()).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;
    let before = proxy.all_cuts().await;

    let body = assert_block(proxy.post(&stream_request()).await, &["EMAIL"]).await;
    assert!(!body.contains("chatcmpl"), "no byte of the upstream body");
    // metrics, "A detection before the first byte".
    assert_eq!(proxy.all_cuts().await, before);
}

// ---------------------------------------------------------------------------
// After the first byte a stop ends the stream with one error event
// ---------------------------------------------------------------------------

/// Also metrics, "A detection after the first byte", "A stream under
/// fail_close", and the label set of the streams-cut family.
#[tokio::test]
async fn a_detection_after_the_first_release() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::sse(recorded_with(&[content(&format!(" mail {EMAIL} now"))])).await;
    let proxy = Proxy::start(Setup::top(SMALL_WINDOW), &upstream.url).await;
    let labels = [
        ("mode", "reverse_proxy"),
        ("route", ROUTE),
        ("direction", "response"),
    ];
    let before = (
        proxy.cuts("detection").await,
        proxy.metric("voidwall_blocked_total", &labels).await,
        proxy.metric("voidwall_pii_blocked_total", &labels).await,
    );

    let error = assert_cut(proxy.post(&stream_request()).await).await;
    assert_eq!(
        error,
        json!({
            "message": "content blocked. Kinds: EMAIL", "type": "invalid_request_error",
            "param": null, "code": "content_filter", "kinds": ["EMAIL"],
        })
    );

    let after = (
        proxy.cuts("detection").await,
        proxy.metric("voidwall_blocked_total", &labels).await,
        proxy.metric("voidwall_pii_blocked_total", &labels).await,
    );
    assert_eq!(after, (before.0 + 1.0, before.1 + 1.0, before.2 + 1.0));

    let text = reqwest::get(format!("http://{}/metrics", proxy.admin))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let sample = text
        .lines()
        .find(|l| l.starts_with("voidwall_streams_cut_total{"))
        .unwrap();
    let mut names: Vec<&str> = sample
        .split('{')
        .nth(1)
        .unwrap()
        .split('}')
        .next()
        .unwrap()
        .split(',')
        .map(|pair| pair.split('=').next().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["mode", "reason", "route"]);
}

// ---------------------------------------------------------------------------
// A guard error follows on_error
// ---------------------------------------------------------------------------

/// A stream that sends recorded events, then, in a later read, the word that
/// makes the model guard fail.
async fn failing_model_stream() -> (Upstream, tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture {
        nan_row: Some(TRIGGER_ID),
        ..Fixture::default()
    };
    let guards = model_guard(dir.path(), fixture);
    let steps = vec![
        Step::Send(recorded_text_events().concat()),
        Step::Wait(Duration::from_millis(200)),
        Step::Send(content(&format!(" pull the {TRIGGER} now"))),
        Step::Send(content(&format!(" {EMAIL}"))),
        Step::Send(DONE.to_string()),
    ];
    (Upstream::stream(steps, None).await, dir, guards)
}

#[tokio::test]
async fn a_scanner_failure_under_fail_close_after_the_first_byte() {
    let _m = METRICS.lock().await;
    let (upstream, _dir, guards) = failing_model_stream().await;
    let proxy = Proxy::start_owning(Setup::top(SMALL_WINDOW), &upstream.url, &guards).await;

    let error = assert_cut(proxy.post(&stream_request()).await).await;
    assert_eq!(error["code"], "internal_error");
}

#[tokio::test]
async fn a_scanner_failure_under_fail_open_in_a_stream() {
    let _m = METRICS.lock().await;
    let (upstream, _dir, guards) = failing_model_stream().await;
    let setup =
        Setup::top("on_error = \"fail_open\"\nstream_holdback_bytes = 32\nstream_scan_bytes = 8\n");
    let proxy = Proxy::start_owning(setup, &upstream.url, &guards).await;
    let before = proxy.errors("passed", "inference_failure").await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.ends_with(DONE), "the client receives the rest: {body}");
    assert_eq!(
        proxy.errors("passed", "inference_failure").await,
        before + 1.0
    );
}

// ---------------------------------------------------------------------------
// The stream ends at DONE or at a clean end of the body
// ---------------------------------------------------------------------------

/// The upstream sends the whole body with its length. Also "The upstream
/// length is not forwarded": hold-back sends no length, buffer mode the
/// length of what it sends.
#[test_case("", None ; "hold-back")]
#[test_case("stream = \"buffer\"", Some(STREAM.len() as u64) ; "buffer")]
#[tokio::test]
async fn bytes_after_done(route: &'static str, length: Option<u64>) {
    let _m = METRICS.lock().await;
    let upstream =
        Upstream::start(200, LMSTUDIO_STREAM, STREAM.to_string() + &content("after")).await;
    let setup = Setup {
        route,
        ..Setup::default()
    };
    let proxy = Proxy::start(setup, &upstream.url).await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.content_length(), length);
    assert_eq!(resp.text().await.unwrap(), STREAM);
}

#[tokio::test]
async fn no_done_line() {
    let _m = METRICS.lock().await;
    let stream = recorded_text_events().concat();
    let upstream = Upstream::sse(stream.clone()).await;
    let proxy = Proxy::start(Setup::top(SMALL_WINDOW), &upstream.url).await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), stream);
}

#[tokio::test]
async fn the_upstream_connection_fails() {
    let _m = METRICS.lock().await;
    let steps = vec![
        Step::Send(recorded_text_events().concat()),
        Step::Wait(Duration::from_millis(200)),
        Step::Fail,
    ];
    let upstream = Upstream::stream(steps, None).await;
    let proxy = Proxy::start(Setup::top(SMALL_WINDOW), &upstream.url).await;

    let error = assert_cut(proxy.post(&stream_request()).await).await;
    assert_eq!(error["code"], "upstream_error");
}

// ---------------------------------------------------------------------------
// The idle timeout limits each gap in a stream
// ---------------------------------------------------------------------------

/// Also metrics, "An idle stream" and "An idle stream after the first byte".
#[tokio::test]
async fn the_upstream_goes_silent() {
    let _m = METRICS.lock().await;
    let steps = vec![
        Step::Send(recorded_text_events().concat()),
        Step::Wait(Duration::from_millis(1500)),
        Step::Send(DONE.to_string()),
    ];
    let upstream = Upstream::stream(steps, None).await;
    let setup = Setup::top(
        "stream_idle_timeout_secs = 1\nstream_holdback_bytes = 32\nstream_scan_bytes = 8\n",
    );
    let proxy = Proxy::start(setup, &upstream.url).await;
    let before = (
        proxy.cuts("idle_timeout").await,
        proxy.stopped("response").await,
        proxy.errors("blocked", "upstream_timeout").await,
    );

    let error = assert_cut(proxy.post(&stream_request()).await).await;
    assert_eq!(error["code"], "upstream_timeout");
    let after = (
        proxy.cuts("idle_timeout").await,
        proxy.stopped("response").await,
        proxy.errors("blocked", "upstream_timeout").await,
    );
    assert_eq!(after, (before.0 + 1.0, before.1, before.2 + 1.0));
}

#[tokio::test]
async fn keep_alive_comments() {
    let _m = METRICS.lock().await;
    let mut steps = vec![Step::Send(recorded_events()[0].clone())];
    for _ in 0..3 {
        steps.push(Step::Wait(Duration::from_millis(600)));
        steps.push(Step::Send(": keep-alive\n\n".to_string()));
    }
    steps.push(Step::Send(recorded_events()[1..].concat()));
    let upstream = Upstream::stream(steps, None).await;
    let proxy = Proxy::start(Setup::top("stream_idle_timeout_secs = 1"), &upstream.url).await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.ends_with(DONE), "{body}");
    assert_eq!(body.matches(": keep-alive").count(), 3);
}

#[tokio::test]
async fn on_error_does_not_change_the_idle_answer() {
    let _m = METRICS.lock().await;
    let steps = vec![
        Step::Send(recorded_events()[0].clone()),
        Step::Wait(Duration::from_millis(1500)),
    ];
    let upstream = Upstream::stream(steps, None).await;
    let setup = Setup::top("on_error = \"fail_open\"\nstream_idle_timeout_secs = 1");
    let proxy = Proxy::start(setup, &upstream.url).await;

    let error = openai_error(proxy.post(&stream_request()).await, 504).await;
    assert_eq!(error["code"], "upstream_timeout");
}

// ---------------------------------------------------------------------------
// The stream size counts against max_body_size
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_stream_larger_than_the_limit() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::start(200, LMSTUDIO_STREAM, STREAM).await;
    let proxy = Proxy::start(Setup::top("max_body_size = 4096"), &upstream.url).await;
    let before = proxy.errors("blocked", "response_too_large").await;

    assert_eq!(
        stop_code(proxy.post(&stream_request()).await).await,
        "upstream_error"
    );
    assert_eq!(
        proxy.errors("blocked", "response_too_large").await,
        before + 1.0
    );
}

#[tokio::test]
async fn a_stream_at_the_limit() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::start(200, LMSTUDIO_STREAM, STREAM).await;
    let top: &'static str = format!("max_body_size = {}", STREAM.len()).leak();
    let proxy = Proxy::start(Setup::top(top), &upstream.url).await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), STREAM);
}

// ---------------------------------------------------------------------------
// Buffer mode scans the whole stream before the first byte
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_clean_stream_in_buffer_mode() {
    let _m = METRICS.lock().await;
    let mut steps: Vec<Step> = recorded_text_events().into_iter().map(Step::Send).collect();
    steps.push(Step::Wait(Duration::from_millis(300)));
    steps.push(Step::Send(DONE.to_string()));
    let upstream = Upstream::stream(steps, None).await;
    let setup = Setup {
        route: r#"stream = "buffer""#,
        ..Setup::default()
    };
    let proxy = Proxy::start(setup, &upstream.url).await;

    let started = Instant::now();
    let resp = proxy.post(&stream_request()).await;
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), STREAM);
}

#[tokio::test]
async fn a_detection_in_buffer_mode() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::sse(recorded_with(&[content(&format!(" {EMAIL}"))])).await;
    let setup = Setup {
        route: r#"stream = "buffer""#,
        ..Setup::default()
    };
    let proxy = Proxy::start(setup, &upstream.url).await;

    let body = assert_block(proxy.post(&stream_request()).await, &["EMAIL"]).await;
    assert!(
        !body.contains("chatcmpl"),
        "no body byte reached the client"
    );
}

// ---------------------------------------------------------------------------
// Startup warns about custom patterns without a bound
// ---------------------------------------------------------------------------

/// Load a config with a custom pattern without keywords and one openai-chat
/// route carrying `route`, and return it with what the load logged.
fn load_with_custom_pattern(upstream: &str, route: &str) -> (AppConfig, String) {
    use std::io::Write;
    use std::sync::Mutex as StdMutex;

    #[derive(Clone, Default)]
    struct Logs(Arc<StdMutex<Vec<u8>>>);
    impl Write for Logs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let toml = format!(
        r#"
[builtin_guards.pii]
scanner_threads = 1

[[builtin_guards.pii.custom]]
label = "TICKET_ID"
pattern = "TCK-[0-9]+"

[reverse_proxy]
enabled = true

[[reverse_proxy.routes]]
path_prefix = "{ROUTE}"
upstream = "{upstream}"
format = "openai-chat"
{route}
"#
    );
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(toml.as_bytes()).unwrap();

    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let config =
        tracing::subscriber::with_default(subscriber, || AppConfig::load(file.path()).unwrap());
    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    (config, logged)
}

#[tokio::test]
async fn a_custom_pattern_without_keywords() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let (config, logs) = load_with_custom_pattern(&upstream.url, "");

    let warnings: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("WARN") && l.contains("without keywords"))
        .collect();
    assert_eq!(warnings.len(), 1, "{logs}");
    assert!(
        warnings[0].contains("TICKET_ID") && warnings[0].contains(ROUTE),
        "{logs}"
    );

    // The proxy starts.
    let engine = Arc::new(Engine::from_config(&config).unwrap());
    let proxy = Proxy::start_with(config, engine).await;
    assert_eq!(proxy.post(&clean_request()).await.status(), 200);
}

#[tokio::test]
async fn buffer_mode_does_not_warn() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let (_, logs) = load_with_custom_pattern(&upstream.url, r#"stream = "buffer""#);

    assert!(!logs.contains("without keywords"), "{logs}");
}

// ---------------------------------------------------------------------------
// A response that is not JSON is unscannable
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// A compressed stream is unscannable content
// ---------------------------------------------------------------------------

/// A stream labelled `gzip` that holds [`EMAIL`]. The body is not really
/// compressed: the proxy must not read it either way.
async fn gzip_stream() -> (Upstream, String) {
    let body = recorded_with(&[content(&format!("Mail {EMAIL}"))]);
    let upstream = Upstream::stream(
        vec![Step::Send(body.clone())],
        Some(("content-encoding", "gzip")),
    )
    .await;
    (upstream, body)
}

#[tokio::test]
async fn a_compressed_stream_under_fail_close() {
    let _m = METRICS.lock().await;
    let (upstream, _) = gzip_stream().await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    // A 422 with the OpenAI error body: no byte of the upstream body.
    let error = openai_error(proxy.post(&stream_request()).await, 422).await;
    assert_eq!(error["code"], "unscannable_content");
}

#[tokio::test]
async fn a_compressed_stream_in_buffer_mode_under_fail_close() {
    let _m = METRICS.lock().await;
    let (upstream, _) = gzip_stream().await;
    let setup = Setup {
        route: "stream = \"buffer\"",
        ..Setup::default()
    };
    let proxy = Proxy::start(setup, &upstream.url).await;

    let error = openai_error(proxy.post(&stream_request()).await, 422).await;
    assert_eq!(error["code"], "unscannable_content");
}

#[tokio::test]
async fn a_compressed_stream_under_fail_open() {
    let _m = METRICS.lock().await;
    let (upstream, body) = gzip_stream().await;
    let proxy = Proxy::start(Setup::top(r#"on_error = "fail_open""#), &upstream.url).await;
    let before = proxy.errors("passed", "unscannable_content").await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.text().await.unwrap(),
        body,
        "the stream passes unscanned"
    );
    assert_eq!(
        proxy.errors("passed", "unscannable_content").await,
        before + 1.0
    );
}

const HTML: &str = "<html><body>502 Bad Gateway</body></html>";

#[tokio::test]
async fn an_html_error_page_under_fail_close() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::start(502, "text/html", HTML).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;
    let before = proxy.errors("blocked", "unscannable_content").await;

    let error = openai_error(proxy.post(&clean_request()).await, 422).await;
    assert_eq!(error["code"], "unscannable_content");
    assert_eq!(
        proxy.errors("blocked", "unscannable_content").await,
        before + 1.0
    );
}

#[tokio::test]
async fn an_html_error_page_under_fail_open() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::start(502, "text/html", HTML).await;
    let proxy = Proxy::start(Setup::top(r#"on_error = "fail_open""#), &upstream.url).await;

    let resp = proxy.post(&clean_request()).await;
    assert_eq!(resp.status(), 502);
    assert_eq!(resp.text().await.unwrap(), HTML);
}

// ---------------------------------------------------------------------------
// A detection answers 400 in the OpenAI error shape
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_kinds_in_a_request() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    let payload = request(|p| {
        message(p, "user")["content"][0]["text"] =
            json!(format!("My IBAN is {IBAN} and my email is {EMAIL}"));
    });
    let body = assert_block(proxy.post(&payload).await, &["EMAIL", "IBAN"]).await;
    let error = &serde_json::from_str::<Value>(&body).unwrap()["error"];
    assert_eq!(error["type"], "invalid_request_error");
    assert_eq!(error["param"], Value::Null);
    assert_eq!(error["message"], "content blocked. Kinds: EMAIL, IBAN");
    assert!(!body.contains(IBAN) && !body.contains(EMAIL), "{body}");
    assert_eq!(upstream.hits(), 0);
}

#[tokio::test]
async fn a_detection_in_the_response() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::json(200, RESPONSE, |r| {
        r["choices"][0]["message"]["content"] = json!(format!("Write to {EMAIL}"));
    })
    .await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;
    let before = proxy.stopped("response").await;

    assert_block(proxy.post(&clean_request()).await, &["EMAIL"]).await;
    assert_eq!(proxy.stopped("response").await, before + 1.0);
}

// ---------------------------------------------------------------------------
// Every other answer uses the OpenAI error shape
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_scanner_failure_under_fail_close() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start_broken(Setup::default(), &upstream.url).await;

    let error = openai_error(proxy.post(&clean_request()).await, 500).await;
    assert_eq!(
        error,
        json!({"message": "internal error", "type": "server_error", "param": null, "code": "internal_error"})
    );
}

#[tokio::test]
async fn the_upstream_cannot_be_reached() {
    let _m = METRICS.lock().await;
    let proxy = Proxy::start(Setup::default(), "http://127.0.0.1:9").await;

    let error = openai_error(proxy.post(&clean_request()).await, 502).await;
    assert_eq!(error["code"], "upstream_error");
}

#[tokio::test]
async fn the_upstream_times_out() {
    let _m = METRICS.lock().await;
    let upstream = silent_upstream().await;
    let proxy = Proxy::start(Setup::top("upstream_timeout_secs = 1"), &upstream).await;

    let error = openai_error(proxy.post(&clean_request()).await, 504).await;
    assert_eq!(error["code"], "upstream_timeout");
}

#[tokio::test]
async fn an_oversize_request_under_fail_close() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start(Setup::top("max_body_size = 64\nstream_holdback_bytes = 64\nstream_context_bytes = 64\nstream_scan_bytes = 64"), &upstream.url).await;

    let error = openai_error(proxy.post(&request(|_| {})).await, 413).await;
    assert_eq!(error["code"], "body_too_large");
    assert_eq!(upstream.hits(), 0);
}

#[tokio::test]
async fn an_upstream_error_is_forwarded() {
    let _m = METRICS.lock().await;
    let body = r#"{"error":{"message":"Rate limit reached","type":"requests","code":"rate_limit_exceeded"}}"#;
    let upstream = Upstream::start(429, LMSTUDIO_JSON, body).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    let resp = proxy.post(&clean_request()).await;
    assert_eq!(resp.status(), 429);
    assert_eq!(resp.text().await.unwrap(), body);
}

// ---------------------------------------------------------------------------
// The fixtures hold no PII
// ---------------------------------------------------------------------------

#[test_case(200, RESPONSE ; "plain answer")]
#[test_case(200, RESPONSE_TOOL_CALL ; "tool call")]
#[test_case(400, ERROR_FLAT ; "flat error")]
#[test_case(400, ERROR_OBJECT ; "error object")]
#[tokio::test]
async fn each_clean_fixture_is_forwarded(status: u16, response: &'static str) {
    let _m = METRICS.lock().await;
    let upstream = Upstream::start(status, LMSTUDIO_JSON, response).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;

    let resp = proxy.post(&request(|_| {})).await;
    assert_eq!(resp.status(), status);
    assert_eq!(resp.text().await.unwrap(), response);
    assert_eq!(upstream.hits(), 1);
}

// ---------------------------------------------------------------------------
// reverse-proxy and metrics deltas
// ---------------------------------------------------------------------------

/// metrics, "A detection blocks a request on an openai-chat route", and
/// reverse-proxy, "An openai-chat route blocks with 400".
#[tokio::test]
async fn a_detection_on_the_route_counts_the_block() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;
    let labels = [
        ("mode", "reverse_proxy"),
        ("route", ROUTE),
        ("direction", "request"),
    ];
    let before = (
        proxy.metric("voidwall_blocked_total", &labels).await,
        proxy.metric("voidwall_pii_blocked_total", &labels).await,
    );

    let payload = request(|p| message(p, "user")["content"][0]["text"] = json!(EMAIL));
    assert_block(proxy.post(&payload).await, &["EMAIL"]).await;
    assert_eq!(upstream.hits(), 0);

    let after = (
        proxy.metric("voidwall_blocked_total", &labels).await,
        proxy.metric("voidwall_pii_blocked_total", &labels).await,
    );
    assert_eq!(after, (before.0 + 1.0, before.1 + 1.0));
}

/// metrics, "A stream passes under fail_open", and "A clean stream".
#[tokio::test]
async fn a_clean_stream_under_fail_open_counts_nothing() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::start(200, LMSTUDIO_STREAM, STREAM).await;
    let proxy = Proxy::start(Setup::top(r#"on_error = "fail_open""#), &upstream.url).await;
    let before = (proxy.stopped("response").await, proxy.all_cuts().await);

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), STREAM);
    for outcome in ["passed", "blocked"] {
        assert_eq!(proxy.errors(outcome, "unscannable_stream").await, 0.0);
    }
    assert_eq!(
        (proxy.stopped("response").await, proxy.all_cuts().await),
        before
    );
}

/// reverse-proxy, "A stream outlives the upstream timeout".
#[tokio::test]
async fn a_stream_outlives_the_upstream_timeout() {
    let _m = METRICS.lock().await;
    let mut steps = Vec::new();
    for event in recorded_text_events().into_iter().take(4) {
        steps.push(Step::Send(event));
        steps.push(Step::Wait(Duration::from_millis(450)));
    }
    steps.push(Step::Send(recorded_events()[4..].concat()));
    let upstream = Upstream::stream(steps, None).await;
    let proxy = Proxy::start(Setup::top("upstream_timeout_secs = 1"), &upstream.url).await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), STREAM);
}

/// metrics, "An unparseable body under fail_close", on the route: a response
/// that declares JSON and does not parse follows the generic rule.
#[tokio::test]
async fn an_unparseable_json_response_under_fail_close() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::start(200, LMSTUDIO_JSON, "{not json").await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;
    let before = proxy.stopped("response").await;

    let error = openai_error(proxy.post(&clean_request()).await, 400).await;
    assert_eq!(error["code"], "malformed_body");
    assert_eq!(proxy.stopped("response").await, before + 1.0);
}

/// reverse-proxy, "A guard fails and another guard detects on an openai-chat
/// route". A model guard fails on any unit holding the trigger word; its
/// fixture's trigger embedding row is NaN.
#[tokio::test]
async fn a_guard_fails_and_another_guard_detects() {
    let _m = METRICS.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let fixture_model = Fixture {
        nan_row: Some(TRIGGER_ID),
        ..Fixture::default()
    };
    let guards = format!(
        r#"{PII}
[guards.injection]
adapter = "text_classifier"
model_path = "{model}"
tokenizer_path = "{tokenizer}"
max_tokens = 16
labels = ["PROMPT_INJECTION"]
threads = 1

[guards.injection.thresholds]
PROMPT_INJECTION = 0.90
"#,
        model = fixture_model.write(dir.path()).display(),
        tokenizer = TokenizerFixture::default().write(dir.path()).display(),
    );
    let upstream = Upstream::clean().await;
    let proxy = Proxy::start_owning(Setup::default(), &upstream.url, &guards).await;

    // The trigger alone: the model guard fails and nothing detects, so
    // fail_close answers 500. This shows the failure the block must beat.
    let mut payload = clean_request();
    payload["messages"][0]["content"] = json!(TRIGGER);
    let error = openai_error(proxy.post(&payload).await, 500).await;
    assert_eq!(error["code"], "internal_error");

    let mut payload = clean_request();
    payload["messages"][0]["content"] = json!(format!("{TRIGGER} {EMAIL}"));
    assert_block(proxy.post(&payload).await, &["EMAIL"]).await;
}
