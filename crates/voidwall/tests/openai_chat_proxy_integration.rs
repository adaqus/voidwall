//! A reverse proxy route with `format = "openai-chat"` end to end: a real
//! reverse proxy and a real admin server in front of a stub upstream that
//! answers JSON, `text/event-stream`, or `text/html`.
//!
//! One test per scenario of `specs/openai-chat-proxy/spec.md`, then the
//! scenarios of the `reverse-proxy` and `metrics` deltas it does not cover.
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

use axum::Router;
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
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

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
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
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            top: "",
            request_scan: true,
            response_scan: true,
            openai_chat: true,
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
             [[reverse_proxy.routes]]\npath_prefix = \"{ROUTE}\"\nupstream = \"{upstream}\"\n{format}\n",
            top = self.top,
            request = self.request_scan,
            response = self.response_scan,
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
// A stream is unscannable
// ---------------------------------------------------------------------------

fn stream_request() -> Value {
    let mut payload = clean_request();
    payload["stream"] = json!(true);
    payload
}

#[tokio::test]
async fn stream_true_under_fail_close() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::start(200, LMSTUDIO_STREAM, STREAM).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;
    let before = proxy.errors("blocked", "unscannable_stream").await;

    let error = openai_error(proxy.post(&stream_request()).await, 422).await;
    assert_eq!(error["code"], "unscannable_content");
    assert_eq!(upstream.hits(), 0);
    assert_eq!(
        proxy.errors("blocked", "unscannable_stream").await,
        before + 1.0
    );
}

#[tokio::test]
async fn stream_true_under_fail_open() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::start(200, LMSTUDIO_STREAM, STREAM).await;
    let proxy = Proxy::start(Setup::top(r#"on_error = "fail_open""#), &upstream.url).await;
    let before = proxy.errors("passed", "unscannable_stream").await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], LMSTUDIO_STREAM);
    assert_eq!(resp.text().await.unwrap(), STREAM);
    assert_eq!(
        proxy.errors("passed", "unscannable_stream").await,
        before + 1.0,
        "the message counts once"
    );
}

#[tokio::test]
async fn a_stream_with_request_scan_off() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::start(200, LMSTUDIO_STREAM, STREAM).await;
    let setup = Setup {
        request_scan: false,
        ..Setup::default()
    };
    let proxy = Proxy::start(setup, &upstream.url).await;

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 422);
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("chatcmpl"),
        "a part of the stream reached the client"
    );
}

#[tokio::test]
async fn a_stream_with_response_scan_off() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::start(200, LMSTUDIO_STREAM, STREAM).await;
    let setup = Setup {
        response_scan: false,
        ..Setup::default()
    };
    let proxy = Proxy::start(setup, &upstream.url).await;
    let before = (
        proxy.errors("passed", "unscannable_stream").await,
        proxy.errors("blocked", "unscannable_stream").await,
    );

    let resp = proxy.post(&stream_request()).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), STREAM);
    let after = (
        proxy.errors("passed", "unscannable_stream").await,
        proxy.errors("blocked", "unscannable_stream").await,
    );
    assert_eq!(after, before);
}

// ---------------------------------------------------------------------------
// A response that is not JSON is unscannable
// ---------------------------------------------------------------------------

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
    let proxy = Proxy::start(Setup::top("max_body_size = 64"), &upstream.url).await;

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

/// metrics, "A stream under fail_close".
#[tokio::test]
async fn a_stream_under_fail_close_counts_the_block() {
    let _m = METRICS.lock().await;
    let upstream = Upstream::start(200, LMSTUDIO_STREAM, STREAM).await;
    let proxy = Proxy::start(Setup::default(), &upstream.url).await;
    let before = proxy.stopped("request").await;

    assert_eq!(proxy.post(&stream_request()).await.status(), 422);
    assert_eq!(proxy.stopped("request").await, before + 1.0);
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
