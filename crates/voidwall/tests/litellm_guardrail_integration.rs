//! The LiteLLM Generic Guardrail API route end to end: a real HTTP API server
//! and a real admin server, posted the payloads LiteLLM v1.105.1 sends.
//!
//! One test per scenario of `specs/litellm-guardrail-api/spec.md`. Metrics are
//! read from the admin `/metrics` endpoint. The metric families are shared by
//! every test in this binary, so a test that asserts an exact change holds
//! [`METRICS`] and every other test that can move the same sample holds it too.

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use serde_json::{Value, json};
use test_case::test_case;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use voidwall::admin::{self, AdminState};
use voidwall::config::AppConfig;
use voidwall::engine::Engine;
use voidwall::http_api;
use voidwall_ml::fixtures::{Fixture, TRIGGER, TRIGGER_ID, TokenizerFixture, runtime};

const ROUTE: &str = "/beta/litellm_basic_guardrail_api";

const REQUEST_TOOLS: &str = include_str!("fixtures/litellm/v1.105.1-request-tools.json");
const RESPONSE: &str = include_str!("fixtures/litellm/v1.105.1-response.json");
const REQUEST_INLINE_IMAGE: &str =
    include_str!("fixtures/litellm/v1.105.1-request-inline-image.json");

const EMAIL: &str = "jane.doe@example.com";
const IBAN: &str = "GB82WEST12345698765432";

/// Serialises the tests that assert an exact change of a shared sample.
static METRICS: Mutex<()> = Mutex::const_new(());

// ---------------------------------------------------------------------------
// Servers
// ---------------------------------------------------------------------------

const PII: &str = "[builtin_guards.pii]\nscanner_threads = 1\n";

static SHARED_ENGINE: LazyLock<Arc<Engine>> =
    LazyLock::new(|| Arc::new(Engine::from_config(runtime(), &config("", "")).unwrap()));

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

/// A validated config: the PII guard (or `guards`), the HTTP API, and `extra`
/// top-level keys and tables. The listen addresses are set by [`Server`].
fn config(guards: &str, extra: &str) -> AppConfig {
    let guards = if guards.is_empty() { PII } else { guards };
    let toml = format!("{extra}\n{guards}\n[http_api]\nenabled = true\n");
    let config: AppConfig = toml::from_str(&toml).unwrap();
    config.validate().unwrap();
    config
}

struct Server {
    api: SocketAddr,
    admin: SocketAddr,
    cancel: CancellationToken,
}

impl Server {
    /// The PII guard on the shared engine, with `extra` config.
    async fn start(extra: &str) -> Self {
        Self::start_with(config("", extra), SHARED_ENGINE.clone()).await
    }

    /// An engine of its own, built from `guards` and `extra`.
    async fn start_owning(guards: &str, extra: &str) -> Self {
        let config = config(guards, extra);
        let engine = Arc::new(Engine::from_config(runtime(), &config).unwrap());
        Self::start_with(config, engine).await
    }

    /// A PII guard whose pool owns no scanner threads, so every submit
    /// fails. Validation rejects that value, so it is set after validation.
    async fn start_broken(extra: &str) -> Self {
        let mut config = config("", extra);
        config.builtin_guards.pii.as_mut().unwrap().scanner_threads = Some(0);
        let engine = Arc::new(Engine::from_config(runtime(), &config).unwrap());
        Self::start_with(config, engine).await
    }

    async fn start_with(mut config: AppConfig, engine: Arc<Engine>) -> Self {
        let (api, admin) = (free_addr().await, free_addr().await);
        config.http_api.listen = api.to_string();
        config.admin.listen = admin.to_string();
        let cancel = CancellationToken::new();

        let (api_cancel, admin_cancel) = (cancel.clone(), cancel.clone());
        let admin_config = config.admin.clone();
        tokio::spawn(async move {
            http_api::serve(&config, engine, api_cancel).await.unwrap();
        });
        tokio::spawn(async move {
            let state = AdminState {
                ready: Arc::new(true.into()),
            };
            admin::serve(&admin_config, state, admin_cancel)
                .await
                .unwrap();
        });
        wait_for_port(api).await;
        wait_for_port(admin).await;
        Server { api, admin, cancel }
    }

    async fn post(
        &self,
        path: &str,
        content_type: &str,
        body: impl Into<reqwest::Body>,
    ) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("http://{}{path}", self.api))
            .header("content-type", content_type)
            .body(body)
            .send()
            .await
            .unwrap()
    }

    async fn post_litellm(&self, payload: &Value) -> reqwest::Response {
        self.post(ROUTE, "application/json", payload.to_string())
            .await
    }

    /// The answer to `payload` as JSON, asserting a 200.
    async fn verdict(&self, payload: &Value) -> Value {
        let resp = self.post_litellm(payload).await;
        assert_eq!(resp.status(), 200);
        resp.json().await.unwrap()
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
}

impl Drop for Server {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

fn fixture(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap()
}

/// The request fixture with `edit` applied.
fn request(edit: impl FnOnce(&mut Value)) -> Value {
    let mut payload = fixture(REQUEST_TOOLS);
    edit(&mut payload);
    payload
}

fn message<'a>(payload: &'a mut Value, role: &str) -> &'a mut Value {
    payload["structured_messages"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|m| m["role"] == role)
        .unwrap()
}

fn blocked(kinds: &str) -> Value {
    json!({
        "action": "BLOCKED",
        "blocked_reason": format!("Voidwall blocked the message. Kinds: {kinds}"),
    })
}

fn none() -> Value {
    json!({"action": "NONE"})
}

// ---------------------------------------------------------------------------
// The route is served
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_route_is_on() {
    let server = Server::start("").await;
    assert_eq!(server.verdict(&fixture(REQUEST_TOOLS)).await, none());
}

#[tokio::test]
async fn the_route_is_off() {
    let server = Server::start("[http_api.litellm]\nenabled = false\n").await;
    let resp = server.post_litellm(&fixture(REQUEST_TOOLS)).await;
    assert_eq!(resp.status(), 404);
    let scan = server.post("/v1/scan", "text/plain", "hello").await;
    assert_eq!(scan.status(), 200);
}

#[tokio::test]
async fn the_route_without_v1_scan() {
    let server = Server::start("[http_api.scan]\nenabled = false\n").await;
    assert_eq!(server.verdict(&fixture(REQUEST_TOOLS)).await, none());
    let scan = server.post("/v1/scan", "text/plain", "hello").await;
    assert_eq!(scan.status(), 404);
}

// ---------------------------------------------------------------------------
// A JSON body within max_body_size
// ---------------------------------------------------------------------------

#[tokio::test]
async fn json_is_admitted_although_content_types_omits_it() {
    let server = Server::start(r#"content_types = ["text/plain"]"#).await;
    let payload = request(|p| message(p, "user")["content"] = json!(EMAIL));
    assert_eq!(server.verdict(&payload).await, blocked("EMAIL"));
}

#[tokio::test]
async fn another_content_type_answers_415() {
    let server = Server::start("").await;
    let resp = server.post(ROUTE, "text/plain", REQUEST_TOOLS).await;
    assert_eq!(resp.status(), 415);
    assert_eq!(
        resp.text().await.unwrap(),
        r#"{"error":"unsupported content type"}"#
    );
}

#[tokio::test]
async fn an_oversize_body_answers_as_v1_scan_does() {
    let server = Server::start("max_body_size = 64\nstream_holdback_bytes = 64\nstream_context_bytes = 64\nstream_scan_bytes = 64").await;
    let litellm = server.post_litellm(&fixture(REQUEST_TOOLS)).await;
    let scan = server
        .post("/v1/scan", "application/json", REQUEST_TOOLS)
        .await;
    assert_eq!(litellm.status(), 413);
    assert_eq!(scan.status(), 413);
    assert_eq!(litellm.text().await.unwrap(), scan.text().await.unwrap());
}

// ---------------------------------------------------------------------------
// A malformed payload
// ---------------------------------------------------------------------------

#[test_case("fail_open" ; "fail open")]
#[test_case("fail_close" ; "fail close")]
#[tokio::test]
async fn a_body_that_is_not_json_answers_400(on_error: &str) {
    let server = Server::start(&format!("on_error = \"{on_error}\"")).await;
    let resp = server.post(ROUTE, "application/json", "{not json").await;
    assert_eq!(resp.status(), 400);
    assert_eq!(
        resp.text().await.unwrap(),
        r#"{"error":"malformed body for declared content type"}"#
    );
}

#[tokio::test]
async fn a_payload_without_input_type_answers_400() {
    let server = Server::start("").await;
    let payload = request(|p| {
        p.as_object_mut().unwrap().remove("input_type");
    });
    assert_eq!(server.post_litellm(&payload).await.status(), 400);
}

#[tokio::test]
async fn an_unknown_top_level_field_is_not_scanned() {
    let server = Server::start("").await;
    let payload = request(|p| p["future_field"] = json!(EMAIL));
    assert_eq!(server.verdict(&payload).await, none());
}

// ---------------------------------------------------------------------------
// The request side
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_system_message() {
    let server = Server::start("").await;
    let payload =
        request(|p| message(p, "system")["content"] = json!(format!("Escalate to {EMAIL}")));
    assert_eq!(server.verdict(&payload).await, blocked("EMAIL"));
}

#[tokio::test]
async fn a_tool_message() {
    let server = Server::start("").await;
    let payload = request(|p| {
        message(p, "tool")["content"] = json!(format!("{{\"customer_email\": \"{EMAIL}\"}}"))
    });
    assert_eq!(server.verdict(&payload).await, blocked("EMAIL"));
}

#[tokio::test]
async fn tool_call_arguments_in_a_replayed_assistant_message() {
    let server = Server::start("").await;
    let payload = request(|p| {
        // Only the message carries it: the top-level copy LiteLLM sends is
        // removed, so the finding can come from the message alone.
        p.as_object_mut().unwrap().remove("tool_calls");
        message(p, "assistant")["tool_calls"][0]["function"]["arguments"] =
            json!(format!("{{\"email\": \"{EMAIL}\"}}"));
    });
    assert_eq!(server.verdict(&payload).await, blocked("EMAIL"));
}

#[tokio::test]
async fn a_tool_description() {
    let server = Server::start("").await;
    let payload = request(|p| {
        p["tools"][0]["function"]["description"] = json!(format!("Mail results to {EMAIL}."))
    });
    assert_eq!(server.verdict(&payload).await, blocked("EMAIL"));
}

#[tokio::test]
async fn a_built_in_tool_with_only_a_type() {
    let server = Server::start("").await;
    let payload = request(|p| p["tools"] = json!([{"type": "code_interpreter"}]));
    assert_eq!(server.verdict(&payload).await, none());
}

#[tokio::test]
async fn texts_is_ignored_when_structured_messages_exist() {
    let server = Server::start("").await;
    let payload = request(|p| p["texts"] = json!([EMAIL]));
    assert_eq!(server.verdict(&payload).await, none());
}

#[tokio::test]
async fn texts_is_the_fallback() {
    let server = Server::start("").await;
    let payload = request(|p| {
        p["structured_messages"] = Value::Null;
        p["texts"] = json!([format!("Write to {EMAIL}")]);
    });
    assert_eq!(server.verdict(&payload).await, blocked("EMAIL"));
}

// ---------------------------------------------------------------------------
// The response side
// ---------------------------------------------------------------------------

#[tokio::test]
async fn model_output() {
    let server = Server::start("").await;
    let mut payload = fixture(RESPONSE);
    payload["texts"] = json!([format!("Contact {EMAIL} for help.")]);
    assert_eq!(server.verdict(&payload).await, blocked("EMAIL"));
}

#[tokio::test]
async fn a_model_tool_call() {
    let server = Server::start("").await;
    let mut payload = fixture(RESPONSE);
    payload["tool_calls"][0]["function"]["arguments"] =
        json!(format!("{{\"email\": \"{EMAIL}\"}}"));
    assert_eq!(server.verdict(&payload).await, blocked("EMAIL"));
}

#[tokio::test]
async fn the_response_fixture_is_clean() {
    let server = Server::start("").await;
    assert_eq!(server.verdict(&fixture(RESPONSE)).await, none());
}

// ---------------------------------------------------------------------------
// A custom definition fires in both directions
// ---------------------------------------------------------------------------

const CUSTOM: &str = r#"
[builtin_guards.pii]
scanner_threads = 1

[[builtin_guards.pii.custom]]
label = "EMPLOYEE_ID"
pattern = "EMP-[0-9]{6}"
"#;

#[tokio::test]
async fn a_custom_definition_in_a_system_message() {
    let server = Server::start_owning(CUSTOM, "").await;
    let payload =
        request(|p| message(p, "system")["content"] = json!("Staff EMP-123456 may refund"));
    assert_eq!(server.verdict(&payload).await, blocked("EMPLOYEE_ID"));
}

#[tokio::test]
async fn a_custom_definition_in_model_output() {
    let server = Server::start_owning(CUSTOM, "").await;
    let mut payload = fixture(RESPONSE);
    payload["texts"] = json!(["Ask EMP-123456 for a refund"]);
    assert_eq!(server.verdict(&payload).await, blocked("EMPLOYEE_ID"));
}

// ---------------------------------------------------------------------------
// Caller identity and headers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_callers_email_in_request_data() {
    let server = Server::start("").await;
    let payload = request(|p| {
        p["request_data"]["user_api_key_user_email"] = json!(EMAIL);
        p["request_headers"]["x-user-email"] = json!(EMAIL);
    });
    assert_eq!(server.verdict(&payload).await, none());
}

// ---------------------------------------------------------------------------
// An unknown field or role
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unknown_field_on_an_assistant_message() {
    let server = Server::start("").await;
    let payload = request(|p| {
        message(p, "assistant")["reasoning_content"] = json!(format!("The user is {EMAIL}."))
    });
    assert_eq!(server.verdict(&payload).await, blocked("EMAIL"));
}

#[tokio::test]
async fn an_unknown_role() {
    let server = Server::start("").await;
    let payload = request(|p| {
        p["structured_messages"]
            .as_array_mut()
            .unwrap()
            .push(json!({"role": "narrator", "content": format!("Reach me at {EMAIL}")}));
    });
    assert_eq!(server.verdict(&payload).await, blocked("EMAIL"));
}

// ---------------------------------------------------------------------------
// An unknown content part type
// ---------------------------------------------------------------------------

fn hologram_request() -> Value {
    request(|p| {
        message(p, "user")["content"] = json!([
            {"type": "hologram", "hologram": {"frames": 3}},
            {"type": "text", "text": format!("I am {EMAIL}")},
        ]);
    })
}

fn unscannable(outcome: &str) -> [(&'static str, &str); 2] {
    [("outcome", outcome), ("reason", "unscannable_content")]
}

#[tokio::test]
async fn an_unknown_part_under_fail_close() {
    let server = Server::start(r#"on_error = "fail_close""#).await;
    let before = server
        .metric("voidwall_errors_total", &unscannable("blocked"))
        .await;

    let resp = server.post_litellm(&hologram_request()).await;

    assert_eq!(resp.status(), 422);
    assert_eq!(
        resp.text().await.unwrap(),
        r#"{"error":"unscannable content"}"#
    );
    let after = server
        .metric("voidwall_errors_total", &unscannable("blocked"))
        .await;
    assert!(after > before, "{before} -> {after}");
}

#[tokio::test]
async fn an_unknown_part_under_fail_open() {
    let server = Server::start(r#"on_error = "fail_open""#).await;
    let before = server
        .metric("voidwall_errors_total", &unscannable("passed"))
        .await;

    assert_eq!(server.verdict(&hologram_request()).await, blocked("EMAIL"));

    let after = server
        .metric("voidwall_errors_total", &unscannable("passed"))
        .await;
    assert!(after > before, "{before} -> {after}");
}

// ---------------------------------------------------------------------------
// Encoded data
// ---------------------------------------------------------------------------

const ENCODED_REQUEST: [(&str, &str); 4] = [
    ("mode", "http_api"),
    ("route", "global"),
    ("direction", "request"),
    ("reason", "encoded_data"),
];

/// The unscanned count's change while `payload` is answered `expected`.
async fn unscanned_delta(payload: &Value, expected: Value) -> f64 {
    let _lock = METRICS.lock().await;
    let server = Server::start("").await;
    let before = server
        .metric("voidwall_unscanned_total", &ENCODED_REQUEST)
        .await;
    assert_eq!(server.verdict(payload).await, expected);
    server
        .metric("voidwall_unscanned_total", &ENCODED_REQUEST)
        .await
        - before
}

#[tokio::test]
async fn an_inline_image() {
    let delta = unscanned_delta(&fixture(REQUEST_INLINE_IMAGE), none()).await;
    assert_eq!(delta, 1.0);
}

#[tokio::test]
async fn an_image_url() {
    let mut payload = fixture(REQUEST_INLINE_IMAGE);
    let url = "https://example.com/pixel.png";
    payload["structured_messages"][0]["content"][1]["image_url"]["url"] = json!(url);
    payload["images"] = json!([url]);
    assert_eq!(unscanned_delta(&payload, none()).await, 0.0);
}

#[tokio::test]
async fn images_without_structured_messages() {
    let mut payload = fixture(REQUEST_INLINE_IMAGE);
    payload["structured_messages"] = Value::Null;
    payload["images"]
        .as_array_mut()
        .unwrap()
        .push(json!("https://example.com/pixel.png"));
    assert_eq!(unscanned_delta(&payload, none()).await, 1.0);
}

/// metrics, "Two inline images".
#[tokio::test]
async fn two_inline_images() {
    let mut payload = fixture(REQUEST_INLINE_IMAGE);
    let content = payload["structured_messages"][0]["content"]
        .as_array_mut()
        .unwrap();
    content.push(content[1].clone());
    assert_eq!(unscanned_delta(&payload, none()).await, 2.0);
}

/// metrics, "Nothing is skipped".
#[tokio::test]
async fn nothing_is_skipped() {
    assert_eq!(unscanned_delta(&fixture(REQUEST_TOOLS), none()).await, 0.0);
}

// ---------------------------------------------------------------------------
// NONE or BLOCKED
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_clean_payload() {
    let server = Server::start("").await;
    let resp = server.post_litellm(&fixture(REQUEST_TOOLS)).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), r#"{"action":"NONE"}"#);
}

#[tokio::test]
async fn two_kinds() {
    let server = Server::start("").await;
    let payload = request(|p| {
        message(p, "user")["content"] = json!(format!("My IBAN is {IBAN} and my email is {EMAIL}"))
    });
    let resp = server.post_litellm(&payload).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(!body.contains(IBAN) && !body.contains(EMAIL), "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        blocked("EMAIL, IBAN")
    );
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_scanner_failure_under_fail_close() {
    let server = Server::start_broken(r#"on_error = "fail_close""#).await;
    let resp = server.post_litellm(&fixture(REQUEST_TOOLS)).await;
    assert_eq!(resp.status(), 500);
    assert_eq!(resp.text().await.unwrap(), r#"{"error":"internal error"}"#);
}

#[tokio::test]
async fn a_scanner_failure_under_fail_open_with_no_finding() {
    let server = Server::start_broken(r#"on_error = "fail_open""#).await;
    let payload = request(|p| message(p, "user")["content"] = json!(EMAIL));
    assert_eq!(server.verdict(&payload).await, none());
}

/// A model guard that fails on any unit holding the trigger word, next to the
/// PII guard. The fixture's trigger embedding row is NaN.
#[tokio::test]
async fn a_scanner_failure_under_fail_open_with_a_finding() {
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
    let server = Server::start_owning(&guards, r#"on_error = "fail_open""#).await;
    let failures = [("outcome", "passed"), ("reason", "inference_failure")];
    let before = server.metric("voidwall_errors_total", &failures).await;

    let payload = request(|p| message(p, "user")["content"] = json!(format!("{TRIGGER} {EMAIL}")));
    assert_eq!(server.verdict(&payload).await, blocked("EMAIL"));

    let after = server.metric("voidwall_errors_total", &failures).await;
    assert!(
        after > before,
        "the model guard must have failed: {before} -> {after}"
    );
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_detection_on_the_response_side() {
    let server = Server::start("").await;
    let labels = [
        ("guard", "pii"),
        ("mode", "http_api"),
        ("route", "global"),
        ("direction", "response"),
    ];
    let before = server.metric("voidwall_detections_total", &labels).await;

    let mut payload = fixture(RESPONSE);
    payload["texts"] = json!([format!("Contact {EMAIL}")]);
    assert_eq!(server.verdict(&payload).await, blocked("EMAIL"));

    let after = server.metric("voidwall_detections_total", &labels).await;
    assert!(after > before, "{before} -> {after}");
}

#[tokio::test]
async fn blocked_is_not_a_block_count() {
    let server = Server::start("").await;
    let labels = [("mode", "http_api")];
    let payload = request(|p| message(p, "user")["content"] = json!(EMAIL));

    assert_eq!(server.verdict(&payload).await, blocked("EMAIL"));

    // Nothing on the HTTP API ever counts a block, so any sample is wrong.
    assert_eq!(server.metric("voidwall_blocked_total", &labels).await, 0.0);
    assert_eq!(
        server.metric("voidwall_pii_blocked_total", &labels).await,
        0.0
    );
}
