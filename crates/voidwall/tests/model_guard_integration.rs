//! A model guard end to end: the real binary loads a fixture model at startup,
//! and its findings block on the reverse proxy and report on `/v1/scan`.
//!
//! The fixture is a tiny bag-of-embeddings classifier from `voidwall-ml`'s
//! `test-fixtures` feature. Every text scores 0.27 except one holding the word
//! `trigger`, which scores 1.0.
//! The token fixture drops the sum over tokens, so it labels each token: the
//! word `trigger` as label 1, every other word as label 0.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::any;
use http_body_util::BodyExt;
use tempfile::{NamedTempFile, TempDir};
use tokio::net::TcpListener;
use voidwall_ml::fixtures::{
    Fixture, TRIGGER_ID, TokenizerFixture, write_config as write_model_config,
};

const BIN: &str = env!("CARGO_BIN_EXE_voidwall");

/// An upstream that echoes the body and counts the requests that reach it.
async fn start_counting_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/{*rest}", any(echo))
        .with_state(Arc::clone(&hits));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, hits)
}

async fn echo(State(hits): State<Arc<AtomicUsize>>, req: Request) -> impl IntoResponse {
    hits.fetch_add(1, Ordering::SeqCst);
    let body = req.into_body().collect().await.unwrap().to_bytes();
    (StatusCode::OK, [("content-type", "text/plain")], body)
}

/// A port picked by binding port 0 and releasing it. Another test can take it
/// before the binary binds it; `start_with_env` handles that.
async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

/// The running binary. Its stdout and stderr are read while it runs, so a test
/// can wait for a line it logs. Killed when dropped.
struct Proxy {
    child: Option<Child>,
    logs: Arc<Mutex<String>>,
    readers: Vec<JoinHandle<()>>,
}

impl Proxy {
    fn spawn(config: &Path) -> Self {
        Self::spawn_with_env(config, &[])
    }

    fn spawn_with_env(config: &Path, env: &[(&str, &str)]) -> Self {
        let mut child = Command::new(BIN)
            .arg("--config")
            .arg(config)
            .env_remove("VOIDWALL_CONFIG")
            .envs(env.iter().copied())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn voidwall");
        let logs = Arc::new(Mutex::new(String::new()));
        let readers = vec![
            read_into(child.stdout.take().unwrap(), Arc::clone(&logs)),
            read_into(child.stderr.take().unwrap(), Arc::clone(&logs)),
        ];
        Self {
            child: Some(child),
            logs,
            readers,
        }
    }

    /// What the process has logged so far.
    fn logs(&self) -> String {
        self.logs.lock().unwrap().clone()
    }

    /// Wait until the process exits by itself, and return its status and logs.
    async fn wait_for_exit(mut self) -> (ExitStatus, String) {
        for _ in 0..200 {
            if let Some(status) = self.try_wait() {
                return (status, self.stop());
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("voidwall must exit by itself");
    }

    fn try_wait(&mut self) -> Option<ExitStatus> {
        let child = self.child.as_mut().unwrap();
        child.try_wait().expect("poll voidwall")
    }

    /// Stop the process and return everything it logged.
    fn stop(&mut self) -> String {
        let mut child = self.child.take().unwrap();
        let _ = child.kill();
        child.wait().expect("wait for voidwall");
        for reader in std::mem::take(&mut self.readers) {
            reader.join().expect("log reader");
        }
        self.logs()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Appends each line of `pipe` to `logs` until the pipe closes. A line that is
/// not UTF-8 is kept lossily, so the reader never stops early and fills the pipe.
fn read_into(pipe: impl Read + Send + 'static, logs: Arc<Mutex<String>>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        let mut line = Vec::new();
        while reader.read_until(b'\n', &mut line).is_ok_and(|n| n > 0) {
            logs.lock()
                .unwrap()
                .push_str(&String::from_utf8_lossy(&line));
            line.clear();
        }
    })
}

/// The line each listener logs once it is bound.
const LISTENERS: [&str; 3] = [
    "reverse proxy started",
    "HTTP API started",
    "admin server started",
];

/// A fixture model and tokenizer on disk.
struct Artifacts {
    model: PathBuf,
    tokenizer: PathBuf,
    _dir: TempDir,
}

fn artifacts(fixture: Fixture, tokenizer: TokenizerFixture) -> Artifacts {
    let dir = tempfile::tempdir().unwrap();
    Artifacts {
        model: fixture.write(dir.path()),
        tokenizer: tokenizer.write(dir.path()),
        _dir: dir,
    }
}

fn trigger_artifacts() -> Artifacts {
    artifacts(
        Fixture {
            trigger: true,
            ..Fixture::default()
        },
        TokenizerFixture::default(),
    )
}

/// One `[guards.injection]` section over `artifacts`, with `extra` keys.
fn guard_section(artifacts: &Artifacts, extra: &str) -> String {
    format!(
        r#"
[guards.injection]
adapter = "text_classifier"
model_path = "{model}"
tokenizer_path = "{tokenizer}"
max_tokens = 16
labels = ["PROMPT_INJECTION"]
{extra}

[guards.injection.thresholds]
PROMPT_INJECTION = 0.90
"#,
        model = artifacts.model.display(),
        tokenizer = artifacts.tokenizer.display(),
    )
}

fn write_config(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

/// A started binary and what the tests read from it.
struct Running {
    proxy_addr: SocketAddr,
    api_addr: SocketAddr,
    admin_addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    proxy: Proxy,
    _config: NamedTempFile,
}

/// Start the binary with `guards` in front of a counting upstream, the
/// reverse proxy route carrying `route_extra`, and the REST API.
///
/// A port from `free_addr` can be lost to another test before the binary
/// binds it. A connect cannot tell the binary from the listener that took its
/// port, so readiness is the binary's own log line for each listener. A start
/// that lost a port exits and logs `Address already in use`, so it is repeated
/// on new ports. Any other exit fails the test.
async fn start(guards: &str, route_extra: &str, top: &str) -> Running {
    start_with_env(guards, route_extra, top, &[]).await
}

/// [`start`], with `env` set for the binary.
async fn start_with_env(
    guards: &str,
    route_extra: &str,
    top: &str,
    env: &[(&str, &str)],
) -> Running {
    let (upstream, hits) = start_counting_upstream().await;
    for _ in 0..5 {
        let proxy_addr = free_addr().await;
        let api_addr = free_addr().await;
        let admin_addr = free_addr().await;
        let config = write_config(&format!(
            r#"
{top}
{guards}

[reverse_proxy]
enabled = true
listen = "{proxy_addr}"

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://{upstream}"
{route_extra}

[http_api]
enabled = true
listen = "{api_addr}"

[admin]
listen = "{admin_addr}"
"#
        ));

        let mut proxy = Proxy::spawn_with_env(config.path(), env);
        // The PII guard compiles its databases before the data plane binds,
        // so a start can take seconds.
        let mut exit = None;
        for _ in 0..1200 {
            let logs = proxy.logs();
            if LISTENERS.iter().all(|started| logs.contains(started)) {
                return Running {
                    proxy_addr,
                    api_addr,
                    admin_addr,
                    hits,
                    proxy,
                    _config: config,
                };
            }
            exit = proxy.try_wait();
            if exit.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let logs = proxy.stop();
        let Some(status) = exit else {
            panic!("voidwall did not bind every listener: {logs}");
        };
        assert!(
            logs.contains("Address already in use"),
            "voidwall exited with {status} before it bound: {logs}"
        );
    }
    panic!("voidwall lost a port on every attempt");
}

async fn post(addr: SocketAddr, path: &str, body: impl Into<reqwest::Body>) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .header("content-type", "text/plain")
        .body(body)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn the_model_guard_blocks_on_the_proxy_and_reports_on_the_api() {
    let artifacts = trigger_artifacts();
    let server = start(&guard_section(&artifacts, "threads = 1"), "", "").await;

    // A request the model scores above the threshold is blocked with the
    // fixed 403 and never reaches the upstream.
    let resp = post(server.proxy_addr, "/chat", "voidwall trigger test").await;
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "content blocked");
    assert_eq!(body["kinds"], serde_json::json!(["PROMPT_INJECTION"]));
    assert_eq!(server.hits.load(Ordering::SeqCst), 0);

    // A clean request is forwarded unchanged.
    let resp = post(server.proxy_addr, "/chat", "voidwall smoke test").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "voidwall smoke test");
    assert_eq!(server.hits.load(Ordering::SeqCst), 1);

    // The API reports the finding as one match.
    let resp = post(server.api_addr, "/v1/scan", "voidwall trigger test").await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["detected"], true);
    assert_eq!(body["matches_count"], 1);
    assert_eq!(body["kinds"], serde_json::json!(["PROMPT_INJECTION"]));
}

/// A `[guards.pii_ml]` token classifier over the fixture token model, whose
/// `config.json` labels the word `trigger` as `SECRET` and every other word `O`.
fn token_guard_section(dir: &Path) -> String {
    token_guard_section_with(dir, "SECRET", "")
}

/// [`token_guard_section`], labelling the word `trigger` as `label`, with
/// `extra` keys.
fn token_guard_section_with(dir: &Path, label: &str, extra: &str) -> String {
    let model = Fixture {
        tokens: true,
        trigger: true,
        width: 3,
        ..Fixture::default()
    };
    format!(
        r#"
[guards.pii_ml]
adapter = "token_classifier"
model_path = "{model}"
tokenizer_path = "{tokenizer}"
config_path = "{config}"
max_tokens = 16
labels = ["{label}"]
threads = 1
{extra}

[guards.pii_ml.thresholds]
{label} = 0.4
"#,
        model = model.write(dir).display(),
        tokenizer = TokenizerFixture::default().write(dir).display(),
        config =
            write_model_config(dir, &["O", &format!("B-{label}"), &format!("I-{label}")]).display(),
    )
}

/// The token classifier guard reports its span's kind on the API and blocks on
/// the proxy, and no log line, even at debug, holds the scanned text.
#[tokio::test]
async fn the_token_classifier_guard_reports_on_the_api_and_blocks_on_the_proxy() {
    const BODY: &str = "smoke trigger test";
    let dir = tempfile::tempdir().unwrap();
    let mut server = start_with_env(
        &token_guard_section(dir.path()),
        "",
        "",
        &[("RUST_LOG", "debug")],
    )
    .await;

    let resp = post(server.api_addr, "/v1/scan", BODY).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["detected"], true);
    assert_eq!(body["matches_count"], 1);
    assert_eq!(body["kinds"], serde_json::json!(["SECRET"]));

    let resp = post(server.proxy_addr, "/chat", BODY).await;
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "content blocked");
    assert_eq!(body["kinds"], serde_json::json!(["SECRET"]));
    assert_eq!(server.hits.load(Ordering::SeqCst), 0);

    let resp = post(server.proxy_addr, "/chat", "voidwall smoke test").await;
    assert_eq!(resp.status(), 200, "a body with no span is forwarded");

    let logs = server.proxy.stop();
    assert!(
        logs.contains("model thread started"),
        "the run logged at debug: {logs}"
    );
    assert!(!logs.contains(BODY), "a log line holds the text: {logs}");
}

/// http-api, "Two guards report the same kind for one value": a custom
/// definition of the `pii` guard and the `pii_ml` model guard each report
/// `SECRET` for the word `trigger`. The kind is listed once, both findings
/// count, and `guards` shows each guard's share. A body only one guard finds
/// something in lists that guard alone.
#[tokio::test]
async fn the_scan_api_breaks_the_findings_down_by_guard() {
    let dir = tempfile::tempdir().unwrap();
    let guards = format!(
        r#"
[builtin_guards.pii]
scanner_threads = 1
detect = ["Email"]

[[builtin_guards.pii.custom]]
label = "SECRET"
pattern = "trigger"
{}"#,
        token_guard_section(dir.path())
    );
    let server = start(&guards, "", "").await;

    let resp = post(server.api_addr, "/v1/scan", "smoke trigger test").await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["matches_count"], 2, "{body}");
    assert_eq!(body["kinds"], serde_json::json!(["SECRET"]));
    assert_eq!(
        body["guards"],
        serde_json::json!([
            {"name": "pii", "matches_count": 1, "kinds": ["SECRET"]},
            {"name": "pii_ml", "matches_count": 1, "kinds": ["SECRET"]},
        ])
    );

    let resp = post(server.api_addr, "/v1/scan", "mail user@example.com").await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["guards"],
        serde_json::json!([{"name": "pii", "matches_count": 1, "kinds": ["EMAIL"]}])
    );
}

/// The samples of the `voidwall_pii_*` families and `voidwall_blocked_total`
/// on the admin metrics endpoint.
async fn pii_and_block_samples(admin: SocketAddr) -> Vec<String> {
    reqwest::get(format!("http://{admin}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("voidwall_pii_") || l.starts_with("voidwall_blocked_total{"))
        .map(str::to_owned)
        .collect()
}

/// metrics, "A PII model guard's kind" and "Only a PII model guard detects":
/// a token guard with `class = "pii"` counts in the PII families under its
/// configured label, and a classless one does not.
#[tokio::test]
async fn a_pii_model_guard_counts_in_the_pii_families_and_a_classless_one_does_not() {
    const BLOCKED: &str =
        r#"voidwall_blocked_total{direction="request",mode="reverse_proxy",route="/"} 1"#;
    for (class, expected) in [
        (
            r#"class = "pii""#,
            vec![
                BLOCKED,
                r#"voidwall_pii_blocked_total{direction="request",mode="reverse_proxy",route="/"} 1"#,
                r#"voidwall_pii_detections_total{direction="request",mode="reverse_proxy",pii_kind="PERSON_NAME",route="/"} 1"#,
            ],
        ),
        ("", vec![BLOCKED]),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let server = start(
            &token_guard_section_with(dir.path(), "PERSON_NAME", class),
            "",
            "",
        )
        .await;

        let resp = post(server.proxy_addr, "/chat", "smoke trigger test").await;
        assert_eq!(resp.status(), 403);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["kinds"], serde_json::json!(["PERSON_NAME"]));

        let mut samples = pii_and_block_samples(server.admin_addr).await;
        samples.sort();
        assert_eq!(samples, expected, "class line: {class:?}");
    }
}

/// guard-configuration, "A route selects a model guard": a route naming the
/// PII guard and the model guard runs both.
#[tokio::test]
async fn a_route_that_names_the_pii_guard_and_a_model_guard_runs_both() {
    let artifacts = trigger_artifacts();
    let guards = format!(
        "[builtin_guards.pii]\nscanner_threads = 1\ndetect = [\"Email\"]\n{}",
        guard_section(&artifacts, "threads = 1")
    );
    let server = start(&guards, r#"guards = ["pii", "injection"]"#, "").await;

    let resp = post(server.proxy_addr, "/chat", "voidwall trigger test").await;
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["kinds"], serde_json::json!(["PROMPT_INJECTION"]));

    let resp = post(server.proxy_addr, "/chat", "mail john.doe@example.com").await;
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["kinds"], serde_json::json!(["EMAIL"]));

    assert_eq!(server.hits.load(Ordering::SeqCst), 0);
}

/// model-runtime, "A cancelled run is not counted as an error": the PII guard
/// blocks while the model guard is mid-run; the model run is cancelled, no
/// error is counted, and the model guard's only worker is free at once.
#[tokio::test]
async fn a_block_cancels_the_model_run_without_an_error() {
    let artifacts = artifacts(
        Fixture {
            trigger: true,
            slow: Some(300),
            ..Fixture::default()
        },
        TokenizerFixture::default(),
    );
    let guards = format!(
        "[builtin_guards.pii]\nscanner_threads = 1\ndetect = [\"Email\"]\n{}",
        guard_section(&artifacts, "threads = 1")
    );
    let server = start(
        &guards,
        r#"guards = ["pii", "injection"]"#,
        r#"on_error = "fail_close""#,
    )
    .await;
    // 80 tokens: eight windows of 16 with a stride of 8.
    let long = "voidwall smoke test test ".repeat(20);

    let started = std::time::Instant::now();
    let resp = post(server.proxy_addr, "/chat", long.clone()).await;
    let full = started.elapsed();
    assert_eq!(resp.status(), 200, "a clean long body is forwarded");

    let resp = post(
        server.proxy_addr,
        "/chat",
        format!("mail john.doe@example.com {long}"),
    )
    .await;
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["kinds"], serde_json::json!(["EMAIL"]));

    let started = std::time::Instant::now();
    let resp = post(server.proxy_addr, "/chat", "voidwall").await;
    let freed = started.elapsed();
    assert_eq!(resp.status(), 200);
    assert!(
        freed < full / 4,
        "answered after {freed:?}; full run {full:?}"
    );

    let metrics = reqwest::get(format!("http://{}/metrics", server.admin_addr))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let errors: Vec<&str> = metrics
        .lines()
        .filter(|l| l.starts_with("voidwall_errors_total{"))
        .collect();
    assert!(errors.is_empty(), "no error is counted: {errors:?}");
}

/// guard-configuration, "The total is above the CPU count": the start logs one
/// warning naming both numbers and goes on.
#[tokio::test]
async fn model_threads_above_the_cpu_count_warn_and_the_proxy_starts() {
    let cpus = std::thread::available_parallelism().unwrap().get();
    let threads = cpus + 1;
    let artifacts = trigger_artifacts();
    let mut server = start(
        &guard_section(&artifacts, &format!("threads = {threads}")),
        "",
        "",
    )
    .await;

    let resp = post(server.proxy_addr, "/chat", "voidwall smoke test").await;
    assert_eq!(resp.status(), 200, "the proxy starts and serves");

    let logs = strip_ansi(&server.proxy.stop());
    let warning = logs
        .lines()
        .find(|l| l.contains("model guard threads add up to more than the CPU count"))
        .unwrap_or_else(|| panic!("no thread warning in: {logs}"));
    assert!(warning.contains(&format!("threads={threads}")), "{warning}");
    assert!(warning.contains(&format!("cpus={cpus}")), "{warning}");
}

/// reverse-proxy, "Model inference failure under fail_close": 500 with the
/// fixed body, and the log names the guard.
#[tokio::test]
async fn an_inference_failure_answers_500_and_the_log_names_the_guard() {
    // The trigger's embedding row is NaN, so only a unit holding it fails;
    // the smoke inference at load does not.
    let artifacts = artifacts(
        Fixture {
            nan_row: Some(TRIGGER_ID),
            ..Fixture::default()
        },
        TokenizerFixture::default(),
    );
    let mut server = start(
        &guard_section(&artifacts, "threads = 1"),
        "",
        r#"on_error = "fail_close""#,
    )
    .await;

    let resp = post(server.proxy_addr, "/chat", "voidwall trigger test").await;
    assert_eq!(resp.status(), 500);
    assert_eq!(resp.text().await.unwrap(), r#"{"error":"internal error"}"#);
    assert_eq!(server.hits.load(Ordering::SeqCst), 0);

    let logs = server.proxy.stop();
    let line = logs
        .lines()
        .find(|l| l.contains("model guard 'injection' failed"))
        .unwrap_or_else(|| panic!("no guard error in: {logs}"));
    assert!(line.contains("non-finite"), "{line}");
    assert!(
        !line.contains("voidwall trigger test"),
        "the log holds no text: {line}"
    );
}

/// configuration, "The overlap leaves no room in the window": the start exits
/// non-zero, naming the guard, the window, and the overlap, with no data plane.
#[tokio::test]
async fn an_overlap_that_leaves_no_room_in_the_window_stops_the_start() {
    let artifacts = artifacts(
        Fixture::default(),
        TokenizerFixture {
            special_tokens: true,
            ..TokenizerFixture::default()
        },
    );
    // The fixture adds 2 special tokens ([CLS] $A [SEP]); 4 more [CLS] make 6,
    // so max_tokens 10 leaves a window of 4, not longer than an overlap of 5.
    add_leading_cls(&artifacts.tokenizer, 4);

    // The data plane never binds, so its port is never taken. The admin server
    // binds before the load, so it takes port 0, which no other test can hold.
    let proxy_addr = free_addr().await;
    let config = write_config(&format!(
        r#"
[guards.injection]
adapter = "text_classifier"
model_path = "{model}"
tokenizer_path = "{tokenizer}"
max_tokens = 10
overlap_tokens = 5
labels = ["PROMPT_INJECTION"]
threads = 1

[reverse_proxy]
enabled = true
listen = "{proxy_addr}"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://127.0.0.1:9"

[admin]
listen = "127.0.0.1:0"
"#,
        model = artifacts.model.display(),
        tokenizer = artifacts.tokenizer.display(),
    ));

    let (status, logs) = Proxy::spawn(config.path()).wait_for_exit().await;

    assert!(!status.success(), "a failed load must exit non-zero");
    assert!(
        logs.contains("guards.injection"),
        "must name the guard: {logs}"
    );
    assert!(
        logs.contains("window of 4 tokens") && logs.contains("overlap of 5 tokens"),
        "must name the window and the overlap: {logs}"
    );
    // A connect to the port cannot show this: another test may hold it. The
    // line is logged only once the listener is bound.
    assert!(
        !logs.contains("reverse proxy started"),
        "the data plane must not bind: {logs}"
    );
}

/// Put `n` more `[CLS]` tokens in front of the single-sequence template of a
/// fixture tokenizer file.
fn add_leading_cls(path: &Path, n: usize) {
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let single = json["post_processor"]["single"]
        .as_array_mut()
        .expect("a TemplateProcessing post-processor");
    let cls = single[0].clone();
    assert!(
        cls.to_string().contains("[CLS]"),
        "unexpected template: {cls}"
    );
    for _ in 0..n {
        single.insert(0, cls.clone());
    }
    std::fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
}

/// The log with its terminal colour codes removed, so a field reads `key=value`.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}
