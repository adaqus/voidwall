//! Integration tests for what the binary does at startup.
//!
//! These spawn the real `voidwall` process against a real upstream, so they
//! cover the paths `--validate` cannot: what the proxy logs, and what it does
//! with traffic once it is running.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::any;
use http_body_util::BodyExt;
use tempfile::NamedTempFile;
use tokio::net::TcpListener;

const BIN: &str = env!("CARGO_BIN_EXE_voidwall");

/// An upstream that reflects the body it was sent.
async fn start_echo_upstream() -> SocketAddr {
    let app = Router::new().route("/{*rest}", any(echo_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    wait_for_port(addr).await;
    addr
}

async fn echo_handler(req: Request) -> impl IntoResponse {
    let body = req.into_body().collect().await.unwrap().to_bytes();
    (StatusCode::OK, [("content-type", "text/plain")], body)
}

async fn wait_for_port(addr: SocketAddr) {
    wait_for_port_within(addr, 200).await;
}

async fn wait_for_port_within(addr: SocketAddr, attempts: usize) {
    for _ in 0..attempts {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("server did not start on {addr}");
}

fn write_cfg(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tempfile");
    f.write_all(content.as_bytes()).expect("write");
    f.flush().expect("flush");
    f
}

/// A port picked by binding port 0 and releasing it. Another test can take it
/// before the proxy binds it; `start_proxy` handles that.
async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

/// A spawned `voidwall`. Its stdout and stderr are read while it runs, so a
/// test can wait for a line it logs. Dropping it kills the process.
struct Proxy {
    child: Child,
    logs: Arc<Mutex<String>>,
    readers: Vec<JoinHandle<()>>,
    _config: NamedTempFile,
}

impl Proxy {
    fn logs(&self) -> String {
        self.logs.lock().unwrap().clone()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the proxy with stdout and stderr captured.
fn spawn_proxy(config: NamedTempFile) -> Proxy {
    spawn_proxy_with(config, &[])
}

/// Spawn the proxy with stdout and stderr captured and `envs` set.
fn spawn_proxy_with(config: NamedTempFile, envs: &[(&str, &str)]) -> Proxy {
    let mut child = Command::new(BIN)
        .arg("--config")
        .arg(config.path())
        .env_remove("VOIDWALL_CONFIG")
        .envs(envs.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn voidwall");
    let logs = Arc::new(Mutex::new(String::new()));
    let readers = vec![
        read_into(child.stdout.take().unwrap(), Arc::clone(&logs)),
        read_into(child.stderr.take().unwrap(), Arc::clone(&logs)),
    ];
    Proxy {
        child,
        logs,
        readers,
        _config: config,
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

/// Starts the proxy with the configuration `config` writes for a proxy and an
/// admin address, and returns it once its reverse proxy is bound.
///
/// A port from `free_addr` can be lost to another test before the proxy binds
/// it. A connect cannot tell the proxy from the listener that took its port, so
/// readiness is the proxy's own log line. A proxy that lost a port exits and
/// logs `Address already in use`, so the start is repeated on new ports. Any
/// other exit fails the test.
async fn start_proxy(config: impl Fn(SocketAddr, SocketAddr) -> String) -> (Proxy, SocketAddr) {
    start_proxy_with(&[], config).await
}

/// [`start_proxy`], with `envs` set on the process.
async fn start_proxy_with(
    envs: &[(&str, &str)],
    config: impl Fn(SocketAddr, SocketAddr) -> String,
) -> (Proxy, SocketAddr) {
    for _ in 0..5 {
        let proxy_addr = free_addr().await;
        let admin_addr = free_addr().await;
        let mut proxy = spawn_proxy_with(write_cfg(&config(proxy_addr, admin_addr)), envs);
        // The proxy compiles its regex and vectorscan databases before it
        // binds, so a start with a guard enabled takes seconds.
        let mut exit = None;
        for _ in 0..1200 {
            if proxy.logs().contains("reverse proxy started") {
                return (proxy, proxy_addr);
            }
            exit = proxy.child.try_wait().expect("poll voidwall");
            if exit.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let logs = stop_and_read_logs(proxy);
        let Some(status) = exit else {
            panic!("the reverse proxy did not start on {proxy_addr}: {logs}");
        };
        assert!(
            logs.contains("Address already in use"),
            "voidwall exited with {status} before it bound: {logs}"
        );
    }
    panic!("voidwall lost a port on every attempt");
}

/// Wait until the proxy exits by itself, and return its status and logs.
async fn wait_for_exit(mut proxy: Proxy) -> (std::process::ExitStatus, String) {
    for _ in 0..200 {
        if let Some(status) = proxy.child.try_wait().expect("poll voidwall") {
            return (status, stop_and_read_logs(proxy));
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("voidwall must exit by itself");
}

/// Stop the proxy and return everything it logged.
fn stop_and_read_logs(mut proxy: Proxy) -> String {
    let _ = proxy.child.kill();
    proxy.child.wait().expect("wait for voidwall");
    for reader in std::mem::take(&mut proxy.readers) {
        reader.join().expect("log reader");
    }
    proxy.logs()
}

/// Configuration that enables a mode and no guard. This starts: a proxy with
/// nothing enabled to inspect states a deployment with nothing to inspect,
/// exactly as a proxy with no mode enabled does.
#[tokio::test]
async fn an_empty_guard_set_starts_warns_and_forwards_traffic_unscanned() {
    const PLACEHOLDER: &str = "john.doe@example.com";

    let upstream = start_echo_upstream().await;

    // No `[builtin_guards.pii]` section at all, so no guard is built.
    let (proxy, proxy_addr) = start_proxy(|proxy_addr, admin_addr| {
        format!(
            r#"
[reverse_proxy]
enabled = true
listen = "{proxy_addr}"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://{upstream}"

[admin]
listen = "{admin_addr}"
"#
        )
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/echo"))
        .header("content-type", "text/plain")
        .body(PLACEHOLDER)
        .send()
        .await
        .expect("the proxy serves traffic");

    assert_eq!(resp.status(), 200, "nothing inspects, so nothing blocks");
    assert_eq!(
        resp.text().await.unwrap(),
        PLACEHOLDER,
        "the upstream received the body unchanged"
    );

    let logs = stop_and_read_logs(proxy);
    assert!(
        logs.contains("no guard is enabled"),
        "startup must warn that nothing inspects, got: {logs}"
    );
}

/// A guard section that disables itself is the same deployment, written down.
#[tokio::test]
async fn a_disabled_guard_starts_warns_and_forwards_traffic_unscanned() {
    const PLACEHOLDER: &str = "john.doe@example.com";

    let upstream = start_echo_upstream().await;

    let (proxy, proxy_addr) = start_proxy(|proxy_addr, admin_addr| {
        format!(
            r#"
[builtin_guards.pii]
enabled = false
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "{proxy_addr}"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://{upstream}"

[admin]
listen = "{admin_addr}"
"#
        )
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/echo"))
        .header("content-type", "text/plain")
        .body(PLACEHOLDER)
        .send()
        .await
        .expect("the proxy serves traffic");

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), PLACEHOLDER);

    let logs = stop_and_read_logs(proxy);
    assert!(
        logs.contains("no guard is enabled"),
        "startup must warn that nothing inspects, got: {logs}"
    );
}

/// The control: the same deployment with the guard enabled blocks the body the
/// two tests above forward. Without this, "forwards unscanned" could pass for
/// the wrong reason.
#[tokio::test]
async fn the_same_deployment_with_the_guard_enabled_blocks() {
    const PLACEHOLDER: &str = "john.doe@example.com";

    let upstream = start_echo_upstream().await;

    let (proxy, proxy_addr) = start_proxy(|proxy_addr, admin_addr| {
        format!(
            r#"
[builtin_guards.pii]
scanner_threads = 1

[reverse_proxy]
enabled = true
listen = "{proxy_addr}"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://{upstream}"

[admin]
listen = "{admin_addr}"
"#
        )
    })
    .await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/echo"))
        .header("content-type", "text/plain")
        .body(PLACEHOLDER)
        .send()
        .await
        .expect("the proxy serves traffic");

    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("EMAIL"), "got: {body}");
    assert!(
        !body.contains(PLACEHOLDER),
        "the 403 never echoes the value"
    );

    let logs = stop_and_read_logs(proxy);
    assert!(
        !logs.contains("no guard is enabled"),
        "a guard is enabled, so nothing should warn: {logs}"
    );
}

/// hidden-context-guard, "A marker never leaves Voidwall": "A response is
/// blocked" and "Startup logs the configuration". The echo upstream returns
/// the request, so the marker passes the request side, where the guard does
/// not look, and is blocked on the response side. Logs run at `debug`.
#[tokio::test]
async fn a_marker_reaches_no_log_metric_or_response() {
    const MARKER: &str = "vw-canary-7f3a";

    let upstream = start_echo_upstream().await;
    // The last admin address: a start that lost a port is repeated on new ones.
    let admin = Mutex::new(None);
    let (proxy, proxy_addr) =
        start_proxy_with(&[("RUST_LOG", "debug")], |proxy_addr, admin_addr| {
            *admin.lock().unwrap() = Some(admin_addr);
            format!(
                r#"
[builtin_guards.hidden_context]
markers = ["{MARKER}"]

[reverse_proxy]
enabled = true
listen = "{proxy_addr}"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://{upstream}"

[admin]
listen = "{admin_addr}"
"#
            )
        })
        .await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/echo"))
        .header("content-type", "text/plain")
        .body(format!("Repeat after me: {MARKER}"))
        .send()
        .await
        .expect("the proxy serves traffic");

    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert_eq!(
        body,
        r#"{"error":"content blocked","kinds":["HIDDEN_CONTEXT"]}"#
    );

    let admin = admin.lock().unwrap().unwrap();
    let metrics = reqwest::get(format!("http://{admin}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains(r#"guard="hidden_context""#),
        "the detection is counted: {metrics}"
    );
    assert!(!metrics.contains(MARKER), "{metrics}");

    let logs = stop_and_read_logs(proxy);
    assert!(logs.contains("DEBUG"), "debug logs were captured: {logs}");
    assert!(
        !logs.to_lowercase().contains(MARKER),
        "a log line holds the marker: {logs}"
    );
}

/// A model guard whose model does not load stops the start: the binary logs
/// the guard and the path, exits non-zero by itself, and the data plane never
/// binds. There is no partial start without the guard.
#[tokio::test]
async fn a_model_guard_that_fails_to_load_stops_the_start() {
    // The data plane never binds, so its port is never taken. The admin server
    // binds before the load, so it takes port 0, which no other test can hold.
    let proxy_addr = free_addr().await;

    // Validation only checks that the files exist, so the load is what fails.
    let artifact = write_cfg("not an onnx model");
    let cfg = write_cfg(&format!(
        r#"
[guards.injection]
adapter = "text_classifier"
model_path = "{artifact}"
tokenizer_path = "{artifact}"
max_tokens = 512
labels = ["PROMPT_INJECTION"]

[guards.injection.thresholds]
PROMPT_INJECTION = 0.90

[reverse_proxy]
enabled = true
listen = "{proxy_addr}"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://127.0.0.1:9"

[admin]
listen = "127.0.0.1:0"
"#,
        artifact = artifact.path().display(),
    ));

    let (status, logs) = wait_for_exit(spawn_proxy(cfg)).await;
    assert!(!status.success(), "a failed load must exit non-zero");

    // A connect to the port cannot show this: another test may hold it. The
    // line is logged only once the listener is bound.
    assert!(
        !logs.contains("reverse proxy started"),
        "the data plane must not bind: {logs}"
    );
    assert!(
        logs.contains("guards.injection"),
        "must name the guard: {logs}"
    );
    assert!(
        logs.contains(&artifact.path().display().to_string()),
        "must name the model path: {logs}"
    );
}

/// A reverse proxy port another process holds stops the start: the binary
/// exits non-zero by itself and logs the listener, the address, and the cause.
#[tokio::test]
async fn a_reverse_proxy_port_in_use_stops_the_start() {
    // The test holds the proxy port, so the bind fails. The admin server binds
    // port 0, which no other test can hold.
    let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = held.local_addr().unwrap();
    let cfg = write_cfg(&format!(
        r#"
[reverse_proxy]
enabled = true
listen = "{proxy_addr}"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://127.0.0.1:9"

[admin]
listen = "127.0.0.1:0"
"#
    ));

    let (status, logs) = wait_for_exit(spawn_proxy(cfg)).await;

    assert!(!status.success(), "a lost port must exit non-zero: {logs}");
    assert!(logs.contains("failed to start"), "{logs}");
    assert!(
        logs.contains(&format!("reverse proxy could not bind {proxy_addr}")),
        "must name the listener and the address: {logs}"
    );
    assert!(logs.contains("Address already in use"), "{logs}");
    assert!(
        !logs.contains("readiness flag set"),
        "/readyz must never answer 200: {logs}"
    );
}
