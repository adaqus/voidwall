//! Integration tests for what the binary does at startup.
//!
//! These spawn the real `voidwall` process against a real upstream, so they
//! cover the paths `--validate` cannot: what the proxy logs, and what it does
//! with traffic once it is running.

use std::io::Write;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};

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

/// The proxy compiles its regex and vectorscan databases before it binds, so a
/// spawn with a guard enabled takes seconds rather than milliseconds.
async fn wait_for_proxy(addr: SocketAddr) {
    wait_for_port_within(addr, 1200).await;
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

/// Spawn the proxy with stdout and stderr captured, so a test can read what it
/// logged after stopping it.
fn spawn_proxy(config: &std::path::Path) -> Child {
    Command::new(BIN)
        .arg("--config")
        .arg(config)
        .env_remove("VOIDWALL_CONFIG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn voidwall")
}

/// Stop the proxy and return everything it logged.
fn stop_and_read_logs(mut child: Child) -> String {
    let _ = child.kill();
    let out = child.wait_with_output().expect("wait for voidwall");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    )
}

/// Configuration that enables a mode and no guard. This starts: a proxy with
/// nothing enabled to inspect states a deployment with nothing to inspect,
/// exactly as a proxy with no mode enabled does.
#[tokio::test]
async fn an_empty_guard_set_starts_warns_and_forwards_traffic_unscanned() {
    const PLACEHOLDER: &str = "john.doe@example.com";

    let upstream = start_echo_upstream().await;

    // An ephemeral port, released before the proxy binds it.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    drop(listener);
    let admin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin.local_addr().unwrap();
    drop(admin);

    // No `[builtin_guards.pii]` section at all, so no guard is built.
    let cfg = write_cfg(&format!(
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
    ));

    let child = spawn_proxy(cfg.path());
    wait_for_proxy(proxy_addr).await;

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

    let logs = stop_and_read_logs(child);
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

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    drop(listener);
    let admin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin.local_addr().unwrap();
    drop(admin);

    let cfg = write_cfg(&format!(
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
    ));

    let child = spawn_proxy(cfg.path());
    wait_for_proxy(proxy_addr).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{proxy_addr}/echo"))
        .header("content-type", "text/plain")
        .body(PLACEHOLDER)
        .send()
        .await
        .expect("the proxy serves traffic");

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), PLACEHOLDER);

    let logs = stop_and_read_logs(child);
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

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    drop(listener);
    let admin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin.local_addr().unwrap();
    drop(admin);

    let cfg = write_cfg(&format!(
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
    ));

    let child = spawn_proxy(cfg.path());
    wait_for_proxy(proxy_addr).await;

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

    let logs = stop_and_read_logs(child);
    assert!(
        !logs.contains("no guard is enabled"),
        "a guard is enabled, so nothing should warn: {logs}"
    );
}

/// A model guard whose model does not load stops the start: the binary logs
/// the guard and the path, exits non-zero by itself, and the data plane never
/// binds. There is no partial start without the guard.
#[tokio::test]
async fn a_model_guard_that_fails_to_load_stops_the_start() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    drop(listener);
    let admin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin.local_addr().unwrap();
    drop(admin);

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
listen = "{admin_addr}"
"#,
        artifact = artifact.path().display(),
    ));

    let mut child = spawn_proxy(cfg.path());
    let mut status = None;
    for _ in 0..200 {
        if let Some(s) = child.try_wait().expect("poll voidwall") {
            status = Some(s);
            break;
        }
        assert!(
            tokio::net::TcpStream::connect(proxy_addr).await.is_err(),
            "the data plane must not bind"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let status = status.expect("voidwall must exit by itself");
    assert!(!status.success(), "a failed load must exit non-zero");

    let logs = stop_and_read_logs(child);
    assert!(
        logs.contains("guards.injection"),
        "must name the guard: {logs}"
    );
    assert!(
        logs.contains(&artifact.path().display().to_string()),
        "must name the model path: {logs}"
    );
}
