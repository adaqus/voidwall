use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use voidwall::admin::{AdminState, serve};
use voidwall::config::AdminConfig;

/// Bind admin server to an ephemeral port and return the address.
async fn start_admin(ready: bool) -> (SocketAddr, Arc<AtomicBool>, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // free the port so serve() can bind it

    let ready_flag = Arc::new(AtomicBool::new(ready));
    let cancel = CancellationToken::new();

    let config = AdminConfig {
        listen: addr.to_string(),
        ..AdminConfig::default()
    };
    let state = AdminState {
        ready: ready_flag.clone(),
    };

    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        serve(&config, state, cancel_clone).await.unwrap();
    });

    // Wait for the server to be accepting connections.
    wait_for_port(addr).await;

    (addr, ready_flag, cancel)
}

async fn wait_for_port(addr: SocketAddr) {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("server did not start on {addr}");
}

#[tokio::test]
async fn health_endpoint_returns_200() {
    let (addr, _, cancel) = start_admin(false).await;

    let resp = reqwest::get(format!("http://{addr}/healthz"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    cancel.cancel();
}

#[tokio::test]
async fn readiness_returns_503_then_200() {
    let (addr, ready_flag, cancel) = start_admin(false).await;

    // Not ready yet
    let resp = reqwest::get(format!("http://{addr}/readyz")).await.unwrap();
    assert_eq!(resp.status(), 503);

    // Flip to ready
    ready_flag.store(true, Ordering::Release);

    let resp = reqwest::get(format!("http://{addr}/readyz")).await.unwrap();
    assert_eq!(resp.status(), 200);

    cancel.cancel();
}

#[tokio::test]
async fn metrics_endpoint_returns_prometheus_format() {
    let (addr, _, cancel) = start_admin(true).await;

    // Force a metric so there's output.
    voidwall::metrics::inc_error("passed", "test_probe");

    let resp = reqwest::get(format!("http://{addr}/metrics"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(content_type.contains("text/plain"));

    let body = resp.text().await.unwrap();
    assert!(body.contains("voidwall_errors_total"));

    cancel.cancel();
}

#[tokio::test]
async fn metrics_endpoint_carries_no_specialization_surface() {
    let (addr, _, cancel) = start_admin(true).await;

    // Force a detection sample so the counter family is emitted.
    voidwall::metrics::inc_detection("Email", "http_api", "global", "request");

    let resp = reqwest::get(format!("http://{addr}/metrics"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    assert!(
        !body.contains("voidwall_specialization_errors_total"),
        "the retired specialization error family must not be registered"
    );
    let detection_samples: Vec<&str> = body
        .lines()
        .filter(|l| l.starts_with("voidwall_pii_detections_total{"))
        .collect();
    assert!(
        !detection_samples.is_empty(),
        "expected at least one detection sample"
    );
    for sample in detection_samples {
        assert!(
            !sample.contains("specialization"),
            "detection sample must carry no specialization label: {sample}"
        );
    }

    cancel.cancel();
}

/// The two guard families carry exactly the label sets the metrics spec names,
/// and no kind label.
#[tokio::test]
async fn metrics_endpoint_carries_the_guard_families() {
    let (addr, _, cancel) = start_admin(true).await;

    // Force one sample of each family so both are emitted.
    voidwall::metrics::inc_guard_detection("pii", "reverse_proxy", "/admin-scrape", "request");
    voidwall::metrics::inc_message_blocked("reverse_proxy", "/admin-scrape", "request");

    let body = reqwest::get(format!("http://{addr}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let label_names = |family: &str| -> Vec<Vec<String>> {
        body.lines()
            .filter_map(|l| l.strip_prefix(&format!("{family}{{")))
            .map(|rest| {
                let labels = rest.split('}').next().unwrap();
                let mut names: Vec<String> = labels
                    .split(',')
                    .map(|pair| pair.split('=').next().unwrap().to_string())
                    .collect();
                names.sort();
                names
            })
            .collect()
    };

    let detections = label_names("voidwall_detections_total");
    assert!(!detections.is_empty(), "expected a detections sample");
    for names in detections {
        assert_eq!(names, ["direction", "guard", "mode", "route"]);
    }

    let blocked = label_names("voidwall_blocked_total");
    assert!(!blocked.is_empty(), "expected a blocked sample");
    for names in blocked {
        assert_eq!(names, ["direction", "mode", "route"]);
    }

    cancel.cancel();
}

// --- Startup order: the admin server answers while the guards load ---

/// A free local port.
async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// The admin server binds before the guards load and the data plane binds
/// after. The engine builder is held on a channel, so the test sees the
/// process as it is during a slow model load.
#[tokio::test]
async fn the_admin_server_answers_while_the_guards_load_and_the_data_plane_waits() {
    use voidwall::config::AppConfig;
    use voidwall::engine::Engine;

    let admin_addr = free_addr().await;
    let api_addr = free_addr().await;
    let config: AppConfig = toml::from_str(&format!(
        r#"
[http_api]
enabled = true
listen = "{api_addr}"

[admin]
listen = "{admin_addr}"
"#
    ))
    .unwrap();

    let (release, held) = std::sync::mpsc::channel::<()>();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let run = tokio::spawn(voidwall::server::run(
        config,
        move |config: &AppConfig| {
            held.recv().unwrap();
            Engine::new(&config.builtin_guards)
        },
        async move {
            let _ = stopped.await;
        },
    ));

    wait_for_port(admin_addr).await;
    let get = |path: &str| reqwest::get(format!("http://{admin_addr}{path}"));
    assert_eq!(get("/healthz").await.unwrap().status(), 200);
    assert_eq!(get("/readyz").await.unwrap().status(), 503);
    assert!(
        tokio::net::TcpStream::connect(api_addr).await.is_err(),
        "the data plane must not bind while the guards load"
    );

    release.send(()).unwrap();
    wait_for_port(api_addr).await;
    let mut ready = false;
    for _ in 0..50 {
        if get("/readyz").await.unwrap().status() == 200 {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(ready, "/readyz must answer 200 once the guards loaded");

    stop.send(()).unwrap();
    run.await.unwrap().expect("the run ends cleanly");
}

/// A failed build stops the admin server and returns the error, so the
/// binary can exit non-zero.
#[tokio::test]
async fn a_failed_engine_build_returns_the_error_and_binds_no_data_plane() {
    use voidwall::config::AppConfig;
    use voidwall::error::Error;

    let admin_addr = free_addr().await;
    let api_addr = free_addr().await;
    let config: AppConfig = toml::from_str(&format!(
        r#"
[http_api]
enabled = true
listen = "{api_addr}"

[admin]
listen = "{admin_addr}"
"#
    ))
    .unwrap();

    let result = voidwall::server::run(
        config,
        |_: &AppConfig| Err(Error::Config("guards.injection: bad model".into())),
        std::future::pending(),
    )
    .await;

    let err = result.expect_err("the build failed");
    assert!(err.to_string().contains("guards.injection"));
    assert!(tokio::net::TcpStream::connect(api_addr).await.is_err());
}
