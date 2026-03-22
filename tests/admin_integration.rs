use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use pii_proxy::admin::{AdminState, serve};
use pii_proxy::config::AdminConfig;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

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
    let resp = reqwest::get(format!("http://{addr}/readyz"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);

    // Flip to ready
    ready_flag.store(true, Ordering::Release);

    let resp = reqwest::get(format!("http://{addr}/readyz"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    cancel.cancel();
}

#[tokio::test]
async fn metrics_endpoint_returns_prometheus_format() {
    let (addr, _, cancel) = start_admin(true).await;

    // Force a metric so there's output.
    pii_proxy::metrics::inc_error("passed", "test_probe");

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
    assert!(body.contains("pii_proxy_errors_total"));

    cancel.cancel();
}
