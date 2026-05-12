use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use prometheus::Encoder;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing;

use crate::config::AdminConfig;

/// Shared state for the admin server.
#[derive(Clone)]
pub struct AdminState {
    /// Flipped to `true` once all data-plane listeners are bound.
    pub ready: Arc<AtomicBool>,
}

/// Build the admin axum router using the configured paths.
pub fn router(config: &AdminConfig, state: AdminState) -> Router {
    Router::new()
        .route(&config.metrics_path, get(metrics_handler))
        .route(&config.health_path, get(health_handler))
        .route(&config.ready_path, get(ready_handler))
        .with_state(state)
}

/// Start the admin server, binding to the configured address.
/// Runs until the cancellation token is triggered.
pub async fn serve(
    config: &AdminConfig,
    state: AdminState,
    cancel: CancellationToken,
) -> Result<(), crate::error::Error> {
    let app = router(config, state);
    let listener = TcpListener::bind(&config.listen).await?;
    tracing::info!(listen = %config.listen, "admin server started");

    axum::serve(listener, app)
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await
        .map_err(crate::error::Error::Io)?;

    Ok(())
}

async fn metrics_handler() -> impl IntoResponse {
    crate::metrics::update_process_metrics();
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        buffer,
    )
}

async fn health_handler() -> StatusCode {
    StatusCode::OK
}

async fn ready_handler(State(state): State<AdminState>) -> StatusCode {
    if state.ready.load(Ordering::Acquire) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use hyper::Request;
    use tower::ServiceExt;

    fn default_state(ready: bool) -> AdminState {
        AdminState {
            ready: Arc::new(AtomicBool::new(ready)),
        }
    }

    #[tokio::test]
    async fn healthz_returns_200() {
        let config = AdminConfig::default();
        let app = router(&config, default_state(false));

        let resp = app
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_returns_503_when_not_ready() {
        let config = AdminConfig::default();
        let app = router(&config, default_state(false));

        let resp = app
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn readyz_returns_200_when_ready() {
        let config = AdminConfig::default();
        let app = router(&config, default_state(true));

        let resp = app
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_returns_prometheus_text() {
        // Force a metric so the registry has something to output.
        crate::metrics::inc_error("passed", "admin_unit_test");

        let config = AdminConfig::default();
        let app = router(&config, default_state(true));

        let resp = app
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let content_type = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(content_type.contains("text/plain"));

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("pii_proxy_errors_total"));
    }

    #[tokio::test]
    async fn readyz_flips_at_runtime() {
        let state = default_state(false);
        let config = AdminConfig::default();
        let app = router(&config, state.clone());

        // Not ready yet
        let resp = app
            .clone()
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Flip to ready
        state.ready.store(true, Ordering::Release);

        let resp = app
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn custom_paths() {
        let config = AdminConfig {
            listen: "127.0.0.1:0".into(),
            metrics_path: "/custom/metrics".into(),
            health_path: "/custom/health".into(),
            ready_path: "/custom/ready".into(),
        };
        let app = router(&config, default_state(true));

        let resp = app
            .clone()
            .oneshot(Request::get("/custom/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .clone()
            .oneshot(Request::get("/custom/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .oneshot(Request::get("/custom/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
