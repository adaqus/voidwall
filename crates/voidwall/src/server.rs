//! The startup sequence and the run until shutdown.
//!
//! The order is the readiness contract: the admin server binds first, so
//! `/healthz` answers while the guards load and `/readyz` answers 503; the
//! data-plane listeners bind only once every guard has loaded, and only then
//! does `/readyz` answer 200.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::admin::{self, AdminState};
use crate::config::AppConfig;
use crate::engine::Engine;
use crate::error::{Error, Listener};
use crate::{http_api, reverse_proxy};

/// Start every enabled mode and run until `shutdown` completes.
///
/// `build_engine` builds the guards. It runs on the blocking pool, because a
/// model guard loads its model there, which takes seconds; the admin server
/// keeps answering meanwhile. When it fails, the admin server stops and the
/// error is returned, so the caller can exit non-zero. A listener that cannot
/// bind ends the run the same way, with an error that names it. A `shutdown`
/// that completes during the build ends the run without binding the data plane.
pub async fn run<B, S>(config: AppConfig, build_engine: B, shutdown: S) -> Result<(), Error>
where
    B: FnOnce(&AppConfig) -> Result<Engine, Error> + Send + 'static,
    S: Future<Output = ()>,
{
    let cancel = CancellationToken::new();
    let ready = Arc::new(AtomicBool::new(false));
    let shutdown_timeout = Duration::from_secs(config.shutdown_timeout_secs);
    let mut task_handles = Vec::new();
    tokio::pin!(shutdown);

    // Admin server (always on), before the guards load.
    {
        let listener = bind(Listener::Admin, &config.admin.listen, &cancel).await?;
        let admin_config = config.admin.clone();
        let state = AdminState {
            ready: Arc::clone(&ready),
        };
        let cancel = cancel.clone();
        task_handles.push(tokio::spawn(async move {
            if let Err(e) = admin::serve_on(listener, &admin_config, state, cancel).await {
                tracing::error!(error = %e, "admin server failed");
            }
        }));
        tracing::info!("admin server task spawned");
    }

    // Build the detection engine and its guards.
    let build = {
        let config = config.clone();
        tokio::task::spawn_blocking(move || build_engine(&config))
    };
    let built = tokio::select! {
        built = build => built,
        () = &mut shutdown => {
            tracing::info!("shutdown signal received while the guards load");
            cancel.cancel();
            return Ok(());
        }
    };
    let engine = match built {
        Ok(Ok(engine)) => Arc::new(engine),
        Ok(Err(e)) => {
            cancel.cancel();
            return Err(e);
        }
        Err(join) => {
            cancel.cancel();
            return Err(Error::Config(format!(
                "building the guards panicked: {join}"
            )));
        }
    };

    let mut guards = config.builtin_guards.enabled_names();
    guards.extend(config.guards.keys().map(String::as_str));
    tracing::info!(
        guards = ?guards,
        threads = config
            .builtin_guards
            .enabled_pii()
            .map(|g| g.effective_scanner_threads())
            .unwrap_or(0),
        "detection engine initialized"
    );

    // Reverse proxy (if enabled)
    if config.reverse_proxy.enabled {
        let listener = bind(
            Listener::ReverseProxy,
            &config.reverse_proxy.listen,
            &cancel,
        )
        .await?;
        let config = config.clone();
        let engine = Arc::clone(&engine);
        let cancel = cancel.clone();
        task_handles.push(tokio::spawn(async move {
            if let Err(e) = reverse_proxy::serve_on(listener, &config, engine, cancel).await {
                tracing::error!(error = %e, "reverse proxy failed");
            }
        }));
        tracing::info!("reverse proxy task spawned");
    }

    // HTTP API (if enabled)
    if config.http_api.enabled {
        let listener = bind(Listener::HttpApi, &config.http_api.listen, &cancel).await?;
        let config = config.clone();
        let engine = Arc::clone(&engine);
        let cancel = cancel.clone();
        task_handles.push(tokio::spawn(async move {
            if let Err(e) = http_api::serve_on(listener, &config, engine, cancel).await {
                tracing::error!(error = %e, "HTTP API failed");
            }
        }));
        tracing::info!("HTTP API task spawned");
    }

    // Every enabled data-plane listener is bound. A connection that arrives
    // before its task serves waits in the listen backlog.
    ready.store(true, Ordering::Release);
    tracing::info!("readiness flag set");

    shutdown.await;
    tracing::info!("shutdown signal received, initiating graceful shutdown");

    // Trigger cancellation — listeners stop accepting new connections
    // and axum drains in-flight requests via with_graceful_shutdown.
    cancel.cancel();

    // Wait for all tasks to complete, with a timeout to avoid hanging
    if tokio::time::timeout(shutdown_timeout, async {
        for handle in task_handles {
            let _ = handle.await;
        }
    })
    .await
    .is_err()
    {
        tracing::warn!(
            timeout_secs = config.shutdown_timeout_secs,
            "shutdown timeout exceeded, some tasks may not have finished"
        );
    }

    // Release the detection engine. Every listener task has finished, so this
    // is the last reference: dropping the engine drops each guard, and a
    // guard's pool joins every thread on its way out.
    match Arc::into_inner(engine) {
        Some(engine) => engine.shutdown(),
        None => tracing::info!("detection engine released to its remaining holders"),
    }

    Ok(())
}

/// Bind `addr` for `listener`. On a failure, cancel `cancel`, so every
/// listener already serving stops, and return an error that names both.
async fn bind(
    listener: Listener,
    addr: &str,
    cancel: &CancellationToken,
) -> Result<TcpListener, Error> {
    TcpListener::bind(addr).await.map_err(|source| {
        cancel.cancel();
        Error::Bind {
            listener,
            addr: addr.to_owned(),
            source,
        }
    })
}
