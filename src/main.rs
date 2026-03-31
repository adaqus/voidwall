#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::Parser;
use pii_proxy::admin::{self, AdminState};
use pii_proxy::config::{AppConfig, Cli};
use pii_proxy::reverse_proxy;
use pii_proxy::scanner::ScannerPool;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Load and validate config
    let config = match AppConfig::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to load configuration");
            std::process::exit(1);
        }
    };

    tracing::info!(config_path = %cli.config.display(), "configuration loaded");

    // Create ScannerPool
    let scanner = match ScannerPool::new(&config.pii) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!(error = %e, "failed to initialize scanner pool");
            std::process::exit(1);
        }
    };

    tracing::info!(
        threads = config.pii.effective_scanner_threads(),
        "scanner pool initialized"
    );

    // Set up cancellation token and readiness signal
    let cancel = CancellationToken::new();
    let ready = Arc::new(AtomicBool::new(false));
    let shutdown_timeout = Duration::from_secs(config.shutdown_timeout_secs);

    // Spawn enabled listeners as tokio tasks
    let mut task_handles = Vec::new();

    // Admin server (always on)
    {
        let admin_config = config.admin.clone();
        let state = AdminState {
            ready: Arc::clone(&ready),
        };
        let cancel = cancel.clone();
        task_handles.push(tokio::spawn(async move {
            if let Err(e) = admin::serve(&admin_config, state, cancel).await {
                tracing::error!(error = %e, "admin server failed");
            }
        }));
        tracing::info!("admin server task spawned");
    }

    // Reverse proxy (if enabled)
    if config.reverse_proxy.enabled {
        let config = config.clone();
        let scanner = Arc::clone(&scanner);
        let cancel = cancel.clone();
        task_handles.push(tokio::spawn(async move {
            if let Err(e) = reverse_proxy::serve(&config, scanner, cancel).await {
                tracing::error!(error = %e, "reverse proxy failed");
            }
        }));
        tracing::info!("reverse proxy task spawned");
    }

    // Forward proxy (if enabled) — not yet implemented
    if config.forward_proxy.enabled {
        tracing::warn!("forward proxy mode is enabled but not yet implemented");
    }

    // REST API (if enabled) — not yet implemented
    if config.rest_api.enabled {
        tracing::warn!("REST API mode is enabled but not yet implemented");
    }

    // Set readiness flag once all listeners are bound
    // The listeners bind inside their serve() calls. We give a brief moment
    // for them to bind, then set readiness. A more robust approach would use
    // per-listener readiness signals, but the current serve() functions bind
    // immediately on start.
    {
        let ready = Arc::clone(&ready);
        tokio::spawn(async move {
            // Small yield to let listener tasks bind their ports
            tokio::task::yield_now().await;
            ready.store(true, Ordering::Release);
            tracing::info!("readiness flag set");
        });
    }

    // Await shutdown signal (ctrl-c or SIGTERM)
    shutdown_signal().await;
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

    // Shutdown scanner pool — drain channel, join threads
    match Arc::try_unwrap(scanner) {
        Ok(mut pool) => pool.shutdown(),
        Err(_) => {
            tracing::warn!("scanner pool still referenced, dropping without explicit shutdown")
        }
    }

    tracing::info!("shutdown complete");
}

/// Wait for either ctrl-c or SIGTERM.
async fn shutdown_signal() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
}
