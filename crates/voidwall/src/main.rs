#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::path::Path;

use clap::Parser;
use voidwall::config::{AppConfig, Cli};
use voidwall::engine::Engine;
use voidwall::{server, validate};
use voidwall_ml::OnnxRuntime;

/// Runs before every static constructor, including ONNX Runtime's, which use
/// x86-64-v3 instructions. A check in `main` would come too late: an older
/// CPU dies on an illegal instruction before `main` is reached.
///
/// Keep this in the binary crate. A shared library ignores `.preinit_array`,
/// and from a library crate the linker may drop the static without notice.
/// The function runs before std's own setup, so it uses only `cpuid`,
/// `eprintln!`, and `process::exit`.
#[used]
#[unsafe(link_section = ".preinit_array")]
static CPU_FLOOR_CHECK: extern "C" fn() = refuse_cpu_below_floor;

extern "C" fn refuse_cpu_below_floor() {
    let missing = voidwall_ml::cpu::missing_features();
    if !missing.is_empty() {
        eprintln!(
            "error: this CPU is below the minimum {}; missing features: {}",
            voidwall_ml::cpu::MIN_CPU_LEVEL,
            missing.join(", "),
        );
        std::process::exit(1);
    }
}

fn main() {
    let cli = Cli::parse();

    if let Some(path) = cli.validate.as_deref() {
        std::process::exit(run_validate(path));
    }

    let Some(config_path) = cli.config.clone() else {
        eprintln!(
            "error: --config <PATH> is required to run the proxy (or set VOIDWALL_CONFIG). \
             Use --validate <PATH> to check a config file without starting the proxy.",
        );
        std::process::exit(2);
    };
    run_server(config_path);
}

/// Validate-only code path. Loads and validates the config, builds a scanner
/// (exercising regex and vectorscan compilation) and discards it. Does not
/// initialize tracing, spawn threads, bind sockets, or build any clients.
fn run_validate(path: &Path) -> i32 {
    match validate::validate_config_file(path) {
        Ok(()) => {
            println!("config OK: {}", path.display());
            0
        }
        Err(e) => {
            eprintln!("config validation failed: {e}");
            1
        }
    }
}

#[tokio::main]
async fn run_server(config_path: std::path::PathBuf) {
    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Load and validate config
    let config = match AppConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to load configuration");
            std::process::exit(1);
        }
    };

    tracing::info!(config_path = %config_path.display(), "configuration loaded");

    // The process's one ONNX Runtime environment, for every model guard.
    let runtime = match OnnxRuntime::new() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "failed to initialize detection engine");
            std::process::exit(1);
        }
    };
    let build_engine = move |config: &AppConfig| Engine::from_config(&runtime, config);

    if let Err(e) = server::run(config, build_engine, shutdown_signal()).await {
        tracing::error!(error = %e, "failed to initialize detection engine");
        std::process::exit(1);
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
