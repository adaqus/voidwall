#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::io::Write;
use std::path::Path;

use clap::{CommandFactory, FromArgMatches};
use voidwall::config::{self, AppConfig, Cli, Mode};
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
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    let mode = config::mode(&cli, matches.value_source("config")).unwrap_or_else(|e| e.exit());

    match mode {
        Mode::PrintConfig(path) => std::process::exit(run_print_config(&path)),
        Mode::Validate(path) => std::process::exit(run_validate(&path)),
        Mode::Run(path) => run_server(path),
    }
}

/// Writes the config file to stdout as it is on disk, comments included.
/// Does not parse or validate it, and runs before any load, tracing setup, or
/// runtime start.
fn run_print_config(path: &Path) -> i32 {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read config file {}: {e}", path.display());
            return 1;
        }
    };
    let mut stdout = std::io::stdout().lock();
    if let Err(e) = stdout.write_all(&bytes).and_then(|()| stdout.flush()) {
        eprintln!("cannot write config file {} to stdout: {e}", path.display());
        return 1;
    }
    0
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
            tracing::error!(error = %e, "failed to start");
            std::process::exit(1);
        }
    };
    let build_engine = move |config: &AppConfig| Engine::from_config(&runtime, config);

    if let Err(e) = server::run(config, build_engine, shutdown_signal()).await {
        tracing::error!(error = %e, "failed to start");
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
