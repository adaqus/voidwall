//! Integration tests for the `--validate` CLI flag.
//!
//! Each test invokes the `voidwall` binary in validate mode, using a
//! temp-file config crafted for the specific failure (or success) case,
//! and asserts on the exit code, stderr tag, and stdout.

use std::net::TcpListener;
use std::process::Command;

use tempfile::NamedTempFile;

const BIN: &str = env!("CARGO_BIN_EXE_voidwall");

/// Minimal valid config template. The `{listen}` placeholder lets tests point
/// the reverse proxy at an ephemeral port so each case is self-contained.
fn valid_config_with_listen(listen: &str) -> String {
    format!(
        r#"
[builtin_guards.pii]
countries = ["Us"]
languages = ["En"]

[reverse_proxy]
enabled = true
listen = "{listen}"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = true

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#
    )
}

fn write_cfg(content: &str) -> NamedTempFile {
    use std::io::Write;
    let mut f = NamedTempFile::new().expect("tempfile");
    f.write_all(content.as_bytes()).expect("write");
    f.flush().expect("flush");
    f
}

fn run_validate(path: &std::path::Path) -> std::process::Output {
    Command::new(BIN)
        .arg("--validate")
        .arg(path)
        .env_remove("VOIDWALL_CONFIG")
        .output()
        .expect("spawn voidwall")
}

#[test]
fn valid_config_exits_zero() {
    let cfg = write_cfg(&valid_config_with_listen("127.0.0.1:18082"));
    let out = run_validate(cfg.path());
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("config OK"), "stdout was: {stdout}");
}

#[test]
fn missing_config_file_exits_non_zero_with_file_tag() {
    let out = Command::new(BIN)
        .arg("--validate")
        .arg("/definitely/does/not/exist.toml")
        .env_remove("VOIDWALL_CONFIG")
        .output()
        .expect("spawn voidwall");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[file]"), "stderr: {stderr}");
}

#[test]
fn invalid_toml_exits_non_zero_with_parse_tag() {
    let cfg = write_cfg("this is = not [ valid toml ][");
    let out = run_validate(cfg.path());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[toml parse]"), "stderr: {stderr}");
}

/// An operator's pre-change file names an action. The schema no longer defines
/// the key, so `--validate` refuses it and names it. This is the migration
/// guarantee: an old config stops the proxy rather than being reinterpreted.
#[test]
fn invalid_schema_retired_actions_key_exits_non_zero() {
    let bad = r#"
[builtin_guards.pii]
countries = ["Us"]
languages = ["En"]

[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[reverse_proxy.request]
actions = ["redact"]

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
    let cfg = write_cfg(bad);
    let out = run_validate(cfg.path());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[schema]"), "stderr: {stderr}");
    assert!(
        stderr.contains("actions"),
        "stderr should name the key: {stderr}"
    );
}

#[test]
fn detect_and_ignore_both_set_exits_non_zero() {
    let bad = r#"
[builtin_guards.pii]
countries = ["Us"]
languages = ["En"]
detect = ["Email"]
ignore = ["UsPhoneNumber"]

[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
    let cfg = write_cfg(bad);
    let out = run_validate(cfg.path());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[semantic]"), "stderr: {stderr}");
    assert!(stderr.contains("mutually exclusive"), "stderr: {stderr}",);
}

#[test]
fn custom_pii_bad_regex_exits_non_zero_and_cites_label() {
    let bad = r#"
[builtin_guards.pii]
countries = ["Us"]
languages = ["En"]

[[builtin_guards.pii.custom]]
label = "BAD_ENTRY"
pattern = "["

[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
    let cfg = write_cfg(bad);
    let out = run_validate(cfg.path());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[scanner build]"), "stderr: {stderr}");
    assert!(stderr.contains("BAD_ENTRY"), "stderr: {stderr}");
}

#[test]
fn custom_label_collides_with_builtin_exits_non_zero() {
    let bad = r#"
[builtin_guards.pii]
countries = ["Us"]
languages = ["En"]

[[builtin_guards.pii.custom]]
label = "EMAIL"
pattern = "foo"

[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
    let cfg = write_cfg(bad);
    let out = run_validate(cfg.path());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[semantic]"), "stderr: {stderr}");
    assert!(stderr.contains("EMAIL"), "stderr: {stderr}");
}

#[test]
fn custom_entries_over_cap_exits_non_zero() {
    // MAX_CUSTOM_PII_ENTRIES = 64; synthesize 65 entries.
    let mut entries = String::new();
    for i in 0..=64 {
        entries.push_str(&format!(
            "[[builtin_guards.pii.custom]]\nlabel = \"CUSTOM_{i}\"\npattern = \"x\"\n\n"
        ));
    }
    let bad = format!(
        r#"
[builtin_guards.pii]
countries = ["Us"]
languages = ["En"]

{entries}
[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#
    );
    let cfg = write_cfg(&bad);
    let out = run_validate(cfg.path());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[semantic]"), "stderr: {stderr}");
    assert!(stderr.contains("too many entries"), "stderr: {stderr}");
}

#[test]
fn custom_reserved_in_detect_exits_non_zero() {
    let bad = r#"
[builtin_guards.pii]
countries = ["Us"]
languages = ["En"]
detect = ["Custom"]

[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
    let cfg = write_cfg(bad);
    let out = run_validate(cfg.path());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[semantic]"), "stderr: {stderr}");
    assert!(
        stderr.contains("Custom") || stderr.contains("custom"),
        "stderr: {stderr}"
    );
}

#[test]
fn custom_reserved_in_ignore_exits_non_zero() {
    let bad = r#"
[builtin_guards.pii]
countries = ["Us"]
languages = ["En"]
ignore = ["Custom"]

[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
    let cfg = write_cfg(bad);
    let out = run_validate(cfg.path());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[semantic]"), "stderr: {stderr}");
    assert!(
        stderr.contains("Custom") || stderr.contains("custom"),
        "stderr: {stderr}"
    );
}

#[test]
fn validate_does_not_bind_configured_ports() {
    // Pre-bind the port that the config declares. If `--validate` tried to
    // start a listener it would fail; if it skips binding (as required),
    // validation still succeeds.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test port");
    let port = listener.local_addr().unwrap().port();
    let listen = format!("127.0.0.1:{port}");

    let cfg = write_cfg(&valid_config_with_listen(&listen));
    let out = run_validate(cfg.path());

    drop(listener); // keep the port occupied for the duration of the call

    assert!(
        out.status.success(),
        "validate should not bind listeners. stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn validate_and_config_cannot_be_combined() {
    let cfg = write_cfg(&valid_config_with_listen("127.0.0.1:18082"));
    let out = Command::new(BIN)
        .arg("--validate")
        .arg(cfg.path())
        .arg("--config")
        .arg(cfg.path())
        .env_remove("VOIDWALL_CONFIG")
        .output()
        .expect("spawn voidwall");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // clap emits usage diagnostics for mutually-exclusive ArgGroup members.
    assert!(
        stderr.contains("cannot be used with") || stderr.contains("error"),
        "stderr: {stderr}",
    );
}

#[test]
fn missing_both_args_prints_usage_error() {
    let out = Command::new(BIN)
        .env_remove("VOIDWALL_CONFIG")
        .output()
        .expect("spawn voidwall");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // clap's ArgGroup `required = true` surfaces as a usage error.
    assert!(
        stderr.contains("required") || stderr.contains("Usage"),
        "stderr: {stderr}",
    );
}

// ---------------------------------------------------------------------------
// Guard configuration
// ---------------------------------------------------------------------------

#[test]
fn unknown_built_in_guard_exits_non_zero_and_names_it() {
    let bad = r#"
[builtin_guards.pii]
countries = ["Us"]

[builtin_guards.jailbreak]
threshold = 0.5

[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
    let cfg = write_cfg(bad);
    let out = run_validate(cfg.path());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[semantic]"), "stderr: {stderr}");
    assert!(stderr.contains("jailbreak"), "stderr: {stderr}");
}

#[test]
fn route_naming_a_guard_that_is_not_enabled_exits_non_zero() {
    let bad = r#"
[builtin_guards.pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
guards = ["injection"]
"#;
    let cfg = write_cfg(bad);
    let out = run_validate(cfg.path());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[semantic]"), "stderr: {stderr}");
    assert!(stderr.contains("injection"), "stderr: {stderr}");
}

/// Enabling no guard is a deployment with nothing to inspect, not an invalid
/// config. It validates, and the proxy starts — see
/// `empty_guard_set_starts_and_warns` for what startup then does.
#[test]
fn a_config_enabling_no_guard_validates() {
    let toml = r#"
[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
    let cfg = write_cfg(toml);
    let out = run_validate(cfg.path());
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
}

// ---------------------------------------------------------------------------
// HTTP API route switches
// ---------------------------------------------------------------------------

#[test]
fn http_api_with_every_route_off_exits_non_zero_and_names_both_switches() {
    let bad = r#"
[builtin_guards.pii]
countries = ["Us"]

[http_api]
enabled = true
listen = "127.0.0.1:18083"

[http_api.scan]
enabled = false

[http_api.litellm]
enabled = false
"#;
    let cfg = write_cfg(bad);
    let out = run_validate(cfg.path());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[semantic]"), "stderr: {stderr}");
    assert!(stderr.contains("http_api.scan.enabled"), "stderr: {stderr}");
    assert!(
        stderr.contains("http_api.litellm.enabled"),
        "stderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// The old configuration format
// ---------------------------------------------------------------------------

/// A config written before this change names `pii` or `scan` at the top level.
/// Neither key exists now, so startup stops and names the offending key rather
/// than running with the old settings quietly ignored.
#[test]
fn a_config_in_the_old_format_is_rejected_at_startup() {
    for (section, key) in [
        ("[pii]\ncountries = [\"Us\"]", "pii"),
        ("[scan]\nbody = true\nmax_body_size = 2048", "scan"),
    ] {
        let bad = format!(
            r#"
{section}

[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#
        );
        let cfg = write_cfg(&bad);

        // `--validate` is the same load path the proxy runs at startup.
        let out = run_validate(cfg.path());
        assert!(!out.status.success(), "`{key}` must stop the start");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("[schema]"), "stderr: {stderr}");
        assert!(
            stderr.contains("unknown field") && stderr.contains(key),
            "the failure must name `{key}`, got: {stderr}",
        );

        // And the proxy itself refuses to run, with the same diagnostic. It
        // has a tracing subscriber by then, so the message goes to the log
        // stream rather than to stderr directly.
        let out = Command::new(BIN)
            .arg("--config")
            .arg(cfg.path())
            .env_remove("VOIDWALL_CONFIG")
            .output()
            .expect("spawn voidwall");
        assert!(!out.status.success(), "`{key}` must stop the start");
        let logs = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        assert!(logs.contains(key), "the failure must name `{key}`: {logs}");
    }
}

/// `--validate` stays offline: a model guard whose model file exists but is
/// not ONNX passes, because validation never loads a model.
#[test]
fn validate_does_not_load_a_model() {
    let artifact = write_cfg("not an onnx model");
    let cfg = write_cfg(&format!(
        r#"
[guards.injection]
adapter = "text_classifier"
model_path = "{path}"
tokenizer_path = "{path}"
max_tokens = 512
labels = ["PROMPT_INJECTION"]

[guards.injection.thresholds]
PROMPT_INJECTION = 0.90

[http_api]
enabled = true
listen = "127.0.0.1:18083"
"#,
        path = artifact.path().display(),
    ));
    let out = run_validate(cfg.path());
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}
