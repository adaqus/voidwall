//! Integration tests for the `--validate` CLI flag.
//!
//! Each test invokes the `pii-proxy` binary in validate mode, using a
//! temp-file config crafted for the specific failure (or success) case,
//! and asserts on the exit code, stderr tag, and stdout.

use std::net::TcpListener;
use std::process::Command;

use tempfile::NamedTempFile;

const BIN: &str = env!("CARGO_BIN_EXE_pii-proxy");

/// Minimal valid config template. The `{listen}` placeholder lets tests point
/// the reverse proxy at an ephemeral port so each case is self-contained.
fn valid_config_with_listen(listen: &str) -> String {
    format!(
        r#"
[pii]
countries = ["Us"]
languages = ["En"]

[reverse_proxy]
enabled = true
listen = "{listen}"

[reverse_proxy.request]
actions = ["redact"]
redact_strategy = "type_label"

[reverse_proxy.response]
actions = ["redact"]
redact_strategy = "type_label"

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
        .env_remove("PII_PROXY_CONFIG")
        .output()
        .expect("spawn pii-proxy")
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
        .env_remove("PII_PROXY_CONFIG")
        .output()
        .expect("spawn pii-proxy");
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

#[test]
fn invalid_schema_unknown_action_exits_non_zero() {
    let bad = r#"
[pii]
countries = ["Us"]
languages = ["En"]

[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[reverse_proxy.request]
actions = ["nope"]

[reverse_proxy.response]
actions = []

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
    let cfg = write_cfg(bad);
    let out = run_validate(cfg.path());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[schema]"), "stderr: {stderr}");
}

#[test]
fn detect_and_ignore_both_set_exits_non_zero() {
    let bad = r#"
[pii]
countries = ["Us"]
languages = ["En"]
detect = ["Email"]
ignore = ["PhoneNumber"]

[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[reverse_proxy.request]
actions = ["redact"]
redact_strategy = "type_label"

[reverse_proxy.response]
actions = []

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
[pii]
countries = ["Us"]
languages = ["En"]

[[pii.custom]]
label = "BAD_ENTRY"
pattern = "["

[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[reverse_proxy.request]
actions = ["redact"]
redact_strategy = "type_label"

[reverse_proxy.response]
actions = []

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
[pii]
countries = ["Us"]
languages = ["En"]

[[pii.custom]]
label = "EMAIL"
pattern = "foo"

[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[reverse_proxy.request]
actions = ["redact"]
redact_strategy = "type_label"

[reverse_proxy.response]
actions = []

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
            "[[pii.custom]]\nlabel = \"CUSTOM_{i}\"\npattern = \"x\"\n\n"
        ));
    }
    let bad = format!(
        r#"
[pii]
countries = ["Us"]
languages = ["En"]

{entries}
[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[reverse_proxy.request]
actions = ["redact"]
redact_strategy = "type_label"

[reverse_proxy.response]
actions = []

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
[pii]
countries = ["Us"]
languages = ["En"]
detect = ["Custom"]

[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[reverse_proxy.request]
actions = ["redact"]
redact_strategy = "type_label"

[reverse_proxy.response]
actions = []

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
[pii]
countries = ["Us"]
languages = ["En"]
ignore = ["Custom"]

[reverse_proxy]
enabled = true
listen = "127.0.0.1:18082"

[reverse_proxy.request]
actions = ["redact"]
redact_strategy = "type_label"

[reverse_proxy.response]
actions = []

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
        .env_remove("PII_PROXY_CONFIG")
        .output()
        .expect("spawn pii-proxy");
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
        .env_remove("PII_PROXY_CONFIG")
        .output()
        .expect("spawn pii-proxy");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // clap's ArgGroup `required = true` surfaces as a usage error.
    assert!(
        stderr.contains("required") || stderr.contains("Usage"),
        "stderr: {stderr}",
    );
}
