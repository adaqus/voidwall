//! Integration tests for the `--version` and `--print-config` CLI flags.
//!
//! Each test invokes the `voidwall` binary and asserts on the exit code,
//! stdout, and stderr. Neither flag loads a config, a model, or a listener.

use std::io::Write;
use std::process::{Command, Output};

use tempfile::NamedTempFile;

const BIN: &str = env!("CARGO_BIN_EXE_voidwall");

fn write_file(content: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tempfile");
    f.write_all(content).expect("write");
    f.flush().expect("flush");
    f
}

fn run(args: &[&std::ffi::OsStr], env_config: Option<&std::path::Path>) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args).env_remove("VOIDWALL_CONFIG");
    if let Some(path) = env_config {
        cmd.env("VOIDWALL_CONFIG", path);
    }
    cmd.output().expect("spawn voidwall")
}

#[test]
fn version_prints_the_workspace_version_without_a_config() {
    let out = run(&["--version".as_ref()], None);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim_end(),
        concat!("voidwall ", env!("CARGO_PKG_VERSION")),
    );
}

#[test]
fn print_config_writes_a_commented_file_byte_for_byte() {
    let content = b"# a comment the operator keeps\n[http_api]\nenabled = true # trailing\n\n# [[reverse_proxy.routes]]\n";
    let file = write_file(content);
    let out = run(&["--print-config".as_ref()], Some(file.path()));
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, content);
}

#[test]
fn print_config_writes_a_file_that_is_not_toml_byte_for_byte() {
    let content = b"this is = not [ valid toml ][\n\xff\xfe";
    let file = write_file(content);
    let out = run(
        &[
            "--config".as_ref(),
            file.path().as_os_str(),
            "--print-config".as_ref(),
        ],
        None,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, content);
}

#[test]
fn print_config_names_the_path_of_a_missing_file() {
    let missing = "/definitely/does/not/exist.toml";
    let out = run(
        &[
            "--config".as_ref(),
            missing.as_ref(),
            "--print-config".as_ref(),
        ],
        None,
    );
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(missing), "stderr: {stderr}");
}

#[test]
fn print_config_with_no_path_is_a_usage_error() {
    let out = run(&["--print-config".as_ref()], None);
    assert_eq!(out.status.code(), Some(2));
}
