//! Pre-flight config validation for the `--validate` CLI flag.
//!
//! Separates the four failure modes into distinct categories so operators
//! (and CI pipelines) can immediately see where the problem is.

use std::path::Path;

use crate::config::AppConfig;
use crate::error::Error;
use crate::scanner;

/// Category of a validation failure. Surfaced as a bracketed tag in the
/// diagnostic message — kept deliberately small so CI log scrapers can
/// pattern-match on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Config file could not be read from disk.
    File,
    /// TOML syntax error — file is not well-formed TOML.
    TomlParse,
    /// TOML is well-formed but does not match the expected schema
    /// (missing fields, unknown variants, wrong types).
    Schema,
    /// Semantic validation failed (`AppConfig::validate`).
    Semantic,
    /// Scanner construction failed (regex or vectorscan compilation).
    ScannerBuild,
}

impl Category {
    pub fn tag(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::TomlParse => "toml parse",
            Self::Schema => "schema",
            Self::Semantic => "semantic",
            Self::ScannerBuild => "scanner build",
        }
    }
}

/// A categorised validation failure with a human-readable message.
#[derive(Debug)]
pub struct ValidationError {
    pub category: Category,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.category.tag(), self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Run the full validation pipeline for a TOML config at `path`.
///
/// Each stage maps its native error to a `ValidationError` with the
/// appropriate category, preserving the original message as the body.
pub fn validate_config_file(path: &Path) -> Result<(), ValidationError> {
    // 1. File I/O.
    let content = std::fs::read_to_string(path).map_err(|e| ValidationError {
        category: Category::File,
        message: e.to_string(),
    })?;

    // 2. TOML syntax (target = `toml::Value`, so only the parse stage runs).
    let value: toml::Value = toml::from_str(&content).map_err(|e| ValidationError {
        category: Category::TomlParse,
        message: e.to_string(),
    })?;

    // 3. Schema (deserialization from the parsed AST into typed structs).
    let config: AppConfig = value
        .try_into()
        .map_err(|e: toml::de::Error| ValidationError {
            category: Category::Schema,
            message: e.to_string(),
        })?;

    // 4. Semantic validation.
    config.validate().map_err(|e| ValidationError {
        category: Category::Semantic,
        message: inner_message(&e),
    })?;

    // 5. Scanner build (regex + vectorscan compilation).
    scanner::validate_build(&config.pii).map_err(|e| ValidationError {
        category: Category::ScannerBuild,
        message: inner_message(&e),
    })?;

    Ok(())
}

/// Strip the "<variant>: " prefix that `Error`'s `Display` adds, so the
/// category tag we prepend isn't duplicated (e.g. avoid
/// `"[scanner build] scanner error: ..."`).
fn inner_message(err: &Error) -> String {
    match err {
        Error::Config(m) | Error::Scanner(m) | Error::Proxy(m) => m.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_tmp(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        f
    }

    fn valid_toml() -> &'static str {
        r#"
[pii]
countries = ["Us"]
languages = ["En"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

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
    }

    #[test]
    fn valid_config_returns_ok() {
        let f = write_tmp(valid_toml());
        validate_config_file(f.path()).expect("valid config should pass");
    }

    #[test]
    fn missing_file_categorised_as_file() {
        let err = validate_config_file(Path::new("/definitely/does/not/exist.toml"))
            .expect_err("missing file must fail");
        assert_eq!(err.category, Category::File);
        assert!(err.to_string().starts_with("[file]"), "got: {err}",);
    }

    #[test]
    fn toml_syntax_error_categorised_as_toml_parse() {
        let f = write_tmp("this is = not [ valid toml ][");
        let err = validate_config_file(f.path()).expect_err("bad toml must fail");
        assert_eq!(err.category, Category::TomlParse);
        assert!(err.to_string().starts_with("[toml parse]"), "got: {err}");
    }

    #[test]
    fn schema_error_categorised_as_schema() {
        // Well-formed TOML, but `actions` contains an unknown variant.
        let bad = r#"
[pii]
countries = ["Us"]
languages = ["En"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[reverse_proxy.request]
actions = ["nope"]

[reverse_proxy.response]
actions = []

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
        let f = write_tmp(bad);
        let err = validate_config_file(f.path()).expect_err("unknown action must fail");
        assert_eq!(err.category, Category::Schema);
        assert!(err.to_string().starts_with("[schema]"), "got: {err}");
    }

    #[test]
    fn semantic_error_categorised_as_semantic() {
        // Well-formed and well-typed, but `block` and `header` are mutually
        // exclusive in the same direction.
        let bad = r#"
[pii]
countries = ["Us"]
languages = ["En"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[reverse_proxy.request]
actions = ["block", "header"]

[reverse_proxy.response]
actions = []

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
        let f = write_tmp(bad);
        let err = validate_config_file(f.path()).expect_err("block+header must fail");
        assert_eq!(err.category, Category::Semantic);
        assert!(err.to_string().starts_with("[semantic]"), "got: {err}");
        assert!(
            err.message.contains("mutually exclusive"),
            "message should cite the semantic rule, got: {}",
            err.message,
        );
    }

    #[test]
    fn scanner_build_error_categorised_and_cites_label() {
        // An invalid regex in `[[pii.custom]]` must fail with the scanner
        // category and the failing entry's label in the message.
        let bad = r#"
[pii]
countries = ["Us"]
languages = ["En"]

[[pii.custom]]
label = "BAD_ENTRY"
pattern = "["

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[reverse_proxy.request]
actions = ["redact"]
redact_strategy = "type_label"

[reverse_proxy.response]
actions = []

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
        let f = write_tmp(bad);
        let err = validate_config_file(f.path()).expect_err("bad regex must fail");
        assert_eq!(err.category, Category::ScannerBuild);
        assert!(
            err.message.contains("BAD_ENTRY"),
            "scanner diagnostic must cite the offending label, got: {}",
            err.message,
        );
    }
}
