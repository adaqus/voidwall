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

    // 5. Model guard artifacts. Held apart from step 4 because a missing file
    //    is a `file` failure, and because it is the only check that touches the
    //    filesystem. It does not open what it finds.
    config
        .validate_model_guard_artifacts()
        .map_err(|e| ValidationError {
            category: Category::File,
            message: inner_message(&e),
        })?;

    // 6. Scanner build (regex + vectorscan compilation). A guard section that
    //    is absent or disabled builds nothing, so there is nothing to compile.
    if let Some(pii) = config.builtin_guards.enabled_pii() {
        scanner::validate_build(pii).map_err(|e| ValidationError {
            category: Category::ScannerBuild,
            message: inner_message(&e),
        })?;
    }

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
[builtin_guards.pii]
countries = ["Us"]
languages = ["En"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = true

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
        // Well-formed TOML, but `actions` is a retired key that the schema
        // no longer defines. This doubles as the migration guarantee.
        let bad = r#"
[builtin_guards.pii]
countries = ["Us"]
languages = ["En"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[reverse_proxy.request]
actions = ["redact"]

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
        let f = write_tmp(bad);
        let err = validate_config_file(f.path()).expect_err("retired actions key must fail");
        assert_eq!(err.category, Category::Schema);
        assert!(err.to_string().starts_with("[schema]"), "got: {err}");
    }

    #[test]
    fn an_upstream_timeout_outside_the_range_is_schema_and_names_the_key() {
        let f = write_tmp(&format!("upstream_timeout_secs = 3601\n{}", valid_toml()));
        let err = validate_config_file(f.path()).expect_err("3601 is above the bound");
        assert_eq!(err.category, Category::Schema);
        assert!(
            err.to_string().contains("upstream_timeout_secs"),
            "got: {err}"
        );
    }

    #[test]
    fn semantic_error_categorised_as_semantic() {
        // Well-formed and well-typed, but two routes claim the same prefix.
        // This is the surviving semantic rule on the reverse proxy.
        let bad = r#"
[builtin_guards.pii]
countries = ["Us"]
languages = ["En"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9001"
"#;
        let f = write_tmp(bad);
        let err = validate_config_file(f.path()).expect_err("duplicate prefix must fail");
        assert_eq!(err.category, Category::Semantic);
        assert!(err.to_string().starts_with("[semantic]"), "got: {err}");
        assert!(
            err.message.contains("duplicate path_prefix"),
            "message should cite the semantic rule, got: {}",
            err.message,
        );
    }

    #[test]
    fn scanner_build_error_categorised_and_cites_label() {
        // An invalid regex in `[[builtin_guards.pii.custom]]` must fail with
        // the scanner category and the failing entry's label in the message.
        let bad = r#"
[builtin_guards.pii]
countries = ["Us"]
languages = ["En"]

[[builtin_guards.pii.custom]]
label = "BAD_ENTRY"
pattern = "["

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = false

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

    /// A guard the build does not have is well-typed TOML asking for something
    /// that does not exist, so it is semantic rather than schema — and the
    /// diagnostic names it.
    #[test]
    fn unknown_built_in_guard_is_semantic_and_names_the_guard() {
        let bad = r#"
[builtin_guards.pii]
countries = ["Us"]

[builtin_guards.jailbreak]
threshold = 0.5

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
        let f = write_tmp(bad);
        let err = validate_config_file(f.path()).expect_err("unknown guard must fail");
        assert_eq!(err.category, Category::Semantic);
        assert!(err.message.contains("jailbreak"), "got: {}", err.message);
    }

    #[test]
    fn a_route_naming_an_unknown_guard_is_semantic_and_names_it() {
        let bad = r#"
[builtin_guards.pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
guards = ["injection"]
"#;
        let f = write_tmp(bad);
        let err = validate_config_file(f.path()).expect_err("unknown route guard must fail");
        assert_eq!(err.category, Category::Semantic);
        assert!(err.message.contains("injection"), "got: {}", err.message);
    }

    /// A reserved name is rejected through the same semantic stage. The
    /// configured-guard section does not exist yet, so the rule is exercised
    /// directly here — this is the stage that categorises it.
    #[test]
    fn a_reserved_guard_name_is_semantic_and_names_the_guard() {
        let err = crate::config::validate_configured_guard_name("pii")
            .map_err(|e| ValidationError {
                category: Category::Semantic,
                message: inner_message(&e),
            })
            .expect_err("`pii` is reserved for the built-in guard");
        assert_eq!(err.category, Category::Semantic);
        assert!(err.message.contains("pii"), "got: {}", err.message);
        assert!(err.message.contains("reserved"), "got: {}", err.message);
    }

    /// Enabling no guard is a deployment with nothing to inspect, not a config
    /// the proxy cannot honour. It starts.
    #[test]
    fn a_config_enabling_no_guard_still_validates() {
        let toml = r#"
[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
        let f = write_tmp(toml);
        validate_config_file(f.path()).expect("no guard is valid, and warns at startup");
    }

    /// A model guard is well-typed TOML asking for something the rules reject,
    /// so it is semantic — the same stage a duplicate prefix lands in.
    #[test]
    fn a_model_guard_rule_failure_is_semantic_and_names_the_guard() {
        let bad = r#"
[builtin_guards.pii]
countries = ["Us"]

[guards.injection]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["PROMPT_INJECTION"]

[guards.injection.thresholds]
PROMPT_INJECTION = 1.4

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
        let f = write_tmp(bad);
        let err = validate_config_file(f.path()).expect_err("out-of-range threshold must fail");
        assert_eq!(err.category, Category::Semantic);
        assert!(err.message.contains("injection"), "got: {}", err.message);
        assert!(err.message.contains("0..=1"), "got: {}", err.message);
    }

    /// The multilabel adapter deserialises, because the schema knows its
    /// name, and a rule rejects it: its run side is not built.
    #[test]
    fn the_multilabel_adapter_is_semantic_and_names_the_guard() {
        let bad = r#"
[builtin_guards.pii]
countries = ["Us"]

[guards.safety]
adapter = "text_multilabel_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["PROMPT_INJECTION", "HATE_SPEECH"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
        let f = write_tmp(bad);
        let err = validate_config_file(f.path()).expect_err("the multilabel adapter must fail");
        assert_eq!(err.category, Category::Semantic);
        assert!(err.message.contains("safety"), "got: {}", err.message);
        assert!(err.message.contains("not built"), "got: {}", err.message);
    }

    /// A guard name outside the charset reaches the same stage, through the
    /// caller `[guards.<name>]` finally gave `validate_configured_guard_name`.
    #[test]
    fn a_model_guard_name_outside_the_charset_is_semantic_and_names_the_guard() {
        let bad = r#"
[builtin_guards.pii]
countries = ["Us"]

[guards."inj.v2"]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["PROMPT_INJECTION"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
        let f = write_tmp(bad);
        let err = validate_config_file(f.path()).expect_err("a dotted guard name must fail");
        assert_eq!(err.category, Category::Semantic);
        assert!(err.message.contains("inj.v2"), "got: {}", err.message);
    }

    /// The build fixes the adapter names, so the schema states the set and an
    /// unknown one never reaches a rule.
    #[test]
    fn an_unknown_adapter_is_schema_and_names_the_value() {
        let bad = r#"
[builtin_guards.pii]
countries = ["Us"]

[guards.injection]
adapter = "tea_leaves"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["PROMPT_INJECTION"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#;
        let f = write_tmp(bad);
        let err = validate_config_file(f.path()).expect_err("an unknown adapter must fail");
        assert_eq!(err.category, Category::Schema);
        assert!(err.message.contains("tea_leaves"), "got: {}", err.message);
        assert!(
            err.message.contains("text_classifier"),
            "must list what the build ships, got: {}",
            err.message,
        );
    }

    /// A missing artifact is a property of the deployment rather than of the
    /// file, so it carries the `file` category and names the path.
    #[test]
    fn a_missing_model_artifact_is_file_and_names_the_expected_path() {
        let missing = "/definitely/does/not/exist/tokenizer.json";
        let bad = format!(
            r#"
[builtin_guards.pii]
countries = ["Us"]

[guards.injection]
adapter = "text_classifier"
model_path = "{missing}"
tokenizer_path = "{missing}"
max_tokens = 512
labels = ["PROMPT_INJECTION"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#
        );
        let f = write_tmp(&bad);
        let err = validate_config_file(f.path()).expect_err("a missing artifact must fail");
        assert_eq!(err.category, Category::File);
        assert!(err.to_string().starts_with("[file]"), "got: {err}");
        assert!(err.message.contains(missing), "got: {}", err.message);
        assert!(err.message.contains("injection"), "got: {}", err.message);
    }

    /// The whole pipeline over a model guard whose artifacts are present but
    /// hold nothing a model runtime would accept. Validation never opens them.
    #[test]
    fn a_model_guard_whose_artifacts_exist_passes_every_stage() {
        let artifact = write_tmp("not an onnx model");
        let good = format!(
            r#"
[builtin_guards.pii]
countries = ["Us"]

[guards.injection]
adapter = "text_classifier"
model_path = "{path}"
tokenizer_path = "{path}"
max_tokens = 512
labels = ["PROMPT_INJECTION"]

[guards.injection.thresholds]
PROMPT_INJECTION = 0.90

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
guards = ["pii", "injection"]
"#,
            path = artifact.path().display(),
        );
        let f = write_tmp(&good);
        validate_config_file(f.path()).expect("a configured model guard is valid");
    }
}
