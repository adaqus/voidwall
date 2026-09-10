use std::collections::HashSet;
use std::path::{Path, PathBuf};

use clap::{ArgGroup, Parser};
use serde::Deserialize;

use crate::error::Error;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "voidwall",
    about = "AI guardrails engine — PII detection today"
)]
#[command(group(
    ArgGroup::new("mode")
        .required(true)
        .multiple(false)
        .args(["config", "validate"])
))]
pub struct Cli {
    /// Path to TOML configuration file (runs the proxy)
    #[arg(long = "config", env = "VOIDWALL_CONFIG")]
    pub config: Option<PathBuf>,

    /// Validate the config at the given path and exit without binding listeners
    #[arg(long = "validate")]
    pub validate: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub pii: PiiConfig,

    #[serde(default)]
    pub scan: ScanConfig,

    #[serde(default)]
    pub reverse_proxy: ReverseProxyConfig,

    #[serde(default)]
    pub forward_proxy: ForwardProxyConfig,

    #[serde(default)]
    pub http_api: HttpApiConfig,

    #[serde(default)]
    pub admin: AdminConfig,

    /// Seconds to wait for in-flight requests to drain during graceful shutdown.
    #[serde(default = "default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,
}

fn default_shutdown_timeout_secs() -> u64 {
    30
}

// ---------------------------------------------------------------------------
// PII scanner config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PiiConfig {
    #[serde(default)]
    pub countries: Vec<voidwall_pii::Country>,

    #[serde(default)]
    pub languages: Vec<voidwall_pii::Language>,

    #[serde(default)]
    pub scanner_threads: Option<usize>,

    #[serde(default)]
    pub detect: Option<Vec<voidwall_pii::PiiKind>>,

    #[serde(default)]
    pub ignore: Option<Vec<voidwall_pii::PiiKind>>,

    #[serde(default)]
    pub custom: Vec<voidwall_pii::UserPiiDefinition>,
}

/// Maximum number of `[[pii.custom]]` entries accepted at config load.
pub const MAX_CUSTOM_PII_ENTRIES: usize = 64;

impl PiiConfig {
    /// Effective number of scanner threads, applying the auto-detection logic.
    pub fn effective_scanner_threads(&self) -> usize {
        if let Some(n) = self.scanner_threads {
            return n;
        }
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        if cores <= 8 { cores.min(4) } else { cores / 2 }
    }
}

// ---------------------------------------------------------------------------
// Scan settings
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    #[serde(default = "default_content_types")]
    pub content_types: Vec<String>,

    #[serde(default = "default_true")]
    pub url_path: bool,

    #[serde(default = "default_true")]
    pub query_params: bool,

    #[serde(default)]
    pub headers: Vec<String>,

    #[serde(default = "default_true")]
    pub body: bool,

    #[serde(default = "default_on_error")]
    pub on_error: OnError,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_body_size: default_max_body_size(),
            content_types: default_content_types(),
            url_path: true,
            query_params: true,
            headers: Vec::new(),
            body: true,
            on_error: OnError::FailOpen,
        }
    }
}

fn default_max_body_size() -> usize {
    1_048_576
}

fn default_content_types() -> Vec<String> {
    vec![
        "application/json".into(),
        "text/plain".into(),
        "text/html".into(),
        "application/x-www-form-urlencoded".into(),
        "text/csv".into(),
        "application/csv".into(),
        "text/x-csv".into(),
        "text/tab-separated-values".into(),
        "text/tsv".into(),
    ]
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// On-error policy
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    FailOpen,
    FailClose,
}

fn default_on_error() -> OnError {
    OnError::FailOpen
}

// ---------------------------------------------------------------------------
// Direction config (per-direction scan switch)
// ---------------------------------------------------------------------------

/// Whether one direction of a proxy mode is inspected.
///
/// A detection blocks the message, so there is nothing else to configure here:
/// the only question a direction answers is whether it is looked at.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DirectionConfig {
    /// Inspect this direction. `false` disables the scan for it and leaves the
    /// other direction untouched.
    #[serde(default = "default_true")]
    pub scan: bool,
}

impl Default for DirectionConfig {
    fn default() -> Self {
        Self { scan: true }
    }
}

// ---------------------------------------------------------------------------
// Reverse proxy
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ReverseProxyConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_reverse_proxy_listen")]
    pub listen: String,

    #[serde(default)]
    pub request: DirectionConfig,

    #[serde(default)]
    pub response: DirectionConfig,

    #[serde(default)]
    pub tls: TlsConfig,

    #[serde(default)]
    pub routes: Vec<Route>,
}

impl Default for ReverseProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_reverse_proxy_listen(),
            request: DirectionConfig::default(),
            response: DirectionConfig::default(),
            tls: TlsConfig::default(),
            routes: Vec::new(),
        }
    }
}

fn default_reverse_proxy_listen() -> String {
    "0.0.0.0:8082".into()
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub path_prefix: String,
    pub upstream: String,
    pub scan: Option<ScanConfig>,
}

// ---------------------------------------------------------------------------
// Forward proxy
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ForwardProxyConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_forward_proxy_listen")]
    pub listen: String,

    #[serde(default)]
    pub request: DirectionConfig,

    #[serde(default)]
    pub response: DirectionConfig,

    #[serde(default)]
    pub tls: TlsConfig,
}

impl Default for ForwardProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_forward_proxy_listen(),
            request: DirectionConfig::default(),
            response: DirectionConfig::default(),
            tls: TlsConfig::default(),
        }
    }
}

fn default_forward_proxy_listen() -> String {
    "0.0.0.0:8084".into()
}

// ---------------------------------------------------------------------------
// HTTP API
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct HttpApiConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_http_api_listen")]
    pub listen: String,
}

fn default_http_api_listen() -> String {
    "0.0.0.0:8083".into()
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    #[serde(default = "default_admin_listen")]
    pub listen: String,

    #[serde(default = "default_metrics_path")]
    pub metrics_path: String,

    #[serde(default = "default_health_path")]
    pub health_path: String,

    #[serde(default = "default_ready_path")]
    pub ready_path: String,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen: default_admin_listen(),
            metrics_path: default_metrics_path(),
            health_path: default_health_path(),
            ready_path: default_ready_path(),
        }
    }
}

fn default_admin_listen() -> String {
    "127.0.0.1:9090".into()
}

fn default_metrics_path() -> String {
    "/metrics".into()
}

fn default_health_path() -> String {
    "/healthz".into()
}

fn default_ready_path() -> String {
    "/readyz".into()
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,

    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("failed to read config file: {e}")))?;
        let config: AppConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

impl AppConfig {
    pub fn validate(&self) -> Result<(), Error> {
        self.validate_at_least_one_mode()?;
        self.validate_no_port_conflicts()?;
        self.validate_scanner_threads()?;
        self.validate_pii_kinds_exclusivity()?;
        self.validate_custom_pii()?;
        self.validate_reverse_proxy()?;
        Ok(())
    }

    fn validate_at_least_one_mode(&self) -> Result<(), Error> {
        if !self.reverse_proxy.enabled && !self.forward_proxy.enabled && !self.http_api.enabled {
            return Err(Error::Config(
                "at least one mode must be enabled (reverse_proxy, forward_proxy, or http_api)"
                    .into(),
            ));
        }
        Ok(())
    }

    fn validate_no_port_conflicts(&self) -> Result<(), Error> {
        let mut listeners: Vec<(&str, &str)> = Vec::new();
        listeners.push(("admin", &self.admin.listen));
        if self.reverse_proxy.enabled {
            listeners.push(("reverse_proxy", &self.reverse_proxy.listen));
        }
        if self.forward_proxy.enabled {
            listeners.push(("forward_proxy", &self.forward_proxy.listen));
        }
        if self.http_api.enabled {
            listeners.push(("http_api", &self.http_api.listen));
        }

        for i in 0..listeners.len() {
            for j in (i + 1)..listeners.len() {
                if listeners[i].1 == listeners[j].1 {
                    return Err(Error::Config(format!(
                        "port conflict: {} and {} both listen on {}",
                        listeners[i].0, listeners[j].0, listeners[i].1,
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_scanner_threads(&self) -> Result<(), Error> {
        if let Some(n) = self.pii.scanner_threads
            && n < 1
        {
            return Err(Error::Config("scanner_threads must be >= 1".into()));
        }
        Ok(())
    }

    fn validate_pii_kinds_exclusivity(&self) -> Result<(), Error> {
        if self.pii.detect.is_some() && self.pii.ignore.is_some() {
            return Err(Error::Config(
                "detect and ignore are mutually exclusive".into(),
            ));
        }
        for (field, kinds) in [("detect", &self.pii.detect), ("ignore", &self.pii.ignore)] {
            if let Some(list) = kinds
                && list.contains(&voidwall_pii::PiiKind::Custom)
            {
                return Err(Error::Config(format!(
                    "{field}: 'Custom' is reserved for user-defined PII and cannot be listed here",
                )));
            }
        }
        Ok(())
    }

    fn validate_custom_pii(&self) -> Result<(), Error> {
        let custom = &self.pii.custom;
        if custom.len() > MAX_CUSTOM_PII_ENTRIES {
            return Err(Error::Config(format!(
                "pii.custom: too many entries ({}); max is {MAX_CUSTOM_PII_ENTRIES}",
                custom.len(),
            )));
        }

        let builtin_labels: HashSet<&'static str> = voidwall_pii::PiiKind::all()
            .iter()
            .map(|k| k.label())
            .collect();

        let mut seen: HashSet<&str> = HashSet::new();
        for entry in custom {
            if entry.label.is_empty() {
                return Err(Error::Config("pii.custom: label must be non-empty".into()));
            }
            if entry.pattern.is_empty() {
                return Err(Error::Config(format!(
                    "pii.custom: entry '{}' has empty pattern",
                    entry.label,
                )));
            }
            if builtin_labels.contains(entry.label.as_str()) {
                return Err(Error::Config(format!(
                    "pii.custom: label '{}' collides with a built-in PiiKind label",
                    entry.label,
                )));
            }
            if !seen.insert(entry.label.as_str()) {
                return Err(Error::Config(format!(
                    "pii.custom: duplicate label '{}'",
                    entry.label,
                )));
            }
        }
        Ok(())
    }

    fn validate_reverse_proxy(&self) -> Result<(), Error> {
        if !self.reverse_proxy.enabled {
            return Ok(());
        }

        let mut prefixes = HashSet::new();
        for route in &self.reverse_proxy.routes {
            if !prefixes.insert(&route.path_prefix) {
                return Err(Error::Config(format!(
                    "reverse_proxy: duplicate path_prefix '{}'",
                    route.path_prefix,
                )));
            }

            let uri = route.upstream.parse::<hyper::Uri>().map_err(|_| {
                Error::Config(format!(
                    "reverse_proxy: invalid upstream URL '{}'",
                    route.upstream,
                ))
            })?;
            let valid_scheme = uri
                .scheme_str()
                .is_some_and(|s| s == "http" || s == "https");
            if !valid_scheme || uri.authority().is_none() {
                return Err(Error::Config(format!(
                    "reverse_proxy: invalid upstream URL '{}'",
                    route.upstream,
                )));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    fn minimal_toml() -> String {
        r#"
[pii]
countries = ["Us"]
languages = ["En"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
scan = true

[forward_proxy.response]
scan = true
"#
        .into()
    }

    fn parse(toml_str: &str) -> Result<AppConfig, Error> {
        let config: AppConfig = toml::from_str(toml_str)?;
        config.validate()?;
        Ok(config)
    }

    // --- Valid configs ---

    #[test]
    fn valid_minimal() {
        parse(&minimal_toml()).expect("minimal config should be valid");
    }

    #[test]
    fn valid_all_modes_enabled() {
        let toml = r#"
[pii]
countries = ["Us"]
languages = ["En"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = true

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
scan = true

[forward_proxy.response]
scan = true

[http_api]
enabled = true
listen = "0.0.0.0:8083"
"#;
        parse(toml).expect("all-modes config should be valid");
    }

    #[test]
    fn valid_block_action() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = true

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"
"#;
        parse(toml).expect("block action should be valid");
    }

    #[test]
    fn valid_scan_false_disables_scanning() {
        let toml = r#"
[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
scan = false

[forward_proxy.response]
scan = false
"#;
        parse(toml).expect("scan = false should be valid");
    }

    #[test]
    fn valid_defaults_used_when_direction_omitted() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"
"#;
        let config = parse(toml).expect("defaults should apply");
        assert!(config.reverse_proxy.request.scan);
        assert!(config.reverse_proxy.response.scan);
    }

    #[test]
    fn valid_forward_proxy_defaults() {
        let toml = r#"
[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let config = parse(toml).expect("forward proxy defaults should apply");
        assert!(config.forward_proxy.request.scan);
        assert!(config.forward_proxy.response.scan);
    }

    // --- Invalid: at least one mode ---

    #[test]
    fn invalid_no_mode_enabled() {
        let toml = r#"
[pii]
countries = ["Us"]
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("at least one mode"));
    }

    // --- Invalid: port conflicts ---

    #[test]
    fn invalid_port_conflict() {
        let toml = r#"
[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:9090"

[forward_proxy.request]
scan = false

[forward_proxy.response]
scan = false

[admin]
listen = "0.0.0.0:9090"
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("port conflict"));
    }

    // --- Invalid: scanner_threads ---

    #[test]
    fn invalid_scanner_threads_zero() {
        let toml = r#"
[pii]
countries = ["Us"]
scanner_threads = 0

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
scan = false

[forward_proxy.response]
scan = false
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("scanner_threads"));
    }

    // --- Invalid: detect/ignore exclusivity ---

    #[test]
    fn invalid_detect_and_ignore() {
        let toml = r#"
[pii]
countries = ["Us"]
detect = ["Email"]
ignore = ["IpAddress"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
scan = false

[forward_proxy.response]
scan = false
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    // --- Invalid: block and header mutually exclusive ---

    // --- Invalid: header in wrong direction ---


    // --- Invalid: char strategy requires mask_char ---

    // --- Invalid: duplicate path prefix ---

    #[test]
    fn invalid_duplicate_path_prefix() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[reverse_proxy.request]
scan = false

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:9090"
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("duplicate path_prefix"));
    }

    // --- Invalid: bad upstream URL ---

    #[test]
    fn invalid_upstream_url() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[reverse_proxy.request]
scan = false

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "://broken"
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("invalid upstream URL"));
    }

    // --- Invalid: REST API char without mask ---

    // --- Default values ---

    #[test]
    fn defaults_scan_config() {
        let scan = ScanConfig::default();
        assert_eq!(scan.max_body_size, 1_048_576);
        assert!(scan.url_path);
        assert!(scan.query_params);
        assert!(scan.body);
        assert_eq!(scan.content_types.len(), 9);
        assert_eq!(scan.on_error, OnError::FailOpen);
    }

    #[test]
    fn defaults_admin_config() {
        let admin = AdminConfig::default();
        assert_eq!(admin.listen, "127.0.0.1:9090");
        assert_eq!(admin.metrics_path, "/metrics");
        assert_eq!(admin.health_path, "/healthz");
        assert_eq!(admin.ready_path, "/readyz");
    }

    #[test]
    fn defaults_on_error_in_scan() {
        let config = parse(&minimal_toml()).unwrap();
        assert_eq!(config.scan.on_error, OnError::FailOpen);
    }

    #[test]
    fn effective_scanner_threads_explicit() {
        let pii = PiiConfig {
            countries: vec![],
            languages: vec![],
            scanner_threads: Some(7),
            detect: None,
            ignore: None,
            custom: Vec::new(),
        };
        assert_eq!(pii.effective_scanner_threads(), 7);
    }

    #[test]
    fn effective_scanner_threads_auto() {
        let pii = PiiConfig {
            countries: vec![],
            languages: vec![],
            scanner_threads: None,
            detect: None,
            ignore: None,
            custom: Vec::new(),
        };
        let n = pii.effective_scanner_threads();
        assert!(n >= 1);
    }

    // --- Deserialization edge cases ---

    #[test]
    fn on_error_fail_close() {
        let toml = r#"
[pii]
countries = ["Us"]

[scan]
on_error = "fail_close"

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
scan = false

[forward_proxy.response]
scan = false
"#;
        let config = parse(toml).unwrap();
        assert_eq!(config.scan.on_error, OnError::FailClose);
    }

    // --- Unknown keys ---

    // --- Invalid: keys retired with the action layer ---
    //
    // These are the migration guarantee. An operator's old file names an
    // action, a redaction setting, or a block-response setting; each is now a
    // key the schema does not define, so startup stops and names it rather
    // than silently reinterpreting what the deployment does.

    #[test_case("actions = [\"redact\"]", "actions" ; "action list")]
    #[test_case("redact_strategy = \"type_label\"", "redact_strategy" ; "redaction strategy")]
    #[test_case("mask_char = \"*\"", "mask_char" ; "mask character")]
    #[test_case("block_status = 451", "block_status" ; "block status")]
    #[test_case("block_body = \"nope\"", "block_body" ; "block body")]
    #[test_case("block_headers = []", "block_headers" ; "block headers")]
    fn invalid_retired_direction_key_is_rejected(line: &str, key: &str) {
        let toml = format!(
            r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:18082"

[reverse_proxy.request]
{line}

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
"#
        );
        let err = parse(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains(key), "got: {msg}");
    }

    #[test]
    fn invalid_retired_http_api_redaction_key_is_rejected() {
        let toml = r#"
[pii]
countries = ["Us"]

[http_api]
enabled = true
listen = "0.0.0.0:18083"
redact_strategy = "type_label"
"#;
        let err = parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("redact_strategy"), "got: {msg}");
    }

    #[test]
    fn invalid_unknown_top_level_key_is_rejected() {
        let toml = r#"
shutdown_timeout_secs_typo = 30

[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
scan = false

[forward_proxy.response]
scan = false
"#;
        let err = parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("shutdown_timeout_secs_typo"), "got: {msg}");
    }

    #[test]
    fn invalid_retired_route_specialization_key_is_rejected() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[reverse_proxy.request]
scan = false

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/g/collect"
upstream = "http://localhost:8080"
specialization = "ga4"
"#;
        let err = parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("specialization"), "got: {msg}");
    }

    #[test]
    fn route_with_scan_override() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[reverse_proxy.request]
scan = false

[reverse_proxy.response]
scan = false

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"

[reverse_proxy.routes.scan]
body = true
url_path = false
query_params = false
"#;
        let config = parse(toml).unwrap();
        let scan = config.reverse_proxy.routes[0].scan.as_ref().unwrap();
        assert!(scan.body);
        assert!(!scan.url_path);
        assert!(!scan.query_params);
    }

    #[test]
    fn full_example_config() {
        let toml = r#"
[pii]
countries = ["International", "Us", "Gb"]
languages = ["En"]
scanner_threads = 4

[scan]
max_body_size = 1048576
content_types = ["application/json", "text/plain"]
url_path = true
query_params = true
headers = ["Authorization", "Cookie"]
body = true
on_error = "fail_open"

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[reverse_proxy.request]
scan = true

[reverse_proxy.response]
scan = true

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://backend-api:8080"

[[reverse_proxy.routes]]
path_prefix = "/payments"
upstream = "http://payments-svc:9090"

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
scan = true

[forward_proxy.response]
scan = true

[http_api]
enabled = true
listen = "0.0.0.0:8083"

[admin]
listen = "127.0.0.1:9090"
"#;
        let config = parse(toml).unwrap();
        assert!(config.reverse_proxy.enabled);
        assert!(config.forward_proxy.enabled);
        assert!(config.http_api.enabled);
        assert_eq!(config.reverse_proxy.routes.len(), 2);
        assert_eq!(config.pii.effective_scanner_threads(), 4);
    }

    #[test]
    fn detect_field_deserialization() {
        let toml = r#"
[pii]
countries = ["Us"]
detect = ["Email", "UsSsn"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
scan = false

[forward_proxy.response]
scan = false
"#;
        let config = parse(toml).unwrap();
        let detect = config.pii.detect.as_ref().unwrap();
        assert_eq!(detect.len(), 2);
    }

    // --- Custom PII definitions ---

    fn custom_pii_toml(body: &str) -> String {
        format!(
            r#"
[pii]
countries = ["Us", "International"]
{body}

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
scan = false

[forward_proxy.response]
scan = false
"#
        )
    }

    #[test]
    fn valid_custom_pii_entries() {
        let toml = custom_pii_toml(
            r#"
[[pii.custom]]
label = "EMPLOYEE_ID"
pattern = 'EMP-\d{6}'

[[pii.custom]]
label = "PROJECT_CODE"
pattern = '[A-Z]{3}-\d{3}'
keywords = ["project code", "proj id"]
country = "International"
"#,
        );
        let config = parse(&toml).expect("valid custom entries should parse");
        assert_eq!(config.pii.custom.len(), 2);
        assert_eq!(config.pii.custom[0].label, "EMPLOYEE_ID");
        assert_eq!(config.pii.custom[0].pattern, r"EMP-\d{6}");
        assert!(config.pii.custom[0].keywords.is_empty());
        assert_eq!(config.pii.custom[1].label, "PROJECT_CODE");
        assert_eq!(
            config.pii.custom[1].keywords,
            vec!["project code".to_string(), "proj id".to_string()]
        );
        assert_eq!(
            config.pii.custom[1].country,
            voidwall_pii::Country::International
        );
    }

    #[test]
    fn valid_custom_pii_defaults_to_empty() {
        let config = parse(&minimal_toml()).unwrap();
        assert!(config.pii.custom.is_empty());
    }

    #[test_case(
        r#"
[[pii.custom]]
label = ""
pattern = 'abc'
"#,
        "label must be non-empty"
        ; "empty label"
    )]
    #[test_case(
        r#"
[[pii.custom]]
label = "FOO"
pattern = ""
"#,
        "empty pattern"
        ; "empty pattern"
    )]
    #[test_case(
        r#"
[[pii.custom]]
label = "EMPLOYEE_ID"
pattern = 'EMP-\d{6}'

[[pii.custom]]
label = "EMPLOYEE_ID"
pattern = 'ID-\d+'
"#,
        "duplicate label"
        ; "duplicate label"
    )]
    #[test_case(
        r#"
[[pii.custom]]
label = "EMAIL"
pattern = 'foo@bar'
"#,
        "collides with a built-in PiiKind label"
        ; "builtin collision"
    )]
    fn invalid_custom_pii(body: &str, expected_msg: &str) {
        let toml = custom_pii_toml(body);
        let err = parse(&toml).unwrap_err();
        assert!(err.to_string().contains(expected_msg), "got: {err}");
    }

    #[test]
    fn invalid_custom_pii_cap_exceeded() {
        let mut entries = String::new();
        for i in 0..=MAX_CUSTOM_PII_ENTRIES {
            entries.push_str(&format!(
                "\n[[pii.custom]]\nlabel = \"LBL_{i}\"\npattern = 'x{i}'\n"
            ));
        }
        let toml = custom_pii_toml(&entries);
        let err = parse(&toml).unwrap_err();
        assert!(err.to_string().contains("too many entries"));
    }

    #[test_case("detect" ; "custom in detect")]
    #[test_case("ignore" ; "custom in ignore")]
    fn invalid_custom_in_kinds_list(field: &str) {
        let toml = format!(
            r#"
[pii]
countries = ["Us"]
{field} = ["Custom"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
scan = false

[forward_proxy.response]
scan = false
"#
        );
        let err = parse(&toml).unwrap_err();
        assert!(
            err.to_string().contains("'Custom' is reserved"),
            "got: {err}"
        );
    }

    #[test]
    fn ignore_field_deserialization() {
        let toml = r#"
[pii]
countries = ["Us"]
ignore = ["IpAddress"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
scan = false

[forward_proxy.response]
scan = false
"#;
        let config = parse(toml).unwrap();
        let ignore = config.pii.ignore.as_ref().unwrap();
        assert_eq!(ignore.len(), 1);
    }

    // --- CLI parsing ---

    #[test]
    fn cli_accepts_config_only() {
        let cli = Cli::try_parse_from(["voidwall", "--config", "config.toml"])
            .expect("--config alone must parse");
        assert_eq!(cli.config.as_deref(), Some(Path::new("config.toml")));
        assert!(cli.validate.is_none());
    }

    #[test]
    fn cli_accepts_validate_only() {
        let cli = Cli::try_parse_from(["voidwall", "--validate", "config.toml"])
            .expect("--validate alone must parse");
        assert_eq!(cli.validate.as_deref(), Some(Path::new("config.toml")));
        assert!(cli.config.is_none());
    }

    #[test]
    fn cli_rejects_both_flags() {
        let err = Cli::try_parse_from(["voidwall", "--config", "a.toml", "--validate", "b.toml"])
            .expect_err("--config and --validate must be mutually exclusive");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn cli_rejects_neither_flag() {
        // SAFETY: clear the env fallback so the group's `required=true`
        // actually fires; no other test reads VOIDWALL_CONFIG.
        unsafe {
            std::env::remove_var("VOIDWALL_CONFIG");
        }
        let err = Cli::try_parse_from(["voidwall"])
            .expect_err("at least one of --config / --validate is required");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }
}
