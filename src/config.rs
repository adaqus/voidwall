use std::collections::HashSet;
use std::path::{Path, PathBuf};

use clap::Parser;
use serde::Deserialize;

use crate::error::Error;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "pii-proxy", about = "PII-inspecting HTTP proxy")]
pub struct Cli {
    /// Path to TOML configuration file
    #[arg(long = "config", env = "PII_PROXY_CONFIG")]
    pub config: PathBuf,
}

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub pii: PiiConfig,

    #[serde(default)]
    pub scan: ScanConfig,

    #[serde(default = "default_on_error")]
    pub on_error: OnError,

    #[serde(default)]
    pub reverse_proxy: ReverseProxyConfig,

    #[serde(default)]
    pub forward_proxy: ForwardProxyConfig,

    #[serde(default)]
    pub rest_api: RestApiConfig,

    #[serde(default)]
    pub admin: AdminConfig,
}

// ---------------------------------------------------------------------------
// PII scanner config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PiiConfig {
    #[serde(default)]
    pub countries: Vec<pii::Country>,

    #[serde(default)]
    pub languages: Vec<pii::Language>,

    #[serde(default)]
    pub scanner_threads: Option<usize>,

    #[serde(default)]
    pub pii_kinds: Option<Vec<pii::PiiKind>>,

    #[serde(default)]
    pub exclude_pii_kinds: Option<Vec<pii::PiiKind>>,
}

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
pub struct ScanConfig {
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    #[serde(default = "default_content_types")]
    pub content_types: Vec<String>,

    #[serde(default = "default_true")]
    pub url: bool,

    #[serde(default = "default_true")]
    pub query_params: bool,

    #[serde(default)]
    pub headers: Vec<String>,

    #[serde(default = "default_true")]
    pub body: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_body_size: default_max_body_size(),
            content_types: default_content_types(),
            url: true,
            query_params: true,
            headers: Vec::new(),
            body: true,
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
// Actions & redact strategy
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Warn,
    Block,
    Header,
    Redact,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RedactStrategy {
    Char,
    TypeLabel,
}

// ---------------------------------------------------------------------------
// Reverse proxy
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct ReverseProxyConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_reverse_proxy_listen")]
    pub listen: String,

    #[serde(default)]
    pub tls: TlsConfig,

    #[serde(default)]
    pub routes: Vec<Route>,
}

fn default_reverse_proxy_listen() -> String {
    "0.0.0.0:8082".into()
}

#[derive(Debug, Deserialize)]
pub struct Route {
    pub path_prefix: String,
    pub upstream: String,
    #[serde(default)]
    pub actions: Vec<Action>,
    pub redact_strategy: Option<RedactStrategy>,
    pub mask_char: Option<char>,
    pub scan: Option<ScanConfig>,
}

// ---------------------------------------------------------------------------
// Forward proxy
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct ForwardProxyConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_forward_proxy_listen")]
    pub listen: String,

    #[serde(default)]
    pub actions: Vec<Action>,

    pub redact_strategy: Option<RedactStrategy>,
    pub mask_char: Option<char>,

    #[serde(default)]
    pub tls: TlsConfig,
}

fn default_forward_proxy_listen() -> String {
    "0.0.0.0:8084".into()
}

// ---------------------------------------------------------------------------
// REST API
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct RestApiConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_rest_api_listen")]
    pub listen: String,

    pub redact_strategy: Option<RedactStrategy>,
    pub mask_char: Option<char>,
}

fn default_rest_api_listen() -> String {
    "0.0.0.0:8083".into()
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize, Default)]
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
        self.validate_forward_proxy_actions()?;
        self.validate_rest_api_actions()?;
        self.validate_reverse_proxy_routes()?;
        Ok(())
    }

    fn validate_at_least_one_mode(&self) -> Result<(), Error> {
        if !self.reverse_proxy.enabled
            && !self.forward_proxy.enabled
            && !self.rest_api.enabled
        {
            return Err(Error::Config(
                "at least one mode must be enabled (reverse_proxy, forward_proxy, or rest_api)"
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
        if self.rest_api.enabled {
            listeners.push(("rest_api", &self.rest_api.listen));
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
            return Err(Error::Config(
                "scanner_threads must be >= 1".into(),
            ));
        }
        Ok(())
    }

    fn validate_pii_kinds_exclusivity(&self) -> Result<(), Error> {
        if self.pii.pii_kinds.is_some() && self.pii.exclude_pii_kinds.is_some() {
            return Err(Error::Config(
                "pii_kinds and exclude_pii_kinds are mutually exclusive".into(),
            ));
        }
        Ok(())
    }

    fn validate_forward_proxy_actions(&self) -> Result<(), Error> {
        if self.forward_proxy.enabled {
            validate_actions(
                &self.forward_proxy.actions,
                self.forward_proxy.redact_strategy,
                self.forward_proxy.mask_char,
                "forward_proxy",
            )?;
        }
        Ok(())
    }

    fn validate_rest_api_actions(&self) -> Result<(), Error> {
        if self.rest_api.enabled
            && let Some(RedactStrategy::Char) = self.rest_api.redact_strategy
            && self.rest_api.mask_char.is_none()
        {
            return Err(Error::Config(
                "rest_api: char redact strategy requires mask_char".into(),
            ));
        }
        Ok(())
    }

    fn validate_reverse_proxy_routes(&self) -> Result<(), Error> {
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

            let uri = route
                .upstream
                .parse::<hyper::Uri>()
                .map_err(|_| {
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

            validate_actions(
                &route.actions,
                route.redact_strategy,
                route.mask_char,
                &format!("reverse_proxy route '{}'", route.path_prefix),
            )?;
        }
        Ok(())
    }
}

/// Validate action combination rules shared by forward proxy and reverse proxy routes.
fn validate_actions(
    actions: &[Action],
    redact_strategy: Option<RedactStrategy>,
    mask_char: Option<char>,
    context: &str,
) -> Result<(), Error> {
    let set: HashSet<&Action> = actions.iter().collect();

    if set.contains(&Action::Header)
        && !set.contains(&Action::Warn)
        && !set.contains(&Action::Redact)
    {
        return Err(Error::Config(format!(
            "{context}: header action requires warn or redact",
        )));
    }

    if set.contains(&Action::Redact) && redact_strategy.is_none() {
        return Err(Error::Config(format!(
            "{context}: redact action requires redact_strategy",
        )));
    }

    if redact_strategy == Some(RedactStrategy::Char) && mask_char.is_none() {
        return Err(Error::Config(format!(
            "{context}: char redact strategy requires mask_char",
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_toml() -> String {
        r#"
[pii]
countries = ["Us"]
languages = ["En"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
actions = ["warn"]
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

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"
actions = ["warn"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
actions = ["warn"]

[rest_api]
enabled = true
listen = "0.0.0.0:8083"
"#;
        parse(toml).expect("all-modes config should be valid");
    }

    #[test]
    fn valid_redact_with_type_label() {
        let toml = r#"
[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
actions = ["redact"]
redact_strategy = "type_label"
"#;
        parse(toml).expect("redact with type_label should be valid");
    }

    #[test]
    fn valid_redact_with_char_and_mask() {
        let toml = r#"
[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
actions = ["redact"]
redact_strategy = "char"
mask_char = "*"
"#;
        parse(toml).expect("redact with char+mask should be valid");
    }

    #[test]
    fn valid_header_with_warn() {
        let toml = r#"
[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
actions = ["warn", "header"]
"#;
        parse(toml).expect("header with warn should be valid");
    }

    #[test]
    fn valid_header_with_redact() {
        let toml = r#"
[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
actions = ["redact", "header"]
redact_strategy = "type_label"
"#;
        parse(toml).expect("header with redact should be valid");
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
actions = ["warn"]

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
actions = ["warn"]
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("scanner_threads"));
    }

    // --- Invalid: pii_kinds exclusivity ---

    #[test]
    fn invalid_pii_kinds_and_exclude() {
        let toml = r#"
[pii]
countries = ["Us"]
pii_kinds = ["Email"]
exclude_pii_kinds = ["IpAddress"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
actions = ["warn"]
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    // --- Invalid: header requires warn or redact ---

    #[test]
    fn invalid_header_standalone() {
        let toml = r#"
[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
actions = ["header"]
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("header action requires warn or redact"));
    }

    // --- Invalid: redact requires strategy ---

    #[test]
    fn invalid_redact_without_strategy() {
        let toml = r#"
[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
actions = ["redact"]
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("redact action requires redact_strategy"));
    }

    // --- Invalid: char strategy requires mask_char ---

    #[test]
    fn invalid_char_without_mask() {
        let toml = r#"
[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
actions = ["redact"]
redact_strategy = "char"
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("char redact strategy requires mask_char"));
    }

    // --- Invalid: duplicate path prefix ---

    #[test]
    fn invalid_duplicate_path_prefix() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"
actions = ["warn"]

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:9090"
actions = ["warn"]
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

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "://broken"
actions = ["warn"]
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("invalid upstream URL"));
    }

    // --- Invalid: REST API char without mask ---

    #[test]
    fn invalid_rest_api_char_without_mask() {
        let toml = r#"
[pii]
countries = ["Us"]

[rest_api]
enabled = true
listen = "0.0.0.0:8083"
redact_strategy = "char"
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("char redact strategy requires mask_char"));
    }

    // --- Invalid: reverse proxy route actions ---

    #[test]
    fn invalid_route_header_standalone() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"
actions = ["header"]
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("header action requires warn or redact"));
    }

    #[test]
    fn invalid_route_redact_without_strategy() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"
actions = ["redact"]
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("redact action requires redact_strategy"));
    }

    // --- Default values ---

    #[test]
    fn defaults_scan_config() {
        let scan = ScanConfig::default();
        assert_eq!(scan.max_body_size, 1_048_576);
        assert!(scan.url);
        assert!(scan.query_params);
        assert!(scan.body);
        assert_eq!(scan.content_types.len(), 4);
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
    fn defaults_on_error() {
        let config = parse(&minimal_toml()).unwrap();
        assert_eq!(config.on_error, OnError::FailOpen);
    }

    #[test]
    fn effective_scanner_threads_explicit() {
        let pii = PiiConfig {
            countries: vec![],
            languages: vec![],
            scanner_threads: Some(7),
            pii_kinds: None,
            exclude_pii_kinds: None,
        };
        assert_eq!(pii.effective_scanner_threads(), 7);
    }

    #[test]
    fn effective_scanner_threads_auto() {
        let pii = PiiConfig {
            countries: vec![],
            languages: vec![],
            scanner_threads: None,
            pii_kinds: None,
            exclude_pii_kinds: None,
        };
        let n = pii.effective_scanner_threads();
        assert!(n >= 1);
    }

    // --- Deserialization edge cases ---

    #[test]
    fn on_error_fail_close() {
        let toml = r#"
on_error = "fail_close"

[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
actions = ["warn"]
"#;
        let config = parse(toml).unwrap();
        assert_eq!(config.on_error, OnError::FailClose);
    }

    #[test]
    fn route_with_scan_override() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"
actions = ["warn"]

[reverse_proxy.routes.scan]
body = true
url = false
query_params = false
"#;
        let config = parse(toml).unwrap();
        let scan = config.reverse_proxy.routes[0].scan.as_ref().unwrap();
        assert!(scan.body);
        assert!(!scan.url);
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
url = true
query_params = true
headers = ["Authorization", "Cookie"]
body = true

on_error = "fail_open"

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://backend-api:8080"
actions = ["warn", "header", "redact"]
redact_strategy = "type_label"

[[reverse_proxy.routes]]
path_prefix = "/payments"
upstream = "http://payments-svc:9090"
actions = ["block"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
actions = ["warn", "redact"]
redact_strategy = "type_label"

[rest_api]
enabled = true
listen = "0.0.0.0:8083"
redact_strategy = "type_label"

[admin]
listen = "127.0.0.1:9090"
"#;
        let config = parse(toml).unwrap();
        assert!(config.reverse_proxy.enabled);
        assert!(config.forward_proxy.enabled);
        assert!(config.rest_api.enabled);
        assert_eq!(config.reverse_proxy.routes.len(), 2);
        assert_eq!(config.pii.effective_scanner_threads(), 4);
    }
}
