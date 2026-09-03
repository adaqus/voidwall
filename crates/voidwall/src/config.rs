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
// Actions & redact strategy
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Action {
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
// Direction config (request/response action settings)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct DirectionConfig {
    #[serde(default)]
    pub actions: Vec<Action>,

    pub redact_strategy: Option<RedactStrategy>,
    pub mask_char: Option<char>,

    #[serde(default = "default_block_status")]
    pub block_status: u16,

    pub block_body: Option<String>,

    #[serde(default)]
    pub block_headers: Vec<(String, String)>,
}

fn default_block_status() -> u16 {
    403
}

impl DirectionConfig {
    fn with_actions(actions: Vec<Action>, redact_strategy: Option<RedactStrategy>) -> Self {
        Self {
            actions,
            redact_strategy,
            mask_char: None,
            block_status: default_block_status(),
            block_body: None,
            block_headers: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Reverse proxy
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct ReverseProxyConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_reverse_proxy_listen")]
    pub listen: String,

    #[serde(default = "default_reverse_proxy_request")]
    pub request: DirectionConfig,

    #[serde(default = "default_reverse_proxy_response")]
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
            request: default_reverse_proxy_request(),
            response: default_reverse_proxy_response(),
            tls: TlsConfig::default(),
            routes: Vec::new(),
        }
    }
}

fn default_reverse_proxy_listen() -> String {
    "0.0.0.0:8082".into()
}

fn default_reverse_proxy_request() -> DirectionConfig {
    DirectionConfig::with_actions(
        vec![Action::Redact, Action::Header],
        Some(RedactStrategy::TypeLabel),
    )
}

fn default_reverse_proxy_response() -> DirectionConfig {
    DirectionConfig::with_actions(vec![Action::Redact], Some(RedactStrategy::TypeLabel))
}

#[derive(Debug, Deserialize, Clone)]
pub struct Route {
    pub path_prefix: String,
    pub upstream: String,
    pub scan: Option<ScanConfig>,

    /// Optional specialization name (e.g. `"ga4"`, `"matomo"`). When set,
    /// the named specialization owns query+body decoding for this route.
    /// Resolved against [`crate::specialization::lookup`] at startup; an
    /// unknown name fails validation.
    pub specialization: Option<String>,
}

// ---------------------------------------------------------------------------
// Forward proxy
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct ForwardProxyConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_forward_proxy_listen")]
    pub listen: String,

    #[serde(default = "default_forward_proxy_request")]
    pub request: DirectionConfig,

    #[serde(default = "default_forward_proxy_response")]
    pub response: DirectionConfig,

    #[serde(default)]
    pub tls: TlsConfig,
}

impl Default for ForwardProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_forward_proxy_listen(),
            request: default_forward_proxy_request(),
            response: default_forward_proxy_response(),
            tls: TlsConfig::default(),
        }
    }
}

fn default_forward_proxy_listen() -> String {
    "0.0.0.0:8084".into()
}

fn default_forward_proxy_request() -> DirectionConfig {
    DirectionConfig::with_actions(vec![Action::Redact], Some(RedactStrategy::TypeLabel))
}

fn default_forward_proxy_response() -> DirectionConfig {
    DirectionConfig::with_actions(
        vec![Action::Redact, Action::Header],
        Some(RedactStrategy::TypeLabel),
    )
}

// ---------------------------------------------------------------------------
// HTTP API
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default, Clone)]
pub struct HttpApiConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_http_api_listen")]
    pub listen: String,

    pub redact_strategy: Option<RedactStrategy>,
    pub mask_char: Option<char>,
}

fn default_http_api_listen() -> String {
    "0.0.0.0:8083".into()
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
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

/// Allowed positions for the `header` action.
enum DirectionKind {
    ReverseProxyRequest,
    ReverseProxyResponse,
    ForwardProxyRequest,
    ForwardProxyResponse,
}

impl AppConfig {
    pub fn validate(&self) -> Result<(), Error> {
        self.validate_at_least_one_mode()?;
        self.validate_no_port_conflicts()?;
        self.validate_scanner_threads()?;
        self.validate_pii_kinds_exclusivity()?;
        self.validate_custom_pii()?;
        self.validate_reverse_proxy()?;
        self.validate_forward_proxy()?;
        self.validate_http_api()?;
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

        validate_direction_config(
            &self.reverse_proxy.request,
            DirectionKind::ReverseProxyRequest,
            "reverse_proxy.request",
        )?;
        validate_direction_config(
            &self.reverse_proxy.response,
            DirectionKind::ReverseProxyResponse,
            "reverse_proxy.response",
        )?;

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

            if let Some(name) = &route.specialization
                && crate::specialization::lookup(name).is_none()
            {
                return Err(Error::Config(format!(
                    "reverse_proxy: route '{}' references unknown specialization '{}'",
                    route.path_prefix, name,
                )));
            }
        }
        Ok(())
    }

    fn validate_forward_proxy(&self) -> Result<(), Error> {
        if !self.forward_proxy.enabled {
            return Ok(());
        }

        validate_direction_config(
            &self.forward_proxy.request,
            DirectionKind::ForwardProxyRequest,
            "forward_proxy.request",
        )?;
        validate_direction_config(
            &self.forward_proxy.response,
            DirectionKind::ForwardProxyResponse,
            "forward_proxy.response",
        )?;
        Ok(())
    }

    fn validate_http_api(&self) -> Result<(), Error> {
        if !self.http_api.enabled {
            return Ok(());
        }

        if let Some(RedactStrategy::Char) = self.http_api.redact_strategy
            && self.http_api.mask_char.is_none()
        {
            return Err(Error::Config(
                "http_api: char redact strategy requires mask_char".into(),
            ));
        }
        Ok(())
    }
}

/// Validate a direction config (request or response action set).
fn validate_direction_config(
    config: &DirectionConfig,
    kind: DirectionKind,
    context: &str,
) -> Result<(), Error> {
    let set: HashSet<&Action> = config.actions.iter().collect();

    // block and header are mutually exclusive
    if set.contains(&Action::Block) && set.contains(&Action::Header) {
        return Err(Error::Config(format!(
            "{context}: block and header are mutually exclusive",
        )));
    }

    // header is only valid in reverse_proxy.request and forward_proxy.response
    if set.contains(&Action::Header) {
        match kind {
            DirectionKind::ReverseProxyRequest | DirectionKind::ForwardProxyResponse => {}
            _ => {
                return Err(Error::Config(format!(
                    "{context}: header action is not valid in this direction",
                )));
            }
        }
    }

    // redact requires redact_strategy
    if set.contains(&Action::Redact) && config.redact_strategy.is_none() {
        return Err(Error::Config(format!(
            "{context}: redact action requires redact_strategy",
        )));
    }

    // char strategy requires mask_char
    if config.redact_strategy == Some(RedactStrategy::Char) && config.mask_char.is_none() {
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
actions = ["redact"]
redact_strategy = "type_label"

[forward_proxy.response]
actions = ["redact", "header"]
redact_strategy = "type_label"
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
actions = ["redact", "header"]
redact_strategy = "type_label"

[reverse_proxy.response]
actions = ["redact"]
redact_strategy = "type_label"

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
actions = ["redact"]
redact_strategy = "type_label"

[forward_proxy.response]
actions = ["redact", "header"]
redact_strategy = "type_label"

[http_api]
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

[forward_proxy.request]
actions = ["redact"]
redact_strategy = "type_label"

[forward_proxy.response]
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

[forward_proxy.request]
actions = ["redact"]
redact_strategy = "char"
mask_char = "*"

[forward_proxy.response]
actions = ["redact"]
redact_strategy = "char"
mask_char = "*"
"#;
        parse(toml).expect("redact with char+mask should be valid");
    }

    #[test]
    fn valid_header_with_redact() {
        let toml = r#"
[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
actions = ["redact"]
redact_strategy = "type_label"

[forward_proxy.response]
actions = ["redact", "header"]
redact_strategy = "type_label"
"#;
        parse(toml).expect("header with redact should be valid");
    }

    #[test]
    fn valid_header_alone_in_allowed_direction() {
        let toml = r#"
[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
actions = []

[forward_proxy.response]
actions = ["header"]
"#;
        parse(toml).expect("header alone in forward_proxy.response should be valid");
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
actions = ["block"]

[reverse_proxy.response]
actions = ["block"]

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"
"#;
        parse(toml).expect("block action should be valid");
    }

    #[test]
    fn valid_empty_actions_disables_scanning() {
        let toml = r#"
[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
actions = []

[forward_proxy.response]
actions = []
"#;
        parse(toml).expect("empty actions should be valid");
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
        assert_eq!(
            config.reverse_proxy.request.actions,
            vec![Action::Redact, Action::Header]
        );
        assert_eq!(config.reverse_proxy.response.actions, vec![Action::Redact]);
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
        assert_eq!(config.forward_proxy.request.actions, vec![Action::Redact]);
        assert_eq!(
            config.forward_proxy.response.actions,
            vec![Action::Redact, Action::Header]
        );
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
actions = []

[forward_proxy.response]
actions = []

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
actions = []

[forward_proxy.response]
actions = []
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
actions = []

[forward_proxy.response]
actions = []
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    // --- Invalid: block and header mutually exclusive ---

    #[test]
    fn invalid_block_and_header() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[reverse_proxy.request]
actions = ["block", "header"]

[reverse_proxy.response]
actions = []

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"
"#;
        let err = parse(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("block and header are mutually exclusive")
        );
    }

    // --- Invalid: header in wrong direction ---

    #[test]
    fn invalid_header_in_reverse_proxy_response() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[reverse_proxy.request]
actions = []

[reverse_proxy.response]
actions = ["header"]

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"
"#;
        let err = parse(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("header action is not valid in this direction")
        );
    }

    #[test]
    fn invalid_header_in_forward_proxy_request() {
        let toml = r#"
[pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

[forward_proxy.request]
actions = ["header"]

[forward_proxy.response]
actions = []
"#;
        let err = parse(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("header action is not valid in this direction")
        );
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

[forward_proxy.request]
actions = ["redact"]

[forward_proxy.response]
actions = []
"#;
        let err = parse(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("redact action requires redact_strategy")
        );
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

[forward_proxy.request]
actions = ["redact"]
redact_strategy = "char"

[forward_proxy.response]
actions = []
"#;
        let err = parse(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("char redact strategy requires mask_char")
        );
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

[reverse_proxy.request]
actions = []

[reverse_proxy.response]
actions = []

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
actions = []

[reverse_proxy.response]
actions = []

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "://broken"
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("invalid upstream URL"));
    }

    // --- Invalid: REST API char without mask ---

    #[test]
    fn invalid_http_api_char_without_mask() {
        let toml = r#"
[pii]
countries = ["Us"]

[http_api]
enabled = true
listen = "0.0.0.0:8083"
redact_strategy = "char"
"#;
        let err = parse(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("char redact strategy requires mask_char")
        );
    }

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
actions = []

[forward_proxy.response]
actions = []
"#;
        let config = parse(toml).unwrap();
        assert_eq!(config.scan.on_error, OnError::FailClose);
    }

    // --- Route specialization ---

    #[test]
    fn valid_route_with_known_specialization() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[reverse_proxy.request]
actions = []

[reverse_proxy.response]
actions = []

[[reverse_proxy.routes]]
path_prefix = "/g/collect"
upstream = "http://localhost:8080"
specialization = "ga4"

[[reverse_proxy.routes]]
path_prefix = "/matomo.php"
upstream = "http://localhost:8081"
specialization = "matomo"
"#;
        let config = parse(toml).expect("known specializations should validate");
        assert_eq!(
            config.reverse_proxy.routes[0].specialization.as_deref(),
            Some("ga4")
        );
        assert_eq!(
            config.reverse_proxy.routes[1].specialization.as_deref(),
            Some("matomo")
        );
    }

    #[test]
    fn route_without_specialization_field_defaults_to_none() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[reverse_proxy.request]
actions = []

[reverse_proxy.response]
actions = []

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"
"#;
        let config = parse(toml).expect("omitted specialization is accepted");
        assert!(config.reverse_proxy.routes[0].specialization.is_none());
    }

    #[test]
    fn invalid_unknown_specialization_is_rejected() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[reverse_proxy.request]
actions = []

[reverse_proxy.response]
actions = []

[[reverse_proxy.routes]]
path_prefix = "/foo"
upstream = "http://localhost:8080"
specialization = "plausible"
"#;
        let err = parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown specialization"), "got: {msg}");
        assert!(msg.contains("plausible"), "got: {msg}");
        assert!(msg.contains("/foo"), "got: {msg}");
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
actions = []

[reverse_proxy.response]
actions = []

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
actions = ["redact", "header"]
redact_strategy = "type_label"

[reverse_proxy.response]
actions = ["redact"]
redact_strategy = "type_label"

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
actions = ["redact"]
redact_strategy = "type_label"

[forward_proxy.response]
actions = ["redact", "header"]
redact_strategy = "type_label"

[http_api]
enabled = true
listen = "0.0.0.0:8083"
redact_strategy = "type_label"

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
    fn block_response_configurable() {
        let toml = r#"
[pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[reverse_proxy.request]
actions = ["block"]
block_status = 451
block_body = '{"error": "Blocked by policy"}'

[reverse_proxy.response]
actions = []

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"
"#;
        let config = parse(toml).unwrap();
        assert_eq!(config.reverse_proxy.request.block_status, 451);
        assert_eq!(
            config.reverse_proxy.request.block_body.as_deref(),
            Some(r#"{"error": "Blocked by policy"}"#)
        );
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
actions = []

[forward_proxy.response]
actions = []
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
actions = []

[forward_proxy.response]
actions = []
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
actions = []

[forward_proxy.response]
actions = []
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
actions = []

[forward_proxy.response]
actions = []
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
