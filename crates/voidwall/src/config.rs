use std::collections::{BTreeMap, HashSet};
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

/// Deployment-wide settings, the guards, and the modes.
///
/// The ingest keys — `max_body_size`, `content_types`, and `on_error` — are
/// bare top-level keys, so a config file has to write them before its first
/// `[section]`. TOML binds a bare key to the table above it, so one written
/// later parses as that section's field and `deny_unknown_fields` rejects it
/// naming the path.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// The largest body admitted for inspection, in bytes. Ingest governs how
    /// much of a message is read before detection begins, so this applies to
    /// every guard alike rather than belonging to one of them.
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// The content types whose body is decoded and inspected. A body outside
    /// the list is skipped in silence; that is not an error.
    #[serde(default = "default_content_types")]
    pub content_types: Vec<String>,

    /// What an ingest limit or a guard failure does to the message.
    #[serde(default = "default_on_error")]
    pub on_error: OnError,

    #[serde(default)]
    pub builtin_guards: BuiltinGuards,

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

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            max_body_size: default_max_body_size(),
            content_types: default_content_types(),
            on_error: default_on_error(),
            builtin_guards: BuiltinGuards::default(),
            reverse_proxy: ReverseProxyConfig::default(),
            forward_proxy: ForwardProxyConfig::default(),
            http_api: HttpApiConfig::default(),
            admin: AdminConfig::default(),
            shutdown_timeout_secs: default_shutdown_timeout_secs(),
        }
    }
}

fn default_shutdown_timeout_secs() -> u64 {
    30
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

/// The section key of the built-in regex PII guard, and so the name it carries
/// into every finding it reports.
pub const BUILTIN_PII_GUARD_NAME: &str = "pii";

/// The guard names the build reserves for guards that ship with Voidwall.
///
/// Every guard a route can select is drawn from one flat name space, so a
/// configured guard may not take one of these.
pub const BUILTIN_GUARD_NAMES: &[&str] = &[BUILTIN_PII_GUARD_NAME];

/// The guards that ship with Voidwall.
///
/// A built-in is a singleton with a fixed key and no `type` field: the section
/// key identifies it, so two instances of one built-in guard are not
/// expressible and no rule is needed to forbid them.
///
/// `deny_unknown_fields` is deliberately absent here. A key under
/// `[builtin_guards]` that this struct does not define names a guard the build
/// does not have, which is a semantic failure naming the guard rather than a
/// schema one — so the key is captured and rejected in validation.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct BuiltinGuards {
    #[serde(default)]
    pub pii: Option<PiiGuardConfig>,

    #[serde(flatten)]
    unknown: BTreeMap<String, toml::Value>,
}

impl BuiltinGuards {
    /// The guard set holding just this PII guard.
    ///
    /// `unknown` is private — it exists only so validation can name a key that
    /// matches no built-in guard — so this is how a caller outside `config`
    /// builds a guard set without a TOML file.
    pub fn with_pii(pii: PiiGuardConfig) -> Self {
        Self {
            pii: Some(pii),
            unknown: BTreeMap::new(),
        }
    }

    /// The built-in PII guard, when its section is present and enabled.
    pub fn enabled_pii(&self) -> Option<&PiiGuardConfig> {
        self.pii.as_ref().filter(|g| g.enabled)
    }

    /// Keys under `[builtin_guards]` naming no built-in guard.
    fn unknown_names(&self) -> impl Iterator<Item = &str> {
        self.unknown.keys().map(String::as_str)
    }

    /// Every enabled guard's name, in the order the engine builds them.
    pub fn enabled_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.enabled_pii().is_some() {
            names.push(BUILTIN_PII_GUARD_NAME);
        }
        names
    }
}

/// The built-in regex and keyword PII guard.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PiiGuardConfig {
    /// A present section is enabled unless it says otherwise. A guard section
    /// naming countries and twenty lines of patterns is not visibly
    /// incomplete, so defaulting it off would detect nothing and say nothing.
    #[serde(default = "default_true")]
    pub enabled: bool,

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

    #[serde(default)]
    pub surface: GuardSurface,
}

impl Default for PiiGuardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            countries: Vec::new(),
            languages: Vec::new(),
            scanner_threads: None,
            detect: None,
            ignore: None,
            custom: Vec::new(),
            surface: GuardSurface::default(),
        }
    }
}

/// Maximum number of `[[builtin_guards.pii.custom]]` entries accepted at
/// config load.
pub const MAX_CUSTOM_PII_ENTRIES: usize = 64;

impl PiiGuardConfig {
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

/// Reject a configured guard that takes a name the build reserves.
///
/// Guard names live in one flat space so a route can select any guard by name,
/// which means a configured guard may not shadow a built-in one. The
/// configured-guard section itself — `[guards.<name>]`, for model-backed
/// guards — is not built yet, so the set this runs over is empty today.
pub fn validate_configured_guard_name(name: &str) -> Result<(), Error> {
    if BUILTIN_GUARD_NAMES.contains(&name) {
        return Err(Error::Config(format!(
            "guards: '{name}' is a reserved built-in guard name",
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Guard scan surface
// ---------------------------------------------------------------------------

/// One guard's scan surface: which parts of a message it wants to see.
///
/// This is the configuration form of the guard's `Interest`, and it belongs to
/// the guard rather than to a global section, so two enabled guards may carry
/// different surfaces. A unit kind no selected guard admits is never built.
///
/// There is deliberately no header allowlist here. Which headers carry
/// sensitive values is a property of the traffic, not of a detector — an
/// `authorization` header on an auth route, an `x-user-id` on a chat one — and
/// a guard scans whatever text it is handed either way. So the route names
/// them: see [`Route::headers`]. It also keeps the surface to what the engine
/// can actually enforce, since a unit carries its kind and not a header name.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardSurface {
    #[serde(default = "default_true")]
    pub url_path: bool,

    #[serde(default = "default_true")]
    pub query_params: bool,

    #[serde(default = "default_true")]
    pub body: bool,
}

impl Default for GuardSurface {
    fn default() -> Self {
        Self {
            url_path: true,
            query_params: true,
            body: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Ingest defaults
// ---------------------------------------------------------------------------

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
    OnError::FailClose
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

    /// The guards that run for this route, by name. An absent list selects
    /// every enabled guard; an empty list selects none, which is how a route
    /// opts out of inspection.
    #[serde(default)]
    pub guards: Option<Vec<String>>,

    /// Header names whose value this route exposes to detection, in both
    /// directions. Empty by default: a header carries credentials at least as
    /// often as PII, so reading one is opt-in.
    ///
    /// A header the route does not name is never decoded into a unit, so no
    /// guard can see it. A header it does name is seen by every guard the
    /// route selected — the route decides what exists, the guard's surface
    /// decides which kinds of unit it wants.
    #[serde(default)]
    pub headers: Vec<String>,
}

impl Route {
    /// The guards that run for this route.
    ///
    /// A route that names none takes every enabled guard; one that names an
    /// empty list takes none, and its traffic is forwarded uninspected. Every
    /// name here is known to be enabled — validation rejected the rest.
    pub fn selected_guards<'a>(&'a self, enabled: &[&'a str]) -> Vec<&'a str> {
        match &self.guards {
            Some(names) => names.iter().map(String::as_str).collect(),
            None => enabled.to_vec(),
        }
    }
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
        config.warn_on_empty_guard_set();
        Ok(config)
    }

    /// Warn once when configuration enables no guard.
    ///
    /// This is not an invalid config. A proxy with no mode enabled starts and
    /// serves nothing, and guards follow that precedent: the deployment states
    /// that there is nothing to inspect, rather than something the proxy
    /// cannot honour.
    pub fn warn_on_empty_guard_set(&self) {
        if self.builtin_guards.enabled_names().is_empty() {
            tracing::warn!("no guard is enabled; traffic is forwarded uninspected");
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

impl AppConfig {
    pub fn validate(&self) -> Result<(), Error> {
        self.validate_at_least_one_mode()?;
        self.validate_no_port_conflicts()?;
        self.validate_builtin_guard_names()?;
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

    /// A key under `[builtin_guards]` naming a guard the build does not have.
    ///
    /// This is semantic rather than schema: the file is well-typed, but it asks
    /// for a guard that does not exist, and the diagnostic names it.
    fn validate_builtin_guard_names(&self) -> Result<(), Error> {
        if let Some(name) = self.builtin_guards.unknown_names().next() {
            return Err(Error::Config(format!(
                "builtin_guards: unknown built-in guard '{name}'; known guards: {}",
                BUILTIN_GUARD_NAMES.join(", "),
            )));
        }
        Ok(())
    }

    /// The configured guard sections, enabled or not. A disabled section still
    /// has to be well-formed: there is no partial start.
    fn pii_guard(&self) -> Option<&PiiGuardConfig> {
        self.builtin_guards.pii.as_ref()
    }

    fn validate_scanner_threads(&self) -> Result<(), Error> {
        if let Some(pii) = self.pii_guard()
            && let Some(n) = pii.scanner_threads
            && n < 1
        {
            return Err(Error::Config(
                "builtin_guards.pii.scanner_threads must be >= 1".into(),
            ));
        }
        Ok(())
    }

    fn validate_pii_kinds_exclusivity(&self) -> Result<(), Error> {
        let Some(pii) = self.pii_guard() else {
            return Ok(());
        };
        if pii.detect.is_some() && pii.ignore.is_some() {
            return Err(Error::Config(
                "builtin_guards.pii: detect and ignore are mutually exclusive".into(),
            ));
        }
        for (field, kinds) in [("detect", &pii.detect), ("ignore", &pii.ignore)] {
            if let Some(list) = kinds
                && list.contains(&voidwall_pii::PiiKind::Custom)
            {
                return Err(Error::Config(format!(
                    "builtin_guards.pii.{field}: 'Custom' is reserved for user-defined PII \
                     and cannot be listed here",
                )));
            }
        }
        Ok(())
    }

    fn validate_custom_pii(&self) -> Result<(), Error> {
        let Some(pii) = self.pii_guard() else {
            return Ok(());
        };
        let custom = &pii.custom;
        if custom.len() > MAX_CUSTOM_PII_ENTRIES {
            return Err(Error::Config(format!(
                "builtin_guards.pii.custom: too many entries ({}); \
                 max is {MAX_CUSTOM_PII_ENTRIES}",
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
                return Err(Error::Config(
                    "builtin_guards.pii.custom: label must be non-empty".into(),
                ));
            }
            if entry.pattern.is_empty() {
                return Err(Error::Config(format!(
                    "builtin_guards.pii.custom: entry '{}' has empty pattern",
                    entry.label,
                )));
            }
            if builtin_labels.contains(entry.label.as_str()) {
                return Err(Error::Config(format!(
                    "builtin_guards.pii.custom: label '{}' collides with a built-in \
                     PiiKind label",
                    entry.label,
                )));
            }
            if !seen.insert(entry.label.as_str()) {
                return Err(Error::Config(format!(
                    "builtin_guards.pii.custom: duplicate label '{}'",
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

        let enabled = self.builtin_guards.enabled_names();
        let mut prefixes = HashSet::new();
        for route in &self.reverse_proxy.routes {
            if let Some(selected) = &route.guards {
                for name in selected {
                    if !enabled.contains(&name.as_str()) {
                        return Err(Error::Config(format!(
                            "reverse_proxy: route '{}' names guard '{}', which is not an \
                             enabled guard",
                            route.path_prefix, name,
                        )));
                    }
                }
            }

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
[builtin_guards.pii]
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
[builtin_guards.pii]
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
"#;
        parse(toml).expect("all-modes config should be valid");
    }

    #[test]
    fn valid_defaults_used_when_direction_omitted() {
        let toml = r#"
[builtin_guards.pii]
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

    // --- Ingest keys are top-level (1.1) ---

    #[test]
    fn ingest_defaults_apply_when_the_keys_are_absent() {
        let config = parse(&minimal_toml()).unwrap();
        assert_eq!(config.max_body_size, 1_048_576);
        assert_eq!(config.on_error, OnError::FailClose);
        assert_eq!(config.content_types.len(), 9);
        assert!(
            config
                .content_types
                .iter()
                .any(|c| c == "application/json")
        );
    }

    #[test]
    fn ingest_keys_are_read_from_the_top_level() {
        let toml = r#"
max_body_size = 2048
content_types = ["application/json"]
on_error = "fail_open"

[builtin_guards.pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let config = parse(toml).unwrap();
        assert_eq!(config.max_body_size, 2048);
        assert_eq!(config.content_types, vec!["application/json".to_string()]);
        assert_eq!(config.on_error, OnError::FailOpen);
    }

    /// Ingest governs admission before any guard runs, so it is not a guard
    /// setting. A limit written under a guard is a schema error naming it.
    #[test]
    fn an_ingest_key_under_a_guard_is_rejected() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]
max_body_size = 2048

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let err = parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("max_body_size"), "got: {msg}");
    }

    // --- Guard surface (1.2) ---

    #[test]
    fn default_surface_takes_the_path_the_query_and_the_body() {
        let surface = GuardSurface::default();
        assert!(surface.url_path);
        assert!(surface.query_params);
        assert!(surface.body);
    }

    #[test]
    fn a_guard_section_without_a_surface_takes_the_default() {
        let config = parse(&minimal_toml()).unwrap();
        let pii = config.builtin_guards.pii.as_ref().unwrap();
        assert_eq!(pii.surface, GuardSurface::default());
    }

    #[test]
    fn a_surface_can_switch_one_target_off() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[builtin_guards.pii.surface]
body = false

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let config = parse(toml).unwrap();
        let surface = &config.builtin_guards.pii.as_ref().unwrap().surface;
        assert!(!surface.body);
        assert!(surface.url_path, "the other targets keep their default");
        assert!(surface.query_params);
    }

    /// Which headers carry sensitive values is a property of the traffic, so
    /// the route names them. A guard that reaches for the setting is told it
    /// does not live there.
    #[test]
    fn a_surface_naming_headers_is_rejected() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[builtin_guards.pii.surface]
headers = ["x-forwarded-for"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let err = parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("headers"), "got: {msg}");
    }

    #[test]
    fn a_route_names_the_headers_it_exposes_to_detection() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[[reverse_proxy.routes]]
path_prefix = "/auth"
upstream = "http://localhost:8080"
headers = ["authorization"]

[[reverse_proxy.routes]]
path_prefix = "/public"
upstream = "http://localhost:8080"
"#;
        let config = parse(toml).unwrap();
        let routes = &config.reverse_proxy.routes;
        assert_eq!(routes[0].headers, vec!["authorization".to_string()]);
        assert!(
            routes[1].headers.is_empty(),
            "a route that names none reads no header"
        );
    }

    // --- Built-in guard section (1.3) ---

    #[test]
    fn a_guard_section_without_enabled_is_enabled() {
        let config = parse(&minimal_toml()).unwrap();
        assert!(config.builtin_guards.pii.as_ref().unwrap().enabled);
        assert!(config.builtin_guards.enabled_pii().is_some());
        assert_eq!(config.builtin_guards.enabled_names(), vec!["pii"]);
    }

    #[test]
    fn a_guard_section_can_disable_itself() {
        let toml = r#"
[builtin_guards.pii]
enabled = false
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let config = parse(toml).unwrap();
        assert!(!config.builtin_guards.pii.as_ref().unwrap().enabled);
        assert!(config.builtin_guards.enabled_pii().is_none());
        assert!(config.builtin_guards.enabled_names().is_empty());
    }

    #[test]
    fn an_absent_guard_section_builds_no_guard() {
        let toml = r#"
[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let config = parse(toml).unwrap();
        assert!(config.builtin_guards.pii.is_none());
        assert!(config.builtin_guards.enabled_names().is_empty());
    }

    /// The section key identifies a built-in guard, so there is nothing for a
    /// `type` field to say.
    #[test]
    fn a_built_in_guard_carrying_a_type_field_is_rejected() {
        let toml = r#"
[builtin_guards.pii]
type = "regex"
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let err = parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("type"), "got: {msg}");
    }

    // --- The old sections are gone (1.4) ---

    #[test_case("[pii]\ncountries = [\"Us\"]", "pii" ; "retired pii section")]
    #[test_case("[scan]\nbody = true", "scan" ; "retired scan section")]
    #[test_case("[[pii.custom]]\nlabel = \"X\"\npattern = \"x\"", "pii" ; "retired custom path")]
    fn a_config_in_the_old_format_is_rejected(section: &str, key: &str) {
        let toml = format!(
            r#"
{section}

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#
        );
        let err = parse(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains(key), "got: {msg}");
    }

    // --- Route guard selection (1.5) ---

    #[test]
    fn a_route_resolves_its_guard_set_from_the_names_it_carries() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[[reverse_proxy.routes]]
path_prefix = "/named"
upstream = "http://localhost:8080"
guards = ["pii"]

[[reverse_proxy.routes]]
path_prefix = "/opted-out"
upstream = "http://localhost:8080"
guards = []

[[reverse_proxy.routes]]
path_prefix = "/default"
upstream = "http://localhost:8080"
"#;
        let config = parse(toml).unwrap();
        let enabled = config.builtin_guards.enabled_names();
        let routes = &config.reverse_proxy.routes;

        assert_eq!(routes[0].guards.as_deref(), Some(["pii".to_string()].as_slice()));
        assert_eq!(routes[0].selected_guards(&enabled), vec!["pii"]);

        assert_eq!(routes[1].guards.as_deref(), Some([].as_slice()));
        assert!(routes[1].selected_guards(&enabled).is_empty());

        assert!(routes[2].guards.is_none());
        assert_eq!(routes[2].selected_guards(&enabled), vec!["pii"]);
    }

    /// An absent list means every enabled guard, so a route that named none
    /// inspects nothing once the last guard is switched off.
    #[test]
    fn a_route_without_a_guard_list_follows_the_enabled_set() {
        let toml = r#"
[builtin_guards.pii]
enabled = false

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:8080"
"#;
        let config = parse(toml).unwrap();
        let enabled = config.builtin_guards.enabled_names();
        assert!(config.reverse_proxy.routes[0].selected_guards(&enabled).is_empty());
    }

    // --- Scanner threads (1.6) ---

    #[test]
    fn effective_scanner_threads_explicit() {
        let pii = PiiGuardConfig {
            scanner_threads: Some(7),
            ..PiiGuardConfig::default()
        };
        assert_eq!(pii.effective_scanner_threads(), 7);
    }

    #[test]
    fn effective_scanner_threads_auto() {
        let pii = PiiGuardConfig::default();
        assert!(pii.effective_scanner_threads() >= 1);
    }

    /// The setting belongs to the guard that owns the scanner, so it is not a
    /// top-level key.
    #[test]
    fn scanner_threads_outside_the_guard_is_rejected() {
        let toml = r#"
scanner_threads = 4

[builtin_guards.pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let err = parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("scanner_threads"), "got: {msg}");
    }

    // --- Invalid: at least one mode ---

    #[test]
    fn invalid_no_mode_enabled() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("at least one mode"));
    }

    // --- Invalid: port conflicts ---

    #[test]
    fn invalid_port_conflict() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:9090"

[admin]
listen = "0.0.0.0:9090"
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("port conflict"));
    }

    // --- Invalid: unknown built-in guard (2.1) ---

    #[test]
    fn an_unknown_built_in_guard_is_rejected_by_name() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[builtin_guards.jailbreak]
threshold = 0.5

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let err = parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown built-in guard"), "got: {msg}");
        assert!(msg.contains("jailbreak"), "got: {msg}");
        // Semantic, not schema: the file is well-typed and names a guard the
        // build does not have. `validate.rs` maps `Error::Config` from
        // `validate()` onto `Category::Semantic`.
        assert!(matches!(err, Error::Config(_)), "got: {err:?}");
    }

    // --- Invalid: a configured guard takes a reserved name (2.2) ---

    #[test]
    fn a_configured_guard_may_not_take_a_reserved_name() {
        let err =
            validate_configured_guard_name("pii").expect_err("`pii` is reserved for the built-in");
        let msg = err.to_string();
        assert!(msg.contains("pii"), "got: {msg}");
        assert!(msg.contains("reserved"), "got: {msg}");
        // `Error::Config` is what `validate.rs` categorises as `semantic`.
        assert!(matches!(err, Error::Config(_)), "got: {err:?}");
    }

    #[test]
    fn a_configured_guard_may_take_any_other_name() {
        validate_configured_guard_name("jailbreak").expect("only built-in names are reserved");
    }

    // --- Invalid: a route names a guard that is not enabled (2.3) ---

    #[test_case("injection", "no such guard exists" ; "unknown guard")]
    #[test_case("pii", "the guard exists but is disabled" ; "disabled guard")]
    fn a_route_naming_a_guard_that_is_not_enabled_is_rejected(guard: &str, _why: &str) {
        let toml = format!(
            r#"
[builtin_guards.pii]
enabled = false

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"
guards = ["{guard}"]
"#
        );
        let err = parse(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(guard), "got: {msg}");
        assert!(msg.contains("not an enabled guard"), "got: {msg}");
        assert!(matches!(err, Error::Config(_)), "got: {err:?}");
    }

    // --- Invalid: scanner_threads ---

    #[test]
    fn invalid_scanner_threads_zero() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]
scanner_threads = 0

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("scanner_threads"));
    }

    // --- Invalid: detect/ignore exclusivity ---

    #[test]
    fn invalid_detect_and_ignore() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]
detect = ["Email"]
ignore = ["IpAddress"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    // --- Invalid: duplicate path prefix ---

    #[test]
    fn invalid_duplicate_path_prefix() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

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
[builtin_guards.pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "://broken"
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("invalid upstream URL"));
    }

    // --- Default values ---

    #[test]
    fn defaults_admin_config() {
        let admin = AdminConfig::default();
        assert_eq!(admin.listen, "127.0.0.1:9090");
        assert_eq!(admin.metrics_path, "/metrics");
        assert_eq!(admin.health_path, "/healthz");
        assert_eq!(admin.ready_path, "/readyz");
    }

    // --- Deserialization edge cases ---

    #[test_case("fail_close", OnError::FailClose ; "fail close")]
    #[test_case("fail_open", OnError::FailOpen ; "fail open overrides the default")]
    fn on_error_is_read_from_the_top_level(written: &str, expected: OnError) {
        let toml = format!(
            r#"
on_error = "{written}"

[builtin_guards.pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#
        );
        assert_eq!(parse(&toml).unwrap().on_error, expected);
    }

    // --- Unknown keys ---
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
[builtin_guards.pii]
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
[builtin_guards.pii]
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

[builtin_guards.pii]
countries = ["Us"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let err = parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("shutdown_timeout_secs_typo"), "got: {msg}");
    }

    #[test]
    fn invalid_retired_route_specialization_key_is_rejected() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

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

    /// A route selects guards; it no longer overrides a scan table.
    #[test]
    fn invalid_route_scan_table_is_rejected() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[[reverse_proxy.routes]]
path_prefix = "/api"
upstream = "http://localhost:8080"

[reverse_proxy.routes.scan]
body = true
"#;
        let err = parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("scan"), "got: {msg}");
    }

    #[test]
    fn full_example_config() {
        let toml = r#"
max_body_size = 2097152
content_types = ["application/json", "text/plain"]
on_error = "fail_open"

[builtin_guards.pii]
enabled = true
countries = ["International", "Us", "Gb"]
languages = ["En"]
scanner_threads = 4

[builtin_guards.pii.surface]
body = true
url_path = true
query_params = true

[[builtin_guards.pii.custom]]
label = "EMPLOYEE_ID"
pattern = 'EMP-\d{6}'
keywords = ["employee", "badge"]

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
guards = ["pii"]
headers = ["Authorization", "Cookie"]

[[reverse_proxy.routes]]
path_prefix = "/static"
upstream = "http://cdn:8080"
guards = []

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"

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
        assert_eq!(config.reverse_proxy.routes.len(), 3);
        assert_eq!(config.max_body_size, 2_097_152);
        assert_eq!(config.on_error, OnError::FailOpen);

        let pii = config.builtin_guards.enabled_pii().expect("pii is enabled");
        assert_eq!(pii.effective_scanner_threads(), 4);
        assert_eq!(pii.custom.len(), 1);
        assert_eq!(config.reverse_proxy.routes[1].headers.len(), 2);
    }

    #[test]
    fn detect_field_deserialization() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]
detect = ["Email", "UsSsn"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let config = parse(toml).unwrap();
        let pii = config.builtin_guards.pii.as_ref().unwrap();
        assert_eq!(pii.detect.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn ignore_field_deserialization() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]
ignore = ["IpAddress"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let config = parse(toml).unwrap();
        let pii = config.builtin_guards.pii.as_ref().unwrap();
        assert_eq!(pii.ignore.as_ref().unwrap().len(), 1);
    }

    // --- Custom PII definitions ---

    fn custom_pii_toml(body: &str) -> String {
        format!(
            r#"
[builtin_guards.pii]
countries = ["Us", "International"]
{body}

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#
        )
    }

    #[test]
    fn valid_custom_pii_entries() {
        let toml = custom_pii_toml(
            r#"
[[builtin_guards.pii.custom]]
label = "EMPLOYEE_ID"
pattern = 'EMP-\d{6}'

[[builtin_guards.pii.custom]]
label = "PROJECT_CODE"
pattern = '[A-Z]{3}-\d{3}'
keywords = ["project code", "proj id"]
country = "International"
"#,
        );
        let config = parse(&toml).expect("valid custom entries should parse");
        let custom = &config.builtin_guards.pii.as_ref().unwrap().custom;
        assert_eq!(custom.len(), 2);
        assert_eq!(custom[0].label, "EMPLOYEE_ID");
        assert_eq!(custom[0].pattern, r"EMP-\d{6}");
        assert!(custom[0].keywords.is_empty());
        assert_eq!(custom[1].label, "PROJECT_CODE");
        assert_eq!(
            custom[1].keywords,
            vec!["project code".to_string(), "proj id".to_string()]
        );
        assert_eq!(custom[1].country, voidwall_pii::Country::International);
    }

    #[test]
    fn valid_custom_pii_defaults_to_empty() {
        let config = parse(&minimal_toml()).unwrap();
        assert!(config.builtin_guards.pii.as_ref().unwrap().custom.is_empty());
    }

    #[test_case(
        r#"
[[builtin_guards.pii.custom]]
label = ""
pattern = 'abc'
"#,
        "label must be non-empty"
        ; "empty label"
    )]
    #[test_case(
        r#"
[[builtin_guards.pii.custom]]
label = "FOO"
pattern = ""
"#,
        "empty pattern"
        ; "empty pattern"
    )]
    #[test_case(
        r#"
[[builtin_guards.pii.custom]]
label = "EMPLOYEE_ID"
pattern = 'EMP-\d{6}'

[[builtin_guards.pii.custom]]
label = "EMPLOYEE_ID"
pattern = 'ID-\d+'
"#,
        "duplicate label"
        ; "duplicate label"
    )]
    #[test_case(
        r#"
[[builtin_guards.pii.custom]]
label = "EMAIL"
pattern = 'foo@bar'
"#,
        "collides with a built-in"
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
                "\n[[builtin_guards.pii.custom]]\nlabel = \"LBL_{i}\"\npattern = 'x{i}'\n"
            ));
        }
        let toml = custom_pii_toml(&entries);
        let err = parse(&toml).unwrap_err();
        assert!(err.to_string().contains("too many entries"));
    }

    /// A custom definition belongs to the guard that runs it.
    #[test]
    fn a_custom_entry_outside_the_guard_is_rejected() {
        let toml = r#"
[[pii.custom]]
label = "EMPLOYEE_ID"
pattern = 'EMP-\d{6}'

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#;
        let err = parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("pii"), "got: {msg}");
    }

    #[test_case("detect" ; "custom in detect")]
    #[test_case("ignore" ; "custom in ignore")]
    fn invalid_custom_in_kinds_list(field: &str) {
        let toml = format!(
            r#"
[builtin_guards.pii]
countries = ["Us"]
{field} = ["Custom"]

[forward_proxy]
enabled = true
listen = "0.0.0.0:8084"
"#
        );
        let err = parse(&toml).unwrap_err();
        assert!(
            err.to_string().contains("'Custom' is reserved"),
            "got: {err}"
        );
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
