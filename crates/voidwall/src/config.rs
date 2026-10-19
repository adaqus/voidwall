use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{ArgGroup, Parser};
use serde::Deserialize;
use voidwall_ml::AdapterKind;

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

    /// The model-backed guards an operator configured, by name. Empty by
    /// default. Each entry loads its model at startup and runs.
    #[serde(default)]
    pub guards: BTreeMap<String, ModelGuardConfig>,

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

    /// Seconds one upstream exchange may take: from sending the request until
    /// the response headers arrive, and the body read when response scan
    /// buffers it. The type rejects a value outside its range at parse.
    #[serde(default)]
    pub upstream_timeout_secs: UpstreamTimeout,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            max_body_size: default_max_body_size(),
            content_types: default_content_types(),
            on_error: default_on_error(),
            builtin_guards: BuiltinGuards::default(),
            guards: BTreeMap::new(),
            reverse_proxy: ReverseProxyConfig::default(),
            forward_proxy: ForwardProxyConfig::default(),
            http_api: HttpApiConfig::default(),
            admin: AdminConfig::default(),
            shutdown_timeout_secs: default_shutdown_timeout_secs(),
            upstream_timeout_secs: UpstreamTimeout::default(),
        }
    }
}

fn default_shutdown_timeout_secs() -> u64 {
    30
}

/// The limit on one upstream exchange, in whole seconds from 1 to
/// [`UpstreamTimeout::MAX_SECS`]. The upper bound keeps `Instant::now() +
/// timeout` from overflowing, which would panic on every request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "u64")]
pub struct UpstreamTimeout(u64);

impl UpstreamTimeout {
    pub const MAX_SECS: u64 = 3600;

    pub fn as_duration(self) -> Duration {
        Duration::from_secs(self.0)
    }
}

impl Default for UpstreamTimeout {
    fn default() -> Self {
        Self(300)
    }
}

impl TryFrom<u64> for UpstreamTimeout {
    type Error = String;

    fn try_from(secs: u64) -> Result<Self, Self::Error> {
        if (1..=Self::MAX_SECS).contains(&secs) {
            Ok(Self(secs))
        } else {
            Err(format!(
                "upstream_timeout_secs must be from 1 to {}, got {secs}",
                Self::MAX_SECS
            ))
        }
    }
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

/// The longest guard name configuration may supply.
///
/// The name reaches a finding record and can reach a metric label, so its
/// shape is bounded as well as its set.
pub const MAX_GUARD_NAME_LEN: usize = 64;

/// Whether `c` may appear in a configured guard name.
fn is_guard_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Reject a configured guard name the build cannot carry.
///
/// Guard names live in one flat space so a route can select any guard by name,
/// which means a configured guard may not shadow a built-in one. The name also
/// travels into every finding that guard reports and can reach a metric label,
/// so it is held to ASCII `[a-zA-Z0-9_-]` and a length cap on top of that.
///
/// The charset is checked before the length, so [`MAX_GUARD_NAME_LEN`] counts
/// characters rather than bytes by the time it is applied.
pub fn validate_configured_guard_name(name: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::Config(
            "guards: a guard name must not be empty".into(),
        ));
    }
    if let Some(c) = name.chars().find(|c| !is_guard_name_char(*c)) {
        return Err(Error::Config(format!(
            "guards: '{name}' holds '{c}'; a guard name may hold only a-z, A-Z, 0-9, \
             '_', and '-'",
        )));
    }
    if name.len() > MAX_GUARD_NAME_LEN {
        return Err(Error::Config(format!(
            "guards: '{name}' is {} characters; the limit is {MAX_GUARD_NAME_LEN}",
            name.len(),
        )));
    }
    if BUILTIN_GUARD_NAMES.contains(&name) {
        return Err(Error::Config(format!(
            "guards: '{name}' is a reserved built-in guard name",
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Model-backed guards
// ---------------------------------------------------------------------------

/// The fewest tokens a model guard may be given.
///
/// A window this small holds the adapter's special tokens and little else, so
/// the guard would be configured to judge nothing. The floor is a sanity bound
/// rather than a tuned number.
pub const MIN_MODEL_GUARD_MAX_TOKENS: usize = 10;

/// A model-backed guard, declared under `[guards.<name>]`.
///
/// One section carries everything one guard needs to run one model. There is
/// no model section and no model reference, so "one guard owns one model" is
/// structural: a guard's model is not addressable from anywhere else, and no
/// rule is needed to keep it that way.
///
/// Two guards may name the same artifacts. That loads the model twice, which
/// is the operator's choice rather than an error the schema detects.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ModelGuardConfig {
    /// The build-shipped code path that runs the model.
    pub adapter: AdapterKind,

    pub model_path: PathBuf,
    pub tokenizer_path: PathBuf,

    /// The longest input the adapter feeds the model, in tokens. At least
    /// [`MIN_MODEL_GUARD_MAX_TOKENS`]. A longer input is split into
    /// overlapping windows.
    pub max_tokens: usize,

    /// Tokens shared by neighbouring windows of one unit. Absent means
    /// [`voidwall_ml::default_overlap`]; at most `max_tokens / 2`.
    pub overlap_tokens: Option<usize>,

    /// Worker threads, each owning one model session. Absent means an even
    /// share of the CPUs; see [`AppConfig::effective_model_threads`]. At
    /// least 1 when set — a rule rather than `NonZeroUsize`, so the diagnostic
    /// can name the guard.
    pub threads: Option<usize>,

    /// The finding kinds the guard can report. For `text_classifier`, exactly
    /// one entry, naming class 1 of the model's two outputs.
    ///
    /// A label is whatever the operator writes: the build has no closed set of
    /// finding kinds to check one against. The list must be non-empty and its
    /// entries distinct.
    pub labels: Vec<String>,

    /// The lowest score that turns a detection into a finding, per kind.
    ///
    /// No default, because the build has no evaluated number for an arbitrary
    /// model. A label absent from here reports nothing, and that absence is the
    /// only detection-layer off switch — which is why a key absent from
    /// `labels` is an error rather than a silently disabled kind.
    #[serde(default)]
    pub thresholds: BTreeMap<String, f32>,

    #[serde(default)]
    pub surface: ModelGuardSurface,
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
/// `headers` is a boolean and deliberately not a header allowlist. Which
/// headers carry sensitive values is a property of the traffic, not of a
/// detector — an `authorization` header on an auth route, an `x-user-id` on a
/// chat one — and a guard scans whatever text it is handed either way. So the
/// route names them: see [`Route::headers`], which decides what exists, while
/// the boolean here decides only whether this guard is handed it. It also keeps
/// the surface to what the engine can enforce, since a unit carries its kind
/// and not a header name.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardSurface {
    #[serde(default = "default_true")]
    pub url_path: bool,

    #[serde(default = "default_true")]
    pub query_params: bool,

    #[serde(default = "default_true")]
    pub body: bool,

    /// Whether this guard sees the header units the route built. A boolean and
    /// not a list: the route decides which headers exist, the guard decides
    /// only whether it wants them.
    #[serde(default = "default_true")]
    pub headers: bool,
}

impl Default for GuardSurface {
    fn default() -> Self {
        Self {
            url_path: true,
            query_params: true,
            body: true,
            headers: true,
        }
    }
}

impl GuardSurface {
    /// Whether this surface admits nothing, which describes a guard that can
    /// never be called.
    fn admits_nothing(&self) -> bool {
        !(self.url_path || self.query_params || self.body || self.headers)
    }
}

/// One model guard's scan surface.
///
/// A separate type from [`GuardSurface`] rather than one struct with two
/// default sets, because a `#[serde(default = "...")]` on the *field* does not
/// change the *inner* per-field defaults: a partially written
/// `[guards.<name>.surface]` would silently take the built-in guard's `true`s
/// for the keys it omits. Two types put each default set where serde reads it.
///
/// Each unit a model guard admits costs one model execution, so the default is
/// the body alone — a whole-input verdict on a URL path is cost without signal.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelGuardSurface {
    #[serde(default)]
    pub url_path: bool,

    #[serde(default)]
    pub query_params: bool,

    #[serde(default = "default_true")]
    pub body: bool,

    #[serde(default)]
    pub headers: bool,
}

impl Default for ModelGuardSurface {
    fn default() -> Self {
        Self {
            url_path: false,
            query_params: false,
            body: true,
            headers: false,
        }
    }
}

impl ModelGuardSurface {
    /// Whether this surface admits nothing, which describes a guard that can
    /// never be called.
    fn admits_nothing(&self) -> bool {
        !(self.url_path || self.query_params || self.body || self.headers)
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

    /// How the route decodes its bodies and shapes its answers. Absent, the
    /// route scans bodies generically.
    #[serde(default)]
    pub format: RouteFormat,
}

/// The body format of a reverse proxy route. The only value a config can
/// write is `openai-chat`; `Generic` is what an absent key means.
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum RouteFormat {
    /// Bodies are scanned by content type, and a detection answers the fixed
    /// 403.
    #[default]
    #[serde(skip_deserializing)]
    Generic,
    /// Bodies are decoded as OpenAI Chat Completions, and every answer uses
    /// the OpenAI error shape.
    #[serde(rename = "openai-chat")]
    OpenAiChat,
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

    /// `POST /v1/scan`.
    #[serde(default)]
    pub scan: RouteSwitch,

    /// `POST /beta/litellm_basic_guardrail_api`.
    #[serde(default)]
    pub litellm: RouteSwitch,
}

fn default_http_api_listen() -> String {
    "0.0.0.0:8083".into()
}

/// Turns one HTTP API route on or off. `http_api.enabled` starts the
/// listener; this table decides whether the route exists on it.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RouteSwitch {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Written by hand: `HttpApiConfig` derives `Default`, and a derived default
/// here would turn every route off.
impl Default for RouteSwitch {
    fn default() -> Self {
        Self { enabled: true }
    }
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
        config.validate_model_guard_artifacts()?;
        config.warn_on_empty_guard_set();
        config.warn_on_model_thread_total();
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

    /// Warn once when the model guards' threads add up to more than the CPUs.
    ///
    /// Not an error: a config valid on a 16-CPU host must not fail on an
    /// 8-CPU one. Above the CPU count, sessions compete for cores and latency
    /// rises without a throughput gain. PII scanner threads are not counted;
    /// a regex scan takes microseconds.
    pub fn warn_on_model_thread_total(&self) {
        let cpus = available_cpus();
        let total = self.model_thread_total(cpus);
        if total > cpus {
            tracing::warn!(
                threads = total,
                cpus,
                "model guard threads add up to more than the CPU count",
            );
        }
    }

    /// The worker threads of the model guard `name`, given `cpus` available
    /// CPUs: the configured `threads`, or an even share of the CPUs among the
    /// model guards, at least 1.
    pub fn effective_model_threads(&self, name: &str, cpus: usize) -> NonZeroUsize {
        // Validation rejects `threads = 0`, so a set value is never replaced.
        self.guards[name]
            .threads
            .and_then(NonZeroUsize::new)
            .unwrap_or_else(|| {
                NonZeroUsize::new(cpus / self.guards.len()).unwrap_or(NonZeroUsize::MIN)
            })
    }

    /// The sum of every model guard's threads, given `cpus` available CPUs.
    fn model_thread_total(&self, cpus: usize) -> usize {
        self.guards
            .keys()
            .map(|name| self.effective_model_threads(name, cpus).get())
            .sum()
    }
}

/// The CPUs this process may use. Follows cgroup limits such as Docker's
/// `--cpus`.
pub fn available_cpus() -> usize {
    std::thread::available_parallelism()
        .map(NonZeroUsize::get)
        .unwrap_or(1)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

impl AppConfig {
    pub fn validate(&self) -> Result<(), Error> {
        self.validate_forward_proxy_disabled()?;
        self.validate_at_least_one_mode()?;
        self.validate_at_least_one_http_api_route()?;
        self.validate_no_port_conflicts()?;
        self.validate_tls_disabled()?;
        self.validate_builtin_guard_names()?;
        self.validate_scanner_threads()?;
        self.validate_pii_kinds_exclusivity()?;
        self.validate_custom_pii()?;
        self.validate_guard_surfaces()?;
        self.validate_model_guards()?;
        self.validate_reverse_proxy()?;
        Ok(())
    }

    /// Every guard's name, built-in and configured, in one flat space. This is
    /// what a route may select from.
    fn known_guard_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.builtin_guards.enabled_names();
        names.extend(self.guards.keys().map(String::as_str));
        names
    }

    /// The forward proxy is not built. Enabling it would start a proxy that
    /// lacks the mode the config asks for. It runs before the mode check, so a
    /// config that enables only the forward proxy hears the real cause.
    fn validate_forward_proxy_disabled(&self) -> Result<(), Error> {
        if self.forward_proxy.enabled {
            return Err(Error::Config(
                "forward_proxy.enabled = true is not supported: the forward proxy is not built"
                    .into(),
            ));
        }
        Ok(())
    }

    fn validate_at_least_one_mode(&self) -> Result<(), Error> {
        if !self.reverse_proxy.enabled && !self.http_api.enabled {
            return Err(Error::Config(
                "at least one mode must be enabled (reverse_proxy or http_api)".into(),
            ));
        }
        Ok(())
    }

    /// An enabled HTTP API with every route off would bind a listener that
    /// answers 404 to everything. While the listener is off, the switches
    /// have no effect and any value is valid.
    fn validate_at_least_one_http_api_route(&self) -> Result<(), Error> {
        let api = &self.http_api;
        if api.enabled && !api.scan.enabled && !api.litellm.enabled {
            return Err(Error::Config(
                "http_api.enabled = true needs at least one route: \
                 http_api.scan.enabled and http_api.litellm.enabled are both false"
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

    /// TLS is not built. A `tls` table that asks for it would start a proxy
    /// that serves plaintext, so it fails whether or not its mode is enabled.
    fn validate_tls_disabled(&self) -> Result<(), Error> {
        let tables = [
            ("reverse_proxy", &self.reverse_proxy.tls),
            ("forward_proxy", &self.forward_proxy.tls),
        ];
        if let Some((mode, _)) = tables.iter().find(|(_, tls)| tls.enabled) {
            return Err(Error::Config(format!(
                "{mode}.tls.enabled = true is not supported: TLS is not built; \
                 terminate TLS in front of the proxy"
            )));
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

    /// A surface that admits nothing describes a guard that can never be
    /// called, whichever kind of guard carries it.
    fn validate_guard_surfaces(&self) -> Result<(), Error> {
        if let Some(pii) = self.pii_guard()
            && pii.surface.admits_nothing()
        {
            return Err(Error::Config(format!(
                "builtin_guards.{BUILTIN_PII_GUARD_NAME}.surface: every target is \
                 disabled, so the guard can never be called",
            )));
        }
        for (name, guard) in &self.guards {
            if guard.surface.admits_nothing() {
                return Err(Error::Config(format!(
                    "guards.{name}.surface: every target is disabled, so the guard can \
                     never be called",
                )));
            }
        }
        Ok(())
    }

    /// The `[guards.<name>]` rules the schema cannot express.
    ///
    /// An unknown `adapter` is absent here: the build fixes the adapter names,
    /// so serde rejects one at the schema stage. Artifact existence is absent
    /// too — it touches the filesystem and carries the `file` category, so it
    /// lives in [`AppConfig::validate_model_guard_artifacts`].
    fn validate_model_guards(&self) -> Result<(), Error> {
        for (name, guard) in &self.guards {
            validate_configured_guard_name(name)?;

            if guard.labels.is_empty() {
                return Err(Error::Config(format!(
                    "guards.{name}.labels: must not be empty; a guard that declares no \
                     label can report nothing",
                )));
            }
            let mut seen: HashSet<&str> = HashSet::new();
            for label in &guard.labels {
                if !seen.insert(label.as_str()) {
                    return Err(Error::Config(format!(
                        "guards.{name}.labels: duplicate label '{label}'; each label \
                         names one kind",
                    )));
                }
            }

            match guard.adapter {
                AdapterKind::TextClassifier => {
                    if guard.labels.len() != 1 {
                        return Err(Error::Config(format!(
                            "guards.{name}.labels: holds {} labels; text_classifier takes \
                             exactly one, naming class 1 of the model's two outputs",
                            guard.labels.len(),
                        )));
                    }
                }
                AdapterKind::TextMultilabelClassifier => {
                    return Err(Error::Config(format!(
                        "guards.{name}.adapter: '{}' is not built",
                        guard.adapter.name(),
                    )));
                }
            }

            if guard.max_tokens < MIN_MODEL_GUARD_MAX_TOKENS {
                return Err(Error::Config(format!(
                    "guards.{name}.max_tokens: is {}; the minimum is \
                     {MIN_MODEL_GUARD_MAX_TOKENS}",
                    guard.max_tokens,
                )));
            }

            if guard.threads == Some(0) {
                return Err(Error::Config(format!(
                    "guards.{name}.threads: must be >= 1",
                )));
            }

            if let Some(overlap) = guard.overlap_tokens {
                voidwall_ml::check_overlap(guard.max_tokens, overlap)
                    .map_err(|e| Error::Config(format!("guards.{name}: {e}")))?;
            }

            let range = guard.adapter.score_range();
            for (kind, score) in &guard.thresholds {
                if !guard.labels.iter().any(|label| label == kind) {
                    return Err(Error::Config(format!(
                        "guards.{name}.thresholds: '{kind}' is absent from labels, so it \
                         names a kind this guard does not declare",
                    )));
                }
                if !range.contains(score) {
                    return Err(Error::Config(format!(
                        "guards.{name}.thresholds: '{kind}' is {score}, outside the \
                         adapter's score range {}..={}",
                        range.start(),
                        range.end(),
                    )));
                }
            }
        }
        Ok(())
    }

    /// Every artifact a configured model guard names must be on disk.
    ///
    /// Held apart from [`AppConfig::validate`] for two reasons: a missing file
    /// is a `file` failure rather than a semantic one, and this is the only
    /// check that touches the filesystem — the rest of validation is a pure
    /// function of the config file.
    ///
    /// It asks whether the path is a file and nothing more. Reading, parsing,
    /// or executing an artifact belongs to the phase that builds the runtime:
    /// a tensor shape cannot prove label semantics, so there is nothing here
    /// worth opening the file for.
    pub fn validate_model_guard_artifacts(&self) -> Result<(), Error> {
        for (name, guard) in &self.guards {
            for (field, path) in [
                ("model_path", &guard.model_path),
                ("tokenizer_path", &guard.tokenizer_path),
            ] {
                if !path.is_file() {
                    return Err(Error::Config(format!(
                        "guards.{name}.{field}: no file at '{}'",
                        path.display(),
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_reverse_proxy(&self) -> Result<(), Error> {
        if !self.reverse_proxy.enabled {
            return Ok(());
        }

        let known = self.known_guard_names();
        let mut prefixes = HashSet::new();
        for route in &self.reverse_proxy.routes {
            if let Some(selected) = &route.guards {
                for name in selected {
                    if !known.contains(&name.as_str()) {
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
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
        assert!(config.content_types.iter().any(|c| c == "application/json"));
    }

    #[test]
    fn ingest_keys_are_read_from_the_top_level() {
        let toml = r#"
max_body_size = 2048
content_types = ["application/json"]
on_error = "fail_open"

[builtin_guards.pii]
countries = ["Us"]

[http_api]
enabled = true
listen = "0.0.0.0:8083"
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
"#;
        let err = parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("max_body_size"), "got: {msg}");
    }

    // --- Upstream timeout ---

    #[test]
    fn upstream_timeout_defaults_to_300_seconds() {
        let config = parse(&minimal_toml()).unwrap();
        assert_eq!(
            config.upstream_timeout_secs.as_duration(),
            Duration::from_secs(300)
        );
    }

    #[test_case(1 ; "lower bound")]
    #[test_case(60 ; "inside")]
    #[test_case(3600 ; "upper bound")]
    fn upstream_timeout_is_read_from_the_top_level(secs: u64) {
        let toml = format!("upstream_timeout_secs = {secs}\n{}", minimal_toml());
        let config = parse(&toml).unwrap();
        assert_eq!(
            config.upstream_timeout_secs.as_duration(),
            Duration::from_secs(secs)
        );
    }

    #[test_case("0" ; "zero")]
    #[test_case("-1" ; "negative")]
    #[test_case("3601" ; "above the upper bound")]
    #[test_case("9223372036854775807" ; "largest TOML integer")]
    fn upstream_timeout_outside_the_range_is_rejected(value: &str) {
        let toml = format!("upstream_timeout_secs = {value}\n{}", minimal_toml());
        let msg = parse(&toml).unwrap_err().to_string();
        assert!(msg.contains("upstream_timeout_secs"), "got: {msg}");
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
"#;
        let config = parse(toml).unwrap();
        let surface = &config.builtin_guards.pii.as_ref().unwrap().surface;
        assert!(!surface.body);
        assert!(surface.url_path, "the other targets keep their default");
        assert!(surface.query_params);
    }

    /// `headers` is an on/off switch over units the route already built, never
    /// a header allowlist. Which headers carry sensitive values is a property
    /// of the traffic, so a guard reaching for the *list* is told it does not
    /// live there.
    #[test]
    fn a_surface_naming_headers_is_rejected() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[builtin_guards.pii.surface]
headers = ["x-forwarded-for"]

[http_api]
enabled = true
listen = "0.0.0.0:8083"
"#;
        let err = parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("expected a boolean"), "got: {msg}");
        assert!(msg.contains("headers"), "got: {msg}");
    }

    #[test]
    fn a_built_in_guard_may_decline_header_units() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[builtin_guards.pii.surface]
headers = false

[http_api]
enabled = true
listen = "0.0.0.0:8083"
"#;
        let config = parse(toml).unwrap();
        let surface = &config.builtin_guards.pii.as_ref().unwrap().surface;
        assert!(!surface.headers);
        assert!(surface.body, "the other targets keep their default");
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

    #[test_case("", RouteFormat::Generic ; "format is absent")]
    #[test_case("format = \"openai-chat\"", RouteFormat::OpenAiChat ; "format is openai-chat")]
    fn a_route_reads_its_format(line: &str, expected: RouteFormat) {
        let toml = format!(
            "{}\n[reverse_proxy]\nenabled = true\n\n[[reverse_proxy.routes]]\n\
             path_prefix = \"/v1\"\nupstream = \"http://localhost:8080\"\n{line}\n",
            minimal_toml()
        );
        let config = parse(&toml).unwrap();
        assert_eq!(config.reverse_proxy.routes[0].format, expected);
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
"#;
        let config = parse(toml).unwrap();
        assert!(!config.builtin_guards.pii.as_ref().unwrap().enabled);
        assert!(config.builtin_guards.enabled_pii().is_none());
        assert!(config.builtin_guards.enabled_names().is_empty());
    }

    #[test]
    fn an_absent_guard_section_builds_no_guard() {
        let toml = r#"
[http_api]
enabled = true
listen = "0.0.0.0:8083"
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
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

        assert_eq!(
            routes[0].guards.as_deref(),
            Some(["pii".to_string()].as_slice())
        );
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
        assert!(
            config.reverse_proxy.routes[0]
                .selected_guards(&enabled)
                .is_empty()
        );
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
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

    // --- HTTP API route switches ---

    #[test_case("", true, true ; "both tables absent")]
    #[test_case("[http_api.scan]\nenabled = false\n", false, true ; "only the litellm route")]
    #[test_case("[http_api.litellm]\nenabled = false\n", true, false ; "only the scan route")]
    #[test_case("[http_api.scan]\n[http_api.litellm]\n", true, true ; "empty tables")]
    fn route_switches_parse_and_validate(tables: &str, scan: bool, litellm: bool) {
        let cfg = parse(&format!("{}\n{tables}", minimal_toml())).expect("valid");
        assert_eq!(cfg.http_api.scan.enabled, scan);
        assert_eq!(cfg.http_api.litellm.enabled, litellm);
    }

    #[test]
    fn every_http_api_route_off_fails_and_names_both_switches() {
        let toml = format!(
            "{}\n[http_api.scan]\nenabled = false\n[http_api.litellm]\nenabled = false\n",
            minimal_toml()
        );
        let err = parse(&toml).expect_err("an enabled HTTP API needs a route");
        let msg = err.to_string();
        assert!(msg.contains("http_api.scan.enabled"), "got: {msg}");
        assert!(msg.contains("http_api.litellm.enabled"), "got: {msg}");
        // `Error::Config` is what `validate.rs` categorises as `semantic`.
        assert!(matches!(err, Error::Config(_)), "got: {err:?}");
    }

    #[test]
    fn every_route_off_is_valid_while_the_http_api_is_disabled() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[http_api]
enabled = false

[http_api.scan]
enabled = false

[http_api.litellm]
enabled = false

[reverse_proxy]
enabled = true
listen = "0.0.0.0:8082"

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:8080"
"#;
        let cfg = parse(toml).expect("the switches have no effect while the listener is off");
        assert!(!cfg.http_api.enabled);
    }

    #[test]
    fn an_unknown_key_in_a_route_table_is_rejected_by_name() {
        let toml = format!("{}\n[http_api.litellm]\npath = \"/x\"\n", minimal_toml());
        let msg = parse(&toml).unwrap_err().to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("path"), "got: {msg}");
    }

    // --- Invalid: port conflicts ---

    #[test]
    fn invalid_port_conflict() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[http_api]
enabled = true
listen = "0.0.0.0:9090"

[admin]
listen = "0.0.0.0:9090"
"#;
        let err = parse(toml).unwrap_err();
        assert!(err.to_string().contains("port conflict"));
    }

    // --- Invalid: the forward proxy is enabled ---

    #[test_case("[http_api]\nenabled = true\n" ; "with another mode")]
    #[test_case("" ; "as the only mode")]
    fn forward_proxy_enabled_fails_and_names_the_key(other_mode: &str) {
        let toml = format!(
            r#"
[builtin_guards.pii]
countries = ["Us"]

{other_mode}
[forward_proxy]
enabled = true
"#
        );
        let err = parse(&toml).expect_err("the forward proxy is not built");
        let msg = err.to_string();
        assert!(msg.contains("forward_proxy.enabled"), "got: {msg}");
        assert!(!msg.contains("at least one mode"), "got: {msg}");
        // `Error::Config` is what `validate.rs` categorises as `semantic`.
        assert!(matches!(err, Error::Config(_)), "got: {err:?}");
    }

    #[test]
    fn forward_proxy_disabled_table_passes() {
        let toml = format!(
            "{}{}",
            minimal_toml(),
            r#"
[forward_proxy]
enabled = false
listen = "0.0.0.0:8084"

[forward_proxy.request]
scan = true

[forward_proxy.response]
scan = false
"#
        );
        parse(&toml).expect("a disabled forward proxy table is valid");
    }

    #[test]
    fn forward_proxy_schema_rules_still_apply() {
        let toml = format!(
            "{}{}",
            minimal_toml(),
            "\n[forward_proxy.request]\nscan = true\nactions = [\"block\"]\n"
        );
        let err = parse(&toml).expect_err("an unknown key fails even though the mode does not run");
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }

    // --- Invalid: TLS is enabled ---

    #[test_case("reverse_proxy", true ; "reverse proxy, mode enabled")]
    #[test_case("forward_proxy", false ; "forward proxy, mode disabled")]
    fn tls_enabled_fails_and_names_the_key(mode: &str, mode_enabled: bool) {
        let toml = format!(
            r#"
[builtin_guards.pii]
countries = ["Us"]

[http_api]
enabled = true

[{mode}]
enabled = {mode_enabled}
listen = "0.0.0.0:18080"

[{mode}.tls]
enabled = true
cert_path = "/etc/voidwall/cert.pem"
key_path = "/etc/voidwall/key.pem"
"#
        );
        let err = parse(&toml).expect_err("TLS is not built");
        assert!(
            err.to_string().contains(&format!("{mode}.tls.enabled")),
            "got: {err}"
        );
        // `Error::Config` is what `validate.rs` categorises as `semantic`.
        assert!(matches!(err, Error::Config(_)), "got: {err:?}");
    }

    #[test_case("reverse_proxy" ; "reverse proxy")]
    #[test_case("forward_proxy" ; "forward proxy")]
    fn tls_disabled_with_paths_passes(mode: &str) {
        let toml = format!(
            r#"
[builtin_guards.pii]
countries = ["Us"]

[http_api]
enabled = true

[{mode}.tls]
enabled = false
cert_path = "/etc/voidwall/cert.pem"
key_path = "/etc/voidwall/key.pem"
"#
        );
        parse(&toml).expect("a disabled TLS table is valid");
    }

    // --- Invalid: unknown built-in guard (2.1) ---

    #[test]
    fn an_unknown_built_in_guard_is_rejected_by_name() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[builtin_guards.jailbreak]
threshold = 0.5

[http_api]
enabled = true
listen = "0.0.0.0:8083"
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"

[admin]
listen = "127.0.0.1:9090"
"#;
        let config = parse(toml).unwrap();
        assert!(config.reverse_proxy.enabled);
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
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
        assert!(
            config
                .builtin_guards
                .pii
                .as_ref()
                .unwrap()
                .custom
                .is_empty()
        );
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
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

[http_api]
enabled = true
listen = "0.0.0.0:8083"
"#
        );
        let err = parse(&toml).unwrap_err();
        assert!(
            err.to_string().contains("'Custom' is reserved"),
            "got: {err}"
        );
    }

    // --- Model guards: schema ---

    /// The smallest section from the design's § 3, plus a mode so the file is
    /// startable. Artifact paths are not opened by `validate`.
    fn model_guard_toml(section: &str) -> String {
        format!(
            r#"
[builtin_guards.pii]
countries = ["Us"]

{section}

[http_api]
enabled = true
"#
        )
    }

    const SMALLEST_MODEL_GUARD: &str = r#"
[guards.injection]
adapter = "text_classifier"
model_path = "/opt/voidwall/models/injection/model.onnx"
tokenizer_path = "/opt/voidwall/models/injection/tokenizer.json"
max_tokens = 512
labels = ["PROMPT_INJECTION"]

[guards.injection.thresholds]
PROMPT_INJECTION = 0.90
"#;

    #[test]
    fn the_smallest_model_guard_section_loads() {
        let config = parse(&model_guard_toml(SMALLEST_MODEL_GUARD)).expect("should be valid");
        let guard = &config.guards["injection"];
        assert_eq!(guard.adapter, AdapterKind::TextClassifier);
        assert_eq!(guard.max_tokens, 512);
        assert_eq!(guard.labels, vec!["PROMPT_INJECTION".to_string()]);
        assert_eq!(guard.thresholds["PROMPT_INJECTION"], 0.90);
        assert_eq!(guard.surface, ModelGuardSurface::default());
    }

    /// `guards` is a new optional key, so a file that never mentions it keeps
    /// its meaning.
    #[test]
    fn the_guards_key_is_optional_and_empty_by_default() {
        assert!(parse(&minimal_toml()).unwrap().guards.is_empty());
    }

    #[test_case("text_classifier", AdapterKind::TextClassifier ; "single label")]
    #[test_case("text_multilabel_classifier", AdapterKind::TextMultilabelClassifier ; "multi label")]
    fn an_adapter_name_the_build_ships_deserialises(name: &str, expected: AdapterKind) {
        let toml = format!(
            r#"
[guards.g]
adapter = "{name}"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["K"]
"#
        );
        let config = toml::from_str::<AppConfig>(&model_guard_toml(&toml))
            .expect("shipped adapter should deserialise");
        assert_eq!(config.guards["g"].adapter, expected);
    }

    /// The build fixes the adapter names, so serde states the set and an
    /// unknown one never reaches a validation rule.
    #[test]
    fn an_unknown_adapter_is_a_schema_error_naming_the_value() {
        let toml = model_guard_toml(
            r#"
[guards.g]
adapter = "tea_leaves"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["K"]
"#,
        );
        let err = toml::from_str::<AppConfig>(&toml).expect_err("unknown adapter must fail");
        let msg = err.to_string();
        assert!(msg.contains("tea_leaves"), "got: {msg}");
        assert!(msg.contains("text_classifier"), "got: {msg}");
    }

    /// ONNX is the only runtime, so the key could only be written wrong.
    #[test]
    fn a_model_guard_naming_a_runtime_is_rejected() {
        let toml = model_guard_toml(
            r#"
[guards.g]
adapter = "text_classifier"
runtime = "onnx"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["K"]
"#,
        );
        let err = toml::from_str::<AppConfig>(&toml).expect_err("runtime must be rejected");
        assert!(err.to_string().contains("runtime"), "got: {err}");
    }

    /// Two guards may point at the same artifacts. That loads the model twice,
    /// which is the operator's choice rather than an error.
    #[test]
    fn two_guards_may_name_the_same_artifacts() {
        let toml = model_guard_toml(
            r#"
[guards.a]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["K"]

[guards.b]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["K"]
"#,
        );
        assert_eq!(parse(&toml).expect("should be valid").guards.len(), 2);
    }

    // --- Model guards: surface defaults ---

    /// The footgun a shared surface type would have: the keys this table omits
    /// have to fall back to the *model* defaults, not the built-in guard's.
    #[test]
    fn a_partial_model_guard_surface_takes_the_model_defaults() {
        let toml = model_guard_toml(
            r#"
[guards.g]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["K"]

[guards.g.surface]
url_path = true
"#,
        );
        let surface = parse(&toml).expect("should be valid").guards["g"]
            .surface
            .clone();
        assert!(surface.url_path);
        assert!(surface.body, "body defaults on");
        assert!(
            !surface.query_params,
            "query defaults off for a model guard"
        );
        assert!(!surface.headers, "headers default off for a model guard");
    }

    #[test]
    fn an_omitted_model_guard_surface_is_the_body_alone() {
        let surface = ModelGuardSurface::default();
        assert!(surface.body);
        assert!(!surface.url_path);
        assert!(!surface.query_params);
        assert!(!surface.headers);
    }

    /// The built-in guard keeps its own defaults, headers included, so no
    /// existing config changes meaning.
    #[test]
    fn a_built_in_guard_surface_defaults_every_target_on() {
        let surface = GuardSurface::default();
        assert!(surface.url_path && surface.query_params && surface.body && surface.headers);
    }

    // --- Guard names ---

    #[test_case("injection" ; "plain")]
    #[test_case("injection_check" ; "underscore")]
    #[test_case("general-safety" ; "hyphen")]
    #[test_case("G9" ; "upper and digit")]
    #[test_case(&"n".repeat(MAX_GUARD_NAME_LEN) ; "at the cap")]
    fn a_permitted_guard_name_is_accepted(name: &str) {
        validate_configured_guard_name(name).expect("name should be accepted");
    }

    #[test_case("injection.v2", "." ; "dot")]
    #[test_case("inj ection", " " ; "space")]
    #[test_case("wstrzyknięcie", "ę" ; "non ascii")]
    fn a_guard_name_outside_the_charset_is_rejected(name: &str, offender: &str) {
        let err = validate_configured_guard_name(name).expect_err("must be rejected");
        let msg = err.to_string();
        assert!(msg.contains(name), "must name the guard, got: {msg}");
        assert!(
            msg.contains(offender),
            "must name the character, got: {msg}"
        );
    }

    #[test]
    fn an_empty_guard_name_is_rejected() {
        let err = validate_configured_guard_name("").expect_err("must be rejected");
        assert!(err.to_string().contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn a_guard_name_over_the_cap_is_rejected_naming_the_limit() {
        let name = "n".repeat(MAX_GUARD_NAME_LEN + 1);
        let err = validate_configured_guard_name(&name).expect_err("must be rejected");
        let msg = err.to_string();
        assert!(msg.contains(&MAX_GUARD_NAME_LEN.to_string()), "got: {msg}");
    }

    #[test_case(BUILTIN_PII_GUARD_NAME ; "the built-in pii guard")]
    fn a_reserved_guard_name_is_rejected(name: &str) {
        let err = validate_configured_guard_name(name).expect_err("must be rejected");
        assert!(err.to_string().contains("reserved"), "got: {err}");
    }

    /// The rule had no caller until `[guards.<name>]` existed. This is it.
    #[test]
    fn a_model_guard_name_outside_the_charset_fails_the_load() {
        let toml = model_guard_toml(
            r#"
[guards."inj.v2"]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["K"]
"#,
        );
        let err = parse(&toml).expect_err("a dotted guard name must fail");
        assert!(err.to_string().contains("inj.v2"), "got: {err}");
    }

    #[test]
    fn a_model_guard_may_not_take_a_built_in_name() {
        let toml = model_guard_toml(
            r#"
[guards.pii]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["K"]
"#,
        );
        let err = parse(&toml).expect_err("a reserved name must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("pii") && msg.contains("reserved"),
            "got: {msg}"
        );
    }

    // --- Model guards: semantic rules ---

    #[test]
    fn a_threshold_absent_from_labels_is_rejected_naming_the_guard_and_the_kind() {
        let toml = model_guard_toml(
            r#"
[guards.injection]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["PROMPT_INJECTION"]

[guards.injection.thresholds]
PROMPT_INJETCION = 0.9
"#,
        );
        let err = parse(&toml).expect_err("a misspelled threshold key must fail");
        let msg = err.to_string();
        assert!(msg.contains("injection"), "must name the guard, got: {msg}");
        assert!(
            msg.contains("PROMPT_INJETCION"),
            "must name the kind, got: {msg}"
        );
    }

    /// A label is whatever the operator writes: the build has no closed set of
    /// finding kinds to check one against.
    #[test]
    fn a_label_the_build_has_never_heard_of_still_loads() {
        let toml = model_guard_toml(
            r#"
[guards.g]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["SOMETHING_ONLY_THIS_MODEL_EMITS"]

[guards.g.thresholds]
SOMETHING_ONLY_THIS_MODEL_EMITS = 0.5
"#,
        );
        let config = parse(&toml).expect("an unknown label is not an error");
        assert_eq!(config.guards["g"].labels.len(), 1);
    }

    /// A label with no threshold reports nothing. That absence is the only
    /// detection-layer off switch, so it is valid rather than incomplete.
    #[test]
    fn a_label_with_no_threshold_loads() {
        let toml = model_guard_toml(
            r#"
[guards.g]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["HATE_SPEECH"]
"#,
        );
        let config = parse(&toml).expect("a label without a threshold is valid");
        assert!(!config.guards["g"].thresholds.contains_key("HATE_SPEECH"));
    }

    #[test_case(1.5 ; "above the range")]
    #[test_case(-0.1 ; "below the range")]
    fn a_threshold_outside_the_adapters_range_is_rejected(score: f32) {
        let toml = model_guard_toml(&format!(
            r#"
[guards.injection]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["PROMPT_INJECTION"]

[guards.injection.thresholds]
PROMPT_INJECTION = {score}
"#
        ));
        let err = parse(&toml).expect_err("an out-of-range threshold must fail");
        let msg = err.to_string();
        assert!(msg.contains("injection"), "must name the guard, got: {msg}");
        assert!(
            msg.contains("PROMPT_INJECTION"),
            "must name the kind, got: {msg}"
        );
        assert!(msg.contains("0..=1"), "must name the range, got: {msg}");
    }

    #[test_case(0.0 ; "the low bound")]
    #[test_case(1.0 ; "the high bound")]
    fn a_threshold_on_the_range_bound_is_accepted(score: f32) {
        let toml = model_guard_toml(&format!(
            r#"
[guards.g]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["K"]

[guards.g.thresholds]
K = {score}
"#
        ));
        parse(&toml).expect("the range is inclusive");
    }

    #[test]
    fn a_model_guard_surface_with_every_target_disabled_is_rejected() {
        let toml = model_guard_toml(
            r#"
[guards.injection]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["K"]

[guards.injection.surface]
url_path = false
query_params = false
body = false
headers = false
"#,
        );
        let err = parse(&toml).expect_err("a guard that can never be called must fail");
        assert!(err.to_string().contains("injection"), "got: {err}");
    }

    #[test]
    fn a_built_in_guard_surface_with_every_target_disabled_is_rejected() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[builtin_guards.pii.surface]
url_path = false
query_params = false
body = false
headers = false

[http_api]
enabled = true
"#;
        let err = parse(toml).expect_err("a guard that can never be called must fail");
        assert!(err.to_string().contains("pii"), "got: {err}");
    }

    /// A configured model guard is a selectable name.
    #[test]
    fn a_route_may_select_a_configured_model_guard_by_name() {
        let toml = r#"
[builtin_guards.pii]
countries = ["Us"]

[guards.injection]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["PROMPT_INJECTION"]

[reverse_proxy]
enabled = true

[[reverse_proxy.routes]]
path_prefix = "/"
upstream = "http://localhost:9000"
guards = ["pii", "injection"]
"#;
        parse(toml).expect("a configured model guard is a selectable name");
    }

    /// A guard that declares no label can report nothing, so the list is not
    /// an optional part of the tensor contract.
    #[test]
    fn an_empty_labels_list_is_rejected_naming_the_guard() {
        let toml = model_guard_toml(
            r#"
[guards.injection]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = []
"#,
        );
        let err = parse(&toml).expect_err("a guard with no label must fail");
        let msg = err.to_string();
        assert!(msg.contains("injection"), "must name the guard, got: {msg}");
        assert!(msg.contains("must not be empty"), "got: {msg}");
    }

    /// One label names one kind, so a repeated label is a config no adapter
    /// can mean.
    #[test]
    fn a_duplicate_label_is_rejected_naming_the_guard_and_the_label() {
        let toml = model_guard_toml(
            r#"
[guards.safety]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["PROMPT_INJECTION", "PROMPT_INJECTION"]
"#,
        );
        let err = parse(&toml).expect_err("a duplicate label must fail");
        let msg = err.to_string();
        assert!(msg.contains("safety"), "must name the guard, got: {msg}");
        assert!(
            msg.contains("PROMPT_INJECTION"),
            "must name the label, got: {msg}"
        );
        assert!(msg.contains("duplicate"), "got: {msg}");
    }

    #[test_case(0 ; "zero")]
    #[test_case(1 ; "one")]
    #[test_case(MIN_MODEL_GUARD_MAX_TOKENS - 1 ; "just under the floor")]
    fn a_max_tokens_under_the_floor_is_rejected_naming_the_limit(max_tokens: usize) {
        let toml = model_guard_toml(&format!(
            r#"
[guards.injection]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = {max_tokens}
labels = ["PROMPT_INJECTION"]
"#
        ));
        let err = parse(&toml).expect_err("a window this small must fail");
        let msg = err.to_string();
        assert!(msg.contains("injection"), "must name the guard, got: {msg}");
        assert!(
            msg.contains(&MIN_MODEL_GUARD_MAX_TOKENS.to_string()),
            "must name the limit, got: {msg}",
        );
    }

    #[test]
    fn a_max_tokens_on_the_floor_is_accepted() {
        let toml = model_guard_toml(&format!(
            r#"
[guards.g]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = {MIN_MODEL_GUARD_MAX_TOKENS}
labels = ["K"]
"#
        ));
        parse(&toml).expect("the floor is inclusive");
    }

    // --- Model guards: adapter, threads, overlap ---

    /// A model guard section with `extra` lines added under it.
    fn model_guard_with(extra: &str) -> String {
        model_guard_toml(&format!(
            r#"
[guards.injection]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 16
labels = ["PROMPT_INJECTION"]
{extra}
"#
        ))
    }

    #[test]
    fn the_multilabel_adapter_is_rejected_as_not_built() {
        let toml = model_guard_toml(
            r#"
[guards.safety]
adapter = "text_multilabel_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["PROMPT_INJECTION", "HATE_SPEECH"]
"#,
        );
        let err = parse(&toml).expect_err("the multilabel adapter must fail");
        let msg = err.to_string();
        assert!(msg.contains("safety"), "must name the guard, got: {msg}");
        assert!(
            msg.contains("text_multilabel_classifier") && msg.contains("not built"),
            "got: {msg}"
        );
    }

    #[test]
    fn a_text_classifier_with_two_labels_is_rejected() {
        let toml = model_guard_toml(
            r#"
[guards.injection]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["PROMPT_INJECTION", "HATE_SPEECH"]
"#,
        );
        let err = parse(&toml).expect_err("two labels must fail");
        let msg = err.to_string();
        assert!(msg.contains("injection"), "must name the guard, got: {msg}");
        assert!(msg.contains("exactly one"), "got: {msg}");
    }

    #[test_case("threads = 3", Some(3) ; "set")]
    #[test_case("", None ; "absent")]
    fn threads_parse(line: &str, expected: Option<usize>) {
        let config = parse(&model_guard_with(line)).expect("should be valid");
        assert_eq!(config.guards["injection"].threads, expected);
    }

    #[test]
    fn zero_threads_are_rejected_naming_the_key() {
        let err = parse(&model_guard_with("threads = 0")).expect_err("zero must fail");
        let msg = err.to_string();
        assert!(msg.contains("threads"), "must name the key, got: {msg}");
        assert!(
            msg.contains("guards.injection"),
            "must name the guard, got: {msg}"
        );
    }

    #[test_case("overlap_tokens = 8" ; "at the bound")]
    #[test_case("overlap_tokens = 0" ; "zero")]
    #[test_case("" ; "absent")]
    fn an_overlap_within_the_bound_is_accepted(line: &str) {
        parse(&model_guard_with(line)).expect("should be valid");
    }

    #[test]
    fn an_overlap_above_the_bound_is_rejected_naming_both_numbers() {
        let err = parse(&model_guard_with("overlap_tokens = 9")).expect_err("must fail");
        let msg = err.to_string();
        assert!(msg.contains("injection"), "must name the guard, got: {msg}");
        assert!(msg.contains('9') && msg.contains('8'), "got: {msg}");
    }

    /// `n` model guards, each with `threads` set when given.
    fn with_model_guards(threads: &[Option<usize>]) -> AppConfig {
        let mut sections = String::new();
        for (i, t) in threads.iter().enumerate() {
            let line = t.map(|t| format!("threads = {t}")).unwrap_or_default();
            sections.push_str(&format!(
                r#"
[guards.g{i}]
adapter = "text_classifier"
model_path = "/m"
tokenizer_path = "/t"
max_tokens = 512
labels = ["K"]
{line}
"#
            ));
        }
        parse(&model_guard_toml(&sections)).expect("should be valid")
    }

    #[test_case(8, &[None, None], &[4, 4], false ; "even split")]
    #[test_case(2, &[None, None, None], &[1, 1, 1], true ; "more guards than cpus")]
    #[test_case(4, &[Some(6)], &[6], true ; "set above the cpus")]
    #[test_case(4, &[Some(1), None], &[1, 2], false ; "one set one default")]
    fn model_guard_threads(cpus: usize, set: &[Option<usize>], expected: &[usize], above: bool) {
        let config = with_model_guards(set);
        let got: Vec<usize> = config
            .guards
            .keys()
            .map(|name| config.effective_model_threads(name, cpus).get())
            .collect();
        assert_eq!(got, expected);
        assert_eq!(config.model_thread_total(cpus) > cpus, above);
    }

    // --- Model guard artifacts ---

    /// Validation asks whether the path is a file and never opens it: the
    /// tensor contract is checked when the guard loads at startup.
    #[test]
    fn validation_does_not_read_the_artifact_it_finds() {
        let model = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(model.path(), b"not an onnx model").expect("write");
        let toml = model_guard_toml(&format!(
            r#"
[guards.g]
adapter = "text_classifier"
model_path = "{path}"
tokenizer_path = "{path}"
max_tokens = 512
labels = ["K"]
"#,
            path = model.path().display(),
        ));
        let config = parse(&toml).expect("semantic rules pass");
        config
            .validate_model_guard_artifacts()
            .expect("the bytes are never read");
    }

    #[test_case("model_path" ; "the model")]
    #[test_case("tokenizer_path" ; "the tokenizer")]
    fn a_missing_artifact_is_reported_with_the_path_that_was_expected(field: &str) {
        let present = tempfile::NamedTempFile::new().expect("tempfile");
        let missing = "/definitely/does/not/exist/artifact.bin";
        let (model, tokenizer) = match field {
            "model_path" => (missing.to_string(), present.path().display().to_string()),
            _ => (present.path().display().to_string(), missing.to_string()),
        };
        let toml = model_guard_toml(&format!(
            r#"
[guards.injection]
adapter = "text_classifier"
model_path = "{model}"
tokenizer_path = "{tokenizer}"
max_tokens = 512
labels = ["K"]
"#
        ));
        let config = parse(&toml).expect("semantic rules pass");
        let err = config
            .validate_model_guard_artifacts()
            .expect_err("a missing artifact must fail");
        let msg = err.to_string();
        assert!(msg.contains("injection"), "must name the guard, got: {msg}");
        assert!(msg.contains(field), "must name the field, got: {msg}");
        assert!(msg.contains(missing), "must name the path, got: {msg}");
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
