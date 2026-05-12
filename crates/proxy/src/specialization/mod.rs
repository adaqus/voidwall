//! Specialization framework — per-endpoint adapters that decode a known
//! analytics wire format (GA4, Matomo, ...), scan a curated subset of fields,
//! and re-encode the result. See DESIGN.md § "Specializations" for the design
//! and TASKS.md § Phase 16 for the rollout plan.
//!
//! Phase 16.1 introduces the trait, registry, rate-limited warn helper, and
//! placeholder GA4/Matomo stubs. The real decoders land in 16.3 and 16.4.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;

use bytes::Bytes;
use tracing::warn;

use crate::config::OnError;
use crate::error::Error;
use crate::scanner::{BodyFormat, LogRateLimiter, RedactWith, ScanRequest, ScannerPool};
use crate::structured::OwnedContextFragment;

mod ga4;
mod matomo;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A re-encoded slice of an HTTP request — either the query string or the
/// body. Returned by [`Specialization::process`] when the specialization
/// touched that slot. `content_type` is the type the caller should attach
/// when forwarding `bytes` (relevant for the body slot; ignored for query).
#[derive(Debug, Clone)]
pub struct ProcessedPart {
    pub bytes: Bytes,
    pub content_type: Option<String>,
}

/// Output of a [`Specialization::process`] call.
///
/// `query` and `body` are each `Option<ProcessedPart>`. `None` means the
/// specialization left that slot untouched — both the case where the input
/// slot was `None` and the case where the spec deliberately skipped it. The
/// caller forwards the original bytes when a slot is `None`.
#[derive(Debug)]
pub struct ProcessedRequest {
    pub query: Option<ProcessedPart>,
    pub body: Option<ProcessedPart>,
    pub scan_result: AggregatedScan,
}

/// Aggregated scan results across every field a specialization fed through
/// the [`ScanHandle`].
#[derive(Debug, Default, Clone)]
pub struct AggregatedScan {
    /// Unique PII kind labels detected across all scanned fields, preserving
    /// first-seen order.
    pub kinds: Vec<String>,
    /// Total resolved matches across all scanned fields.
    pub matches_count: usize,
}

impl AggregatedScan {
    /// Merge a single field's scan result. Kind labels are deduplicated to
    /// preserve the bounded label cardinality contract that downstream
    /// metrics rely on.
    pub fn merge_field(&mut self, field: &FieldScanResult) {
        self.matches_count = self.matches_count.saturating_add(field.matches_count);
        for k in &field.kinds {
            if !self.kinds.iter().any(|existing| existing == k) {
                self.kinds.push(k.clone());
            }
        }
    }
}

/// Per-field result returned by [`ScanHandle::scan`].
#[derive(Debug, Clone, Default)]
pub struct FieldScanResult {
    pub kinds: Vec<String>,
    pub matches_count: usize,
    /// The redacted value, populated when redaction is enabled on the
    /// handle and at least one PII match was found. `None` when redaction
    /// is disabled or there was nothing to redact — the caller forwards the
    /// original value unchanged in both cases.
    pub redacted: Option<String>,
}

/// Why a specialization could not process a payload. Converted by the proxy
/// into a fallback to default scanning plus a
/// `pii_proxy_specialization_errors_total{reason=...}` increment, with the
/// exception of [`SpecializationError::UnsupportedContentType`] which is the
/// expected common case on the response side (1x1 gif / 204) and is silent.
#[derive(Debug, Clone)]
pub enum SpecializationError {
    /// Payload could not be decoded — invalid JSON, malformed form-encoding,
    /// unexpected top-level shape, etc. `reason` is a short stable tag used
    /// for the metrics label.
    Decode { reason: String },

    /// The body content-type is not one the spec handles. Silent fallback —
    /// no log, no error-counter increment.
    UnsupportedContentType,

    /// Nested URL decoding hit the spec's depth bound. Distinguished from
    /// `Decode` so operators can spot pathological payloads quickly.
    RecursionLimit,
}

impl SpecializationError {
    /// Stable short tag for the `pii_proxy_specialization_errors_total`
    /// `reason` label. Keeps cardinality bounded regardless of the freeform
    /// `Decode { reason }` body.
    pub fn reason_label(&self) -> &'static str {
        match self {
            SpecializationError::Decode { .. } => "decode",
            SpecializationError::UnsupportedContentType => "unsupported_content_type",
            SpecializationError::RecursionLimit => "recursion_limit",
        }
    }
}

impl std::fmt::Display for SpecializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpecializationError::Decode { reason } => write!(f, "decode error: {reason}"),
            SpecializationError::UnsupportedContentType => write!(f, "unsupported content type"),
            SpecializationError::RecursionLimit => write!(f, "recursion limit reached"),
        }
    }
}

impl std::error::Error for SpecializationError {}

/// Pinned boxed future returned by [`Specialization::process`]. Boxing keeps
/// the trait dyn-compatible so the registry can hand out
/// `&'static dyn Specialization`.
pub type ProcessFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ProcessedRequest, SpecializationError>> + Send + 'a>>;

/// Adapter for a specific third-party endpoint's wire format. See DESIGN.md
/// § "Specializations" for the contract.
///
/// Specializations own the full decode → scan → encode loop for the query
/// string and the body. They never expose raw byte offsets to the
/// redaction code — instead they call [`ScanHandle::scan`] per field and
/// stitch the redacted replacements back into the re-encoded payload.
pub trait Specialization: Send + Sync + 'static {
    /// Stable identifier used in config and metrics (e.g. `"ga4"`,
    /// `"matomo"`).
    fn name(&self) -> &'static str;

    /// Decode → scan → re-encode a request's query and body.
    fn process<'a>(
        &'a self,
        query: Option<&'a str>,
        body: Option<&'a [u8]>,
        body_content_type: Option<&'a str>,
        scan: &'a ScanHandle<'a>,
    ) -> ProcessFuture<'a>;
}

/// Handle that lets a specialization scan (and optionally redact) one field
/// value at a time. Each call submits a single-fragment structured scan to
/// the shared [`ScannerPool`]; keyword-context detectors see `context` as
/// the field's path next to the value, which is what makes per-field
/// scanning at least as accurate as flat scanning of the same byte range.
pub struct ScanHandle<'a> {
    pool: &'a ScannerPool,
    redact: bool,
    strategy: Option<RedactWith>,
    on_error: OnError,
}

impl<'a> ScanHandle<'a> {
    pub fn new(
        pool: &'a ScannerPool,
        redact: bool,
        strategy: Option<RedactWith>,
        on_error: OnError,
    ) -> Self {
        Self {
            pool,
            redact,
            strategy,
            on_error,
        }
    }

    /// True when this handle will populate `FieldScanResult::redacted` on a
    /// detection. Specializations check this before doing extra encoding
    /// work for the redact path.
    pub fn redact_enabled(&self) -> bool {
        self.redact && self.strategy.is_some()
    }

    /// Scan a single field value. `context` is the field's path in the
    /// spec's wire format (e.g. `"uid"`, `"events[0].params.email"`) — it
    /// drives keyword-context detection. Empty `value` short-circuits.
    pub async fn scan(&self, context: &str, value: &str) -> Result<FieldScanResult, Error> {
        if value.is_empty() {
            return Ok(FieldScanResult::default());
        }
        let raw = Bytes::copy_from_slice(value.as_bytes());
        let fragments = vec![OwnedContextFragment {
            context: context.to_string(),
            value: value.to_string(),
            offset: 0,
        }];
        let req = ScanRequest {
            body: Some(BodyFormat::Structured { fragments, raw }),
            path: None,
            query: None,
            headers: None,
            redact: self.redact,
            redact_strategy: self.strategy.clone(),
        };
        let result = self.pool.process(req, self.on_error).await?;
        let redacted = result
            .redacted_body
            .and_then(|b| String::from_utf8(b.to_vec()).ok());
        Ok(FieldScanResult {
            kinds: result.kinds,
            matches_count: result.matches_count,
            redacted,
        })
    }
}

// ---------------------------------------------------------------------------
// Built-in registry
// ---------------------------------------------------------------------------

/// Look up a built-in specialization by stable name. Returns `None` for
/// unknown names; callers translate that into a startup error (reverse
/// proxy config) or a per-request `400` (HTTP API).
pub fn lookup(name: &str) -> Option<&'static dyn Specialization> {
    match name {
        "ga4" => Some(&ga4::Ga4Specialization),
        "matomo" => Some(&matomo::MatomoSpecialization),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Rate-limited warn helper
// ---------------------------------------------------------------------------

const WARN_INTERVAL_MS: u64 = 60_000;

static WARN_LIMITERS: LazyLock<HashMap<&'static str, LogRateLimiter>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert("ga4", LogRateLimiter::new(WARN_INTERVAL_MS));
    m.insert("matomo", LogRateLimiter::new(WARN_INTERVAL_MS));
    m
});

/// Emit a warning when a specialization decode fails. At most one log line
/// per specialization name per minute (per process). Never logs payload
/// contents — only the spec name and a short failure reason.
pub fn warn_failure(specialization: &str, reason: &str) {
    let Some(limiter) = WARN_LIMITERS.get(specialization) else {
        return;
    };
    if let Some(dropped) = limiter.should_log() {
        warn!(
            specialization,
            reason, dropped, "specialization processing failed; falling back to default scan"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    // --- Registry ---

    #[test_case("ga4" ; "ga4 hit")]
    #[test_case("matomo" ; "matomo hit")]
    fn lookup_known(name: &str) {
        let spec = lookup(name).expect("registry hit");
        assert_eq!(spec.name(), name);
    }

    #[test_case("" ; "empty")]
    #[test_case("GA4" ; "uppercase no match")]
    #[test_case("ga5" ; "near miss")]
    #[test_case("plausible" ; "unknown")]
    fn lookup_unknown(name: &str) {
        assert!(lookup(name).is_none(), "expected miss for {name}");
    }

    // --- SpecializationError ---

    #[test_case(SpecializationError::Decode { reason: "invalid_json".into() }, "decode")]
    #[test_case(
        SpecializationError::UnsupportedContentType,
        "unsupported_content_type"
    )]
    #[test_case(SpecializationError::RecursionLimit, "recursion_limit")]
    fn reason_label_is_stable(err: SpecializationError, expected: &str) {
        assert_eq!(err.reason_label(), expected);
    }

    // --- ProcessedRequest shape ---

    #[test]
    fn processed_request_holds_query_body_and_scan_result() {
        let pr = ProcessedRequest {
            query: Some(ProcessedPart {
                bytes: Bytes::from_static(b"a=b"),
                content_type: None,
            }),
            body: Some(ProcessedPart {
                bytes: Bytes::from_static(br#"{"x":1}"#),
                content_type: Some("application/json".into()),
            }),
            scan_result: AggregatedScan {
                kinds: vec!["EMAIL".into()],
                matches_count: 1,
            },
        };

        let q = pr.query.expect("query present");
        assert_eq!(q.bytes.as_ref(), b"a=b");
        assert!(q.content_type.is_none());

        let b = pr.body.expect("body present");
        assert_eq!(b.bytes.as_ref(), br#"{"x":1}"#);
        assert_eq!(b.content_type.as_deref(), Some("application/json"));

        assert_eq!(pr.scan_result.kinds, vec!["EMAIL".to_string()]);
        assert_eq!(pr.scan_result.matches_count, 1);
    }

    #[test]
    fn processed_request_none_slots_signal_passthrough() {
        let pr = ProcessedRequest {
            query: None,
            body: None,
            scan_result: AggregatedScan::default(),
        };
        assert!(pr.query.is_none());
        assert!(pr.body.is_none());
        assert!(pr.scan_result.kinds.is_empty());
        assert_eq!(pr.scan_result.matches_count, 0);
    }

    // --- AggregatedScan::merge_field ---

    #[test]
    fn merge_field_dedups_kinds_preserving_order() {
        let mut agg = AggregatedScan::default();
        agg.merge_field(&FieldScanResult {
            kinds: vec!["EMAIL".into(), "US_SSN".into()],
            matches_count: 2,
            redacted: None,
        });
        agg.merge_field(&FieldScanResult {
            kinds: vec!["US_SSN".into(), "US_PHONE_NUMBER".into()],
            matches_count: 3,
            redacted: None,
        });
        assert_eq!(
            agg.kinds,
            vec![
                "EMAIL".to_string(),
                "US_SSN".into(),
                "US_PHONE_NUMBER".into()
            ]
        );
        assert_eq!(agg.matches_count, 5);
    }

    // --- Rate limiter ---

    #[test]
    fn rate_limiter_emits_once_then_suppresses_in_window() {
        // A locally-constructed limiter so the test doesn't depend on or
        // perturb the module-level `WARN_LIMITERS` state shared with other
        // tests.
        let limiter = LogRateLimiter::new(60_000);
        assert!(
            limiter.should_log().is_some(),
            "first call within window must emit"
        );
        assert!(
            limiter.should_log().is_none(),
            "second call within window must suppress"
        );
        assert!(
            limiter.should_log().is_none(),
            "third call within window must suppress"
        );
    }

    // --- warn_failure dispatch ---

    #[test]
    fn warn_failure_is_a_noop_for_unknown_specialization() {
        // No panic, no global state perturbed for an unknown name.
        warn_failure("not-a-real-spec", "decode");
    }

    // --- Stub specialization process() ---

    #[tokio::test]
    async fn stub_ga4_process_returns_decode_error_until_phase_16_3() {
        let spec = lookup("ga4").unwrap();
        // We exercise the trait object without a real `ScanHandle`; the
        // stub never touches it, so building one against a dropped pool
        // would be wasted ceremony. Once 16.3 lands this assertion flips.
        let pool = ScannerPool::new(&crate::config::PiiConfig {
            countries: vec![pii::Country::International],
            languages: vec![pii::Language::En],
            scanner_threads: Some(1),
            detect: None,
            ignore: None,
            custom: Vec::new(),
        })
        .expect("pool starts");
        let handle = ScanHandle::new(&pool, false, None, OnError::FailOpen);
        let err = spec
            .process(None, Some(b"{}"), Some("application/json"), &handle)
            .await
            .expect_err("stub returns Err until 16.3 implements GA4");
        assert!(matches!(err, SpecializationError::Decode { .. }));
    }

    #[tokio::test]
    async fn stub_matomo_process_returns_decode_error_until_phase_16_4() {
        let spec = lookup("matomo").unwrap();
        let pool = ScannerPool::new(&crate::config::PiiConfig {
            countries: vec![pii::Country::International],
            languages: vec![pii::Language::En],
            scanner_threads: Some(1),
            detect: None,
            ignore: None,
            custom: Vec::new(),
        })
        .expect("pool starts");
        let handle = ScanHandle::new(&pool, false, None, OnError::FailOpen);
        let err = spec
            .process(Some("idsite=1"), None, None, &handle)
            .await
            .expect_err("stub returns Err until 16.4 implements Matomo");
        assert!(matches!(err, SpecializationError::Decode { .. }));
    }

    // --- ScanHandle smoke test ---

    #[tokio::test]
    async fn scan_handle_detects_pii_in_field_value() {
        let pool = ScannerPool::new(&crate::config::PiiConfig {
            countries: vec![pii::Country::International],
            languages: vec![pii::Language::En],
            scanner_threads: Some(1),
            detect: None,
            ignore: None,
            custom: Vec::new(),
        })
        .expect("pool starts");
        let handle = ScanHandle::new(&pool, true, Some(RedactWith::TypeLabel), OnError::FailOpen);
        let result = handle
            .scan("uid", "user@example.com")
            .await
            .expect("scan succeeds");
        assert!(result.kinds.iter().any(|k| k == "EMAIL"));
        assert_eq!(
            result.redacted.as_deref(),
            Some("[EMAIL]"),
            "redacted output should mirror the field value"
        );
    }

    #[tokio::test]
    async fn scan_handle_empty_value_short_circuits() {
        let pool = ScannerPool::new(&crate::config::PiiConfig {
            countries: vec![pii::Country::International],
            languages: vec![pii::Language::En],
            scanner_threads: Some(1),
            detect: None,
            ignore: None,
            custom: Vec::new(),
        })
        .expect("pool starts");
        let handle = ScanHandle::new(&pool, false, None, OnError::FailOpen);
        let result = handle.scan("uid", "").await.expect("scan succeeds");
        assert_eq!(result.matches_count, 0);
        assert!(result.kinds.is_empty());
        assert!(result.redacted.is_none());
    }

    #[test]
    fn scan_handle_redact_enabled_reflects_constructor_args() {
        let pool = ScannerPool::new(&crate::config::PiiConfig {
            countries: vec![pii::Country::International],
            languages: vec![pii::Language::En],
            scanner_threads: Some(1),
            detect: None,
            ignore: None,
            custom: Vec::new(),
        })
        .expect("pool starts");

        let off = ScanHandle::new(&pool, false, None, OnError::FailOpen);
        assert!(!off.redact_enabled());

        let on = ScanHandle::new(&pool, true, Some(RedactWith::TypeLabel), OnError::FailOpen);
        assert!(on.redact_enabled());

        // redact=true without a strategy still counts as disabled — the
        // scanner won't actually redact without one.
        let half = ScanHandle::new(&pool, true, None, OnError::FailOpen);
        assert!(!half.redact_enabled());
    }
}
