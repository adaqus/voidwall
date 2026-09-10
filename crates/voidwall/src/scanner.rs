use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;

use crate::config::PiiConfig;
use crate::engine::UnitContent;
use crate::error::Error;
use crate::structured::csv::flatten_csv;
use crate::structured::json::flatten_json;

// ---------------------------------------------------------------------------
// Body decoding
// ---------------------------------------------------------------------------

/// Convert raw body bytes into a [`UnitContent`] based on Content-Type.
///
/// JSON is parsed into `Structured`; CSV/TSV degrade to `PlainText` when no
/// header row is detected (per the pii-scanning spec). Unknown or non-structured content
/// types map to `PlainText` unchanged. Parse failures (malformed JSON,
/// unterminated quotes in CSV) propagate as `Err` — the caller decides
/// whether to fall back via `on_error`.
pub fn classify_body(raw: Bytes, content_type: &str) -> Result<UnitContent, Error> {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    if is_json_media_type(&media_type) {
        let fragments = flatten_json(&raw)?;
        return Ok(UnitContent::Structured { fragments });
    }
    if is_csv_media_type(&media_type) {
        return Ok(match flatten_csv(&raw, b',')? {
            Some(fragments) => UnitContent::Structured { fragments },
            None => UnitContent::PlainText(raw),
        });
    }
    if is_tsv_media_type(&media_type) {
        return Ok(match flatten_csv(&raw, b'\t')? {
            Some(fragments) => UnitContent::Structured { fragments },
            None => UnitContent::PlainText(raw),
        });
    }
    Ok(UnitContent::PlainText(raw))
}

/// True when `media_type` (already lowercased and parameter-stripped) names a
/// JSON document. Covers `application/json`, the legacy `text/json`, and any
/// `application/*+json` structured-suffix type per RFC 6839 (e.g.
/// `application/ld+json`, `application/hal+json`, `application/problem+json`,
/// `application/vnd.api+json`).
fn is_json_media_type(media_type: &str) -> bool {
    media_type == "application/json"
        || media_type == "text/json"
        || (media_type.starts_with("application/") && media_type.ends_with("+json"))
}

/// True when `media_type` names a CSV document. Covers the canonical
/// `text/csv` (RFC 7111) plus the non-standard but widely seen
/// `application/csv` and `text/x-csv`. Excludes `application/vnd.ms-excel`
/// which is used both for CSV downloads and binary `.xls` and so cannot
/// be dispatched to the CSV parser without misclassifying spreadsheets.
fn is_csv_media_type(media_type: &str) -> bool {
    matches!(media_type, "text/csv" | "application/csv" | "text/x-csv")
}

/// True when `media_type` names a TSV document. Covers IANA's
/// `text/tab-separated-values` plus the non-standard short form `text/tsv`.
fn is_tsv_media_type(media_type: &str) -> bool {
    matches!(media_type, "text/tab-separated-values" | "text/tsv")
}

/// Canonical body Content-Types accepted by `classify_body` for documentation
/// purposes (HTTP API OpenAPI spec, public docs). The actual dispatch in
/// `classify_body` is more lenient — it also accepts `text/json`,
/// `application/*+json`, `application/csv`, `text/x-csv`, and `text/tsv` —
/// but those are non-standard variants and not worth advertising. Keep this
/// list in sync with the canonical IANA names.
pub const SUPPORTED_BODY_CONTENT_TYPES: &[&str] = &[
    "text/plain",
    "application/json",
    "text/csv",
    "text/tab-separated-values",
];

// ---------------------------------------------------------------------------
// Log rate limiting
// ---------------------------------------------------------------------------

/// A rate limiter for log messages. Tracks a drop count and only allows
/// emission once per `interval_ms`. Thread-safe via atomics.
pub struct LogRateLimiter {
    last_log_ms: AtomicU64,
    dropped: AtomicU64,
    interval_ms: u64,
}

impl LogRateLimiter {
    pub const fn new(interval_ms: u64) -> Self {
        Self {
            last_log_ms: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            interval_ms,
        }
    }

    /// Record an occurrence. Returns `Some(dropped_count)` if enough time has
    /// elapsed and this caller won the race to log, `None` otherwise.
    pub fn should_log(&self) -> Option<u64> {
        let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let last = self.last_log_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) >= self.interval_ms
            && self
                .last_log_ms
                .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.dropped.store(0, Ordering::Relaxed);
            return Some(dropped);
        }
        None
    }
}

pub static SCANNER_ERROR_LIMITER: LogRateLimiter = LogRateLimiter::new(1_000);

// ---------------------------------------------------------------------------
// Scanner construction
// ---------------------------------------------------------------------------

/// Exercise scanner construction for the given PII configuration without
/// spawning any threads. Used by `--validate` to surface regex and hyperscan
/// compilation errors at startup.
pub fn validate_build(config: &PiiConfig) -> Result<(), Error> {
    build_scanner(config).map(|_| ())
}

/// Build a `voidwall_pii::Scanner` from the proxy's PII configuration.
pub(crate) fn build_scanner(config: &PiiConfig) -> Result<voidwall_pii::Scanner, Error> {
    precheck_custom_pii(&config.custom)?;

    let mut builder = voidwall_pii::Scanner::builder();

    if !config.countries.is_empty() {
        builder = builder.countries(config.countries.iter().copied());
    }
    if !config.languages.is_empty() {
        builder = builder.languages(config.languages.iter().copied());
    }
    if let Some(ref kinds) = config.detect {
        builder = builder.pii_kinds(kinds.iter().copied());
    }
    if let Some(ref exclude) = config.ignore {
        builder = builder.exclude_pii_kinds(exclude.iter().copied());
    }
    if !config.custom.is_empty() {
        builder = builder.user_piis(config.custom.iter().cloned());
    }

    builder.build().map_err(|e| match e {
        voidwall_pii::PiiError::RegexCompilation(_)
        | voidwall_pii::PiiError::HyperscanCompilation(_) => {
            // The `regex` crate precheck didn't flag anything, but the full
            // builder still rejected a pattern — most likely a vectorscan-only
            // restriction. Isolate the offender by rebuilding with one entry
            // at a time.
            if let Some(def) = isolate_failing_custom_entry(&config.custom) {
                Error::Scanner(format!(
                    "pii.custom entry '{}': scanner build failed ({e})",
                    def.label,
                ))
            } else {
                let labels: Vec<&str> = config.custom.iter().map(|d| d.label.as_str()).collect();
                Error::Scanner(format!(
                    "pii.custom: scanner build failed ({e}); labels configured: {labels:?}"
                ))
            }
        }
        other => other.into(),
    })
}

/// Per-entry regex pre-check so compilation failures name the offending label.
fn precheck_custom_pii(defs: &[voidwall_pii::UserPiiDefinition]) -> Result<(), Error> {
    for def in defs {
        if let Err(e) = regex::Regex::new(&def.pattern) {
            return Err(Error::Scanner(format!(
                "pii.custom entry '{}': invalid regex: {e}",
                def.label,
            )));
        }
    }
    Ok(())
}

/// Rebuild the scanner with one custom entry at a time, returning the first
/// entry that causes the builder to fail. Only called on an error path, so
/// the O(N) rebuild cost is acceptable.
fn isolate_failing_custom_entry(
    defs: &[voidwall_pii::UserPiiDefinition],
) -> Option<&voidwall_pii::UserPiiDefinition> {
    defs.iter().find(|def| {
        voidwall_pii::Scanner::builder()
            .user_piis(std::iter::once((*def).clone()))
            .build()
            .is_err()
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    fn pii_config_with_custom(defs: Vec<voidwall_pii::UserPiiDefinition>) -> PiiConfig {
        PiiConfig {
            countries: vec![voidwall_pii::Country::International],
            languages: vec![voidwall_pii::Language::En],
            scanner_threads: Some(1),
            detect: None,
            ignore: None,
            custom: defs,
        }
    }

    #[test]
    fn build_scanner_with_kinds_filter() {
        let config = PiiConfig {
            detect: Some(vec![voidwall_pii::PiiKind::Email]),
            ..pii_config_with_custom(Vec::new())
        };
        assert!(build_scanner(&config).is_ok());
    }

    #[test]
    fn build_scanner_with_valid_custom_detects_match() {
        let config = pii_config_with_custom(vec![voidwall_pii::UserPiiDefinition {
            label: "EMPLOYEE_ID".into(),
            pattern: r"EMP-\d{6}".into(),
            keywords: Vec::new(),
            country: voidwall_pii::Country::International,
        }]);
        let scanner = build_scanner(&config).expect("scanner should build");
        let matches = scanner.mark_piis("employee EMP-123456 on file");
        assert!(
            matches.iter().any(|m| m.label() == "EMPLOYEE_ID"),
            "expected EMPLOYEE_ID match, got {matches:?}"
        );
    }

    #[test]
    fn build_scanner_with_invalid_custom_regex_cites_label() {
        let config = pii_config_with_custom(vec![voidwall_pii::UserPiiDefinition {
            label: "BROKEN".into(),
            pattern: r"[unclosed".into(),
            keywords: Vec::new(),
            country: voidwall_pii::Country::International,
        }]);
        let err = match build_scanner(&config) {
            Ok(_) => panic!("expected build_scanner to fail"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("BROKEN"),
            "expected label in error, got: {msg}"
        );
        assert!(
            msg.contains("invalid regex"),
            "expected regex diagnostic, got: {msg}"
        );
    }


    // --- classify_body / is_json_media_type ---

    #[test_case("application/json" ; "canonical")]
    #[test_case("text/json" ; "legacy text json")]
    #[test_case("application/ld+json" ; "linked data json")]
    #[test_case("application/hal+json" ; "hal json")]
    #[test_case("application/problem+json" ; "rfc 7807 problem json")]
    #[test_case("application/vnd.api+json" ; "json api")]
    fn json_media_types_classify_as_structured(media_type: &str) {
        let raw = Bytes::from_static(br#"{"k": "v"}"#);
        let content = classify_body(raw, media_type).expect("classify ok");
        assert!(matches!(content, UnitContent::Structured { .. }));
    }

    #[test_case("application/xml" ; "xml not json")]
    #[test_case("application/jsonld" ; "no plus before json")]
    #[test_case("application/problem+xml" ; "problem xml")]
    fn non_json_media_types_dont_match_json(media_type: &str) {
        // These must not be parsed as JSON. Body is invalid JSON to make
        // misclassification observable: classify_body would return Err if it
        // tried to flatten as JSON, but PlainText path swallows arbitrary bytes.
        let raw = Bytes::from_static(b"not json");
        let content = classify_body(raw, media_type).expect("classify ok");
        assert!(matches!(content, UnitContent::PlainText(_)));
    }

    #[test]
    fn json_with_charset_parameter_classifies_as_structured() {
        let raw = Bytes::from_static(br#"{"k": "v"}"#);
        let content = classify_body(raw, "application/json; charset=utf-8").unwrap();
        assert!(matches!(content, UnitContent::Structured { .. }));
    }

    #[test]
    fn json_uppercase_content_type_classifies_as_structured() {
        let raw = Bytes::from_static(br#"{"k": "v"}"#);
        let content = classify_body(raw, "Application/JSON").unwrap();
        assert!(matches!(content, UnitContent::Structured { .. }));
    }

    #[test]
    fn invalid_json_returns_error() {
        let raw = Bytes::from_static(b"{not json");
        assert!(classify_body(raw, "application/json").is_err());
    }

    #[test_case("text/csv" ; "canonical")]
    #[test_case("application/csv" ; "non standard application")]
    #[test_case("text/x-csv" ; "x prefix")]
    fn csv_media_types_with_headers_classify_as_structured(media_type: &str) {
        let raw = Bytes::from_static(b"name,phone\nJohn,555-1234");
        let content = classify_body(raw, media_type).unwrap();
        assert!(matches!(content, UnitContent::Structured { .. }));
    }

    #[test_case("application/vnd.ms-excel" ; "excel binary not csv")]
    #[test_case("text/comma-separated-values" ; "legacy form not supported")]
    fn non_csv_media_types_dont_match_csv(media_type: &str) {
        // Even with a CSV-shaped payload, these must not route to the CSV
        // parser — Excel can be binary, the legacy form is intentionally
        // excluded.
        let raw = Bytes::from_static(b"name,phone\nJohn,555-1234");
        let content = classify_body(raw, media_type).unwrap();
        assert!(matches!(content, UnitContent::PlainText(_)));
    }

    #[test]
    fn csv_without_headers_falls_back_to_plain_text() {
        let raw = Bytes::from_static(b"123,456\n789,012");
        let content = classify_body(raw, "text/csv").unwrap();
        assert!(matches!(content, UnitContent::PlainText(_)));
    }

    #[test_case("text/tab-separated-values" ; "canonical")]
    #[test_case("text/tsv" ; "short form")]
    fn tsv_media_types_with_headers_classify_as_structured(media_type: &str) {
        let raw = Bytes::from_static(b"name\tphone\nJohn\t555-1234");
        let content = classify_body(raw, media_type).unwrap();
        assert!(matches!(content, UnitContent::Structured { .. }));
    }

    #[test]
    fn unknown_content_type_is_plain_text() {
        let raw = Bytes::from_static(b"hello world");
        let content = classify_body(raw, "text/plain").unwrap();
        assert!(matches!(content, UnitContent::PlainText(_)));
    }
}
