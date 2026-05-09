use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use bytes::Bytes;
use crossbeam_channel::{SendTimeoutError, Sender};
use tracing::{debug, error, info};

use crate::config::{OnError, PiiConfig, RedactStrategy};
use crate::error::Error;
use crate::structured::OwnedContextFragment;
use crate::structured::csv::flatten_csv;
use crate::structured::json::flatten_json;

// ---------------------------------------------------------------------------
// Redaction strategy (previously in the pii crate)
// ---------------------------------------------------------------------------

/// How to replace detected PII text.
#[derive(Debug, Clone)]
pub enum RedactWith {
    /// Replace with the given character repeated for the length of the kind label.
    Char(char),
    /// Replace with `[KIND_LABEL]`.
    TypeLabel,
}

// ---------------------------------------------------------------------------
// Scan request / result types
// ---------------------------------------------------------------------------

/// How a request/response body is represented before scanning.
///
/// `PlainText` is the historical flat-text path: the body bytes are scanned
/// as a single UTF-8 string. `Structured` carries pre-parsed
/// context/value/offset fragments (e.g. JSON keys + string values, CSV column
/// headers + cells) along with the original raw bytes, so detection can use
/// keyword context and redaction can rewrite the original body in-place at
/// document-absolute offsets.
pub enum BodyFormat {
    PlainText(Bytes),
    Structured {
        fragments: Vec<OwnedContextFragment>,
        raw: Bytes,
    },
}

/// Convert raw body bytes into a `BodyFormat` based on Content-Type.
///
/// JSON is parsed into `Structured`; CSV/TSV degrade to `PlainText` when no
/// header row is detected (per DESIGN.md). Unknown or non-structured content
/// types map to `PlainText` unchanged. Parse failures (malformed JSON,
/// unterminated quotes in CSV) propagate as `Err` — the caller decides
/// whether to fall back via `on_error`.
pub fn classify_body(raw: Bytes, content_type: &str) -> Result<BodyFormat, Error> {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    if is_json_media_type(&media_type) {
        let fragments = flatten_json(&raw)?;
        return Ok(BodyFormat::Structured { fragments, raw });
    }
    if is_csv_media_type(&media_type) {
        return Ok(match flatten_csv(&raw, b',')? {
            Some(fragments) => BodyFormat::Structured { fragments, raw },
            None => BodyFormat::PlainText(raw),
        });
    }
    if is_tsv_media_type(&media_type) {
        return Ok(match flatten_csv(&raw, b'\t')? {
            Some(fragments) => BodyFormat::Structured { fragments, raw },
            None => BodyFormat::PlainText(raw),
        });
    }
    Ok(BodyFormat::PlainText(raw))
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

/// A request to scan (and optionally redact) text fragments.
pub struct ScanRequest {
    pub body: Option<BodyFormat>,
    pub path: Option<String>,
    pub query: Option<String>,
    pub headers: Option<Vec<(String, String)>>,
    pub redact: bool,
    pub redact_strategy: Option<RedactWith>,
}

/// Result of scanning (and optionally redacting) text fragments.
#[derive(Debug)]
pub struct ScanResult {
    pub detected: bool,
    pub kinds: Vec<String>,
    pub matches_count: usize,
    pub redacted_body: Option<Bytes>,
    pub redacted_path: Option<String>,
    pub redacted_query: Option<String>,
    pub redacted_headers: Option<Vec<(String, String)>>,
}

// ---------------------------------------------------------------------------
// Internal message type
// ---------------------------------------------------------------------------

type WorkItem = (ScanRequest, tokio::sync::oneshot::Sender<ScanResult>);

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

static CHANNEL_FULL_LIMITER: LogRateLimiter = LogRateLimiter::new(1_000);
pub static SCANNER_ERROR_LIMITER: LogRateLimiter = LogRateLimiter::new(1_000);

// ---------------------------------------------------------------------------
// Scanner pool
// ---------------------------------------------------------------------------

/// How long `process()` will wait for a free channel slot before giving up.
const SEND_TIMEOUT: Duration = Duration::from_secs(1);

/// A pool of dedicated OS threads, each owning a `pii::Scanner` instance.
///
/// Work is dispatched via a bounded crossbeam channel. Responses are sent back
/// through tokio oneshot channels so the async caller can `.await` results.
pub struct ScannerPool {
    sender: Option<Sender<WorkItem>>,
    handles: Vec<JoinHandle<()>>,
}

impl ScannerPool {
    /// Create a new scanner pool with the given PII configuration.
    ///
    /// Spawns `pii_config.effective_scanner_threads()` OS threads, each with
    /// its own `pii::Scanner` instance. The bounded channel capacity is
    /// `4 * num_threads` to absorb short bursts while still providing backpressure.
    pub fn new(pii_config: &PiiConfig) -> Result<Self, Error> {
        let num_threads = pii_config.effective_scanner_threads();
        let channel_capacity = num_threads * 4;
        let (sender, receiver) = crossbeam_channel::bounded::<WorkItem>(channel_capacity);

        let mut handles = Vec::with_capacity(num_threads);

        for thread_id in 0..num_threads {
            let rx = receiver.clone();
            let scanner = build_scanner(pii_config)?;

            let handle = std::thread::Builder::new()
                .name(format!("pii-scanner-{thread_id}"))
                .spawn(move || {
                    debug!(thread_id, "scanner thread started");
                    while let Ok((request, reply_tx)) = rx.recv() {
                        let result = execute_scan(&scanner, request);
                        let _ = reply_tx.send(result);
                    }
                    debug!(thread_id, "scanner thread exiting");
                })
                .map_err(|e| Error::Scanner(format!("failed to spawn scanner thread: {e}")))?;

            handles.push(handle);
        }

        info!(num_threads, "scanner pool started");

        Ok(Self {
            sender: Some(sender),
            handles,
        })
    }

    /// Submit a scan request and await the result.
    ///
    /// If the channel is full the caller blocks (on the tokio blocking pool)
    /// for up to [`SEND_TIMEOUT`] before giving up. This applies backpressure
    /// to the HTTP layer instead of instantly rejecting bursts.
    pub async fn process(
        &self,
        request: ScanRequest,
        on_error: OnError,
    ) -> Result<ScanResult, Error> {
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| Error::Scanner("scanner pool is shut down".into()))?
            .clone();

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let item = (request, reply_tx);

        // send_timeout blocks, so run it on the tokio blocking thread pool
        // to avoid stalling the async runtime.
        let send_result =
            tokio::task::spawn_blocking(move || sender.send_timeout(item, SEND_TIMEOUT))
                .await
                .map_err(|_| Error::Scanner("blocking send task panicked".into()))?;

        match send_result {
            Ok(()) => {}
            Err(SendTimeoutError::Timeout(_)) => {
                log_channel_full("scanner pool channel full");
                return Err(Error::Scanner("scanner pool overloaded".into()));
            }
            Err(SendTimeoutError::Disconnected(_)) => {
                error!("all scanner threads are dead");
                return Err(Error::Scanner("all scanner threads are dead".into()));
            }
        }

        reply_rx.await.map_err(|_| {
            let msg = match on_error {
                OnError::FailOpen => "scanner thread died while processing request (fail_open)",
                OnError::FailClose => "scanner thread died while processing request (fail_close)",
            };
            Error::Scanner(msg.into())
        })
    }

    /// Shut down the pool: close the channel and join all threads.
    pub fn shutdown(&mut self) {
        self.sender.take();

        for handle in self.handles.drain(..) {
            if let Err(e) = handle.join() {
                error!(?e, "scanner thread panicked during shutdown");
            }
        }

        info!("scanner pool shut down");
    }
}

impl Drop for ScannerPool {
    fn drop(&mut self) {
        if self.sender.is_some() {
            self.shutdown();
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Log a "channel full" message, rate-limited to once per second.
fn log_channel_full(message: &str) {
    if let Some(dropped) = CHANNEL_FULL_LIMITER.should_log() {
        error!(dropped, "{message}");
    }
}

/// Exercise scanner construction for the given PII configuration without
/// spawning any threads. Used by `--validate` to surface regex and hyperscan
/// compilation errors at startup.
pub fn validate_build(config: &PiiConfig) -> Result<(), Error> {
    build_scanner(config).map(|_| ())
}

/// Build a `pii::Scanner` from the proxy's PII configuration.
fn build_scanner(config: &PiiConfig) -> Result<pii::Scanner, Error> {
    precheck_custom_pii(&config.custom)?;

    let mut builder = pii::Scanner::builder();

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
        pii::PiiError::RegexCompilation(_) | pii::PiiError::HyperscanCompilation(_) => {
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
fn precheck_custom_pii(defs: &[pii::UserPiiDefinition]) -> Result<(), Error> {
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
    defs: &[pii::UserPiiDefinition],
) -> Option<&pii::UserPiiDefinition> {
    defs.iter().find(|def| {
        pii::Scanner::builder()
            .user_piis(std::iter::once((*def).clone()))
            .build()
            .is_err()
    })
}

/// Convert a `RedactStrategy` config value to a `RedactWith`.
pub fn to_redact_with(strategy: RedactStrategy, mask_char: Option<char>) -> RedactWith {
    match strategy {
        RedactStrategy::Char => RedactWith::Char(mask_char.unwrap_or('*')),
        RedactStrategy::TypeLabel => RedactWith::TypeLabel,
    }
}

/// Redact PII in `text` in place using pre-computed `matches`.
///
/// Replacement length is fixed per PII kind (equal to the kind label length)
/// to avoid leaking information about the original value's length.
///
/// For `Char` strategy the replacement is the mask char repeated `label().len()`
/// times (e.g. EMAIL → `*****`). For `TypeLabel` the replacement is `[LABEL]`.
///
/// Matches are replaced back-to-front so that byte offsets stay valid.
fn redact_in_place(text: &mut String, matches: &mut [pii::PiiMatch], strategy: &RedactWith) {
    if matches.is_empty() {
        return;
    }

    // Sort by start descending so replace_range doesn't invalidate later offsets.
    matches.sort_unstable_by(|a, b| b.start.cmp(&a.start));
    let mut prev_start = usize::MAX;
    for m in matches.iter() {
        if m.end > prev_start {
            continue;
        }
        let label = m.label();
        let replacement = match strategy {
            RedactWith::Char(c) => c.to_string().repeat(label.len()),
            RedactWith::TypeLabel => format!("[{label}]"),
        };
        text.replace_range(m.start..m.end, &replacement);
        prev_start = m.start;
    }
}

/// Execute scan (and optional redaction) synchronously on a scanner thread.
fn execute_scan(scanner: &pii::Scanner, request: ScanRequest) -> ScanResult {
    let mut all_kinds: HashSet<String> = HashSet::new();
    let mut matches_count: usize = 0;

    let mut redacted_body = None;
    let mut redacted_path = None;
    let mut redacted_query = None;
    let mut redacted_headers = None;

    // Scan body
    match request.body {
        Some(BodyFormat::PlainText(ref body)) => {
            if let Ok(text) = std::str::from_utf8(body) {
                let mut matches = pii::resolve_overlaps(scanner.mark_piis(text));
                matches_count += matches.len();
                for m in &matches {
                    all_kinds.insert(m.label().to_string());
                }

                if request.redact
                    && !matches.is_empty()
                    && let Some(ref strategy) = request.redact_strategy
                {
                    let mut owned = text.to_string();
                    redact_in_place(&mut owned, &mut matches, strategy);
                    redacted_body = Some(Bytes::from(owned));
                }
            }
        }
        Some(BodyFormat::Structured {
            ref fragments,
            ref raw,
        }) => {
            // Borrow owned fragments as the pii crate's ContextFragment view.
            let borrowed: Vec<pii::ContextFragment<'_>> = fragments
                .iter()
                .map(|f| pii::ContextFragment {
                    context: &f.context,
                    value: &f.value,
                    offset: f.offset,
                })
                .collect();

            let mut matches = pii::resolve_overlaps(scanner.mark_piis_structured(&borrowed));
            matches_count += matches.len();
            for m in &matches {
                all_kinds.insert(m.label().to_string());
            }

            // Redact against the document-absolute offsets in `raw`. The raw
            // bytes must be UTF-8 here: JSON requires it, and CSV that
            // flattened successfully had every cell validated as UTF-8 (the
            // delimiter/newline bytes between cells are ASCII).
            if request.redact
                && !matches.is_empty()
                && let Some(ref strategy) = request.redact_strategy
                && let Ok(text) = std::str::from_utf8(raw)
            {
                let mut owned = text.to_string();
                redact_in_place(&mut owned, &mut matches, strategy);
                redacted_body = Some(Bytes::from(owned));
            }
        }
        None => {}
    }

    // Scan URL
    if let Some(ref path) = request.path {
        let mut matches = pii::resolve_overlaps(scanner.mark_piis(path));
        matches_count += matches.len();
        for m in &matches {
            all_kinds.insert(m.label().to_string());
        }

        if request.redact
            && !matches.is_empty()
            && let Some(ref strategy) = request.redact_strategy
        {
            let mut owned = path.clone();
            redact_in_place(&mut owned, &mut matches, strategy);
            redacted_path = Some(owned);
        }
    }

    // Scan query string
    if let Some(ref query) = request.query {
        let mut matches = pii::resolve_overlaps(scanner.mark_piis(query));
        matches_count += matches.len();
        for m in &matches {
            all_kinds.insert(m.label().to_string());
        }

        if request.redact
            && !matches.is_empty()
            && let Some(ref strategy) = request.redact_strategy
        {
            let mut owned = query.clone();
            redact_in_place(&mut owned, &mut matches, strategy);
            redacted_query = Some(owned);
        }
    }

    // Scan headers
    if let Some(ref headers) = request.headers {
        let mut header_results: Vec<(String, String)> = Vec::with_capacity(headers.len());
        let mut any_redacted = false;

        for (name, value) in headers {
            let mut matches = pii::resolve_overlaps(scanner.mark_piis(value));
            matches_count += matches.len();
            for m in &matches {
                all_kinds.insert(m.label().to_string());
            }

            if request.redact
                && !matches.is_empty()
                && let Some(ref strategy) = request.redact_strategy
            {
                let mut owned = value.clone();
                redact_in_place(&mut owned, &mut matches, strategy);
                header_results.push((name.clone(), owned));
                any_redacted = true;
            } else {
                header_results.push((name.clone(), value.clone()));
            }
        }

        if any_redacted {
            redacted_headers = Some(header_results);
        }
    }

    let kinds: Vec<String> = all_kinds.into_iter().collect();
    let detected = !kinds.is_empty();

    ScanResult {
        detected,
        kinds,
        matches_count,
        redacted_body,
        redacted_path,
        redacted_query,
        redacted_headers,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;
    use test_case::test_case;

    static SCANNER: LazyLock<pii::Scanner> = LazyLock::new(|| pii::Scanner::new().unwrap());

    fn test_pii_config() -> PiiConfig {
        PiiConfig {
            countries: vec![pii::Country::International, pii::Country::Us],
            languages: vec![pii::Language::En],
            scanner_threads: Some(1),
            detect: None,
            ignore: None,
            custom: Vec::new(),
        }
    }

    fn make_pool() -> ScannerPool {
        ScannerPool::new(&test_pii_config()).expect("pool should start")
    }

    #[tokio::test]
    async fn scan_no_pii() {
        let pool = make_pool();
        let req = ScanRequest {
            body: Some(BodyFormat::PlainText(Bytes::from("hello world"))),
            path: None,
            query: None,
            headers: None,
            redact: false,
            redact_strategy: None,
        };
        let result = pool.process(req, OnError::FailOpen).await.unwrap();
        assert!(!result.detected);
        assert_eq!(result.matches_count, 0);
        assert!(result.kinds.is_empty());
        assert!(result.redacted_body.is_none());
    }

    #[tokio::test]
    async fn scan_detects_email() {
        let pool = make_pool();
        let req = ScanRequest {
            body: Some(BodyFormat::PlainText(Bytes::from(
                "contact me at user@example.com please",
            ))),
            path: None,
            query: None,
            headers: None,
            redact: false,
            redact_strategy: None,
        };
        let result = pool.process(req, OnError::FailOpen).await.unwrap();
        assert!(result.detected);
        assert!(result.matches_count >= 1);
        assert!(result.kinds.contains(&"EMAIL".to_string()));
        assert!(result.redacted_body.is_none());
    }

    #[tokio::test]
    async fn redact_body_type_label() {
        let pool = make_pool();
        let req = ScanRequest {
            body: Some(BodyFormat::PlainText(Bytes::from(
                "email: user@example.com",
            ))),
            path: None,
            query: None,
            headers: None,
            redact: true,
            redact_strategy: Some(RedactWith::TypeLabel),
        };
        let result = pool.process(req, OnError::FailOpen).await.unwrap();
        assert!(result.detected);
        let body = result.redacted_body.expect("body should be redacted");
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("[EMAIL]"), "expected [EMAIL] in '{text}'");
        assert!(!text.contains("user@example.com"));
    }

    #[tokio::test]
    async fn redact_body_char() {
        let pool = make_pool();
        let req = ScanRequest {
            body: Some(BodyFormat::PlainText(Bytes::from(
                "email: user@example.com",
            ))),
            path: None,
            query: None,
            headers: None,
            redact: true,
            redact_strategy: Some(RedactWith::Char('*')),
        };
        let result = pool.process(req, OnError::FailOpen).await.unwrap();
        assert!(result.detected);
        let body = result.redacted_body.expect("body should be redacted");
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("***"), "expected masking in '{text}'");
        assert!(!text.contains("user@example.com"));
    }

    #[tokio::test]
    async fn scan_path_with_pii() {
        let pool = make_pool();
        let req = ScanRequest {
            body: None,
            path: Some("/api/users/user@example.com".into()),
            query: None,
            headers: None,
            redact: true,
            redact_strategy: Some(RedactWith::TypeLabel),
        };
        let result = pool.process(req, OnError::FailOpen).await.unwrap();
        assert!(result.detected);
        let path = result.redacted_path.expect("path should be redacted");
        assert!(path.contains("[EMAIL]"), "expected [EMAIL] in '{path}'");
    }

    #[tokio::test]
    async fn scan_query_with_pii() {
        let pool = make_pool();
        let req = ScanRequest {
            body: None,
            path: None,
            query: Some("user=user@example.com&action=login".into()),
            headers: None,
            redact: true,
            redact_strategy: Some(RedactWith::TypeLabel),
        };
        let result = pool.process(req, OnError::FailOpen).await.unwrap();
        assert!(result.detected);
        let query = result.redacted_query.expect("query should be redacted");
        assert!(query.contains("[EMAIL]"), "expected [EMAIL] in '{query}'");
        assert!(!query.contains("user@example.com"));
    }

    #[tokio::test]
    async fn scan_headers_with_pii() {
        let pool = make_pool();
        let req = ScanRequest {
            body: None,
            path: None,
            query: None,
            headers: Some(vec![
                ("Authorization".into(), "Bearer user@example.com".into()),
                ("X-Safe".into(), "nothing here".into()),
            ]),
            redact: true,
            redact_strategy: Some(RedactWith::TypeLabel),
        };
        let result = pool.process(req, OnError::FailOpen).await.unwrap();
        assert!(result.detected);
        let headers = result.redacted_headers.expect("headers should be redacted");
        let auth = &headers
            .iter()
            .find(|(n, _)| n == "Authorization")
            .unwrap()
            .1;
        assert!(auth.contains("[EMAIL]"), "expected [EMAIL] in '{auth}'");
        let safe = &headers.iter().find(|(n, _)| n == "X-Safe").unwrap().1;
        assert_eq!(safe, "nothing here");
    }

    #[tokio::test]
    async fn scan_empty_request() {
        let pool = make_pool();
        let req = ScanRequest {
            body: None,
            path: None,
            query: None,
            headers: None,
            redact: false,
            redact_strategy: None,
        };
        let result = pool.process(req, OnError::FailOpen).await.unwrap();
        assert!(!result.detected);
        assert_eq!(result.matches_count, 0);
    }

    #[tokio::test]
    async fn shutdown_then_process_errors() {
        let mut pool = make_pool();
        pool.shutdown();
        let req = ScanRequest {
            body: Some(BodyFormat::PlainText(Bytes::from("test"))),
            path: None,
            query: None,
            headers: None,
            redact: false,
            redact_strategy: None,
        };
        let err = pool.process(req, OnError::FailOpen).await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("shut down"));
    }

    #[test]
    fn build_scanner_with_kinds_filter() {
        let config = PiiConfig {
            countries: vec![pii::Country::International],
            languages: vec![pii::Language::En],
            scanner_threads: Some(1),
            detect: Some(vec![pii::PiiKind::Email]),
            ignore: None,
            custom: Vec::new(),
        };
        assert!(build_scanner(&config).is_ok());
    }

    fn pii_config_with_custom(defs: Vec<pii::UserPiiDefinition>) -> PiiConfig {
        PiiConfig {
            countries: vec![pii::Country::International],
            languages: vec![pii::Language::En],
            scanner_threads: Some(1),
            detect: None,
            ignore: None,
            custom: defs,
        }
    }

    #[test]
    fn build_scanner_with_valid_custom_detects_match() {
        let config = pii_config_with_custom(vec![pii::UserPiiDefinition {
            label: "EMPLOYEE_ID".into(),
            pattern: r"EMP-\d{6}".into(),
            keywords: Vec::new(),
            country: pii::Country::International,
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
        let config = pii_config_with_custom(vec![pii::UserPiiDefinition {
            label: "BROKEN".into(),
            pattern: r"[unclosed".into(),
            keywords: Vec::new(),
            country: pii::Country::International,
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

    #[tokio::test]
    async fn custom_label_propagates_through_scan_and_redact() {
        let config = pii_config_with_custom(vec![pii::UserPiiDefinition {
            label: "EMPLOYEE_ID".into(),
            pattern: r"EMP-\d{6}".into(),
            keywords: Vec::new(),
            country: pii::Country::International,
        }]);
        let pool = ScannerPool::new(&config).expect("pool should start");

        let req = ScanRequest {
            body: Some(BodyFormat::PlainText(Bytes::from_static(
                b"emp EMP-123456 tag",
            ))),
            path: None,
            query: None,
            headers: None,
            redact: true,
            redact_strategy: Some(RedactWith::TypeLabel),
        };
        let result = pool
            .process(req, OnError::FailClose)
            .await
            .expect("scan succeeds");

        assert!(
            result.kinds.iter().any(|k| k == "EMPLOYEE_ID"),
            "expected EMPLOYEE_ID in kinds, got {:?}",
            result.kinds
        );
        let redacted = result.redacted_body.expect("body should be redacted");
        let redacted_str = std::str::from_utf8(&redacted).unwrap();
        assert!(
            redacted_str.contains("[EMPLOYEE_ID]"),
            "expected [EMPLOYEE_ID] in redacted body, got: {redacted_str}"
        );
        assert!(
            !redacted_str.contains("[CUSTOM]"),
            "redacted body should not contain [CUSTOM], got: {redacted_str}"
        );
    }

    #[test]
    fn to_redact_with_char() {
        let rw = to_redact_with(RedactStrategy::Char, Some('#'));
        assert!(matches!(rw, RedactWith::Char('#')));
    }

    #[test]
    fn to_redact_with_char_default() {
        let rw = to_redact_with(RedactStrategy::Char, None);
        assert!(matches!(rw, RedactWith::Char('*')));
    }

    #[test]
    fn to_redact_with_type_label() {
        let rw = to_redact_with(RedactStrategy::TypeLabel, None);
        assert!(matches!(rw, RedactWith::TypeLabel));
    }

    #[tokio::test]
    async fn pool_multiple_threads() {
        let config = PiiConfig {
            countries: vec![pii::Country::International],
            languages: vec![pii::Language::En],
            scanner_threads: Some(3),
            detect: None,
            ignore: None,
            custom: Vec::new(),
        };
        let pool = ScannerPool::new(&config).expect("pool should start");

        for _ in 0..6 {
            let req = ScanRequest {
                body: Some(BodyFormat::PlainText(Bytes::from(
                    "email: user@example.com",
                ))),
                path: None,
                query: None,
                headers: None,
                redact: false,
                redact_strategy: None,
            };
            let result = pool.process(req, OnError::FailOpen).await.unwrap();
            assert!(result.detected);
        }
    }

    // --- redact_in_place: char-mask tests ---

    // Char-mask replacement length = kind label length (EMAIL=5, US_PHONE_NUMBER=15, US_SSN=6)
    #[test_case("email me at test@example.com please", '*', "email me at ***** please" ; "basic email char mask")]
    #[test_case("nothing sensitive here", '*', "nothing sensitive here" ; "no pii preserves text char mask")]
    #[test_case("contact user%40example.com now", '*', "contact ***** now" ; "url encoded at char mask")]
    #[test_case("contact user&#64;example.com now", '*', "contact ***** now" ; "html entity at char mask")]
    #[test_case("contact user&commat;example.com now", '*', "contact ***** now" ; "html named entity at char mask")]
    #[test_case("contact user\u{200B}@example.com now", '*', "contact ***** now" ; "zwsp in email char mask")]
    #[test_case("user@ex\u{0430}mple.com", '*', "*****" ; "cyrillic homoglyph char mask")]
    #[test_case("phone: 555-123-4567", '*', "phone: ***************" ; "keyword context phone char mask")]
    #[test_case("mask: test@example.com done", '#', "mask: ##### done" ; "custom mask char")]
    #[test_case("\u{00E9}l\u{00E8}ve user@example.com fin", '*', "\u{00E9}l\u{00E8}ve ***** fin" ; "accented chars surrounding preserved")]
    #[test_case("\u{2603} user@example.com \u{2764}", '*', "\u{2603} ***** \u{2764}" ; "emoji surrounding preserved")]
    #[test_case("\u{00BF}hola? user@example.com \u{00A1}s\u{00ED}!", '*', "\u{00BF}hola? ***** \u{00A1}s\u{00ED}!" ; "spanish punctuation surrounding preserved")]
    #[test_case("\u{200E}LTR user@example.com \u{200E}end", '*', "\u{200E}LTR ***** \u{200E}end" ; "ltr marks surrounding preserved")]
    fn redact_char_mask(input: &str, mask: char, expected: &str) {
        let scanner = &*SCANNER;
        let mut matches = scanner.mark_piis(input);
        let mut text = input.to_string();
        redact_in_place(&mut text, &mut matches, &RedactWith::Char(mask));
        assert_eq!(
            text, expected,
            "char-mask redaction mismatch for input: {input}"
        );
    }

    // --- redact_in_place: type-label tests ---

    #[test_case("email me at test@example.com please", "[EMAIL]" ; "basic email type label")]
    #[test_case("nothing sensitive here", "nothing sensitive here" ; "no pii preserves text type label")]
    #[test_case("contact user%40example.com now", "[EMAIL]" ; "url encoded at type label")]
    #[test_case("contact user&#64;example.com now", "[EMAIL]" ; "html entity at type label")]
    #[test_case("contact user&commat;example.com now", "[EMAIL]" ; "html named entity at type label")]
    #[test_case("contact user\u{200B}@example.com now", "[EMAIL]" ; "zwsp in email type label")]
    #[test_case("user@ex\u{0430}mple.com", "[EMAIL]" ; "cyrillic homoglyph type label")]
    fn redact_type_label_contains(input: &str, expected_label: &str) {
        let scanner = &*SCANNER;
        let mut matches = scanner.mark_piis(input);
        let mut text = input.to_string();
        redact_in_place(&mut text, &mut matches, &RedactWith::TypeLabel);
        assert!(
            text.contains(expected_label),
            "expected {expected_label} in redacted output, got: {text}"
        );
    }

    #[test]
    fn redact_type_label_multiple_pii_types() {
        let scanner = &*SCANNER;
        let input = "email: user@test.com, SSN: 123-45-6789";
        let mut matches = scanner.mark_piis(input);
        let mut text = input.to_string();
        redact_in_place(&mut text, &mut matches, &RedactWith::TypeLabel);
        assert!(text.contains("[EMAIL]"));
        assert!(text.contains("[US_SSN]"));
        assert!(!text.contains("user@test.com"));
        assert!(!text.contains("123-45-6789"));
    }

    #[test]
    fn redact_type_label_multiple_encoded_piis() {
        let scanner = &*SCANNER;
        let input = "email: user%40test.com, SSN: 123-45-6789";
        let mut matches = scanner.mark_piis(input);
        let mut text = input.to_string();
        redact_in_place(&mut text, &mut matches, &RedactWith::TypeLabel);
        assert!(text.contains("[EMAIL]"));
        assert!(text.contains("[US_SSN]"));
        assert!(!text.contains("user%40test.com"));
        assert!(!text.contains("123-45-6789"));
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
        let bf = classify_body(raw, media_type).expect("classify ok");
        assert!(matches!(bf, BodyFormat::Structured { .. }));
    }

    #[test_case("application/xml" ; "xml not json")]
    #[test_case("application/jsonld" ; "no plus before json")]
    #[test_case("application/problem+xml" ; "problem xml")]
    fn non_json_media_types_dont_match_json(media_type: &str) {
        // These must not be parsed as JSON. Body is invalid JSON to make
        // misclassification observable: classify_body would return Err if it
        // tried to flatten as JSON, but PlainText path swallows arbitrary bytes.
        let raw = Bytes::from_static(b"not json");
        let bf = classify_body(raw, media_type).expect("classify ok");
        assert!(matches!(bf, BodyFormat::PlainText(_)));
    }

    #[test]
    fn json_with_charset_parameter_classifies_as_structured() {
        let raw = Bytes::from_static(br#"{"k": "v"}"#);
        let bf = classify_body(raw, "application/json; charset=utf-8").unwrap();
        assert!(matches!(bf, BodyFormat::Structured { .. }));
    }

    #[test]
    fn json_uppercase_content_type_classifies_as_structured() {
        let raw = Bytes::from_static(br#"{"k": "v"}"#);
        let bf = classify_body(raw, "Application/JSON").unwrap();
        assert!(matches!(bf, BodyFormat::Structured { .. }));
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
        let bf = classify_body(raw, media_type).unwrap();
        assert!(matches!(bf, BodyFormat::Structured { .. }));
    }

    #[test_case("application/vnd.ms-excel" ; "excel binary not csv")]
    #[test_case("text/comma-separated-values" ; "legacy form not supported")]
    fn non_csv_media_types_dont_match_csv(media_type: &str) {
        // Even with a CSV-shaped payload, these must not route to the CSV
        // parser — Excel can be binary, the legacy form is intentionally
        // excluded.
        let raw = Bytes::from_static(b"name,phone\nJohn,555-1234");
        let bf = classify_body(raw, media_type).unwrap();
        assert!(matches!(bf, BodyFormat::PlainText(_)));
    }

    #[test]
    fn csv_without_headers_falls_back_to_plain_text() {
        let raw = Bytes::from_static(b"123,456\n789,012");
        let bf = classify_body(raw, "text/csv").unwrap();
        assert!(matches!(bf, BodyFormat::PlainText(_)));
    }

    #[test_case("text/tab-separated-values" ; "canonical")]
    #[test_case("text/tsv" ; "short form")]
    fn tsv_media_types_with_headers_classify_as_structured(media_type: &str) {
        let raw = Bytes::from_static(b"name\tphone\nJohn\t555-1234");
        let bf = classify_body(raw, media_type).unwrap();
        assert!(matches!(bf, BodyFormat::Structured { .. }));
    }

    #[test]
    fn unknown_content_type_is_plain_text() {
        let raw = Bytes::from_static(b"hello world");
        let bf = classify_body(raw, "text/plain").unwrap();
        assert!(matches!(bf, BodyFormat::PlainText(_)));
    }

    // --- execute_scan with BodyFormat::Structured ---

    #[tokio::test]
    async fn structured_body_detects_pii_via_keyword_context() {
        let pool = make_pool();
        // The flat-text body `{"phone_number":"555-123-4567"}` already detects
        // via keyword context; this test instead asserts that the structured
        // path is wired up — same input, but pre-flattened.
        let raw = Bytes::from_static(br#"{"phone_number":"555-123-4567"}"#);
        let bf = classify_body(raw, "application/json").unwrap();
        let req = ScanRequest {
            body: Some(bf),
            path: None,
            query: None,
            headers: None,
            redact: false,
            redact_strategy: None,
        };
        let result = pool.process(req, OnError::FailOpen).await.unwrap();
        assert!(result.detected, "expected phone detected, got {result:?}");
        assert!(result.kinds.iter().any(|k| k == "US_PHONE_NUMBER"));
    }

    #[tokio::test]
    async fn structured_body_redacts_in_place_preserving_json() {
        let pool = make_pool();
        let raw = Bytes::from_static(br#"{"phone_number":"555-123-4567"}"#);
        let bf = classify_body(raw, "application/json").unwrap();
        let req = ScanRequest {
            body: Some(bf),
            path: None,
            query: None,
            headers: None,
            redact: true,
            redact_strategy: Some(RedactWith::TypeLabel),
        };
        let result = pool.process(req, OnError::FailOpen).await.unwrap();
        let body = result.redacted_body.expect("body should be redacted");
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("[US_PHONE_NUMBER]"), "got: {text}");
        assert!(!text.contains("555-123-4567"));
        // Surrounding JSON structure must remain intact (quotes, braces, key).
        assert!(text.starts_with(r#"{"phone_number":""#));
        assert!(text.ends_with(r#""}"#));
        // Re-parse to confirm valid JSON.
        let v: serde_json::Value = serde_json::from_slice(&body).expect("redacted JSON valid");
        assert_eq!(v["phone_number"], "[US_PHONE_NUMBER]");
    }

    #[tokio::test]
    async fn structured_csv_body_detects_pii_via_column_context() {
        let pool = make_pool();
        let raw = Bytes::from_static(b"name,phone_number\nAda,555-123-4567");
        let bf = classify_body(raw, "text/csv").unwrap();
        let req = ScanRequest {
            body: Some(bf),
            path: None,
            query: None,
            headers: None,
            redact: true,
            redact_strategy: Some(RedactWith::TypeLabel),
        };
        let result = pool.process(req, OnError::FailOpen).await.unwrap();
        assert!(result.detected);
        assert!(result.kinds.iter().any(|k| k == "US_PHONE_NUMBER"));
        let body = result.redacted_body.expect("body should be redacted");
        let text = std::str::from_utf8(&body).unwrap();
        // Header row and delimiter structure must be preserved.
        assert!(text.starts_with("name,phone_number\nAda,"));
        assert!(text.contains("[US_PHONE_NUMBER]"));
        assert!(!text.contains("555-123-4567"));
    }
}
