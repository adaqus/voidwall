use std::collections::HashSet;
use std::thread::JoinHandle;

use bytes::Bytes;
use crossbeam_channel::{Sender, TrySendError};
use tracing::{debug, error, info};

use crate::config::{OnError, PiiConfig, RedactStrategy};
use crate::error::Error;

// ---------------------------------------------------------------------------
// Scan request / result types
// ---------------------------------------------------------------------------

/// A request to scan (and optionally redact) text fragments.
pub struct ScanRequest {
    pub body: Option<Bytes>,
    pub url: Option<String>,
    pub query: Option<String>,
    pub headers: Option<Vec<(String, String)>>,
    pub redact: bool,
    pub redact_strategy: Option<pii::RedactWith>,
}

/// Result of scanning (and optionally redacting) text fragments.
#[derive(Debug)]
pub struct ScanResult {
    pub detected: bool,
    pub kinds: Vec<String>,
    pub matches_count: usize,
    pub redacted_body: Option<Bytes>,
    pub redacted_url: Option<String>,
    pub redacted_headers: Option<Vec<(String, String)>>,
}

// ---------------------------------------------------------------------------
// Internal message type
// ---------------------------------------------------------------------------

type WorkItem = (ScanRequest, tokio::sync::oneshot::Sender<ScanResult>);

// ---------------------------------------------------------------------------
// Scanner pool
// ---------------------------------------------------------------------------

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
    /// its own `pii::Scanner` instance. The bounded channel capacity equals
    /// the number of threads.
    pub fn new(pii_config: &PiiConfig) -> Result<Self, Error> {
        let num_threads = pii_config.effective_scanner_threads();
        let (sender, receiver) = crossbeam_channel::bounded::<WorkItem>(num_threads);

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
    pub async fn process(
        &self,
        request: ScanRequest,
        on_error: OnError,
    ) -> Result<ScanResult, Error> {
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| Error::Scanner("scanner pool is shut down".into()))?;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

        match sender.try_send((request, reply_tx)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                error!("scanner pool channel full");
                return Err(Error::Scanner("scanner pool overloaded".into()));
            }
            Err(TrySendError::Disconnected(_)) => {
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

/// Build a `pii::Scanner` from the proxy's PII configuration.
fn build_scanner(config: &PiiConfig) -> Result<pii::Scanner, Error> {
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

    Ok(builder.build()?)
}

/// Convert a `RedactStrategy` config value to a `pii::RedactWith`.
pub fn to_redact_with(strategy: RedactStrategy, mask_char: Option<char>) -> pii::RedactWith {
    match strategy {
        RedactStrategy::Char => pii::RedactWith::Char(mask_char.unwrap_or('*')),
        RedactStrategy::TypeLabel => pii::RedactWith::TypeLabel,
    }
}

/// Execute scan (and optional redaction) synchronously on a scanner thread.
fn execute_scan(scanner: &pii::Scanner, request: ScanRequest) -> ScanResult {
    let mut all_kinds: HashSet<String> = HashSet::new();
    let mut matches_count: usize = 0;

    let mut redacted_body = None;
    let mut redacted_url = None;
    let mut redacted_headers = None;

    // Scan body
    if let Some(ref body) = request.body {
        if let Ok(text) = std::str::from_utf8(body) {
            let matches = scanner.mark_piis(text);
            matches_count += matches.len();
            for m in &matches {
                all_kinds.insert(m.kind.label().to_string());
            }

            if request.redact && !matches.is_empty()
                && let Some(ref strategy) = request.redact_strategy
            {
                let mut owned = text.to_string();
                scanner.redact(&mut owned, strategy);
                redacted_body = Some(Bytes::from(owned));
            }
        }
    }

    // Scan URL
    if let Some(ref url) = request.url {
        let matches = scanner.mark_piis(url);
        matches_count += matches.len();
        for m in &matches {
            all_kinds.insert(m.kind.label().to_string());
        }

        if request.redact && !matches.is_empty()
            && let Some(ref strategy) = request.redact_strategy
        {
            let mut owned = url.clone();
            scanner.redact(&mut owned, strategy);
            redacted_url = Some(owned);
        }
    }

    // Scan query string
    if let Some(ref query) = request.query {
        let matches = scanner.mark_piis(query);
        matches_count += matches.len();
        for m in &matches {
            all_kinds.insert(m.kind.label().to_string());
        }
    }

    // Scan headers
    if let Some(ref headers) = request.headers {
        let mut header_results: Vec<(String, String)> = Vec::with_capacity(headers.len());
        let mut any_redacted = false;

        for (name, value) in headers {
            let matches = scanner.mark_piis(value);
            matches_count += matches.len();
            for m in &matches {
                all_kinds.insert(m.kind.label().to_string());
            }

            if request.redact && !matches.is_empty()
                && let Some(ref strategy) = request.redact_strategy
            {
                let mut owned = value.clone();
                scanner.redact(&mut owned, strategy);
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
        redacted_url,
        redacted_headers,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pii_config() -> PiiConfig {
        PiiConfig {
            countries: vec![pii::Country::International, pii::Country::Us],
            languages: vec![pii::Language::En],
            scanner_threads: Some(1),
            detect: None,
            ignore: None,
        }
    }

    fn make_pool() -> ScannerPool {
        ScannerPool::new(&test_pii_config()).expect("pool should start")
    }

    #[tokio::test]
    async fn scan_no_pii() {
        let pool = make_pool();
        let req = ScanRequest {
            body: Some(Bytes::from("hello world")),
            url: None,
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
            body: Some(Bytes::from("contact me at user@example.com please")),
            url: None,
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
            body: Some(Bytes::from("email: user@example.com")),
            url: None,
            query: None,
            headers: None,
            redact: true,
            redact_strategy: Some(pii::RedactWith::TypeLabel),
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
            body: Some(Bytes::from("email: user@example.com")),
            url: None,
            query: None,
            headers: None,
            redact: true,
            redact_strategy: Some(pii::RedactWith::Char('*')),
        };
        let result = pool.process(req, OnError::FailOpen).await.unwrap();
        assert!(result.detected);
        let body = result.redacted_body.expect("body should be redacted");
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("***"), "expected masking in '{text}'");
        assert!(!text.contains("user@example.com"));
    }

    #[tokio::test]
    async fn scan_url_with_pii() {
        let pool = make_pool();
        let req = ScanRequest {
            body: None,
            url: Some("/api/users/user@example.com".into()),
            query: None,
            headers: None,
            redact: true,
            redact_strategy: Some(pii::RedactWith::TypeLabel),
        };
        let result = pool.process(req, OnError::FailOpen).await.unwrap();
        assert!(result.detected);
        let url = result.redacted_url.expect("url should be redacted");
        assert!(url.contains("[EMAIL]"), "expected [EMAIL] in '{url}'");
    }

    #[tokio::test]
    async fn scan_headers_with_pii() {
        let pool = make_pool();
        let req = ScanRequest {
            body: None,
            url: None,
            query: None,
            headers: Some(vec![
                ("Authorization".into(), "Bearer user@example.com".into()),
                ("X-Safe".into(), "nothing here".into()),
            ]),
            redact: true,
            redact_strategy: Some(pii::RedactWith::TypeLabel),
        };
        let result = pool.process(req, OnError::FailOpen).await.unwrap();
        assert!(result.detected);
        let headers = result.redacted_headers.expect("headers should be redacted");
        let auth = &headers.iter().find(|(n, _)| n == "Authorization").unwrap().1;
        assert!(auth.contains("[EMAIL]"), "expected [EMAIL] in '{auth}'");
        let safe = &headers.iter().find(|(n, _)| n == "X-Safe").unwrap().1;
        assert_eq!(safe, "nothing here");
    }

    #[tokio::test]
    async fn scan_empty_request() {
        let pool = make_pool();
        let req = ScanRequest {
            body: None,
            url: None,
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
            body: Some(Bytes::from("test")),
            url: None,
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
        };
        assert!(build_scanner(&config).is_ok());
    }

    #[test]
    fn to_redact_with_char() {
        let rw = to_redact_with(RedactStrategy::Char, Some('#'));
        assert!(matches!(rw, pii::RedactWith::Char('#')));
    }

    #[test]
    fn to_redact_with_char_default() {
        let rw = to_redact_with(RedactStrategy::Char, None);
        assert!(matches!(rw, pii::RedactWith::Char('*')));
    }

    #[test]
    fn to_redact_with_type_label() {
        let rw = to_redact_with(RedactStrategy::TypeLabel, None);
        assert!(matches!(rw, pii::RedactWith::TypeLabel));
    }

    #[tokio::test]
    async fn pool_multiple_threads() {
        let config = PiiConfig {
            countries: vec![pii::Country::International],
            languages: vec![pii::Language::En],
            scanner_threads: Some(3),
            detect: None,
            ignore: None,
        };
        let pool = ScannerPool::new(&config).expect("pool should start");

        for _ in 0..6 {
            let req = ScanRequest {
                body: Some(Bytes::from("email: user@example.com")),
                url: None,
                query: None,
                headers: None,
                redact: false,
                redact_strategy: None,
            };
            let result = pool.process(req, OnError::FailOpen).await.unwrap();
            assert!(result.detected);
        }
    }
}
