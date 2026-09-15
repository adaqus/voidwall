//! The regex PII guard, and the scanner pool it owns.
//!
//! This is the one real guard today. It wraps `voidwall_pii::Scanner`, which is
//! CPU-bound and must never run on the tokio runtime, so the guard owns a pool
//! of dedicated OS threads. `detect` hands the units to a pool thread over a
//! bounded channel and awaits the reply on a oneshot.
//!
//! Overlap resolution runs here, on the pool thread, once per unit. That is
//! correct while this guard is the only producer of the PII kind vocabulary —
//! see the note on scoping in [`super`].

use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crossbeam_channel::{SendTimeoutError, Sender};
use tracing::{debug, error, info};

use crate::config::{OnError, PiiGuardConfig};
use crate::error::Error;
use crate::scanner::{LogRateLimiter, build_scanner};

use super::finding::{Finding, Span};
use super::guard::{DetectFuture, Guard, GuardInput, Interest};
use super::unit::{Unit, UnitContent, UnitId};

/// How long a submit waits for a free channel slot before giving up.
const SEND_TIMEOUT: Duration = Duration::from_secs(1);

static CHANNEL_FULL_LIMITER: LogRateLimiter = LogRateLimiter::new(1_000);

/// One unit of work for a scanner thread: the message's units, and the subset
/// this guard was asked to look at.
struct ScanJob {
    units: Arc<[Unit]>,
    selected: Vec<UnitId>,
    /// The guard's configured name, put on every finding the job produces.
    guard: Arc<str>,
}

type WorkItem = (ScanJob, tokio::sync::oneshot::Sender<Vec<Finding>>);

/// A pool of dedicated OS threads, each owning a `voidwall_pii::Scanner`.
///
/// Work is dispatched over a bounded crossbeam channel; replies come back
/// through tokio oneshot channels so the async caller can await them.
///
/// The pool has no explicit shutdown. It sits behind a boxed guard inside the
/// engine, so no caller can reclaim it to shut it down; `Drop` closes the
/// channel and joins every thread.
pub(crate) struct ScannerPool {
    sender: Option<Sender<WorkItem>>,
    handles: Vec<JoinHandle<()>>,
}

impl ScannerPool {
    /// Spawn `pii_config.effective_scanner_threads()` OS threads, each with its
    /// own `voidwall_pii::Scanner`. The bounded channel capacity is four times
    /// the thread count, to absorb short bursts while still applying
    /// backpressure.
    pub(crate) fn new(pii_config: &PiiGuardConfig) -> Result<Self, Error> {
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
                    while let Ok((job, reply_tx)) = rx.recv() {
                        let findings = execute_scan(&scanner, &job);
                        let _ = reply_tx.send(findings);
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

    /// Submit a job and await its findings.
    ///
    /// If the channel is full the caller blocks (on the tokio blocking pool)
    /// for up to [`SEND_TIMEOUT`] before giving up, so backpressure reaches the
    /// HTTP layer instead of bursts being rejected instantly.
    async fn submit(&self, job: ScanJob, on_error: OnError) -> Result<Vec<Finding>, Error> {
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| Error::Scanner("scanner pool is shut down".into()))?
            .clone();

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let item = (job, reply_tx);

        // send_timeout blocks, so run it on the tokio blocking thread pool to
        // avoid stalling the async runtime.
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
}

impl Drop for ScannerPool {
    fn drop(&mut self) {
        self.sender.take();

        for handle in self.handles.drain(..) {
            if let Err(e) = handle.join() {
                error!(?e, "scanner thread panicked during shutdown");
            }
        }

        info!("scanner pool shut down");
    }
}

/// Log a "channel full" message, rate-limited to once per second.
fn log_channel_full(message: &str) {
    if let Some(dropped) = CHANNEL_FULL_LIMITER.should_log() {
        error!(dropped, "{message}");
    }
}

/// Scan the selected units on a scanner thread and map every resolved match to
/// a finding.
///
/// `resolve_overlaps` runs once per unit, matching the granularity the proxy
/// has always used — the body, the path, the query, and each header value
/// resolved separately.
fn execute_scan(scanner: &voidwall_pii::Scanner, job: &ScanJob) -> Vec<Finding> {
    let mut findings = Vec::new();

    for id in &job.selected {
        let Some(unit) = job.units.get(id.index()) else {
            continue;
        };

        let matches = match &unit.content {
            UnitContent::PlainText(bytes) => {
                let Ok(text) = std::str::from_utf8(bytes) else {
                    continue;
                };
                voidwall_pii::resolve_overlaps(scanner.mark_piis(text))
            }
            UnitContent::Structured { fragments, .. } => {
                // Borrow the owned fragments as the pii crate's view type.
                let borrowed: Vec<voidwall_pii::ContextFragment<'_>> = fragments
                    .iter()
                    .map(|f| voidwall_pii::ContextFragment {
                        context: &f.context,
                        value: &f.value,
                        offset: f.offset,
                    })
                    .collect();
                voidwall_pii::resolve_overlaps(scanner.mark_piis_structured(&borrowed))
            }
        };

        findings.extend(matches.into_iter().map(|m| {
            Finding::spanned(
                *id,
                m.label(),
                Arc::clone(&job.guard),
                Span::new(m.start, m.end),
            )
        }));
    }

    findings
}

/// The regex and keyword PII guard.
pub(crate) struct RegexPiiGuard {
    name: Arc<str>,
    pool: ScannerPool,
    interest: Interest,
}

impl RegexPiiGuard {
    /// Build the guard, and with it the scanner pool, from the guard's
    /// configuration. The name is the one configuration gave the guard — its
    /// built-in section key — and the interest comes from its scan surface.
    pub(crate) fn new(name: &str, pii_config: &PiiGuardConfig) -> Result<Self, Error> {
        Ok(Self {
            name: Arc::from(name),
            pool: ScannerPool::new(pii_config)?,
            interest: Interest::from_surface(&pii_config.surface),
        })
    }
}

impl Guard for RegexPiiGuard {
    fn name(&self) -> &Arc<str> {
        &self.name
    }

    fn interest(&self) -> &Interest {
        &self.interest
    }

    fn detect<'a>(&'a self, input: GuardInput<'a>) -> DetectFuture<'a> {
        let job = ScanJob {
            units: Arc::clone(input.units),
            selected: input.selected.to_vec(),
            guard: Arc::clone(&self.name),
        };
        let on_error = input.on_error;
        Box::pin(async move { self.pool.submit(job, on_error).await })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::unit::{UnitKind, Units};
    use crate::scanner::classify_body;
    use bytes::Bytes;

    fn test_pii_config() -> PiiGuardConfig {
        PiiGuardConfig {
            countries: vec![
                voidwall_pii::Country::International,
                voidwall_pii::Country::Us,
            ],
            languages: vec![voidwall_pii::Language::En],
            scanner_threads: Some(1),
            ..PiiGuardConfig::default()
        }
    }

    fn guard() -> RegexPiiGuard {
        RegexPiiGuard::new("pii", &test_pii_config()).expect("guard should build")
    }

    async fn detect_all(guard: &RegexPiiGuard, units: Units) -> Vec<Finding> {
        let units = units.into_shared();
        let selected: Vec<UnitId> = units.iter().map(|u| u.id).collect();
        guard
            .detect(GuardInput {
                units: &units,
                selected: &selected,
                on_error: OnError::FailOpen,
            })
            .await
            .expect("detect should succeed")
    }

    fn body_units(bytes: &'static [u8]) -> Units {
        let mut units = Units::new();
        units.push_body(UnitContent::PlainText(Bytes::from_static(bytes)));
        units
    }

    /// The default surface takes the path, the query, and the body. Header
    /// values come from whatever the route named, so the guard always admits
    /// the kind.
    #[test]
    fn the_guard_takes_its_interest_from_its_configured_surface() {
        let guard = guard();
        for kind in UnitKind::ALL {
            assert!(
                guard.interest().wants(*kind),
                "expected interest in {kind:?}"
            );
        }
        assert_eq!(guard.name().as_ref(), "pii");
    }

    #[test]
    fn a_configured_surface_narrows_what_the_guard_is_called_with() {
        let config = PiiGuardConfig {
            surface: crate::config::GuardSurface {
                body: false,
                ..crate::config::GuardSurface::default()
            },
            ..test_pii_config()
        };
        let guard = RegexPiiGuard::new("pii", &config).expect("guard should build");
        assert!(!guard.interest().wants(UnitKind::Body));
        assert!(guard.interest().wants(UnitKind::UrlPath));
    }

    /// The name is configuration's, not the build's: a differently named
    /// section produces a differently named guard.
    #[test]
    fn the_guard_carries_the_name_configuration_gave_it() {
        let guard = RegexPiiGuard::new("secondary_pii", &test_pii_config())
            .expect("guard should build");
        assert_eq!(guard.name().as_ref(), "secondary_pii");
    }

    #[tokio::test]
    async fn clean_content_produces_no_finding() {
        let findings = detect_all(&guard(), body_units(b"hello world")).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn a_match_becomes_a_spanned_finding_naming_its_unit_and_guard() {
        let findings = detect_all(
            &guard(),
            body_units(b"contact me at user@example.com please"),
        )
        .await;
        let email = findings
            .iter()
            .find(|f| f.kind.as_str() == "EMAIL")
            .expect("expected an EMAIL finding");
        assert_eq!(email.unit, UnitId(0));
        assert_eq!(email.guard.as_ref(), "pii");
        let span = email.span.expect("expected a span");
        assert!(span.start < span.end);
    }

    #[tokio::test]
    async fn every_unit_kind_is_scanned() {
        let mut units = Units::new();
        units.push_body(UnitContent::PlainText(Bytes::from_static(
            b"body user@example.com",
        )));
        units.push_path("/users/other@example.com".into());
        units.push_query("q=third@example.com".into());
        units.push_header("Bearer fourth@example.com".into());

        let findings = detect_all(&guard(), units).await;
        let mut hit: Vec<usize> = findings.iter().map(|f| f.unit.index()).collect();
        hit.sort_unstable();
        hit.dedup();
        assert_eq!(hit, vec![0, 1, 2, 3]);
    }

    #[tokio::test]
    async fn a_structured_body_is_scanned_through_its_fragments() {
        let raw = Bytes::from_static(br#"{"phone_number":"555-123-4567"}"#);
        let content = classify_body(raw, "application/json").expect("classify ok");
        let mut units = Units::new();
        units.push_body(content);

        let findings = detect_all(&guard(), units).await;
        assert!(
            findings
                .iter()
                .any(|f| f.kind.as_str() == "US_PHONE_NUMBER")
        );
        // Spans are document-absolute, so they point inside the JSON string.
        let span = findings[0].span.expect("expected a span");
        assert!(span.start > 0);
    }

    #[tokio::test]
    async fn an_unselected_unit_is_not_scanned() {
        let mut units = Units::new();
        units.push_body(UnitContent::PlainText(Bytes::from_static(
            b"body user@example.com",
        )));
        units.push_path("/users/other@example.com".into());
        let units = units.into_shared();

        let guard = guard();
        let findings = guard
            .detect(GuardInput {
                units: &units,
                selected: &[UnitId(1)],
                on_error: OnError::FailOpen,
            })
            .await
            .expect("detect should succeed");

        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| f.unit == UnitId(1)));
    }

    /// A guard reports and changes nothing.
    ///
    /// The content half is asserted here. The rest is structural and cannot
    /// regress: `detect` returns `Vec<Finding>` and no message to mutate, and
    /// `GuardInput` carries no metric labels, so a guard has no mode, route, or
    /// direction to label a counter with even if it reached for one.
    #[tokio::test]
    async fn a_guard_leaves_the_units_it_scanned_untouched() {
        let scanned = b"contact me at user@example.com please";
        let mut units = Units::new();
        units.push_body(UnitContent::PlainText(Bytes::from_static(scanned)));
        let units = units.into_shared();
        let selected: Vec<UnitId> = units.iter().map(|u| u.id).collect();

        let findings = guard()
            .detect(GuardInput {
                units: &units,
                selected: &selected,
                on_error: OnError::FailOpen,
            })
            .await
            .expect("detect should succeed");

        assert!(!findings.is_empty(), "the guard did find something");
        let UnitContent::PlainText(bytes) = &units[0].content else {
            panic!("expected plain text");
        };
        assert_eq!(bytes, &Bytes::from_static(scanned));
    }

    #[tokio::test]
    async fn non_utf8_content_is_skipped_without_erroring() {
        let findings = detect_all(&guard(), body_units(&[0xff, 0xfe, 0xfd])).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn a_custom_label_reaches_the_finding() {
        let config = PiiGuardConfig {
            custom: vec![voidwall_pii::UserPiiDefinition {
                label: "EMPLOYEE_ID".into(),
                pattern: r"EMP-\d{6}".into(),
                keywords: Vec::new(),
                country: voidwall_pii::Country::International,
            }],
            ..test_pii_config()
        };
        let guard = RegexPiiGuard::new("pii", &config).expect("guard should build");
        let findings = detect_all(&guard, body_units(b"emp EMP-123456 tag")).await;
        assert!(findings.iter().any(|f| f.kind.as_str() == "EMPLOYEE_ID"));
    }

    #[tokio::test]
    async fn the_pool_serves_every_thread() {
        let config = PiiGuardConfig {
            scanner_threads: Some(3),
            ..test_pii_config()
        };
        let guard = RegexPiiGuard::new("pii", &config).expect("guard should build");
        for _ in 0..6 {
            let findings = detect_all(&guard, body_units(b"email: user@example.com")).await;
            assert!(!findings.is_empty());
        }
    }

    #[tokio::test]
    async fn the_pool_joins_its_threads_when_the_last_holder_drops_it() {
        let pool = Arc::new(ScannerPool::new(&test_pii_config()).expect("pool should start"));
        let second = Arc::clone(&pool);

        // One holder releasing the pool leaves the threads running for the
        // other; the job below would fail if the channel had closed.
        drop(pool);

        let mut units = Units::new();
        units.push_body(UnitContent::PlainText(Bytes::from_static(
            b"email: user@example.com",
        )));
        let units = units.into_shared();
        let findings = second
            .submit(
                ScanJob {
                    units,
                    selected: vec![UnitId(0)],
                    guard: Arc::from("pii"),
                },
                OnError::FailOpen,
            )
            .await
            .expect("pool still serves the remaining holder");
        assert!(!findings.is_empty());

        // Dropping the last holder joins every thread. The test hangs here if
        // one never exits.
        drop(second);
    }
}
