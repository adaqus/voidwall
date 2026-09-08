//! The detection engine: one aggregation point for every guard.
//!
//! A handler decodes an HTTP message into [`Units`], hands them to
//! [`Engine::guard`], and acts on the [`ScanResult`] it gets back. The engine
//! owns the stage order — select, filter by interest, fan out, sort,
//! short-circuit — so a later stage attaches here rather than in a handler,
//! and a new detector is a new [`Guard`] rather than a new branch in a
//! handler.
//!
//! # Overlap resolution is scoped to a vocabulary
//!
//! `voidwall_pii::resolve_overlaps` is a greedy pairwise pass, so resolving twice
//! is not the same as resolving once: resolving each guard's findings and then
//! resolving the union keeps a different set than resolving the union. While
//! one guard is the only producer of a kind vocabulary, that guard resolves its
//! own matches and the engine adds nothing — which is what happens today. When
//! a second producer of the same vocabulary appears, resolution moves here, over
//! the union, and the per-guard pass is removed. Never both.

pub mod finding;
pub mod guard;
mod regex_pii;
pub mod unit;

use std::cmp::Ordering;
use std::sync::Arc;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use tracing::info;

use crate::config::{OnError, PiiConfig};
use crate::error::Error;

pub use finding::{Finding, FindingKind, ScanResult, Span};
pub use guard::{DetectFuture, Guard, GuardInput, Interest};
pub use unit::{Unit, UnitContent, UnitId, UnitKind, Units};

/// When the engine may stop waiting for the guards still running.
///
/// The engine short-circuits for a block and nothing else: a blocked message is
/// not going anywhere, so the remaining findings cannot change the outcome. A
/// redact or header outcome needs the full set, so it never short-circuits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BlockPolicy {
    /// No finding blocks. Every interested guard runs to completion.
    #[default]
    Never,
    /// Any finding blocks. This is what a configured `block` action means
    /// today: detection alone decides.
    AnyFinding,
}

impl BlockPolicy {
    /// Whether this batch of findings ends the scan.
    fn blocks(self, findings: &[Finding]) -> bool {
        match self {
            BlockPolicy::Never => false,
            BlockPolicy::AnyFinding => !findings.is_empty(),
        }
    }
}

/// Owns every guard and runs them over one message.
pub struct Engine {
    guards: Vec<Box<dyn Guard>>,
}

impl Engine {
    /// Build the engine and its guards from configuration. Guards are
    /// constructed once, at startup, never per request.
    pub fn new(pii_config: &PiiConfig) -> Result<Self, Error> {
        Ok(Self {
            guards: vec![Box::new(regex_pii::RegexPiiGuard::new(pii_config)?)],
        })
    }

    /// Run every interested guard over `units` and return the merged findings.
    ///
    /// A guard whose declared interest matches no unit is not called. The
    /// findings come back in canonical order, whatever order the guards
    /// finished in. `policy` decides whether a finding ends the scan early; a
    /// guard still running when that happens is abandoned, and its findings do
    /// not appear in the result.
    pub async fn guard(
        &self,
        units: Arc<[Unit]>,
        policy: BlockPolicy,
        on_error: OnError,
    ) -> Result<ScanResult, Error> {
        // Apply each guard's declared interest. `plans` outlives the futures
        // that borrow its selections.
        let plans: Vec<(&dyn Guard, Vec<UnitId>)> = self
            .guards
            .iter()
            .filter_map(|g| {
                let interest = g.interest();
                let selected: Vec<UnitId> = units
                    .iter()
                    .filter(|u| interest.wants(u.kind))
                    .map(|u| u.id)
                    .collect();
                if selected.is_empty() {
                    None
                } else {
                    Some((g.as_ref(), selected))
                }
            })
            .collect();

        // Fan out. The guard futures mostly await a worker's reply, so the
        // parallelism that matters is already inside each guard; polling them
        // together costs nothing and lets them borrow the shared units instead
        // of cloning the content.
        let mut in_flight = FuturesUnordered::new();
        for (guard, selected) in &plans {
            in_flight.push(guard.detect(GuardInput {
                units: &units,
                selected,
                on_error,
            }));
        }

        let mut findings = Vec::new();
        while let Some(result) = in_flight.next().await {
            let batch = result?;
            let blocks = policy.blocks(&batch);
            findings.extend(batch);
            if blocks {
                break;
            }
        }
        // Abandon whatever is still running. The worker behind an abandoned
        // future runs to completion and its reply is discarded.
        drop(in_flight);

        findings.sort_by(canonical_order);
        Ok(ScanResult::new(findings))
    }

    /// Release the guards, then say so.
    ///
    /// There is no explicit shutdown below this: dropping a guard drops the
    /// resources it owns, and a scanner pool joins every thread as it goes. The
    /// log line is written after that, so it means the threads are gone.
    pub fn shutdown(self) {
        drop(self.guards);
        info!("detection engine shut down");
    }

    /// Build an engine over a given guard list. Tests only — production guards
    /// come from configuration.
    #[cfg(test)]
    pub(crate) fn with_guards(guards: Vec<Box<dyn Guard>>) -> Self {
        Self { guards }
    }
}

/// Order findings by unit, then span start, then span end, then guard, then
/// kind. Span-less findings sort after spanned ones within their unit.
fn canonical_order(a: &Finding, b: &Finding) -> Ordering {
    a.unit
        .cmp(&b.unit)
        .then_with(|| match (a.span, b.span) {
            (Some(x), Some(y)) => x.start.cmp(&y.start).then(x.end.cmp(&y.end)),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
        .then_with(|| a.guard.cmp(b.guard))
        .then_with(|| a.kind.cmp(&b.kind))
}

// ---------------------------------------------------------------------------
// Test-only second guard
// ---------------------------------------------------------------------------

/// A second guard, for tests only.
///
/// One real guard exists, so the interest filter, the fan-out, and the
/// short-circuit would all be unreachable code without this. It never appears
/// in a release build.
#[cfg(test)]
pub(crate) mod test_guard {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::time::Duration;

    use super::*;

    /// Counters a test can read after the engine has taken ownership of the
    /// guard.
    #[derive(Clone, Default)]
    pub(crate) struct GuardProbe {
        calls: Arc<AtomicUsize>,
        completions: Arc<AtomicUsize>,
    }

    impl GuardProbe {
        /// How many times `detect` was entered.
        pub(crate) fn calls(&self) -> usize {
            self.calls.load(AtomicOrdering::SeqCst)
        }

        /// How many times `detect` ran to completion. A guard the engine
        /// abandoned is entered but never completed.
        pub(crate) fn completions(&self) -> usize {
            self.completions.load(AtomicOrdering::SeqCst)
        }
    }

    /// Reports one finding of a fixed kind per selected unit.
    pub(crate) struct TestGuard {
        name: &'static str,
        kind: &'static str,
        interest: Interest,
        delay: Option<Duration>,
        probe: GuardProbe,
    }

    impl TestGuard {
        pub(crate) fn new(name: &'static str, kind: &'static str) -> Self {
            Self {
                name,
                kind,
                interest: Interest::all(),
                delay: None,
                probe: GuardProbe::default(),
            }
        }

        pub(crate) fn with_interest(mut self, interest: Interest) -> Self {
            self.interest = interest;
            self
        }

        /// Make the guard slow, so a test can observe it being abandoned.
        pub(crate) fn with_delay(mut self, delay: Duration) -> Self {
            self.delay = Some(delay);
            self
        }

        pub(crate) fn probe(&self) -> GuardProbe {
            self.probe.clone()
        }
    }

    impl Guard for TestGuard {
        fn name(&self) -> &'static str {
            self.name
        }

        fn interest(&self) -> &Interest {
            &self.interest
        }

        fn detect<'a>(&'a self, input: GuardInput<'a>) -> DetectFuture<'a> {
            self.probe.calls.fetch_add(1, AtomicOrdering::SeqCst);
            Box::pin(async move {
                if let Some(delay) = self.delay {
                    tokio::time::sleep(delay).await;
                }
                let findings = input
                    .selected
                    .iter()
                    .map(|id| Finding::spanned(*id, self.kind, self.name, Span::new(0, 1)))
                    .collect();
                self.probe.completions.fetch_add(1, AtomicOrdering::SeqCst);
                Ok(findings)
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::test_guard::TestGuard;
    use super::*;
    use bytes::Bytes;
    use std::time::Duration;

    const SLOW: Duration = Duration::from_millis(200);

    fn body_only() -> Arc<[Unit]> {
        let mut units = Units::new();
        units.push_body(UnitContent::PlainText(Bytes::from_static(b"content")));
        units.into_shared()
    }

    fn body_and_path() -> Arc<[Unit]> {
        let mut units = Units::new();
        units.push_body(UnitContent::PlainText(Bytes::from_static(b"content")));
        units.push_path("/a".into());
        units.into_shared()
    }

    async fn run(engine: &Engine, units: Arc<[Unit]>, policy: BlockPolicy) -> ScanResult {
        engine
            .guard(units, policy, OnError::FailOpen)
            .await
            .expect("guard should succeed")
    }

    #[tokio::test]
    async fn a_guard_interested_in_no_selected_unit_is_not_called() {
        let guard = TestGuard::new("headers_only", "EMAIL")
            .with_interest(Interest::in_kinds([UnitKind::HeaderValue]));
        let probe = guard.probe();
        let engine = Engine::with_guards(vec![Box::new(guard)]);

        let result = run(&engine, body_only(), BlockPolicy::Never).await;

        assert_eq!(probe.calls(), 0);
        assert!(!result.detected());
        assert_eq!(result.matches_count(), 0);
    }

    #[tokio::test]
    async fn two_guards_both_run_and_both_report() {
        let first = TestGuard::new("guard_a", "EMAIL");
        let second = TestGuard::new("guard_b", "US_SSN");
        let (a, b) = (first.probe(), second.probe());
        let engine = Engine::with_guards(vec![Box::new(first), Box::new(second)]);

        let result = run(&engine, body_only(), BlockPolicy::Never).await;

        assert_eq!((a.completions(), b.completions()), (1, 1));
        assert_eq!(result.matches_count(), 2);
        let guards: Vec<&str> = result.findings().iter().map(|f| f.guard).collect();
        assert_eq!(guards, vec!["guard_a", "guard_b"]);
    }

    #[tokio::test]
    async fn the_same_message_scanned_twice_lists_its_findings_in_the_same_order() {
        let engine = Engine::with_guards(vec![
            Box::new(TestGuard::new("guard_b", "US_SSN")),
            Box::new(TestGuard::new("guard_a", "EMAIL")),
        ]);

        let first = run(&engine, body_and_path(), BlockPolicy::Never).await;
        let second = run(&engine, body_and_path(), BlockPolicy::Never).await;

        let shape = |r: &ScanResult| -> Vec<(usize, &'static str)> {
            r.findings()
                .iter()
                .map(|f| (f.unit.index(), f.guard))
                .collect()
        };
        assert_eq!(shape(&first), shape(&second));
        // Unit order first, guard name second — not the order the guards were
        // registered or finished in.
        assert_eq!(
            shape(&first),
            vec![
                (0, "guard_a"),
                (0, "guard_b"),
                (1, "guard_a"),
                (1, "guard_b"),
            ]
        );
        assert_eq!(first.kinds(), vec!["EMAIL".to_string(), "US_SSN".to_string()]);
    }

    #[tokio::test]
    async fn a_blocking_finding_abandons_a_guard_still_running() {
        let fast = TestGuard::new("fast", "EMAIL");
        let slow = TestGuard::new("slow", "US_SSN").with_delay(SLOW);
        let (fast_probe, slow_probe) = (fast.probe(), slow.probe());
        let engine = Engine::with_guards(vec![Box::new(fast), Box::new(slow)]);

        let result = run(&engine, body_only(), BlockPolicy::AnyFinding).await;

        assert_eq!(fast_probe.completions(), 1);
        assert_eq!(slow_probe.calls(), 1, "the slow guard was called");
        assert_eq!(slow_probe.completions(), 0, "and then abandoned");
        assert_eq!(result.matches_count(), 1);
        assert_eq!(result.kinds(), vec!["EMAIL".to_string()]);
    }

    #[tokio::test]
    async fn a_redacting_finding_does_not_abandon_a_guard_still_running() {
        let fast = TestGuard::new("fast", "EMAIL");
        let slow = TestGuard::new("slow", "US_SSN").with_delay(SLOW);
        let (fast_probe, slow_probe) = (fast.probe(), slow.probe());
        let engine = Engine::with_guards(vec![Box::new(fast), Box::new(slow)]);

        let result = run(&engine, body_only(), BlockPolicy::Never).await;

        assert_eq!((fast_probe.completions(), slow_probe.completions()), (1, 1));
        assert_eq!(result.matches_count(), 2);
        assert_eq!(result.kinds(), vec!["EMAIL".to_string(), "US_SSN".to_string()]);
    }

    #[tokio::test]
    async fn two_guards_reporting_the_same_kind_produce_one_entry() {
        let engine = Engine::with_guards(vec![
            Box::new(TestGuard::new("guard_a", "EMAIL")),
            Box::new(TestGuard::new("guard_b", "EMAIL")),
        ]);

        let result = run(&engine, body_only(), BlockPolicy::Never).await;

        assert_eq!(result.matches_count(), 2);
        assert_eq!(result.kinds(), vec!["EMAIL".to_string()]);
    }

    #[tokio::test]
    async fn the_engine_does_not_resolve_what_a_guard_already_resolved() {
        // Both guards report the same kind over the same span. That is exactly
        // what `resolve_overlaps` would collapse under its first rule, so a
        // second resolution pass in the engine would show up as one finding
        // instead of two.
        let engine = Engine::with_guards(vec![
            Box::new(TestGuard::new("guard_a", "EMAIL")),
            Box::new(TestGuard::new("guard_b", "EMAIL")),
        ]);

        let result = run(&engine, body_only(), BlockPolicy::Never).await;

        let spans: Vec<Option<Span>> = result.findings().iter().map(|f| f.span).collect();
        assert_eq!(spans, vec![Some(Span::new(0, 1)), Some(Span::new(0, 1))]);
        assert_eq!(result.matches_count(), 2);
    }

    #[tokio::test]
    async fn span_less_findings_sort_after_spanned_ones() {
        let findings = vec![
            Finding::whole_unit(UnitId(0), "TOPIC", "classifier", 0.9),
            Finding::spanned(UnitId(0), "EMAIL", "regex_pii", Span::new(5, 9)),
            Finding::spanned(UnitId(0), "EMAIL", "regex_pii", Span::new(1, 3)),
        ];
        let mut sorted = findings;
        sorted.sort_by(canonical_order);

        let spans: Vec<Option<Span>> = sorted.iter().map(|f| f.span).collect();
        assert_eq!(
            spans,
            vec![Some(Span::new(1, 3)), Some(Span::new(5, 9)), None]
        );
    }

    #[tokio::test]
    async fn an_engine_with_no_guard_finds_nothing() {
        let engine = Engine::with_guards(Vec::new());
        let result = run(&engine, body_only(), BlockPolicy::Never).await;
        assert!(!result.detected());
    }

    #[tokio::test]
    async fn shutdown_joins_every_scanner_thread_before_it_logs() {
        let config = PiiConfig {
            countries: vec![voidwall_pii::Country::International],
            languages: vec![voidwall_pii::Language::En],
            scanner_threads: Some(3),
            detect: None,
            ignore: None,
            custom: Vec::new(),
        };
        let engine = Engine::new(&config).expect("engine should build");

        // The engine holds the only reference to the pool, so this drops it.
        // `Drop for ScannerPool` joins each thread before `shutdown` returns;
        // the test hangs here if one never exits.
        engine.shutdown();
    }
}
