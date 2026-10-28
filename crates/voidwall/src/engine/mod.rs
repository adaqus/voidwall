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
//! A vocabulary is the set of kinds one guard produces. Two guards that report a
//! kind of the same name do not share one, so the engine merges their findings
//! and resolves nothing between them.
//!
//! `voidwall_pii::resolve_overlaps` is a greedy pairwise pass, so resolving twice
//! is not the same as resolving once: resolving each guard's findings and then
//! resolving the union keeps a different set than resolving the union. Each
//! guard resolves its own matches and the engine adds nothing. If two guards are
//! ever built to produce one vocabulary, resolution moves here, over their union,
//! and the per-guard pass is removed. Never both.

pub mod finding;
pub mod guard;
mod model;
mod regex_pii;
pub mod unit;
mod unit_text;

use std::cmp::Ordering;
use std::sync::Arc;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use tracing::{info, warn};
use voidwall_ml::OnnxRuntime;

use crate::config::{AppConfig, BUILTIN_PII_GUARD_NAME, BuiltinGuards, OnError, available_cpus};
use crate::error::Error;
use crate::scanner::SCANNER_ERROR_LIMITER;

pub use finding::{Finding, FindingKind, GuardSummary, ScanResult, Span};
pub use guard::{DetectFuture, Guard, GuardInput, Interest};
pub use unit::{Unit, UnitContent, UnitId, UnitKind, Units};

/// When the engine may stop waiting for the guards still running.
///
/// The engine short-circuits for a block and nothing else: a blocked message is
/// not going anywhere, so the remaining findings cannot change the outcome. A
/// caller that reports rather than blocks needs the full set, so it never
/// short-circuits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BlockPolicy {
    /// No finding blocks. Every interested guard runs to completion.
    #[default]
    Never,
    /// Any finding blocks. This is what the proxy passes: detection alone
    /// decides, and the message is stopped.
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

/// The guards that run for one message, resolved once at startup.
///
/// A route names guards; the engine turns that into the guards it will run and
/// the surface a handler has to decode for. Resolving once keeps the name
/// lookup off the request path, and keeps the handler from deciding anything
/// about which guard sees what.
#[derive(Debug, Clone)]
pub struct GuardSelection {
    /// Indices into [`Engine::guards`].
    indices: Vec<usize>,
    /// The union of the selected guards' interests. Nothing outside this is
    /// worth building: no selected guard would be handed it.
    interest: Interest,
}

impl GuardSelection {
    /// Whether any selected guard admits this unit kind.
    pub fn wants(&self, kind: UnitKind) -> bool {
        self.interest.wants(kind)
    }

    /// Whether this selection runs no guard at all. A route that selected none
    /// is forwarded uninspected.
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    /// A selection carrying a given surface and no guard. Tests only — a real
    /// selection comes from [`Engine::select`], which builds the surface from
    /// the guards it selected.
    #[cfg(test)]
    pub(crate) fn for_test(interest: Interest) -> Self {
        Self {
            indices: Vec::new(),
            interest,
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
    ///
    /// A guard whose section is absent or disabled is not built, so it loads
    /// none of its resources — no scanner thread, no gazetteer.
    pub fn new(builtin_guards: &BuiltinGuards) -> Result<Self, Error> {
        let mut guards: Vec<Box<dyn Guard>> = Vec::new();
        if let Some(pii) = builtin_guards.enabled_pii() {
            guards.push(Box::new(regex_pii::RegexPiiGuard::new(
                BUILTIN_PII_GUARD_NAME,
                pii,
            )?));
        }
        Ok(Self { guards })
    }

    /// Build the built-in guards and then every model guard, in name order.
    ///
    /// Each model guard loads its model here, which takes seconds per guard,
    /// so a caller on the async runtime runs this on the blocking pool. A
    /// load failure names the guard and stops the start.
    pub fn from_config(runtime: &OnnxRuntime, config: &AppConfig) -> Result<Self, Error> {
        let mut engine = Self::new(&config.builtin_guards)?;
        let cpus = available_cpus();
        for (name, guard) in &config.guards {
            engine.guards.push(Box::new(model::ModelGuard::new(
                runtime,
                name,
                guard,
                config.max_body_size,
                config.effective_model_threads(name, cpus),
            )?));
        }
        Ok(engine)
    }

    /// Resolve a guard selection by name.
    ///
    /// `None` selects every guard the engine built, which is what a route that
    /// names no guard and what the API — which has no route to attach a
    /// selection to — both get. A name matching no built guard is skipped:
    /// validation already rejected a route that names one.
    pub fn select(&self, names: Option<&[&str]>) -> GuardSelection {
        let indices: Vec<usize> = match names {
            None => (0..self.guards.len()).collect(),
            Some(names) => self
                .guards
                .iter()
                .enumerate()
                .filter(|(_, g)| names.iter().any(|n| *n == g.name().as_ref()))
                .map(|(i, _)| i)
                .collect(),
        };

        let kinds: Vec<UnitKind> = indices
            .iter()
            .flat_map(|&i| self.guards[i].interest().kinds().iter().copied())
            .collect();

        GuardSelection {
            indices,
            interest: Interest::in_kinds(kinds),
        }
    }

    /// Run the selected, interested guards over `units` and return the merged
    /// findings.
    ///
    /// A guard whose declared interest matches no unit is not called, and nor
    /// is one the selection left out. The findings come back in canonical
    /// order, whatever order the guards finished in. `policy` decides whether a
    /// finding ends the scan early; a guard still running when that happens is
    /// abandoned, and its findings do not appear in the result.
    ///
    /// A guard error does not end the scan. The result carries the findings
    /// of the guards that succeeded and the first guard error; the caller
    /// decides which wins.
    pub async fn guard(
        &self,
        units: Arc<[Unit]>,
        selection: &GuardSelection,
        policy: BlockPolicy,
        on_error: OnError,
    ) -> ScanResult {
        // Apply each selected guard's declared interest. `plans` outlives the
        // futures that borrow its selections.
        let plans: Vec<(&dyn Guard, Vec<UnitId>)> = selection
            .indices
            .iter()
            .filter_map(|&i| {
                let g = &self.guards[i];
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
            let name = guard.name();
            let detect = guard.detect(GuardInput {
                units: &units,
                selected,
                on_error,
            });
            in_flight.push(async move { (name, detect.await) });
        }

        let mut findings = Vec::new();
        let mut first_error = None;
        while let Some((name, result)) = in_flight.next().await {
            // A guard error does not end the scan: another guard may still
            // block. The first error is kept for the caller; a later one is
            // only logged.
            let batch = match result {
                Ok(batch) => batch,
                Err(e) => {
                    if first_error.is_none() {
                        first_error = Some(e);
                    } else if let Some(dropped) = SCANNER_ERROR_LIMITER.should_log() {
                        warn!(dropped, guard = %name, error = %e, "further guard error");
                    }
                    continue;
                }
            };
            let blocks = policy.blocks(&batch);
            findings.extend(batch);
            if blocks {
                break;
            }
        }
        // Abandon whatever is still running. Dropping a guard's future is the
        // whole signal: a model guard cancels its run on drop.
        drop(in_flight);

        findings.sort_by(canonical_order);
        ScanResult::with_error(findings, first_error)
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
        .then_with(|| a.guard.cmp(&b.guard))
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
        seen: Arc<std::sync::Mutex<Vec<UnitId>>>,
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

        /// The units the engine handed this guard, in order.
        pub(crate) fn seen(&self) -> Vec<UnitId> {
            self.seen.lock().expect("probe lock").clone()
        }
    }

    /// Reports one finding of a fixed kind per selected unit.
    /// The error a failing [`TestGuard`] returns.
    #[derive(Clone, Copy)]
    pub(crate) enum TestFailure {
        Scanner,
        Inference,
        WindowLimit,
    }

    pub(crate) struct TestGuard {
        name: Arc<str>,
        kind: &'static str,
        interest: Interest,
        delay: Option<Duration>,
        fails: Option<TestFailure>,
        silent: bool,
        needle: Option<&'static str>,
        fails_on: Option<&'static str>,
        probe: GuardProbe,
    }

    impl TestGuard {
        pub(crate) fn new(name: &str, kind: &'static str) -> Self {
            Self {
                name: Arc::from(name),
                kind,
                interest: Interest::all(),
                delay: None,
                fails: None,
                silent: false,
                needle: None,
                fails_on: None,
                probe: GuardProbe::default(),
            }
        }

        /// Make `detect` succeed and report nothing.
        pub(crate) fn silent(mut self) -> Self {
            self.silent = true;
            self
        }

        /// Make `detect` return a scanner error instead of findings, after the
        /// delay if there is one.
        pub(crate) fn failing(self) -> Self {
            self.failing_with(TestFailure::Scanner)
        }

        /// Make `detect` return the given error instead of findings.
        pub(crate) fn failing_with(mut self, failure: TestFailure) -> Self {
            self.fails = Some(failure);
            self
        }

        /// Fail only when a selected unit holds `needle`; otherwise report
        /// as configured.
        pub(crate) fn failing_on(mut self, needle: &'static str) -> Self {
            self.fails_on = Some(needle);
            self.failing()
        }

        /// Report a finding only where `needle` occurs in a unit, spanning
        /// it, instead of one per unit.
        pub(crate) fn matching(mut self, needle: &'static str) -> Self {
            self.needle = Some(needle);
            self
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
        fn name(&self) -> &Arc<str> {
            &self.name
        }

        fn interest(&self) -> &Interest {
            &self.interest
        }

        fn detect<'a>(&'a self, input: GuardInput<'a>) -> DetectFuture<'a> {
            self.probe.calls.fetch_add(1, AtomicOrdering::SeqCst);
            self.probe
                .seen
                .lock()
                .expect("probe lock")
                .extend_from_slice(input.selected);
            Box::pin(async move {
                if let Some(delay) = self.delay {
                    tokio::time::sleep(delay).await;
                }
                let triggered = self.fails_on.is_none_or(|needle| {
                    input.selected.iter().any(|id| {
                        !needle_spans(&input.units[id.index()].content, needle).is_empty()
                    })
                });
                if let Some(failure) = self.fails.filter(|_| triggered) {
                    self.probe.completions.fetch_add(1, AtomicOrdering::SeqCst);
                    let guard = Arc::clone(&self.name);
                    return Err(match failure {
                        TestFailure::Scanner => Error::Scanner(format!("{guard} failed")),
                        TestFailure::Inference => Error::Inference {
                            guard,
                            detail: "test failure".into(),
                        },
                        TestFailure::WindowLimit => Error::WindowLimit {
                            guard,
                            windows: 3,
                            limit: 2,
                        },
                    });
                }
                let findings = match self.needle {
                    Some(needle) => input
                        .selected
                        .iter()
                        .flat_map(|id| {
                            needle_spans(&input.units[id.index()].content, needle)
                                .into_iter()
                                .map(|span| {
                                    Finding::spanned(*id, self.kind, Arc::clone(&self.name), span)
                                })
                        })
                        .collect(),
                    None => input
                        .selected
                        .iter()
                        .filter(|_| !self.silent)
                        .map(|id| {
                            Finding::spanned(
                                *id,
                                self.kind,
                                Arc::clone(&self.name),
                                Span::new(0, 1),
                            )
                        })
                        .collect(),
                };
                self.probe.completions.fetch_add(1, AtomicOrdering::SeqCst);
                Ok(findings)
            })
        }
    }

    /// Every span of `needle` in `content`: in a structured unit, at the
    /// fragment offset plus its place in the value.
    fn needle_spans(content: &UnitContent, needle: &str) -> Vec<Span> {
        let at = |text: &str, offset: usize| -> Vec<Span> {
            text.match_indices(needle)
                .map(|(i, m)| Span::new(offset + i, offset + i + m.len()))
                .collect()
        };
        match content {
            UnitContent::PlainText(bytes) => at(&String::from_utf8_lossy(bytes), 0),
            UnitContent::Structured { fragments } => fragments
                .iter()
                .flat_map(|f| at(&f.value, f.offset))
                .collect(),
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
    use crate::config::{BuiltinGuards, GuardSurface, PiiGuardConfig};
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
        let mut result = run_with_errors(engine, units, policy).await;
        assert!(result.take_error().is_none(), "guard should succeed");
        result
    }

    async fn run_with_errors(
        engine: &Engine,
        units: Arc<[Unit]>,
        policy: BlockPolicy,
    ) -> ScanResult {
        let selection = engine.select(None);
        engine
            .guard(units, &selection, policy, OnError::FailOpen)
            .await
    }

    fn guard_names(result: &ScanResult) -> Vec<String> {
        result
            .findings()
            .iter()
            .map(|f| f.guard.to_string())
            .collect()
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
        assert_eq!(guard_names(&result), vec!["guard_a", "guard_b"]);
    }

    #[tokio::test]
    async fn the_same_message_scanned_twice_lists_its_findings_in_the_same_order() {
        let engine = Engine::with_guards(vec![
            Box::new(TestGuard::new("guard_b", "US_SSN")),
            Box::new(TestGuard::new("guard_a", "EMAIL")),
        ]);

        let first = run(&engine, body_and_path(), BlockPolicy::Never).await;
        let second = run(&engine, body_and_path(), BlockPolicy::Never).await;

        let shape = |r: &ScanResult| -> Vec<(usize, String)> {
            r.findings()
                .iter()
                .map(|f| (f.unit.index(), f.guard.to_string()))
                .collect()
        };
        assert_eq!(shape(&first), shape(&second));
        // Unit order first, guard name second — not the order the guards were
        // registered or finished in.
        assert_eq!(
            shape(&first),
            vec![
                (0, "guard_a".to_string()),
                (0, "guard_b".to_string()),
                (1, "guard_a".to_string()),
                (1, "guard_b".to_string()),
            ]
        );
        assert_eq!(
            first.kinds(),
            vec!["EMAIL".to_string(), "US_SSN".to_string()]
        );
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
    async fn a_non_blocking_policy_does_not_abandon_a_guard_still_running() {
        let fast = TestGuard::new("fast", "EMAIL");
        let slow = TestGuard::new("slow", "US_SSN").with_delay(SLOW);
        let (fast_probe, slow_probe) = (fast.probe(), slow.probe());
        let engine = Engine::with_guards(vec![Box::new(fast), Box::new(slow)]);

        let result = run(&engine, body_only(), BlockPolicy::Never).await;

        assert_eq!((fast_probe.completions(), slow_probe.completions()), (1, 1));
        assert_eq!(result.matches_count(), 2);
        assert_eq!(
            result.kinds(),
            vec!["EMAIL".to_string(), "US_SSN".to_string()]
        );
    }

    // --- A guard error does not end the scan ---

    #[test_case::test_case(BlockPolicy::AnyFinding ; "blocking caller")]
    #[test_case::test_case(BlockPolicy::Never ; "reporting caller")]
    #[tokio::test]
    async fn a_guard_error_waits_for_a_slower_guard_that_reports(policy: BlockPolicy) {
        let failing = TestGuard::new("failing", "EMAIL").failing();
        let slow = TestGuard::new("slow", "US_SSN").with_delay(SLOW);
        let slow_probe = slow.probe();
        let engine = Engine::with_guards(vec![Box::new(failing), Box::new(slow)]);

        let mut result = run_with_errors(&engine, body_only(), policy).await;

        assert_eq!(slow_probe.completions(), 1, "the slow guard ran to the end");
        assert_eq!(result.kinds(), vec!["US_SSN".to_string()]);
        assert!(result.take_error().is_some());
    }

    #[tokio::test]
    async fn a_guard_error_alone_returns_the_error_and_no_finding() {
        let engine =
            Engine::with_guards(vec![Box::new(TestGuard::new("failing", "EMAIL").failing())]);

        let mut result = run_with_errors(&engine, body_only(), BlockPolicy::AnyFinding).await;

        assert!(!result.detected());
        assert!(result.take_error().is_some());
    }

    #[tokio::test]
    async fn a_guard_error_with_a_guard_that_reports_nothing_returns_the_error() {
        let engine = Engine::with_guards(vec![
            Box::new(TestGuard::new("failing", "EMAIL").failing()),
            Box::new(TestGuard::new("quiet", "US_SSN").silent()),
        ]);

        let mut result = run_with_errors(&engine, body_only(), BlockPolicy::AnyFinding).await;

        assert!(!result.detected());
        assert!(result.take_error().is_some());
    }

    #[tokio::test]
    async fn two_guard_errors_return_one_error() {
        let engine = Engine::with_guards(vec![
            Box::new(TestGuard::new("first", "EMAIL").failing()),
            Box::new(TestGuard::new("second", "US_SSN").failing()),
        ]);

        let mut result = run_with_errors(&engine, body_only(), BlockPolicy::Never).await;

        assert!(!result.detected());
        assert!(result.take_error().is_some());
        assert!(result.take_error().is_none(), "only one error is carried");
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

    // --- Interest comes from the configured surface (3.2) ---

    #[tokio::test]
    async fn a_guard_whose_surface_excludes_the_body_is_not_called_with_the_body_unit() {
        let surface = GuardSurface {
            body: false,
            ..GuardSurface::default()
        };
        let guard =
            TestGuard::new("path_only", "EMAIL").with_interest(Interest::from_surface(&surface));
        let probe = guard.probe();
        let engine = Engine::with_guards(vec![Box::new(guard)]);

        // Unit 0 is the body, unit 1 the path.
        let result = run(&engine, body_and_path(), BlockPolicy::Never).await;

        assert_eq!(probe.seen(), vec![UnitId(1)]);
        assert_eq!(result.matches_count(), 1);
        assert!(result.findings().iter().all(|f| f.unit == UnitId(1)));
    }

    /// Two guards, two surfaces. Each is handed its own units and no more —
    /// the surface is per guard, not a global setting the engine applies once.
    #[tokio::test]
    async fn two_guard_surfaces_are_applied_independently() {
        let body_surface = GuardSurface {
            url_path: false,
            query_params: false,
            ..GuardSurface::default()
        };
        let query_surface = GuardSurface {
            url_path: false,
            body: false,
            ..GuardSurface::default()
        };
        let body_guard = TestGuard::new("body_guard", "EMAIL")
            .with_interest(Interest::from_surface(&body_surface));
        let query_guard = TestGuard::new("query_guard", "US_SSN")
            .with_interest(Interest::from_surface(&query_surface));
        let (body_probe, query_probe) = (body_guard.probe(), query_guard.probe());
        let engine = Engine::with_guards(vec![Box::new(body_guard), Box::new(query_guard)]);

        let mut units = Units::new();
        units.push_body(UnitContent::PlainText(Bytes::from_static(b"content")));
        units.push_query("q=1".into());
        let units = units.into_shared();

        run(&engine, units, BlockPolicy::Never).await;

        assert_eq!(body_probe.seen(), vec![UnitId(0)], "the body and no query");
        assert_eq!(query_probe.seen(), vec![UnitId(1)], "the query and no body");
    }

    // --- Guard selection (3.4) ---

    #[tokio::test]
    async fn an_empty_selection_calls_no_guard_and_finds_nothing() {
        let guard = TestGuard::new("pii", "EMAIL");
        let probe = guard.probe();
        let engine = Engine::with_guards(vec![Box::new(guard)]);

        let selection = engine.select(Some(&[]));
        assert!(selection.is_empty());

        let result = engine
            .guard(
                body_only(),
                &selection,
                BlockPolicy::AnyFinding,
                OnError::FailOpen,
            )
            .await;

        assert_eq!(probe.calls(), 0);
        assert!(!result.detected());
    }

    #[tokio::test]
    async fn a_named_selection_runs_only_the_guards_it_names() {
        let first = TestGuard::new("guard_a", "EMAIL");
        let second = TestGuard::new("guard_b", "US_SSN");
        let (a, b) = (first.probe(), second.probe());
        let engine = Engine::with_guards(vec![Box::new(first), Box::new(second)]);

        let selection = engine.select(Some(&["guard_b"]));
        let result = engine
            .guard(
                body_only(),
                &selection,
                BlockPolicy::Never,
                OnError::FailOpen,
            )
            .await;

        assert_eq!(a.calls(), 0);
        assert_eq!(b.completions(), 1);
        assert_eq!(guard_names(&result), vec!["guard_b"]);
    }

    /// The selection is what a handler decodes for, so it carries the union of
    /// the selected guards' surfaces and nothing wider.
    #[tokio::test]
    async fn a_selection_carries_the_union_of_the_surfaces_it_selected() {
        let body_only_surface = GuardSurface {
            url_path: false,
            query_params: false,
            ..GuardSurface::default()
        };
        let query_only_surface = GuardSurface {
            url_path: false,
            body: false,
            ..GuardSurface::default()
        };
        let engine = Engine::with_guards(vec![
            Box::new(
                TestGuard::new("body_guard", "EMAIL")
                    .with_interest(Interest::from_surface(&body_only_surface)),
            ),
            Box::new(
                TestGuard::new("query_guard", "US_SSN")
                    .with_interest(Interest::from_surface(&query_only_surface)),
            ),
        ]);

        let all = engine.select(None);
        assert!(all.wants(UnitKind::Body));
        assert!(all.wants(UnitKind::QueryString));

        let body_only = engine.select(Some(&["body_guard"]));
        assert!(body_only.wants(UnitKind::Body));
        assert!(!body_only.wants(UnitKind::QueryString));
        assert!(!body_only.wants(UnitKind::UrlPath));
    }

    // --- Guards are built from configuration (3.3) ---

    fn builtin_pii(pii: PiiGuardConfig) -> BuiltinGuards {
        BuiltinGuards::with_pii(pii)
    }

    #[test]
    fn a_disabled_guard_is_not_built() {
        let guards = builtin_pii(PiiGuardConfig {
            enabled: false,
            scanner_threads: Some(3),
            ..PiiGuardConfig::default()
        });
        let engine = Engine::new(&guards).expect("engine should build");

        // The scanner pool is owned by the regex PII guard and reachable from
        // nowhere else, so building no guard is what "no scanner thread
        // starts" means: there is no pool to start one.
        assert!(engine.guards.is_empty());
        assert!(engine.select(None).is_empty());
    }

    #[test]
    fn an_absent_guard_section_builds_no_guard() {
        let engine = Engine::new(&BuiltinGuards::default()).expect("engine should build");
        assert!(engine.guards.is_empty());
    }

    #[test]
    fn an_enabled_guard_is_built_under_its_section_name() {
        let guards = builtin_pii(PiiGuardConfig {
            countries: vec![voidwall_pii::Country::International],
            languages: vec![voidwall_pii::Language::En],
            scanner_threads: Some(1),
            ..PiiGuardConfig::default()
        });
        let engine = Engine::new(&guards).expect("engine should build");
        assert_eq!(engine.guards.len(), 1);
        assert_eq!(engine.guards[0].name().as_ref(), "pii");
        engine.shutdown();
    }

    /// A config with no built-in guard and one fixture model guard.
    fn model_guard_config(dir: &std::path::Path, model: &[u8]) -> AppConfig {
        use voidwall_ml::fixtures::{Fixture, TokenizerFixture};
        let model_path = Fixture::default().write(dir);
        if !model.is_empty() {
            std::fs::write(&model_path, model).unwrap();
        }
        let toml = format!(
            r#"
[guards.injection]
adapter = "text_classifier"
model_path = "{model}"
tokenizer_path = "{tokenizer}"
max_tokens = 16
labels = ["PROMPT_INJECTION"]
threads = 1

[http_api]
enabled = true
"#,
            model = model_path.display(),
            tokenizer = TokenizerFixture::default().write(dir).display(),
        );
        toml::from_str(&toml).unwrap()
    }

    #[test]
    fn a_model_guard_is_built_and_selectable_by_name_and_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::from_config(
            voidwall_ml::fixtures::runtime(),
            &model_guard_config(dir.path(), b""),
        )
        .expect("engine should build");
        assert_eq!(engine.guards.len(), 1);
        assert_eq!(engine.guards[0].name().as_ref(), "injection");
        assert!(!engine.select(Some(&["injection"])).is_empty());
        assert!(!engine.select(None).is_empty());
    }

    #[test]
    fn a_bad_model_fails_the_engine_naming_the_guard_and_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let config = model_guard_config(dir.path(), b"not an onnx model");
        let err = Engine::from_config(voidwall_ml::fixtures::runtime(), &config)
            .err()
            .expect("a bad model must fail");
        let msg = err.to_string();
        assert!(msg.contains("guards.injection"), "got: {msg}");
        assert!(
            msg.contains(&config.guards["injection"].model_path.display().to_string()),
            "got: {msg}"
        );
    }

    /// A config with one fixture token classifier guard, `pii_ml`, whose
    /// model labels the word `trigger` as `SECRET`.
    fn token_guard_config(dir: &std::path::Path) -> AppConfig {
        use voidwall_ml::fixtures::{Fixture, TokenizerFixture, write_config};
        let model = Fixture {
            tokens: true,
            trigger: true,
            width: 3,
            ..Fixture::default()
        };
        let toml = format!(
            r#"
[guards.pii_ml]
adapter = "token_classifier"
model_path = "{model}"
tokenizer_path = "{tokenizer}"
config_path = "{config}"
max_tokens = 16
labels = ["SECRET"]
threads = 1

[guards.pii_ml.thresholds]
SECRET = 0.4

[http_api]
enabled = true
"#,
            model = model.write(dir).display(),
            tokenizer = TokenizerFixture::default().write(dir).display(),
            config = write_config(dir, &["O", "B-SECRET", "I-SECRET"]).display(),
        );
        toml::from_str(&toml).unwrap()
    }

    #[tokio::test]
    async fn a_token_guard_is_built_selected_by_name_and_reports_spans() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::from_config(
            voidwall_ml::fixtures::runtime(),
            &token_guard_config(dir.path()),
        )
        .expect("engine should build");
        assert_eq!(engine.guards[0].name().as_ref(), "pii_ml");

        let mut units = Units::new();
        units.push_body(UnitContent::PlainText(Bytes::from_static(
            b"voidwall trigger test",
        )));
        let mut result = engine
            .guard(
                units.into_shared(),
                &engine.select(Some(&["pii_ml"])),
                BlockPolicy::Never,
                OnError::FailClose,
            )
            .await;

        assert!(result.take_error().is_none());
        assert_eq!(result.kinds(), vec!["SECRET".to_string()]);
        assert_eq!(result.findings()[0].span, Some(Span::new(9, 16)));
    }

    #[test]
    fn a_token_guard_load_error_names_the_guard() {
        let dir = tempfile::tempdir().unwrap();
        let config = token_guard_config(dir.path());
        let path = config.guards["pii_ml"].config_path.clone().unwrap();
        std::fs::write(&path, b"{ not json").unwrap();
        let err = Engine::from_config(voidwall_ml::fixtures::runtime(), &config)
            .err()
            .expect("a bad config.json must fail");
        let msg = err.to_string();
        assert!(msg.contains("guards.pii_ml"), "got: {msg}");
        assert!(msg.contains(&path.display().to_string()), "got: {msg}");
    }

    /// pii-scanning, "Two guards report a kind of the same name": the engine
    /// merges and resolves nothing between two vocabularies.
    #[tokio::test]
    async fn two_guards_reporting_one_kind_name_over_the_same_bytes_keep_both_findings() {
        let engine = Engine::with_guards(vec![
            Box::new(TestGuard::new("pii", "PERSON_NAME").matching("content")),
            Box::new(TestGuard::new("pii_ml", "PERSON_NAME").matching("content")),
        ]);

        let result = run(&engine, body_only(), BlockPolicy::Never).await;

        let found: Vec<_> = result
            .findings()
            .iter()
            .map(|f| (&*f.guard, f.kind.as_str(), f.span))
            .collect();
        let span = Some(Span::new(0, 7));
        assert_eq!(
            found,
            [
                ("pii", "PERSON_NAME", span),
                ("pii_ml", "PERSON_NAME", span)
            ]
        );
        assert_eq!(result.kinds(), vec!["PERSON_NAME".to_string()]);
        assert_eq!(result.matches_count(), 2);
    }

    #[tokio::test]
    async fn shutdown_joins_every_scanner_thread_before_it_logs() {
        let guards = builtin_pii(PiiGuardConfig {
            countries: vec![voidwall_pii::Country::International],
            languages: vec![voidwall_pii::Language::En],
            scanner_threads: Some(3),
            ..PiiGuardConfig::default()
        });
        let engine = Engine::new(&guards).expect("engine should build");

        // The engine holds the only reference to the pool, so this drops it.
        // `Drop for ScannerPool` joins each thread before `shutdown` returns;
        // the test hangs here if one never exits.
        engine.shutdown();
    }
}
