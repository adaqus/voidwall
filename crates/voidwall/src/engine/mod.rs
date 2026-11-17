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
mod hidden_context;
mod invisible_text;
mod model;
mod regex_pii;
mod scan_view;
pub mod unit;
mod unit_text;

use std::cmp::Ordering;
use std::sync::Arc;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use tracing::{info, warn};
use voidwall_ml::OnnxRuntime;

use crate::config::{
    AppConfig, BUILTIN_HIDDEN_CONTEXT_GUARD_NAME, BUILTIN_INVISIBLE_TEXT_GUARD_NAME,
    BUILTIN_PII_GUARD_NAME, BuiltinGuards, OnError, available_cpus,
};
use crate::error::Error;
use crate::scanner::SCANNER_ERROR_LIMITER;

pub use finding::{Finding, FindingKind, GuardSummary, ScanResult, Span};
pub use guard::{DetectFuture, Direction, Guard, GuardInput, Interest};
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
    /// The selected guards' interests. Nothing outside their union is worth
    /// building: no selected guard would be handed it. They are kept apart
    /// rather than merged into one interest, because a guard that wants
    /// request headers and another that wants response bodies together want
    /// neither request bodies nor response headers.
    interests: Vec<Interest>,
}

impl GuardSelection {
    /// Whether any selected guard admits this unit kind in a message
    /// travelling in `direction`.
    pub fn wants(&self, direction: Direction, kind: UnitKind) -> bool {
        self.interests.iter().any(|i| i.wants(direction, kind))
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
            interests: vec![interest],
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
        if let Some(hidden_context) = builtin_guards.enabled_hidden_context() {
            guards.push(Box::new(hidden_context::HiddenContextGuard::new(
                BUILTIN_HIDDEN_CONTEXT_GUARD_NAME,
                hidden_context,
            )?));
        }
        if builtin_guards.enabled_invisible_text().is_some() {
            guards.push(Box::new(invisible_text::InvisibleTextGuard::new(
                BUILTIN_INVISIBLE_TEXT_GUARD_NAME,
            )));
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

        let interests = indices
            .iter()
            .map(|&i| self.guards[i].interest().clone())
            .collect();

        GuardSelection { indices, interests }
    }

    /// Run the selected, interested guards over `units`, the units of one
    /// message travelling in `direction`, and return the merged findings.
    ///
    /// A guard whose declared interest matches no unit is not called, nor is
    /// one whose interest lacks `direction`, nor one the selection left out.
    /// The findings come back in canonical
    /// order, whatever order the guards finished in. `policy` decides whether a
    /// finding ends the scan early; a guard still running when that happens is
    /// abandoned, and its findings do not appear in the result.
    ///
    /// A guard error does not end the scan. The result carries the findings
    /// of the guards that succeeded and the first guard error; the caller
    /// decides which wins.
    ///
    /// For a request, a guard that reads the scan view is passed the view of
    /// its units instead of their raw text (`hidden-unicode-normalization`).
    /// Every span leaves in raw-message coordinates.
    pub async fn guard(
        &self,
        units: Arc<[Unit]>,
        selection: &GuardSelection,
        direction: Direction,
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
                    .filter(|u| interest.wants(direction, u.kind))
                    .map(|u| u.id)
                    .collect();
                if selected.is_empty() {
                    None
                } else {
                    Some((g.as_ref(), selected))
                }
            })
            .collect();

        // The scan view exists for a request only, and only when a planned
        // guard reads it and a rule changes one of that guard's units.
        let view = match direction {
            Direction::Request => view_units(&units, &plans),
            Direction::Response => None,
        };

        // Fan out. The guard futures mostly await a worker's reply, so the
        // parallelism that matters is already inside each guard; polling them
        // together costs nothing and lets them borrow the shared units instead
        // of cloning the content.
        let mut in_flight = FuturesUnordered::new();
        for (guard, selected) in &plans {
            let name = guard.name();
            let read = match &view {
                Some(view) if guard.reads_scan_view() => view,
                _ => &units,
            };
            let detect = guard.detect(GuardInput {
                units: read,
                selected,
                on_error,
            });
            in_flight.push(async move { (name, read, detect.await) });
        }

        let mut findings = Vec::new();
        let mut first_error = None;
        while let Some((name, read, result)) = in_flight.next().await {
            // A guard error does not end the scan: another guard may still
            // block. The first error is kept for the caller; a later one is
            // only logged.
            let mut batch = match result {
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
            // Each guard's spans map through the units it read.
            map_spans(read, &mut batch);
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

/// The units a guard that reads the scan view is passed: the view of each
/// unit such a guard selected, or `None` when no rule changes any of them, so
/// every guard reads the raw units.
///
/// A unit no rule changes is shared with the raw set: a plain-text unit by
/// its reference-counted bytes, a structured unit by a copy of its fragments.
/// A unit no such guard selected is left empty, since no guard reads it here.
fn view_units(units: &Arc<[Unit]>, plans: &[(&dyn Guard, Vec<UnitId>)]) -> Option<Arc<[Unit]>> {
    let mut wanted = vec![false; units.len()];
    for (guard, selected) in plans {
        if guard.reads_scan_view() {
            for id in selected {
                wanted[id.index()] = true;
            }
        }
    }
    let views: Vec<Option<UnitContent>> = units
        .iter()
        .zip(&wanted)
        .map(|(unit, &wanted)| wanted.then(|| scan_view::view(&unit.content)).flatten())
        .collect();
    if views.iter().all(Option::is_none) {
        return None;
    }
    let set = units
        .iter()
        .zip(views)
        .zip(wanted)
        .map(|((unit, view), wanted)| Unit {
            id: unit.id,
            kind: unit.kind,
            content: match view {
                Some(view) => view,
                None if wanted => unit.content.clone(),
                None => UnitContent::plain(bytes::Bytes::new()),
            },
        })
        .collect();
    Some(set)
}

/// Map the span of each finding to the raw bytes it came from. In a structured
/// unit a guard reports a fragment's `offset` plus a position in its value;
/// the fragment's maps turn that into raw bytes: the scan view's edits first,
/// then the escape sequences. In a plain-text unit the span maps through the
/// unit's edits, which are empty for raw text.
///
/// Neither decoding nor the scan view grows a value, so a guard's span already
/// lies inside the raw range of its fragment, and spans of two fragments never
/// overlap. The maps keep order, so a span that starts before another does
/// not start after it in the raw bytes; overlap resolution inside a guard runs
/// on the spans it reported. Two findings inside one decoded run map to the
/// same raw range and stay two findings.
///
/// Every parser emits a unit's fragments in document order, so the fragment
/// of a span is found by a binary search on `offset`: the cost is one search
/// per finding, never findings times fragments.
fn map_spans(units: &[Unit], findings: &mut [Finding]) {
    debug_assert!(
        units.iter().all(|u| match &u.content {
            UnitContent::Structured { fragments } =>
                fragments.windows(2).all(|w| w[0].offset < w[1].offset),
            UnitContent::PlainText { .. } => true,
        }),
        "the fragments of a unit are in document order"
    );
    for finding in findings {
        let Some(span) = finding.span else {
            continue;
        };
        let fragments = match &units[finding.unit.index()].content {
            UnitContent::Structured { fragments } => fragments,
            UnitContent::PlainText { edits, .. } => {
                if !edits.is_empty() {
                    let raw = edits.raw_range(span.start..span.end);
                    finding.span = Some(Span::new(raw.start, raw.end));
                }
                continue;
            }
        };
        // The last fragment that starts at or before the span.
        let at = fragments.partition_point(|f| f.offset <= span.start);
        match at
            .checked_sub(1)
            .and_then(|i| fragments[i].raw_range(span.start..span.end))
        {
            Some(raw) => finding.span = Some(Span::new(raw.start, raw.end)),
            // Kept as it is: a span in no fragment cannot be mapped.
            None => debug_assert!(false, "a span in a structured unit lies in no fragment"),
        }
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
        texts: Arc<std::sync::Mutex<Vec<String>>>,
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

        /// The text of each unit the engine handed this guard: its bytes, or
        /// its values joined with a newline.
        pub(crate) fn texts(&self) -> Vec<String> {
            self.texts.lock().expect("probe lock").clone()
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
        scan_view: bool,
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
                scan_view: false,
                probe: GuardProbe::default(),
            }
        }

        /// Make the guard read the scan view of a request.
        pub(crate) fn reading_the_view(mut self) -> Self {
            self.scan_view = true;
            self
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

        fn reads_scan_view(&self) -> bool {
            self.scan_view
        }

        fn detect<'a>(&'a self, input: GuardInput<'a>) -> DetectFuture<'a> {
            self.probe.calls.fetch_add(1, AtomicOrdering::SeqCst);
            self.probe
                .seen
                .lock()
                .expect("probe lock")
                .extend_from_slice(input.selected);
            self.probe
                .texts
                .lock()
                .expect("probe lock")
                .extend(input.selected.iter().map(|id| {
                    match &input.units[id.index()].content {
                        UnitContent::PlainText { bytes, .. } => {
                            String::from_utf8_lossy(bytes).into_owned()
                        }
                        UnitContent::Structured { fragments } => fragments
                            .iter()
                            .map(|f| f.value.as_str())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    }
                }));
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
                                first_byte(&input.units[id.index()].content),
                            )
                        })
                        .collect(),
                };
                self.probe.completions.fetch_add(1, AtomicOrdering::SeqCst);
                Ok(findings)
            })
        }
    }

    /// The span a guard without a needle reports: the first byte of the unit,
    /// or of its first fragment's value, as a real guard reports only spans
    /// inside a value.
    fn first_byte(content: &UnitContent) -> Span {
        match content {
            UnitContent::Structured { fragments } => {
                fragments.first().map_or(Span::new(0, 1), |f| {
                    Span::new(f.offset, f.offset + f.value.len().min(1))
                })
            }
            UnitContent::PlainText { .. } => Span::new(0, 1),
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
            UnitContent::PlainText { bytes, .. } => at(&String::from_utf8_lossy(bytes), 0),
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
    use crate::config::{BuiltinGuards, GuardSurface, HiddenContextConfig, PiiGuardConfig};
    use bytes::Bytes;
    use std::time::Duration;

    const SLOW: Duration = Duration::from_millis(200);

    fn body_only() -> Arc<[Unit]> {
        let mut units = Units::new();
        units.push_body(UnitContent::plain(Bytes::from_static(b"content")));
        units.into_shared()
    }

    fn body_and_path() -> Arc<[Unit]> {
        let mut units = Units::new();
        units.push_body(UnitContent::plain(Bytes::from_static(b"content")));
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
            .guard(
                units,
                &selection,
                Direction::Request,
                policy,
                OnError::FailOpen,
            )
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
        units.push_body(UnitContent::plain(Bytes::from_static(b"content")));
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
                Direction::Request,
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
                Direction::Request,
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

        const REQUEST: Direction = Direction::Request;
        let all = engine.select(None);
        assert!(all.wants(REQUEST, UnitKind::Body));
        assert!(all.wants(REQUEST, UnitKind::QueryString));

        let body_only = engine.select(Some(&["body_guard"]));
        assert!(body_only.wants(REQUEST, UnitKind::Body));
        assert!(!body_only.wants(REQUEST, UnitKind::QueryString));
        assert!(!body_only.wants(REQUEST, UnitKind::UrlPath));
    }

    // --- Direction is an axis of interest ---

    #[test_case::test_case(Direction::Request, 0 ; "not called for a request")]
    #[test_case::test_case(Direction::Response, 1 ; "called for a response")]
    #[tokio::test]
    async fn a_response_only_guard_is_called_for_a_response_only(
        direction: Direction,
        calls: usize,
    ) {
        let guard = TestGuard::new("response_only", "HIDDEN_CONTEXT")
            .with_interest(Interest::all().in_directions([Direction::Response]));
        let probe = guard.probe();
        let engine = Engine::with_guards(vec![Box::new(guard)]);

        let result = engine
            .guard(
                body_only(),
                &engine.select(None),
                direction,
                BlockPolicy::Never,
                OnError::FailOpen,
            )
            .await;

        assert_eq!(probe.calls(), calls);
        assert_eq!(result.matches_count(), calls);
    }

    /// A selection keeps each guard's interest whole. One guard that wants
    /// request headers and one that wants response bodies together want
    /// neither a request body nor a response header.
    #[test]
    fn a_selection_does_not_cross_one_guards_direction_with_anothers_kind() {
        let engine = Engine::with_guards(vec![
            Box::new(TestGuard::new("request_headers", "EMAIL").with_interest(
                Interest::in_kinds([UnitKind::HeaderValue]).in_directions([Direction::Request]),
            )),
            Box::new(
                TestGuard::new("response_body", "HIDDEN_CONTEXT").with_interest(
                    Interest::in_kinds([UnitKind::Body]).in_directions([Direction::Response]),
                ),
            ),
        ]);

        let selection = engine.select(None);
        assert!(selection.wants(Direction::Request, UnitKind::HeaderValue));
        assert!(selection.wants(Direction::Response, UnitKind::Body));
        assert!(!selection.wants(Direction::Request, UnitKind::Body));
        assert!(!selection.wants(Direction::Response, UnitKind::HeaderValue));
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

    fn hidden_context(enabled: bool) -> BuiltinGuards {
        BuiltinGuards::with_hidden_context(HiddenContextConfig {
            enabled,
            markers: vec!["vw-canary-0000".into()],
        })
    }

    #[test]
    fn an_enabled_hidden_context_section_builds_the_guard_under_its_name() {
        let engine = Engine::new(&hidden_context(true)).expect("engine should build");
        assert_eq!(engine.guards.len(), 1);
        assert_eq!(engine.guards[0].name().as_ref(), "hidden_context");
        assert!(!engine.select(Some(&["hidden_context"])).is_empty());
    }

    #[test]
    fn a_disabled_hidden_context_section_builds_no_guard() {
        let engine = Engine::new(&hidden_context(false)).expect("engine should build");
        assert!(engine.guards.is_empty());
    }

    /// pii-scanning and hidden-context-guard: on a route selecting both, the
    /// request goes to `pii` alone and the response body to both.
    #[test_case::test_case(Direction::Request, &["EMAIL"] ; "a request")]
    #[test_case::test_case(Direction::Response, &["EMAIL", "HIDDEN_CONTEXT"] ; "a response")]
    #[tokio::test]
    async fn the_hidden_context_guard_inspects_responses_only(
        direction: Direction,
        kinds: &[&str],
    ) {
        let mut guards = hidden_context(true);
        guards.pii = Some(PiiGuardConfig {
            countries: vec![voidwall_pii::Country::International],
            languages: vec![voidwall_pii::Language::En],
            scanner_threads: Some(1),
            ..PiiGuardConfig::default()
        });
        let engine = Engine::new(&guards).expect("engine should build");
        let mut units = Units::new();
        units.push_body(UnitContent::text(
            "mail jane@example.com about vw-canary-0000".into(),
        ));

        let result = engine
            .guard(
                units.into_shared(),
                &engine.select(None),
                direction,
                BlockPolicy::Never,
                OnError::FailClose,
            )
            .await;

        assert_eq!(result.kinds(), kinds);
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
        units.push_body(UnitContent::plain(Bytes::from_static(
            b"voidwall trigger test",
        )));
        let mut result = engine
            .guard(
                units.into_shared(),
                &engine.select(Some(&["pii_ml"])),
                Direction::Request,
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

    // --- A span in a JSON value names the raw bytes ---

    /// One body unit flattened from the JSON document `raw`.
    fn json_body(raw: &[u8]) -> Arc<[Unit]> {
        let fragments = crate::structured::json::flatten_json(raw).unwrap();
        let mut units = Units::new();
        units.push_body(UnitContent::Structured { fragments });
        units.into_shared()
    }

    /// The byte range of the one occurrence of `needle` in `raw`.
    fn raw_span(raw: &[u8], needle: &[u8]) -> Span {
        let start = raw
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("needle in raw");
        Span::new(start, start + needle.len())
    }

    /// The span of each finding, in order.
    fn spans(result: &ScanResult) -> Vec<Option<Span>> {
        result.findings().iter().map(|f| f.span).collect()
    }

    /// The spans a guard reporting the decoded text `a@b.c` gets back.
    async fn placeholder_spans(units: Arc<[Unit]>) -> Vec<Option<Span>> {
        let engine = Engine::with_guards(vec![Box::new(
            TestGuard::new("pii", "EMAIL").matching("a@b.c"),
        )]);
        spans(&run(&engine, units, BlockPolicy::Never).await)
    }

    /// pii-scanning, "A value after an escape sequence", "A value that holds
    /// an escape sequence", and "A value that starts and ends with an escape
    /// sequence": the span is the raw bytes of `placeholder`.
    #[test_case::test_case(b"{\"k\": \"x\", \"s\": \"\\n\\u00e9 a@b.c\"}", b"a@b.c" ; "after an escape")]
    #[test_case::test_case(b"{\"s\": \"to a\\u0040b.c\"}", b"a\\u0040b.c" ; "over an escape")]
    #[test_case::test_case(
        b"{\"s\": \"\\u0061\\u0040\\u0062\\u002e\\u0063\"}",
        b"\\u0061\\u0040\\u0062\\u002e\\u0063" ;
        "from the first backslash to the last digit"
    )]
    #[tokio::test]
    async fn a_span_in_a_json_value_names_the_raw_bytes(raw: &[u8], placeholder: &[u8]) {
        assert_eq!(
            placeholder_spans(json_body(raw)).await,
            [Some(raw_span(raw, placeholder))]
        );
    }

    /// The fragment of each span is found among many, by its offset.
    #[tokio::test]
    async fn spans_in_many_escaped_values_each_name_their_raw_bytes() {
        let values: Vec<String> = (0..300).map(|i| format!("\"{i} a\\u0040b.c\"")).collect();
        let raw = format!("[{}]", values.join(", "));
        let expected: Vec<Option<Span>> = raw
            .match_indices("a\\u0040b.c")
            .map(|(i, m)| Some(Span::new(i, i + m.len())))
            .collect();
        assert_eq!(expected.len(), 300);
        assert_eq!(placeholder_spans(json_body(raw.as_bytes())).await, expected);
    }

    #[tokio::test]
    async fn a_span_in_a_plain_text_unit_is_left_as_it_is() {
        let text: &[u8] = b"to a\\u0040b.c or a@b.c";
        let mut units = Units::new();
        units.push_body(UnitContent::plain(Bytes::from_static(text)));
        assert_eq!(
            placeholder_spans(units.into_shared()).await,
            [Some(Span::new(17, 22))]
        );
    }

    /// The regex PII guard over the international set and English.
    fn international_pii() -> Engine {
        Engine::new(&builtin_pii(PiiGuardConfig {
            countries: vec![voidwall_pii::Country::International],
            languages: vec![voidwall_pii::Language::En],
            scanner_threads: Some(1),
            ..PiiGuardConfig::default()
        }))
        .expect("engine should build")
    }

    /// Overlap resolution and `matches_count` see the same set as without
    /// escapes: two escaped values with one match each count two, and each
    /// span is the raw range of its value.
    #[tokio::test]
    async fn two_escaped_values_count_two_matches() {
        let first: &[u8] = b"\\u006a\\u0040\\u0065\\u0078\\u0061\\u006d\\u0070\\u006c\\u0065.com";
        let second: &[u8] = b"k\\u0040example.org";
        let raw = [
            b"{\"a\": \"".as_slice(),
            first,
            b"\", \"b\": \"",
            second,
            b"\"}",
        ]
        .concat();
        let engine = international_pii();
        let result = run(&engine, json_body(&raw), BlockPolicy::Never).await;

        assert_eq!(result.kinds(), vec!["EMAIL".to_string()]);
        assert_eq!(result.matches_count(), 2);
        assert_eq!(
            spans(&result),
            [Some(raw_span(&raw, first)), Some(raw_span(&raw, second))]
        );
        engine.shutdown();
    }

    /// dictionary-detection, "A JSON value holds a name", after an escape: the
    /// finding's span is the raw byte range of the name.
    #[tokio::test]
    async fn a_dictionary_name_after_an_escape_spans_its_raw_bytes() {
        let raw = b"{\"note\": \"Hi,\\n\\u00e9t\\u00e9: John Smith\"}";
        let engine = international_pii();
        let result = run(&engine, json_body(raw), BlockPolicy::Never).await;

        let names: Vec<Option<Span>> = result
            .findings()
            .iter()
            .filter(|f| f.kind.as_str() == "PERSON_NAME")
            .map(|f| f.span)
            .collect();
        assert_eq!(names, [Some(raw_span(raw, b"John Smith"))]);
        engine.shutdown();
    }

    /// guard-configuration, "A span in a JSON value with escaped non-ASCII":
    /// the fixture's name `TRIGGER_NAME`, with its non-ASCII letter written as
    /// an escape, in the second string value.
    #[tokio::test]
    async fn a_token_guard_span_of_a_name_with_escaped_non_ascii_names_the_raw_bytes() {
        let escaped: &[u8] = b"J\\u00f3zef";
        let raw = [
            b"{\"a\": \"smoke\", \"b\": \"voidwall ".as_slice(),
            escaped,
            b" test\"}",
        ]
        .concat();
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::from_config(
            voidwall_ml::fixtures::runtime(),
            &token_guard_config(dir.path()),
        )
        .expect("engine should build");

        let mut result = engine
            .guard(
                json_body(&raw),
                &engine.select(Some(&["pii_ml"])),
                Direction::Request,
                BlockPolicy::Never,
                OnError::FailClose,
            )
            .await;

        assert!(result.take_error().is_none());
        assert_eq!(result.kinds(), vec!["SECRET".to_string()]);
        assert_eq!(spans(&result), [Some(raw_span(&raw, escaped))]);
    }

    // --- The scan view of a request (hidden-unicode-normalization) ---

    /// One plain-text body unit holding `text`.
    fn plain_body(text: &str) -> Arc<[Unit]> {
        let mut units = Units::new();
        units.push_body(UnitContent::text(text.into()));
        units.into_shared()
    }

    async fn run_in(engine: &Engine, units: Arc<[Unit]>, direction: Direction) -> ScanResult {
        let mut result = engine
            .guard(
                units,
                &engine.select(None),
                direction,
                BlockPolicy::Never,
                OnError::FailClose,
            )
            .await;
        assert!(result.take_error().is_none(), "guard should succeed");
        result
    }

    #[test_case::test_case(Direction::Request, "ab" ; "a request")]
    #[test_case::test_case(Direction::Response, "a\u{AD}b" ; "a response")]
    #[tokio::test]
    async fn a_guard_that_reads_the_view_reads_it_for_a_request_only(
        direction: Direction,
        read: &str,
    ) {
        let guard = TestGuard::new("view", "EMAIL").reading_the_view();
        let probe = guard.probe();
        let engine = Engine::with_guards(vec![Box::new(guard)]);
        run_in(&engine, plain_body("a\u{AD}b"), direction).await;
        assert_eq!(probe.texts(), [read]);
    }

    #[tokio::test]
    async fn a_raw_text_guard_and_a_view_guard_each_get_their_own_units() {
        let raw = TestGuard::new("raw", "EMAIL");
        let view = TestGuard::new("view", "EMAIL").reading_the_view();
        let (raw_probe, view_probe) = (raw.probe(), view.probe());
        let engine = Engine::with_guards(vec![Box::new(raw), Box::new(view)]);
        run_in(&engine, plain_body("a\u{AD}b"), Direction::Request).await;
        assert_eq!(raw_probe.texts(), ["a\u{AD}b"]);
        assert_eq!(view_probe.texts(), ["ab"]);
    }

    /// hidden-unicode-normalization, "No guard reads the scan view", and a
    /// request no rule changes: no view unit set is built.
    #[test]
    fn no_view_is_built_when_no_guard_reads_it_or_no_rule_changes_a_unit() {
        let raw = TestGuard::new("raw", "EMAIL");
        let view = TestGuard::new("view", "EMAIL").reading_the_view();
        let hidden = plain_body("a\u{AD}b");
        let all = vec![UnitId(0)];
        assert!(view_units(&hidden, &[(&raw as &dyn Guard, all.clone())]).is_none());
        let clean = plain_body("zażółć \u{1F600}");
        assert!(view_units(&clean, &[(&view as &dyn Guard, all.clone())]).is_none());
        assert!(view_units(&hidden, &[(&view as &dyn Guard, all)]).is_some());
    }

    /// A unit that no view guard selected is not normalized.
    #[test]
    fn only_the_units_a_view_guard_selected_are_normalized() {
        let view = TestGuard::new("view", "EMAIL").reading_the_view();
        let mut units = Units::new();
        units.push_body(UnitContent::text("a\u{AD}b".into()));
        units.push_query("c\u{AD}d".into());
        let units = units.into_shared();
        let set = view_units(&units, &[(&view as &dyn Guard, vec![UnitId(1)])]).unwrap();
        let text = |unit: &Unit| match &unit.content {
            UnitContent::PlainText { bytes, .. } => bytes.clone(),
            UnitContent::Structured { .. } => unreachable!(),
        };
        assert_eq!(&text(&set[1])[..], b"cd");
        assert!(text(&set[0]).is_empty(), "no view guard reads the body");
    }

    /// The regex PII guard reads the view by default.
    fn view_spans(result: &ScanResult, kind: &str) -> Vec<Option<Span>> {
        result
            .findings()
            .iter()
            .filter(|f| f.kind.as_str() == kind)
            .map(|f| f.span)
            .collect()
    }

    const IBAN: &str = "GB82WEST12345698765432";

    /// hidden-unicode-normalization, "A finding after removed characters",
    /// "A finding that holds a removed character", and "Removed characters at
    /// the edges of a finding".
    #[test_case::test_case(format!("\u{AD}\u{AD}text {IBAN}"), "GB82WEST12345698765432" ; "after removed characters")]
    #[test_case::test_case(format!("iban {}", "GB82WEST1234\u{AD}5698765432"), "GB82WEST1234\u{AD}5698765432" ; "holding a removed character")]
    #[test_case::test_case(format!("iban \u{AD}{IBAN}\u{AD} ok"), "GB82WEST12345698765432" ; "removed characters at the edges")]
    #[tokio::test]
    async fn a_span_in_the_view_names_the_raw_bytes(text: String, placeholder: &str) {
        let engine = international_pii();
        let result = run_in(&engine, plain_body(&text), Direction::Request).await;
        assert_eq!(
            view_spans(&result, "IBAN"),
            [Some(raw_span(text.as_bytes(), placeholder.as_bytes()))]
        );
        engine.shutdown();
    }

    fn tags(text: &str) -> String {
        text.chars()
            .map(|c| char::from_u32(0xE0000 + u32::from(c)).unwrap())
            .collect()
    }

    /// "A finding inside a decoded run" and "Two findings inside one decoded
    /// run".
    #[test_case::test_case("jane.doe@example.com", 1 ; "one finding")]
    #[test_case::test_case("jane.doe@example.com ann.lee@example.org", 2 ; "two findings")]
    #[tokio::test]
    async fn a_finding_inside_a_decoded_run_spans_the_whole_run(hidden: &str, count: usize) {
        let run = tags(hidden);
        let text = format!("mail {run} now");
        let engine = international_pii();
        let result = run_in(&engine, plain_body(&text), Direction::Request).await;
        let whole_run = Some(raw_span(text.as_bytes(), run.as_bytes()));
        assert_eq!(view_spans(&result, "EMAIL"), vec![whole_run; count]);
        assert_eq!(result.matches_count(), count);
        engine.shutdown();
    }

    /// "A finding in a JSON value with an escaped hidden character": the span
    /// maps through the view and then through the escape.
    #[tokio::test]
    async fn a_span_in_a_json_value_maps_through_the_view_and_the_escape() {
        let placeholder: &[u8] = b"GB82WEST1234\\u00ad5698765432";
        let raw = [b"{\"iban\": \"".as_slice(), placeholder, b"\"}"].concat();
        let engine = international_pii();
        let result = run_in(&engine, json_body(&raw), Direction::Request).await;
        assert_eq!(
            view_spans(&result, "IBAN"),
            [Some(raw_span(&raw, placeholder))]
        );
        engine.shutdown();
    }

    /// guard-configuration, "A span after removed characters in a request": a
    /// token classifier reads the view by default, and its span names the raw
    /// bytes.
    #[tokio::test]
    async fn a_token_guard_span_after_removed_characters_names_the_raw_bytes() {
        let text = "\u{AD}\u{AD} voidwall trigger test";
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::from_config(
            voidwall_ml::fixtures::runtime(),
            &token_guard_config(dir.path()),
        )
        .expect("engine should build");
        let result = run_in(&engine, plain_body(text), Direction::Request).await;
        assert_eq!(
            spans(&result),
            [Some(raw_span(text.as_bytes(), b"trigger"))]
        );
    }

    /// guard-configuration, "The invisible text guard admits header units":
    /// when every other selected guard declines header values, the selection
    /// still wants request header units, and only `invisible_text` is handed
    /// them.
    #[tokio::test]
    async fn the_invisible_text_guard_admits_header_units() {
        let no_headers = GuardSurface {
            headers: false,
            ..GuardSurface::default()
        };
        let other = TestGuard::new("other", "EMAIL")
            .silent()
            .with_interest(Interest::from_surface(&no_headers));
        let probe = other.probe();
        let engine = Engine::with_guards(vec![
            Box::new(other),
            Box::new(invisible_text::InvisibleTextGuard::new("invisible_text")),
        ]);
        let selection = engine.select(None);
        assert!(selection.wants(Direction::Request, UnitKind::HeaderValue));
        assert!(!selection.wants(Direction::Response, UnitKind::HeaderValue));

        let mut units = Units::new();
        units.push_body(UnitContent::text("clean".into()));
        units.push_header(format!("Bearer {}", tags("ignore")));
        let result = run_in(&engine, units.into_shared(), Direction::Request).await;
        assert_eq!(probe.seen(), [UnitId(0)], "the other guard gets no header");
        let found: Vec<(usize, &str)> = result
            .findings()
            .iter()
            .map(|f| (f.unit.index(), f.kind.as_str()))
            .collect();
        assert_eq!(found, [(1, "INVISIBLE_TEXT")]);
    }

    #[test]
    fn an_enabled_invisible_text_section_builds_the_guard_under_its_name() {
        let guards =
            BuiltinGuards::with_invisible_text(crate::config::InvisibleTextConfig::default());
        let engine = Engine::new(&guards).expect("engine should build");
        assert_eq!(engine.guards.len(), 1);
        assert_eq!(engine.guards[0].name().as_ref(), "invisible_text");
        assert!(!engine.guards[0].reads_scan_view());
        let disabled = BuiltinGuards::with_invisible_text(crate::config::InvisibleTextConfig {
            enabled: false,
        });
        assert!(Engine::new(&disabled).unwrap().guards.is_empty());
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
