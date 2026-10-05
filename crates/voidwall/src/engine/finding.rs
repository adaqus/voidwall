//! What a guard returns, and what the engine returns to a handler.
//!
//! A [`Finding`] is one detection: the unit it came from, the kind that was
//! found, the guard that reported it, and — when the guard has them — a byte
//! span and a confidence. A guard returns findings and nothing else: it does
//! not block the message, change it, or write a metric.
//!
//! [`ScanResult`] wraps the merged findings. `detected`, `matches_count`, `kinds`,
//! and `guards` are derived from `findings` rather than stored beside them, so they
//! cannot drift from the set they describe.

use std::sync::Arc;

use super::unit::UnitId;
use crate::error::Error;

/// A byte range inside a unit's source bytes.
///
/// Offsets are document-absolute for a structured unit, so two spans from two
/// different fragments are directly comparable — which is what overlap
/// resolution and the resolved match count are defined over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

/// The name of what a guard found — `EMAIL`, `US_SSN`, or an operator-defined
/// custom label.
///
/// Cheap to clone, and ordered by name so the kind list of a scan result sorts
/// deterministically.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FindingKind(Arc<str>);

impl FindingKind {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for FindingKind {
    fn from(value: &str) -> Self {
        Self(Arc::from(value))
    }
}

/// One detection reported by one guard.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The unit this was found in.
    pub unit: UnitId,
    /// What was found.
    pub kind: FindingKind,
    /// The guard that reported it, by its configured name. The set of names
    /// is fixed when configuration is loaded, so a name that reaches a metric
    /// label is bounded by the deployment and never by request content.
    pub guard: Arc<str>,
    /// The bytes matched, when the guard localises its finding. A guard that
    /// classifies a whole unit reports `None`.
    pub span: Option<Span>,
    /// How sure the guard is, when it has a number to give.
    pub confidence: Option<f32>,
}

impl Finding {
    /// A finding localised to a byte span.
    pub fn spanned(
        unit: UnitId,
        kind: impl Into<FindingKind>,
        guard: impl Into<Arc<str>>,
        span: Span,
    ) -> Self {
        Self {
            unit,
            kind: kind.into(),
            guard: guard.into(),
            span: Some(span),
            confidence: None,
        }
    }

    /// A finding about a whole unit, carrying a confidence instead of a span.
    pub fn whole_unit(
        unit: UnitId,
        kind: impl Into<FindingKind>,
        guard: impl Into<Arc<str>>,
        confidence: f32,
    ) -> Self {
        Self {
            unit,
            kind: kind.into(),
            guard: guard.into(),
            span: None,
            confidence: Some(confidence),
        }
    }
}

/// The merged findings of one scan.
///
/// The findings are held in the engine's canonical order. Everything a caller
/// reports is derived from them.
///
/// A guard error does not end the scan, so a result can hold the findings of
/// the guards that succeeded and the first guard error together. The caller
/// decides which wins.
#[derive(Debug, Default)]
pub struct ScanResult {
    findings: Vec<Finding>,
    error: Option<Error>,
}

impl ScanResult {
    /// Wrap findings that are already in canonical order.
    pub fn new(findings: Vec<Finding>) -> Self {
        Self {
            findings,
            error: None,
        }
    }

    /// Wrap findings together with the guard error that came with them.
    pub fn with_error(findings: Vec<Finding>, error: Option<Error>) -> Self {
        Self { findings, error }
    }

    /// Take the guard error out of the result, if a guard failed.
    pub fn take_error(&mut self) -> Option<Error> {
        self.error.take()
    }

    /// The findings, in canonical order.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Whether anything was found.
    pub fn detected(&self) -> bool {
        !self.findings.is_empty()
    }

    /// How many findings there are. Overlap resolution has already run, so
    /// this is the resolved match count.
    pub fn matches_count(&self) -> usize {
        self.findings.len()
    }

    /// The kinds found, sorted by name and holding each kind once however many
    /// findings — and however many guards — reported it.
    pub fn kinds(&self) -> Vec<String> {
        let mut kinds: Vec<&str> = self.findings.iter().map(|f| f.kind.as_str()).collect();
        kinds.sort_unstable();
        kinds.dedup();
        kinds.into_iter().map(str::to_owned).collect()
    }

    /// The guards that reported findings, sorted by name and holding each guard
    /// once however many findings it reported.
    pub fn guards(&self) -> Vec<Arc<str>> {
        let mut guards: Vec<Arc<str>> =
            self.findings.iter().map(|f| Arc::clone(&f.guard)).collect();
        guards.sort_unstable();
        guards.dedup();
        guards
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUARD: &str = "test_guard";

    fn kinds_of(labels: &[&str]) -> ScanResult {
        ScanResult::new(
            labels
                .iter()
                .enumerate()
                .map(|(i, label)| {
                    Finding::spanned(UnitId(0), *label, GUARD, Span::new(i * 10, i * 10 + 4))
                })
                .collect(),
        )
    }

    #[test]
    fn a_spanned_finding_carries_its_span_and_no_confidence() {
        let finding = Finding::spanned(UnitId(2), "EMAIL", GUARD, Span::new(4, 9));
        assert_eq!(finding.unit, UnitId(2));
        assert_eq!(finding.kind.as_str(), "EMAIL");
        assert_eq!(&*finding.guard, GUARD);
        assert_eq!(finding.span, Some(Span::new(4, 9)));
        assert!(finding.confidence.is_none());
    }

    #[test]
    fn a_whole_unit_finding_carries_a_confidence_and_no_span() {
        let finding = Finding::whole_unit(UnitId(0), "PROMPT_INJECTION", GUARD, 0.75);
        assert!(finding.span.is_none());
        assert_eq!(finding.confidence, Some(0.75));
    }

    #[test]
    fn an_empty_result_detects_nothing() {
        let result = ScanResult::default();
        assert!(!result.detected());
        assert_eq!(result.matches_count(), 0);
        assert!(result.kinds().is_empty());
    }

    #[test]
    fn matches_count_is_the_finding_count() {
        assert_eq!(kinds_of(&["EMAIL", "EMAIL", "US_SSN"]).matches_count(), 3);
    }

    #[test]
    fn kinds_holds_each_kind_once() {
        let result = kinds_of(&["EMAIL", "EMAIL", "EMAIL", "EMAIL"]);
        assert_eq!(result.kinds(), vec!["EMAIL".to_string()]);
    }

    #[test]
    fn kinds_is_sorted_and_stable_across_runs() {
        let result = kinds_of(&["US_SSN", "EMAIL", "IBAN_CODE"]);
        let expected = vec![
            "EMAIL".to_string(),
            "IBAN_CODE".to_string(),
            "US_SSN".to_string(),
        ];
        assert_eq!(result.kinds(), expected);
        assert_eq!(result.kinds(), expected);
    }

    /// The guard name comes from configuration, so it is owned rather than a
    /// fixed string the build defines.
    #[test]
    fn a_finding_names_the_guard_that_configuration_named() {
        let configured: Arc<str> = Arc::from("regex_pii");
        let finding =
            Finding::spanned(UnitId(0), "EMAIL", Arc::clone(&configured), Span::new(0, 4));
        assert_eq!(finding.guard, configured);
    }

    #[test]
    fn kinds_holds_one_entry_when_two_guards_report_it() {
        let result = ScanResult::new(vec![
            Finding::spanned(UnitId(0), "EMAIL", "guard_a", Span::new(0, 5)),
            Finding::spanned(UnitId(0), "EMAIL", "guard_b", Span::new(0, 5)),
        ]);
        assert_eq!(result.kinds(), vec!["EMAIL".to_string()]);
        assert_eq!(result.matches_count(), 2);
    }

    #[test]
    fn guards_holds_one_entry_for_many_findings_of_one_guard() {
        let result = kinds_of(&["EMAIL", "EMAIL", "US_SSN", "IBAN_CODE"]);
        assert_eq!(result.guards(), vec![Arc::<str>::from(GUARD)]);
    }

    #[test]
    fn guards_is_sorted_and_holds_each_guard_once() {
        let result = ScanResult::new(vec![
            Finding::spanned(UnitId(0), "EMAIL", "guard_b", Span::new(0, 5)),
            Finding::spanned(UnitId(0), "EMAIL", "guard_a", Span::new(0, 5)),
            Finding::spanned(UnitId(1), "US_SSN", "guard_b", Span::new(0, 5)),
        ]);
        assert_eq!(
            result.guards(),
            vec![Arc::<str>::from("guard_a"), Arc::<str>::from("guard_b")]
        );
    }

    #[test]
    fn guards_is_empty_without_findings() {
        assert!(ScanResult::default().guards().is_empty());
    }
}
