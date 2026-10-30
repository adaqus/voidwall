//! The hidden context guard.
//!
//! The operator lists markers: text that must never leave in a response, such
//! as a canary planted in a system prompt or an internal codename. The guard
//! reports a response body that holds one, with the fixed kind
//! `HIDDEN_CONTEXT`.
//!
//! Its interest is fixed in code to the response body. A request that holds a
//! marker is not this guard's concern: the system message of a request is
//! where the operator put the marker in the first place.
//!
//! `detect` runs inline, with no worker thread. It is one linear-time literal
//! scan per unit, bounded by `max_body_size`, which costs less than the
//! channel round trip a worker would add.

use std::sync::Arc;

use crate::config::{HiddenContextConfig, markers_regex};
use crate::error::Error;

use super::finding::{Finding, Span};
use super::guard::{DetectFuture, Direction, Guard, GuardInput, Interest};
use super::unit::{UnitContent, UnitKind};

/// The one kind this guard reports, for every marker.
pub(crate) const HIDDEN_CONTEXT_KIND: &str = "HIDDEN_CONTEXT";

/// The guard that reports a response body holding a marker.
pub(crate) struct HiddenContextGuard {
    name: Arc<str>,
    interest: Interest,
    /// Every marker, as one case-insensitive alternation of literals. The
    /// markers are held nowhere else. A bytes regex, so a body that is not
    /// valid UTF-8 is still searched.
    markers: regex::bytes::Regex,
}

impl HiddenContextGuard {
    /// Build the guard from its section. Validation has already rejected an
    /// empty list and an empty marker.
    pub(crate) fn new(name: &str, config: &HiddenContextConfig) -> Result<Self, Error> {
        // Validation compiled the same regex. The error is left out: its text
        // can quote the pattern.
        let markers = markers_regex(&config.markers).map_err(|_| {
            Error::Config(format!(
                "builtin_guards.{name}: the markers cannot be compiled"
            ))
        })?;
        Ok(Self {
            name: Arc::from(name),
            interest: Interest::in_kinds([UnitKind::Body]).in_directions([Direction::Response]),
            markers,
        })
    }

    /// The leftmost marker match in `content`. A structured unit is searched
    /// value by value, so a marker split across two values does not match.
    fn find(&self, content: &UnitContent) -> Option<Span> {
        let at = |text: &[u8], offset: usize| {
            self.markers
                .find(text)
                .map(|m| Span::new(offset + m.start(), offset + m.end()))
        };
        match content {
            UnitContent::PlainText(bytes) => at(bytes, 0),
            UnitContent::Structured { fragments } => fragments
                .iter()
                .find_map(|f| at(f.value.as_bytes(), f.offset)),
        }
    }
}

impl Guard for HiddenContextGuard {
    fn name(&self) -> &Arc<str> {
        &self.name
    }

    fn interest(&self) -> &Interest {
        &self.interest
    }

    /// At most one finding per unit, at the leftmost match: the kind is the
    /// same for every marker, so a second match would add nothing.
    fn detect<'a>(&'a self, input: GuardInput<'a>) -> DetectFuture<'a> {
        let findings = input
            .selected
            .iter()
            .filter_map(|id| {
                let unit = input.units.get(id.index())?;
                let span = self.find(&unit.content)?;
                Some(Finding::spanned(
                    *id,
                    HIDDEN_CONTEXT_KIND,
                    Arc::clone(&self.name),
                    span,
                ))
            })
            .collect();
        Box::pin(std::future::ready(Ok(findings)))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OnError;
    use crate::engine::unit::{UnitId, Units};
    use crate::structured::OwnedContextFragment;
    use bytes::Bytes;
    use test_case::test_case;

    fn guard(markers: &[&str]) -> HiddenContextGuard {
        let config = HiddenContextConfig {
            enabled: true,
            markers: markers.iter().map(|m| m.to_string()).collect(),
        };
        HiddenContextGuard::new("hidden_context", &config).expect("guard should build")
    }

    async fn detect(guard: &HiddenContextGuard, units: Units) -> Vec<Finding> {
        let units = units.into_shared();
        let selected: Vec<UnitId> = units.iter().map(|u| u.id).collect();
        guard
            .detect(GuardInput {
                units: &units,
                selected: &selected,
                on_error: OnError::FailClose,
            })
            .await
            .expect("detect never fails")
    }

    fn body(text: &str) -> Units {
        let mut units = Units::new();
        units.push_body(UnitContent::PlainText(Bytes::copy_from_slice(
            text.as_bytes(),
        )));
        units
    }

    fn spans(findings: &[Finding]) -> Vec<Option<Span>> {
        findings.iter().map(|f| f.span).collect()
    }

    #[test]
    fn the_guard_wants_the_response_body_only() {
        let guard = guard(&["vw-canary-0000"]);
        assert_eq!(guard.name().as_ref(), "hidden_context");
        for kind in UnitKind::ALL {
            assert!(!guard.interest().wants(Direction::Request, *kind));
            assert_eq!(
                guard.interest().wants(Direction::Response, *kind),
                *kind == UnitKind::Body,
                "{kind:?}"
            );
        }
    }

    // --- A marker matches without regard to case ---

    #[test_case("Project Bluefin", "the project BLUEFIN plan", Some(Span::new(4, 19)) ; "different ascii case")]
    #[test_case("Żubr", "ŻUBR", Some(Span::new(0, 5)) ; "different non-ascii case")]
    #[test_case("bluefin", "two bluefins", Some(Span::new(4, 11)) ; "inside a longer word")]
    #[test_case("kelvin", "\u{212A}elvin", Some(Span::new(0, 8)) ; "the kelvin sign folds to k")]
    #[test_case("a.b", "it holds a.b", Some(Span::new(9, 12)) ; "pattern characters match literally")]
    #[test_case("a.b", "it holds axb", None ; "pattern characters are not patterns")]
    #[test_case("bluefin", "nothing here", None ; "no marker")]
    #[tokio::test]
    async fn a_marker_matches_without_regard_to_case(
        marker: &str,
        text: &str,
        expected: Option<Span>,
    ) {
        let findings = detect(&guard(&[marker]), body(text)).await;
        assert_eq!(
            spans(&findings),
            expected.into_iter().map(Some).collect::<Vec<_>>()
        );
    }

    /// The unit is searched as bytes, so one invalid byte does not hide a
    /// marker.
    #[tokio::test]
    async fn a_body_that_is_not_utf8_is_still_searched() {
        let mut units = Units::new();
        units.push_body(UnitContent::PlainText(Bytes::from_static(
            b"\xff vw-canary-0000",
        )));
        let findings = detect(&guard(&["vw-canary-0000"]), units).await;
        assert_eq!(spans(&findings), vec![Some(Span::new(2, 16))]);
    }

    // --- One HIDDEN_CONTEXT finding per unit ---

    #[test_case(&["bluefin"], "bluefin, Bluefin, BLUEFIN", Span::new(0, 7) ; "one marker three times")]
    #[test_case(&["bluefin", "vw-canary-0000"], "vw-canary-0000 then bluefin", Span::new(0, 14) ; "two markers")]
    #[tokio::test]
    async fn the_guard_reports_one_finding_per_unit_at_the_leftmost_match(
        markers: &[&str],
        text: &str,
        span: Span,
    ) {
        let findings = detect(&guard(markers), body(text)).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind.as_str(), HIDDEN_CONTEXT_KIND);
        assert_eq!(&*findings[0].guard, "hidden_context");
        assert_eq!(findings[0].span, Some(span));
    }

    #[tokio::test]
    async fn each_unit_gets_its_own_finding() {
        let mut units = body("bluefin");
        units.push_body(UnitContent::text("and bluefin".into()));
        let findings = detect(&guard(&["bluefin"]), units).await;
        let units: Vec<usize> = findings.iter().map(|f| f.unit.index()).collect();
        assert_eq!(units, vec![0, 1]);
    }

    // --- Structured units are matched value by value ---

    fn structured(values: &[(&str, usize)]) -> Units {
        let mut units = Units::new();
        units.push_body(UnitContent::Structured {
            fragments: values
                .iter()
                .map(|(value, offset)| OwnedContextFragment {
                    context: "a.b".into(),
                    value: (*value).into(),
                    offset: *offset,
                })
                .collect(),
        });
        units
    }

    #[tokio::test]
    async fn a_marker_in_a_json_value_is_found_at_its_document_offset() {
        let units = structured(&[("clean", 8), ("the bluefin plan", 30)]);
        let findings = detect(&guard(&["bluefin"]), units).await;
        assert_eq!(spans(&findings), vec![Some(Span::new(34, 41))]);
    }

    #[tokio::test]
    async fn a_marker_split_across_two_json_values_does_not_match() {
        let units = structured(&[("blue", 8), ("fin", 20)]);
        assert!(detect(&guard(&["bluefin"]), units).await.is_empty());
    }

    /// The context is a key path, not a value the model wrote.
    #[tokio::test]
    async fn a_marker_in_the_key_path_does_not_match() {
        let units = structured(&[("clean", 8)]);
        assert!(detect(&guard(&["a.b"]), units).await.is_empty());
    }
}
