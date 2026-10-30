//! The guard contract.
//!
//! A guard is one detection concern. It looks at the units the engine selected
//! for it and returns findings — it does not block the message, change it,
//! or write a metric. The trait is defined here, in `voidwall`, because
//! `voidwall-pii` and the detection crates after it cannot depend on the
//! binary crate; each guard adapts one such crate to this contract.
//!
//! `detect` is `async` but does almost no work of its own: a CPU-bound
//! detector must not run on the tokio runtime, so a guard hands the units to
//! its own threads and awaits the reply. A `detect` that is a single linear
//! literal scan of its units may run inline instead.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::Deserialize;
use utoipa::ToSchema;

use crate::config::{GuardSurface, ModelGuardSurface, OnError};
use crate::error::Error;

use super::finding::Finding;
use super::unit::{Unit, UnitId, UnitKind};

/// What a guard's `detect` returns. Boxed so the trait stays object-safe: the
/// engine holds `Box<dyn Guard>`.
pub type DetectFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<Finding>, Error>> + Send + 'a>>;

/// Which way a message travels: the request to the upstream, or the
/// response from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Request,
    Response,
}

impl Direction {
    /// Both directions, for an interest that inspects either.
    pub const ALL: &'static [Direction] = &[Direction::Request, Direction::Response];

    /// The `direction` metric label.
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Request => "request",
            Direction::Response => "response",
        }
    }
}

/// The units a guard wants to see: the directions it inspects, and the unit
/// kinds it inspects in them.
///
/// Two axes only. There is deliberately no trust class and no
/// internal/external/tool axis: nothing produces either yet, and freezing a
/// taxonomy that nothing exercises is how the previous design failed. An axis
/// is added when a producer exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interest {
    directions: Vec<Direction>,
    kinds: Vec<UnitKind>,
}

impl Interest {
    /// Interest in the given unit kinds, in both directions.
    pub fn in_kinds(kinds: impl IntoIterator<Item = UnitKind>) -> Self {
        let mut kinds: Vec<UnitKind> = kinds.into_iter().collect();
        kinds.sort_unstable();
        kinds.dedup();
        Self {
            directions: Direction::ALL.to_vec(),
            kinds,
        }
    }

    /// Narrow this interest to the given directions.
    pub fn in_directions(mut self, directions: impl IntoIterator<Item = Direction>) -> Self {
        let mut directions: Vec<Direction> = directions.into_iter().collect();
        directions.sort_unstable();
        directions.dedup();
        self.directions = directions;
        self
    }

    /// Interest in every unit kind, in both directions.
    pub fn all() -> Self {
        Self::in_kinds(UnitKind::ALL.iter().copied())
    }

    /// Interest in nothing. A guard declaring this is never called.
    pub fn none() -> Self {
        Self::in_kinds([])
    }

    /// The unit kinds a configured scan surface admits, in both directions.
    ///
    /// `headers` is the guard's half of a two-part decision: the route decides
    /// which header values become units at all, and this decides whether the
    /// guard is handed the ones that did. A route that names no header builds
    /// no header unit either way.
    pub fn from_surface(surface: &GuardSurface) -> Self {
        let mut kinds = Vec::new();
        if surface.headers {
            kinds.push(UnitKind::HeaderValue);
        }
        if surface.body {
            kinds.push(UnitKind::Body);
        }
        if surface.url_path {
            kinds.push(UnitKind::UrlPath);
        }
        if surface.query_params {
            kinds.push(UnitKind::QueryString);
        }
        Self::in_kinds(kinds)
    }

    /// The unit kinds a model guard's scan surface admits, in both directions.
    pub fn from_model_surface(surface: &ModelGuardSurface) -> Self {
        Self::from_surface(&GuardSurface {
            url_path: surface.url_path,
            query_params: surface.query_params,
            body: surface.body,
            headers: surface.headers,
        })
    }

    /// Whether this interest covers units of `kind` in a message travelling
    /// in `direction`. It must hold both.
    pub fn wants(&self, direction: Direction, kind: UnitKind) -> bool {
        self.directions.contains(&direction) && self.kinds.contains(&kind)
    }
}

/// What the engine hands a guard for one message.
pub struct GuardInput<'a> {
    /// Every unit of the message. Shared, so a guard that needs owned data can
    /// clone the `Arc` rather than the content.
    pub units: &'a Arc<[Unit]>,
    /// The units this guard declared interest in. A guard reads these and
    /// leaves the rest alone.
    pub selected: &'a [UnitId],
    /// The configured failure policy, needed only to word the error when a
    /// guard's own worker drops the reply channel. The policy itself is
    /// applied by the handler, never inside `detect`.
    pub on_error: OnError,
}

/// One detection concern.
pub trait Guard: Send + Sync {
    /// This guard's name, the one configuration gave it. It reaches finding
    /// records and can reach a metric label, so the set of names is bounded by
    /// startup configuration and never by request content.
    fn name(&self) -> &Arc<str>;

    /// The unit kinds this guard wants. The engine, not the guard, applies it.
    fn interest(&self) -> &Interest;

    /// Look at the selected units and report what was found.
    fn detect<'a>(&'a self, input: GuardInput<'a>) -> DetectFuture<'a>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    /// Whether an interest built for both directions covers `kind`. Both
    /// directions must give the same answer.
    fn wants(interest: &Interest, kind: UnitKind) -> bool {
        let request = interest.wants(Direction::Request, kind);
        assert_eq!(request, interest.wants(Direction::Response, kind));
        request
    }

    #[test_case(Direction::Response, UnitKind::Body, true ; "held direction and held kind")]
    #[test_case(Direction::Request, UnitKind::Body, false ; "other direction")]
    #[test_case(Direction::Response, UnitKind::HeaderValue, false ; "other kind")]
    #[test_case(Direction::Request, UnitKind::UrlPath, false ; "neither")]
    fn an_interest_wants_a_pair_only_when_it_holds_both(
        direction: Direction,
        kind: UnitKind,
        expected: bool,
    ) {
        let interest = Interest::in_kinds([UnitKind::Body]).in_directions([Direction::Response]);
        assert_eq!(interest.wants(direction, kind), expected);
    }

    /// The `pii` guard and model guards build their interest from a surface,
    /// so they keep both directions.
    #[test]
    fn a_surface_interest_covers_both_directions() {
        let interest = Interest::from_surface(&GuardSurface::default());
        for direction in Direction::ALL {
            assert!(interest.wants(*direction, UnitKind::Body));
        }
    }

    #[test]
    fn direction_labels_match_the_metric_label() {
        assert_eq!(Direction::Request.as_str(), "request");
        assert_eq!(Direction::Response.as_str(), "response");
    }

    #[test]
    fn interest_covers_only_the_declared_kinds() {
        let interest = Interest::in_kinds([UnitKind::Body, UnitKind::UrlPath]);
        assert!(wants(&interest, UnitKind::Body));
        assert!(wants(&interest, UnitKind::UrlPath));
        assert!(!wants(&interest, UnitKind::HeaderValue));
        assert!(!wants(&interest, UnitKind::QueryString));
    }

    #[test]
    fn interest_all_covers_every_kind() {
        let interest = Interest::all();
        assert!(UnitKind::ALL.iter().all(|k| wants(&interest, *k)));
    }

    #[test]
    fn interest_none_covers_nothing() {
        let interest = Interest::none();
        assert!(!UnitKind::ALL.iter().any(|k| wants(&interest, *k)));
    }

    #[test]
    fn a_default_surface_admits_the_path_the_query_the_body_and_headers() {
        let interest = Interest::from_surface(&GuardSurface::default());
        assert!(wants(&interest, UnitKind::Body));
        assert!(wants(&interest, UnitKind::UrlPath));
        assert!(wants(&interest, UnitKind::QueryString));
        assert!(wants(&interest, UnitKind::HeaderValue));
    }

    /// The route decides which header values become units; the surface decides
    /// whether this guard is handed them. A built-in guard defaults to yes, so
    /// no existing config changes meaning.
    #[test]
    fn a_surface_with_headers_off_does_not_admit_header_values() {
        let surface = GuardSurface {
            headers: false,
            ..GuardSurface::default()
        };
        let interest = Interest::from_surface(&surface);
        assert!(!wants(&interest, UnitKind::HeaderValue));
        assert!(wants(&interest, UnitKind::Body));
    }

    #[test]
    fn a_surface_with_the_body_off_does_not_admit_the_body() {
        let surface = GuardSurface {
            body: false,
            ..GuardSurface::default()
        };
        let interest = Interest::from_surface(&surface);
        assert!(!wants(&interest, UnitKind::Body));
        assert!(wants(&interest, UnitKind::UrlPath));
    }

    /// Such a surface fails validation, so the engine never sees one. The
    /// mapping is still total, and it maps to the interest that is never called.
    #[test]
    fn a_surface_with_every_target_off_admits_nothing() {
        let surface = GuardSurface {
            url_path: false,
            query_params: false,
            body: false,
            headers: false,
        };
        assert_eq!(Interest::from_surface(&surface), Interest::none());
    }

    #[test]
    fn duplicate_kinds_collapse() {
        let interest = Interest::in_kinds([UnitKind::Body, UnitKind::Body]);
        assert_eq!(interest, Interest::in_kinds([UnitKind::Body]));
    }
}
