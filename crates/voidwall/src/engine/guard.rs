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
//! its own threads and awaits the reply.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::config::{GuardSurface, ModelGuardSurface, OnError};
use crate::error::Error;

use super::finding::Finding;
use super::unit::{Unit, UnitId, UnitKind};

/// What a guard's `detect` returns. Boxed so the trait stays object-safe: the
/// engine holds `Box<dyn Guard>`.
pub type DetectFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<Finding>, Error>> + Send + 'a>>;

/// The unit kinds a guard wants to see.
///
/// One axis only. There is deliberately no trust class and no
/// internal/external/tool axis: nothing produces either yet, and freezing a
/// taxonomy that nothing exercises is how the previous design failed. The axis
/// is added when a producer exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interest {
    kinds: Vec<UnitKind>,
}

impl Interest {
    /// Interest in the given unit kinds.
    pub fn in_kinds(kinds: impl IntoIterator<Item = UnitKind>) -> Self {
        let mut kinds: Vec<UnitKind> = kinds.into_iter().collect();
        kinds.sort_unstable();
        kinds.dedup();
        Self { kinds }
    }

    /// Interest in every unit kind.
    pub fn all() -> Self {
        Self::in_kinds(UnitKind::ALL.iter().copied())
    }

    /// Interest in nothing. A guard declaring this is never called.
    pub fn none() -> Self {
        Self { kinds: Vec::new() }
    }

    /// The unit kinds a configured scan surface admits.
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

    /// The unit kinds a model guard's scan surface admits.
    pub fn from_model_surface(surface: &ModelGuardSurface) -> Self {
        Self::from_surface(&GuardSurface {
            url_path: surface.url_path,
            query_params: surface.query_params,
            body: surface.body,
            headers: surface.headers,
        })
    }

    /// The kinds this interest covers.
    pub fn kinds(&self) -> &[UnitKind] {
        &self.kinds
    }

    /// Whether this interest covers `kind`.
    pub fn wants(&self, kind: UnitKind) -> bool {
        self.kinds.contains(&kind)
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

    #[test]
    fn interest_covers_only_the_declared_kinds() {
        let interest = Interest::in_kinds([UnitKind::Body, UnitKind::UrlPath]);
        assert!(interest.wants(UnitKind::Body));
        assert!(interest.wants(UnitKind::UrlPath));
        assert!(!interest.wants(UnitKind::HeaderValue));
        assert!(!interest.wants(UnitKind::QueryString));
    }

    #[test]
    fn interest_all_covers_every_kind() {
        let interest = Interest::all();
        assert!(UnitKind::ALL.iter().all(|k| interest.wants(*k)));
    }

    #[test]
    fn interest_none_covers_nothing() {
        let interest = Interest::none();
        assert!(!UnitKind::ALL.iter().any(|k| interest.wants(*k)));
    }

    #[test]
    fn a_default_surface_admits_the_path_the_query_the_body_and_headers() {
        let interest = Interest::from_surface(&GuardSurface::default());
        assert!(interest.wants(UnitKind::Body));
        assert!(interest.wants(UnitKind::UrlPath));
        assert!(interest.wants(UnitKind::QueryString));
        assert!(interest.wants(UnitKind::HeaderValue));
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
        assert!(!interest.wants(UnitKind::HeaderValue));
        assert!(interest.wants(UnitKind::Body));
    }

    #[test]
    fn a_surface_with_the_body_off_does_not_admit_the_body() {
        let surface = GuardSurface {
            body: false,
            ..GuardSurface::default()
        };
        let interest = Interest::from_surface(&surface);
        assert!(!interest.wants(UnitKind::Body));
        assert!(interest.wants(UnitKind::UrlPath));
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
