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

use crate::config::OnError;
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
    /// A fixed name for this guard type. It reaches metric labels and finding
    /// records, so it is never operator-supplied — that would make label
    /// cardinality unbounded.
    fn name(&self) -> &'static str;

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
    fn duplicate_kinds_collapse() {
        let interest = Interest::in_kinds([UnitKind::Body, UnitKind::Body]);
        assert_eq!(interest, Interest::in_kinds([UnitKind::Body]));
    }
}
