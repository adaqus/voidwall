//! The unit: one piece of a message that a guard can look at.
//!
//! A handler decodes an HTTP message into units — one for the body, one for
//! the URL path, one for the query string, one per scanned header value — and
//! hands the whole set to the [`Engine`](super::Engine). A unit is identified
//! by its index in that set, so a [`Finding`](super::Finding) names its origin
//! with a [`UnitId`] and a span means an offset inside one known unit rather
//! than somewhere in the message.

use std::fmt;
use std::sync::Arc;

use bytes::Bytes;

use crate::structured::OwnedContextFragment;

/// Identifies one unit inside a message's unit set.
///
/// The value is the unit's index in that set, so lookup is O(1) and the
/// canonical finding order sorts by the order the handler built the units in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnitId(pub usize);

impl UnitId {
    /// The index this id points at.
    pub fn index(self) -> usize {
        self.0
    }
}

/// What part of a message a unit holds.
///
/// This is the only axis a guard declares interest over — see
/// [`Interest`](super::Interest). A header value carries its header name in
/// [`Unit::label`] rather than in the kind, so the kind stays a small fieldless
/// enum that an interest set can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnitKind {
    /// The request or response body.
    Body,
    /// The URL path.
    UrlPath,
    /// The URL query string, without the leading `?`.
    QueryString,
    /// One header value. The header name is in [`Unit::label`].
    HeaderValue,
}

impl UnitKind {
    /// Every unit kind, for building an interest set that wants all of them.
    pub const ALL: &'static [UnitKind] = &[
        UnitKind::Body,
        UnitKind::UrlPath,
        UnitKind::QueryString,
        UnitKind::HeaderValue,
    ];
}

/// The content of a unit.
///
/// `PlainText` is the flat path: the bytes are scanned as a single UTF-8
/// string. `Structured` carries pre-parsed context/value/offset fragments —
/// JSON key paths and string values, CSV column headers and cells — so
/// detection can use keyword context. The offsets are document-absolute, which
/// is what lets overlap resolution compare spans from two fragments; the
/// document itself is not kept, so the body buffer is released when parsing
/// ends.
///
/// `Debug` is written by hand, not derived: see the impl below.
#[derive(Clone)]
pub enum UnitContent {
    /// Flat text, scanned as one UTF-8 string.
    PlainText(Bytes),
    /// Pre-parsed fragments carrying document-absolute offsets.
    Structured {
        fragments: Vec<OwnedContextFragment>,
    },
}

/// Print the shape and the size, never the content.
///
/// A unit holds the raw scanned bytes — a body, a URL path, a query string, or
/// a header value — and a structured unit's fragments hold the parsed values on
/// top of that. A derived `Debug` would therefore put matched PII into any log
/// line, panic message, or assertion that formats a unit, a unit set, or a
/// `GuardInput`. Detection safety says never log a detected value, so the
/// content has no way out through this impl.
impl fmt::Debug for UnitContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnitContent::PlainText(bytes) => f
                .debug_struct("PlainText")
                .field("bytes", &bytes.len())
                .finish(),
            UnitContent::Structured { fragments } => f
                .debug_struct("Structured")
                .field("fragments", &fragments.len())
                .finish(),
        }
    }
}

impl UnitContent {
    /// Build plain-text content from an owned string.
    pub fn text(value: String) -> Self {
        UnitContent::PlainText(Bytes::from(value))
    }
}

/// One piece of a message that guards can look at.
#[derive(Debug, Clone)]
pub struct Unit {
    /// This unit's index in the message's unit set.
    pub id: UnitId,
    /// What part of the message this unit holds.
    pub kind: UnitKind,
    /// The content to scan.
    pub content: UnitContent,
}

/// Builds a message's unit set, assigning each unit its id.
///
/// The build order fixes the ids, and the canonical finding order sorts by
/// unit id, so two scans of the same message list their findings identically.
#[derive(Debug, Default)]
pub struct Units {
    units: Vec<Unit>,
}

impl Units {
    /// A new, empty unit set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a unit and return the id it was given.
    pub fn push(&mut self, kind: UnitKind, content: UnitContent) -> UnitId {
        let id = UnitId(self.units.len());
        self.units.push(Unit { id, kind, content });
        id
    }

    /// Append a body unit.
    pub fn push_body(&mut self, content: UnitContent) -> UnitId {
        self.push(UnitKind::Body, content)
    }

    /// Append a URL path unit.
    pub fn push_path(&mut self, path: String) -> UnitId {
        self.push(UnitKind::UrlPath, UnitContent::text(path))
    }

    /// Append a query string unit.
    pub fn push_query(&mut self, query: String) -> UnitId {
        self.push(UnitKind::QueryString, UnitContent::text(query))
    }

    /// Append one header value unit.
    pub fn push_header(&mut self, value: String) -> UnitId {
        self.push(UnitKind::HeaderValue, UnitContent::text(value))
    }

    /// True when nothing was pushed.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Freeze the set for the engine. The guards share this slice; the regex
    /// guard clones the `Arc` to hand the units to a scanner thread.
    pub fn into_shared(self) -> Arc<[Unit]> {
        self.units.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_are_numbered_in_push_order() {
        let mut units = Units::new();
        let body = units.push_body(UnitContent::PlainText(Bytes::from_static(b"body")));
        let path = units.push_path("/a".into());
        let header = units.push_header("Bearer x".into());

        assert_eq!((body, path, header), (UnitId(0), UnitId(1), UnitId(2)));
        let shared = units.into_shared();
        assert_eq!(shared[0].kind, UnitKind::Body);
        assert_eq!(shared[1].kind, UnitKind::UrlPath);
        assert_eq!(shared[2].kind, UnitKind::HeaderValue);
    }

    #[test]
    fn debug_never_prints_the_content() {
        // No PII needed: the point is that the bytes do not reach the output.
        const CONTENT: &str = "SCANNED-CONTENT-MUST-NOT-APPEAR";

        let plain = UnitContent::text(CONTENT.into());
        let rendered = format!("{plain:?}");
        assert!(!rendered.contains("SCANNED-CONTENT"), "got: {rendered}");
        assert_eq!(
            rendered,
            format!("PlainText {{ bytes: {} }}", CONTENT.len())
        );

        let structured = UnitContent::Structured {
            fragments: vec![OwnedContextFragment {
                context: "k".into(),
                value: CONTENT.into(),
                offset: 6,
            }],
        };
        assert!(
            !format!("{structured:?}").contains("SCANNED-CONTENT"),
            "got: {structured:?}"
        );

        // A whole unit, and a unit set, are the shapes a log line would reach
        // for. Neither may carry the content out.
        let mut units = Units::new();
        units.push_header(CONTENT.into());
        units.push_body(plain);
        let units = units.into_shared();
        assert!(!format!("{:?}", units[0]).contains("SCANNED-CONTENT"));
        assert!(!format!("{units:?}").contains("SCANNED-CONTENT"));
        // The kind stays legible: it names a position, not a value.
        assert!(format!("{:?}", units[0]).contains("HeaderValue"));
    }

    #[test]
    fn empty_unit_set_is_empty() {
        assert!(Units::new().is_empty());
    }
}
