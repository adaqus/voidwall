//! Structured body parsing for content-aware PII scanning.
//!
//! Each parser produces a `Vec<OwnedContextFragment>` — context/value/offset
//! triples that the scanner can pair with `pii::ContextFragment` for
//! `Scanner::mark_piis_structured`. The byte offsets are document-absolute,
//! so matches can be redacted in-place against the original raw body while
//! preserving the source format's structure (valid JSON, intact CSV
//! delimiters, etc.).
//!
//! Submodules:
//! - [`json`] — `application/json` flattener
//! - (future) `csv` — `text/csv` and `text/tab-separated-values` parser
//! - (future) per-format dispatch keyed off Content-Type

pub mod json;

/// One context/value/offset triple emitted by a structured-body parser. Owned
/// so the raw body buffer can be released before the scanner runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedContextFragment {
    pub context: String,
    pub value: String,
    pub offset: usize,
}
