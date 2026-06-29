//! Dictionary-based PII detection via FST gazetteer membership.
//!
//! See DESIGN.md § "Dictionary-Based Detection (`DictionaryDetector`)" and
//! `docs/ner-vs-regex-latency-research.md`. A name form is looked up in an FST
//! whose value carries the flag bitmask below. The detector itself is added in
//! a later task; this module currently defines the shared flag contract.

/// Flag bitmask stored as the `fst::Map` value for each name form.
///
/// **Single source of truth** — the offline build tool
/// (`tools/build_names_fst.rs`) imports these exact constants, so the artifact
/// and the detector can never drift. A form may set several bits (OR-ed).
pub mod flags {
    /// The form is used as a given (first) name.
    pub const IS_GIVEN: u64 = 1 << 0;
    /// The form is used as a surname (family name).
    pub const IS_SURNAME: u64 = 1 << 1;
    /// The form is also an ordinary English word (`will`, `rose`, `brown`) —
    /// auto-derived from a word-frequency list. A bare hit on such a form is
    /// suppressed unless promoted by evidence (caps / adjacent name / title).
    pub const ALSO_COMMON_WORD: u64 = 1 << 2;
}
