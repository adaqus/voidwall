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

use crate::PiiError;
use fst::Map;

/// The committed names gazetteer, embedded at compile time.
///
/// `include_bytes!` (rather than a runtime mmap) is deliberate: it yields a
/// single `&'static [u8]` baked into the binary, shared read-only across every
/// scanner thread with **no per-thread cost and no runtime file path** to
/// resolve. At ~1.2 MB the artifact is small enough that embedding it is
/// cheaper and simpler than mmap; revisit only if it grows to many MB.
const NAMES_FST_BYTES: &[u8] = include_bytes!("../data/names_en.fst");

/// Read-only name gazetteer backed by an `fst::Map` over the embedded artifact.
///
/// The map borrows `&'static` bytes, so the wrapper is `Send + Sync` and cheap
/// to clone-by-reload — no `Arc`/mmap needed (see `NAMES_FST_BYTES`).
pub struct Gazetteer {
    map: Map<&'static [u8]>,
}

impl Gazetteer {
    /// Load the embedded gazetteer. A corrupt/unparseable artifact returns
    /// [`PiiError::GazetteerLoad`] so it surfaces at scanner build time (and is
    /// caught by `--validate`), never as a runtime panic.
    pub fn load() -> Result<Self, PiiError> {
        let map = Map::new(NAMES_FST_BYTES).map_err(|e| PiiError::GazetteerLoad(e.to_string()))?;
        Ok(Self { map })
    }

    /// Number of name forms in the gazetteer.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the gazetteer holds no entries.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Look up a canonical (lowercased + NFC) key; returns its flag bitmask if
    /// present. See [`flags`] for the bit meanings.
    pub fn get(&self, key: &str) -> Option<u64> {
        self.map.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::flags::*;
    use super::*;

    #[test]
    fn loads_and_resolves_known_name() {
        let g = Gazetteer::load().expect("embedded gazetteer must load");
        assert_ne!(g.len(), 0, "gazetteer should not be empty");
        assert!(!g.is_empty());

        // `smith` is the most common US surname — must resolve as a surname.
        let flags = g.get("smith").expect("`smith` should be present");
        assert!(flags & IS_SURNAME != 0, "`smith` should have IS_SURNAME set");

        // A clearly absent token resolves to nothing.
        assert!(g.get("asdfghjkl").is_none());
    }
}
