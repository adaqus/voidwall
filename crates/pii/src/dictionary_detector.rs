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
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

// NOTE: the tokenization/windowing helpers below are consumed by the
// `Detector` impl added in task 20.5 (and exercised by this module's tests).
// The `allow(dead_code)` attributes are removed once that impl wires them in.

/// Longest token window (in tokens) we look up — covers names like
/// `de la cruz` / `van der berg`.
#[allow(dead_code)]
const MAX_WINDOW: usize = 3;

/// Canonical key normalization: lowercase (Unicode-correct) → NFC.
///
/// **Single source of truth** shared with the offline build tool
/// (`tools/build_names_fst.rs`), so a stored key and a query key for the same
/// surface are byte-identical — otherwise `fst` lookups silently miss. The
/// `trim` is a no-op on word tokens but guards raw fields the build tool reads.
pub fn normalize(s: &str) -> String {
    s.trim().to_lowercase().nfc().collect()
}

/// A word token with its byte span `[start, end)` into the source text.
#[allow(dead_code)]
struct Token {
    start: usize,
    end: usize,
}

/// Split `text` into Unicode word tokens (UAX#29), each with byte offsets.
///
/// Skips whitespace and punctuation, and yields valid UTF-8 boundaries. Note
/// punctuation *inside* a token also splits it: `Jean-Pierre` becomes two
/// tokens (`Jean`, `Pierre`) — the hyphen is a word boundary.
#[allow(dead_code)]
fn tokenize(text: &str) -> Vec<Token> {
    text.unicode_word_indices()
        .map(|(start, word)| Token {
            start,
            end: start + word.len(),
        })
        .collect()
}

/// A 1–`MAX_WINDOW` token window: the canonical lookup key plus the original
/// byte span (for redaction / `resolve_overlaps`).
#[allow(dead_code)]
struct Window {
    /// Tokens normalized (lowercase + NFC) and single-space joined.
    key: String,
    /// Document-absolute byte span of the original (un-normalized) text.
    start: usize,
    end: usize,
}

/// Produce every 1–`MAX_WINDOW`-token window over `tokens`, in start order.
///
/// The canonical key collapses any run of separators between tokens to a single
/// space, so `"Jan   Kowalski"` and `"Jan\nKowalski"` both key as `jan kowalski`.
#[allow(dead_code)]
fn windows(text: &str, tokens: &[Token]) -> Vec<Window> {
    let mut out = Vec::new();
    for i in 0..tokens.len() {
        let mut parts: Vec<String> = Vec::with_capacity(MAX_WINDOW);
        for tok in &tokens[i..(i + MAX_WINDOW).min(tokens.len())] {
            parts.push(normalize(&text[tok.start..tok.end]));
            out.push(Window {
                key: parts.join(" "),
                start: tokens[i].start,
                end: tok.end,
            });
        }
    }
    out
}

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
        assert!(
            flags & IS_SURNAME != 0,
            "`smith` should have IS_SURNAME set"
        );

        // A clearly absent token resolves to nothing.
        assert!(g.get("asdfghjkl").is_none());
    }

    /// Collect `(slice, start, end)` for each token to assert offsets.
    fn toks(text: &str) -> Vec<(&str, usize, usize)> {
        tokenize(text)
            .iter()
            .map(|t| (&text[t.start..t.end], t.start, t.end))
            .collect()
    }

    #[test]
    fn token_offsets_ascii() {
        assert_eq!(toks("John Smith"), vec![("John", 0, 4), ("Smith", 5, 10)]);
    }

    #[test]
    fn token_offsets_accented() {
        // `é` and `í` are 2 bytes each, so spans must track byte (not char) length.
        assert_eq!(toks("José García"), vec![("José", 0, 5), ("García", 6, 13)]);
    }

    #[test]
    fn hyphenated_token_splits() {
        // Documented behaviour: the hyphen is a word boundary.
        assert_eq!(toks("Jean-Pierre"), vec![("Jean", 0, 4), ("Pierre", 5, 11)]);
    }

    #[test]
    fn windows_keys_and_spans() {
        let text = "John Smith";
        let ws = windows(text, &tokenize(text));
        let got: Vec<(&str, usize, usize)> = ws
            .iter()
            .map(|w| (w.key.as_str(), w.start, w.end))
            .collect();
        assert_eq!(
            got,
            vec![("john", 0, 4), ("john smith", 0, 10), ("smith", 5, 10),]
        );
    }

    #[test]
    fn multi_space_and_newline_collapse_to_single_space_key() {
        for text in ["John   Smith", "John\nSmith", "John \t Smith"] {
            let tokens = tokenize(text);
            let two = windows(text, &tokens)
                .into_iter()
                .find(|w| w.key.contains(' '))
                .expect("a 2-token window");
            assert_eq!(two.key, "john smith");
            // Span covers the original text from first token start to last end.
            assert_eq!(two.start, 0);
            assert_eq!(&text[two.start..two.end], text);
        }
    }

    #[test]
    fn windows_capped_at_max_window() {
        let text = "a b c d e";
        let tokens = tokenize(text);
        let max_key_tokens = windows(text, &tokens)
            .iter()
            .map(|w| w.key.split(' ').count())
            .max()
            .unwrap();
        assert_eq!(max_key_tokens, MAX_WINDOW);
    }
}
