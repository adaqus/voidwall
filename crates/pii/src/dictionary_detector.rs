//! Dictionary-based PII detection via FST gazetteer membership.
//!
//! See DESIGN.md § "Dictionary-Based Detection (`DictionaryDetector`)" and
//! `docs/ner-vs-regex-latency-research.md`. A name form is looked up in an FST
//! whose value carries the flag bitmask below. The embedded gazetteer covers
//! English given names + surnames and Italian/Spanish surnames; the detector
//! itself is language-agnostic.

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

use crate::detector::Detector;
use crate::dictionary_detector::flags::{ALSO_COMMON_WORD, IS_GIVEN, IS_SURNAME};
use crate::{ContextFragment, PiiError, PiiKind, PiiMatch};
use fst::Map;
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

/// Longest token window (in tokens) we look up — covers names like
/// `de la cruz` / `van der berg`.
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
struct Token {
    start: usize,
    end: usize,
}

/// Split `text` into Unicode word tokens (UAX#29), each with byte offsets.
///
/// Skips whitespace and punctuation, and yields valid UTF-8 boundaries. Note
/// punctuation *inside* a token also splits it: `Jean-Pierre` becomes two
/// tokens (`Jean`, `Pierre`) — the hyphen is a word boundary.
fn tokenize(text: &str) -> Vec<Token> {
    text.unicode_word_indices()
        .map(|(start, word)| Token {
            start,
            end: start + word.len(),
        })
        .collect()
}

/// A 1–`MAX_WINDOW` token window: the canonical lookup key, the original byte
/// span (for redaction / `resolve_overlaps`), and the token range it covers
/// (for gating).
struct Window {
    /// Tokens normalized (lowercase + NFC) and single-space joined.
    key: String,
    /// Document-absolute byte span of the original (un-normalized) text.
    start: usize,
    end: usize,
    /// Index of the first token and number of tokens in the window.
    tok_start: usize,
    tok_len: usize,
}

/// Lazily yield every 1–`MAX_WINDOW`-token window over `tokens`, in start order
/// (and, per start, increasing length). Being lazy lets `has_piis` stop at the
/// first gated hit without building the rest.
///
/// Windows are produced **only** at a capitalised start token (`cap[i]`):
/// `gated` rejects any window whose first token isn't capitalised, so skipping
/// those starts avoids building their keys and FST lookups entirely — a large
/// win on lowercase prose — while leaving the emitted set unchanged. (A numeric
/// token is never `cap`, so this also covers the non-numeric-start rule.)
///
/// The canonical key collapses any run of separators between tokens to a single
/// space, so `"Jan   Kowalski"` and `"Jan\nKowalski"` both key as `jan kowalski`.
fn windows<'a>(
    text: &'a str,
    tokens: &'a [Token],
    cap: &'a [bool],
) -> impl Iterator<Item = Window> + 'a {
    (0..tokens.len())
        .filter(move |&i| cap[i])
        .flat_map(move |i| {
            let upper = (i + MAX_WINDOW).min(tokens.len());
            // `scan` grows the canonical key one token at a time across the window.
            tokens[i..upper]
                .iter()
                .enumerate()
                .scan(String::new(), move |key, (j, tok)| {
                    if j > 0 {
                        key.push(' ');
                    }
                    key.push_str(&normalize(&text[tok.start..tok.end]));
                    Some(Window {
                        key: key.clone(),
                        start: tokens[i].start,
                        end: tok.end,
                        tok_start: i,
                        tok_len: j + 1,
                    })
                })
        })
}

/// The committed names gazetteer, embedded at compile time.
///
/// `include_bytes!` (rather than a runtime mmap) is deliberate: it yields a
/// single `&'static [u8]` baked into the binary, shared read-only across every
/// scanner thread with **no per-thread cost and no runtime file path** to
/// resolve. At ~0.8 MB the artifact is small enough that embedding it is
/// cheaper and simpler than mmap; revisit only if it grows to many MB.
const NAMES_FST_BYTES: &[u8] = include_bytes!("../data/names.fst");

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

/// Title/honorific tokens (normalized) that promote a following common-word
/// name form. Trailing dots are stripped by tokenization, so `Mr.` → `mr`.
const TITLES: &[&str] = &[
    "mr", "mrs", "ms", "mx", "miss", "dr", "prof", "sir", "madam", "mister",
];

/// High-frequency function words from the other supported languages
/// (DE/FR/ES/IT/NL/PL) that collide with rare US-Census surnames in the
/// English-only gazetteer (e.g. German `Alle`). They are suppressed as
/// **single-token** hits only — multi-word gazetteer entries such as
/// `de la cruz` look up the full window and are unaffected.
///
/// Deliberately small and incomplete: a proper per-language stoplist (and the
/// capitalisation gate German defeats) is Phase-2 work — see the research doc
/// §7. Stored normalized (lowercase + NFC), so accented forms keep their marks.
const STOPWORDS: &[&str] = &[
    // German
    "der", "die", "das", "den", "dem", "des", "ein", "eine", "einen", "und", "oder", "aber", "alle",
    "aller", "allen", "auch", "über", "für", "mit", "von", "aus", "auf", "ist", "sind", "wird",
    "werden", "nicht", "wir", "sie", "ihr", "ihre", "dass", "zum", "zur", "bei", "nach",
    // French
    "le", "la", "les", "un", "une", "du", "et", "ou", "que", "qui", "pour", "par", "sur", "dans",
    "avec", "sont", "sera", "ne", "pas", "ce", "cette", "leur", "aux", // Spanish
    "el", "los", "unos", "unas", "para", "con", "sin", "sus", "está", "están", "este", "esto",
    "como", // Italian
    "lo", "gli", "della", "che", "per", "suo", "questo", "questa", "nel", // Dutch
    "het", "een", "en", "dat", "voor", "op", "zijn", "niet", "ook", "naar", // Polish
    "oraz", "lub", "ale", "na", "do", "od", "za", "ten", "jest", "czy",
];

/// Per-token signals precomputed once per scanned text, used for precision
/// gating of common-word name forms.
struct Analysis {
    /// FST flag bitmask for each token's 1-token key (`None` = not a name form).
    raw: Vec<Option<u64>>,
    /// First character is uppercase.
    cap: Vec<bool>,
    /// Token is a title/honorific (`TITLES`).
    title: Vec<bool>,
    /// Token is a non-English function word (`STOPWORDS`).
    stop: Vec<bool>,
    /// The gap before this token is whitespace-only (so the previous token is a
    /// true left-neighbour, not separated by punctuation). `false` for token 0.
    ws_before: Vec<bool>,
}

impl Analysis {
    fn has(&self, i: usize, bit: u64) -> bool {
        self.raw[i].is_some_and(|f| f & bit != 0)
    }

    /// Is a capitalised common-word form at tokens `i..i+len` promoted by
    /// corroborating evidence? Capitalisation **alone** is too weak — it fires
    /// on `Home`, `Test`, header-case, and sentence starts — so a capitalised
    /// common word is treated as an ordinary word unless corroborated. A lone
    /// capitalised common-word name (`I met Rose`) is a deliberate recall gap,
    /// deferred to a future contextual tier.
    fn promoted(&self, i: usize, len: usize) -> bool {
        // Corroboration: a given+surname pair (both capitalised and whitespace-
        // adjacent, so `Will you` and `Friday. The` do not pair), or a title.
        let n = self.raw.len();
        let right = i + len;
        let pair_fwd = self.has(i, IS_GIVEN)
            && right < n
            && self.ws_before[right]
            && self.cap[right]
            && self.has(right, IS_SURNAME);
        let pair_bwd = self.has(i, IS_SURNAME)
            && i > 0
            && self.ws_before[i]
            && self.cap[i - 1]
            && self.has(i - 1, IS_GIVEN);
        // Titles carry a trailing dot (`Mr.`), so no whitespace-gap requirement.
        let titled = i > 0 && self.title[i - 1];
        pair_fwd || pair_bwd || titled
    }

    /// A window hit fires only if the first token is **capitalised** (a name
    /// occurrence looks like a name — this rejects lowercase foreign words / URL
    /// params that merely coincide with a gazetteer entry). A non-common form
    /// then fires; a common-word form additionally needs [`Self::promoted`]. A
    /// lone foreign function word (`STOPWORDS`) never fires.
    fn gated(&self, tok_start: usize, tok_len: usize, flags: u64) -> bool {
        if tok_len == 1 && self.stop[tok_start] {
            return false;
        }
        self.cap[tok_start] && (flags & ALSO_COMMON_WORD == 0 || self.promoted(tok_start, tok_len))
    }
}

/// Dictionary/FST membership detector for dictionary-shaped PII (`PersonName`:
/// EN given+surnames, IT/ES surnames). See the module docs and DESIGN.md.
pub struct DictionaryDetector {
    gaz: Gazetteer,
}

impl DictionaryDetector {
    /// Build the detector, loading the embedded gazetteer. Surfaces
    /// [`PiiError::GazetteerLoad`] at scanner-build time on a corrupt artifact.
    pub fn new() -> Result<Self, PiiError> {
        Ok(Self {
            gaz: Gazetteer::load()?,
        })
    }

    fn analyze(&self, text: &str, tokens: &[Token]) -> Analysis {
        let mut raw = Vec::with_capacity(tokens.len());
        let mut cap = Vec::with_capacity(tokens.len());
        let mut title = Vec::with_capacity(tokens.len());
        let mut stop = Vec::with_capacity(tokens.len());
        let mut ws_before = Vec::with_capacity(tokens.len());
        for (i, t) in tokens.iter().enumerate() {
            let slice = &text[t.start..t.end];
            let key = normalize(slice);
            raw.push(self.gaz.get(&key));
            // "Capitalised" means Titlecase, not ALL-CAPS: an all-uppercase
            // token (NHI, AWS, VIN) is an acronym, not a name, so it must carry
            // at least one lowercase letter to count.
            cap.push(
                slice.chars().next().is_some_and(char::is_uppercase)
                    && slice.chars().any(char::is_lowercase),
            );
            title.push(TITLES.contains(&key.as_str()));
            stop.push(STOPWORDS.contains(&key.as_str()));
            ws_before.push(
                i > 0
                    && text[tokens[i - 1].end..t.start]
                        .chars()
                        .all(char::is_whitespace),
            );
        }
        Analysis {
            raw,
            cap,
            title,
            stop,
            ws_before,
        }
    }

    /// Compute non-overlapping `PersonName` byte spans over `text`: the longest
    /// gated window per start, then adjacent (whitespace-gap) windows merged
    /// into one span (so `John Smith` is a single match).
    fn name_spans(&self, text: &str) -> Vec<(usize, usize)> {
        let tokens = tokenize(text);
        if tokens.is_empty() {
            return Vec::new();
        }
        let a = self.analyze(text, &tokens);

        // Longest gated window starting at each token, stored as
        // `(last_token, byte_start, byte_end)`.
        let mut best: Vec<Option<(usize, usize, usize)>> = vec![None; tokens.len()];
        for w in windows(text, &tokens, &a.cap) {
            if let Some(f) = self.gaz.get(&w.key)
                && a.gated(w.tok_start, w.tok_len, f)
            {
                let last = w.tok_start + w.tok_len - 1;
                let slot = &mut best[w.tok_start];
                if slot.is_none_or(|(prev_last, ..)| last > prev_last) {
                    *slot = Some((last, w.start, w.end));
                }
            }
        }

        // Merge runs of adjacent name windows separated only by whitespace. A
        // non-name (skipped) token between two hits leaves non-whitespace in the
        // gap, which breaks the run.
        let mut out = Vec::new();
        let mut run: Option<(usize, usize, usize)> = None; // (last_token, byte_start, byte_end)
        for (s, slot) in best.iter().enumerate() {
            let Some((last, bs, be)) = *slot else {
                continue;
            };
            run = match run {
                // window starts within/overlapping the current run (e.g. a
                // 1-token sub-hit inside a matched `de la cruz`)
                Some((l, rbs, rbe)) if s <= l => Some((last.max(l), rbs, be.max(rbe))),
                // contiguous: only whitespace between the run end and this window
                Some((l, rbs, rbe)) if text[rbe..bs].chars().all(char::is_whitespace) => {
                    Some((last.max(l), rbs, be.max(rbe)))
                }
                Some((_, rbs, rbe)) => {
                    out.push((rbs, rbe));
                    Some((last, bs, be))
                }
                None => Some((last, bs, be)),
            };
        }
        if let Some((_, bs, be)) = run {
            out.push((bs, be));
        }
        out
    }
}

impl Detector for DictionaryDetector {
    fn mark_piis(&self, input: &str) -> Vec<PiiMatch> {
        self.name_spans(input)
            .into_iter()
            .map(|(start, end)| PiiMatch {
                kind: PiiKind::PersonName,
                start,
                end,
                user_label: None,
            })
            .collect()
    }

    fn has_piis(&self, input: &str) -> bool {
        let tokens = tokenize(input);
        if tokens.is_empty() {
            return false;
        }
        let a = self.analyze(input, &tokens);
        // `windows` is lazy, so `any` stops at the first gated hit without
        // building the rest.
        windows(input, &tokens, &a.cap).any(|w| {
            self.gaz
                .get(&w.key)
                .is_some_and(|f| a.gated(w.tok_start, w.tok_len, f))
        })
    }

    /// Names need no key-path context, so each fragment's **value** is scanned
    /// directly (like a pattern-only detector) and matches are shifted by
    /// `fragment.offset` to document-absolute spans.
    fn mark_piis_structured(&self, fragments: &[ContextFragment<'_>]) -> Vec<PiiMatch> {
        fragments
            .iter()
            .flat_map(|f| {
                self.mark_piis(f.value).into_iter().map(|mut m| {
                    m.start += f.offset;
                    m.end += f.offset;
                    m
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::flags::*;
    use super::*;
    use test_case::test_case;

    /// `(value, start, end)` for each detected match.
    fn detect(text: &str) -> Vec<(String, usize, usize)> {
        let d = DictionaryDetector::new().expect("detector builds");
        d.mark_piis(text)
            .into_iter()
            .map(|m| {
                assert_eq!(m.kind, PiiKind::PersonName);
                (text[m.start..m.end].to_string(), m.start, m.end)
            })
            .collect()
    }

    fn values(text: &str) -> Vec<String> {
        detect(text).into_iter().map(|(v, ..)| v).collect()
    }

    #[test_case("Kowalski"   ; "bare surname, not a common word")]
    #[test_case("John Smith" ; "given+surname pair, both common words")]
    #[test_case("Will Smith" ; "common given promoted by adjacent surname")]
    #[test_case("Mr. Will"   ; "common given promoted by preceding title")]
    #[test_case("Esposito"   ; "bare Italian surname")]
    #[test_case("García"     ; "bare accented Spanish surname")]
    #[test_case("John Costa" ; "common IT/ES word surname promoted by adjacent given")]
    fn detected(text: &str) {
        assert!(
            DictionaryDetector::new().unwrap().has_piis(text),
            "expected a detection in {text:?}"
        );
        assert!(!values(text).is_empty());
    }

    #[test_case("asdfghjkl"       ; "unknown token")]
    #[test_case("i will go"       ; "lowercase common words in prose")]
    #[test_case("Will you go"     ; "sentence-initial common word, no name pair")]
    #[test_case("I met Rose today"; "lone capitalised common-word name, uncorroborated (recall gap)")]
    #[test_case("Costa"           ; "bare IT/ES common-word surname, uncorroborated")]
    fn not_detected(text: &str) {
        assert!(
            !DictionaryDetector::new().unwrap().has_piis(text),
            "expected no detection in {text:?}"
        );
        assert!(values(text).is_empty());
    }

    #[test]
    fn bare_surname_span_is_exact() {
        assert_eq!(detect("Kowalski"), vec![("Kowalski".into(), 0, 8)]);
    }

    #[test]
    fn multi_token_name_is_single_longest_match() {
        // `John` and `Smith` merge into one span, not two matches.
        assert_eq!(detect("John Smith"), vec![("John Smith".into(), 0, 10)]);
    }

    #[test]
    fn offsets_are_document_absolute() {
        let text = "please contact Kowalski regarding the case";
        let got = detect(text);
        let expected_start = text.find("Kowalski").unwrap();
        assert!(
            got.contains(&("Kowalski".into(), expected_start, expected_start + 8)),
            "got {got:?}"
        );
    }

    #[test]
    fn structured_value_detected_with_absolute_offsets() {
        // Simulates a parsed `{"name": "John Smith"}` fragment: only the value
        // is scanned, and the match span is shifted to document-absolute bytes.
        let doc = r#"{"name": "John Smith"}"#;
        let value_off = doc.find("John Smith").unwrap();
        let frag = ContextFragment {
            context: "name",
            value: "John Smith",
            offset: value_off,
        };
        let d = DictionaryDetector::new().unwrap();
        let got = d.mark_piis_structured(&[frag]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind, PiiKind::PersonName);
        assert_eq!((got[0].start, got[0].end), (value_off, value_off + 10));
        assert_eq!(&doc[got[0].start..got[0].end], "John Smith");
    }

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

        // Italian and (accent-preserving) Spanish surnames resolve as surnames.
        // Look up through `normalize` so the query key is NFC — identical to the
        // scan path — rather than depending on this source file's Unicode form.
        assert!(
            g.get(&normalize("Esposito"))
                .is_some_and(|f| f & IS_SURNAME != 0),
            "`esposito` should be present as IT surname"
        );
        assert!(
            g.get(&normalize("García"))
                .is_some_and(|f| f & IS_SURNAME != 0),
            "`garcía` (accented) should be present as ES surname"
        );

        // Homograph gating: a surname that is also a common IT/ES word (`Costa`)
        // carries ALSO_COMMON_WORD so a bare hit needs corroboration; a surname
        // that is *only* a surname (`García`, `Esposito`) must NOT — otherwise
        // standalone-surname recall is lost.
        let costa = g.get(&normalize("Costa")).expect("`costa` present");
        assert!(
            costa & IS_SURNAME != 0 && costa & ALSO_COMMON_WORD != 0,
            "`costa` should be a common-word surname"
        );
        for pure in ["García", "Esposito"] {
            let f = g.get(&normalize(pure)).expect("surname present");
            assert!(
                f & ALSO_COMMON_WORD == 0,
                "`{pure}` is a surname, not a common word — must not be gated"
            );
        }
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
        let tokens = tokenize(text);
        let cap = vec![true; tokens.len()];
        let ws: Vec<Window> = windows(text, &tokens, &cap).collect();
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
            let cap = vec![true; tokens.len()];
            let two = windows(text, &tokens, &cap)
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
        let cap = vec![true; tokens.len()];
        let max_key_tokens = windows(text, &tokens, &cap)
            .map(|w| w.key.split(' ').count())
            .max()
            .unwrap();
        assert_eq!(max_key_tokens, MAX_WINDOW);
    }
}
