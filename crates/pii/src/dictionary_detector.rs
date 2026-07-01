//! Dictionary-based PII detection via FST gazetteer membership.
//!
//! See DESIGN.md § "Dictionary-Based Detection (`DictionaryDetector`)" and
//! `docs/ner-vs-regex-latency-research.md`. A name form is looked up in an FST
//! whose value carries the flag bitmask below. The embedded gazetteer covers
//! English (US) given names + surnames, multilingual given names (Wikidata CC0),
//! and Italian/Spanish surnames; the detector itself is language-agnostic.

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
use fst::raw::Output;
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

/// Normalize each token once (lowercase + NFC), shared by `analyze` (1-token
/// FST lookups, title/stop tests) and the window walk (FST prefix traversal) so
/// no token is normalized twice.
fn normalized(text: &str, tokens: &[Token]) -> Vec<String> {
    tokens
        .iter()
        .map(|t| normalize(&text[t.start..t.end]))
        .collect()
}

/// The committed names gazetteer, embedded at compile time.
///
/// `include_bytes!` (rather than a runtime mmap) is deliberate: it yields a
/// single `&'static [u8]` baked into the binary, shared read-only across every
/// scanner thread with **no per-thread cost and no runtime file path** to
/// resolve. At ~3.5 MB the artifact is small enough that embedding it is
/// cheaper and simpler than mmap; revisit only if it grows to many tens of MB.
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

    /// The underlying raw FST, for byte-by-byte prefix traversal (see
    /// [`DictionaryDetector::walk_gated`]).
    fn fst(&self) -> &fst::raw::Fst<&'static [u8]> {
        self.map.as_fst()
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
    /// FST flag bitmask for each token's 1-token key (`None` = not a name form
    /// **or** an un-capitalised token whose lookup was skipped — `raw` is only
    /// ever read at capitalised indices, see [`Analysis::promoted`]).
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

    fn analyze(&self, text: &str, tokens: &[Token], norm: &[String]) -> Analysis {
        let mut raw = Vec::with_capacity(tokens.len());
        let mut cap = Vec::with_capacity(tokens.len());
        let mut title = Vec::with_capacity(tokens.len());
        let mut stop = Vec::with_capacity(tokens.len());
        let mut ws_before = Vec::with_capacity(tokens.len());
        for (i, t) in tokens.iter().enumerate() {
            let slice = &text[t.start..t.end];
            let key = norm[i].as_str();
            // "Capitalised" means Titlecase, not ALL-CAPS: an all-uppercase
            // token (NHI, AWS, VIN) is an acronym, not a name, so it must carry
            // at least one lowercase letter to count.
            let is_cap = slice.chars().next().is_some_and(char::is_uppercase)
                && slice.chars().any(char::is_lowercase);
            // The 1-token FST lookup is the detector's dominant per-token cost.
            // `raw` is only ever read at capitalised indices (see `promoted`),
            // so skipping the lookup on lowercase tokens is behaviour-preserving
            // and removes the bulk of the work on lowercase prose.
            raw.push(if is_cap { self.gaz.get(key) } else { None });
            cap.push(is_cap);
            title.push(TITLES.contains(&key));
            stop.push(STOPWORDS.contains(&key));
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

    /// Walk the FST once per capitalised start token, extending token-by-token
    /// with **prefix-pruning**: as soon as a prefix has no continuation in the
    /// FST the window is abandoned, so no key string is built and no from-root
    /// lookup is repeated. For each gated 1–`MAX_WINDOW`-token window that
    /// resolves to a name form, `emit(tok_start, tok_len, byte_start, byte_end)`
    /// is called in (start, increasing-length) order. Emitting stops early — and
    /// the whole walk returns — the first time `emit` returns `false`, letting
    /// `has_piis` short-circuit on the first hit.
    ///
    /// Emits exactly the set the old per-window `gaz.get` produced: a single
    /// space separates tokens (matching the canonical key), and only capitalised
    /// starts are considered (`gated` requires it). See `walk_emits_same_*` test.
    fn walk_gated(
        &self,
        tokens: &[Token],
        norm: &[String],
        a: &Analysis,
        mut emit: impl FnMut(usize, usize, usize, usize) -> bool,
    ) {
        let fst = self.gaz.fst();
        for i in 0..tokens.len() {
            if !a.cap[i] {
                continue;
            }
            let mut node = fst.root();
            let mut out = Output::zero();
            // Extend the window from start `i` one token at a time.
            'extend: for j in 0..MAX_WINDOW {
                let t = i + j;
                if t >= tokens.len() {
                    break;
                }
                // A single space joins tokens in the canonical key; if the FST
                // has no such continuation, no longer window can match.
                if j > 0 {
                    let Some(idx) = node.find_input(b' ') else {
                        break 'extend;
                    };
                    let tr = node.transition(idx);
                    out = out.cat(tr.out);
                    node = fst.node(tr.addr);
                }
                // Feed token `t`'s normalized bytes; a dead prefix ends the walk
                // (this window and every longer one contain token `t` in full).
                for &b in norm[t].as_bytes() {
                    let Some(idx) = node.find_input(b) else {
                        break 'extend;
                    };
                    let tr = node.transition(idx);
                    out = out.cat(tr.out);
                    node = fst.node(tr.addr);
                }
                if node.is_final() {
                    let flags = out.cat(node.final_output()).value();
                    if a.gated(i, j + 1, flags) && !emit(i, j + 1, tokens[i].start, tokens[t].end) {
                        return;
                    }
                }
            }
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
        let norm = normalized(text, &tokens);
        let a = self.analyze(text, &tokens, &norm);

        // Longest gated window starting at each token, stored as
        // `(last_token, byte_start, byte_end)`.
        let mut best: Vec<Option<(usize, usize, usize)>> = vec![None; tokens.len()];
        self.walk_gated(&tokens, &norm, &a, |tok_start, tok_len, start, end| {
            let last = tok_start + tok_len - 1;
            let slot = &mut best[tok_start];
            if slot.is_none_or(|(prev_last, ..)| last > prev_last) {
                *slot = Some((last, start, end));
            }
            true
        });

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
        let norm = normalized(input, &tokens);
        let a = self.analyze(input, &tokens, &norm);
        // Returning `false` from `emit` on the first gated hit stops the walk
        // immediately (short-circuit).
        let mut found = false;
        self.walk_gated(&tokens, &norm, &a, |_, _, _, _| {
            found = true;
            false
        });
        found
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

    #[test_case("John   Smith" ; "multiple spaces")]
    #[test_case("John\nSmith"   ; "newline")]
    #[test_case("John \t Smith" ; "mixed whitespace")]
    fn adjacent_names_merge_across_any_whitespace(text: &str) {
        // Any run of separators keys tokens the same, and adjacent name windows
        // separated only by whitespace merge into one span over the whole input.
        assert_eq!(detect(text), vec![(text.to_string(), 0, text.len())]);
    }

    /// The prefix-pruning FST walk must emit exactly the gated windows the
    /// straightforward per-window `gaz.get` (walked from root for every length)
    /// would — this is the AC guaranteeing the emitted match set is unchanged.
    #[test]
    fn walk_emits_same_gated_windows_as_get_per_window() {
        let d = DictionaryDetector::new().unwrap();
        let texts = [
            "please contact John Smith and Will Smith about Mr. Will today",
            "i will go home then Rose Costa and José García called",
            "John\n\nSmith   and    Kowalski wrote to Esposito",
            "asdfghjkl Will you go, Home Test AWS VIN",
        ];
        for text in texts {
            let tokens = tokenize(text);
            let norm = normalized(text, &tokens);
            let a = d.analyze(text, &tokens, &norm);

            // Reference: brute-force every gated window via a from-root lookup.
            let mut reference = Vec::new();
            for i in 0..tokens.len() {
                if !a.cap[i] {
                    continue;
                }
                for len in 1..=MAX_WINDOW {
                    if i + len > tokens.len() {
                        break;
                    }
                    let key = norm[i..i + len].join(" ");
                    if let Some(f) = d.gaz.get(&key)
                        && a.gated(i, len, f)
                    {
                        reference.push((i, len, tokens[i].start, tokens[i + len - 1].end));
                    }
                }
            }

            let mut got = Vec::new();
            d.walk_gated(&tokens, &norm, &a, |ts, tl, bs, be| {
                got.push((ts, tl, bs, be));
                true
            });
            assert_eq!(got, reference, "walk vs get mismatch on {text:?}");
        }
    }
}
