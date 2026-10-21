//! The word-level decoder of a token classifier: each token's pooled
//! probabilities become typed, trimmed spans of the unit's text.
//!
//! It ports steps 1–5 of bards.ai's `pii_detector.py` (D1) onto byte
//! positions. `parity/reference.py` holds the Python copy it must match.
//!
//! ```text
//! records ──► cells: summed per text position (first non-whitespace char of each token)
//!         ──► words: split, edges trimmed, mean of their cells, argmax type
//!         ──► spans: neighbouring words of one type merged, then trimmed
//! ```

use std::ops::Range;

use crate::token::TokenProbs;

/// Characters that end a word, besides whitespace.
const WORD_BREAK: &[char] = &[
    ',', ';', '|', '"', '<', '>', '(', ')', '[', ']', '{', '}', '*', '^',
];
/// Removed from a word's start.
const WORD_LEAD: &[char] = &['(', '[', '{', '<', '"', '\'', '«', '„'];
/// Removed from a word's end.
const WORD_TRAIL: &[char] = &[
    ')', ']', '}', '>', '"', '\'', '»', '.', ',', ';', ':', '!', '?',
];
/// The only characters that may stand between two words of one span.
const JOINERS: &[char] = &[' ', ',', '-', '/', '.', '(', ')'];
/// Trimmed from both edges of a span, besides whitespace.
const TRIM_BOTH: &[char] = &[
    ',', '.', ';', ':', '!', '?', '"', '\'', '“', '”', '‘', '’', '«', '»', '„',
];
/// Trimmed from the end of a span only.
const TRIM_END: &[char] = &[')', ']', '}'];
/// A word whose start probability is at least this starts a new span.
const NEW_ENTITY: f32 = 0.5;

/// Byte positions of a text that no span crosses, sorted and distinct: a
/// word ends at one, and words on its two sides never merge. Built only by
/// collecting positions, which sorts them, so an unsorted list cannot reach
/// the decoder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Boundaries(Vec<usize>);

impl Boundaries {
    pub fn as_slice(&self) -> &[usize] {
        &self.0
    }
}

impl FromIterator<usize> for Boundaries {
    fn from_iter<I: IntoIterator<Item = usize>>(positions: I) -> Self {
        let mut positions: Vec<usize> = positions.into_iter().collect();
        positions.sort_unstable();
        positions.dedup();
        Self(positions)
    }
}

/// One entity a token classifier found.
#[derive(Debug, Clone, PartialEq)]
pub struct Span {
    /// The entity type, an index into [`Labels::types`](crate::Labels::types).
    pub ty: usize,
    /// The bytes of the text the span covers, trimmed. Never empty.
    pub bytes: Range<usize>,
    /// The mean, over the span's words, of each word's highest pooled
    /// probability. In `0.0..=1.0`.
    pub confidence: f32,
}

/// Decodes the spans of `text` from the records of one run over it. No span
/// crosses one of `boundaries`.
pub(crate) fn decode(text: &str, probs: &TokenProbs, boundaries: &Boundaries) -> Vec<Span> {
    let boundaries = boundaries.as_slice();
    let cells = Cells::new(text, probs);
    let outside = probs.slots() - 1;
    let mut mean = vec![0.0f32; probs.slots()];
    let mut open: Vec<Open> = Vec::new();
    for word in words(text, boundaries) {
        let held = cells.within(&word);
        if held.is_empty() {
            continue;
        }
        mean.fill(0.0);
        let mut count = 0u32;
        for cell in held.clone() {
            for (m, p) in mean.iter_mut().zip(cells.pooled(cell)) {
                *m += p;
            }
            count += cells.count[cell];
        }
        for m in &mut mean {
            *m /= count as f32;
        }
        let (ty, p) = argmax(&mean);
        if ty == outside {
            continue;
        }
        let first = held.start;
        let start = cells.start[first] / cells.count[first] as f32;
        match open.last_mut() {
            Some(span)
                if span.ty == ty
                    && start < NEW_ENTITY
                    && joins(&text[span.bytes.end..word.start])
                    && !crosses(boundaries, span.bytes.end, word.start) =>
            {
                span.bytes.end = word.end;
                span.sum += f64::from(p);
                span.words += 1;
            }
            _ => open.push(Open {
                ty,
                bytes: word,
                sum: f64::from(p),
                words: 1,
            }),
        }
    }
    open.into_iter()
        .filter_map(|span| {
            Some(Span {
                ty: span.ty,
                bytes: trim(text, span.bytes)?,
                confidence: (span.sum / f64::from(span.words)) as f32,
            })
        })
        .collect()
}

/// A span still open to the next word.
struct Open {
    ty: usize,
    bytes: Range<usize>,
    /// The sum of its words' highest pooled probabilities.
    sum: f64,
    words: u32,
}

/// The records summed per text position, kept only where a record landed.
struct Cells {
    slots: usize,
    /// Byte positions, sorted and distinct.
    at: Vec<usize>,
    /// Records summed into each position.
    count: Vec<u32>,
    /// Summed start probabilities.
    start: Vec<f32>,
    /// `at.len() × slots` summed pooled probabilities.
    pooled: Vec<f32>,
}

impl Cells {
    fn new(text: &str, probs: &TokenProbs) -> Self {
        let mut records: Vec<_> = probs
            .records()
            .filter_map(|record| Some((record_at(text, &record.bytes)?, record)))
            .collect();
        // Stable, so the records of one position are summed in window order.
        records.sort_by_key(|(at, _)| *at);
        let slots = probs.slots();
        let mut cells = Self {
            slots,
            at: Vec::new(),
            count: Vec::new(),
            start: Vec::new(),
            pooled: Vec::new(),
        };
        for (at, record) in records {
            if cells.at.last() != Some(&at) {
                cells.at.push(at);
                cells.count.push(0);
                cells.start.push(0.0);
                cells.pooled.resize(cells.pooled.len() + slots, 0.0);
            }
            let last = cells.at.len() - 1;
            cells.count[last] += 1;
            cells.start[last] += record.start;
            for (sum, p) in cells.pooled[last * slots..].iter_mut().zip(record.pooled) {
                *sum += p;
            }
        }
        cells
    }

    /// The cells whose position is inside `bytes`.
    fn within(&self, bytes: &Range<usize>) -> Range<usize> {
        self.at.partition_point(|&at| at < bytes.start)
            ..self.at.partition_point(|&at| at < bytes.end)
    }

    fn pooled(&self, cell: usize) -> &[f32] {
        &self.pooled[cell * self.slots..(cell + 1) * self.slots]
    }
}

/// Where a token's record lands: its first character that is not
/// whitespace, or its last character when all are. An empty token lands
/// nowhere; so does one outside `text`, which the tokenizer never gives.
fn record_at(text: &str, bytes: &Range<usize>) -> Option<usize> {
    let token = text.get(bytes.clone())?;
    let mut last = None;
    for (i, c) in token.char_indices() {
        if !c.is_whitespace() {
            return Some(bytes.start + i);
        }
        last = Some(bytes.start + i);
    }
    last
}

/// The words of `text`, their edges trimmed, in order. A word is a run of
/// characters that are neither whitespace nor [`WORD_BREAK`]; a boundary
/// also ends one. A word trimmed to nothing is left out.
fn words(text: &str, boundaries: &[usize]) -> Vec<Range<usize>> {
    let mut words = Vec::new();
    let mut close = |start: usize, end: usize| {
        let word = &text[start..end];
        let lead = word.len() - word.trim_start_matches(WORD_LEAD).len();
        let kept = word[lead..].trim_end_matches(WORD_TRAIL);
        if !kept.is_empty() {
            words.push(start + lead..start + lead + kept.len());
        }
    };
    let mut boundaries = boundaries.iter().copied().peekable();
    let mut start = None;
    for (i, c) in text.char_indices() {
        let mut cut = false;
        while boundaries.next_if(|&b| b <= i).is_some() {
            cut = true;
        }
        if cut && let Some(s) = start.take() {
            close(s, i);
        }
        if c.is_whitespace() || WORD_BREAK.contains(&c) {
            if let Some(s) = start.take() {
                close(s, i);
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        close(s, text.len());
    }
    words
}

/// The slot of the highest probability, and that probability. The first
/// slot wins a tie, as in the reference.
fn argmax(probs: &[f32]) -> (usize, f32) {
    probs
        .iter()
        .copied()
        .enumerate()
        .fold((0, f32::NEG_INFINITY), |best, (i, p)| {
            if p > best.1 { (i, p) } else { best }
        })
}

/// True when `gap`, the text between two words, lets them form one span.
fn joins(gap: &str) -> bool {
    // A newline is no joiner, so the blank-line rule follows from the first;
    // it is kept as the rule is stated.
    gap.chars().all(|c| JOINERS.contains(&c)) && !gap.contains("\n\n")
}

/// True when a boundary lies in `from..=to`, between the end of one word and
/// the start of the next.
fn crosses(boundaries: &[usize], from: usize, to: usize) -> bool {
    let next = boundaries.partition_point(|&b| b < from);
    boundaries.get(next).is_some_and(|&b| b <= to)
}

/// `bytes` of `text` without its edge characters: whitespace and
/// [`TRIM_BOTH`] at both edges, [`TRIM_END`] at the end. `None` when nothing
/// is left.
fn trim(text: &str, bytes: Range<usize>) -> Option<Range<usize>> {
    let both = |c: char| c.is_whitespace() || TRIM_BOTH.contains(&c);
    let span = &text[bytes.clone()];
    let rest = span.trim_start_matches(both);
    let start = bytes.end - rest.len();
    let kept = rest.trim_end_matches(|c| both(c) || TRIM_END.contains(&c));
    (!kept.is_empty()).then(|| start..start + kept.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    /// Types `NAME` (slot 0) and `PHONE` (slot 1); `O` is slot 2.
    const SLOTS: usize = 3;
    const NAME: usize = 0;
    const PHONE: usize = 1;

    /// A pooled row where `ty` gets `p` and `O` the rest.
    fn row(ty: usize, p: f32) -> [f32; SLOTS] {
        let mut row = [0.0; SLOTS];
        row[ty] += p;
        row[SLOTS - 1] += 1.0 - p;
        row
    }

    /// Hand-made records over `text`: each is the bytes of the `n`-th
    /// occurrence of a token, its pooled row and its start probability.
    struct Records<'a> {
        text: &'a str,
        probs: TokenProbs,
    }

    impl<'a> Records<'a> {
        fn new(text: &'a str) -> Self {
            Self {
                text,
                probs: TokenProbs::new(SLOTS),
            }
        }

        /// Records the token `token`, the first time it occurs at or after `from`.
        fn at(mut self, token: &str, from: usize, pooled: [f32; SLOTS], start: f32) -> Self {
            let s = from + self.text[from..].find(token).expect("token in text");
            self.probs.push_pooled(s..s + token.len(), &pooled, start);
            self
        }

        fn add(self, token: &str, pooled: [f32; SLOTS], start: f32) -> Self {
            self.at(token, 0, pooled, start)
        }

        fn decode(&self, boundaries: &[usize]) -> Vec<Span> {
            decode(
                self.text,
                &self.probs,
                &boundaries.iter().copied().collect(),
            )
        }

        /// The decoded spans as (text, type, confidence).
        fn spans(&self) -> Vec<(&'a str, usize, f32)> {
            self.decode(&[])
                .into_iter()
                .map(|s| (&self.text[s.bytes], s.ty, s.confidence))
                .collect()
        }
    }

    fn close(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-6
    }

    #[test]
    fn a_token_in_two_windows_is_labelled_from_the_mean() {
        // Window 1 says O (0.7), window 2 says NAME (0.9): the mean is NAME 0.6.
        let spans = Records::new("call Ann now")
            .add("Ann", row(NAME, 0.3), 0.9)
            .add("Ann", row(NAME, 0.9), 0.9)
            .spans();
        assert_eq!(spans.len(), 1);
        assert_eq!((spans[0].0, spans[0].1), ("Ann", NAME));
        assert!(close(spans[0].2, 0.6), "{spans:?}");
    }

    #[test]
    fn a_word_predicted_as_outside_is_in_no_span() {
        let spans = Records::new("call Ann now")
            .add("call", row(NAME, 0.2), 0.1)
            .add("Ann", row(NAME, 0.8), 0.9)
            .add("now", row(PHONE, 0.4), 0.4)
            .spans();
        assert_eq!(spans.iter().map(|s| s.0).collect::<Vec<_>>(), ["Ann"]);
    }

    #[test]
    fn a_word_is_labelled_from_the_mean_of_its_tokens() {
        // NAME (0.9 + 0.3) / 2 = 0.6 beats O 0.4.
        let spans = Records::new("Kowalski")
            .add("Kow", row(NAME, 0.9), 0.9)
            .add("alski", row(NAME, 0.3), 0.0)
            .spans();
        assert_eq!(spans.len(), 1);
        assert!(close(spans[0].2, 0.6), "{spans:?}");
    }

    #[test]
    fn the_highest_type_wins_a_word() {
        let mut pooled = [0.0; SLOTS];
        pooled[NAME] = 0.3;
        pooled[PHONE] = 0.45;
        pooled[2] = 0.25;
        let spans = Records::new("555").add("555", pooled, 0.9).spans();
        assert_eq!(spans, [("555", PHONE, 0.45)]);
    }

    #[test]
    fn a_two_word_name_is_one_span() {
        let spans = Records::new("Ann Lee")
            .add("Ann", row(NAME, 0.9), 0.9)
            .add("Lee", row(NAME, 0.7), 0.1)
            .spans();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].0, "Ann Lee");
        assert!(close(spans[0].2, 0.8), "the mean of 0.9 and 0.7: {spans:?}");
    }

    #[test]
    fn a_high_start_probability_starts_a_new_span() {
        let spans = Records::new("Ann Lee")
            .add("Ann", row(NAME, 0.9), 0.9)
            .add("Lee", row(NAME, 0.7), 0.8)
            .spans();
        assert_eq!(
            spans.iter().map(|s| s.0).collect::<Vec<_>>(),
            ["Ann", "Lee"]
        );
    }

    #[test]
    fn a_start_probability_of_exactly_one_half_starts_a_new_span() {
        let spans = Records::new("Ann Lee")
            .add("Ann", row(NAME, 0.9), 0.9)
            .add("Lee", row(NAME, 0.7), 0.5)
            .spans();
        assert_eq!(spans.len(), 2);
    }

    #[test]
    fn the_start_probability_is_the_mean_over_the_first_records() {
        // Two windows record "Lee": starts 0.9 and 0.0, mean 0.45 < 0.5.
        let spans = Records::new("Ann Lee")
            .add("Ann", row(NAME, 0.9), 0.9)
            .add("Lee", row(NAME, 0.7), 0.9)
            .add("Lee", row(NAME, 0.7), 0.0)
            .spans();
        assert_eq!(spans.iter().map(|s| s.0).collect::<Vec<_>>(), ["Ann Lee"]);
    }

    #[test]
    fn the_start_probability_is_read_at_the_words_first_record() {
        // "Lee" starts low; the later token "son" starts high but is not first.
        let spans = Records::new("Ann Leeson")
            .add("Ann", row(NAME, 0.9), 0.9)
            .add("Lee", row(NAME, 0.7), 0.1)
            .add("son", row(NAME, 0.7), 0.9)
            .spans();
        assert_eq!(
            spans.iter().map(|s| s.0).collect::<Vec<_>>(),
            ["Ann Leeson"]
        );
    }

    #[test]
    fn words_of_two_types_are_two_spans() {
        let spans = Records::new("Ann 555")
            .add("Ann", row(NAME, 0.9), 0.9)
            .add("555", row(PHONE, 0.9), 0.1)
            .spans();
        assert_eq!(spans.len(), 2);
    }

    #[test_case("Ann Lee", true ; "a space")]
    #[test_case("AnnLee", true ; "nothing")]
    #[test_case("Ann, Lee", true ; "a comma")]
    #[test_case("Ann (Lee", true ; "an opening bracket")]
    #[test_case("Ann . / - Lee", true ; "every joiner")]
    #[test_case("Ann\n\nLee", false ; "a blank line")]
    #[test_case("Ann\nLee", false ; "a newline")]
    #[test_case("Ann\tLee", false ; "a tab")]
    #[test_case("Ann; Lee", false ; "a semicolon")]
    #[test_case("Ann | Lee", false ; "a bar")]
    #[test_case("Ann and Lee", false ; "a word with no record")]
    fn the_gap_decides_a_merge(text: &str, merged: bool) {
        // "AnnLee" is one word, so its two records give one span either way.
        let records =
            Records::new(text)
                .add("Ann", row(NAME, 0.9), 0.9)
                .at("Lee", 3, row(NAME, 0.9), 0.1);
        let count = records.spans().len();
        assert_eq!(count, if merged { 1 } else { 2 }, "{text:?}");
    }

    #[test_case('\u{85}', true ; "next line")]
    #[test_case('\u{a0}', true ; "no break space")]
    #[test_case('\u{3000}', true ; "ideographic space")]
    #[test_case('\u{1f}', false ; "unit separator")]
    #[test_case('\u{1c}', false ; "file separator")]
    #[test_case('\u{200b}', false ; "zero width space")]
    fn whitespace_is_the_unicode_white_space_property(c: char, breaks: bool) {
        // Python's `str.isspace` also holds U+001C to U+001F; the decoder
        // and its Python copy do not.
        let text = format!("Ann{c}Lee");
        let words: Vec<_> = words(&text, &[]).into_iter().map(|w| &text[w]).collect();
        let expected = if breaks {
            vec!["Ann", "Lee"]
        } else {
            vec![text.as_str()]
        };
        assert_eq!(words, expected);
    }

    #[test]
    fn a_boundary_between_words_stops_a_merge() {
        let records =
            Records::new("Ann Lee")
                .add("Ann", row(NAME, 0.9), 0.9)
                .add("Lee", row(NAME, 0.9), 0.1);
        for boundary in [3, 4] {
            let spans = records.decode(&[boundary]);
            let texts: Vec<_> = spans
                .iter()
                .map(|s| &records.text[s.bytes.clone()])
                .collect();
            assert_eq!(texts, ["Ann", "Lee"], "boundary at {boundary}");
        }
        assert_eq!(
            records.decode(&[0, 7]).len(),
            1,
            "boundaries at the edges cut nothing"
        );
    }

    #[test]
    fn boundaries_are_sorted_and_distinct_whatever_order_they_come_in() {
        let boundaries: Boundaries = [7, 3, 7, 0].into_iter().collect();
        assert_eq!(boundaries.as_slice(), [0, 3, 7]);
    }

    #[test]
    fn a_boundary_ends_a_word() {
        let records =
            Records::new("AnnLee")
                .add("Ann", row(NAME, 0.9), 0.9)
                .add("Lee", row(NAME, 0.9), 0.1);
        let bytes: Vec<_> = records.decode(&[3]).into_iter().map(|s| s.bytes).collect();
        assert_eq!(bytes, [0..3, 3..6]);
    }

    #[test]
    fn a_token_is_recorded_at_its_first_non_whitespace_character() {
        // The token " Ann" starts on the space; its record belongs to "Ann".
        let spans = Records::new("hi Ann")
            .add(" Ann", row(NAME, 0.9), 0.9)
            .spans();
        assert_eq!(spans, [("Ann", NAME, 0.9)]);
    }

    #[test]
    fn a_whitespace_token_is_recorded_at_its_last_character() {
        let text = "Ann  Lee";
        let records = Records::new(text).add("  ", row(NAME, 0.9), 0.9);
        let cells = Cells::new(text, &records.probs);
        assert_eq!(cells.at, [4]);
    }

    #[test]
    fn an_empty_token_records_nothing() {
        let mut records = Records::new("Ann");
        records.probs.push_pooled(1..1, &row(NAME, 0.9), 0.9);
        assert!(records.spans().is_empty());
    }

    #[test]
    fn a_word_whose_records_were_trimmed_away_is_skipped() {
        // The token "«Ann»" lands on «, which the word trim removes.
        let spans = Records::new("«Ann»")
            .add("«Ann»", row(NAME, 0.9), 0.9)
            .spans();
        assert!(spans.is_empty(), "{spans:?}");
    }

    #[test_case("'Ann'.", "Ann" ; "quotes and a full stop")]
    #[test_case("„Ann", "Ann" ; "a low opening quote")]
    #[test_case("<Ann>", "Ann" ; "angle brackets break the word")]
    #[test_case("Ann?!", "Ann" ; "trailing marks")]
    fn word_edges_are_trimmed(text: &str, word: &str) {
        let spans = Records::new(text).add(word, row(NAME, 0.9), 0.9).spans();
        assert_eq!(spans.iter().map(|s| s.0).collect::<Vec<_>>(), [word]);
    }

    #[test]
    fn a_multibyte_word_keeps_its_bytes() {
        let text = "pan Łukasz Żółć.";
        let spans = Records::new(text)
            .add("Łukasz", row(NAME, 0.9), 0.9)
            .add("Żółć", row(NAME, 0.8), 0.1)
            .spans();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].0, "Łukasz Żółć");
    }

    #[test]
    fn no_record_gives_no_span() {
        assert!(Records::new("Ann Lee").spans().is_empty());
        assert!(Records::new("").spans().is_empty());
    }

    #[test]
    fn a_curly_quote_the_word_keeps_is_trimmed_from_the_span() {
        // The word trim keeps “ and ”; the span trim removes them.
        let spans = Records::new("“Ann”")
            .add("“Ann”", row(NAME, 0.9), 0.9)
            .spans();
        assert_eq!(spans, [("Ann", NAME, 0.9)]);
    }

    #[test_case("value).", Some("value") ; "a closing bracket and a full stop")]
    #[test_case("(value", Some("(value") ; "an opening bracket is kept")]
    #[test_case("(value)", Some("(value") ; "only the closing bracket goes")]
    #[test_case("\"value\"", Some("value") ; "straight quotes")]
    #[test_case("“value”", Some("value") ; "curly quotes")]
    #[test_case("‘value’", Some("value") ; "single curly quotes")]
    #[test_case("«value»", Some("value") ; "guillemets")]
    #[test_case("„value", Some("value") ; "a low quote")]
    #[test_case(" value \n", Some("value") ; "whitespace")]
    #[test_case(", value;:!?", Some("value") ; "punctuation")]
    #[test_case("value]}", Some("value") ; "closing brackets")]
    #[test_case("[value", Some("[value") ; "an opening square bracket is kept")]
    #[test_case("+48-value/#", Some("+48-value/#") ; "plus minus slash and hash are kept")]
    #[test_case(").,", None ; "trimmed to empty")]
    fn spans_are_trimmed(span: &str, kept: Option<&str>) {
        let text = format!("ab{span}cd");
        let bytes = 2..2 + span.len();
        assert_eq!(trim(&text, bytes).map(|b| &text[b]), kept);
    }

    #[test]
    fn a_span_trimmed_to_nothing_is_dropped() {
        // The word "“”" is kept by the word trim and emptied by the span trim.
        let spans = Records::new("“” Ann")
            .add("“”", row(NAME, 0.9), 0.9)
            .add("Ann", row(PHONE, 0.9), 0.9)
            .spans();
        assert_eq!(spans, [("Ann", PHONE, 0.9)]);
    }

    #[test]
    fn confidence_stays_in_range() {
        let spans = Records::new("Ann Lee Kim")
            .add("Ann", row(NAME, 1.0), 1.0)
            .add("Lee", row(NAME, 1.0), 0.0)
            .add("Kim", row(NAME, 1.0), 0.0)
            .spans();
        assert_eq!(spans, [("Ann Lee Kim", NAME, 1.0)]);
    }
}
