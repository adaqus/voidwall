//! Structured body parsing for content-aware PII scanning.
//!
//! Each parser produces a `Vec<OwnedContextFragment>` — context/value/offset
//! triples that the scanner can pair with `voidwall_pii::ContextFragment` for
//! `Scanner::mark_piis_structured`. The byte offsets are document-absolute, so
//! a span from one fragment is directly comparable with a span from another.
//! Overlap resolution and the resolved match count are defined over those
//! spans, so fragment-local offsets would make two unrelated values look like
//! they overlap.
//!
//! Submodules:
//! - [`json`] — `application/json` flattener
//! - [`csv`] — `text/csv` and `text/tab-separated-values` parser
//! - [`chat_completions`] — the fields of Chat Completions messages and tools
//!   to scan, selected from the [`json`] fragments
//! - [`litellm`] — the LiteLLM Generic Guardrail API payload
//! - [`openai_chat`] — OpenAI Chat Completions bodies on a reverse proxy route
//! - [`sse`] — `text/event-stream` framer
//! - [`openai_chat_stream`] — Chat Completions stream chunks and the joined
//!   text of each choice and field
//! - (future) per-format dispatch keyed off Content-Type

pub mod chat_completions;
pub mod csv;
pub mod json;
pub mod litellm;
pub mod openai_chat;
pub mod openai_chat_stream;
pub mod sse;

use std::ops::Range;

/// One string value emitted by a structured-body parser, with its context
/// and its place in the document. Owned so the raw body buffer can be released
/// before the scanner runs.
///
/// `offset` is the document position of the value's first raw byte. A guard
/// reports a span as `offset` plus a position in `value`; the engine maps it
/// through `view` and then through `escapes` to the raw bytes, with
/// [`OwnedContextFragment::raw_range`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedContextFragment {
    pub context: String,
    pub value: String,
    pub offset: usize,
    /// Where the escape sequences of the value sit in the raw document. Empty
    /// for a value with none, and for a fragment built by hand.
    pub escapes: EditMap,
    /// Where a view in `value` (the scan view or the decoded view) differs
    /// from the escape-decoded value. Empty unless `value` is a view that a
    /// rule or a decoded run changed.
    pub view: EditMap,
}

impl OwnedContextFragment {
    /// A fragment whose value is its raw bytes: no escape sequence, so the map
    /// is the identity. For a parser without escapes and a fragment built by
    /// hand.
    pub fn plain(context: String, value: String, offset: usize) -> Self {
        Self {
            context,
            value,
            offset,
            escapes: EditMap::default(),
            view: EditMap::default(),
        }
    }

    /// The document range that `span` was decoded from, or `None` when `span`
    /// does not lie inside this fragment's value. `span` is `offset` plus a
    /// range of positions in `value`. It maps through the view's edits first
    /// and the escape sequences second; a character that came from an escape
    /// sequence maps to the whole sequence.
    pub fn raw_range(&self, span: Range<usize>) -> Option<Range<usize>> {
        if span.start > span.end
            || span.start < self.offset
            || span.end > self.offset + self.value.len()
        {
            return None;
        }
        let local = self
            .view
            .raw_range(span.start - self.offset..span.end - self.offset);
        let raw = self.escapes.raw_range(local);
        Some(self.offset + raw.start..self.offset + raw.end)
    }
}

/// The edits that turn a text into another one, in order: for each, where
/// its result sits in the edited text (the view) and where the bytes it
/// replaced sit in the source. Between two edits the two texts are equal byte
/// for byte. A JSON escape sequence is one edit; so is a character that the
/// scan view removes (`view_len` 0) or replaces.
///
/// It holds positions and lengths only, so its `Debug` prints no scanned
/// content. An empty map allocates nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EditMap(Vec<Edit>);

/// One edit. Positions count from the start of the text: `view` in the
/// edited text, `raw` in the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Edit {
    view: usize,
    raw: usize,
    /// 0 when the edit removed its source bytes.
    view_len: usize,
    raw_len: usize,
}

impl Edit {
    fn view_end(self) -> usize {
        self.view + self.view_len
    }

    fn raw_end(self) -> usize {
        self.raw + self.raw_len
    }
}

impl EditMap {
    /// Add the next edit: its result starts at `view` in the edited text, and
    /// the bytes it replaced at `raw` in the source. Edits are added in
    /// order. A removal directly after another removal extends it.
    pub(crate) fn push(&mut self, view: usize, raw: usize, view_len: usize, raw_len: usize) {
        debug_assert!(
            self.0
                .last()
                .is_none_or(|e| e.view_end() <= view && e.raw_end() <= raw),
            "edits are added in order"
        );
        if let Some(last) = self.0.last_mut()
            && view_len == 0
            && last.view_len == 0
            && last.view == view
            && last.raw_end() == raw
        {
            last.raw_len += raw_len;
            return;
        }
        self.0.push(Edit {
            view,
            raw,
            view_len,
            raw_len,
        });
    }

    /// Whether the edited text equals its source.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The map of a text edited twice: `self` maps a middle text to the
    /// source, `second` maps the final text to the middle text, and the
    /// result maps the final text to the source in one step (design D6 of
    /// `decode-base64-hex`). One linear merge of the two edit lists.
    ///
    /// Edits of the two maps whose middle ranges overlap become one edit
    /// that covers all of them. A removal of `self` at the edge of an edit of
    /// `second` stays a removal of its own, so it stays outside a span that
    /// ends or starts there. The result maps a span as the two maps do in
    /// turn, as long as no edit of `self` with a result of more than one
    /// byte crosses an edge of an edit of `second`. The scan view never makes
    /// one: a decoded tag or selector run is spaced on both sides, so a
    /// base64 run lies inside it or outside it.
    pub(crate) fn compose(&self, second: &EditMap) -> EditMap {
        let (first, second) = (&self.0, &second.0);
        // The range of an edit in the middle text.
        let mid_first = |e: &Edit| (e.view, e.view_end());
        let mid_second = |e: &Edit| (e.raw, e.raw_end());
        let mut out = EditMap::default();
        let (mut i, mut j) = (0, 0);
        // The end of the last edit taken from each map: its middle position,
        // and its source position (for `self`) or final position (for
        // `second`). Between edits a map is the identity, so these place any
        // middle position that no later edit holds.
        let (mut first_mid, mut first_raw) = (0, 0);
        let (mut second_mid, mut second_view) = (0, 0);
        while i < first.len() || j < second.len() {
            // A group starts with the edit that starts first in the middle
            // text; on a tie, with the edit of `self`, so that a removal there
            // stays a group of its own.
            let starts_first = match (first.get(i), second.get(j)) {
                (Some(a), Some(b)) => a.view <= b.raw,
                (a, _) => a.is_some(),
            };
            let (start, mut end) = if starts_first {
                mid_first(&first[i])
            } else {
                mid_second(&second[j])
            };
            let view = second_view + (start - second_mid);
            let raw = first_raw + (start - first_mid);
            // An edit joins a group that has a length when it overlaps the
            // group inside: a point strictly inside it, or a range that starts
            // before its end.
            let joins = |(s, e): (usize, usize), end: usize| {
                start < end
                    && if s == e {
                        start < s && s < end
                    } else {
                        s < end
                    }
            };
            let mut seed = true;
            loop {
                if let Some(a) = first.get(i)
                    && ((seed && starts_first) || (!seed && joins(mid_first(a), end)))
                {
                    end = end.max(a.view_end());
                    (first_mid, first_raw) = (a.view_end(), a.raw_end());
                    i += 1;
                } else if let Some(b) = second.get(j)
                    && ((seed && !starts_first) || (!seed && joins(mid_second(b), end)))
                {
                    end = end.max(b.raw_end());
                    (second_mid, second_view) = (b.raw_end(), b.view_end());
                    j += 1;
                } else {
                    break;
                }
                seed = false;
            }
            let view_end = second_view + (end - second_mid);
            let raw_end = first_raw + (end - first_mid);
            out.push(view, raw, view_end - view, raw_end - raw);
        }
        out
    }

    /// The source range that the edited range `span` came from: its start
    /// maps as a span start and its end as a span end, see [`EditMap::raw`].
    pub(crate) fn raw_range(&self, span: Range<usize>) -> Range<usize> {
        self.raw(span.start, false)..self.raw(span.end, true)
    }

    /// The source position of edited position `at`, for a span start or, when
    /// `end` is set, a span end.
    ///
    /// A position inside the result of an edit goes to the start of its
    /// source range, or to its end for a span end. A position at a removal
    /// goes past the removed bytes for a span start and before them for a
    /// span end, so a removed character at the edge of a span is outside it
    /// and two spans that meet at a removal still do not overlap.
    fn raw(&self, at: usize, end: bool) -> usize {
        // The edits that lie wholly before `at`. A removal at `at` counts for
        // a span start; a result that ends at `at` counts for both.
        let before = self.0.partition_point(|e| {
            if end {
                e.view_end() < at || (e.view_end() == at && e.view_len > 0)
            } else {
                e.view_end() <= at
            }
        });
        if let Some(&inside) = self.0.get(before)
            && inside.view < at
        {
            return if end { inside.raw_end() } else { inside.raw };
        }
        match before.checked_sub(1).map(|i| self.0[i]) {
            // Only unchanged bytes lie between the last edit and `at`.
            Some(last) => last.raw_end() + (at - last.view_end()),
            None => at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(value: &str, offset: usize, escapes: EditMap) -> OwnedContextFragment {
        OwnedContextFragment {
            context: String::new(),
            value: value.to_string(),
            offset,
            escapes,
            view: EditMap::default(),
        }
    }

    fn map(edits: &[(usize, usize, usize, usize)]) -> EditMap {
        let mut map = EditMap::default();
        for &(view, raw, view_len, raw_len) in edits {
            map.push(view, raw, view_len, raw_len);
        }
        map
    }

    #[test]
    fn an_empty_map_is_the_identity() {
        let f = fragment("abc", 10, EditMap::default());
        assert_eq!(f.raw_range(10..13), Some(10..13));
        assert_eq!(f.raw_range(11..12), Some(11..12));
    }

    #[test]
    fn a_span_outside_the_value_is_not_held() {
        let f = fragment("abc", 10, EditMap::default());
        assert_eq!(f.raw_range(9..11), None);
        assert_eq!(f.raw_range(12..14), None);
    }

    #[test]
    fn one_escape() {
        // Raw `a`, a six-byte escape of `@`, `b`; decoded `a@b`.
        let f = fragment("a@b", 0, map(&[(1, 1, 1, 6)]));
        assert_eq!(f.raw_range(0..1), Some(0..1), "before the escape");
        assert_eq!(f.raw_range(1..2), Some(1..7), "the escape");
        assert_eq!(f.raw_range(2..3), Some(7..8), "after the escape");
        assert_eq!(f.raw_range(0..3), Some(0..8), "the whole value");
    }

    #[test]
    fn a_surrogate_pair() {
        // Raw `x`, a twelve-byte pair, `y`; decoded `x`, 4 bytes, `y`.
        let f = fragment("x\u{1F600}y", 5, map(&[(1, 1, 4, 12)]));
        assert_eq!(f.raw_range(6..10), Some(6..18));
        assert_eq!(f.raw_range(10..11), Some(18..19));
        // A position inside the character goes to the start or the end of the
        // sequence.
        assert_eq!(f.raw_range(7..9), Some(6..18));
    }

    #[test]
    fn adjacent_escapes() {
        // Raw `\n\t` then `z`; decoded a newline, a tab, `z`.
        let f = fragment("\n\tz", 0, map(&[(0, 0, 1, 2), (1, 2, 1, 2)]));
        assert_eq!(f.raw_range(0..1), Some(0..2));
        assert_eq!(f.raw_range(1..2), Some(2..4));
        assert_eq!(f.raw_range(0..2), Some(0..4));
        assert_eq!(f.raw_range(2..3), Some(4..5));
    }

    #[test]
    fn the_debug_output_holds_positions_only() {
        let printed = format!("{:?}", map(&[(1, 1, 1, 6)]));
        assert_eq!(
            printed,
            "EditMap([Edit { view: 1, raw: 1, view_len: 1, raw_len: 6 }])"
        );
    }

    // --- Removal edits (view_len 0) and replacements ---

    /// Raw `ab`, two removed bytes, `cd`; edited `abcd`.
    fn one_removal() -> EditMap {
        map(&[(2, 2, 0, 2)])
    }

    #[test]
    fn a_removal_inside_a_span_is_inside_its_range() {
        assert_eq!(one_removal().raw_range(1..3), 1..5);
        assert_eq!(one_removal().raw_range(0..4), 0..6);
    }

    #[test]
    fn a_removal_at_a_span_start_is_outside_its_range() {
        assert_eq!(one_removal().raw_range(2..4), 4..6);
    }

    #[test]
    fn a_removal_at_a_span_end_is_outside_its_range() {
        assert_eq!(one_removal().raw_range(0..2), 0..2);
    }

    #[test]
    fn two_spans_that_meet_at_a_removal_do_not_overlap() {
        let (first, second) = (one_removal().raw_range(0..2), one_removal().raw_range(2..4));
        assert!(first.end <= second.start, "{first:?} and {second:?}");
    }

    #[test]
    fn a_removal_at_the_start_and_at_the_end_of_the_text() {
        // Raw: 2 removed bytes, `ab`, 3 removed bytes; edited `ab`.
        let edits = map(&[(0, 0, 0, 2), (2, 4, 0, 3)]);
        assert_eq!(edits.raw_range(0..2), 2..4);
        assert_eq!(edits.raw_range(0..1), 2..3);
    }

    #[test]
    fn a_replacement_with_a_result() {
        // Raw `a`, 3 bytes folded to 1, `b`; edited `aXb`.
        let edits = map(&[(1, 1, 1, 3)]);
        assert_eq!(edits.raw_range(0..1), 0..1);
        assert_eq!(edits.raw_range(1..2), 1..4);
        assert_eq!(edits.raw_range(2..3), 4..5);
        assert_eq!(edits.raw_range(0..3), 0..5);
    }

    #[test]
    fn a_span_start_and_end_inside_a_replacement_cover_all_of_it() {
        // Raw `x`, a run of 40 bytes decoded to 9, `y`.
        let edits = map(&[(1, 1, 9, 40)]);
        assert_eq!(edits.raw_range(3..7), 1..41);
        assert_eq!(edits.raw_range(2..4), edits.raw_range(5..8));
    }

    #[test]
    fn adjacent_edits() {
        // Raw: a removal of 2, a replacement of 3 by 1, a removal of 2, then
        // a replacement of 4 by 2; edited one character, then two.
        let edits = map(&[(0, 0, 0, 2), (0, 2, 1, 3), (1, 5, 0, 2), (1, 7, 2, 4)]);
        assert_eq!(edits.raw_range(0..1), 2..5);
        assert_eq!(edits.raw_range(1..3), 7..11);
        assert_eq!(edits.raw_range(0..3), 2..11);
    }

    #[test]
    fn a_removal_after_a_removal_extends_it() {
        let edits = map(&[(2, 2, 0, 2), (2, 4, 0, 3)]);
        assert_eq!(edits, map(&[(2, 2, 0, 5)]));
    }

    // --- Composed maps ---

    #[test]
    fn composing_with_an_empty_map_keeps_the_other() {
        let edits = map(&[(1, 1, 0, 2), (3, 5, 1, 3)]);
        assert_eq!(EditMap::default().compose(&edits), edits);
        assert_eq!(edits.compose(&EditMap::default()), edits);
    }

    /// Source: `x`, 2 removed bytes, a run of 4 bytes, 2 removed bytes, 6
    /// more bytes of the run, `y`. The middle text drops the removed bytes;
    /// the final text decodes the run of 10 middle bytes to 7.
    #[test]
    fn a_removal_inside_an_edit_joins_it_and_one_at_its_edge_does_not() {
        let first = map(&[(1, 1, 0, 2), (5, 7, 0, 2)]);
        let second = map(&[(1, 1, 7, 10)]);
        let composed = first.compose(&second);
        assert_eq!(composed, map(&[(1, 1, 0, 2), (1, 3, 7, 12)]));
        assert_eq!(composed.raw_range(2..4), 3..15, "inside the run");
        assert_eq!(
            composed.raw_range(1..8),
            3..15,
            "the removal before is outside"
        );
        assert_eq!(composed.raw_range(8..9), 15..16);
    }

    /// A span maps through the scan view's edits and then through the escape
    /// sequences: here a removed `­` inside and at the edge of a span.
    #[test]
    fn a_fragment_chains_its_two_maps() {
        // Raw `1­2` at offset 10: decoded `1`, U+00AD, `2`; viewed `12`.
        let mut f = fragment("12", 10, map(&[(1, 1, 2, 6)]));
        f.view = map(&[(1, 1, 0, 2)]);
        assert_eq!(f.raw_range(10..12), Some(10..18), "the escape inside");
        assert_eq!(f.raw_range(11..12), Some(17..18), "the escape before");
        assert_eq!(f.raw_range(10..11), Some(10..11), "the escape after");
    }
}
