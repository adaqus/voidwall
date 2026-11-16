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
/// reports a span as `offset` plus a position in the decoded `value`; the
/// engine maps it through `escapes` to the raw bytes, with
/// [`OwnedContextFragment::raw_range`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedContextFragment {
    pub context: String,
    pub value: String,
    pub offset: usize,
    /// Where the escape sequences of the value sit in the raw document. Empty
    /// for a value with none, and for a fragment built by hand.
    pub escapes: EscapeMap,
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
            escapes: EscapeMap::default(),
        }
    }

    /// The document range that `span` was decoded from, or `None` when `span`
    /// does not lie inside this fragment's value. `span` is `offset` plus a
    /// range of positions in `value`. A character that came from an escape
    /// sequence maps to the whole sequence.
    pub fn raw_range(&self, span: Range<usize>) -> Option<Range<usize>> {
        if span.start > span.end
            || span.start < self.offset
            || span.end > self.offset + self.value.len()
        {
            return None;
        }
        let (start, end) = (span.start - self.offset, span.end - self.offset);
        Some(
            self.offset + self.escapes.raw(start, false)..self.offset + self.escapes.raw(end, true),
        )
    }
}

/// The escape sequences of one JSON string value, in order: for each, where
/// its decoded character sits in the value and where the sequence sits in the
/// raw bytes. It holds positions and lengths only, so its `Debug` prints no
/// scanned content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EscapeMap(Vec<Escape>);

/// One escape sequence. Positions count from the start of the value: `decoded`
/// in the decoded value, `raw` in the raw bytes after the opening quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Escape {
    decoded: usize,
    raw: usize,
    /// 1 to 4 bytes of UTF-8.
    decoded_len: u8,
    /// 2 for `\n` and its kind, 6 for `\uXXXX`, 12 for a surrogate pair.
    raw_len: u8,
}

impl Escape {
    fn decoded_end(self) -> usize {
        self.decoded + usize::from(self.decoded_len)
    }

    fn raw_end(self) -> usize {
        self.raw + usize::from(self.raw_len)
    }
}

impl EscapeMap {
    /// Add the next sequence: its decoded character starts at `decoded` in
    /// the value, and the sequence at `raw` in the raw bytes. Sequences are
    /// added in order.
    pub(crate) fn push(&mut self, decoded: usize, raw: usize, decoded_len: u8, raw_len: u8) {
        debug_assert!(
            self.0
                .last()
                .is_none_or(|e| e.decoded_end() <= decoded && e.raw_end() <= raw),
            "escape sequences are added in order"
        );
        self.0.push(Escape {
            decoded,
            raw,
            decoded_len,
            raw_len,
        });
    }

    /// The raw position of decoded position `at`. A position inside the
    /// decoded character of a sequence goes to the start of the sequence, or
    /// to its end when `end` is set.
    fn raw(&self, at: usize, end: bool) -> usize {
        // The sequences whose decoded character ends at or before `at`.
        let before = self.0.partition_point(|e| e.decoded_end() <= at);
        if let Some(&inside) = self.0.get(before)
            && inside.decoded < at
        {
            return if end { inside.raw_end() } else { inside.raw };
        }
        match before.checked_sub(1).map(|i| self.0[i]) {
            // Only plain bytes lie between the last sequence and `at`.
            Some(last) => last.raw_end() + (at - last.decoded_end()),
            None => at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(value: &str, offset: usize, escapes: EscapeMap) -> OwnedContextFragment {
        OwnedContextFragment {
            context: String::new(),
            value: value.to_string(),
            offset,
            escapes,
        }
    }

    fn map(escapes: &[(usize, usize, u8, u8)]) -> EscapeMap {
        let mut map = EscapeMap::default();
        for &(decoded, raw, decoded_len, raw_len) in escapes {
            map.push(decoded, raw, decoded_len, raw_len);
        }
        map
    }

    #[test]
    fn an_empty_map_is_the_identity() {
        let f = fragment("abc", 10, EscapeMap::default());
        assert_eq!(f.raw_range(10..13), Some(10..13));
        assert_eq!(f.raw_range(11..12), Some(11..12));
    }

    #[test]
    fn a_span_outside_the_value_is_not_held() {
        let f = fragment("abc", 10, EscapeMap::default());
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
            "EscapeMap([Escape { decoded: 1, raw: 1, decoded_len: 1, raw_len: 6 }])"
        );
    }
}
