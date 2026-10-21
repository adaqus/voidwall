//! The one text a model guard scores for a unit, and the way from a span of
//! that text back to the unit's bytes (D4).
//!
//! ```text
//! plain       b"ab\xffcd"            ─► "ab\u{FFFD}cd"
//!             pieces  text 0..2 ─► 0..2   text 2..5 ─► 2..3 (replaced)   text 5..7 ─► 3..5
//!
//! fragments   "Ann" at 7, "Lee" at 21 ─► "Ann\nLee"
//!             pieces  text 0..3 ─► 7..10   text 4..7 ─► 21..24   boundary 3
//! ```
//!
//! A piece is a run of text that came from one run of the unit's bytes. The
//! pieces of one segment are adjacent in the text and in the source, so a
//! span inside one segment maps to one contiguous source range. A plain-text
//! unit is one segment; each fragment value is its own, and the newline that
//! joins two values is a boundary the decoder never merges across.

use std::borrow::Cow;
use std::ops::Range;

use voidwall_ml::Boundaries;

use crate::structured::OwnedContextFragment;

use super::finding::Span;
use super::unit::UnitContent;

/// The text of one unit, its pieces, and its hard boundaries.
pub(crate) struct UnitText<'a> {
    text: Cow<'a, str>,
    /// Sorted by text position, never empty, never overlapping.
    pieces: Vec<Piece>,
    boundaries: Boundaries,
}

/// A run of text bytes that came from one run of source bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Piece {
    text: Range<usize>,
    source: Range<usize>,
    /// The U+FFFD that replaced the invalid bytes `source`. Only its two
    /// edges map; a position inside it is not a character boundary.
    replaced: bool,
    segment: usize,
}

impl<'a> UnitText<'a> {
    pub(crate) fn new(content: &'a UnitContent) -> Self {
        match content {
            UnitContent::PlainText(bytes) => Self::plain(bytes),
            UnitContent::Structured { fragments } => Self::fragments(fragments),
        }
    }

    /// The bytes decoded as UTF-8, each invalid sequence replaced by one
    /// U+FFFD, as `String::from_utf8_lossy` does.
    fn plain(bytes: &'a [u8]) -> Self {
        let mut pieces = Vec::new();
        let mut push = |text: Range<usize>, source: Range<usize>, replaced: bool| {
            if !source.is_empty() {
                pieces.push(Piece {
                    text,
                    source,
                    replaced,
                    segment: 0,
                });
            }
        };
        let text = match std::str::from_utf8(bytes) {
            // Valid UTF-8 is one piece, borrowed.
            Ok(valid) => {
                push(0..valid.len(), 0..valid.len(), false);
                Cow::Borrowed(valid)
            }
            Err(_) => {
                let mut text = String::with_capacity(bytes.len());
                let mut source = 0;
                for chunk in bytes.utf8_chunks() {
                    for (part, len, replaced) in [
                        (chunk.valid(), chunk.valid().len(), false),
                        ("\u{FFFD}", chunk.invalid().len(), true),
                    ] {
                        if len > 0 {
                            let start = text.len();
                            text.push_str(part);
                            push(start..text.len(), source..source + len, replaced);
                            source += len;
                        }
                    }
                }
                Cow::Owned(text)
            }
        };
        Self {
            text,
            pieces,
            boundaries: Boundaries::default(),
        }
    }

    /// The values in document order, joined with a newline; keys are left
    /// out. Each join is a boundary.
    fn fragments(fragments: &[OwnedContextFragment]) -> Self {
        let mut ordered: Vec<_> = fragments.iter().collect();
        ordered.sort_by_key(|f| f.offset);
        let mut text = String::new();
        let mut pieces = Vec::new();
        let mut joins = Vec::new();
        for (segment, fragment) in ordered.into_iter().enumerate() {
            if segment > 0 {
                joins.push(text.len());
                text.push('\n');
            }
            let start = text.len();
            text.push_str(&fragment.value);
            if !fragment.value.is_empty() {
                pieces.push(Piece {
                    text: start..text.len(),
                    source: fragment.offset..fragment.offset + fragment.value.len(),
                    replaced: false,
                    segment,
                });
            }
        }
        Self {
            text: Cow::Owned(text),
            pieces,
            boundaries: joins.into_iter().collect(),
        }
    }

    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    pub(crate) fn boundaries(&self) -> &Boundaries {
        &self.boundaries
    }

    /// The unit bytes that the text bytes `bytes` came from. `None` when the
    /// range is empty, leaves one segment, or cuts a U+FFFD: a decoded span
    /// does none of these.
    pub(crate) fn source(&self, bytes: Range<usize>) -> Option<Span> {
        if bytes.is_empty() {
            return None;
        }
        let first = &self.pieces[self.pieces.partition_point(|p| p.text.end <= bytes.start)..];
        let first = first.first()?;
        let last = self
            .pieces
            .get(self.pieces.partition_point(|p| p.text.end < bytes.end))?;
        if first.segment != last.segment
            || bytes.start < first.text.start
            || bytes.end <= last.text.start
        {
            return None;
        }
        let start = if first.replaced {
            (bytes.start == first.text.start).then_some(first.source.start)?
        } else {
            first.source.start + (bytes.start - first.text.start)
        };
        let end = if last.replaced {
            (bytes.end == last.text.end).then_some(last.source.end)?
        } else {
            last.source.start + (bytes.end - last.text.start)
        };
        Some(Span::new(start, end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use proptest::prelude::*;
    use test_case::test_case;

    fn plain(bytes: &[u8]) -> UnitContent {
        UnitContent::PlainText(Bytes::copy_from_slice(bytes))
    }

    fn fragment(value: &str, offset: usize) -> OwnedContextFragment {
        OwnedContextFragment {
            context: "k".into(),
            value: value.into(),
            offset,
        }
    }

    #[test_case(b"" ; "empty")]
    #[test_case(b"plain text" ; "ascii")]
    #[test_case(b"za\xc5\xbc\xc3\xb3\xc5\x82\xc4\x87" ; "multi byte")]
    #[test_case(b"a\xffb\xe2\x82c\xf0\x9f" ; "invalid sequences")]
    fn plain_text_is_decoded_as_from_utf8_lossy(bytes: &[u8]) {
        let content = plain(bytes);
        assert_eq!(
            UnitText::new(&content).text(),
            String::from_utf8_lossy(bytes)
        );
    }

    #[test]
    fn valid_plain_text_is_borrowed() {
        let content = plain(b"plain text");
        assert!(matches!(UnitText::new(&content).text, Cow::Borrowed(_)));
    }

    #[test]
    fn a_span_after_an_invalid_byte_maps_to_its_source_bytes() {
        // "ab\xffcd": the text is "ab\u{FFFD}cd", 7 bytes for 5.
        let content = plain(b"ab\xffcd");
        let text = UnitText::new(&content);
        assert_eq!(text.source(5..7), Some(Span::new(3, 5)));
        assert_eq!(text.source(2..5), Some(Span::new(2, 3)), "the U+FFFD");
        assert_eq!(text.source(0..7), Some(Span::new(0, 5)));
        assert_eq!(text.source(3..7), None, "inside the U+FFFD");
    }

    #[test]
    fn structured_values_are_joined_in_document_order() {
        let content = UnitContent::Structured {
            fragments: vec![fragment("second", 20), fragment("first", 5)],
        };
        let text = UnitText::new(&content);
        assert_eq!(text.text(), "first\nsecond");
        assert_eq!(text.boundaries().as_slice(), [5]);
    }

    #[test]
    fn a_span_in_a_value_maps_to_its_document_absolute_bytes() {
        // {"a":"Ann","b":"Lee"}: "Ann" at 6, "Lee" at 16.
        let content = UnitContent::Structured {
            fragments: vec![fragment("Ann", 6), fragment("Lee", 16)],
        };
        let text = UnitText::new(&content);
        assert_eq!(text.source(4..7), Some(Span::new(16, 19)));
        assert_eq!(text.source(0..3), Some(Span::new(6, 9)));
        assert_eq!(text.source(0..7), None, "two values are two segments");
        assert_eq!(text.source(3..4), None, "the join maps to nothing");
    }

    #[test]
    fn an_empty_value_adds_a_join_and_no_piece() {
        let content = UnitContent::Structured {
            fragments: vec![fragment("Ann", 2), fragment("", 10), fragment("Lee", 20)],
        };
        let text = UnitText::new(&content);
        assert_eq!(text.text(), "Ann\n\nLee");
        assert_eq!(text.boundaries().as_slice(), [3, 4]);
        assert_eq!(text.source(5..8), Some(Span::new(20, 23)));
    }

    #[test]
    fn an_empty_range_maps_to_nothing() {
        let content = plain(b"abc");
        assert_eq!(UnitText::new(&content).source(1..1), None);
    }

    /// The char boundaries of `text` in `range`, ends included.
    fn char_boundaries(text: &str, range: Range<usize>) -> Vec<usize> {
        range.filter(|&i| text.is_char_boundary(i)).collect()
    }

    /// Valid text with multi-byte characters, and bytes that are often not
    /// valid UTF-8, in any order.
    fn unit_bytes() -> impl Strategy<Value = Vec<u8>> {
        let part = prop_oneof![
            "(?s).{0,6}".prop_map(String::into_bytes),
            prop::collection::vec(any::<u8>(), 1..4),
        ];
        prop::collection::vec(part, 0..6).prop_map(|parts| parts.concat())
    }

    proptest! {
        /// Every text range of a plain unit maps to source bytes that decode
        /// to the same text.
        #[test]
        fn a_plain_range_maps_to_bytes_that_decode_to_it(bytes in unit_bytes()) {
            let content = plain(&bytes);
            let text = UnitText::new(&content);
            let s = text.text();
            let ends = char_boundaries(s, 0..s.len() + 1);
            for (i, &a) in ends.iter().enumerate() {
                for &b in &ends[i + 1..] {
                    let span = text.source(a..b).expect("one segment maps");
                    prop_assert_eq!(
                        String::from_utf8_lossy(&bytes[span.start..span.end]),
                        &s[a..b]
                    );
                }
            }
        }

        /// Every text range inside one value maps to the document bytes of
        /// that range; a range that leaves the value maps to nothing.
        #[test]
        fn a_fragment_range_maps_to_its_document_bytes(
            values in prop::collection::vec("(?s).{0,6}", 0..6),
        ) {
            // A document holding each value between quotes, given to the unit
            // in reverse order, so document order is rebuilt from the offsets.
            let mut document = Vec::new();
            let mut fragments = Vec::new();
            for value in &values {
                document.extend_from_slice(b"\"k\":\"");
                fragments.push(fragment(value, document.len()));
                document.extend_from_slice(value.as_bytes());
                document.extend_from_slice(b"\",");
            }
            fragments.reverse();
            let content = UnitContent::Structured { fragments };
            let text = UnitText::new(&content);
            let s = text.text();
            prop_assert_eq!(s, values.join("\n"));

            let mut start = 0;
            for value in &values {
                let ends = char_boundaries(s, start..start + value.len() + 1);
                for (i, &a) in ends.iter().enumerate() {
                    for &b in &ends[i + 1..] {
                        let span = text.source(a..b).expect("one value maps");
                        prop_assert_eq!(&document[span.start..span.end], &s.as_bytes()[a..b]);
                    }
                }
                if start > 0 && !value.is_empty() {
                    // From the value before, across the join.
                    prop_assert_eq!(text.source(start - 1..start + value.len()), None);
                }
                start += value.len() + 1;
            }
        }
    }
}
