//! The dataset row model and the offsets that annotations and predictions meet in.

use serde::Deserialize;

/// One annotated span from `privacy_mask`. Offsets are characters; `value` is the
/// literal text, used to check and repair the offsets.
#[derive(Debug, Clone, Deserialize)]
pub struct MaskSpan {
    pub label: String,
    #[serde(default)]
    pub start: usize,
    #[serde(default)]
    pub end: usize,
    #[serde(default)]
    pub value: String,
}

/// A dataset row. Unknown fields are ignored.
#[derive(Debug, Deserialize)]
pub struct Row {
    #[serde(alias = "unmasked_text")]
    pub source_text: String,
    #[serde(default, deserialize_with = "de_privacy_mask")]
    pub privacy_mask: Vec<MaskSpan>,
    #[serde(default)]
    pub language: Option<String>,
}

/// Accepts `privacy_mask` as a JSON array or as a JSON string that holds the
/// array, which older dumps write.
fn de_privacy_mask<'de, D>(de: D) -> Result<Vec<MaskSpan>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Shim {
        List(Vec<MaskSpan>),
        Str(String),
        Null,
    }
    match Shim::deserialize(de)? {
        Shim::List(v) => Ok(v),
        Shim::Str(s) => serde_json::from_str(&s).map_err(D::Error::custom),
        Shim::Null => Ok(Vec::new()),
    }
}

/// Resolves an annotation to `(start, end)` character offsets in `text`.
///
/// Trusts the offsets when the slice equals `value`. Otherwise tries them as
/// byte offsets, then searches for `value`, then clamps the raw offsets so the
/// annotation still counts toward recall.
pub fn resolve_annotation(text: &str, chars: &[char], m: &MaskSpan) -> (usize, usize) {
    if m.start <= m.end && m.end <= chars.len() {
        let slice: String = chars[m.start..m.end].iter().collect();
        if m.value.is_empty() || slice == m.value {
            return (m.start, m.end);
        }
    }
    if !m.value.is_empty()
        && m.start <= m.end
        && m.end <= text.len()
        && text.is_char_boundary(m.start)
        && text.is_char_boundary(m.end)
        && text[m.start..m.end] == m.value
    {
        let cs = text[..m.start].chars().count();
        return (cs, cs + m.value.chars().count());
    }
    if !m.value.is_empty()
        && let Some(byte_pos) = text.find(&m.value)
    {
        let cs = text[..byte_pos].chars().count();
        return (cs, cs + m.value.chars().count());
    }
    let s = m.start.min(chars.len());
    (s, m.end.clamp(s, chars.len()))
}

/// Maps each byte offset of `text` (and `text.len()`) to a character offset, in
/// one pass. A byte inside a multi-byte character maps to that character.
pub struct CharIndex(Vec<usize>);

impl CharIndex {
    pub fn new(text: &str) -> Self {
        let mut map = Vec::with_capacity(text.len() + 1);
        for (ci, (_, c)) in text.char_indices().enumerate() {
            map.extend(std::iter::repeat_n(ci, c.len_utf8()));
        }
        map.push(text.chars().count());
        CharIndex(map)
    }

    pub fn char_at(&self, byte: usize) -> usize {
        self.0[byte.min(self.0.len() - 1)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(start: usize, end: usize, value: &str) -> MaskSpan {
        MaskSpan {
            label: "EMAIL".into(),
            start,
            end,
            value: value.into(),
        }
    }

    #[test]
    fn privacy_mask_as_array() {
        let row: Row = serde_json::from_str(
            r#"{"source_text":"a","privacy_mask":[{"label":"EMAIL","start":0,"end":1,"value":"a"}],"language":"English"}"#,
        )
        .unwrap();
        assert_eq!(row.privacy_mask.len(), 1);
        assert_eq!(row.language.as_deref(), Some("English"));
    }

    #[test]
    fn privacy_mask_as_string() {
        let row: Row = serde_json::from_str(
            r#"{"source_text":"a","privacy_mask":"[{\"label\":\"TEL\",\"start\":0,\"end\":1,\"value\":\"a\"}]"}"#,
        )
        .unwrap();
        assert_eq!(row.privacy_mask[0].label, "TEL");
        assert_eq!(row.language, None);
    }

    #[test]
    fn unknown_fields_and_alias() {
        let row: Row = serde_json::from_str(
            r#"{"unmasked_text":"a","privacy_mask":null,"mbert_bio_labels":[],"set":"train"}"#,
        )
        .unwrap();
        assert_eq!(row.source_text, "a");
        assert!(row.privacy_mask.is_empty());
    }

    #[test]
    fn trusts_char_offsets() {
        let text = "hello user@example.com world";
        let chars: Vec<char> = text.chars().collect();
        assert_eq!(
            resolve_annotation(text, &chars, &span(6, 22, "user@example.com")),
            (6, 22)
        );
    }

    #[test]
    fn falls_back_to_byte_offsets() {
        let text = "Café user@example.com";
        let chars: Vec<char> = text.chars().collect();
        let b = text.find("user@").unwrap();
        let (s, e) = resolve_annotation(text, &chars, &span(b, b + 16, "user@example.com"));
        assert_eq!(chars[s..e].iter().collect::<String>(), "user@example.com");
        assert_eq!((s, e), (5, 21));
    }

    #[test]
    fn falls_back_to_search() {
        let text = "hello user@example.com world";
        let chars: Vec<char> = text.chars().collect();
        assert_eq!(
            resolve_annotation(text, &chars, &span(999, 1001, "user@example.com")),
            (6, 22)
        );
    }

    #[test]
    fn falls_back_to_clamp() {
        let text = "hello";
        let chars: Vec<char> = text.chars().collect();
        assert_eq!(
            resolve_annotation(text, &chars, &span(3, 99, "absent")),
            (3, 5)
        );
    }

    #[test]
    fn char_index_after_multibyte() {
        // 'é' and 'ż' are two bytes, '😀' is four.
        let text = "é ż 😀 user@example.com";
        let idx = CharIndex::new(text);
        let b = text.find("user@").unwrap();
        assert_eq!(idx.char_at(b), 6);
        assert_eq!(idx.char_at(text.len()), text.chars().count());
        assert_eq!(idx.char_at(1), 0);
    }
}
