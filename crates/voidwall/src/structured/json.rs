//! JSON body flattener.
//!
//! Walks a JSON document and emits one fragment per string value. Parsing
//! and validation are delegated to `serde_json` (with the `preserve_order`
//! feature, so object iteration follows document order). Byte offsets —
//! which `Value` does not preserve — are recovered with a single linear
//! scan over the raw bytes that records the position of every quoted string
//! in the document. The structural walk consumes one recorded position per
//! object key and per string value, in order, which pairs them with the
//! corresponding `Value` nodes.
//!
//! The pairing holds only when the tree keeps every string of the raw bytes.
//! `serde_json` keeps one entry for a repeated key, so a document in which an
//! object holds a key twice is refused as one that does not parse.

use std::fmt::Write as _;

use serde_json::Value;

use super::{EscapeMap, OwnedContextFragment};
use crate::error::Error;

/// Walk a JSON document and emit one fragment per string value.
///
/// `value` is the decoded string, as a JSON parser reads it: every escape
/// sequence is resolved once. `offset` is the position of the first raw byte
/// after the opening quote, and `escapes` maps positions in `value` back to
/// the raw bytes. Numbers, booleans, and `null` are skipped. A document in
/// which an object holds a key twice is an error, as invalid JSON is.
pub fn flatten_json(raw: &[u8]) -> Result<Vec<OwnedContextFragment>, Error> {
    let mut positions = Vec::new();
    let value = parse(raw, |p| positions.push(p))?;

    let mut frags = Vec::new();
    let mut path = String::new();
    let mut cursor = 0usize;
    walk(value, raw, &positions, &mut cursor, &mut path, &mut frags)?;
    Ok(frags)
}

/// Parse a JSON document in which no object holds a key twice. Two keys are
/// the same when they are equal after their escapes are decoded. A repeated
/// key is the error that invalid JSON gives.
pub fn parse_unique(raw: &[u8]) -> Result<Value, Error> {
    parse(raw, |_| {})
}

/// Parse `raw`, and pass the content range of every quoted string in it to
/// `each`, in document order. The tree holds fewer keys and string values
/// than the raw bytes hold quoted strings exactly when an object holds a key
/// twice, at any depth.
fn parse(raw: &[u8], mut each: impl FnMut((usize, usize))) -> Result<Value, Error> {
    let value: Value =
        serde_json::from_slice(raw).map_err(|e| Error::Scanner(format!("invalid JSON: {e}")))?;
    let strings = scan_strings(raw, &mut each)?;
    if count_strings(&value) != strings {
        return Err(Error::Scanner(
            "invalid JSON: an object holds a key twice".into(),
        ));
    }
    Ok(value)
}

/// The keys and string values of `value`, counted at every depth.
fn count_strings(value: &Value) -> usize {
    match value {
        Value::Object(map) => map.values().map(|child| 1 + count_strings(child)).sum(),
        Value::Array(items) => items.iter().map(count_strings).sum(),
        Value::String(_) => 1,
        _ => 0,
    }
}

/// The escape map of one string, from its raw content bytes. `serde_json` has
/// validated them, so each backslash starts a well-formed sequence and a high
/// surrogate is followed by its low half. `decoded_len` is the byte length
/// of the decoded value; a map that does not end there is an internal error.
fn escape_map(raw: &[u8], decoded_len: usize) -> Result<EscapeMap, Error> {
    let mut map = EscapeMap::default();
    // Every byte before the first backslash is copied as it is.
    let Some(first) = raw.iter().position(|&b| b == b'\\') else {
        return Ok(map);
    };
    let internal = || Error::Scanner("internal: a JSON escape does not match its value".into());
    let (mut at, mut decoded) = (first, first);
    while at < raw.len() {
        if raw[at] != b'\\' {
            at += 1;
            decoded += 1;
            continue;
        }
        let (char_len, seq_len) = match raw.get(at + 1) {
            Some(b'u') => {
                let unit = hex4(raw, at + 2).ok_or_else(internal)?;
                if (0xD800..0xDC00).contains(&unit) {
                    // A surrogate pair: one character outside the BMP.
                    (4, 12)
                } else {
                    let c = char::from_u32(unit).ok_or_else(internal)?;
                    (c.len_utf8() as u8, 6)
                }
            }
            Some(_) => (1, 2),
            None => return Err(internal()),
        };
        map.push(decoded, at, char_len, seq_len);
        at += usize::from(seq_len);
        decoded += usize::from(char_len);
    }
    if at != raw.len() || decoded != decoded_len {
        return Err(internal());
    }
    Ok(map)
}

/// The four hex digits of a `\uXXXX` escape that start at `at`.
fn hex4(raw: &[u8], at: usize) -> Option<u32> {
    let digits = std::str::from_utf8(raw.get(at..at + 4)?).ok()?;
    u32::from_str_radix(digits, 16).ok()
}

/// Pass `(content_start, content_end)` of every quoted string in `raw` to
/// `each`, in document order, and return how many there are. Both object
/// keys and string values are included; the structural walk distinguishes
/// them by consuming one position per key and one per leaf string value.
fn scan_strings(raw: &[u8], mut each: impl FnMut((usize, usize))) -> Result<usize, Error> {
    let mut count = 0usize;
    let mut i = 0;
    while i < raw.len() {
        if raw[i] != b'"' {
            i += 1;
            continue;
        }
        let start = i + 1;
        i += 1;
        loop {
            if i >= raw.len() {
                return Err(Error::Scanner("unterminated JSON string".into()));
            }
            match raw[i] {
                b'\\' => {
                    // Skip the escape introducer plus the next byte. `\uXXXX`
                    // hex digits cannot be quote or backslash, so the loop
                    // walks past them naturally on subsequent iterations.
                    i += 2;
                    if i > raw.len() {
                        return Err(Error::Scanner("unterminated escape".into()));
                    }
                }
                b'"' => {
                    each((start, i));
                    count += 1;
                    i += 1;
                    break;
                }
                _ => i += 1,
            }
        }
    }
    Ok(count)
}

/// One step of a key path: an object key or an array index.
#[derive(Debug, Clone, Copy)]
pub enum PathSegment<'a> {
    Key(&'a str),
    Index(usize),
}

/// Append one segment to a key path: `.key` (no dot at the start) or `[i]`.
///
/// Every key path is built here, by the flattener and by any decoder that
/// selects fragments by path, so two builders cannot format a path apart.
pub fn push_path_segment(path: &mut String, segment: PathSegment<'_>) {
    match segment {
        PathSegment::Key(key) => {
            if !path.is_empty() {
                path.push('.');
            }
            path.push_str(key);
        }
        PathSegment::Index(i) => {
            write!(path, "[{i}]").expect("write to String never fails");
        }
    }
}

/// Consumes the tree, so each decoded string moves into its fragment.
fn walk(
    value: Value,
    raw: &[u8],
    positions: &[(usize, usize)],
    cursor: &mut usize,
    path: &mut String,
    frags: &mut Vec<OwnedContextFragment>,
) -> Result<(), Error> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                // Each object entry consumes one position for its key, then
                // recurses into the value.
                *cursor += 1;
                let saved = path.len();
                push_path_segment(path, PathSegment::Key(&key));
                walk(child, raw, positions, cursor, path, frags)?;
                path.truncate(saved);
            }
        }
        Value::Array(arr) => {
            for (i, child) in arr.into_iter().enumerate() {
                let saved = path.len();
                push_path_segment(path, PathSegment::Index(i));
                walk(child, raw, positions, cursor, path, frags)?;
                path.truncate(saved);
            }
        }
        Value::String(text) => {
            let (start, end) = positions.get(*cursor).copied().ok_or_else(|| {
                Error::Scanner(
                    "internal: ran out of string positions while walking JSON tree".into(),
                )
            })?;
            *cursor += 1;
            // The raw bytes are read only for the map; the value is the
            // string serde_json decoded.
            let escapes = escape_map(&raw[start..end], text.len())?;
            frags.push(OwnedContextFragment {
                context: path.clone(),
                value: text,
                offset: start,
                escapes,
            });
        }
        // Numbers, booleans, null produce no fragment.
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use test_case::test_case;

    fn ctx(c: &str, v: &str, o: usize) -> OwnedContextFragment {
        OwnedContextFragment::plain(c.to_string(), v.to_string(), o)
    }

    /// The JSON string content `raw` decodes to.
    fn decode(raw: &[u8]) -> String {
        serde_json::from_slice(&[b"\"", raw, b"\""].concat()).expect("one JSON string")
    }

    /// Verify that each fragment maps its whole value, and each character of
    /// it, to the raw bytes that decode to it, and that the value ends at the
    /// closing quote.
    fn check_offsets(raw: &[u8], frags: &[OwnedContextFragment]) {
        for f in frags {
            let whole = f
                .raw_range(f.offset..f.offset + f.value.len())
                .expect("the value lies in its fragment");
            assert_eq!(raw[whole.end], b'"', "fragment {f:?} ends at its quote");
            assert_eq!(decode(&raw[whole]), f.value, "fragment {f:?}");
            for (i, c) in f.value.char_indices() {
                let at = f.offset + i;
                let range = f.raw_range(at..at + c.len_utf8()).unwrap();
                assert_eq!(decode(&raw[range]), c.to_string(), "fragment {f:?} at {i}");
            }
        }
    }

    #[test]
    fn flat_object_one_string() {
        let raw = br#"{"phone": "555-1234"}"#;
        let frags = flatten_json(raw).unwrap();
        assert_eq!(frags, vec![ctx("phone", "555-1234", 11)]);
        check_offsets(raw, &frags);
    }

    #[test]
    fn nested_object_dot_path() {
        let raw = br#"{"a": {"b": "val"}}"#;
        let frags = flatten_json(raw).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].context, "a.b");
        assert_eq!(frags[0].value, "val");
        check_offsets(raw, &frags);
    }

    #[test]
    fn array_indexed_paths() {
        let raw = br#"{"x": ["a", "b"]}"#;
        let frags = flatten_json(raw).unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].context, "x[0]");
        assert_eq!(frags[0].value, "a");
        assert_eq!(frags[1].context, "x[1]");
        assert_eq!(frags[1].value, "b");
        check_offsets(raw, &frags);
    }

    #[test]
    fn nested_arrays() {
        let raw = br#"{"a": [["x"]]}"#;
        let frags = flatten_json(raw).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].context, "a[0][0]");
        assert_eq!(frags[0].value, "x");
        check_offsets(raw, &frags);
    }

    #[test]
    fn mixed_types_only_strings_emitted() {
        let raw = br#"{"s": "hello", "n": 42, "b": true, "z": null, "f": false}"#;
        let frags = flatten_json(raw).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].context, "s");
        assert_eq!(frags[0].value, "hello");
        check_offsets(raw, &frags);
    }

    #[test]
    fn empty_object() {
        let frags = flatten_json(b"{}").unwrap();
        assert!(frags.is_empty());
    }

    #[test]
    fn empty_array() {
        let frags = flatten_json(b"[]").unwrap();
        assert!(frags.is_empty());
    }

    #[test]
    fn invalid_json_returns_error() {
        assert!(flatten_json(b"{").is_err());
        assert!(flatten_json(b"{\"a\":}").is_err());
        assert!(flatten_json(b"not json").is_err());
        assert!(flatten_json(b"").is_err());
    }

    #[test]
    fn array_of_objects_keeps_document_order() {
        let raw = br#"{"users": [{"name": "Ada"}, {"name": "Bob"}]}"#;
        let frags = flatten_json(raw).unwrap();
        let contexts: Vec<&str> = frags.iter().map(|f| f.context.as_str()).collect();
        assert_eq!(contexts, vec!["users[0].name", "users[1].name"]);
        assert_eq!(frags[0].value, "Ada");
        assert_eq!(frags[1].value, "Bob");
        check_offsets(raw, &frags);
    }

    #[test]
    fn object_keys_iterate_in_document_order() {
        // Without preserve_order, BTreeMap would re-sort to {a, b, z}; this
        // test guards that the feature is enabled.
        let raw = br#"{"z": "first", "a": "second", "b": "third"}"#;
        let frags = flatten_json(raw).unwrap();
        assert_eq!(
            frags.iter().map(|f| f.context.clone()).collect::<Vec<_>>(),
            vec!["z", "a", "b"]
        );
        check_offsets(raw, &frags);
    }

    #[test]
    fn whitespace_between_tokens() {
        let raw = b"{\n  \"a\" : \"x\" ,\n  \"b\" : \"y\"\n}";
        let frags = flatten_json(raw).unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].context, "a");
        assert_eq!(frags[0].value, "x");
        assert_eq!(frags[1].context, "b");
        assert_eq!(frags[1].value, "y");
        check_offsets(raw, &frags);
    }

    /// pii-scanning, "A Unicode escape", "The two-character escapes", "An
    /// escaped backslash before the text of an escape", and "A surrogate pair".
    #[test_case(b"{\"s\": \"a\\u0040b\"}", "a@b" ; "a unicode escape")]
    #[test_case(b"{\"s\": \"\\\"\\\\\\/\\b\\f\\n\\r\\t\"}", "\"\\/\u{8}\u{c}\n\r\t" ; "the two-character escapes")]
    #[test_case(b"{\"s\": \"a\\\\u0040b\"}", "a\\u0040b" ; "an escaped backslash before the text of an escape")]
    #[test_case(b"{\"s\": \"x\\ud83d\\ude00y\"}", "x\u{1F600}y" ; "a surrogate pair")]
    fn an_escape_is_decoded(raw: &[u8], value: &str) {
        let frags = flatten_json(raw).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].value, value);
        assert_eq!(frags[0].offset, 7);
        check_offsets(raw, &frags);
    }

    /// pii-scanning, "An escaped key".
    #[test]
    fn an_escaped_key_is_decoded_in_the_context() {
        let raw = b"{\"\\u0065mail\": \"x\"}";
        let frags = flatten_json(raw).unwrap();
        assert_eq!(frags, vec![ctx("email", "x", 16)]);
        check_offsets(raw, &frags);
    }

    #[test]
    fn escapes_in_many_values_keep_each_offset() {
        let raw = "{\"a\": \"\\u00f3\\n\", \"b\": [\"\\u4e00x\", \"plain\", \"caf\u{e9}\\t\"]}"
            .as_bytes();
        let frags = flatten_json(raw).unwrap();
        let values: Vec<&str> = frags.iter().map(|f| f.value.as_str()).collect();
        assert_eq!(values, ["\u{f3}\n", "\u{4e00}x", "plain", "caf\u{e9}\t"]);
        assert_eq!(
            frags[2].escapes,
            EscapeMap::default(),
            "a plain value has no map"
        );
        check_offsets(raw, &frags);
    }

    /// pii-scanning, "A lone surrogate".
    #[test_case(b"{\"s\": \"abc \\ud800 def\"}" ; "a high surrogate alone")]
    #[test_case(b"{\"s\": \"abc \\udc00 def\"}" ; "a low surrogate alone")]
    #[test_case(b"{\"s\": \"\\ud800\\u0041\"}" ; "a high surrogate before another escape")]
    fn a_lone_surrogate_fails_to_parse(raw: &[u8]) {
        assert!(flatten_json(raw).is_err());
    }

    /// pii-scanning, "A duplicate key in a nested object", "A duplicate key
    /// written with an escape", and the duplicate at the top level.
    #[test_case(b"{\"a\": \"x\", \"a\": \"y\"}" ; "at the top level")]
    #[test_case(b"{\"l\": [{\"k\": \"1\", \"k\": \"2\"}]}" ; "in an object inside an array")]
    #[test_case(b"{\"a\": 1, \"a\": 2}" ; "with values that are not strings")]
    #[test_case(b"{\"a\": \"x\", \"\\u0061\": \"y\"}" ; "written with an escape")]
    fn a_duplicate_key_fails_to_parse(raw: &[u8]) {
        assert!(parse_unique(raw).is_err());
        assert!(flatten_json(raw).is_err());
    }

    #[test]
    fn the_same_key_in_two_objects_is_not_a_duplicate() {
        let raw = b"{\"a\": {\"a\": \"x\"}, \"b\": [{\"a\": \"a\"}, {\"a\": \"a\"}]}";
        assert!(parse_unique(raw).is_ok());
        let contexts: Vec<String> = flatten_json(raw)
            .unwrap()
            .into_iter()
            .map(|f| f.context)
            .collect();
        assert_eq!(contexts, ["a.a", "b[0].a", "b[1].a"]);
    }

    #[test]
    fn top_level_array_of_strings() {
        let raw = br#"["a", "bb"]"#;
        let frags = flatten_json(raw).unwrap();
        assert_eq!(
            frags.iter().map(|f| f.context.clone()).collect::<Vec<_>>(),
            vec!["[0]", "[1]"]
        );
        assert_eq!(frags[0].value, "a");
        assert_eq!(frags[1].value, "bb");
        check_offsets(raw, &frags);
    }

    #[test]
    fn top_level_string() {
        let raw = br#""hello""#;
        let frags = flatten_json(raw).unwrap();
        assert_eq!(frags, vec![ctx("", "hello", 1)]);
        check_offsets(raw, &frags);
    }

    #[test]
    fn four_segment_nested_path() {
        // Mix of object keys and an array index totalling four segments.
        let raw = br#"{"user": {"contact": {"phones": [{"primary": "555-123-4567"}]}}}"#;
        let frags = flatten_json(raw).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].context, "user.contact.phones[0].primary");
        assert_eq!(frags[0].value, "555-123-4567");
        check_offsets(raw, &frags);
    }

    #[test]
    fn utf8_multibyte_value() {
        // "café" is 5 bytes (`é` is two bytes); offsets must use bytes, not chars.
        let raw = "{\"k\": \"café\"}".as_bytes();
        let frags = flatten_json(raw).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].value, "café");
        check_offsets(raw, &frags);
    }
}
