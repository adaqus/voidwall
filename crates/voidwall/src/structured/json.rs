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

use std::fmt::Write as _;

use serde_json::Value;

use super::OwnedContextFragment;
use crate::error::Error;

/// Walk a JSON document and emit one fragment per string value.
///
/// `value` holds the raw bytes between the surrounding quotes (UTF-8
/// validated, escape sequences kept as literal characters so byte offsets
/// stay aligned with the raw body). Numbers, booleans, and `null` are
/// skipped.
pub fn flatten_json(raw: &[u8]) -> Result<Vec<OwnedContextFragment>, Error> {
    let value: Value =
        serde_json::from_slice(raw).map_err(|e| Error::Scanner(format!("invalid JSON: {e}")))?;

    let positions = scan_string_positions(raw)?;

    let mut frags = Vec::new();
    let mut path = String::new();
    let mut cursor = 0usize;
    walk(&value, raw, &positions, &mut cursor, &mut path, &mut frags)?;
    Ok(frags)
}

/// Returns `(content_start, content_end)` for every quoted string in `raw`
/// in document order. Both object keys and string values are included; the
/// structural walk distinguishes them by consuming one position per key and
/// one per leaf string value.
fn scan_string_positions(raw: &[u8]) -> Result<Vec<(usize, usize)>, Error> {
    let mut out = Vec::new();
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
                    out.push((start, i));
                    i += 1;
                    break;
                }
                _ => i += 1,
            }
        }
    }
    Ok(out)
}

fn walk(
    value: &Value,
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
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(key);
                walk(child, raw, positions, cursor, path, frags)?;
                path.truncate(saved);
            }
        }
        Value::Array(arr) => {
            for (i, child) in arr.iter().enumerate() {
                let saved = path.len();
                write!(path, "[{i}]").expect("write to String never fails");
                walk(child, raw, positions, cursor, path, frags)?;
                path.truncate(saved);
            }
        }
        Value::String(_) => {
            let (start, end) = positions.get(*cursor).copied().ok_or_else(|| {
                Error::Scanner(
                    "internal: ran out of string positions while walking JSON tree".into(),
                )
            })?;
            *cursor += 1;
            let bytes = &raw[start..end];
            let text = std::str::from_utf8(bytes)
                .map_err(|e| Error::Scanner(format!("invalid UTF-8 in JSON string: {e}")))?
                .to_owned();
            frags.push(OwnedContextFragment {
                context: path.clone(),
                value: text,
                offset: start,
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

    fn ctx(c: &str, v: &str, o: usize) -> OwnedContextFragment {
        OwnedContextFragment {
            context: c.to_string(),
            value: v.to_string(),
            offset: o,
        }
    }

    /// Verify each fragment's `offset` actually points at its `value` in `raw`.
    fn check_offsets(raw: &[u8], frags: &[OwnedContextFragment]) {
        for f in frags {
            let slice = &raw[f.offset..f.offset + f.value.len()];
            let actual = std::str::from_utf8(slice).expect("utf-8 slice");
            assert_eq!(
                actual, f.value,
                "fragment {f:?} offset does not point to value bytes",
            );
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

    #[test]
    fn string_with_escapes_keeps_raw_bytes() {
        // Escape sequences are kept as literal bytes in the value so offsets
        // continue to map directly into the raw JSON.
        let raw = br#"{"s": "a\"b\\c"}"#;
        let frags = flatten_json(raw).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].value, r#"a\"b\\c"#);
        check_offsets(raw, &frags);
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
