//! JSON text with `\uXXXX` escapes, for the tests of decoded JSON values.
//!
//! Included with `#[path = "support/json_escape.rs"] mod json_escape;`, so
//! every test crate that needs it compiles its own copy; a test uses part of it.
#![allow(dead_code)]

/// `text` with every character written as a `\uXXXX` escape. A character
/// outside the Basic Multilingual Plane becomes a surrogate pair.
pub fn escape_all(text: &str) -> String {
    text.encode_utf16().map(|u| format!("\\u{u:04x}")).collect()
}

/// `text` with each character in `chars` written as a `\uXXXX` escape.
pub fn escape_some(text: &str, chars: &str) -> String {
    text.chars()
        .map(|c| {
            if chars.contains(c) {
                escape_all(&c.to_string())
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// A string a test puts in a document, to replace it with escaped JSON text.
pub const MARK: &str = "ESCAPED-VALUE";

/// `text` with `mark` replaced by `raw`. `mark` must occur exactly once.
pub fn replace_once(text: &str, mark: &str, raw: &str) -> String {
    assert_eq!(text.matches(mark).count(), 1, "{mark} once in {text}");
    text.replace(mark, raw)
}

/// The JSON text of `document` with the string `mark` replaced by `raw`, which
/// is JSON string content written as it should appear on the wire. `mark`
/// must occur in the serialized text exactly once.
pub fn with_raw(document: &serde_json::Value, mark: &str, raw: &str) -> String {
    replace_once(&document.to_string(), mark, raw)
}

/// The JSON text of `document` with the key `"x"` held twice at the start of
/// its top-level object.
pub fn with_duplicate_key(document: &serde_json::Value) -> String {
    let text = document.to_string();
    let rest = text.strip_prefix('{').expect("an object");
    format!(r#"{{"x":"a","x":"b",{rest}"#)
}
