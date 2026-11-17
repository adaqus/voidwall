//! Text hidden with invisible or decorative Unicode, for the tests of the scan
//! view (`hidden-unicode-normalization`) and the `invisible_text` guard.
#![allow(dead_code)]

/// A UK IBAN placeholder the `pii` guard reports in plain form.
pub const IBAN: &str = "GB82WEST12345698765432";

/// A `US_SSN` placeholder the `pii` guard reports in plain form.
pub const SSN: &str = "536-22-8726";

/// An e-mail placeholder the `pii` guard reports in plain form.
pub const EMAIL: &str = "jane.doe@example.com";

/// The soft hyphen U+00AD.
pub const SHY: char = '\u{AD}';

/// The `pii` guard alone, on one scanner thread, with the kinds of the
/// placeholders above.
pub const PII: &str = "[builtin_guards.pii]\ncountries = [\"International\", \"Us\"]\n\
                       languages = [\"En\"]\nscanner_threads = 1\n";

/// The `invisible_text` guard alone.
pub const INVISIBLE_TEXT: &str = "[builtin_guards.invisible_text]\n";

/// `value` with `hidden` inserted after its byte `at`. `at` lies on a
/// character boundary.
pub fn insert(value: &str, at: usize, hidden: &str) -> String {
    format!("{}{hidden}{}", &value[..at], &value[at..])
}

/// The IBAN placeholder with `hidden` between two of its digits.
pub fn hidden_iban(hidden: &str) -> String {
    insert(IBAN, 12, hidden)
}

/// The IBAN placeholder with a soft hyphen between two of its digits.
pub fn shy_iban() -> String {
    hidden_iban("\u{AD}")
}

/// `text` written as Unicode tag characters: each ASCII character `c` becomes
/// U+E0000 + `c`.
pub fn tags(text: &str) -> String {
    text.chars()
        .map(|c| {
            assert!(c.is_ascii(), "only ASCII has a tag character");
            char::from_u32(0xE0000 + c as u32).unwrap()
        })
        .collect()
}

/// `text` as tag characters with `between` between each two of them.
pub fn tags_split(text: &str, between: &str) -> String {
    let tags: Vec<String> = tags(text).chars().map(String::from).collect();
    tags.join(between)
}

/// The variation selector that stands for `byte`: U+FE00 to U+FE0F for 0 to
/// 15, U+E0100 to U+E01EF for 16 to 255.
pub fn selector(byte: u8) -> char {
    let code = match byte {
        0..=15 => 0xFE00 + u32::from(byte),
        _ => 0xE0100 + u32::from(byte) - 16,
    };
    char::from_u32(code).unwrap()
}

/// The UTF-8 of `text` as variation selectors ("emoji smuggling").
pub fn selectors(text: &str) -> String {
    text.bytes().map(selector).collect()
}

/// [`selectors`] with `between` between each two selectors.
pub fn selectors_split(text: &str, between: &str) -> String {
    let selectors: Vec<String> = text.bytes().map(|b| selector(b).to_string()).collect();
    selectors.join(between)
}

/// An emoji followed by `text` smuggled in variation selectors.
pub fn smuggled(text: &str) -> String {
    format!("\u{1F600}{}", selectors(text))
}

/// `text` with every printable ASCII character written full width.
pub fn full_width(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '!'..='~' => char::from_u32(c as u32 + 0xFEE0).unwrap(),
            other => other,
        })
        .collect()
}

/// `text` with `mark` after each ASCII digit.
pub fn marked_digits(text: &str, mark: char) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_ascii_digit() {
                vec![c, mark]
            } else {
                vec![c]
            }
        })
        .collect()
}
