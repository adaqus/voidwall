//! Text written in base64, base64url and hex, for the tests of the decoded
//! view and the scan view (`encoded-content-decoding`).
#![allow(dead_code)]

/// An e-mail placeholder the `pii` guard reports in plain form. Its base64
/// ends with one `=`.
pub const EMAIL: &str = "jane.doe@example.com";

/// A second e-mail placeholder. Its base64 ends with `==`.
pub const EMAIL_2: &str = "ann.lee@example.org";

/// A PESEL placeholder the `pii` guard reports in plain form.
pub const PESEL: &str = "44051401359";

/// A 16-digit card-number placeholder the `pii` guard reports in plain form.
pub const CARD: &str = "4111111111111111";

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `bytes` in base64, or base64url with `url`, with padding when `pad`.
fn encode(bytes: &[u8], url: bool, pad: bool) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut acc = [0u8; 3];
        acc[..chunk.len()].copy_from_slice(chunk);
        let n = (u32::from(acc[0]) << 16) | (u32::from(acc[1]) << 8) | u32::from(acc[2]);
        for i in 0..=chunk.len() {
            let c = ALPHABET[((n >> (18 - 6 * i)) & 63) as usize];
            out.push(char::from(match (url, c) {
                (true, b'+') => b'-',
                (true, b'/') => b'_',
                (_, c) => c,
            }));
        }
        if pad {
            out.extend(std::iter::repeat_n('=', 3 - chunk.len()));
        }
    }
    out
}

/// The UTF-8 of `text` in standard base64, with padding.
pub fn base64(text: &str) -> String {
    encode(text.as_bytes(), false, true)
}

/// The UTF-8 of `text` in standard base64, without padding.
pub fn base64_unpadded(text: &str) -> String {
    encode(text.as_bytes(), false, false)
}

/// The UTF-8 of `text` in base64url, without padding.
pub fn base64url(text: &str) -> String {
    encode(text.as_bytes(), true, false)
}

/// The UTF-8 of `text` in lower-case hex.
pub fn hex(text: &str) -> String {
    text.bytes().map(|b| format!("{b:02x}")).collect()
}

/// A value of the base64 alphabet back to its 6 bits.
fn sextet(c: u8) -> u32 {
    u32::from(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' | b'-' => 62,
        _ => 63,
    })
}

/// base64 or base64url text back to its bytes, with or without padding.
pub fn decode_base64(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in text.trim_end_matches('=').as_bytes().chunks(4) {
        let acc = chunk.iter().fold(0u32, |acc, &c| (acc << 6) | sextet(c));
        let acc = acc << (6 * (4 - chunk.len()));
        out.extend_from_slice(&acc.to_be_bytes()[1..chunk.len()]);
    }
    out
}

/// Hex text back to its bytes.
pub fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn the_writers_round_trip() {
    for text in [EMAIL, EMAIL_2, PESEL, "a", "ab", "abc", "zażółć \u{1F600}"] {
        assert_eq!(decode_base64(&base64(text)), text.as_bytes());
        assert_eq!(decode_base64(&base64_unpadded(text)), text.as_bytes());
        assert_eq!(decode_base64(&base64url(text)), text.as_bytes());
        assert_eq!(decode_hex(&hex(text)), text.as_bytes());
    }
    assert!(base64(EMAIL).ends_with('=') && !base64(EMAIL).ends_with("=="));
    assert!(base64(EMAIL_2).ends_with("=="));
    // Known values, so the writer is not checked only against itself.
    assert_eq!(base64(EMAIL), "amFuZS5kb2VAZXhhbXBsZS5jb20=");
    assert_eq!(hex(PESEL), "3434303531343031333539");
    assert_eq!(base64url("\u{FB}\u{FF}"), "w7vDvw");
}
