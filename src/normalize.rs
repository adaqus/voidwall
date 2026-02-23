/// Strips zero-width invisible characters (U+200B ZERO WIDTH SPACE,
/// U+200C ZERO WIDTH NON-JOINER, U+200D ZERO WIDTH JOINER) that are commonly
/// inserted between PII tokens to break pattern matching.
///
/// Returns `None` when no such characters are present (fast path).
/// Otherwise returns `(stripped, offset_map)` where `offset_map[i]` maps
/// byte position `i` in the stripped string back to the corresponding byte
/// position in the original input.
pub(crate) fn strip_zero_width(input: &str) -> Option<(String, Vec<usize>)> {
    let bytes = input.as_bytes();
    // All three codepoints share the 3-byte prefix E2 80; the third byte
    // distinguishes them: 8B = U+200B, 8C = U+200C, 8D = U+200D.
    if !bytes
        .windows(3)
        .any(|w| w[0] == 0xE2 && w[1] == 0x80 && matches!(w[2], 0x8B..=0x8D))
    {
        return None;
    }

    let mut out = Vec::with_capacity(bytes.len());
    let mut map = Vec::with_capacity(bytes.len() + 1);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0xE2
            && i + 2 < bytes.len()
            && bytes[i + 1] == 0x80
            && matches!(bytes[i + 2], 0x8B..=0x8D)
        {
            i += 3;
            continue;
        }
        map.push(i);
        out.push(bytes[i]);
        i += 1;
    }
    map.push(i); // sentinel: maps stripped.len() → original.len()

    // SAFETY: We only removed complete 3-byte UTF-8 codepoints (E2 80 8B/8C/8D)
    // from valid UTF-8 input; all remaining bytes are unchanged.
    Some((unsafe { String::from_utf8_unchecked(out) }, map))
}

/// Returns `true` if `bytes` contains any zero-width invisible character
/// (U+200B, U+200C, or U+200D).
pub(crate) fn has_zero_width(bytes: &[u8]) -> bool {
    bytes
        .windows(3)
        .any(|w| w[0] == 0xE2 && w[1] == 0x80 && matches!(w[2], 0x8B..=0x8D))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_op_on_ascii() {
        assert!(strip_zero_width("hello world").is_none());
    }

    #[test]
    fn strips_zwsp() {
        let (s, map) = strip_zero_width("a\u{200B}b").unwrap();
        assert_eq!(s, "ab");
        assert_eq!(map[0], 0); // 'a' at original 0
        assert_eq!(map[1], 4); // 'b' at original 4 (after 3-byte ZWSP)
        assert_eq!(map[2], 5); // sentinel
    }

    #[test]
    fn strips_zwnj_and_zwj() {
        let (s, _) = strip_zero_width("x\u{200C}y\u{200D}z").unwrap();
        assert_eq!(s, "xyz");
    }

    #[test]
    fn preserves_other_multibyte() {
        // Cyrillic 'а' (U+0430 = D0 B0) should not be stripped.
        assert!(strip_zero_width("café").is_none());
        assert!(strip_zero_width("ex\u{0430}mple").is_none());
    }

    #[test]
    fn has_zero_width_detection() {
        assert!(!has_zero_width(b"hello"));
        assert!(has_zero_width("a\u{200B}b".as_bytes()));
        assert!(has_zero_width("a\u{200C}b".as_bytes()));
        assert!(has_zero_width("a\u{200D}b".as_bytes()));
    }
}
