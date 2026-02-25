/// Returns `true` if `bytes` contains any zero-width invisible character
/// (U+200B, U+200C, or U+200D).
fn has_zero_width(bytes: &[u8]) -> bool {
    bytes
        .windows(3)
        .any(|w| w[0] == 0xE2 && w[1] == 0x80 && matches!(w[2], 0x8B..=0x8D))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_percent(hi: u8, lo: u8) -> Option<u8> {
    let val = (hex_val(hi)? << 4) | hex_val(lo)?;
    if (0x20..=0x7e).contains(&val) {
        Some(val)
    } else {
        None
    }
}

fn decode_html_entity(bytes: &[u8]) -> Option<(u8, usize)> {
    debug_assert!(bytes[0] == b'&');
    let max_len = bytes.len().min(12);
    let semi = bytes[1..max_len].iter().position(|&b| b == b';')? + 1;

    if bytes[1] == b'#' {
        if bytes.len() > 2 && (bytes[2] == b'x' || bytes[2] == b'X') {
            // &#xHH;
            if semi < 4 {
                return None;
            }
            let mut val: u16 = 0;
            for &b in &bytes[3..semi] {
                val = val.checked_mul(16)?.checked_add(hex_val(b)? as u16)?;
            }
            if val == 160 {
                return Some((b' ', semi + 1));
            }
            if (0x20..=0x7e).contains(&val) {
                Some((val as u8, semi + 1))
            } else {
                None
            }
        } else {
            // &#DDD;
            if semi < 3 {
                return None;
            }
            let mut val: u16 = 0;
            for &b in &bytes[2..semi] {
                if !b.is_ascii_digit() {
                    return None;
                }
                val = val.checked_mul(10)?.checked_add((b - b'0') as u16)?;
            }
            if val == 160 {
                return Some((b' ', semi + 1));
            }
            if (0x20..=0x7e).contains(&val) {
                Some((val as u8, semi + 1))
            } else {
                None
            }
        }
    } else {
        let name = &bytes[1..semi];
        let ch = match name {
            b"nbsp" => b' ',
            b"quot" => b'"',
            b"amp" => b'&',
            b"lt" => b'<',
            b"gt" => b'>',
            b"period" => b'.',
            b"commat" => b'@',
            b"colon" => b':',
            b"num" => b'#',
            b"plus" => b'+',
            b"comma" => b',',
            b"lpar" => b'(',
            b"rpar" => b')',
            b"sol" => b'/',
            b"hyphen" => b'-',
            _ => return None,
        };
        Some((ch, semi + 1))
    }
}

/// Normalises input for detection: decodes URL percent-encoding and HTML
/// entities to plain ASCII, and strips zero-width invisible characters
/// (U+200B/C/D) that are inserted to break keyword and value patterns.
/// Returns `None` if the input needs no normalisation (fast path).
/// Otherwise returns `(normalised, offset_map)` where `offset_map[i]` maps
/// normalised byte position `i` to the corresponding original byte position.
pub(crate) fn decode_for_detection(input: &str) -> Option<(String, Vec<usize>)> {
    let bytes = input.as_bytes();
    let has_encoding = bytes.iter().any(|&b| b == b'%' || b == b'&');
    if !has_encoding && !has_zero_width(bytes) {
        return None;
    }

    let mut decoded = Vec::with_capacity(bytes.len());
    let mut offset_map = Vec::with_capacity(bytes.len() + 1);
    let mut i = 0;
    let mut changed = false;

    while i < bytes.len() {
        // Strip zero-width invisible characters inserted to evade detection.
        if bytes[i] == 0xE2
            && i + 2 < bytes.len()
            && bytes[i + 1] == 0x80
            && matches!(bytes[i + 2], 0x8B..=0x8D)
        {
            i += 3;
            changed = true;
            continue;
        }

        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Some(ch) = decode_percent(bytes[i + 1], bytes[i + 2])
        {
            offset_map.push(i);
            decoded.push(ch);
            i += 3;
            changed = true;
            continue;
        }
        if bytes[i] == b'&'
            && let Some((ch, len)) = decode_html_entity(&bytes[i..])
        {
            offset_map.push(i);
            decoded.push(ch);
            i += len;
            changed = true;
            continue;
        }
        offset_map.push(i);
        decoded.push(bytes[i]);
        i += 1;
    }
    offset_map.push(i);

    if !changed {
        return None;
    }

    // SAFETY: We only replace ASCII-encoded sequences (%XX, &#DD;, &name;) with
    // single ASCII bytes (0x20..=0x7E), strip complete 3-byte zero-width
    // codepoints (E2 80 8B/8C/8D), and copy all other bytes verbatim from
    // valid UTF-8 input. The result is always valid UTF-8.
    Some((unsafe { String::from_utf8_unchecked(decoded) }, offset_map))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_op_on_ascii() {
        assert!(decode_for_detection("hello world").is_none());
    }

    #[test]
    fn strips_zwsp() {
        let (s, map) = decode_for_detection("a\u{200B}b").unwrap();
        assert_eq!(s, "ab");
        assert_eq!(map[0], 0); // 'a' at original 0
        assert_eq!(map[1], 4); // 'b' at original 4 (after 3-byte ZWSP)
        assert_eq!(map[2], 5); // sentinel
    }

    #[test]
    fn strips_zwnj_and_zwj() {
        let (s, _) = decode_for_detection("x\u{200C}y\u{200D}z").unwrap();
        assert_eq!(s, "xyz");
    }

    #[test]
    fn preserves_other_multibyte() {
        // Cyrillic 'а' (U+0430 = D0 B0) should not be stripped.
        assert!(decode_for_detection("café").is_none());
        assert!(decode_for_detection("ex\u{0430}mple").is_none());
    }

    #[test]
    fn decodes_percent_encoding() {
        let (s, map) = decode_for_detection("a%40b").unwrap();
        assert_eq!(s, "a@b");
        assert_eq!(map[0], 0); // 'a'
        assert_eq!(map[1], 1); // '%40' starts at 1
        assert_eq!(map[2], 4); // 'b' at 4
    }

    #[test]
    fn decodes_html_entity() {
        let (s, _) = decode_for_detection("a&commat;b").unwrap();
        assert_eq!(s, "a@b");
    }

    #[test]
    fn has_zero_width_detection() {
        assert!(!has_zero_width(b"hello"));
        assert!(has_zero_width("a\u{200B}b".as_bytes()));
        assert!(has_zero_width("a\u{200C}b".as_bytes()));
        assert!(has_zero_width("a\u{200D}b".as_bytes()));
    }
}
