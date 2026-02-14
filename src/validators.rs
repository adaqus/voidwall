pub(crate) fn always_valid(_s: &str) -> bool {
    true
}

pub(crate) fn luhn_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let checksum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    checksum % 10 == 0
}

pub(crate) fn ssn_check(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let area: u32 = parts[0].parse().unwrap_or(0);
    let group: u32 = parts[1].parse().unwrap_or(0);
    let serial: u32 = parts[2].parse().unwrap_or(0);
    if area == 0 || area == 666 || (900..=999).contains(&area) {
        return false;
    }
    if group == 0 {
        return false;
    }
    if serial == 0 {
        return false;
    }
    true
}

pub(crate) fn nino_check(s: &str) -> bool {
    let upper: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    if upper.len() != 9 {
        return false;
    }
    let bytes = upper.as_bytes();
    let first = bytes[0] as char;
    let second = bytes[1] as char;
    if matches!(first, 'D' | 'F' | 'I' | 'Q' | 'U' | 'V') {
        return false;
    }
    if matches!(second, 'D' | 'F' | 'I' | 'O' | 'Q' | 'U' | 'V') {
        return false;
    }
    let prefix = &upper[..2];
    if matches!(prefix, "BG" | "GB" | "NK" | "KN" | "TN" | "NT" | "ZZ") {
        return false;
    }
    true
}

pub(crate) fn iban_check(s: &str) -> bool {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 15 || compact.len() > 34 {
        return false;
    }
    let rearranged = format!("{}{}", &compact[4..], &compact[..4]);
    let mut numeric = String::new();
    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            numeric.push(c);
        } else if c.is_ascii_uppercase() {
            let val = (c as u32) - ('A' as u32) + 10;
            numeric.push_str(&val.to_string());
        } else {
            return false;
        }
    }
    let mut remainder: u64 = 0;
    for chunk in numeric.as_bytes().chunks(9) {
        let s = std::str::from_utf8(chunk).unwrap();
        let combined = format!("{remainder}{s}");
        remainder = combined.parse::<u64>().unwrap_or(0) % 97;
    }
    remainder == 1
}

pub(crate) fn ip_check(s: &str) -> bool {
    if s.contains('.') {
        for octet_str in s.split('.') {
            let octet: u32 = match octet_str.parse() {
                Ok(v) => v,
                Err(_) => return false,
            };
            if octet > 255 {
                return false;
            }
        }
    }
    true
}

pub(crate) fn itin_check(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let group: u32 = parts[1].parse().unwrap_or(0);
    matches!(group, 50..=65 | 70..=88 | 90..=92 | 94..=99)
}

pub(crate) fn sin_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 9 {
        return false;
    }
    if digits[0] == 0 {
        return false;
    }
    let checksum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    checksum % 10 == 0
}

pub(crate) fn ppsn_check(s: &str) -> bool {
    let upper = s.to_uppercase();
    let bytes = upper.as_bytes();
    let digit_count = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    if digit_count != 7 {
        return false;
    }
    let weights = [8, 7, 6, 5, 4, 3, 2];
    let sum: u32 = bytes[..7]
        .iter()
        .zip(weights.iter())
        .map(|(&b, &w)| (b - b'0') as u32 * w)
        .sum();
    let expected = sum % 23;
    let check_letter = if expected == 0 {
        b'W'
    } else {
        b'A' + (expected as u8 - 1)
    };
    bytes[7] == check_letter
}

pub(crate) fn uk_dl_check(s: &str) -> bool {
    if s.len() != 16 {
        return false;
    }
    let bytes = s.as_bytes();
    let month: u32 = ((bytes[6] - b'0') as u32) * 10 + (bytes[7] - b'0') as u32;
    if !((1..=12).contains(&month) || (51..=62).contains(&month)) {
        return false;
    }
    let day: u32 = ((bytes[8] - b'0') as u32) * 10 + (bytes[9] - b'0') as u32;
    if !(1..=31).contains(&day) {
        return false;
    }
    true
}

pub(crate) fn vin_check(s: &str) -> bool {
    if s.len() != 17 {
        return false;
    }
    let transliterate = |c: u8| -> Option<u32> {
        match c {
            b'0'..=b'9' => Some((c - b'0') as u32),
            b'A' => Some(1),
            b'B' => Some(2),
            b'C' => Some(3),
            b'D' => Some(4),
            b'E' => Some(5),
            b'F' => Some(6),
            b'G' => Some(7),
            b'H' => Some(8),
            b'J' => Some(1),
            b'K' => Some(2),
            b'L' => Some(3),
            b'M' => Some(4),
            b'N' => Some(5),
            b'P' => Some(7),
            b'R' => Some(9),
            b'S' => Some(2),
            b'T' => Some(3),
            b'U' => Some(4),
            b'V' => Some(5),
            b'W' => Some(6),
            b'X' => Some(7),
            b'Y' => Some(8),
            b'Z' => Some(9),
            _ => None,
        }
    };
    let weights: [u32; 17] = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
    let bytes = s.as_bytes();
    let mut sum: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let val = match transliterate(b) {
            Some(v) => v,
            None => return false,
        };
        sum += val * weights[i];
    }
    let remainder = sum % 11;
    let check_char = bytes[8];
    let expected = if remainder == 10 {
        b'X'
    } else {
        b'0' + remainder as u8
    };
    if check_char == expected {
        return true;
    }
    // Non-NA VINs may not use mod-11 check digit; pass through
    true
}
