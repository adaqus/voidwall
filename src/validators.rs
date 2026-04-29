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
    // Old format: 7 digits + 1 check letter (+ optional 'W')
    // New format: 7 digits + 1 check letter + 1 letter (A-Z, not W)
    // The 9th character (if present and not 'W') contributes to the checksum
    // with weight 9 × (alphabetic position).
    let weights = [8, 7, 6, 5, 4, 3, 2];
    let mut sum: u32 = bytes[..7]
        .iter()
        .zip(weights.iter())
        .map(|(&b, &w)| (b - b'0') as u32 * w)
        .sum();
    // New format: 9th character modifies the check digit
    if bytes.len() >= 9 && bytes[8].is_ascii_uppercase() && bytes[8] != b'W' {
        sum += 9 * (bytes[8] - b'A' + 1) as u32;
    }
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

pub(crate) fn tfn_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 9 {
        return false;
    }
    let weights: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    let sum: u32 = digits
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    sum % 11 == 0
}

pub(crate) fn ird_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 8 && digits.len() != 9 {
        return false;
    }
    let num: u64 = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0);
    if !(10_000_000..=150_000_000).contains(&num) {
        return false;
    }

    // For 8-digit: weights on first 7, check digit is 8th
    // For 9-digit: weights on first 8, check digit is 9th
    let len = digits.len();
    let check_digit = digits[len - 1];
    let body = &digits[..len - 1];

    let primary_weights: &[u32] = if len == 8 {
        &[3, 2, 7, 6, 5, 4, 3]
    } else {
        &[3, 2, 7, 6, 5, 4, 3, 2]
    };

    let sum: u32 = body
        .iter()
        .zip(primary_weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let remainder = sum % 11;
    let computed = if remainder == 0 { 0 } else { 11 - remainder };
    if computed != 10 {
        return computed == check_digit;
    }

    // Primary gave check=10, retry with secondary weights
    let secondary_weights: &[u32] = if len == 8 {
        &[7, 4, 3, 2, 5, 2, 7]
    } else {
        &[7, 4, 3, 2, 5, 2, 7, 6]
    };

    let sum2: u32 = body
        .iter()
        .zip(secondary_weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let remainder2 = sum2 % 11;
    let computed2 = if remainder2 == 0 { 0 } else { 11 - remainder2 };
    if computed2 == 10 {
        return false;
    }
    computed2 == check_digit
}

pub(crate) fn nhs_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 10 {
        return false;
    }
    let weights: [u32; 9] = [10, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum: u32 = digits[..9]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let remainder = sum % 11;
    let check_digit = if remainder == 0 { 0 } else { 11 - remainder };
    if check_digit == 10 {
        return false;
    }
    check_digit == digits[9]
}

pub(crate) fn medicare_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 10 {
        return false;
    }
    // First digit must be 2-6
    if !(2..=6).contains(&digits[0]) {
        return false;
    }
    let weights: [u32; 8] = [1, 3, 7, 9, 1, 3, 7, 9];
    let sum: u32 = digits[..8]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    sum % 10 == digits[8]
}

pub(crate) fn phone_check(_s: &str) -> bool {
    true
}

pub(crate) fn passport_check(_s: &str) -> bool {
    true
}

pub(crate) fn passport_new_check(s: &str) -> bool {
    if s.len() != 9 {
        return false;
    }
    let first = s.as_bytes()[0].to_ascii_uppercase();
    matches!(first, b'A' | b'X' | b'Y' | b'Z')
}

#[rustfmt::skip]
const ISO_3166_ALPHA2: &[&str] = &[
    "AD","AE","AF","AG","AI","AL","AM","AO","AQ","AR","AS","AT","AU","AW","AX","AZ",
    "BA","BB","BD","BE","BF","BG","BH","BI","BJ","BL","BM","BN","BO","BQ","BR","BS","BT","BV","BW","BY","BZ",
    "CA","CC","CD","CF","CG","CH","CI","CK","CL","CM","CN","CO","CR","CU","CV","CW","CX","CY","CZ",
    "DE","DJ","DK","DM","DO","DZ",
    "EC","EE","EG","EH","ER","ES","ET",
    "FI","FJ","FK","FM","FO","FR",
    "GA","GB","GD","GE","GF","GG","GH","GI","GL","GM","GN","GP","GQ","GR","GS","GT","GU","GW","GY",
    "HK","HM","HN","HR","HT","HU",
    "ID","IE","IL","IM","IN","IO","IQ","IR","IS","IT",
    "JE","JM","JO","JP",
    "KE","KG","KH","KI","KM","KN","KP","KR","KW","KY","KZ",
    "LA","LB","LC","LI","LK","LR","LS","LT","LU","LV","LY",
    "MA","MC","MD","ME","MF","MG","MH","MK","ML","MM","MN","MO","MP","MQ","MR","MS","MT","MU","MV","MW","MX","MY","MZ",
    "NA","NC","NE","NF","NG","NI","NL","NO","NP","NR","NU","NZ",
    "OM",
    "PA","PE","PF","PG","PH","PK","PL","PM","PN","PR","PS","PT","PW","PY",
    "QA",
    "RE","RO","RS","RU","RW",
    "SA","SB","SC","SD","SE","SG","SH","SI","SJ","SK","SL","SM","SN","SO","SR","SS","ST","SV","SX","SY","SZ",
    "TC","TD","TF","TG","TH","TJ","TK","TL","TM","TN","TO","TR","TT","TV","TW","TZ",
    "UA","UG","UM","US","UY","UZ",
    "VA","VC","VE","VG","VI","VN","VU",
    "WF","WS",
    "XK",
    "YE","YT",
    "ZA","ZM","ZW",
];

pub(crate) fn swift_bic_check(s: &str) -> bool {
    let len = s.len();
    if len != 8 && len != 11 {
        return false;
    }
    let country = &s[4..6].to_uppercase();
    ISO_3166_ALPHA2.binary_search(&country.as_str()).is_ok()
}

#[rustfmt::skip]
const VALID_EIN_PREFIXES: &[u32] = &[
    1, 2, 3, 4, 5, 6,
    10, 11, 12, 13, 14, 15, 16,
    20, 21, 22, 23, 24, 25, 26, 27,
    30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 44, 45, 46, 47, 48,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
    60, 61, 62, 63, 64, 65,
    66, 67, 68, 71, 72, 73, 74, 75, 76, 77,
    80, 81, 82, 83, 84, 85, 86, 87, 88,
    90, 91, 92, 93, 94, 95, 98, 99,
];

pub(crate) fn ein_check(s: &str) -> bool {
    let prefix: u32 = match s[..2].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    VALID_EIN_PREFIXES.binary_search(&prefix).is_ok()
}

pub(crate) fn imei_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 15 {
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

pub(crate) fn utr_check(s: &str) -> bool {
    if s.len() != 10 {
        return false;
    }
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 10 {
        return false;
    }
    let weights: [u32; 9] = [6, 7, 8, 9, 10, 5, 4, 3, 2];
    let sum: u32 = digits[1..]
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    let remainder = sum % 11;
    let check = if remainder == 0 { 0 } else { 11 - remainder };
    // Check digit 10 means the UTR is invalid
    if check == 10 {
        return false;
    }
    check == digits[0]
}

pub(crate) fn aba_check(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 9 {
        return false;
    }
    let sum = 3 * (digits[0] + digits[3] + digits[6])
        + 7 * (digits[1] + digits[4] + digits[7])
        + (digits[2] + digits[5] + digits[8]);
    sum % 10 == 0
}

pub(crate) fn geolocation_check(s: &str) -> bool {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 2 {
        return false;
    }
    let lat: f64 = match parts[0].trim().parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let lon: f64 = match parts[1].trim().parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)
}

pub(crate) fn a_number_check(s: &str) -> bool {
    let first = s.as_bytes()[0].to_ascii_uppercase();
    if first != b'A' {
        return false;
    }
    let digits = &s[1..];
    (7..=9).contains(&digits.len()) && digits.chars().all(|c| c.is_ascii_digit())
}

#[rustfmt::skip]
const USCIS_CENTER_CODES: &[&str] = &[
    "EAC", "IOE", "LIN", "MSC", "NBC", "SRC", "WAC", "YSC",
];

pub(crate) fn uscis_receipt_check(s: &str) -> bool {
    if s.len() != 13 {
        return false;
    }
    let prefix = s[..3].to_uppercase();
    USCIS_CENTER_CODES.binary_search(&prefix.as_str()).is_ok()
}

pub(crate) fn za_luhn13_check(s: &str) -> bool {
    if s.len() != 13 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let month: u32 = s[2..4].parse().unwrap_or(0);
    if !(1..=12).contains(&month) {
        return false;
    }
    let day: u32 = s[4..6].parse().unwrap_or(0);
    if !(1..=31).contains(&day) {
        return false;
    }
    let citizenship = s.as_bytes()[10] - b'0';
    if citizenship > 1 {
        return false;
    }
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
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

pub(crate) fn za_postal_check(s: &str) -> bool {
    if s.len() != 4 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let n: u32 = s.parse().unwrap_or(0);
    (1..=9999).contains(&n)
}

/// US ZIP code: 5 digits, optionally followed by `-NNNN` (ZIP+4).
/// Structural check only — there is no published checksum for ZIP codes.
pub(crate) fn us_zip_check(s: &str) -> bool {
    let bytes = s.as_bytes();
    match bytes.len() {
        5 => bytes.iter().all(|b| b.is_ascii_digit()),
        10 => {
            bytes[5] == b'-'
                && bytes[..5].iter().all(|b| b.is_ascii_digit())
                && bytes[6..].iter().all(|b| b.is_ascii_digit())
        }
        _ => false,
    }
}

/// Combined US/ZA postal code validator. Accepts ZA 4-digit form or US 5-digit /
/// ZIP+4 form. Used by `PiiKind::UsZaPostalCode`, which shares English keywords
/// (`zip`, `postal_code`, `postcode`) across both countries.
pub(crate) fn us_za_postal_check(s: &str) -> bool {
    us_zip_check(s) || za_postal_check(s)
}

/// Irish Eircode: 7 alphanumeric characters in the form `A##XXXX` (one letter,
/// two digits — or the literal `6W` for the D6W routing key — followed by four
/// alphanumerics). Whitespace between the routing key and the unique
/// identifier is permitted and stripped before validation.
pub(crate) fn ie_eircode_check(s: &str) -> bool {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() != 7 {
        return false;
    }
    let bytes = clean.as_bytes();
    if !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    let routing_digits = bytes[1].is_ascii_digit() && bytes[2].is_ascii_digit();
    let routing_d6w = bytes[1] == b'6' && bytes[2].eq_ignore_ascii_case(&b'W');
    if !routing_digits && !routing_d6w {
        return false;
    }
    bytes[3..7].iter().all(|b| b.is_ascii_alphanumeric())
}

pub(crate) fn us_dl_check(s: &str) -> bool {
    let clean: String = s.chars().filter(|c| *c != '-').collect();
    let letter_count = clean
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .count();
    if !(1..=2).contains(&letter_count) {
        return false;
    }
    let digit_part = &clean[letter_count..];
    if !digit_part.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let digit_count = digit_part.len();
    match letter_count {
        1 => (7..=14).contains(&digit_count),
        2 => (4..=8).contains(&digit_count),
        _ => false,
    }
}

pub(crate) fn sort_code_check(s: &str) -> bool {
    // Basic structural validation: 6 digits in NN-NN-NN format
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    digits.len() == 6
}

/// NZ NHI Number check (old format: 3 letters + 4 digits, check digit).
/// Letters exclude I and O. Mapping: A=1..H=8, J=9..N=13, P=14..Z=24.
pub(crate) fn nhi_check(s: &str) -> bool {
    let upper = s.to_uppercase();
    let bytes = upper.as_bytes();
    if bytes.len() != 7 {
        return false;
    }
    let alpha_val = |b: u8| -> Option<u32> {
        match b {
            b'A'..=b'H' => Some((b - b'A' + 1) as u32),
            b'J'..=b'N' => Some((b - b'J' + 9) as u32),
            b'P'..=b'Z' => Some((b - b'P' + 14) as u32),
            _ => None,
        }
    };
    // First 3 must be letters (not I, O)
    let a1 = match alpha_val(bytes[0]) {
        Some(v) => v,
        None => return false,
    };
    let a2 = match alpha_val(bytes[1]) {
        Some(v) => v,
        None => return false,
    };
    let a3 = match alpha_val(bytes[2]) {
        Some(v) => v,
        None => return false,
    };
    // Next 4 must be digits
    if !bytes[3..7].iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let d1 = (bytes[3] - b'0') as u32;
    let d2 = (bytes[4] - b'0') as u32;
    let d3 = (bytes[5] - b'0') as u32;
    let check = (bytes[6] - b'0') as u32;

    let sum = a1 * 7 + a2 * 6 + a3 * 5 + d1 * 4 + d2 * 3 + d3 * 2;
    let remainder = sum % 11;
    if remainder == 0 {
        return false; // check digit would be 11, invalid
    }
    let expected = 11 - remainder;
    if expected == 10 {
        return check == 0;
    }
    expected == check
}

/// NZ Driver Licence: 2 uppercase letters + 6 digits.
pub(crate) fn nz_dl_check(s: &str) -> bool {
    if s.len() != 8 {
        return false;
    }
    let bytes = s.as_bytes();
    bytes[0].is_ascii_uppercase()
        && bytes[1].is_ascii_uppercase()
        && bytes[2..].iter().all(|b| b.is_ascii_digit())
}

/// IE Driver Number: exactly 9 digits.
pub(crate) fn ie_driver_check(s: &str) -> bool {
    s.len() == 9 && s.bytes().all(|b| b.is_ascii_digit())
}

/// ZA Tax Reference Number: 10 digits, first digit in {0,1,2,3,9}.
pub(crate) fn za_trn_check(s: &str) -> bool {
    if s.len() != 10 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    matches!(s.as_bytes()[0], b'0' | b'1' | b'2' | b'3' | b'9')
}

/// Date of birth validator: accepts year 1900..=current_year, month 1..=12, day 1..=31.
/// Handles formats: DD/MM/YYYY, MM/DD/YYYY, YYYY-MM-DD, "15 March 1990", "March 15, 1990".
/// Rejects ISO timestamps (values containing 'T' after the date portion).
pub(crate) fn dob_check(s: &str) -> bool {
    // Reject ISO timestamps like "2024-10-15T12:00:00"
    if s.contains('T') || s.contains('t') {
        return false;
    }

    // Current year upper bound
    const MAX_YEAR: u32 = 2030; // generous upper bound; birth years won't exceed current year

    // Helper to validate y/m/d components
    let valid_date = |y: u32, m: u32, d: u32| -> bool {
        (1900..=MAX_YEAR).contains(&y) && (1..=12).contains(&m) && (1..=31).contains(&d)
    };

    let month_from_name = |name: &str| -> Option<u32> {
        match name.to_lowercase().as_str() {
            "jan" | "january" | "janvier" => Some(1),
            "feb" | "february" | "février" | "fevrier" => Some(2),
            "mar" | "march" | "mars" => Some(3),
            "apr" | "april" | "avril" => Some(4),
            "may" | "mai" => Some(5),
            "jun" | "june" | "juin" => Some(6),
            "jul" | "july" | "juillet" => Some(7),
            "aug" | "august" | "août" | "aout" => Some(8),
            "sep" | "september" | "septembre" => Some(9),
            "oct" | "october" | "octobre" => Some(10),
            "nov" | "november" | "novembre" => Some(11),
            "dec" | "december" | "décembre" | "decembre" | "dezember" => Some(12),
            "januar" => Some(1),
            "februar" => Some(2),
            "märz" | "maerz" => Some(3),
            "juni" => Some(6),
            "juli" => Some(7),
            "oktober" => Some(10),
            _ => None,
        }
    };

    let trimmed = s.trim();

    // Try numeric formats: DD/MM/YYYY, MM/DD/YYYY, YYYY-MM-DD (separators: / - .)
    let parts: Vec<&str> = trimmed.split(['/', '-', '.']).collect();
    if parts.len() == 3 {
        let a: Option<u32> = parts[0].trim().parse().ok();
        let b: Option<u32> = parts[1].trim().parse().ok();
        let c: Option<u32> = parts[2].trim().parse().ok();
        if let (Some(a), Some(b), Some(c)) = (a, b, c) {
            // YYYY-MM-DD: first part is 4-digit year
            if parts[0].trim().len() == 4 && a >= 1900 {
                return valid_date(a, b, c);
            }
            // DD/MM/YYYY or MM/DD/YYYY: last part is 4-digit year
            if parts[2].trim().len() == 4 && c >= 1900 {
                return valid_date(c, b, a) || valid_date(c, a, b);
            }
        }
    }

    // Try "DD Month YYYY" — e.g. "15 March 1990", "15 mars 1990"
    let words: Vec<&str> = trimmed.split_whitespace().collect();
    if words.len() == 3 {
        // "DD Month YYYY"
        if let (Ok(day), Some(month), Ok(year)) = (
            words[0].parse::<u32>(),
            month_from_name(words[1]),
            words[2].parse::<u32>(),
        ) {
            return valid_date(year, month, day);
        }
        // "Month DD, YYYY" or "Month DD YYYY"
        let day_str = words[1].trim_end_matches(',');
        if let (Some(month), Ok(day), Ok(year)) = (
            month_from_name(words[0]),
            day_str.parse::<u32>(),
            words[2].parse::<u32>(),
        ) {
            return valid_date(year, month, day);
        }
    }

    false
}

/// France SIREN Luhn check: exactly 9 digits, Luhn mod-10.
pub(crate) fn siren_luhn_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 9 {
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

/// France SIRET Luhn check: exactly 14 digits, Luhn mod-10.
pub(crate) fn siret_luhn_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 14 {
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

/// France NIR (Sécurité Sociale) check: 13-digit body + 2-digit key.
/// Handles Corsica departments (2A → 19, 2B → 18 substitution before numeric check).
/// Valid if key == 97 - (body % 97).
pub(crate) fn nir_check(s: &str) -> bool {
    // Strip spaces, dots, hyphens
    let clean: String = s
        .chars()
        .filter(|c| !matches!(c, ' ' | '.' | '-'))
        .collect();

    if clean.len() != 15 {
        return false;
    }

    // Handle Corsica: 2A/2B in department position (chars 5-6, 0-indexed)
    let numeric_str = if clean.len() >= 7 {
        let dept = &clean[5..7];
        if dept.eq_ignore_ascii_case("2A") {
            format!("{}19{}", &clean[..5], &clean[7..])
        } else if dept.eq_ignore_ascii_case("2B") {
            format!("{}18{}", &clean[..5], &clean[7..])
        } else {
            clean.clone()
        }
    } else {
        clean.clone()
    };

    if !numeric_str.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    let body: u64 = match numeric_str[..13].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let key: u64 = match numeric_str[13..15].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };

    key == 97 - (body % 97)
}

/// France postal code check: 5 digits, range 01000..=98999.
pub(crate) fn fr_postal_check(s: &str) -> bool {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() != 5 || !clean.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let val: u32 = match clean.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    (1000..=98999).contains(&val)
}

/// France NIF (Numéro d'Identification Fiscale / SPI) check: 13 digits, first digit 0-3.
pub(crate) fn fr_nif_check(s: &str) -> bool {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() != 13 || !clean.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    matches!(clean.as_bytes()[0], b'0' | b'1' | b'2' | b'3')
}

/// German Steuer-ID (Steueridentifikationsnummer) check: ISO 7064 MOD 11,10.
/// 11 digits, first digit nonzero.
pub(crate) fn de_steuer_id_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 11 {
        return false;
    }
    if digits[0] == 0 {
        return false;
    }
    let mut product: u32 = 10;
    for &d in &digits[..10] {
        let mut sum = (d + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (sum * 2) % 11;
    }
    let check = if product == 1 { 0 } else { 11 - product };
    check == digits[10]
}

/// German Personalausweis (new format) check: 1 letter + 8 alphanumeric + 1 check digit.
/// Check digit: weighted sum mod 10 (weights 7,3,1 repeating over 9 chars).
/// Letters: A=10..Z=35, digits 0-9.
pub(crate) fn de_personalausweis_check(s: &str) -> bool {
    let upper = s.to_uppercase();
    let bytes = upper.as_bytes();
    if bytes.len() != 10 {
        return false;
    }
    if !bytes[0].is_ascii_uppercase() {
        return false;
    }
    let char_val = |b: u8| -> Option<u32> {
        if b.is_ascii_digit() {
            Some((b - b'0') as u32)
        } else if b.is_ascii_uppercase() {
            Some((b - b'A') as u32 + 10)
        } else {
            None
        }
    };
    let weights: [u32; 9] = [7, 3, 1, 7, 3, 1, 7, 3, 1];
    let mut total: u32 = 0;
    for i in 0..9 {
        let val = match char_val(bytes[i]) {
            Some(v) => v,
            None => return false,
        };
        total += val * weights[i];
    }
    let expected = total % 10;
    let check = match char_val(bytes[9]) {
        Some(v) => v,
        None => return false,
    };
    expected == check
}

/// German Reisepass (ePassport) check: 9 chars, alphabet restricted to digits
/// and letters from `[CFGHJKLMNPRTVWXYZ]`, at least one letter present to
/// distinguish from generic numeric passport formats.
pub(crate) fn de_passport_check(s: &str) -> bool {
    let upper = s.to_uppercase();
    let bytes = upper.as_bytes();
    if bytes.len() != 9 {
        return false;
    }
    let mut has_letter = false;
    for &b in bytes {
        match b {
            b'0'..=b'9' => {}
            b'C' | b'F' | b'G' | b'H' | b'J' | b'K' | b'L' | b'M' | b'N' | b'P' | b'R' | b'T'
            | b'V' | b'W' | b'X' | b'Y' | b'Z' => has_letter = true,
            _ => return false,
        }
    }
    has_letter
}

/// German postal code check: 5 digits, range 01000–99999.
pub(crate) fn de_postal_check(s: &str) -> bool {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() != 5 || !clean.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let val: u32 = match clean.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    (1000..=99999).contains(&val)
}

/// Austrian SVNR (Sozialversicherungsnummer) check: 10 digits.
/// Format: NNNN+DDMMYY where position 3 (0-indexed) is the check digit.
/// Weights: [3,7,9,_,5,8,4,2,1,6], sum mod 11 == digit[3].
pub(crate) fn at_svnr_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 10 {
        return false;
    }
    let weights: [u32; 10] = [3, 7, 9, 0, 5, 8, 4, 2, 1, 6];
    let mut total: u32 = 0;
    for i in 0..10 {
        if i == 3 {
            continue;
        }
        total += digits[i] * weights[i];
    }
    let check = total % 11;
    if check >= 10 {
        return false;
    }
    check == digits[3]
}

/// Austrian postal code check: 4 digits, range 1010–9992.
pub(crate) fn at_postal_check(s: &str) -> bool {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() != 4 || !clean.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let val: u32 = match clean.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    (1010..=9992).contains(&val)
}

/// Swiss AHV/OASI number check: 13 digits starting with "756", EAN-13 check digit.
pub(crate) fn ch_ahv_check(s: &str) -> bool {
    let clean: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if clean.len() != 13 {
        return false;
    }
    if !clean.starts_with("756") {
        return false;
    }
    let digits: Vec<u32> = clean.chars().filter_map(|c| c.to_digit(10)).collect();
    let total: u32 = digits[..12]
        .iter()
        .enumerate()
        .map(|(i, &d)| {
            let w = if i % 2 == 0 { 1 } else { 3 };
            d * w
        })
        .sum();
    let expected = (10 - total % 10) % 10;
    expected == digits[12]
}

/// Swiss postal code check: 4 digits, range 1000–9658.
pub(crate) fn ch_postal_check(s: &str) -> bool {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() != 4 || !clean.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let val: u32 = match clean.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    (1000..=9658).contains(&val)
}

/// Ontario Health Insurance Plan (OHIP) number: 10 digits, Luhn mod-10.
pub(crate) fn ohip_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 10 {
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

/// German/Austrian street address check: validates the captured span from a keyword-context match.
/// Expects a string like "Musterstraße 42, 10115 Berlin" or "Schillerstraße 10, 1010 Wien".
/// Checks: has a valid 4-digit AT PLZ or 5-digit DE PLZ + city, at least 3 tokens, reasonable length.
pub(crate) fn de_at_address_check(s: &str) -> bool {
    let trimmed = s.trim();
    let len = trimmed.len();
    if !(10..=200).contains(&len) {
        return false;
    }
    // Must contain at least one digit (house number or PLZ)
    if !trimmed.chars().any(|c| c.is_ascii_digit()) {
        return false;
    }
    // Must have at least 3 whitespace-separated tokens
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 3 {
        return false;
    }
    // Find the PLZ: scan tokens for a 4-digit AT/CH or 5-digit DE PLZ
    tokens.iter().any(|t| {
        let clean = t.trim_matches(|c: char| c == ',' || c.is_whitespace());
        if clean.chars().all(|c| c.is_ascii_digit()) {
            (clean.len() == 5 && de_postal_check(clean))
                || (clean.len() == 4 && (at_postal_check(clean) || ch_postal_check(clean)))
        } else {
            false
        }
    })
}

/// German/Austrian/Swiss Postfach (PO box) check: validates "NNNNN, PLZ Stadt" captured span.
/// Postfach number is 1-6 digits, followed by 4-digit AT/CH or 5-digit DE PLZ + city.
pub(crate) fn de_at_postfach_check(s: &str) -> bool {
    let trimmed = s.trim();
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 2 {
        return false;
    }
    // First token(s) should be the Postfach number (1-6 digits, possibly with spaces)
    let first_clean = tokens[0].trim_matches(|c: char| c == ',' || c.is_whitespace());
    let digits_only: String = first_clean.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits_only.is_empty() || digits_only.len() > 6 {
        return false;
    }
    // Must contain a valid 4-digit AT/CH or 5-digit DE PLZ somewhere
    tokens.iter().any(|t| {
        let clean = t.trim_matches(|c: char| c == ',' || c.is_whitespace());
        if clean.chars().all(|c| c.is_ascii_digit()) {
            (clean.len() == 5 && de_postal_check(clean))
                || (clean.len() == 4 && (at_postal_check(clean) || ch_postal_check(clean)))
        } else {
            false
        }
    })
}

/// German Packstation/Postfiliale check: validates "NNN, PLZ Stadt" captured span.
/// Station number is 3-4 digits, followed by 5-digit PLZ + city.
pub(crate) fn de_packstation_check(s: &str) -> bool {
    let trimmed = s.trim();
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 2 {
        return false;
    }
    // First token should be the station number (3-4 digits)
    let first_clean = tokens[0].trim_matches(|c: char| c == ',' || c.is_whitespace());
    if first_clean.len() < 3
        || first_clean.len() > 4
        || !first_clean.chars().all(|c| c.is_ascii_digit())
    {
        return false;
    }
    // Must contain a valid 5-digit PLZ somewhere
    tokens.iter().any(|t| {
        let clean = t.trim_matches(|c: char| c == ',' || c.is_whitespace());
        clean.len() == 5 && clean.chars().all(|c| c.is_ascii_digit()) && de_postal_check(clean)
    })
}

/// UK street address check: validates captured span.
/// Length 10–200, ≥3 tokens, must contain a valid GB postcode.
pub(crate) fn gb_address_check(s: &str) -> bool {
    let trimmed = s.trim();
    let len = trimmed.len();
    if !(10..=200).contains(&len) {
        return false;
    }
    if !trimmed.chars().any(|c| c.is_ascii_digit()) {
        return false;
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 3 {
        return false;
    }
    // Must contain a GB postcode. Postcodes can be one token ("SW1A2AA") or
    // two whitespace-separated tokens ("SW1A" + "2AA").
    let is_outward = |s: &str| {
        let b = s.as_bytes();
        (2..=4).contains(&b.len())
            && b[0].is_ascii_alphabetic()
            && b.iter().all(|c| c.is_ascii_alphanumeric())
            && b[1..].iter().any(|c| c.is_ascii_digit())
    };
    let is_inward = |s: &str| {
        s.len() == 3
            && s.as_bytes()[0].is_ascii_digit()
            && s.as_bytes()[1].is_ascii_alphabetic()
            && s.as_bytes()[2].is_ascii_alphabetic()
    };
    let clean: Vec<String> = tokens
        .iter()
        .map(|t| {
            t.trim_matches(|c: char| c == ',' || c.is_whitespace())
                .to_string()
        })
        .collect();
    // Two-token postcode: adjacent tokens match outward + inward.
    let two_token = clean
        .windows(2)
        .any(|w| is_outward(&w[0]) && is_inward(&w[1]));
    // One-token postcode: 5–7 char alphanumeric ending with 1 digit + 2 letters.
    let one_token = clean.iter().any(|t| {
        let b = t.as_bytes();
        let n = b.len();
        (5..=7).contains(&n)
            && b.iter().all(|c| c.is_ascii_alphanumeric())
            && b[n - 3].is_ascii_digit()
            && b[n - 2].is_ascii_alphabetic()
            && b[n - 1].is_ascii_alphabetic()
            && is_outward(&t[..n - 3])
    });
    two_token || one_token
}

/// French/Swiss French street address check: validates captured span.
/// Length 10–200, ≥3 tokens, must contain a valid postal code (5-digit FR or 4-digit CH).
pub(crate) fn fr_ch_address_check(s: &str) -> bool {
    let trimmed = s.trim();
    let len = trimmed.len();
    if !(10..=200).contains(&len) {
        return false;
    }
    if !trimmed.chars().any(|c| c.is_ascii_digit()) {
        return false;
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 3 {
        return false;
    }
    tokens.iter().any(|t| {
        let clean = t.trim_matches(|c: char| c == ',' || c.is_whitespace());
        if clean.chars().all(|c| c.is_ascii_digit()) {
            match clean.len() {
                5 => fr_postal_check(clean),
                4 => ch_postal_check(clean),
                _ => false,
            }
        } else {
            false
        }
    })
}

/// French/Swiss PO box (Boîte Postale / Case Postale) check.
/// First token is 1–6 digits (BP/CP number), must contain a valid postal code (5-digit FR or 4-digit CH).
pub(crate) fn fr_ch_boite_postale_check(s: &str) -> bool {
    let trimmed = s.trim();
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 2 {
        return false;
    }
    let first_clean = tokens[0].trim_matches(|c: char| c == ',' || c.is_whitespace());
    let digits_only: String = first_clean.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits_only.is_empty() || digits_only.len() > 6 {
        return false;
    }
    // Skip first token (BP/CP number) when looking for postal code
    tokens[1..].iter().any(|t| {
        let clean = t.trim_matches(|c: char| c == ',' || c.is_whitespace());
        if clean.chars().all(|c| c.is_ascii_digit()) {
            match clean.len() {
                5 => fr_postal_check(clean),
                4 => ch_postal_check(clean),
                _ => false,
            }
        } else {
            false
        }
    })
}

/// AU Drivers License: 6-10 digits, or letter + 5-9 digits.
/// No checksum — just format validation.
pub(crate) fn au_dl_check(s: &str) -> bool {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if bytes.iter().all(|b| b.is_ascii_digit()) {
        // Pure digits: 6-10
        (6..=10).contains(&len) && bytes.iter().any(|&b| b != b'0')
    } else if (6..=10).contains(&len)
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..].iter().all(|b| b.is_ascii_digit())
    {
        // Letter + 5-9 digits
        bytes[1..].iter().any(|&b| b != b'0')
    } else {
        false
    }
}

/// AU ABN (Australian Business Number): 11 digits, mod-89 weighted checksum.
/// Algorithm from abr.business.gov.au:
/// 1. Subtract 1 from first digit
/// 2. Multiply each digit by weight [10,1,3,5,7,9,11,13,15,17,19]
/// 3. Sum products; valid if sum % 89 == 0
pub(crate) fn au_abn_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() != 11 {
        return false;
    }
    if digits[0] == 0 {
        return false;
    }
    const WEIGHTS: [u32; 11] = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
    let sum: u32 = digits
        .iter()
        .enumerate()
        .map(|(i, &d)| {
            let d = if i == 0 { d - 1 } else { d };
            d * WEIGHTS[i]
        })
        .sum();
    sum % 89 == 0
}

pub(crate) fn person_name_check(s: &str) -> bool {
    if s.len() < 2 {
        return false;
    }
    s.chars().any(|c| c.is_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    // --- nir_check ---
    #[test_case("1 85 05 78 006 084 91", true ; "valid standard with spaces")]
    #[test_case("185057800608491", true ; "valid no spaces")]
    #[test_case("284112A03345714", true ; "valid corsica 2A")]
    #[test_case("284112B03345741", true ; "valid corsica 2B")]
    #[test_case("185036912304532", true ; "valid lyon from superindep.fr")]
    #[test_case("175012A00403288", true ; "valid corsica 2A ajaccio")]
    #[test_case("290052B03301001", true ; "valid corsica 2B commune 033")]
    #[test_case("1 85 03 69 123 045 32", true ; "valid lyon with spaces")]
    #[test_case("185057800608499", false ; "invalid checksum")]
    #[test_case("185036912304533", false ; "invalid off by one")]
    #[test_case("18505780060843", false ; "wrong length")]
    fn nir(input: &str, expected: bool) {
        assert_eq!(nir_check(input), expected);
    }

    // --- fr_postal_check ---
    #[test_case("75008", true ; "valid paris")]
    #[test_case("97100", true ; "valid dom tom")]
    #[test_case("75001", true ; "valid paris 1er")]
    #[test_case("13001", true ; "valid marseille")]
    #[test_case("69001", true ; "valid lyon")]
    #[test_case("31000", true ; "valid toulouse")]
    #[test_case("06000", true ; "valid nice")]
    #[test_case("97110", true ; "valid guadeloupe")]
    #[test_case("97400", true ; "valid reunion")]
    #[test_case("01000", true ; "valid low")]
    #[test_case("00100", false ; "invalid below range")]
    #[test_case("99000", false ; "invalid above range")]
    fn fr_postal(input: &str, expected: bool) {
        assert_eq!(fr_postal_check(input), expected);
    }

    // --- fr_nif_check ---
    #[test_case("0123456789012", true ; "valid first digit 0")]
    #[test_case("3123456789012", true ; "valid first digit 3")]
    #[test_case("012345678901", false ; "invalid length")]
    #[test_case("4123456789012", false ; "invalid first digit 4")]
    fn fr_nif(input: &str, expected: bool) {
        assert_eq!(fr_nif_check(input), expected);
    }

    // --- siren_luhn_check ---
    // Real SIREN numbers from annuaire-entreprises.data.gouv.fr
    #[test_case("775670417", true ; "valid LVMH")]
    #[test_case("542051180", true ; "valid TotalEnergies")]
    #[test_case("441639465", true ; "valid Renault SA")]
    #[test_case("780129987", true ; "valid Renault SAS")]
    #[test_case("712049618", true ; "valid EssilorLuxottica")]
    #[test_case("775670418", false ; "invalid off by one")]
    #[test_case("77567041", false ; "invalid wrong length")]
    fn siren(input: &str, expected: bool) {
        assert_eq!(siren_luhn_check(input), expected);
    }

    // --- siret_luhn_check ---
    // Real SIRET numbers from annuaire-entreprises.data.gouv.fr
    #[test_case("77567041700051", true ; "valid LVMH HQ")]
    #[test_case("54205118000066", true ; "valid TotalEnergies HQ")]
    #[test_case("71204961800739", true ; "valid EssilorLuxottica HQ")]
    #[test_case("77567041700052", false ; "invalid off by one")]
    #[test_case("7756704170005", false ; "invalid wrong length")]
    fn siret(input: &str, expected: bool) {
        assert_eq!(siret_luhn_check(input), expected);
    }

    // --- de_steuer_id_check ---
    // Values from kryptografie.de and github.com/rechtlogisch/steuer-id
    #[test_case("65929970489", true ; "valid from kryptografie")]
    #[test_case("86095742719", true ; "valid 2")]
    #[test_case("26954371827", true ; "valid from kontist")]
    #[test_case("12345678995", true ; "valid sequential from kryptografie")]
    #[test_case("65929970480", false ; "invalid checksum")]
    #[test_case("26954371820", false ; "invalid checksum 2")]
    #[test_case("05929970489", false ; "invalid first digit zero")]
    #[test_case("6592997048", false ; "wrong length short")]
    #[test_case("659299704890", false ; "wrong length long")]
    fn de_steuer_id(input: &str, expected: bool) {
        assert_eq!(de_steuer_id_check(input), expected);
    }

    // --- de_personalausweis_check ---
    // Values from kryptografie.de/personalausweis.htm
    #[test_case("L01X00T471", true ; "valid newest format since 2021")]
    #[test_case("T220001293", true ; "valid new format 2010-2021")]
    #[test_case("C01X00T478", true ; "valid C prefix")]
    #[test_case("M123456788", true ; "valid sequential")]
    #[test_case("Y0A1B2C3D6", true ; "valid mixed alphanumeric")]
    #[test_case("L01X00T470", false ; "invalid check digit")]
    #[test_case("T220001290", false ; "invalid check digit 2")]
    #[test_case("L01X00T47", false ; "wrong length")]
    #[test_case("1220001297", false ; "invalid starts with digit")]
    fn de_personalausweis(input: &str, expected: bool) {
        assert_eq!(de_personalausweis_check(input), expected);
    }

    // --- de_postal_check ---
    #[test_case("10115", true ; "valid berlin")]
    #[test_case("01067", true ; "valid dresden")]
    #[test_case("80331", true ; "valid munich")]
    #[test_case("20095", true ; "valid hamburg")]
    #[test_case("60311", true ; "valid frankfurt")]
    #[test_case("00100", false ; "invalid below range")]
    #[test_case("00000", false ; "invalid all zeros")]
    fn de_postal(input: &str, expected: bool) {
        assert_eq!(de_postal_check(input), expected);
    }

    // --- at_svnr_check ---
    // Values from gist.github.com/jensens (documented example: 1237010180)
    #[test_case("1238150185", true ; "valid")]
    #[test_case("1233250689", true ; "valid 2")]
    #[test_case("1237010180", true ; "valid documented from jensens")]
    #[test_case("4567150390", true ; "valid born 1990")]
    #[test_case("7892281275", true ; "valid born 1975")]
    #[test_case("1230150185", false ; "invalid checksum")]
    #[test_case("1238010180", false ; "invalid check off by one")]
    #[test_case("123815018", false ; "wrong length")]
    fn at_svnr(input: &str, expected: bool) {
        assert_eq!(at_svnr_check(input), expected);
    }

    // --- at_postal_check ---
    #[test_case("1010", true ; "valid vienna")]
    #[test_case("5020", true ; "valid salzburg")]
    #[test_case("8010", true ; "valid graz")]
    #[test_case("6020", true ; "valid innsbruck")]
    #[test_case("1000", false ; "invalid below range")]
    #[test_case("1009", false ; "invalid just below")]
    fn at_postal(input: &str, expected: bool) {
        assert_eq!(at_postal_check(input), expected);
    }

    // --- ch_ahv_check ---
    // Values from sozialversicherungsnummer.ch and gist.github.com/rordi
    #[test_case("7561234567897", true ; "valid")]
    #[test_case("7569217076985", true ; "valid from sozialversicherungsnummer.ch")]
    #[test_case("7560081378250", true ; "valid from gist rordi")]
    #[test_case("7563026070592", true ; "valid 3026")]
    #[test_case("7561122334402", true ; "valid check digit 2")]
    #[test_case("7561234567890", false ; "invalid checksum")]
    #[test_case("7569217076980", false ; "invalid checksum real prefix")]
    #[test_case("1231234567897", false ; "invalid prefix not 756")]
    #[test_case("756123456789", false ; "wrong length")]
    fn ch_ahv(input: &str, expected: bool) {
        assert_eq!(ch_ahv_check(input), expected);
    }

    // --- ch_postal_check ---
    #[test_case("8001", true ; "valid zurich")]
    #[test_case("3000", true ; "valid bern")]
    #[test_case("1200", true ; "valid geneva")]
    #[test_case("1000", true ; "valid low")]
    #[test_case("9658", true ; "valid upper bound")]
    #[test_case("9999", false ; "invalid above range")]
    #[test_case("9659", false ; "invalid just above")]
    #[test_case("0999", false ; "invalid below range")]
    fn ch_postal(input: &str, expected: bool) {
        assert_eq!(ch_postal_check(input), expected);
    }

    // --- ssn_check ---
    #[test_case("078-05-1120", true ; "valid woolworth wallet SSN from ssa.gov")]
    #[test_case("219-09-9999", true ; "valid SSA pamphlet from ssa.gov")]
    #[test_case("457-55-5462", true ; "valid lifelock CEO")]
    #[test_case("000-12-3456", false ; "invalid area zero")]
    #[test_case("666-12-3456", false ; "invalid area 666")]
    #[test_case("901-12-3456", false ; "invalid area 900 range")]
    fn ssn(input: &str, expected: bool) {
        assert_eq!(ssn_check(input), expected);
    }

    // --- ein_check ---
    #[test_case("53-0196605", true ; "valid Red Cross from ProPublica")]
    #[test_case("20-0049703", true ; "valid Wikimedia Foundation")]
    #[test_case("20-0097189", true ; "valid Mozilla Foundation")]
    #[test_case("07-1234567", false ; "invalid prefix 07")]
    fn ein(input: &str, expected: bool) {
        assert_eq!(ein_check(input), expected);
    }

    // --- aba_check ---
    #[test_case("021000021", true ; "valid JPMorgan Chase from chase.com")]
    #[test_case("026009593", true ; "valid Bank of America wire from bankofamerica.com")]
    #[test_case("121000248", true ; "valid Wells Fargo from wise.com")]
    #[test_case("021000089", true ; "valid Citibank from wise.com")]
    #[test_case("111000025", true ; "valid BofA Virginia from Wikipedia")]
    #[test_case("021000022", false ; "invalid checksum")]
    fn aba(input: &str, expected: bool) {
        assert_eq!(aba_check(input), expected);
    }

    // --- nino_check ---
    #[test_case("AA123456C", true ; "valid AA prefix")]
    #[test_case("CE987654B", true ; "valid CE prefix")]
    #[test_case("JY 55 55 55 D", true ; "valid JY with spaces")]
    #[test_case("BG123456C", false ; "invalid prefix BG")]
    #[test_case("GB123456C", false ; "invalid prefix GB")]
    #[test_case("DA123456C", false ; "invalid first letter D")]
    #[test_case("QQ123456C", false ; "invalid Q prefix per GOV.UK")]
    fn nino(input: &str, expected: bool) {
        assert_eq!(nino_check(input), expected);
    }

    // --- nhs_check ---
    #[test_case("9434765919", true ; "valid Wikipedia example")]
    #[test_case("9278462608", true ; "valid from pfwd GitHub")]
    #[test_case("4010232137", true ; "valid computed mod 11")]
    #[test_case("9990000018", true ; "valid NHS test range")]
    #[test_case("9434765910", false ; "invalid checksum")]
    fn nhs(input: &str, expected: bool) {
        assert_eq!(nhs_check(input), expected);
    }

    // --- utr_check ---
    #[test_case("5555555555", true ; "valid fives from HMRC")]
    #[test_case("9987654321", true ; "valid descending")]
    #[test_case("7999888777", true ; "valid nines and eights")]
    #[test_case("1123456789", true ; "valid sequential")]
    #[test_case("1555555555", false ; "invalid checksum")]
    fn utr(input: &str, expected: bool) {
        assert_eq!(utr_check(input), expected);
    }

    // --- uk_dl_check ---
    #[test_case("JONES901157A99Y1", true ; "valid jones male born 15 Nov")]
    #[test_case("JONES900057A99Y1", false ; "invalid month 00")]
    #[test_case("JONES901007A99Y1", false ; "invalid day 00")]
    fn uk_dl(input: &str, expected: bool) {
        assert_eq!(uk_dl_check(input), expected);
    }

    // --- sort_code_check ---
    #[test_case("20-26-86", true ; "valid Barclays Leicester from wise.com")]
    #[test_case("40-05-30", true ; "valid HSBC London from wise.com")]
    #[test_case("60-00-01", true ; "valid NatWest London")]
    #[test_case("30-96-26", true ; "valid Lloyds")]
    fn sort_code(input: &str, expected: bool) {
        assert_eq!(sort_code_check(input), expected);
    }

    // --- tfn_check ---
    #[test_case("123 456 782", true ; "valid canonical from clearwater.com.au")]
    #[test_case("100 000 001", true ; "valid generated 1")]
    #[test_case("100 000 028", true ; "valid generated 2")]
    #[test_case("123 456 789", false ; "invalid checksum")]
    fn tfn(input: &str, expected: bool) {
        assert_eq!(tfn_check(input), expected);
    }

    // --- medicare_check ---
    #[test_case("2123 45670 1", true ; "valid canonical from clearwater.com.au")]
    #[test_case("3189 97702 1", true ; "valid clearwater calc")]
    #[test_case("6950 50739 1", true ; "valid medipass from GitHub")]
    #[test_case("1123 45670 1", false ; "invalid first digit 1")]
    #[test_case("7123 45670 1", false ; "invalid first digit 7")]
    fn medicare(input: &str, expected: bool) {
        assert_eq!(medicare_check(input), expected);
    }

    // --- ird_check ---
    #[test_case("49-091-857", true ; "valid existing 8 digit")]
    #[test_case("10-000-008", true ; "valid generated 8 digit")]
    #[test_case("100-000-148", true ; "valid generated 9 digit")]
    #[test_case("01-000-000", false ; "invalid below range")]
    fn ird(input: &str, expected: bool) {
        assert_eq!(ird_check(input), expected);
    }

    // --- nhi_check ---
    #[test_case("JBX3656", true ; "valid Wikipedia canonical")]
    #[test_case("ZAC5361", true ; "valid from rapidrehita.health.nz")]
    #[test_case("CGC2720", true ; "valid from Wikipedia")]
    #[test_case("EPT6335", true ; "valid from Wikipedia 2")]
    #[test_case("WLD9413", true ; "valid from elilambnz npm")]
    #[test_case("DAB8745", true ; "valid existing")]
    #[test_case("DAI5765", false ; "invalid letter I")]
    #[test_case("DAO5765", false ; "invalid letter O")]
    #[test_case("DAB8740", false ; "invalid check digit")]
    fn nhi(input: &str, expected: bool) {
        assert_eq!(nhi_check(input), expected);
    }

    // --- sin_check ---
    #[test_case("130-692-544", true ; "valid from Straight Line International")]
    #[test_case("810-620-716", true ; "valid from TNAADO")]
    #[test_case("046-454-286", false ; "invalid first digit zero")]
    #[test_case("123-456-789", false ; "invalid luhn")]
    fn sin(input: &str, expected: bool) {
        assert_eq!(sin_check(input), expected);
    }

    // --- ppsn_check ---
    #[test_case("1234567T", true ; "valid Wikipedia old format")]
    #[test_case("1234567TW", true ; "valid old format with W suffix")]
    #[test_case("1234567FA", true ; "valid Wikipedia new format")]
    #[test_case("7654321G", true ; "valid computed 1")]
    #[test_case("5555555N", true ; "valid computed 2")]
    #[test_case("1234567A", false ; "invalid check letter")]
    fn ppsn(input: &str, expected: bool) {
        assert_eq!(ppsn_check(input), expected);
    }

    // --- za_luhn13_check ---
    #[test_case("8001015009087", true ; "valid born 1980-01-01 male citizen")]
    #[test_case("9506150089081", true ; "valid born 1995-06-15 female citizen")]
    #[test_case("9001245289086", true ; "valid from za-id-number PyPI")]
    #[test_case("8801235111088", true ; "valid from Medium article")]
    #[test_case("9501015000084", true ; "valid generated")]
    #[test_case("8013015009087", false ; "invalid month 13")]
    #[test_case("8001325009087", false ; "invalid day 32")]
    #[test_case("8001015009086", false ; "invalid luhn")]
    fn sa_id(input: &str, expected: bool) {
        assert_eq!(za_luhn13_check(input), expected);
    }

    // --- za_postal_check ---
    #[test_case("0001", true ; "valid lower bound")]
    #[test_case("9999", true ; "valid upper bound")]
    #[test_case("8001", true ; "valid cape town")]
    #[test_case("0000", false ; "invalid zero")]
    #[test_case("10000", false ; "invalid five digits")]
    #[test_case("abcd", false ; "invalid letters")]
    fn za_postal(input: &str, expected: bool) {
        assert_eq!(za_postal_check(input), expected);
    }

    // --- us_zip_check ---
    // Real ZIP codes from USPS / Wikipedia.
    #[test_case("90210", true ; "valid beverly hills")]
    #[test_case("10001", true ; "valid manhattan")]
    #[test_case("20500", true ; "valid white house")]
    #[test_case("00501", true ; "valid lowest holtsville ny")]
    #[test_case("99950", true ; "valid highest ketchikan ak")]
    #[test_case("90210-1234", true ; "valid zip plus four")]
    #[test_case("00000", true ; "valid all zeros structurally")]
    #[test_case("9021", false ; "invalid four digits")]
    #[test_case("902100", false ; "invalid six digits")]
    #[test_case("90210-12345", false ; "invalid zip plus five")]
    #[test_case("9021A", false ; "invalid letter")]
    #[test_case("90210 1234", false ; "invalid space separator")]
    fn us_zip(input: &str, expected: bool) {
        assert_eq!(us_zip_check(input), expected);
    }

    // --- us_za_postal_check ---
    #[test_case("0001", true ; "valid za")]
    #[test_case("90210", true ; "valid us")]
    #[test_case("90210-1234", true ; "valid us zip plus four")]
    #[test_case("0000", false ; "invalid za zero")]
    #[test_case("123", false ; "invalid three digits")]
    #[test_case("100000", false ; "invalid six digits")]
    fn us_za_postal(input: &str, expected: bool) {
        assert_eq!(us_za_postal_check(input), expected);
    }

    // --- ie_eircode_check ---
    // Real Eircodes from Wikipedia and eircode.ie.
    #[test_case("D02 X285", true ; "valid dublin 2")]
    #[test_case("D02X285", true ; "valid dublin 2 no space")]
    #[test_case("d02 x285", true ; "valid lowercase normalised")]
    #[test_case("T12 N5CY", true ; "valid cork")]
    #[test_case("D6W FD93", true ; "valid d6w special routing key")]
    #[test_case("D6w fd93", true ; "valid d6w lowercase")]
    #[test_case("F92 AB12", true ; "valid donegal")]
    #[test_case("D02-X285", false ; "invalid hyphen separator")]
    #[test_case("D02 X28", false ; "invalid too short")]
    #[test_case("D02 X2855", false ; "invalid too long")]
    #[test_case("12 X285", false ; "invalid digit first")]
    #[test_case("DXX X285", false ; "invalid letters in routing digits")]
    #[test_case("D2W X285", false ; "invalid w not at d6")]
    fn ie_eircode(input: &str, expected: bool) {
        assert_eq!(ie_eircode_check(input), expected);
    }

    // --- za_trn_check ---
    #[test_case("0123456789", true ; "valid prefix 0")]
    #[test_case("1234567890", true ; "valid prefix 1")]
    #[test_case("9876543210", true ; "valid prefix 9")]
    #[test_case("4123456789", false ; "invalid prefix 4")]
    #[test_case("5123456789", false ; "invalid prefix 5")]
    fn za_trn(input: &str, expected: bool) {
        assert_eq!(za_trn_check(input), expected);
    }

    // --- ohip_check ---
    #[test_case("1234567897", true ; "valid existing")]
    #[test_case("1234567898", false ; "invalid luhn")]
    fn ohip(input: &str, expected: bool) {
        assert_eq!(ohip_check(input), expected);
    }

    // --- ie_driver_check ---
    #[test_case("123456789", true ; "valid 9 digits")]
    #[test_case("12345678", false ; "invalid 8 digits")]
    #[test_case("1234567890", false ; "invalid 10 digits")]
    fn ie_driver(input: &str, expected: bool) {
        assert_eq!(ie_driver_check(input), expected);
    }

    // --- person_name_check ---
    #[test_case("John Smith", true ; "valid simple name")]
    #[test_case("Jean-Pierre Müller", true ; "valid accented")]
    #[test_case("O'Brien", true ; "valid apostrophe")]
    #[test_case("Madonna", true ; "valid single word")]
    #[test_case("12345", false ; "reject digits only")]
    #[test_case("A", false ; "reject single char")]
    #[test_case("", false ; "reject empty")]
    fn person_name(input: &str, expected: bool) {
        assert_eq!(person_name_check(input), expected);
    }

    // --- de_at_address_check ---
    #[test_case("Musterstraße 42, 10115 Berlin", true ; "valid standard de address")]
    #[test_case("Am Markt 3a, 01067 Dresden", true ; "valid with suffix")]
    #[test_case("Hauptstraße 10-12, 80331 München", true ; "valid with range")]
    #[test_case("Friedrichstraße 43, 10117 Berlin", true ; "valid berlin friedrichstr")]
    #[test_case("Bahnhofstr. 1, 60311 Frankfurt", true ; "valid abbreviated street")]
    #[test_case("Unter den Linden 77, 10117 Berlin", true ; "valid multi word street")]
    #[test_case("Schillerstraße 10, 1010 Wien", true ; "valid at address vienna")]
    #[test_case("Josefstädterstraße 21/5, 1080 Wien", true ; "valid at address slash notation")]
    #[test_case("Mariahilfer Straße 45/2/14, 1060 Wien", true ; "valid at address multi slash")]
    #[test_case("Landstraßer Hauptstraße 5a, 1030 Wien", true ; "valid at address letter suffix")]
    // CH addresses — verified real locations
    #[test_case("Bahnhofstrasse 1, 8001 Zürich", true ; "valid ch address zurich")] // Hauser & Wirth gallery
    #[test_case("Bundesplatz 3, 3003 Bern", true ; "valid ch address bern")] // Federal Palace
    #[test_case("Pilatusstrasse 15, 6003 Luzern", true ; "valid ch address luzern")] // From Yelp
    #[test_case("Marktgasse 46, 3011 Bern", true ; "valid ch address bern marktgasse")] // Swiss Post location
    #[test_case("Bahnhofstrasse 1, 0500 Zürich", false ; "invalid ch plz below 1000")]
    #[test_case("Str. 42", false ; "invalid no PLZ")]
    #[test_case("short", false ; "invalid too short")]
    #[test_case("Musterstraße Berlin", false ; "invalid no digits")]
    #[test_case("Schillerstraße 10, 0999 Wien", false ; "invalid at plz below 1010")]
    fn de_at_address(input: &str, expected: bool) {
        assert_eq!(de_at_address_check(input), expected);
    }

    // --- de_at_postfach_check ---
    #[test_case("1234, 10557 Berlin", true ; "valid postfach berlin")]
    #[test_case("56, 80331 München", true ; "valid short postfach number")]
    #[test_case("123456, 01067 Dresden", true ; "valid 6 digit postfach")]
    #[test_case("789, 5020 Salzburg", true ; "valid at postfach salzburg")]
    #[test_case("56, 4020 Linz", true ; "valid at postfach linz")]
    #[test_case("567, 6000 Luzern", true ; "valid ch postfach luzern")]
    #[test_case("1234, 8001 Zürich", true ; "valid ch postfach zurich")]
    #[test_case("12, 00000 Nowhere", false ; "invalid PLZ zeros")]
    #[test_case("1234567, 10115 Berlin", false ; "invalid 7 digit postfach")]
    fn de_at_postfach(input: &str, expected: bool) {
        assert_eq!(de_at_postfach_check(input), expected);
    }

    // --- de_packstation_check ---
    #[test_case("109, 01099 Dresden", true ; "valid packstation 3 digits")]
    #[test_case("1234, 10115 Berlin", true ; "valid packstation 4 digits")]
    #[test_case("12, 10115 Berlin", false ; "invalid 2 digit station")]
    #[test_case("12345, 10115 Berlin", false ; "invalid 5 digit station")]
    #[test_case("109, 00000 Nowhere", false ; "invalid PLZ zeros")]
    fn de_packstation(input: &str, expected: bool) {
        assert_eq!(de_packstation_check(input), expected);
    }

    // --- de_passport_check ---
    #[test_case("C01X00T47", true ; "valid de passport restricted letters")]
    #[test_case("CFGHJKLMN", true ; "valid de passport all letters from restricted set")]
    #[test_case("c01x00t47", true ; "valid de passport lowercase normalised")]
    #[test_case("123456789", false ; "invalid all digits no letter")]
    #[test_case("C01X00T4", false ; "invalid too short")]
    #[test_case("C01X00T478", false ; "invalid too long")]
    #[test_case("A01X00T47", false ; "invalid letter A not in restricted alphabet")]
    #[test_case("B01X00T47", false ; "invalid letter B not in restricted alphabet")]
    #[test_case("D01X00T47", false ; "invalid letter D not in restricted alphabet")]
    #[test_case("S01X00T47", false ; "invalid letter S not in restricted alphabet")]
    fn de_passport(input: &str, expected: bool) {
        assert_eq!(de_passport_check(input), expected);
    }

    // --- gb_address_check ---
    #[test_case("10 Downing Street, London, SW1A 2AA", true ; "valid downing street")]
    #[test_case("221B Baker Street, London NW1 6XE", true ; "valid baker street")]
    #[test_case("30 St Mary Axe, London EC3A 8BF", true ; "valid gherkin")]
    #[test_case("350 Euston Road, London NW1 2RH", true ; "valid euston road")]
    #[test_case("20 Fenchurch Street, London EC3M 8AF", true ; "valid walkie talkie")]
    #[test_case("1 Church Lane, Manchester M2 5AB", true ; "valid manchester one-token postcode")]
    #[test_case("short", false ; "invalid too short")]
    #[test_case("1600 Pennsylvania Avenue NW, Washington DC 20500", false ; "invalid us address")]
    #[test_case("Street Without Postcode, London", false ; "invalid no postcode")]
    #[test_case("10 Downing Street", false ; "invalid not enough tokens")]
    fn gb_address(input: &str, expected: bool) {
        assert_eq!(gb_address_check(input), expected);
    }

    // --- fr_ch_address_check ---
    #[test_case("15 Rue de la Paix, 75002 Paris", true ; "valid paris street")]
    #[test_case("1 Avenue des Champs-Élysées, 75008 Paris", true ; "valid champs elysees")]
    #[test_case("42 Boulevard Haussmann, 75009 Paris", true ; "valid boulevard haussmann")]
    #[test_case("3 Place Bellecour, 69002 Lyon", true ; "valid lyon place")]
    #[test_case("7 Allée des Pins, 13008 Marseille", true ; "valid marseille allee")]
    #[test_case("25 Cours de l'Intendance, 33000 Bordeaux", true ; "valid bordeaux cours")]
    #[test_case("10 Impasse du Moulin, 97100 Basse-Terre", true ; "valid overseas guadeloupe")]
    #[test_case("5 Rue du Port, 97400 Saint-Denis", true ; "valid overseas reunion")]
    #[test_case("8bis Rue Victor Hugo, 75016 Paris", true ; "valid with bis")]
    // Real-world FR addresses from official sources
    #[test_case("55 rue du Faubourg Saint-Honoré, 75008 Paris", true ; "valid elysee palace")] // From elysee.fr
    #[test_case("5 avenue Anatole France, 75007 Paris", true ; "valid tour eiffel")] // From toureiffel.paris
    #[test_case("1 rue de la Légion d'Honneur, 75007 Paris", true ; "valid musee orsay")] // From musee-orsay.fr
    #[test_case("36 quai des Orfèvres, 75001 Paris", true ; "valid quai des orfevres")] // From Wikipedia
    #[test_case("86 quai Perrache, 69002 Lyon", true ; "valid musee confluences lyon")] // From museedesconfluences.fr
    #[test_case("37 promenade des Anglais, 06000 Nice", true ; "valid negresco nice")] // From lenegresco.com
    #[test_case("1 boulevard de la Croisette, 06400 Cannes", true ; "valid palais festivals cannes")] // From palaisdesfestivals.com
    #[test_case("151 bis rue de Rennes, 75006 Paris", true ; "valid bis suffix rennes")] // From connexionfrance.com
    // Real-world Swiss French addresses
    #[test_case("Rue du Général-Dufour 24, 1211 Genève", true ; "valid ch geneve unige")] // Université de Genève
    #[test_case("Quai d'Ouchy 1, 1006 Lausanne", true ; "valid ch lausanne olympic")] // Musée Olympique
    #[test_case("Avenue de Cour 135, 1007 Lausanne", true ; "valid ch lausanne cour")] // CIO Lausanne
    #[test_case("Avenue de Chillon 21, 1820 Veytaux", true ; "valid ch veytaux chateau")] // Château de Chillon
    #[test_case("Avenue Nestlé 55, 1800 Vevey", true ; "valid ch vevey nestle")] // Nestlé HQ
    #[test_case("Rue, 00000 Nowhere", false ; "invalid plz zeros")]
    #[test_case("short, 75001", false ; "too short")]
    #[test_case("ab cd", false ; "too few tokens")]
    #[test_case("Rue du Port 5, 0999 Nowhere", false ; "invalid ch plz below range")]
    fn fr_ch_address(input: &str, expected: bool) {
        assert_eq!(fr_ch_address_check(input), expected);
    }

    // --- fr_ch_boite_postale_check ---
    #[test_case("1234, 75008 Paris", true ; "valid bp paris")]
    #[test_case("56, 69001 Lyon", true ; "valid bp lyon")]
    #[test_case("123456, 13001 Marseille", true ; "valid bp 6 digits")]
    #[test_case("1, 33000 Bordeaux", true ; "valid bp single digit")]
    #[test_case("789, 97100 Basse-Terre", true ; "valid bp overseas")]
    // Real-world FR BP addresses
    #[test_case("7008, 97307 Cayenne", true ; "valid bp cayenne guyane")] // From guyane.gouv.fr
    #[test_case("523, 98000 Monaco", true ; "valid bp monaco")] // From mairie.mc
    // Real-world Swiss Case Postale addresses
    #[test_case("2272, 1950 Sion", true ; "valid cp sion")] // Ville de Sion
    #[test_case("440, 1211 Genève", true ; "valid cp geneve")] // From ge.ch
    #[test_case("1234567, 75008 Paris", false ; "invalid bp 7 digits")]
    #[test_case("1234, 00000 Nowhere", false ; "invalid plz zeros")]
    #[test_case("1234, 0999 Nowhere", false ; "invalid ch plz below range")]
    fn fr_ch_boite_postale(input: &str, expected: bool) {
        assert_eq!(fr_ch_boite_postale_check(input), expected);
    }

    // --- au_dl_check ---
    #[test_case("12345678", true ; "valid nsw 8 digits")]
    #[test_case("1234567890", true ; "valid vic 10 digits")]
    #[test_case("01234567", true ; "valid qld 8 digits starting 0")]
    #[test_case("1234567", true ; "valid wa 7 digits")]
    #[test_case("123456", true ; "valid act 6 digits")]
    #[test_case("A12345", true ; "valid tas letter plus 5")]
    #[test_case("B123456789", true ; "valid letter plus 9")]
    #[test_case("12345", false ; "invalid too short 5 digits")]
    #[test_case("12345678901", false ; "invalid too long 11 digits")]
    #[test_case("0000000", false ; "invalid all zeros")]
    #[test_case("A00000", false ; "invalid letter all zeros")]
    #[test_case("AB12345", false ; "invalid two letters")]
    fn au_dl(input: &str, expected: bool) {
        assert_eq!(au_dl_check(input), expected);
    }

    // --- au_abn_check ---
    #[test_case("51824753556", true ; "valid ato abn")] // ATO — from abr.business.gov.au
    #[test_case("53004085616", true ; "valid bp australia")] // BP Australia — from abr.business.gov.au
    #[test_case("33051775556", true ; "valid telstra")] // Telstra — from abr.business.gov.au
    #[test_case("49004028077", true ; "valid bhp")] // BHP — from abr.business.gov.au
    #[test_case("88000014675", true ; "valid woolworths")] // Woolworths — from abr.business.gov.au
    #[test_case("51824753557", false ; "invalid bad checksum")]
    #[test_case("00000000000", false ; "invalid all zeros")]
    #[test_case("1234567890", false ; "invalid 10 digits")]
    #[test_case("123456789012", false ; "invalid 12 digits")]
    fn au_abn(input: &str, expected: bool) {
        assert_eq!(au_abn_check(input), expected);
    }
}
