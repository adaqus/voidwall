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
    let parts: Vec<&str> = s.split(['-', '.', ' ']).collect();
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

// ITU-T E.164 assigned country/global-service codes.
// Sorted ascending for binary_search. Source: ITU-T Recommendation E.164,
// Annex to ITU Operational Bulletin No. 1199 (latest list of assigned codes).
const E164_COUNTRY_CODES: &[u16] = &[
    1, 7, 20, 27, 30, 31, 32, 33, 34, 36, 39, 40, 41, 43, 44, 45, 46, 47, 48, 49, 51, 52, 53, 54,
    55, 56, 57, 58, 60, 61, 62, 63, 64, 65, 66, 81, 82, 84, 86, 90, 91, 92, 93, 94, 95, 98, 211,
    212, 213, 216, 218, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234,
    235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253,
    254, 255, 256, 257, 258, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 290, 291, 297, 298,
    299, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 370, 371, 372, 373, 374, 375, 376, 377,
    378, 379, 380, 381, 382, 383, 385, 386, 387, 389, 420, 421, 423, 500, 501, 502, 503, 504, 505,
    506, 507, 508, 509, 590, 591, 592, 593, 594, 595, 596, 597, 598, 599, 670, 672, 673, 674, 675,
    676, 677, 678, 679, 680, 681, 682, 683, 685, 686, 687, 688, 689, 690, 691, 692, 800, 808, 850,
    852, 853, 855, 856, 870, 878, 880, 881, 882, 883, 886, 888, 960, 961, 962, 963, 964, 965, 966,
    967, 968, 970, 971, 972, 973, 974, 975, 976, 977, 979, 991, 992, 993, 994, 995, 996, 998,
];

pub(crate) fn e164_check(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'+') {
        return false;
    }
    let mut digits = [0u8; 15];
    let mut len = 0usize;
    for &b in &bytes[1..] {
        if b.is_ascii_digit() {
            if len >= 15 {
                return false;
            }
            digits[len] = b - b'0';
            len += 1;
        }
    }
    if !(8..=15).contains(&len) || digits[0] == 0 {
        return false;
    }
    // Longest-prefix match against assigned codes.
    let cc3 = digits[0] as u16 * 100 + digits[1] as u16 * 10 + digits[2] as u16;
    if E164_COUNTRY_CODES.binary_search(&cc3).is_ok() {
        return true;
    }
    let cc2 = digits[0] as u16 * 10 + digits[1] as u16;
    if E164_COUNTRY_CODES.binary_search(&cc2).is_ok() {
        return true;
    }
    let cc1 = digits[0] as u16;
    E164_COUNTRY_CODES.binary_search(&cc1).is_ok()
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

/// US driver's-license number, numeric-only state formats (no letter prefix,
/// e.g. Georgia/Florida-style all-digit numbers). Keyword-gated, so only
/// structural validation: 6–12 digits, not a single repeated digit (rejects
/// placeholders like `00000000`).
pub(crate) fn us_dl_numeric_check(s: &str) -> bool {
    let digits: Vec<u8> = s.bytes().filter(|b| b.is_ascii_digit()).collect();
    if !(6..=12).contains(&digits.len()) {
        return false;
    }
    !digits.iter().all(|&b| b == digits[0])
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

/// Canadian driver's-licence number, letter-carrying provincial formats only
/// (ON, QC, NL, NS, MB). No province publishes a check digit, so this is
/// structural validation of the layout after stripping optional hyphens. Each
/// accepted format has a unique cleaned length, so length selects the layout:
///   ON  1 letter + 14 digits            (len 15)
///   NS  5 letters + 9 digits            (len 14)
///   QC  1 letter + 12 digits            (len 13)
///   MB  7 letters + 3 digits + 2 letters(len 12)
///   NL  1 letter + 9 digits             (len 10)
/// A digit run that is a single repeated digit is rejected as a placeholder.
pub(crate) fn ca_dl_check(s: &str) -> bool {
    let clean: Vec<u8> = s.bytes().filter(|&b| b != b'-').collect();
    let alpha = |sl: &[u8]| sl.iter().all(|b| b.is_ascii_alphabetic());
    // All digits, and not a single repeated digit (rejects 000000000 filler).
    let digits =
        |sl: &[u8]| sl.iter().all(|b| b.is_ascii_digit()) && !sl.iter().all(|&b| b == sl[0]);
    match clean.len() {
        15 => alpha(&clean[..1]) && digits(&clean[1..]), // ON
        14 => alpha(&clean[..5]) && digits(&clean[5..]), // NS
        13 => alpha(&clean[..1]) && digits(&clean[1..]), // QC
        12 => alpha(&clean[..7]) && digits(&clean[7..10]) && alpha(&clean[10..]), // MB
        10 => alpha(&clean[..1]) && digits(&clean[1..]), // NL
        _ => false,
    }
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
    // Current year upper bound
    const MAX_YEAR: u32 = 2030; // generous upper bound; birth years won't exceed current year

    // Helper to validate y/m/d components
    let valid_date = |y: u32, m: u32, d: u32| -> bool {
        (1900..=MAX_YEAR).contains(&y) && (1..=12).contains(&m) && (1..=31).contains(&d)
    };

    // Month names across all supported languages (en, fr, de, nl), full names plus
    // common abbreviations. to_lowercase() (not to_ascii_lowercase) so non-ASCII names
    // like "février" and "märz" match.
    let month_from_name = |name: &str| -> Option<u32> {
        match name.to_lowercase().as_str() {
            "jan" | "january" | "janvier" | "janv" | "januar" | "januari" | "gennaio" | "gen"
            | "enero" | "ene" | "stycznia" | "styczeń" | "sty" => Some(1),
            "feb" | "february" | "février" | "fevrier" | "févr" | "fevr" | "februar"
            | "februari" | "febbraio" | "febrero" | "lutego" | "luty" | "lut" => Some(2),
            "mar" | "march" | "mars" | "märz" | "maerz" | "mär" | "mrz" | "maart" | "mrt"
            | "marzo" | "marca" | "marzec" => Some(3),
            "apr" | "april" | "avril" | "avr" | "aprile" | "abril" | "abr" | "kwietnia"
            | "kwiecień" | "kwi" => Some(4),
            "may" | "mai" | "mei" | "maggio" | "mag" | "mayo" | "maja" | "maj" => Some(5),
            "jun" | "june" | "juin" | "juni" | "giugno" | "giu" | "junio" | "czerwca"
            | "czerwiec" | "cze" => Some(6),
            "jul" | "july" | "juillet" | "juil" | "juli" | "luglio" | "lug" | "julio" | "lipca"
            | "lipiec" | "lip" => Some(7),
            "aug" | "august" | "août" | "aout" | "augustus" | "agosto" | "ago" | "sierpnia"
            | "sierpień" | "sie" => Some(8),
            "sep" | "september" | "septembre" | "sept" | "settembre" | "sett" | "set"
            | "septiembre" | "setiembre" | "września" | "wrzesień" | "wrz" => Some(9),
            "oct" | "october" | "octobre" | "oktober" | "okt" | "ottobre" | "ott" | "octubre"
            | "października" | "październik" | "paź" => Some(10),
            "nov" | "november" | "novembre" | "noviembre" | "listopada" | "listopad" | "lis" => {
                Some(11)
            }
            "dec" | "december" | "décembre" | "decembre" | "déc" | "dezember" | "dez"
            | "dicembre" | "dic" | "diciembre" | "grudnia" | "grudzień" | "gru" => Some(12),
            _ => None,
        }
    };

    let trimmed = s.trim();

    // Accept an ISO 8601 date-time ("1960-05-27T00:00:00") by validating its date
    // component only. The 'T'/'t' separator sits between two digits, so a bare 't'
    // inside a month name ("maart", "august") is never treated as one.
    let bytes = trimmed.as_bytes();
    let date_part = (1..bytes.len().saturating_sub(1))
        .find(|&i| {
            (bytes[i] == b'T' || bytes[i] == b't')
                && bytes[i - 1].is_ascii_digit()
                && bytes[i + 1].is_ascii_digit()
        })
        .map_or(trimmed, |i| &trimmed[..i]);

    // Try numeric formats: DD/MM/YYYY, MM/DD/YYYY, YYYY-MM-DD (separators: / - .)
    let parts: Vec<&str> = date_part.split(['/', '-', '.']).collect();
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

    // "Month/YY" — month name + 2-digit year, no day (e.g. "October/97"). A
    // reduced-precision birth date; only accepted because the keyword gate already
    // confirmed birth context. Requires a real month name so "12/97" can't match.
    if parts.len() == 2
        && parts[1].trim().len() == 2
        && month_from_name(parts[0].trim()).is_some()
        && parts[1].trim().parse::<u32>().is_ok()
    {
        return true;
    }

    // Parse a day with an optional English ordinal suffix and trailing comma:
    // "15", "3rd", "10th," → the leading digits. Any other trailing text → None.
    let parse_day = |w: &str| -> Option<u32> {
        let w = w.trim_end_matches(',');
        let n: String = w.chars().take_while(|c| c.is_ascii_digit()).collect();
        let rest = &w[n.len()..];
        if rest.is_empty()
            || matches!(
                rest.to_ascii_lowercase().as_str(),
                "st" | "nd" | "rd" | "th"
            )
        {
            n.parse().ok()
        } else {
            None
        }
    };

    // Try "DD Month YYYY" — e.g. "15 March 1990", "3rd October 1965", "15 mars 1990"
    let words: Vec<&str> = date_part.split_whitespace().collect();
    if words.len() == 3 {
        // "DD Month YYYY"
        if let (Some(day), Some(month), Ok(year)) = (
            parse_day(words[0]),
            month_from_name(words[1]),
            words[2].parse::<u32>(),
        ) {
            return valid_date(year, month, day);
        }
        // "Month DD, YYYY" / "Month DDth, YYYY"
        if let (Some(month), Some(day), Ok(year)) = (
            month_from_name(words[0]),
            parse_day(words[1]),
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

/// Dutch BSN (Burgerservicenummer) check: 8 or 9 digits validated with the
/// "11-proef" (eleven test). Weights 9,8,7,6,5,4,3,2 on the first eight digits
/// and −1 on the check digit; valid when the weighted sum is divisible by 11.
/// 8-digit numbers (leading zero dropped) are left-padded with a zero. The
/// all-zero number is rejected.
pub(crate) fn bsn_check(s: &str) -> bool {
    let mut digits: Vec<i32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10).map(|d| d as i32))
        .collect();
    if digits.len() == 8 {
        digits.insert(0, 0);
    }
    if digits.len() != 9 {
        return false;
    }
    if digits.iter().all(|&d| d == 0) {
        return false;
    }
    let weights: [i32; 9] = [9, 8, 7, 6, 5, 4, 3, 2, -1];
    let sum: i32 = digits
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d * w)
        .sum();
    sum % 11 == 0
}

/// Dutch BTW (VAT identification) number check: structural validation of the
/// `NL` + 9 digits + `B` + 2-digit sub-number form (e.g. `NL123456789B01`).
/// The post-2020 btw-id uses a randomly generated core that does not follow
/// the 11-test, so only structure is validated. The sub-number must be 01–99.
pub(crate) fn nl_btw_check(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 14 {
        return false;
    }
    if !bytes[0].eq_ignore_ascii_case(&b'N') || !bytes[1].eq_ignore_ascii_case(&b'L') {
        return false;
    }
    if !bytes[2..11].iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if !bytes[11].eq_ignore_ascii_case(&b'B') {
        return false;
    }
    if !bytes[12..14].iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let sub: u32 = s[12..14].parse().unwrap_or(0);
    (1..=99).contains(&sub)
}

/// Dutch postal code check: 4 digits (first digit 1–9) followed by 2 letters,
/// optional whitespace between (e.g. `1011 AB`, `3062PA`). Structural only —
/// there is no published checksum for Dutch postal codes.
pub(crate) fn nl_postal_check(s: &str) -> bool {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = clean.as_bytes();
    if bytes.len() != 6 {
        return false;
    }
    if !(b'1'..=b'9').contains(&bytes[0]) {
        return false;
    }
    bytes[1..4].iter().all(|b| b.is_ascii_digit())
        && bytes[4..6].iter().all(|b| b.is_ascii_alphabetic())
}

/// Dutch passport / identity-card document number check: 9 alphanumeric
/// characters containing at least one letter and at least one digit. The
/// letter requirement distinguishes it from the 9-digit BSN; the digit
/// requirement keeps plain words from matching.
pub(crate) fn nl_passport_check(s: &str) -> bool {
    if s.len() != 9 || !s.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    s.bytes().any(|b| b.is_ascii_alphabetic()) && s.bytes().any(|b| b.is_ascii_digit())
}

/// Dutch driving licence (rijbewijs) number check: exactly 10 digits, not all
/// zero. Structural only — no published checksum.
pub(crate) fn nl_dl_check(s: &str) -> bool {
    s.len() == 10 && s.bytes().all(|b| b.is_ascii_digit()) && s.bytes().any(|b| b != b'0')
}

/// Italian codice fiscale check: 16 alphanumeric characters whose final
/// character is a check letter computed from the first 15 via the odd/even
/// conversion tables (DM 23/12/1976). Validates the structural mask
/// (`LLLLLL DD L DD L DDD L`) and the check character.
pub(crate) fn it_codice_fiscale_check(s: &str) -> bool {
    let cf = s.trim().to_ascii_uppercase();
    let bytes = cf.as_bytes();
    if bytes.len() != 16 || !bytes.iter().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    // Structural mask: L=letter, D=digit.
    const MASK: &[u8; 16] = b"LLLLLLDDLDDLDDDL";
    for (&b, &m) in bytes.iter().zip(MASK.iter()) {
        match m {
            b'L' if !b.is_ascii_alphabetic() => return false,
            b'D' if !b.is_ascii_digit() => return false,
            _ => {}
        }
    }
    // Odd-position (1-indexed) conversion table.
    let odd = |c: u8| -> u32 {
        match c {
            b'0' | b'A' => 1,
            b'1' | b'B' => 0,
            b'2' | b'C' => 5,
            b'3' | b'D' => 7,
            b'4' | b'E' => 9,
            b'5' | b'F' => 13,
            b'6' | b'G' => 15,
            b'7' | b'H' => 17,
            b'8' | b'I' => 19,
            b'9' | b'J' => 21,
            b'K' => 2,
            b'L' => 4,
            b'M' => 18,
            b'N' => 20,
            b'O' => 11,
            b'P' => 3,
            b'Q' => 6,
            b'R' => 8,
            b'S' => 12,
            b'T' => 14,
            b'U' => 16,
            b'V' => 10,
            b'W' => 22,
            b'X' => 25,
            b'Y' => 24,
            _ => 23, // 'Z'
        }
    };
    let even = |c: u8| -> u32 {
        if c.is_ascii_digit() {
            (c - b'0') as u32
        } else {
            (c - b'A') as u32
        }
    };
    let sum: u32 = bytes[..15]
        .iter()
        .enumerate()
        // 1-indexed position: index 0 is position 1 (odd).
        .map(|(i, &c)| if i % 2 == 0 { odd(c) } else { even(c) })
        .sum();
    bytes[15] == b'A' + (sum % 26) as u8
}

/// Italian partita IVA (VAT) check: 11 digits validated with the Luhn (mod-10)
/// algorithm. An optional `IT` country prefix is ignored.
pub(crate) fn it_partita_iva_check(s: &str) -> bool {
    let t = s.trim();
    let b = t.as_bytes();
    let core =
        if b.len() == 13 && b[0].eq_ignore_ascii_case(&b'I') && b[1].eq_ignore_ascii_case(&b'T') {
            &t[2..]
        } else {
            t
        };
    if core.len() != 11 || !core.bytes().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let sum: u32 = core
        .bytes()
        .enumerate()
        .map(|(i, c)| {
            let d = (c - b'0') as u32;
            if i % 2 == 0 {
                d
            } else {
                let x = d * 2;
                if x > 9 { x - 9 } else { x }
            }
        })
        .sum();
    sum % 10 == 0
}

/// Italian CAP (postal code) check: exactly 5 digits within the assigned
/// range 00010–98168. Structural/range only — there is no checksum.
pub(crate) fn it_postal_check(s: &str) -> bool {
    let t = s.trim();
    if t.len() != 5 || !t.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let n: u32 = t.parse().unwrap_or(0);
    (10..=98168).contains(&n)
}

/// Italian passport number check: 2 letters followed by 7 digits
/// (e.g. `AA1234567`). Structural only — no public checksum.
pub(crate) fn it_passport_check(s: &str) -> bool {
    let b = s.trim().as_bytes();
    b.len() == 9
        && b[..2].iter().all(|c| c.is_ascii_alphabetic())
        && b[2..].iter().all(|c| c.is_ascii_digit())
}

/// Italian driving licence (patente) number check: 10 alphanumeric characters
/// beginning and ending with a letter and containing at least one digit
/// (e.g. `U1H68I903B`, `MI5023443R`). Structural only — no public checksum.
pub(crate) fn it_dl_check(s: &str) -> bool {
    let b = s.trim().as_bytes();
    b.len() == 10
        && b.iter().all(|c| c.is_ascii_alphanumeric())
        && b[0].is_ascii_alphabetic()
        && b[9].is_ascii_alphabetic()
        && b.iter().any(|c| c.is_ascii_digit())
}

/// DNI/NIE control-letter table. The letter is the body number mod 23 indexed
/// into this string. Same table for DNI and NIE.
const ES_DNI_TABLE: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";

/// Spanish DNI / NIF (individual) check: 8 digits + control letter (mod-23).
/// e.g. `12345678Z`. The letter is `ES_DNI_TABLE[number % 23]`.
pub(crate) fn es_dni_check(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 9 || !b[..8].iter().all(|c| c.is_ascii_digit()) || !b[8].is_ascii_alphabetic() {
        return false;
    }
    let num: u32 = s[..8].parse().unwrap_or(0);
    ES_DNI_TABLE[(num % 23) as usize] == b[8].to_ascii_uppercase()
}

/// Spanish NIE (foreigner) check: leading X/Y/Z + 7 digits + control letter.
/// The prefix maps X→0, Y→1, Z→2; the resulting 8-digit number is validated
/// with the DNI mod-23 algorithm. e.g. `X1234567L`.
pub(crate) fn es_nie_check(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 9 || !b[1..8].iter().all(|c| c.is_ascii_digit()) || !b[8].is_ascii_alphabetic() {
        return false;
    }
    let prefix = match b[0].to_ascii_uppercase() {
        b'X' => 0,
        b'Y' => 1,
        b'Z' => 2,
        _ => return false,
    };
    let num: u32 = (prefix * 10_000_000) + s[1..8].parse::<u32>().unwrap_or(0);
    ES_DNI_TABLE[(num % 23) as usize] == b[8].to_ascii_uppercase()
}

/// Spanish CIF (legal-entity tax ID) check: org-type letter + 7 digits +
/// control character. The control is a weighted sum of the 7 digits (odd
/// positions doubled, capped at 9). Depending on the org letter the control
/// is a digit (`A,B,E,H`), a letter from `JABCDEFGHI` (`P,Q,S,W`), or either.
pub(crate) fn es_cif_check(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 9 || !b[1..8].iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let org = b[0].to_ascii_uppercase();
    if !matches!(
        org,
        b'A' | b'B'
            | b'C'
            | b'D'
            | b'E'
            | b'F'
            | b'G'
            | b'H'
            | b'J'
            | b'N'
            | b'P'
            | b'Q'
            | b'R'
            | b'S'
            | b'U'
            | b'V'
            | b'W'
    ) {
        return false;
    }
    let mut sum: u32 = 0;
    for (i, &c) in b[1..8].iter().enumerate() {
        let d = (c - b'0') as u32;
        if i % 2 == 0 {
            // CIF positions 1,3,5,7 (1-indexed): doubled, digits summed if >9.
            let v = d * 2;
            sum += if v > 9 { v - 9 } else { v };
        } else {
            sum += d;
        }
    }
    let last = sum % 10;
    let ctrl = if last != 0 { 10 - last } else { 0 };
    let ctrl_digit = b'0' + ctrl as u8;
    let ctrl_letter = b"JABCDEFGHI"[ctrl as usize];
    let given = b[8].to_ascii_uppercase();
    match org {
        b'P' | b'Q' | b'S' | b'W' => given == ctrl_letter,
        b'A' | b'B' | b'E' | b'H' => given == ctrl_digit,
        _ => given == ctrl_digit || given == ctrl_letter,
    }
}

/// Spanish social-security number (NUSS/NAF) check: 11 or 12 digits, first two
/// being the province of allocation (01–66). Structural only — the control-
/// digit algorithm is not publicly documented.
pub(crate) fn es_nuss_check(s: &str) -> bool {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 11 && digits.len() != 12 {
        return false;
    }
    let prov: u32 = digits[..2].parse().unwrap_or(0);
    (1..=66).contains(&prov)
}

/// Spanish passport number check: 2 or 3 letters followed by 6 digits
/// (e.g. `ABC123456`). Structural only — no public checksum.
pub(crate) fn es_passport_check(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 8 && b.len() != 9 {
        return false;
    }
    let letters = b.len() - 6;
    b[..letters].iter().all(|c| c.is_ascii_alphabetic())
        && b[letters..].iter().all(|c| c.is_ascii_digit())
}

/// Spanish postal code check: 5 digits whose first two are the province
/// (01–52), giving the range 01000–52999.
pub(crate) fn es_postal_check(s: &str) -> bool {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() != 5 || !clean.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let prov: u32 = clean[..2].parse().unwrap_or(0);
    (1..=52).contains(&prov)
}

/// Polish PESEL check: 11 digits YYMMDDZZZXQ. Weighted mod-10 check digit
/// (weights 1,3,7,9 repeating) plus birth-date validation — the month field
/// encodes the century (+0 → 1900s, +20 → 2000s, +40 → 2100s, +60 → 2200s,
/// +80 → 1800s).
pub(crate) fn pl_pesel_check(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 11 {
        return false;
    }
    const WEIGHTS: [u32; 10] = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let sum: u32 = digits[..10].iter().zip(WEIGHTS).map(|(d, w)| d * w).sum();
    if (10 - sum % 10) % 10 != digits[10] {
        return false;
    }
    let mm = digits[2] * 10 + digits[3];
    let dd = digits[4] * 10 + digits[5];
    (1..=12).contains(&(mm % 20)) && mm / 20 <= 4 && (1..=31).contains(&dd)
}

/// Polish NIP (tax ID) check: 10 digits (separators allowed, optional `PL`
/// prefix in the EU-VAT form). Weighted mod-11 checksum with weights
/// 6,5,7,2,3,4,5,6,7; a remainder of 10 is invalid by definition.
pub(crate) fn pl_nip_check(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 10 {
        return false;
    }
    const WEIGHTS: [u32; 9] = [6, 5, 7, 2, 3, 4, 5, 6, 7];
    let rem = digits[..9]
        .iter()
        .zip(WEIGHTS)
        .map(|(d, w)| d * w)
        .sum::<u32>()
        % 11;
    rem != 10 && rem == digits[9]
}

fn pl_regon9_valid(digits: &[u32]) -> bool {
    const WEIGHTS: [u32; 8] = [8, 9, 2, 3, 4, 5, 6, 7];
    let rem = digits[..8]
        .iter()
        .zip(WEIGHTS)
        .map(|(d, w)| d * w)
        .sum::<u32>()
        % 11;
    (if rem == 10 { 0 } else { rem }) == digits[8]
}

/// Polish REGON (business registry) check: 9 digits, or 14 digits for local
/// units. Weighted mod-11 checksum (remainder 10 → check digit 0); the first
/// 9 digits of a 14-digit REGON must themselves be a valid 9-digit REGON.
pub(crate) fn pl_regon_check(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    match digits.len() {
        9 => pl_regon9_valid(&digits),
        14 => {
            const WEIGHTS: [u32; 13] = [2, 4, 8, 5, 0, 9, 7, 3, 6, 1, 2, 4, 8];
            let rem = digits[..13]
                .iter()
                .zip(WEIGHTS)
                .map(|(d, w)| d * w)
                .sum::<u32>()
                % 11;
            pl_regon9_valid(&digits[..9]) && (if rem == 10 { 0 } else { rem }) == digits[13]
        }
        _ => false,
    }
}

// ICAO 9303-style character value: digits keep face value, letters A=10..Z=35.
fn pl_mrz_char_value(c: u8) -> u32 {
    if c.is_ascii_digit() {
        (c - b'0') as u32
    } else {
        (c.to_ascii_uppercase() - b'A' + 10) as u32
    }
}

/// Polish ID card (dowód osobisty) check: 3 letters + 6 digits, where the
/// first digit is the check digit. ICAO-style weights 7,3,1,9,7,3,1,7,3 over
/// all 9 characters; valid iff the weighted sum is divisible by 10
/// (e.g. `ABS123456` from romek.info).
pub(crate) fn pl_id_card_check(s: &str) -> bool {
    let chars: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if chars.len() != 9
        || !chars[..3].iter().all(|c| c.is_ascii_alphabetic())
        || !chars[3..].iter().all(|c| c.is_ascii_digit())
    {
        return false;
    }
    const WEIGHTS: [u32; 9] = [7, 3, 1, 9, 7, 3, 1, 7, 3];
    let sum: u32 = chars
        .iter()
        .zip(WEIGHTS)
        .map(|(&c, w)| pl_mrz_char_value(c) * w)
        .sum();
    sum % 10 == 0
}

/// Polish passport number check: 2 letters + 7 digits, where the first digit
/// is the check digit. ICAO-style weights 7,3,9,1,7,3,1,7,3 over all 9
/// characters; valid iff the weighted sum is divisible by 10
/// (e.g. `CC7999486` from romek.info).
pub(crate) fn pl_passport_check(s: &str) -> bool {
    let chars: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if chars.len() != 9
        || !chars[..2].iter().all(|c| c.is_ascii_alphabetic())
        || !chars[2..].iter().all(|c| c.is_ascii_digit())
    {
        return false;
    }
    const WEIGHTS: [u32; 9] = [7, 3, 9, 1, 7, 3, 1, 7, 3];
    let sum: u32 = chars
        .iter()
        .zip(WEIGHTS)
        .map(|(&c, w)| pl_mrz_char_value(c) * w)
        .sum();
    sum % 10 == 0
}

/// Polish postal code check: `dd-ddd` (e.g. `00-950` Warsaw). Structural
/// only — all two-digit prefixes are in use.
pub(crate) fn pl_postal_check(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 6
        && b[..2].iter().all(|c| c.is_ascii_digit())
        && b[2] == b'-'
        && b[3..].iter().all(|c| c.is_ascii_digit())
}

/// Polish driving licence number check: 5 digits / 2 digits / 4 or 7 digits
/// (e.g. `12345/67/8901`). Structural only — no public checksum.
pub(crate) fn pl_dl_check(s: &str) -> bool {
    let parts: Vec<&str> = s.split('/').collect();
    parts.len() == 3
        && parts[0].len() == 5
        && parts[1].len() == 2
        && (parts[2].len() == 4 || parts[2].len() == 7)
        && parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit()))
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
    #[test_case("078.05.1120", true ; "valid woolworth wallet SSN dot separators")]
    #[test_case("078 05 1120", true ; "valid woolworth wallet SSN space separators")]
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

    // --- us_dl_numeric_check ---
    #[test_case("466530638", true ; "valid 9 digits")]
    #[test_case("123456", true ; "valid 6 digits min")]
    #[test_case("123456789012", true ; "valid 12 digits max")]
    #[test_case("12345", false ; "too few 5 digits")]
    #[test_case("1234567890123", false ; "too many 13 digits")]
    #[test_case("00000000", false ; "all zeros placeholder")]
    fn us_dl_numeric(input: &str, expected: bool) {
        assert_eq!(us_dl_numeric_check(input), expected);
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

    // --- ca_dl_check --- (letter-carrying provincial formats, hyphens optional)
    #[test_case("A1234-56789-01234", true ; "ontario hyphenated")]
    #[test_case("A12345678901234", true ; "ontario plain l+14")]
    #[test_case("L1234-567890-12", true ; "quebec hyphenated")]
    #[test_case("L123456789012", true ; "quebec plain l+12")]
    #[test_case("A123456789", true ; "newfoundland l+9")]
    #[test_case("SMITH123456789", true ; "nova scotia 5l+9")]
    #[test_case("SMITH-123456789", true ; "nova scotia hyphenated")]
    #[test_case("ABCDEFG123HI", true ; "manitoba 7l+3d+2l")]
    #[test_case("AB-CD-EF-G123HI", true ; "manitoba hyphenated")]
    #[test_case("A000000000", false ; "placeholder all zeros nl")]
    #[test_case("A12345", false ; "too short")]
    #[test_case("ABCDEF123456789", false ; "six letter prefix not ns")]
    #[test_case("A1234567890123", false ; "l+13 unknown length")]
    #[test_case("1234567890", false ; "no letter prefix")]
    fn ca_dl(input: &str, expected: bool) {
        assert_eq!(ca_dl_check(input), expected);
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

    // --- bsn_check ---
    // Valid 11-test BSNs verified independently with a Python reimplementation
    // of the eleven-test (weights 9..2,-1). 111222333 and 123456782 are the
    // commonly published Dutch test BSNs; the others were generated and checked.
    #[test_case("111222333", true ; "valid published test bsn")]
    #[test_case("123456782", true ; "valid classic test bsn")]
    #[test_case("100000009", true ; "valid low bsn")]
    #[test_case("627861945", true ; "valid generated bsn")]
    #[test_case("66279008", true ; "valid 8 digit leading zero dropped")] // 066279008
    #[test_case("1234.56.782", true ; "valid with dot separators")]
    #[test_case("111222334", false ; "invalid check digit off by one")]
    #[test_case("123456783", false ; "invalid check digit")]
    #[test_case("000000000", false ; "invalid all zeros")]
    #[test_case("12345678", false ; "invalid 8 digit fails 11 test")] // 012345678 not divisible
    #[test_case("1234567", false ; "invalid too short")]
    #[test_case("1234567890", false ; "invalid too long")]
    fn bsn(input: &str, expected: bool) {
        assert_eq!(bsn_check(input), expected);
    }

    // --- nl_btw_check ---
    #[test_case("NL000099998B57", true ; "valid belastingdienst example")] // official NL tax authority example
    #[test_case("NL123456789B01", true ; "valid format example")]
    #[test_case("nl123456789b01", true ; "valid lowercase")]
    #[test_case("NL123456789B00", false ; "invalid sub number zero")]
    #[test_case("NL123456789C01", false ; "invalid missing B")]
    #[test_case("NL12345678B01", false ; "invalid too few digits")]
    #[test_case("DE123456789B01", false ; "invalid wrong country")]
    fn nl_btw(input: &str, expected: bool) {
        assert_eq!(nl_btw_check(input), expected);
    }

    // --- nl_postal_check ---
    #[test_case("1011 AB", true ; "valid amsterdam with space")] // Amsterdam centre
    #[test_case("1011AB", true ; "valid no space")]
    #[test_case("3062 PA", true ; "valid rotterdam")]
    #[test_case("9999 ZZ", true ; "valid upper range")]
    #[test_case("1000 aa", true ; "valid lowercase letters")]
    #[test_case("0123 AB", false ; "invalid leading zero")]
    #[test_case("123 AB", false ; "invalid three digits")]
    #[test_case("1011 A", false ; "invalid one letter")]
    #[test_case("1011 A1", false ; "invalid digit in letters")]
    fn nl_postal(input: &str, expected: bool) {
        assert_eq!(nl_postal_check(input), expected);
    }

    // --- nl_passport_check ---
    #[test_case("BX1234567", true ; "valid two letters seven digits")]
    #[test_case("NP0A1B2C3", true ; "valid mixed alphanumeric")]
    #[test_case("123456789", false ; "invalid all digits is bsn")]
    #[test_case("ABCDEFGHI", false ; "invalid all letters")]
    #[test_case("BX123456", false ; "invalid too short")]
    #[test_case("BX12345678", false ; "invalid too long")]
    fn nl_passport(input: &str, expected: bool) {
        assert_eq!(nl_passport_check(input), expected);
    }

    // --- nl_dl_check ---
    #[test_case("1234567890", true ; "valid ten digits")]
    #[test_case("0000000001", true ; "valid leading zeros")]
    #[test_case("0000000000", false ; "invalid all zeros")]
    #[test_case("123456789", false ; "invalid nine digits")]
    #[test_case("12345678901", false ; "invalid eleven digits")]
    #[test_case("123456789A", false ; "invalid contains letter")]
    fn nl_dl(input: &str, expected: bool) {
        assert_eq!(nl_dl_check(input), expected);
    }

    // --- it_codice_fiscale_check ---
    // Real valid examples verified independently against the DM 23/12/1976
    // check-character algorithm (see en.wikipedia.org/wiki/Italian_fiscal_code).
    #[test_case("RSSMRA80A01H501U", true ; "valid rome h501")]
    #[test_case("RSSMRA85T10A562S", true ; "valid a562")]
    #[test_case("rssmra80a01h501u", true ; "valid lowercase")]
    #[test_case("RSSMRA80A01H501Z", false ; "invalid check char")]
    #[test_case("RSSMRA85T10A562X", false ; "invalid check char a562")]
    #[test_case("RSSMRA80A01H501", false ; "invalid too short")]
    #[test_case("RSSMRA80A01H501UX", false ; "invalid too long")]
    #[test_case("1SSMRA80A01H501U", false ; "invalid digit in surname slot")]
    #[test_case("RSSMRAA0A01H501U", false ; "invalid letter in year slot")]
    fn it_codice_fiscale(input: &str, expected: bool) {
        assert_eq!(it_codice_fiscale_check(input), expected);
    }

    // --- it_partita_iva_check ---
    // 00488410010 documented at vatdb.com; 12345678903 computed independently.
    #[test_case("00488410010", true ; "valid documented")]
    #[test_case("12345678903", true ; "valid computed")]
    #[test_case("IT00488410010", true ; "valid with it prefix")]
    #[test_case("it12345678903", true ; "valid lowercase prefix")]
    #[test_case("00488410011", false ; "invalid checksum")]
    #[test_case("1234567890", false ; "invalid ten digits")]
    #[test_case("123456789012", false ; "invalid twelve digits")]
    #[test_case("1234567890A", false ; "invalid non digit")]
    fn it_partita_iva(input: &str, expected: bool) {
        assert_eq!(it_partita_iva_check(input), expected);
    }

    // --- it_postal_check ---
    #[test_case("00184", true ; "valid rome")]
    #[test_case("20121", true ; "valid milan")]
    #[test_case("98168", true ; "valid messina upper bound")]
    #[test_case("00010", true ; "valid lower bound")]
    #[test_case("00009", false ; "invalid below range")]
    #[test_case("98169", false ; "invalid above range")]
    #[test_case("99999", false ; "invalid far above range")]
    #[test_case("0018", false ; "invalid four digits")]
    #[test_case("001844", false ; "invalid six digits")]
    #[test_case("0018A", false ; "invalid non digit")]
    fn it_postal(input: &str, expected: bool) {
        assert_eq!(it_postal_check(input), expected);
    }

    // --- it_passport_check ---
    #[test_case("AA1234567", true ; "valid two letters seven digits")]
    #[test_case("YA9876543", true ; "valid alt")]
    #[test_case("A12345678", false ; "invalid one letter")]
    #[test_case("AAA123456", false ; "invalid three letters")]
    #[test_case("AA123456", false ; "invalid too short")]
    #[test_case("AA12345678", false ; "invalid too long")]
    #[test_case("123456789", false ; "invalid all digits")]
    fn it_passport(input: &str, expected: bool) {
        assert_eq!(it_passport_check(input), expected);
    }

    // --- it_dl_check ---
    #[test_case("U1H68I903B", true ; "valid post 2011 format")]
    #[test_case("MI5023443R", true ; "valid older format")]
    #[test_case("RM1234567A", true ; "valid rm series")]
    #[test_case("1234567890", false ; "invalid starts with digit")]
    #[test_case("U1H68I9035", false ; "invalid ends with digit")]
    #[test_case("ABCDEFGHIJ", false ; "invalid no digit")]
    #[test_case("U1H68I903", false ; "invalid too short")]
    #[test_case("U1H68I903BB", false ; "invalid too long")]
    fn it_dl(input: &str, expected: bool) {
        assert_eq!(it_dl_check(input), expected);
    }

    // --- es_dni_check ---
    // 12345678Z is the canonical worked example; others computed independently.
    #[test_case("12345678Z", true ; "valid canonical")]
    #[test_case("00000000T", true ; "valid all zeros")]
    #[test_case("99999999R", true ; "valid all nines")]
    #[test_case("01234567L", true ; "valid leading zero")]
    #[test_case("12345678z", true ; "valid lowercase letter")]
    #[test_case("12345678A", false ; "invalid wrong letter")]
    #[test_case("1234567Z", false ; "invalid seven digits")]
    #[test_case("123456789", false ; "invalid all digits")]
    #[test_case("1234567 Z", false ; "invalid space")]
    #[test_case("X1234567L", false ; "invalid nie shape")]
    fn es_dni(input: &str, expected: bool) {
        assert_eq!(es_dni_check(input), expected);
    }

    // --- es_nie_check ---
    // X1234567L, Y1234567X, Z1234567R computed via X→0,Y→1,Z→2 + mod-23.
    #[test_case("X1234567L", true ; "valid x prefix")]
    #[test_case("Y1234567X", true ; "valid y prefix")]
    #[test_case("Z1234567R", true ; "valid z prefix")]
    #[test_case("x1234567l", true ; "valid lowercase")]
    #[test_case("X1234567A", false ; "invalid wrong letter")]
    #[test_case("W1234567L", false ; "invalid prefix w")]
    #[test_case("X123456L", false ; "invalid six digits")]
    #[test_case("12345678Z", false ; "invalid dni shape")]
    fn es_nie(input: &str, expected: bool) {
        assert_eq!(es_nie_check(input), expected);
    }

    // --- es_cif_check ---
    // Real-world CIFs: A28015865 (Telefónica), A39000013 (Santander),
    // A15022510 (Inditex), B67338921 computed. Letter-control forms computed.
    #[test_case("A28015865", true ; "valid telefonica digit control")]
    #[test_case("A39000013", true ; "valid santander digit control")]
    #[test_case("A15022510", true ; "valid inditex digit control")]
    #[test_case("B67338921", true ; "valid b digit control")]
    #[test_case("P2800000H", true ; "valid p letter control")]
    #[test_case("Q2818001F", true ; "valid q letter control")]
    #[test_case("a28015865", true ; "valid lowercase org letter")]
    #[test_case("A28015860", false ; "invalid wrong control digit")]
    #[test_case("P28000008", false ; "invalid p needs letter control")]
    #[test_case("A2801586", false ; "invalid too short")]
    #[test_case("I28015865", false ; "invalid org letter i")]
    fn es_cif(input: &str, expected: bool) {
        assert_eq!(es_cif_check(input), expected);
    }

    // --- es_nuss_check ---
    #[test_case("281234567840", true ; "valid 12 digits madrid province")]
    #[test_case("28123456784", true ; "valid 11 digits")]
    #[test_case("011234567812", true ; "valid province 01")]
    #[test_case("661234567812", true ; "valid province 66 upper bound")]
    #[test_case("671234567812", false ; "invalid province above 66")]
    #[test_case("001234567812", false ; "invalid province 00")]
    #[test_case("2812345678", false ; "invalid ten digits")]
    #[test_case("2812345678123", false ; "invalid thirteen digits")]
    fn es_nuss(input: &str, expected: bool) {
        assert_eq!(es_nuss_check(input), expected);
    }

    // --- es_passport_check ---
    #[test_case("ABC123456", true ; "valid three letters six digits")]
    #[test_case("AB123456", true ; "valid two letters six digits")]
    #[test_case("XDA123456", true ; "valid alt")]
    #[test_case("A1234567", false ; "invalid one letter seven digits")]
    #[test_case("ABCD12345", false ; "invalid four letters")]
    #[test_case("ABC12345", false ; "invalid five digits")]
    #[test_case("123456789", false ; "invalid all digits")]
    fn es_passport(input: &str, expected: bool) {
        assert_eq!(es_passport_check(input), expected);
    }

    // --- es_postal_check ---
    #[test_case("28001", true ; "valid madrid")]
    #[test_case("08001", true ; "valid barcelona")]
    #[test_case("01000", true ; "valid lower bound province 01")]
    #[test_case("52999", true ; "valid melilla upper bound")]
    #[test_case("00999", false ; "invalid province 00")]
    #[test_case("53000", false ; "invalid province above 52")]
    #[test_case("2800", false ; "invalid four digits")]
    #[test_case("280011", false ; "invalid six digits")]
    #[test_case("2800A", false ; "invalid non digit")]
    fn es_postal(input: &str, expected: bool) {
        assert_eq!(es_postal_check(input), expected);
    }

    // --- pl_pesel_check ---
    // 44051401359 is the canonical example from Wikipedia (born 1944-05-14).
    // 02070803628 (born 1902) and the +20 month-offset values computed and
    // verified against the published weights 1,3,7,9 repeating.
    #[test_case("44051401359", true ; "valid wikipedia example")]
    #[test_case("02070803628", true ; "valid 1900s")]
    #[test_case("85051512346", true ; "valid 1985")]
    #[test_case("03320145679", true ; "valid 2003 month offset 32")]
    #[test_case("44051401358", false ; "invalid check digit")]
    #[test_case("44131401350", false ; "invalid month 13 valid checksum")]
    #[test_case("44053201353", false ; "invalid day 32 valid checksum")]
    #[test_case("4405140135", false ; "invalid ten digits")]
    #[test_case("440514013591", false ; "invalid twelve digits")]
    #[test_case("4405140135A", false ; "invalid letter")]
    fn pl_pesel(input: &str, expected: bool) {
        assert_eq!(pl_pesel_check(input), expected);
    }

    // --- pl_nip_check ---
    // Real-world NIPs: 7740001454 (PKN Orlen), 5250007738 (PKO BP),
    // 5260250274 — all verified against the weights 6,5,7,2,3,4,5,6,7.
    #[test_case("7740001454", true ; "valid orlen")]
    #[test_case("5250007738", true ; "valid pko bp")]
    #[test_case("5260250274", true ; "valid warsaw office")]
    #[test_case("774-000-14-54", true ; "valid with separators")]
    #[test_case("PL7740001454", true ; "valid eu vat form")]
    #[test_case("7740001455", false ; "invalid check digit")]
    #[test_case("1234567890", false ; "invalid remainder ten")]
    #[test_case("774000145", false ; "invalid nine digits")]
    #[test_case("77400014541", false ; "invalid eleven digits")]
    fn pl_nip(input: &str, expected: bool) {
        assert_eq!(pl_nip_check(input), expected);
    }

    // --- pl_regon_check ---
    // Real-world REGONs: 610188201 (PKN Orlen), 016298263 (PKO BP) — verified
    // against the weights 8,9,2,3,4,5,6,7. 14-digit values computed with the
    // weights 2,4,8,5,0,9,7,3,6,1,2,4,8 over a valid 9-digit base.
    #[test_case("610188201", true ; "valid orlen")]
    #[test_case("016298263", true ; "valid pko bp")]
    #[test_case("123456785", true ; "valid computed")]
    #[test_case("61018820100010", true ; "valid fourteen digit local unit")]
    #[test_case("12345678500010", true ; "valid fourteen digit computed")]
    #[test_case("610188202", false ; "invalid check digit")]
    #[test_case("61018820100011", false ; "invalid fourteenth digit")]
    #[test_case("61018820200010", false ; "invalid nine digit base in fourteen")]
    #[test_case("6101882010", false ; "invalid ten digits")]
    fn pl_regon(input: &str, expected: bool) {
        assert_eq!(pl_regon_check(input), expected);
    }

    // --- pl_id_card_check ---
    // ABS123456 is the worked example from romek.info; AAA000000 covers the
    // weighted-sum-is-zero edge; ZZC445678 computed and verified.
    #[test_case("ABS123456", true ; "valid romek example")]
    #[test_case("AAA000000", true ; "valid zero sum edge")]
    #[test_case("ZZC445678", true ; "valid computed")]
    #[test_case("abs123456", true ; "valid lowercase")]
    #[test_case("ABS 123456", true ; "valid with space")]
    #[test_case("ABS123457", false ; "invalid check digit")]
    #[test_case("AB1234567", false ; "invalid two letters")]
    #[test_case("ABCD12345", false ; "invalid four letters")]
    #[test_case("ABS12345", false ; "invalid eight chars")]
    fn pl_id_card(input: &str, expected: bool) {
        assert_eq!(pl_id_card_check(input), expected);
    }

    // --- pl_passport_check ---
    // CC7999486 is the worked example from romek.info; EH3222222 computed
    // and verified against the weights 7,3,9,1,7,3,1,7,3.
    #[test_case("CC7999486", true ; "valid romek example")]
    #[test_case("EH3222222", true ; "valid computed")]
    #[test_case("cc7999486", true ; "valid lowercase")]
    #[test_case("CC 7999486", true ; "valid with space")]
    #[test_case("CC7999487", false ; "invalid check digit")]
    #[test_case("C17999486", false ; "invalid one letter")]
    #[test_case("CCC999486", false ; "invalid three letters")]
    #[test_case("CC799948", false ; "invalid eight chars")]
    fn pl_passport(input: &str, expected: bool) {
        assert_eq!(pl_passport_check(input), expected);
    }

    // --- pl_postal_check ---
    #[test_case("00-950", true ; "valid warsaw")]
    #[test_case("30-024", true ; "valid krakow")]
    #[test_case("99-999", true ; "valid upper bound")]
    #[test_case("00950", false ; "invalid no dash")]
    #[test_case("000-95", false ; "invalid three two split")]
    #[test_case("00-95A", false ; "invalid letter")]
    #[test_case("0-0950", false ; "invalid one digit prefix")]
    fn pl_postal(input: &str, expected: bool) {
        assert_eq!(pl_postal_check(input), expected);
    }

    // --- pl_dl_check ---
    #[test_case("12345/67/8901", true ; "valid four digit tail")]
    #[test_case("12345/67/8901234", true ; "valid seven digit tail")]
    #[test_case("00001/22/1234", true ; "valid leading zeros")]
    #[test_case("1234/67/8901", false ; "invalid four digit head")]
    #[test_case("12345/6/8901", false ; "invalid one digit middle")]
    #[test_case("12345/67/89012", false ; "invalid five digit tail")]
    #[test_case("12345/67/890123", false ; "invalid six digit tail")]
    #[test_case("12345678901", false ; "invalid no slashes")]
    #[test_case("12345/67/89A1", false ; "invalid letter")]
    fn pl_dl(input: &str, expected: bool) {
        assert_eq!(pl_dl_check(input), expected);
    }
}
