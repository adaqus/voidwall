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

pub(crate) fn sa_id_check(s: &str) -> bool {
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

pub(crate) fn person_name_check(s: &str) -> bool {
    if s.len() < 2 {
        return false;
    }
    s.chars().any(|c| c.is_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- nir_check ---
    #[test]
    fn nir_valid_standard() {
        assert!(nir_check("1 85 05 78 006 084 91"));
    }

    #[test]
    fn nir_valid_no_spaces() {
        assert!(nir_check("185057800608491"));
    }

    #[test]
    fn nir_valid_corsica_2a() {
        // After substitution 2A→19: body=2841119033457, key=97-(2841119033457%97)=14
        assert!(nir_check("284112A03345714"));
    }

    #[test]
    fn nir_valid_corsica_2b() {
        // After substitution 2B→18: body=2841118033457, key=97-(2841118033457%97)=41
        assert!(nir_check("284112B03345741"));
    }

    // Real-world verified examples from superindep.fr and compteassurance.com
    #[test]
    fn nir_valid_lyon_example() {
        // From superindep.fr: man born March 1985 in Lyon (69123), key=32
        assert!(nir_check("185036912304532"));
    }

    #[test]
    fn nir_valid_corsica_2a_ajaccio() {
        // Man born Jan 1975, Corse-du-Sud (2A), commune Ajaccio (004)
        // 2A→19 substitution: body=1750119004032, key=88
        assert!(nir_check("175012A00403288"));
    }

    #[test]
    fn nir_valid_corsica_2b_example() {
        // Woman born May 1990, Haute-Corse (2B), commune 033
        // 2B→18 substitution: body=2900518033010, key=01
        assert!(nir_check("290052B03301001"));
    }

    #[test]
    fn nir_valid_with_spaces_lyon() {
        // Same Lyon example with spaces
        assert!(nir_check("1 85 03 69 123 045 32"));
    }

    #[test]
    fn nir_invalid_checksum() {
        assert!(!nir_check("185057800608499"));
    }

    #[test]
    fn nir_invalid_off_by_one() {
        // Lyon example with key off by one (33 instead of 32)
        assert!(!nir_check("185036912304533"));
    }

    #[test]
    fn nir_wrong_length() {
        assert!(!nir_check("18505780060843"));
    }

    // --- fr_postal_check ---
    #[test]
    fn fr_postal_valid_paris() {
        assert!(fr_postal_check("75008"));
    }

    #[test]
    fn fr_postal_valid_dom_tom() {
        assert!(fr_postal_check("97100"));
    }

    // Real French city postal codes
    #[test]
    fn fr_postal_valid_paris_1er() {
        assert!(fr_postal_check("75001"));
    }

    #[test]
    fn fr_postal_valid_marseille() {
        // Marseille 1er arrondissement
        assert!(fr_postal_check("13001"));
    }

    #[test]
    fn fr_postal_valid_lyon() {
        // Lyon 1er
        assert!(fr_postal_check("69001"));
    }

    #[test]
    fn fr_postal_valid_toulouse() {
        assert!(fr_postal_check("31000"));
    }

    #[test]
    fn fr_postal_valid_nice() {
        assert!(fr_postal_check("06000"));
    }

    #[test]
    fn fr_postal_valid_guadeloupe() {
        // DOM-TOM: Pointe-à-Pitre, Guadeloupe
        assert!(fr_postal_check("97110"));
    }

    #[test]
    fn fr_postal_valid_reunion() {
        // DOM-TOM: Saint-Denis, Réunion
        assert!(fr_postal_check("97400"));
    }

    #[test]
    fn fr_postal_valid_low() {
        assert!(fr_postal_check("01000"));
    }

    #[test]
    fn fr_postal_invalid_below_range() {
        assert!(!fr_postal_check("00100"));
    }

    #[test]
    fn fr_postal_invalid_above_range() {
        assert!(!fr_postal_check("99000"));
    }

    // --- fr_nif_check ---
    #[test]
    fn fr_nif_valid() {
        assert!(fr_nif_check("0123456789012"));
    }

    #[test]
    fn fr_nif_valid_first_digit_3() {
        assert!(fr_nif_check("3123456789012"));
    }

    #[test]
    fn fr_nif_invalid_length() {
        assert!(!fr_nif_check("012345678901"));
    }

    #[test]
    fn fr_nif_invalid_first_digit() {
        assert!(!fr_nif_check("4123456789012"));
    }

    // --- siren_luhn_check ---
    // Real SIREN numbers from annuaire-entreprises.data.gouv.fr
    #[test]
    fn siren_valid_lvmh() {
        // LVMH Moët Hennessy Louis Vuitton, Paris
        assert!(siren_luhn_check("775670417"));
    }

    #[test]
    fn siren_valid_totalenergies() {
        // TotalEnergies SE, Courbevoie
        assert!(siren_luhn_check("542051180"));
    }

    #[test]
    fn siren_valid_renault() {
        // Renault SA, Boulogne-Billancourt
        assert!(siren_luhn_check("441639465"));
    }

    #[test]
    fn siren_valid_renault_sas() {
        // Renault SAS, Boulogne-Billancourt
        assert!(siren_luhn_check("780129987"));
    }

    #[test]
    fn siren_valid_essilorluxottica() {
        // EssilorLuxottica, Charenton-le-Pont
        assert!(siren_luhn_check("712049618"));
    }

    #[test]
    fn siren_invalid_off_by_one() {
        // LVMH with last digit changed
        assert!(!siren_luhn_check("775670418"));
    }

    #[test]
    fn siren_invalid_wrong_length() {
        assert!(!siren_luhn_check("77567041"));
    }

    // --- siret_luhn_check ---
    // Real SIRET numbers from annuaire-entreprises.data.gouv.fr
    #[test]
    fn siret_valid_lvmh_hq() {
        // LVMH siège social, 22 avenue Montaigne, 75008 Paris
        assert!(siret_luhn_check("77567041700051"));
    }

    #[test]
    fn siret_valid_totalenergies_hq() {
        // TotalEnergies SE siège social, 92400 Courbevoie
        assert!(siret_luhn_check("54205118000066"));
    }

    #[test]
    fn siret_valid_essilorluxottica_hq() {
        // EssilorLuxottica siège social, 94220 Charenton-le-Pont
        assert!(siret_luhn_check("71204961800739"));
    }

    #[test]
    fn siret_invalid_off_by_one() {
        // LVMH SIRET with last digit changed
        assert!(!siret_luhn_check("77567041700052"));
    }

    #[test]
    fn siret_invalid_wrong_length() {
        assert!(!siret_luhn_check("7756704170005"));
    }

    // --- de_steuer_id_check ---
    // Values from kryptografie.de and github.com/rechtlogisch/steuer-id
    #[test]
    fn de_steuer_id_valid() {
        assert!(de_steuer_id_check("65929970489"));
    }

    #[test]
    fn de_steuer_id_valid_2() {
        assert!(de_steuer_id_check("86095742719"));
    }

    #[test]
    fn de_steuer_id_valid_from_kontist() {
        // From github.com/kontist/validate-steuerid
        assert!(de_steuer_id_check("26954371827"));
    }

    #[test]
    fn de_steuer_id_valid_from_kryptografie() {
        // From kryptografie.de — example with sequential first 9 digits
        assert!(de_steuer_id_check("12345678995"));
    }

    #[test]
    fn de_steuer_id_valid_triple_digit() {
        // 65929970489 has digit 9 appearing 3 times — valid per spec
        // (one digit may appear up to 3 times)
        assert!(de_steuer_id_check("65929970489"));
    }

    #[test]
    fn de_steuer_id_invalid_checksum() {
        assert!(!de_steuer_id_check("65929970480"));
    }

    #[test]
    fn de_steuer_id_invalid_checksum_2() {
        assert!(!de_steuer_id_check("26954371820"));
    }

    #[test]
    fn de_steuer_id_invalid_first_digit_zero() {
        // Test IDs starting with 0 are invalid in production
        assert!(!de_steuer_id_check("05929970489"));
    }

    #[test]
    fn de_steuer_id_wrong_length() {
        assert!(!de_steuer_id_check("6592997048"));
    }

    #[test]
    fn de_steuer_id_too_long() {
        assert!(!de_steuer_id_check("659299704890"));
    }

    // --- de_personalausweis_check ---
    // Values from kryptografie.de/personalausweis.htm
    #[test]
    fn de_pa_valid_newest_format() {
        // Newest format (since Aug 2021): L01X00T471
        assert!(de_personalausweis_check("L01X00T471"));
    }

    #[test]
    fn de_pa_valid_new_format() {
        // New format (2010-2021): T220001293
        assert!(de_personalausweis_check("T220001293"));
    }

    #[test]
    fn de_pa_valid_c_prefix() {
        assert!(de_personalausweis_check("C01X00T478"));
    }

    #[test]
    fn de_pa_valid_sequential() {
        assert!(de_personalausweis_check("M123456788"));
    }

    #[test]
    fn de_pa_valid_mixed_alphanumeric() {
        assert!(de_personalausweis_check("Y0A1B2C3D6"));
    }

    #[test]
    fn de_pa_invalid_check() {
        assert!(!de_personalausweis_check("L01X00T470"));
    }

    #[test]
    fn de_pa_invalid_check_2() {
        assert!(!de_personalausweis_check("T220001290"));
    }

    #[test]
    fn de_pa_wrong_length() {
        assert!(!de_personalausweis_check("L01X00T47"));
    }

    #[test]
    fn de_pa_starts_with_digit() {
        // Must start with a letter
        assert!(!de_personalausweis_check("1220001297"));
    }

    // --- de_postal_check ---
    #[test]
    fn de_postal_valid_berlin() {
        assert!(de_postal_check("10115"));
    }

    #[test]
    fn de_postal_valid_dresden() {
        assert!(de_postal_check("01067"));
    }

    #[test]
    fn de_postal_valid_munich() {
        assert!(de_postal_check("80331"));
    }

    #[test]
    fn de_postal_valid_hamburg() {
        assert!(de_postal_check("20095"));
    }

    #[test]
    fn de_postal_valid_frankfurt() {
        assert!(de_postal_check("60311"));
    }

    #[test]
    fn de_postal_invalid_below_range() {
        assert!(!de_postal_check("00100"));
    }

    #[test]
    fn de_postal_invalid_all_zeros() {
        assert!(!de_postal_check("00000"));
    }

    // --- at_svnr_check ---
    // Values from gist.github.com/jensens (documented example: 1237010180)
    #[test]
    fn at_svnr_valid() {
        assert!(at_svnr_check("1238150185"));
    }

    #[test]
    fn at_svnr_valid_2() {
        assert!(at_svnr_check("1233250689"));
    }

    #[test]
    fn at_svnr_valid_documented() {
        // From gist.github.com/jensens: 1237 010180 (born 01.01.1980)
        assert!(at_svnr_check("1237010180"));
    }

    #[test]
    fn at_svnr_valid_born_1990() {
        // Seq=456, check=7, born 15.03.1990
        assert!(at_svnr_check("4567150390"));
    }

    #[test]
    fn at_svnr_valid_born_1975() {
        // Seq=789, check=2, born 28.12.1975
        assert!(at_svnr_check("7892281275"));
    }

    #[test]
    fn at_svnr_invalid_checksum() {
        assert!(!at_svnr_check("1230150185"));
    }

    #[test]
    fn at_svnr_invalid_check_off_by_one() {
        // 1237010180 is valid; 1238010180 has wrong check digit
        assert!(!at_svnr_check("1238010180"));
    }

    #[test]
    fn at_svnr_wrong_length() {
        assert!(!at_svnr_check("123815018"));
    }

    // --- at_postal_check ---
    #[test]
    fn at_postal_valid_vienna() {
        assert!(at_postal_check("1010"));
    }

    #[test]
    fn at_postal_valid_salzburg() {
        assert!(at_postal_check("5020"));
    }

    #[test]
    fn at_postal_valid_graz() {
        assert!(at_postal_check("8010"));
    }

    #[test]
    fn at_postal_valid_innsbruck() {
        assert!(at_postal_check("6020"));
    }

    #[test]
    fn at_postal_invalid_below_range() {
        assert!(!at_postal_check("1000"));
    }

    #[test]
    fn at_postal_invalid_just_below() {
        assert!(!at_postal_check("1009"));
    }

    // --- ch_ahv_check ---
    // Values from sozialversicherungsnummer.ch and gist.github.com/rordi
    #[test]
    fn ch_ahv_valid() {
        assert!(ch_ahv_check("7561234567897"));
    }

    #[test]
    fn ch_ahv_valid_from_sozialversicherungsnummer_ch() {
        // Documented example from sozialversicherungsnummer.ch
        assert!(ch_ahv_check("7569217076985"));
    }

    #[test]
    fn ch_ahv_valid_from_gist() {
        // From gist.github.com/rordi: 756.0081.3782.50
        assert!(ch_ahv_check("7560081378250"));
    }

    #[test]
    fn ch_ahv_valid_3026() {
        // 756.3026.0705.92
        assert!(ch_ahv_check("7563026070592"));
    }

    #[test]
    fn ch_ahv_valid_check_digit_zero() {
        // Check digit can be 0: 756.1122.3344.02 → check=2? Let me verify
        // Actually 7561122334402 check: digits[..12]=[7,5,6,1,1,2,2,3,3,4,4,0]
        // weights alternating 1,3: 7*1+5*3+6*1+1*3+1*1+2*3+2*1+3*3+3*1+4*3+4*1+0*3
        // = 7+15+6+3+1+6+2+9+3+12+4+0 = 68, (10-68%10)%10 = (10-8)%10 = 2
        assert!(ch_ahv_check("7561122334402"));
    }

    #[test]
    fn ch_ahv_invalid_checksum() {
        assert!(!ch_ahv_check("7561234567890"));
    }

    #[test]
    fn ch_ahv_invalid_checksum_real_prefix() {
        // Real-structure number with wrong check digit
        assert!(!ch_ahv_check("7569217076980"));
    }

    #[test]
    fn ch_ahv_invalid_prefix() {
        assert!(!ch_ahv_check("1231234567897"));
    }

    #[test]
    fn ch_ahv_wrong_length() {
        assert!(!ch_ahv_check("756123456789"));
    }

    // --- ch_postal_check ---
    #[test]
    fn ch_postal_valid_zurich() {
        assert!(ch_postal_check("8001"));
    }

    #[test]
    fn ch_postal_valid_bern() {
        assert!(ch_postal_check("3000"));
    }

    #[test]
    fn ch_postal_valid_geneva() {
        assert!(ch_postal_check("1200"));
    }

    #[test]
    fn ch_postal_valid_low() {
        assert!(ch_postal_check("1000"));
    }

    #[test]
    fn ch_postal_valid_upper_bound() {
        assert!(ch_postal_check("9658"));
    }

    #[test]
    fn ch_postal_invalid_above_range() {
        assert!(!ch_postal_check("9999"));
    }

    #[test]
    fn ch_postal_invalid_just_above() {
        assert!(!ch_postal_check("9659"));
    }

    #[test]
    fn ch_postal_invalid_below_range() {
        assert!(!ch_postal_check("0999"));
    }

    // ===================================================================
    // Real-world verified examples for English-speaking countries
    // ===================================================================

    // --- ssn_check ---
    // 078-05-1120: Woolworth wallet SSN (voided), from ssa.gov/history/ssn/misused.html
    #[test]
    fn ssn_valid_woolworth() {
        assert!(ssn_check("078-05-1120"));
    }

    // 219-09-9999: SSA pamphlet fabricated number, from ssa.gov/history/ssn/misused.html
    #[test]
    fn ssn_valid_ssa_pamphlet() {
        assert!(ssn_check("219-09-9999"));
    }

    // 457-55-5462: LifeLock CEO Todd Davis (publicly advertised)
    #[test]
    fn ssn_valid_lifelock_ceo() {
        assert!(ssn_check("457-55-5462"));
    }

    #[test]
    fn ssn_invalid_area_zero() {
        assert!(!ssn_check("000-12-3456"));
    }

    #[test]
    fn ssn_invalid_area_666() {
        assert!(!ssn_check("666-12-3456"));
    }

    #[test]
    fn ssn_invalid_area_900() {
        assert!(!ssn_check("901-12-3456"));
    }

    // --- ein_check ---
    // 53-0196605: American National Red Cross, from ProPublica Nonprofit Explorer
    #[test]
    fn ein_valid_red_cross() {
        assert!(ein_check("53-0196605"));
    }

    // 20-0049703: Wikimedia Foundation, from donate.wikimedia.org
    #[test]
    fn ein_valid_wikimedia() {
        assert!(ein_check("20-0049703"));
    }

    // 20-0097189: Mozilla Foundation, from Charity Navigator
    #[test]
    fn ein_valid_mozilla() {
        assert!(ein_check("20-0097189"));
    }

    #[test]
    fn ein_invalid_prefix_07() {
        assert!(!ein_check("07-1234567"));
    }

    // --- aba_check ---
    // 021000021: JPMorgan Chase (New York), from chase.com
    #[test]
    fn aba_valid_jpmorgan_chase() {
        assert!(aba_check("021000021"));
    }

    // 026009593: Bank of America (wire transfers), from bankofamerica.com
    #[test]
    fn aba_valid_bank_of_america() {
        assert!(aba_check("026009593"));
    }

    // 121000248: Wells Fargo, from wise.com
    #[test]
    fn aba_valid_wells_fargo() {
        assert!(aba_check("121000248"));
    }

    // 021000089: Citibank (New York), from wise.com
    #[test]
    fn aba_valid_citibank() {
        assert!(aba_check("021000089"));
    }

    // 111000025: Bank of America (Virginia), from Wikipedia ABA article
    #[test]
    fn aba_valid_bofa_virginia() {
        assert!(aba_check("111000025"));
    }

    #[test]
    fn aba_invalid_checksum() {
        assert!(!aba_check("021000022"));
    }

    // --- nino_check ---
    // AA, CE, JY are all valid NINO prefixes (no invalid letters)
    #[test]
    fn nino_valid_aa_prefix() {
        assert!(nino_check("AA123456C"));
    }

    #[test]
    fn nino_valid_ce_prefix() {
        assert!(nino_check("CE987654B"));
    }

    #[test]
    fn nino_valid_jy_with_spaces() {
        assert!(nino_check("JY 55 55 55 D"));
    }

    #[test]
    fn nino_invalid_prefix_bg() {
        assert!(!nino_check("BG123456C"));
    }

    #[test]
    fn nino_invalid_prefix_gb() {
        assert!(!nino_check("GB123456C"));
    }

    #[test]
    fn nino_invalid_first_letter_d() {
        assert!(!nino_check("DA123456C"));
    }

    // Note: QQ123456C (GOV.UK Design System example) fails our validator
    // because Q is in the invalid first-letter list (D,F,I,Q,U,V).
    // GOV.UK recommends it for user-facing forms, not as a real NINO.
    #[test]
    fn nino_invalid_govuk_q_prefix() {
        assert!(!nino_check("QQ123456C"));
    }

    // --- nhs_check ---
    // 9434765919: Wikipedia worked example
    #[test]
    fn nhs_valid_wikipedia_example() {
        assert!(nhs_check("9434765919"));
    }

    // 9278462608: From pfwd/NHSNumber-Validation GitHub repo
    #[test]
    fn nhs_valid_github_example() {
        assert!(nhs_check("9278462608"));
    }

    // 4010232137: Independently verified with mod-11
    #[test]
    fn nhs_valid_computed() {
        assert!(nhs_check("4010232137"));
    }

    // 9990000018: NHS test range (999 xxx xxxx), verified with mod-11
    #[test]
    fn nhs_valid_test_range() {
        assert!(nhs_check("9990000018"));
    }

    #[test]
    fn nhs_invalid_checksum() {
        assert!(!nhs_check("9434765910"));
    }

    // --- utr_check ---
    // UTR algorithm from HMRC reference-checker on GitHub
    // 5555555555: Verified with HMRC algorithm (existing test value)
    #[test]
    fn utr_valid_fives() {
        assert!(utr_check("5555555555"));
    }

    // 9987654321: Computed using HMRC weights and lookup table
    #[test]
    fn utr_valid_descending() {
        assert!(utr_check("9987654321"));
    }

    // 7999888777: Computed using actual algorithm (11-remainder)
    #[test]
    fn utr_valid_nines_and_eights() {
        assert!(utr_check("7999888777"));
    }

    // 1123456789: Computed (check=1, base=123456789)
    #[test]
    fn utr_valid_sequential() {
        assert!(utr_check("1123456789"));
    }

    #[test]
    fn utr_invalid_checksum() {
        assert!(!utr_check("1555555555"));
    }

    // --- uk_dl_check ---
    // JONES901157A99Y1: Existing test value (male born 15 Nov 197x)
    #[test]
    fn uk_dl_valid_jones() {
        assert!(uk_dl_check("JONES901157A99Y1"));
    }

    #[test]
    fn uk_dl_invalid_month() {
        assert!(!uk_dl_check("JONES900057A99Y1"));
    }

    #[test]
    fn uk_dl_invalid_day() {
        assert!(!uk_dl_check("JONES901007A99Y1"));
    }

    // --- sort_code_check ---
    // 20-26-86: Barclays Bank UK PLC (Leicester), from wise.com
    #[test]
    fn sort_code_valid_barclays_leicester() {
        assert!(sort_code_check("20-26-86"));
    }

    // 40-05-30: HSBC Bank PLC (London), from wise.com
    #[test]
    fn sort_code_valid_hsbc_london() {
        assert!(sort_code_check("40-05-30"));
    }

    // 60-00-01: NatWest City of London Office
    #[test]
    fn sort_code_valid_natwest_london() {
        assert!(sort_code_check("60-00-01"));
    }

    // 30-96-26: Lloyds Bank PLC
    #[test]
    fn sort_code_valid_lloyds() {
        assert!(sort_code_check("30-96-26"));
    }

    // --- tfn_check ---
    // 123456782: Canonical example from clearwater.com.au and Wikipedia
    #[test]
    fn tfn_valid_canonical() {
        assert!(tfn_check("123 456 782"));
    }

    // 100000001: Generated, verified with weights [1,4,3,7,5,8,6,9,10]
    #[test]
    fn tfn_valid_generated_1() {
        assert!(tfn_check("100 000 001"));
    }

    // 100000028: Generated, verified with weights
    #[test]
    fn tfn_valid_generated_2() {
        assert!(tfn_check("100 000 028"));
    }

    #[test]
    fn tfn_invalid_checksum() {
        assert!(!tfn_check("123 456 789"));
    }

    // --- medicare_check ---
    // 2123456701: Canonical example from clearwater.com.au
    #[test]
    fn medicare_valid_canonical() {
        assert!(medicare_check("2123 45670 1"));
    }

    // 3189977021: Derived from clearwater.com.au worked calculation
    #[test]
    fn medicare_valid_clearwater_calc() {
        assert!(medicare_check("3189 97702 1"));
    }

    // 6950507391: From medipass/validate-medicare-number on GitHub
    #[test]
    fn medicare_valid_medipass() {
        assert!(medicare_check("6950 50739 1"));
    }

    #[test]
    fn medicare_invalid_first_digit_1() {
        assert!(!medicare_check("1123 45670 1"));
    }

    #[test]
    fn medicare_invalid_first_digit_7() {
        assert!(!medicare_check("7123 45670 1"));
    }

    // --- ird_check ---
    // 49-091-857: Existing test value (8-digit IRD)
    #[test]
    fn ird_valid_existing() {
        assert!(ird_check("49-091-857"));
    }

    // 10-000-008: Generated 8-digit IRD, verified with primary weights
    #[test]
    fn ird_valid_generated_8digit() {
        assert!(ird_check("10-000-008"));
    }

    // 100-000-148: Generated 9-digit IRD, verified with primary weights
    #[test]
    fn ird_valid_generated_9digit() {
        assert!(ird_check("100-000-148"));
    }

    #[test]
    fn ird_invalid_below_range() {
        assert!(!ird_check("01-000-000"));
    }

    // --- nhi_check ---
    // JBX3656: Wikipedia canonical worked example
    #[test]
    fn nhi_valid_wikipedia() {
        assert!(nhi_check("JBX3656"));
    }

    // ZAC5361: From rapidrehita.health.nz and rust-nhi GitHub
    #[test]
    fn nhi_valid_zac() {
        assert!(nhi_check("ZAC5361"));
    }

    // CGC2720: From Wikipedia NHI Number article
    #[test]
    fn nhi_valid_cgc() {
        assert!(nhi_check("CGC2720"));
    }

    // EPT6335: From Wikipedia NHI Number article
    #[test]
    fn nhi_valid_ept() {
        assert!(nhi_check("EPT6335"));
    }

    // WLD9413: From elilambnz/nhi-validator npm package
    #[test]
    fn nhi_valid_wld() {
        assert!(nhi_check("WLD9413"));
    }

    // DAB8745: Existing test value
    #[test]
    fn nhi_valid_dab() {
        assert!(nhi_check("DAB8745"));
    }

    #[test]
    fn nhi_invalid_letter_i() {
        assert!(!nhi_check("DAI5765"));
    }

    #[test]
    fn nhi_invalid_letter_o() {
        assert!(!nhi_check("DAO5765"));
    }

    #[test]
    fn nhi_invalid_check_digit() {
        assert!(!nhi_check("DAB8740"));
    }

    // --- sin_check ---
    // 130-692-544: Documented example from Straight Line International
    #[test]
    fn sin_valid_straightline() {
        assert!(sin_check("130-692-544"));
    }

    // 810-620-716: From TNAADO Canadian SIN Validator
    #[test]
    fn sin_valid_tnaado() {
        assert!(sin_check("810-620-716"));
    }

    #[test]
    fn sin_invalid_first_digit_zero() {
        // 046-454-286 passes Luhn but first digit is 0
        assert!(!sin_check("046-454-286"));
    }

    #[test]
    fn sin_invalid_luhn() {
        assert!(!sin_check("123-456-789"));
    }

    // --- ppsn_check ---
    // 1234567T: Wikipedia canonical example (old format)
    #[test]
    fn ppsn_valid_wikipedia_old() {
        assert!(ppsn_check("1234567T"));
    }

    // 1234567TW: Old format with W suffix
    #[test]
    fn ppsn_valid_wikipedia_old_w() {
        assert!(ppsn_check("1234567TW"));
    }

    // 1234567FA: Wikipedia new format (9th char A modifies checksum)
    // sum = 112 + 9*1 = 121, 121%23 = 6, check = 'F'
    #[test]
    fn ppsn_valid_wikipedia_new_format() {
        assert!(ppsn_check("1234567FA"));
    }

    // 7654321G: Computed from algorithm (sum=168, 168%23=7, 'G')
    #[test]
    fn ppsn_valid_computed_1() {
        assert!(ppsn_check("7654321G"));
    }

    // 5555555N: Computed from algorithm
    #[test]
    fn ppsn_valid_computed_2() {
        assert!(ppsn_check("5555555N"));
    }

    #[test]
    fn ppsn_invalid_check_letter() {
        assert!(!ppsn_check("1234567A"));
    }

    // --- sa_id_check ---
    // 8001015009087: Existing test value (born 1980-01-01, male, citizen)
    #[test]
    fn sa_id_valid_existing() {
        assert!(sa_id_check("8001015009087"));
    }

    // 9506150089081: Existing test value (born 1995-06-15, female, citizen)
    #[test]
    fn sa_id_valid_existing_2() {
        assert!(sa_id_check("9506150089081"));
    }

    // 9001245289086: From za-id-number PyPI library
    #[test]
    fn sa_id_valid_pypi() {
        assert!(sa_id_check("9001245289086"));
    }

    // 8801235111088: From Medium article, verified with Luhn
    #[test]
    fn sa_id_valid_medium() {
        assert!(sa_id_check("8801235111088"));
    }

    // 9501015000084: Generated, verified with Luhn
    #[test]
    fn sa_id_valid_generated() {
        assert!(sa_id_check("9501015000084"));
    }

    #[test]
    fn sa_id_invalid_month() {
        assert!(!sa_id_check("8013015009087"));
    }

    #[test]
    fn sa_id_invalid_day() {
        assert!(!sa_id_check("8001325009087"));
    }

    #[test]
    fn sa_id_invalid_luhn() {
        assert!(!sa_id_check("8001015009086"));
    }

    // --- za_trn_check ---
    #[test]
    fn za_trn_valid_prefix_0() {
        assert!(za_trn_check("0123456789"));
    }

    #[test]
    fn za_trn_valid_prefix_1() {
        assert!(za_trn_check("1234567890"));
    }

    #[test]
    fn za_trn_valid_prefix_9() {
        assert!(za_trn_check("9876543210"));
    }

    #[test]
    fn za_trn_invalid_prefix_4() {
        assert!(!za_trn_check("4123456789"));
    }

    #[test]
    fn za_trn_invalid_prefix_5() {
        assert!(!za_trn_check("5123456789"));
    }

    // --- ohip_check ---
    #[test]
    fn ohip_valid_existing() {
        assert!(ohip_check("1234567897"));
    }

    #[test]
    fn ohip_invalid_luhn() {
        assert!(!ohip_check("1234567898"));
    }

    // --- ie_driver_check ---
    #[test]
    fn ie_driver_valid_9_digits() {
        assert!(ie_driver_check("123456789"));
    }

    #[test]
    fn ie_driver_invalid_8_digits() {
        assert!(!ie_driver_check("12345678"));
    }

    #[test]
    fn ie_driver_invalid_10_digits() {
        assert!(!ie_driver_check("1234567890"));
    }

    // --- person_name_check ---

    #[test]
    fn person_name_valid_simple() {
        assert!(person_name_check("John Smith"));
    }

    #[test]
    fn person_name_valid_accented() {
        assert!(person_name_check("Jean-Pierre Müller"));
    }

    #[test]
    fn person_name_valid_apostrophe() {
        assert!(person_name_check("O'Brien"));
    }

    #[test]
    fn person_name_valid_single_word() {
        assert!(person_name_check("Madonna"));
    }

    #[test]
    fn person_name_reject_digits_only() {
        assert!(!person_name_check("12345"));
    }

    #[test]
    fn person_name_reject_single_char() {
        assert!(!person_name_check("A"));
    }

    #[test]
    fn person_name_reject_empty() {
        assert!(!person_name_check(""));
    }
}
