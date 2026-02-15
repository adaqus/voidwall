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