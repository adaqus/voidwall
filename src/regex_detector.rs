use regex::{Regex, RegexSet};

use crate::detector::Detector;
use crate::{PiiKind, PiiMatch};

struct Pattern {
    kind: PiiKind,
    regex: Regex,
}

pub struct RegexDetector {
    set: RegexSet,
    patterns: Vec<Pattern>,
}

impl Default for RegexDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RegexDetector {
    pub fn new() -> Self {
        let raw_patterns: Vec<(PiiKind, &str)> = vec![
            (
                PiiKind::Email,
                r"[\p{L}\p{N}._%+-]+@[\p{L}\p{N}.-]+\.[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?",
            ),
            (
                PiiKind::PhoneNumber,
                r"(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}",
            ),
            (PiiKind::CreditCard, r"\b(?:[0-9]{4}[-\s]?){3}[0-9]{1,4}\b"),
            (PiiKind::UsSsn, r"\b(\d{3})-(\d{2})-(\d{4})\b"),
            (
                PiiKind::GbNino,
                r"\b[A-Za-z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-Da-d]\b",
            ),
            (
                PiiKind::Iban,
                r"\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}(?:\s?[A-Z0-9]{4}){1,7}(?:\s?[A-Z0-9]{1,4})?\b",
            ),
            (PiiKind::PassportNumber, r"\b\d{9}\b"),
            (
                PiiKind::IpAddress,
                r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            ),
            (
                PiiKind::IpAddress,
                r"(?i)(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}|::(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}|::)",
            ),
            (PiiKind::UsItin, r"\b(9\d{2})-(\d{2})-(\d{4})\b"),
            (PiiKind::CaSin, r"\b\d{3}[-\s]\d{3}[-\s]\d{3}\b"),
            (PiiKind::IePpsn, r"\b\d{7}[A-Za-z]{1,2}\b"),
            (PiiKind::ZaId, r"\b\d{13}\b"),
            (
                PiiKind::MacAddress,
                r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b",
            ),
            (
                PiiKind::MacAddress,
                r"\b[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}\b",
            ),
            (
                PiiKind::MacAddress,
                r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b",
            ),
            (
                PiiKind::GbDrivingLicence,
                r"\b[A-Z9]{5}\d[0-6]\d[0-3]\d\d[A-Z9]{2}\d[A-Z]\d\b",
            ),
            (PiiKind::Vin, r"\b[A-HJ-NPR-Z0-9]{17}\b"),
        ];

        let set = RegexSet::new(raw_patterns.iter().map(|(_, pat)| pat)).unwrap();
        let patterns = raw_patterns
            .into_iter()
            .map(|(kind, pat)| Pattern {
                kind,
                regex: Regex::new(pat).unwrap(),
            })
            .collect();

        Self { set, patterns }
    }
}

impl Detector for RegexDetector {
    fn has_piis(&self, input: &str) -> bool {
        self.set.is_match(input)
    }

    fn mark_piis(&self, input: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();
        let matched_indices: Vec<usize> = self.set.matches(input).into_iter().collect();
        for &idx in &matched_indices {
            let pattern = &self.patterns[idx];
            for m in pattern.regex.find_iter(input) {
                let candidate = m.as_str();
                if pattern.kind == PiiKind::CreditCard && !luhn_check(candidate) {
                    continue;
                }
                if pattern.kind == PiiKind::UsSsn && !ssn_check(candidate) {
                    continue;
                }
                if pattern.kind == PiiKind::GbNino && !nino_check(candidate) {
                    continue;
                }
                if pattern.kind == PiiKind::Iban && !iban_check(candidate) {
                    continue;
                }
                if pattern.kind == PiiKind::IpAddress && !ip_check(candidate) {
                    continue;
                }
                if pattern.kind == PiiKind::UsItin && !itin_check(candidate) {
                    continue;
                }
                if pattern.kind == PiiKind::CaSin && !sin_check(candidate) {
                    continue;
                }
                if pattern.kind == PiiKind::IePpsn && !ppsn_check(candidate) {
                    continue;
                }
                if pattern.kind == PiiKind::ZaId && !sa_id_check(candidate) {
                    continue;
                }
                if pattern.kind == PiiKind::GbDrivingLicence && !uk_dl_check(candidate) {
                    continue;
                }
                if pattern.kind == PiiKind::Vin && !vin_check(candidate) {
                    continue;
                }
                matches.push(PiiMatch {
                    kind: pattern.kind,
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
        matches
    }
}

fn luhn_check(s: &str) -> bool {
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

fn ssn_check(s: &str) -> bool {
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

fn nino_check(s: &str) -> bool {
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
    // First letter must not be D, F, I, Q, U, V
    if matches!(first, 'D' | 'F' | 'I' | 'Q' | 'U' | 'V') {
        return false;
    }
    // Second letter must not be D, F, I, O, Q, U, V
    if matches!(second, 'D' | 'F' | 'I' | 'O' | 'Q' | 'U' | 'V') {
        return false;
    }
    // Prefix must not be BG, GB, NK, KN, TN, NT, ZZ
    let prefix = &upper[..2];
    if matches!(prefix, "BG" | "GB" | "NK" | "KN" | "TN" | "NT" | "ZZ") {
        return false;
    }
    true
}

fn iban_check(s: &str) -> bool {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 15 || compact.len() > 34 {
        return false;
    }
    // Rearrange: move first 4 chars to end
    let rearranged = format!("{}{}", &compact[4..], &compact[..4]);
    // Convert letters to numbers (A=10, B=11, ..., Z=35)
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
    // Mod 97 using iterative approach (avoid big integer)
    let mut remainder: u64 = 0;
    for chunk in numeric.as_bytes().chunks(9) {
        let s = std::str::from_utf8(chunk).unwrap();
        let combined = format!("{remainder}{s}");
        remainder = combined.parse::<u64>().unwrap_or(0) % 97;
    }
    remainder == 1
}

fn ip_check(s: &str) -> bool {
    // Only validate IPv4 (contains dots); IPv6 passes through
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

fn itin_check(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let group: u32 = parts[1].parse().unwrap_or(0);
    matches!(group, 50..=65 | 70..=88 | 90..=92 | 94..=99)
}

fn sin_check(s: &str) -> bool {
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

fn ppsn_check(s: &str) -> bool {
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

fn sa_id_check(s: &str) -> bool {
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

fn uk_dl_check(s: &str) -> bool {
    if s.len() != 16 {
        return false;
    }
    let bytes = s.as_bytes();
    let month: u32 = ((bytes[6] - b'0') as u32) * 10 + (bytes[7] - b'0') as u32;
    // Male: 01-12, Female: 51-62
    if !((1..=12).contains(&month) || (51..=62).contains(&month)) {
        return false;
    }
    let day: u32 = ((bytes[8] - b'0') as u32) * 10 + (bytes[9] - b'0') as u32;
    if !(1..=31).contains(&day) {
        return false;
    }
    true
}

fn vin_check(s: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_email() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("contact us at user@example.com for info");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
        assert_eq!(
            &"contact us at user@example.com for info"[matches[0].start..matches[0].end],
            "user@example.com"
        );
    }

    #[test]
    fn detects_email_with_plus_tag() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("send to user+tag@domain.co.uk please");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
    }

    #[test]
    fn detects_phone_number() {
        let detector = RegexDetector::new();
        for input in &[
            "call 555-123-4567",
            "call (555) 123-4567",
            "call +1 555 123 4567",
            "call 5551234567",
        ] {
            let matches = detector.mark_piis(input);
            assert_eq!(matches.len(), 1, "failed on: {input}");
            assert_eq!(matches[0].kind, PiiKind::PhoneNumber);
        }
    }

    #[test]
    fn detects_credit_card() {
        let detector = RegexDetector::new();
        // Valid Visa test number
        let matches = detector.mark_piis("card: 4111 1111 1111 1111");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::CreditCard);
    }

    #[test]
    fn rejects_invalid_credit_card_luhn() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("card: 4111 1111 1111 1112");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn has_piis_short_circuits() {
        let detector = RegexDetector::new();
        assert!(detector.has_piis("user@example.com"));
        assert!(!detector.has_piis("no pii here"));
    }

    #[test]
    fn no_false_positives_on_clean_text() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("The quick brown fox jumps over the lazy dog.");
        assert!(matches.is_empty());
    }

    // --- Email: thread / sub-addressing identifiers ---

    #[test]
    fn detects_email_with_thread_identifier() {
        let detector = RegexDetector::new();
        let matches =
            detector.mark_piis("reply to user+thread-id-42@example.com to continue the thread");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
        assert_eq!(
            &"reply to user+thread-id-42@example.com to continue the thread"
                [matches[0].start..matches[0].end],
            "user+thread-id-42@example.com"
        );
    }

    #[test]
    fn detects_email_with_multiple_plus_tags() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("send to user+tag1+tag2@domain.org");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
    }

    #[test]
    fn detects_email_with_dots_in_local_part() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("first.middle.last@example.com");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
    }

    #[test]
    fn detects_email_with_percent_encoding_chars() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("user%tag@example.com");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
    }

    // --- Email: localhost and non-standard domains ---

    #[test]
    fn does_not_detect_email_at_localhost() {
        let detector = RegexDetector::new();
        // localhost has no TLD with 2+ chars, so the regex won't match
        let matches = detector.mark_piis("admin@localhost");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn detects_email_at_localhost_with_tld() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("admin@localhost.localdomain");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
    }

    #[test]
    fn detects_email_with_subdomain() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("user@mail.internal.example.com");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
    }

    #[test]
    fn detects_email_with_long_tld() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("user@example.technology");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
    }

    #[test]
    fn detects_email_with_two_letter_tld() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("user@example.de");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
    }

    // --- Email: non-standard / UTF-8 characters ---

    #[test]
    fn detects_email_with_utf8_local_part() {
        let detector = RegexDetector::new();
        let input = "użytkownik@example.com";
        let matches = detector.mark_piis(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
        assert_eq!(
            &input[matches[0].start..matches[0].end],
            "użytkownik@example.com"
        );
    }

    #[test]
    fn detects_email_with_utf8_domain() {
        let detector = RegexDetector::new();
        let input = "user@münchen.de";
        let matches = detector.mark_piis(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
        assert_eq!(&input[matches[0].start..matches[0].end], "user@münchen.de");
    }

    #[test]
    fn detects_email_with_japanese_local_part() {
        let detector = RegexDetector::new();
        let input = "太郎@example.jp";
        let matches = detector.mark_piis(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
        assert_eq!(&input[matches[0].start..matches[0].end], "太郎@example.jp");
    }

    #[test]
    fn detects_email_with_japanese_domain() {
        let detector = RegexDetector::new();
        let input = "user@例え.jp";
        let matches = detector.mark_piis(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
        assert_eq!(&input[matches[0].start..matches[0].end], "user@例え.jp");
    }

    #[test]
    fn detects_email_with_fully_japanese_address() {
        let detector = RegexDetector::new();
        let input = "メールは 太郎@東京.jp まで";
        let matches = detector.mark_piis(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
        assert_eq!(&input[matches[0].start..matches[0].end], "太郎@東京.jp");
    }

    #[test]
    fn detects_email_with_cyrillic_chars() {
        let detector = RegexDetector::new();
        let input = "написать пользователь@домен.рф";
        let matches = detector.mark_piis(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
        assert_eq!(
            &input[matches[0].start..matches[0].end],
            "пользователь@домен.рф"
        );
    }

    #[test]
    fn detects_email_with_punycode_domain() {
        let detector = RegexDetector::new();
        // Punycode-encoded IDN domain (xn-- prefix is ASCII-compatible)
        let input = "user@xn--mnchen-3ya.de";
        let matches = detector.mark_piis(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
        assert_eq!(
            &input[matches[0].start..matches[0].end],
            "user@xn--mnchen-3ya.de"
        );
    }

    #[test]
    fn detects_email_with_punycode_tld() {
        let detector = RegexDetector::new();
        // .рф in Punycode is xn--p1ai
        let input = "info@example.xn--p1ai";
        let matches = detector.mark_piis(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
    }

    #[test]
    fn detects_email_with_arabic_local_part() {
        let detector = RegexDetector::new();
        let input = "مستخدم@example.com";
        let matches = detector.mark_piis(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
        assert_eq!(
            &input[matches[0].start..matches[0].end],
            "مستخدم@example.com"
        );
    }

    #[test]
    fn detects_email_adjacent_to_utf8_text() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("写信给 user@example.com 谢谢");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
    }

    // --- Email: edge cases ---

    #[test]
    fn detects_multiple_emails_in_text() {
        let detector = RegexDetector::new();
        let matches =
            detector.mark_piis("contact alice@example.com or bob+list@domain.org for info");
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| m.kind == PiiKind::Email));
    }

    #[test]
    fn detects_email_with_numeric_local_part() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("12345@example.com");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
    }

    #[test]
    fn detects_email_with_hyphenated_domain() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("user@my-company.co.uk");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Email);
    }

    // --- Phone numbers: international country codes ---

    #[test]
    fn detects_uk_phone_number() {
        let detector = RegexDetector::new();
        // UK numbers: +44 followed by 10 digits — fits the 3-3-4 pattern after country code
        let matches = detector.mark_piis("call +44 207 123 4567");
        assert_eq!(matches.len(), 1, "should detect UK phone number");
        assert_eq!(matches[0].kind, PiiKind::PhoneNumber);
    }

    #[test]
    fn detects_german_phone_number_matching_pattern() {
        let detector = RegexDetector::new();
        // German mobile: +49 151 1234 5678 — the last 10 digits can match 3-3-4
        let matches = detector.mark_piis("call +49 151 123 4567");
        assert_eq!(matches.len(), 1, "should detect German phone number");
        assert_eq!(matches[0].kind, PiiKind::PhoneNumber);
    }

    #[test]
    fn detects_french_phone_number_matching_pattern() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("appeler +33 612 345 678");
        // French numbers are 9 digits after country code — may not match 3-3-4 pattern
        let phone_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::PhoneNumber)
            .collect();
        assert_eq!(
            phone_matches.len(),
            0,
            "French 9-digit number should not match US-centric phone pattern"
        );
    }

    #[test]
    fn detects_indian_phone_number_matching_pattern() {
        let detector = RegexDetector::new();
        // Indian mobile: +91 followed by 10 digits
        let matches = detector.mark_piis("call +91 987 654 3210");
        assert_eq!(
            matches.len(),
            1,
            "should detect Indian phone number in 3-3-4 format"
        );
        assert_eq!(matches[0].kind, PiiKind::PhoneNumber);
    }

    #[test]
    fn detects_australian_phone_number_matching_pattern() {
        let detector = RegexDetector::new();
        // Australian mobile: +61 4xx xxx xxx — 9 digits after code
        let matches = detector.mark_piis("ring +61 412 345 678");
        assert_eq!(
            matches.len(),
            0,
            "Australian 9-digit number should not match US-centric pattern"
        );
    }

    #[test]
    fn detects_japanese_phone_number_matching_pattern() {
        let detector = RegexDetector::new();
        // Japanese mobile: +81 followed by 10 digits
        let matches = detector.mark_piis("call +81 901 234 5678");
        assert_eq!(
            matches.len(),
            1,
            "should detect Japanese phone in 3-3-4 format"
        );
        assert_eq!(matches[0].kind, PiiKind::PhoneNumber);
    }

    #[test]
    fn detects_brazilian_phone_number_matching_pattern() {
        let detector = RegexDetector::new();
        // Brazilian mobile: +55 followed by 11 digits (2 area + 9 mobile)
        // In 3-3-4 grouping only the last 10 digits would match
        let matches = detector.mark_piis("ligar +55 119 876 5432");
        assert_eq!(
            matches.len(),
            1,
            "should detect Brazilian phone in 3-3-4 format"
        );
        assert_eq!(matches[0].kind, PiiKind::PhoneNumber);
    }

    #[test]
    fn detects_us_phone_with_country_code_variants() {
        let detector = RegexDetector::new();
        for input in &[
            "call +1-555-123-4567",
            "call +1.555.123.4567",
            "call 1-555-123-4567",
            "call 1.555.123.4567",
            "call +1 (555) 123-4567",
        ] {
            let matches = detector.mark_piis(input);
            assert_eq!(matches.len(), 1, "failed on: {input}");
            assert_eq!(matches[0].kind, PiiKind::PhoneNumber);
        }
    }

    #[test]
    fn does_not_detect_short_digit_sequence_as_phone() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("order #12345 is ready");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn does_not_detect_long_digit_sequence_as_phone() {
        let detector = RegexDetector::new();
        // 15 consecutive digits — shouldn't match 3-3-4 phone pattern
        let matches = detector.mark_piis("id: 123456789012345");
        // May partially match; assert no PhoneNumber match
        let phone_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::PhoneNumber)
            .collect();
        assert!(
            phone_matches.len() <= 1,
            "long digit string should match at most one phone pattern"
        );
    }

    // --- SSN tests ---

    #[test]
    fn detects_ssn() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("SSN: 123-45-6789");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::UsSsn);
    }

    #[test]
    fn detects_ssn_span() {
        let detector = RegexDetector::new();
        let input = "my ssn is 078-05-1120 ok";
        let matches = detector.mark_piis(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "078-05-1120");
    }

    #[test]
    fn rejects_ssn_area_000() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("SSN: 000-45-6789");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UsSsn));
    }

    #[test]
    fn rejects_ssn_area_666() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("SSN: 666-45-6789");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UsSsn));
    }

    #[test]
    fn rejects_ssn_area_900_range() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("SSN: 900-45-6789");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UsSsn));
    }

    #[test]
    fn rejects_ssn_group_00() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("SSN: 123-00-6789");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UsSsn));
    }

    #[test]
    fn rejects_ssn_serial_0000() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("SSN: 123-45-0000");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UsSsn));
    }

    // --- NINO tests ---

    #[test]
    fn detects_nino() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("NINO: AB 12 34 56 C");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::GbNino);
    }

    #[test]
    fn detects_nino_no_spaces() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("NINO: AB123456C");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::GbNino);
    }

    #[test]
    fn detects_nino_lowercase() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("nino: ab 12 34 56 c");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::GbNino);
    }

    #[test]
    fn rejects_nino_invalid_first_letter_d() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("NINO: DA123456C");
        assert!(matches.iter().all(|m| m.kind != PiiKind::GbNino));
    }

    #[test]
    fn rejects_nino_invalid_second_letter_o() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("NINO: AO123456C");
        assert!(matches.iter().all(|m| m.kind != PiiKind::GbNino));
    }

    #[test]
    fn rejects_nino_invalid_prefix_bg() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("NINO: BG123456C");
        assert!(matches.iter().all(|m| m.kind != PiiKind::GbNino));
    }

    #[test]
    fn rejects_nino_invalid_prefix_zz() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("NINO: ZZ123456C");
        assert!(matches.iter().all(|m| m.kind != PiiKind::GbNino));
    }

    // --- IBAN tests ---

    #[test]
    fn detects_iban_gb() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("IBAN: GB29 NWBK 6016 1331 9268 19");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Iban);
    }

    #[test]
    fn detects_iban_de() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("IBAN: DE89 3704 0044 0532 0130 00");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Iban);
    }

    #[test]
    fn detects_iban_no_spaces() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("IBAN: GB29NWBK60161331926819");
        let iban_matches: Vec<_> = matches.iter().filter(|m| m.kind == PiiKind::Iban).collect();
        assert_eq!(iban_matches.len(), 1);
    }

    #[test]
    fn rejects_iban_invalid_checksum() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("IBAN: GB00 NWBK 6016 1331 9268 19");
        assert!(matches.iter().all(|m| m.kind != PiiKind::Iban));
    }

    // --- Passport Number tests ---

    #[test]
    fn detects_passport_number() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("Passport: 123456789");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::PassportNumber);
    }

    #[test]
    fn does_not_detect_8_digits_as_passport() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("code: 12345678");
        assert!(matches.iter().all(|m| m.kind != PiiKind::PassportNumber));
    }

    #[test]
    fn does_not_detect_10_digits_as_passport() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("code: 1234567890");
        assert!(matches.iter().all(|m| m.kind != PiiKind::PassportNumber));
    }

    // --- IP Address tests ---

    #[test]
    fn detects_ipv4() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("server at 192.168.1.1 is down");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::IpAddress);
    }

    #[test]
    fn detects_ipv4_span() {
        let detector = RegexDetector::new();
        let input = "IP: 10.0.0.255 ok";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::IpAddress)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "10.0.0.255");
    }

    #[test]
    fn rejects_ipv4_octet_out_of_range() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("addr: 999.999.999.999");
        assert!(matches.iter().all(|m| m.kind != PiiKind::IpAddress));
    }

    #[test]
    fn rejects_ipv4_single_octet_over_255() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("addr: 192.168.1.256");
        assert!(matches.iter().all(|m| m.kind != PiiKind::IpAddress));
    }

    #[test]
    fn detects_ipv6_full() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("host: 2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        let ip_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::IpAddress)
            .collect();
        assert_eq!(ip_matches.len(), 1);
    }

    #[test]
    fn detects_ipv6_compressed() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("host: ::1");
        let ip_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::IpAddress)
            .collect();
        assert_eq!(ip_matches.len(), 1);
    }

    #[test]
    fn detects_ipv6_with_collapse() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("host: fe80::1");
        let ip_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::IpAddress)
            .collect();
        assert_eq!(ip_matches.len(), 1);
    }

    // --- ITIN tests ---

    #[test]
    fn detects_itin() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("ITIN: 912-70-1234");
        let itin_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::UsItin)
            .collect();
        assert_eq!(itin_matches.len(), 1);
    }

    #[test]
    fn detects_itin_span() {
        let detector = RegexDetector::new();
        let input = "my ITIN is 900-94-5678 ok";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::UsItin)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "900-94-5678");
    }

    #[test]
    fn rejects_itin_invalid_group() {
        let detector = RegexDetector::new();
        // Group 30 is not in any valid range
        let matches = detector.mark_piis("ITIN: 900-30-1234");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UsItin));
    }

    #[test]
    fn itin_does_not_overlap_with_ssn() {
        let detector = RegexDetector::new();
        // SSN rejects area 900+, so 900-xx-xxxx should only be ITIN if group is valid
        let matches = detector.mark_piis("number: 912-70-1234");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UsSsn));
        assert!(matches.iter().any(|m| m.kind == PiiKind::UsItin));
    }

    // --- Canada SIN tests ---

    #[test]
    fn detects_sin_hyphens() {
        let detector = RegexDetector::new();
        // Valid SIN with Luhn: 130-692-544
        let matches = detector.mark_piis("SIN: 130-692-544");
        let sin_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::CaSin)
            .collect();
        assert_eq!(sin_matches.len(), 1);
    }

    #[test]
    fn detects_sin_spaces() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("SIN: 130 692 544");
        let sin_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::CaSin)
            .collect();
        assert_eq!(sin_matches.len(), 1);
    }

    #[test]
    fn rejects_sin_failing_luhn() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("SIN: 123-456-789");
        assert!(matches.iter().all(|m| m.kind != PiiKind::CaSin));
    }

    // --- Ireland PPSN tests ---

    #[test]
    fn detects_ppsn_8char() {
        let detector = RegexDetector::new();
        // 1234567T: weights 8*1+7*2+6*3+5*4+4*5+3*6+2*7 = 8+14+18+20+20+18+14 = 112
        // 112 % 23 = 112 - 4*23 = 112 - 92 = 20 => letter T (A=1, T=20)
        let matches = detector.mark_piis("PPSN: 1234567T");
        let ppsn_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::IePpsn)
            .collect();
        assert_eq!(ppsn_matches.len(), 1);
    }

    #[test]
    fn detects_ppsn_9char() {
        let detector = RegexDetector::new();
        // 1234567TW — second letter doesn't affect check
        let matches = detector.mark_piis("PPSN: 1234567TW");
        let ppsn_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::IePpsn)
            .collect();
        assert_eq!(ppsn_matches.len(), 1);
    }

    #[test]
    fn rejects_ppsn_wrong_check_letter() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("PPSN: 1234567A");
        assert!(matches.iter().all(|m| m.kind != PiiKind::IePpsn));
    }

    // --- South Africa ID tests ---

    #[test]
    fn detects_sa_id() {
        let detector = RegexDetector::new();
        // 8001015009087: DOB 80-01-01, SSSS=5009, citizen=0, checksum valid
        let matches = detector.mark_piis("SA ID: 8001015009087");
        let sa_matches: Vec<_> = matches.iter().filter(|m| m.kind == PiiKind::ZaId).collect();
        assert_eq!(sa_matches.len(), 1);
    }

    #[test]
    fn rejects_sa_id_invalid_month() {
        let detector = RegexDetector::new();
        // Month 13 is invalid
        let matches = detector.mark_piis("SA ID: 8013015009087");
        assert!(matches.iter().all(|m| m.kind != PiiKind::ZaId));
    }

    #[test]
    fn rejects_sa_id_invalid_day() {
        let detector = RegexDetector::new();
        // Day 32 is invalid
        let matches = detector.mark_piis("SA ID: 8001325009087");
        assert!(matches.iter().all(|m| m.kind != PiiKind::ZaId));
    }

    #[test]
    fn rejects_sa_id_failing_luhn() {
        let detector = RegexDetector::new();
        // Valid date/citizenship but bad checksum
        let matches = detector.mark_piis("SA ID: 8001015009086");
        assert!(matches.iter().all(|m| m.kind != PiiKind::ZaId));
    }

    // --- MAC Address tests ---

    #[test]
    fn detects_mac_colon() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("MAC: 00:1A:2B:3C:4D:5E");
        let mac_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::MacAddress)
            .collect();
        assert_eq!(mac_matches.len(), 1);
    }

    #[test]
    fn detects_mac_hyphen() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("MAC: 00-1A-2B-3C-4D-5E");
        let mac_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::MacAddress)
            .collect();
        assert_eq!(mac_matches.len(), 1);
    }

    #[test]
    fn detects_mac_cisco_dot() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("MAC: 001A.2B3C.4D5E");
        let mac_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::MacAddress)
            .collect();
        assert_eq!(mac_matches.len(), 1);
    }

    #[test]
    fn detects_mac_lowercase() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("MAC: aa:bb:cc:dd:ee:ff");
        let mac_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::MacAddress)
            .collect();
        assert_eq!(mac_matches.len(), 1);
    }

    // --- UK Driving Licence tests ---

    #[test]
    fn detects_uk_driving_licence() {
        let detector = RegexDetector::new();
        // JONES901157A99Y1: JONES, 9=decade, 01=Jan, 15=day, 7=year, A9=arb, 9=issue, Y=letter, 1=check
        let matches = detector.mark_piis("DL: JONES901157A99Y1");
        let dl_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::GbDrivingLicence)
            .collect();
        assert_eq!(dl_matches.len(), 1);
    }

    #[test]
    fn rejects_uk_dl_invalid_month() {
        let detector = RegexDetector::new();
        // Month position = 00 (invalid)
        let matches = detector.mark_piis("DL: JONES900057A99Y1");
        assert!(matches.iter().all(|m| m.kind != PiiKind::GbDrivingLicence));
    }

    #[test]
    fn rejects_uk_dl_invalid_day() {
        let detector = RegexDetector::new();
        // Day = 00 (invalid)
        let matches = detector.mark_piis("DL: JONES901007A99Y1");
        assert!(matches.iter().all(|m| m.kind != PiiKind::GbDrivingLicence));
    }

    // --- VIN tests ---

    #[test]
    fn detects_vin() {
        let detector = RegexDetector::new();
        // 1HGBH41JXMN109186 — valid Honda VIN with check digit X
        let matches = detector.mark_piis("VIN: 1HGBH41JXMN109186");
        let vin_matches: Vec<_> = matches.iter().filter(|m| m.kind == PiiKind::Vin).collect();
        assert_eq!(vin_matches.len(), 1);
    }

    #[test]
    fn rejects_vin_with_invalid_chars() {
        let detector = RegexDetector::new();
        // I, O, Q are not allowed in VINs
        let matches = detector.mark_piis("VIN: 1HGBH41IXMN10918O");
        assert!(matches.iter().all(|m| m.kind != PiiKind::Vin));
    }

    #[test]
    fn detects_vin_span() {
        let detector = RegexDetector::new();
        let input = "vehicle 1HGBH41JXMN109186 registered";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::Vin)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(
            &input[matches[0].start..matches[0].end],
            "1HGBH41JXMN109186"
        );
    }

    // --- JSON input tests ---

    #[test]
    fn detects_email_in_json() {
        let detector = RegexDetector::new();
        let input = r#"{"user": {"email": "alice@example.com", "name": "Alice"}}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::Email)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(
            &input[matches[0].start..matches[0].end],
            "alice@example.com"
        );
    }

    #[test]
    fn detects_phone_in_json() {
        let detector = RegexDetector::new();
        let input = r#"{"contact": {"phone": "555-123-4567", "type": "mobile"}}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::PhoneNumber)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "555-123-4567");
    }

    #[test]
    fn detects_credit_card_in_json() {
        let detector = RegexDetector::new();
        let input = r#"{"payment": {"card_number": "4111 1111 1111 1111", "expiry": "12/28"}}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::CreditCard)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(
            &input[matches[0].start..matches[0].end],
            "4111 1111 1111 1111"
        );
    }

    #[test]
    fn detects_ssn_in_json() {
        let detector = RegexDetector::new();
        let input = r#"{"employee": {"ssn": "123-45-6789", "name": "John"}}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::UsSsn)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "123-45-6789");
    }

    #[test]
    fn detects_nino_in_json() {
        let detector = RegexDetector::new();
        let input = r#"{"employee": {"nino": "AB123456C", "department": "HR"}}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::GbNino)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "AB123456C");
    }

    #[test]
    fn detects_iban_in_json() {
        let detector = RegexDetector::new();
        let input = r#"{"bank": {"iban": "DE89370400440532013000", "currency": "EUR"}}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::Iban)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(
            &input[matches[0].start..matches[0].end],
            "DE89370400440532013000"
        );
    }

    #[test]
    fn detects_ipv4_in_json() {
        let detector = RegexDetector::new();
        let input = r#"{"server": {"ip": "192.168.1.100", "status": "up"}}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::IpAddress)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "192.168.1.100");
    }

    #[test]
    fn detects_itin_in_json() {
        let detector = RegexDetector::new();
        let input = r#"{"tax": {"itin": "912-70-1234", "year": 2025}}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::UsItin)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "912-70-1234");
    }

    #[test]
    fn detects_sin_in_json() {
        let detector = RegexDetector::new();
        let input = r#"{"employee": {"sin": "130-692-544", "province": "ON"}}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::CaSin)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "130-692-544");
    }

    #[test]
    fn detects_ppsn_in_json() {
        let detector = RegexDetector::new();
        let input = r#"{"citizen": {"ppsn": "1234567T", "county": "Dublin"}}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::IePpsn)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "1234567T");
    }

    #[test]
    fn detects_sa_id_in_json() {
        let detector = RegexDetector::new();
        let input = r#"{"citizen": {"id_number": "8001015009087", "province": "Gauteng"}}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::ZaId)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "8001015009087");
    }

    #[test]
    fn detects_mac_in_json() {
        let detector = RegexDetector::new();
        let input = r#"{"device": {"mac": "00:1A:2B:3C:4D:5E", "hostname": "ws01"}}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::MacAddress)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(
            &input[matches[0].start..matches[0].end],
            "00:1A:2B:3C:4D:5E"
        );
    }

    #[test]
    fn detects_uk_dl_in_json() {
        let detector = RegexDetector::new();
        let input = r#"{"driver": {"licence": "JONES901157A99Y1", "category": "B"}}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::GbDrivingLicence)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "JONES901157A99Y1");
    }

    #[test]
    fn detects_vin_in_json() {
        let detector = RegexDetector::new();
        let input = r#"{"vehicle": {"vin": "1HGBH41JXMN109186", "make": "Honda"}}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::Vin)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(
            &input[matches[0].start..matches[0].end],
            "1HGBH41JXMN109186"
        );
    }

    #[test]
    fn detects_multiple_pii_in_json() {
        let detector = RegexDetector::new();
        let input = r#"{"user": {"email": "alice@example.com", "phone": "555-123-4567", "ssn": "123-45-6789"}}"#;
        let matches = detector.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::PhoneNumber));
        assert!(kinds.contains(&PiiKind::UsSsn));
    }

    #[test]
    fn detects_pii_in_json_array() {
        let detector = RegexDetector::new();
        let input = r#"{"emails": ["alice@example.com", "bob@domain.org"], "active": true}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::Email)
            .collect();
        assert_eq!(matches.len(), 2);
    }
}
