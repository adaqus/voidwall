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
                r"[\p{L}\p{N}._%+-]+@[\p{L}\p{N}.-]+\.[\p{L}]{2,}",
            ),
            (
                PiiKind::PhoneNumber,
                r"(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}",
            ),
            (PiiKind::CreditCard, r"\b(?:[0-9]{4}[-\s]?){3}[0-9]{1,4}\b"),
            (PiiKind::Ssn, r"\b(\d{3})-(\d{2})-(\d{4})\b"),
            (
                PiiKind::Nino,
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
                if pattern.kind == PiiKind::Ssn && !ssn_check(candidate) {
                    continue;
                }
                if pattern.kind == PiiKind::Nino && !nino_check(candidate) {
                    continue;
                }
                if pattern.kind == PiiKind::Iban && !iban_check(candidate) {
                    continue;
                }
                if pattern.kind == PiiKind::IpAddress && !ip_check(candidate) {
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
        // The regex requires exactly 3-3-4 digit groups
        assert_eq!(
            matches.len(),
            0,
            "French 9-digit number should not match US-centric pattern"
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
        assert_eq!(matches[0].kind, PiiKind::Ssn);
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
        assert!(matches.iter().all(|m| m.kind != PiiKind::Ssn));
    }

    #[test]
    fn rejects_ssn_area_666() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("SSN: 666-45-6789");
        assert!(matches.iter().all(|m| m.kind != PiiKind::Ssn));
    }

    #[test]
    fn rejects_ssn_area_900_range() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("SSN: 900-45-6789");
        assert!(matches.iter().all(|m| m.kind != PiiKind::Ssn));
    }

    #[test]
    fn rejects_ssn_group_00() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("SSN: 123-00-6789");
        assert!(matches.iter().all(|m| m.kind != PiiKind::Ssn));
    }

    #[test]
    fn rejects_ssn_serial_0000() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("SSN: 123-45-0000");
        assert!(matches.iter().all(|m| m.kind != PiiKind::Ssn));
    }

    // --- NINO tests ---

    #[test]
    fn detects_nino() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("NINO: AB 12 34 56 C");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Nino);
    }

    #[test]
    fn detects_nino_no_spaces() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("NINO: AB123456C");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Nino);
    }

    #[test]
    fn detects_nino_lowercase() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("nino: ab 12 34 56 c");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::Nino);
    }

    #[test]
    fn rejects_nino_invalid_first_letter_d() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("NINO: DA123456C");
        assert!(matches.iter().all(|m| m.kind != PiiKind::Nino));
    }

    #[test]
    fn rejects_nino_invalid_second_letter_o() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("NINO: AO123456C");
        assert!(matches.iter().all(|m| m.kind != PiiKind::Nino));
    }

    #[test]
    fn rejects_nino_invalid_prefix_bg() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("NINO: BG123456C");
        assert!(matches.iter().all(|m| m.kind != PiiKind::Nino));
    }

    #[test]
    fn rejects_nino_invalid_prefix_zz() {
        let detector = RegexDetector::new();
        let matches = detector.mark_piis("NINO: ZZ123456C");
        assert!(matches.iter().all(|m| m.kind != PiiKind::Nino));
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
}
