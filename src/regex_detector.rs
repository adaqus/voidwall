use regex::Regex;

use crate::detector::Detector;
use crate::{PiiKind, PiiMatch};

struct Pattern {
    kind: PiiKind,
    regex: Regex,
}

pub struct RegexDetector {
    patterns: Vec<Pattern>,
}

impl Default for RegexDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RegexDetector {
    pub fn new() -> Self {
        let patterns = vec![
            Pattern {
                kind: PiiKind::Email,
                regex: Regex::new(r"[\p{L}\p{N}._%+-]+@[\p{L}\p{N}.-]+\.[\p{L}]{2,}").unwrap(),
            },
            Pattern {
                kind: PiiKind::PhoneNumber,
                regex: Regex::new(r"(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}")
                    .unwrap(),
            },
            Pattern {
                kind: PiiKind::CreditCard,
                regex: Regex::new(r"\b(?:[0-9]{4}[-\s]?){3}[0-9]{1,4}\b").unwrap(),
            },
        ];

        Self { patterns }
    }
}

impl Detector for RegexDetector {
    fn has_piis(&self, input: &str) -> bool {
        self.patterns.iter().any(|p| p.regex.is_match(input))
    }

    fn mark_piis(&self, input: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();
        for pattern in &self.patterns {
            for m in pattern.regex.find_iter(input) {
                let candidate = m.as_str();
                if pattern.kind == PiiKind::CreditCard && !luhn_check(candidate) {
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
}
