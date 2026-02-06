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
                regex: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),
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
}
