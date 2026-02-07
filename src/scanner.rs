use crate::PiiMatch;
use crate::detector::Detector;
use crate::keyword_context_detector::KeywordContextDetector;
use crate::regex_detector::RegexDetector;

pub struct Scanner {
    detectors: Vec<Box<dyn Detector>>,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            detectors: vec![
                Box::new(RegexDetector::new()),
                Box::new(KeywordContextDetector::new()),
            ],
        }
    }

    /// Returns `true` if any PII is detected in the input.
    ///
    /// Short-circuits as soon as any detector finds a match.
    pub fn has_piis(&self, input: &str) -> bool {
        self.detectors.iter().any(|d| d.has_piis(input))
    }

    /// Returns all PII matches found across all detectors.
    pub fn mark_piis(&self, input: &str) -> Vec<PiiMatch> {
        self.detectors
            .iter()
            .flat_map(|d| d.mark_piis(input))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PiiKind;

    #[test]
    fn has_piis_detects_email() {
        let scanner = Scanner::new();
        assert!(scanner.has_piis("email me at test@example.com"));
    }

    #[test]
    fn has_piis_returns_false_for_clean_text() {
        let scanner = Scanner::new();
        assert!(!scanner.has_piis("nothing sensitive here"));
    }

    #[test]
    fn mark_piis_finds_multiple_types() {
        let scanner = Scanner::new();
        let input = "email: user@test.com, phone: 555-123-4567, card: 4111 1111 1111 1111";
        let matches = scanner.mark_piis(input);

        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::PhoneNumber));
        assert!(kinds.contains(&PiiKind::CreditCard));
    }

    #[test]
    fn mark_piis_returns_correct_spans() {
        let scanner = Scanner::new();
        let input = "hello user@test.com world";
        let matches = scanner.mark_piis(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "user@test.com");
    }
}
