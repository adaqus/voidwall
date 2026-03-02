use std::collections::HashSet;

use crate::detector::Detector;
use crate::hyperscan_detector::HyperscanDetector;
use crate::keyword_context_detector::KeywordContextDetector;
use crate::{Country, Language, PiiError, PiiKind, PiiMatch, RedactWith};

pub struct Scanner {
    detectors: Vec<Box<dyn Detector + Send + Sync>>,
}

pub struct ScannerBuilder {
    countries: HashSet<Country>,
    languages: HashSet<Language>,
    pii_kinds: HashSet<PiiKind>,
    exclude_pii_kinds: HashSet<PiiKind>,
}

impl Scanner {
    /// Creates a scanner with all countries and languages enabled.
    pub fn new() -> Result<Self, PiiError> {
        Self::builder().build()
    }

    pub fn builder() -> ScannerBuilder {
        ScannerBuilder {
            countries: HashSet::new(),
            languages: HashSet::new(),
            pii_kinds: HashSet::new(),
            exclude_pii_kinds: HashSet::new(),
        }
    }

    /// Returns `true` if any PII is detected in the input.
    pub fn has_piis(&self, input: &str) -> bool {
        self.detectors.iter().any(|d| d.has_piis(input))
    }

    /// Returns all PII matches found in the input.
    ///
    /// Match offsets are absolute byte positions from the start of the string.
    pub fn mark_piis(&self, input: &str) -> Vec<PiiMatch> {
        self.detectors
            .iter()
            .flat_map(|d| d.mark_piis(input))
            .collect()
    }

    /// Redacts all PII found in `input` in place.
    ///
    /// Non-PII text is left unchanged. PII regions are replaced according to
    /// the given `strategy`. Matches are applied back-to-front so that byte
    /// offsets remain valid after each replacement.
    pub fn redact(&self, input: &mut String, strategy: &RedactWith) {
        let mut matches = self.mark_piis(input);
        // Sort by start descending so we can replace back-to-front.
        matches.sort_by(|a, b| b.start.cmp(&a.start));

        let mut prev_start = usize::MAX;
        for m in &matches {
            // Skip overlapping matches (already covered by an earlier replacement).
            if m.end > prev_start {
                continue;
            }
            let replacement = strategy.apply(m.kind, &input[m.start..m.end]);
            input.replace_range(m.start..m.end, &replacement);
            prev_start = m.start;
        }
    }
}

impl ScannerBuilder {
    /// Set the countries whose PII types should be detected.
    ///
    /// If not called (or called with an empty iterator), all countries are
    /// enabled by default.
    pub fn countries(mut self, countries: impl IntoIterator<Item = Country>) -> Self {
        self.countries = countries.into_iter().collect();
        self
    }

    /// Set the keyword languages to use.
    ///
    /// If not called (or called with an empty iterator), all languages are
    /// enabled by default.
    pub fn languages(mut self, languages: impl IntoIterator<Item = Language>) -> Self {
        self.languages = languages.into_iter().collect();
        self
    }

    /// Set the PII types to detect (allowlist).
    ///
    /// Only these PII types will be detected. Mutually exclusive with
    /// `exclude_pii_kinds` — setting both produces an `InvalidConfiguration`
    /// error at `build()` time.
    ///
    /// If not called (or called with an empty iterator), all PII types
    /// reachable from the selected countries are enabled by default.
    ///
    /// When both `countries` and `pii_kinds` are set explicitly (non-empty),
    /// `build()` validates that every explicit PII kind is reachable from at
    /// least one enabled country, and every explicit country contributes at
    /// least one enabled PII kind.
    pub fn pii_kinds(mut self, pii_kinds: impl IntoIterator<Item = PiiKind>) -> Self {
        self.pii_kinds = pii_kinds.into_iter().collect();
        self
    }

    /// Exclude specific PII types from detection (blocklist).
    ///
    /// All PII types reachable from the selected countries will be detected
    /// *except* the ones listed here. Mutually exclusive with `pii_kinds` —
    /// setting both produces an `InvalidConfiguration` error at `build()` time.
    ///
    /// When `countries` is also set explicitly, `build()` validates that every
    /// excluded kind is reachable from the enabled countries and that every
    /// explicit country still contributes at least one kind after exclusion.
    pub fn exclude_pii_kinds(mut self, exclude: impl IntoIterator<Item = PiiKind>) -> Self {
        self.exclude_pii_kinds = exclude.into_iter().collect();
        self
    }

    /// Build the scanner, compiling all selected patterns.
    pub fn build(self) -> Result<Scanner, PiiError> {
        let countries_explicit = !self.countries.is_empty();
        let pii_kinds_explicit = !self.pii_kinds.is_empty();
        let exclude_explicit = !self.exclude_pii_kinds.is_empty();

        // Mutual exclusion: allowlist and blocklist cannot both be set.
        if pii_kinds_explicit && exclude_explicit {
            return Err(PiiError::InvalidConfiguration(
                "pii_kinds and exclude_pii_kinds are mutually exclusive".into(),
            ));
        }

        let countries: HashSet<Country> = if countries_explicit {
            self.countries
        } else {
            Country::all().iter().copied().collect()
        };

        let languages = if self.languages.is_empty() {
            Language::all().iter().copied().collect()
        } else {
            self.languages
        };

        let country_kinds = PiiKind::enabled_for_countries(&countries);

        let enabled_kinds = if pii_kinds_explicit {
            // Allowlist mode: only these PII types.

            // Validate: every explicit PiiKind must be reachable from enabled countries.
            let unreachable: Vec<&PiiKind> = self
                .pii_kinds
                .iter()
                .filter(|k| !country_kinds.contains(k))
                .collect();
            if !unreachable.is_empty() {
                let labels: Vec<&str> = unreachable.iter().map(|k| k.label()).collect();
                return Err(PiiError::InvalidConfiguration(format!(
                    "PII kinds not reachable from the selected countries: {}",
                    labels.join(", ")
                )));
            }

            // Validate: every explicit Country must contribute at least one enabled PiiKind.
            if countries_explicit {
                validate_no_unused_countries(&countries, &self.pii_kinds)?;
            }

            self.pii_kinds
        } else if exclude_explicit {
            // Blocklist mode: all country kinds minus excluded.

            // Validate: every excluded kind must be reachable from enabled countries.
            let unreachable: Vec<&PiiKind> = self
                .exclude_pii_kinds
                .iter()
                .filter(|k| !country_kinds.contains(k))
                .collect();
            if !unreachable.is_empty() {
                let labels: Vec<&str> = unreachable.iter().map(|k| k.label()).collect();
                return Err(PiiError::InvalidConfiguration(format!(
                    "excluded PII kinds not reachable from the selected countries: {}",
                    labels.join(", ")
                )));
            }

            let remaining: HashSet<PiiKind> = country_kinds
                .difference(&self.exclude_pii_kinds)
                .copied()
                .collect();

            // Validate: every explicit Country must still contribute after exclusion.
            if countries_explicit {
                validate_no_unused_countries(&countries, &remaining)?;
            }

            remaining
        } else {
            country_kinds
        };

        let regex_detector: Box<dyn Detector + Send + Sync> =
            Box::new(HyperscanDetector::new(&enabled_kinds)?);

        Ok(Scanner {
            detectors: vec![
                regex_detector,
                Box::new(KeywordContextDetector::new(&enabled_kinds, &languages)?),
            ],
        })
    }
}

fn validate_no_unused_countries(
    countries: &HashSet<Country>,
    enabled_kinds: &HashSet<PiiKind>,
) -> Result<(), PiiError> {
    let unused: Vec<Country> = countries
        .iter()
        .filter(|c| {
            !enabled_kinds
                .iter()
                .any(|k| k.applicable_countries().contains(c))
        })
        .copied()
        .collect();
    if !unused.is_empty() {
        let labels: Vec<String> = unused.iter().map(|c| format!("{c:?}")).collect();
        return Err(PiiError::InvalidConfiguration(format!(
            "countries that contribute no enabled PII kinds: {}",
            labels.join(", ")
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use super::*;
    use test_case::test_case;

    static SCANNER: LazyLock<Scanner> = LazyLock::new(|| Scanner::new().unwrap());

    #[test]
    fn has_piis_detects_email() {
        let scanner = &*SCANNER;
        assert!(scanner.has_piis("email me at test@example.com"));
    }

    #[test]
    fn has_piis_returns_false_for_clean_text() {
        let scanner = &*SCANNER;
        assert!(!scanner.has_piis("nothing sensitive here"));
    }

    #[test]
    fn mark_piis_finds_multiple_types() {
        let scanner = &*SCANNER;
        let input = "email: user@test.com, phone: 555-123-4567, card: 4111 1111 1111 1111";
        let matches = scanner.mark_piis(input);

        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::PhoneNumber));
        assert!(kinds.contains(&PiiKind::CreditCard));
    }

    #[test]
    fn mark_piis_returns_correct_spans() {
        let scanner = &*SCANNER;
        let input = "hello user@test.com world";
        let matches = scanner.mark_piis(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "user@test.com");
    }

    #[test]
    fn builder_all_countries_matches_new() {
        let scanner_new = &*SCANNER;
        let scanner_builder = Scanner::builder().build().unwrap();
        let input = "email: user@test.com, SSN: 123-45-6789, NINO: AB 12 34 56 C, \
                     phone: 555-123-4567, card: 4111 1111 1111 1111";
        let matches_new = scanner_new.mark_piis(input);
        let matches_builder = scanner_builder.mark_piis(input);
        assert_eq!(matches_new.len(), matches_builder.len());
    }

    #[test]
    fn builder_single_country_us() {
        let scanner = Scanner::builder()
            .countries([Country::Us, Country::International])
            .build()
            .unwrap();
        // US SSN should be detected
        let input = "SSN: 123-45-6789 and NINO: AB 12 34 56 C";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::UsSsn));
        // GB NINO should NOT be detected
        assert!(!kinds.contains(&PiiKind::GbNino));
    }

    #[test]
    fn builder_single_country_gb() {
        let scanner = Scanner::builder()
            .countries([Country::Gb, Country::International])
            .build()
            .unwrap();
        let input = "SSN: 123-45-6789 and NINO: AB 12 34 56 C";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::GbNino));
        assert!(!kinds.contains(&PiiKind::UsSsn));
    }

    #[test]
    fn builder_international_only() {
        let scanner = Scanner::builder()
            .countries([Country::International])
            .build()
            .unwrap();
        let input = "email: user@test.com, SSN: 123-45-6789, card: 4111 1111 1111 1111";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::CreditCard));
        assert!(!kinds.contains(&PiiKind::UsSsn));
    }

    #[test]
    fn builder_excludes_unselected_countries() {
        let scanner = Scanner::builder().countries([Country::Us]).build().unwrap();
        // Input with US SSN + GB NINO + GB UTR
        let input = "SSN: 123-45-6789, NINO: AB 12 34 56 C, UTR: 5555555555";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::UsSsn));
        assert!(!kinds.contains(&PiiKind::GbNino));
        assert!(!kinds.contains(&PiiKind::GbUtr));
    }

    #[test]
    fn builder_empty_countries_defaults_to_all() {
        let scanner = Scanner::builder()
            .countries(std::iter::empty::<Country>())
            .build()
            .unwrap();
        let input = "SSN: 123-45-6789 and NINO: AB 12 34 56 C";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::UsSsn));
        assert!(kinds.contains(&PiiKind::GbNino));
    }

    #[test]
    fn builder_empty_languages_defaults_to_all() {
        let scanner = Scanner::builder()
            .languages(std::iter::empty::<Language>())
            .build()
            .unwrap();
        // keyword-based detection should still work
        let input = "phone: 555-123-4567";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::PhoneNumber));
    }

    // --- pii_kinds builder tests ---

    #[test]
    fn builder_pii_kinds_filters_detection() {
        let scanner = Scanner::builder()
            .countries([Country::Us, Country::International])
            .pii_kinds([PiiKind::Email, PiiKind::UsSsn])
            .build()
            .unwrap();
        let input = "email: user@test.com, SSN: 123-45-6789, card: 4111 1111 1111 1111";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::UsSsn));
        assert!(!kinds.contains(&PiiKind::CreditCard));
    }

    #[test]
    fn builder_pii_kinds_multiple_types() {
        let scanner = Scanner::builder()
            .countries([Country::Us, Country::International])
            .pii_kinds([PiiKind::Email, PiiKind::UsSsn])
            .build()
            .unwrap();
        let input = "email: user@test.com, SSN: 123-45-6789, card: 4111 1111 1111 1111";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::UsSsn));
        assert!(!kinds.contains(&PiiKind::CreditCard));
    }

    #[test]
    fn builder_pii_kinds_empty_defaults_to_all() {
        let scanner = Scanner::builder()
            .pii_kinds(std::iter::empty::<PiiKind>())
            .build()
            .unwrap();
        let input = "email: user@test.com, SSN: 123-45-6789";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::UsSsn));
    }

    #[test]
    fn builder_pii_kinds_without_countries_uses_all_countries() {
        // pii_kinds explicit, countries implicit (all) — no validation error
        let scanner = Scanner::builder()
            .pii_kinds([PiiKind::UsSsn, PiiKind::GbNino])
            .build()
            .unwrap();
        let input = "SSN: 123-45-6789 and NINO: AB 12 34 56 C";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::UsSsn));
        assert!(kinds.contains(&PiiKind::GbNino));
    }

    #[test]
    fn builder_pii_kinds_unreachable_from_countries_errors() {
        let err = match Scanner::builder()
            .countries([Country::Us, Country::International])
            .pii_kinds([PiiKind::UsSsn, PiiKind::Email, PiiKind::GbPostcode])
            .build()
        {
            Err(e) => e,
            Ok(_) => panic!("should fail with unreachable PII kind"),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("GB_POSTCODE"),
            "error should name the unreachable kind: {msg}"
        );
    }

    #[test]
    fn builder_country_contributes_no_enabled_kinds_errors() {
        let err = match Scanner::builder()
            .countries([Country::Us, Country::Gb, Country::International])
            .pii_kinds([PiiKind::UsSsn, PiiKind::Email])
            .build()
        {
            Err(e) => e,
            Ok(_) => panic!("should fail with unused country"),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("Gb"),
            "error should name the unused country: {msg}"
        );
    }

    #[test]
    fn builder_pii_kinds_keyword_detector_type() {
        // PhoneNumber is keyword-context detected — verify it works with pii_kinds filter
        let scanner = Scanner::builder()
            .countries([Country::International])
            .pii_kinds([PiiKind::PhoneNumber])
            .languages([Language::En])
            .build()
            .unwrap();
        let input = "phone: 555-123-4567";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::PhoneNumber));
    }

    // --- exclude_pii_kinds builder tests ---

    #[test]
    fn builder_exclude_pii_kinds_removes_types() {
        let scanner = Scanner::builder()
            .countries([Country::Us, Country::International])
            .exclude_pii_kinds([PiiKind::CreditCard])
            .build()
            .unwrap();
        let input = "email: user@test.com, SSN: 123-45-6789, card: 4111 1111 1111 1111";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::UsSsn));
        assert!(!kinds.contains(&PiiKind::CreditCard));
    }

    #[test]
    fn builder_exclude_pii_kinds_empty_defaults_to_all() {
        let scanner = Scanner::builder()
            .exclude_pii_kinds(std::iter::empty::<PiiKind>())
            .build()
            .unwrap();
        let input = "email: user@test.com, SSN: 123-45-6789";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::UsSsn));
    }

    #[test]
    fn builder_exclude_and_include_pii_kinds_errors() {
        let err = match Scanner::builder()
            .pii_kinds([PiiKind::Email])
            .exclude_pii_kinds([PiiKind::CreditCard])
            .build()
        {
            Err(e) => e,
            Ok(_) => panic!("should fail when both pii_kinds and exclude_pii_kinds are set"),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("mutually exclusive"),
            "error should mention mutual exclusivity: {msg}"
        );
    }

    #[test]
    fn builder_exclude_unreachable_kind_errors() {
        let err = match Scanner::builder()
            .countries([Country::Us, Country::International])
            .exclude_pii_kinds([PiiKind::GbPostcode])
            .build()
        {
            Err(e) => e,
            Ok(_) => panic!("should fail with unreachable excluded kind"),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("GB_POSTCODE"),
            "error should name the unreachable excluded kind: {msg}"
        );
    }

    #[test]
    fn builder_exclude_leaves_country_empty_errors() {
        // Exclude all US-specific kinds so Country::Us contributes nothing
        let err = match Scanner::builder()
            .countries([Country::Us, Country::International])
            .exclude_pii_kinds([
                PiiKind::UsSsn,
                PiiKind::UsItin,
                PiiKind::UsPassportNew,
                PiiKind::UsEin,
                PiiKind::UsAbaRouting,
                PiiKind::UsDriversLicense,
                PiiKind::UsAlienNumber,
                PiiKind::UsUscisReceiptNumber,
            ])
            .build()
        {
            Err(e) => e,
            Ok(_) => panic!("should fail when exclusion leaves a country with no kinds"),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("Us"),
            "error should name the empty country: {msg}"
        );
    }

    #[test]
    fn builder_exclude_without_countries_uses_all_countries() {
        // exclude_pii_kinds explicit, countries implicit — no country validation
        let scanner = Scanner::builder()
            .exclude_pii_kinds([PiiKind::CreditCard])
            .build()
            .unwrap();
        let input = "email: user@test.com, card: 4111 1111 1111 1111";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(!kinds.contains(&PiiKind::CreditCard));
    }

    // --- Redaction char-mask tests ---

    #[test_case("email me at test@example.com please", '*', "email me at **************** please" ; "basic email char mask")]
    #[test_case("test@example.com", '#', "################" ; "whole string char mask")]
    #[test_case("nothing sensitive here at all", '*', "nothing sensitive here at all" ; "no pii preserves text")]
    // URL-encoded @ sign
    #[test_case("contact user%40example.com now", '*', "contact ****************** now" ; "url encoded at sign char mask")]
    // HTML decimal entity @ sign
    #[test_case("contact user&#64;example.com now", '*', "contact ******************** now" ; "html decimal entity at char mask")]
    // HTML hex entity @ sign
    #[test_case("contact user&#x40;example.com now", '*', "contact ********************* now" ; "html hex entity at char mask")]
    // HTML named entity @ sign
    #[test_case("contact user&commat;example.com now", '*', "contact *********************** now" ; "html named entity at char mask")]
    // URL-encoded dot in host
    #[test_case("contact user@example%2Ecom now", '*', "contact ****************** now" ; "url encoded dot in host char mask")]
    // Zero-width space in email — ZWSP is stripped for detection but present in output
    #[test_case("contact user\u{200B}@example.com now", '*', "contact ***************** now" ; "zwsp in email char mask")]
    // Zero-width space in SSN
    #[test_case("SSN: 123\u{200B}-45-6789", '*', "SSN: ************" ; "zwsp in ssn char mask")]
    // RTL mark surrounding email (U+200F is not stripped, but email still detected)
    #[test_case("contact \u{200F}user@example.com\u{200F} please", '*', "contact \u{200F}****************\u{200F} please" ; "rtl marks surrounding email char mask")]
    // Cyrillic homoglyph in domain (U+0430 looks like Latin 'a')
    #[test_case("user@ex\u{0430}mple.com", '*', "****************" ; "cyrillic homoglyph email char mask")]
    // Surrounding text with URL-encoded characters preserved
    #[test_case("100%25 sure user@example.com is valid", '*', "100%25 sure **************** is valid" ; "url encoded surrounding text preserved")]
    #[test_case("path/to%2Ffile user@example.com end", '*', "path/to%2Ffile **************** end" ; "url encoded slash surrounding preserved")]
    // Surrounding text with HTML entities preserved
    #[test_case("price &gt; 0 user@example.com ok", '*', "price &gt; 0 **************** ok" ; "html entity gt surrounding preserved")]
    #[test_case("a &amp; b user@example.com end", '*', "a &amp; b **************** end" ; "html entity amp surrounding preserved")]
    #[test_case("&#169; 2024 user@example.com end", '*', "&#169; 2024 **************** end" ; "html decimal entity surrounding preserved")]
    // Surrounding text with ZWSP preserved
    #[test_case("hello\u{200B}world user@example.com end", '*', "hello\u{200B}world **************** end" ; "zwsp in surrounding text preserved")]
    #[test_case("before\u{200B}\u{200B}after user@example.com end", '*', "before\u{200B}\u{200B}after **************** end" ; "multiple zwsp in surrounding preserved")]
    // Surrounding text with other Unicode characters preserved
    #[test_case("\u{00E9}l\u{00E8}ve user@example.com fin", '*', "\u{00E9}l\u{00E8}ve **************** fin" ; "accented chars surrounding preserved")]
    #[test_case("\u{2603} user@example.com \u{2764}", '*', "\u{2603} **************** \u{2764}" ; "emoji surrounding preserved")]
    #[test_case("\u{00BF}hola? user@example.com \u{00A1}s\u{00ED}!", '*', "\u{00BF}hola? **************** \u{00A1}s\u{00ED}!" ; "spanish punctuation surrounding preserved")]
    #[test_case("\u{200E}LTR user@example.com \u{200E}end", '*', "\u{200E}LTR **************** \u{200E}end" ; "ltr marks surrounding preserved")]
    fn redact_char_mask(input: &str, mask: char, expected: &str) {
        let scanner = &*SCANNER;
        let mut text = String::from(input);
        scanner.redact(&mut text, &crate::RedactWith::Char(mask));
        assert_eq!(
            text, expected,
            "char-mask redaction mismatch for input: {input}"
        );
    }

    // --- Redaction type-label tests ---

    #[test_case("email me at test@example.com please", "[EMAIL]" ; "basic email type label")]
    #[test_case("nothing sensitive here", "nothing sensitive here" ; "no pii preserves text type label")]
    // URL-encoded @ sign
    #[test_case("contact user%40example.com now", "[EMAIL]" ; "url encoded at type label")]
    // HTML entity @ sign
    #[test_case("contact user&#64;example.com now", "[EMAIL]" ; "html entity at type label")]
    // HTML named entity @ sign
    #[test_case("contact user&commat;example.com now", "[EMAIL]" ; "html named entity at type label")]
    // Zero-width space in email
    #[test_case("contact user\u{200B}@example.com now", "[EMAIL]" ; "zwsp in email type label")]
    // Cyrillic homoglyph in domain
    #[test_case("user@ex\u{0430}mple.com", "[EMAIL]" ; "cyrillic homoglyph type label")]
    fn redact_type_label_contains(input: &str, expected_label: &str) {
        let scanner = &*SCANNER;
        let mut text = String::from(input);
        scanner.redact(&mut text, &crate::RedactWith::TypeLabel);
        assert!(
            text.contains(expected_label),
            "expected {expected_label} in redacted output, got: {text}"
        );
    }

    #[test]
    fn redact_type_label_multiple_pii_types() {
        let scanner = &*SCANNER;
        let mut input = String::from("email: user@test.com, SSN: 123-45-6789");
        scanner.redact(&mut input, &crate::RedactWith::TypeLabel);
        assert!(input.contains("[EMAIL]"));
        assert!(input.contains("[US_SSN]"));
        assert!(!input.contains("user@test.com"));
        assert!(!input.contains("123-45-6789"));
    }

    #[test]
    fn redact_type_label_multiple_encoded_piis() {
        let scanner = &*SCANNER;
        let mut input = String::from("email: user%40test.com, SSN: 123-45-6789");
        scanner.redact(&mut input, &crate::RedactWith::TypeLabel);
        assert!(input.contains("[EMAIL]"));
        assert!(input.contains("[US_SSN]"));
        assert!(!input.contains("user%40test.com"));
        assert!(!input.contains("123-45-6789"));
    }

    // Compile-time assertion that Scanner is Send + Sync.
    #[test]
    fn scanner_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Scanner>();
    }
}
