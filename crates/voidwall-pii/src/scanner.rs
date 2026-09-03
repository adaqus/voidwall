use std::collections::HashSet;

use crate::detector::Detector;
use crate::dictionary_detector::DictionaryDetector;
use crate::hyperscan_detector::HyperscanDetector;
use crate::keyword_context_detector::KeywordContextDetector;
use crate::user_detector::{UserDetector, UserPiiDefinition};
use crate::{ContextFragment, Country, Language, PiiError, PiiKind, PiiMatch};

pub struct Scanner {
    detectors: Vec<Box<dyn Detector + Send + Sync>>,
}

pub struct ScannerBuilder {
    countries: HashSet<Country>,
    languages: HashSet<Language>,
    pii_kinds: HashSet<PiiKind>,
    exclude_pii_kinds: HashSet<PiiKind>,
    user_piis: Vec<UserPiiDefinition>,
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
            user_piis: Vec::new(),
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

    /// Scans pre-parsed context/value fragments (e.g. JSON keys + values, or
    /// CSV columns + cells). Returned match offsets are document-absolute,
    /// using each fragment's `offset` field.
    pub fn mark_piis_structured(&self, fragments: &[ContextFragment<'_>]) -> Vec<PiiMatch> {
        self.detectors
            .iter()
            .flat_map(|d| d.mark_piis_structured(fragments))
            .collect()
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

    /// Register user-defined PII definitions.
    ///
    /// Entries are scanned by a separate `UserDetector` that isolates
    /// user-supplied regex patterns from the built-in vectorscan database.
    /// Entries whose `country` is not in the scanner's enabled country set
    /// are dropped at build time. Matches are reported with
    /// `PiiKind::Custom` and the per-entry label on `PiiMatch::user_label`.
    pub fn user_piis(mut self, defs: impl IntoIterator<Item = UserPiiDefinition>) -> Self {
        self.user_piis = defs.into_iter().collect();
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

        let mut detectors: Vec<Box<dyn Detector + Send + Sync>> = vec![
            regex_detector,
            Box::new(KeywordContextDetector::new(&enabled_kinds, &languages)?),
        ];

        if !self.user_piis.is_empty() {
            detectors.push(Box::new(UserDetector::new(&self.user_piis, &countries)?));
        }

        // DictionaryDetector runs last: `mark_piis` order is output-neutral
        // (`resolve_overlaps` arbitrates), and last placement lets the cheap
        // single-pass vectorscan detectors short-circuit `has_piis` first.
        // Built — and the FST loaded — only when `PersonName` is enabled, so a
        // corrupt artifact surfaces here (caught by `--validate`).
        if enabled_kinds.contains(&PiiKind::PersonName) {
            detectors.push(Box::new(DictionaryDetector::new()?));
        }

        Ok(Scanner { detectors })
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
        assert!(kinds.contains(&PiiKind::UsPhoneNumber));
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
    fn mark_piis_structured_empty_returns_empty() {
        let scanner = &*SCANNER;
        let matches = scanner.mark_piis_structured(&[]);
        assert!(matches.is_empty());
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
        assert!(kinds.contains(&PiiKind::UsPhoneNumber));
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
        // UsPhoneNumber is keyword-context detected — verify it works with pii_kinds filter
        let scanner = Scanner::builder()
            .countries([Country::International])
            .pii_kinds([PiiKind::UsPhoneNumber])
            .languages([Language::En])
            .build()
            .unwrap();
        let input = "phone: 555-123-4567";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::UsPhoneNumber));
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
                PiiKind::UsZaPostalCode,
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

    // --- PII detection in URL paths ---

    // Structured PII (HyperscanDetector) embedded in URL paths
    #[test_case(
        "/api/users/user@example.com/profile",
        PiiKind::Email, "user@example.com"
        ; "email in url path"
    )]
    #[test_case(
        "/api/users/user%40example.com/profile",
        PiiKind::Email, "user%40example.com"
        ; "email percent encoded in url path"
    )]
    #[test_case(
        "/lookup?ssn=123-45-6789",
        PiiKind::UsSsn, "123-45-6789"
        ; "ssn in query string"
    )]
    #[test_case(
        "/lookup?ssn=123%2D45%2D6789",
        PiiKind::UsSsn, "123%2D45%2D6789"
        ; "ssn percent encoded in query string"
    )]
    #[test_case(
        "/verify?card=4111111111111111",
        PiiKind::CreditCard, "4111111111111111"
        ; "credit card in query string"
    )]
    #[test_case(
        "/v1/iban/GB29NWBK60161331926819/check",
        PiiKind::Iban, "GB29NWBK60161331926819"
        ; "iban in url path segment"
    )]
    #[test_case(
        "/v1/nino/AB123456C/benefits",
        PiiKind::GbNino, "AB123456C"
        ; "nino in url path"
    )]
    #[test_case(
        "/admin/ip/192.168.1.1/block",
        PiiKind::IpAddress, "192.168.1.1"
        ; "ipv4 in url path"
    )]
    #[test_case(
        "/tax/itin/912-70-1234/verify",
        PiiKind::UsItin, "912-70-1234"
        ; "itin in url path"
    )]
    #[test_case(
        "/ca/sin/130-692-544/status",
        PiiKind::CaSin, "130-692-544"
        ; "ca sin in url path"
    )]
    #[test_case(
        "/ie/ppsn/1234567T/lookup",
        PiiKind::IePpsn, "1234567T"
        ; "ie ppsn in url path"
    )]
    #[test_case(
        "/devices/mac/00:1A:2B:3C:4D:5E/info",
        PiiKind::MacAddress, "00:1A:2B:3C:4D:5E"
        ; "mac address in url path"
    )]
    #[test_case(
        "/uk/dl/JONES901157A99Y1/check",
        PiiKind::GbDrivingLicence, "JONES901157A99Y1"
        ; "gb driving licence in url path"
    )]
    #[test_case(
        "/vehicles/vin/1HGBH41JXMN109186/recall",
        PiiKind::Vin, "1HGBH41JXMN109186"
        ; "vin in url path"
    )]
    #[test_case(
        "/keys/AKIAIOSFODNN7EXAMPLE/revoke",
        PiiKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE"
        ; "aws access key in url path"
    )]
    #[test_case(
        "/tokens/ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH12/revoke",
        PiiKind::GithubToken, "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH12"
        ; "github token in url path"
    )]
    #[test_case(
        "/uk/postcode/SW1A1AA/nearby",
        PiiKind::GbPostcode, "SW1A1AA"
        ; "gb postcode in url path no space"
    )]
    #[test_case(
        "/btc/1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf/balance",
        PiiKind::BitcoinAddress, "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"
        ; "bitcoin address in url path"
    )]
    #[test_case(
        "/eth/0x1234567890abcdef1234567890abcdef12345678/balance",
        PiiKind::EthereumAddress, "0x1234567890abcdef1234567890abcdef12345678"
        ; "ethereum address in url path"
    )]
    // Keyword-context PII in URL query parameters
    #[test_case(
        "/api/search?phone_number=555-123-4567",
        PiiKind::UsPhoneNumber, "555-123-4567"
        ; "phone in query param"
    )]
    #[test_case(
        "/api/search?passport_number=123456789",
        PiiKind::PassportNumber, "123456789"
        ; "passport in query param"
    )]
    #[test_case(
        "/api/search?date_of_birth=15/03/1990",
        PiiKind::DateOfBirth, "15/03/1990"
        ; "dob in query param"
    )]
    #[test_case(
        "/api/search?last_name=Lopez",
        PiiKind::PersonName, "Lopez"
        ; "person name in query param"
    )]
    // Multiple query parameters
    #[test_case(
        "/form?first_name=John&phone_number=555-123-4567&ref=abc",
        PiiKind::UsPhoneNumber, "555-123-4567"
        ; "phone among multiple query params"
    )]
    #[test_case(
        "/form?first_name=John&phone_number=555-123-4567&ref=abc",
        PiiKind::PersonName, "John"
        ; "name among multiple query params"
    )]
    // Percent-encoded keyword separators in URL paths
    #[test_case(
        "/log?phone%3A%20555-123-4567",
        PiiKind::UsPhoneNumber, "555-123-4567"
        ; "phone with encoded colon in url"
    )]
    #[test_case(
        "/data?passport%3A123456789",
        PiiKind::PassportNumber, "123456789"
        ; "passport with encoded colon in url"
    )]
    // Array bracket notation in query string
    #[test_case(
        "/form?par=1&user[last_name]=Maurice",
        PiiKind::PersonName, "Maurice"
        ; "bracket last_name in url"
    )]
    #[test_case(
        "/form?par=1&user[first_name]=Zidane",
        PiiKind::PersonName, "Zidane"
        ; "bracket first_name in url"
    )]
    // URL path with keyword as path segment
    #[test_case(
        "/api/phone/555-123-4567/details",
        PiiKind::UsPhoneNumber, "555-123-4567"
        ; "phone as path segment with slash separator"
    )]
    #[test_case(
        "/api/passport/123456789",
        PiiKind::PassportNumber, "123456789"
        ; "passport as path segment with slash separator"
    )]
    fn detects_pii_in_url(input: &str, kind: PiiKind, expected_span: &str) {
        let scanner = &*SCANNER;
        // Resolve overlaps to match how the proxy counts: a value carrying a
        // keyword (e.g. `postcode/SW1A1AA`) can fire both the structural and
        // keyword-gated GbPostcode rules on the same span; resolve_overlaps
        // dedupes them.
        let matches: Vec<_> = crate::resolve_overlaps(scanner.mark_piis(input))
            .into_iter()
            .filter(|m| m.kind == kind)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected 1 match for {kind:?} in: {input}"
        );
        assert_eq!(&input[matches[0].start..matches[0].end], expected_span);
    }

    #[test]
    fn has_piis_detects_in_url_path() {
        let scanner = &*SCANNER;
        assert!(scanner.has_piis("/api/users/user@example.com/profile"));
        assert!(scanner.has_piis("/lookup?ssn=123-45-6789"));
        assert!(scanner.has_piis("/api/search?phone_number=555-123-4567"));
    }

    #[test]
    fn url_path_no_false_positives() {
        let scanner = &*SCANNER;
        assert!(!scanner.has_piis("/api/users/12345/profile"));
        assert!(!scanner.has_piis("/search?q=hello+world&page=2"));
        assert!(!scanner.has_piis("/v1/status/healthy"));
    }

    #[test]
    fn url_multiple_pii_in_query_string() {
        let scanner = &*SCANNER;
        let input = "/submit?email=user@test.com&phone_number=555-123-4567&ssn=123-45-6789";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email), "should detect email");
        assert!(
            kinds.contains(&PiiKind::UsPhoneNumber),
            "should detect phone"
        );
        assert!(kinds.contains(&PiiKind::UsSsn), "should detect ssn");
    }

    // --- DictionaryDetector activation gate (PersonName) ---

    #[test]
    fn person_name_detected_when_enabled() {
        // Allowlist with only PersonName builds the dictionary detector.
        let scanner = Scanner::builder()
            .pii_kinds([PiiKind::PersonName])
            .build()
            .unwrap();
        assert!(scanner.has_piis("Jan Kowalski"));
        assert!(
            scanner
                .mark_piis("Jan Kowalski")
                .iter()
                .any(|m| m.kind == PiiKind::PersonName)
        );
    }

    #[test]
    fn person_name_absent_when_excluded() {
        // Blocklisting PersonName means the detector is never constructed and
        // the FST is never loaded; no PERSON_NAME match can fire.
        let scanner = Scanner::builder()
            .exclude_pii_kinds([PiiKind::PersonName])
            .build()
            .unwrap();
        assert!(
            scanner
                .mark_piis("Jan Kowalski")
                .iter()
                .all(|m| m.kind != PiiKind::PersonName)
        );
    }

    // --- PII in Matomo tracking requests ---

    // uid param often carries an email or other user identifier
    #[test_case(
        "/matomo.php?idsite=1&rec=1&uid=user@example.com&action_name=Home",
        PiiKind::Email, "user@example.com"
        ; "matomo uid email"
    )]
    // PII leaked inside the tracked page URL
    #[test_case(
        "/matomo.php?idsite=1&rec=1&url=https://app.example.com/profile/user@example.com",
        PiiKind::Email, "user@example.com"
        ; "matomo url param contains email"
    )]
    #[test_case(
        "/matomo.php?idsite=1&rec=1&url=https://app.example.com/search?phone_number=555-123-4567",
        PiiKind::UsPhoneNumber, "555-123-4567"
        ; "matomo url param contains phone"
    )]
    // PII in referrer URL
    #[test_case(
        "/matomo.php?idsite=1&rec=1&urlref=https://site.com/account/user@example.com&action_name=Dashboard",
        PiiKind::Email, "user@example.com"
        ; "matomo urlref contains email"
    )]
    // Site search keyword containing PII
    #[test_case(
        "/matomo.php?idsite=1&rec=1&search=user@example.com",
        PiiKind::Email, "user@example.com"
        ; "matomo search keyword is email"
    )]
    #[test_case(
        "/matomo.php?idsite=1&rec=1&search=123-45-6789",
        PiiKind::UsSsn, "123-45-6789"
        ; "matomo search keyword is ssn"
    )]
    // Custom variable JSON containing PII
    #[test_case(
        r#"/matomo.php?idsite=1&rec=1&_cvar={"1":["email","user@example.com"]}"#,
        PiiKind::Email, "user@example.com"
        ; "matomo cvar contains email"
    )]
    #[test_case(
        r#"/matomo.php?idsite=1&rec=1&_cvar={"1":["phone_number","555-123-4567"]}"#,
        PiiKind::UsPhoneNumber, "555-123-4567"
        ; "matomo cvar contains phone"
    )]
    // Custom dimensions carrying PII
    #[test_case(
        "/matomo.php?idsite=1&rec=1&dimension1=user@example.com&dimension2=premium",
        PiiKind::Email, "user@example.com"
        ; "matomo custom dimension email"
    )]
    // PII in action_name (page title)
    #[test_case(
        "/matomo.php?idsite=1&rec=1&action_name=Profile%20of%20user@example.com",
        PiiKind::Email, "user@example.com"
        ; "matomo action name contains email"
    )]
    // Credit card in event value (e.g. mis-instrumented payment tracking)
    #[test_case(
        "/matomo.php?idsite=1&rec=1&e_c=payment&e_a=submit&e_n=4111111111111111",
        PiiKind::CreditCard, "4111111111111111"
        ; "matomo event name is credit card"
    )]
    // IP address in custom variable
    #[test_case(
        "/matomo.php?idsite=1&rec=1&cip=192.168.1.1",
        PiiKind::IpAddress, "192.168.1.1"
        ; "matomo cip override ip"
    )]
    fn detects_pii_in_matomo(input: &str, kind: PiiKind, expected_span: &str) {
        let scanner = &*SCANNER;
        // Resolve overlaps to match how the proxy counts: a name value can fire
        // both the keyword-context rule (e.g. `first_name=`) and the dictionary
        // detector on the same span; resolve_overlaps dedupes them.
        let matches: Vec<_> = crate::resolve_overlaps(scanner.mark_piis(input))
            .into_iter()
            .filter(|m| m.kind == kind)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected 1 match for {kind:?} in: {input}"
        );
        assert_eq!(&input[matches[0].start..matches[0].end], expected_span);
    }

    #[test]
    fn matomo_multiple_pii_leaks() {
        let scanner = &*SCANNER;
        let input = "/matomo.php?idsite=1&rec=1&uid=user@example.com&url=https://app.example.com/lookup?ssn=123-45-6789&action_name=Profile";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(
            kinds.contains(&PiiKind::Email),
            "should detect email in uid"
        );
        assert!(
            kinds.contains(&PiiKind::UsSsn),
            "should detect ssn in url param"
        );
    }

    #[test]
    fn matomo_clean_request_no_false_positives() {
        let scanner = &*SCANNER;
        assert!(!scanner.has_piis(
            "/matomo.php?idsite=1&rec=1&action_name=Home&url=https://example.com/products&rand=123456"
        ));
    }

    // --- PII in Google Analytics tracking requests ---

    // UA (/collect) — uid carrying email
    #[test_case(
        "/collect?v=1&tid=UA-123456-1&cid=555&uid=user@example.com&t=pageview&dl=https://example.com/home",
        PiiKind::Email, "user@example.com"
        ; "ga ua uid email"
    )]
    // UA — PII leaked inside document location (dl)
    #[test_case(
        "/collect?v=1&tid=UA-123456-1&cid=555&t=pageview&dl=https://app.example.com/profile/user@example.com",
        PiiKind::Email, "user@example.com"
        ; "ga ua dl contains email"
    )]
    #[test_case(
        "/collect?v=1&tid=UA-123456-1&cid=555&t=pageview&dl=https://app.example.com/search?phone_number=555-123-4567",
        PiiKind::UsPhoneNumber, "555-123-4567"
        ; "ga ua dl contains phone"
    )]
    // UA — PII in document referrer (dr)
    #[test_case(
        "/collect?v=1&tid=UA-123456-1&cid=555&t=pageview&dr=https://site.com/account/user@example.com",
        PiiKind::Email, "user@example.com"
        ; "ga ua dr contains email"
    )]
    // UA — PII in document title (dt)
    #[test_case(
        "/collect?v=1&tid=UA-123456-1&cid=555&t=pageview&dt=Profile%20of%20user@example.com",
        PiiKind::Email, "user@example.com"
        ; "ga ua dt contains email"
    )]
    // UA — PII in custom dimensions (cd1, cd2, ...)
    #[test_case(
        "/collect?v=1&tid=UA-123456-1&cid=555&t=event&cd1=user@example.com&cd2=premium",
        PiiKind::Email, "user@example.com"
        ; "ga ua custom dimension email"
    )]
    // UA — PII in event label (el)
    #[test_case(
        "/collect?v=1&tid=UA-123456-1&cid=555&t=event&ec=form&ea=submit&el=4111111111111111",
        PiiKind::CreditCard, "4111111111111111"
        ; "ga ua event label credit card"
    )]
    // UA — SSN in event label
    #[test_case(
        "/collect?v=1&tid=UA-123456-1&cid=555&t=event&ec=lookup&ea=search&el=123-45-6789",
        PiiKind::UsSsn, "123-45-6789"
        ; "ga ua event label ssn"
    )]
    // GA4 (/g/collect) — uid carrying email
    #[test_case(
        "/g/collect?v=2&tid=G-ABC123&cid=555&uid=user@example.com&en=page_view",
        PiiKind::Email, "user@example.com"
        ; "ga4 uid email"
    )]
    // GA4 — PII in document location (dl)
    #[test_case(
        "/g/collect?v=2&tid=G-ABC123&cid=555&en=page_view&dl=https://app.example.com/users/user@example.com",
        PiiKind::Email, "user@example.com"
        ; "ga4 dl contains email"
    )]
    // GA4 — PII in event parameter (ep.xxx)
    #[test_case(
        "/g/collect?v=2&tid=G-ABC123&cid=555&en=login&ep.phone_number=555-123-4567",
        PiiKind::UsPhoneNumber, "555-123-4567"
        ; "ga4 event param phone"
    )]
    #[test_case(
        "/g/collect?v=2&tid=G-ABC123&cid=555&en=purchase&ep.last_name=Lopez",
        PiiKind::PersonName, "Lopez"
        ; "ga4 event param person name"
    )]
    // GA4 — PII in user property (up.xxx)
    #[test_case(
        "/g/collect?v=2&tid=G-ABC123&cid=555&en=page_view&up.first_name=Alberto",
        PiiKind::PersonName, "Alberto"
        ; "ga4 user property person name"
    )]
    // GA4 — PII in document referrer (dr)
    #[test_case(
        "/g/collect?v=2&tid=G-ABC123&cid=555&en=page_view&dr=https://site.com/verify?ssn=123-45-6789",
        PiiKind::UsSsn, "123-45-6789"
        ; "ga4 dr contains ssn"
    )]
    // GA4 — PII in document title (dt)
    #[test_case(
        "/g/collect?v=2&tid=G-ABC123&cid=555&en=page_view&dt=Order%20for%20user@example.com",
        PiiKind::Email, "user@example.com"
        ; "ga4 dt contains email"
    )]
    // GA4 — IP address in event parameter
    #[test_case(
        "/g/collect?v=2&tid=G-ABC123&cid=555&en=error&ep.client_ip=192.168.1.1",
        PiiKind::IpAddress, "192.168.1.1"
        ; "ga4 event param ip address"
    )]
    fn detects_pii_in_ga(input: &str, kind: PiiKind, expected_span: &str) {
        let scanner = &*SCANNER;
        // Resolve overlaps to match how the proxy counts: a name value can fire
        // both the keyword-context rule (e.g. `first_name=`) and the dictionary
        // detector on the same span; resolve_overlaps dedupes them.
        let matches: Vec<_> = crate::resolve_overlaps(scanner.mark_piis(input))
            .into_iter()
            .filter(|m| m.kind == kind)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected 1 match for {kind:?} in: {input}"
        );
        assert_eq!(&input[matches[0].start..matches[0].end], expected_span);
    }

    #[test]
    fn ga_multiple_pii_leaks() {
        let scanner = &*SCANNER;
        let input = "/collect?v=1&tid=UA-123456-1&cid=555&uid=user@example.com&t=event&ec=form&ea=submit&el=123-45-6789&cd1=4111111111111111";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(
            kinds.contains(&PiiKind::Email),
            "should detect email in uid"
        );
        assert!(
            kinds.contains(&PiiKind::UsSsn),
            "should detect ssn in event label"
        );
        assert!(
            kinds.contains(&PiiKind::CreditCard),
            "should detect credit card in cd1"
        );
    }

    #[test]
    fn ga_clean_request_no_false_positives() {
        let scanner = &*SCANNER;
        // UA clean hit
        assert!(!scanner.has_piis(
            "/collect?v=1&tid=UA-123456-1&cid=555&t=pageview&dl=https://example.com/products&dt=Products"
        ));
        // GA4 clean hit
        assert!(!scanner.has_piis(
            "/g/collect?v=2&tid=G-ABC123&cid=555&en=page_view&dl=https://example.com/about&dt=About%20Us"
        ));
    }

    // --- PII in Meta Conversions API (CAPI) requests ---
    //
    // Meta CAPI is a server-side event pipeline used by advertisers to send
    // conversions (Purchase, Lead, AddToCart, ...) to Meta's ads platform.
    // Payloads are POSTed as JSON to graph.facebook.com/v{ver}/{pixel}/events.
    // Meta *requires* customer identifiers (em, ph, fn, ln, db, ct, st, zp,
    // external_id) to be SHA256-hashed; `client_ip_address`, `client_user_agent`,
    // `fbc`, `fbp`, and `event_source_url` are passed as-is.
    //
    // In practice, raw PII regularly leaks through:
    //   1. Developers forget to apply SHA256 on a new field.
    //   2. GTM server-side variable mappings are typo'd and pass raw values.
    //   3. `event_source_url` is taken from the browser's current URL on a
    //      logged-in page that includes email/phone/id in the query string.
    //   4. `custom_data` free-form fields carry order notes, support transcripts,
    //      fraud signals, etc. with embedded PII.
    //   5. Shopify / WooCommerce plugins misroute cart attributes (card tokens,
    //      customer notes) into `content_ids`, `order_id`, `content_name`.
    //   6. Lead Ads CRM sync / offline conversion uploads forward raw customer
    //      records when the hashing step was never configured.

    // Unhashed raw email in the canonical `em` advanced-matching field —
    // classic "forgot to SHA256" leak.
    #[test_case(
        r#"{"data":[{"event_name":"Purchase","event_time":1712841600,"action_source":"website","user_data":{"em":["john.doe@example.com"],"client_user_agent":"Mozilla/5.0"},"custom_data":{"currency":"USD","value":49.99}}]}"#,
        PiiKind::Email, "john.doe@example.com"
        ; "capi unhashed email in em field"
    )]
    // Unhashed client IPv4 — always sent raw per Meta's spec, but still PII.
    #[test_case(
        r#"{"data":[{"event_name":"Lead","event_time":1712841600,"action_source":"website","user_data":{"client_ip_address":"203.0.113.45","fbp":"fb.1.1700000000.1234567890"}}]}"#,
        PiiKind::IpAddress, "203.0.113.45"
        ; "capi ipv4 in client_ip_address"
    )]
    // IPv6 client address (mobile networks commonly send v6).
    #[test_case(
        r#"{"data":[{"event_name":"AddToCart","event_time":1712841600,"user_data":{"client_ip_address":"2001:0db8:85a3:0000:0000:8a2e:0370:7334"}}]}"#,
        PiiKind::IpAddress, "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        ; "capi ipv6 in client_ip_address"
    )]
    // event_source_url captured from a logged-in account page where the
    // email is rendered into the query string (session-restore token flow).
    #[test_case(
        r#"{"data":[{"event_name":"ViewContent","event_time":1712841600,"event_source_url":"https://shop.example.com/account/orders?user=jane.smith@example.com&ref=email","user_data":{"fbp":"fb.1.1700000000.0987654321"}}]}"#,
        PiiKind::Email, "jane.smith@example.com"
        ; "capi email leaked via event_source_url query"
    )]
    // Support-callback landing page passes phone as a query param — ends up
    // in event_source_url verbatim.
    #[test_case(
        r#"{"data":[{"event_name":"Contact","event_time":1712841600,"event_source_url":"https://support.example.com/callback?phone_number=555-123-4567&topic=billing","user_data":{"client_ip_address":"198.51.100.12"}}]}"#,
        PiiKind::UsPhoneNumber, "555-123-4567"
        ; "capi phone leaked via event_source_url query"
    )]
    // Developer used SSN as `external_id` to deduplicate customers across
    // devices (real anti-pattern observed in healthcare / tax verticals).
    #[test_case(
        r#"{"data":[{"event_name":"CompleteRegistration","event_time":1712841600,"user_data":{"external_id":["123-45-6789"],"client_ip_address":"198.51.100.7"}}]}"#,
        PiiKind::UsSsn, "123-45-6789"
        ; "capi ssn in external_id"
    )]
    // Shopify-style misconfiguration: raw PAN passed as `order_id` because
    // the template pulled `{{ checkout.payment_method_token }}` incorrectly.
    #[test_case(
        r#"{"data":[{"event_name":"Purchase","event_time":1712841600,"custom_data":{"currency":"USD","value":142.00,"order_id":"4111111111111111","num_items":2}}]}"#,
        PiiKind::CreditCard, "4111111111111111"
        ; "capi credit card misused as order_id"
    )]
    // Subscription signup flow forwards bank details into `custom_data` as a
    // free-form note (SEPA mandate). IBAN is structural so it matches.
    #[test_case(
        r#"{"data":[{"event_name":"Subscribe","event_time":1712841600,"custom_data":{"predicted_ltv":240,"currency":"GBP","subscription_note":"bank GB29NWBK60161331926819 direct debit"}}]}"#,
        PiiKind::Iban, "GB29NWBK60161331926819"
        ; "capi iban in custom_data subscription note"
    )]
    // French IBAN arriving through a European Lead Ads integration.
    #[test_case(
        r#"{"data":[{"event_name":"Lead","event_time":1712841600,"custom_data":{"lead_event_source":"landing-fr","iban":"FR1420041010050500013M02606","currency":"EUR"}}]}"#,
        PiiKind::Iban, "FR1420041010050500013M02606"
        ; "capi fr iban in custom_data"
    )]
    // Advanced-matching expansion: some SDKs send `full_name` inside
    // custom_data instead of (or in addition to) hashed fn/ln.
    #[test_case(
        r#"{"data":[{"event_name":"Lead","event_time":1712841600,"custom_data":{"full_name":"Maria Rodriguez","lead_source":"landing_page","currency":"USD"}}]}"#,
        PiiKind::PersonName, "Maria Rodriguez"
        ; "capi person name in custom_data full_name"
    )]
    // CRM sync pushes descriptive advanced-matching keys alongside Meta's
    // `ln` field — the descriptive key trips the keyword detector.
    #[test_case(
        r#"{"data":[{"event_name":"CompleteRegistration","event_time":1712841600,"user_data":{"ln":["abc123hashedlastname"],"last_name":"O'Brien"}}]}"#,
        PiiKind::PersonName, "O'Brien"
        ; "capi last_name advanced matching leaked"
    )]
    // WooCommerce plugin shoves card number into content_ids for a
    // "product id" field (observed in support tickets).
    #[test_case(
        r#"{"data":[{"event_name":"Purchase","event_time":1712841600,"custom_data":{"content_type":"product","content_ids":["SKU-4532","5555555555554444"],"currency":"USD","value":75.50}}]}"#,
        PiiKind::CreditCard, "5555555555554444"
        ; "capi credit card in content_ids array"
    )]
    // Fraud-signal enrichment: the advertiser's own risk engine attached an
    // IP address as a custom field to aid manual review in Meta reporting.
    #[test_case(
        r#"{"data":[{"event_name":"Purchase","event_time":1712841600,"custom_data":{"currency":"USD","value":3200.00,"fraud_signal":"high","reported_ip":"198.51.100.23"}}]}"#,
        PiiKind::IpAddress, "198.51.100.23"
        ; "capi ipv4 in custom_data fraud signal"
    )]
    // US tax filing flow: the funnel landing page embeds the SSN in the URL
    // before the checkout event fires. event_source_url carries it verbatim.
    #[test_case(
        r#"{"data":[{"event_name":"InitiateCheckout","event_time":1712841600,"event_source_url":"https://taxapp.example.com/file?ssn=123-45-6789&tax_year=2025","user_data":{"client_ip_address":"192.0.2.88"}}]}"#,
        PiiKind::UsSsn, "123-45-6789"
        ; "capi ssn leaked via event_source_url query"
    )]
    // Customer service webhook relays the customer's phone as a descriptive
    // custom_data field — hits the keyword detector via "customer_phone".
    #[test_case(
        r#"{"data":[{"event_name":"Contact","event_time":1712841600,"custom_data":{"case_id":"CS-88412","channel":"callback","customer_phone":"555-867-5309"}}]}"#,
        PiiKind::UsPhoneNumber, "555-867-5309"
        ; "capi customer_phone in custom_data"
    )]
    // Meta batch endpoint: `data` is an array of events. The second event
    // contains an email in `em` — detector must scan the full payload.
    #[test_case(
        r#"{"data":[{"event_name":"PageView","event_time":1712841500,"user_data":{"fbp":"fb.1.1700000000.1234567890"}},{"event_name":"ViewContent","event_time":1712841600,"user_data":{"em":["alice.wonder@example.com"]}}]}"#,
        PiiKind::Email, "alice.wonder@example.com"
        ; "capi email in second event of batch"
    )]
    fn detects_pii_in_capi(input: &str, kind: PiiKind, expected_span: &str) {
        let scanner = &*SCANNER;
        // Resolve overlaps to match how the proxy counts: a name value can fire
        // both the keyword-context rule (e.g. `first_name=`) and the dictionary
        // detector on the same span; resolve_overlaps dedupes them.
        let matches: Vec<_> = crate::resolve_overlaps(scanner.mark_piis(input))
            .into_iter()
            .filter(|m| m.kind == kind)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected 1 match for {kind:?} in: {input}"
        );
        assert_eq!(&input[matches[0].start..matches[0].end], expected_span);
    }

    // Realistic batch-mode Purchase event with multiple simultaneous leaks:
    // a dev forgot to hash `em`, the standard `client_ip_address` field
    // carries the raw buyer IP, and the Shopify plugin misrouted a PAN into
    // `order_id`. All three must surface in a single scan.
    #[test]
    fn capi_purchase_multi_pii_leak() {
        let scanner = &*SCANNER;
        let input = r#"{"data":[{"event_name":"Purchase","event_time":1712841600,"action_source":"website","event_source_url":"https://shop.example.com/thank-you","user_data":{"em":["bob.buyer@example.com"],"client_ip_address":"203.0.113.99","client_user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)","fbp":"fb.1.1700000000.1122334455","fbc":"fb.1.1700000000.IwAR2abcdef"},"custom_data":{"currency":"USD","value":199.00,"order_id":"4242424242424242","num_items":3,"content_type":"product"}}]}"#;
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(
            kinds.contains(&PiiKind::Email),
            "should detect email in em field"
        );
        assert!(
            kinds.contains(&PiiKind::IpAddress),
            "should detect ip in client_ip_address"
        );
        assert!(
            kinds.contains(&PiiKind::CreditCard),
            "should detect card misused as order_id"
        );
    }

    // Sandbox `test_event_code` payload where a developer is iterating on a
    // new integration. `user_data` is populated with a full unhashed customer
    // profile and `event_source_url` carries the phone number from a
    // pre-filled callback form — the messy reality of staging traffic.
    #[test]
    fn capi_test_event_sandbox_raw_profile() {
        let scanner = &*SCANNER;
        let input = r#"{"data":[{"event_name":"Lead","event_time":1712841600,"action_source":"website","event_source_url":"https://leads.example.com/callback?phone_number=555-222-3344","user_data":{"em":["carla.tester@example.com"],"external_id":["123-45-6789"],"client_ip_address":"198.51.100.44","first_name":"Carla","last_name":"Tester"},"custom_data":{"lead_event_source":"landing","currency":"USD"}}],"test_event_code":"TEST12345"}"#;
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email), "expected email");
        assert!(kinds.contains(&PiiKind::UsSsn), "expected ssn");
        assert!(kinds.contains(&PiiKind::IpAddress), "expected ip");
        assert!(kinds.contains(&PiiKind::UsPhoneNumber), "expected phone");
        assert!(kinds.contains(&PiiKind::PersonName), "expected person name");
    }

    // Properly-implemented CAPI request: all customer identifiers are
    // SHA256-hashed (64-char lowercase hex). Meta-specific opaque IDs
    // (`fbp`, `fbc`, `event_id`) are passthrough. Must produce zero matches.
    #[test]
    fn capi_properly_hashed_no_false_positives() {
        let scanner = &*SCANNER;
        let input = r#"{"data":[{"event_name":"Purchase","event_time":1712841600,"event_id":"order-9af12b","action_source":"website","event_source_url":"https://shop.example.com/checkout/success","user_data":{"em":["973dfe463ec85785f5f95af5ba3906eedb2d931c24e69824a89ea65dba4e813b"],"ph":["c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646"],"fn":["ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"],"ln":["3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"],"fbp":"fb.1.1700000000.AbCdEfGhIj","fbc":"fb.1.1700000000.IwAR2XyZaBcDeFg"},"custom_data":{"currency":"USD","value":49.99,"content_type":"product","num_items":1}}]}"#;
        assert!(
            !scanner.has_piis(input),
            "properly-hashed CAPI payload should not trigger any detector"
        );
    }

    // --- Student essay PII detection tests ---
    //
    // Inspired by the Kaggle "PII Data Detection" competition
    // (pii-detection-removal-from-educational-data). The competition dataset
    // contains ~22,000 student essays about design thinking where students
    // accidentally include personal information. These tests simulate that
    // scenario with multi-sentence prose containing embedded PII.

    #[test]
    fn essay_email_in_prose() {
        let scanner = &*SCANNER;
        let input = "For this assignment I interviewed my colleague at the design firm. \
                     If you have questions about my submission, please reach out to me at \
                     jessica.martinez@university.edu and I will respond within 24 hours.";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        let email_match = matches.iter().find(|m| m.kind == PiiKind::Email).unwrap();
        assert_eq!(
            &input[email_match.start..email_match.end],
            "jessica.martinez@university.edu"
        );
    }

    #[test]
    fn essay_phone_in_prose() {
        let scanner = &*SCANNER;
        let input = "During the empathize phase, I conducted interviews with three users. \
                     One participant asked me to follow up later. My phone number is \
                     555-867-5309 so they could text me their additional feedback.";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::UsPhoneNumber));
    }

    #[test]
    fn essay_name_in_prose() {
        let scanner = &*SCANNER;
        let input = "I chose to apply design thinking to the onboarding process at my \
                     workplace. My last name is Rodriguez and I have been working in UX design \
                     for the past five years.";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(
            kinds.contains(&PiiKind::PersonName),
            "should detect person name in essay, found: {kinds:?}"
        );
    }

    #[test]
    fn essay_multiple_pii_types() {
        let scanner = &*SCANNER;
        let input = "Reflection on Design Thinking Application\n\n\
                     My last name is Thompson and I am a graduate student in the HCI program. \
                     For the ideation phase, I organized a brainstorming session with \
                     five stakeholders from the product team. The prototype was tested \
                     with eight users over two weeks.\n\n\
                     If the instructor needs to reach me, my email is \
                     alex.thompson@studentmail.edu and my phone number is 555-234-5678. \
                     My student ID (SSN) is 234-56-7890.";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email), "should detect email");
        assert!(
            kinds.contains(&PiiKind::UsPhoneNumber),
            "should detect phone"
        );
        assert!(kinds.contains(&PiiKind::UsSsn), "should detect SSN");
        assert!(
            kinds.contains(&PiiKind::PersonName),
            "should detect person name"
        );
    }

    #[test]
    fn essay_credit_card_in_survey_response() {
        let scanner = &*SCANNER;
        let input = "During the user research phase, one participant accidentally \
                     typed their payment information into the survey form. The card \
                     number 4532015112830366 was immediately flagged by our system. \
                     This incident highlighted the need for input validation.";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::CreditCard));
    }

    #[test]
    fn essay_ssn_as_student_id() {
        let scanner = &*SCANNER;
        let input = "Please note my student identification number for grading: \
                     SSN 345-67-8901. I am submitting this assignment for the \
                     Human-Centered Design course, section 3.";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::UsSsn));
    }

    #[test]
    fn essay_clean_text_no_false_positives() {
        let scanner = &*SCANNER;
        let input = "Design Thinking is a methodology used by designers to solve complex \
                     problems and find desirable solutions for clients. It draws upon logic, \
                     imagination, intuition, and systemic reasoning to explore possibilities \
                     and create desired outcomes that benefit the end user. The five stages \
                     of design thinking are Empathize, Define, Ideate, Prototype, and Test. \
                     Each stage provides a structured approach to innovation that can be \
                     applied across many different fields and industries.";
        assert!(!scanner.has_piis(input));
    }

    #[test]
    fn essay_clean_with_numbers_no_false_positives() {
        let scanner = &*SCANNER;
        let input = "In the testing phase, we gathered feedback from 15 participants \
                     over a period of 3 weeks. The results showed a 42% improvement in \
                     task completion rate and a 28% reduction in average time on task. \
                     We conducted 5 rounds of iteration, each lasting approximately \
                     2-3 days, before arriving at the final prototype in version 4.1.";
        assert!(!scanner.has_piis(input));
    }

    #[test]
    fn essay_iban_in_reimbursement_note() {
        let scanner = &*SCANNER;
        let input = "For the prototype materials I purchased supplies out of pocket. \
                     Please reimburse me via bank transfer to \
                     GB29NWBK60161331926819. The total cost was 47.50 GBP for \
                     cardboard, markers, and adhesive tape.";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Iban));
    }

    #[test]
    fn essay_ip_address_in_technical_context() {
        let scanner = &*SCANNER;
        let input = "We deployed the prototype on our internal server at 10.0.42.15 \
                     and asked participants to test the interface remotely. The server \
                     logs showed 342 unique sessions during the two-week testing period.";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::IpAddress));
    }

    #[test]
    fn essay_has_piis_short_circuits_on_long_text() {
        let scanner = &*SCANNER;
        // Simulate a longer essay with PII near the beginning — has_piis should
        // short-circuit without scanning the entire text.
        let pii_paragraph = "Contact me at student@university.edu for questions.\n\n";
        let filler = "Design thinking is an iterative process. ".repeat(200);
        let input = format!("{pii_paragraph}{filler}");
        assert!(scanner.has_piis(&input));
    }

    #[test]
    fn essay_pii_at_end_of_long_text() {
        let scanner = &*SCANNER;
        let filler = "The empathize stage involves understanding the user's needs. ".repeat(200);
        let pii_paragraph = "\n\nSubmitted by: email contact@student.org, SSN 456-78-9012";
        let input = format!("{filler}{pii_paragraph}");
        let matches = scanner.mark_piis(&input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::UsSsn));
    }

    #[test]
    fn essay_mixed_pii_span_accuracy() {
        let scanner = &*SCANNER;
        let input = "Author: first name Chen, email wei.chen@designlab.io, \
                     date of birth 15/03/1995";
        let matches = scanner.mark_piis(input);

        // Verify email span is exact
        let email = matches.iter().find(|m| m.kind == PiiKind::Email).unwrap();
        assert_eq!(&input[email.start..email.end], "wei.chen@designlab.io");

        // Verify DOB detected
        let dob = matches.iter().find(|m| m.kind == PiiKind::DateOfBirth);
        assert!(dob.is_some(), "should detect date of birth");
    }

    // --- AI4Privacy-style PII detection tests ---
    //
    // Inspired by the ai4privacy/pii-masking-200k dataset (Hugging Face /
    // Kaggle). The dataset contains 209K synthetic multi-domain texts
    // (legal, business, healthcare, education) in English, French, German,
    // and Italian with 54 PII categories annotated at character offsets.
    // These tests use the dataset's text style and PII category mappings:
    //
    // AI4Privacy category     → PiiKind
    // ─────────────────────────────────────
    // EMAIL                   → Email
    // PHONENUMBER             → UsPhoneNumber
    // CREDITCARDNUMBER        → CreditCard
    // IBAN                    → Iban
    // BITCOINADDRESS          → BitcoinAddress
    // ETHEREUMADDRESS         → EthereumAddress
    // IPV4 / IPV6             → IpAddress
    // MAC                     → MacAddress
    // VEHICLEVIN              → Vin
    // DOB                     → DateOfBirth
    // NEARBYGPSCOORDINATE     → PreciseGeolocation
    // FIRSTNAME / LASTNAME    → PersonName
    // PHONEIMEI               → Imei

    // -- Single-PII-type detection in domain-specific prose --

    #[test]
    fn ai4p_email_in_hr_onboarding() {
        let scanner = &*SCANNER;
        let input = "Welcome to the team! Please complete your onboarding \
                     paperwork by Friday. If you have any questions, contact HR \
                     at patricia.nguyen@acmecorp.com for assistance with benefits \
                     enrollment and policy documents.";
        let matches = scanner.mark_piis(input);
        let email = matches.iter().find(|m| m.kind == PiiKind::Email).unwrap();
        assert_eq!(
            &input[email.start..email.end],
            "patricia.nguyen@acmecorp.com"
        );
    }

    #[test]
    fn ai4p_credit_card_in_billing_dispute() {
        let scanner = &*SCANNER;
        let input = "Re: Billing Dispute Case #4821\n\n\
                     We have reviewed the unauthorized charge on card \
                     4532015112830366. A provisional credit of $249.99 has been \
                     applied to your account while we investigate the merchant.";
        let matches = scanner.mark_piis(input);
        let cc = matches
            .iter()
            .find(|m| m.kind == PiiKind::CreditCard)
            .unwrap();
        assert_eq!(&input[cc.start..cc.end], "4532015112830366");
    }

    #[test]
    fn ai4p_iban_in_wire_transfer() {
        let scanner = &*SCANNER;
        let input = "Please initiate the wire transfer for invoice #INV-2024-0397. \
                     The beneficiary account is DE89370400440532013000. Ensure the \
                     reference field includes the invoice number for reconciliation.";
        let matches = scanner.mark_piis(input);
        let iban = matches.iter().find(|m| m.kind == PiiKind::Iban).unwrap();
        assert_eq!(&input[iban.start..iban.end], "DE89370400440532013000");
    }

    #[test]
    fn ai4p_bitcoin_in_security_alert() {
        let scanner = &*SCANNER;
        let input = "SECURITY ALERT: We have detected a potential breach. Ensure \
                     users' sensitive details including wallet \
                     34EUu2QzxVkmBLo4anvhitwWwV1ux6vDW are encrypted and rotate \
                     all API keys immediately.";
        let matches = scanner.mark_piis(input);
        let btc = matches
            .iter()
            .find(|m| m.kind == PiiKind::BitcoinAddress)
            .unwrap();
        assert_eq!(
            &input[btc.start..btc.end],
            "34EUu2QzxVkmBLo4anvhitwWwV1ux6vDW"
        );
    }

    #[test]
    fn ai4p_ethereum_in_compliance_report() {
        let scanner = &*SCANNER;
        let input = "Compliance Report - Q3 Crypto Transactions\n\n\
                     The following wallet address was flagged for review: \
                     0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe. Transaction \
                     volume exceeded the quarterly threshold by 340%.";
        let matches = scanner.mark_piis(input);
        let eth = matches
            .iter()
            .find(|m| m.kind == PiiKind::EthereumAddress)
            .unwrap();
        assert_eq!(
            &input[eth.start..eth.end],
            "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
        );
    }

    #[test]
    fn ai4p_ipv4_in_incident_report() {
        let scanner = &*SCANNER;
        let input = "Incident Report #IR-7832\n\n\
                     At 14:32 UTC, our IDS flagged anomalous traffic originating \
                     from 109.4.61.213. The source attempted 4,200 login requests \
                     against the authentication endpoint within 15 minutes.";
        let matches = scanner.mark_piis(input);
        let ip = matches
            .iter()
            .find(|m| m.kind == PiiKind::IpAddress)
            .unwrap();
        assert_eq!(&input[ip.start..ip.end], "109.4.61.213");
    }

    #[test]
    fn ai4p_mac_in_device_inventory() {
        let scanner = &*SCANNER;
        let input = "Device Inventory - Floor 3, Building A\n\n\
                     The workstation assigned to the new analyst has MAC address \
                     00:1B:44:11:3A:B7. Please register it in the DHCP reservation \
                     table before the employee's start date.";
        let matches = scanner.mark_piis(input);
        let mac = matches
            .iter()
            .find(|m| m.kind == PiiKind::MacAddress)
            .unwrap();
        assert_eq!(&input[mac.start..mac.end], "00:1B:44:11:3A:B7");
    }

    #[test]
    fn ai4p_vin_in_fleet_management() {
        let scanner = &*SCANNER;
        let input = "As per our records, the company vehicle with VIN \
                     1HGBH41JXMN109186 is due for scheduled maintenance. Please \
                     coordinate with the fleet manager to arrange service at the \
                     authorized dealership.";
        let matches = scanner.mark_piis(input);
        let vin = matches.iter().find(|m| m.kind == PiiKind::Vin).unwrap();
        assert_eq!(&input[vin.start..vin.end], "1HGBH41JXMN109186");
    }

    #[test]
    fn ai4p_phone_in_patient_intake() {
        let scanner = &*SCANNER;
        let input = "Patient Intake Form - Dental Clinic\n\n\
                     Emergency contact phone: 555-392-7184. Please ensure all \
                     contact information is current before the scheduled appointment.";
        let matches = scanner.mark_piis(input);
        let phone = matches
            .iter()
            .find(|m| m.kind == PiiKind::UsPhoneNumber)
            .unwrap();
        assert_eq!(&input[phone.start..phone.end], "555-392-7184");
    }

    #[test]
    fn ai4p_dob_in_enrollment() {
        let scanner = &*SCANNER;
        let input = "Enrollment Verification - Academic Year 2024\n\n\
                     The applicant's date of birth is 23/07/1998. Please verify \
                     the age requirement before processing the scholarship application.";
        let matches = scanner.mark_piis(input);
        let dob = matches
            .iter()
            .find(|m| m.kind == PiiKind::DateOfBirth)
            .unwrap();
        assert_eq!(&input[dob.start..dob.end], "23/07/1998");
    }

    #[test]
    fn ai4p_imei_in_device_report() {
        let scanner = &*SCANNER;
        let input = "A student's assessment was found on a device bearing \
                     IMEI: 35-209900-176148-1. The device has been secured and \
                     stored in the IT department's lost-and-found locker.";
        let matches = scanner.mark_piis(input);
        let imei = matches.iter().find(|m| m.kind == PiiKind::Imei).unwrap();
        assert_eq!(&input[imei.start..imei.end], "35-209900-176148-1");
    }

    #[test]
    fn ai4p_person_name_in_legal_notice() {
        let scanner = &*SCANNER;
        let input = "LEGAL NOTICE\n\n\
                     This document is addressed to the party identified as \
                     client name: Harrington. Case reference #LC-2024-5539. \
                     Please respond within 30 business days.";
        let matches = scanner.mark_piis(input);
        let name = matches
            .iter()
            .find(|m| m.kind == PiiKind::PersonName)
            .unwrap();
        assert_eq!(&input[name.start..name.end], "Harrington");
    }

    #[test]
    fn ai4p_geolocation_in_logistics() {
        let scanner = &*SCANNER;
        let input = "Delivery Route Optimization Report\n\n\
                     The new distribution hub coordinates: 40.7128, -74.0060. \
                     This location reduces average last-mile delivery time by 18% \
                     compared to the current warehouse.";
        let matches = scanner.mark_piis(input);
        let geo = matches
            .iter()
            .find(|m| m.kind == PiiKind::PreciseGeolocation)
            .unwrap();
        assert_eq!(&input[geo.start..geo.end], "40.7128, -74.0060");
    }

    // -- Multi-PII detection in a single text --

    #[test]
    fn ai4p_multi_pii_employee_record() {
        let scanner = &*SCANNER;
        let input = "Employee Record - Confidential\n\n\
                     Full name: Maria Santos-Rivera\n\
                     Email: maria.santos@globaltech.io\n\
                     Phone: 555-741-2938\n\
                     Date of birth: 12/04/1985\n\
                     SSN: 567-89-0123\n\n\
                     Department: Engineering | Start Date: 2024-01-15";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::PersonName), "name: {kinds:?}");
        assert!(kinds.contains(&PiiKind::Email), "email: {kinds:?}");
        assert!(kinds.contains(&PiiKind::UsPhoneNumber), "phone: {kinds:?}");
        assert!(kinds.contains(&PiiKind::DateOfBirth), "dob: {kinds:?}");
        assert!(kinds.contains(&PiiKind::UsSsn), "ssn: {kinds:?}");
    }

    #[test]
    fn ai4p_multi_pii_it_audit() {
        let scanner = &*SCANNER;
        let input = "IT Security Audit - Network Segment B\n\n\
                     Flagged device MAC: 00:1A:2B:3C:4D:5E connected from \
                     192.168.42.107 at 09:14 UTC. The device attempted to access \
                     the payment gateway containing card 4111111111111111. \
                     Email alert sent to admin@internal.corp.";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::MacAddress), "mac: {kinds:?}");
        assert!(kinds.contains(&PiiKind::IpAddress), "ip: {kinds:?}");
        assert!(kinds.contains(&PiiKind::CreditCard), "cc: {kinds:?}");
        assert!(kinds.contains(&PiiKind::Email), "email: {kinds:?}");
    }

    #[test]
    fn ai4p_multi_pii_crypto_investigation() {
        let scanner = &*SCANNER;
        let input = "Fraud Investigation Case #FI-9021\n\n\
                     Suspicious transfers detected between Bitcoin wallet \
                     1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf and Ethereum address \
                     0x1234567890abcdef1234567890abcdef12345678. Source IP \
                     traced to 203.0.113.42. Contact investigator at \
                     fraud.team@enforcement.gov for case coordination.";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::BitcoinAddress), "btc: {kinds:?}");
        assert!(kinds.contains(&PiiKind::EthereumAddress), "eth: {kinds:?}");
        assert!(kinds.contains(&PiiKind::IpAddress), "ip: {kinds:?}");
        assert!(kinds.contains(&PiiKind::Email), "email: {kinds:?}");
    }

    // -- French-language texts (AI4Privacy includes fr) --

    #[test]
    fn ai4p_fr_email_in_business_letter() {
        let scanner = &*SCANNER;
        let input = "Madame, Monsieur,\n\n\
                     Suite à notre entretien du 15 mars, veuillez trouver ci-joint \
                     les documents demandés. Pour toute question, vous pouvez me \
                     contacter à l'adresse sophie.lefebvre@entreprise.fr.\n\n\
                     Cordialement,\nSophie Lefebvre";
        let matches = scanner.mark_piis(input);
        let email = matches.iter().find(|m| m.kind == PiiKind::Email).unwrap();
        assert_eq!(
            &input[email.start..email.end],
            "sophie.lefebvre@entreprise.fr"
        );
    }

    #[test]
    fn ai4p_fr_iban_in_invoice() {
        let scanner = &*SCANNER;
        let input = "FACTURE N° 2024-0892\n\n\
                     Merci de procéder au règlement par virement bancaire sur le \
                     compte suivant : FR7630006000011234567890189. Le délai de \
                     paiement est de 30 jours à compter de la date de facturation.";
        let matches = scanner.mark_piis(input);
        let iban = matches.iter().find(|m| m.kind == PiiKind::Iban).unwrap();
        assert_eq!(&input[iban.start..iban.end], "FR7630006000011234567890189");
    }

    #[test]
    fn ai4p_fr_phone_in_contact_form() {
        let scanner = &*SCANNER;
        let input = "Formulaire de contact - Service clientèle\n\n\
                     Votre demande a été enregistrée sous le numéro #DC-4417. \
                     Un conseiller vous rappellera au numéro de téléphone: \
                     555-823-4190 dans les 48 heures ouvrables.";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::UsPhoneNumber));
    }

    // -- German-language texts (AI4Privacy includes de) --

    #[test]
    fn ai4p_de_email_in_job_application() {
        let scanner = &*SCANNER;
        let input = "Sehr geehrte Damen und Herren,\n\n\
                     hiermit bewerbe ich mich auf die ausgeschriebene Stelle als \
                     Softwareentwickler. Meine Unterlagen finden Sie im Anhang. \
                     Für Rückfragen erreichen Sie mich unter \
                     stefan.bauer@bewerbung.de.\n\n\
                     Mit freundlichen Grüßen";
        let matches = scanner.mark_piis(input);
        let email = matches.iter().find(|m| m.kind == PiiKind::Email).unwrap();
        assert_eq!(&input[email.start..email.end], "stefan.bauer@bewerbung.de");
    }

    #[test]
    fn ai4p_de_iban_in_contract() {
        let scanner = &*SCANNER;
        let input = "Mietvertrag - Paragraph 5: Zahlungsmodalitäten\n\n\
                     Die monatliche Miete in Höhe von 850,00 EUR ist bis zum \
                     3. Werktag auf das Konto DE89370400440532013000 zu überweisen. \
                     Der Verwendungszweck muss die Wohnungsnummer enthalten.";
        let matches = scanner.mark_piis(input);
        let iban = matches.iter().find(|m| m.kind == PiiKind::Iban).unwrap();
        assert_eq!(&input[iban.start..iban.end], "DE89370400440532013000");
    }

    // -- French-language: country-specific PII types --

    #[test]
    fn ai4p_fr_nir_in_social_security() {
        let scanner = &*SCANNER;
        let input = "Dossier d'inscription - Caisse d'Assurance Maladie\n\n\
                     Veuillez fournir votre numéro de sécurité sociale: \
                     2 85 01 75 108 042 47. Ce numéro est indispensable pour le \
                     traitement de votre dossier.";
        let matches = scanner.mark_piis(input);
        let nir = matches.iter().find(|m| m.kind == PiiKind::FrNir).unwrap();
        assert_eq!(&input[nir.start..nir.end], "2 85 01 75 108 042 47");
    }

    #[test]
    fn ai4p_fr_siret_in_commercial_register() {
        let scanner = &*SCANNER;
        let input = "Extrait Kbis - Registre du Commerce\n\n\
                     Dénomination sociale : Dupont Consulting SARL\n\
                     SIRET: 73282932000074\n\
                     Date d'immatriculation : 15/03/2018";
        let matches = scanner.mark_piis(input);
        let siret = matches.iter().find(|m| m.kind == PiiKind::FrSiret).unwrap();
        assert_eq!(&input[siret.start..siret.end], "73282932000074");
    }

    #[test]
    fn ai4p_fr_siren_in_invoice() {
        let scanner = &*SCANNER;
        let input = "FACTURE N° F-2024-1287\n\n\
                     Fournisseur : Atelier Graphique EURL\n\
                     SIREN: 732829320\n\
                     Montant HT : 3 450,00 EUR";
        let matches = scanner.mark_piis(input);
        let siren = matches.iter().find(|m| m.kind == PiiKind::FrSiren).unwrap();
        assert_eq!(&input[siren.start..siren.end], "732829320");
    }

    #[test]
    fn ai4p_fr_cni_in_identity_verification() {
        let scanner = &*SCANNER;
        let input = "Vérification d'identité - Procédure KYC\n\n\
                     Le client a présenté sa carte d'identité: 012345678901. \
                     La pièce est valide jusqu'au 23/09/2029.";
        let matches = scanner.mark_piis(input);
        let cni = matches.iter().find(|m| m.kind == PiiKind::FrCni).unwrap();
        assert_eq!(&input[cni.start..cni.end], "012345678901");
    }

    #[test]
    fn ai4p_fr_drivers_license_in_rental() {
        let scanner = &*SCANNER;
        let input = "Contrat de location de véhicule\n\n\
                     Le locataire a fourni son permis de conduire: 012345678901. \
                     Catégorie B, délivré le 10/06/2015 par la préfecture de Paris.";
        let matches = scanner.mark_piis(input);
        let dl = matches
            .iter()
            .find(|m| m.kind == PiiKind::FrDriversLicense)
            .unwrap();
        assert_eq!(&input[dl.start..dl.end], "012345678901");
    }

    #[test]
    fn ai4p_fr_phone_in_medical_record() {
        let scanner = &*SCANNER;
        let input = "Fiche patient - Cabinet du Dr. Martin\n\n\
                     Personne à contacter en cas d'urgence :\n\
                     Téléphone: 06 12 34 56 78\n\
                     Relation : conjoint(e)";
        let matches = scanner.mark_piis(input);
        let phone = matches
            .iter()
            .find(|m| m.kind == PiiKind::FrPhoneNumber)
            .unwrap();
        assert_eq!(&input[phone.start..phone.end], "06 12 34 56 78");
    }

    #[test]
    fn ai4p_fr_postal_code_in_delivery() {
        let scanner = &*SCANNER;
        let input = "Bon de livraison #BL-8842\n\n\
                     Adresse de livraison : 12 rue de la Paix\n\
                     Code postal: 75002\n\
                     Créneau : 14h-18h";
        let matches = scanner.mark_piis(input);
        let cp = matches
            .iter()
            .find(|m| m.kind == PiiKind::FrPostalCode)
            .unwrap();
        assert_eq!(&input[cp.start..cp.end], "75002");
    }

    #[test]
    fn ai4p_fr_nif_in_tax_notice() {
        let scanner = &*SCANNER;
        let input = "Avis d'imposition - Année fiscale 2023\n\n\
                     Votre numéro d'identification fiscale: 0123456789012. \
                     Ce numéro figure sur tous vos documents fiscaux.";
        let matches = scanner.mark_piis(input);
        let nif = matches.iter().find(|m| m.kind == PiiKind::FrNif).unwrap();
        assert_eq!(&input[nif.start..nif.end], "0123456789012");
    }

    #[test]
    fn ai4p_fr_passport_in_travel_agency() {
        let scanner = &*SCANNER;
        let input = "Réservation de vol - Agence Voyages du Monde\n\n\
                     Veuillez vérifier les informations du passager :\n\
                     Passeport français: 05AB12345\n\
                     Date d'expiration : 22/11/2028";
        let matches = scanner.mark_piis(input);
        let pp = matches
            .iter()
            .find(|m| m.kind == PiiKind::FrPassportNumber)
            .unwrap();
        assert_eq!(&input[pp.start..pp.end], "05AB12345");
    }

    #[test]
    fn ai4p_fr_dob_in_registration() {
        let scanner = &*SCANNER;
        let input = "Formulaire d'inscription - Association Sportive\n\n\
                     Catégorie d'âge déterminée par la date de naissance: \
                     14/07/2001. Les inscriptions sont ouvertes jusqu'au 30 septembre.";
        let matches = scanner.mark_piis(input);
        let dob = matches
            .iter()
            .find(|m| m.kind == PiiKind::DateOfBirth)
            .unwrap();
        assert_eq!(&input[dob.start..dob.end], "14/07/2001");
    }

    #[test]
    fn ai4p_fr_person_name_in_notary() {
        let scanner = &*SCANNER;
        let input = "Acte Notarié - Étude Me Renard\n\n\
                     Comparaît devant nous, notaire soussigné, le \
                     bénéficiaire: Lefèvre. Lequel déclare vouloir procéder à \
                     la vente de l'immeuble ci-après désigné.";
        let matches = scanner.mark_piis(input);
        let name = matches
            .iter()
            .find(|m| m.kind == PiiKind::PersonName)
            .unwrap();
        assert_eq!(&input[name.start..name.end], "Lefèvre");
    }

    #[test]
    fn ai4p_fr_geolocation_in_delivery_route() {
        let scanner = &*SCANNER;
        let input = "Optimisation de la tournée de livraison\n\n\
                     Le point de dépôt se situe aux coordonnées GPS: \
                     48.8566, 2.3522. Temps de trajet estimé : 25 minutes \
                     depuis l'entrepôt principal.";
        let matches = scanner.mark_piis(input);
        let geo = matches
            .iter()
            .find(|m| m.kind == PiiKind::PreciseGeolocation)
            .unwrap();
        assert_eq!(&input[geo.start..geo.end], "48.8566, 2.3522");
    }

    #[test]
    fn ai4p_fr_swift_in_bank_transfer() {
        let scanner = &*SCANNER;
        let input = "Ordre de virement international\n\n\
                     Banque bénéficiaire : Crédit Lyonnais\n\
                     Identifiant bancaire: CRLYFRPP\n\
                     Montant : 15 000,00 EUR";
        let matches = scanner.mark_piis(input);
        let swift = matches
            .iter()
            .find(|m| m.kind == PiiKind::SwiftBic)
            .unwrap();
        assert_eq!(&input[swift.start..swift.end], "CRLYFRPP");
    }

    #[test]
    fn ai4p_fr_multi_pii_employee_file() {
        let scanner = &*SCANNER;
        let input = "Dossier du personnel - Confidentiel\n\n\
                     Nom de famille: Moreau\n\
                     Numéro de sécurité sociale: 1 90 03 75 115 004 03\n\
                     Téléphone: 07 98 76 54 32\n\
                     Date de naissance: 15/03/1990\n\
                     Email: jean.moreau@entreprise.fr";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::PersonName), "name: {kinds:?}");
        assert!(kinds.contains(&PiiKind::FrNir), "nir: {kinds:?}");
        assert!(kinds.contains(&PiiKind::FrPhoneNumber), "phone: {kinds:?}");
        assert!(kinds.contains(&PiiKind::DateOfBirth), "dob: {kinds:?}");
        assert!(kinds.contains(&PiiKind::Email), "email: {kinds:?}");
    }

    #[test]
    fn ai4p_fr_clean_administrative_text() {
        let scanner = &*SCANNER;
        let input = "Arrêté municipal n° 2024-0145\n\n\
                     Le maire de la commune, vu le code général des collectivités \
                     territoriales, vu la délibération du conseil municipal en date \
                     du 12 février 2024, arrête que les travaux de voirie sur \
                     l'avenue principale seront effectués du 1er au 30 avril 2024. \
                     La circulation sera déviée par la rue du Commerce.";
        assert!(!scanner.has_piis(input));
    }

    // -- German-language: country-specific PII types --

    #[test]
    fn ai4p_de_steuer_id_in_tax_filing() {
        let scanner = &*SCANNER;
        let input = "Einkommensteuererklärung 2023\n\n\
                     Bitte geben Sie Ihre Steuer-ID: 65929970489 an. \
                     Diese Nummer finden Sie auf Ihrem Steuerbescheid.";
        let matches = scanner.mark_piis(input);
        let sid = matches
            .iter()
            .find(|m| m.kind == PiiKind::DeSteuerId)
            .unwrap();
        assert_eq!(&input[sid.start..sid.end], "65929970489");
    }

    #[test]
    fn ai4p_de_personalausweis_in_verification() {
        let scanner = &*SCANNER;
        let input = "Identitätsprüfung - Kontoeröffnung\n\n\
                     Der Antragsteller hat seinen Personalausweis: T220001293 \
                     vorgelegt. Gültigkeit wurde elektronisch bestätigt.";
        let matches = scanner.mark_piis(input);
        let pa = matches
            .iter()
            .find(|m| m.kind == PiiKind::DePersonalausweis)
            .unwrap();
        assert_eq!(&input[pa.start..pa.end], "T220001293");
    }

    #[test]
    fn ai4p_de_phone_in_appointment() {
        let scanner = &*SCANNER;
        let input = "Terminbestätigung - Zahnarztpraxis Dr. Weber\n\n\
                     Ihr nächster Termin ist am 15.04.2024 um 10:30 Uhr. \
                     Bei Verhinderung bitten wir um Absage unter \
                     Telefonnummer: 030 12345678.";
        let matches = scanner.mark_piis(input);
        let phone = matches
            .iter()
            .find(|m| m.kind == PiiKind::DePhoneNumber)
            .unwrap();
        assert_eq!(&input[phone.start..phone.end], "030 12345678");
    }

    #[test]
    fn ai4p_de_postal_code_in_address() {
        let scanner = &*SCANNER;
        let input = "Lieferadresse aktualisieren\n\n\
                     Bitte bestätigen Sie Ihre neue Postleitzahl: 10115. \
                     Die Zustellung erfolgt innerhalb von 3 Werktagen.";
        let matches = scanner.mark_piis(input);
        let plz = matches
            .iter()
            .find(|m| m.kind == PiiKind::DePostalCode)
            .unwrap();
        assert_eq!(&input[plz.start..plz.end], "10115");
    }

    #[test]
    fn ai4p_de_passport_in_travel() {
        let scanner = &*SCANNER;
        let input = "Reisebuchung - Bestätigung #RB-44821\n\n\
                     Bitte überprüfen Sie die Reisedokumente:\n\
                     Reisepass: 123456789\n\
                     Ablaufdatum: 15.08.2029";
        let matches = scanner.mark_piis(input);
        let pp = matches
            .iter()
            .find(|m| m.kind == PiiKind::PassportNumber)
            .unwrap();
        assert_eq!(&input[pp.start..pp.end], "123456789");
    }

    #[test]
    fn ai4p_de_dob_with_month_name() {
        let scanner = &*SCANNER;
        let input = "Anmeldeformular - Sprachkurs B2\n\n\
                     Zur Altersfeststellung benötigen wir Ihr \
                     Geburtsdatum: 23 März 1995. Die Kursgebühr beträgt 450 EUR.";
        let matches = scanner.mark_piis(input);
        let dob = matches
            .iter()
            .find(|m| m.kind == PiiKind::DateOfBirth)
            .unwrap();
        assert_eq!(&input[dob.start..dob.end], "23 März 1995");
    }

    #[test]
    fn ai4p_de_geolocation_in_logistics() {
        let scanner = &*SCANNER;
        let input = "Routenplanung - Außendienst\n\n\
                     Der nächste Kundenbesuch befindet sich am \
                     Standort: 52.5200, 13.4050. Geschätzte Anfahrtszeit: \
                     35 Minuten ab Hauptniederlassung.";
        let matches = scanner.mark_piis(input);
        let geo = matches
            .iter()
            .find(|m| m.kind == PiiKind::PreciseGeolocation)
            .unwrap();
        assert_eq!(&input[geo.start..geo.end], "52.5200, 13.4050");
    }

    #[test]
    fn ai4p_de_person_name_in_insurance() {
        let scanner = &*SCANNER;
        let input = "Versicherungspolice #VP-2024-8193\n\n\
                     Versicherter: Müller. Der Vertrag tritt zum 01.01.2025 \
                     in Kraft und hat eine Laufzeit von 12 Monaten.";
        let matches = scanner.mark_piis(input);
        let name = matches
            .iter()
            .find(|m| m.kind == PiiKind::PersonName)
            .unwrap();
        assert_eq!(&input[name.start..name.end], "Müller");
    }

    #[test]
    fn ai4p_de_swift_in_payment() {
        let scanner = &*SCANNER;
        let input = "Zahlungsanweisung - Internationale Überweisung\n\n\
                     Empfängerbank: Deutsche Bank AG\n\
                     BIC-Code: DEUTDEFF\n\
                     Betrag: 25.000,00 EUR";
        let matches = scanner.mark_piis(input);
        let swift = matches
            .iter()
            .find(|m| m.kind == PiiKind::SwiftBic)
            .unwrap();
        assert_eq!(&input[swift.start..swift.end], "DEUTDEFF");
    }

    #[test]
    fn ai4p_de_address_in_registration() {
        let scanner = &*SCANNER;
        let input = "Meldebestätigung - Einwohnermeldeamt\n\n\
                     Ihre neue Anschrift: Friedrichstraße 43, 10117 Berlin. \
                     Bitte bewahren Sie diese Bestätigung für Ihre Unterlagen auf.";
        let matches = scanner.mark_piis(input);
        let addr = matches
            .iter()
            .find(|m| m.kind == PiiKind::DeAtChAddress)
            .unwrap();
        assert_eq!(
            &input[addr.start..addr.end],
            "Friedrichstraße 43, 10117 Berlin"
        );
    }

    // -- Austria-specific PII types --

    #[test]
    fn ai4p_at_svnr_in_health_insurance() {
        let scanner = &*SCANNER;
        let input = "Bestätigung der Pflichtversicherung - ÖGK\n\n\
                     Ihre Sozialversicherungsnummer: 1237 010180. \
                     Bitte geben Sie diese Nummer bei jedem Arztbesuch an.";
        let matches = scanner.mark_piis(input);
        let svnr = matches.iter().find(|m| m.kind == PiiKind::AtSvnr).unwrap();
        assert_eq!(&input[svnr.start..svnr.end], "1237 010180");
    }

    #[test]
    fn ai4p_at_phone_in_restaurant() {
        let scanner = &*SCANNER;
        let input = "Reservierungsbestätigung - Gasthaus zum Goldenen Hirschen\n\n\
                     Ihre Reservierung für 4 Personen am 20.04.2024 um 19:00 Uhr \
                     ist bestätigt. Bei Änderungen erreichen Sie uns unter \
                     Telefonnummer: +43 1 5127839.";
        let matches = scanner.mark_piis(input);
        let phone = matches
            .iter()
            .find(|m| m.kind == PiiKind::AtPhoneNumber)
            .unwrap();
        assert_eq!(&input[phone.start..phone.end], "+43 1 5127839");
    }

    #[test]
    fn ai4p_at_postal_code_in_shipping() {
        let scanner = &*SCANNER;
        let input = "Versandbestätigung - Bestellung #AT-9921\n\n\
                     Ihr Paket wird an die folgende PLZ: 1010 zugestellt. \
                     Voraussichtliche Lieferung: 2 Werktage.";
        let matches = scanner.mark_piis(input);
        let plz = matches
            .iter()
            .find(|m| m.kind == PiiKind::AtPostalCode)
            .unwrap();
        assert_eq!(&input[plz.start..plz.end], "1010");
    }

    // -- Switzerland-specific PII types --

    #[test]
    fn ai4p_ch_ahv_in_pension() {
        let scanner = &*SCANNER;
        let input = "Vorsorgeausweis - Pensionskasse\n\n\
                     Ihre AHV-Nummer: 756.1234.5678.97. \
                     Der aktuelle Umwandlungssatz beträgt 6,8%.";
        let matches = scanner.mark_piis(input);
        let ahv = matches.iter().find(|m| m.kind == PiiKind::ChAhv).unwrap();
        assert_eq!(&input[ahv.start..ahv.end], "756.1234.5678.97");
    }

    #[test]
    fn ai4p_ch_phone_in_bank() {
        let scanner = &*SCANNER;
        let input = "Kontaktänderung - Kantonalbank\n\n\
                     Ihre neue Kontaktnummer: +41 44 123 45 67 wurde \
                     erfolgreich hinterlegt. Bei Fragen wenden Sie sich an \
                     Ihren Kundenberater.";
        let matches = scanner.mark_piis(input);
        let phone = matches
            .iter()
            .find(|m| m.kind == PiiKind::ChPhoneNumber)
            .unwrap();
        assert_eq!(&input[phone.start..phone.end], "+41 44 123 45 67");
    }

    #[test]
    fn ai4p_ch_postal_code_in_directory() {
        let scanner = &*SCANNER;
        let input = "Firmenverzeichnis - Kanton Zürich\n\n\
                     Der Hauptsitz befindet sich in der PLZ: 8001. \
                     Weitere Niederlassungen in Bern und Basel.";
        let matches = scanner.mark_piis(input);
        let plz = matches
            .iter()
            .find(|m| m.kind == PiiKind::ChPostalCode)
            .unwrap();
        assert_eq!(&input[plz.start..plz.end], "8001");
    }

    // -- German multi-PII --

    #[test]
    fn ai4p_de_multi_pii_patient_record() {
        let scanner = &*SCANNER;
        let input = "Patientenakte - Vertraulich\n\n\
                     Nachname: Schneider\n\
                     Geburtsdatum: 05.11.1978\n\
                     Steuer-ID: 65929970489\n\
                     Telefonnummer: 089 98765432\n\
                     Email: k.schneider@patient.de\n\
                     Anschrift: Marienplatz 1, 80331 München";
        let matches = scanner.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::PersonName), "name: {kinds:?}");
        assert!(kinds.contains(&PiiKind::DateOfBirth), "dob: {kinds:?}");
        assert!(kinds.contains(&PiiKind::DeSteuerId), "steuer-id: {kinds:?}");
        assert!(kinds.contains(&PiiKind::DePhoneNumber), "phone: {kinds:?}");
        assert!(kinds.contains(&PiiKind::Email), "email: {kinds:?}");
        assert!(
            kinds.contains(&PiiKind::DeAtChAddress),
            "address: {kinds:?}"
        );
    }

    // -- German/Austrian/Swiss clean texts --

    #[test]
    fn ai4p_de_clean_corporate_announcement() {
        let scanner = &*SCANNER;
        let input = "Unternehmensmitteilung\n\n\
                     Aufgrund der gestiegenen Nachfrage erweitern wir unsere \
                     Produktionskapazität um 30 Prozent. Die neue Fertigungslinie \
                     wird im dritten Quartal in Betrieb genommen. Alle Abteilungen \
                     werden rechtzeitig über die geänderten Schichtpläne informiert. \
                     Die Investitionssumme beträgt 2,5 Millionen Euro.";
        assert!(!scanner.has_piis(input));
    }

    // -- Clean texts: no false positives --

    #[test]
    fn ai4p_clean_business_memo() {
        let scanner = &*SCANNER;
        let input = "MEMORANDUM\n\n\
                     To: All Department Heads\n\
                     Re: Quarterly Budget Review\n\n\
                     Please submit your Q3 expenditure reports by end of business \
                     on Friday. The finance committee will review all submissions \
                     during the following week. Budget overruns exceeding 15% will \
                     require a written justification and director-level approval.";
        assert!(!scanner.has_piis(input));
    }

    #[test]
    fn ai4p_clean_legal_boilerplate() {
        let scanner = &*SCANNER;
        let input = "TERMS OF SERVICE\n\n\
                     By accessing this platform, you agree to comply with all \
                     applicable laws and regulations. The company reserves the \
                     right to modify these terms at any time. Users are responsible \
                     for maintaining the confidentiality of their credentials. \
                     Any unauthorized use may result in termination of access and \
                     legal action as permitted by applicable jurisdiction.";
        assert!(!scanner.has_piis(input));
    }

    #[test]
    fn ai4p_clean_technical_spec() {
        let scanner = &*SCANNER;
        let input = "System Requirements Specification v2.4\n\n\
                     The application shall support a minimum of 10,000 concurrent \
                     users with response times under 200 milliseconds at the 95th \
                     percentile. The database layer requires at least 64 GB of RAM \
                     and 500 GB of SSD storage. Failover must complete within 30 \
                     seconds with zero data loss.";
        assert!(!scanner.has_piis(input));
    }

    // -- Span accuracy on multi-PII texts --

    #[test]
    fn ai4p_span_accuracy_financial() {
        let scanner = &*SCANNER;
        let input = "Transfer details: IBAN GB29NWBK60161331926819, \
                     email recipient@bank.co.uk, card 4111111111111111";
        let matches = scanner.mark_piis(input);

        let iban = matches.iter().find(|m| m.kind == PiiKind::Iban).unwrap();
        assert_eq!(&input[iban.start..iban.end], "GB29NWBK60161331926819");

        let email = matches.iter().find(|m| m.kind == PiiKind::Email).unwrap();
        assert_eq!(&input[email.start..email.end], "recipient@bank.co.uk");

        let cc = matches
            .iter()
            .find(|m| m.kind == PiiKind::CreditCard)
            .unwrap();
        assert_eq!(&input[cc.start..cc.end], "4111111111111111");
    }

    #[test]
    fn ai4p_span_accuracy_network() {
        let scanner = &*SCANNER;
        let input = "Audit log: source 192.168.1.42, device MAC 00:1A:2B:3C:4D:5E, \
                     alert sent to soc@monitoring.net";
        let matches = scanner.mark_piis(input);

        let ip = matches
            .iter()
            .find(|m| m.kind == PiiKind::IpAddress)
            .unwrap();
        assert_eq!(&input[ip.start..ip.end], "192.168.1.42");

        let mac = matches
            .iter()
            .find(|m| m.kind == PiiKind::MacAddress)
            .unwrap();
        assert_eq!(&input[mac.start..mac.end], "00:1A:2B:3C:4D:5E");

        let email = matches.iter().find(|m| m.kind == PiiKind::Email).unwrap();
        assert_eq!(&input[email.start..email.end], "soc@monitoring.net");
    }

    // Compile-time assertion that Scanner is Send + Sync.
    #[test]
    fn scanner_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Scanner>();
    }

    // --- user-defined PII ---

    #[test]
    fn builder_user_piis_detects_and_reports_label() {
        let scanner = Scanner::builder()
            .user_piis([UserPiiDefinition {
                label: "EMPLOYEE_ID".into(),
                pattern: r"EMP-\d{6}".into(),
                keywords: Vec::new(),
                country: Country::International,
            }])
            .build()
            .unwrap();

        let input = "new hire EMP-123456 onboarded";
        assert!(scanner.has_piis(input));
        let matches = scanner.mark_piis(input);
        let custom: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::Custom)
            .collect();
        assert_eq!(custom.len(), 1);
        assert_eq!(custom[0].label(), "EMPLOYEE_ID");
        assert_eq!(&input[custom[0].start..custom[0].end], "EMP-123456");
    }

    #[test]
    fn builder_user_piis_country_filter_matches_scanner_countries() {
        let scanner = Scanner::builder()
            .countries([Country::Fr])
            .user_piis([UserPiiDefinition {
                label: "US_ONLY".into(),
                pattern: r"UID-\d{4}".into(),
                keywords: Vec::new(),
                country: Country::Us,
            }])
            .build()
            .unwrap();

        assert!(!scanner.has_piis("value UID-1234 here"));
    }

    #[test]
    fn builder_user_piis_coexists_with_builtin_matches() {
        let scanner = Scanner::builder()
            .user_piis([UserPiiDefinition {
                label: "INTERNAL".into(),
                pattern: r"INT-\d{5}".into(),
                keywords: Vec::new(),
                country: Country::International,
            }])
            .build()
            .unwrap();

        let input = "contact user@test.com re INT-12345";
        let matches = scanner.mark_piis(input);
        assert!(matches.iter().any(|m| m.kind == PiiKind::Email));
        assert!(
            matches
                .iter()
                .any(|m| m.kind == PiiKind::Custom && m.label() == "INTERNAL")
        );
    }

    #[test]
    fn builder_user_piis_invalid_regex_surfaces_error() {
        let err = Scanner::builder()
            .user_piis([UserPiiDefinition {
                label: "BAD".into(),
                pattern: "[unterminated".into(),
                keywords: Vec::new(),
                country: Country::International,
            }])
            .build()
            .err()
            .expect("invalid user regex should fail build");
        assert!(matches!(err, PiiError::RegexCompilation(_)));
    }
}
