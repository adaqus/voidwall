use std::collections::HashSet;

use crate::detector::Detector;
use crate::hyperscan_detector::HyperscanDetector;
use crate::keyword_context_detector::KeywordContextDetector;
use crate::{Country, Language, PiiError, PiiKind, PiiMatch};

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
        PiiKind::PhoneNumber, "555-123-4567"
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
        PiiKind::PhoneNumber, "555-123-4567"
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
        PiiKind::PhoneNumber, "555-123-4567"
        ; "phone with encoded colon in url"
    )]
    #[test_case(
        "/data?passport%3A123456789",
        PiiKind::PassportNumber, "123456789"
        ; "passport with encoded colon in url"
    )]
    // URL path with keyword as path segment
    #[test_case(
        "/api/phone/555-123-4567/details",
        PiiKind::PhoneNumber, "555-123-4567"
        ; "phone as path segment with slash separator"
    )]
    #[test_case(
        "/api/passport/123456789",
        PiiKind::PassportNumber, "123456789"
        ; "passport as path segment with slash separator"
    )]
    fn detects_pii_in_url(input: &str, kind: PiiKind, expected_span: &str) {
        let scanner = &*SCANNER;
        let matches: Vec<_> = scanner
            .mark_piis(input)
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
        assert!(kinds.contains(&PiiKind::PhoneNumber), "should detect phone");
        assert!(kinds.contains(&PiiKind::UsSsn), "should detect ssn");
    }

    // Compile-time assertion that Scanner is Send + Sync.
    #[test]
    fn scanner_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Scanner>();
    }
}
