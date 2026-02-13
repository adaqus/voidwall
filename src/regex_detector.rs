use std::collections::HashSet;

use regex::{Regex, RegexSet};

use crate::detector::Detector;
use crate::validators::*;
use crate::{PiiError, PiiKind, PiiMatch};

struct Pattern {
    kind: PiiKind,
    regex: Regex,
}

pub struct RegexDetector {
    set: RegexSet,
    patterns: Vec<Pattern>,
}

impl RegexDetector {
    pub fn new(enabled: &HashSet<PiiKind>) -> Result<Self, PiiError> {
        let all_patterns: Vec<(PiiKind, &str)> = vec![
            (
                PiiKind::Email,
                r"[\p{L}\p{N}._%+-]+@[\p{L}\p{N}.-]+\.[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?",
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

        let raw_patterns: Vec<(PiiKind, &str)> = all_patterns
            .into_iter()
            .filter(|(kind, _)| enabled.contains(kind))
            .collect();

        let set = RegexSet::new(raw_patterns.iter().map(|(_, pat)| pat))
            .map_err(PiiError::RegexCompilation)?;
        let patterns = raw_patterns
            .into_iter()
            .map(|(kind, pat)| {
                Ok(Pattern {
                    kind,
                    regex: Regex::new(pat).map_err(PiiError::RegexCompilation)?,
                })
            })
            .collect::<Result<Vec<_>, PiiError>>()?;

        Ok(Self { set, patterns })
    }

    #[cfg(test)]
    fn new_all() -> Result<Self, PiiError> {
        let enabled: HashSet<PiiKind> =
            crate::PiiKind::enabled_for_countries(&crate::Country::all().iter().copied().collect());
        Self::new(&enabled)
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

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    // --- Detection with span verification ---

    #[test_case("contact us at user@example.com for info", PiiKind::Email, "user@example.com" ; "email basic")]
    #[test_case("SSN: 123-45-6789", PiiKind::UsSsn, "123-45-6789" ; "ssn")]
    #[test_case("my ssn is 078-05-1120 ok", PiiKind::UsSsn, "078-05-1120" ; "ssn span")]
    #[test_case("NINO: AB 12 34 56 C", PiiKind::GbNino, "AB 12 34 56 C" ; "nino with spaces")]
    #[test_case("NINO: AB123456C", PiiKind::GbNino, "AB123456C" ; "nino no spaces")]
    #[test_case("nino: ab 12 34 56 c", PiiKind::GbNino, "ab 12 34 56 c" ; "nino lowercase")]
    #[test_case("IBAN: GB29 NWBK 6016 1331 9268 19", PiiKind::Iban, "GB29 NWBK 6016 1331 9268 19" ; "iban gb")]
    #[test_case("IBAN: DE89 3704 0044 0532 0130 00", PiiKind::Iban, "DE89 3704 0044 0532 0130 00" ; "iban de")]
    #[test_case("server at 192.168.1.1 is down", PiiKind::IpAddress, "192.168.1.1" ; "ipv4")]
    #[test_case("IP: 10.0.0.255 ok", PiiKind::IpAddress, "10.0.0.255" ; "ipv4 span")]
    #[test_case("ITIN: 912-70-1234", PiiKind::UsItin, "912-70-1234" ; "itin")]
    #[test_case("my ITIN is 900-94-5678 ok", PiiKind::UsItin, "900-94-5678" ; "itin span")]
    #[test_case("SIN: 130-692-544", PiiKind::CaSin, "130-692-544" ; "sin hyphens")]
    #[test_case("SIN: 130 692 544", PiiKind::CaSin, "130 692 544" ; "sin spaces")]
    #[test_case("PPSN: 1234567T", PiiKind::IePpsn, "1234567T" ; "ppsn 8char")]
    #[test_case("PPSN: 1234567TW", PiiKind::IePpsn, "1234567TW" ; "ppsn 9char")]
    #[test_case("MAC: 00:1A:2B:3C:4D:5E", PiiKind::MacAddress, "00:1A:2B:3C:4D:5E" ; "mac colon")]
    #[test_case("MAC: 00-1A-2B-3C-4D-5E", PiiKind::MacAddress, "00-1A-2B-3C-4D-5E" ; "mac hyphen")]
    #[test_case("MAC: 001A.2B3C.4D5E", PiiKind::MacAddress, "001A.2B3C.4D5E" ; "mac cisco dot")]
    #[test_case("MAC: aa:bb:cc:dd:ee:ff", PiiKind::MacAddress, "aa:bb:cc:dd:ee:ff" ; "mac lowercase")]
    #[test_case("DL: JONES901157A99Y1", PiiKind::GbDrivingLicence, "JONES901157A99Y1" ; "uk driving licence")]
    #[test_case("VIN: 1HGBH41JXMN109186", PiiKind::Vin, "1HGBH41JXMN109186" ; "vin")]
    #[test_case("vehicle 1HGBH41JXMN109186 registered", PiiKind::Vin, "1HGBH41JXMN109186" ; "vin span")]
    #[test_case("card: 4111 1111 1111 1111", PiiKind::CreditCard, "4111 1111 1111 1111" ; "credit card")]
    fn detects_pii(input: &str, kind: PiiKind, expected_span: &str) {
        let detector = RegexDetector::new_all().unwrap();
        let matches: Vec<_> = detector
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

    // --- IBAN no spaces (may have other matches too) ---

    #[test]
    fn detects_iban_no_spaces() {
        let detector = RegexDetector::new_all().unwrap();
        let matches = detector.mark_piis("IBAN: GB29NWBK60161331926819");
        let iban_matches: Vec<_> = matches.iter().filter(|m| m.kind == PiiKind::Iban).collect();
        assert_eq!(iban_matches.len(), 1);
    }

    // --- Rejection tests ---

    #[test_case("card: 4111 1111 1111 1112", PiiKind::CreditCard ; "invalid credit card luhn")]
    #[test_case("SSN: 000-45-6789", PiiKind::UsSsn ; "ssn area 000")]
    #[test_case("SSN: 666-45-6789", PiiKind::UsSsn ; "ssn area 666")]
    #[test_case("SSN: 900-45-6789", PiiKind::UsSsn ; "ssn area 900 range")]
    #[test_case("SSN: 123-00-6789", PiiKind::UsSsn ; "ssn group 00")]
    #[test_case("SSN: 123-45-0000", PiiKind::UsSsn ; "ssn serial 0000")]
    #[test_case("NINO: DA123456C", PiiKind::GbNino ; "nino invalid first letter d")]
    #[test_case("NINO: AO123456C", PiiKind::GbNino ; "nino invalid second letter o")]
    #[test_case("NINO: BG123456C", PiiKind::GbNino ; "nino invalid prefix bg")]
    #[test_case("NINO: ZZ123456C", PiiKind::GbNino ; "nino invalid prefix zz")]
    #[test_case("IBAN: GB00 NWBK 6016 1331 9268 19", PiiKind::Iban ; "iban invalid checksum")]
    #[test_case("addr: 999.999.999.999", PiiKind::IpAddress ; "ipv4 octet out of range")]
    #[test_case("addr: 192.168.1.256", PiiKind::IpAddress ; "ipv4 single octet over 255")]
    #[test_case("ITIN: 900-30-1234", PiiKind::UsItin ; "itin invalid group")]
    #[test_case("SIN: 123-456-789", PiiKind::CaSin ; "sin failing luhn")]
    #[test_case("PPSN: 1234567A", PiiKind::IePpsn ; "ppsn wrong check letter")]
    #[test_case("DL: JONES900057A99Y1", PiiKind::GbDrivingLicence ; "uk dl invalid month")]
    #[test_case("DL: JONES901007A99Y1", PiiKind::GbDrivingLicence ; "uk dl invalid day")]
    #[test_case("VIN: 1HGBH41IXMN10918O", PiiKind::Vin ; "vin invalid chars")]
    fn rejects_invalid_pii(input: &str, kind: PiiKind) {
        let detector = RegexDetector::new_all().unwrap();
        let matches = detector.mark_piis(input);
        assert!(
            matches.iter().all(|m| m.kind != kind),
            "should reject {kind:?} in: {input}"
        );
    }

    // --- Email variant tests ---

    #[test_case("reply to user+thread-id-42@example.com to continue the thread", "user+thread-id-42@example.com" ; "thread identifier")]
    #[test_case("send to user+tag1+tag2@domain.org", "user+tag1+tag2@domain.org" ; "multiple plus tags")]
    #[test_case("send to user+tag@domain.co.uk please", "user+tag@domain.co.uk" ; "plus tag")]
    #[test_case("first.middle.last@example.com", "first.middle.last@example.com" ; "dots in local part")]
    #[test_case("user%tag@example.com", "user%tag@example.com" ; "percent encoding chars")]
    #[test_case("admin@localhost.localdomain", "admin@localhost.localdomain" ; "localhost with tld")]
    #[test_case("user@mail.internal.example.com", "user@mail.internal.example.com" ; "subdomain")]
    #[test_case("user@example.technology", "user@example.technology" ; "long tld")]
    #[test_case("user@example.de", "user@example.de" ; "two letter tld")]
    #[test_case("użytkownik@example.com", "użytkownik@example.com" ; "utf8 local part")]
    #[test_case("user@münchen.de", "user@münchen.de" ; "utf8 domain")]
    #[test_case("太郎@example.jp", "太郎@example.jp" ; "japanese local part")]
    #[test_case("user@例え.jp", "user@例え.jp" ; "japanese domain")]
    #[test_case("メールは 太郎@東京.jp まで", "太郎@東京.jp" ; "fully japanese address")]
    #[test_case("написать пользователь@домен.рф", "пользователь@домен.рф" ; "cyrillic chars")]
    #[test_case("user@xn--mnchen-3ya.de", "user@xn--mnchen-3ya.de" ; "punycode domain")]
    #[test_case("info@example.xn--p1ai", "info@example.xn--p1ai" ; "punycode tld")]
    #[test_case("مستخدم@example.com", "مستخدم@example.com" ; "arabic local part")]
    #[test_case("写信给 user@example.com 谢谢", "user@example.com" ; "adjacent to utf8 text")]
    #[test_case("12345@example.com", "12345@example.com" ; "numeric local part")]
    #[test_case("user@my-company.co.uk", "user@my-company.co.uk" ; "hyphenated domain")]
    fn detects_email_variant(input: &str, expected_span: &str) {
        let detector = RegexDetector::new_all().unwrap();
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::Email)
            .collect();
        assert_eq!(matches.len(), 1, "expected 1 email in: {input}");
        assert_eq!(&input[matches[0].start..matches[0].end], expected_span);
    }

    #[test]
    fn does_not_detect_email_at_localhost() {
        let detector = RegexDetector::new_all().unwrap();
        let matches = detector.mark_piis("admin@localhost");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn detects_multiple_emails_in_text() {
        let detector = RegexDetector::new_all().unwrap();
        let matches =
            detector.mark_piis("contact alice@example.com or bob+list@domain.org for info");
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| m.kind == PiiKind::Email));
    }

    // --- IPv6 variant tests ---

    #[test_case("host: 2001:0db8:85a3:0000:0000:8a2e:0370:7334" ; "ipv6 full")]
    #[test_case("host: ::1" ; "ipv6 compressed")]
    #[test_case("host: fe80::1" ; "ipv6 with collapse")]
    fn detects_ipv6_variant(input: &str) {
        let detector = RegexDetector::new_all().unwrap();
        let ip_matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::IpAddress)
            .collect();
        assert_eq!(ip_matches.len(), 1);
    }

    // --- Misc standalone tests ---

    #[test]
    fn has_piis_short_circuits() {
        let detector = RegexDetector::new_all().unwrap();
        assert!(detector.has_piis("user@example.com"));
        assert!(!detector.has_piis("no pii here"));
    }

    #[test]
    fn no_false_positives_on_clean_text() {
        let detector = RegexDetector::new_all().unwrap();
        let matches = detector.mark_piis("The quick brown fox jumps over the lazy dog.");
        assert!(matches.is_empty());
    }

    #[test]
    fn itin_does_not_overlap_with_ssn() {
        let detector = RegexDetector::new_all().unwrap();
        let matches = detector.mark_piis("number: 912-70-1234");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UsSsn));
        assert!(matches.iter().any(|m| m.kind == PiiKind::UsItin));
    }

    // --- JSON input tests ---

    #[test_case(r#"{"user": {"email": "alice@example.com", "name": "Alice"}}"#, PiiKind::Email, "alice@example.com" ; "email in json")]
    #[test_case(r#"{"payment": {"card_number": "4111 1111 1111 1111", "expiry": "12/28"}}"#, PiiKind::CreditCard, "4111 1111 1111 1111" ; "credit card in json")]
    #[test_case(r#"{"employee": {"ssn": "123-45-6789", "name": "John"}}"#, PiiKind::UsSsn, "123-45-6789" ; "ssn in json")]
    #[test_case(r#"{"employee": {"nino": "AB123456C", "department": "HR"}}"#, PiiKind::GbNino, "AB123456C" ; "nino in json")]
    #[test_case(r#"{"bank": {"iban": "DE89370400440532013000", "currency": "EUR"}}"#, PiiKind::Iban, "DE89370400440532013000" ; "iban in json")]
    #[test_case(r#"{"server": {"ip": "192.168.1.100", "status": "up"}}"#, PiiKind::IpAddress, "192.168.1.100" ; "ipv4 in json")]
    #[test_case(r#"{"tax": {"itin": "912-70-1234", "year": 2025}}"#, PiiKind::UsItin, "912-70-1234" ; "itin in json")]
    #[test_case(r#"{"employee": {"sin": "130-692-544", "province": "ON"}}"#, PiiKind::CaSin, "130-692-544" ; "sin in json")]
    #[test_case(r#"{"citizen": {"ppsn": "1234567T", "county": "Dublin"}}"#, PiiKind::IePpsn, "1234567T" ; "ppsn in json")]
    #[test_case(r#"{"device": {"mac": "00:1A:2B:3C:4D:5E", "hostname": "ws01"}}"#, PiiKind::MacAddress, "00:1A:2B:3C:4D:5E" ; "mac in json")]
    #[test_case(r#"{"driver": {"licence": "JONES901157A99Y1", "category": "B"}}"#, PiiKind::GbDrivingLicence, "JONES901157A99Y1" ; "uk dl in json")]
    #[test_case(r#"{"vehicle": {"vin": "1HGBH41JXMN109186", "make": "Honda"}}"#, PiiKind::Vin, "1HGBH41JXMN109186" ; "vin in json")]
    fn detects_pii_in_json(input: &str, kind: PiiKind, expected_span: &str) {
        let detector = RegexDetector::new_all().unwrap();
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == kind)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], expected_span);
    }

    #[test]
    fn detects_multiple_pii_in_json() {
        let detector = RegexDetector::new_all().unwrap();
        let input = r#"{"user": {"email": "alice@example.com", "card": "4111 1111 1111 1111", "ssn": "123-45-6789"}}"#;
        let matches = detector.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::CreditCard));
        assert!(kinds.contains(&PiiKind::UsSsn));
    }

    #[test]
    fn detects_pii_in_json_array() {
        let detector = RegexDetector::new_all().unwrap();
        let input = r#"{"emails": ["alice@example.com", "bob@domain.org"], "active": true}"#;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::Email)
            .collect();
        assert_eq!(matches.len(), 2);
    }
}
