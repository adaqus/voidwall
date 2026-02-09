use regex::{Regex, RegexSet};

use crate::detector::Detector;
use crate::{PiiKind, PiiMatch};

struct KeywordPattern {
    kind: PiiKind,
    full_regex: Regex,
    validate: fn(&str) -> bool,
}

pub struct KeywordContextDetector {
    set: RegexSet,
    patterns: Vec<KeywordPattern>,
}

impl Default for KeywordContextDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl KeywordContextDetector {
    #[allow(clippy::type_complexity)]
    pub fn new() -> Self {
        let raw_patterns: Vec<(PiiKind, &str, fn(&str) -> bool)> = vec![
            (
                PiiKind::AustraliaTfn,
                r"(?i)(?:australian tax file number|australian tfn|aus tfn|ato tax file number|ato tfn|individual tax file number|tax file number|tax file no\.?|tax file num|tax file #|tax file ref(?:erence)?|tax file identifier|applicant tfn|employee tfn|client tfn|customer tfn|my tfn|your tfn|tfn number|tfn no\.?|tfn num|tfn)[\s:.#/\-]*?(\d{3}\s\d{3}\s\d{3})",
                tfn_check as fn(&str) -> bool,
            ),
            (
                PiiKind::NzIrdNumber,
                r"(?i)(?:inland revenue dep(?:artmen)?t|inland revenue number|inland revenue no\.?|new zealand ird|new zealand tax number|new zealand tax id|nz ird|nz tax number|nz tax id|ird number nz|ird number|ird no\.?|ird num|ird #|ird ref(?:erence)?|applicant ird|employee ird|client ird|customer ird|my ird|your ird|gst registration|gst number|gst no\.?|tax number nz|ird)[\s:.#/\-]*?(\d{2,3}-\d{3}-\d{3})",
                ird_check as fn(&str) -> bool,
            ),
            (
                PiiKind::NhsNumber,
                r"(?i)(?:national health service number|national health service no\.?|nhs patient number|nhs patient id|nhs patient no\.?|nhs record number|nhs registration|nhs identifier|nhs number|nhs no\.?|nhs num|nhs #|nhs id|nhs ref(?:erence)?|nhs record|health service number|health service no\.?|health index number|health id|patient number|patient no\.?|patient id|my nhs number|your nhs number|chi number|h&c number|hc number|nhs)[\s:.#/\-]*?(\d{3}\s\d{3}\s\d{4})",
                nhs_check as fn(&str) -> bool,
            ),
            (
                PiiKind::AuMedicare,
                r"(?i)(?:medicare card number|medicare card no\.?|medicare card|australian medicare|medicare enrol(?:l)?ment|medicare registration|medicare identifier|medicare number|medicare no\.?|medicare num|medicare #|medicare id|medicare ref(?:erence)?|medicare patient|aus medicare|au medicare|applicant medicare|employee medicare|client medicare|customer medicare|my medicare|your medicare|medicare|irn)[\s:.#/\-]*?(\d{4}\s\d{5}\s\d)",
                medicare_check as fn(&str) -> bool,
            ),
            (
                PiiKind::UsPassportNew,
                r"(?i)(?:united states passport|passport book number|passport book no\.?|passport card number|us passport number|us passport no\.?|american passport|travel document number|travel document no\.?|travel doc number|travel doc no\.?|passport number|passport no\.?|passport num|passport #|passport id|passport card|us passport|travel doc|applicant passport|my passport|your passport|document number|document no\.?|doc number|doc no\.?|passport)[\s:.#/\-]*?([AXYZaxyz]\d{8})",
                passport_new_check as fn(&str) -> bool,
            ),
            (
                PiiKind::SwiftBic,
                r"(?i)(?:bank identifier code|bank identifier|correspondent (?:bank )?swift|intermediary swift|intermediary bic|international bank code|beneficiary swift|beneficiary bic|swift/bic|swift bic|bic/swift|swift code|swift number|swift no\.?|swift #|swift address|swift id|bank swift|bank routing|bank bic|bic code|bic number|bic no\.?|bic #|bic id|routing code|clearing code|my swift|swift|bic)[\s:.#/\-]*?([A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?)\b",
                swift_bic_check as fn(&str) -> bool,
            ),
            (
                PiiKind::Ein,
                r"(?i)(?:employer identification number|employer identification no\.?|federal employer identification|employer id number|employer id no\.?|federal employer id|federal tax identification|tax identification number|federal id number|federal id no\.?|federal tax id|federal ein|tax id number|employer number|employer no\.?|business tax id|company tax id|company ein|irs employer id|applicant ein|ein number|ein no\.?|ein num|ein #|tax id|irs ein|our ein|my ein|fein|ein)[\s:.#/\-]*?(\d{2}-\d{7})",
                ein_check as fn(&str) -> bool,
            ),
            (
                PiiKind::Imei,
                r"(?i)(?:international mobile equipment identity|mobile equipment identity|equipment identity|device identifier|device id number|device serial|device imei|handset imei|serial imei|mobile imei|tablet imei|equipment id|phone imei|imei identifier|imei number|imei no\.?|imei num|imei #|imei code|imei id|your imei|my imei|meid|imei)[\s:.#/\-]*?(\d{2}-?\d{6}-?\d{6}-?\d)",
                imei_check as fn(&str) -> bool,
            ),
            (
                PiiKind::UkUtr,
                r"(?i)(?:unique taxpayer ref(?:erence)?|unique tax ref(?:erence)?|taxpayer ref(?:erence)?|tax ref(?:erence)?|hmrc ref(?:erence)?|hmrc utr|self assessment ref(?:erence)?|self assessment utr|self assessment number|self assessment no\.?|sa utr|sa ref(?:erence)?|sa number|sa no\.?|corporation tax ref(?:erence)?|corporation tax utr|ct utr|ct ref(?:erence)?|company utr|company tax ref(?:erence)?|partnership utr|partnership ref(?:erence)?|your utr|my utr|client utr|customer utr|applicant utr|utr number|utr no\.?|utr num|utr #|utr ref(?:erence)?|utr)[\s:.#/\-]*?(\d{10})\b",
                utr_check as fn(&str) -> bool,
            ),
            (
                PiiKind::UsAbaRouting,
                r"(?i)(?:aba routing number|aba routing no\.?|aba routing|aba number|aba no\.?|aba #|routing transit number|routing transit no\.?|routing number|routing no\.?|routing #|bank routing number|bank routing no\.?|bank routing|transit number|transit no\.?|transit #|aba rtn|rtn number|rtn no\.?|rtn #|fed routing|fedwire routing|ach routing|wire routing|wire transfer routing|my routing number|your routing number|bank rtn|routing code|aba|rtn)[\s:.#/\-]*?(\d{9})\b",
                aba_check as fn(&str) -> bool,
            ),
            (
                PiiKind::UkSortCode,
                r"(?i)(?:sort code|sort-code|sortcode|sort code number|sort code no\.?|sort code #|bank sort code|bank sort|branch sort code|branch sort|branch code|branch number|branch no\.?|branch #|bank code|bank number|bank no\.?|uk sort code|uk sort|bacs sort code|bacs code|my sort code|your sort code|account sort code|account sort)[\s:.#/\-]*?(\d{2}-\d{2}-\d{2})\b",
                sort_code_check as fn(&str) -> bool,
            ),
            (
                PiiKind::PreciseGeolocation,
                r"(?i)(?:gps coordinates|gps coordinate|gps coords|gps location|gps position|precise location|precise coordinates|exact location|exact coordinates|location coordinates|map coordinates|position coordinates|geo coordinates|geocoordinates|geo coords|geocoords|latitude/longitude|latitude longitude|lat/long|lat/lon|lat long|lat lon|latlong|latlon|lat lng|latlng|geolocation|geo-location|geo location|geo position|geoposition|map position|map location|current location|current coordinates|current position|device location|device coordinates|device position|my location|my coordinates|my position|coordinates|coordinate|coords)[\s:.#/\-]*?(-?\d{1,3}\.\d{4,},\s?-?\d{1,3}\.\d{4,})",
                geolocation_check as fn(&str) -> bool,
            ),
            (
                PiiKind::UsDriversLicense,
                r"(?i)(?:driver'?s?\s*licen[cs]e\s*(?:number|no\.?|num|#)?|driving\s*licen[cs]e\s*(?:number|no\.?|num|#)?|operator'?s?\s*licen[cs]e\s*(?:number|no\.?|num|#)?|state\s*identification\s*(?:number|no\.?|num|#)?|state\s*id\s*(?:number|no\.?|num|#)?|dmv\s*(?:number|no\.?|num|#)|dl\s*(?:number|no\.?|num|#)|my\s*(?:driver'?s?\s*licen[cs]e|dl)|your\s*(?:driver'?s?\s*licen[cs]e|dl)|applicant\s*(?:driver'?s?\s*licen[cs]e|dl)|licen[cs]e\s*(?:number|no\.?|num|#)|dl)[\s:.#/\-]*?([A-Za-z]{1,2}\d{3}(?:-\d{3,4}){1,3}|[A-Za-z]{1,2}\d{4,14})\b",
                us_dl_check as fn(&str) -> bool,
            ),
        ];

        let set_patterns: Vec<&str> = raw_patterns.iter().map(|(_, pat, _)| *pat).collect();
        let set = RegexSet::new(&set_patterns).unwrap();
        let patterns = raw_patterns
            .into_iter()
            .map(|(kind, pat, validate)| KeywordPattern {
                kind,
                full_regex: Regex::new(pat).unwrap(),
                validate,
            })
            .collect();

        Self { set, patterns }
    }
}

impl Detector for KeywordContextDetector {
    fn has_piis(&self, input: &str) -> bool {
        let matched_indices: Vec<usize> = self.set.matches(input).into_iter().collect();
        for &idx in &matched_indices {
            let pattern = &self.patterns[idx];
            for caps in pattern.full_regex.captures_iter(input) {
                if let Some(value_match) = caps.get(1)
                    && (pattern.validate)(value_match.as_str())
                {
                    return true;
                }
            }
        }
        false
    }

    fn mark_piis(&self, input: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();
        let matched_indices: Vec<usize> = self.set.matches(input).into_iter().collect();
        for &idx in &matched_indices {
            let pattern = &self.patterns[idx];
            for caps in pattern.full_regex.captures_iter(input) {
                if let Some(value_match) = caps.get(1)
                    && (pattern.validate)(value_match.as_str())
                {
                    matches.push(PiiMatch {
                        kind: pattern.kind,
                        start: value_match.start(),
                        end: value_match.end(),
                    });
                }
            }
        }
        matches
    }
}

fn tfn_check(s: &str) -> bool {
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

fn ird_check(s: &str) -> bool {
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

fn nhs_check(s: &str) -> bool {
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

fn medicare_check(s: &str) -> bool {
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

fn passport_new_check(s: &str) -> bool {
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

fn swift_bic_check(s: &str) -> bool {
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

fn ein_check(s: &str) -> bool {
    let prefix: u32 = match s[..2].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    VALID_EIN_PREFIXES.binary_search(&prefix).is_ok()
}

fn imei_check(s: &str) -> bool {
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

fn utr_check(s: &str) -> bool {
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

fn aba_check(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 9 {
        return false;
    }
    let sum = 3 * (digits[0] + digits[3] + digits[6])
        + 7 * (digits[1] + digits[4] + digits[7])
        + (digits[2] + digits[5] + digits[8]);
    sum % 10 == 0
}

fn geolocation_check(s: &str) -> bool {
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

fn us_dl_check(s: &str) -> bool {
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

fn sort_code_check(s: &str) -> bool {
    // Basic structural validation: 6 digits in NN-NN-NN format
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    digits.len() == 6
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Australia TFN =====

    #[test]
    fn detects_tfn_with_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("TFN: 123 456 782");
        let tfn: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::AustraliaTfn)
            .collect();
        assert_eq!(tfn.len(), 1);
    }

    #[test]
    fn tfn_span_covers_only_value() {
        let detector = KeywordContextDetector::new();
        let input = "TFN: 123 456 782";
        let matches = detector.mark_piis(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "123 456 782");
    }

    #[test]
    fn tfn_multiple_keyword_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("tax file number: 123 456 782"));
        assert!(detector.has_piis("australian tfn 123 456 782"));
        assert!(detector.has_piis("my tfn: 123 456 782"));
    }

    #[test]
    fn tfn_case_insensitive() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("TFN: 123 456 782"));
        assert!(detector.has_piis("tfn: 123 456 782"));
        assert!(detector.has_piis("Tfn: 123 456 782"));
    }

    #[test]
    fn tfn_rejects_bad_checksum() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("TFN: 123 456 789");
        assert!(matches.iter().all(|m| m.kind != PiiKind::AustraliaTfn));
    }

    #[test]
    fn tfn_no_detection_without_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("my number is 123 456 782");
        assert!(matches.iter().all(|m| m.kind != PiiKind::AustraliaTfn));
    }

    #[test]
    fn tfn_separator_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("TFN: 123 456 782"));
        assert!(detector.has_piis("TFN 123 456 782"));
        assert!(detector.has_piis("TFN:123 456 782"));
        assert!(detector.has_piis("TFN#123 456 782"));
    }

    // ===== NZ IRD Number =====

    #[test]
    fn detects_ird_with_keyword() {
        let detector = KeywordContextDetector::new();
        // 49-091-857: valid IRD
        let matches = detector.mark_piis("IRD: 49-091-857");
        let ird: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::NzIrdNumber)
            .collect();
        assert_eq!(ird.len(), 1);
    }

    #[test]
    fn ird_span_covers_only_value() {
        let detector = KeywordContextDetector::new();
        let input = "IRD number: 49-091-857";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::NzIrdNumber)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "49-091-857");
    }

    #[test]
    fn ird_multiple_keyword_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("inland revenue number: 49-091-857"));
        assert!(detector.has_piis("nz ird 49-091-857"));
        assert!(detector.has_piis("gst number: 49-091-857"));
    }

    #[test]
    fn ird_case_insensitive() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("IRD: 49-091-857"));
        assert!(detector.has_piis("ird: 49-091-857"));
        assert!(detector.has_piis("Ird: 49-091-857"));
    }

    #[test]
    fn ird_rejects_out_of_range() {
        let detector = KeywordContextDetector::new();
        // 01-000-000 = 1,000,000 which is below 10,000,000
        let matches = detector.mark_piis("IRD: 01-000-000");
        assert!(matches.iter().all(|m| m.kind != PiiKind::NzIrdNumber));
    }

    #[test]
    fn ird_no_detection_without_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("number is 49-091-857");
        assert!(matches.iter().all(|m| m.kind != PiiKind::NzIrdNumber));
    }

    #[test]
    fn ird_separator_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("IRD: 49-091-857"));
        assert!(detector.has_piis("IRD 49-091-857"));
        assert!(detector.has_piis("IRD:49-091-857"));
        assert!(detector.has_piis("IRD#49-091-857"));
    }

    // ===== UK NHS Number =====

    #[test]
    fn detects_nhs_with_keyword() {
        let detector = KeywordContextDetector::new();
        // 943 476 5919: valid NHS number
        let matches = detector.mark_piis("NHS: 943 476 5919");
        let nhs: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::NhsNumber)
            .collect();
        assert_eq!(nhs.len(), 1);
    }

    #[test]
    fn nhs_span_covers_only_value() {
        let detector = KeywordContextDetector::new();
        let input = "NHS number: 943 476 5919";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::NhsNumber)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "943 476 5919");
    }

    #[test]
    fn nhs_multiple_keyword_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("national health service number: 943 476 5919"));
        assert!(detector.has_piis("patient number 943 476 5919"));
        assert!(detector.has_piis("my nhs number: 943 476 5919"));
    }

    #[test]
    fn nhs_case_insensitive() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("NHS: 943 476 5919"));
        assert!(detector.has_piis("nhs: 943 476 5919"));
        assert!(detector.has_piis("Nhs: 943 476 5919"));
    }

    #[test]
    fn nhs_rejects_bad_checksum() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("NHS: 943 476 5910");
        assert!(matches.iter().all(|m| m.kind != PiiKind::NhsNumber));
    }

    #[test]
    fn nhs_no_detection_without_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("number is 943 476 5919");
        assert!(matches.iter().all(|m| m.kind != PiiKind::NhsNumber));
    }

    #[test]
    fn nhs_separator_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("NHS: 943 476 5919"));
        assert!(detector.has_piis("NHS 943 476 5919"));
        assert!(detector.has_piis("NHS:943 476 5919"));
        assert!(detector.has_piis("NHS#943 476 5919"));
    }

    // ===== Australia Medicare =====

    #[test]
    fn detects_medicare_with_keyword() {
        let detector = KeywordContextDetector::new();
        // 2123 45670 1: first digit 2 (valid), weights check
        let matches = detector.mark_piis("Medicare: 2123 45670 1");
        let med: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::AuMedicare)
            .collect();
        assert_eq!(med.len(), 1);
    }

    #[test]
    fn medicare_span_covers_only_value() {
        let detector = KeywordContextDetector::new();
        let input = "Medicare number: 2123 45670 1";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::AuMedicare)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "2123 45670 1");
    }

    #[test]
    fn medicare_multiple_keyword_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("medicare card number: 2123 45670 1"));
        assert!(detector.has_piis("australian medicare 2123 45670 1"));
        assert!(detector.has_piis("my medicare: 2123 45670 1"));
    }

    #[test]
    fn medicare_case_insensitive() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("Medicare: 2123 45670 1"));
        assert!(detector.has_piis("medicare: 2123 45670 1"));
        assert!(detector.has_piis("MEDICARE: 2123 45670 1"));
    }

    #[test]
    fn medicare_rejects_invalid_first_digit() {
        let detector = KeywordContextDetector::new();
        // First digit 1 is invalid (must be 2-6)
        let matches = detector.mark_piis("Medicare: 1123 45670 1");
        assert!(matches.iter().all(|m| m.kind != PiiKind::AuMedicare));
    }

    #[test]
    fn medicare_no_detection_without_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("number is 2123 45670 1");
        assert!(matches.iter().all(|m| m.kind != PiiKind::AuMedicare));
    }

    #[test]
    fn medicare_separator_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("Medicare: 2123 45670 1"));
        assert!(detector.has_piis("Medicare 2123 45670 1"));
        assert!(detector.has_piis("Medicare:2123 45670 1"));
        assert!(detector.has_piis("Medicare#2123 45670 1"));
    }

    // ===== US Passport (New format) =====

    #[test]
    fn detects_us_passport_new_with_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("Passport: A12345678");
        let pp: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::UsPassportNew)
            .collect();
        assert_eq!(pp.len(), 1);
    }

    #[test]
    fn us_passport_new_span_covers_only_value() {
        let detector = KeywordContextDetector::new();
        let input = "Passport number: A12345678";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::UsPassportNew)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "A12345678");
    }

    #[test]
    fn us_passport_new_multiple_keyword_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("us passport number: X12345678"));
        assert!(detector.has_piis("travel document number Y12345678"));
        assert!(detector.has_piis("my passport: Z12345678"));
    }

    #[test]
    fn us_passport_new_case_insensitive() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("PASSPORT: A12345678"));
        assert!(detector.has_piis("passport: a12345678"));
        assert!(detector.has_piis("Passport: A12345678"));
    }

    #[test]
    fn us_passport_new_rejects_invalid_prefix() {
        let detector = KeywordContextDetector::new();
        // B is not a valid prefix (only A, X, Y, Z)
        let matches = detector.mark_piis("Passport: B12345678");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UsPassportNew));
    }

    #[test]
    fn us_passport_new_no_detection_without_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("code is A12345678");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UsPassportNew));
    }

    #[test]
    fn us_passport_new_separator_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("Passport: A12345678"));
        assert!(detector.has_piis("Passport A12345678"));
        assert!(detector.has_piis("Passport:A12345678"));
        assert!(detector.has_piis("Passport#A12345678"));
    }

    // ===== SWIFT/BIC =====

    #[test]
    fn detects_swift_bic_with_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("SWIFT: DEUTDEFF");
        let swift: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::SwiftBic)
            .collect();
        assert_eq!(swift.len(), 1);
    }

    #[test]
    fn swift_bic_span_covers_only_value() {
        let detector = KeywordContextDetector::new();
        let input = "SWIFT code: DEUTDEFF";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::SwiftBic)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "DEUTDEFF");
    }

    #[test]
    fn swift_bic_11_char() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("BIC: DEUTDEFFXXX");
        let swift: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::SwiftBic)
            .collect();
        assert_eq!(swift.len(), 1);
    }

    #[test]
    fn swift_bic_case_insensitive() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("SWIFT: DEUTDEFF"));
        assert!(detector.has_piis("swift: DEUTDEFF"));
        assert!(detector.has_piis("Swift: DEUTDEFF"));
    }

    #[test]
    fn swift_bic_rejects_invalid_country() {
        let detector = KeywordContextDetector::new();
        // "XX" is not a valid ISO country code
        let matches = detector.mark_piis("SWIFT: DEUTXXFF");
        assert!(matches.iter().all(|m| m.kind != PiiKind::SwiftBic));
    }

    #[test]
    fn swift_bic_no_detection_without_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("code is DEUTDEFF");
        assert!(matches.iter().all(|m| m.kind != PiiKind::SwiftBic));
    }

    #[test]
    fn swift_bic_separator_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("SWIFT: DEUTDEFF"));
        assert!(detector.has_piis("SWIFT DEUTDEFF"));
        assert!(detector.has_piis("SWIFT:DEUTDEFF"));
        assert!(detector.has_piis("SWIFT#DEUTDEFF"));
    }

    // ===== US EIN =====

    #[test]
    fn detects_ein_with_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("EIN: 12-3456789");
        let ein: Vec<_> = matches.iter().filter(|m| m.kind == PiiKind::Ein).collect();
        assert_eq!(ein.len(), 1);
    }

    #[test]
    fn ein_span_covers_only_value() {
        let detector = KeywordContextDetector::new();
        let input = "EIN number: 12-3456789";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::Ein)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "12-3456789");
    }

    #[test]
    fn ein_multiple_keyword_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("employer identification number: 12-3456789"));
        assert!(detector.has_piis("federal ein 12-3456789"));
        assert!(detector.has_piis("tax id number: 12-3456789"));
    }

    #[test]
    fn ein_case_insensitive() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("EIN: 12-3456789"));
        assert!(detector.has_piis("ein: 12-3456789"));
        assert!(detector.has_piis("Ein: 12-3456789"));
    }

    #[test]
    fn ein_rejects_invalid_prefix() {
        let detector = KeywordContextDetector::new();
        // 07 is not a valid EIN prefix
        let matches = detector.mark_piis("EIN: 07-3456789");
        assert!(matches.iter().all(|m| m.kind != PiiKind::Ein));
    }

    #[test]
    fn ein_no_detection_without_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("number is 12-3456789");
        assert!(matches.iter().all(|m| m.kind != PiiKind::Ein));
    }

    #[test]
    fn ein_separator_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("EIN: 12-3456789"));
        assert!(detector.has_piis("EIN 12-3456789"));
        assert!(detector.has_piis("EIN:12-3456789"));
        assert!(detector.has_piis("EIN#12-3456789"));
    }

    // ===== IMEI =====

    #[test]
    fn detects_imei_with_keyword() {
        let detector = KeywordContextDetector::new();
        // 490154203237518: valid Luhn
        let matches = detector.mark_piis("IMEI: 490154203237518");
        let imei: Vec<_> = matches.iter().filter(|m| m.kind == PiiKind::Imei).collect();
        assert_eq!(imei.len(), 1);
    }

    #[test]
    fn imei_span_covers_only_value() {
        let detector = KeywordContextDetector::new();
        let input = "IMEI number: 490154203237518";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::Imei)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "490154203237518");
    }

    #[test]
    fn imei_with_hyphens() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("IMEI: 49-015420-323751-8");
        let imei: Vec<_> = matches.iter().filter(|m| m.kind == PiiKind::Imei).collect();
        assert_eq!(imei.len(), 1);
    }

    #[test]
    fn imei_case_insensitive() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("IMEI: 490154203237518"));
        assert!(detector.has_piis("imei: 490154203237518"));
        assert!(detector.has_piis("Imei: 490154203237518"));
    }

    #[test]
    fn imei_rejects_bad_luhn() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("IMEI: 490154203237519");
        assert!(matches.iter().all(|m| m.kind != PiiKind::Imei));
    }

    #[test]
    fn imei_no_detection_without_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("number is 490154203237518");
        assert!(matches.iter().all(|m| m.kind != PiiKind::Imei));
    }

    #[test]
    fn imei_separator_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("IMEI: 490154203237518"));
        assert!(detector.has_piis("IMEI 490154203237518"));
        assert!(detector.has_piis("IMEI:490154203237518"));
        assert!(detector.has_piis("IMEI#490154203237518"));
    }

    // ===== UK UTR =====

    #[test]
    fn detects_utr_with_keyword() {
        let detector = KeywordContextDetector::new();
        // 5555555555: check digit 5, body 555555555, sum=270, 270%11=6, 11-6=5
        let matches = detector.mark_piis("UTR: 5555555555");
        let utr: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::UkUtr)
            .collect();
        assert_eq!(utr.len(), 1);
    }

    #[test]
    fn utr_span_covers_only_value() {
        let detector = KeywordContextDetector::new();
        let input = "UTR number: 5555555555";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::UkUtr)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "5555555555");
    }

    #[test]
    fn utr_multiple_keyword_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("unique taxpayer reference: 5555555555"));
        assert!(detector.has_piis("self assessment utr 5555555555"));
        assert!(detector.has_piis("hmrc utr: 5555555555"));
    }

    #[test]
    fn utr_case_insensitive() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("UTR: 5555555555"));
        assert!(detector.has_piis("utr: 5555555555"));
        assert!(detector.has_piis("Utr: 5555555555"));
    }

    #[test]
    fn utr_rejects_bad_checksum() {
        let detector = KeywordContextDetector::new();
        // Change first digit (check digit) to make it invalid
        let matches = detector.mark_piis("UTR: 1555555555");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UkUtr));
    }

    #[test]
    fn utr_no_detection_without_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("number is 5555555555");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UkUtr));
    }

    #[test]
    fn utr_separator_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("UTR: 5555555555"));
        assert!(detector.has_piis("UTR 5555555555"));
        assert!(detector.has_piis("UTR:5555555555"));
        assert!(detector.has_piis("UTR#5555555555"));
    }

    // ===== US ABA Routing =====

    #[test]
    fn detects_aba_with_keyword() {
        let detector = KeywordContextDetector::new();
        // 021000021: 3*(0+0+0)+7*(2+0+2)+(1+0+1)=0+28+2=30, 30%10=0
        let matches = detector.mark_piis("Routing number: 021000021");
        let aba: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::UsAbaRouting)
            .collect();
        assert_eq!(aba.len(), 1);
    }

    #[test]
    fn aba_span_covers_only_value() {
        let detector = KeywordContextDetector::new();
        let input = "ABA routing number: 021000021";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::UsAbaRouting)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "021000021");
    }

    #[test]
    fn aba_multiple_keyword_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("routing transit number: 021000021"));
        assert!(detector.has_piis("ach routing 021000021"));
        assert!(detector.has_piis("wire routing: 021000021"));
    }

    #[test]
    fn aba_case_insensitive() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("ROUTING NUMBER: 021000021"));
        assert!(detector.has_piis("routing number: 021000021"));
        assert!(detector.has_piis("Routing Number: 021000021"));
    }

    #[test]
    fn aba_rejects_bad_checksum() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("Routing number: 021000022");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UsAbaRouting));
    }

    #[test]
    fn aba_no_detection_without_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("number is 021000021");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UsAbaRouting));
    }

    #[test]
    fn aba_separator_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("Routing number: 021000021"));
        assert!(detector.has_piis("Routing number 021000021"));
        assert!(detector.has_piis("Routing number:021000021"));
        assert!(detector.has_piis("Routing number#021000021"));
    }

    // ===== UK Sort Code =====

    #[test]
    fn detects_sort_code_with_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("Sort code: 20-00-00");
        let sc: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::UkSortCode)
            .collect();
        assert_eq!(sc.len(), 1);
    }

    #[test]
    fn sort_code_span_covers_only_value() {
        let detector = KeywordContextDetector::new();
        let input = "Bank sort code: 20-00-00";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::UkSortCode)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "20-00-00");
    }

    #[test]
    fn sort_code_multiple_keyword_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("sort code: 20-00-00"));
        assert!(detector.has_piis("branch sort code 20-00-00"));
        assert!(detector.has_piis("bacs sort code: 20-00-00"));
    }

    #[test]
    fn sort_code_case_insensitive() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("SORT CODE: 20-00-00"));
        assert!(detector.has_piis("sort code: 20-00-00"));
        assert!(detector.has_piis("Sort Code: 20-00-00"));
    }

    #[test]
    fn sort_code_various_values() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("Sort code: 40-47-84"));
        assert!(detector.has_piis("Sort code: 30-90-53"));
    }

    #[test]
    fn sort_code_no_detection_without_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("date is 20-00-00");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UkSortCode));
    }

    #[test]
    fn sort_code_separator_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("Sort code: 20-00-00"));
        assert!(detector.has_piis("Sort code 20-00-00"));
        assert!(detector.has_piis("Sort code:20-00-00"));
        assert!(detector.has_piis("Sort code#20-00-00"));
    }

    // ===== Newline separator between keyword and value =====

    #[test]
    fn tfn_newline_separator() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("TFN:\n123 456 782"));
        assert!(detector.has_piis("Tax file number\n123 456 782"));
    }

    #[test]
    fn ird_newline_separator() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("IRD:\n49-091-857"));
        assert!(detector.has_piis("IRD number\n49-091-857"));
    }

    #[test]
    fn nhs_newline_separator() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("NHS:\n943 476 5919"));
        assert!(detector.has_piis("NHS number\n943 476 5919"));
    }

    #[test]
    fn medicare_newline_separator() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("Medicare:\n2123 45670 1"));
        assert!(detector.has_piis("Medicare number\n2123 45670 1"));
    }

    #[test]
    fn us_passport_new_newline_separator() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("Passport:\nA12345678"));
        assert!(detector.has_piis("Passport number\nA12345678"));
    }

    #[test]
    fn swift_bic_newline_separator() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("SWIFT:\nDEUTDEFF"));
        assert!(detector.has_piis("SWIFT code\nDEUTDEFF"));
    }

    #[test]
    fn ein_newline_separator() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("EIN:\n12-3456789"));
        assert!(detector.has_piis("EIN number\n12-3456789"));
    }

    #[test]
    fn imei_newline_separator() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("IMEI:\n490154203237518"));
        assert!(detector.has_piis("IMEI number\n490154203237518"));
    }

    #[test]
    fn utr_newline_separator() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("UTR:\n5555555555"));
        assert!(detector.has_piis("UTR number\n5555555555"));
    }

    #[test]
    fn aba_newline_separator() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("Routing number:\n021000021"));
        assert!(detector.has_piis("ABA routing\n021000021"));
    }

    #[test]
    fn sort_code_newline_separator() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("Sort code:\n20-00-00"));
        assert!(detector.has_piis("Bank sort code\n20-00-00"));
    }

    // ===== Precise Geolocation =====

    #[test]
    fn detects_geolocation_with_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("GPS coordinates: 40.7128,-74.0060");
        let geo: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::PreciseGeolocation)
            .collect();
        assert_eq!(geo.len(), 1);
    }

    #[test]
    fn geolocation_span_covers_only_value() {
        let detector = KeywordContextDetector::new();
        let input = "coordinates: 40.7128,-74.0060";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::PreciseGeolocation)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "40.7128,-74.0060");
    }

    #[test]
    fn geolocation_with_space_after_comma() {
        let detector = KeywordContextDetector::new();
        let input = "coordinates: 40.7128, -74.0060";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::PreciseGeolocation)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(
            &input[matches[0].start..matches[0].end],
            "40.7128, -74.0060"
        );
    }

    #[test]
    fn geolocation_multiple_keyword_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("lat/long: 40.7128,-74.0060"));
        assert!(detector.has_piis("geolocation 40.7128,-74.0060"));
        assert!(detector.has_piis("gps position: 40.7128,-74.0060"));
        assert!(detector.has_piis("precise location: 40.7128,-74.0060"));
    }

    #[test]
    fn geolocation_case_insensitive() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("GPS COORDINATES: 40.7128,-74.0060"));
        assert!(detector.has_piis("gps coordinates: 40.7128,-74.0060"));
        assert!(detector.has_piis("Gps Coordinates: 40.7128,-74.0060"));
    }

    #[test]
    fn geolocation_rejects_out_of_range_latitude() {
        let detector = KeywordContextDetector::new();
        // Latitude 91 is out of range
        let matches = detector.mark_piis("coordinates: 91.0000,-74.0060");
        assert!(
            matches
                .iter()
                .all(|m| m.kind != PiiKind::PreciseGeolocation)
        );
    }

    #[test]
    fn geolocation_rejects_out_of_range_longitude() {
        let detector = KeywordContextDetector::new();
        // Longitude 181 is out of range
        let matches = detector.mark_piis("coordinates: 40.7128,181.0060");
        assert!(
            matches
                .iter()
                .all(|m| m.kind != PiiKind::PreciseGeolocation)
        );
    }

    #[test]
    fn geolocation_rejects_insufficient_precision() {
        let detector = KeywordContextDetector::new();
        // Only 2 decimal places — not precise enough
        let matches = detector.mark_piis("coordinates: 40.71,-74.00");
        assert!(
            matches
                .iter()
                .all(|m| m.kind != PiiKind::PreciseGeolocation)
        );
    }

    #[test]
    fn geolocation_no_detection_without_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("values are 40.7128,-74.0060");
        assert!(
            matches
                .iter()
                .all(|m| m.kind != PiiKind::PreciseGeolocation)
        );
    }

    #[test]
    fn geolocation_separator_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("coordinates: 40.7128,-74.0060"));
        assert!(detector.has_piis("coordinates 40.7128,-74.0060"));
        assert!(detector.has_piis("coordinates:40.7128,-74.0060"));
        assert!(detector.has_piis("coordinates#40.7128,-74.0060"));
    }

    #[test]
    fn geolocation_negative_latitude() {
        let detector = KeywordContextDetector::new();
        // Sydney
        let input = "coordinates: -33.8688,151.2093";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::PreciseGeolocation)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(
            &input[matches[0].start..matches[0].end],
            "-33.8688,151.2093"
        );
    }

    #[test]
    fn geolocation_newline_separator() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("GPS coordinates:\n40.7128,-74.0060"));
        assert!(detector.has_piis("coordinates\n40.7128,-74.0060"));
    }

    // ===== US Driver's License =====

    #[test]
    fn detects_us_dl_with_keyword_1_letter_7_digits() {
        let detector = KeywordContextDetector::new();
        // California format: 1 letter + 7 digits
        let matches = detector.mark_piis("Driver's license: B1234568");
        let dl: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::UsDriversLicense)
            .collect();
        assert_eq!(dl.len(), 1);
    }

    #[test]
    fn detects_us_dl_1_letter_12_digits() {
        let detector = KeywordContextDetector::new();
        // Florida format: 1 letter + 12 digits
        let matches = detector.mark_piis("DL number: W123456789012");
        let dl: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::UsDriversLicense)
            .collect();
        assert_eq!(dl.len(), 1);
    }

    #[test]
    fn detects_us_dl_2_letters_6_digits() {
        let detector = KeywordContextDetector::new();
        // Ohio format: 2 letters + 6 digits
        let matches = detector.mark_piis("License number: AB123456");
        let dl: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::UsDriversLicense)
            .collect();
        assert_eq!(dl.len(), 1);
    }

    #[test]
    fn detects_us_dl_hyphenated_il_format() {
        let detector = KeywordContextDetector::new();
        // Illinois format: 1 letter + 3-4-4 hyphenated
        let matches = detector.mark_piis("Driver's license number: S530-4000-0001");
        let dl: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::UsDriversLicense)
            .collect();
        assert_eq!(dl.len(), 1);
    }

    #[test]
    fn detects_us_dl_hyphenated_mi_format() {
        let detector = KeywordContextDetector::new();
        // Michigan format: 1 letter + 3-3-3-3 hyphenated
        let matches = detector.mark_piis("DL: S123-456-789-012");
        let dl: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::UsDriversLicense)
            .collect();
        assert_eq!(dl.len(), 1);
    }

    #[test]
    fn us_dl_span_covers_only_value() {
        let detector = KeywordContextDetector::new();
        let input = "Driver's license: B1234568";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::UsDriversLicense)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "B1234568");
    }

    #[test]
    fn us_dl_multiple_keyword_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("driver's license number: B1234568"));
        assert!(detector.has_piis("driving licence: B1234568"));
        assert!(detector.has_piis("state id number: B1234568"));
        assert!(detector.has_piis("DL number: B1234568"));
        assert!(detector.has_piis("DMV number: B1234568"));
    }

    #[test]
    fn us_dl_case_insensitive() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("DRIVER'S LICENSE: B1234568"));
        assert!(detector.has_piis("driver's license: B1234568"));
        assert!(detector.has_piis("Driver's License: b1234568"));
    }

    #[test]
    fn us_dl_rejects_too_few_digits() {
        let detector = KeywordContextDetector::new();
        // 1 letter + 3 digits is too short
        let matches = detector.mark_piis("DL: B123");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UsDriversLicense));
    }

    #[test]
    fn us_dl_no_detection_without_keyword() {
        let detector = KeywordContextDetector::new();
        let matches = detector.mark_piis("code is B1234568");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UsDriversLicense));
    }

    #[test]
    fn us_dl_separator_variants() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("DL: B1234568"));
        assert!(detector.has_piis("DL B1234568"));
        assert!(detector.has_piis("DL:B1234568"));
        assert!(detector.has_piis("DL#B1234568"));
    }

    #[test]
    fn us_dl_newline_separator() {
        let detector = KeywordContextDetector::new();
        assert!(detector.has_piis("Driver's license:\nB1234568"));
        assert!(detector.has_piis("DL number\nB1234568"));
    }
}
