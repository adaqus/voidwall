use regex::{Regex, RegexSet};

use crate::detector::Detector;
use crate::{PiiError, PiiKind, PiiMatch};

struct KeywordPattern {
    kind: PiiKind,
    full_regex: Regex,
    validate: fn(&str) -> bool,
}

pub struct KeywordContextDetector {
    set: RegexSet,
    patterns: Vec<KeywordPattern>,
}

impl KeywordContextDetector {
    #[allow(clippy::type_complexity)]
    pub fn new() -> Result<Self, PiiError> {
        let raw_patterns: Vec<(PiiKind, &str, fn(&str) -> bool)> = vec![
            (
                PiiKind::AuTfn,
                r"(?i)(?:australian tax file number|australian tfn|aus tfn|ato tax file number|ato tfn|individual tax file number|tax file number|tax file no\.?|tax file num|tax file #|tax file ref(?:erence)?|tax file identifier|applicant tfn|employee tfn|client tfn|customer tfn|my tfn|your tfn|tfn number|tfn no\.?|tfn num|tfn)[\s:.#/\-\x22]*?(\d{3}\s\d{3}\s\d{3})",
                tfn_check,
            ),
            (
                PiiKind::NzIrdNumber,
                r"(?i)(?:inland revenue dep(?:artmen)?t|inland revenue number|inland revenue no\.?|new zealand ird|new zealand tax number|new zealand tax id|nz ird|nz tax number|nz tax id|ird number nz|ird number|ird no\.?|ird num|ird #|ird ref(?:erence)?|applicant ird|employee ird|client ird|customer ird|my ird|your ird|gst registration|gst number|gst no\.?|tax number nz|ird)[\s:.#/\-\x22]*?(\d{2,3}-\d{3}-\d{3})",
                ird_check,
            ),
            (
                PiiKind::GbNhsNumber,
                r"(?i)(?:national health service number|national health service no\.?|nhs patient number|nhs patient id|nhs patient no\.?|nhs record number|nhs registration|nhs identifier|nhs number|nhs no\.?|nhs num|nhs #|nhs id|nhs ref(?:erence)?|nhs record|health service number|health service no\.?|health index number|health id|patient number|patient no\.?|patient id|my nhs number|your nhs number|chi number|h&c number|hc number|nhs)[\s:.#/\-\x22]*?(\d{3}\s\d{3}\s\d{4})",
                nhs_check,
            ),
            (
                PiiKind::AuMedicare,
                r"(?i)(?:medicare card number|medicare card no\.?|medicare card|australian medicare|medicare enrol(?:l)?ment|medicare registration|medicare identifier|medicare number|medicare no\.?|medicare num|medicare #|medicare id|medicare ref(?:erence)?|medicare patient|aus medicare|au medicare|applicant medicare|employee medicare|client medicare|customer medicare|my medicare|your medicare|medicare|irn)[\s:.#/\-\x22]*?(\d{4}\s\d{5}\s\d)",
                medicare_check,
            ),
            (
                PiiKind::PhoneNumber,
                r"(?i)(?:phone number|phone no\.?|phone num|phone #|telephone number|telephone no\.?|telephone|mobile number|mobile no\.?|mobile phone|mobile|cell phone|cell number|cell|contact number|contact no\.?|contact phone|callback number|callback no\.?|callback|fax number|fax no\.?|fax|tel number|tel no\.?|tel|landline|home phone|work phone|office phone|alternate phone|alt phone|my phone|your phone|customer phone|applicant phone|phone)[\s:.#/\-\x22]*?((?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})",
                phone_check,
            ),
            (
                PiiKind::PassportNumber,
                r"(?i)(?:united states passport|passport book number|passport book no\.?|passport card number|us passport number|us passport no\.?|american passport|travel document number|travel document no\.?|travel doc number|travel doc no\.?|passport number|passport no\.?|passport num|passport #|passport id|passport card|us passport|travel doc|applicant passport|my passport|your passport|document number|document no\.?|doc number|doc no\.?|passport)[\s:.#/\-\x22]*?(\d{9})\b",
                passport_check,
            ),
            (
                PiiKind::UsPassportNew,
                r"(?i)(?:united states passport|passport book number|passport book no\.?|passport card number|us passport number|us passport no\.?|american passport|travel document number|travel document no\.?|travel doc number|travel doc no\.?|passport number|passport no\.?|passport num|passport #|passport id|passport card|us passport|travel doc|applicant passport|my passport|your passport|document number|document no\.?|doc number|doc no\.?|passport)[\s:.#/\-\x22]*?([AXYZaxyz]\d{8})",
                passport_new_check,
            ),
            (
                PiiKind::SwiftBic,
                r"(?i)(?:bank identifier code|bank identifier|correspondent (?:bank )?swift|intermediary swift|intermediary bic|international bank code|beneficiary swift|beneficiary bic|swift/bic|swift bic|bic/swift|swift code|swift number|swift no\.?|swift #|swift address|swift id|bank swift|bank routing|bank bic|bic code|bic number|bic no\.?|bic #|bic id|routing code|clearing code|my swift|swift|bic)[\s:.#/\-\x22]*?([A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?)\b",
                swift_bic_check,
            ),
            (
                PiiKind::UsEin,
                r"(?i)(?:employer identification number|employer identification no\.?|federal employer identification|employer id number|employer id no\.?|federal employer id|federal tax identification|tax identification number|federal id number|federal id no\.?|federal tax id|federal ein|tax id number|employer number|employer no\.?|business tax id|company tax id|company ein|irs employer id|applicant ein|ein number|ein no\.?|ein num|ein #|tax id|irs ein|our ein|my ein|fein|ein)[\s:.#/\-\x22]*?(\d{2}-\d{7})",
                ein_check,
            ),
            (
                PiiKind::Imei,
                r"(?i)(?:international mobile equipment identity|mobile equipment identity|equipment identity|device identifier|device id number|device serial|device imei|handset imei|serial imei|mobile imei|tablet imei|equipment id|phone imei|imei identifier|imei number|imei no\.?|imei num|imei #|imei code|imei id|your imei|my imei|meid|imei)[\s:.#/\-\x22]*?(\d{2}-?\d{6}-?\d{6}-?\d)",
                imei_check,
            ),
            (
                PiiKind::GbUtr,
                r"(?i)(?:unique taxpayer ref(?:erence)?|unique tax ref(?:erence)?|taxpayer ref(?:erence)?|tax ref(?:erence)?|hmrc ref(?:erence)?|hmrc utr|self assessment ref(?:erence)?|self assessment utr|self assessment number|self assessment no\.?|sa utr|sa ref(?:erence)?|sa number|sa no\.?|corporation tax ref(?:erence)?|corporation tax utr|ct utr|ct ref(?:erence)?|company utr|company tax ref(?:erence)?|partnership utr|partnership ref(?:erence)?|your utr|my utr|client utr|customer utr|applicant utr|utr number|utr no\.?|utr num|utr #|utr ref(?:erence)?|utr)[\s:.#/\-\x22]*?(\d{10})\b",
                utr_check,
            ),
            (
                PiiKind::UsAbaRouting,
                r"(?i)(?:aba routing number|aba routing no\.?|aba routing|aba number|aba no\.?|aba #|routing transit number|routing transit no\.?|routing number|routing no\.?|routing #|bank routing number|bank routing no\.?|bank routing|transit number|transit no\.?|transit #|aba rtn|rtn number|rtn no\.?|rtn #|fed routing|fedwire routing|ach routing|wire routing|wire transfer routing|my routing number|your routing number|bank rtn|routing code|aba|rtn)[\s:.#/\-\x22]*?(\d{9})\b",
                aba_check,
            ),
            (
                PiiKind::GbSortCode,
                r"(?i)(?:sort code|sort-code|sortcode|sort code number|sort code no\.?|sort code #|bank sort code|bank sort|branch sort code|branch sort|branch code|branch number|branch no\.?|branch #|bank code|bank number|bank no\.?|uk sort code|uk sort|bacs sort code|bacs code|my sort code|your sort code|account sort code|account sort)[\s:.#/\-\x22]*?(\d{2}-\d{2}-\d{2})\b",
                sort_code_check,
            ),
            (
                PiiKind::PreciseGeolocation,
                r"(?i)(?:gps coordinates|gps coordinate|gps coords|gps location|gps position|precise location|precise coordinates|exact location|exact coordinates|location coordinates|map coordinates|position coordinates|geo coordinates|geocoordinates|geo coords|geocoords|latitude/longitude|latitude longitude|lat/long|lat/lon|lat long|lat lon|latlong|latlon|lat lng|latlng|geolocation|geo-location|geo location|geo position|geoposition|map position|map location|current location|current coordinates|current position|device location|device coordinates|device position|my location|my coordinates|my position|coordinates|coordinate|coords)[\s:.#/\-\x22]*?(-?\d{1,3}\.\d{4,},\s?-?\d{1,3}\.\d{4,})",
                geolocation_check,
            ),
            (
                PiiKind::UsAlienNumber,
                r"(?i)(?:alien registration number|alien registration no\.?|alien registration|alien number|alien no\.?|alien #|a-number|uscis alien number|uscis alien no\.?|uscis number|uscis no\.?|uscis id|uscis #|green card number|green card no\.?|green card #|permanent resident number|permanent resident no\.?|immigration number|immigration no\.?|immigration id|dhs number|dhs no\.?|my a-number|your a-number|applicant a-number)[\s:.#/\-\x22]*?([Aa]\d{7,9})\b",
                a_number_check,
            ),
            (
                PiiKind::UsUscisReceiptNumber,
                r"(?i)(?:uscis receipt number|uscis receipt no\.?|uscis receipt|uscis case number|uscis case no\.?|uscis case|immigration case number|immigration case no\.?|immigration case|petition receipt number|petition receipt no\.?|petition receipt|application receipt number|application receipt no\.?|application receipt|i-797 receipt|i-797 number|i-797 no\.?|receipt number|receipt no\.?|receipt #|case number|case no\.?|case #|petition number|petition no\.?|petition #|my receipt number|your receipt number|beneficiary receipt|applicant receipt)[\s:.#/\-\x22]*?([A-Za-z]{3}\d{10})\b",
                uscis_receipt_check,
            ),
            (
                PiiKind::UsDriversLicense,
                r"(?i)(?:driver'?s?\s*licen[cs]e\s*(?:number|no\.?|num|#)?|driving\s*licen[cs]e\s*(?:number|no\.?|num|#)?|operator'?s?\s*licen[cs]e\s*(?:number|no\.?|num|#)?|state\s*identification\s*(?:number|no\.?|num|#)?|state\s*id\s*(?:number|no\.?|num|#)?|dmv\s*(?:number|no\.?|num|#)|dl\s*(?:number|no\.?|num|#)|my\s*(?:driver'?s?\s*licen[cs]e|dl)|your\s*(?:driver'?s?\s*licen[cs]e|dl)|applicant\s*(?:driver'?s?\s*licen[cs]e|dl)|licen[cs]e\s*(?:number|no\.?|num|#)|dl)[\s:.#/\-\x22]*?([A-Za-z]{1,2}\d{3}(?:-\d{3,4}){1,3}|[A-Za-z]{1,2}\d{4,14})\b",
                us_dl_check,
            ),
        ];

        let set_patterns: Vec<&str> = raw_patterns.iter().map(|(_, pat, _)| *pat).collect();
        let set = RegexSet::new(&set_patterns).map_err(PiiError::RegexCompilation)?;
        let patterns = raw_patterns
            .into_iter()
            .map(|(kind, pat, validate)| {
                Ok(KeywordPattern {
                    kind,
                    full_regex: Regex::new(pat).map_err(PiiError::RegexCompilation)?,
                    validate,
                })
            })
            .collect::<Result<Vec<_>, PiiError>>()?;

        Ok(Self { set, patterns })
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

fn phone_check(_s: &str) -> bool {
    true
}

fn passport_check(_s: &str) -> bool {
    true
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

fn a_number_check(s: &str) -> bool {
    let first = s.as_bytes()[0].to_ascii_uppercase();
    if first != b'A' {
        return false;
    }
    let digits = &s[1..];
    (7..=9).contains(&digits.len()) && digits.chars().all(|c| c.is_ascii_digit())
}

#[rustfmt::skip]
const USCIS_CENTER_CODES: &[&str] = &[
    "EAC", "IOE", "LIN", "MSC", "NBC", "SRC", "WAC", "YSC",
];

fn uscis_receipt_check(s: &str) -> bool {
    if s.len() != 13 {
        return false;
    }
    let prefix = s[..3].to_uppercase();
    USCIS_CENTER_CODES.binary_search(&prefix.as_str()).is_ok()
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
    use test_case::test_case;

    // --- Detection with span verification ---

    #[test_case("phone: 555-123-4567", PiiKind::PhoneNumber, "555-123-4567" ; "phone basic")]
    #[test_case("phone: (555) 123-4567", PiiKind::PhoneNumber, "(555) 123-4567" ; "phone parens")]
    #[test_case("phone: 555.123.4567", PiiKind::PhoneNumber, "555.123.4567" ; "phone dots")]
    #[test_case("phone: +1-555-123-4567", PiiKind::PhoneNumber, "+1-555-123-4567" ; "phone country code")]
    #[test_case("phone: 5551234567", PiiKind::PhoneNumber, "5551234567" ; "phone no separators")]
    #[test_case("Passport Number: 123456789", PiiKind::PassportNumber, "123456789" ; "passport")]
    #[test_case("passport: 987654321", PiiKind::PassportNumber, "987654321" ; "passport lowercase")]
    #[test_case("TFN: 123 456 782", PiiKind::AuTfn, "123 456 782" ; "tfn")]
    #[test_case("IRD: 49-091-857", PiiKind::NzIrdNumber, "49-091-857" ; "ird")]
    #[test_case("IRD number: 49-091-857", PiiKind::NzIrdNumber, "49-091-857" ; "ird span")]
    #[test_case("NHS: 943 476 5919", PiiKind::GbNhsNumber, "943 476 5919" ; "nhs")]
    #[test_case("NHS number: 943 476 5919", PiiKind::GbNhsNumber, "943 476 5919" ; "nhs span")]
    #[test_case("Medicare: 2123 45670 1", PiiKind::AuMedicare, "2123 45670 1" ; "medicare")]
    #[test_case("Medicare number: 2123 45670 1", PiiKind::AuMedicare, "2123 45670 1" ; "medicare span")]
    #[test_case("Passport: A12345678", PiiKind::UsPassportNew, "A12345678" ; "us passport new")]
    #[test_case("Passport number: A12345678", PiiKind::UsPassportNew, "A12345678" ; "us passport new span")]
    #[test_case("SWIFT: DEUTDEFF", PiiKind::SwiftBic, "DEUTDEFF" ; "swift bic 8char")]
    #[test_case("SWIFT code: DEUTDEFF", PiiKind::SwiftBic, "DEUTDEFF" ; "swift bic span")]
    #[test_case("BIC: DEUTDEFFXXX", PiiKind::SwiftBic, "DEUTDEFFXXX" ; "swift bic 11char")]
    #[test_case("EIN: 12-3456789", PiiKind::UsEin, "12-3456789" ; "ein")]
    #[test_case("EIN number: 12-3456789", PiiKind::UsEin, "12-3456789" ; "ein span")]
    #[test_case("IMEI: 490154203237518", PiiKind::Imei, "490154203237518" ; "imei")]
    #[test_case("IMEI number: 490154203237518", PiiKind::Imei, "490154203237518" ; "imei span")]
    #[test_case("IMEI: 49-015420-323751-8", PiiKind::Imei, "49-015420-323751-8" ; "imei hyphens")]
    #[test_case("UTR: 5555555555", PiiKind::GbUtr, "5555555555" ; "utr")]
    #[test_case("UTR number: 5555555555", PiiKind::GbUtr, "5555555555" ; "utr span")]
    #[test_case("Routing number: 021000021", PiiKind::UsAbaRouting, "021000021" ; "aba")]
    #[test_case("ABA routing number: 021000021", PiiKind::UsAbaRouting, "021000021" ; "aba span")]
    #[test_case("Sort code: 20-00-00", PiiKind::GbSortCode, "20-00-00" ; "sort code")]
    #[test_case("Bank sort code: 20-00-00", PiiKind::GbSortCode, "20-00-00" ; "sort code span")]
    #[test_case("GPS coordinates: 40.7128,-74.0060", PiiKind::PreciseGeolocation, "40.7128,-74.0060" ; "geolocation")]
    #[test_case("coordinates: 40.7128,-74.0060", PiiKind::PreciseGeolocation, "40.7128,-74.0060" ; "geolocation span")]
    #[test_case("Alien number: A012345678", PiiKind::UsAlienNumber, "A012345678" ; "a number")]
    #[test_case("Alien registration number: A012345678", PiiKind::UsAlienNumber, "A012345678" ; "a number span")]
    #[test_case("Receipt number: SRC2190000001", PiiKind::UsUscisReceiptNumber, "SRC2190000001" ; "uscis receipt")]
    #[test_case("USCIS receipt number: SRC2190000001", PiiKind::UsUscisReceiptNumber, "SRC2190000001" ; "uscis receipt span")]
    #[test_case("Driver's license: B1234568", PiiKind::UsDriversLicense, "B1234568" ; "us dl 1 letter 7 digits")]
    #[test_case("DL number: W123456789012", PiiKind::UsDriversLicense, "W123456789012" ; "us dl 1 letter 12 digits")]
    #[test_case("License number: AB123456", PiiKind::UsDriversLicense, "AB123456" ; "us dl 2 letters 6 digits")]
    #[test_case("Driver's license number: S530-4000-0001", PiiKind::UsDriversLicense, "S530-4000-0001" ; "us dl hyphenated il")]
    #[test_case("DL: S123-456-789-012", PiiKind::UsDriversLicense, "S123-456-789-012" ; "us dl hyphenated mi")]
    fn detects_with_keyword(input: &str, kind: PiiKind, expected_span: &str) {
        let detector = KeywordContextDetector::new().unwrap();
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

    // --- has_piis: keyword variants, case insensitive, separator variants ---

    #[test_case("phone number: 555-123-4567" ; "phone keyword variant 1")]
    #[test_case("telephone: 555-123-4567" ; "phone keyword variant 2")]
    #[test_case("mobile: 555-123-4567" ; "phone keyword variant 3")]
    #[test_case("cell: 555-123-4567" ; "phone keyword variant 4")]
    #[test_case("tel: 555-123-4567" ; "phone keyword variant 5")]
    #[test_case("fax: 555-123-4567" ; "phone keyword variant 6")]
    #[test_case("callback number: 555-123-4567" ; "phone keyword variant 7")]
    #[test_case("contact number: 555-123-4567" ; "phone keyword variant 8")]
    #[test_case("PHONE: 555-123-4567" ; "phone case upper")]
    #[test_case("phone: 555-123-4567" ; "phone case lower")]
    #[test_case("Phone: 555-123-4567" ; "phone case title")]
    #[test_case("phone 555-123-4567" ; "phone sep space")]
    #[test_case("phone:555-123-4567" ; "phone sep colon")]
    #[test_case("phone#555-123-4567" ; "phone sep hash")]
    #[test_case("passport number: 123456789" ; "passportnum keyword variant 1")]
    #[test_case("travel document number: 123456789" ; "passportnum keyword variant 2")]
    #[test_case("my passport: 123456789" ; "passportnum keyword variant 3")]
    #[test_case("PASSPORT: 123456789" ; "passportnum case upper")]
    #[test_case("passport: 123456789" ; "passportnum case lower")]
    #[test_case("Passport: 123456789" ; "passportnum case title")]
    #[test_case("passport 123456789" ; "passportnum sep space")]
    #[test_case("passport:123456789" ; "passportnum sep colon")]
    #[test_case("passport#123456789" ; "passportnum sep hash")]
    #[test_case("tax file number: 123 456 782" ; "tfn keyword variant 1")]
    #[test_case("australian tfn 123 456 782" ; "tfn keyword variant 2")]
    #[test_case("my tfn: 123 456 782" ; "tfn keyword variant 3")]
    #[test_case("TFN: 123 456 782" ; "tfn case upper")]
    #[test_case("tfn: 123 456 782" ; "tfn case lower")]
    #[test_case("Tfn: 123 456 782" ; "tfn case mixed")]
    #[test_case("TFN 123 456 782" ; "tfn sep space")]
    #[test_case("TFN:123 456 782" ; "tfn sep colon")]
    #[test_case("TFN#123 456 782" ; "tfn sep hash")]
    #[test_case("inland revenue number: 49-091-857" ; "ird keyword variant 1")]
    #[test_case("nz ird 49-091-857" ; "ird keyword variant 2")]
    #[test_case("gst number: 49-091-857" ; "ird keyword variant 3")]
    #[test_case("IRD: 49-091-857" ; "ird case upper")]
    #[test_case("ird: 49-091-857" ; "ird case lower")]
    #[test_case("Ird: 49-091-857" ; "ird case mixed")]
    #[test_case("IRD 49-091-857" ; "ird sep space")]
    #[test_case("IRD:49-091-857" ; "ird sep colon")]
    #[test_case("IRD#49-091-857" ; "ird sep hash")]
    #[test_case("national health service number: 943 476 5919" ; "nhs keyword variant 1")]
    #[test_case("patient number 943 476 5919" ; "nhs keyword variant 2")]
    #[test_case("my nhs number: 943 476 5919" ; "nhs keyword variant 3")]
    #[test_case("NHS: 943 476 5919" ; "nhs case upper")]
    #[test_case("nhs: 943 476 5919" ; "nhs case lower")]
    #[test_case("Nhs: 943 476 5919" ; "nhs case mixed")]
    #[test_case("NHS 943 476 5919" ; "nhs sep space")]
    #[test_case("NHS:943 476 5919" ; "nhs sep colon")]
    #[test_case("NHS#943 476 5919" ; "nhs sep hash")]
    #[test_case("medicare card number: 2123 45670 1" ; "medicare keyword variant 1")]
    #[test_case("australian medicare 2123 45670 1" ; "medicare keyword variant 2")]
    #[test_case("my medicare: 2123 45670 1" ; "medicare keyword variant 3")]
    #[test_case("Medicare: 2123 45670 1" ; "medicare case title")]
    #[test_case("medicare: 2123 45670 1" ; "medicare case lower")]
    #[test_case("MEDICARE: 2123 45670 1" ; "medicare case upper")]
    #[test_case("Medicare 2123 45670 1" ; "medicare sep space")]
    #[test_case("Medicare:2123 45670 1" ; "medicare sep colon")]
    #[test_case("Medicare#2123 45670 1" ; "medicare sep hash")]
    #[test_case("us passport number: X12345678" ; "passport keyword variant 1")]
    #[test_case("travel document number Y12345678" ; "passport keyword variant 2")]
    #[test_case("my passport: Z12345678" ; "passport keyword variant 3")]
    #[test_case("PASSPORT: A12345678" ; "passport case upper")]
    #[test_case("passport: a12345678" ; "passport case lower")]
    #[test_case("Passport: A12345678" ; "passport case title")]
    #[test_case("Passport A12345678" ; "passport sep space")]
    #[test_case("Passport:A12345678" ; "passport sep colon")]
    #[test_case("Passport#A12345678" ; "passport sep hash")]
    #[test_case("SWIFT: DEUTDEFF" ; "swift case upper")]
    #[test_case("swift: DEUTDEFF" ; "swift case lower")]
    #[test_case("Swift: DEUTDEFF" ; "swift case mixed")]
    #[test_case("SWIFT DEUTDEFF" ; "swift sep space")]
    #[test_case("SWIFT:DEUTDEFF" ; "swift sep colon")]
    #[test_case("SWIFT#DEUTDEFF" ; "swift sep hash")]
    #[test_case("employer identification number: 12-3456789" ; "ein keyword variant 1")]
    #[test_case("federal ein 12-3456789" ; "ein keyword variant 2")]
    #[test_case("tax id number: 12-3456789" ; "ein keyword variant 3")]
    #[test_case("EIN: 12-3456789" ; "ein case upper")]
    #[test_case("ein: 12-3456789" ; "ein case lower")]
    #[test_case("Ein: 12-3456789" ; "ein case mixed")]
    #[test_case("EIN 12-3456789" ; "ein sep space")]
    #[test_case("EIN:12-3456789" ; "ein sep colon")]
    #[test_case("EIN#12-3456789" ; "ein sep hash")]
    #[test_case("IMEI: 490154203237518" ; "imei case upper")]
    #[test_case("imei: 490154203237518" ; "imei case lower")]
    #[test_case("Imei: 490154203237518" ; "imei case mixed")]
    #[test_case("IMEI 490154203237518" ; "imei sep space")]
    #[test_case("IMEI:490154203237518" ; "imei sep colon")]
    #[test_case("IMEI#490154203237518" ; "imei sep hash")]
    #[test_case("unique taxpayer reference: 5555555555" ; "utr keyword variant 1")]
    #[test_case("self assessment utr 5555555555" ; "utr keyword variant 2")]
    #[test_case("hmrc utr: 5555555555" ; "utr keyword variant 3")]
    #[test_case("UTR: 5555555555" ; "utr case upper")]
    #[test_case("utr: 5555555555" ; "utr case lower")]
    #[test_case("Utr: 5555555555" ; "utr case mixed")]
    #[test_case("UTR 5555555555" ; "utr sep space")]
    #[test_case("UTR:5555555555" ; "utr sep colon")]
    #[test_case("UTR#5555555555" ; "utr sep hash")]
    #[test_case("routing transit number: 021000021" ; "aba keyword variant 1")]
    #[test_case("ach routing 021000021" ; "aba keyword variant 2")]
    #[test_case("wire routing: 021000021" ; "aba keyword variant 3")]
    #[test_case("ROUTING NUMBER: 021000021" ; "aba case upper")]
    #[test_case("routing number: 021000021" ; "aba case lower")]
    #[test_case("Routing Number: 021000021" ; "aba case title")]
    #[test_case("Routing number 021000021" ; "aba sep space")]
    #[test_case("Routing number:021000021" ; "aba sep colon")]
    #[test_case("Routing number#021000021" ; "aba sep hash")]
    #[test_case("sort code: 20-00-00" ; "sort code keyword variant 1")]
    #[test_case("branch sort code 20-00-00" ; "sort code keyword variant 2")]
    #[test_case("bacs sort code: 20-00-00" ; "sort code keyword variant 3")]
    #[test_case("SORT CODE: 20-00-00" ; "sort code case upper")]
    #[test_case("Sort Code: 20-00-00" ; "sort code case title")]
    #[test_case("Sort code 20-00-00" ; "sort code sep space")]
    #[test_case("Sort code:20-00-00" ; "sort code sep colon")]
    #[test_case("Sort code#20-00-00" ; "sort code sep hash")]
    #[test_case("Sort code: 40-47-84" ; "sort code value 1")]
    #[test_case("Sort code: 30-90-53" ; "sort code value 2")]
    #[test_case("lat/long: 40.7128,-74.0060" ; "geolocation keyword variant 1")]
    #[test_case("geolocation 40.7128,-74.0060" ; "geolocation keyword variant 2")]
    #[test_case("gps position: 40.7128,-74.0060" ; "geolocation keyword variant 3")]
    #[test_case("precise location: 40.7128,-74.0060" ; "geolocation keyword variant 4")]
    #[test_case("GPS COORDINATES: 40.7128,-74.0060" ; "geolocation case upper")]
    #[test_case("gps coordinates: 40.7128,-74.0060" ; "geolocation case lower")]
    #[test_case("Gps Coordinates: 40.7128,-74.0060" ; "geolocation case title")]
    #[test_case("coordinates 40.7128,-74.0060" ; "geolocation sep space")]
    #[test_case("coordinates:40.7128,-74.0060" ; "geolocation sep colon")]
    #[test_case("coordinates#40.7128,-74.0060" ; "geolocation sep hash")]
    #[test_case("alien registration number: A012345678" ; "a number keyword variant 1")]
    #[test_case("green card number: A012345678" ; "a number keyword variant 2")]
    #[test_case("permanent resident number: A012345678" ; "a number keyword variant 3")]
    #[test_case("USCIS number: A012345678" ; "a number keyword variant 4")]
    #[test_case("A-number: A012345678" ; "a number keyword variant 5")]
    #[test_case("ALIEN NUMBER: A012345678" ; "a number case upper")]
    #[test_case("alien number: a012345678" ; "a number case lower")]
    #[test_case("Alien Number: A012345678" ; "a number case title")]
    #[test_case("Alien number A012345678" ; "a number sep space")]
    #[test_case("Alien number:A012345678" ; "a number sep colon")]
    #[test_case("Alien number#A012345678" ; "a number sep hash")]
    #[test_case("USCIS number: A1234567" ; "a number 7 digit")]
    #[test_case("USCIS number: A12345678" ; "a number 8 digit")]
    #[test_case("USCIS receipt number: SRC2190000001" ; "uscis receipt keyword variant 1")]
    #[test_case("USCIS case number: SRC2190000001" ; "uscis receipt keyword variant 2")]
    #[test_case("petition receipt: SRC2190000001" ; "uscis receipt keyword variant 3")]
    #[test_case("I-797 receipt: SRC2190000001" ; "uscis receipt keyword variant 4")]
    #[test_case("case number: SRC2190000001" ; "uscis receipt keyword variant 5")]
    #[test_case("RECEIPT NUMBER: SRC2190000001" ; "uscis receipt case upper")]
    #[test_case("receipt number: src2190000001" ; "uscis receipt case lower")]
    #[test_case("Receipt Number: Src2190000001" ; "uscis receipt case title")]
    #[test_case("Receipt number SRC2190000001" ; "uscis receipt sep space")]
    #[test_case("Receipt number:SRC2190000001" ; "uscis receipt sep colon")]
    #[test_case("Receipt number#SRC2190000001" ; "uscis receipt sep hash")]
    #[test_case("Receipt number: EAC2190000001" ; "uscis receipt center EAC")]
    #[test_case("Receipt number: WAC2190000001" ; "uscis receipt center WAC")]
    #[test_case("Receipt number: LIN2190000001" ; "uscis receipt center LIN")]
    #[test_case("Receipt number: IOE2190000001" ; "uscis receipt center IOE")]
    #[test_case("Receipt number: MSC2190000001" ; "uscis receipt center MSC")]
    #[test_case("driver's license number: B1234568" ; "us dl keyword variant 1")]
    #[test_case("driving licence: B1234568" ; "us dl keyword variant 2")]
    #[test_case("state id number: B1234568" ; "us dl keyword variant 3")]
    #[test_case("DL number: B1234568" ; "us dl keyword variant 4")]
    #[test_case("DMV number: B1234568" ; "us dl keyword variant 5")]
    #[test_case("DRIVER'S LICENSE: B1234568" ; "us dl case upper")]
    #[test_case("driver's license: B1234568" ; "us dl case lower")]
    #[test_case("Driver's License: b1234568" ; "us dl case title")]
    #[test_case("DL B1234568" ; "us dl sep space")]
    #[test_case("DL:B1234568" ; "us dl sep colon")]
    #[test_case("DL#B1234568" ; "us dl sep hash")]
    fn has_piis_with_keyword(input: &str) {
        let detector = KeywordContextDetector::new().unwrap();
        assert!(detector.has_piis(input), "should detect PII in: {input}");
    }

    // --- Whitespace separator variants (newline, tab, crlf) ---

    #[test_case("phone:\n555-123-4567" ; "phone newline")]
    #[test_case("phone number\n555-123-4567" ; "phone keyword newline")]
    #[test_case("phone:\t555-123-4567" ; "phone tab")]
    #[test_case("phone number\t555-123-4567" ; "phone keyword tab")]
    #[test_case("phone:\r\n555-123-4567" ; "phone crlf")]
    #[test_case("phone number\r\n555-123-4567" ; "phone keyword crlf")]
    #[test_case("passport:\n123456789" ; "passportnum newline")]
    #[test_case("passport number\n123456789" ; "passportnum keyword newline")]
    #[test_case("passport:\t123456789" ; "passportnum tab")]
    #[test_case("passport number\t123456789" ; "passportnum keyword tab")]
    #[test_case("passport:\r\n123456789" ; "passportnum crlf")]
    #[test_case("passport number\r\n123456789" ; "passportnum keyword crlf")]
    #[test_case("TFN:\n123 456 782" ; "tfn newline")]
    #[test_case("Tax file number\n123 456 782" ; "tfn keyword newline")]
    #[test_case("TFN:\t123 456 782" ; "tfn tab")]
    #[test_case("Tax file number\t123 456 782" ; "tfn keyword tab")]
    #[test_case("TFN:\r\n123 456 782" ; "tfn crlf")]
    #[test_case("Tax file number\r\n123 456 782" ; "tfn keyword crlf")]
    #[test_case("IRD:\n49-091-857" ; "ird newline")]
    #[test_case("IRD number\n49-091-857" ; "ird keyword newline")]
    #[test_case("IRD:\t49-091-857" ; "ird tab")]
    #[test_case("IRD number\t49-091-857" ; "ird keyword tab")]
    #[test_case("IRD:\r\n49-091-857" ; "ird crlf")]
    #[test_case("IRD number\r\n49-091-857" ; "ird keyword crlf")]
    #[test_case("NHS:\n943 476 5919" ; "nhs newline")]
    #[test_case("NHS number\n943 476 5919" ; "nhs keyword newline")]
    #[test_case("NHS:\t943 476 5919" ; "nhs tab")]
    #[test_case("NHS number\t943 476 5919" ; "nhs keyword tab")]
    #[test_case("NHS:\r\n943 476 5919" ; "nhs crlf")]
    #[test_case("NHS number\r\n943 476 5919" ; "nhs keyword crlf")]
    #[test_case("Medicare:\n2123 45670 1" ; "medicare newline")]
    #[test_case("Medicare number\n2123 45670 1" ; "medicare keyword newline")]
    #[test_case("Medicare:\t2123 45670 1" ; "medicare tab")]
    #[test_case("Medicare number\t2123 45670 1" ; "medicare keyword tab")]
    #[test_case("Medicare:\r\n2123 45670 1" ; "medicare crlf")]
    #[test_case("Medicare number\r\n2123 45670 1" ; "medicare keyword crlf")]
    #[test_case("Passport:\nA12345678" ; "passport newline")]
    #[test_case("Passport number\nA12345678" ; "passport keyword newline")]
    #[test_case("Passport:\tA12345678" ; "passport tab")]
    #[test_case("Passport number\tA12345678" ; "passport keyword tab")]
    #[test_case("Passport:\r\nA12345678" ; "passport crlf")]
    #[test_case("Passport number\r\nA12345678" ; "passport keyword crlf")]
    #[test_case("SWIFT:\nDEUTDEFF" ; "swift newline")]
    #[test_case("SWIFT code\nDEUTDEFF" ; "swift keyword newline")]
    #[test_case("SWIFT:\tDEUTDEFF" ; "swift tab")]
    #[test_case("SWIFT code\tDEUTDEFF" ; "swift keyword tab")]
    #[test_case("SWIFT:\r\nDEUTDEFF" ; "swift crlf")]
    #[test_case("SWIFT code\r\nDEUTDEFF" ; "swift keyword crlf")]
    #[test_case("EIN:\n12-3456789" ; "ein newline")]
    #[test_case("EIN number\n12-3456789" ; "ein keyword newline")]
    #[test_case("EIN:\t12-3456789" ; "ein tab")]
    #[test_case("EIN number\t12-3456789" ; "ein keyword tab")]
    #[test_case("EIN:\r\n12-3456789" ; "ein crlf")]
    #[test_case("EIN number\r\n12-3456789" ; "ein keyword crlf")]
    #[test_case("IMEI:\n490154203237518" ; "imei newline")]
    #[test_case("IMEI number\n490154203237518" ; "imei keyword newline")]
    #[test_case("IMEI:\t490154203237518" ; "imei tab")]
    #[test_case("IMEI number\t490154203237518" ; "imei keyword tab")]
    #[test_case("IMEI:\r\n490154203237518" ; "imei crlf")]
    #[test_case("IMEI number\r\n490154203237518" ; "imei keyword crlf")]
    #[test_case("UTR:\n5555555555" ; "utr newline")]
    #[test_case("UTR number\n5555555555" ; "utr keyword newline")]
    #[test_case("UTR:\t5555555555" ; "utr tab")]
    #[test_case("UTR number\t5555555555" ; "utr keyword tab")]
    #[test_case("UTR:\r\n5555555555" ; "utr crlf")]
    #[test_case("UTR number\r\n5555555555" ; "utr keyword crlf")]
    #[test_case("Routing number:\n021000021" ; "aba newline")]
    #[test_case("ABA routing\n021000021" ; "aba keyword newline")]
    #[test_case("Routing number:\t021000021" ; "aba tab")]
    #[test_case("ABA routing\t021000021" ; "aba keyword tab")]
    #[test_case("Routing number:\r\n021000021" ; "aba crlf")]
    #[test_case("ABA routing\r\n021000021" ; "aba keyword crlf")]
    #[test_case("Sort code:\n20-00-00" ; "sort code newline")]
    #[test_case("Bank sort code\n20-00-00" ; "sort code keyword newline")]
    #[test_case("Sort code:\t20-00-00" ; "sort code tab")]
    #[test_case("Bank sort code\t20-00-00" ; "sort code keyword tab")]
    #[test_case("Sort code:\r\n20-00-00" ; "sort code crlf")]
    #[test_case("Bank sort code\r\n20-00-00" ; "sort code keyword crlf")]
    #[test_case("GPS coordinates:\n40.7128,-74.0060" ; "geolocation newline")]
    #[test_case("coordinates\n40.7128,-74.0060" ; "geolocation keyword newline")]
    #[test_case("GPS coordinates:\t40.7128,-74.0060" ; "geolocation tab")]
    #[test_case("coordinates\t40.7128,-74.0060" ; "geolocation keyword tab")]
    #[test_case("GPS coordinates:\r\n40.7128,-74.0060" ; "geolocation crlf")]
    #[test_case("coordinates\r\n40.7128,-74.0060" ; "geolocation keyword crlf")]
    #[test_case("Alien number:\nA012345678" ; "a number newline")]
    #[test_case("USCIS number\nA012345678" ; "a number keyword newline")]
    #[test_case("Alien number:\tA012345678" ; "a number tab")]
    #[test_case("USCIS number\tA012345678" ; "a number keyword tab")]
    #[test_case("Alien number:\r\nA012345678" ; "a number crlf")]
    #[test_case("USCIS number\r\nA012345678" ; "a number keyword crlf")]
    #[test_case("Receipt number:\nSRC2190000001" ; "uscis receipt newline")]
    #[test_case("USCIS case\nSRC2190000001" ; "uscis receipt keyword newline")]
    #[test_case("Receipt number:\tSRC2190000001" ; "uscis receipt tab")]
    #[test_case("USCIS case\tSRC2190000001" ; "uscis receipt keyword tab")]
    #[test_case("Receipt number:\r\nSRC2190000001" ; "uscis receipt crlf")]
    #[test_case("USCIS case\r\nSRC2190000001" ; "uscis receipt keyword crlf")]
    #[test_case("Driver's license:\nB1234568" ; "us dl newline")]
    #[test_case("DL number\nB1234568" ; "us dl keyword newline")]
    #[test_case("Driver's license:\tB1234568" ; "us dl tab")]
    #[test_case("DL number\tB1234568" ; "us dl keyword tab")]
    #[test_case("Driver's license:\r\nB1234568" ; "us dl crlf")]
    #[test_case("DL number\r\nB1234568" ; "us dl keyword crlf")]
    fn has_piis_with_whitespace_separator(input: &str) {
        let detector = KeywordContextDetector::new().unwrap();
        assert!(detector.has_piis(input), "should detect PII in: {input}");
    }

    // --- Rejection tests ---

    #[test_case("TFN: 123 456 789", PiiKind::AuTfn ; "tfn bad checksum")]
    #[test_case("IRD: 01-000-000", PiiKind::NzIrdNumber ; "ird out of range")]
    #[test_case("NHS: 943 476 5910", PiiKind::GbNhsNumber ; "nhs bad checksum")]
    #[test_case("Medicare: 1123 45670 1", PiiKind::AuMedicare ; "medicare invalid first digit")]
    #[test_case("Passport: B12345678", PiiKind::UsPassportNew ; "passport invalid prefix")]
    #[test_case("SWIFT: DEUTXXFF", PiiKind::SwiftBic ; "swift invalid country")]
    #[test_case("EIN: 07-3456789", PiiKind::UsEin ; "ein invalid prefix")]
    #[test_case("IMEI: 490154203237519", PiiKind::Imei ; "imei bad luhn")]
    #[test_case("UTR: 1555555555", PiiKind::GbUtr ; "utr bad checksum")]
    #[test_case("Routing number: 021000022", PiiKind::UsAbaRouting ; "aba bad checksum")]
    #[test_case("coordinates: 91.0000,-74.0060", PiiKind::PreciseGeolocation ; "geolocation lat out of range")]
    #[test_case("coordinates: 40.7128,181.0060", PiiKind::PreciseGeolocation ; "geolocation lon out of range")]
    #[test_case("coordinates: 40.71,-74.00", PiiKind::PreciseGeolocation ; "geolocation insufficient precision")]
    #[test_case("Receipt number: XYZ2190000001", PiiKind::UsUscisReceiptNumber ; "uscis receipt invalid center")]
    #[test_case("DL: B123", PiiKind::UsDriversLicense ; "us dl too few digits")]
    #[test_case("passport: 12345678", PiiKind::PassportNumber ; "passportnum 8 digits")]
    #[test_case("passport: 1234567890", PiiKind::PassportNumber ; "passportnum 10 digits")]
    fn rejects_invalid_with_keyword(input: &str, kind: PiiKind) {
        let detector = KeywordContextDetector::new().unwrap();
        let matches = detector.mark_piis(input);
        assert!(
            matches.iter().all(|m| m.kind != kind),
            "should reject {kind:?} in: {input}"
        );
    }

    // --- No detection without keyword ---

    #[test_case("call 555-123-4567 today", PiiKind::PhoneNumber ; "phone no keyword")]
    #[test_case("code: 123456789", PiiKind::PassportNumber ; "passportnum no keyword")]
    #[test_case("my number is 123 456 782", PiiKind::AuTfn ; "tfn no keyword")]
    #[test_case("number is 49-091-857", PiiKind::NzIrdNumber ; "ird no keyword")]
    #[test_case("number is 943 476 5919", PiiKind::GbNhsNumber ; "nhs no keyword")]
    #[test_case("number is 2123 45670 1", PiiKind::AuMedicare ; "medicare no keyword")]
    #[test_case("code is A12345678", PiiKind::UsPassportNew ; "passport no keyword")]
    #[test_case("code is DEUTDEFF", PiiKind::SwiftBic ; "swift no keyword")]
    #[test_case("number is 12-3456789", PiiKind::UsEin ; "ein no keyword")]
    #[test_case("number is 490154203237518", PiiKind::Imei ; "imei no keyword")]
    #[test_case("number is 5555555555", PiiKind::GbUtr ; "utr no keyword")]
    #[test_case("number is 021000021", PiiKind::UsAbaRouting ; "aba no keyword")]
    #[test_case("date is 20-00-00", PiiKind::GbSortCode ; "sort code no keyword")]
    #[test_case("values are 40.7128,-74.0060", PiiKind::PreciseGeolocation ; "geolocation no keyword")]
    #[test_case("code is A012345678", PiiKind::UsAlienNumber ; "a number no keyword")]
    #[test_case("code is SRC2190000001", PiiKind::UsUscisReceiptNumber ; "uscis receipt no keyword")]
    #[test_case("code is B1234568", PiiKind::UsDriversLicense ; "us dl no keyword")]
    fn no_detection_without_keyword(input: &str, kind: PiiKind) {
        let detector = KeywordContextDetector::new().unwrap();
        let matches = detector.mark_piis(input);
        assert!(
            matches.iter().all(|m| m.kind != kind),
            "should not detect {kind:?} without keyword in: {input}"
        );
    }

    // --- Special cases kept as individual tests ---

    #[test]
    fn geolocation_with_space_after_comma() {
        let detector = KeywordContextDetector::new().unwrap();
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
    fn geolocation_negative_latitude() {
        let detector = KeywordContextDetector::new().unwrap();
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

    // --- JSON input tests ---

    #[test_case(r#"{"contact": {"phone": "555-123-4567", "type": "mobile"}}"#, PiiKind::PhoneNumber, "555-123-4567" ; "phone in json")]
    #[test_case(r#"{"traveler": {"passport": "123456789", "nationality": "US"}}"#, PiiKind::PassportNumber, "123456789" ; "passport in json")]
    #[test_case(r#"{"tax_file_number": "TFN: 123 456 782", "state": "NSW"}"#, PiiKind::AuTfn, "123 456 782" ; "tfn in json")]
    #[test_case(r#"{"taxpayer": {"IRD number": "49-091-857", "name": "Smith"}}"#, PiiKind::NzIrdNumber, "49-091-857" ; "ird in json")]
    #[test_case(r#"{"patient": {"NHS number": "943 476 5919", "ward": "A3"}}"#, PiiKind::GbNhsNumber, "943 476 5919" ; "nhs in json")]
    #[test_case(r#"{"member": {"Medicare number": "2123 45670 1", "state": "VIC"}}"#, PiiKind::AuMedicare, "2123 45670 1" ; "medicare in json")]
    #[test_case(r#"{"traveler": {"passport number": "A12345678", "expiry": "2028-06"}}"#, PiiKind::UsPassportNew, "A12345678" ; "us passport in json")]
    #[test_case(r#"{"bank": {"SWIFT code": "DEUTDEFF", "name": "Deutsche Bank"}}"#, PiiKind::SwiftBic, "DEUTDEFF" ; "swift in json")]
    #[test_case(r#"{"company": {"EIN": "12-3456789", "name": "Acme Corp"}}"#, PiiKind::UsEin, "12-3456789" ; "ein in json")]
    #[test_case(r#"{"device": {"IMEI": "490154203237518", "model": "iPhone"}}"#, PiiKind::Imei, "490154203237518" ; "imei in json")]
    #[test_case(r#"{"taxpayer": {"UTR": "5555555555", "year": "2024-25"}}"#, PiiKind::GbUtr, "5555555555" ; "utr in json")]
    #[test_case(r#"{"bank": {"routing number": "021000021", "type": "checking"}}"#, PiiKind::UsAbaRouting, "021000021" ; "aba in json")]
    #[test_case(r#"{"bank": {"sort code": "20-00-00", "account": "12345678"}}"#, PiiKind::GbSortCode, "20-00-00" ; "sort code in json")]
    #[test_case(r#"{"location": {"coordinates": "40.7128,-74.0060", "city": "New York"}}"#, PiiKind::PreciseGeolocation, "40.7128,-74.0060" ; "geolocation in json")]
    #[test_case(r#"{"immigration": {"alien number": "A012345678", "status": "LPR"}}"#, PiiKind::UsAlienNumber, "A012345678" ; "alien number in json")]
    #[test_case(r#"{"case": {"receipt number": "SRC2190000001", "form": "I-130"}}"#, PiiKind::UsUscisReceiptNumber, "SRC2190000001" ; "uscis receipt in json")]
    #[test_case(r#"{"identity": {"license number": "B1234568", "state": "CA"}}"#, PiiKind::UsDriversLicense, "B1234568" ; "us dl in json")]
    fn detects_in_json(input: &str, kind: PiiKind, expected_span: &str) {
        let detector = KeywordContextDetector::new().unwrap();
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == kind)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], expected_span);
    }

    #[test]
    fn detects_multiple_keyword_pii_in_json() {
        let detector = KeywordContextDetector::new().unwrap();
        let input =
            r#"{"employee": {"EIN": "12-3456789", "UTR": "5555555555", "TFN": "123 456 782"}}"#;
        let matches = detector.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::UsEin));
        assert!(kinds.contains(&PiiKind::GbUtr));
        assert!(kinds.contains(&PiiKind::AuTfn));
    }
}
