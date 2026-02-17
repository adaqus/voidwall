use std::cell::RefCell;
use std::collections::HashSet;

use regex::Regex;
use vectorscan_rs::{BlockDatabase, BlockScanner, Flag, Pattern, Scan};

use crate::Language;
use crate::detector::Detector;
use crate::validators::{
    a_number_check, aba_check, ein_check, geolocation_check, ie_driver_check, imei_check,
    ird_check, medicare_check, nhi_check, nhs_check, nz_dl_check, ohip_check, passport_check,
    passport_new_check, phone_check, sa_id_check, sort_code_check, swift_bic_check, tfn_check,
    us_dl_check, uscis_receipt_check, utr_check, za_trn_check,
};
use crate::{PiiError, PiiKind, PiiMatch};

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_percent(hi: u8, lo: u8) -> Option<u8> {
    let val = (hex_val(hi)? << 4) | hex_val(lo)?;
    if (0x20..=0x7e).contains(&val) {
        Some(val)
    } else {
        None
    }
}

fn decode_html_entity(bytes: &[u8]) -> Option<(u8, usize)> {
    debug_assert!(bytes[0] == b'&');
    let max_len = bytes.len().min(12);
    let semi = bytes[1..max_len].iter().position(|&b| b == b';')? + 1;

    if bytes[1] == b'#' {
        if bytes.len() > 2 && (bytes[2] == b'x' || bytes[2] == b'X') {
            // &#xHH;
            if semi < 4 {
                return None;
            }
            let mut val: u16 = 0;
            for &b in &bytes[3..semi] {
                val = val.checked_mul(16)?.checked_add(hex_val(b)? as u16)?;
            }
            if val == 160 {
                return Some((b' ', semi + 1));
            }
            if (0x20..=0x7e).contains(&val) {
                Some((val as u8, semi + 1))
            } else {
                None
            }
        } else {
            // &#DDD;
            if semi < 3 {
                return None;
            }
            let mut val: u16 = 0;
            for &b in &bytes[2..semi] {
                if !b.is_ascii_digit() {
                    return None;
                }
                val = val.checked_mul(10)?.checked_add((b - b'0') as u16)?;
            }
            if val == 160 {
                return Some((b' ', semi + 1));
            }
            if (0x20..=0x7e).contains(&val) {
                Some((val as u8, semi + 1))
            } else {
                None
            }
        }
    } else {
        let name = &bytes[1..semi];
        let ch = match name {
            b"nbsp" => b' ',
            b"quot" => b'"',
            b"amp" => b'&',
            b"lt" => b'<',
            b"gt" => b'>',
            b"period" => b'.',
            b"commat" => b'@',
            b"colon" => b':',
            b"num" => b'#',
            b"plus" => b'+',
            b"comma" => b',',
            b"lpar" => b'(',
            b"rpar" => b')',
            b"sol" => b'/',
            b"hyphen" => b'-',
            _ => return None,
        };
        Some((ch, semi + 1))
    }
}

/// Decodes URL percent-encoding and HTML entities to plain ASCII.
/// Returns `None` if input contains no encoded sequences (fast path).
/// Otherwise returns `(decoded, offset_map)` where `offset_map[i]` maps
/// decoded byte position `i` to the corresponding original byte position.
fn decode_for_detection(input: &str) -> Option<(String, Vec<usize>)> {
    if !input.as_bytes().iter().any(|&b| b == b'%' || b == b'&') {
        return None;
    }

    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut offset_map = Vec::with_capacity(bytes.len() + 1);
    let mut i = 0;
    let mut changed = false;

    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Some(ch) = decode_percent(bytes[i + 1], bytes[i + 2])
        {
            offset_map.push(i);
            decoded.push(ch);
            i += 3;
            changed = true;
            continue;
        }
        if bytes[i] == b'&'
            && let Some((ch, len)) = decode_html_entity(&bytes[i..])
        {
            offset_map.push(i);
            decoded.push(ch);
            i += len;
            changed = true;
            continue;
        }
        offset_map.push(i);
        decoded.push(bytes[i]);
        i += 1;
    }
    offset_map.push(i);

    if !changed {
        return None;
    }

    // SAFETY: We only replace ASCII-encoded sequences (%XX, &#DD;, &name;) with
    // single ASCII bytes (0x20..=0x7E), and copy all other bytes verbatim from
    // valid UTF-8 input. The result is always valid UTF-8.
    Some((unsafe { String::from_utf8_unchecked(decoded) }, offset_map))
}

thread_local! {
    static KW_DETECTION_CACHE: RefCell<Option<(usize, BlockScanner<'static>)>>
        = const { RefCell::new(None) };
}

struct KeywordPattern {
    kind: PiiKind,
    full_regex: Regex,
    validate: fn(&str) -> bool,
}

pub struct KeywordContextDetector {
    detection_db: Box<BlockDatabase>,
    detection_prototype: BlockScanner<'static>,
    patterns: Vec<KeywordPattern>,
}

impl KeywordContextDetector {
    #[allow(clippy::type_complexity)]
    pub fn new(
        enabled_kinds: &HashSet<PiiKind>,
        enabled_languages: &HashSet<Language>,
    ) -> Result<Self, PiiError> {
        let all_patterns: Vec<(PiiKind, Language, &str, fn(&str) -> bool)> = vec![
            (
                PiiKind::AuTfn,
                Language::En,
                r"(?i)(?:australian tax file number|australian tfn|aus tfn|ato tax file number|ato tfn|individual tax file number|tax file number|tax file no\.?|tax file num|tax file #|tax file ref(?:erence)?|tax file identifier|applicant tfn|employee tfn|client tfn|customer tfn|my tfn|your tfn|tfn number|tfn no\.?|tfn num|tfn)[\s:.#/\-\x22]*?(\d{3}\s\d{3}\s\d{3})",
                tfn_check,
            ),
            (
                PiiKind::NzIrdNumber,
                Language::En,
                r"(?i)(?:inland revenue dep(?:artmen)?t|inland revenue number|inland revenue no\.?|new zealand ird|new zealand tax number|new zealand tax id|nz ird|nz tax number|nz tax id|ird number nz|ird number|ird no\.?|ird num|ird #|ird ref(?:erence)?|applicant ird|employee ird|client ird|customer ird|my ird|your ird|gst registration|gst number|gst no\.?|tax number nz|ird)[\s:.#/\-\x22]*?(\d{2,3}-\d{3}-\d{3})",
                ird_check,
            ),
            (
                PiiKind::GbNhsNumber,
                Language::En,
                r"(?i)(?:national health service number|national health service no\.?|nhs patient number|nhs patient id|nhs patient no\.?|nhs record number|nhs registration|nhs identifier|nhs number|nhs no\.?|nhs num|nhs #|nhs id|nhs ref(?:erence)?|nhs record|health service number|health service no\.?|health index number|health id|patient number|patient no\.?|patient id|my nhs number|your nhs number|chi number|h&c number|hc number|nhs)[\s:.#/\-\x22]*?(\d{3}\s\d{3}\s\d{4})",
                nhs_check,
            ),
            (
                PiiKind::AuMedicare,
                Language::En,
                r"(?i)(?:medicare card number|medicare card no\.?|medicare card|australian medicare|medicare enrol(?:l)?ment|medicare registration|medicare identifier|medicare number|medicare no\.?|medicare num|medicare #|medicare id|medicare ref(?:erence)?|medicare patient|aus medicare|au medicare|applicant medicare|employee medicare|client medicare|customer medicare|my medicare|your medicare|medicare|irn)[\s:.#/\-\x22]*?(\d{4}\s\d{5}\s\d)",
                medicare_check,
            ),
            (
                PiiKind::PhoneNumber,
                Language::En,
                r"(?i)(?:phone number|phone no\.?|phone num|phone #|telephone number|telephone no\.?|telephone|mobile number|mobile no\.?|mobile phone|mobile|cell phone|cell number|cell|contact number|contact no\.?|contact phone|callback number|callback no\.?|callback|fax number|fax no\.?|fax|tel number|tel no\.?|tel|landline|home phone|work phone|office phone|alternate phone|alt phone|my phone|your phone|customer phone|applicant phone|phone)[\s:.#/\-\x22]*?((?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})",
                phone_check,
            ),
            (
                PiiKind::PassportNumber,
                Language::En,
                r"(?i)(?:united states passport|passport book number|passport book no\.?|passport card number|us passport number|us passport no\.?|american passport|travel document number|travel document no\.?|travel doc number|travel doc no\.?|passport number|passport no\.?|passport num|passport #|passport id|passport card|us passport|travel doc|applicant passport|my passport|your passport|document number|document no\.?|doc number|doc no\.?|passport)[\s:.#/\-\x22]*?(\d{9})\b",
                passport_check,
            ),
            (
                PiiKind::UsPassportNew,
                Language::En,
                r"(?i)(?:united states passport|passport book number|passport book no\.?|passport card number|us passport number|us passport no\.?|american passport|travel document number|travel document no\.?|travel doc number|travel doc no\.?|passport number|passport no\.?|passport num|passport #|passport id|passport card|us passport|travel doc|applicant passport|my passport|your passport|document number|document no\.?|doc number|doc no\.?|passport)[\s:.#/\-\x22]*?([AXYZaxyz]\d{8})",
                passport_new_check,
            ),
            (
                PiiKind::SwiftBic,
                Language::En,
                r"(?i)(?:bank identifier code|bank identifier|correspondent (?:bank )?swift|intermediary swift|intermediary bic|international bank code|beneficiary swift|beneficiary bic|swift/bic|swift bic|bic/swift|swift code|swift number|swift no\.?|swift #|swift address|swift id|bank swift|bank routing|bank bic|bic code|bic number|bic no\.?|bic #|bic id|routing code|clearing code|my swift|swift|bic)[\s:.#/\-\x22]*?([A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?)\b",
                swift_bic_check,
            ),
            (
                PiiKind::UsEin,
                Language::En,
                r"(?i)(?:employer identification number|employer identification no\.?|federal employer identification|employer id number|employer id no\.?|federal employer id|federal tax identification|tax identification number|federal id number|federal id no\.?|federal tax id|federal ein|tax id number|employer number|employer no\.?|business tax id|company tax id|company ein|irs employer id|applicant ein|ein number|ein no\.?|ein num|ein #|tax id|irs ein|our ein|my ein|fein|ein)[\s:.#/\-\x22]*?(\d{2}-\d{7})",
                ein_check,
            ),
            (
                PiiKind::Imei,
                Language::En,
                r"(?i)(?:international mobile equipment identity|mobile equipment identity|equipment identity|device identifier|device id number|device serial|device imei|handset imei|serial imei|mobile imei|tablet imei|equipment id|phone imei|imei identifier|imei number|imei no\.?|imei num|imei #|imei code|imei id|your imei|my imei|meid|imei)[\s:.#/\-\x22]*?(\d{2}-?\d{6}-?\d{6}-?\d)",
                imei_check,
            ),
            (
                PiiKind::GbUtr,
                Language::En,
                r"(?i)(?:unique taxpayer ref(?:erence)?|unique tax ref(?:erence)?|taxpayer ref(?:erence)?|tax ref(?:erence)?|hmrc ref(?:erence)?|hmrc utr|self assessment ref(?:erence)?|self assessment utr|self assessment number|self assessment no\.?|sa utr|sa ref(?:erence)?|sa number|sa no\.?|corporation tax ref(?:erence)?|corporation tax utr|ct utr|ct ref(?:erence)?|company utr|company tax ref(?:erence)?|partnership utr|partnership ref(?:erence)?|your utr|my utr|client utr|customer utr|applicant utr|utr number|utr no\.?|utr num|utr #|utr ref(?:erence)?|utr)[\s:.#/\-\x22]*?(\d{10})\b",
                utr_check,
            ),
            (
                PiiKind::UsAbaRouting,
                Language::En,
                r"(?i)(?:aba routing number|aba routing no\.?|aba routing|aba number|aba no\.?|aba #|routing transit number|routing transit no\.?|routing number|routing no\.?|routing #|bank routing number|bank routing no\.?|bank routing|transit number|transit no\.?|transit #|aba rtn|rtn number|rtn no\.?|rtn #|fed routing|fedwire routing|ach routing|wire routing|wire transfer routing|my routing number|your routing number|bank rtn|routing code|aba|rtn)[\s:.#/\-\x22]*?(\d{9})\b",
                aba_check,
            ),
            (
                PiiKind::GbSortCode,
                Language::En,
                r"(?i)(?:sort code|sort-code|sortcode|sort code number|sort code no\.?|sort code #|bank sort code|bank sort|branch sort code|branch sort|branch code|branch number|branch no\.?|branch #|bank code|bank number|bank no\.?|uk sort code|uk sort|bacs sort code|bacs code|my sort code|your sort code|account sort code|account sort)[\s:.#/\-\x22]*?(\d{2}-\d{2}-\d{2})\b",
                sort_code_check,
            ),
            (
                PiiKind::PreciseGeolocation,
                Language::En,
                r"(?i)(?:gps coordinates|gps coordinate|gps coords|gps location|gps position|precise location|precise coordinates|exact location|exact coordinates|location coordinates|map coordinates|position coordinates|geo coordinates|geocoordinates|geo coords|geocoords|latitude/longitude|latitude longitude|lat/long|lat/lon|lat long|lat lon|latlong|latlon|lat lng|latlng|geolocation|geo-location|geo location|geo position|geoposition|map position|map location|current location|current coordinates|current position|device location|device coordinates|device position|my location|my coordinates|my position|coordinates|coordinate|coords)[\s:.#/\-\x22]*?(-?\d{1,3}\.\d{4,},\s?-?\d{1,3}\.\d{4,})",
                geolocation_check,
            ),
            (
                PiiKind::UsAlienNumber,
                Language::En,
                r"(?i)(?:alien registration number|alien registration no\.?|alien registration|alien number|alien no\.?|alien #|a-number|uscis alien number|uscis alien no\.?|uscis number|uscis no\.?|uscis id|uscis #|green card number|green card no\.?|green card #|permanent resident number|permanent resident no\.?|immigration number|immigration no\.?|immigration id|dhs number|dhs no\.?|my a-number|your a-number|applicant a-number)[\s:.#/\-\x22]*?([Aa]\d{7,9})\b",
                a_number_check,
            ),
            (
                PiiKind::UsUscisReceiptNumber,
                Language::En,
                r"(?i)(?:uscis receipt number|uscis receipt no\.?|uscis receipt|uscis case number|uscis case no\.?|uscis case|immigration case number|immigration case no\.?|immigration case|petition receipt number|petition receipt no\.?|petition receipt|application receipt number|application receipt no\.?|application receipt|i-797 receipt|i-797 number|i-797 no\.?|receipt number|receipt no\.?|receipt #|case number|case no\.?|case #|petition number|petition no\.?|petition #|my receipt number|your receipt number|beneficiary receipt|applicant receipt)[\s:.#/\-\x22]*?([A-Za-z]{3}\d{10})\b",
                uscis_receipt_check,
            ),
            (
                PiiKind::ZaId,
                Language::En,
                r"(?i)(?:south african id number|south african id no\.?|south african id|south african identity number|south african identity|sa id number|sa id no\.?|sa id|sa identity number|sa identity|national id number|national id no\.?|national identity number|national identity|id number|id no\.?|id book|id card|identity number|identity no\.?|identity document|identity card|home affairs number|home affairs no\.?|home affairs id|citizen id|citizen number|applicant id|my id|your id)[\s:.#/\-\x22]*?(\d{13})\b",
                sa_id_check,
            ),
            (
                PiiKind::UsDriversLicense,
                Language::En,
                r"(?i)(?:driver'?s?\s*licen[cs]e\s*(?:number|no\.?|num|#)?|driving\s*licen[cs]e\s*(?:number|no\.?|num|#)?|operator'?s?\s*licen[cs]e\s*(?:number|no\.?|num|#)?|state\s*identification\s*(?:number|no\.?|num|#)?|state\s*id\s*(?:number|no\.?|num|#)?|dmv\s*(?:number|no\.?|num|#)|dl\s*(?:number|no\.?|num|#)|my\s*(?:driver'?s?\s*licen[cs]e|dl)|your\s*(?:driver'?s?\s*licen[cs]e|dl)|applicant\s*(?:driver'?s?\s*licen[cs]e|dl)|licen[cs]e\s*(?:number|no\.?|num|#)|dl)[\s:.#/\-\x22]*?([A-Za-z]{1,2}\d{3}(?:-\d{3,4}){1,3}|[A-Za-z]{1,2}\d{4,14})\b",
                us_dl_check,
            ),
            (
                PiiKind::NzNhiNumber,
                Language::En,
                r"(?i)(?:national health index number|national health index no\.?|national health index|nhi number|nhi no\.?|nhi num|nhi #|nhi id|nhi ref(?:erence)?|nhi code|my nhi|your nhi|patient nhi|nhi)[\s:.#/\-\x22]*?([A-HJ-NP-Za-hj-np-z]{3}\d{4})",
                nhi_check,
            ),
            (
                PiiKind::NzDriverLicence,
                Language::En,
                r"(?i)(?:new zealand driver licen[cs]e|nz driver licen[cs]e|nz driving licen[cs]e|driver licen[cs]e|licen[cs]e number|licen[cs]e no\.?|licence num|driving licence)[\s:.#/\-\x22]*?([A-Z]{2}\d{6})\b",
                nz_dl_check,
            ),
            (
                PiiKind::IeDriverNumber,
                Language::En,
                r"(?i)(?:irish driver number|irish driving licen[cs]e|ireland driver number|ireland driving licen[cs]e|ie driver number|ie driving licen[cs]e|driver number|driving licen[cs]e|licen[cs]e number|driver no\.?)[\s:.#/\-\x22]*?(\d{9})\b",
                ie_driver_check,
            ),
            (
                PiiKind::ZaTaxReference,
                Language::En,
                r"(?i)(?:south african tax ref(?:erence)?|south african tax number|sa tax ref(?:erence)?|sa tax number|sars ref(?:erence)?|sars number|sars tax|tax ref(?:erence)?|tax number|tax ref|SARS)[\s:.#/\-\x22]*?([0-3,9]\d{9})\b",
                za_trn_check,
            ),
            (
                PiiKind::CaOhip,
                Language::En,
                r"(?i)(?:ontario health insurance plan|ontario health card|ontario health number|health card number|health card no\.?|health card|health insurance number|health insurance no\.?|health number|carte sant[eé]|OHIP number|OHIP no\.?|OHIP card|OHIP)[\s:.#/\-\x22]*?(\d{10}(?:\s?[A-Za-z]{2})?)\b",
                ohip_check,
            ),
        ];

        let raw_patterns: Vec<(PiiKind, Language, &str, fn(&str) -> bool)> = all_patterns
            .into_iter()
            .filter(|(kind, lang, _, _)| {
                enabled_kinds.contains(kind) && enabled_languages.contains(lang)
            })
            .collect();

        let mut vs_patterns = Vec::with_capacity(raw_patterns.len());
        for (id, (_, _, pat, _)) in raw_patterns.iter().enumerate() {
            vs_patterns.push(Pattern::new(
                pat.as_bytes().to_vec(),
                Flag::UTF8 | Flag::SINGLEMATCH,
                Some(id as u32),
            ));
        }

        let detection_db =
            Box::new(BlockDatabase::new(vs_patterns).map_err(|e| {
                PiiError::HyperscanCompilation(format!("keyword detection db: {e}"))
            })?);
        let detection_prototype = {
            let scanner = BlockScanner::new(&detection_db).expect("scratch alloc");
            // SAFETY: Box guarantees a stable heap address for the database.
            // The prototype (and its clones) hold a reference into the Box.
            // This is sound because: (1) detection_prototype is declared before
            // detection_db so it is dropped first; (2) BlockScanner::drop only
            // frees scratch via hs_free_scratch and does not dereference the
            // database pointer; (3) thread-local clones may outlive the detector
            // but their drop also only frees scratch.
            unsafe { std::mem::transmute::<BlockScanner<'_>, BlockScanner<'static>>(scanner) }
        };

        let patterns = raw_patterns
            .into_iter()
            .map(|(kind, _, pat, validate)| {
                Ok(KeywordPattern {
                    kind,
                    full_regex: Regex::new(pat).map_err(PiiError::RegexCompilation)?,
                    validate,
                })
            })
            .collect::<Result<Vec<_>, PiiError>>()?;

        Ok(Self {
            detection_db,
            detection_prototype,
            patterns,
        })
    }

    #[cfg(test)]
    fn new_all() -> Result<Self, PiiError> {
        let enabled_kinds: HashSet<PiiKind> =
            crate::PiiKind::enabled_for_countries(&crate::Country::all().iter().copied().collect());
        let enabled_languages: HashSet<Language> = crate::Language::all().iter().copied().collect();
        Self::new(&enabled_kinds, &enabled_languages)
    }
}

impl KeywordContextDetector {
    fn with_detection_scanner<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut BlockScanner<'static>) -> R,
    {
        let db_key = &*self.detection_db as *const BlockDatabase as usize;
        KW_DETECTION_CACHE.with(|cell| {
            let mut opt = cell.borrow_mut();
            if opt.as_ref().is_none_or(|(k, _)| *k != db_key) {
                *opt = Some((db_key, self.detection_prototype.clone()));
            }
            f(&mut opt.as_mut().unwrap().1)
        })
    }

    fn scan_matched_ids(&self, input: &str) -> Vec<usize> {
        let mut matched = Vec::new();
        self.with_detection_scanner(|scanner| {
            let _ = scanner.scan(input.as_bytes(), |id, _from, _to, _flags| {
                matched.push(id as usize);
                Scan::Continue
            });
        });
        matched
    }

    fn has_piis_on(&self, input: &str) -> bool {
        let matched_indices = self.scan_matched_ids(input);
        for idx in matched_indices {
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

    fn mark_piis_on(&self, input: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();
        let matched_indices = self.scan_matched_ids(input);
        for idx in matched_indices {
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

impl Detector for KeywordContextDetector {
    fn has_piis(&self, input: &str) -> bool {
        match decode_for_detection(input) {
            Some((decoded, _)) => self.has_piis_on(&decoded),
            None => self.has_piis_on(input),
        }
    }

    fn mark_piis(&self, input: &str) -> Vec<PiiMatch> {
        match decode_for_detection(input) {
            Some((decoded, offset_map)) => self
                .mark_piis_on(&decoded)
                .into_iter()
                .map(|m| PiiMatch {
                    kind: m.kind,
                    start: offset_map[m.start],
                    end: offset_map[m.end],
                })
                .collect(),
            None => self.mark_piis_on(input),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use super::*;
    use test_case::test_case;

    // Global detector for unit tests optimization (otherwise veery slow)
    static DETECTOR: LazyLock<KeywordContextDetector> =
        LazyLock::new(|| KeywordContextDetector::new_all().unwrap());

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
    #[test_case("SA ID: 8001015009087", PiiKind::ZaId, "8001015009087" ; "sa id")]
    #[test_case("identity number: 9506150089081", PiiKind::ZaId, "9506150089081" ; "sa id span")]
    #[test_case("Driver's license: B1234568", PiiKind::UsDriversLicense, "B1234568" ; "us dl 1 letter 7 digits")]
    #[test_case("DL number: W123456789712", PiiKind::UsDriversLicense, "W123456789712" ; "us dl 1 letter 12 digits")]
    #[test_case("License number: AB123456", PiiKind::UsDriversLicense, "AB123456" ; "us dl 2 letters 6 digits")]
    #[test_case("Driver's license number: S530-4000-0001", PiiKind::UsDriversLicense, "S530-4000-0001" ; "us dl hyphenated il")]
    #[test_case("DL: S123-456-789-012", PiiKind::UsDriversLicense, "S123-456-789-012" ; "us dl hyphenated mi")]
    #[test_case("NHI: DAB8745", PiiKind::NzNhiNumber, "DAB8745" ; "nz nhi")]
    #[test_case("NHI number: DAB8745", PiiKind::NzNhiNumber, "DAB8745" ; "nz nhi span")]
    #[test_case("licence number: AB123456", PiiKind::NzDriverLicence, "AB123456" ; "nz dl")]
    #[test_case("driver licence: CD789012", PiiKind::NzDriverLicence, "CD789012" ; "nz dl span")]
    #[test_case("driver number: 123456789", PiiKind::IeDriverNumber, "123456789" ; "ie driver")]
    #[test_case("driving licence: 987654321", PiiKind::IeDriverNumber, "987654321" ; "ie driver span")]
    #[test_case("tax reference: 0123456789", PiiKind::ZaTaxReference, "0123456789" ; "za trn")]
    #[test_case("SARS: 9876543210", PiiKind::ZaTaxReference, "9876543210" ; "za trn sars")]
    #[test_case("OHIP: 1234567897", PiiKind::CaOhip, "1234567897" ; "ca ohip")]
    #[test_case("health card: 1234567897", PiiKind::CaOhip, "1234567897" ; "ca ohip span")]
    fn detects_with_keyword(input: &str, kind: PiiKind, expected_span: &str) {
        let detector = &*DETECTOR;
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
    #[test_case("south african id: 8001015009087" ; "sa id keyword variant 1")]
    #[test_case("sa id: 8001015009087" ; "sa id keyword variant 2")]
    #[test_case("id number: 8001015009087" ; "sa id keyword variant 3")]
    #[test_case("identity number: 8001015009087" ; "sa id keyword variant 4")]
    #[test_case("SA ID: 8001015009087" ; "sa id case upper")]
    #[test_case("sa id: 8001015009087" ; "sa id case lower")]
    #[test_case("Sa Id: 8001015009087" ; "sa id case mixed")]
    #[test_case("SA ID 8001015009087" ; "sa id sep space")]
    #[test_case("SA ID:8001015009087" ; "sa id sep colon")]
    #[test_case("SA ID#8001015009087" ; "sa id sep hash")]
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
    #[test_case("NHI: DAB8745" ; "nz nhi keyword")]
    #[test_case("national health index: DAB8745" ; "nz nhi keyword variant")]
    #[test_case("nhi DAB8745" ; "nz nhi sep space")]
    #[test_case("nhi:DAB8745" ; "nz nhi sep colon")]
    #[test_case("driver licence: AB123456" ; "nz dl keyword")]
    #[test_case("licence number: AB123456" ; "nz dl keyword variant")]
    #[test_case("licence number AB123456" ; "nz dl sep space")]
    #[test_case("licence number:AB123456" ; "nz dl sep colon")]
    #[test_case("driver number: 123456789" ; "ie driver keyword")]
    #[test_case("driving licence: 123456789" ; "ie driver keyword variant")]
    #[test_case("driver number 123456789" ; "ie driver sep space")]
    #[test_case("driver number:123456789" ; "ie driver sep colon")]
    #[test_case("tax reference: 0123456789" ; "za trn keyword")]
    #[test_case("SARS: 9876543210" ; "za trn keyword sars")]
    #[test_case("tax number: 1234567897" ; "za trn keyword variant")]
    #[test_case("tax reference 0123456789" ; "za trn sep space")]
    #[test_case("tax reference:0123456789" ; "za trn sep colon")]
    #[test_case("OHIP: 1234567897" ; "ca ohip keyword")]
    #[test_case("health card: 1234567897" ; "ca ohip keyword variant")]
    #[test_case("health insurance number: 1234567897" ; "ca ohip keyword variant 2")]
    #[test_case("OHIP 1234567897" ; "ca ohip sep space")]
    #[test_case("OHIP:1234567897" ; "ca ohip sep colon")]
    fn has_piis_with_keyword(input: &str) {
        let detector = &*DETECTOR;
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
    #[test_case("SA ID:\n8001015009087" ; "sa id newline")]
    #[test_case("identity number\n8001015009087" ; "sa id keyword newline")]
    #[test_case("SA ID:\t8001015009087" ; "sa id tab")]
    #[test_case("identity number\t8001015009087" ; "sa id keyword tab")]
    #[test_case("SA ID:\r\n8001015009087" ; "sa id crlf")]
    #[test_case("identity number\r\n8001015009087" ; "sa id keyword crlf")]
    #[test_case("Driver's license:\nB1234568" ; "us dl newline")]
    #[test_case("DL number\nB1234568" ; "us dl keyword newline")]
    #[test_case("Driver's license:\tB1234568" ; "us dl tab")]
    #[test_case("DL number\tB1234568" ; "us dl keyword tab")]
    #[test_case("Driver's license:\r\nB1234568" ; "us dl crlf")]
    #[test_case("DL number\r\nB1234568" ; "us dl keyword crlf")]
    #[test_case("NHI:\nDAB8745" ; "nz nhi newline")]
    #[test_case("NHI:\tDAB8745" ; "nz nhi tab")]
    #[test_case("NHI:\r\nDAB8745" ; "nz nhi crlf")]
    #[test_case("licence number:\nAB123456" ; "nz dl newline")]
    #[test_case("licence number:\tAB123456" ; "nz dl tab")]
    #[test_case("licence number:\r\nAB123456" ; "nz dl crlf")]
    #[test_case("driver number:\n123456789" ; "ie driver newline")]
    #[test_case("driver number:\t123456789" ; "ie driver tab")]
    #[test_case("driver number:\r\n123456789" ; "ie driver crlf")]
    #[test_case("tax reference:\n0123456789" ; "za trn newline")]
    #[test_case("tax reference:\t0123456789" ; "za trn tab")]
    #[test_case("tax reference:\r\n0123456789" ; "za trn crlf")]
    #[test_case("OHIP:\n1234567897" ; "ca ohip newline")]
    #[test_case("OHIP:\t1234567897" ; "ca ohip tab")]
    #[test_case("OHIP:\r\n1234567897" ; "ca ohip crlf")]
    fn has_piis_with_whitespace_separator(input: &str) {
        let detector = &*DETECTOR;
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
    #[test_case("SA ID: 8013015009087", PiiKind::ZaId ; "sa id invalid month")]
    #[test_case("SA ID: 8001325009087", PiiKind::ZaId ; "sa id invalid day")]
    #[test_case("SA ID: 8001015009086", PiiKind::ZaId ; "sa id failing luhn")]
    #[test_case("DL: B123", PiiKind::UsDriversLicense ; "us dl too few digits")]
    #[test_case("passport: 12345678", PiiKind::PassportNumber ; "passportnum 8 digits")]
    #[test_case("passport: 1234567897", PiiKind::PassportNumber ; "passportnum 10 digits")]
    #[test_case("NHI: DAI5765", PiiKind::NzNhiNumber ; "nz nhi letter I")]
    #[test_case("NHI: DAO5765", PiiKind::NzNhiNumber ; "nz nhi letter O")]
    #[test_case("NHI: DAB8740", PiiKind::NzNhiNumber ; "nz nhi bad check digit")]
    #[test_case("licence number: A1234567", PiiKind::NzDriverLicence ; "nz dl 1 letter")]
    #[test_case("licence number: ABC12345", PiiKind::NzDriverLicence ; "nz dl 3 letters")]
    #[test_case("driver number: 12345678", PiiKind::IeDriverNumber ; "ie driver 8 digits")]
    #[test_case("driver number: 1234567897", PiiKind::IeDriverNumber ; "ie driver 10 digits")]
    #[test_case("tax reference: 4123456789", PiiKind::ZaTaxReference ; "za trn invalid first digit 4")]
    #[test_case("tax reference: 5123456789", PiiKind::ZaTaxReference ; "za trn invalid first digit 5")]
    #[test_case("OHIP: 1234567898", PiiKind::CaOhip ; "ca ohip bad luhn")]
    fn rejects_invalid_with_keyword(input: &str, kind: PiiKind) {
        let detector = &*DETECTOR;
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
    #[test_case("number is 8001015009087", PiiKind::ZaId ; "sa id no keyword")]
    #[test_case("code is B1234568", PiiKind::UsDriversLicense ; "us dl no keyword")]
    #[test_case("code is DAB8745", PiiKind::NzNhiNumber ; "nz nhi no keyword")]
    #[test_case("code is AB123456", PiiKind::NzDriverLicence ; "nz dl no keyword")]
    #[test_case("code is 123456789", PiiKind::IeDriverNumber ; "ie driver no keyword")]
    #[test_case("code is 0123456789", PiiKind::ZaTaxReference ; "za trn no keyword")]
    #[test_case("code is 1234567897", PiiKind::CaOhip ; "ca ohip no keyword")]
    fn no_detection_without_keyword(input: &str, kind: PiiKind) {
        let detector = &*DETECTOR;
        let matches = detector.mark_piis(input);
        assert!(
            matches.iter().all(|m| m.kind != kind),
            "should not detect {kind:?} without keyword in: {input}"
        );
    }

    // --- Special cases kept as individual tests ---

    #[test]
    fn geolocation_with_space_after_comma() {
        let detector = &*DETECTOR;
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
        let detector = &*DETECTOR;
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
    #[test_case(r#"{"citizen": {"id number": "8001015009087", "province": "Gauteng"}}"#, PiiKind::ZaId, "8001015009087" ; "sa id in json")]
    #[test_case(r#"{"identity": {"license number": "B1234568", "state": "CA"}}"#, PiiKind::UsDriversLicense, "B1234568" ; "us dl in json")]
    #[test_case(r#"{"patient": {"NHI": "DAB8745", "ward": "B2"}}"#, PiiKind::NzNhiNumber, "DAB8745" ; "nz nhi in json")]
    #[test_case(r#"{"driver": {"licence number": "AB123456", "expiry": "2028"}}"#, PiiKind::NzDriverLicence, "AB123456" ; "nz dl in json")]
    #[test_case(r#"{"driver": {"driver number": "123456789", "country": "IE"}}"#, PiiKind::IeDriverNumber, "123456789" ; "ie driver in json")]
    #[test_case(r#"{"tax": {"tax reference": "0123456789", "year": "2025"}}"#, PiiKind::ZaTaxReference, "0123456789" ; "za trn in json")]
    #[test_case(r#"{"health": {"OHIP": "1234567897", "province": "ON"}}"#, PiiKind::CaOhip, "1234567897" ; "ca ohip in json")]
    fn detects_in_json(input: &str, kind: PiiKind, expected_span: &str) {
        let detector = &*DETECTOR;
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
        let detector = &*DETECTOR;
        let input =
            r#"{"employee": {"EIN": "12-3456789", "UTR": "5555555555", "TFN": "123 456 782"}}"#;
        let matches = detector.mark_piis(input);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::UsEin));
        assert!(kinds.contains(&PiiKind::GbUtr));
        assert!(kinds.contains(&PiiKind::AuTfn));
    }

    // --- URL-encoded input tests ---

    #[test_case("phone%3A 555-123-4567", PiiKind::PhoneNumber, "555-123-4567" ; "url phone sep colon")]
    #[test_case("phone%3A%20555-123-4567", PiiKind::PhoneNumber, "555-123-4567" ; "url phone sep colon space")]
    #[test_case("phone%20number%3A 555-123-4567", PiiKind::PhoneNumber, "555-123-4567" ; "url phone keyword space")]
    #[test_case("passport%3A 123456789", PiiKind::PassportNumber, "123456789" ; "url passport sep")]
    #[test_case("TFN%3A 123 456 782", PiiKind::AuTfn, "123 456 782" ; "url tfn sep")]
    #[test_case("EIN%3A 12-3456789", PiiKind::UsEin, "12-3456789" ; "url ein sep")]
    #[test_case("SWIFT%3A DEUTDEFF", PiiKind::SwiftBic, "DEUTDEFF" ; "url swift sep")]
    #[test_case("sort%20code%3A 20-00-00", PiiKind::GbSortCode, "20-00-00" ; "url sort code keyword")]
    #[test_case("coordinates%3A 40.7128,-74.0060", PiiKind::PreciseGeolocation, "40.7128,-74.0060" ; "url geolocation sep")]
    #[test_case("IMEI%3A 490154203237518", PiiKind::Imei, "490154203237518" ; "url imei sep")]
    #[test_case("UTR%3A 5555555555", PiiKind::GbUtr, "5555555555" ; "url utr sep")]
    #[test_case("NHS%3A 943 476 5919", PiiKind::GbNhsNumber, "943 476 5919" ; "url nhs sep")]
    #[test_case("Medicare%3A 2123 45670 1", PiiKind::AuMedicare, "2123 45670 1" ; "url medicare sep")]
    #[test_case("IRD%3A 49-091-857", PiiKind::NzIrdNumber, "49-091-857" ; "url ird sep")]
    #[test_case("routing%20number%3A 021000021", PiiKind::UsAbaRouting, "021000021" ; "url aba keyword")]
    #[test_case("alien%20number%3A A012345678", PiiKind::UsAlienNumber, "A012345678" ; "url alien number keyword")]
    #[test_case("receipt%20number%3A SRC2190000001", PiiKind::UsUscisReceiptNumber, "SRC2190000001" ; "url uscis receipt keyword")]
    #[test_case("SA%20ID%3A 8001015009087", PiiKind::ZaId, "8001015009087" ; "url sa id keyword")]
    #[test_case("DL%3A B1234568", PiiKind::UsDriversLicense, "B1234568" ; "url us dl sep")]
    #[test_case("NHI%3A DAB8745", PiiKind::NzNhiNumber, "DAB8745" ; "url nz nhi sep")]
    #[test_case("licence%20number%3A AB123456", PiiKind::NzDriverLicence, "AB123456" ; "url nz dl keyword")]
    #[test_case("driver%20number%3A 123456789", PiiKind::IeDriverNumber, "123456789" ; "url ie driver keyword")]
    #[test_case("tax%20reference%3A 0123456789", PiiKind::ZaTaxReference, "0123456789" ; "url za trn keyword")]
    #[test_case("OHIP%3A 1234567897", PiiKind::CaOhip, "1234567897" ; "url ca ohip sep")]
    fn detects_url_encoded(input: &str, kind: PiiKind, expected_span: &str) {
        let detector = &*DETECTOR;
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

    // --- HTML entity input tests ---

    #[test_case("phone&#58; 555-123-4567", PiiKind::PhoneNumber, "555-123-4567" ; "html phone decimal colon")]
    #[test_case("phone&colon; 555-123-4567", PiiKind::PhoneNumber, "555-123-4567" ; "html phone named colon")]
    #[test_case("phone&#x3A; 555-123-4567", PiiKind::PhoneNumber, "555-123-4567" ; "html phone hex colon")]
    #[test_case("phone&nbsp;number: 555-123-4567", PiiKind::PhoneNumber, "555-123-4567" ; "html phone nbsp keyword")]
    #[test_case("passport&#58; 123456789", PiiKind::PassportNumber, "123456789" ; "html passport colon")]
    #[test_case("EIN&colon; 12-3456789", PiiKind::UsEin, "12-3456789" ; "html ein named colon")]
    #[test_case("SWIFT&#58; DEUTDEFF", PiiKind::SwiftBic, "DEUTDEFF" ; "html swift colon")]
    #[test_case("sort&nbsp;code: 20-00-00", PiiKind::GbSortCode, "20-00-00" ; "html sort code nbsp")]
    #[test_case("coordinates&#58; 40.7128,-74.0060", PiiKind::PreciseGeolocation, "40.7128,-74.0060" ; "html geolocation colon")]
    #[test_case("phone&#58;&#32;555-123-4567", PiiKind::PhoneNumber, "555-123-4567" ; "html phone colon and space")]
    #[test_case("NHS&#58; 943 476 5919", PiiKind::GbNhsNumber, "943 476 5919" ; "html nhs colon")]
    #[test_case("UTR&colon; 5555555555", PiiKind::GbUtr, "5555555555" ; "html utr named colon")]
    #[test_case("IMEI&#x3a; 490154203237518", PiiKind::Imei, "490154203237518" ; "html imei hex colon lowercase")]
    #[test_case("alien&nbsp;number: A012345678", PiiKind::UsAlienNumber, "A012345678" ; "html alien number nbsp")]
    #[test_case("NHI&#58; DAB8745", PiiKind::NzNhiNumber, "DAB8745" ; "html nz nhi colon")]
    #[test_case("OHIP&#58; 1234567897", PiiKind::CaOhip, "1234567897" ; "html ca ohip colon")]
    fn detects_html_entities(input: &str, kind: PiiKind, expected_span: &str) {
        let detector = &*DETECTOR;
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

    // --- has_piis with encoded input ---

    #[test_case("phone%3A 555-123-4567" ; "url encoded has_piis")]
    #[test_case("phone&#58; 555-123-4567" ; "html entity has_piis")]
    #[test_case("phone&colon; 555-123-4567" ; "html named entity has_piis")]
    #[test_case("TFN%3A%20123%20456%20782" ; "url fully encoded has_piis")]
    fn has_piis_with_encoded_input(input: &str) {
        let detector = &*DETECTOR;
        assert!(detector.has_piis(input), "should detect PII in: {input}");
    }

    // --- Encoded values (span includes encoded form) ---

    #[test]
    fn url_encoded_value_hyphens() {
        let detector = &*DETECTOR;
        let input = "EIN%3A 12%2D3456789";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::UsEin)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "12%2D3456789");
    }

    #[test]
    fn html_entity_value_hyphens() {
        let detector = &*DETECTOR;
        let input = "EIN&#58; 12&#45;3456789";
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::UsEin)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "12&#45;3456789");
    }

    // --- No false positives from partial encoding ---

    #[test]
    fn no_detection_partial_percent_encoding() {
        let detector = &*DETECTOR;
        // %ZZ is not valid percent encoding, should not be decoded
        let input = "phone%ZZ 555-123-4567";
        assert!(
            !detector.has_piis(input),
            "should not detect PII with invalid encoding: {input}"
        );
    }
}
