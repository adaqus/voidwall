use std::cell::RefCell;
use std::collections::HashSet;

use regex::Regex;
use vectorscan_rs::{BlockDatabase, BlockScanner, Flag, Pattern, Scan};

use crate::Language;
use crate::detector::Detector;
use crate::normalize::decode_for_detection;
use crate::validators::{
    a_number_check, aba_check, always_valid, at_postal_check, at_svnr_check, au_abn_check,
    au_dl_check, ch_ahv_check, ch_postal_check, de_at_address_check, de_at_postfach_check,
    de_packstation_check, de_personalausweis_check, de_postal_check, de_steuer_id_check, dob_check,
    ein_check, fr_ch_address_check, fr_ch_boite_postale_check, fr_nif_check, fr_postal_check,
    geolocation_check, ie_driver_check, imei_check, ird_check, medicare_check, nhi_check,
    nhs_check, nir_check, nz_dl_check, ohip_check, passport_check, passport_new_check,
    person_name_check, phone_check, siren_luhn_check, siret_luhn_check, sort_code_check,
    swift_bic_check, tfn_check, us_dl_check, uscis_receipt_check, utr_check, za_luhn13_check,
    za_postal_check, za_trn_check,
};
use crate::{PiiError, PiiKind, PiiMatch};

thread_local! {
    static KW_DETECTION_CACHE: RefCell<Option<(usize, BlockScanner<'static>)>>
        = const { RefCell::new(None) };
}

struct KeywordPattern {
    kind: PiiKind,
    value_regex: Regex,
    validate: fn(&str) -> bool,
}

/// Extract the capture-group content from a keyword pattern string.
/// Most patterns follow `(?i)(?:keywords)SEPARATOR(value)\b?`.
/// Returns just the inner `value` portion (without outer parens).
fn extract_value_expr(pattern: &str) -> &str {
    // Find the last top-level capturing group: `(` not followed by `?`.
    let bytes = pattern.as_bytes();
    let mut group_start = None;
    let mut depth = 0i32;
    for (i, &b) in bytes.iter().enumerate() {
        let escaped = i > 0 && bytes[i - 1] == b'\\';
        if b == b'(' && !escaped {
            if depth == 0 && bytes.get(i + 1) != Some(&b'?') {
                group_start = Some(i);
            }
            depth += 1;
        } else if b == b')' && !escaped {
            depth -= 1;
        }
    }
    let start = group_start.expect("pattern has no capture group");
    // Find matching close paren from `start`.
    let mut depth = 0i32;
    let mut close = 0;
    for (i, &b) in bytes[start..].iter().enumerate() {
        let escaped = i > 0 && bytes[start + i - 1] == b'\\';
        if b == b'(' && !escaped {
            depth += 1;
        } else if b == b')' && !escaped {
            depth -= 1;
            if depth == 0 {
                close = start + i;
                break;
            }
        }
    }
    &pattern[start + 1..close]
}

pub struct KeywordContextDetector {
    detection_db: Option<Box<BlockDatabase>>,
    detection_prototype: Option<BlockScanner<'static>>,
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
                r"(?i)(?:australian[\s_]tax[\s_]file[\s_]number|australian[\s_]tfn|aus[\s_]tfn|ato[\s_]tax[\s_]file[\s_]number|ato[\s_]tfn|individual[\s_]tax[\s_]file[\s_]number|tax[\s_]file[\s_]number|tax[\s_]file[\s_]no\.?|tax[\s_]file[\s_]num|tax[\s_]file[\s_]#|tax[\s_]file[\s_]ref(?:erence)?|tax[\s_]file[\s_]identifier|applicant[\s_]tfn|employee[\s_]tfn|client[\s_]tfn|customer[\s_]tfn|my[\s_]tfn|your[\s_]tfn|tfn[\s_]number|tfn[\s_]no\.?|tfn[\s_]num|tfn)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{3}\s\d{3}\s\d{3})",
                tfn_check,
            ),
            (
                PiiKind::NzIrdNumber,
                Language::En,
                r"(?i)(?:inland[\s_]revenue[\s_]dep(?:artmen)?t|inland[\s_]revenue[\s_]number|inland[\s_]revenue[\s_]no\.?|new[\s_]zealand[\s_]ird|new[\s_]zealand[\s_]tax[\s_]number|new[\s_]zealand[\s_]tax[\s_]id|nz[\s_]ird|nz[\s_]tax[\s_]number|nz[\s_]tax[\s_]id|ird[\s_]number[\s_]nz|ird[\s_]number|ird[\s_]no\.?|ird[\s_]num|ird[\s_]#|ird[\s_]ref(?:erence)?|applicant[\s_]ird|employee[\s_]ird|client[\s_]ird|customer[\s_]ird|my[\s_]ird|your[\s_]ird|gst[\s_]registration|gst[\s_]number|gst[\s_]no\.?|tax[\s_]number[\s_]nz|ird)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{2,3}-\d{3}-\d{3})",
                ird_check,
            ),
            (
                PiiKind::GbNhsNumber,
                Language::En,
                r"(?i)(?:national[\s_]health[\s_]service[\s_]number|national[\s_]health[\s_]service[\s_]no\.?|nhs[\s_]patient[\s_]number|nhs[\s_]patient[\s_]id|nhs[\s_]patient[\s_]no\.?|nhs[\s_]record[\s_]number|nhs[\s_]registration|nhs[\s_]identifier|nhs[\s_]number|nhs[\s_]no\.?|nhs[\s_]num|nhs[\s_]#|nhs[\s_]id|nhs[\s_]ref(?:erence)?|nhs[\s_]record|health[\s_]service[\s_]number|health[\s_]service[\s_]no\.?|health[\s_]index[\s_]number|health[\s_]id|patient[\s_]number|patient[\s_]no\.?|patient[\s_]id|my[\s_]nhs[\s_]number|your[\s_]nhs[\s_]number|chi[\s_]number|h&c[\s_]number|hc[\s_]number|nhs)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{3}\s\d{3}\s\d{4})",
                nhs_check,
            ),
            (
                PiiKind::AuMedicare,
                Language::En,
                r"(?i)(?:medicare[\s_]card[\s_]number|medicare[\s_]card[\s_]no\.?|medicare[\s_]card|australian[\s_]medicare|medicare[\s_]enrol(?:l)?ment|medicare[\s_]registration|medicare[\s_]identifier|medicare[\s_]number|medicare[\s_]no\.?|medicare[\s_]num|medicare[\s_]#|medicare[\s_]id|medicare[\s_]ref(?:erence)?|medicare[\s_]patient|aus[\s_]medicare|au[\s_]medicare|applicant[\s_]medicare|employee[\s_]medicare|client[\s_]medicare|customer[\s_]medicare|my[\s_]medicare|your[\s_]medicare|medicare|irn)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{4}\s\d{5}\s\d)",
                medicare_check,
            ),
            (
                PiiKind::PhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_]number|phone[\s_]no\.?|phone[\s_]num|phone[\s_]#|telephone[\s_]number|telephone[\s_]no\.?|telephone|mobile[\s_]number|mobile[\s_]no\.?|mobile[\s_]phone|mobile|cell[\s_]phone|cell[\s_]number|cell|contact[\s_]number|contact[\s_]no\.?|contact[\s_]phone|callback[\s_]number|callback[\s_]no\.?|callback|fax[\s_]number|fax[\s_]no\.?|fax|tel[\s_]number|tel[\s_]no\.?|tel|landline|home[\s_]phone|work[\s_]phone|office[\s_]phone|alternate[\s_]phone|alt[\s_]phone|my[\s_]phone|your[\s_]phone|customer[\s_]phone|applicant[\s_]phone|phone)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)((?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})",
                phone_check,
            ),
            (
                PiiKind::PassportNumber,
                Language::En,
                r"(?i)(?:united[\s_]states[\s_]passport|passport[\s_]book[\s_]number|passport[\s_]book[\s_]no\.?|passport[\s_]card[\s_]number|us[\s_]passport[\s_]number|us[\s_]passport[\s_]no\.?|american[\s_]passport|travel[\s_]document[\s_]number|travel[\s_]document[\s_]no\.?|travel[\s_]doc[\s_]number|travel[\s_]doc[\s_]no\.?|passport[\s_]number|passport[\s_]no\.?|passport[\s_]num|passport[\s_]#|passport[\s_]id|passport[\s_]card|us[\s_]passport|travel[\s_]doc|applicant[\s_]passport|my[\s_]passport|your[\s_]passport|document[\s_]number|document[\s_]no\.?|doc[\s_]number|doc[\s_]no\.?|passport)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{9})\b",
                passport_check,
            ),
            (
                PiiKind::UsPassportNew,
                Language::En,
                r"(?i)(?:united[\s_]states[\s_]passport|passport[\s_]book[\s_]number|passport[\s_]book[\s_]no\.?|passport[\s_]card[\s_]number|us[\s_]passport[\s_]number|us[\s_]passport[\s_]no\.?|american[\s_]passport|travel[\s_]document[\s_]number|travel[\s_]document[\s_]no\.?|travel[\s_]doc[\s_]number|travel[\s_]doc[\s_]no\.?|passport[\s_]number|passport[\s_]no\.?|passport[\s_]num|passport[\s_]#|passport[\s_]id|passport[\s_]card|us[\s_]passport|travel[\s_]doc|applicant[\s_]passport|my[\s_]passport|your[\s_]passport|document[\s_]number|document[\s_]no\.?|doc[\s_]number|doc[\s_]no\.?|passport)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([AXYZaxyz]\d{8})",
                passport_new_check,
            ),
            (
                PiiKind::SwiftBic,
                Language::En,
                r"(?i)(?:bank[\s_]identifier[\s_]code|bank[\s_]identifier|correspondent[\s_](?:bank[\s_])?swift|intermediary[\s_]swift|intermediary[\s_]bic|international[\s_]bank[\s_]code|beneficiary[\s_]swift|beneficiary[\s_]bic|swift/bic|swift[\s_]bic|bic/swift|swift[\s_]code|swift[\s_]number|swift[\s_]no\.?|swift[\s_]#|swift[\s_]address|swift[\s_]id|bank[\s_]swift|bank[\s_]routing|bank[\s_]bic|bic[\s_]code|bic[\s_]number|bic[\s_]no\.?|bic[\s_]#|bic[\s_]id|routing[\s_]code|clearing[\s_]code|my[\s_]swift|swift|bic)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?)\b",
                swift_bic_check,
            ),
            (
                PiiKind::UsEin,
                Language::En,
                r"(?i)(?:employer[\s_]identification[\s_]number|employer[\s_]identification[\s_]no\.?|federal[\s_]employer[\s_]identification|employer[\s_]id[\s_]number|employer[\s_]id[\s_]no\.?|federal[\s_]employer[\s_]id|federal[\s_]tax[\s_]identification|tax[\s_]identification[\s_]number|federal[\s_]id[\s_]number|federal[\s_]id[\s_]no\.?|federal[\s_]tax[\s_]id|federal[\s_]ein|tax[\s_]id[\s_]number|employer[\s_]number|employer[\s_]no\.?|business[\s_]tax[\s_]id|company[\s_]tax[\s_]id|company[\s_]ein|irs[\s_]employer[\s_]id|applicant[\s_]ein|ein[\s_]number|ein[\s_]no\.?|ein[\s_]num|ein[\s_]#|tax[\s_]id|irs[\s_]ein|our[\s_]ein|my[\s_]ein|fein|ein)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{2}-\d{7})",
                ein_check,
            ),
            (
                PiiKind::Imei,
                Language::En,
                r"(?i)(?:international[\s_]mobile[\s_]equipment[\s_]identity|mobile[\s_]equipment[\s_]identity|equipment[\s_]identity|device[\s_]identifier|device[\s_]id[\s_]number|device[\s_]serial|device[\s_]imei|handset[\s_]imei|serial[\s_]imei|mobile[\s_]imei|tablet[\s_]imei|equipment[\s_]id|phone[\s_]imei|imei[\s_]identifier|imei[\s_]number|imei[\s_]no\.?|imei[\s_]num|imei[\s_]#|imei[\s_]code|imei[\s_]id|your[\s_]imei|my[\s_]imei|meid|imei)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{2}-?\d{6}-?\d{6}-?\d)",
                imei_check,
            ),
            (
                PiiKind::GbUtr,
                Language::En,
                r"(?i)(?:unique[\s_]taxpayer[\s_]ref(?:erence)?|unique[\s_]tax[\s_]ref(?:erence)?|taxpayer[\s_]ref(?:erence)?|tax[\s_]ref(?:erence)?|hmrc[\s_]ref(?:erence)?|hmrc[\s_]utr|self[\s_]assessment[\s_]ref(?:erence)?|self[\s_]assessment[\s_]utr|self[\s_]assessment[\s_]number|self[\s_]assessment[\s_]no\.?|sa[\s_]utr|sa[\s_]ref(?:erence)?|sa[\s_]number|sa[\s_]no\.?|corporation[\s_]tax[\s_]ref(?:erence)?|corporation[\s_]tax[\s_]utr|ct[\s_]utr|ct[\s_]ref(?:erence)?|company[\s_]utr|company[\s_]tax[\s_]ref(?:erence)?|partnership[\s_]utr|partnership[\s_]ref(?:erence)?|your[\s_]utr|my[\s_]utr|client[\s_]utr|customer[\s_]utr|applicant[\s_]utr|utr[\s_]number|utr[\s_]no\.?|utr[\s_]num|utr[\s_]#|utr[\s_]ref(?:erence)?|utr)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{10})\b",
                utr_check,
            ),
            (
                PiiKind::UsAbaRouting,
                Language::En,
                r"(?i)(?:aba[\s_]routing[\s_]number|aba[\s_]routing[\s_]no\.?|aba[\s_]routing|aba[\s_]number|aba[\s_]no\.?|aba[\s_]#|routing[\s_]transit[\s_]number|routing[\s_]transit[\s_]no\.?|routing[\s_]number|routing[\s_]no\.?|routing[\s_]#|bank[\s_]routing[\s_]number|bank[\s_]routing[\s_]no\.?|bank[\s_]routing|transit[\s_]number|transit[\s_]no\.?|transit[\s_]#|aba[\s_]rtn|rtn[\s_]number|rtn[\s_]no\.?|rtn[\s_]#|fed[\s_]routing|fedwire[\s_]routing|ach[\s_]routing|wire[\s_]routing|wire[\s_]transfer[\s_]routing|my[\s_]routing[\s_]number|your[\s_]routing[\s_]number|bank[\s_]rtn|routing[\s_]code|aba|rtn)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{9})\b",
                aba_check,
            ),
            (
                PiiKind::GbSortCode,
                Language::En,
                r"(?i)(?:sort[\s_]code|sort-code|sortcode|sort[\s_]code[\s_]number|sort[\s_]code[\s_]no\.?|sort[\s_]code[\s_]#|bank[\s_]sort[\s_]code|bank[\s_]sort|branch[\s_]sort[\s_]code|branch[\s_]sort|branch[\s_]code|branch[\s_]number|branch[\s_]no\.?|branch[\s_]#|bank[\s_]code|bank[\s_]number|bank[\s_]no\.?|uk[\s_]sort[\s_]code|uk[\s_]sort|bacs[\s_]sort[\s_]code|bacs[\s_]code|my[\s_]sort[\s_]code|your[\s_]sort[\s_]code|account[\s_]sort[\s_]code|account[\s_]sort)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{2}-\d{2}-\d{2})\b",
                sort_code_check,
            ),
            (
                PiiKind::PreciseGeolocation,
                Language::En,
                r"(?i)(?:gps[\s_]coordinates|gps[\s_]coordinate|gps[\s_]coords|gps[\s_]location|gps[\s_]position|precise[\s_]location|precise[\s_]coordinates|exact[\s_]location|exact[\s_]coordinates|location[\s_]coordinates|map[\s_]coordinates|position[\s_]coordinates|geo[\s_]coordinates|geocoordinates|geo[\s_]coords|geocoords|latitude/longitude|latitude[\s_]longitude|lat/long|lat/lon|lat[\s_]long|lat[\s_]lon|latlong|latlon|lat[\s_]lng|latlng|geolocation|geo-location|geo[\s_]location|geo[\s_]position|geoposition|map[\s_]position|map[\s_]location|current[\s_]location|current[\s_]coordinates|current[\s_]position|device[\s_]location|device[\s_]coordinates|device[\s_]position|my[\s_]location|my[\s_]coordinates|my[\s_]position|coordinates|coordinate|coords)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(-?\d{1,3}\.\d{4,},\s?-?\d{1,3}\.\d{4,})",
                geolocation_check,
            ),
            (
                PiiKind::UsAlienNumber,
                Language::En,
                r"(?i)(?:alien[\s_]registration[\s_]number|alien[\s_]registration[\s_]no\.?|alien[\s_]registration|alien[\s_]number|alien[\s_]no\.?|alien[\s_]#|a-number|uscis[\s_]alien[\s_]number|uscis[\s_]alien[\s_]no\.?|uscis[\s_]number|uscis[\s_]no\.?|uscis[\s_]id|uscis[\s_]#|green[\s_]card[\s_]number|green[\s_]card[\s_]no\.?|green[\s_]card[\s_]#|permanent[\s_]resident[\s_]number|permanent[\s_]resident[\s_]no\.?|immigration[\s_]number|immigration[\s_]no\.?|immigration[\s_]id|dhs[\s_]number|dhs[\s_]no\.?|my[\s_]a-number|your[\s_]a-number|applicant[\s_]a-number)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([Aa]\d{7,9})\b",
                a_number_check,
            ),
            (
                PiiKind::UsUscisReceiptNumber,
                Language::En,
                r"(?i)(?:uscis[\s_]receipt[\s_]number|uscis[\s_]receipt[\s_]no\.?|uscis[\s_]receipt|uscis[\s_]case[\s_]number|uscis[\s_]case[\s_]no\.?|uscis[\s_]case|immigration[\s_]case[\s_]number|immigration[\s_]case[\s_]no\.?|immigration[\s_]case|petition[\s_]receipt[\s_]number|petition[\s_]receipt[\s_]no\.?|petition[\s_]receipt|application[\s_]receipt[\s_]number|application[\s_]receipt[\s_]no\.?|application[\s_]receipt|i-797[\s_]receipt|i-797[\s_]number|i-797[\s_]no\.?|receipt[\s_]number|receipt[\s_]no\.?|receipt[\s_]#|case[\s_]number|case[\s_]no\.?|case[\s_]#|petition[\s_]number|petition[\s_]no\.?|petition[\s_]#|my[\s_]receipt[\s_]number|your[\s_]receipt[\s_]number|beneficiary[\s_]receipt|applicant[\s_]receipt)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-Za-z]{3}\d{10})\b",
                uscis_receipt_check,
            ),
            (
                PiiKind::ZaId,
                Language::En,
                r"(?i)(?:south[\s_]african[\s_]id[\s_]number|south[\s_]african[\s_]id[\s_]no\.?|south[\s_]african[\s_]id|south[\s_]african[\s_]identity[\s_]number|south[\s_]african[\s_]identity|sa[\s_]id[\s_]number|sa[\s_]id[\s_]no\.?|sa[\s_]id|sa[\s_]identity[\s_]number|sa[\s_]identity|national[\s_]id[\s_]number|national[\s_]id[\s_]no\.?|national[\s_]identity[\s_]number|national[\s_]identity|id[\s_]number|id[\s_]no\.?|id[\s_]book|id[\s_]card|identity[\s_]number|identity[\s_]no\.?|identity[\s_]document|identity[\s_]card|home[\s_]affairs[\s_]number|home[\s_]affairs[\s_]no\.?|home[\s_]affairs[\s_]id|citizen[\s_]id|citizen[\s_]number|applicant[\s_]id|my[\s_]id|your[\s_]id)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{13})\b",
                za_luhn13_check,
            ),
            (
                PiiKind::UsDriversLicense,
                Language::En,
                r"(?i)(?:driver'?s?\s*licen[cs]e\s*(?:number|no\.?|num|#)?|driving\s*licen[cs]e\s*(?:number|no\.?|num|#)?|operator'?s?\s*licen[cs]e\s*(?:number|no\.?|num|#)?|state\s*identification\s*(?:number|no\.?|num|#)?|state\s*id\s*(?:number|no\.?|num|#)?|dmv\s*(?:number|no\.?|num|#)|dl\s*(?:number|no\.?|num|#)|my\s*(?:driver'?s?\s*licen[cs]e|dl)|your\s*(?:driver'?s?\s*licen[cs]e|dl)|applicant\s*(?:driver'?s?\s*licen[cs]e|dl)|licen[cs]e\s*(?:number|no\.?|num|#)|dl)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-Za-z]{1,2}\d{3}(?:-\d{3,4}){1,3}|[A-Za-z]{1,2}\d{4,14})\b",
                us_dl_check,
            ),
            (
                PiiKind::NzNhiNumber,
                Language::En,
                r"(?i)(?:national[\s_]health[\s_]index[\s_]number|national[\s_]health[\s_]index[\s_]no\.?|national[\s_]health[\s_]index|nhi[\s_]number|nhi[\s_]no\.?|nhi[\s_]num|nhi[\s_]#|nhi[\s_]id|nhi[\s_]ref(?:erence)?|nhi[\s_]code|my[\s_]nhi|your[\s_]nhi|patient[\s_]nhi|nhi)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-HJ-NP-Za-hj-np-z]{3}\d{4})",
                nhi_check,
            ),
            (
                PiiKind::NzDriverLicence,
                Language::En,
                r"(?i)(?:new[\s_]zealand[\s_]driver[\s_]licen[cs]e|nz[\s_]driver[\s_]licen[cs]e|nz[\s_]driving[\s_]licen[cs]e|driver[\s_]licen[cs]e|licen[cs]e[\s_]number|licen[cs]e[\s_]no\.?|licence[\s_]num|driving[\s_]licence)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-Z]{2}\d{6})\b",
                nz_dl_check,
            ),
            (
                PiiKind::IeDriverNumber,
                Language::En,
                r"(?i)(?:irish[\s_]driver[\s_]number|irish[\s_]driving[\s_]licen[cs]e|ireland[\s_]driver[\s_]number|ireland[\s_]driving[\s_]licen[cs]e|ie[\s_]driver[\s_]number|ie[\s_]driving[\s_]licen[cs]e|driver[\s_]number|driving[\s_]licen[cs]e|licen[cs]e[\s_]number|driver[\s_]no\.?)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{9})\b",
                ie_driver_check,
            ),
            (
                PiiKind::ZaTaxReference,
                Language::En,
                r"(?i)(?:south[\s_]african[\s_]tax[\s_]ref(?:erence)?|south[\s_]african[\s_]tax[\s_]number|sa[\s_]tax[\s_]ref(?:erence)?|sa[\s_]tax[\s_]number|sars[\s_]ref(?:erence)?|sars[\s_]number|sars[\s_]tax|tax[\s_]ref(?:erence)?|tax[\s_]number|tax[\s_]ref|SARS)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([0-3,9]\d{9})\b",
                za_trn_check,
            ),
            (
                PiiKind::ZaDriversLicense,
                Language::En,
                r"(?i)(?:south[\s_]african[\s_]driver'?s?[\s_]licen[cs]e|sa[\s_]driver'?s?[\s_]licen[cs]e|driver'?s?[\s_]licen[cs]e[\s_]number|driver'?s?[\s_]licen[cs]e[\s_]no\.?|driver'?s?[\s_]licen[cs]e|driving[\s_]licen[cs]e[\s_]number|driving[\s_]licen[cs]e[\s_]no\.?|driving[\s_]licen[cs]e|learner'?s?[\s_]licen[cs]e)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{13})\b",
                za_luhn13_check,
            ),
            (
                PiiKind::ZaPostalCode,
                Language::En,
                r"(?i)(?:postal[\s_]code|post[\s_]code|postcode|zip[\s_]code|zip)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{4})\b",
                za_postal_check,
            ),
            (
                PiiKind::AuDriversLicense,
                Language::En,
                r"(?i)(?:australian[\s_]driver'?s?[\s_]licen[cs]e|aus[\s_]driver'?s?[\s_]licen[cs]e|nsw[\s_]licen[cs]e|vic[\s_]licen[cs]e|qld[\s_]licen[cs]e|wa[\s_]licen[cs]e|act[\s_]licen[cs]e|sa[\s_]licen[cs]e|tas[\s_]licen[cs]e|nt[\s_]licen[cs]e|australian[\s_]dl|aus[\s_]dl)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{6,10}|[A-Za-z]\d{5,9})\b",
                au_dl_check,
            ),
            (
                PiiKind::AuAbn,
                Language::En,
                r"(?i)(?:australian[\s_]business[\s_]number|australian[\s_]business[\s_]no\.?|aus[\s_]business[\s_]number|abn[\s_]number|abn[\s_]no\.?|abn[\s_]#|abn)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{2}\s?\d{3}\s?\d{3}\s?\d{3})\b",
                au_abn_check,
            ),
            (
                PiiKind::CaOhip,
                Language::En,
                r"(?i)(?:ontario[\s_]health[\s_]insurance[\s_]plan|ontario[\s_]health[\s_]card|ontario[\s_]health[\s_]number|health[\s_]card[\s_]number|health[\s_]card[\s_]no\.?|health[\s_]card|health[\s_]insurance[\s_]number|health[\s_]insurance[\s_]no\.?|health[\s_]number|carte[\s_]sant[eé]|OHIP[\s_]number|OHIP[\s_]no\.?|OHIP[\s_]card|OHIP)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{10}(?:\s?[A-Za-z]{2})?)\b",
                ohip_check,
            ),
            // International phone numbers
            (
                PiiKind::GbPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_]number|phone[\s_]no\.?|phone[\s_]num|phone[\s_]#|telephone[\s_]number|telephone[\s_]no\.?|telephone|mobile[\s_]number|mobile[\s_]no\.?|mobile[\s_]phone|mobile|cell[\s_]phone|cell[\s_]number|cell|contact[\s_]number|contact[\s_]no\.?|contact[\s_]phone|callback[\s_]number|callback[\s_]no\.?|callback|fax[\s_]number|fax[\s_]no\.?|fax|tel[\s_]number|tel[\s_]no\.?|tel|landline|home[\s_]phone|work[\s_]phone|office[\s_]phone|alternate[\s_]phone|alt[\s_]phone|my[\s_]phone|your[\s_]phone|customer[\s_]phone|applicant[\s_]phone|phone)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)((?:\+?44[\s\-.]?|0)(?:7\d{3}[\s\-.]?\d{3}[\s\-.]?\d{3}|\d{2,4}[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}))",
                phone_check,
            ),
            (
                PiiKind::AuPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_]number|phone[\s_]no\.?|phone[\s_]num|phone[\s_]#|telephone[\s_]number|telephone[\s_]no\.?|telephone|mobile[\s_]number|mobile[\s_]no\.?|mobile[\s_]phone|mobile|cell[\s_]phone|cell[\s_]number|cell|contact[\s_]number|contact[\s_]no\.?|contact[\s_]phone|callback[\s_]number|callback[\s_]no\.?|callback|fax[\s_]number|fax[\s_]no\.?|fax|tel[\s_]number|tel[\s_]no\.?|tel|landline|home[\s_]phone|work[\s_]phone|office[\s_]phone|alternate[\s_]phone|alt[\s_]phone|my[\s_]phone|your[\s_]phone|customer[\s_]phone|applicant[\s_]phone|phone)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)((?:\+?61[\s\-.]?|0)[2-578][\s\-.]?\d{4}[\s\-.]?\d{4})",
                phone_check,
            ),
            (
                PiiKind::NzPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_]number|phone[\s_]no\.?|phone[\s_]num|phone[\s_]#|telephone[\s_]number|telephone[\s_]no\.?|telephone|mobile[\s_]number|mobile[\s_]no\.?|mobile[\s_]phone|mobile|cell[\s_]phone|cell[\s_]number|cell|contact[\s_]number|contact[\s_]no\.?|contact[\s_]phone|callback[\s_]number|callback[\s_]no\.?|callback|fax[\s_]number|fax[\s_]no\.?|fax|tel[\s_]number|tel[\s_]no\.?|tel|landline|home[\s_]phone|work[\s_]phone|office[\s_]phone|alternate[\s_]phone|alt[\s_]phone|my[\s_]phone|your[\s_]phone|customer[\s_]phone|applicant[\s_]phone|phone)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)((?:\+?64[\s\-.]?|0)[2-9][\s\-.]?\d{3,4}[\s\-.]?\d{4})",
                phone_check,
            ),
            (
                PiiKind::IePhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_]number|phone[\s_]no\.?|phone[\s_]num|phone[\s_]#|telephone[\s_]number|telephone[\s_]no\.?|telephone|mobile[\s_]number|mobile[\s_]no\.?|mobile[\s_]phone|mobile|cell[\s_]phone|cell[\s_]number|cell|contact[\s_]number|contact[\s_]no\.?|contact[\s_]phone|callback[\s_]number|callback[\s_]no\.?|callback|fax[\s_]number|fax[\s_]no\.?|fax|tel[\s_]number|tel[\s_]no\.?|tel|landline|home[\s_]phone|work[\s_]phone|office[\s_]phone|alternate[\s_]phone|alt[\s_]phone|my[\s_]phone|your[\s_]phone|customer[\s_]phone|applicant[\s_]phone|phone)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)((?:\+?353[\s\-.]?|0)[1-9]\d[\s\-.]?\d{3,4}[\s\-.]?\d{4})",
                phone_check,
            ),
            (
                PiiKind::ZaPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_]number|phone[\s_]no\.?|phone[\s_]num|phone[\s_]#|telephone[\s_]number|telephone[\s_]no\.?|telephone|mobile[\s_]number|mobile[\s_]no\.?|mobile[\s_]phone|mobile|cell[\s_]phone|cell[\s_]number|cell|contact[\s_]number|contact[\s_]no\.?|contact[\s_]phone|callback[\s_]number|callback[\s_]no\.?|callback|fax[\s_]number|fax[\s_]no\.?|fax|tel[\s_]number|tel[\s_]no\.?|tel|landline|home[\s_]phone|work[\s_]phone|office[\s_]phone|alternate[\s_]phone|alt[\s_]phone|my[\s_]phone|your[\s_]phone|customer[\s_]phone|applicant[\s_]phone|phone)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)((?:\+?27[\s\-.]?|0)[1-9]\d[\s\-.]?\d{3}[\s\-.]?\d{4})",
                phone_check,
            ),
            // AWS Secret Key
            (
                PiiKind::AwsSecretKey,
                Language::En,
                r"(?:AWS_SECRET_ACCESS_KEY=?|aws_secret_access_key=?|secret_access_key[\s:.=]+|aws[_\s]secret[\s:.=]+)([A-Za-z0-9/+=]{40})",
                always_valid,
            ),
            // Country-specific passport numbers
            (
                PiiKind::GbZaPassportNumber,
                Language::En,
                r"(?i)(?:british[\s_]passport|uk[\s_]passport|united[\s_]kingdom[\s_]passport|hmpo|south[\s_]african[\s_]passport|sa[\s_]passport)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{9})\b",
                always_valid,
            ),
            (
                PiiKind::AuPassportNumber,
                Language::En,
                r"(?i)(?:australian[\s_]passport|australia[\s_]passport|passport[\s_]number|passport[\s_]no\.?|passport)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-Za-z]\d{7})\b",
                always_valid,
            ),
            (
                PiiKind::CaPassportNumber,
                Language::En,
                r"(?i)(?:canadian[\s_]passport|canada[\s_]passport|passport[\s_]number|passport[\s_]no\.?|passport)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-Za-z]{2}\d{6})\b",
                always_valid,
            ),
            (
                PiiKind::NzPassportNumber,
                Language::En,
                r"(?i)(?:new[\s_]zealand[\s_]passport|nz[\s_]passport|passport[\s_]number|passport[\s_]no\.?|passport)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-Za-z]{1,2}\d{6,7})\b",
                always_valid,
            ),
            (
                PiiKind::IePassportNumber,
                Language::En,
                r"(?i)(?:irish[\s_]passport|ireland[\s_]passport|passport[\s_]number|passport[\s_]no\.?|passport)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-Za-z]{2}\d{7})\b",
                always_valid,
            ),
            // Date of birth
            (
                PiiKind::DateOfBirth,
                Language::En,
                r"(?i)(?:date[\s_]of[\s_]birth|birth[\s_]date|birthdate|dob|d\.o\.b\.?|born[\s_]on)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}|\d{1,2}\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{4}|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+\d{4})",
                dob_check,
            ),
            // Bank accounts
            (
                PiiKind::AuBankAccount,
                Language::En,
                r"(?i)(?:bsb|bank[\s_]state[\s_]branch|bsb[\s_]number|bsb[\s_]no\.?)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{3}-?\d{3}(?:[\s]+\d{6,10})?)",
                always_valid,
            ),
            (
                PiiKind::CaBankAccount,
                Language::En,
                r"(?i)(?:transit[\s_]number|transit[\s_]no\.?|institution[\s_]number|chequing[\s_]account|savings[\s_]account|canadian[\s_]account|ca[\s_]account)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{5}[-\s]\d{3}[-\s]\d{7,12}|\d{7,12})",
                always_valid,
            ),
            // --- France-specific PII types (Language::Fr) ---
            (
                PiiKind::FrNir,
                Language::Fr,
                r"(?i)(?:num[eé]ro[\s_]de[\s_]s[eé]curit[eé][\s_]sociale|num[eé]ro[\s_]s[eé]curit[eé][\s_]sociale|n°[\s_]de[\s_]s[eé]curit[eé][\s_]sociale|n°[\s_]s[eé]curit[eé][\s_]sociale|num[eé]ro[\s_]de[\s_]s[eé]cu|num[eé]ro[\s_]s[eé]cu|n°[\s_]s[eé]cu|s[eé]curit[eé][\s_]sociale|num[eé]ro[\s_]SS|n°[\s_]SS|code[\s_]s[eé]cu|NIR|s[eé]cu)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d[\s.]?\d{2}[\s.]?\d{2}[\s.]?[0-9AB]{2,3}[\s.]?\d{2,3}[\s.]?\d{3}[\s.]?\d{2})",
                nir_check,
            ),
            (
                PiiKind::FrSiret,
                Language::Fr,
                r"(?i)(?:num[eé]ro[\s_]SIRET|n°[\s_]SIRET|[eé]tablissement[\s_]SIRET|SIRET)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{14})\b",
                siret_luhn_check,
            ),
            (
                PiiKind::FrSiren,
                Language::Fr,
                r"(?i)(?:num[eé]ro[\s_]SIREN|n°[\s_]SIREN|entreprise[\s_]SIREN|SIREN)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{9})\b",
                siren_luhn_check,
            ),
            (
                PiiKind::FrPassportNumber,
                Language::Fr,
                r"(?i)(?:passeport[\s_]fran[cç]ais|passeport[\s_]france|num[eé]ro[\s_]de[\s_]passeport)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{2}[A-Za-z]{2}\d{5})\b",
                always_valid,
            ),
            (
                PiiKind::FrCni,
                Language::Fr,
                r"(?i)(?:carte[\s_]nationale[\s_]d'identit[eé]|carte[\s_]d'identit[eé]|pi[eè]ce[\s_]d'identit[eé]|num[eé]ro[\s_]CNI|CNI)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{12})\b",
                always_valid,
            ),
            (
                PiiKind::FrDriversLicense,
                Language::Fr,
                r"(?i)(?:permis[\s_]de[\s_]conduire|num[eé]ro[\s_]de[\s_]permis|n°[\s_]permis)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{12})\b",
                always_valid,
            ),
            (
                PiiKind::FrPhoneNumber,
                Language::Fr,
                r"(?i)(?:num[eé]ro[\s_]de[\s_]t[eé]l[eé]phone|num[eé]ro[\s_]de[\s_]t[eé]l|n°[\s_]de[\s_]t[eé]l[eé]phone|n°[\s_]de[\s_]t[eé]l|t[eé]l[eé]phone|portable|mobile|fixe|t[eé]l|tel|num[eé]ro[\s_]t[eé]l|appeler|rappel|contact)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)((?:\+?33[\s\-.]?|0)[1-9](?:[\s\-.]?\d{2}){4})",
                phone_check,
            ),
            (
                PiiKind::FrPostalCode,
                Language::Fr,
                r"(?i)(?:code[\s_]postal|CP)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{5})\b",
                fr_postal_check,
            ),
            (
                PiiKind::FrNif,
                Language::Fr,
                r"(?i)(?:num[eé]ro[\s_]d'identification[\s_]fiscale|num[eé]ro[\s_]fiscal|identifiant[\s_]fiscal|avis[\s_]d'imposition|NIF|SPI)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{13})\b",
                fr_nif_check,
            ),
            // --- French keywords for existing international types ---
            (
                PiiKind::PhoneNumber,
                Language::Fr,
                r"(?i)(?:num[eé]ro[\s_]de[\s_]t[eé]l[eé]phone|num[eé]ro[\s_]de[\s_]t[eé]l|n°[\s_]de[\s_]t[eé]l[eé]phone|t[eé]l[eé]phone|portable|mobile|fixe|t[eé]l|appeler|rappel)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)((?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})",
                phone_check,
            ),
            (
                PiiKind::PassportNumber,
                Language::Fr,
                r"(?i)(?:passeport|num[eé]ro[\s_]de[\s_]passeport|document[\s_]de[\s_]voyage)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{9})\b",
                passport_check,
            ),
            (
                PiiKind::DateOfBirth,
                Language::Fr,
                r"(?i)(?:date[\s_]de[\s_]naissance|n[eé]e?[\s_]le|DDN|d\.d\.n\.?)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}|\d{1,2}\s+(?:janvier|fevrier|f[eé]vrier|mars|avril|mai|juin|juillet|aout|ao[uû]t|septembre|octobre|novembre|decembre|d[eé]cembre)\s+\d{4})",
                dob_check,
            ),
            (
                PiiKind::PreciseGeolocation,
                Language::Fr,
                r"(?i)(?:coordonn[eé]es[\s_]GPS|position[\s_]GPS|g[eé]olocalisation|coordonn[eé]es[\s_]g[eé]ographiques|latitude/longitude)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(-?\d{1,3}\.\d{4,},\s?-?\d{1,3}\.\d{4,})",
                geolocation_check,
            ),
            (
                PiiKind::SwiftBic,
                Language::Fr,
                r"(?i)(?:identifiant[\s_]bancaire)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?)\b",
                swift_bic_check,
            ),
            (
                PiiKind::Imei,
                Language::Fr,
                r"(?i)(?:num[eé]ro[\s_]IMEI|identifiant[\s_]appareil)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{2}-?\d{6}-?\d{6}-?\d)",
                imei_check,
            ),
            // --- Germany-specific PII types (Language::De) ---
            (
                PiiKind::DeSteuerId,
                Language::De,
                r"(?i)(?:Steueridentifikationsnummer|Steuerliche[\s_]Identifikationsnummer|Steuer-ID|IdNr|Steuernummer)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{11})\b",
                de_steuer_id_check,
            ),
            (
                PiiKind::DePersonalausweis,
                Language::De,
                r"(?i)(?:Personalausweisnummer|Personalausweis|Ausweisnummer)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-Za-z][A-Za-z0-9]{8}[0-9])\b",
                de_personalausweis_check,
            ),
            (
                PiiKind::DePhoneNumber,
                Language::De,
                r"(?i)(?:Telefonnummer|Rufnummer|Festnetz|Handynummer|Mobilnummer|Kontaktnummer|Anruf|R[uü]ckruf)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)((?:\+?49[\s\-.]?|0)[1-9]\d{1,4}[\s\-./]?\d{3,8})",
                phone_check,
            ),
            (
                PiiKind::DePostalCode,
                Language::De,
                r"(?i)(?:Postleitzahl|PLZ)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{5})\b",
                de_postal_check,
            ),
            // --- Austria-specific PII types (Language::De) ---
            (
                PiiKind::AtSvnr,
                Language::De,
                r"(?i)(?:Sozialversicherungsnummer|Versicherungsnummer|SVNR)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{4}\s?\d{6})\b",
                at_svnr_check,
            ),
            (
                PiiKind::AtPhoneNumber,
                Language::De,
                r"(?i)(?:Telefonnummer|Rufnummer|Festnetz|Handynummer|Mobilnummer|Kontaktnummer|Anruf|R[uü]ckruf)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)((?:\+?43[\s\-.]?|0)[1-9]\d{0,4}[\s\-./]?\d{3,8})",
                phone_check,
            ),
            (
                PiiKind::AtPostalCode,
                Language::De,
                r"(?i)(?:Postleitzahl|PLZ)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{4})\b",
                at_postal_check,
            ),
            // --- Switzerland-specific PII types (Language::De) ---
            (
                PiiKind::ChAhv,
                Language::De,
                r"(?i)(?:AHV-Nummer|AHV-Nr|OASI|Versichertennummer)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(756[\s.]?\d{4}[\s.]?\d{4}[\s.]?\d{2})\b",
                ch_ahv_check,
            ),
            (
                PiiKind::ChPhoneNumber,
                Language::De,
                r"(?i)(?:Telefonnummer|Rufnummer|Festnetz|Handynummer|Mobilnummer|Kontaktnummer|Anruf|R[uü]ckruf)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)((?:\+?41[\s\-.]?|0)[1-9]\d[\s\-.]?\d{3}[\s\-.]?\d{2}[\s\-.]?\d{2})",
                phone_check,
            ),
            (
                PiiKind::ChPostalCode,
                Language::De,
                r"(?i)(?:Postleitzahl|PLZ)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{4})\b",
                ch_postal_check,
            ),
            // --- German keywords for existing international types ---
            (
                PiiKind::PhoneNumber,
                Language::De,
                r"(?i)(?:Telefonnummer|Rufnummer|Festnetz|Handynummer|Mobilnummer|Kontaktnummer|Anruf|R[uü]ckruf)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)((?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})",
                phone_check,
            ),
            (
                PiiKind::PassportNumber,
                Language::De,
                r"(?i)(?:Reisepass|Passnummer)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{9})\b",
                passport_check,
            ),
            (
                PiiKind::DateOfBirth,
                Language::De,
                r"(?i)(?:Geburtsdatum|geboren[\s_]am|Geb\.?datum)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}|\d{1,2}\s+(?:Januar|Februar|M[aä]rz|Maerz|April|Mai|Juni|Juli|August|September|Oktober|November|Dezember)\s+\d{4})",
                dob_check,
            ),
            (
                PiiKind::PreciseGeolocation,
                Language::De,
                r"(?i)(?:GPS-Koordinaten|Standort|Geokoordinaten)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(-?\d{1,3}\.\d{4,},\s?-?\d{1,3}\.\d{4,})",
                geolocation_check,
            ),
            (
                PiiKind::SwiftBic,
                Language::De,
                r"(?i)(?:Bankleitzahl|BIC-Code)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?)\b",
                swift_bic_check,
            ),
            (
                PiiKind::Imei,
                Language::De,
                r"(?i)(?:Ger[aä]tekennung|Ger[aä]te-IMEI)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{2}-?\d{6}-?\d{6}-?\d)",
                imei_check,
            ),
            // --- PersonName (International) ---
            (
                PiiKind::PersonName,
                Language::En,
                r"(?i)(?:full[\s_]name|first[\s_]name|last[\s_]name|given[\s_]name|family[\s_]name|surname|forename|maiden[\s_]name|middle[\s_]name|patient[\s_]name|client[\s_]name|customer[\s_]name|employee[\s_]name|applicant[\s_]name|cardholder[\s_]name|account[\s_]holder|account[\s_]name|beneficiary[\s_]name|recipient[\s_]name|sender[\s_]name|passenger[\s_]name|insured[\s_]name)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+){0,4})",
                person_name_check,
            ),
            (
                PiiKind::PersonName,
                Language::Fr,
                r"(?i)(?:nom[\s_]complet|nom[\s_]de[\s_]famille|nom[\s_]de[\s_]naissance|nom[\s_]de[\s_]jeune[\s_]fille|nom[\s_]d'usage|pr[eé]nom|patronyme|titulaire|b[eé]n[eé]ficiaire|destinataire|exp[eé]diteur|passager|assur[eé])(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+){0,4})",
                person_name_check,
            ),
            (
                PiiKind::PersonName,
                Language::De,
                r"(?i)(?:vollst[aä]ndiger[\s_]Name|Nachname|Familienname|Vorname|Geburtsname|M[aä]dchenname|Kontoinhaber|Beg[uü]nstigter|Empf[aä]nger|Versicherter|Fahrgast|Antragsteller)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+){0,4})",
                person_name_check,
            ),
            // --- French/Swiss French physical address types (Language::Fr) ---
            (
                PiiKind::FrChAddress,
                Language::Fr,
                r"(?i)(?:adresse\s+(?:postale|de\s+livraison|de\s+facturation|personnelle|du\s+domicile|de\s+r[eé]sidence|du\s+si[eè]ge)|adresse|domicile|r[eé]sidence|si[eè]ge\s+social|habitation)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)((?:\d{1,4}\s?(?:bis|ter)?\s*,?\s*)?(?:rue|avenue|boulevard|place|all[eé]e|impasse|chemin|route|passage|cours|quai|square|voie|sentier|mont[eé]e|traverse|r[eé]sidence|cit[eé]|lotissement|hameau|lieu-dit|promenade|parvis|rond-point|esplanade|av|bd|pl|imp|ch)\s+[A-Za-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,6}(?:\s+\d{1,4}\s?[a-z]?)?[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
                fr_ch_address_check,
            ),
            (
                PiiKind::FrChBoitePostale,
                Language::Fr,
                r"(?i)(?:bo[iî]te\s+postale|case\s+postale|BP|CP)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{1,6}[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
                fr_ch_boite_postale_check,
            ),
            // --- German/Austrian physical address types (Language::De) ---
            (
                PiiKind::DeAtChAddress,
                Language::De,
                r"(?i)(?:Anschrift|Wohnadresse|Wohnanschrift|Hausanschrift|Wohnsitz|Lieferadresse|Rechnungsadresse|Meldeadresse|Zustelladresse|Privatadresse|Heimatadresse|Adresse)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-ZÀ-Ž][A-Za-zÀ-ž.\-]+(?:[\s\-]+[A-Za-zÀ-ž.\-]+)*\s+\d{1,4}\s?[a-zA-Z]?(?:\s?[\-/]\s?\d{1,4}\s?[a-zA-Z]?){0,3}[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
                de_at_address_check,
            ),
            (
                PiiKind::DeAtChPostfach,
                Language::De,
                r"(?i)(?:Postfach|PF)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{1,6}[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
                de_at_postfach_check,
            ),
            (
                PiiKind::DePackstation,
                Language::De,
                r"(?i)(?:Packstation|Postfiliale|Paketshop)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{3,4}[,\s]+\d{5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
                de_packstation_check,
            ),
        ];

        // Detection-only expressions for vectorscan, used instead of the full
        // extraction regex when the latter would cause DFA bloat. The extraction
        // regex (used by the regex crate for capture groups) can be wider/more
        // complex since it only runs on inputs vectorscan already confirmed.
        // PLZ uses \d{4,5} to cover DE (5-digit), AT (4-digit), and CH (4-digit).
        let detection_overrides: &[(PiiKind, &str)] = &[
            (
                PiiKind::DeAtChAddress,
                r"(?i)(?:Anschrift|Wohnadresse|Wohnanschrift|Hausanschrift|Wohnsitz|Lieferadresse|Rechnungsadresse|Meldeadresse|Zustelladresse|Privatadresse|Heimatadresse|Adresse)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)([A-ZÀ-Ž][A-Za-zÀ-ž.\-]+(?:[\s\-]+[A-Za-zÀ-ž.\-]+)*\s+\d{1,4}\s?[a-zA-Z]?(?:\s?[\-/]\s?\d{1,4}\s?[a-zA-Z]?){0,3}[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
            ),
            (
                PiiKind::DeAtChPostfach,
                r"(?i)(?:Postfach|PF)(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)(\d{1,6}[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
            ),
        ];

        let raw_patterns: Vec<(PiiKind, Language, &str, fn(&str) -> bool)> = all_patterns
            .into_iter()
            .filter(|(kind, lang, _, _)| {
                enabled_kinds.contains(kind) && enabled_languages.contains(lang)
            })
            .collect();

        let mut vs_patterns = Vec::with_capacity(raw_patterns.len());
        for (id, (kind, _, pat, _)) in raw_patterns.iter().enumerate() {
            let detection_pat = detection_overrides
                .iter()
                .find(|(k, _)| k == kind)
                .map(|(_, p)| *p)
                .unwrap_or(pat);
            vs_patterns.push(Pattern::new(
                detection_pat.as_bytes().to_vec(),
                Flag::UTF8,
                Some(id as u32),
            ));
        }

        if vs_patterns.is_empty() {
            return Ok(Self {
                detection_db: None,
                detection_prototype: None,
                patterns: Vec::new(),
            });
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
                let value_expr = extract_value_expr(pat);
                Ok(KeywordPattern {
                    kind,
                    value_regex: Regex::new(&format!("(?i)({value_expr})$"))
                        .map_err(PiiError::RegexCompilation)?,
                    validate,
                })
            })
            .collect::<Result<Vec<_>, PiiError>>()?;

        Ok(Self {
            detection_db: Some(detection_db),
            detection_prototype: Some(detection_prototype),
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
    fn with_detection_scanner<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&mut BlockScanner<'static>) -> R,
    {
        let db = self.detection_db.as_ref()?;
        let proto = self.detection_prototype.as_ref()?;
        let db_key = &**db as *const BlockDatabase as usize;
        Some(KW_DETECTION_CACHE.with(|cell| {
            let mut opt = cell.borrow_mut();
            if opt.as_ref().is_none_or(|(k, _)| *k != db_key) {
                *opt = Some((db_key, proto.clone()));
            }
            f(&mut opt.as_mut().unwrap().1)
        }))
    }

    /// Maximum byte lookback from vectorscan's `to` position. Covers the
    /// longest keyword (~40 bytes) + separator (~20 bytes) + value (~100 bytes
    /// for addresses with multi-byte UTF-8). 512 gives a comfortable 3× margin.
    const MATCH_LOOKBACK: usize = 512;

    /// Given vectorscan's `to` (end-of-match byte offset), return the start
    /// of a substring that is guaranteed to contain the full match, aligned
    /// to a UTF-8 character boundary.
    fn region_start(input: &str, to: usize) -> usize {
        let mut start = to.saturating_sub(Self::MATCH_LOOKBACK);
        // Align forward to a UTF-8 char boundary.
        while !input.is_char_boundary(start) {
            start += 1;
        }
        start
    }

    fn has_piis_on(&self, input: &str) -> bool {
        let patterns = &self.patterns;
        self.with_detection_scanner(|scanner| {
            let mut found = false;
            let _ = scanner.scan(input.as_bytes(), |id, _from, to, _flags| {
                let pattern = &patterns[id as usize];
                let start = Self::region_start(input, to as usize);
                let region = &input[start..to as usize];
                if let Some(caps) = pattern.value_regex.captures(region)
                    && let Some(value_match) = caps.get(1)
                    && (pattern.validate)(value_match.as_str())
                {
                    found = true;
                    return Scan::Terminate;
                }
                Scan::Continue
            });
            found
        })
        .unwrap_or(false)
    }

    fn mark_piis_on(&self, input: &str) -> Vec<PiiMatch> {
        let mut match_regions: Vec<(usize, usize)> = Vec::new();
        self.with_detection_scanner(|scanner| {
            let _ = scanner.scan(input.as_bytes(), |id, _from, to, _flags| {
                match_regions.push((id as usize, to as usize));
                Scan::Continue
            });
        });
        // Without SINGLEMATCH, vectorscan fires at every end position where
        // the DFA reaches a match state. For patterns with variable-length
        // endings (e.g. addresses with [A-Za-z]+), this produces many hits
        // per logical match. Sort by (id, to) descending so we process the
        // longest region first, then skip shorter overlapping regions.
        match_regions.sort_unstable();
        let mut matches = Vec::new();
        let mut prev_to: usize = 0;
        let mut prev_id: usize = usize::MAX;
        for &(idx, to) in match_regions.iter().rev() {
            // Skip if this is the same pattern close to an already-processed
            // `to` (overlapping vectorscan hit for the same logical match).
            if idx == prev_id && prev_to.saturating_sub(to) < Self::MATCH_LOOKBACK {
                continue;
            }
            prev_id = idx;
            prev_to = to;
            let pattern = &self.patterns[idx];
            let start = Self::region_start(input, to);
            let region = &input[start..to];
            if let Some(caps) = pattern.value_regex.captures(region)
                && let Some(value_match) = caps.get(1)
                && (pattern.validate)(value_match.as_str())
            {
                matches.push(PiiMatch {
                    kind: pattern.kind,
                    start: start + value_match.start(),
                    end: start + value_match.end(),
                    user_label: None,
                });
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
                    user_label: m.user_label,
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

    // Zero-width space (U+200B) is stripped before matching; the returned span
    // covers the original bytes so the caller can redact the full obfuscated token.
    #[test_case("phone: 555\u{200B}-123-4567", PiiKind::PhoneNumber, "555\u{200B}-123-4567" ; "phone zwsp in value stripped")]
    // ZWS inside a digit group (not replacing a separator) — after stripping,
    // "1\u{200B}23 456 782" becomes "123 456 782" which passes the TFN checksum.
    #[test_case("TFN: 1\u{200B}23 456 782", PiiKind::AuTfn, "1\u{200B}23 456 782" ; "tfn zwsp in digit stripped")]
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
    #[test_case("phone: +44 7911 123456", PiiKind::GbPhoneNumber, "+44 7911 123456" ; "gb phone mobile intl")]
    #[test_case("phone: 07700 900123", PiiKind::GbPhoneNumber, "07700 900123" ; "gb phone mobile local")]
    #[test_case("tel: +61 4 1234 5678", PiiKind::AuPhoneNumber, "+61 4 1234 5678" ; "au phone mobile intl")]
    #[test_case("phone: 04 1234 5678", PiiKind::AuPhoneNumber, "04 1234 5678" ; "au phone mobile local")]
    #[test_case("phone: +64 2 123 4567", PiiKind::NzPhoneNumber, "+64 2 123 4567" ; "nz phone mobile intl")]
    #[test_case("phone: 02 123 4567", PiiKind::NzPhoneNumber, "02 123 4567" ; "nz phone mobile local")]
    #[test_case("phone: +353 87 123 4567", PiiKind::IePhoneNumber, "+353 87 123 4567" ; "ie phone mobile intl")]
    #[test_case("phone: 087 123 4567", PiiKind::IePhoneNumber, "087 123 4567" ; "ie phone mobile local")]
    #[test_case("phone: +27 71 123 4567", PiiKind::ZaPhoneNumber, "+27 71 123 4567" ; "za phone mobile intl")]
    #[test_case("phone: 071 123 4567", PiiKind::ZaPhoneNumber, "071 123 4567" ; "za phone mobile local")]
    #[test_case("british passport: 123456789", PiiKind::GbZaPassportNumber, "123456789" ; "gb passport")]
    #[test_case("uk passport: 987654321", PiiKind::GbZaPassportNumber, "987654321" ; "gb passport uk keyword")]
    #[test_case("south african passport: 123456789", PiiKind::GbZaPassportNumber, "123456789" ; "za passport")]
    #[test_case("sa passport: 987654321", PiiKind::GbZaPassportNumber, "987654321" ; "za passport sa keyword")]
    #[test_case("driver's licence: 8001015009087", PiiKind::ZaDriversLicense, "8001015009087" ; "za drivers licence")]
    #[test_case("driving licence number: 9506150089081", PiiKind::ZaDriversLicense, "9506150089081" ; "za driving licence")]
    #[test_case("postal code: 0001", PiiKind::ZaPostalCode, "0001" ; "za postal code lower")]
    #[test_case("zip code: 8001", PiiKind::ZaPostalCode, "8001" ; "za postal code cape town")]
    #[test_case("australian driver's licence: 12345678", PiiKind::AuDriversLicense, "12345678" ; "au dl nsw 8 digit")]
    #[test_case("aus driver's license: 1234567890", PiiKind::AuDriversLicense, "1234567890" ; "au dl vic 10 digit")]
    #[test_case("nsw licence: 01234567", PiiKind::AuDriversLicense, "01234567" ; "au dl qld starting 0")]
    #[test_case("vic licence: 1234567", PiiKind::AuDriversLicense, "1234567" ; "au dl wa 7 digit")]
    #[test_case("tas licence: A12345", PiiKind::AuDriversLicense, "A12345" ; "au dl tas letter plus 5")]
    #[test_case("australian dl: 123456", PiiKind::AuDriversLicense, "123456" ; "au dl act 6 digit")]
    #[test_case("ABN: 51 824 753 556", PiiKind::AuAbn, "51 824 753 556" ; "au abn ato")] // ATO — from abr.business.gov.au
    #[test_case("australian business number: 33 051 775 556", PiiKind::AuAbn, "33 051 775 556" ; "au abn telstra")] // Telstra — from abr.business.gov.au
    #[test_case("abn number: 49004028077", PiiKind::AuAbn, "49004028077" ; "au abn bhp no spaces")] // BHP — from abr.business.gov.au
    #[test_case("australian passport: A1234567", PiiKind::AuPassportNumber, "A1234567" ; "au passport")]
    #[test_case("passport number: B7654321", PiiKind::AuPassportNumber, "B7654321" ; "au passport generic keyword")]
    #[test_case("canadian passport: AB123456", PiiKind::CaPassportNumber, "AB123456" ; "ca passport")]
    #[test_case("passport number: XY987654", PiiKind::CaPassportNumber, "XY987654" ; "ca passport generic keyword")]
    #[test_case("new zealand passport: NZ123456", PiiKind::NzPassportNumber, "NZ123456" ; "nz passport")]
    #[test_case("nz passport: L1234567", PiiKind::NzPassportNumber, "L1234567" ; "nz passport short keyword")]
    #[test_case("irish passport: AB1234567", PiiKind::IePassportNumber, "AB1234567" ; "ie passport")]
    #[test_case("ireland passport: CD7654321", PiiKind::IePassportNumber, "CD7654321" ; "ie passport ireland keyword")]
    #[test_case("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", PiiKind::AwsSecretKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" ; "aws secret env")]
    #[test_case("secret_access_key: abcdefghijklmnopqrstuvwxyz0123456789ABCD", PiiKind::AwsSecretKey, "abcdefghijklmnopqrstuvwxyz0123456789ABCD" ; "aws secret keyword")]
    #[test_case("date of birth: 15/03/1990", PiiKind::DateOfBirth, "15/03/1990" ; "dob dd/mm/yyyy")]
    #[test_case("dob: 1990-03-15", PiiKind::DateOfBirth, "1990-03-15" ; "dob iso")]
    #[test_case("born on: 01-01-2000", PiiKind::DateOfBirth, "01-01-2000" ; "dob born on")]
    #[test_case("BSB: 012-345", PiiKind::AuBankAccount, "012-345" ; "au bsb bare")]
    #[test_case("bsb number: 012345", PiiKind::AuBankAccount, "012345" ; "au bsb no hyphen")]
    #[test_case("transit number: 12345 001 1234567", PiiKind::CaBankAccount, "12345 001 1234567" ; "ca transit full")]
    #[test_case("chequing account: 1234567890", PiiKind::CaBankAccount, "1234567890" ; "ca chequing account")]
    // France-specific PII types
    #[test_case("numéro de sécu: 1 85 05 78 006 084 91", PiiKind::FrNir, "1 85 05 78 006 084 91" ; "fr nir")]
    #[test_case("SIRET: 73282932000074", PiiKind::FrSiret, "73282932000074" ; "fr siret")]
    #[test_case("SIREN: 732829320", PiiKind::FrSiren, "732829320" ; "fr siren")]
    #[test_case("passeport français: 05AB12345", PiiKind::FrPassportNumber, "05AB12345" ; "fr passport")]
    #[test_case("carte d'identité: 123456789012", PiiKind::FrCni, "123456789012" ; "fr cni")]
    #[test_case("permis de conduire: 123456789012", PiiKind::FrDriversLicense, "123456789012" ; "fr drivers license")]
    #[test_case("téléphone: 06 12 34 56 78", PiiKind::FrPhoneNumber, "06 12 34 56 78" ; "fr phone")]
    #[test_case("code postal: 75008", PiiKind::FrPostalCode, "75008" ; "fr postal code")]
    #[test_case("numéro fiscal: 0123456789012", PiiKind::FrNif, "0123456789012" ; "fr nif")]
    // Real-world French PII examples from public sources
    // NIR — from superindep.fr and compteassurance.com (verified with mod-97)
    #[test_case("sécurité sociale: 185036912304532", PiiKind::FrNir, "185036912304532" ; "fr nir lyon superindep")]
    #[test_case("numéro SS: 1 85 03 69 123 045 32", PiiKind::FrNir, "1 85 03 69 123 045 32" ; "fr nir lyon with spaces")]
    #[test_case("n° sécu: 175012A00403288", PiiKind::FrNir, "175012A00403288" ; "fr nir corsica 2a ajaccio")]
    #[test_case("code sécu: 290052B03301001", PiiKind::FrNir, "290052B03301001" ; "fr nir corsica 2b")]
    // SIREN — from annuaire-entreprises.data.gouv.fr (verified with Luhn)
    #[test_case("SIREN: 775670417", PiiKind::FrSiren, "775670417" ; "fr siren lvmh")]
    #[test_case("numéro SIREN: 542051180", PiiKind::FrSiren, "542051180" ; "fr siren totalenergies")]
    #[test_case("entreprise SIREN: 441639465", PiiKind::FrSiren, "441639465" ; "fr siren renault")]
    #[test_case("n° SIREN: 780129987", PiiKind::FrSiren, "780129987" ; "fr siren renault sas")]
    // SIRET — from annuaire-entreprises.data.gouv.fr (verified with Luhn)
    #[test_case("numéro SIRET: 77567041700051", PiiKind::FrSiret, "77567041700051" ; "fr siret lvmh hq")]
    #[test_case("n° SIRET: 54205118000066", PiiKind::FrSiret, "54205118000066" ; "fr siret totalenergies hq")]
    #[test_case("établissement SIRET: 71204961800739", PiiKind::FrSiret, "71204961800739" ; "fr siret essilorluxottica")]
    // French postal codes — real cities
    #[test_case("code postal: 75001", PiiKind::FrPostalCode, "75001" ; "fr postal paris 1er")]
    #[test_case("CP: 13001", PiiKind::FrPostalCode, "13001" ; "fr postal marseille")]
    #[test_case("code postal: 69001", PiiKind::FrPostalCode, "69001" ; "fr postal lyon")]
    #[test_case("code postal: 31000", PiiKind::FrPostalCode, "31000" ; "fr postal toulouse")]
    #[test_case("CP: 97110", PiiKind::FrPostalCode, "97110" ; "fr postal guadeloupe")]
    // French phone — various formats
    #[test_case("portable: +33 6 12 34 56 78", PiiKind::FrPhoneNumber, "+33 6 12 34 56 78" ; "fr phone intl mobile")]
    #[test_case("fixe: 01 23 45 67 89", PiiKind::FrPhoneNumber, "01 23 45 67 89" ; "fr phone paris landline")]
    #[test_case("contact: 09 12 34 56 78", PiiKind::FrPhoneNumber, "09 12 34 56 78" ; "fr phone voip")]
    // French keywords for existing international types
    #[test_case("date de naissance: 15 mars 1990", PiiKind::DateOfBirth, "15 mars 1990" ; "fr dob")]
    #[test_case("rappel: 555-123-4567", PiiKind::PhoneNumber, "555-123-4567" ; "fr keyword us phone")]
    #[test_case("document de voyage: 123456789", PiiKind::PassportNumber, "123456789" ; "fr keyword passport")]
    #[test_case("géolocalisation: 40.7128,-74.0060", PiiKind::PreciseGeolocation, "40.7128,-74.0060" ; "fr keyword geolocation")]
    #[test_case("identifiant bancaire: DEUTDEFF", PiiKind::SwiftBic, "DEUTDEFF" ; "fr keyword swift")]
    #[test_case("identifiant appareil: 490154203237518", PiiKind::Imei, "490154203237518" ; "fr keyword imei")]
    // Real-world examples for English-speaking countries
    // US EIN: 53-0196605 (American National Red Cross, ProPublica), 20-0049703 (Wikimedia Foundation)
    #[test_case("employer identification number: 53-0196605", PiiKind::UsEin, "53-0196605" ; "ein red cross")]
    #[test_case("EIN: 20-0049703", PiiKind::UsEin, "20-0049703" ; "ein wikimedia")]
    #[test_case("federal ein: 20-0097189", PiiKind::UsEin, "20-0097189" ; "ein mozilla")]
    // US ABA: 026009593 (BofA wire), 121000248 (Wells Fargo), 021000089 (Citibank)
    #[test_case("routing number: 026009593", PiiKind::UsAbaRouting, "026009593" ; "aba bank of america")]
    #[test_case("ABA routing number: 121000248", PiiKind::UsAbaRouting, "121000248" ; "aba wells fargo")]
    #[test_case("wire routing: 021000089", PiiKind::UsAbaRouting, "021000089" ; "aba citibank")]
    #[test_case("ach routing: 111000025", PiiKind::UsAbaRouting, "111000025" ; "aba bofa virginia")]
    // GB NHS: 9278462608 (pfwd/NHSNumber-Validation), 4010232137 (verified mod-11), 9990000018 (NHS test range)
    #[test_case("NHS number: 927 846 2608", PiiKind::GbNhsNumber, "927 846 2608" ; "nhs github example")]
    #[test_case("patient number: 401 023 2137", PiiKind::GbNhsNumber, "401 023 2137" ; "nhs computed example")]
    #[test_case("NHS: 999 000 0018", PiiKind::GbNhsNumber, "999 000 0018" ; "nhs test range")]
    // GB UTR: 9987654321 and 1123456789 (computed using HMRC reference-checker algorithm)
    #[test_case("unique taxpayer reference: 9987654321", PiiKind::GbUtr, "9987654321" ; "utr descending")]
    #[test_case("hmrc utr: 7999888777", PiiKind::GbUtr, "7999888777" ; "utr nines and eights")]
    #[test_case("self assessment utr: 1123456789", PiiKind::GbUtr, "1123456789" ; "utr sequential")]
    // GB Sort code: 20-26-86 (Barclays Leicester), 40-05-30 (HSBC London), 60-00-01 (NatWest London)
    #[test_case("sort code: 20-26-86", PiiKind::GbSortCode, "20-26-86" ; "sort code barclays leicester")]
    #[test_case("branch code: 40-05-30", PiiKind::GbSortCode, "40-05-30" ; "sort code hsbc london")]
    #[test_case("bank sort code: 60-00-01", PiiKind::GbSortCode, "60-00-01" ; "sort code natwest london")]
    #[test_case("sort code: 30-96-26", PiiKind::GbSortCode, "30-96-26" ; "sort code lloyds")]
    // AU TFN: 100000001 and 100000028 (generated, verified with weights)
    #[test_case("tax file number: 100 000 001", PiiKind::AuTfn, "100 000 001" ; "tfn generated 1")]
    #[test_case("TFN: 100 000 028", PiiKind::AuTfn, "100 000 028" ; "tfn generated 2")]
    // AU Medicare: 3189977021 (clearwater.com.au worked calc), 6950507391 (medipass/validate-medicare-number)
    #[test_case("medicare number: 3189 97702 1", PiiKind::AuMedicare, "3189 97702 1" ; "medicare clearwater")]
    #[test_case("australian medicare: 6950 50739 1", PiiKind::AuMedicare, "6950 50739 1" ; "medicare medipass")]
    // NZ NHI: JBX3656 (Wikipedia), ZAC5361 (rapidrehita.health.nz), CGC2720, EPT6335 (Wikipedia), WLD9413 (nhi-validator npm)
    #[test_case("NHI: JBX3656", PiiKind::NzNhiNumber, "JBX3656" ; "nz nhi wikipedia")]
    #[test_case("national health index: ZAC5361", PiiKind::NzNhiNumber, "ZAC5361" ; "nz nhi rapidrehita")]
    #[test_case("NHI number: CGC2720", PiiKind::NzNhiNumber, "CGC2720" ; "nz nhi wikipedia cgc")]
    #[test_case("patient nhi: EPT6335", PiiKind::NzNhiNumber, "EPT6335" ; "nz nhi wikipedia ept")]
    #[test_case("NHI: WLD9413", PiiKind::NzNhiNumber, "WLD9413" ; "nz nhi validator npm")]
    // NZ IRD: 10-000-008 (generated 8-digit), 100-000-148 (generated 9-digit)
    #[test_case("IRD: 10-000-008", PiiKind::NzIrdNumber, "10-000-008" ; "ird generated 8digit")]
    #[test_case("IRD number: 100-000-148", PiiKind::NzIrdNumber, "100-000-148" ; "ird generated 9digit")]
    // Note: CA SIN and IE PPSN are detected by HyperscanDetector, not KeywordContextDetector
    // ZA ID: 9001245289086 (za-id-number PyPI), 8801235111088 (Medium article), 9501015000084 (generated)
    #[test_case("SA ID: 9001245289086", PiiKind::ZaId, "9001245289086" ; "sa id pypi")]
    #[test_case("identity number: 8801235111088", PiiKind::ZaId, "8801235111088" ; "sa id medium")]
    #[test_case("south african id: 9501015000084", PiiKind::ZaId, "9501015000084" ; "sa id generated")]
    // Germany-specific PII types
    // Germany-specific PII types — values from kryptografie.de and rechtlogisch/steuer-id
    #[test_case("Steuer-ID: 65929970489", PiiKind::DeSteuerId, "65929970489" ; "de steuer id")]
    #[test_case("Steueridentifikationsnummer: 86095742719", PiiKind::DeSteuerId, "86095742719" ; "de steuer id long keyword")]
    #[test_case("IdNr: 26954371827", PiiKind::DeSteuerId, "26954371827" ; "de steuer id idnr keyword")]
    #[test_case("Steuernummer: 12345678995", PiiKind::DeSteuerId, "12345678995" ; "de steuer id kryptografie example")]
    // Personalausweis — values from kryptografie.de/personalausweis.htm
    #[test_case("Personalausweis: L01X00T471", PiiKind::DePersonalausweis, "L01X00T471" ; "de personalausweis newest format")]
    #[test_case("Ausweisnummer: T220001293", PiiKind::DePersonalausweis, "T220001293" ; "de personalausweis new format")]
    #[test_case("Personalausweisnummer: C01X00T478", PiiKind::DePersonalausweis, "C01X00T478" ; "de personalausweis long keyword")]
    #[test_case("Personalausweis: M123456788", PiiKind::DePersonalausweis, "M123456788" ; "de personalausweis sequential digits")]
    // German phones
    #[test_case("Rufnummer: +49 30 12345678", PiiKind::DePhoneNumber, "+49 30 12345678" ; "de phone berlin landline")]
    #[test_case("Handynummer: +49 151 12345678", PiiKind::DePhoneNumber, "+49 151 12345678" ; "de phone mobile")]
    #[test_case("Telefonnummer: +49 89 98765432", PiiKind::DePhoneNumber, "+49 89 98765432" ; "de phone munich landline")]
    #[test_case("Festnetz: 030 12345678", PiiKind::DePhoneNumber, "030 12345678" ; "de phone local format")]
    #[test_case("Kontaktnummer: +49 221 1234567", PiiKind::DePhoneNumber, "+49 221 1234567" ; "de phone cologne")]
    // German postal codes
    #[test_case("Postleitzahl: 10115", PiiKind::DePostalCode, "10115" ; "de postal code berlin")]
    #[test_case("PLZ: 80331", PiiKind::DePostalCode, "80331" ; "de postal code munich")]
    #[test_case("Postleitzahl: 01067", PiiKind::DePostalCode, "01067" ; "de postal code dresden")]
    #[test_case("PLZ: 60311", PiiKind::DePostalCode, "60311" ; "de postal code frankfurt")]
    #[test_case("PLZ: 20095", PiiKind::DePostalCode, "20095" ; "de postal code hamburg")]
    // Austria-specific PII types — SVNR from gist.github.com/jensens
    #[test_case("SVNR: 1238150185", PiiKind::AtSvnr, "1238150185" ; "at svnr")]
    #[test_case("Sozialversicherungsnummer: 1233250689", PiiKind::AtSvnr, "1233250689" ; "at svnr long keyword")]
    #[test_case("Versicherungsnummer: 1237010180", PiiKind::AtSvnr, "1237010180" ; "at svnr documented example")]
    #[test_case("SVNR: 4567150390", PiiKind::AtSvnr, "4567150390" ; "at svnr born 1990")]
    #[test_case("SVNR: 7892281275", PiiKind::AtSvnr, "7892281275" ; "at svnr born 1975")]
    // Austrian phones and postal
    #[test_case("Rufnummer: +43 1 12345678", PiiKind::AtPhoneNumber, "+43 1 12345678" ; "at phone vienna")]
    #[test_case("Handynummer: +43 664 1234567", PiiKind::AtPhoneNumber, "+43 664 1234567" ; "at phone mobile")]
    #[test_case("PLZ: 1010", PiiKind::AtPostalCode, "1010" ; "at postal code vienna")]
    #[test_case("Postleitzahl: 5020", PiiKind::AtPostalCode, "5020" ; "at postal code salzburg")]
    #[test_case("PLZ: 8010", PiiKind::AtPostalCode, "8010" ; "at postal code graz")]
    // Switzerland-specific — AHV from sozialversicherungsnummer.ch and gist.github.com/rordi
    #[test_case("AHV-Nummer: 756.1234.5678.97", PiiKind::ChAhv, "756.1234.5678.97" ; "ch ahv dotted")]
    #[test_case("Versichertennummer: 7561234567897", PiiKind::ChAhv, "7561234567897" ; "ch ahv plain")]
    #[test_case("AHV-Nr: 756.9217.0769.85", PiiKind::ChAhv, "756.9217.0769.85" ; "ch ahv sozialversicherungsnummer.ch example")]
    #[test_case("AHV-Nummer: 756.0081.3782.50", PiiKind::ChAhv, "756.0081.3782.50" ; "ch ahv gist example")]
    #[test_case("OASI: 756.3026.0705.92", PiiKind::ChAhv, "756.3026.0705.92" ; "ch ahv oasi keyword")]
    // Swiss phones and postal
    #[test_case("Rufnummer: +41 44 123 45 67", PiiKind::ChPhoneNumber, "+41 44 123 45 67" ; "ch phone zurich")]
    #[test_case("Handynummer: +41 79 123 45 67", PiiKind::ChPhoneNumber, "+41 79 123 45 67" ; "ch phone mobile")]
    #[test_case("PLZ: 8001", PiiKind::ChPostalCode, "8001" ; "ch postal code zurich")]
    #[test_case("Postleitzahl: 3000", PiiKind::ChPostalCode, "3000" ; "ch postal code bern")]
    #[test_case("PLZ: 1200", PiiKind::ChPostalCode, "1200" ; "ch postal code geneva")]
    // German keywords for existing international types
    #[test_case("Rufnummer: 555-123-4567", PiiKind::PhoneNumber, "555-123-4567" ; "de keyword us phone")]
    #[test_case("Kontaktnummer: (555) 234-5678", PiiKind::PhoneNumber, "(555) 234-5678" ; "de keyword us phone parens")]
    #[test_case("Reisepass: 123456789", PiiKind::PassportNumber, "123456789" ; "de keyword passport")]
    #[test_case("Passnummer: 987654321", PiiKind::PassportNumber, "987654321" ; "de keyword passport alt")]
    #[test_case("Geburtsdatum: 15.03.1990", PiiKind::DateOfBirth, "15.03.1990" ; "de keyword dob numeric")]
    #[test_case("Geburtsdatum: 15 März 1990", PiiKind::DateOfBirth, "15 März 1990" ; "de keyword dob month name")]
    #[test_case("geboren am: 1985-07-22", PiiKind::DateOfBirth, "1985-07-22" ; "de keyword dob geboren am")]
    #[test_case("Gebdatum: 28/12/1975", PiiKind::DateOfBirth, "28/12/1975" ; "de keyword dob gebdatum")]
    #[test_case("Standort: 48.1351,11.5820", PiiKind::PreciseGeolocation, "48.1351,11.5820" ; "de keyword geolocation munich")]
    #[test_case("GPS-Koordinaten: 47.3769,8.5417", PiiKind::PreciseGeolocation, "47.3769,8.5417" ; "de keyword geolocation zurich")]
    #[test_case("Geokoordinaten: 48.2082,16.3738", PiiKind::PreciseGeolocation, "48.2082,16.3738" ; "de keyword geolocation vienna")]
    #[test_case("BIC-Code: DEUTDEFF", PiiKind::SwiftBic, "DEUTDEFF" ; "de keyword swift deutsche bank")]
    #[test_case("Bankleitzahl: COBADEFFXXX", PiiKind::SwiftBic, "COBADEFFXXX" ; "de keyword swift commerzbank")]
    #[test_case("Gerätekennung: 490154203237518", PiiKind::Imei, "490154203237518" ; "de keyword imei")]
    #[test_case("Gerätekennung: 35-209900-176148-1", PiiKind::Imei, "35-209900-176148-1" ; "de keyword imei hyphenated")]
    // PersonName — English
    #[test_case("full name: John Smith", PiiKind::PersonName, "John Smith" ; "person name en full name")]
    #[test_case("first name: Alice", PiiKind::PersonName, "Alice" ; "person name en first name")]
    #[test_case("last name: O'Brien", PiiKind::PersonName, "O'Brien" ; "person name en last name apostrophe")]
    #[test_case("patient name: Maria Garcia-Lopez", PiiKind::PersonName, "Maria Garcia-Lopez" ; "person name en patient hyphen")]
    #[test_case("cardholder name: Jean-Pierre Müller", PiiKind::PersonName, "Jean-Pierre Müller" ; "person name en cardholder accented")]
    #[test_case("employee name: Maria de Los Santos Garcia", PiiKind::PersonName, "Maria de Los Santos Garcia" ; "person name en employee multi word")]
    #[test_case("surname: Thompson", PiiKind::PersonName, "Thompson" ; "person name en surname")]
    #[test_case("beneficiary name: André Lefèvre", PiiKind::PersonName, "André Lefèvre" ; "person name en beneficiary accented")]
    // PersonName — French
    #[test_case("nom complet: Jacques Dupont", PiiKind::PersonName, "Jacques Dupont" ; "person name fr nom complet")]
    #[test_case("prénom: François", PiiKind::PersonName, "François" ; "person name fr prenom")]
    #[test_case("nom de famille: Beaumont", PiiKind::PersonName, "Beaumont" ; "person name fr nom de famille")]
    #[test_case("titulaire: Marie-Claire Dubois", PiiKind::PersonName, "Marie-Claire Dubois" ; "person name fr titulaire")]
    #[test_case("destinataire: Émile Zola", PiiKind::PersonName, "Émile Zola" ; "person name fr destinataire")]
    // PersonName — German
    #[test_case("Nachname: Schmidt", PiiKind::PersonName, "Schmidt" ; "person name de nachname")]
    #[test_case("Vorname: Hans", PiiKind::PersonName, "Hans" ; "person name de vorname")]
    #[test_case("Familienname: Von Trapp", PiiKind::PersonName, "Von Trapp" ; "person name de familienname")]
    #[test_case("Kontoinhaber: Günther Müller", PiiKind::PersonName, "Günther Müller" ; "person name de kontoinhaber")]
    #[test_case("Empfänger: Björk Sigurdsson", PiiKind::PersonName, "Björk Sigurdsson" ; "person name de empfaenger")]
    // French/Swiss French address types
    #[test_case("adresse: 15 rue de la Paix, 75002 Paris", PiiKind::FrChAddress, "15 rue de la Paix, 75002 Paris" ; "fr address rue de la paix")]
    #[test_case("domicile: 42 boulevard Haussmann, 75009 Paris", PiiKind::FrChAddress, "42 boulevard Haussmann, 75009 Paris" ; "fr address boulevard")]
    #[test_case("résidence: 3 place Bellecour, 69002 Lyon", PiiKind::FrChAddress, "3 place Bellecour, 69002 Lyon" ; "fr address place lyon")]
    #[test_case("habitation: 7 allée des Pins, 13008 Marseille", PiiKind::FrChAddress, "7 allée des Pins, 13008 Marseille" ; "fr address allee marseille")]
    #[test_case("adresse de livraison: 25 cours de l'Intendance, 33000 Bordeaux", PiiKind::FrChAddress, "25 cours de l'Intendance, 33000 Bordeaux" ; "fr address cours bordeaux")]
    #[test_case("siège social: 1 avenue des Champs, 75008 Paris", PiiKind::FrChAddress, "1 avenue des Champs, 75008 Paris" ; "fr address siege social")]
    #[test_case("adresse du domicile: 10 impasse du Moulin, 97100 Basse-Terre", PiiKind::FrChAddress, "10 impasse du Moulin, 97100 Basse-Terre" ; "fr address overseas guadeloupe")]
    #[test_case("adresse de facturation: 8 chemin des Vignes, 31000 Toulouse", PiiKind::FrChAddress, "8 chemin des Vignes, 31000 Toulouse" ; "fr address chemin toulouse")]
    // Real-world French addresses — verified from official sources
    #[test_case("adresse: 55 rue du Faubourg Saint-Honoré, 75008 Paris", PiiKind::FrChAddress, "55 rue du Faubourg Saint-Honoré, 75008 Paris" ; "fr address elysee palace")] // From elysee.fr
    #[test_case("domicile: 5 avenue Anatole France, 75007 Paris", PiiKind::FrChAddress, "5 avenue Anatole France, 75007 Paris" ; "fr address tour eiffel")] // From toureiffel.paris
    #[test_case("adresse: 1 rue de la Légion d'Honneur, 75007 Paris", PiiKind::FrChAddress, "1 rue de la Légion d'Honneur, 75007 Paris" ; "fr address musee orsay")] // From musee-orsay.fr
    #[test_case("résidence: 36 quai des Orfèvres, 75001 Paris", PiiKind::FrChAddress, "36 quai des Orfèvres, 75001 Paris" ; "fr address quai des orfevres")] // From Wikipedia
    #[test_case("adresse: 35 rue du Chevalier de la Barre, 75018 Paris", PiiKind::FrChAddress, "35 rue du Chevalier de la Barre, 75018 Paris" ; "fr address sacre coeur")] // From Yelp
    #[test_case("adresse: 129 rue de Grenelle, 75007 Paris", PiiKind::FrChAddress, "129 rue de Grenelle, 75007 Paris" ; "fr address invalides")] // From musee-armee.fr
    #[test_case("siège social: 2 boulevard du Général Martial-Valin, 75015 Paris", PiiKind::FrChAddress, "2 boulevard du Général Martial-Valin, 75015 Paris" ; "fr address safran hq")] // From safran-group.com
    #[test_case("adresse: 86 quai Perrache, 69002 Lyon", PiiKind::FrChAddress, "86 quai Perrache, 69002 Lyon" ; "fr address musee confluences lyon")] // From museedesconfluences.fr
    #[test_case("domicile: 37 promenade des Anglais, 06000 Nice", PiiKind::FrChAddress, "37 promenade des Anglais, 06000 Nice" ; "fr address negresco nice")] // From lenegresco.com
    #[test_case("adresse: 1 boulevard de la Croisette, 06400 Cannes", PiiKind::FrChAddress, "1 boulevard de la Croisette, 06400 Cannes" ; "fr address palais festivals cannes")] // From palaisdesfestivals.com
    #[test_case("adresse: 151 bis rue de Rennes, 75006 Paris", PiiKind::FrChAddress, "151 bis rue de Rennes, 75006 Paris" ; "fr address bis suffix")] // From connexionfrance.com
    // Swiss French addresses — number after street name (CH format)
    #[test_case("domicile: rue du Général-Dufour 24, 1211 Genève", PiiKind::FrChAddress, "rue du Général-Dufour 24, 1211 Genève" ; "ch address geneve unige")] // Université de Genève
    #[test_case("résidence: quai d'Ouchy 1, 1006 Lausanne", PiiKind::FrChAddress, "quai d'Ouchy 1, 1006 Lausanne" ; "ch address lausanne olympic")] // Musée Olympique
    #[test_case("habitation: avenue de Cour 135, 1007 Lausanne", PiiKind::FrChAddress, "avenue de Cour 135, 1007 Lausanne" ; "ch address lausanne cour")] // CIO Lausanne
    #[test_case("domicile: avenue de Chillon 21, 1820 Veytaux", PiiKind::FrChAddress, "avenue de Chillon 21, 1820 Veytaux" ; "ch address veytaux chateau")] // Château de Chillon
    #[test_case("résidence: avenue Nestlé 55, 1800 Vevey", PiiKind::FrChAddress, "avenue Nestlé 55, 1800 Vevey" ; "ch address vevey nestle")] // Nestlé HQ
    // French/Swiss PO box
    #[test_case("BP: 1234, 75008 Paris", PiiKind::FrChBoitePostale, "1234, 75008 Paris" ; "fr bp paris")]
    #[test_case("boîte postale: 56, 69001 Lyon", PiiKind::FrChBoitePostale, "56, 69001 Lyon" ; "fr bp lyon")]
    #[test_case("BP: 789, 97100 Basse-Terre", PiiKind::FrChBoitePostale, "789, 97100 Basse-Terre" ; "fr bp overseas")]
    #[test_case("boîte postale: 123456, 13001 Marseille", PiiKind::FrChBoitePostale, "123456, 13001 Marseille" ; "fr bp 6 digits")]
    // Real-world FR BP addresses
    #[test_case("BP: 7008, 97307 Cayenne", PiiKind::FrChBoitePostale, "7008, 97307 Cayenne" ; "fr bp cayenne guyane")] // From guyane.gouv.fr
    #[test_case("boîte postale: 523, 98000 Monaco", PiiKind::FrChBoitePostale, "523, 98000 Monaco" ; "fr bp monaco")] // From mairie.mc
    // Swiss Case Postale addresses
    #[test_case("case postale: 2272, 1950 Sion", PiiKind::FrChBoitePostale, "2272, 1950 Sion" ; "ch cp sion")] // Ville de Sion
    #[test_case("CP: 440, 1211 Genève", PiiKind::FrChBoitePostale, "440, 1211 Genève" ; "ch cp geneve")] // From ge.ch
    // German/Austrian address types
    #[test_case("Anschrift: Musterstraße 42, 10115 Berlin", PiiKind::DeAtChAddress, "Musterstraße 42, 10115 Berlin" ; "de address standard")]
    #[test_case("Wohnadresse: Am Markt 3a, 01067 Dresden", PiiKind::DeAtChAddress, "Am Markt 3a, 01067 Dresden" ; "de address with suffix")]
    #[test_case("Rechnungsadresse: Hauptstraße 10-12, 80331 München", PiiKind::DeAtChAddress, "Hauptstraße 10-12, 80331 München" ; "de address with range")]
    #[test_case("Lieferadresse: Unter den Linden 77, 10117 Berlin", PiiKind::DeAtChAddress, "Unter den Linden 77, 10117 Berlin" ; "de address multi word street")]
    #[test_case("Meldeadresse: Bahnhofstr. 1, 60311 Frankfurt", PiiKind::DeAtChAddress, "Bahnhofstr. 1, 60311 Frankfurt" ; "de address abbreviated")]
    #[test_case("Adresse: Friedrichstraße 43, 10117 Berlin", PiiKind::DeAtChAddress, "Friedrichstraße 43, 10117 Berlin" ; "de address keyword adresse")]
    #[test_case("Anschrift: Schillerstraße 10, 1010 Wien", PiiKind::DeAtChAddress, "Schillerstraße 10, 1010 Wien" ; "at address vienna")]
    #[test_case("Wohnadresse: Josefstädterstraße 21/5, 1080 Wien", PiiKind::DeAtChAddress, "Josefstädterstraße 21/5, 1080 Wien" ; "at address slash notation")]
    #[test_case("Adresse: Mariahilfer Straße 45/2/14, 1060 Wien", PiiKind::DeAtChAddress, "Mariahilfer Straße 45/2/14, 1060 Wien" ; "at address multi slash")]
    #[test_case("Lieferadresse: Landstraßer Hauptstraße 5a, 1030 Wien", PiiKind::DeAtChAddress, "Landstraßer Hauptstraße 5a, 1030 Wien" ; "at address letter suffix")]
    // CH addresses — verified real locations
    #[test_case("Anschrift: Bahnhofstrasse 1, 8001 Zürich", PiiKind::DeAtChAddress, "Bahnhofstrasse 1, 8001 Zürich" ; "ch address zurich")] // Hauser & Wirth gallery
    #[test_case("Wohnadresse: Bundesplatz 3, 3003 Bern", PiiKind::DeAtChAddress, "Bundesplatz 3, 3003 Bern" ; "ch address bern")] // Federal Palace
    #[test_case("Adresse: Pilatusstrasse 15, 6003 Luzern", PiiKind::DeAtChAddress, "Pilatusstrasse 15, 6003 Luzern" ; "ch address luzern")] // From Yelp
    #[test_case("Postfach: 1234, 10557 Berlin", PiiKind::DeAtChPostfach, "1234, 10557 Berlin" ; "de postfach berlin")]
    #[test_case("PF: 56, 80331 München", PiiKind::DeAtChPostfach, "56, 80331 München" ; "de postfach short keyword")]
    #[test_case("Postfach: 123456, 01067 Dresden", PiiKind::DeAtChPostfach, "123456, 01067 Dresden" ; "de postfach 6 digits")]
    #[test_case("Postfach: 789, 5020 Salzburg", PiiKind::DeAtChPostfach, "789, 5020 Salzburg" ; "at postfach salzburg")]
    #[test_case("PF: 56, 4020 Linz", PiiKind::DeAtChPostfach, "56, 4020 Linz" ; "at postfach linz")]
    #[test_case("Postfach: 567, 6000 Luzern", PiiKind::DeAtChPostfach, "567, 6000 Luzern" ; "ch postfach luzern")]
    #[test_case("Packstation: 109, 01099 Dresden", PiiKind::DePackstation, "109, 01099 Dresden" ; "de packstation 3 digits")]
    #[test_case("Postfiliale: 502, 10115 Berlin", PiiKind::DePackstation, "502, 10115 Berlin" ; "de postfiliale")]
    #[test_case("Paketshop: 1234, 20095 Hamburg", PiiKind::DePackstation, "1234, 20095 Hamburg" ; "de paketshop 4 digits")]
    // Address city capture must not extend into trailing prose (regression)
    #[test_case("adresse: 15 rue de la Paix, 75002 Paris. Merci de confirmer.", PiiKind::FrChAddress, "15 rue de la Paix, 75002 Paris" ; "fr address trailing prose")]
    #[test_case("BP: 1234, 75008 Paris. Veuillez vérifier.", PiiKind::FrChBoitePostale, "1234, 75008 Paris" ; "fr bp trailing prose")]
    #[test_case("Anschrift: Friedrichstraße 43, 10117 Berlin. Bitte bewahren Sie diese Bestätigung.", PiiKind::DeAtChAddress, "Friedrichstraße 43, 10117 Berlin" ; "de address trailing prose")]
    #[test_case("Lieferadresse: Unter den Linden 77, 10117 Berlin. Die Zustellung erfolgt morgen.", PiiKind::DeAtChAddress, "Unter den Linden 77, 10117 Berlin" ; "de address multi word street trailing prose")]
    #[test_case("Postfach: 1234, 10557 Berlin. Bitte verwenden Sie diese Adresse.", PiiKind::DeAtChPostfach, "1234, 10557 Berlin" ; "de postfach trailing prose")]
    #[test_case("Packstation: 109, 01099 Dresden. Ihr Paket wird dort abgelegt.", PiiKind::DePackstation, "109, 01099 Dresden" ; "de packstation trailing prose")]
    // Multi-word city names must still be captured correctly
    #[test_case("Anschrift: Rathausplatz 1, 60311 Frankfurt am Main. Bitte bestätigen.", PiiKind::DeAtChAddress, "Rathausplatz 1, 60311 Frankfurt am Main" ; "de address multi word city trailing prose")]
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

    // Unicode context — detection still succeeds.
    // RTL mark (U+200F) before the keyword is just a prefix byte; vectorscan
    // finds "phone" at its actual position in the byte stream.
    #[test_case("\u{200F}phone: 555-123-4567" ; "phone rtl mark prefix")]
    #[test_case("\u{200F}passport: 123456789" ; "passport rtl mark prefix")]
    // U+200B inside the keyword is stripped before scanning, so "ph\u{200B}one"
    // normalises to "phone" and the keyword is matched.
    #[test_case("ph\u{200B}one: 555-123-4567" ; "phone zwsp in keyword stripped")]
    #[test_case("pass\u{200B}port: 123456789" ; "passport zwsp in keyword stripped")]
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
    // French address
    #[test_case("adresse: 15 rue de la Paix, 75002 Paris" ; "fr address keyword adresse")]
    #[test_case("domicile: 42 boulevard Haussmann, 75009 Paris" ; "fr address keyword domicile")]
    #[test_case("BP: 1234, 75008 Paris" ; "fr bp keyword bp")]
    #[test_case("boîte postale: 56, 69001 Lyon" ; "fr bp keyword boite postale")]
    // German address
    #[test_case("Anschrift: Musterstraße 42, 10115 Berlin" ; "de address keyword anschrift")]
    #[test_case("Wohnsitz: Hauptstraße 1, 80331 München" ; "de address keyword wohnsitz")]
    #[test_case("Adresse: Friedrichstraße 43, 10117 Berlin" ; "de address keyword adresse")]
    #[test_case("Privatadresse: Bahnhofstr. 1, 60311 Frankfurt" ; "de address keyword privatadresse")]
    // German Postfach
    #[test_case("Postfach: 1234, 10557 Berlin" ; "de postfach keyword postfach")]
    #[test_case("PF: 56, 80331 München" ; "de postfach keyword pf")]
    // German Packstation
    #[test_case("Packstation: 109, 01099 Dresden" ; "de packstation keyword packstation")]
    #[test_case("Postfiliale: 502, 10115 Berlin" ; "de packstation keyword postfiliale")]
    #[test_case("Paketshop: 1234, 20095 Hamburg" ; "de packstation keyword paketshop")]
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
    #[test_case("dob: 15/13/1990", PiiKind::DateOfBirth ; "dob invalid month 13")]
    #[test_case("dob: 00/00/0000", PiiKind::DateOfBirth ; "dob all zeros")]
    // France
    #[test_case("numéro de sécu: 1 85 05 78 006 084 99", PiiKind::FrNir ; "fr nir bad checksum")]
    #[test_case("n° sécu: 185036912304533", PiiKind::FrNir ; "fr nir lyon off by one")]
    #[test_case("code postal: 00100", PiiKind::FrPostalCode ; "fr postal below range")]
    #[test_case("code postal: 99999", PiiKind::FrPostalCode ; "fr postal above range")]
    #[test_case("numéro fiscal: 4123456789012", PiiKind::FrNif ; "fr nif invalid first digit")]
    #[test_case("SIRET: 73282932000075", PiiKind::FrSiret ; "fr siret bad luhn")]
    #[test_case("SIRET: 77567041700052", PiiKind::FrSiret ; "fr siret lvmh off by one")]
    #[test_case("SIREN: 732829321", PiiKind::FrSiren ; "fr siren bad luhn")]
    #[test_case("SIREN: 775670418", PiiKind::FrSiren ; "fr siren lvmh off by one")]
    // Germany/Austria/Switzerland
    #[test_case("Steuer-ID: 65929970480", PiiKind::DeSteuerId ; "de steuer id bad checksum")]
    #[test_case("Steuer-ID: 26954371820", PiiKind::DeSteuerId ; "de steuer id bad checksum 2")]
    #[test_case("Personalausweis: L01X00T470", PiiKind::DePersonalausweis ; "de personalausweis bad check")]
    #[test_case("Personalausweis: T220001290", PiiKind::DePersonalausweis ; "de personalausweis bad check 2")]
    #[test_case("PLZ: 00100", PiiKind::DePostalCode ; "de postal below range")]
    #[test_case("PLZ: 00000", PiiKind::DePostalCode ; "de postal all zeros")]
    #[test_case("SVNR: 1230150185", PiiKind::AtSvnr ; "at svnr bad checksum")]
    #[test_case("SVNR: 1238010180", PiiKind::AtSvnr ; "at svnr check digit off by one")]
    #[test_case("PLZ: 1000", PiiKind::AtPostalCode ; "at postal below range")]
    #[test_case("PLZ: 1009", PiiKind::AtPostalCode ; "at postal just below range")]
    #[test_case("AHV-Nummer: 7561234567890", PiiKind::ChAhv ; "ch ahv bad checksum")]
    #[test_case("AHV-Nummer: 756.9217.0769.80", PiiKind::ChAhv ; "ch ahv bad checksum real prefix")]
    #[test_case("AHV-Nummer: 1231234567897", PiiKind::ChAhv ; "ch ahv wrong prefix")]
    #[test_case("PLZ: 9999", PiiKind::ChPostalCode ; "ch postal above range")]
    #[test_case("PLZ: 0999", PiiKind::ChPostalCode ; "ch postal below range")]
    // PersonName — rejects non-name values
    #[test_case("full name: 12345", PiiKind::PersonName ; "person name digits only")]
    #[test_case("first name: a", PiiKind::PersonName ; "person name single lowercase")]
    // French/Swiss address — invalid PLZ
    #[test_case("adresse: 15 rue de la Paix, 00000 Paris", PiiKind::FrChAddress ; "fr address invalid plz zeros")]
    #[test_case("domicile: rue du Général-Dufour 24, 0999 Genève", PiiKind::FrChAddress ; "ch address invalid plz below range")]
    #[test_case("BP: 1234567, 75008 Paris", PiiKind::FrChBoitePostale ; "fr bp too many digits")]
    #[test_case("CP: 1234, 0999 Genève", PiiKind::FrChBoitePostale ; "ch cp invalid plz below range")]
    // German/Austrian address — invalid PLZ
    #[test_case("Anschrift: Musterstraße 42, 00000 Berlin", PiiKind::DeAtChAddress ; "de address invalid plz zeros")]
    #[test_case("Anschrift: Schillerstraße 10, 0999 Wien", PiiKind::DeAtChAddress ; "at address plz below 1010")]
    #[test_case("Anschrift: Bahnhofstrasse 1, 0500 Zürich", PiiKind::DeAtChAddress ; "ch address plz below 1000")]
    #[test_case("Postfach: 1234567, 10115 Berlin", PiiKind::DeAtChPostfach ; "de postfach too many digits")]
    #[test_case("Packstation: 12, 10115 Berlin", PiiKind::DePackstation ; "de packstation too few digits")]
    #[test_case("driver's licence: 8013015009087", PiiKind::ZaDriversLicense ; "za dl invalid month")]
    #[test_case("driver's licence: 8001015009086", PiiKind::ZaDriversLicense ; "za dl bad luhn")]
    #[test_case("postal code: 0000", PiiKind::ZaPostalCode ; "za postal code zero")]
    #[test_case("australian driver's licence: 12345", PiiKind::AuDriversLicense ; "au dl too short")]
    #[test_case("australian driver's licence: 0000000", PiiKind::AuDriversLicense ; "au dl all zeros")]
    #[test_case("ABN: 51824753557", PiiKind::AuAbn ; "au abn bad checksum")]
    #[test_case("ABN: 1234567890", PiiKind::AuAbn ; "au abn 10 digits")]
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
    #[test_case("+44 7911 123456", PiiKind::GbPhoneNumber ; "gb phone no keyword")]
    #[test_case("04 1234 5678", PiiKind::AuPhoneNumber ; "au phone no keyword")]
    #[test_case("02 123 4567", PiiKind::NzPhoneNumber ; "nz phone no keyword")]
    #[test_case("087 123 4567", PiiKind::IePhoneNumber ; "ie phone no keyword")]
    #[test_case("071 123 4567", PiiKind::ZaPhoneNumber ; "za phone no keyword")]
    #[test_case("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", PiiKind::AwsSecretKey ; "aws secret no keyword")]
    #[test_case("123456789", PiiKind::GbZaPassportNumber ; "gb passport no keyword")]
    #[test_case("A1234567", PiiKind::AuPassportNumber ; "au passport no keyword")]
    #[test_case("AB123456", PiiKind::CaPassportNumber ; "ca passport no keyword")]
    #[test_case("NZ123456", PiiKind::NzPassportNumber ; "nz passport no keyword")]
    #[test_case("AB1234567", PiiKind::IePassportNumber ; "ie passport no keyword")]
    #[test_case("15/03/1990", PiiKind::DateOfBirth ; "dob no keyword")]
    #[test_case("012-345", PiiKind::AuBankAccount ; "au bsb no keyword")]
    #[test_case("1234567890", PiiKind::CaBankAccount ; "ca bank no keyword")]
    // France
    #[test_case("185057800608491", PiiKind::FrNir ; "fr nir no keyword")]
    #[test_case("73282932000074", PiiKind::FrSiret ; "fr siret no keyword")]
    #[test_case("06 12 34 56 78", PiiKind::FrPhoneNumber ; "fr phone no keyword")]
    #[test_case("75008", PiiKind::FrPostalCode ; "fr postal no keyword")]
    #[test_case("0123456789012", PiiKind::FrNif ; "fr nif no keyword")]
    // Germany/Austria/Switzerland
    #[test_case("65929970489", PiiKind::DeSteuerId ; "de steuer id no keyword")]
    #[test_case("L01X00T471", PiiKind::DePersonalausweis ; "de personalausweis no keyword")]
    #[test_case("+49 30 12345678", PiiKind::DePhoneNumber ; "de phone no keyword")]
    #[test_case("10115", PiiKind::DePostalCode ; "de postal no keyword")]
    #[test_case("1238150185", PiiKind::AtSvnr ; "at svnr no keyword")]
    #[test_case("+43 1 12345678", PiiKind::AtPhoneNumber ; "at phone no keyword")]
    #[test_case("1010", PiiKind::AtPostalCode ; "at postal no keyword")]
    #[test_case("7561234567897", PiiKind::ChAhv ; "ch ahv no keyword")]
    #[test_case("+41 44 123 45 67", PiiKind::ChPhoneNumber ; "ch phone no keyword")]
    #[test_case("8001", PiiKind::ChPostalCode ; "ch postal no keyword")]
    #[test_case("John Smith", PiiKind::PersonName ; "person name no keyword")]
    #[test_case("Maria Garcia-Lopez", PiiKind::PersonName ; "person name hyphenated no keyword")]
    // French/Swiss address types — no keyword
    #[test_case("15 rue de la Paix, 75002 Paris", PiiKind::FrChAddress ; "fr address no keyword")]
    #[test_case("rue du Général-Dufour 24, 1211 Genève", PiiKind::FrChAddress ; "ch fr address no keyword")]
    #[test_case("1234, 75008 Paris", PiiKind::FrChBoitePostale ; "fr bp no keyword")]
    #[test_case("2272, 1950 Sion", PiiKind::FrChBoitePostale ; "ch cp no keyword")]
    // German/Austrian address types — no keyword
    #[test_case("Musterstraße 42, 10115 Berlin", PiiKind::DeAtChAddress ; "de address no keyword")]
    #[test_case("Schillerstraße 10, 1010 Wien", PiiKind::DeAtChAddress ; "at address no keyword")]
    #[test_case("Bahnhofstrasse 1, 8001 Zürich", PiiKind::DeAtChAddress ; "ch address no keyword")]
    #[test_case("1234, 10557 Berlin", PiiKind::DeAtChPostfach ; "de postfach no keyword")]
    #[test_case("109, 01099 Dresden", PiiKind::DePackstation ; "de packstation no keyword")]
    #[test_case("8001015009087", PiiKind::ZaDriversLicense ; "za dl no keyword")]
    #[test_case("0001", PiiKind::ZaPostalCode ; "za postal no keyword")]
    #[test_case("12345678", PiiKind::AuDriversLicense ; "au dl no keyword")]
    #[test_case("51824753556", PiiKind::AuAbn ; "au abn no keyword")]
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

    // --- URL query parameter format (underscore keywords, = separator) ---

    #[test_case("last_name=Lopez", PiiKind::PersonName, "Lopez" ; "url qp last_name")]
    #[test_case("first_name=Alberto", PiiKind::PersonName, "Alberto" ; "url qp first_name")]
    #[test_case("full_name=Alberto Lopez", PiiKind::PersonName, "Alberto Lopez" ; "url qp full_name")]
    #[test_case("phone_number=555-123-4567", PiiKind::PhoneNumber, "555-123-4567" ; "url qp phone_number")]
    #[test_case("passport_number=123456789", PiiKind::PassportNumber, "123456789" ; "url qp passport_number")]
    #[test_case("date_of_birth=15/03/1990", PiiKind::DateOfBirth, "15/03/1990" ; "url qp date_of_birth")]
    #[test_case("sort_code=20-00-00", PiiKind::GbSortCode, "20-00-00" ; "url qp sort_code")]
    // Array bracket notation: param[key]=value
    #[test_case("user[last_name]=Lopez", PiiKind::PersonName, "Lopez" ; "url qp bracket last_name")]
    #[test_case("user[first_name]=Alberto", PiiKind::PersonName, "Alberto" ; "url qp bracket first_name")]
    #[test_case("data[phone_number]=555-123-4567", PiiKind::PhoneNumber, "555-123-4567" ; "url qp bracket phone_number")]
    #[test_case("person[date_of_birth]=15/03/1990", PiiKind::DateOfBirth, "15/03/1990" ; "url qp bracket date_of_birth")]
    fn detects_url_query_params(input: &str, kind: PiiKind, expected_span: &str) {
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
