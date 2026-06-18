use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use vectorscan_rs::{BlockDatabase, BlockScanner, Flag, Pattern, Scan};

use crate::Language;
use crate::detector::Detector;
use crate::normalize::decode_for_detection;
use crate::validators::{
    a_number_check, aba_check, always_valid, at_postal_check, at_svnr_check, au_abn_check,
    au_dl_check, bsn_check, ch_ahv_check, ch_postal_check, de_at_address_check,
    de_at_postfach_check, de_packstation_check, de_passport_check, de_personalausweis_check,
    de_postal_check, de_steuer_id_check, dob_check, ein_check, es_nuss_check, es_passport_check,
    es_postal_check, fr_ch_address_check, fr_ch_boite_postale_check, fr_nif_check, fr_postal_check,
    gb_address_check, geolocation_check, ie_driver_check, imei_check, ird_check,
    it_codice_fiscale_check, it_dl_check, it_partita_iva_check, it_passport_check, it_postal_check,
    medicare_check, nhi_check, nhs_check, nir_check, nl_dl_check, nl_passport_check,
    nl_postal_check, nz_dl_check, ohip_check, passport_check, passport_new_check,
    person_name_check, phone_check, pl_dl_check, pl_id_card_check, pl_nip_check, pl_passport_check,
    pl_pesel_check, pl_postal_check, pl_regon_check, siren_luhn_check, siret_luhn_check,
    sort_code_check, swift_bic_check, tfn_check, us_dl_check, us_za_postal_check,
    uscis_receipt_check, utr_check, za_luhn13_check, za_trn_check,
};
use crate::{ContextFragment, PiiError, PiiKind, PiiMatch};

thread_local! {
    static KW_DETECTION_CACHE: RefCell<Option<(usize, BlockScanner<'static>)>>
        = const { RefCell::new(None) };
}

/// Matches `[<digits>]` array-index segments like `[0]`, `[42]` so they can
/// be stripped from a structured-scan key path before iterating prefixes.
static ARRAY_INDEX_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[\d+\]").unwrap());

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

/// Marker in keyword patterns for the keyword→value gap. Expanded per pattern
/// at build time into the pattern's `Language`-specific connector alternation
/// OR-ed with the language-neutral punctuation separator class. Keeping the gap
/// as a placeholder means each language carries only its own connectors in the
/// vectorscan DFA — see `Language::connector_words` and `expand_connectors`.
const CONNECTOR_PLACEHOLDER: &str = "<<C>>";

/// Replace the `<<C>>` gap marker in `pattern` with the concrete keyword→value
/// gap for `lang`: a word-framed alternation of the language's connector words,
/// OR the lazy punctuation separator class that covers structured payloads
/// (JSON/CSV/URL), markdown emphasis wrappers (`*`, `_`, `` ` ``, `~`),
/// bracket/paren wrappers around the keyword or value (`[`, `]`, `(`, `)`,
/// `{`, `}`), and XML/HTML tag delimiters (`<`, `>`) so a tag-name keyword
/// reaches the value (e.g. `<passport>123456789</passport>`). `\x22` is `"`
/// and the trailing `\\` is a literal backslash; the template is a raw string
/// so both reach the regex engine verbatim.
fn expand_connectors(pattern: &str, lang: Language) -> String {
    let gap = format!(
        r"(?:\s+(?:{})\s+|[\s:.#/\-\x22=,()\[\]{{}}<>\\*_~`]*?)",
        lang.connector_words()
    );
    pattern.replace(CONNECTOR_PLACEHOLDER, &gap)
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
                r"(?i)(?:australian[\s_-]?tax[\s_-]?file[\s_-]?numbers?|australian[\s_-]?tfn|aus[\s_-]?tfn|ato[\s_-]?tax[\s_-]?file[\s_-]?numbers?|ato[\s_-]?tfn|individual[\s_-]?tax[\s_-]?file[\s_-]?numbers?|tax[\s_-]?file[\s_-]?numbers?|tax[\s_-]?file[\s_-]?no\.?|tax[\s_-]?file[\s_-]?num|tax[\s_-]?file[\s_-]?#|tax[\s_-]?file[\s_-]?ref(?:erence)?|tax[\s_-]?file[\s_-]?identifier|applicant[\s_-]?tfn|employee[\s_-]?tfn|client[\s_-]?tfn|customer[\s_-]?tfn|my[\s_-]?tfn|your[\s_-]?tfn|tfn[\s_-]?numbers?|tfn[\s_-]?no\.?|tfn[\s_-]?num|tfn)<<C>>(\d{3}[\s\-]?\d{3}[\s\-]?\d{3})",
                tfn_check,
            ),
            (
                PiiKind::NzIrdNumber,
                Language::En,
                r"(?i)(?:inland[\s_-]?revenue[\s_-]?dep(?:artmen)?t|inland[\s_-]?revenue[\s_-]?numbers?|inland[\s_-]?revenue[\s_-]?no\.?|new[\s_-]?zealand[\s_-]?ird|new[\s_-]?zealand[\s_-]?tax[\s_-]?numbers?|new[\s_-]?zealand[\s_-]?tax[\s_-]?id|nz[\s_-]?ird|nz[\s_-]?tax[\s_-]?numbers?|nz[\s_-]?tax[\s_-]?id|ird[\s_-]?numbers?[\s_-]?nz|ird[\s_-]?numbers?|ird[\s_-]?no\.?|ird[\s_-]?num|ird[\s_-]?#|ird[\s_-]?ref(?:erence)?|applicant[\s_-]?ird|employee[\s_-]?ird|client[\s_-]?ird|customer[\s_-]?ird|my[\s_-]?ird|your[\s_-]?ird|gst[\s_-]?registration|gst[\s_-]?numbers?|gst[\s_-]?no\.?|tax[\s_-]?numbers?[\s_-]?nz|ird)<<C>>(\d{2,3}-?\d{3}-?\d{3})",
                ird_check,
            ),
            (
                PiiKind::GbNhsNumber,
                Language::En,
                r"(?i)(?:national[\s_-]?health[\s_-]?service[\s_-]?numbers?|national[\s_-]?health[\s_-]?service[\s_-]?no\.?|nhs[\s_-]?patient[\s_-]?numbers?|nhs[\s_-]?patient[\s_-]?id|nhs[\s_-]?patient[\s_-]?no\.?|nhs[\s_-]?record[\s_-]?numbers?|nhs[\s_-]?registration|nhs[\s_-]?identifier|nhs[\s_-]?numbers?|nhs[\s_-]?no\.?|nhs[\s_-]?num|nhs[\s_-]?#|nhs[\s_-]?id|nhs[\s_-]?ref(?:erence)?|nhs[\s_-]?record|health[\s_-]?service[\s_-]?numbers?|health[\s_-]?service[\s_-]?no\.?|health[\s_-]?index[\s_-]?numbers?|health[\s_-]?id|patient[\s_-]?numbers?|patient[\s_-]?no\.?|patient[\s_-]?id|my[\s_-]?nhs[\s_-]?numbers?|your[\s_-]?nhs[\s_-]?numbers?|chi[\s_-]?numbers?|h&c[\s_-]?numbers?|hc[\s_-]?numbers?|nhs)<<C>>(\d{3}\s\d{3}\s\d{4})",
                nhs_check,
            ),
            (
                PiiKind::AuMedicare,
                Language::En,
                r"(?i)(?:medicare[\s_-]?cards?[\s_-]?numbers?|medicare[\s_-]?cards?[\s_-]?no\.?|medicare[\s_-]?cards?|australian[\s_-]?medicare|medicare[\s_-]?enrol(?:l)?ment|medicare[\s_-]?registration|medicare[\s_-]?identifier|medicare[\s_-]?numbers?|medicare[\s_-]?no\.?|medicare[\s_-]?num|medicare[\s_-]?#|medicare[\s_-]?id|medicare[\s_-]?ref(?:erence)?|medicare[\s_-]?patient|aus[\s_-]?medicare|au[\s_-]?medicare|applicant[\s_-]?medicare|employee[\s_-]?medicare|client[\s_-]?medicare|customer[\s_-]?medicare|my[\s_-]?medicare|your[\s_-]?medicare|medicare|irn)<<C>>(\d{4}\s\d{5}\s\d)",
                medicare_check,
            ),
            (
                PiiKind::UsPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_-]?us|phone[\s_-]?usa|phone[\s_-]?numbers?|phone[\s_-]?no\.?|phone[\s_-]?num|phone[\s_-]?#|telephone[\s_-]?numbers?|telephone[\s_-]?no\.?|telephones?|mobile[\s_-]?numbers?|mobile[\s_-]?no\.?|mobile[\s_-]?phones?|mobiles?|cell[\s_-]?phones?|cell[\s_-]?numbers?|cells?|contact[\s_-]?numbers?|contact[\s_-]?no\.?|contact[\s_-]?phones?|callback[\s_-]?numbers?|callback[\s_-]?no\.?|callbacks?|fax[\s_-]?numbers?|fax[\s_-]?no\.?|fax(?:es)?|tel[\s_-]?numbers?|tel[\s_-]?no\.?|tel|landlines?|home[\s_-]?phones?|work[\s_-]?phones?|office[\s_-]?phones?|alternate[\s_-]?phones?|alt[\s_-]?phones?|my[\s_-]?phones?|your[\s_-]?phones?|customer[\s_-]?phones?|applicant[\s_-]?phones?|phones?)<<C>>((?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})",
                phone_check,
            ),
            (
                PiiKind::PassportNumber,
                Language::En,
                r"(?i)(?:united[\s_-]?states[\s_-]?passports?|passport[\s_-]?book[\s_-]?numbers?|passport[\s_-]?book[\s_-]?no\.?|passport[\s_-]?cards?[\s_-]?numbers?|us[\s_-]?passports?[\s_-]?numbers?|us[\s_-]?passports?[\s_-]?no\.?|american[\s_-]?passports?|travel[\s_-]?document[\s_-]?numbers?|travel[\s_-]?document[\s_-]?no\.?|travel[\s_-]?doc[\s_-]?numbers?|travel[\s_-]?doc[\s_-]?no\.?|passport[\s_-]?numbers?|passport[\s_-]?no\.?|passport[\s_-]?num|passport[\s_-]?#|passport[\s_-]?id|passport[\s_-]?cards?|us[\s_-]?passports?|travel[\s_-]?doc|applicant[\s_-]?passports?|my[\s_-]?passports?|your[\s_-]?passports?|document[\s_-]?numbers?|document[\s_-]?no\.?|doc[\s_-]?numbers?|doc[\s_-]?no\.?|passports?)<<C>>(\d{9}|\d{2}[A-Za-z]{2}\d{5})\b",
                passport_check,
            ),
            (
                PiiKind::UsPassportNew,
                Language::En,
                r"(?i)(?:united[\s_-]?states[\s_-]?passports?|passport[\s_-]?book[\s_-]?numbers?|passport[\s_-]?book[\s_-]?no\.?|passport[\s_-]?cards?[\s_-]?numbers?|us[\s_-]?passports?[\s_-]?numbers?|us[\s_-]?passports?[\s_-]?no\.?|american[\s_-]?passports?|travel[\s_-]?document[\s_-]?numbers?|travel[\s_-]?document[\s_-]?no\.?|travel[\s_-]?doc[\s_-]?numbers?|travel[\s_-]?doc[\s_-]?no\.?|passport[\s_-]?numbers?|passport[\s_-]?no\.?|passport[\s_-]?num|passport[\s_-]?#|passport[\s_-]?id|passport[\s_-]?cards?|us[\s_-]?passports?|travel[\s_-]?doc|applicant[\s_-]?passports?|my[\s_-]?passports?|your[\s_-]?passports?|document[\s_-]?numbers?|document[\s_-]?no\.?|doc[\s_-]?numbers?|doc[\s_-]?no\.?|passports?)<<C>>([AXYZaxyz]\d{8})",
                passport_new_check,
            ),
            (
                PiiKind::SwiftBic,
                Language::En,
                r"(?i)(?:bank[\s_-]?identifier[\s_-]?code|bank[\s_-]?identifier|correspondent[\s_-]?(?:bank[\s_-]?)?swift|intermediary[\s_-]?swift|intermediary[\s_-]?bic|international[\s_-]?bank[\s_-]?code|beneficiary[\s_-]?swift|beneficiary[\s_-]?bic|swift/bic|swift[\s_-]?bic|bic/swift|swift[\s_-]?code|swift[\s_-]?numbers?|swift[\s_-]?no\.?|swift[\s_-]?#|swift[\s_-]?address(?:es)?|swift[\s_-]?id|bank[\s_-]?swift|bank[\s_-]?routing|bank[\s_-]?bic|bic[\s_-]?code|bic[\s_-]?numbers?|bic[\s_-]?no\.?|bic[\s_-]?#|bic[\s_-]?id|routing[\s_-]?code|clearing[\s_-]?code|my[\s_-]?swift|swift|bic)<<C>>([A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?)\b",
                swift_bic_check,
            ),
            (
                PiiKind::UsEin,
                Language::En,
                r"(?i)(?:employer[\s_-]?identification[\s_-]?numbers?|employer[\s_-]?identification[\s_-]?no\.?|federal[\s_-]?employer[\s_-]?identification|employer[\s_-]?id[\s_-]?numbers?|employer[\s_-]?id[\s_-]?no\.?|federal[\s_-]?employer[\s_-]?id|federal[\s_-]?tax[\s_-]?identification|tax[\s_-]?identification[\s_-]?numbers?|federal[\s_-]?id[\s_-]?numbers?|federal[\s_-]?id[\s_-]?no\.?|federal[\s_-]?tax[\s_-]?id|federal[\s_-]?ein|tax[\s_-]?id[\s_-]?numbers?|employer[\s_-]?numbers?|employer[\s_-]?no\.?|business[\s_-]?tax[\s_-]?id|company[\s_-]?tax[\s_-]?id|company[\s_-]?ein|irs[\s_-]?employer[\s_-]?id|applicant[\s_-]?ein|ein[\s_-]?numbers?|ein[\s_-]?no\.?|ein[\s_-]?num|ein[\s_-]?#|tax[\s_-]?id|irs[\s_-]?ein|our[\s_-]?ein|my[\s_-]?ein|fein|ein)<<C>>(\d{2}-\d{7})",
                ein_check,
            ),
            (
                PiiKind::Imei,
                Language::En,
                r"(?i)(?:international[\s_-]?mobile[\s_-]?equipment[\s_-]?identity|mobile[\s_-]?equipment[\s_-]?identity|equipment[\s_-]?identity|device[\s_-]?identifier|device[\s_-]?id[\s_-]?numbers?|device[\s_-]?serial|device[\s_-]?imei|handset[\s_-]?imei|serial[\s_-]?imei|mobile[\s_-]?imei|tablet[\s_-]?imei|equipment[\s_-]?id|phone[\s_-]?imei|imei[\s_-]?identifier|imei[\s_-]?numbers?|imei[\s_-]?no\.?|imei[\s_-]?num|imei[\s_-]?#|imei[\s_-]?code|imei[\s_-]?id|your[\s_-]?imei|my[\s_-]?imei|meid|imei)<<C>>(\d{2}-?\d{6}-?\d{6}-?\d)",
                imei_check,
            ),
            (
                PiiKind::GbUtr,
                Language::En,
                r"(?i)(?:unique[\s_-]?taxpayer[\s_-]?ref(?:erence)?|unique[\s_-]?tax[\s_-]?ref(?:erence)?|taxpayer[\s_-]?ref(?:erence)?|tax[\s_-]?ref(?:erence)?|hmrc[\s_-]?ref(?:erence)?|hmrc[\s_-]?utr|self[\s_-]?assessment[\s_-]?ref(?:erence)?|self[\s_-]?assessment[\s_-]?utr|self[\s_-]?assessment[\s_-]?numbers?|self[\s_-]?assessment[\s_-]?no\.?|sa[\s_-]?utr|sa[\s_-]?ref(?:erence)?|sa[\s_-]?numbers?|sa[\s_-]?no\.?|corporation[\s_-]?tax[\s_-]?ref(?:erence)?|corporation[\s_-]?tax[\s_-]?utr|ct[\s_-]?utr|ct[\s_-]?ref(?:erence)?|company[\s_-]?utr|company[\s_-]?tax[\s_-]?ref(?:erence)?|partnership[\s_-]?utr|partnership[\s_-]?ref(?:erence)?|your[\s_-]?utr|my[\s_-]?utr|client[\s_-]?utr|customer[\s_-]?utr|applicant[\s_-]?utr|utr[\s_-]?numbers?|utr[\s_-]?no\.?|utr[\s_-]?num|utr[\s_-]?#|utr[\s_-]?ref(?:erence)?|utr)<<C>>(\d{10})\b",
                utr_check,
            ),
            (
                PiiKind::UsAbaRouting,
                Language::En,
                r"(?i)(?:aba[\s_-]?routing[\s_-]?numbers?|aba[\s_-]?routing[\s_-]?no\.?|aba[\s_-]?routing|aba[\s_-]?numbers?|aba[\s_-]?no\.?|aba[\s_-]?#|routing[\s_-]?transit[\s_-]?numbers?|routing[\s_-]?transit[\s_-]?no\.?|routing[\s_-]?numbers?|routing[\s_-]?no\.?|routing[\s_-]?#|bank[\s_-]?routing[\s_-]?numbers?|bank[\s_-]?routing[\s_-]?no\.?|bank[\s_-]?routing|transit[\s_-]?numbers?|transit[\s_-]?no\.?|transit[\s_-]?#|aba[\s_-]?rtn|rtn[\s_-]?numbers?|rtn[\s_-]?no\.?|rtn[\s_-]?#|fed[\s_-]?routing|fedwire[\s_-]?routing|ach[\s_-]?routing|wire[\s_-]?routing|wire[\s_-]?transfer[\s_-]?routing|my[\s_-]?routing[\s_-]?numbers?|your[\s_-]?routing[\s_-]?numbers?|bank[\s_-]?rtn|routing[\s_-]?code|aba|rtn)<<C>>(\d{9})\b",
                aba_check,
            ),
            (
                PiiKind::GbSortCode,
                Language::En,
                r"(?i)(?:sort[\s_-]?code|sort-code|sortcode|sort[\s_-]?code[\s_-]?numbers?|sort[\s_-]?code[\s_-]?no\.?|sort[\s_-]?code[\s_-]?#|bank[\s_-]?sort[\s_-]?code|bank[\s_-]?sort|branch[\s_-]?sort[\s_-]?code|branch[\s_-]?sort|branch[\s_-]?code|branch[\s_-]?numbers?|branch[\s_-]?no\.?|branch[\s_-]?#|bank[\s_-]?code|bank[\s_-]?numbers?|bank[\s_-]?no\.?|uk[\s_-]?sort[\s_-]?code|uk[\s_-]?sort|bacs[\s_-]?sort[\s_-]?code|bacs[\s_-]?code|my[\s_-]?sort[\s_-]?code|your[\s_-]?sort[\s_-]?code|account[\s_-]?sort[\s_-]?code|account[\s_-]?sort)<<C>>(\d{2}-?\d{2}-?\d{2})\b",
                sort_code_check,
            ),
            (
                PiiKind::PreciseGeolocation,
                Language::En,
                r"(?i)(?:gps[\s_-]?coordinates|gps[\s_-]?coordinate|gps[\s_-]?coords|gps[\s_-]?location|gps[\s_-]?position|precise[\s_-]?location|precise[\s_-]?coordinates|exact[\s_-]?location|exact[\s_-]?coordinates|location[\s_-]?coordinates|map[\s_-]?coordinates|position[\s_-]?coordinates|geo[\s_-]?coordinates|geocoordinates|geo[\s_-]?coords|geocoords|latitude/longitude|latitude[\s_-]?longitude|lat/long|lat/lon|lat[\s_-]?long|lat[\s_-]?lon|latlong|latlon|lat[\s_-]?lng|latlng|geolocation|geo-location|geo[\s_-]?location|geo[\s_-]?position|geoposition|map[\s_-]?position|map[\s_-]?location|current[\s_-]?location|current[\s_-]?coordinates|current[\s_-]?position|device[\s_-]?location|device[\s_-]?coordinates|device[\s_-]?position|my[\s_-]?location|my[\s_-]?coordinates|my[\s_-]?position|coordinates|coordinate|coords)<<C>>(-?\d{1,3}\.\d{4,},\s?-?\d{1,3}\.\d{4,})",
                geolocation_check,
            ),
            (
                PiiKind::UsAlienNumber,
                Language::En,
                r"(?i)(?:alien[\s_-]?registration[\s_-]?numbers?|alien[\s_-]?registration[\s_-]?no\.?|alien[\s_-]?registration|alien[\s_-]?numbers?|alien[\s_-]?no\.?|alien[\s_-]?#|a-number|uscis[\s_-]?alien[\s_-]?numbers?|uscis[\s_-]?alien[\s_-]?no\.?|uscis[\s_-]?numbers?|uscis[\s_-]?no\.?|uscis[\s_-]?id|uscis[\s_-]?#|green[\s_-]?cards?[\s_-]?numbers?|green[\s_-]?cards?[\s_-]?no\.?|green[\s_-]?cards?[\s_-]?#|permanent[\s_-]?resident[\s_-]?numbers?|permanent[\s_-]?resident[\s_-]?no\.?|immigration[\s_-]?numbers?|immigration[\s_-]?no\.?|immigration[\s_-]?id|dhs[\s_-]?numbers?|dhs[\s_-]?no\.?|my[\s_-]?a-number|your[\s_-]?a-number|applicant[\s_-]?a-number)<<C>>([Aa]\d{7,9})\b",
                a_number_check,
            ),
            (
                PiiKind::UsUscisReceiptNumber,
                Language::En,
                r"(?i)(?:uscis[\s_-]?receipt[\s_-]?numbers?|uscis[\s_-]?receipt[\s_-]?no\.?|uscis[\s_-]?receipt|uscis[\s_-]?case[\s_-]?numbers?|uscis[\s_-]?case[\s_-]?no\.?|uscis[\s_-]?case|immigration[\s_-]?case[\s_-]?numbers?|immigration[\s_-]?case[\s_-]?no\.?|immigration[\s_-]?case|petition[\s_-]?receipt[\s_-]?numbers?|petition[\s_-]?receipt[\s_-]?no\.?|petition[\s_-]?receipt|application[\s_-]?receipt[\s_-]?numbers?|application[\s_-]?receipt[\s_-]?no\.?|application[\s_-]?receipt|i-797[\s_-]?receipt|i-797[\s_-]?numbers?|i-797[\s_-]?no\.?|receipt[\s_-]?numbers?|receipt[\s_-]?no\.?|receipt[\s_-]?#|case[\s_-]?numbers?|case[\s_-]?no\.?|case[\s_-]?#|petition[\s_-]?numbers?|petition[\s_-]?no\.?|petition[\s_-]?#|my[\s_-]?receipt[\s_-]?numbers?|your[\s_-]?receipt[\s_-]?numbers?|beneficiary[\s_-]?receipt|applicant[\s_-]?receipt)<<C>>([A-Za-z]{3}\d{10})\b",
                uscis_receipt_check,
            ),
            (
                PiiKind::ZaId,
                Language::En,
                r"(?i)(?:south[\s_-]?african[\s_-]?id[\s_-]?numbers?|south[\s_-]?african[\s_-]?id[\s_-]?no\.?|south[\s_-]?african[\s_-]?id|south[\s_-]?african[\s_-]?identity[\s_-]?numbers?|south[\s_-]?african[\s_-]?identity|sa[\s_-]?id[\s_-]?numbers?|sa[\s_-]?id[\s_-]?no\.?|sa[\s_-]?id|sa[\s_-]?identity[\s_-]?numbers?|sa[\s_-]?identity|national[\s_-]?id[\s_-]?numbers?|national[\s_-]?id[\s_-]?no\.?|national[\s_-]?identity[\s_-]?numbers?|national[\s_-]?identity|id[\s_-]?numbers?|id[\s_-]?no\.?|id[\s_-]?book|id[\s_-]?cards?|identity[\s_-]?numbers?|identity[\s_-]?no\.?|identity[\s_-]?document|identity[\s_-]?cards?|home[\s_-]?affairs[\s_-]?numbers?|home[\s_-]?affairs[\s_-]?no\.?|home[\s_-]?affairs[\s_-]?id|citizen[\s_-]?id|citizen[\s_-]?numbers?|applicant[\s_-]?id|my[\s_-]?id|your[\s_-]?id)<<C>>(\d{13})\b",
                za_luhn13_check,
            ),
            (
                PiiKind::UsDriversLicense,
                Language::En,
                r"(?i)(?:driver'?s?[\s_-]*licen[cs]es?[\s_-]*(?:number|no\.?|num|#)?|driving[\s_-]*licen[cs]es?[\s_-]*(?:number|no\.?|num|#)?|operator'?s?[\s_-]*licen[cs]es?[\s_-]*(?:number|no\.?|num|#)?|state[\s_-]*identification[\s_-]*(?:number|no\.?|num|#)?|state[\s_-]*id[\s_-]*(?:number|no\.?|num|#)?|dmv[\s_-]*(?:number|no\.?|num|#)|dl[\s_-]*(?:number|no\.?|num|#)|my[\s_-]*(?:driver'?s?[\s_-]*licen[cs]es?|dl)|your[\s_-]*(?:driver'?s?[\s_-]*licen[cs]es?|dl)|applicant[\s_-]*(?:driver'?s?[\s_-]*licen[cs]es?|dl)|licen[cs]es?[\s_-]*(?:number|no\.?|num|#)|dl)<<C>>([A-Za-z]{1,2}\d{3}(?:-\d{3,4}){1,3}|[A-Za-z]{1,2}\d{4,14})\b",
                us_dl_check,
            ),
            (
                PiiKind::NzNhiNumber,
                Language::En,
                r"(?i)(?:national[\s_-]?health[\s_-]?index[\s_-]?numbers?|national[\s_-]?health[\s_-]?index[\s_-]?no\.?|national[\s_-]?health[\s_-]?index|nhi[\s_-]?numbers?|nhi[\s_-]?no\.?|nhi[\s_-]?num|nhi[\s_-]?#|nhi[\s_-]?id|nhi[\s_-]?ref(?:erence)?|nhi[\s_-]?code|my[\s_-]?nhi|your[\s_-]?nhi|patient[\s_-]?nhi|nhi)<<C>>([A-HJ-NP-Za-hj-np-z]{3}\d{4})",
                nhi_check,
            ),
            (
                PiiKind::NzDriverLicence,
                Language::En,
                r"(?i)(?:new[\s_-]?zealand[\s_-]?driver[\s_-]?licen[cs]es?|nz[\s_-]?driver[\s_-]?licen[cs]es?|nz[\s_-]?driving[\s_-]?licen[cs]es?|driver[\s_-]?licen[cs]es?|licen[cs]es?[\s_-]?numbers?|licen[cs]es?[\s_-]?no\.?|licence[\s_-]?num|driving[\s_-]?licence)<<C>>([A-Z]{2}\d{6})\b",
                nz_dl_check,
            ),
            (
                PiiKind::IeDriverNumber,
                Language::En,
                r"(?i)(?:irish[\s_-]?driver[\s_-]?numbers?|irish[\s_-]?driving[\s_-]?licen[cs]es?|ireland[\s_-]?driver[\s_-]?numbers?|ireland[\s_-]?driving[\s_-]?licen[cs]es?|ie[\s_-]?driver[\s_-]?numbers?|ie[\s_-]?driving[\s_-]?licen[cs]es?|driver[\s_-]?numbers?|driving[\s_-]?licen[cs]es?|licen[cs]es?[\s_-]?numbers?|driver[\s_-]?no\.?)<<C>>(\d{9})\b",
                ie_driver_check,
            ),
            (
                PiiKind::ZaTaxReference,
                Language::En,
                r"(?i)(?:south[\s_-]?african[\s_-]?tax[\s_-]?ref(?:erence)?|south[\s_-]?african[\s_-]?tax[\s_-]?numbers?|sa[\s_-]?tax[\s_-]?ref(?:erence)?|sa[\s_-]?tax[\s_-]?numbers?|sars[\s_-]?ref(?:erence)?|sars[\s_-]?numbers?|sars[\s_-]?tax|tax[\s_-]?ref(?:erence)?|tax[\s_-]?numbers?|tax[\s_-]?ref|SARS)<<C>>([0-3,9]\d{9})\b",
                za_trn_check,
            ),
            (
                PiiKind::ZaDriversLicense,
                Language::En,
                r"(?i)(?:south[\s_-]?african[\s_-]?driver'?s?[\s_-]?licen[cs]es?|sa[\s_-]?driver'?s?[\s_-]?licen[cs]es?|driver'?s?[\s_-]?licen[cs]es?[\s_-]?numbers?|driver'?s?[\s_-]?licen[cs]es?[\s_-]?no\.?|driver'?s?[\s_-]?licen[cs]es?|driving[\s_-]?licen[cs]es?[\s_-]?numbers?|driving[\s_-]?licen[cs]es?[\s_-]?no\.?|driving[\s_-]?licen[cs]es?|learner'?s?[\s_-]?licen[cs]es?)<<C>>(\d{13})\b",
                za_luhn13_check,
            ),
            (
                PiiKind::UsZaPostalCode,
                Language::En,
                r"(?i)(?:postal[\s_-]?code|post[\s_-]?code|postcode|zip[\s_-]?code|zip)<<C>>(\d{5}-\d{4}|\d{5}|\d{4})\b",
                us_za_postal_check,
            ),
            (
                PiiKind::AuDriversLicense,
                Language::En,
                r"(?i)(?:australian[\s_-]?driver'?s?[\s_-]?licen[cs]es?|aus[\s_-]?driver'?s?[\s_-]?licen[cs]es?|nsw[\s_-]?licen[cs]es?|vic[\s_-]?licen[cs]es?|qld[\s_-]?licen[cs]es?|wa[\s_-]?licen[cs]es?|act[\s_-]?licen[cs]es?|sa[\s_-]?licen[cs]es?|tas[\s_-]?licen[cs]es?|nt[\s_-]?licen[cs]es?|australian[\s_-]?dl|aus[\s_-]?dl)<<C>>(\d{6,10}|[A-Za-z]\d{5,9})\b",
                au_dl_check,
            ),
            (
                PiiKind::AuAbn,
                Language::En,
                r"(?i)(?:australian[\s_-]?business[\s_-]?numbers?|australian[\s_-]?business[\s_-]?no\.?|aus[\s_-]?business[\s_-]?numbers?|abn[\s_-]?numbers?|abn[\s_-]?no\.?|abn[\s_-]?#|abn)<<C>>(\d{2}\s?\d{3}\s?\d{3}\s?\d{3})\b",
                au_abn_check,
            ),
            (
                PiiKind::CaOhip,
                Language::En,
                r"(?i)(?:ontario[\s_-]?health[\s_-]?insurance[\s_-]?plan|ontario[\s_-]?health[\s_-]?cards?|ontario[\s_-]?health[\s_-]?numbers?|health[\s_-]?cards?[\s_-]?numbers?|health[\s_-]?cards?[\s_-]?no\.?|health[\s_-]?cards?|health[\s_-]?insurance[\s_-]?numbers?|health[\s_-]?insurance[\s_-]?no\.?|health[\s_-]?numbers?|carte[\s_-]?sant[eé]|OHIP[\s_-]?numbers?|OHIP[\s_-]?no\.?|OHIP[\s_-]?cards?|OHIP)<<C>>(\d{10}(?:\s?[A-Za-z]{2})?)\b",
                ohip_check,
            ),
            // International phone numbers
            (
                PiiKind::GbPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_-]?uk|phone[\s_-]?gb|phone[\s_-]?numbers?|phone[\s_-]?no\.?|phone[\s_-]?num|phone[\s_-]?#|telephone[\s_-]?numbers?|telephone[\s_-]?no\.?|telephones?|mobile[\s_-]?numbers?|mobile[\s_-]?no\.?|mobile[\s_-]?phones?|mobiles?|cell[\s_-]?phones?|cell[\s_-]?numbers?|cells?|contact[\s_-]?numbers?|contact[\s_-]?no\.?|contact[\s_-]?phones?|callback[\s_-]?numbers?|callback[\s_-]?no\.?|callbacks?|fax[\s_-]?numbers?|fax[\s_-]?no\.?|fax(?:es)?|tel[\s_-]?numbers?|tel[\s_-]?no\.?|tel|landlines?|home[\s_-]?phones?|work[\s_-]?phones?|office[\s_-]?phones?|alternate[\s_-]?phones?|alt[\s_-]?phones?|my[\s_-]?phones?|your[\s_-]?phones?|customer[\s_-]?phones?|applicant[\s_-]?phones?|phones?)<<C>>((?:\+?44[\s\-.]?|0)(?:7\d{3}[\s\-.]?\d{3}[\s\-.]?\d{3}|\d{2,4}[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}))",
                phone_check,
            ),
            (
                PiiKind::AuPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_-]?au|phone[\s_-]?aus|phone[\s_-]?numbers?|phone[\s_-]?no\.?|phone[\s_-]?num|phone[\s_-]?#|telephone[\s_-]?numbers?|telephone[\s_-]?no\.?|telephones?|mobile[\s_-]?numbers?|mobile[\s_-]?no\.?|mobile[\s_-]?phones?|mobiles?|cell[\s_-]?phones?|cell[\s_-]?numbers?|cells?|contact[\s_-]?numbers?|contact[\s_-]?no\.?|contact[\s_-]?phones?|callback[\s_-]?numbers?|callback[\s_-]?no\.?|callbacks?|fax[\s_-]?numbers?|fax[\s_-]?no\.?|fax(?:es)?|tel[\s_-]?numbers?|tel[\s_-]?no\.?|tel|landlines?|home[\s_-]?phones?|work[\s_-]?phones?|office[\s_-]?phones?|alternate[\s_-]?phones?|alt[\s_-]?phones?|my[\s_-]?phones?|your[\s_-]?phones?|customer[\s_-]?phones?|applicant[\s_-]?phones?|phones?)<<C>>((?:\+?61[\s\-.]?|0)[2-578][\s\-.]?\d{4}[\s\-.]?\d{4})",
                phone_check,
            ),
            (
                PiiKind::NzPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_-]?nz|phone[\s_-]?numbers?|phone[\s_-]?no\.?|phone[\s_-]?num|phone[\s_-]?#|telephone[\s_-]?numbers?|telephone[\s_-]?no\.?|telephones?|mobile[\s_-]?numbers?|mobile[\s_-]?no\.?|mobile[\s_-]?phones?|mobiles?|cell[\s_-]?phones?|cell[\s_-]?numbers?|cells?|contact[\s_-]?numbers?|contact[\s_-]?no\.?|contact[\s_-]?phones?|callback[\s_-]?numbers?|callback[\s_-]?no\.?|callbacks?|fax[\s_-]?numbers?|fax[\s_-]?no\.?|fax(?:es)?|tel[\s_-]?numbers?|tel[\s_-]?no\.?|tel|landlines?|home[\s_-]?phones?|work[\s_-]?phones?|office[\s_-]?phones?|alternate[\s_-]?phones?|alt[\s_-]?phones?|my[\s_-]?phones?|your[\s_-]?phones?|customer[\s_-]?phones?|applicant[\s_-]?phones?|phones?)<<C>>((?:\+?64[\s\-.]?|0)[2-9][\s\-.]?\d{3,4}[\s\-.]?\d{4})",
                phone_check,
            ),
            (
                PiiKind::IePhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_-]?ie|phone[\s_-]?numbers?|phone[\s_-]?no\.?|phone[\s_-]?num|phone[\s_-]?#|telephone[\s_-]?numbers?|telephone[\s_-]?no\.?|telephones?|mobile[\s_-]?numbers?|mobile[\s_-]?no\.?|mobile[\s_-]?phones?|mobiles?|cell[\s_-]?phones?|cell[\s_-]?numbers?|cells?|contact[\s_-]?numbers?|contact[\s_-]?no\.?|contact[\s_-]?phones?|callback[\s_-]?numbers?|callback[\s_-]?no\.?|callbacks?|fax[\s_-]?numbers?|fax[\s_-]?no\.?|fax(?:es)?|tel[\s_-]?numbers?|tel[\s_-]?no\.?|tel|landlines?|home[\s_-]?phones?|work[\s_-]?phones?|office[\s_-]?phones?|alternate[\s_-]?phones?|alt[\s_-]?phones?|my[\s_-]?phones?|your[\s_-]?phones?|customer[\s_-]?phones?|applicant[\s_-]?phones?|phones?)<<C>>((?:\+?353[\s\-.]?|0)[1-9](?:[\s\-.]?\d)?[\s\-.]?\d{3,4}[\s\-.]?\d{4})",
                phone_check,
            ),
            (
                PiiKind::ZaPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_-]?za|phone[\s_-]?sa|phone[\s_-]?numbers?|phone[\s_-]?no\.?|phone[\s_-]?num|phone[\s_-]?#|telephone[\s_-]?numbers?|telephone[\s_-]?no\.?|telephones?|mobile[\s_-]?numbers?|mobile[\s_-]?no\.?|mobile[\s_-]?phones?|mobiles?|cell[\s_-]?phones?|cell[\s_-]?numbers?|cells?|contact[\s_-]?numbers?|contact[\s_-]?no\.?|contact[\s_-]?phones?|callback[\s_-]?numbers?|callback[\s_-]?no\.?|callbacks?|fax[\s_-]?numbers?|fax[\s_-]?no\.?|fax(?:es)?|tel[\s_-]?numbers?|tel[\s_-]?no\.?|tel|landlines?|home[\s_-]?phones?|work[\s_-]?phones?|office[\s_-]?phones?|alternate[\s_-]?phones?|alt[\s_-]?phones?|my[\s_-]?phones?|your[\s_-]?phones?|customer[\s_-]?phones?|applicant[\s_-]?phones?|phones?)<<C>>((?:\+?27[\s\-.]?|0)[1-9]\d[\s\-.]?\d{3}[\s\-.]?\d{4})",
                phone_check,
            ),
            // AWS Secret Key
            (
                PiiKind::AwsSecretKey,
                Language::En,
                r"(?i)(?:aws[\s_-]?secret[\s_-]?access[\s_-]?key=?|secret[\s_-]?access[\s_-]?key[\s:.=\x22]+|aws[\s_-]?secret[\s:.=\x22]+)([A-Za-z0-9/+=]{40})",
                always_valid,
            ),
            // Country-specific passport numbers
            (
                PiiKind::GbZaPassportNumber,
                Language::En,
                r"(?i)(?:british[\s_-]?passports?|uk[\s_-]?passports?|united[\s_-]?kingdom[\s_-]?passports?|hmpo|south[\s_-]?african[\s_-]?passports?|sa[\s_-]?passports?)<<C>>(\d{9})\b",
                always_valid,
            ),
            (
                PiiKind::AuPassportNumber,
                Language::En,
                r"(?i)(?:australian[\s_-]?passports?|australia[\s_-]?passports?|passport[\s_-]?numbers?|passport[\s_-]?no\.?|passports?)<<C>>([A-Za-z]\d{7})\b",
                always_valid,
            ),
            (
                PiiKind::CaPassportNumber,
                Language::En,
                r"(?i)(?:canadian[\s_-]?passports?|canada[\s_-]?passports?|passport[\s_-]?numbers?|passport[\s_-]?no\.?|passports?)<<C>>([A-Za-z]{2}\d{6})\b",
                always_valid,
            ),
            (
                PiiKind::NzPassportNumber,
                Language::En,
                r"(?i)(?:new[\s_-]?zealand[\s_-]?passports?|nz[\s_-]?passports?|passport[\s_-]?numbers?|passport[\s_-]?no\.?|passports?)<<C>>([A-Za-z]{1,2}\d{6,7})\b",
                always_valid,
            ),
            (
                PiiKind::IePassportNumber,
                Language::En,
                r"(?i)(?:irish[\s_-]?passports?|ireland[\s_-]?passports?|passport[\s_-]?numbers?|passport[\s_-]?no\.?|passports?)<<C>>([A-Za-z]{2}\d{7})\b",
                always_valid,
            ),
            (
                PiiKind::DePassportNumber,
                Language::En,
                r"(?i)(?:german[\s_-]?passports?|germany[\s_-]?passports?|passport[\s_-]?numbers?|passport[\s_-]?no\.?|passports?)<<C>>([CFGHJKLMNPRTVWXYZ0-9]{9})\b",
                de_passport_check,
            ),
            // German-keyword tuple. Substring-disjoint from the English
            // tuple above: no German keyword contains "passport", and no
            // English keyword contains a German stem ("reisepass", "pass
            // nr", "passdokument", "dokumentennummer", "bundespass", etc.).
            // `deutsche passport(s)` is intentionally absent — it would
            // double-match via the English `passports?` alternation.
            (
                PiiKind::DePassportNumber,
                Language::De,
                r"(?i)(?:deutscher[\s_\-]reisepass|deutscher[\s_\-]pass|bundespass|reisepassnummern?|reisepass[\s_\-]nummern?|reisepass[\s_\-]nr\.?|reisepass[\s_\-]no\.?|reisepass[\s_\-]#|reisepass|passnummern?|pass[\s_\-]nummern?|pass[\s_\-]nr\.?|pass[\s_\-]no\.?|pass[\s_\-]#|passdokumentennummern?|passdokument|reisedokumentennummern?|reisedokument|amtliches[\s_\-]reisedokument|dokumentennummern?)<<C>>([CFGHJKLMNPRTVWXYZ0-9]{9})\b",
                de_passport_check,
            ),
            // Date of birth
            (
                PiiKind::DateOfBirth,
                Language::En,
                r"(?i)(?:date[\s_-]?of[\s_-]?birth|birth[\s_-]?date|birthdate|dob|d\.o\.b\.?|born[\s_-]?on)<<C>>(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}|\d{1,2}\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{4}|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+\d{4})",
                dob_check,
            ),
            // Bank accounts
            (
                PiiKind::AuBankAccount,
                Language::En,
                r"(?i)(?:bsb|bank[\s_-]?state[\s_-]?branch|bsb[\s_-]?numbers?|bsb[\s_-]?no\.?)<<C>>(\d{3}-?\d{3}(?:[\s]+\d{6,10})?)",
                always_valid,
            ),
            (
                PiiKind::CaBankAccount,
                Language::En,
                r"(?i)(?:transit[\s_-]?numbers?|transit[\s_-]?no\.?|institution[\s_-]?numbers?|chequing[\s_-]?account|savings[\s_-]?account|canadian[\s_-]?account|ca[\s_-]?account)<<C>>(\d{5}[-\s]\d{3}[-\s]\d{7,12}|\d{7,12})",
                always_valid,
            ),
            // --- UK street address ---
            // Narrower keyword list (qualified address forms only) with the GB
            // postcode as a hard anchor at the end of the value regex.
            (
                PiiKind::GbAddress,
                Language::En,
                r"(?i)(?:home[\s_-]?address(?:es)?|postal[\s_-]?address(?:es)?|mailing[\s_-]?address(?:es)?|delivery[\s_-]?address(?:es)?|billing[\s_-]?address(?:es)?|shipping[\s_-]?address(?:es)?|correspondence[\s_-]?address(?:es)?|residential[\s_-]?address(?:es)?|business[\s_-]?address(?:es)?|office[\s_-]?address(?:es)?|street[\s_-]?address(?:es)?|registered[\s_-]?office|address[\s_-]?line(?:[\s_-]??[12])?|addr[\s_-]?line(?:[\s_-]??[12])?)<<C>>(\d{1,4}[A-Za-z]?\s+[A-Za-z][A-Za-z'\-]*(?:\s+[A-Za-z'\-.]+){0,6}[,\s]+(?:[A-Za-z][A-Za-z'\-]*(?:\s+[A-Za-z'\-]+){0,3}[,\s]+)?[A-Za-z]{1,2}[0-9][0-9A-Za-z]?\s?[0-9][A-Za-z]{2})",
                gb_address_check,
            ),
            // --- France-specific PII types (Language::Fr) ---
            (
                PiiKind::FrNir,
                Language::Fr,
                r"(?i)(?:num[eé]ros?[\s_-]?de[\s_-]?s[eé]curit[eé][\s_-]?sociale|num[eé]ros?[\s_-]?s[eé]curit[eé][\s_-]?sociale|n°[\s_-]?de[\s_-]?s[eé]curit[eé][\s_-]?sociale|n°[\s_-]?s[eé]curit[eé][\s_-]?sociale|num[eé]ros?[\s_-]?de[\s_-]?s[eé]cu|num[eé]ros?[\s_-]?s[eé]cu|n°[\s_-]?s[eé]cu|s[eé]curit[eé][\s_-]?sociale|num[eé]ros?[\s_-]?SS|n°[\s_-]?SS|code[\s_-]?s[eé]cu|NIR|s[eé]cu)<<C>>(\d[\s.]?\d{2}[\s.]?\d{2}[\s.]?[0-9AB]{2,3}[\s.]?\d{2,3}[\s.]?\d{3}[\s.]?\d{2})",
                nir_check,
            ),
            // Substring-disjoint: French stems "numéro" / "sécu" /
            // "sociale" (with trailing "e") / "n°" / "NIR" / bare "SS" do
            // not appear in any English literal here. The English noun
            // "social" is not a substring of "sociale", so bare phrases
            // like "social security number" are safe — but they would
            // collide with US/other-country usage, so we keep country-
            // prefixed forms only.
            (
                PiiKind::FrNir,
                Language::En,
                r"(?i)(?:french[\s_-]?social[\s_-]?security[\s_-]?numbers?|france[\s_-]?social[\s_-]?security[\s_-]?numbers?|fr[\s_-]?social[\s_-]?security[\s_-]?numbers?|french[\s_-]?ssns?|france[\s_-]?ssns?|fr[\s_-]?ssns?)<<C>>(\d[\s.]?\d{2}[\s.]?\d{2}[\s.]?[0-9AB]{2,3}[\s.]?\d{2,3}[\s.]?\d{3}[\s.]?\d{2})",
                nir_check,
            ),
            (
                PiiKind::FrSiret,
                Language::Fr,
                r"(?i)(?:num[eé]ros?[\s_-]?SIRET|n°[\s_-]?SIRET|[eé]tablissement[\s_-]?SIRET|SIRET)<<C>>(\d{14})\b",
                siret_luhn_check,
            ),
            // Substring-disjoint: every French alternation contains
            // "SIRET", which English alternations must avoid; conversely
            // no French alternation contains "establishment", "branch",
            // or "french/france/fr".
            (
                PiiKind::FrSiret,
                Language::En,
                r"(?i)(?:french[\s_-]?establishment[\s_-]?numbers?|france[\s_-]?establishment[\s_-]?numbers?|fr[\s_-]?establishment[\s_-]?numbers?|french[\s_-]?establishment[\s_-]?ids?|france[\s_-]?establishment[\s_-]?ids?|fr[\s_-]?establishment[\s_-]?ids?|french[\s_-]?business[\s_-]?establishment[\s_-]?numbers?|french[\s_-]?branch[\s_-]?numbers?|france[\s_-]?branch[\s_-]?numbers?)<<C>>(\d{14})\b",
                siret_luhn_check,
            ),
            (
                PiiKind::FrSiren,
                Language::Fr,
                r"(?i)(?:num[eé]ros?[\s_-]?SIREN|n°[\s_-]?SIREN|entreprise[\s_-]?SIREN|SIREN)<<C>>(\d{9})\b",
                siren_luhn_check,
            ),
            // Substring-disjoint: French alternations all contain "SIREN";
            // English alternations must avoid that token. No French
            // alternation contains "company" / "business" / "registration"
            // / "french/france/fr".
            (
                PiiKind::FrSiren,
                Language::En,
                r"(?i)(?:french[\s_-]?company[\s_-]?numbers?|france[\s_-]?company[\s_-]?numbers?|fr[\s_-]?company[\s_-]?numbers?|french[\s_-]?business[\s_-]?numbers?|france[\s_-]?business[\s_-]?numbers?|fr[\s_-]?business[\s_-]?numbers?|french[\s_-]?company[\s_-]?registration[\s_-]?numbers?|france[\s_-]?company[\s_-]?registration[\s_-]?numbers?|french[\s_-]?business[\s_-]?registration[\s_-]?numbers?|french[\s_-]?company[\s_-]?ids?|france[\s_-]?company[\s_-]?ids?)<<C>>(\d{9})\b",
                siren_luhn_check,
            ),
            (
                PiiKind::FrPassportNumber,
                Language::Fr,
                r"(?i)(?:passeports?[\s_-]?fran[cç]ais|passeports?[\s_-]?france|num[eé]ros?[\s_-]?de[\s_-]?passeports?)<<C>>(\d{2}[A-Za-z]{2}\d{5})\b",
                always_valid,
            ),
            // Substring-disjoint: French uses "passeport" (no "passport"
            // substring). The French alternation `passeport france` does
            // contain the literal "france", but vectorscan only fires when
            // the FULL alternation is present in input, so `france
            // passport` (different word order) does not double-match.
            (
                PiiKind::FrPassportNumber,
                Language::En,
                r"(?i)(?:french[\s_-]?passport[\s_-]?numbers?|france[\s_-]?passport[\s_-]?numbers?|fr[\s_-]?passport[\s_-]?numbers?|french[\s_-]?passports?|france[\s_-]?passports?|fr[\s_-]?passports?)<<C>>(\d{2}[A-Za-z]{2}\d{5})\b",
                always_valid,
            ),
            (
                PiiKind::FrCni,
                Language::Fr,
                r"(?i)(?:carte[\s_-]?nationale[\s_-]?d'identit[eé]|carte[\s_-]?d'identit[eé]|pi[eè]ce[\s_-]?d'identit[eé]|num[eé]ros?[\s_-]?CNI|CNI)<<C>>(\d{12})\b",
                always_valid,
            ),
            // Substring-disjoint: French uses "carte" / "d'identité" /
            // "pièce" / "CNI" — none in English here. English "identity"
            // is not a substring of "identité" (y vs é at end). The bare
            // "CNI" must be omitted from English alternations to avoid
            // duplicate matches against the French pattern.
            (
                PiiKind::FrCni,
                Language::En,
                r"(?i)(?:french[\s_-]?national[\s_-]?id[\s_-]?cards?|france[\s_-]?national[\s_-]?id[\s_-]?cards?|fr[\s_-]?national[\s_-]?id[\s_-]?cards?|french[\s_-]?id[\s_-]?cards?|france[\s_-]?id[\s_-]?cards?|fr[\s_-]?id[\s_-]?cards?|french[\s_-]?identity[\s_-]?cards?|france[\s_-]?identity[\s_-]?cards?|fr[\s_-]?identity[\s_-]?cards?|french[\s_-]?national[\s_-]?ids?|france[\s_-]?national[\s_-]?ids?|fr[\s_-]?national[\s_-]?ids?)<<C>>(\d{12})\b",
                always_valid,
            ),
            (
                PiiKind::FrDriversLicense,
                Language::Fr,
                r"(?i)(?:permis[\s_-]?de[\s_-]?conduire|num[eé]ros?[\s_-]?de[\s_-]?permis|n°[\s_-]?permis)<<C>>(\d{12})\b",
                always_valid,
            ),
            // Substring-disjoint: French uses "permis" / "conduire" /
            // "numéro" / "n°" — none in English here.
            (
                PiiKind::FrDriversLicense,
                Language::En,
                r"(?i)(?:french[\s_-]?drivers?[\s_-]?licen[cs]es?|france[\s_-]?drivers?[\s_-]?licen[cs]es?|fr[\s_-]?drivers?[\s_-]?licen[cs]es?|french[\s_-]?driving[\s_-]?licen[cs]es?|france[\s_-]?driving[\s_-]?licen[cs]es?|fr[\s_-]?driving[\s_-]?licen[cs]es?)<<C>>(\d{12})\b",
                always_valid,
            ),
            (
                PiiKind::FrPhoneNumber,
                Language::Fr,
                r"(?i)(?:num[eé]ros?[\s_-]?de[\s_-]?t[eé]l[eé]phones?|num[eé]ros?[\s_-]?de[\s_-]?t[eé]l|n°[\s_-]?de[\s_-]?t[eé]l[eé]phones?|n°[\s_-]?de[\s_-]?t[eé]l|t[eé]l[eé]phones?|portable|mobiles?|fixe|t[eé]l|tel|num[eé]ros?[\s_-]?t[eé]l|appeler|rappel|contact)<<C>>((?:\+?33[\s\-.]?|0)[1-9](?:[\s\-.]?\d{2}){4})",
                phone_check,
            ),
            // Substring-disjoint: French keywords include "tel" (3-char
            // ASCII), "mobile", "portable", "fixe", "contact", "rappel".
            // English alternations must not contain any of these as
            // substrings — so no `telephone`, no bare `mobile phone`, no
            // bare `phones?`. We use only country-prefixed forms plus
            // `cell phone` (no "tel"/"mobile" inside).
            (
                PiiKind::FrPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_-]?fr|french[\s_-]?phone[\s_-]?numbers?|france[\s_-]?phone[\s_-]?numbers?|fr[\s_-]?phone[\s_-]?numbers?|french[\s_-]?phones?|france[\s_-]?phones?|french[\s_-]?cell[\s_-]?phones?|france[\s_-]?cell[\s_-]?phones?|fr[\s_-]?cell[\s_-]?phones?)<<C>>(\+?33[\s\-.]?[1-9](?:[\s\-.]?\d{2}){4})",
                phone_check,
            ),
            (
                PiiKind::FrPostalCode,
                Language::Fr,
                r"(?i)(?:code[\s_-]?postal|CP)<<C>>(\d{5})\b",
                fr_postal_check,
            ),
            // Substring-disjoint: French uses "code postal" (different
            // word order than English "postal code") and the bare "CP"
            // 2-char token; neither is a substring of any English literal
            // here. Country-prefixed only — bare "postal code" is owned
            // by `UsZaPostalCode`.
            (
                PiiKind::FrPostalCode,
                Language::En,
                r"(?i)(?:french[\s_-]?postal[\s_-]?codes?|france[\s_-]?postal[\s_-]?codes?|fr[\s_-]?postal[\s_-]?codes?|french[\s_-]?zip[\s_-]?codes?|france[\s_-]?zip[\s_-]?codes?|fr[\s_-]?zip[\s_-]?codes?|french[\s_-]?postcodes?|france[\s_-]?postcodes?|fr[\s_-]?postcodes?)<<C>>(\d{5})\b",
                fr_postal_check,
            ),
            (
                PiiKind::FrNif,
                Language::Fr,
                r"(?i)(?:num[eé]ros?[\s_-]?d'identification[\s_-]?fiscale|num[eé]ros?[\s_-]?fiscal|identifiant[\s_-]?fiscal|avis[\s_-]?d'imposition|NIF|SPI)<<C>>(\d{13})\b",
                fr_nif_check,
            ),
            // Substring-disjoint: French stems "fiscal" / "fiscale" /
            // "identifiant" / "imposition" / "NIF" / "SPI" must not appear
            // in English alternations. English "identification" is not a
            // substring of "identifiant" (n vs c at position 8), so the
            // phrase "tax identification number" is safe.
            (
                PiiKind::FrNif,
                Language::En,
                r"(?i)(?:french[\s_-]?tax[\s_-]?ids?|france[\s_-]?tax[\s_-]?ids?|fr[\s_-]?tax[\s_-]?ids?|french[\s_-]?tax[\s_-]?numbers?|france[\s_-]?tax[\s_-]?numbers?|fr[\s_-]?tax[\s_-]?numbers?|french[\s_-]?tax[\s_-]?identification[\s_-]?numbers?|france[\s_-]?tax[\s_-]?identification[\s_-]?numbers?|french[\s_-]?taxpayer[\s_-]?ids?|france[\s_-]?taxpayer[\s_-]?ids?|fr[\s_-]?taxpayer[\s_-]?ids?)<<C>>(\d{13})\b",
                fr_nif_check,
            ),
            // --- French keywords for existing international types ---
            (
                PiiKind::UsPhoneNumber,
                Language::Fr,
                r"(?i)(?:num[eé]ros?[\s_-]?de[\s_-]?t[eé]l[eé]phones?|num[eé]ros?[\s_-]?de[\s_-]?t[eé]l|n°[\s_-]?de[\s_-]?t[eé]l[eé]phones?|t[eé]l[eé]phones?|portable|mobiles?|fixe|t[eé]l|appeler|rappel)<<C>>((?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})",
                phone_check,
            ),
            (
                PiiKind::PassportNumber,
                Language::Fr,
                r"(?i)(?:passeports?|num[eé]ros?[\s_-]?de[\s_-]?passeports?|document[\s_-]?de[\s_-]?voyage)<<C>>(\d{9})\b",
                passport_check,
            ),
            (
                PiiKind::DateOfBirth,
                Language::Fr,
                r"(?i)(?:date[\s_-]?de[\s_-]?naissance|n[eé]e?[\s_-]?le|DDN|d\.d\.n\.?)<<C>>(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}|\d{1,2}\s+(?:janvier|janv|fevrier|f[eé]vrier|f[eé]vr|mars|avril|avr|mai|juin|juillet|juil|aout|ao[uû]t|septembre|sept|octobre|oct|novembre|nov|decembre|d[eé]cembre|d[eé]c)\s+\d{4})",
                dob_check,
            ),
            (
                PiiKind::PreciseGeolocation,
                Language::Fr,
                r"(?i)(?:coordonn[eé]es[\s_-]?GPS|position[\s_-]?GPS|g[eé]olocalisation|coordonn[eé]es[\s_-]?g[eé]ographiques|latitude/longitude)<<C>>(-?\d{1,3}\.\d{4,},\s?-?\d{1,3}\.\d{4,})",
                geolocation_check,
            ),
            (
                PiiKind::SwiftBic,
                Language::Fr,
                r"(?i)(?:identifiant[\s_-]?bancaire)<<C>>([A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?)\b",
                swift_bic_check,
            ),
            (
                PiiKind::Imei,
                Language::Fr,
                r"(?i)(?:num[eé]ros?[\s_-]?IMEI|identifiant[\s_-]?appareil)<<C>>(\d{2}-?\d{6}-?\d{6}-?\d)",
                imei_check,
            ),
            // --- Germany-specific PII types (Language::De) ---
            (
                PiiKind::DeSteuerId,
                Language::De,
                r"(?i)(?:Steueridentifikationsnummern?|Steuerliche[\s_-]?Identifikationsnummern?|Steuer-ID|IdNr|Steuernummern?)<<C>>(\d{11})\b",
                de_steuer_id_check,
            ),
            // Substring-disjoint with the German pattern above: no German
            // keyword contains "tax" / "german" / "germany" / "de tax", and
            // no English keyword contains "steuer" / "idnr".
            (
                PiiKind::DeSteuerId,
                Language::En,
                r"(?i)(?:german[\s_-]?tax[\s_-]?ids?|germany[\s_-]?tax[\s_-]?ids?|de[\s_-]?tax[\s_-]?ids?|german[\s_-]?tax[\s_-]?numbers?|tax[\s_-]?identification[\s_-]?numbers?|tax[\s_-]?id[\s_-]?numbers?|tax[\s_-]?id[\s_-]?no\.?|tax[\s_-]?ids?)<<C>>(\d{11})\b",
                de_steuer_id_check,
            ),
            (
                PiiKind::DePersonalausweis,
                Language::De,
                r"(?i)(?:Personalausweisnummern?|Personalausweise?|Ausweisnummern?)<<C>>([A-Za-z][A-Za-z0-9]{8}[0-9])\b",
                de_personalausweis_check,
            ),
            // Substring-disjoint: no German keyword contains "national" /
            // "id card" / "identity card" / "german"; no English keyword
            // contains "ausweis".
            (
                PiiKind::DePersonalausweis,
                Language::En,
                r"(?i)(?:german[\s_-]?national[\s_-]?ids?|germany[\s_-]?national[\s_-]?ids?|de[\s_-]?national[\s_-]?ids?|german[\s_-]?id[\s_-]?cards?|germany[\s_-]?id[\s_-]?cards?|de[\s_-]?id[\s_-]?cards?|german[\s_-]?identity[\s_-]?cards?|national[\s_-]?id[\s_-]?cards?)<<C>>([A-Za-z][A-Za-z0-9]{8}[0-9])\b",
                de_personalausweis_check,
            ),
            (
                PiiKind::DePhoneNumber,
                Language::De,
                r"(?i)(?:Telefonnummern?|Rufnummern?|Festnetze?|Handynummern?|Mobilnummern?|Kontaktnummern?|Anrufe?|R[uü]ckruf)<<C>>((?:\+?49[\s\-.]?|0)[1-9]\d{1,4}[\s\-./]?\d{3,8})",
                phone_check,
            ),
            (
                PiiKind::DePhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_-]?de|phone[\s_-]?numbers?|phone[\s_-]?no\.?|phone[\s_-]?num|phone[\s_-]?#|telephone[\s_-]?numbers?|telephone[\s_-]?no\.?|telephones?|mobile[\s_-]?numbers?|mobile[\s_-]?no\.?|mobile[\s_-]?phones?|mobiles?|cell[\s_-]?phones?|cell[\s_-]?numbers?|cells?|contact[\s_-]?numbers?|contact[\s_-]?no\.?|contact[\s_-]?phones?|callback[\s_-]?numbers?|callback[\s_-]?no\.?|callbacks?|fax[\s_-]?numbers?|fax[\s_-]?no\.?|fax(?:es)?|tel[\s_-]?numbers?|tel[\s_-]?no\.?|tel|landlines?|home[\s_-]?phones?|work[\s_-]?phones?|office[\s_-]?phones?|alternate[\s_-]?phones?|alt[\s_-]?phones?|my[\s_-]?phones?|your[\s_-]?phones?|customer[\s_-]?phones?|applicant[\s_-]?phones?|phones?)<<C>>(\+?49[\s\-.]?[1-9]\d{1,4}[\s\-./]?\d{3,8})",
                phone_check,
            ),
            (
                PiiKind::DePostalCode,
                Language::De,
                r"(?i)(?:Postleitzahl(?:en)?|PLZ)<<C>>(\d{5})\b",
                de_postal_check,
            ),
            // Substring-disjoint: no German keyword contains "postal" /
            // "zip" / "postcode" / "german"; no English keyword contains
            // "postleitzahl" / "plz". Country-prefixed only — bare "postal
            // code" is owned by `UsZaPostalCode`.
            (
                PiiKind::DePostalCode,
                Language::En,
                r"(?i)(?:german[\s_-]?postal[\s_-]?codes?|germany[\s_-]?postal[\s_-]?codes?|de[\s_-]?postal[\s_-]?codes?|german[\s_-]?zip[\s_-]?codes?|germany[\s_-]?zip[\s_-]?codes?|de[\s_-]?zip[\s_-]?codes?|german[\s_-]?postcodes?|germany[\s_-]?postcodes?|de[\s_-]?postcodes?)<<C>>(\d{5})\b",
                de_postal_check,
            ),
            // --- Austria-specific PII types (Language::De) ---
            (
                PiiKind::AtSvnr,
                Language::De,
                r"(?i)(?:Sozialversicherungsnummern?|Versicherungsnummern?|SVNR)<<C>>(\d{4}\s?\d{6})\b",
                at_svnr_check,
            ),
            // The bare "SVNR" alternations (and any English keyword containing
            // "svnr") are intentionally absent here — the German pattern above
            // already matches them case-insensitively, so adding them would
            // double-match any string containing "svnr" (e.g. `at_svnr: ...`).
            // This pattern is for the long English phrases the German keyword
            // set does not subsume.
            (
                PiiKind::AtSvnr,
                Language::En,
                r"(?i)(?:austrian[\s_-]?social[\s_-]?security[\s_-]?numbers?|austria[\s_-]?social[\s_-]?security[\s_-]?numbers?|at[\s_-]?social[\s_-]?security[\s_-]?numbers?|austrian[\s_-]?insurance[\s_-]?numbers?|austria[\s_-]?insurance[\s_-]?numbers?|at[\s_-]?insurance[\s_-]?numbers?)<<C>>(\d{4}\s?\d{6})\b",
                at_svnr_check,
            ),
            (
                PiiKind::AtPhoneNumber,
                Language::De,
                r"(?i)(?:Telefonnummern?|Rufnummern?|Festnetze?|Handynummern?|Mobilnummern?|Kontaktnummern?|Anrufe?|R[uü]ckruf)<<C>>((?:\+?43[\s\-.]?|0)[1-9]\d{0,4}[\s\-./]?\d{3,8})",
                phone_check,
            ),
            (
                PiiKind::AtPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_-]?at|phone[\s_-]?numbers?|phone[\s_-]?no\.?|phone[\s_-]?num|phone[\s_-]?#|telephone[\s_-]?numbers?|telephone[\s_-]?no\.?|telephones?|mobile[\s_-]?numbers?|mobile[\s_-]?no\.?|mobile[\s_-]?phones?|mobiles?|cell[\s_-]?phones?|cell[\s_-]?numbers?|cells?|contact[\s_-]?numbers?|contact[\s_-]?no\.?|contact[\s_-]?phones?|callback[\s_-]?numbers?|callback[\s_-]?no\.?|callbacks?|fax[\s_-]?numbers?|fax[\s_-]?no\.?|fax(?:es)?|tel[\s_-]?numbers?|tel[\s_-]?no\.?|tel|landlines?|home[\s_-]?phones?|work[\s_-]?phones?|office[\s_-]?phones?|alternate[\s_-]?phones?|alt[\s_-]?phones?|my[\s_-]?phones?|your[\s_-]?phones?|customer[\s_-]?phones?|applicant[\s_-]?phones?|phones?)<<C>>(\+?43[\s\-.]?[1-9]\d{0,4}[\s\-./]?\d{3,8})",
                phone_check,
            ),
            (
                PiiKind::AtPostalCode,
                Language::De,
                r"(?i)(?:Postleitzahl(?:en)?|PLZ)<<C>>(\d{4})\b",
                at_postal_check,
            ),
            // Substring-disjoint: see DePostalCode rationale; country-
            // prefixed only.
            (
                PiiKind::AtPostalCode,
                Language::En,
                r"(?i)(?:austrian[\s_-]?postal[\s_-]?codes?|austria[\s_-]?postal[\s_-]?codes?|at[\s_-]?postal[\s_-]?codes?|austrian[\s_-]?zip[\s_-]?codes?|austria[\s_-]?zip[\s_-]?codes?|at[\s_-]?zip[\s_-]?codes?|austrian[\s_-]?postcodes?|austria[\s_-]?postcodes?|at[\s_-]?postcodes?)<<C>>(\d{4})\b",
                at_postal_check,
            ),
            // --- Switzerland-specific PII types (Language::De) ---
            (
                PiiKind::ChAhv,
                Language::De,
                r"(?i)(?:AHV-Nummern?|AHV-Nr|OASI|Versichertennummern?)<<C>>(756[\s.]?\d{4}[\s.]?\d{4}[\s.]?\d{2})\b",
                ch_ahv_check,
            ),
            // Substring-disjoint: no German keyword contains "swiss" /
            // "switzerland" / "social security" / "insurance"; no English
            // keyword contains "ahv" / "oasi" / "versicherten".
            (
                PiiKind::ChAhv,
                Language::En,
                r"(?i)(?:swiss[\s_-]?social[\s_-]?security[\s_-]?numbers?|switzerland[\s_-]?social[\s_-]?security[\s_-]?numbers?|ch[\s_-]?social[\s_-]?security[\s_-]?numbers?|swiss[\s_-]?insurance[\s_-]?numbers?|switzerland[\s_-]?insurance[\s_-]?numbers?|ch[\s_-]?insurance[\s_-]?numbers?)<<C>>(756[\s.]?\d{4}[\s.]?\d{4}[\s.]?\d{2})\b",
                ch_ahv_check,
            ),
            (
                PiiKind::ChPhoneNumber,
                Language::De,
                r"(?i)(?:Telefonnummern?|Rufnummern?|Festnetze?|Handynummern?|Mobilnummern?|Kontaktnummern?|Anrufe?|R[uü]ckruf)<<C>>((?:\+?41[\s\-.]?|0)[1-9]\d[\s\-.]?\d{3}[\s\-.]?\d{2}[\s\-.]?\d{2})",
                phone_check,
            ),
            (
                PiiKind::ChPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_-]?ch|phone[\s_-]?numbers?|phone[\s_-]?no\.?|phone[\s_-]?num|phone[\s_-]?#|telephone[\s_-]?numbers?|telephone[\s_-]?no\.?|telephones?|mobile[\s_-]?numbers?|mobile[\s_-]?no\.?|mobile[\s_-]?phones?|mobiles?|cell[\s_-]?phones?|cell[\s_-]?numbers?|cells?|contact[\s_-]?numbers?|contact[\s_-]?no\.?|contact[\s_-]?phones?|callback[\s_-]?numbers?|callback[\s_-]?no\.?|callbacks?|fax[\s_-]?numbers?|fax[\s_-]?no\.?|fax(?:es)?|tel[\s_-]?numbers?|tel[\s_-]?no\.?|tel|landlines?|home[\s_-]?phones?|work[\s_-]?phones?|office[\s_-]?phones?|alternate[\s_-]?phones?|alt[\s_-]?phones?|my[\s_-]?phones?|your[\s_-]?phones?|customer[\s_-]?phones?|applicant[\s_-]?phones?|phones?)<<C>>(\+?41[\s\-.]?[1-9]\d[\s\-.]?\d{3}[\s\-.]?\d{2}[\s\-.]?\d{2})",
                phone_check,
            ),
            (
                PiiKind::ChPostalCode,
                Language::De,
                r"(?i)(?:Postleitzahl(?:en)?|PLZ)<<C>>(\d{4})\b",
                ch_postal_check,
            ),
            // Substring-disjoint: see DePostalCode rationale; country-
            // prefixed only.
            (
                PiiKind::ChPostalCode,
                Language::En,
                r"(?i)(?:swiss[\s_-]?postal[\s_-]?codes?|switzerland[\s_-]?postal[\s_-]?codes?|ch[\s_-]?postal[\s_-]?codes?|swiss[\s_-]?zip[\s_-]?codes?|switzerland[\s_-]?zip[\s_-]?codes?|ch[\s_-]?zip[\s_-]?codes?|swiss[\s_-]?postcodes?|switzerland[\s_-]?postcodes?|ch[\s_-]?postcodes?)<<C>>(\d{4})\b",
                ch_postal_check,
            ),
            // --- German keywords for existing international types ---
            (
                PiiKind::UsPhoneNumber,
                Language::De,
                r"(?i)(?:Telefonnummern?|Rufnummern?|Festnetze?|Handynummern?|Mobilnummern?|Kontaktnummern?|Anrufe?|R[uü]ckruf)<<C>>((?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})",
                phone_check,
            ),
            (
                PiiKind::PassportNumber,
                Language::De,
                r"(?i)(?:Reisepass|Passnummern?)<<C>>(\d{9})\b",
                passport_check,
            ),
            (
                PiiKind::DateOfBirth,
                Language::De,
                r"(?i)(?:Geburtsdatum|geboren[\s_-]?am|Geb\.?datum)<<C>>(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}|\d{1,2}\s+(?:Januar|Jan|Februar|Feb|M[aä]rz|Maerz|M[aä]r|Mrz|April|Apr|Mai|Juni|Jun|Juli|Jul|August|Aug|September|Sept|Sep|Oktober|Okt|November|Nov|Dezember|Dez)\s+\d{4})",
                dob_check,
            ),
            (
                PiiKind::PreciseGeolocation,
                Language::De,
                r"(?i)(?:GPS-Koordinaten|Standorte?|Geokoordinaten)<<C>>(-?\d{1,3}\.\d{4,},\s?-?\d{1,3}\.\d{4,})",
                geolocation_check,
            ),
            (
                PiiKind::SwiftBic,
                Language::De,
                r"(?i)(?:Bankleitzahl(?:en)?)<<C>>([A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?)\b",
                swift_bic_check,
            ),
            (
                PiiKind::Imei,
                Language::De,
                r"(?i)(?:Ger[aä]tekennung|Ger[aä]te-IMEI)<<C>>(\d{2}-?\d{6}-?\d{6}-?\d)",
                imei_check,
            ),
            // --- PersonName (International) ---
            (
                PiiKind::PersonName,
                Language::En,
                r"(?i)(?:full[\s_-]?names?|first[\s_-]?names?|last[\s_-]?names?|given[\s_-]?names?|family[\s_-]?names?|surname|forename|maiden[\s_-]?names?|middle[\s_-]?names?|patient[\s_-]?names?|client[\s_-]?names?|customer[\s_-]?names?|employee[\s_-]?names?|applicant[\s_-]?names?|cardholder[\s_-]?names?|account[\s_-]?holder|account[\s_-]?names?|beneficiary[\s_-]?names?|recipient[\s_-]?names?|sender[\s_-]?names?|passenger[\s_-]?names?|insured[\s_-]?names?)<<C>>((?-i:[A-ZÀ-Ž])[A-Za-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,4})",
                person_name_check,
            ),
            (
                PiiKind::PersonName,
                Language::Fr,
                r"(?i)(?:noms?[\s_-]?complet|noms?[\s_-]?de[\s_-]?famille|noms?[\s_-]?de[\s_-]?naissance|noms?[\s_-]?de[\s_-]?jeune[\s_-]?fille|noms?[\s_-]?d'usage|pr[eé]noms?|patronyme|titulaire|b[eé]n[eé]ficiaire|destinataire|exp[eé]diteur|passager|assur[eé])<<C>>((?-i:[A-ZÀ-Ž])[A-Za-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,4})",
                person_name_check,
            ),
            (
                PiiKind::PersonName,
                Language::De,
                r"(?i)(?:vollst[aä]ndiger[\s_-]?Name|Nachname|Familienname|Vorname|Geburtsname|M[aä]dchenname|Kontoinhaber|Beg[uü]nstigter|Empf[aä]nger|Versicherter|Fahrgast|Antragsteller)<<C>>((?-i:[A-ZÀ-Ž])[A-Za-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,4})",
                person_name_check,
            ),
            // --- French/Swiss French physical address types (Language::Fr) ---
            (
                PiiKind::FrChAddress,
                Language::Fr,
                r"(?i)(?:adresse\s+(?:postale|de\s+livraison|de\s+facturation|personnelle|du\s+domicile|de\s+r[eé]sidence|du\s+si[eè]ge)|adressen?|domicile|r[eé]sidence|si[eè]ge\s+social|habitation)<<C>>((?:\d{1,4}\s?(?:bis|ter)?\s*,?\s*)?(?:rue|avenue|boulevard|place|all[eé]e|impasse|chemin|route|passage|cours|quai|square|voie|sentier|mont[eé]e|traverse|r[eé]sidence|cit[eé]|lotissement|hameau|lieu-dit|promenade|parvis|rond-point|esplanade|av|bd|pl|imp|ch)\s+[A-Za-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,6}(?:\s+\d{1,4}\s?[a-z]?)?[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
                fr_ch_address_check,
            ),
            // Substring-disjoint: French "adresse" (single d) is not a
            // substring of English "address" (double d) or vice versa.
            // French stems "domicile" / "habitation" / "résidence" /
            // "siège" do not appear in English alternations. Generic
            // English address keywords (`home address`, `mailing address`,
            // etc.) are shared with `DeAtChAddress` EN — cross-kind value
            // regex (FR requires `rue/avenue/...`, DE requires capitalized
            // German street name) disambiguates.
            (
                PiiKind::FrChAddress,
                Language::En,
                r"(?i)(?:french[\s_-]?address(?:es)?|france[\s_-]?address(?:es)?|fr[\s_-]?address(?:es)?|swiss[\s_-]?french[\s_-]?address(?:es)?|home[\s_-]?address(?:es)?|street[\s_-]?address(?:es)?|mailing[\s_-]?address(?:es)?|delivery[\s_-]?address(?:es)?|billing[\s_-]?address(?:es)?|shipping[\s_-]?address(?:es)?|residential[\s_-]?address(?:es)?|physical[\s_-]?address(?:es)?|address(?:es)?)<<C>>((?:\d{1,4}\s?(?:bis|ter)?\s*,?\s*)?(?:rue|avenue|boulevard|place|all[eé]e|impasse|chemin|route|passage|cours|quai|square|voie|sentier|mont[eé]e|traverse|r[eé]sidence|cit[eé]|lotissement|hameau|lieu-dit|promenade|parvis|rond-point|esplanade|av|bd|pl|imp|ch)\s+[A-Za-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,6}(?:\s+\d{1,4}\s?[a-z]?)?[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
                fr_ch_address_check,
            ),
            (
                PiiKind::FrChBoitePostale,
                Language::Fr,
                r"(?i)(?:bo[iî]te\s+postale|case\s+postale|BP|CP)<<C>>(\d{1,6}[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
                fr_ch_boite_postale_check,
            ),
            // Substring-disjoint: French uses "boîte postale" / "case
            // postale" / "BP" / "CP". English alternations contain none of
            // these; "post office box" / "postal box" do not contain the
            // continuous "postale" stem. Generic forms are shared with
            // `DeAtChPostfach` EN — same value regex shape, but each
            // validator gates on the country-specific PLZ range.
            (
                PiiKind::FrChBoitePostale,
                Language::En,
                r"(?i)(?:french[\s_-]?po[\s_-]?box(?:es)?|france[\s_-]?po[\s_-]?box(?:es)?|fr[\s_-]?po[\s_-]?box(?:es)?|swiss[\s_-]?french[\s_-]?po[\s_-]?box(?:es)?|french[\s_-]?post[\s_-]?office[\s_-]?box(?:es)?|france[\s_-]?post[\s_-]?office[\s_-]?box(?:es)?|french[\s_-]?postal[\s_-]?box(?:es)?|france[\s_-]?postal[\s_-]?box(?:es)?)<<C>>(\d{1,6}[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
                fr_ch_boite_postale_check,
            ),
            // --- German/Austrian physical address types (Language::De) ---
            (
                PiiKind::DeAtChAddress,
                Language::De,
                r"(?i)(?:Anschrift(?:en)?|Wohnadressen?|Wohnanschrift(?:en)?|Hausanschrift(?:en)?|Wohnsitz|Lieferadressen?|Rechnungsadressen?|Meldeadressen?|Zustelladressen?|Privatadressen?|Heimatadressen?|Adressen?)<<C>>([A-ZÀ-Ž][A-Za-zÀ-ž.\-]+(?:[\s\-]+[A-Za-zÀ-ž.\-]+)*\s+\d{1,4}\s?[a-zA-Z]?(?:\s?[\-/]\s?\d{1,4}\s?[a-zA-Z]?){0,3}[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
                de_at_address_check,
            ),
            // Substring-disjoint: English "address" (double-d) does not
            // contain the German stem "adress" (single-d), so the bare
            // English `address(es)?` keyword does not double-match against
            // the German `Adressen?` keyword. No German keyword contains
            // any English alternation.
            (
                PiiKind::DeAtChAddress,
                Language::En,
                r"(?i)(?:german[\s_-]?address(?:es)?|austrian[\s_-]?address(?:es)?|swiss[\s_-]?address(?:es)?|de[\s_-]?address(?:es)?|at[\s_-]?address(?:es)?|ch[\s_-]?address(?:es)?|home[\s_-]?address(?:es)?|street[\s_-]?address(?:es)?|mailing[\s_-]?address(?:es)?|delivery[\s_-]?address(?:es)?|billing[\s_-]?address(?:es)?|shipping[\s_-]?address(?:es)?|residential[\s_-]?address(?:es)?|physical[\s_-]?address(?:es)?|address(?:es)?)<<C>>([A-ZÀ-Ž][A-Za-zÀ-ž.\-]+(?:[\s\-]+[A-Za-zÀ-ž.\-]+)*\s+\d{1,4}\s?[a-zA-Z]?(?:\s?[\-/]\s?\d{1,4}\s?[a-zA-Z]?){0,3}[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
                de_at_address_check,
            ),
            (
                PiiKind::DeAtChPostfach,
                Language::De,
                r"(?i)(?:Postfach|PF)<<C>>(\d{1,6}[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
                de_at_postfach_check,
            ),
            // Substring-disjoint: no German keyword ("postfach", "pf")
            // contains "po box" / "post office" / "pob"; no English
            // keyword contains "postfach" or the bare "pf" digram.
            (
                PiiKind::DeAtChPostfach,
                Language::En,
                r"(?i)(?:german[\s_-]?po[\s_-]?box(?:es)?|austrian[\s_-]?po[\s_-]?box(?:es)?|swiss[\s_-]?po[\s_-]?box(?:es)?|de[\s_-]?po[\s_-]?box(?:es)?|at[\s_-]?po[\s_-]?box(?:es)?|ch[\s_-]?po[\s_-]?box(?:es)?|post[\s_-]?office[\s_-]?box(?:es)?|postal[\s_-]?box(?:es)?|po[\s_-]?box(?:es)?|pob)<<C>>(\d{1,6}[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
                de_at_postfach_check,
            ),
            (
                PiiKind::DePackstation,
                Language::De,
                r"(?i)(?:Packstation|Postfiliale|Paketshop)<<C>>(\d{3,4}[,\s]+\d{5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
                de_packstation_check,
            ),
            // Substring-disjoint: no German keyword contains "parcel" /
            // "locker" / "dhl"; no English keyword contains "packstation"
            // / "postfiliale" / "paketshop".
            (
                PiiKind::DePackstation,
                Language::En,
                r"(?i)(?:german[\s_-]?parcel[\s_-]?lockers?|dhl[\s_-]?parcel[\s_-]?lockers?|parcel[\s_-]?lockers?)<<C>>(\d{3,4}[,\s]+\d{5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
                de_packstation_check,
            ),
            // --- Netherlands-specific PII types (Language::Nl) ---
            (
                PiiKind::NlBsn,
                Language::Nl,
                r"(?i)(?:burgerservicenummers?|burger[\s_-]?service[\s_-]?nummers?|burgerservice|sofinummers?|sofi[\s_-]?nummers?|persoonsnummers?|persoonlijk[\s_-]?nummers?|persoonsgebonden[\s_-]?nummers?|identiteitsnummers?|BSN[\s_-]?nummers?|BSN)<<C>>(\d{4}\.\d{2}\.\d{3}|\d{8,9})\b",
                bsn_check,
            ),
            // Substring-disjoint: no Dutch keyword contains "citizen" /
            // "social" / "dutch" / "netherlands" / "nl"; no English keyword
            // contains "bsn" / "burgerservice" / "sofinummer" / "persoon".
            (
                PiiKind::NlBsn,
                Language::En,
                r"(?i)(?:citizen[\s_-]?service[\s_-]?numbers?|dutch[\s_-]?citizen[\s_-]?service[\s_-]?numbers?|dutch[\s_-]?social[\s_-]?security[\s_-]?numbers?|netherlands[\s_-]?social[\s_-]?security[\s_-]?numbers?|nl[\s_-]?social[\s_-]?security[\s_-]?numbers?|dutch[\s_-]?citizen[\s_-]?numbers?|netherlands[\s_-]?citizen[\s_-]?numbers?|dutch[\s_-]?national[\s_-]?numbers?|netherlands[\s_-]?national[\s_-]?numbers?|dutch[\s_-]?personal[\s_-]?numbers?)<<C>>(\d{4}\.\d{2}\.\d{3}|\d{8,9})\b",
                bsn_check,
            ),
            (
                PiiKind::NlPostalCode,
                Language::Nl,
                r"(?i)(?:postcodes?|post[\s_-]?codes?|postcodegebieden?)<<C>>(\d{4}\s?[A-Za-z]{2})\b",
                nl_postal_check,
            ),
            // Substring-disjoint: bare "postcode" is the Dutch keyword above;
            // the English alternations use the two-word "postal code" / "zip
            // code" forms only, which do not contain "postcode". Country-
            // prefixed so they never collide with `UsZaPostalCode` semantics.
            (
                PiiKind::NlPostalCode,
                Language::En,
                r"(?i)(?:dutch[\s_-]?postal[\s_-]?codes?|netherlands[\s_-]?postal[\s_-]?codes?|nl[\s_-]?postal[\s_-]?codes?|holland[\s_-]?postal[\s_-]?codes?|dutch[\s_-]?zip[\s_-]?codes?|netherlands[\s_-]?zip[\s_-]?codes?|nl[\s_-]?zip[\s_-]?codes?)<<C>>(\d{4}\s?[A-Za-z]{2})\b",
                nl_postal_check,
            ),
            (
                PiiKind::NlPhoneNumber,
                Language::Nl,
                r"(?i)(?:telefoonnummers?|telefoonnrs?|telefoons?|mobiele?[\s_-]?nummers?|mobiel|gsm[\s_-]?nummers?|gsm|vaste?[\s_-]?nummers?|vaste[\s_-]?lijn|vastnet|belnummers?|doorkiesnummers?|contactnummers?|zakelijk[\s_-]?nummers?)<<C>>((?:\+?31[\s\-.]?|0)[1-9]\d{1,4}[\s\-./]?\d{3,8})",
                phone_check,
            ),
            // Generic English phone keyword list shared with the other
            // country phone kinds. The value regex requires the +31 country
            // code, so a bare 0-prefixed number written with a Dutch keyword
            // does not double-match here.
            (
                PiiKind::NlPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_-]?nl|phone[\s_-]?numbers?|phone[\s_-]?no\.?|phone[\s_-]?num|phone[\s_-]?#|telephone[\s_-]?numbers?|telephone[\s_-]?no\.?|telephones?|mobile[\s_-]?numbers?|mobile[\s_-]?no\.?|mobile[\s_-]?phones?|mobiles?|cell[\s_-]?phones?|cell[\s_-]?numbers?|cells?|contact[\s_-]?numbers?|contact[\s_-]?no\.?|contact[\s_-]?phones?|callback[\s_-]?numbers?|callback[\s_-]?no\.?|callbacks?|fax[\s_-]?numbers?|fax[\s_-]?no\.?|fax(?:es)?|tel[\s_-]?numbers?|tel[\s_-]?no\.?|tel|landlines?|home[\s_-]?phones?|work[\s_-]?phones?|office[\s_-]?phones?|alternate[\s_-]?phones?|alt[\s_-]?phones?|my[\s_-]?phones?|your[\s_-]?phones?|customer[\s_-]?phones?|applicant[\s_-]?phones?|phones?)<<C>>(\+?31[\s\-.]?[1-9]\d{1,4}[\s\-./]?\d{3,8})",
                phone_check,
            ),
            (
                PiiKind::NlPassportNumber,
                Language::Nl,
                r"(?i)(?:nederlands[\s_-]?paspoort|paspoortnummers?|paspoorten|paspoort|identiteitskaartnummers?|identiteitskaarten|identiteitskaart|documentnummers?)<<C>>([A-Za-z0-9]{9})\b",
                nl_passport_check,
            ),
            // Substring-disjoint: Dutch "paspoort" does not contain the
            // English "passport"; the English alternations are all country-
            // prefixed and contain no Dutch stem.
            (
                PiiKind::NlPassportNumber,
                Language::En,
                r"(?i)(?:dutch[\s_-]?passports?|netherlands[\s_-]?passports?|nl[\s_-]?passports?|dutch[\s_-]?identity[\s_-]?cards?|netherlands[\s_-]?identity[\s_-]?cards?|nl[\s_-]?identity[\s_-]?cards?|dutch[\s_-]?id[\s_-]?cards?|dutch[\s_-]?travel[\s_-]?documents?)<<C>>([A-Za-z0-9]{9})\b",
                nl_passport_check,
            ),
            (
                PiiKind::NlDriversLicense,
                Language::Nl,
                r"(?i)(?:rijbewijsnummers?|rijbewijs[\s_-]?nummers?|rijbewijs[\s_-]?nrs?|rijbewijzen|rijbewijs)<<C>>(\d{10})\b",
                nl_dl_check,
            ),
            // Substring-disjoint: Dutch "rijbewijs" contains no English stem
            // and the English alternations contain no Dutch stem.
            (
                PiiKind::NlDriversLicense,
                Language::En,
                r"(?i)(?:dutch[\s_-]?drivers?[\s_-]?licen[cs]es?|netherlands[\s_-]?drivers?[\s_-]?licen[cs]es?|nl[\s_-]?drivers?[\s_-]?licen[cs]es?|dutch[\s_-]?driving[\s_-]?licen[cs]es?|netherlands[\s_-]?driving[\s_-]?licen[cs]es?|nl[\s_-]?driving[\s_-]?licen[cs]es?|dutch[\s_-]?dl|netherlands[\s_-]?dl|nl[\s_-]?dl)<<C>>(\d{10})\b",
                nl_dl_check,
            ),
            // --- Dutch keywords for existing international types ---
            (
                PiiKind::UsPhoneNumber,
                Language::Nl,
                r"(?i)(?:telefoonnummers?|telefoonnrs?|telefoons?|mobiele?[\s_-]?nummers?|mobiel|gsm[\s_-]?nummers?|gsm|vaste?[\s_-]?nummers?|vaste[\s_-]?lijn|vastnet|belnummers?|doorkiesnummers?|contactnummers?|zakelijk[\s_-]?nummers?)<<C>>((?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})",
                phone_check,
            ),
            // Complement to NlPassportNumber Nl: shares the "paspoort" keyword
            // but captures the pure-9-digit form (generic passport), while
            // NlPassportNumber captures the alphanumeric Dutch document number.
            // The validators (digit-only vs ≥1-letter) make them disjoint.
            (
                PiiKind::PassportNumber,
                Language::Nl,
                r"(?i)(?:paspoortnummers?|paspoort|reisdocumentnummers?|reisdocument|documentnummers?)<<C>>(\d{9})\b",
                passport_check,
            ),
            // Note: the bare "geb. datum" abbreviation is intentionally absent —
            // the German `Geb\.?datum` pattern already matches "Gebdatum"
            // case-insensitively, so adding it here would double-match.
            (
                PiiKind::DateOfBirth,
                Language::Nl,
                r"(?i)(?:geboortedatum|datum[\s_-]?van[\s_-]?geboorte|geboren[\s_-]?op|geboortedag)<<C>>(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}|\d{1,2}\s+(?:januari|jan|februari|feb|maart|mrt|april|apr|mei|juni|jun|juli|jul|augustus|aug|september|sept|sep|oktober|okt|november|nov|december|dec)\s+\d{4})",
                dob_check,
            ),
            (
                PiiKind::PreciseGeolocation,
                Language::Nl,
                r"(?i)(?:GPS-co[öo]rdinaten|GPS-locatie|GPS-positie|geografische[\s_-]?co[öo]rdinaten|geolocatie|co[öo]rdinaten|positie|locatie)<<C>>(-?\d{1,3}\.\d{4,},\s?-?\d{1,3}\.\d{4,})",
                geolocation_check,
            ),
            (
                PiiKind::SwiftBic,
                Language::Nl,
                r"(?i)(?:bankidentificatiecode|bankidentificatie)<<C>>([A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?)\b",
                swift_bic_check,
            ),
            (
                PiiKind::Imei,
                Language::Nl,
                r"(?i)(?:apparaatnummers?|toestelnummers?|toestelidentificatie|apparaatidentificatie)<<C>>(\d{2}-?\d{6}-?\d{6}-?\d)",
                imei_check,
            ),
            // --- Italy-specific PII types (Language::It) ---
            // Codice fiscale is detected keyword-free by HyperscanDetector, but
            // only in its canonical uppercase form (lowercase is too hot for the
            // keyword-less vectorscan pass). This keyword pattern recovers any-case
            // CF when a "codice fiscale"/"CF" label is present. The value regex is
            // disjoint from every other Italian kind (16-char L/D mask) and the
            // checksum validator rejects non-CF strings.
            (
                PiiKind::ItCodiceFiscale,
                Language::It,
                r"(?i)(?:codice[\s_-]?fiscale|codici[\s_-]?fiscali|cod\.?[\s_-]?fisc\.?|c\.?f\.?|cf)<<C>>([A-Za-z]{6}\d{2}[A-Za-z]\d{2}[A-Za-z]\d{3}[A-Za-z])\b",
                it_codice_fiscale_check,
            ),
            (
                PiiKind::ItPartitaIva,
                Language::It,
                r"(?i)(?:numero[\s_-]?di[\s_-]?partita[\s_-]?iva|partit[ae][\s_-]?i\.?v\.?a\.?|p\.?[\s_-]?iva|piva|italian[\s_-]?vat[\s_-]?numbers?|italian[\s_-]?vat|vat[\s_-]?numbers?)<<C>>((?:[Ii][Tt])?\d{11})\b",
                it_partita_iva_check,
            ),
            (
                PiiKind::ItPostalCode,
                Language::It,
                r"(?i)(?:codice[\s_-]?di[\s_-]?avviamento[\s_-]?postale|codici[\s_-]?di[\s_-]?avviamento[\s_-]?postale|codice[\s_-]?postale|codici[\s_-]?postali|CAP|C\.A\.P\.?|italian[\s_-]?postal[\s_-]?codes?|italy[\s_-]?postal[\s_-]?codes?)<<C>>(\d{5})\b",
                it_postal_check,
            ),
            (
                PiiKind::ItPhoneNumber,
                Language::It,
                r"(?i)(?:numero[\s_-]?di[\s_-]?telefono|numeri[\s_-]?di[\s_-]?telefono|telefon[oi]|cellular[ei]|cell|recapito[\s_-]?telefonico|recapiti[\s_-]?telefonici|fax|tel)<<C>>((?:\+?39[\s\-.]?)?(?:0\d{1,3}|3\d{2})[\s\-./]?\d{5,8})",
                phone_check,
            ),
            // Generic English phone keyword list shared with the other country
            // phone kinds. The value regex requires the +39 country code so a
            // bare 0/3-prefixed number written with a Dutch/English keyword does
            // not double-match here.
            (
                PiiKind::ItPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_-]?it|phone[\s_-]?numbers?|phone[\s_-]?no\.?|phone[\s_-]?num|phone[\s_-]?#|telephone[\s_-]?numbers?|telephone[\s_-]?no\.?|telephones?|mobile[\s_-]?numbers?|mobile[\s_-]?no\.?|mobile[\s_-]?phones?|mobiles?|cell[\s_-]?phones?|cell[\s_-]?numbers?|cells?|contact[\s_-]?numbers?|contact[\s_-]?no\.?|contact[\s_-]?phones?|callback[\s_-]?numbers?|callback[\s_-]?no\.?|callbacks?|fax[\s_-]?numbers?|fax[\s_-]?no\.?|fax(?:es)?|tel[\s_-]?numbers?|tel[\s_-]?no\.?|tel|landlines?|home[\s_-]?phones?|work[\s_-]?phones?|office[\s_-]?phones?|alternate[\s_-]?phones?|alt[\s_-]?phones?|my[\s_-]?phones?|your[\s_-]?phones?|customer[\s_-]?phones?|applicant[\s_-]?phones?|phones?)<<C>>(\+?39[\s\-.]?(?:0\d{1,3}|3\d{2})[\s\-./]?\d{5,8})",
                phone_check,
            ),
            (
                PiiKind::ItPassportNumber,
                Language::It,
                r"(?i)(?:numero[\s_-]?di[\s_-]?passaporto|numero[\s_-]?del[\s_-]?passaporto|passaport[oi])<<C>>([A-Za-z]{2}\d{7})\b",
                it_passport_check,
            ),
            // Substring-disjoint: Italian "passaporto" does not contain the
            // English "passport"; the English alternations are country-prefixed
            // and the value regex (2 letters + 7 digits) is disjoint from the
            // generic PassportNumber value (\d{9}).
            (
                PiiKind::ItPassportNumber,
                Language::En,
                r"(?i)(?:italian[\s_-]?passports?|italy[\s_-]?passports?|it[\s_-]?passports?)<<C>>([A-Za-z]{2}\d{7})\b",
                it_passport_check,
            ),
            (
                PiiKind::ItDriversLicense,
                Language::It,
                r"(?i)(?:numero[\s_-]?di[\s_-]?patente|numero[\s_-]?patente|patente[\s_-]?di[\s_-]?guida|patent[ei])<<C>>([A-Za-z][A-Za-z0-9]{8}[A-Za-z])\b",
                it_dl_check,
            ),
            // Substring-disjoint: Italian "patente" contains no English stem and
            // the English alternations contain no Italian stem.
            (
                PiiKind::ItDriversLicense,
                Language::En,
                r"(?i)(?:italian[\s_-]?driv(?:ing|ers?)[\s_-]?licen[cs]es?|italy[\s_-]?driv(?:ing|ers?)[\s_-]?licen[cs]es?|it[\s_-]?driv(?:ing|ers?)[\s_-]?licen[cs]es?)<<C>>([A-Za-z][A-Za-z0-9]{8}[A-Za-z])\b",
                it_dl_check,
            ),
            // --- Italian keywords for existing international types ---
            (
                PiiKind::UsPhoneNumber,
                Language::It,
                r"(?i)(?:numero[\s_-]?di[\s_-]?telefono|numeri[\s_-]?di[\s_-]?telefono|telefon[oi]|cellular[ei]|cell|recapito[\s_-]?telefonico|recapiti[\s_-]?telefonici|fax|tel)<<C>>((?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})",
                phone_check,
            ),
            // Complement to ItPassportNumber It: shares the "passaporto" keyword
            // but captures the pure-9-digit generic passport form, while
            // ItPassportNumber captures the 2-letter+7-digit Italian form. The
            // value regexes make them disjoint.
            (
                PiiKind::PassportNumber,
                Language::It,
                r"(?i)(?:numero[\s_-]?di[\s_-]?passaporto|passaport[oi]|documento[\s_-]?di[\s_-]?viaggio|numero[\s_-]?documento)<<C>>(\d{9})\b",
                passport_check,
            ),
            (
                PiiKind::DateOfBirth,
                Language::It,
                r"(?i)(?:data[\s_-]?di[\s_-]?nascita|data[\s_-]?nascita|nat[oa][\s_-]?il)<<C>>(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}|\d{1,2}\s+(?:gennaio|gen|febbraio|feb|marzo|mar|aprile|apr|maggio|mag|giugno|giu|luglio|lug|agosto|ago|settembre|sett|set|ottobre|ott|novembre|nov|dicembre|dic)\s+\d{4})",
                dob_check,
            ),
            (
                PiiKind::PreciseGeolocation,
                Language::It,
                r"(?i)(?:geolocalizzazione|posizione[\s_-]?geografica|posizione[\s_-]?esatta|ubicazione)<<C>>(-?\d{1,3}\.\d{4,},\s?-?\d{1,3}\.\d{4,})",
                geolocation_check,
            ),
            (
                PiiKind::SwiftBic,
                Language::It,
                r"(?i)(?:codice[\s_-]?identificativo[\s_-]?bancario|identificativo[\s_-]?bancario)<<C>>([A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?)\b",
                swift_bic_check,
            ),
            (
                PiiKind::Imei,
                Language::It,
                r"(?i)(?:numero[\s_-]?seriale[\s_-]?del[\s_-]?dispositivo|identificativo[\s_-]?del[\s_-]?dispositivo|identificativo[\s_-]?dispositivo|codice[\s_-]?dispositivo)<<C>>(\d{2}-?\d{6}-?\d{6}-?\d)",
                imei_check,
            ),
            // --- Spain-specific PII types (Language::Es) ---
            // Spanish phone: 9 digits starting 6/7 (mobile) or 8/9 (landline),
            // optional +34. Shares keywords with the UsPhoneNumber Es tuple but
            // the value regexes are disjoint (9-digit [6-9] vs 10-digit US).
            (
                PiiKind::EsPhoneNumber,
                Language::Es,
                r"(?i)(?:n[uú]meros?[\s_-]?de[\s_-]?tel[eé]fono|tel[eé]fonos?|m[oó]vil(?:es)?|celular(?:es)?|tlf|fijo|fax|tel)<<C>>((?:\+?34[\s\-.]?)?[6-9]\d{2}[\s\-.]?\d{3}[\s\-.]?\d{3})",
                phone_check,
            ),
            // Country-prefixed English keywords; value requires the +34 country
            // code so a bare 9-digit number with a generic English keyword does
            // not double-match here.
            (
                PiiKind::EsPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_-]?es|spanish[\s_-]?phone[\s_-]?numbers?|spain[\s_-]?phone[\s_-]?numbers?|es[\s_-]?phone[\s_-]?numbers?|spanish[\s_-]?phones?|spain[\s_-]?phones?)<<C>>(\+?34[\s\-.]?[6-9]\d{2}[\s\-.]?\d{3}[\s\-.]?\d{3})",
                phone_check,
            ),
            (
                PiiKind::EsPostalCode,
                Language::Es,
                r"(?i)(?:c[oó]digos?[\s_-]?postal(?:es)?)<<C>>(\d{5})\b",
                es_postal_check,
            ),
            // Substring-disjoint: Spanish "código postal" has a different word
            // order than English "postal code", so it does not collide. The bare
            // "CP" token is intentionally omitted — it is already owned by
            // FrPostalCode (French "code postal"), and with no postal priority
            // group a shared "CP" would resolve Spanish codes as FR_POSTAL_CODE.
            // English alternations are country-prefixed only.
            (
                PiiKind::EsPostalCode,
                Language::En,
                r"(?i)(?:spanish[\s_-]?postal[\s_-]?codes?|spain[\s_-]?postal[\s_-]?codes?|es[\s_-]?postal[\s_-]?codes?|spanish[\s_-]?zip[\s_-]?codes?|spain[\s_-]?zip[\s_-]?codes?|spanish[\s_-]?postcodes?|spain[\s_-]?postcodes?)<<C>>(\d{5})\b",
                es_postal_check,
            ),
            (
                PiiKind::EsNuss,
                Language::Es,
                r"(?i)(?:n[uú]meros?[\s_-]?de[\s_-]?afiliaci[oó]n|n[uú]meros?[\s_-]?de[\s_-]?la[\s_-]?seguridad[\s_-]?social|n[uú]meros?[\s_-]?seguridad[\s_-]?social|seguridad[\s_-]?social|NUSS|NAF)<<C>>(\d{2}[\s/-]?\d{7,8}[\s/-]?\d{2})\b",
                es_nuss_check,
            ),
            // Substring-disjoint: Spanish stems "afiliación" / "seguridad" /
            // "social" / "NUSS" / "NAF" do not appear in the English literals;
            // country-prefixed English forms only.
            (
                PiiKind::EsNuss,
                Language::En,
                r"(?i)(?:spanish[\s_-]?social[\s_-]?security[\s_-]?numbers?|spain[\s_-]?social[\s_-]?security[\s_-]?numbers?|es[\s_-]?social[\s_-]?security[\s_-]?numbers?|spanish[\s_-]?ssns?|spain[\s_-]?ssns?)<<C>>(\d{2}[\s/-]?\d{7,8}[\s/-]?\d{2})\b",
                es_nuss_check,
            ),
            (
                PiiKind::EsPassportNumber,
                Language::Es,
                r"(?i)(?:n[uú]meros?[\s_-]?de[\s_-]?pasaporte|pasaportes?)<<C>>([A-Za-z]{2,3}\d{6})\b",
                es_passport_check,
            ),
            // Substring-disjoint: Spanish "pasaporte" does not contain the
            // English "passport"; English alternations are country-prefixed and
            // the value regex (2-3 letters + 6 digits) is disjoint from the
            // generic PassportNumber value (\d{9}).
            (
                PiiKind::EsPassportNumber,
                Language::En,
                r"(?i)(?:spanish[\s_-]?passports?|spain[\s_-]?passports?|es[\s_-]?passports?)<<C>>([A-Za-z]{2,3}\d{6})\b",
                es_passport_check,
            ),
            // --- Spanish keywords for existing international types ---
            (
                PiiKind::UsPhoneNumber,
                Language::Es,
                r"(?i)(?:n[uú]meros?[\s_-]?de[\s_-]?tel[eé]fono|tel[eé]fonos?|m[oó]vil(?:es)?|celular(?:es)?|tlf|fijo|tel)<<C>>((?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})",
                phone_check,
            ),
            // Complement to EsPassportNumber Es: shares the "pasaporte" keyword
            // but captures the generic 9-digit form; value regexes are disjoint.
            (
                PiiKind::PassportNumber,
                Language::Es,
                r"(?i)(?:n[uú]meros?[\s_-]?de[\s_-]?pasaporte|pasaportes?|documento[\s_-]?de[\s_-]?viaje)<<C>>(\d{9})\b",
                passport_check,
            ),
            (
                PiiKind::DateOfBirth,
                Language::Es,
                r"(?i)(?:fecha[\s_-]?de[\s_-]?nacimiento|fecha[\s_-]?nacimiento|nacid[oa][\s_-]?el)<<C>>(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}|\d{1,2}\s+(?:enero|ene|febrero|feb|marzo|mar|abril|abr|mayo|may|junio|jun|julio|jul|agosto|ago|septiembre|setiembre|sept|sep|set|octubre|oct|noviembre|nov|diciembre|dic)\s+\d{4})",
                dob_check,
            ),
            (
                PiiKind::PreciseGeolocation,
                Language::Es,
                r"(?i)(?:geolocalizaci[oó]n|ubicaci[oó]n[\s_-]?exacta|posici[oó]n[\s_-]?exacta|coordenadas)<<C>>(-?\d{1,3}\.\d{4,},\s?-?\d{1,3}\.\d{4,})",
                geolocation_check,
            ),
            (
                PiiKind::SwiftBic,
                Language::Es,
                r"(?i)(?:c[oó]digo[\s_-]?de[\s_-]?identificaci[oó]n[\s_-]?bancaria|identificador[\s_-]?bancario)<<C>>([A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?)\b",
                swift_bic_check,
            ),
            (
                PiiKind::Imei,
                Language::Es,
                r"(?i)(?:identificador[\s_-]?del[\s_-]?dispositivo|n[uú]meros?[\s_-]?de[\s_-]?serie[\s_-]?del[\s_-]?dispositivo|c[oó]digo[\s_-]?del[\s_-]?dispositivo)<<C>>(\d{2}-?\d{6}-?\d{6}-?\d)",
                imei_check,
            ),
            // --- Poland-specific PII types (Language::Pl) ---
            // The bare "PESEL" token and Polish "numer PESEL" form live in the
            // Pl tuple; the English structured-key form "pesel_number" lives in
            // the En tuple so it is detected under English-only language configs
            // (the Polish structured key is "numer_pesel", matched by the Pl
            // tuple). The two are substring-disjoint at extraction: bare "pesel"
            // cannot cross the "_" before "number" (the separator class excludes
            // "_"), so the En "pesel_number" form does not double-fire here.
            (
                PiiKind::PlPesel,
                Language::Pl,
                r"(?i)(?:numery?[\s_-]?pesel|pesel)<<C>>(\d{11})\b",
                pl_pesel_check,
            ),
            (
                PiiKind::PlPesel,
                Language::En,
                r"(?i)(?:pesel[\s_-]?numbers?|(?:polish|poland)[\s_-]?national[\s_-]?id(?:entification)?[\s_-]?numbers?|(?:polish|poland)[\s_-]?national[\s_-]?ids?)<<C>>(\d{11})\b",
                pl_pesel_check,
            ),
            // The keyword-gated value deliberately excludes the PL-prefixed
            // EU-VAT form — that one is caught keyword-less by the hyperscan
            // pattern, and capturing it here too would duplicate the match.
            (
                PiiKind::PlNip,
                Language::Pl,
                r"(?i)(?:numery?[\s_-]?identyfikacji[\s_-]?podatkowej|nip(?:u|owi|em)?)<<C>>(\d{3}[\s\-]?\d{2,3}[\s\-]?\d{2}[\s\-]?\d{2,3})\b",
                pl_nip_check,
            ),
            (
                PiiKind::PlNip,
                Language::En,
                r"(?i)(?:nip[\s_-]?numbers?|(?:polish|poland|pl)[\s_-]?tax[\s_-]?id(?:entification)?(?:[\s_-]?numbers?)?|(?:polish|poland|pl)[\s_-]?vat[\s_-]?(?:numbers?|ids?))<<C>>(\d{3}[\s\-]?\d{2,3}[\s\-]?\d{2}[\s\-]?\d{2,3})\b",
                pl_nip_check,
            ),
            // Bare "REGON" and "numer REGON" live in the Pl tuple; the English
            // structured-key form "regon_number" lives in the En tuple (same
            // split as PESEL above).
            (
                PiiKind::PlRegon,
                Language::Pl,
                r"(?i)(?:numery?[\s_-]?regon|regon(?:u|owi|em|y|ów)?)<<C>>(\d{14}|\d{9})\b",
                pl_regon_check,
            ),
            (
                PiiKind::PlRegon,
                Language::En,
                r"(?i)(?:regon[\s_-]?numbers?|(?:polish|poland)[\s_-]?(?:business|company|statistical)[\s_-]?registr(?:y|ation)[\s_-]?numbers?)<<C>>(\d{14}|\d{9})\b",
                pl_regon_check,
            ),
            (
                PiiKind::PlIdCard,
                Language::Pl,
                r"(?i)(?:dow[oó]d(?:u|owi|em|y|om)?[\s_-]?osobist(?:y|ego|emu|ym|e|ymi)?|dow[oó]d(?:u|owi|em|y|om)?)<<C>>([A-Za-z]{3}\s?\d{6})\b",
                pl_id_card_check,
            ),
            (
                PiiKind::PlIdCard,
                Language::En,
                r"(?i)(?:(?:polish|poland)[\s_-]?id(?:entity)?[\s_-]?cards?(?:[\s_-]?numbers?)?)<<C>>([A-Za-z]{3}\s?\d{6})\b",
                pl_id_card_check,
            ),
            // Substring-disjoint: Polish "paszport" does not contain the
            // English "passport" stem ("sz" vs "ss"); English alternations are
            // country-prefixed and the value (2 letters + 7 digits) is
            // disjoint from the generic PassportNumber value (\d{9}).
            (
                PiiKind::PlPassportNumber,
                Language::Pl,
                r"(?i)(?:numery?[\s_-]?paszport(?:u|ów)|paszport(?:u|owi|em|y|ów)?)<<C>>([A-Za-z]{2}\s?\d{7})\b",
                pl_passport_check,
            ),
            (
                PiiKind::PlPassportNumber,
                Language::En,
                r"(?i)(?:(?:polish|poland|pl)[\s_-]?passports?(?:[\s_-]?numbers?)?)<<C>>([A-Za-z]{2}\s?\d{7})\b",
                pl_passport_check,
            ),
            // Polish phone: 9 digits not starting with 0, optional +48. Shares
            // keywords with the UsPhoneNumber Pl tuple; the value regexes are
            // disjoint (9-digit vs 10-digit US).
            (
                PiiKind::PlPhoneNumber,
                Language::Pl,
                r"(?i)(?:numery?[\s_-]?telefon(?:u|ów)|telefon(?:u|owi|em|y|ów)?|kom[oó]rk(?:a|i|owy|owego)|tel)<<C>>((?:\+?48[\s\-.]?)?[1-9]\d{2}[\s\-.]?\d{3}[\s\-.]?\d{3})",
                phone_check,
            ),
            // Country-prefixed English keywords; value requires the +48
            // country code so a bare 9-digit number with a generic English
            // keyword does not double-match here.
            (
                PiiKind::PlPhoneNumber,
                Language::En,
                r"(?i)(?:phone[\s_-]?pl|(?:polish|poland|pl)[\s_-]?phone[\s_-]?numbers?|(?:polish|poland)[\s_-]?phones?)<<C>>(\+?48[\s\-.]?[1-9]\d{2}[\s\-.]?\d{3}[\s\-.]?\d{3})",
                phone_check,
            ),
            (
                PiiKind::PlPostalCode,
                Language::Pl,
                r"(?i)(?:kod(?:y|u|em|ów)?[\s_-]?pocztow(?:y|e|ego|emu|ym|ych))<<C>>(\d{2}-\d{3})\b",
                pl_postal_check,
            ),
            (
                PiiKind::PlPostalCode,
                Language::En,
                r"(?i)(?:(?:polish|poland)[\s_-]?(?:postal[\s_-]?codes?|postcodes?|zip[\s_-]?codes?))<<C>>(\d{2}-\d{3})\b",
                pl_postal_check,
            ),
            // Substring-disjoint: Polish "prawo jazdy" contains no English
            // stem; English alternations are country-prefixed.
            (
                PiiKind::PlDriversLicense,
                Language::Pl,
                r"(?i)(?:praw[oa][\s_-]?jazdy|prawem[\s_-]?jazdy)<<C>>(\d{5}/\d{2}/\d{4}(?:\d{3})?)\b",
                pl_dl_check,
            ),
            (
                PiiKind::PlDriversLicense,
                Language::En,
                r"(?i)(?:(?:polish|poland|pl)[\s_-]?driv(?:ing|ers?)[\s_-]?licen[cs]es?)<<C>>(\d{5}/\d{2}/\d{4}(?:\d{3})?)\b",
                pl_dl_check,
            ),
            // --- Polish keywords for existing international types ---
            (
                PiiKind::UsPhoneNumber,
                Language::Pl,
                r"(?i)(?:numery?[\s_-]?telefon(?:u|ów)|telefon(?:u|owi|em|y|ów)?|kom[oó]rk(?:a|i|owy|owego)|tel)<<C>>((?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})",
                phone_check,
            ),
            // Complement to PlPassportNumber Pl: shares the "paszport" keyword
            // but captures the generic 9-digit form; value regexes are disjoint.
            (
                PiiKind::PassportNumber,
                Language::Pl,
                r"(?i)(?:numery?[\s_-]?paszport(?:u|ów)|paszport(?:u|owi|em|y|ów)?|dokument[\s_-]?podr[oó][żz]y)<<C>>(\d{9})\b",
                passport_check,
            ),
            (
                PiiKind::DateOfBirth,
                Language::Pl,
                r"(?i)(?:dat[aęy][\s_-]?urodzenia|urodzon[aey])<<C>>(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}|\d{1,2}\s+(?:stycznia|sty|lutego|lut|marca|mar|kwietnia|kwi|maja|maj|czerwca|cze|lipca|lip|sierpnia|sie|września|wrz|października|paź|listopada|lis|grudnia|gru)\s+\d{4})",
                dob_check,
            ),
            (
                PiiKind::PreciseGeolocation,
                Language::Pl,
                r"(?i)(?:geolokalizacj[aię]|wsp[oó][lł]rz[eę]dne|dok[lł]adna[\s_-]?lokalizacja)<<C>>(-?\d{1,3}\.\d{4,},\s?-?\d{1,3}\.\d{4,})",
                geolocation_check,
            ),
            (
                PiiKind::SwiftBic,
                Language::Pl,
                r"(?i)(?:kod[\s_-]?identyfikacyjny[\s_-]?banku|identyfikator[\s_-]?bankowy)<<C>>([A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?)\b",
                swift_bic_check,
            ),
            (
                PiiKind::Imei,
                Language::Pl,
                r"(?i)(?:numery?[\s_-]?seryjn[ye][\s_-]?urz[aą]dzenia|identyfikator[\s_-]?urz[aą]dzenia|kod[\s_-]?urz[aą]dzenia)<<C>>(\d{2}-?\d{6}-?\d{6}-?\d)",
                imei_check,
            ),
        ];

        // Detection-only expressions for vectorscan, used instead of the full
        // extraction regex when the latter would cause DFA bloat. The extraction
        // regex (used by the regex crate for capture groups) can be wider/more
        // complex since it only runs on inputs vectorscan already confirmed.
        // PLZ uses \d{4,5} to cover DE (5-digit), AT (4-digit), and CH (4-digit).
        let detection_overrides: &[(PiiKind, Language, &str)] = &[
            (
                PiiKind::DeAtChAddress,
                Language::De,
                r"(?i)(?:Anschrift(?:en)?|Wohnadressen?|Wohnanschrift(?:en)?|Hausanschrift(?:en)?|Wohnsitz|Lieferadressen?|Rechnungsadressen?|Meldeadressen?|Zustelladressen?|Privatadressen?|Heimatadressen?|Adressen?)<<C>>([A-ZÀ-Ž][A-Za-zÀ-ž.\-]+(?:[\s\-]+[A-Za-zÀ-ž.\-]+)*\s+\d{1,4}\s?[a-zA-Z]?(?:\s?[\-/]\s?\d{1,4}\s?[a-zA-Z]?){0,3}[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
            ),
            (
                PiiKind::DeAtChPostfach,
                Language::De,
                r"(?i)(?:Postfach|PF)<<C>>(\d{1,6}[,\s]+\d{4,5}\s+[A-ZÀ-Ž][A-Za-zÀ-ž'\-]+(?:\s+[a-zÀ-ž'\-]+(?:\s+[A-Za-zÀ-ž'\-]+){0,2})?)",
            ),
            // The 12-way Dutch month-name alternation silently fails in the
            // combined vectorscan DFA (see the multi-pattern pitfall). Detect
            // with a generic `[A-Za-z]{3,9}` month token; the full extraction
            // regex (with literal month names) + dob_check still validates.
            (
                PiiKind::DateOfBirth,
                Language::Nl,
                r"(?i)(?:geboortedatum|datum[\s_-]?van[\s_-]?geboorte|geboren[\s_-]?op|geboortedag)<<C>>(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})",
            ),
            // The Italian month-name alternation likewise silently fails in the
            // combined vectorscan DFA; detect with a generic month token and let
            // the full extraction regex + dob_check validate the value.
            (
                PiiKind::DateOfBirth,
                Language::It,
                r"(?i)(?:data[\s_-]?di[\s_-]?nascita|data[\s_-]?nascita|nat[oa][\s_-]?il)<<C>>(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})",
            ),
            // The Spanish month-name alternation likewise silently fails in the
            // combined vectorscan DFA; detect with a generic month token and let
            // the full extraction regex + dob_check validate the value.
            (
                PiiKind::DateOfBirth,
                Language::Es,
                r"(?i)(?:fecha[\s_-]?de[\s_-]?nacimiento|fecha[\s_-]?nacimiento|nacid[oa][\s_-]?el)<<C>>(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})",
            ),
            // The Polish month-name alternation likewise silently fails in the
            // combined vectorscan DFA; detect with a generic month token and let
            // the full extraction regex + dob_check validate the value. The token
            // class is ASCII letters plus the Polish diacritics (e.g. "ś" in
            // "września", "ź" in "października") — narrower than \S, which would
            // add far more NFA/DFA states in UTF-8 mode and admit digit/punct
            // junk tokens. vectorscan's caseless flag is ASCII-only, so both
            // cases of the non-ASCII letters are listed explicitly.
            (
                PiiKind::DateOfBirth,
                Language::Pl,
                r"(?i)(?:dat[aęy][\s_-]?urodzenia|urodzon[aey])<<C>>(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2}|\d{1,2}\s+[A-Za-ząćęłńóśźżĄĆĘŁŃÓŚŹŻ]{3,14}\s+\d{4})",
            ),
        ];

        let raw_patterns: Vec<(PiiKind, Language, &str, fn(&str) -> bool)> = all_patterns
            .into_iter()
            .filter(|(kind, lang, _, _)| {
                enabled_kinds.contains(kind) && enabled_languages.contains(lang)
            })
            .collect();

        let mut vs_patterns = Vec::with_capacity(raw_patterns.len());
        for (id, (kind, lang, pat, _)) in raw_patterns.iter().enumerate() {
            let detection_pat = detection_overrides
                .iter()
                .find(|(k, l, _)| k == kind && l == lang)
                .map(|(_, _, p)| *p)
                .unwrap_or(pat);
            let detection_pat = expand_connectors(detection_pat, *lang);
            vs_patterns.push(Pattern::new(
                detection_pat.into_bytes(),
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
        // per *single* logical value. Sorting by (id, to) groups each pattern's
        // hits and (iterating in reverse) processes them longest-first
        // (descending `to`): the redundant hits for one value extract spans
        // contained in the longest, so we collapse them by skipping a hit whose
        // extracted span overlaps the last kept span of the *same* pattern.
        // Distinct values of one pattern produce disjoint spans and all survive
        // — a flat `to`-distance window instead wrongly dropped distinct values
        // that merely sat close together (e.g. `Passport: A, Passport: B`).
        match_regions.sort_unstable();
        let mut matches = Vec::new();
        // (pattern id, start, end) of the last kept span, for same-pattern
        // overlap collapsing.
        let mut last_kept: Option<(usize, usize, usize)> = None;
        for &(idx, to) in match_regions.iter().rev() {
            let pattern = &self.patterns[idx];
            let start = Self::region_start(input, to);
            let region = &input[start..to];
            if let Some(caps) = pattern.value_regex.captures(region)
                && let Some(value_match) = caps.get(1)
                && (pattern.validate)(value_match.as_str())
            {
                let span_start = start + value_match.start();
                let span_end = start + value_match.end();
                // Collapse the redundant end-hits vectorscan emits for one
                // value: same pattern, span overlaps the last kept one.
                if let Some((pid, pstart, pend)) = last_kept
                    && pid == idx
                    && span_start < pend
                    && pstart < span_end
                {
                    continue;
                }
                last_kept = Some((idx, span_start, span_end));
                matches.push(PiiMatch {
                    kind: pattern.kind,
                    start: span_start,
                    end: span_end,
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

    fn mark_piis_structured(&self, fragments: &[ContextFragment<'_>]) -> Vec<PiiMatch> {
        let mut results = Vec::new();
        for f in fragments {
            let stripped: String = ARRAY_INDEX_RE.replace_all(f.context, "").into_owned();
            let segments: Vec<&str> = stripped.split('.').filter(|s| !s.is_empty()).collect();
            if segments.is_empty() {
                continue;
            }

            // URL-decode and zero-width-strip the value so that encoded
            // separators (e.g. `phone%3A%20...`) and obfuscated payloads are
            // detected here too, just as `mark_piis` already handles them in
            // the flat scan path. `decode_for_detection` returns the offset
            // map so we can translate match offsets back to the original
            // value bytes; if it returns `None`, the value is unchanged and
            // offsets pass through directly.
            let decoded = decode_for_detection(f.value);
            let (scan_value, offset_map): (&str, Option<&Vec<usize>>) = match &decoded {
                Some((s, m)) => (s.as_str(), Some(m)),
                None => (f.value, None),
            };

            // Iterate from the full path down to the first segment, exposing
            // a different segment adjacent to the synthesized `:` each time.
            // If the full prefix is too long for the keyword detector's
            // lookback window, fall back to per-segment synthesis so each
            // segment still gets exposed individually.
            let full_prefix = segments.join(".");
            let prefixes: Vec<String> = if full_prefix.len() > Self::MATCH_LOOKBACK {
                segments.iter().map(|s| (*s).to_string()).collect()
            } else {
                (1..=segments.len())
                    .rev()
                    .map(|n| segments[..n].join("."))
                    .collect()
            };

            for prefix in &prefixes {
                let value_start = prefix.len() + 2; // "{prefix}: "
                let value_end = value_start + scan_value.len();
                let synthetic = format!("{prefix}: {scan_value}");

                let mut found = false;
                for m in self.mark_piis_on(&synthetic) {
                    if m.start >= value_start && m.end <= value_end {
                        // Offsets within `scan_value` (the decoded form).
                        let v_start = m.start - value_start;
                        let v_end = m.end - value_start;
                        // Map back to original value bytes when we decoded.
                        let (orig_start, orig_end) = match offset_map {
                            Some(map) => (map[v_start], map[v_end]),
                            None => (v_start, v_end),
                        };
                        results.push(PiiMatch {
                            kind: m.kind,
                            start: orig_start + f.offset,
                            end: orig_end + f.offset,
                            user_label: m.user_label,
                        });
                        found = true;
                    }
                }
                // Every iteration maps a value-region match to the same
                // document-absolute span, so the first hit wins; dedup is
                // implicit.
                if found {
                    break;
                }
            }
        }
        results
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

    // Regression: English structured-key forms for Polish kinds (pesel_number,
    // nip_number, regon_number) must be detected when ONLY Language::En is
    // enabled (e.g. a deployment scanning English JSON for Polish IDs). They
    // live in the Language::En tuples, not Language::Pl, so language filtering
    // does not drop them. The bare Polish keyword (`pesel:`) correctly does NOT
    // fire under En-only since it is a Polish-language keyword.
    #[test]
    fn english_structured_keys_detected_under_en_only_language() {
        let kinds: HashSet<PiiKind> = [PiiKind::PlPesel, PiiKind::PlNip, PiiKind::PlRegon]
            .into_iter()
            .collect();
        let languages: HashSet<Language> = [Language::En].into_iter().collect();
        let detector = KeywordContextDetector::new(&kinds, &languages).unwrap();

        for (input, kind) in [
            ("pesel_number: 44051401359", PiiKind::PlPesel),
            ("nip_number: 7740001454", PiiKind::PlNip),
            ("regon_number: 610188201", PiiKind::PlRegon),
        ] {
            assert!(
                detector.mark_piis(input).iter().any(|m| m.kind == kind),
                "expected {kind:?} under En-only for: {input}"
            );
        }

        // Bare Polish keyword is Pl-tagged → not detected under En-only.
        assert!(
            detector
                .mark_piis("pesel: 44051401359")
                .iter()
                .all(|m| m.kind != PiiKind::PlPesel),
            "bare Polish `pesel:` keyword should not fire under En-only language"
        );
    }

    // --- Detection with span verification ---

    // Zero-width space (U+200B) is stripped before matching; the returned span
    // covers the original bytes so the caller can redact the full obfuscated token.
    #[test_case("phone: 555\u{200B}-123-4567", PiiKind::UsPhoneNumber, "555\u{200B}-123-4567" ; "phone zwsp in value stripped")]
    // ZWS inside a digit group (not replacing a separator) — after stripping,
    // "1\u{200B}23 456 782" becomes "123 456 782" which passes the TFN checksum.
    #[test_case("TFN: 1\u{200B}23 456 782", PiiKind::AuTfn, "1\u{200B}23 456 782" ; "tfn zwsp in digit stripped")]
    #[test_case("phone: 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "phone basic")]
    #[test_case("phone: (555) 123-4567", PiiKind::UsPhoneNumber, "(555) 123-4567" ; "phone parens")]
    #[test_case("phone: 555.123.4567", PiiKind::UsPhoneNumber, "555.123.4567" ; "phone dots")]
    #[test_case("phone: +1-555-123-4567", PiiKind::UsPhoneNumber, "+1-555-123-4567" ; "phone country code")]
    #[test_case("phone: 5551234567", PiiKind::UsPhoneNumber, "5551234567" ; "phone no separators")]
    #[test_case("Passport Number: 123456789", PiiKind::PassportNumber, "123456789" ; "passport")]
    #[test_case("passport: 987654321", PiiKind::PassportNumber, "987654321" ; "passport lowercase")]
    #[test_case("**Passport Number**: 32BV67680", PiiKind::PassportNumber, "32BV67680" ; "passport alphanumeric french shape en keyword")]
    #[test_case("<passport>123456789</passport>", PiiKind::PassportNumber, "123456789" ; "passport xml tag wrapper")]
    #[test_case("<Passport_Number>123456789</Passport_Number>", PiiKind::PassportNumber, "123456789" ; "passport xml tag underscore")]
    #[test_case("<passport number>123456789</passport number>", PiiKind::PassportNumber, "123456789" ; "passport xml tag space")]
    #[test_case("TFN: 123 456 782", PiiKind::AuTfn, "123 456 782" ; "tfn")]
    // Formatless / hyphenated TFN — value separator is optional (rec 7).
    #[test_case("TFN: 123456782", PiiKind::AuTfn, "123456782" ; "tfn formatless")]
    #[test_case("TFN: 123-456-782", PiiKind::AuTfn, "123-456-782" ; "tfn hyphenated")]
    #[test_case(r#""taxFileNumber": "123456782""#, PiiKind::AuTfn, "123456782" ; "tfn camelcase formatless")]
    #[test_case("IRD: 49-091-857", PiiKind::NzIrdNumber, "49-091-857" ; "ird")]
    #[test_case("IRD number: 49-091-857", PiiKind::NzIrdNumber, "49-091-857" ; "ird span")]
    // Formatless / partially-hyphenated IRD — value separator is optional (rec 7).
    #[test_case("IRD: 49091857", PiiKind::NzIrdNumber, "49091857" ; "ird formatless 8 digit")]
    #[test_case("IRD: 100000148", PiiKind::NzIrdNumber, "100000148" ; "ird formatless 9 digit")]
    #[test_case(r#""irdNumber": "49091857""#, PiiKind::NzIrdNumber, "49091857" ; "ird camelcase formatless")]
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
    // Formatless sort code — value separator is optional (rec 7).
    #[test_case("Sort code: 200000", PiiKind::GbSortCode, "200000" ; "sort code formatless")]
    #[test_case(r#""sortCode": "200000""#, PiiKind::GbSortCode, "200000" ; "sort code camelcase formatless")]
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
    #[test_case("\"phone_uk\":\"+44 20 7946 0958\"", PiiKind::GbPhoneNumber, "+44 20 7946 0958" ; "gb phone json phone_uk suffix")]
    #[test_case("\"phone_gb\":\"+44 20 7946 0958\"", PiiKind::GbPhoneNumber, "+44 20 7946 0958" ; "gb phone json phone_gb suffix")]
    #[test_case("tel: +61 4 1234 5678", PiiKind::AuPhoneNumber, "+61 4 1234 5678" ; "au phone mobile intl")]
    #[test_case("phone: 04 1234 5678", PiiKind::AuPhoneNumber, "04 1234 5678" ; "au phone mobile local")]
    #[test_case("\"phone_au\":\"+61 4 1234 5678\"", PiiKind::AuPhoneNumber, "+61 4 1234 5678" ; "au phone json phone_au suffix")]
    #[test_case("phone: +64 2 123 4567", PiiKind::NzPhoneNumber, "+64 2 123 4567" ; "nz phone mobile intl")]
    #[test_case("phone: 02 123 4567", PiiKind::NzPhoneNumber, "02 123 4567" ; "nz phone mobile local")]
    #[test_case("\"phone_nz\":\"+64 2 123 4567\"", PiiKind::NzPhoneNumber, "+64 2 123 4567" ; "nz phone json phone_nz suffix")]
    #[test_case("phone: +353 87 123 4567", PiiKind::IePhoneNumber, "+353 87 123 4567" ; "ie phone mobile intl")]
    #[test_case("phone: 087 123 4567", PiiKind::IePhoneNumber, "087 123 4567" ; "ie phone mobile local")]
    #[test_case("\"phone_ie\":\"+353 87 123 4567\"", PiiKind::IePhoneNumber, "+353 87 123 4567" ; "ie phone json phone_ie suffix")]
    // IE single-digit area codes (Dublin = 1) with separator between area and subscriber.
    #[test_case("phone: +353 1 234 5678", PiiKind::IePhoneNumber, "+353 1 234 5678" ; "ie phone dublin spaced")]
    #[test_case("phone: 01 234 5678", PiiKind::IePhoneNumber, "01 234 5678" ; "ie phone dublin local spaced")]
    #[test_case("phone: +353-1-234-5678", PiiKind::IePhoneNumber, "+353-1-234-5678" ; "ie phone dublin hyphenated")]
    #[test_case("phone: +353.1.234.5678", PiiKind::IePhoneNumber, "+353.1.234.5678" ; "ie phone dublin dotted")]
    #[test_case("phone: +27 71 123 4567", PiiKind::ZaPhoneNumber, "+27 71 123 4567" ; "za phone mobile intl")]
    #[test_case("phone: 071 123 4567", PiiKind::ZaPhoneNumber, "071 123 4567" ; "za phone mobile local")]
    #[test_case("\"phone_za\":\"+27 71 123 4567\"", PiiKind::ZaPhoneNumber, "+27 71 123 4567" ; "za phone json phone_za suffix")]
    #[test_case("\"phone_sa\":\"+27 71 123 4567\"", PiiKind::ZaPhoneNumber, "+27 71 123 4567" ; "za phone json phone_sa suffix")]
    #[test_case("\"phone_us\":\"+1-415-555-0132\"", PiiKind::UsPhoneNumber, "+1-415-555-0132" ; "us phone json phone_us suffix")]
    #[test_case("british passport: 123456789", PiiKind::GbZaPassportNumber, "123456789" ; "gb passport")]
    #[test_case("uk passport: 987654321", PiiKind::GbZaPassportNumber, "987654321" ; "gb passport uk keyword")]
    #[test_case("south african passport: 123456789", PiiKind::GbZaPassportNumber, "123456789" ; "za passport")]
    #[test_case("sa passport: 987654321", PiiKind::GbZaPassportNumber, "987654321" ; "za passport sa keyword")]
    #[test_case("driver's licence: 8001015009087", PiiKind::ZaDriversLicense, "8001015009087" ; "za drivers licence")]
    #[test_case("driving licence number: 9506150089081", PiiKind::ZaDriversLicense, "9506150089081" ; "za driving licence")]
    #[test_case("postal code: 0001", PiiKind::UsZaPostalCode, "0001" ; "za postal code lower")]
    #[test_case("zip code: 8001", PiiKind::UsZaPostalCode, "8001" ; "za postal code cape town")]
    // US ZIP — real codes from USPS / Wikipedia.
    #[test_case("zip: 90210", PiiKind::UsZaPostalCode, "90210" ; "us zip beverly hills")]
    #[test_case("ZIP code: 10001", PiiKind::UsZaPostalCode, "10001" ; "us zip manhattan")]
    #[test_case("postal code: 20500", PiiKind::UsZaPostalCode, "20500" ; "us zip white house")]
    #[test_case("zip: 90210-1234", PiiKind::UsZaPostalCode, "90210-1234" ; "us zip plus four")]
    #[test_case(r#""zipCode": "20001""#, PiiKind::UsZaPostalCode, "20001" ; "us zip camelcase json")]
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
    #[test_case("german passport: C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de passport en keyword")]
    #[test_case("Reisepass: C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de passport reisepass")]
    #[test_case("Reisepassnummer: C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de passport reisepassnummer")]
    #[test_case("Reisepass-Nr.: C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de passport reisepass nr")]
    #[test_case("Passnummer: C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de passport passnummer")]
    #[test_case("Pass-Nr.: C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de passport pass nr")]
    #[test_case("Reisedokument: C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de passport reisedokument")]
    #[test_case("Dokumentennummer: C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de passport dokumentennummer")]
    #[test_case("bundespass: CFGHJKLMN", PiiKind::DePassportNumber, "CFGHJKLMN" ; "de passport bundespass")]
    #[test_case("\"passport\":\"C01X00T47\"", PiiKind::DePassportNumber, "C01X00T47" ; "de passport json en")]
    #[test_case("\"reisepass\":\"C01X00T47\"", PiiKind::DePassportNumber, "C01X00T47" ; "de passport json reisepass")]
    #[test_case("Reisepassnummern: C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de passport reisepassnummern plural")]
    #[test_case("Passnummern: C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de passport passnummern plural")]
    #[test_case("Dokumentennummern: C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de passport dokumentennummern plural")]
    #[test_case("reisepass_nr: C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de passport reisepass nr snake_case")]
    #[test_case("\"reisepassnummer\":\"C01X00T47\"", PiiKind::DePassportNumber, "C01X00T47" ; "de passport json reisepassnummer")]
    #[test_case("\"passnummer\":\"C01X00T47\"", PiiKind::DePassportNumber, "C01X00T47" ; "de passport json passnummer")]
    // Matomo `_cvar` double-escapes quotes inside the URL-encoded JSON payload,
    // so the raw body contains `\",\"` (literal backslash) between keyword and value.
    #[test_case(r#"_cvar={\"2\":[\"passport\",\"C01X00T47\"]}"#, PiiKind::DePassportNumber, "C01X00T47" ; "de passport matomo cvar double escape")]
    #[test_case("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", PiiKind::AwsSecretKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" ; "aws secret env")]
    #[test_case("secret_access_key: abcdefghijklmnopqrstuvwxyz0123456789ABCD", PiiKind::AwsSecretKey, "abcdefghijklmnopqrstuvwxyz0123456789ABCD" ; "aws secret keyword")]
    #[test_case("\"aws_secret\":\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"", PiiKind::AwsSecretKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" ; "aws secret json quoted")]
    #[test_case("\"secret_access_key\":\"abcdefghijklmnopqrstuvwxyz0123456789ABCD\"", PiiKind::AwsSecretKey, "abcdefghijklmnopqrstuvwxyz0123456789ABCD" ; "aws secret json quoted full key")]
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
    // English keywords for FR PII kinds — exercises JSON-key-in-English / value-in-FR-format case
    // FrNir
    #[test_case("french social security number: 1 85 05 78 006 084 91", PiiKind::FrNir, "1 85 05 78 006 084 91" ; "fr nir en singular")]
    #[test_case("french social security numbers: 1 85 05 78 006 084 91", PiiKind::FrNir, "1 85 05 78 006 084 91" ; "fr nir en plural")]
    #[test_case("french_social_security_number: 185036912304532", PiiKind::FrNir, "185036912304532" ; "fr nir en snake_case")]
    #[test_case("france-social-security-number: 185036912304532", PiiKind::FrNir, "185036912304532" ; "fr nir en kebab-case")]
    #[test_case("\"frenchSocialSecurityNumber\":\"185036912304532\"", PiiKind::FrNir, "185036912304532" ; "fr nir en camelCase json")]
    #[test_case("\"fr_ssn\":\"175012A00403288\"", PiiKind::FrNir, "175012A00403288" ; "fr nir en json fr_ssn")]
    // FrSiret
    #[test_case("french establishment number: 73282932000074", PiiKind::FrSiret, "73282932000074" ; "fr siret en singular")]
    #[test_case("french establishment numbers: 73282932000074", PiiKind::FrSiret, "73282932000074" ; "fr siret en plural")]
    #[test_case("french_establishment_number: 77567041700051", PiiKind::FrSiret, "77567041700051" ; "fr siret en snake_case")]
    #[test_case("france-establishment-number: 54205118000066", PiiKind::FrSiret, "54205118000066" ; "fr siret en kebab-case")]
    #[test_case("\"frenchEstablishmentNumber\":\"71204961800739\"", PiiKind::FrSiret, "71204961800739" ; "fr siret en camelCase json")]
    #[test_case("\"fr_establishment_id\":\"73282932000074\"", PiiKind::FrSiret, "73282932000074" ; "fr siret en json fr prefix")]
    // FrSiren
    #[test_case("french company number: 732829320", PiiKind::FrSiren, "732829320" ; "fr siren en singular")]
    #[test_case("french company numbers: 732829320", PiiKind::FrSiren, "732829320" ; "fr siren en plural")]
    #[test_case("french_company_number: 775670417", PiiKind::FrSiren, "775670417" ; "fr siren en snake_case")]
    #[test_case("france-company-number: 542051180", PiiKind::FrSiren, "542051180" ; "fr siren en kebab-case")]
    #[test_case("\"frenchCompanyNumber\":\"441639465\"", PiiKind::FrSiren, "441639465" ; "fr siren en camelCase json")]
    #[test_case("\"fr_business_number\":\"780129987\"", PiiKind::FrSiren, "780129987" ; "fr siren en json business")]
    // FrPassportNumber
    #[test_case("french passport: 05AB12345", PiiKind::FrPassportNumber, "05AB12345" ; "fr passport en singular")]
    #[test_case("french passports: 05AB12345", PiiKind::FrPassportNumber, "05AB12345" ; "fr passport en plural")]
    #[test_case("french_passport_number: 05AB12345", PiiKind::FrPassportNumber, "05AB12345" ; "fr passport en snake_case")]
    #[test_case("france-passport: 05AB12345", PiiKind::FrPassportNumber, "05AB12345" ; "fr passport en kebab-case")]
    #[test_case("\"frenchPassport\":\"05AB12345\"", PiiKind::FrPassportNumber, "05AB12345" ; "fr passport en camelCase json")]
    #[test_case("\"fr_passport_number\":\"05AB12345\"", PiiKind::FrPassportNumber, "05AB12345" ; "fr passport en json fr prefix")]
    // FrCni
    #[test_case("french national id: 123456789012", PiiKind::FrCni, "123456789012" ; "fr cni en singular")]
    #[test_case("french national ids: 123456789012", PiiKind::FrCni, "123456789012" ; "fr cni en plural")]
    #[test_case("french_id_card: 123456789012", PiiKind::FrCni, "123456789012" ; "fr cni en snake_case")]
    #[test_case("france-id-card: 123456789012", PiiKind::FrCni, "123456789012" ; "fr cni en kebab-case")]
    #[test_case("\"frenchIdentityCard\":\"123456789012\"", PiiKind::FrCni, "123456789012" ; "fr cni en camelCase json")]
    #[test_case("\"fr_national_id\":\"123456789012\"", PiiKind::FrCni, "123456789012" ; "fr cni en json fr prefix")]
    // FrDriversLicense
    #[test_case("french drivers license: 123456789012", PiiKind::FrDriversLicense, "123456789012" ; "fr dl en singular")]
    #[test_case("french drivers licenses: 123456789012", PiiKind::FrDriversLicense, "123456789012" ; "fr dl en plural")]
    #[test_case("french_driving_licence: 123456789012", PiiKind::FrDriversLicense, "123456789012" ; "fr dl en snake_case british")]
    #[test_case("france-drivers-license: 123456789012", PiiKind::FrDriversLicense, "123456789012" ; "fr dl en kebab-case")]
    #[test_case("\"frenchDriversLicense\":\"123456789012\"", PiiKind::FrDriversLicense, "123456789012" ; "fr dl en camelCase json")]
    #[test_case("\"fr_driving_license\":\"123456789012\"", PiiKind::FrDriversLicense, "123456789012" ; "fr dl en json fr prefix")]
    // FrPhoneNumber
    #[test_case("french phone: +33 6 12 34 56 78", PiiKind::FrPhoneNumber, "+33 6 12 34 56 78" ; "fr phone en singular")]
    #[test_case("french phones: +33 6 12 34 56 78", PiiKind::FrPhoneNumber, "+33 6 12 34 56 78" ; "fr phone en plural")]
    #[test_case("french_phone_number: +33 6 12 34 56 78", PiiKind::FrPhoneNumber, "+33 6 12 34 56 78" ; "fr phone en snake_case")]
    #[test_case("france-phone-number: +33 6 12 34 56 78", PiiKind::FrPhoneNumber, "+33 6 12 34 56 78" ; "fr phone en kebab-case")]
    #[test_case("\"frenchPhoneNumber\":\"+33 6 12 34 56 78\"", PiiKind::FrPhoneNumber, "+33 6 12 34 56 78" ; "fr phone en camelCase json")]
    #[test_case("\"phone_fr\":\"+33 6 12 34 56 78\"", PiiKind::FrPhoneNumber, "+33 6 12 34 56 78" ; "fr phone en json phone_fr suffix")]
    // FrPostalCode
    #[test_case("french postal code: 75001", PiiKind::FrPostalCode, "75001" ; "fr postal en singular")]
    #[test_case("french postal codes: 75001", PiiKind::FrPostalCode, "75001" ; "fr postal en plural")]
    #[test_case("french_postal_code: 13001", PiiKind::FrPostalCode, "13001" ; "fr postal en snake_case")]
    #[test_case("france-zip-code: 69001", PiiKind::FrPostalCode, "69001" ; "fr postal en kebab-case zip")]
    #[test_case("\"frenchPostcode\":\"31000\"", PiiKind::FrPostalCode, "31000" ; "fr postal en camelCase json postcode")]
    #[test_case("\"fr_postal_code\":\"97110\"", PiiKind::FrPostalCode, "97110" ; "fr postal en json fr prefix")]
    // FrNif
    #[test_case("french tax id: 0123456789012", PiiKind::FrNif, "0123456789012" ; "fr nif en singular")]
    #[test_case("french tax ids: 0123456789012", PiiKind::FrNif, "0123456789012" ; "fr nif en plural")]
    #[test_case("french_tax_number: 0123456789012", PiiKind::FrNif, "0123456789012" ; "fr nif en snake_case")]
    #[test_case("france-tax-id: 0123456789012", PiiKind::FrNif, "0123456789012" ; "fr nif en kebab-case")]
    #[test_case("\"frenchTaxId\":\"0123456789012\"", PiiKind::FrNif, "0123456789012" ; "fr nif en camelCase json")]
    #[test_case("\"fr_taxpayer_id\":\"0123456789012\"", PiiKind::FrNif, "0123456789012" ; "fr nif en json taxpayer")]
    // French keywords for existing international types
    #[test_case("date de naissance: 15 mars 1990", PiiKind::DateOfBirth, "15 mars 1990" ; "fr dob")]
    #[test_case("date de naissance: 15 déc 1990", PiiKind::DateOfBirth, "15 déc 1990" ; "fr dob abbrev dec")]
    #[test_case("date de naissance: 3 janv 1990", PiiKind::DateOfBirth, "3 janv 1990" ; "fr dob abbrev janv")]
    #[test_case("rappel: 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "fr keyword us phone")]
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
    // English keywords for DE Steuer-ID
    #[test_case("german tax id: 65929970489", PiiKind::DeSteuerId, "65929970489" ; "de steuer id en singular")]
    #[test_case("german tax ids: 65929970489", PiiKind::DeSteuerId, "65929970489" ; "de steuer id en plural")]
    #[test_case("german_tax_id: 65929970489", PiiKind::DeSteuerId, "65929970489" ; "de steuer id en snake_case")]
    #[test_case("german-tax-id: 65929970489", PiiKind::DeSteuerId, "65929970489" ; "de steuer id en kebab-case")]
    #[test_case("\"germanTaxId\":\"65929970489\"", PiiKind::DeSteuerId, "65929970489" ; "de steuer id en camelCase json")]
    #[test_case("tax identification number: 86095742719", PiiKind::DeSteuerId, "86095742719" ; "de steuer id en tax identification long phrase")]
    // Personalausweis — values from kryptografie.de/personalausweis.htm
    #[test_case("Personalausweis: L01X00T471", PiiKind::DePersonalausweis, "L01X00T471" ; "de personalausweis newest format")]
    #[test_case("Ausweisnummer: T220001293", PiiKind::DePersonalausweis, "T220001293" ; "de personalausweis new format")]
    #[test_case("Personalausweisnummer: C01X00T478", PiiKind::DePersonalausweis, "C01X00T478" ; "de personalausweis long keyword")]
    #[test_case("Personalausweis: M123456788", PiiKind::DePersonalausweis, "M123456788" ; "de personalausweis sequential digits")]
    // English keywords for DE Personalausweis
    #[test_case("german national id: L01X00T471", PiiKind::DePersonalausweis, "L01X00T471" ; "de personalausweis en singular")]
    #[test_case("german national ids: L01X00T471", PiiKind::DePersonalausweis, "L01X00T471" ; "de personalausweis en plural")]
    #[test_case("german_id_card: L01X00T471", PiiKind::DePersonalausweis, "L01X00T471" ; "de personalausweis en snake_case")]
    #[test_case("german-id-card: L01X00T471", PiiKind::DePersonalausweis, "L01X00T471" ; "de personalausweis en kebab-case")]
    #[test_case("\"nationalIdCard\":\"L01X00T471\"", PiiKind::DePersonalausweis, "L01X00T471" ; "de personalausweis en camelCase json")]
    #[test_case("\"german_identity_card\":\"C01X00T478\"", PiiKind::DePersonalausweis, "C01X00T478" ; "de personalausweis en json identity card")]
    // German phones
    #[test_case("Rufnummer: +49 30 12345678", PiiKind::DePhoneNumber, "+49 30 12345678" ; "de phone berlin landline")]
    #[test_case("Handynummer: +49 151 12345678", PiiKind::DePhoneNumber, "+49 151 12345678" ; "de phone mobile")]
    #[test_case("Telefonnummer: +49 89 98765432", PiiKind::DePhoneNumber, "+49 89 98765432" ; "de phone munich landline")]
    #[test_case("Festnetz: 030 12345678", PiiKind::DePhoneNumber, "030 12345678" ; "de phone local format")]
    #[test_case("Kontaktnummer: +49 221 1234567", PiiKind::DePhoneNumber, "+49 221 1234567" ; "de phone cologne")]
    // English-keyword variants (Language::En sibling regex). The intl form must
    // include `+49` so we don't conflate with US/local numbers under a generic
    // `phone` keyword.
    #[test_case("phone: +49 30 12345678", PiiKind::DePhoneNumber, "+49 30 12345678" ; "de phone en keyword berlin")]
    #[test_case("\"phone\": \"+49 30 123456\"", PiiKind::DePhoneNumber, "+49 30 123456" ; "de phone json en keyword")]
    #[test_case("\"phone_de\":\"+49 151 12345678\"", PiiKind::DePhoneNumber, "+49 151 12345678" ; "de phone json phone_de suffix")]
    #[test_case("mobile: +49 151 12345678", PiiKind::DePhoneNumber, "+49 151 12345678" ; "de phone en mobile keyword")]
    #[test_case("\"mobilePhone\": \"+49 151 12345678\"", PiiKind::DePhoneNumber, "+49 151 12345678" ; "de phone en mobile camelcase")]
    // German postal codes
    #[test_case("Postleitzahl: 10115", PiiKind::DePostalCode, "10115" ; "de postal code berlin")]
    #[test_case("PLZ: 80331", PiiKind::DePostalCode, "80331" ; "de postal code munich")]
    #[test_case("Postleitzahl: 01067", PiiKind::DePostalCode, "01067" ; "de postal code dresden")]
    #[test_case("PLZ: 60311", PiiKind::DePostalCode, "60311" ; "de postal code frankfurt")]
    #[test_case("PLZ: 20095", PiiKind::DePostalCode, "20095" ; "de postal code hamburg")]
    // English keywords for DE postal code
    #[test_case("german postal code: 10115", PiiKind::DePostalCode, "10115" ; "de postal code en singular")]
    #[test_case("german postal codes: 10115", PiiKind::DePostalCode, "10115" ; "de postal code en plural")]
    #[test_case("german_postal_code: 80331", PiiKind::DePostalCode, "80331" ; "de postal code en snake_case")]
    #[test_case("german-zip-code: 01067", PiiKind::DePostalCode, "01067" ; "de postal code en kebab-case zip")]
    #[test_case("\"germanPostcode\":\"60311\"", PiiKind::DePostalCode, "60311" ; "de postal code en camelCase json postcode")]
    #[test_case("\"de_postal_code\":\"20095\"", PiiKind::DePostalCode, "20095" ; "de postal code en json de prefix")]
    // Austria-specific PII types — SVNR from gist.github.com/jensens
    #[test_case("SVNR: 1238150185", PiiKind::AtSvnr, "1238150185" ; "at svnr")]
    #[test_case("Sozialversicherungsnummer: 1233250689", PiiKind::AtSvnr, "1233250689" ; "at svnr long keyword")]
    #[test_case("Versicherungsnummer: 1237010180", PiiKind::AtSvnr, "1237010180" ; "at svnr documented example")]
    #[test_case("SVNR: 4567150390", PiiKind::AtSvnr, "4567150390" ; "at svnr born 1990")]
    #[test_case("SVNR: 7892281275", PiiKind::AtSvnr, "7892281275" ; "at svnr born 1975")]
    // English keywords for AT SVNR — exercises JSON-key-in-English / value-in-AT-format case.
    #[test_case("austrian social security number: 1238150185", PiiKind::AtSvnr, "1238150185" ; "at svnr en long keyword singular")]
    #[test_case("austrian social security numbers: 1238150185", PiiKind::AtSvnr, "1238150185" ; "at svnr en long keyword plural")]
    #[test_case("at_svnr: 1238150185", PiiKind::AtSvnr, "1238150185" ; "at svnr en snake_case")]
    #[test_case("at-svnr: 1238150185", PiiKind::AtSvnr, "1238150185" ; "at svnr en kebab-case")]
    #[test_case("\"atSvnr\":\"1238150185\"", PiiKind::AtSvnr, "1238150185" ; "at svnr en camelCase json")]
    #[test_case("\"austrian_social_security_number\":\"1238150185\"", PiiKind::AtSvnr, "1238150185" ; "at svnr en json long key")]
    #[test_case("\"austrianInsuranceNumber\":\"1238150185\"", PiiKind::AtSvnr, "1238150185" ; "at svnr en json insurance camelCase")]
    // Austrian phones and postal
    #[test_case("Rufnummer: +43 1 12345678", PiiKind::AtPhoneNumber, "+43 1 12345678" ; "at phone vienna")]
    #[test_case("Handynummer: +43 664 1234567", PiiKind::AtPhoneNumber, "+43 664 1234567" ; "at phone mobile")]
    #[test_case("phone: +43 1 2345678", PiiKind::AtPhoneNumber, "+43 1 2345678" ; "at phone en keyword vienna")]
    #[test_case("\"altPhone\": \"+43 1 2345678\"", PiiKind::AtPhoneNumber, "+43 1 2345678" ; "at phone en keyword camelcase")]
    #[test_case("mobile: +43 664 1234567", PiiKind::AtPhoneNumber, "+43 664 1234567" ; "at phone en mobile keyword")]
    #[test_case("PLZ: 1010", PiiKind::AtPostalCode, "1010" ; "at postal code vienna")]
    #[test_case("Postleitzahl: 5020", PiiKind::AtPostalCode, "5020" ; "at postal code salzburg")]
    #[test_case("PLZ: 8010", PiiKind::AtPostalCode, "8010" ; "at postal code graz")]
    // English keywords for AT postal code
    #[test_case("austrian postal code: 1010", PiiKind::AtPostalCode, "1010" ; "at postal code en singular")]
    #[test_case("austrian postal codes: 1010", PiiKind::AtPostalCode, "1010" ; "at postal code en plural")]
    #[test_case("austrian_postal_code: 5020", PiiKind::AtPostalCode, "5020" ; "at postal code en snake_case")]
    #[test_case("austrian-zip-code: 8010", PiiKind::AtPostalCode, "8010" ; "at postal code en kebab-case zip")]
    #[test_case("\"austrianPostcode\":\"1010\"", PiiKind::AtPostalCode, "1010" ; "at postal code en camelCase json")]
    #[test_case("\"at_postal_code\":\"5020\"", PiiKind::AtPostalCode, "5020" ; "at postal code en json at prefix")]
    // Switzerland-specific — AHV from sozialversicherungsnummer.ch and gist.github.com/rordi
    #[test_case("AHV-Nummer: 756.1234.5678.97", PiiKind::ChAhv, "756.1234.5678.97" ; "ch ahv dotted")]
    #[test_case("Versichertennummer: 7561234567897", PiiKind::ChAhv, "7561234567897" ; "ch ahv plain")]
    #[test_case("AHV-Nr: 756.9217.0769.85", PiiKind::ChAhv, "756.9217.0769.85" ; "ch ahv sozialversicherungsnummer.ch example")]
    #[test_case("AHV-Nummer: 756.0081.3782.50", PiiKind::ChAhv, "756.0081.3782.50" ; "ch ahv gist example")]
    #[test_case("OASI: 756.3026.0705.92", PiiKind::ChAhv, "756.3026.0705.92" ; "ch ahv oasi keyword")]
    // English keywords for CH AHV
    #[test_case("swiss social security number: 756.1234.5678.97", PiiKind::ChAhv, "756.1234.5678.97" ; "ch ahv en singular")]
    #[test_case("swiss social security numbers: 756.1234.5678.97", PiiKind::ChAhv, "756.1234.5678.97" ; "ch ahv en plural")]
    #[test_case("swiss_social_security_number: 756.0081.3782.50", PiiKind::ChAhv, "756.0081.3782.50" ; "ch ahv en snake_case")]
    #[test_case("swiss-insurance-number: 756.9217.0769.85", PiiKind::ChAhv, "756.9217.0769.85" ; "ch ahv en kebab-case insurance")]
    #[test_case("\"swissSocialSecurityNumber\":\"756.3026.0705.92\"", PiiKind::ChAhv, "756.3026.0705.92" ; "ch ahv en camelCase json")]
    #[test_case("\"ch_insurance_number\":\"7561234567897\"", PiiKind::ChAhv, "7561234567897" ; "ch ahv en json ch prefix")]
    // Swiss phones and postal
    #[test_case("Rufnummer: +41 44 123 45 67", PiiKind::ChPhoneNumber, "+41 44 123 45 67" ; "ch phone zurich")]
    #[test_case("Handynummer: +41 79 123 45 67", PiiKind::ChPhoneNumber, "+41 79 123 45 67" ; "ch phone mobile")]
    #[test_case("phone: +41 44 668 18 00", PiiKind::ChPhoneNumber, "+41 44 668 18 00" ; "ch phone en keyword zurich")]
    #[test_case("\"workPhone\": \"+41 44 668 18 00\"", PiiKind::ChPhoneNumber, "+41 44 668 18 00" ; "ch phone en keyword camelcase")]
    #[test_case("\"phone_ch\":\"+41 79 123 45 67\"", PiiKind::ChPhoneNumber, "+41 79 123 45 67" ; "ch phone json phone_ch suffix")]
    #[test_case("mobile: +41 79 123 45 67", PiiKind::ChPhoneNumber, "+41 79 123 45 67" ; "ch phone en mobile keyword")]
    #[test_case("PLZ: 8001", PiiKind::ChPostalCode, "8001" ; "ch postal code zurich")]
    #[test_case("Postleitzahl: 3000", PiiKind::ChPostalCode, "3000" ; "ch postal code bern")]
    #[test_case("PLZ: 1200", PiiKind::ChPostalCode, "1200" ; "ch postal code geneva")]
    // English keywords for CH postal code
    #[test_case("swiss postal code: 8001", PiiKind::ChPostalCode, "8001" ; "ch postal code en singular")]
    #[test_case("swiss postal codes: 8001", PiiKind::ChPostalCode, "8001" ; "ch postal code en plural")]
    #[test_case("swiss_postal_code: 3000", PiiKind::ChPostalCode, "3000" ; "ch postal code en snake_case")]
    #[test_case("swiss-zip-code: 1200", PiiKind::ChPostalCode, "1200" ; "ch postal code en kebab-case zip")]
    #[test_case("\"swissPostcode\":\"8001\"", PiiKind::ChPostalCode, "8001" ; "ch postal code en camelCase json")]
    #[test_case("\"ch_postal_code\":\"3000\"", PiiKind::ChPostalCode, "3000" ; "ch postal code en json ch prefix")]
    // German keywords for existing international types
    #[test_case("Rufnummer: 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "de keyword us phone")]
    #[test_case("Kontaktnummer: (555) 234-5678", PiiKind::UsPhoneNumber, "(555) 234-5678" ; "de keyword us phone parens")]
    #[test_case("Reisepass: 123456789", PiiKind::PassportNumber, "123456789" ; "de keyword passport")]
    #[test_case("Passnummer: 987654321", PiiKind::PassportNumber, "987654321" ; "de keyword passport alt")]
    #[test_case("Geburtsdatum: 15.03.1990", PiiKind::DateOfBirth, "15.03.1990" ; "de keyword dob numeric")]
    #[test_case("Geburtsdatum: 15 März 1990", PiiKind::DateOfBirth, "15 März 1990" ; "de keyword dob month name")]
    #[test_case("Geburtsdatum: 15 Okt 1990", PiiKind::DateOfBirth, "15 Okt 1990" ; "de keyword dob abbrev okt")]
    #[test_case("Geburtsdatum: 3 Dez 1990", PiiKind::DateOfBirth, "3 Dez 1990" ; "de keyword dob abbrev dez")]
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
    // Capture stops at sentence punctuation.
    #[test_case("full name: John Smith. Other notes follow.", PiiKind::PersonName, "John Smith" ; "person name stops at period")]
    #[test_case("full name: John Smith, additional info", PiiKind::PersonName, "John Smith" ; "person name stops at comma")]
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
    // GB address — qualified keywords + GB postcode anchor
    #[test_case("home address: 10 Downing Street, London, SW1A 2AA", PiiKind::GbAddress, "10 Downing Street, London, SW1A 2AA" ; "gb address downing street")]
    #[test_case("postal address: 221B Baker Street, London NW1 6XE", PiiKind::GbAddress, "221B Baker Street, London NW1 6XE" ; "gb address baker street")]
    #[test_case("billing address: 30 St Mary Axe, London EC3A 8BF", PiiKind::GbAddress, "30 St Mary Axe, London EC3A 8BF" ; "gb address gherkin")]
    #[test_case("delivery address: 350 Euston Road, London NW1 2RH", PiiKind::GbAddress, "350 Euston Road, London NW1 2RH" ; "gb address euston road")]
    #[test_case("shipping address: 20 Fenchurch Street, London EC3M 8AF", PiiKind::GbAddress, "20 Fenchurch Street, London EC3M 8AF" ; "gb address walkie talkie")]
    #[test_case("registered office: 1 Church Lane, Manchester M2 5AB", PiiKind::GbAddress, "1 Church Lane, Manchester M2 5AB" ; "gb address manchester")]
    #[test_case("\"home_address\":\"10 Downing Street, London SW1A 2AA\"", PiiKind::GbAddress, "10 Downing Street, London SW1A 2AA" ; "gb address json home_address")]
    #[test_case("\"billing_address\":\"221B Baker Street, London NW1 6XE\"", PiiKind::GbAddress, "221B Baker Street, London NW1 6XE" ; "gb address json billing_address")]
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
    // English keywords for FrChAddress
    #[test_case("french address: 15 rue de la Paix, 75002 Paris", PiiKind::FrChAddress, "15 rue de la Paix, 75002 Paris" ; "fr address en singular")]
    #[test_case("french addresses: 15 rue de la Paix, 75002 Paris", PiiKind::FrChAddress, "15 rue de la Paix, 75002 Paris" ; "fr address en plural")]
    #[test_case("home_address: 42 boulevard Haussmann, 75009 Paris", PiiKind::FrChAddress, "42 boulevard Haussmann, 75009 Paris" ; "fr address en snake_case home")]
    #[test_case("mailing-address: 8 chemin des Vignes, 31000 Toulouse", PiiKind::FrChAddress, "8 chemin des Vignes, 31000 Toulouse" ; "fr address en kebab-case mailing")]
    #[test_case("\"frenchAddress\":\"3 place Bellecour, 69002 Lyon\"", PiiKind::FrChAddress, "3 place Bellecour, 69002 Lyon" ; "fr address en camelCase json")]
    #[test_case("\"billing_address\":\"25 cours de l'Intendance, 33000 Bordeaux\"", PiiKind::FrChAddress, "25 cours de l'Intendance, 33000 Bordeaux" ; "fr address en json billing")]
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
    // English keywords for FrChBoitePostale
    #[test_case("french po box: 1234, 75008 Paris", PiiKind::FrChBoitePostale, "1234, 75008 Paris" ; "fr bp en singular")]
    #[test_case("french po boxes: 1234, 75008 Paris", PiiKind::FrChBoitePostale, "1234, 75008 Paris" ; "fr bp en plural")]
    #[test_case("french_po_box: 56, 69001 Lyon", PiiKind::FrChBoitePostale, "56, 69001 Lyon" ; "fr bp en snake_case")]
    #[test_case("france-po-box: 789, 97100 Basse-Terre", PiiKind::FrChBoitePostale, "789, 97100 Basse-Terre" ; "fr bp en kebab-case")]
    #[test_case("\"frenchPoBox\":\"123456, 13001 Marseille\"", PiiKind::FrChBoitePostale, "123456, 13001 Marseille" ; "fr bp en camelCase json")]
    #[test_case("\"french_post_office_box\":\"7008, 97307 Cayenne\"", PiiKind::FrChBoitePostale, "7008, 97307 Cayenne" ; "fr bp en json post office box")]
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
    // English keywords for DE/AT/CH address
    #[test_case("home address: Musterstraße 42, 10115 Berlin", PiiKind::DeAtChAddress, "Musterstraße 42, 10115 Berlin" ; "de address en home keyword")]
    #[test_case("street addresses: Friedrichstraße 43, 10117 Berlin", PiiKind::DeAtChAddress, "Friedrichstraße 43, 10117 Berlin" ; "de address en street plural")]
    #[test_case("german_address: Bahnhofstr. 1, 60311 Frankfurt", PiiKind::DeAtChAddress, "Bahnhofstr. 1, 60311 Frankfurt" ; "de address en snake_case")]
    #[test_case("austrian-address: Schillerstraße 10, 1010 Wien", PiiKind::DeAtChAddress, "Schillerstraße 10, 1010 Wien" ; "at address en kebab-case")]
    #[test_case("\"swissAddress\":\"Bahnhofstrasse 1, 8001 Zürich\"", PiiKind::DeAtChAddress, "Bahnhofstrasse 1, 8001 Zürich" ; "ch address en camelCase json")]
    #[test_case("\"mailing_address\":\"Unter den Linden 77, 10117 Berlin\"", PiiKind::DeAtChAddress, "Unter den Linden 77, 10117 Berlin" ; "de address en json mailing")]
    #[test_case("Postfach: 1234, 10557 Berlin", PiiKind::DeAtChPostfach, "1234, 10557 Berlin" ; "de postfach berlin")]
    #[test_case("PF: 56, 80331 München", PiiKind::DeAtChPostfach, "56, 80331 München" ; "de postfach short keyword")]
    #[test_case("Postfach: 123456, 01067 Dresden", PiiKind::DeAtChPostfach, "123456, 01067 Dresden" ; "de postfach 6 digits")]
    #[test_case("Postfach: 789, 5020 Salzburg", PiiKind::DeAtChPostfach, "789, 5020 Salzburg" ; "at postfach salzburg")]
    #[test_case("PF: 56, 4020 Linz", PiiKind::DeAtChPostfach, "56, 4020 Linz" ; "at postfach linz")]
    #[test_case("Postfach: 567, 6000 Luzern", PiiKind::DeAtChPostfach, "567, 6000 Luzern" ; "ch postfach luzern")]
    // English keywords for DE/AT/CH PO box
    #[test_case("po box: 1234, 10557 Berlin", PiiKind::DeAtChPostfach, "1234, 10557 Berlin" ; "de postfach en singular")]
    #[test_case("po boxes: 1234, 10557 Berlin", PiiKind::DeAtChPostfach, "1234, 10557 Berlin" ; "de postfach en plural")]
    #[test_case("po_box: 56, 80331 München", PiiKind::DeAtChPostfach, "56, 80331 München" ; "de postfach en snake_case")]
    #[test_case("post-office-box: 789, 5020 Salzburg", PiiKind::DeAtChPostfach, "789, 5020 Salzburg" ; "at postfach en kebab-case")]
    #[test_case("\"poBox\":\"567, 6000 Luzern\"", PiiKind::DeAtChPostfach, "567, 6000 Luzern" ; "ch postfach en camelCase json")]
    #[test_case("\"german_po_box\":\"123456, 01067 Dresden\"", PiiKind::DeAtChPostfach, "123456, 01067 Dresden" ; "de postfach en json german prefix")]
    #[test_case("Packstation: 109, 01099 Dresden", PiiKind::DePackstation, "109, 01099 Dresden" ; "de packstation 3 digits")]
    #[test_case("Postfiliale: 502, 10115 Berlin", PiiKind::DePackstation, "502, 10115 Berlin" ; "de postfiliale")]
    #[test_case("Paketshop: 1234, 20095 Hamburg", PiiKind::DePackstation, "1234, 20095 Hamburg" ; "de paketshop 4 digits")]
    // English keywords for DE Packstation
    #[test_case("parcel locker: 109, 01099 Dresden", PiiKind::DePackstation, "109, 01099 Dresden" ; "de packstation en singular")]
    #[test_case("parcel lockers: 502, 10115 Berlin", PiiKind::DePackstation, "502, 10115 Berlin" ; "de packstation en plural")]
    #[test_case("dhl_parcel_locker: 109, 01099 Dresden", PiiKind::DePackstation, "109, 01099 Dresden" ; "de packstation en snake_case")]
    #[test_case("dhl-parcel-locker: 502, 10115 Berlin", PiiKind::DePackstation, "502, 10115 Berlin" ; "de packstation en kebab-case")]
    #[test_case("\"parcelLocker\":\"1234, 20095 Hamburg\"", PiiKind::DePackstation, "1234, 20095 Hamburg" ; "de packstation en camelCase json")]
    #[test_case("\"german_parcel_locker\":\"109, 01099 Dresden\"", PiiKind::DePackstation, "109, 01099 Dresden" ; "de packstation en json german prefix")]
    // Address city capture must not extend into trailing prose (regression)
    #[test_case("adresse: 15 rue de la Paix, 75002 Paris. Merci de confirmer.", PiiKind::FrChAddress, "15 rue de la Paix, 75002 Paris" ; "fr address trailing prose")]
    #[test_case("BP: 1234, 75008 Paris. Veuillez vérifier.", PiiKind::FrChBoitePostale, "1234, 75008 Paris" ; "fr bp trailing prose")]
    #[test_case("Anschrift: Friedrichstraße 43, 10117 Berlin. Bitte bewahren Sie diese Bestätigung.", PiiKind::DeAtChAddress, "Friedrichstraße 43, 10117 Berlin" ; "de address trailing prose")]
    #[test_case("Lieferadresse: Unter den Linden 77, 10117 Berlin. Die Zustellung erfolgt morgen.", PiiKind::DeAtChAddress, "Unter den Linden 77, 10117 Berlin" ; "de address multi word street trailing prose")]
    #[test_case("Postfach: 1234, 10557 Berlin. Bitte verwenden Sie diese Adresse.", PiiKind::DeAtChPostfach, "1234, 10557 Berlin" ; "de postfach trailing prose")]
    #[test_case("Packstation: 109, 01099 Dresden. Ihr Paket wird dort abgelegt.", PiiKind::DePackstation, "109, 01099 Dresden" ; "de packstation trailing prose")]
    // Multi-word city names must still be captured correctly
    #[test_case("Anschrift: Rathausplatz 1, 60311 Frankfurt am Main. Bitte bestätigen.", PiiKind::DeAtChAddress, "Rathausplatz 1, 60311 Frankfurt am Main" ; "de address multi word city trailing prose")]
    // --- Netherlands-specific PII types ---
    // BSN — values verified valid via the 11-test (elfproef): 111222333 and
    // 123456782 are the commonly published Dutch test BSNs.
    #[test_case("BSN: 111222333", PiiKind::NlBsn, "111222333" ; "nl bsn keyword")]
    #[test_case("burgerservicenummer: 123456782", PiiKind::NlBsn, "123456782" ; "nl bsn long keyword")]
    #[test_case("sofinummer: 111222333", PiiKind::NlBsn, "111222333" ; "nl bsn sofinummer")]
    #[test_case("persoonsnummer: 123456782", PiiKind::NlBsn, "123456782" ; "nl bsn persoonsnummer")]
    #[test_case("BSN: 1234.56.782", PiiKind::NlBsn, "1234.56.782" ; "nl bsn dotted")]
    #[test_case("\"burgerservicenummer\":\"111222333\"", PiiKind::NlBsn, "111222333" ; "nl bsn json")]
    // English keywords for NL BSN
    #[test_case("citizen service number: 111222333", PiiKind::NlBsn, "111222333" ; "nl bsn en citizen service")]
    #[test_case("dutch social security number: 123456782", PiiKind::NlBsn, "123456782" ; "nl bsn en social security")]
    #[test_case("dutch_social_security_number: 111222333", PiiKind::NlBsn, "111222333" ; "nl bsn en snake_case")]
    #[test_case("\"dutchCitizenNumber\":\"123456782\"", PiiKind::NlBsn, "123456782" ; "nl bsn en camelCase json")]
    // Postal code
    #[test_case("postcode: 1011 AB", PiiKind::NlPostalCode, "1011 AB" ; "nl postal amsterdam")]
    #[test_case("postcode: 3062PA", PiiKind::NlPostalCode, "3062PA" ; "nl postal no space")]
    #[test_case("dutch postal code: 1011 AB", PiiKind::NlPostalCode, "1011 AB" ; "nl postal en singular")]
    #[test_case("dutch postal codes: 1011 AB", PiiKind::NlPostalCode, "1011 AB" ; "nl postal en plural")]
    #[test_case("\"dutchZipCode\":\"3062 PA\"", PiiKind::NlPostalCode, "3062 PA" ; "nl postal en camelCase json")]
    // Phone — Dutch keywords with local (0-prefix) numbers
    #[test_case("mobiel: 0612345678", PiiKind::NlPhoneNumber, "0612345678" ; "nl phone mobile local")]
    #[test_case("gsm: 0612345678", PiiKind::NlPhoneNumber, "0612345678" ; "nl phone gsm local")]
    #[test_case("vast nummer: 0201234567", PiiKind::NlPhoneNumber, "0201234567" ; "nl phone landline local")]
    // Phone — English keywords require the +31 country code
    #[test_case("phone: +31 20 1234567", PiiKind::NlPhoneNumber, "+31 20 1234567" ; "nl phone en landline plus31")]
    #[test_case("\"phone_nl\":\"+31 612345678\"", PiiKind::NlPhoneNumber, "+31 612345678" ; "nl phone en json mobile plus31")]
    // Passport / identity-card document number (alphanumeric)
    #[test_case("paspoort: BX1234567", PiiKind::NlPassportNumber, "BX1234567" ; "nl passport")]
    #[test_case("paspoortnummer: NP0A1B2C3", PiiKind::NlPassportNumber, "NP0A1B2C3" ; "nl passport alphanumeric")]
    #[test_case("dutch passport: BX1234567", PiiKind::NlPassportNumber, "BX1234567" ; "nl passport en")]
    #[test_case("\"identiteitskaart\":\"BX1234567\"", PiiKind::NlPassportNumber, "BX1234567" ; "nl passport id card json")]
    // Driving licence
    #[test_case("rijbewijs: 1234567890", PiiKind::NlDriversLicense, "1234567890" ; "nl driving licence")]
    #[test_case("rijbewijsnummer: 1234567890", PiiKind::NlDriversLicense, "1234567890" ; "nl driving licence long keyword")]
    #[test_case("dutch driving licence: 1234567890", PiiKind::NlDriversLicense, "1234567890" ; "nl driving licence en")]
    // Dutch keywords for existing international types
    #[test_case("paspoort: 123456789", PiiKind::PassportNumber, "123456789" ; "nl keyword generic passport digits")]
    #[test_case("gsm: 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "nl keyword us phone")]
    #[test_case("geboortedatum: 15-03-1990", PiiKind::DateOfBirth, "15-03-1990" ; "nl keyword dob numeric")]
    #[test_case("geboortedatum: 15 maart 1990", PiiKind::DateOfBirth, "15 maart 1990" ; "nl keyword dob month name")]
    #[test_case("geboortedatum: 15 mrt 1990", PiiKind::DateOfBirth, "15 mrt 1990" ; "nl keyword dob abbrev mrt")]
    #[test_case("geboortedatum: 3 okt 1990", PiiKind::DateOfBirth, "3 okt 1990" ; "nl keyword dob abbrev okt")]
    #[test_case("geboren op: 1985-07-22", PiiKind::DateOfBirth, "1985-07-22" ; "nl keyword dob geboren op")]
    #[test_case("locatie: 52.3702,4.8952", PiiKind::PreciseGeolocation, "52.3702,4.8952" ; "nl keyword geolocation amsterdam")]
    #[test_case("bankidentificatiecode: ABNANL2A", PiiKind::SwiftBic, "ABNANL2A" ; "nl keyword swift abn amro")]
    #[test_case("apparaatnummer: 490154203237518", PiiKind::Imei, "490154203237518" ; "nl keyword imei")]
    // Natural-language Dutch sentences — keyword followed by " is " or a space.
    #[test_case("Mijn burgerservicenummer is 111222333.", PiiKind::NlBsn, "111222333" ; "nl bsn natural sentence")]
    #[test_case("Het paspoortnummer is BX1234567 op de kaart.", PiiKind::NlPassportNumber, "BX1234567" ; "nl passport natural sentence")]
    #[test_case("Mijn postcode is 1011 AB in Amsterdam.", PiiKind::NlPostalCode, "1011 AB" ; "nl postal natural sentence")]
    #[test_case("Bel mij op mobiel 0612345678 voor vragen.", PiiKind::NlPhoneNumber, "0612345678" ; "nl phone natural sentence")]
    #[test_case("Het rijbewijsnummer is 1234567890 en blijft geldig.", PiiKind::NlDriversLicense, "1234567890" ; "nl driving licence natural sentence")]
    #[test_case("Mijn geboortedatum is 15 maart 1990 te Utrecht.", PiiKind::DateOfBirth, "15 maart 1990" ; "nl dob natural sentence")]
    // Natural-language English sentences referencing Dutch identifiers.
    #[test_case("The citizen service number is 111222333 for this file.", PiiKind::NlBsn, "111222333" ; "nl bsn natural sentence en")]
    #[test_case("Her dutch passport is BX1234567 according to records.", PiiKind::NlPassportNumber, "BX1234567" ; "nl passport natural sentence en")]
    // --- Italy-specific PII types ---
    // Codice fiscale — keyword-gated detection recovers any-case CF (the
    // keyword-less HyperscanDetector path is uppercase-only).
    #[test_case("cf: rssmra80a01h501u", PiiKind::ItCodiceFiscale, "rssmra80a01h501u" ; "it codice fiscale lowercase keyword")]
    #[test_case("codice fiscale: RSSMRA85T10A562S", PiiKind::ItCodiceFiscale, "RSSMRA85T10A562S" ; "it codice fiscale keyword uppercase")]
    #[test_case("codici fiscali: RSSMRA80A01H501U", PiiKind::ItCodiceFiscale, "RSSMRA80A01H501U" ; "it codice fiscale plural keyword")]
    // Partita IVA (00488410010 documented; 12345678903 computed; Luhn-valid)
    #[test_case("partita IVA: 00488410010", PiiKind::ItPartitaIva, "00488410010" ; "it partita iva keyword")]
    #[test_case("p.iva 12345678903", PiiKind::ItPartitaIva, "12345678903" ; "it partita iva p.iva")]
    #[test_case("piva: 00488410010", PiiKind::ItPartitaIva, "00488410010" ; "it partita iva piva")]
    #[test_case("partita IVA: IT00488410010", PiiKind::ItPartitaIva, "IT00488410010" ; "it partita iva it prefix")]
    #[test_case("partite IVA: 12345678903", PiiKind::ItPartitaIva, "12345678903" ; "it partita iva plural")]
    #[test_case("\"partita_iva\":\"00488410010\"", PiiKind::ItPartitaIva, "00488410010" ; "it partita iva json")]
    #[test_case("VAT number: IT12345678903", PiiKind::ItPartitaIva, "IT12345678903" ; "it partita iva en vat")]
    // CAP (postal code)
    #[test_case("CAP: 00184", PiiKind::ItPostalCode, "00184" ; "it cap rome")]
    #[test_case("codice postale: 20121", PiiKind::ItPostalCode, "20121" ; "it cap codice postale milan")]
    #[test_case("italian postal code: 00184", PiiKind::ItPostalCode, "00184" ; "it cap en singular")]
    #[test_case("italian postal codes: 20121", PiiKind::ItPostalCode, "20121" ; "it cap en plural")]
    #[test_case("\"cap\":\"00184\"", PiiKind::ItPostalCode, "00184" ; "it cap json")]
    // Phone — Italian keyword tests use local (non +39) numbers so the
    // +39-requiring English tuple does not double-match the same kind.
    #[test_case("telefono: 06 1234567", PiiKind::ItPhoneNumber, "06 1234567" ; "it phone landline local")]
    #[test_case("cellulare: 320 1234567", PiiKind::ItPhoneNumber, "320 1234567" ; "it phone mobile local")]
    #[test_case("telefoni: 0612345678", PiiKind::ItPhoneNumber, "0612345678" ; "it phone plural local")]
    #[test_case("numero di telefono: 3201234567", PiiKind::ItPhoneNumber, "3201234567" ; "it phone mobile compact")]
    #[test_case("phone: +39 06 1234567", PiiKind::ItPhoneNumber, "+39 06 1234567" ; "it phone en landline plus39")]
    #[test_case("\"phone_it\":\"+39 320 1234567\"", PiiKind::ItPhoneNumber, "+39 320 1234567" ; "it phone en json mobile plus39")]
    // Passport (2 letters + 7 digits)
    #[test_case("passaporto: AA1234567", PiiKind::ItPassportNumber, "AA1234567" ; "it passport")]
    #[test_case("numero di passaporto: YA9876543", PiiKind::ItPassportNumber, "YA9876543" ; "it passport long keyword")]
    #[test_case("italian passport: AA1234567", PiiKind::ItPassportNumber, "AA1234567" ; "it passport en")]
    // Driving licence (patente)
    #[test_case("patente: U1H68I903B", PiiKind::ItDriversLicense, "U1H68I903B" ; "it driving licence post 2011")]
    #[test_case("numero patente: MI5023443R", PiiKind::ItDriversLicense, "MI5023443R" ; "it driving licence older")]
    #[test_case("patente di guida: RM1234567A", PiiKind::ItDriversLicense, "RM1234567A" ; "it driving licence di guida")]
    #[test_case("italian driving licence: U1H68I903B", PiiKind::ItDriversLicense, "U1H68I903B" ; "it driving licence en")]
    // Italian keywords for existing international types
    #[test_case("passaporto: 123456789", PiiKind::PassportNumber, "123456789" ; "it keyword generic passport digits")]
    #[test_case("cellulare: 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "it keyword us phone")]
    #[test_case("data di nascita: 15/03/1990", PiiKind::DateOfBirth, "15/03/1990" ; "it keyword dob numeric")]
    #[test_case("data di nascita: 15 marzo 1990", PiiKind::DateOfBirth, "15 marzo 1990" ; "it keyword dob month name")]
    #[test_case("data di nascita: 15 mar 1990", PiiKind::DateOfBirth, "15 mar 1990" ; "it keyword dob abbrev mar")]
    #[test_case("data di nascita: 3 ott 1990", PiiKind::DateOfBirth, "3 ott 1990" ; "it keyword dob abbrev ott")]
    #[test_case("nato il: 1985-07-22", PiiKind::DateOfBirth, "1985-07-22" ; "it keyword dob nato il")]
    #[test_case("geolocalizzazione: 41.9028,12.4964", PiiKind::PreciseGeolocation, "41.9028,12.4964" ; "it keyword geolocation rome")]
    #[test_case("identificativo bancario: UNCRITMM", PiiKind::SwiftBic, "UNCRITMM" ; "it keyword swift unicredit")]
    #[test_case("identificativo dispositivo: 490154203237518", PiiKind::Imei, "490154203237518" ; "it keyword imei")]
    // Natural-language Italian sentences
    #[test_case("Il mio CAP 00184 si trova a Roma.", PiiKind::ItPostalCode, "00184" ; "it cap natural sentence")]
    #[test_case("Il numero di passaporto AA1234567 è sul documento.", PiiKind::ItPassportNumber, "AA1234567" ; "it passport natural sentence")]
    #[test_case("Chiamami al cellulare 320 1234567 per informazioni.", PiiKind::ItPhoneNumber, "320 1234567" ; "it phone natural sentence")]
    #[test_case("La data di nascita 15 marzo 1990 a Milano.", PiiKind::DateOfBirth, "15 marzo 1990" ; "it dob natural sentence")]
    // --- Spanish keyword tests ---
    // Phone (9 digits, mobile 6/7 or landline 8/9), local + +34 forms.
    #[test_case("teléfono: 612 345 678", PiiKind::EsPhoneNumber, "612 345 678" ; "es phone mobile local")]
    #[test_case("teléfonos: 912 345 678", PiiKind::EsPhoneNumber, "912 345 678" ; "es phone landline plural")]
    #[test_case("telefono: 612345678", PiiKind::EsPhoneNumber, "612345678" ; "es phone no accent compact")]
    #[test_case("número de teléfono: 712-345-678", PiiKind::EsPhoneNumber, "712-345-678" ; "es phone long keyword")]
    #[test_case("móvil: 612 345 678", PiiKind::EsPhoneNumber, "612 345 678" ; "es phone movil")]
    #[test_case("\"telefono\":\"612345678\"", PiiKind::EsPhoneNumber, "612345678" ; "es phone json")]
    #[test_case("teléfono: +34 612 345 678", PiiKind::EsPhoneNumber, "+34 612 345 678" ; "es phone plus34")]
    #[test_case("spanish phone: +34 912 345 678", PiiKind::EsPhoneNumber, "+34 912 345 678" ; "es phone en keyword plus34")]
    // Postal code (5 digits, province 01-52).
    #[test_case("código postal: 28001", PiiKind::EsPostalCode, "28001" ; "es postal madrid")]
    #[test_case("códigos postales: 08001", PiiKind::EsPostalCode, "08001" ; "es postal barcelona plural")]
    #[test_case("códigos postales: 52001", PiiKind::EsPostalCode, "52001" ; "es postal melilla")]
    #[test_case("\"codigo_postal\":\"28001\"", PiiKind::EsPostalCode, "28001" ; "es postal json snakecase")]
    #[test_case("spanish postal code: 28001", PiiKind::EsPostalCode, "28001" ; "es postal en singular")]
    #[test_case("spain postcodes: 08001", PiiKind::EsPostalCode, "08001" ; "es postal en plural")]
    // Social security (NUSS/NAF).
    #[test_case("número de afiliación: 281234567840", PiiKind::EsNuss, "281234567840" ; "es nuss afiliacion")]
    #[test_case("seguridad social: 28 1234567 84", PiiKind::EsNuss, "28 1234567 84" ; "es nuss separators")]
    #[test_case("NUSS: 281234567840", PiiKind::EsNuss, "281234567840" ; "es nuss acronym")]
    #[test_case("NAF: 28123456784", PiiKind::EsNuss, "28123456784" ; "es nuss naf eleven digits")]
    #[test_case("spanish social security number: 281234567840", PiiKind::EsNuss, "281234567840" ; "es nuss en keyword")]
    // Passport (2-3 letters + 6 digits).
    #[test_case("pasaporte: ABC123456", PiiKind::EsPassportNumber, "ABC123456" ; "es passport three letters")]
    #[test_case("pasaportes: AB123456", PiiKind::EsPassportNumber, "AB123456" ; "es passport two letters plural")]
    #[test_case("número de pasaporte: XDA123456", PiiKind::EsPassportNumber, "XDA123456" ; "es passport long keyword")]
    #[test_case("spanish passport: ABC123456", PiiKind::EsPassportNumber, "ABC123456" ; "es passport en keyword")]
    // Spanish keywords for existing international types.
    #[test_case("teléfono: 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "es keyword us phone")]
    #[test_case("pasaporte: 123456789", PiiKind::PassportNumber, "123456789" ; "es keyword generic passport digits")]
    #[test_case("fecha de nacimiento: 15/03/1990", PiiKind::DateOfBirth, "15/03/1990" ; "es keyword dob numeric")]
    #[test_case("fecha de nacimiento: 15 marzo 1990", PiiKind::DateOfBirth, "15 marzo 1990" ; "es keyword dob month name")]
    #[test_case("fecha de nacimiento: 15 mar 1990", PiiKind::DateOfBirth, "15 mar 1990" ; "es keyword dob abbrev mar")]
    #[test_case("fecha de nacimiento: 3 oct 1990", PiiKind::DateOfBirth, "3 oct 1990" ; "es keyword dob abbrev oct")]
    #[test_case("nacido el: 1985-07-22", PiiKind::DateOfBirth, "1985-07-22" ; "es keyword dob nacido el")]
    #[test_case("geolocalización: 40.4168,-3.7038", PiiKind::PreciseGeolocation, "40.4168,-3.7038" ; "es keyword geolocation madrid")]
    #[test_case("identificador bancario: BBVAESMM", PiiKind::SwiftBic, "BBVAESMM" ; "es keyword swift bbva")]
    #[test_case("identificador del dispositivo: 490154203237518", PiiKind::Imei, "490154203237518" ; "es keyword imei")]
    // Natural-language Spanish sentences (value adjacent to keyword — no copula).
    #[test_case("Mi código postal 28001 está en Madrid.", PiiKind::EsPostalCode, "28001" ; "es postal natural sentence")]
    #[test_case("El pasaporte ABC123456 es válido.", PiiKind::EsPassportNumber, "ABC123456" ; "es passport natural sentence")]
    #[test_case("Llámame al teléfono 612 345 678 por favor.", PiiKind::EsPhoneNumber, "612 345 678" ; "es phone natural sentence")]
    #[test_case("La fecha de nacimiento 15 marzo 1990 en Sevilla.", PiiKind::DateOfBirth, "15 marzo 1990" ; "es dob natural sentence")]
    // --- Poland (Language::Pl + country-prefixed English) ---
    // PESEL — 44051401359 is the canonical Wikipedia example.
    #[test_case("PESEL: 44051401359", PiiKind::PlPesel, "44051401359" ; "pl pesel keyword")]
    #[test_case("numer PESEL: 02070803628", PiiKind::PlPesel, "02070803628" ; "pl pesel long keyword")]
    #[test_case("numery PESEL: 44051401359", PiiKind::PlPesel, "44051401359" ; "pl pesel plural keyword")]
    #[test_case("pesel_number: 44051401359", PiiKind::PlPesel, "44051401359" ; "pl pesel snakecase")]
    #[test_case("peselNumber: 44051401359", PiiKind::PlPesel, "44051401359" ; "pl pesel camelcase")]
    #[test_case("pesel-number: 44051401359", PiiKind::PlPesel, "44051401359" ; "pl pesel kebab")]
    #[test_case(r#""pesel":"44051401359""#, PiiKind::PlPesel, "44051401359" ; "pl pesel json")]
    #[test_case("polish national id number: 44051401359", PiiKind::PlPesel, "44051401359" ; "pl pesel en keyword")]
    // NIP — 7740001454 (PKN Orlen), 5250007738 (PKO BP): real published NIPs.
    #[test_case("NIP: 7740001454", PiiKind::PlNip, "7740001454" ; "pl nip keyword")]
    #[test_case("NIP: 774-000-14-54", PiiKind::PlNip, "774-000-14-54" ; "pl nip separators 3-3-2-2")]
    #[test_case("nipem: 5250007738", PiiKind::PlNip, "5250007738" ; "pl nip declined")]
    #[test_case("numer identyfikacji podatkowej: 5250007738", PiiKind::PlNip, "5250007738" ; "pl nip long keyword")]
    #[test_case("nip_number: 7740001454", PiiKind::PlNip, "7740001454" ; "pl nip snakecase")]
    #[test_case(r#""nip":"7740001454""#, PiiKind::PlNip, "7740001454" ; "pl nip json")]
    #[test_case("polish tax id: 7740001454", PiiKind::PlNip, "7740001454" ; "pl nip en tax id")]
    #[test_case("pl vat number: 7740001454", PiiKind::PlNip, "7740001454" ; "pl nip en vat number")]
    // REGON — 610188201 (PKN Orlen), 016298263 (PKO BP): real published REGONs.
    #[test_case("REGON: 610188201", PiiKind::PlRegon, "610188201" ; "pl regon keyword")]
    #[test_case("REGON: 61018820100010", PiiKind::PlRegon, "61018820100010" ; "pl regon fourteen digits")]
    #[test_case("numery REGON: 016298263", PiiKind::PlRegon, "016298263" ; "pl regon plural keyword")]
    #[test_case("regonu: 610188201", PiiKind::PlRegon, "610188201" ; "pl regon declined")]
    #[test_case("regon_number: 610188201", PiiKind::PlRegon, "610188201" ; "pl regon snakecase")]
    #[test_case(r#""regon":"016298263""#, PiiKind::PlRegon, "016298263" ; "pl regon json")]
    #[test_case("poland business registry number: 610188201", PiiKind::PlRegon, "610188201" ; "pl regon en keyword")]
    // ID card — ABS123456 is the worked example from romek.info.
    #[test_case("dowód osobisty: ABS123456", PiiKind::PlIdCard, "ABS123456" ; "pl id card keyword")]
    #[test_case("dowodu osobistego: ZZC445678", PiiKind::PlIdCard, "ZZC445678" ; "pl id card genitive")]
    #[test_case("dowody osobiste: ABS123456", PiiKind::PlIdCard, "ABS123456" ; "pl id card plural")]
    #[test_case("seria i numer dowodu: ABS 123456", PiiKind::PlIdCard, "ABS 123456" ; "pl id card series and number")]
    #[test_case("dowod_osobisty: ABS123456", PiiKind::PlIdCard, "ABS123456" ; "pl id card snakecase no diacritic")]
    #[test_case(r#""dowod":"AAA000000""#, PiiKind::PlIdCard, "AAA000000" ; "pl id card json")]
    #[test_case("polish id card: ABS123456", PiiKind::PlIdCard, "ABS123456" ; "pl id card en keyword")]
    // Passport — CC7999486 is the worked example from romek.info.
    #[test_case("paszport: CC7999486", PiiKind::PlPassportNumber, "CC7999486" ; "pl passport keyword")]
    #[test_case("numer paszportu: EH3222222", PiiKind::PlPassportNumber, "EH3222222" ; "pl passport long keyword")]
    #[test_case("paszporty: CC7999486", PiiKind::PlPassportNumber, "CC7999486" ; "pl passport plural")]
    #[test_case(r#""paszport":"CC7999486""#, PiiKind::PlPassportNumber, "CC7999486" ; "pl passport json")]
    #[test_case("polish passport: CC 7999486", PiiKind::PlPassportNumber, "CC 7999486" ; "pl passport en keyword with space")]
    // Phone — 9-digit national numbers, optional +48.
    #[test_case("telefon: 601 234 567", PiiKind::PlPhoneNumber, "601 234 567" ; "pl phone mobile")]
    #[test_case("komórka: 512345678", PiiKind::PlPhoneNumber, "512345678" ; "pl phone komorka compact")]
    #[test_case("numer telefonu: +48 601 234 567", PiiKind::PlPhoneNumber, "+48 601 234 567" ; "pl phone long keyword plus48")]
    #[test_case("telefony: 221234567", PiiKind::PlPhoneNumber, "221234567" ; "pl phone plural landline")]
    #[test_case(r#""telefon":"601234567""#, PiiKind::PlPhoneNumber, "601234567" ; "pl phone json")]
    #[test_case("polish phone: +48 512 345 678", PiiKind::PlPhoneNumber, "+48 512 345 678" ; "pl phone en keyword plus48")]
    // Postal code — dd-ddd.
    #[test_case("kod pocztowy: 00-950", PiiKind::PlPostalCode, "00-950" ; "pl postal warsaw")]
    #[test_case("kody pocztowe: 30-024", PiiKind::PlPostalCode, "30-024" ; "pl postal plural krakow")]
    #[test_case("kod_pocztowy: 00-950", PiiKind::PlPostalCode, "00-950" ; "pl postal snakecase")]
    #[test_case(r#""kod_pocztowy":"00-950""#, PiiKind::PlPostalCode, "00-950" ; "pl postal json")]
    #[test_case("poland postal code: 00-950", PiiKind::PlPostalCode, "00-950" ; "pl postal en keyword")]
    // Driving licence — 5/2/4-or-7 digits.
    #[test_case("prawo jazdy: 12345/67/8901", PiiKind::PlDriversLicense, "12345/67/8901" ; "pl driving licence")]
    #[test_case("prawa jazdy: 12345/67/8901234", PiiKind::PlDriversLicense, "12345/67/8901234" ; "pl driving licence genitive seven digit tail")]
    #[test_case(r#""prawo_jazdy":"12345/67/8901""#, PiiKind::PlDriversLicense, "12345/67/8901" ; "pl driving licence json")]
    #[test_case("polish driving licence: 12345/67/8901", PiiKind::PlDriversLicense, "12345/67/8901" ; "pl driving licence en keyword")]
    // Polish keywords for international types
    #[test_case("telefon: 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "pl keyword us phone")]
    #[test_case("paszport: 123456789", PiiKind::PassportNumber, "123456789" ; "pl keyword generic passport")]
    #[test_case("data urodzenia: 15.05.1985", PiiKind::DateOfBirth, "15.05.1985" ; "pl keyword dob numeric")]
    #[test_case("data urodzenia: 15 maja 1985", PiiKind::DateOfBirth, "15 maja 1985" ; "pl keyword dob month name")]
    #[test_case("urodzony: 3 października 1990", PiiKind::DateOfBirth, "3 października 1990" ; "pl keyword dob non ascii month")]
    #[test_case("data urodzenia: 3 paź 1990", PiiKind::DateOfBirth, "3 paź 1990" ; "pl keyword dob abbrev paz")]
    #[test_case("data urodzenia: 15 wrz 1985", PiiKind::DateOfBirth, "15 wrz 1985" ; "pl keyword dob abbrev wrz")]
    #[test_case("współrzędne: 52.2297,21.0122", PiiKind::PreciseGeolocation, "52.2297,21.0122" ; "pl keyword geolocation warsaw")]
    #[test_case("identyfikator bankowy: DEUTDEFF", PiiKind::SwiftBic, "DEUTDEFF" ; "pl keyword swift")]
    #[test_case("identyfikator urządzenia: 490154203237518", PiiKind::Imei, "490154203237518" ; "pl keyword imei")]
    // Natural-language Polish sentences (value adjacent to keyword — no copula).
    #[test_case("Mój numer PESEL 44051401359 jest poufny.", PiiKind::PlPesel, "44051401359" ; "pl pesel natural sentence")]
    #[test_case("Zgubiłem dowód osobisty ABS123456 wczoraj.", PiiKind::PlIdCard, "ABS123456" ; "pl id card natural sentence")]
    #[test_case("Zadzwoń na telefon 601 234 567 po południu.", PiiKind::PlPhoneNumber, "601 234 567" ; "pl phone natural sentence")]
    // --- Plural keyword forms ---
    // English plurals (single -s suffix on the head noun)
    #[test_case("phone_numbers: 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "en plural phone_numbers snakecase")]
    #[test_case("phoneNumbers: 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "en plural phoneNumbers camelcase")]
    #[test_case(r#""phoneNumbers": "555-123-4567""#, PiiKind::UsPhoneNumber, "555-123-4567" ; "en plural phoneNumbers json")]
    #[test_case("mobile phones: 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "en plural mobile phones")]
    #[test_case("passport_numbers: A12345678", PiiKind::UsPassportNew, "A12345678" ; "en plural passport_numbers")]
    #[test_case("passports: A12345678", PiiKind::UsPassportNew, "A12345678" ; "en plural passports")]
    #[test_case("tax_file_numbers: 123 456 782", PiiKind::AuTfn, "123 456 782" ; "en plural tax_file_numbers")]
    #[test_case("routing numbers: 021000021", PiiKind::UsAbaRouting, "021000021" ; "en plural routing numbers")]
    #[test_case("driver's licenses: B1234568", PiiKind::UsDriversLicense, "B1234568" ; "en plural drivers licenses")]
    #[test_case("nz driving licences: AB123456", PiiKind::NzDriverLicence, "AB123456" ; "en plural nz driving licences")]
    #[test_case("home addresses: 10 Downing Street, London, SW1A 2AA", PiiKind::GbAddress, "10 Downing Street, London, SW1A 2AA" ; "en plural home addresses")]
    #[test_case("full names: Jean-Pierre Müller", PiiKind::PersonName, "Jean-Pierre Müller" ; "en plural full names")]
    // French plurals (single -s suffix on the head noun)
    #[test_case("numéros de téléphone: 06 12 34 56 78", PiiKind::FrPhoneNumber, "06 12 34 56 78" ; "fr plural numeros de telephone")]
    #[test_case("numeros_de_telephone: 06 12 34 56 78", PiiKind::FrPhoneNumber, "06 12 34 56 78" ; "fr plural numeros_de_telephone snakecase")]
    #[test_case("téléphones: 06 12 34 56 78", PiiKind::FrPhoneNumber, "06 12 34 56 78" ; "fr plural telephones")]
    #[test_case("numéros de passeport: 05AB12345", PiiKind::FrPassportNumber, "05AB12345" ; "fr plural numeros de passeport")]
    #[test_case("passeports français: 05AB12345", PiiKind::FrPassportNumber, "05AB12345" ; "fr plural passeports francais")]
    #[test_case("noms de famille: Beaumont", PiiKind::PersonName, "Beaumont" ; "fr plural noms de famille")]
    #[test_case("prénoms: François", PiiKind::PersonName, "François" ; "fr plural prenoms")]
    // German plurals (varies per word: -n, -en, -e)
    #[test_case("Telefonnummern: +49 30 12345678", PiiKind::DePhoneNumber, "+49 30 12345678" ; "de plural Telefonnummern")]
    #[test_case("Rufnummern: +49 30 12345678", PiiKind::DePhoneNumber, "+49 30 12345678" ; "de plural Rufnummern")]
    #[test_case("Handynummern: +49 151 12345678", PiiKind::DePhoneNumber, "+49 151 12345678" ; "de plural Handynummern")]
    #[test_case("Personalausweise: L01X00T471", PiiKind::DePersonalausweis, "L01X00T471" ; "de plural Personalausweise")]
    #[test_case("Steueridentifikationsnummern: 86095742719", PiiKind::DeSteuerId, "86095742719" ; "de plural Steueridentifikationsnummern")]
    #[test_case("AHV-Nummern: 756.1234.5678.97", PiiKind::ChAhv, "756.1234.5678.97" ; "ch plural AHV-Nummern")]
    #[test_case("Anschriften: Friedrichstraße 43, 10117 Berlin", PiiKind::DeAtChAddress, "Friedrichstraße 43, 10117 Berlin" ; "de plural Anschriften")]
    #[test_case("Wohnadressen: Musterstraße 42, 10115 Berlin", PiiKind::DeAtChAddress, "Musterstraße 42, 10115 Berlin" ; "de plural Wohnadressen")]
    #[test_case("Lieferadressen: Unter den Linden 77, 10117 Berlin", PiiKind::DeAtChAddress, "Unter den Linden 77, 10117 Berlin" ; "de plural Lieferadressen")]
    #[test_case("Postleitzahlen: 10115", PiiKind::DePostalCode, "10115" ; "de plural Postleitzahlen")]
    #[test_case("Standorte: 48.1351,11.5820", PiiKind::PreciseGeolocation, "48.1351,11.5820" ; "de plural Standorte")]
    // English plurals — separator variants (JSON / URL query / kebab / URL-encoded / HTML entity / equals)
    #[test_case(r#""phone_numbers": "555-123-4567""#, PiiKind::UsPhoneNumber, "555-123-4567" ; "en plural phone_numbers json snakecase")]
    #[test_case("phone-numbers: 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "en plural phone-numbers kebab yaml")]
    #[test_case("phone_numbers=555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "en plural phone_numbers url query")]
    #[test_case("phone_numbers%3A%20555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "en plural phone_numbers url-encoded")]
    #[test_case("phone_numbers&#58; 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "en plural phone_numbers html entity")]
    #[test_case("user[phone_numbers]=555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "en plural phone_numbers url bracket")]
    #[test_case(r#""passport_numbers":"A12345678""#, PiiKind::UsPassportNew, "A12345678" ; "en plural passport_numbers tight json")]
    #[test_case("tax-file-numbers=123 456 782", PiiKind::AuTfn, "123 456 782" ; "en plural tax-file-numbers kebab equals")]
    #[test_case("routing_numbers%3A 021000021", PiiKind::UsAbaRouting, "021000021" ; "en plural routing_numbers url-encoded")]
    // French plurals — separator variants (JSON / URL / equals)
    #[test_case(r#""téléphones": "06 12 34 56 78""#, PiiKind::FrPhoneNumber, "06 12 34 56 78" ; "fr plural telephones json")]
    #[test_case(r#""numéros_de_téléphone": "06 12 34 56 78""#, PiiKind::FrPhoneNumber, "06 12 34 56 78" ; "fr plural numeros_de_telephone json")]
    #[test_case("numéros-de-téléphone: 06 12 34 56 78", PiiKind::FrPhoneNumber, "06 12 34 56 78" ; "fr plural numeros-de-telephone kebab")]
    #[test_case("téléphones=06 12 34 56 78", PiiKind::FrPhoneNumber, "06 12 34 56 78" ; "fr plural telephones equals")]
    #[test_case(r#""passeports_français":"05AB12345""#, PiiKind::FrPassportNumber, "05AB12345" ; "fr plural passeports_francais json")]
    // German plurals — separator variants (JSON / URL / equals / kebab)
    #[test_case(r#""Telefonnummern": "+49 30 12345678""#, PiiKind::DePhoneNumber, "+49 30 12345678" ; "de plural Telefonnummern json")]
    #[test_case("Telefonnummern=+49 30 12345678", PiiKind::DePhoneNumber, "+49 30 12345678" ; "de plural Telefonnummern equals")]
    #[test_case(r#""Handynummern":"+49 151 12345678""#, PiiKind::DePhoneNumber, "+49 151 12345678" ; "de plural Handynummern tight json")]
    #[test_case("Handynummern%3A%20+49 151 12345678", PiiKind::DePhoneNumber, "+49 151 12345678" ; "de plural Handynummern url-encoded")]
    #[test_case(r#""Postleitzahlen": "10115""#, PiiKind::DePostalCode, "10115" ; "de plural Postleitzahlen json")]
    #[test_case(r#""Anschriften":"Friedrichstraße 43, 10117 Berlin""#, PiiKind::DeAtChAddress, "Friedrichstraße 43, 10117 Berlin" ; "de plural Anschriften tight json")]
    // Language-specific connector words between keyword and value (single- and
    // multi-word). See `Language::connector_words`. The English `is`/`are` cover
    // Dutch too; every other language's copula and "number" phrases were inert
    // before connector expansion.
    #[test_case("british passports are 123456789", PiiKind::GbZaPassportNumber, "123456789" ; "en connector are")]
    #[test_case("passport with number 123456789", PiiKind::PassportNumber, "123456789" ; "en connector with number")]
    #[test_case("le téléphone est 06 12 34 56 78", PiiKind::FrPhoneNumber, "06 12 34 56 78" ; "fr connector est")]
    #[test_case("carte d'identité numéro 123456789012", PiiKind::FrCni, "123456789012" ; "fr connector numero")]
    #[test_case("carte d'identité portant le numéro 123456789012", PiiKind::FrCni, "123456789012" ; "fr connector portant le numero")]
    #[test_case("Reisepass ist C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de connector ist")]
    #[test_case("Reisepass nummer C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de connector nummer")]
    #[test_case("Personalausweis mit der Nummer T220001293", PiiKind::DePersonalausweis, "T220001293" ; "de connector mit der nummer")]
    #[test_case("paspoort met nummer BX1234567", PiiKind::NlPassportNumber, "BX1234567" ; "nl connector met nummer")]
    #[test_case("il passaporto è YA1234567", PiiKind::ItPassportNumber, "YA1234567" ; "it connector e")]
    #[test_case("passaporto con numero YA1234567", PiiKind::ItPassportNumber, "YA1234567" ; "it connector con numero")]
    #[test_case("passaporto recante il numero YA1234567", PiiKind::ItPassportNumber, "YA1234567" ; "it connector recante il numero")]
    #[test_case("pasaporte con número AAA123456", PiiKind::EsPassportNumber, "AAA123456" ; "es connector con numero")]
    #[test_case("pasaporte con el número AAA123456", PiiKind::EsPassportNumber, "AAA123456" ; "es connector con el numero")]
    #[test_case("pasaporte número AAA123456", PiiKind::EsPassportNumber, "AAA123456" ; "es connector numero")]
    #[test_case("legitymujący się dowodem osobistym o numerze ABS123456", PiiKind::PlIdCard, "ABS123456" ; "pl connector o numerze id card")]
    #[test_case("legitymujący się paszportem o numerze CC7999486", PiiKind::PlPassportNumber, "CC7999486" ; "pl connector o numerze passport")]
    #[test_case("legitymujący się prawem jazdy o numerze 12345/12/2024", PiiKind::PlDriversLicense, "12345/12/2024" ; "pl connector o numerze drivers license")]
    #[test_case("dowód osobisty nr ABS123456", PiiKind::PlIdCard, "ABS123456" ; "pl connector nr")]
    #[test_case("paszport numer CC7999486", PiiKind::PlPassportNumber, "CC7999486" ; "pl connector numer")]
    #[test_case("dowód osobisty seria i numer ABS123456", PiiKind::PlIdCard, "ABS123456" ; "pl connector seria i numer")]
    #[test_case("jego dowód osobisty to ABS123456", PiiKind::PlIdCard, "ABS123456" ; "pl connector to")]
    #[test_case("jego paszport to CC7999486", PiiKind::PlPassportNumber, "CC7999486" ; "pl connector to passport")]
    // Recommend-tier connectors: past copulas, number abbreviations (n°, nr.,
    // n., nº, núm.), and colloquial copulas common in official + everyday text.
    #[test_case("british passport was 123456789", PiiKind::GbZaPassportNumber, "123456789" ; "en connector was")]
    #[test_case("passport numbered 123456789", PiiKind::PassportNumber, "123456789" ; "en connector numbered")]
    #[test_case("carte d'identité n° 123456789012", PiiKind::FrCni, "123456789012" ; "fr connector n degree")]
    #[test_case("le téléphone était 06 12 34 56 78", PiiKind::FrPhoneNumber, "06 12 34 56 78" ; "fr connector etait")]
    #[test_case("le téléphone c'est 06 12 34 56 78", PiiKind::FrPhoneNumber, "06 12 34 56 78" ; "fr connector cest")]
    #[test_case("Reisepass nr. C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de connector nr abbrev")]
    #[test_case("Reisepass war C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de connector war")]
    #[test_case("paspoort nr. BX1234567", PiiKind::NlPassportNumber, "BX1234567" ; "nl connector nr abbrev")]
    #[test_case("paspoort was BX1234567", PiiKind::NlPassportNumber, "BX1234567" ; "nl connector was")]
    #[test_case("passaporto n. YA1234567", PiiKind::ItPassportNumber, "YA1234567" ; "it connector n abbrev")]
    #[test_case("passaporto n° YA1234567", PiiKind::ItPassportNumber, "YA1234567" ; "it connector n degree")]
    #[test_case("il passaporto era YA1234567", PiiKind::ItPassportNumber, "YA1234567" ; "it connector era")]
    #[test_case("pasaporte nº AAA123456", PiiKind::EsPassportNumber, "AAA123456" ; "es connector n ordinal")]
    #[test_case("pasaporte núm. AAA123456", PiiKind::EsPassportNumber, "AAA123456" ; "es connector num abbrev")]
    #[test_case("el pasaporte es el AAA123456", PiiKind::EsPassportNumber, "AAA123456" ; "es connector es el")]
    #[test_case("dowód osobisty pod numerem ABS123456", PiiKind::PlIdCard, "ABS123456" ; "pl connector pod numerem")]
    // Optional longer-phrase connectors: "bearing/under the number" and the
    // legal/official "under the number" forms, plus extra past copulas.
    #[test_case("passport bearing the number 123456789", PiiKind::PassportNumber, "123456789" ; "en connector bearing the number")]
    #[test_case("passport under number 123456789", PiiKind::PassportNumber, "123456789" ; "en connector under number")]
    #[test_case("passport with no. 123456789", PiiKind::PassportNumber, "123456789" ; "en connector with no abbrev")]
    #[test_case("carte d'identité sous le numéro 123456789012", PiiKind::FrCni, "123456789012" ; "fr connector sous le numero")]
    #[test_case("carte d'identité sous le n° 123456789012", PiiKind::FrCni, "123456789012" ; "fr connector sous le n degree")]
    #[test_case("Reisepass unter der Nummer C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de connector unter der nummer")]
    #[test_case("Reisepass trägt die Nummer C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de connector tragt die nummer")]
    #[test_case("Reisepass mit der Nr. C01X00T47", PiiKind::DePassportNumber, "C01X00T47" ; "de connector mit der nr")]
    #[test_case("paspoort met het nummer BX1234567", PiiKind::NlPassportNumber, "BX1234567" ; "nl connector met het nummer")]
    #[test_case("paspoort onder nummer BX1234567", PiiKind::NlPassportNumber, "BX1234567" ; "nl connector onder nummer")]
    #[test_case("paspoort met kenmerk BX1234567", PiiKind::NlPassportNumber, "BX1234567" ; "nl connector met kenmerk")]
    #[test_case("passaporto con il numero YA1234567", PiiKind::ItPassportNumber, "YA1234567" ; "it connector con il numero")]
    #[test_case("pasaporte bajo el número AAA123456", PiiKind::EsPassportNumber, "AAA123456" ; "es connector bajo el numero")]
    #[test_case("el pasaporte era AAA123456", PiiKind::EsPassportNumber, "AAA123456" ; "es connector era")]
    #[test_case("dowód osobisty oznaczony numerem ABS123456", PiiKind::PlIdCard, "ABS123456" ; "pl connector oznaczony numerem")]
    #[test_case("dowód osobisty noszący numer ABS123456", PiiKind::PlIdCard, "ABS123456" ; "pl connector noszacy numer")]
    #[test_case("jego paszport był CC7999486", PiiKind::PlPassportNumber, "CC7999486" ; "pl connector byl")]
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
    #[test_case("french social security number: 1 85 05 78 006 084 99", PiiKind::FrNir ; "fr nir en keyword bad checksum")]
    #[test_case("code postal: 00100", PiiKind::FrPostalCode ; "fr postal below range")]
    #[test_case("code postal: 99999", PiiKind::FrPostalCode ; "fr postal above range")]
    #[test_case("french postal code: 00100", PiiKind::FrPostalCode ; "fr postal en keyword below range")]
    #[test_case("numéro fiscal: 4123456789012", PiiKind::FrNif ; "fr nif invalid first digit")]
    #[test_case("french tax id: 4123456789012", PiiKind::FrNif ; "fr nif en keyword invalid first digit")]
    #[test_case("SIRET: 73282932000075", PiiKind::FrSiret ; "fr siret bad luhn")]
    #[test_case("SIRET: 77567041700052", PiiKind::FrSiret ; "fr siret lvmh off by one")]
    #[test_case("french establishment number: 73282932000075", PiiKind::FrSiret ; "fr siret en keyword bad luhn")]
    #[test_case("SIREN: 732829321", PiiKind::FrSiren ; "fr siren bad luhn")]
    #[test_case("SIREN: 775670418", PiiKind::FrSiren ; "fr siren lvmh off by one")]
    #[test_case("french company number: 732829321", PiiKind::FrSiren ; "fr siren en keyword bad luhn")]
    // Germany/Austria/Switzerland
    #[test_case("Steuer-ID: 65929970480", PiiKind::DeSteuerId ; "de steuer id bad checksum")]
    #[test_case("Steuer-ID: 26954371820", PiiKind::DeSteuerId ; "de steuer id bad checksum 2")]
    #[test_case("german tax id: 65929970480", PiiKind::DeSteuerId ; "de steuer id en keyword bad checksum")]
    #[test_case("Reisepassnummer: 123456789", PiiKind::DePassportNumber ; "de passport no letter")]
    #[test_case("Personalausweis: L01X00T470", PiiKind::DePersonalausweis ; "de personalausweis bad check")]
    #[test_case("Personalausweis: T220001290", PiiKind::DePersonalausweis ; "de personalausweis bad check 2")]
    #[test_case("national id card: L01X00T470", PiiKind::DePersonalausweis ; "de personalausweis en keyword bad check")]
    #[test_case("PLZ: 00100", PiiKind::DePostalCode ; "de postal below range")]
    #[test_case("PLZ: 00000", PiiKind::DePostalCode ; "de postal all zeros")]
    #[test_case("german postal code: 00100", PiiKind::DePostalCode ; "de postal en keyword below range")]
    #[test_case("SVNR: 1230150185", PiiKind::AtSvnr ; "at svnr bad checksum")]
    #[test_case("SVNR: 1238010180", PiiKind::AtSvnr ; "at svnr check digit off by one")]
    #[test_case("\"atSvnr\":\"1230150185\"", PiiKind::AtSvnr ; "at svnr en keyword bad checksum")]
    #[test_case("PLZ: 1000", PiiKind::AtPostalCode ; "at postal below range")]
    #[test_case("PLZ: 1009", PiiKind::AtPostalCode ; "at postal just below range")]
    #[test_case("austrian postal code: 1009", PiiKind::AtPostalCode ; "at postal en keyword below range")]
    #[test_case("AHV-Nummer: 7561234567890", PiiKind::ChAhv ; "ch ahv bad checksum")]
    #[test_case("AHV-Nummer: 756.9217.0769.80", PiiKind::ChAhv ; "ch ahv bad checksum real prefix")]
    #[test_case("AHV-Nummer: 1231234567897", PiiKind::ChAhv ; "ch ahv wrong prefix")]
    #[test_case("swiss social security number: 7561234567890", PiiKind::ChAhv ; "ch ahv en keyword bad checksum")]
    #[test_case("PLZ: 9999", PiiKind::ChPostalCode ; "ch postal above range")]
    #[test_case("PLZ: 0999", PiiKind::ChPostalCode ; "ch postal below range")]
    #[test_case("swiss postal code: 9999", PiiKind::ChPostalCode ; "ch postal en keyword above range")]
    // PersonName — rejects non-name values
    #[test_case("full name: 12345", PiiKind::PersonName ; "person name digits only")]
    #[test_case("first name: a", PiiKind::PersonName ; "person name single lowercase")]
    // Lowercase prose after a PersonName keyword must NOT be captured as a
    // name. Prevents over-capture of phrases like "account holder moved from
    // NZ Legacy passport".
    #[test_case("account holder moved from NZ Legacy passport record", PiiKind::PersonName ; "person name lowercase prose after keyword")]
    #[test_case("recipient name: moved to a new address yesterday", PiiKind::PersonName ; "person name lowercase prose recipient")]
    #[test_case("customer name: please update the records soon", PiiKind::PersonName ; "person name lowercase prose customer")]
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
    #[test_case("postal code: 0000", PiiKind::UsZaPostalCode ; "za postal code zero")]
    #[test_case("australian driver's licence: 12345", PiiKind::AuDriversLicense ; "au dl too short")]
    #[test_case("australian driver's licence: 0000000", PiiKind::AuDriversLicense ; "au dl all zeros")]
    #[test_case("ABN: 51824753557", PiiKind::AuAbn ; "au abn bad checksum")]
    #[test_case("ABN: 1234567890", PiiKind::AuAbn ; "au abn 10 digits")]
    // Netherlands — keyword present but value fails validation
    #[test_case("BSN: 111222334", PiiKind::NlBsn ; "nl bsn bad checksum")]
    #[test_case("burgerservicenummer: 123456783", PiiKind::NlBsn ; "nl bsn bad checksum 2")]
    #[test_case("BSN: 000000000", PiiKind::NlBsn ; "nl bsn all zeros")]
    #[test_case("postcode: 0123 AB", PiiKind::NlPostalCode ; "nl postal leading zero")]
    #[test_case("paspoort: 123456789", PiiKind::NlPassportNumber ; "nl passport pure digits is bsn")]
    #[test_case("paspoort: ABCDEFGHI", PiiKind::NlPassportNumber ; "nl passport all letters")]
    #[test_case("rijbewijs: 0000000000", PiiKind::NlDriversLicense ; "nl dl all zeros")]
    // Italy — keyword present but value fails validation
    #[test_case("partita IVA: 00488410011", PiiKind::ItPartitaIva ; "it partita iva bad checksum")]
    #[test_case("partita IVA: 1234567890", PiiKind::ItPartitaIva ; "it partita iva ten digits")]
    #[test_case("CAP: 00009", PiiKind::ItPostalCode ; "it cap below range")]
    #[test_case("CAP: 99999", PiiKind::ItPostalCode ; "it cap above range")]
    #[test_case("passaporto: 1234567AA", PiiKind::ItPassportNumber ; "it passport digits then letters")]
    #[test_case("patente: ABCDEFGHIJ", PiiKind::ItDriversLicense ; "it dl no digits")]
    #[test_case("código postal: 53001", PiiKind::EsPostalCode ; "es postal province above 52")]
    #[test_case("código postal: 00999", PiiKind::EsPostalCode ; "es postal province 00")]
    #[test_case("teléfono: 123 456 789", PiiKind::EsPhoneNumber ; "es phone bad leading digit")]
    #[test_case("número de afiliación: 671234567812", PiiKind::EsNuss ; "es nuss province above 66")]
    #[test_case("NUSS: 2812345678", PiiKind::EsNuss ; "es nuss ten digits")]
    #[test_case("pasaporte: A1234567", PiiKind::EsPassportNumber ; "es passport one letter seven digits")]
    // Poland — keyword present but value fails validation
    #[test_case("PESEL: 44051401358", PiiKind::PlPesel ; "pl pesel bad check digit")]
    #[test_case("PESEL: 44131401350", PiiKind::PlPesel ; "pl pesel month 13 valid checksum")]
    #[test_case("PESEL: 44053201353", PiiKind::PlPesel ; "pl pesel day 32 valid checksum")]
    #[test_case("NIP: 7740001455", PiiKind::PlNip ; "pl nip bad check digit")]
    #[test_case("NIP: 1234567890", PiiKind::PlNip ; "pl nip remainder ten")]
    #[test_case("REGON: 610188202", PiiKind::PlRegon ; "pl regon bad check digit")]
    #[test_case("REGON: 61018820100011", PiiKind::PlRegon ; "pl regon bad fourteenth digit")]
    #[test_case("dowód osobisty: ABS123457", PiiKind::PlIdCard ; "pl id card bad check digit")]
    #[test_case("paszport: CC7999487", PiiKind::PlPassportNumber ; "pl passport bad check digit")]
    #[test_case("telefon: 012 345 678", PiiKind::PlPhoneNumber ; "pl phone leading zero")]
    #[test_case("kod pocztowy: 00950", PiiKind::PlPostalCode ; "pl postal no dash")]
    #[test_case("prawo jazdy: 12345/67/89012", PiiKind::PlDriversLicense ; "pl dl five digit tail")]
    fn rejects_invalid_with_keyword(input: &str, kind: PiiKind) {
        let detector = &*DETECTOR;
        let matches = detector.mark_piis(input);
        assert!(
            matches.iter().all(|m| m.kind != kind),
            "should reject {kind:?} in: {input}"
        );
    }

    // --- No detection without keyword ---

    #[test_case("call 555-123-4567 today", PiiKind::UsPhoneNumber ; "phone no keyword")]
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
    #[test_case("0001", PiiKind::UsZaPostalCode ; "za postal no keyword")]
    #[test_case("12345678", PiiKind::AuDriversLicense ; "au dl no keyword")]
    #[test_case("51824753556", PiiKind::AuAbn ; "au abn no keyword")]
    // Netherlands — value present but no keyword
    #[test_case("111222333", PiiKind::NlBsn ; "nl bsn no keyword")]
    #[test_case("1011 AB", PiiKind::NlPostalCode ; "nl postal no keyword")]
    #[test_case("0612345678", PiiKind::NlPhoneNumber ; "nl phone no keyword")]
    #[test_case("BX1234567", PiiKind::NlPassportNumber ; "nl passport no keyword")]
    #[test_case("1234567890", PiiKind::NlDriversLicense ; "nl dl no keyword")]
    // Italy — value present but no keyword
    #[test_case("rssmra80a01h501u", PiiKind::ItCodiceFiscale ; "it codice fiscale lowercase no keyword")]
    #[test_case("00488410010", PiiKind::ItPartitaIva ; "it partita iva no keyword")]
    #[test_case("00184", PiiKind::ItPostalCode ; "it cap no keyword")]
    #[test_case("320 1234567", PiiKind::ItPhoneNumber ; "it phone no keyword")]
    #[test_case("AA1234567", PiiKind::ItPassportNumber ; "it passport no keyword")]
    #[test_case("U1H68I903B", PiiKind::ItDriversLicense ; "it dl no keyword")]
    // Spain — value present but no keyword
    #[test_case("28001", PiiKind::EsPostalCode ; "es postal no keyword")]
    #[test_case("612 345 678", PiiKind::EsPhoneNumber ; "es phone no keyword")]
    #[test_case("281234567840", PiiKind::EsNuss ; "es nuss no keyword")]
    #[test_case("ABC123456", PiiKind::EsPassportNumber ; "es passport no keyword")]
    #[test_case("number is 44051401359", PiiKind::PlPesel ; "pl pesel no keyword")]
    #[test_case("number is 7740001454", PiiKind::PlNip ; "pl nip no keyword")]
    #[test_case("number is 610188201", PiiKind::PlRegon ; "pl regon no keyword")]
    #[test_case("ABS123456 on file", PiiKind::PlIdCard ; "pl id card no keyword")]
    #[test_case("CC7999486 on file", PiiKind::PlPassportNumber ; "pl passport no keyword")]
    #[test_case("call 601 234 567 today", PiiKind::PlPhoneNumber ; "pl phone no keyword")]
    #[test_case("00-950 Warszawa", PiiKind::PlPostalCode ; "pl postal no keyword")]
    #[test_case("ref 12345/67/8901", PiiKind::PlDriversLicense ; "pl dl no keyword")]
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

    #[test_case(r#"{"contact": {"phone": "555-123-4567", "type": "mobile"}}"#, PiiKind::UsPhoneNumber, "555-123-4567" ; "phone in json")]
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

    #[test]
    fn detects_multiple_same_kind_values_close_together() {
        // Distinct values of one keyword-gated kind packed within MATCH_LOOKBACK
        // of each other must all be reported — the overlap-based dedup only
        // collapses the redundant vectorscan end-hits for a single value, not
        // separate values. (A flat `to`-distance window kept only the last.)
        let detector = &*DETECTOR;
        let input = "Passport: 123456789, Passport: 987654321, Passport: 234567891";
        let values: Vec<&str> = detector
            .mark_piis(input)
            .iter()
            .filter(|m| m.kind == PiiKind::PassportNumber)
            .map(|m| &input[m.start..m.end])
            .collect();
        assert!(values.contains(&"123456789"), "got {values:?}");
        assert!(values.contains(&"987654321"), "got {values:?}");
        assert!(values.contains(&"234567891"), "got {values:?}");
    }

    // --- Compact keyword forms (camelCase / snake_case / kebab-case / concat) ---
    // Regression coverage for the optional-separator change: every multi-word
    // keyword regex must accept compact field names where the separator is
    // absent, an underscore, or a hyphen. Each case also exercises a different
    // keyword/value separator (JSON `": "`, YAML `: `, env-var `=`, plain
    // whitespace, ` is `, etc.) to verify the regex isn't fragile to a single
    // delimiter style.
    #[test_case(r#""nhsNumber": "943 476 5919""#, PiiKind::GbNhsNumber, "943 476 5919" ; "compact nhs camelcase json")]
    #[test_case("nhs_number=943 476 5919", PiiKind::GbNhsNumber, "943 476 5919" ; "compact nhs snakecase equals")]
    #[test_case("nhs-number: 943 476 5919", PiiKind::GbNhsNumber, "943 476 5919" ; "compact nhs kebabcase yaml")]
    #[test_case("nhsnumber 943 476 5919", PiiKind::GbNhsNumber, "943 476 5919" ; "compact nhs concat whitespace")]
    #[test_case(r#""routingNumber": "021000021""#, PiiKind::UsAbaRouting, "021000021" ; "compact aba camelcase json")]
    #[test_case("routing_number is 021000021", PiiKind::UsAbaRouting, "021000021" ; "compact aba snakecase is")]
    #[test_case("alienNumber=A012345678", PiiKind::UsAlienNumber, "A012345678" ; "compact alien camelcase equals")]
    #[test_case("alien_number: A012345678", PiiKind::UsAlienNumber, "A012345678" ; "compact alien snakecase yaml")]
    #[test_case(r#""uscisReceipt":"SRC2190000001""#, PiiKind::UsUscisReceiptNumber, "SRC2190000001" ; "compact uscis camelcase tight json")]
    #[test_case("uscis_receipt SRC2190000001", PiiKind::UsUscisReceiptNumber, "SRC2190000001" ; "compact uscis snakecase whitespace")]
    #[test_case("einNumber: 12-3456789", PiiKind::UsEin, "12-3456789" ; "compact ein camelcase yaml")]
    #[test_case("ein_number=12-3456789", PiiKind::UsEin, "12-3456789" ; "compact ein snakecase equals")]
    #[test_case(r#""einnumber":"12-3456789""#, PiiKind::UsEin, "12-3456789" ; "compact ein concat tight json")]
    #[test_case("utrNumber 5555555555", PiiKind::GbUtr, "5555555555" ; "compact utr camelcase whitespace")]
    #[test_case("utr_number is 5555555555", PiiKind::GbUtr, "5555555555" ; "compact utr snakecase is")]
    #[test_case(r#""sortCode": "20-00-00""#, PiiKind::GbSortCode, "20-00-00" ; "compact sort code camelcase json")]
    #[test_case("sort_code=20-00-00", PiiKind::GbSortCode, "20-00-00" ; "compact sort code snakecase equals")]
    #[test_case("sort-code: 20-00-00", PiiKind::GbSortCode, "20-00-00" ; "compact sort code kebabcase yaml")]
    #[test_case("bicCode=DEUTDEFF", PiiKind::SwiftBic, "DEUTDEFF" ; "compact bic code camelcase equals")]
    #[test_case("bic-code: DEUTDEFF", PiiKind::SwiftBic, "DEUTDEFF" ; "compact bic code kebabcase yaml")]
    #[test_case(r#""swiftCode": "DEUTDEFF""#, PiiKind::SwiftBic, "DEUTDEFF" ; "compact swift code camelcase json")]
    #[test_case(r#""dateOfBirth": "1990-05-15""#, PiiKind::DateOfBirth, "1990-05-15" ; "compact dob camelcase json")]
    #[test_case("date_of_birth=1990-05-15", PiiKind::DateOfBirth, "1990-05-15" ; "compact dob snakecase equals")]
    #[test_case("birthDate is 1990-05-15", PiiKind::DateOfBirth, "1990-05-15" ; "compact birthdate camelcase is")]
    #[test_case("medicareNumber: 2123 45670 1", PiiKind::AuMedicare, "2123 45670 1" ; "compact medicare camelcase yaml")]
    #[test_case(r#""medicare_number":"2123 45670 1""#, PiiKind::AuMedicare, "2123 45670 1" ; "compact medicare snakecase tight json")]
    #[test_case("taxFileNumber=123 456 782", PiiKind::AuTfn, "123 456 782" ; "compact tfn camelcase equals")]
    #[test_case("tax_file_number is 123 456 782", PiiKind::AuTfn, "123 456 782" ; "compact tfn snakecase is")]
    #[test_case(r#""irdNumber": "49-091-857""#, PiiKind::NzIrdNumber, "49-091-857" ; "compact ird camelcase json")]
    #[test_case("ird_number 49-091-857", PiiKind::NzIrdNumber, "49-091-857" ; "compact ird snakecase whitespace")]
    #[test_case(r#""driverLicense": "B1234568""#, PiiKind::UsDriversLicense, "B1234568" ; "compact us dl camelcase json")]
    #[test_case("driver_license=B1234568", PiiKind::UsDriversLicense, "B1234568" ; "compact us dl snakecase equals")]
    #[test_case("driver-license: B1234568", PiiKind::UsDriversLicense, "B1234568" ; "compact us dl kebabcase yaml")]
    #[test_case("licenseNumber B1234568", PiiKind::UsDriversLicense, "B1234568" ; "compact license number camelcase whitespace")]
    #[test_case("driverNumber=123456789", PiiKind::IeDriverNumber, "123456789" ; "compact ie driver camelcase equals")]
    #[test_case("driver_number is 123456789", PiiKind::IeDriverNumber, "123456789" ; "compact ie driver snakecase is")]
    #[test_case(r#""idNumber": "8001015009087""#, PiiKind::ZaId, "8001015009087" ; "compact za id camelcase json")]
    #[test_case("id_number=8001015009087", PiiKind::ZaId, "8001015009087" ; "compact za id snakecase equals")]
    #[test_case("identityNumber: 8001015009087", PiiKind::ZaId, "8001015009087" ; "compact za identity camelcase yaml")]
    #[test_case(r#""taxNumber": "0123456789""#, PiiKind::ZaTaxReference, "0123456789" ; "compact za trn camelcase json")]
    #[test_case("tax_number=0123456789", PiiKind::ZaTaxReference, "0123456789" ; "compact za trn snakecase equals")]
    #[test_case(r#""awsSecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY""#, PiiKind::AwsSecretKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" ; "compact aws secret camelcase json")]
    #[test_case("aws-secret-access-key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", PiiKind::AwsSecretKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" ; "compact aws secret kebabcase equals")]
    #[test_case("passportNumber: A12345678", PiiKind::UsPassportNew, "A12345678" ; "compact passport camelcase yaml")]
    #[test_case("passport_number=A12345678", PiiKind::UsPassportNew, "A12345678" ; "compact passport snakecase equals")]
    #[test_case("imeiNumber 490154203237518", PiiKind::Imei, "490154203237518" ; "compact imei camelcase whitespace")]
    #[test_case(r#""imei_number":"490154203237518""#, PiiKind::Imei, "490154203237518" ; "compact imei snakecase tight json")]
    #[test_case("ohipNumber: 1234567897", PiiKind::CaOhip, "1234567897" ; "compact ohip camelcase yaml")]
    #[test_case("healthCard=1234567897", PiiKind::CaOhip, "1234567897" ; "compact health card camelcase equals")]
    fn detects_with_compact_keyword(input: &str, kind: PiiKind, expected_span: &str) {
        let detector = &*DETECTOR;
        let matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == kind)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected 1 match for {kind:?} in: {input}, got {} matches",
            matches.len()
        );
        assert_eq!(&input[matches[0].start..matches[0].end], expected_span);
    }

    // --- URL-encoded input tests ---

    #[test_case("phone%3A 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "url phone sep colon")]
    #[test_case("phone%3A%20555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "url phone sep colon space")]
    #[test_case("phone%20number%3A 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "url phone keyword space")]
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

    // --- Markdown / wrapper-character separator tests ---
    // Datasets render labels with markdown emphasis (`**Key**`, `_Key_`,
    // `` `Key` ``, `~~Key~~`) and wrap the *value* in brackets/parens/emphasis
    // (`[v]`, `(v)`, `{v}`, `**v**`). Those wrapper chars sit between keyword
    // and value (or right before the value) and must be skippable by the gap;
    // the captured span is the bare value, never the wrapper.

    #[test_case("**Passport Number**: 123456789", PiiKind::PassportNumber, "123456789" ; "md passport bold")]
    #[test_case("*Passport Number*: 123456789", PiiKind::PassportNumber, "123456789" ; "md passport italic single star")]
    #[test_case("__Passport Number__: 123456789", PiiKind::PassportNumber, "123456789" ; "md passport bold underscore")]
    #[test_case("`Passport Number`: 123456789", PiiKind::PassportNumber, "123456789" ; "md passport code backtick")]
    #[test_case("~~Passport Number~~: 123456789", PiiKind::PassportNumber, "123456789" ; "md passport strikethrough")]
    #[test_case("**Phone Number**: 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "md phone bold")]
    #[test_case("**SWIFT**: DEUTDEFF", PiiKind::SwiftBic, "DEUTDEFF" ; "md swift bold")]
    #[test_case("passport number: [123456789]", PiiKind::PassportNumber, "123456789" ; "wrap value square brackets")]
    #[test_case("passport number: (123456789)", PiiKind::PassportNumber, "123456789" ; "wrap value parens")]
    #[test_case("passport number: {123456789}", PiiKind::PassportNumber, "123456789" ; "wrap value braces")]
    #[test_case("passport number: **123456789**", PiiKind::PassportNumber, "123456789" ; "wrap value bold")]
    #[test_case("(Passport Number): 123456789", PiiKind::PassportNumber, "123456789" ; "wrap keyword parens")]
    fn detects_markdown_separator(input: &str, kind: PiiKind, expected_span: &str) {
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

    #[test_case("phone&#58; 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "html phone decimal colon")]
    #[test_case("phone&colon; 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "html phone named colon")]
    #[test_case("phone&#x3A; 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "html phone hex colon")]
    #[test_case("phone&nbsp;number: 555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "html phone nbsp keyword")]
    #[test_case("passport&#58; 123456789", PiiKind::PassportNumber, "123456789" ; "html passport colon")]
    #[test_case("EIN&colon; 12-3456789", PiiKind::UsEin, "12-3456789" ; "html ein named colon")]
    #[test_case("SWIFT&#58; DEUTDEFF", PiiKind::SwiftBic, "DEUTDEFF" ; "html swift colon")]
    #[test_case("sort&nbsp;code: 20-00-00", PiiKind::GbSortCode, "20-00-00" ; "html sort code nbsp")]
    #[test_case("coordinates&#58; 40.7128,-74.0060", PiiKind::PreciseGeolocation, "40.7128,-74.0060" ; "html geolocation colon")]
    #[test_case("phone&#58;&#32;555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "html phone colon and space")]
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
    #[test_case("phone_number=555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "url qp phone_number")]
    #[test_case("passport_number=123456789", PiiKind::PassportNumber, "123456789" ; "url qp passport_number")]
    #[test_case("date_of_birth=15/03/1990", PiiKind::DateOfBirth, "15/03/1990" ; "url qp date_of_birth")]
    #[test_case("sort_code=20-00-00", PiiKind::GbSortCode, "20-00-00" ; "url qp sort_code")]
    // Array bracket notation: param[key]=value
    #[test_case("user[last_name]=Lopez", PiiKind::PersonName, "Lopez" ; "url qp bracket last_name")]
    #[test_case("user[first_name]=Alberto", PiiKind::PersonName, "Alberto" ; "url qp bracket first_name")]
    #[test_case("data[phone_number]=555-123-4567", PiiKind::UsPhoneNumber, "555-123-4567" ; "url qp bracket phone_number")]
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

    // --- mark_piis_structured ---

    const PHONE: &str = "555-123-4567";

    fn phone_frag<'a>(context: &'a str, offset: usize) -> ContextFragment<'a> {
        ContextFragment {
            context,
            value: PHONE,
            offset,
        }
    }

    #[test_case("phone_number" ; "leaf keyword (iter 1)")]
    #[test_case("user.phone_number" ; "leaf keyword nested (iter 1)")]
    #[test_case("phone_number.primary" ; "keyword at head (iter 2)")]
    #[test_case("user.phone_number.value" ; "keyword in middle (iter 2)")]
    // Plural-form variants (TASKS.md 15.1: phone_numbers[0], etc.)
    #[test_case("phone_numbers" ; "leaf plural keyword (iter 1)")]
    #[test_case("user.phone_numbers" ; "plural keyword nested (iter 1)")]
    #[test_case("phone_numbers[0]" ; "plural keyword in array (iter 1, indices stripped)")]
    #[test_case("user.phone_numbers[0]" ; "plural keyword nested in array")]
    fn structured_detects_phone_in_path(context: &str) {
        let detector = &*DETECTOR;
        let frags = [phone_frag(context, 0)];
        let matches = detector.mark_piis_structured(&frags);
        assert_eq!(
            matches.len(),
            1,
            "expected 1 match for context {context:?}, got {matches:?}"
        );
        assert_eq!(matches[0].kind, PiiKind::UsPhoneNumber);
        // Span covers the value, document-absolute (offset = 0 here).
        assert_eq!(&PHONE[matches[0].start..matches[0].end], PHONE);
    }

    #[test]
    fn structured_no_keyword_no_match_for_keyword_kind() {
        let detector = &*DETECTOR;
        let frags = [phone_frag("unknown_field", 0)];
        let matches = detector.mark_piis_structured(&frags);
        assert!(
            matches.is_empty(),
            "expected no keyword-context match for unknown_field, got {matches:?}"
        );
    }

    #[test]
    fn structured_pattern_only_kind_is_noop() {
        // Email is detected by HyperscanDetector (pattern-only). The
        // keyword-context iteration runs but records nothing because no
        // keyword-context email pattern exists in this detector.
        let detector = &*DETECTOR;
        let frags = [ContextFragment {
            context: "email.work",
            value: "user@example.com",
            offset: 0,
        }];
        let matches = detector.mark_piis_structured(&frags);
        assert!(
            matches.is_empty(),
            "KeywordContextDetector should not match email; got {matches:?}"
        );
    }

    #[test]
    fn structured_multiple_fragments_different_kinds() {
        let detector = &*DETECTOR;
        let frags = [
            ContextFragment {
                context: "phone_number",
                value: PHONE,
                offset: 0,
            },
            ContextFragment {
                context: "passport_number",
                value: "A12345678",
                offset: 100,
            },
        ];
        let matches = detector.mark_piis_structured(&frags);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::UsPhoneNumber));
        assert!(
            kinds.contains(&PiiKind::PassportNumber) || kinds.contains(&PiiKind::UsPassportNew),
            "expected a passport kind in {kinds:?}",
        );
    }

    #[test]
    fn structured_offsets_are_document_absolute() {
        let detector = &*DETECTOR;
        let offset = 137;
        let frags = [phone_frag("user.phone_number", offset)];
        let matches = detector.mark_piis_structured(&frags);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].start, offset);
        assert_eq!(matches[0].end, offset + PHONE.len());
    }

    /// Encoded keyword/value separators inside a fragment value (e.g. a URL
    /// query parameter where `phone%3A%20` is used between keyword and digits)
    /// must still be detected. The structured path decodes the value before
    /// running the keyword regex and remaps offsets back to the original
    /// (encoded) bytes via the offset map.
    #[test]
    fn structured_detects_url_encoded_separator_in_value() {
        let detector = &*DETECTOR;
        // Value contains `phone%3A%205551234567` — `%3A%20` is URL-encoded
        // ": ", which the keyword regex's separator class would otherwise miss.
        let value = "https://app.example.com/p?phone=phone%3A%205551234567";
        let frags = [ContextFragment {
            context: "page_location",
            value,
            offset: 50,
        }];
        let matches = detector.mark_piis_structured(&frags);
        assert!(
            matches.iter().any(|m| m.kind == PiiKind::UsPhoneNumber),
            "expected phone match, got {matches:?}",
        );
        // Spans must point at the encoded digits in the original value, not
        // into the decoded scratch string.
        let phone = matches
            .iter()
            .find(|m| m.kind == PiiKind::UsPhoneNumber)
            .unwrap();
        let local_start = phone.start - 50;
        let local_end = phone.end - 50;
        assert_eq!(&value[local_start..local_end], "5551234567");
    }

    #[test]
    fn structured_short_circuits_on_first_hit() {
        // A nested path where iter 1 (`user.phone_number: V`) already matches —
        // outer iterations should not produce duplicate results.
        let detector = &*DETECTOR;
        let frags = [phone_frag("user.phone_number", 50)];
        let matches = detector.mark_piis_structured(&frags);
        assert_eq!(matches.len(), 1, "expected dedup via short-circuit");
    }

    #[test]
    fn structured_strips_array_indices() {
        // Path with array indices — they should be stripped before iterating.
        // `users[0].phone_number` becomes `users.phone_number`.
        let detector = &*DETECTOR;
        let frags = [phone_frag("users[0].phone_number", 0)];
        let matches = detector.mark_piis_structured(&frags);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, PiiKind::UsPhoneNumber);
    }

    #[test]
    fn structured_detects_fr_plural_keyword() {
        // French plural head noun (`numéros de téléphone`) inside an array
        // context — exercises iter 1 with stripped indices.
        let detector = &*DETECTOR;
        let value = "06 12 34 56 78";
        let frags = [ContextFragment {
            context: "numéros_de_téléphone[0]",
            value,
            offset: 0,
        }];
        let matches = detector.mark_piis_structured(&frags);
        assert!(
            matches.iter().any(|m| m.kind == PiiKind::FrPhoneNumber),
            "expected FrPhoneNumber match for plural French keyword in array, got {matches:?}"
        );
    }

    #[test]
    fn structured_detects_de_plural_keyword() {
        // German plural compound (`Telefonnummern`) inside an array context —
        // exercises iter 1 with stripped indices.
        let detector = &*DETECTOR;
        let value = "+49 30 12345678";
        let frags = [ContextFragment {
            context: "Telefonnummern[0]",
            value,
            offset: 0,
        }];
        let matches = detector.mark_piis_structured(&frags);
        assert!(
            matches.iter().any(|m| m.kind == PiiKind::DePhoneNumber),
            "expected DePhoneNumber match for plural German keyword in array, got {matches:?}"
        );
    }

    #[test]
    fn structured_lookback_overflow_falls_back_per_segment() {
        // Build a path whose joined length exceeds MATCH_LOOKBACK, with
        // `phone_number` as the leaf segment. The path-prefix iteration
        // would synthesize a string too long for the lookback window;
        // per-segment fallback should still detect via the leaf segment alone.
        let detector = &*DETECTOR;
        let mut path = String::new();
        while path.len() < KeywordContextDetector::MATCH_LOOKBACK + 16 {
            if !path.is_empty() {
                path.push('.');
            }
            path.push_str("filler_segment");
        }
        path.push('.');
        path.push_str("phone_number");
        assert!(path.len() > KeywordContextDetector::MATCH_LOOKBACK);

        let frags = [phone_frag(&path, 0)];
        let matches = detector.mark_piis_structured(&frags);
        assert_eq!(
            matches.len(),
            1,
            "expected leaf-segment keyword to match via per-segment fallback"
        );
        assert_eq!(matches[0].kind, PiiKind::UsPhoneNumber);
    }

    #[test]
    fn structured_empty_fragments_returns_empty() {
        let detector = &*DETECTOR;
        let matches = detector.mark_piis_structured(&[]);
        assert!(matches.is_empty());
    }
}
