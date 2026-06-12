//! AI4Privacy effectiveness eval (Phase 18). See `DESIGN.md` §"AI4Privacy
//! Effectiveness Evaluation" and `docs/ai4privacy-eval.md`.
//!
//! Scores Voidwall's PII detection against the public
//! `ai4privacy/pii-masking-300k` dataset, reporting span-level
//! precision/recall/F1 per entity type and overall — comparable to other PII
//! solutions' published numbers. It drives `POST /v1/redact` (configured with
//! `redact_strategy = "type_label"`) and recovers predicted spans by diffing the
//! `[KIND]`-redacted body against the original text.
//!
//! This is a *reporting tool*, not a `cargo test` target: it needs the large
//! external dataset and a running proxy. Run it via `docker/ctl eval`.
//!
//! Env knobs (all optional):
//! - `DATASET`     JSONL file or directory (default: `.cache/ai4privacy`).
//! - `API_URL`     proxy HTTP API base (default: `http://localhost:8083`).
//! - `MAX_ROWS`    cap rows processed.
//! - `LANG`        keep only rows whose `language` matches.
//! - `CONCURRENCY` in-flight requests (default: 32).
//! - `ENFORCE`     `1` → assert committed per-category floors, non-zero on breach.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use regex::Regex;
use serde::Deserialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

// ---------------------------------------------------------------------------
// Config (env)
// ---------------------------------------------------------------------------

struct Config {
    dataset: PathBuf,
    api_url: String,
    max_rows: Option<u64>,
    lang: Option<String>,
    concurrency: usize,
    enforce: bool,
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

impl Config {
    fn from_env() -> Self {
        Config {
            dataset: PathBuf::from(
                env_opt("DATASET").unwrap_or_else(|| ".cache/ai4privacy".to_string()),
            ),
            api_url: env_opt("API_URL")
                .unwrap_or_else(|| "http://localhost:8083".to_string())
                .trim_end_matches('/')
                .to_string(),
            max_rows: env_opt("MAX_ROWS").and_then(|s| s.parse().ok()),
            // `LANG` doubles as the POSIX locale variable (`en_US.UTF-8`).
            // A value carrying `_` or `.` is an inherited locale, not a dataset
            // language filter, so ignore it — "unset" must mean "all languages".
            lang: env_opt("LANG")
                .filter(|s| !s.contains('_') && !s.contains('.'))
                .map(|s| s.to_ascii_lowercase()),
            concurrency: env_opt("CONCURRENCY")
                .and_then(|s| s.parse().ok())
                .filter(|n| *n > 0)
                .unwrap_or(32),
            enforce: env_opt("ENFORCE").as_deref() == Some("1"),
        }
    }
}

// ---------------------------------------------------------------------------
// Dataset row model (lenient serde)
// ---------------------------------------------------------------------------

/// One annotated PII span from the dataset's `privacy_mask`. Char offsets;
/// `value` is the literal text, used to validate/repair the offsets.
#[derive(Debug, Clone, Deserialize)]
struct MaskSpan {
    label: String,
    #[serde(default)]
    start: usize,
    #[serde(default)]
    end: usize,
    #[serde(default)]
    value: String,
}

/// A dataset row. `source_text` (alias `unmasked_text`) is the unredacted text.
/// `privacy_mask` is a list of `MaskSpan`; older dumps stringify it as a JSON
/// string, handled by the deserialize shim below. Extra fields are ignored.
#[derive(Debug, Deserialize)]
struct Row {
    #[serde(alias = "unmasked_text")]
    source_text: String,
    #[serde(default, deserialize_with = "de_privacy_mask")]
    privacy_mask: Vec<MaskSpan>,
    #[serde(default)]
    language: Option<String>,
}

/// Accept `privacy_mask` either as a JSON array (current form) or as a JSON
/// *string* that itself contains the array (older stringified dumps).
fn de_privacy_mask<'de, D>(de: D) -> Result<Vec<MaskSpan>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Shim {
        List(Vec<MaskSpan>),
        Str(String),
        Null,
    }
    match Shim::deserialize(de)? {
        Shim::List(v) => Ok(v),
        Shim::Str(s) => serde_json::from_str(&s).map_err(D::Error::custom),
        Shim::Null => Ok(Vec::new()),
    }
}

// ---------------------------------------------------------------------------
// Dataset file discovery + streaming
// ---------------------------------------------------------------------------

/// Resolve `DATASET` to a non-empty list of `*.jsonl` files. A directory is
/// expanded to its `*.jsonl` children (sorted); a file is taken verbatim.
fn dataset_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    if path.is_dir() {
        let mut files: Vec<PathBuf> = std::fs::read_dir(path)
            .map_err(|e| format!("cannot read dataset dir {}: {e}", path.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .collect();
        files.sort();
        if files.is_empty() {
            return Err(format!(
                "dataset dir {} holds no *.jsonl files (auto-fetch may have failed)",
                path.display()
            ));
        }
        Ok(files)
    } else if path.is_file() {
        Ok(vec![path.to_path_buf()])
    } else {
        Err(format!(
            "DATASET path {} does not exist — run via `docker/ctl eval` to auto-fetch, \
             or point DATASET at a local JSONL file/dir",
            path.display()
        ))
    }
}

/// `LANG` filter. Lenient: matches either way (`en` ↔ `english`) so a code or a
/// full name both work against whatever the dataset's `language` field holds.
fn lang_matches(filter: &str, row_lang: Option<&str>) -> bool {
    match row_lang {
        None => true,
        Some(l) => {
            let l = l.to_ascii_lowercase();
            l.starts_with(filter) || filter.starts_with(&l)
        }
    }
}

// ---------------------------------------------------------------------------
// Span recovery: diff redacted body against the original
// ---------------------------------------------------------------------------

/// Matches a `type_label` redaction token, e.g. `[EMAIL]`, `[US_PHONE_NUMBER]`.
fn token_re() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[[A-Z][A-Z0-9_]*\]").unwrap())
}

/// Find `needle` in `hay[from..]` (char slices). Returns the char index where it
/// begins, or `from` for an empty needle. `None` if not present.
fn find_from(hay: &[char], from: usize, needle: &[char]) -> Option<usize> {
    if needle.is_empty() {
        return Some(from.min(hay.len()));
    }
    if from > hay.len() || needle.len() > hay.len() - from {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Recover predicted spans by diffing the `[KIND]`-redacted body against the
/// original. The redacted body is the original with each detected span replaced
/// by a `[LABEL]` token and everything else byte-identical, so:
///
/// ```text
/// redacted = lit0 [L1] lit1 [L2] lit2 …
/// original = lit0 span1 lit1 span2 lit2 …
/// ```
///
/// We anchor each literal segment left-to-right in the original (char offsets);
/// the text between two anchored literals is the predicted span for the token
/// sitting between them. Returns `(start, end, kind)` in **char** offsets.
///
/// Heuristic limits (negligible on synthetic data, both documented):
/// - **Adjacent tokens** (`[A][B]`) are separated by an empty literal, so the
///   first token collapses to a zero-length span at the boundary — its kind is
///   still recovered but its extent is lost.
/// - A literal `[LABEL]`-shaped substring in the *original* text is
///   indistinguishable from a real token and would be mis-anchored.
fn recover_spans(original: &str, redacted: &str) -> Vec<(usize, usize, String)> {
    let orig: Vec<char> = original.chars().collect();
    let mut out = Vec::new();
    let mut cursor = 0usize; // char index into `orig`
    let mut last_end = 0usize; // byte index into `redacted`, end of prev token
    let mut pending: Option<(String, usize)> = None; // (kind, span_start)

    for m in token_re().find_iter(redacted) {
        let literal: Vec<char> = redacted[last_end..m.start()].chars().collect();
        let pos = find_from(&orig, cursor, &literal).unwrap_or(cursor);
        if let Some((kind, start)) = pending.take() {
            out.push((start, pos, kind));
        }
        cursor = (pos + literal.len()).min(orig.len());
        let tok = m.as_str();
        let kind = tok[1..tok.len() - 1].to_string();
        pending = Some((kind, cursor));
        last_end = m.end();
    }

    // Trailing literal after the last token anchors that token's end. An empty
    // trailing literal means the token ran to the end of the original.
    let trailing: Vec<char> = redacted[last_end..].chars().collect();
    let pos = if trailing.is_empty() {
        orig.len()
    } else {
        find_from(&orig, cursor, &trailing).unwrap_or(orig.len())
    };
    if let Some((kind, start)) = pending.take() {
        out.push((start, pos, kind));
    }
    out
}

/// Two half-open `[start, end)` char ranges overlap.
fn spans_overlap(a: (usize, usize), b: (usize, usize)) -> bool {
    a.0 < b.1 && b.0 < a.1 || (a.0 == a.1 && b.0 <= a.0 && a.0 < b.1)
}

/// Resolve a ground-truth `MaskSpan` to `(start, end)` char offsets in the
/// original. Trusts `start`/`end` when the slice equals `value`; otherwise
/// guards a byte/char coordinate mismatch, then falls back to substring search.
fn resolve_gt(original: &str, orig_chars: &[char], m: &MaskSpan) -> (usize, usize) {
    // 1. Trust char offsets when the slice matches `value`.
    if m.start <= m.end && m.end <= orig_chars.len() {
        let slice: String = orig_chars[m.start..m.end].iter().collect();
        if m.value.is_empty() || slice == m.value {
            return (m.start, m.end);
        }
    }
    // 2. Maybe the offsets are byte coordinates — convert to char.
    if !m.value.is_empty()
        && m.start <= m.end
        && m.end <= original.len()
        && original.is_char_boundary(m.start)
        && original.is_char_boundary(m.end)
        && original[m.start..m.end] == m.value
    {
        let cs = original[..m.start].chars().count();
        return (cs, cs + m.value.chars().count());
    }
    // 3. Last resort: locate `value` by substring search.
    if !m.value.is_empty()
        && let Some(byte_pos) = original.find(&m.value)
    {
        let cs = original[..byte_pos].chars().count();
        return (cs, cs + m.value.chars().count());
    }
    // 4. Give up — clamp the raw offsets so the GT still counts toward recall.
    let s = m.start.min(orig_chars.len());
    (s, m.end.clamp(s, orig_chars.len()))
}

// ---------------------------------------------------------------------------
// Category → PiiKind mapping
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bucket {
    /// Exact / family match — typed-scored against a precise expected kind set.
    Exact,
    /// Keyword-gated family — typed-scored, but recall is structurally lower
    /// because the detector needs nearby keyword context.
    KeywordGated,
    /// Voidwall has no detector — detection recall reported, not typed-scored.
    KnownGap,
    /// Dataset label in no bucket — surfaced so a dataset update can't be
    /// silently ignored.
    Unclassified,
}

// The mapping targets the **OpenPII label set** used by `pii-masking-300k`'s
// train files (`GIVENNAME1`, `SOCIALNUMBER`, `TEL`, `POSTCODE`, `IDCARD`, …),
// NOT the older verbose `pii-masking-200k` vocabulary (`FIRSTNAME`, `SSN`,
// `PHONENUMBER`, …). The two share only `EMAIL`/`IP`/`STREET`. Keep this in
// sync with DESIGN.md §"Category → PiiKind mapping".

/// Known-gap dataset labels — Voidwall has no detector for these, so they are
/// detection-reported but never typed-scored.
const KNOWN_GAPS: &[&str] = &[
    "PASS",  // password (free-form secret, e.g. `r]iD1#8`)
    "TITLE", // honorific (`Mr`, `Friar`)
    "COUNTRY", "CITY", "STATE", "SEX", "DATE", "TIME", "USERNAME",
];

fn bucket_of(label: &str) -> Bucket {
    match label {
        // Structural / family detectors — high recall expected.
        "EMAIL" | "IP" | "GEOCOORD" | "BOD" | "GIVENNAME1" | "GIVENNAME2" | "LASTNAME1"
        | "LASTNAME2" | "LASTNAME3" => Bucket::Exact,
        // Keyword-gated — detector needs nearby context, so recall is lower.
        "TEL" | "POSTCODE" | "STREET" | "SECADDRESS" | "BUILDING" | "PASSPORT" | "IDCARD"
        | "DRIVERLICENSE" | "SOCIALNUMBER" => Bucket::KeywordGated,
        l if KNOWN_GAPS.contains(&l) => Bucket::KnownGap,
        _ => Bucket::Unclassified,
    }
}

/// National "social/insurance number" kinds — the family `SOCIALNUMBER` maps to.
fn is_social_number_kind(k: &str) -> bool {
    matches!(
        k,
        "US_SSN"
            | "US_ITIN"
            | "GB_NINO"
            | "CA_SIN"
            | "IE_PPSN"
            | "AU_TFN"
            | "FR_NIR"
            | "ES_NUSS"
            | "NL_BSN"
            | "PL_PESEL"
            | "IT_CODICE_FISCALE"
            | "CH_AHV"
            | "AT_SVNR"
            | "NZ_IRD_NUMBER"
            | "ZA_ID"
    )
}

/// National ID-card kinds — the family `IDCARD` maps to.
fn is_id_card_kind(k: &str) -> bool {
    matches!(
        k,
        "PL_ID_CARD"
            | "DE_PERSONALAUSWEIS"
            | "ES_DNI"
            | "ES_NIE"
            | "FR_CNI"
            | "IT_CODICE_FISCALE"
            | "ZA_ID"
            | "NL_BSN"
    )
}

/// Whether a predicted `PiiKind` label belongs to the family expected for a
/// dataset `label` — the basis of the *typed* metric.
fn typed_match(label: &str, predicted: &str) -> bool {
    match label {
        "EMAIL" => predicted == "EMAIL",
        "IP" => predicted == "IP_ADDRESS",
        "GEOCOORD" => predicted == "PRECISE_GEOLOCATION",
        "BOD" => predicted == "DATE_OF_BIRTH",
        "GIVENNAME1" | "GIVENNAME2" | "LASTNAME1" | "LASTNAME2" | "LASTNAME3" => {
            predicted == "PERSON_NAME"
        }
        "TEL" => predicted.ends_with("PHONE_NUMBER"),
        "POSTCODE" => {
            predicted.ends_with("POSTAL_CODE")
                || predicted == "GB_POSTCODE"
                || predicted == "IE_EIRCODE"
        }
        "STREET" | "SECADDRESS" | "BUILDING" => {
            matches!(
                predicted,
                "GB_ADDRESS" | "DE_AT_CH_ADDRESS" | "FR_CH_ADDRESS"
            )
        }
        "PASSPORT" => predicted.ends_with("PASSPORT_NUMBER") || predicted == "US_PASSPORT_NEW",
        "DRIVERLICENSE" => predicted.contains("DRIV"),
        "IDCARD" => is_id_card_kind(predicted),
        "SOCIALNUMBER" => is_social_number_kind(predicted),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Strong-validator precision carve-out
// ---------------------------------------------------------------------------

/// Predicted kinds with a strong structural validator. A detection-FP whose
/// kind is in this set *and* passes its validator is a near-certain
/// real-but-unannotated catch, so it is re-classified as *unscored* for the
/// `adjusted_precision` band rather than counted against precision.
fn strong_validator(kind: &str, value: &str) -> Option<bool> {
    match kind {
        "EMAIL" => Some(valid_email(value)),
        "IBAN" => Some(valid_iban(value)),
        "CREDIT_CARD" => Some(luhn(value)),
        "IP_ADDRESS" => Some(value.parse::<std::net::IpAddr>().is_ok()),
        "MAC_ADDRESS" => Some(valid_mac(value)),
        "BITCOIN_ADDRESS" => Some(valid_btc(value)),
        "ETHEREUM_ADDRESS" => Some(valid_eth(value)),
        "VIN" => Some(valid_vin(value)),
        "IMEI" => Some(valid_imei(value)),
        _ => None,
    }
}

fn luhn(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 2 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let d2 = d * 2;
                if d2 > 9 { d2 - 9 } else { d2 }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

fn valid_email(s: &str) -> bool {
    let s = s.trim();
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains(' ')
}

fn valid_iban(s: &str) -> bool {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() < 15 || s.len() > 34 || !s.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    if !s[..2].chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    // Move the first four chars to the end, then mod-97 == 1.
    let rearranged = format!("{}{}", &s[4..], &s[..4]);
    let mut remainder: u32 = 0;
    for c in rearranged.chars() {
        let v = if c.is_ascii_digit() {
            c as u32 - '0' as u32
        } else {
            c.to_ascii_uppercase() as u32 - 'A' as u32 + 10
        };
        // Fold one or two decimal digits at a time, mod 97.
        if v >= 10 {
            remainder = (remainder * 100 + v) % 97;
        } else {
            remainder = (remainder * 10 + v) % 97;
        }
    }
    remainder == 1
}

fn valid_mac(s: &str) -> bool {
    let parts: Vec<&str> = if s.contains(':') {
        s.split(':').collect()
    } else {
        s.split('-').collect()
    };
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn valid_eth(s: &str) -> bool {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn valid_btc(s: &str) -> bool {
    if let Some(rest) = s.strip_prefix("bc1") {
        return (11..=87).contains(&rest.len())
            && rest
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    }
    if s.starts_with('1') || s.starts_with('3') {
        const B58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        return (26..=35).contains(&s.len()) && s.chars().all(|c| B58.contains(c));
    }
    false
}

fn valid_vin(s: &str) -> bool {
    s.len() == 17
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() && !matches!(c.to_ascii_uppercase(), 'I' | 'O' | 'Q')
        })
}

fn valid_imei(s: &str) -> bool {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    digits.len() == 15 && luhn(&digits)
}

// ---------------------------------------------------------------------------
// Per-row scoring
// ---------------------------------------------------------------------------

/// Per-ground-truth-span outcome for one row.
struct GtResult {
    label: String,
    bucket: Bucket,
    det_hit: bool,
    typed_hit: bool,
}

/// Aggregable per-row result. The heavy lifting (diff, overlap, validation)
/// happens off the main task; the single-threaded aggregator just folds these.
struct RowOutcome {
    gts: Vec<GtResult>,
    preds_total: u64,
    det_tp: u64,
    typed_tp: u64,
    /// Detection-FP predicted kinds (preds overlapping no GT). Includes the
    /// carve-out-confirmed ones (also listed in `confirmed`).
    fp_kinds: Vec<String>,
    /// Carve-out: strong-validator FPs that passed their validator.
    confirmed: Vec<String>,
    unclassified: Vec<String>,
    /// `Some(msg)` if the `/v1/redact` request failed — the row's GTs all count
    /// as FN. The message is surfaced (not silenced) so a down/misconfigured
    /// proxy is debuggable.
    error: Option<String>,
}

/// Build a `RowOutcome` for an errored request: all GTs become FN, no preds.
fn error_outcome(masks: &[MaskSpan], msg: String) -> RowOutcome {
    let gts = masks
        .iter()
        .map(|m| GtResult {
            label: m.label.clone(),
            bucket: bucket_of(&m.label),
            det_hit: false,
            typed_hit: false,
        })
        .collect();
    RowOutcome {
        gts,
        preds_total: 0,
        det_tp: 0,
        typed_tp: 0,
        fp_kinds: Vec::new(),
        confirmed: Vec::new(),
        unclassified: Vec::new(),
        error: Some(msg),
    }
}

/// Score one row: recover predicted spans, resolve GT spans, compute detection
/// and typed TP/FP/FN plus the precision carve-out.
fn score_row(original: &str, redacted: &str, masks: &[MaskSpan]) -> RowOutcome {
    let orig_chars: Vec<char> = original.chars().collect();
    let preds = recover_spans(original, redacted);

    let gts: Vec<((usize, usize), &MaskSpan)> = masks
        .iter()
        .map(|m| (resolve_gt(original, &orig_chars, m), m))
        .collect();

    // Per-GT recall.
    let mut gt_results = Vec::with_capacity(gts.len());
    let mut unclassified = Vec::new();
    for (gspan, m) in &gts {
        let bucket = bucket_of(&m.label);
        if bucket == Bucket::Unclassified {
            unclassified.push(m.label.clone());
        }
        let mut det_hit = false;
        let mut typed_hit = false;
        for (ps, pe, pk) in &preds {
            if spans_overlap((*ps, *pe), *gspan) {
                det_hit = true;
                if typed_match(&m.label, pk) {
                    typed_hit = true;
                    break;
                }
            }
        }
        gt_results.push(GtResult {
            label: m.label.clone(),
            bucket,
            det_hit,
            typed_hit,
        });
    }

    // Per-pred precision.
    let mut det_tp = 0u64;
    let mut typed_tp = 0u64;
    let mut fp_kinds = Vec::new();
    let mut confirmed = Vec::new();
    for (ps, pe, pk) in &preds {
        let mut overlaps_any = false;
        let mut typed_ok = false;
        for (gspan, m) in &gts {
            if spans_overlap((*ps, *pe), *gspan) {
                overlaps_any = true;
                if typed_match(&m.label, pk) {
                    typed_ok = true;
                }
            }
        }
        if overlaps_any {
            det_tp += 1;
            if typed_ok {
                typed_tp += 1;
            }
        } else {
            // Detection false positive — apply the strong-validator carve-out.
            fp_kinds.push(pk.clone());
            let value: String = orig_chars
                [(*ps).min(orig_chars.len())..(*pe).min(orig_chars.len())]
                .iter()
                .collect();
            if strong_validator(pk, &value) == Some(true) {
                confirmed.push(pk.clone());
            }
        }
    }

    RowOutcome {
        gts: gt_results,
        preds_total: preds.len() as u64,
        det_tp,
        typed_tp,
        fp_kinds,
        confirmed,
        unclassified,
        error: None,
    }
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CatStat {
    gt: u64,
    det_hits: u64,
    typed_hits: u64,
    bucket: Option<Bucket>,
}

#[derive(Default)]
struct Aggregate {
    rows: u64,
    error_rows: u64,
    parse_errors: u64,
    // Pooled (micro) counts.
    total_preds: u64,
    det_tp: u64,
    typed_tp: u64,
    total_gt: u64,
    det_gt_hits: u64,
    typed_gt_hits: u64,
    confirmed_unannotated: u64,
    // Supported-only GT (Exact + KeywordGated buckets).
    sup_gt: u64,
    sup_det_hits: u64,
    sup_typed_hits: u64,
    per_cat: BTreeMap<String, CatStat>,
    fp_by_kind: BTreeMap<String, u64>,
    confirmed_by_kind: BTreeMap<String, u64>,
    unclassified_labels: BTreeMap<String, u64>,
    /// Request-error messages → count, so failures are debuggable instead of
    /// hidden behind a bare `errors=N`.
    errors_by_msg: BTreeMap<String, u64>,
}

impl Aggregate {
    fn add(&mut self, o: RowOutcome) {
        self.rows += 1;
        if let Some(msg) = &o.error {
            self.error_rows += 1;
            // Surface the first failure immediately — a down proxy shouldn't
            // require waiting for all 300k rows to learn why nothing matched.
            if self.errors_by_msg.is_empty() {
                eprintln!("warning: first request error: {msg}");
            }
            *self.errors_by_msg.entry(msg.clone()).or_default() += 1;
        }
        self.total_preds += o.preds_total;
        self.det_tp += o.det_tp;
        self.typed_tp += o.typed_tp;
        self.confirmed_unannotated += o.confirmed.len() as u64;

        for g in &o.gts {
            self.total_gt += 1;
            if g.det_hit {
                self.det_gt_hits += 1;
            }
            if g.typed_hit {
                self.typed_gt_hits += 1;
            }
            if matches!(g.bucket, Bucket::Exact | Bucket::KeywordGated) {
                self.sup_gt += 1;
                if g.det_hit {
                    self.sup_det_hits += 1;
                }
                if g.typed_hit {
                    self.sup_typed_hits += 1;
                }
            }
            let cat = self.per_cat.entry(g.label.clone()).or_default();
            cat.gt += 1;
            cat.bucket = Some(g.bucket);
            if g.det_hit {
                cat.det_hits += 1;
            }
            if g.typed_hit {
                cat.typed_hits += 1;
            }
        }
        for k in o.fp_kinds {
            *self.fp_by_kind.entry(k).or_default() += 1;
        }
        for k in o.confirmed {
            *self.confirmed_by_kind.entry(k).or_default() += 1;
        }
        for l in o.unclassified {
            *self.unclassified_labels.entry(l).or_default() += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics helpers
// ---------------------------------------------------------------------------

fn ratio(num: u64, den: u64) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

fn f1(p: f64, r: f64) -> f64 {
    if p + r == 0.0 {
        0.0
    } else {
        2.0 * p * r / (p + r)
    }
}

// ---------------------------------------------------------------------------
// Enforcement floors (report-only until baselines are measured)
// ---------------------------------------------------------------------------

/// Committed per-category **detection-recall** floors. `ENFORCE=1` fails the run
/// when a category drops below its floor. Empty until a baseline is measured
/// against the dataset — add entries (e.g. `("EMAIL", 0.95)`) once numbers are
/// known, so the eval can serve as a future CI gate.
const FLOORS: &[(&str, f64)] = &[];

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

fn bucket_tag(b: Bucket) -> &'static str {
    match b {
        Bucket::Exact => "exact",
        Bucket::KeywordGated => "gated",
        Bucket::KnownGap => "gap",
        Bucket::Unclassified => "unclassified",
    }
}

fn report(agg: &Aggregate, cfg: &Config) -> bool {
    println!("\n=== AI4Privacy effectiveness eval ===");
    println!(
        "rows={} (errors={}, parse_errors={}), preds={}, gt_spans={}",
        agg.rows, agg.error_rows, agg.parse_errors, agg.total_preds, agg.total_gt
    );

    // Request-error breakdown — surfaced, not silenced. A high error count with
    // a "Connection refused" message almost always means the proxy/API isn't
    // up (start it with `docker/ctl start`).
    if !agg.errors_by_msg.is_empty() {
        let mut msgs: Vec<(&String, &u64)> = agg.errors_by_msg.iter().collect();
        msgs.sort_by(|a, b| b.1.cmp(a.1));
        println!("\n--- request errors (all rows counted as false negatives) ---");
        for (msg, n) in msgs.iter().take(10) {
            println!("  {n:>7} × {msg}");
        }
        if msgs.len() > 10 {
            println!("  … and {} more distinct error message(s)", msgs.len() - 10);
        }
        if agg.error_rows == agg.rows {
            println!(
                "  NOTE: every request failed — is the proxy API running at the configured \
                 API_URL? Start it with `docker/ctl start`."
            );
        }
    }

    // Per-category table.
    println!(
        "\n{:<22} {:>5} {:>7} {:>8} {:>8}",
        "category", "n", "bucket", "det R", "typed R"
    );
    println!("{}", "-".repeat(54));
    for (label, c) in &agg.per_cat {
        let bucket = c.bucket.unwrap_or(Bucket::Unclassified);
        println!(
            "{:<22} {:>5} {:>7} {:>7.1}% {:>7.1}%",
            label,
            c.gt,
            bucket_tag(bucket),
            ratio(c.det_hits, c.gt) * 100.0,
            ratio(c.typed_hits, c.gt) * 100.0,
        );
    }

    // Overall (micro) — detection & typed, raw vs adjusted precision.
    let det_fp: u64 = agg.fp_by_kind.values().sum();
    let det_p_raw = ratio(agg.det_tp, agg.det_tp + det_fp);
    let adj_den = agg.total_preds.saturating_sub(agg.confirmed_unannotated);
    let det_p_adj = ratio(agg.det_tp, adj_den);
    let det_r = ratio(agg.det_gt_hits, agg.total_gt);
    let typed_p_raw = ratio(agg.typed_tp, agg.total_preds);
    let typed_p_adj = ratio(agg.typed_tp, adj_den);
    let typed_r = ratio(agg.typed_gt_hits, agg.total_gt);

    println!("\n--- Overall (micro, all categories) ---");
    println!(
        "detection  P_raw={:.3} P_adj={:.3}  R={:.3}  F1_raw={:.3}",
        det_p_raw,
        det_p_adj,
        det_r,
        f1(det_p_raw, det_r),
    );
    println!(
        "typed      P_raw={:.3} P_adj={:.3}  R={:.3}  F1_raw={:.3}",
        typed_p_raw,
        typed_p_adj,
        typed_r,
        f1(typed_p_raw, typed_r),
    );

    // Supported-only recall (Exact + KeywordGated GTs).
    println!("\n--- Overall (supported categories only) ---");
    println!(
        "detection  R={:.3}   typed  R={:.3}   (gt_spans={})",
        ratio(agg.sup_det_hits, agg.sup_gt),
        ratio(agg.sup_typed_hits, agg.sup_gt),
        agg.sup_gt,
    );

    // Macro recall over scored categories.
    let scored: Vec<&CatStat> = agg
        .per_cat
        .values()
        .filter(|c| matches!(c.bucket, Some(Bucket::Exact) | Some(Bucket::KeywordGated)))
        .collect();
    if !scored.is_empty() {
        let macro_det: f64 =
            scored.iter().map(|c| ratio(c.det_hits, c.gt)).sum::<f64>() / scored.len() as f64;
        let macro_typed: f64 = scored
            .iter()
            .map(|c| ratio(c.typed_hits, c.gt))
            .sum::<f64>()
            / scored.len() as f64;
        println!(
            "\nMacro recall (scored categories): detection={:.3}  typed={:.3}",
            macro_det, macro_typed
        );
    }

    // Confirmed-unannotated bucket (precision carve-out transparency).
    println!("\n--- confirmed_unannotated (validator-confirmed FPs, unscored) ---");
    if agg.confirmed_by_kind.is_empty() {
        println!("(none)");
    } else {
        for (k, n) in &agg.confirmed_by_kind {
            println!("  {k:<20} {n}");
        }
        println!("  total: {}", agg.confirmed_unannotated);
    }

    // Per-predicted-kind FP breakdown.
    println!("\n--- false positives by predicted kind (detection) ---");
    if agg.fp_by_kind.is_empty() {
        println!("(none)");
    } else {
        for (k, n) in &agg.fp_by_kind {
            let conf = agg.confirmed_by_kind.get(k).copied().unwrap_or(0);
            if conf > 0 {
                println!("  {k:<20} {n}  (of which {conf} validator-confirmed)");
            } else {
                println!("  {k:<20} {n}");
            }
        }
    }

    // Uncovered-gap list.
    let mut gaps: Vec<(&String, &CatStat)> = agg
        .per_cat
        .iter()
        .filter(|(_, c)| c.bucket == Some(Bucket::KnownGap))
        .collect();
    gaps.sort_by(|a, b| b.1.gt.cmp(&a.1.gt));
    println!("\n--- uncovered gaps (no Voidwall detector) ---");
    if gaps.is_empty() {
        println!("(none present in this dataset slice)");
    } else {
        for (label, c) in gaps {
            println!(
                "  {:<20} n={:<6} incidental det R={:.1}%",
                label,
                c.gt,
                ratio(c.det_hits, c.gt) * 100.0
            );
        }
    }

    // Unclassified labels — surfaced prominently.
    if !agg.unclassified_labels.is_empty() {
        println!("\n!!! UNCLASSIFIED dataset labels (update the mapping table) !!!");
        for (l, n) in &agg.unclassified_labels {
            println!("  {l:<20} n={n}");
        }
    }

    // Enforcement.
    enforce(agg, cfg)
}

/// Returns `true` if enforcement passed (or is disabled / has no floors).
// `FLOORS` is intentionally empty until baselines are measured; the emptiness
// check is the whole point, so silence the const-is-empty lint here.
#[allow(clippy::const_is_empty)]
fn enforce(agg: &Aggregate, cfg: &Config) -> bool {
    if !cfg.enforce {
        return true;
    }
    println!("\n--- ENFORCE: committed per-category detection-recall floors ---");
    if FLOORS.is_empty() {
        println!("(no floors committed yet — report-only; passing)");
        return true;
    }
    let mut ok = true;
    for (label, floor) in FLOORS {
        let r = agg
            .per_cat
            .get(*label)
            .map(|c| ratio(c.det_hits, c.gt))
            .unwrap_or(0.0);
        let status = if r + 1e-9 >= *floor { "ok" } else { "BREACH" };
        if status == "BREACH" {
            ok = false;
        }
        println!("  {label:<22} R={r:.3} floor={floor:.3} [{status}]");
    }
    ok
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// Render an error with its full source chain. `reqwest`'s top-level `Display`
/// is generic ("error sending request for url …"); the root cause ("Connection
/// refused") only lives in `source()`, so flatten the chain to keep failures
/// debuggable.
fn chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut src = err.source();
    while let Some(e) = src {
        out.push_str(": ");
        out.push_str(&e.to_string());
        src = e.source();
    }
    out
}

async fn redact(client: &reqwest::Client, api_url: &str, text: &str) -> Result<String, String> {
    let resp = client
        .post(format!("{api_url}/v1/redact"))
        .header("content-type", "text/plain")
        .body(text.to_string())
        .send()
        .await
        .map_err(|e| chain(&e))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    resp.text().await.map_err(|e| chain(&e))
}

#[tokio::main]
async fn main() {
    let cfg = Config::from_env();

    let files = match dataset_files(&cfg.dataset) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    eprintln!(
        "dataset: {} file(s) under {} | api={} | concurrency={}{}{}",
        files.len(),
        cfg.dataset.display(),
        cfg.api_url,
        cfg.concurrency,
        cfg.lang
            .as_deref()
            .map(|l| format!(" | lang={l}"))
            .unwrap_or_default(),
        cfg.max_rows
            .map(|m| format!(" | max_rows={m}"))
            .unwrap_or_default(),
    );

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(cfg.concurrency)
        .build()
        .expect("build reqwest client");
    let client = Arc::new(client);
    let api_url = Arc::new(cfg.api_url.clone());
    let sem = Arc::new(Semaphore::new(cfg.concurrency));

    let mut agg = Aggregate::default();
    let mut set: JoinSet<RowOutcome> = JoinSet::new();
    let mut seen: u64 = 0;

    'outer: for file in &files {
        let f = match File::open(file) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("warning: cannot open {}: {e}", file.display());
                continue;
            }
        };
        for line in BufReader::new(f).lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("warning: read error in {}: {e}", file.display());
                    break;
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let row: Row = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(_) => {
                    agg.parse_errors += 1;
                    continue;
                }
            };
            if let Some(filter) = &cfg.lang
                && !lang_matches(filter, row.language.as_deref())
            {
                continue;
            }
            if let Some(max) = cfg.max_rows
                && seen >= max
            {
                break 'outer;
            }
            seen += 1;

            let permit = sem.clone().acquire_owned().await.unwrap();
            let client = client.clone();
            let api_url = api_url.clone();
            set.spawn(async move {
                let _permit = permit;
                let Row {
                    source_text,
                    privacy_mask,
                    ..
                } = row;
                match redact(&client, &api_url, &source_text).await {
                    Ok(redacted) => score_row(&source_text, &redacted, &privacy_mask),
                    Err(e) => error_outcome(&privacy_mask, e),
                }
            });

            // Drain completed tasks without blocking to bound memory.
            while let Some(done) = set.try_join_next() {
                if let Ok(o) = done {
                    agg.add(o);
                }
            }
        }
    }

    while let Some(done) = set.join_next().await {
        if let Ok(o) = done {
            agg.add(o);
        }
    }

    if agg.rows == 0 {
        eprintln!("error: no rows processed (empty dataset, or LANG filtered everything out)");
        std::process::exit(2);
    }

    let passed = report(&agg, &cfg);
    if cfg.enforce && !passed {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    // --- recover_spans ---------------------------------------------------

    #[test]
    fn recover_single_span() {
        let orig = "Email me at john@x.com please";
        let red = "Email me at [EMAIL] please";
        let spans = recover_spans(orig, red);
        assert_eq!(spans.len(), 1);
        let (s, e, k) = &spans[0];
        assert_eq!(k, "EMAIL");
        let got: String = orig.chars().skip(*s).take(*e - *s).collect();
        assert_eq!(got, "john@x.com");
    }

    #[test]
    fn recover_multiple_spans() {
        let orig = "Call 555-111-2222 or mail a@b.com now";
        let red = "Call [US_PHONE_NUMBER] or mail [EMAIL] now";
        let spans = recover_spans(orig, red);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].2, "US_PHONE_NUMBER");
        assert_eq!(spans[1].2, "EMAIL");
        let p: String = orig
            .chars()
            .skip(spans[0].0)
            .take(spans[0].1 - spans[0].0)
            .collect();
        assert_eq!(p, "555-111-2222");
        let m: String = orig
            .chars()
            .skip(spans[1].0)
            .take(spans[1].1 - spans[1].0)
            .collect();
        assert_eq!(m, "a@b.com");
    }

    #[test]
    fn recover_leading_span() {
        let orig = "john@x.com is my email";
        let red = "[EMAIL] is my email";
        let spans = recover_spans(orig, red);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].0, 0);
        let got: String = orig.chars().take(spans[0].1).collect();
        assert_eq!(got, "john@x.com");
    }

    #[test]
    fn recover_trailing_span() {
        let orig = "my email is john@x.com";
        let red = "my email is [EMAIL]";
        let spans = recover_spans(orig, red);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].1, orig.chars().count());
        let got: String = orig.chars().skip(spans[0].0).collect();
        assert_eq!(got, "john@x.com");
    }

    #[test]
    fn recover_unicode_span() {
        // Multibyte chars before and inside the span exercise char-offset math.
        let orig = "Café notes: señor José Ñoño lives here";
        let red = "Café notes: señor [PERSON_NAME] lives here";
        let spans = recover_spans(orig, red);
        assert_eq!(spans.len(), 1);
        let got: String = orig
            .chars()
            .skip(spans[0].0)
            .take(spans[0].1 - spans[0].0)
            .collect();
        assert_eq!(got, "José Ñoño");
    }

    #[test]
    fn recover_adjacent_tokens_collapse_first() {
        // Adjacent tokens: the first collapses to a zero-length span (documented
        // heuristic limit), the second recovers normally.
        let orig = "ABXY";
        let red = "[A][B]XY";
        let spans = recover_spans(orig, red);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].0, spans[0].1); // zero-length
        assert_eq!(spans[0].2, "A");
        assert_eq!(spans[1].2, "B");
    }

    #[test]
    fn recover_no_tokens() {
        assert!(recover_spans("nothing here", "nothing here").is_empty());
    }

    // --- span overlap ----------------------------------------------------

    #[test_case((0, 5), (3, 8), true ; "partial")]
    #[test_case((0, 5), (5, 8), false ; "touching")]
    #[test_case((0, 5), (1, 4), true ; "contained")]
    #[test_case((2, 2), (0, 5), true ; "zero len inside")]
    #[test_case((10, 12), (0, 5), false ; "disjoint")]
    fn span_overlap(a: (usize, usize), b: (usize, usize), expect: bool) {
        assert_eq!(spans_overlap(a, b), expect);
    }

    // --- category lookup -------------------------------------------------

    #[test_case("EMAIL", Bucket::Exact)]
    #[test_case("GIVENNAME1", Bucket::Exact)]
    #[test_case("BOD", Bucket::Exact)]
    #[test_case("TEL", Bucket::KeywordGated)]
    #[test_case("POSTCODE", Bucket::KeywordGated)]
    #[test_case("SOCIALNUMBER", Bucket::KeywordGated)]
    #[test_case("PASS", Bucket::KnownGap)]
    #[test_case("TITLE", Bucket::KnownGap)]
    #[test_case("SOMETHINGNEW", Bucket::Unclassified)]
    fn category_lookup(label: &str, expect: Bucket) {
        assert_eq!(bucket_of(label), expect);
    }

    #[test_case("EMAIL", "EMAIL", true)]
    #[test_case("EMAIL", "IBAN", false)]
    #[test_case("IP", "IP_ADDRESS", true)]
    #[test_case("BOD", "DATE_OF_BIRTH", true)]
    #[test_case("TEL", "GB_PHONE_NUMBER", true)]
    #[test_case("TEL", "PHONE_NUMBER", true)]
    #[test_case("POSTCODE", "GB_POSTCODE", true)]
    #[test_case("POSTCODE", "FR_POSTAL_CODE", true)]
    #[test_case("STREET", "GB_ADDRESS", true)]
    #[test_case("LASTNAME1", "PERSON_NAME", true)]
    #[test_case("PASSPORT", "DE_PASSPORT_NUMBER", true)]
    #[test_case("PASSPORT", "US_PASSPORT_NEW", true)]
    #[test_case("DRIVERLICENSE", "GB_DRIVING_LICENCE", true)]
    #[test_case("DRIVERLICENSE", "IE_DRIVER_NUMBER", true)]
    #[test_case("SOCIALNUMBER", "US_SSN", true)]
    #[test_case("IDCARD", "ES_DNI", true)]
    #[test_case("TITLE", "PERSON_NAME", false)]
    fn typed_match_table(label: &str, predicted: &str, expect: bool) {
        assert_eq!(typed_match(label, predicted), expect);
    }

    // --- GT offset fallback ----------------------------------------------

    #[test]
    fn gt_trusts_char_offsets() {
        let orig = "hello john@x.com world";
        let chars: Vec<char> = orig.chars().collect();
        let m = MaskSpan {
            label: "EMAIL".into(),
            start: 6,
            end: 16,
            value: "john@x.com".into(),
        };
        assert_eq!(resolve_gt(orig, &chars, &m), (6, 16));
    }

    #[test]
    fn gt_falls_back_to_substring_when_offsets_wrong() {
        let orig = "hello john@x.com world";
        let chars: Vec<char> = orig.chars().collect();
        // Bogus offsets — must recover by searching for `value`.
        let m = MaskSpan {
            label: "EMAIL".into(),
            start: 999,
            end: 1001,
            value: "john@x.com".into(),
        };
        assert_eq!(resolve_gt(orig, &chars, &m), (6, 16));
    }

    #[test]
    fn gt_byte_offset_guard_for_unicode() {
        let orig = "Café john@x.com"; // 'é' is 2 bytes, 1 char
        let chars: Vec<char> = orig.chars().collect();
        // Byte offsets of the email (é shifts bytes by 1 vs chars).
        let byte_start = orig.find("john@x.com").unwrap();
        let m = MaskSpan {
            label: "EMAIL".into(),
            start: byte_start,
            end: byte_start + "john@x.com".len(),
            value: "john@x.com".into(),
        };
        let (s, e) = resolve_gt(orig, &chars, &m);
        let got: String = chars[s..e].iter().collect();
        assert_eq!(got, "john@x.com");
    }

    // --- precision-band carve-out ----------------------------------------

    #[test]
    fn carveout_confirms_strong_validator_fp() {
        // A real email the dataset never annotated: a detection FP that the
        // validator confirms → re-classified as unscored (confirmed bucket),
        // not counted against precision.
        let orig = "Reach me at real@email.com anytime";
        let red = "Reach me at [EMAIL] anytime";
        let masks: Vec<MaskSpan> = vec![]; // nothing annotated
        let o = score_row(orig, red, &masks);
        assert_eq!(o.det_tp, 0);
        assert_eq!(o.fp_kinds, vec!["EMAIL".to_string()]);
        assert_eq!(o.confirmed, vec!["EMAIL".to_string()]);
    }

    #[test]
    fn carveout_skips_invalid_strong_validator_fp() {
        // A structurally invalid "email" stays a counted FP even though EMAIL is
        // a strong-validator kind — the validator rejects it.
        let orig = "token notatall here";
        let red = "token [EMAIL] here";
        let masks: Vec<MaskSpan> = vec![];
        let o = score_row(orig, red, &masks);
        assert_eq!(o.fp_kinds, vec!["EMAIL".to_string()]);
        assert!(o.confirmed.is_empty());
    }

    #[test]
    fn carveout_excludes_fuzzy_kind() {
        // PERSON_NAME has no strong validator: an unannotated catch stays a
        // counted FP, never carved out.
        let orig = "Hello Alice Smith there";
        let red = "Hello [PERSON_NAME] there";
        let masks: Vec<MaskSpan> = vec![];
        let o = score_row(orig, red, &masks);
        assert_eq!(o.fp_kinds, vec!["PERSON_NAME".to_string()]);
        assert!(o.confirmed.is_empty());
    }

    #[test]
    fn score_row_typed_and_detection_tp() {
        let orig = "Mail a@b.com today";
        let red = "Mail [EMAIL] today";
        let masks = vec![MaskSpan {
            label: "EMAIL".into(),
            start: 5,
            end: 12,
            value: "a@b.com".into(),
        }];
        let o = score_row(orig, red, &masks);
        assert_eq!(o.det_tp, 1);
        assert_eq!(o.typed_tp, 1);
        assert!(o.fp_kinds.is_empty());
        assert_eq!(o.gts.len(), 1);
        assert!(o.gts[0].det_hit && o.gts[0].typed_hit);
    }

    #[test]
    fn score_row_detection_hit_but_wrong_type() {
        // Overlaps the GT (detection TP) but the predicted kind is the wrong
        // family → typed miss.
        let orig = "Mail a@b.com today";
        let red = "Mail [IBAN] today";
        let masks = vec![MaskSpan {
            label: "EMAIL".into(),
            start: 5,
            end: 12,
            value: "a@b.com".into(),
        }];
        let o = score_row(orig, red, &masks);
        assert_eq!(o.det_tp, 1);
        assert_eq!(o.typed_tp, 0);
        assert!(o.gts[0].det_hit);
        assert!(!o.gts[0].typed_hit);
    }

    // --- validators ------------------------------------------------------

    #[test_case("4111111111111111", true ; "visa luhn ok")]
    #[test_case("4111111111111112", false ; "luhn bad")]
    fn luhn_check(s: &str, ok: bool) {
        assert_eq!(luhn(s), ok);
    }

    #[test_case("GB82WEST12345698765432", true ; "valid iban")]
    #[test_case("GB00WEST12345698765432", false ; "bad check")]
    fn iban_check(s: &str, ok: bool) {
        assert_eq!(valid_iban(s), ok);
    }

    #[test_case("a@b.com", true)]
    #[test_case("nope", false)]
    fn email_check(s: &str, ok: bool) {
        assert_eq!(valid_email(s), ok);
    }
}
