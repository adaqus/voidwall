use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::Arc;

use regex::Regex;
use serde::Deserialize;
use vectorscan_rs::{BlockDatabase, BlockScanner, Flag, Pattern, Scan};

use crate::detector::Detector;
use crate::keyword_context_detector::ARRAY_INDEX_RE;
use crate::normalize::decode_for_detection;
use crate::{ContextFragment, Country, PiiError, PiiKind, PiiMatch};

thread_local! {
    static USER_DETECTION_CACHE: RefCell<Option<(usize, BlockScanner<'static>)>>
        = const { RefCell::new(None) };
}

/// Separator allowed between keyword and value in keyword-context mode.
/// Matches the shape used by built-in keyword patterns.
const KEYWORD_SEPARATOR: &str = r"(?:\s+is\s+|[\s:.#/\-\x22=,\]]*?)";

/// Upper bound on lookback bytes when slicing the region for regex extraction
/// in keyword-context mode. Mirrors `KeywordContextDetector::MATCH_LOOKBACK`.
const MATCH_LOOKBACK: usize = 512;

fn default_country() -> Country {
    Country::International
}

/// A user-supplied PII definition.
///
/// Callers construct these programmatically or via their own config format
/// (e.g. TOML/YAML/JSON) using `serde`.
#[derive(Debug, Clone, Deserialize)]
pub struct UserPiiDefinition {
    /// Label reported on matches. Propagated to `PiiMatch::user_label`.
    pub label: String,
    /// Regex for the PII value. Must compile in both vectorscan and the `regex`
    /// crate. Avoid backreferences and lookaround (unsupported by vectorscan).
    pub pattern: String,
    /// Optional context keywords. When non-empty, a match requires one of the
    /// keywords to appear just before the pattern (with a permissive
    /// separator), and the reported span covers only the pattern, not the
    /// keyword.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Country scope. Entries whose country is not in the scanner's enabled
    /// country set are dropped at build time.
    #[serde(default = "default_country")]
    pub country: Country,
}

struct UserEntry {
    label: Arc<str>,
    /// Regex used to extract the span from the input.
    /// - No keywords: matches the value directly; whole match is the span.
    /// - With keywords: captures the value in group 1; only the group is the span.
    extract: Regex,
    has_keywords: bool,
}

pub struct UserDetector {
    entries: Vec<UserEntry>,
    detection_db: Option<Box<BlockDatabase>>,
    detection_prototype: Option<BlockScanner<'static>>,
}

impl UserDetector {
    pub fn new(
        defs: &[UserPiiDefinition],
        enabled_countries: &HashSet<Country>,
    ) -> Result<Self, PiiError> {
        let mut entries = Vec::new();
        let mut vs_patterns = Vec::new();

        for def in defs {
            if !enabled_countries.contains(&def.country) {
                continue;
            }
            if def.label.is_empty() {
                return Err(PiiError::InvalidConfiguration(
                    "user PII definition has empty label".into(),
                ));
            }
            if def.pattern.is_empty() {
                return Err(PiiError::InvalidConfiguration(format!(
                    "user PII definition '{}' has empty pattern",
                    def.label
                )));
            }

            let has_keywords = !def.keywords.is_empty();
            let (detection_expr, extract_expr) = if has_keywords {
                let kw_alt = def
                    .keywords
                    .iter()
                    .map(|k| regex::escape(k))
                    .collect::<Vec<_>>()
                    .join("|");
                let combined = format!(
                    "(?i)(?:{kw_alt}){KEYWORD_SEPARATOR}({pat})",
                    pat = def.pattern
                );
                (combined.clone(), combined)
            } else {
                (def.pattern.clone(), def.pattern.clone())
            };

            let extract = Regex::new(&extract_expr).map_err(PiiError::RegexCompilation)?;

            let id = entries.len() as u32;
            vs_patterns.push(Pattern::new(
                detection_expr.as_bytes().to_vec(),
                Flag::UTF8,
                Some(id),
            ));
            entries.push(UserEntry {
                label: Arc::<str>::from(def.label.as_str()),
                extract,
                has_keywords,
            });
        }

        if entries.is_empty() {
            return Ok(Self {
                entries,
                detection_db: None,
                detection_prototype: None,
            });
        }

        let detection_db = Box::new(
            BlockDatabase::new(vs_patterns)
                .map_err(|e| PiiError::HyperscanCompilation(format!("user detection db: {e}")))?,
        );
        let detection_prototype = {
            let scanner = BlockScanner::new(&detection_db).expect("scratch alloc");
            // SAFETY: Same pattern as the built-in detectors — the Box gives a
            // stable heap address, the detector owns both fields, and the
            // prototype is declared before the database so it is dropped first.
            unsafe { std::mem::transmute::<BlockScanner<'_>, BlockScanner<'static>>(scanner) }
        };

        Ok(Self {
            entries,
            detection_db: Some(detection_db),
            detection_prototype: Some(detection_prototype),
        })
    }

    fn with_detection_scanner<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&mut BlockScanner<'static>) -> R,
    {
        let db = self.detection_db.as_ref()?;
        let proto = self.detection_prototype.as_ref()?;
        let db_key = &**db as *const BlockDatabase as usize;
        Some(USER_DETECTION_CACHE.with(|cell| {
            let mut opt = cell.borrow_mut();
            if opt.as_ref().is_none_or(|(k, _)| *k != db_key) {
                *opt = Some((db_key, proto.clone()));
            }
            f(&mut opt.as_mut().unwrap().1)
        }))
    }

    fn region_start(input: &str, to: usize) -> usize {
        let mut start = to.saturating_sub(MATCH_LOOKBACK);
        while !input.is_char_boundary(start) {
            start += 1;
        }
        start
    }

    fn mark_on(&self, input: &str) -> Vec<PiiMatch> {
        let mut hits: Vec<(usize, usize)> = Vec::new();
        self.with_detection_scanner(|scanner| {
            let _ = scanner.scan(input.as_bytes(), |id, _from, to, _flags| {
                hits.push((id as usize, to as usize));
                Scan::Continue
            });
        });
        if hits.is_empty() {
            return Vec::new();
        }

        let mut results = Vec::new();
        let mut processed: HashSet<usize> = HashSet::new();
        for (idx, _to) in &hits {
            if !processed.insert(*idx) {
                continue;
            }
            let entry = &self.entries[*idx];
            if entry.has_keywords {
                for caps in entry.extract.captures_iter(input) {
                    if let Some(value_match) = caps.get(1) {
                        results.push(PiiMatch {
                            kind: PiiKind::Custom,
                            start: value_match.start(),
                            end: value_match.end(),
                            user_label: Some(entry.label.clone()),
                        });
                    }
                }
            } else {
                for m in entry.extract.find_iter(input) {
                    results.push(PiiMatch {
                        kind: PiiKind::Custom,
                        start: m.start(),
                        end: m.end(),
                        user_label: Some(entry.label.clone()),
                    });
                }
            }
        }

        // Dedup: same (start, end, label) can arise if vectorscan reports
        // multiple hits that all resolve to the same regex match.
        Self::sort_dedup(&mut results);
        results
    }

    fn sort_dedup(results: &mut Vec<PiiMatch>) {
        results.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then(a.end.cmp(&b.end))
                .then_with(|| a.label().cmp(b.label()))
        });
        results.dedup_by(|a, b| {
            a.start == b.start
                && a.end == b.end
                && a.user_label.as_deref() == b.user_label.as_deref()
        });
    }

    fn has_on(&self, input: &str) -> bool {
        let mut found = false;
        self.with_detection_scanner(|scanner| {
            let _ = scanner.scan(input.as_bytes(), |id, _from, to, _flags| {
                let entry = &self.entries[id as usize];
                let matched = if entry.has_keywords {
                    let start = Self::region_start(input, to as usize);
                    let region = &input[start..to as usize];
                    entry
                        .extract
                        .captures(region)
                        .and_then(|c| c.get(1))
                        .is_some()
                } else {
                    entry.extract.is_match(input)
                };
                if matched {
                    found = true;
                    Scan::Terminate
                } else {
                    Scan::Continue
                }
            });
        });
        found
    }
}

impl Detector for UserDetector {
    fn has_piis(&self, input: &str) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        match decode_for_detection(input) {
            Some((decoded, _)) => self.has_on(&decoded),
            None => self.has_on(input),
        }
    }

    fn mark_piis(&self, input: &str) -> Vec<PiiMatch> {
        if self.entries.is_empty() {
            return Vec::new();
        }
        match decode_for_detection(input) {
            Some((decoded, offset_map)) => self
                .mark_on(&decoded)
                .into_iter()
                .map(|m| PiiMatch {
                    kind: m.kind,
                    start: offset_map[m.start],
                    end: offset_map[m.end],
                    user_label: m.user_label,
                })
                .collect(),
            None => self.mark_on(input),
        }
    }

    fn mark_piis_structured(&self, fragments: &[ContextFragment<'_>]) -> Vec<PiiMatch> {
        if self.entries.is_empty() {
            return Vec::new();
        }
        let has_keywords = self.entries.iter().any(|e| e.has_keywords);
        let mut results = Vec::new();
        for f in fragments {
            // The value alone: a standalone entry, or a keyword entry whose
            // keyword sits in the value's own text.
            results.extend(self.mark_piis(f.value).into_iter().map(|m| PiiMatch {
                start: m.start + f.offset,
                end: m.end + f.offset,
                ..m
            }));
            if !has_keywords {
                continue;
            }

            // The key path as the keyword, as `KeywordContextDetector` does:
            // `user.employee_id` is tried as `user.employee_id: {value}` and
            // as `user: {value}`. Only a match inside the value counts.
            let stripped = ARRAY_INDEX_RE.replace_all(f.context, "");
            let segments: Vec<&str> = stripped.split('.').filter(|s| !s.is_empty()).collect();
            for n in (1..=segments.len()).rev() {
                let prefix = segments[..n].join(".");
                let value_start = prefix.len() + 2; // "{prefix}: "
                let value_end = value_start + f.value.len();
                let synthetic = format!("{prefix}: {}", f.value);
                for m in self.mark_piis(&synthetic) {
                    if m.start >= value_start && m.end <= value_end {
                        results.push(PiiMatch {
                            start: m.start - value_start + f.offset,
                            end: m.end - value_start + f.offset,
                            ..m
                        });
                    }
                }
            }
        }
        Self::sort_dedup(&mut results);
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    fn all_countries() -> HashSet<Country> {
        Country::all().iter().copied().collect()
    }

    fn make_detector(
        label: &str,
        pattern: &str,
        keywords: &[&str],
        country: Country,
    ) -> UserDetector {
        let def = UserPiiDefinition {
            label: label.into(),
            pattern: pattern.into(),
            keywords: keywords.iter().map(|s| (*s).into()).collect(),
            country,
        };
        UserDetector::new(&[def], &all_countries()).unwrap()
    }

    #[test]
    fn empty_definitions_produces_empty_detector() {
        let det = UserDetector::new(&[], &all_countries()).unwrap();
        assert!(!det.has_piis("anything goes here"));
        assert!(det.mark_piis("anything goes here").is_empty());
    }

    #[test_case(
        "EMPLOYEE_ID", r"EMP-\d{6}",
        "new hire EMP-123456 onboarded", "EMP-123456"
        ; "standalone digits suffix"
    )]
    #[test_case(
        "INTERNAL_TOKEN", r"TOK_[A-Z0-9]{8}",
        "token=TOK_ABCD1234 here", "TOK_ABCD1234"
        ; "standalone alnum suffix"
    )]
    #[test_case(
        "AWS_ROLE", r"arn:aws:iam::\d{12}:role/[A-Za-z0-9_-]+",
        "use arn:aws:iam::123456789012:role/MyRole for access",
        "arn:aws:iam::123456789012:role/MyRole"
        ; "standalone structured identifier"
    )]
    fn standalone_pattern_detects(label: &str, pattern: &str, input: &str, expected_value: &str) {
        let det = make_detector(label, pattern, &[], Country::International);
        assert!(det.has_piis(input));
        let matches = det.mark_piis(input);
        assert_eq!(matches.len(), 1, "{matches:?}");
        assert_eq!(matches[0].label(), label);
        assert_eq!(&input[matches[0].start..matches[0].end], expected_value);
    }

    #[test_case(
        "PROJECT_CODE", r"[A-Z]{3}-\d{3}",
        &["project code", "proj id"],
        "internal: project code ABC-123 confirmed", "ABC-123"
        ; "project code keyword long"
    )]
    #[test_case(
        "PROJECT_CODE", r"[A-Z]{3}-\d{3}",
        &["project code", "proj id"],
        "proj id: XYZ-789 shipped", "XYZ-789"
        ; "project code keyword short"
    )]
    #[test_case(
        "CUSTOMER_REF", r"\d{8}",
        &["customer ref", "cust id"],
        "customer ref = 12345678, verified", "12345678"
        ; "customer ref keyword equals separator"
    )]
    #[test_case(
        "INTERNAL", r"\d{4}",
        &["secret.key*"],
        "secret.key*: 1234", "1234"
        ; "keyword with regex metachars is escaped"
    )]
    fn keyword_mode_detects(
        label: &str,
        pattern: &str,
        keywords: &[&str],
        input: &str,
        expected_value: &str,
    ) {
        let det = make_detector(label, pattern, keywords, Country::International);
        let matches = det.mark_piis(input);
        assert_eq!(matches.len(), 1, "{matches:?}");
        assert_eq!(matches[0].label(), label);
        assert_eq!(&input[matches[0].start..matches[0].end], expected_value);
    }

    #[test_case(
        r"[A-Z]{3}-\d{3}", &["project code"],
        "bare string ABC-123 without context"
        ; "missing keyword"
    )]
    #[test_case(
        r"\d{4}", &["secret.key*"],
        "secretXkeyY: 1234"
        ; "keyword metachar does not match literally"
    )]
    #[test_case(
        r"[A-Z]{3}-\d{3}", &["project code"],
        "projcode: ABC-123"
        ; "keyword word-prefix not matching phrase"
    )]
    fn keyword_mode_does_not_detect(pattern: &str, keywords: &[&str], input: &str) {
        let det = make_detector("X", pattern, keywords, Country::International);
        assert!(!det.has_piis(input), "should not detect in: {input}");
        assert!(det.mark_piis(input).is_empty());
    }

    #[test_case(
        r"EMP-\d{6}", &[],
        "messages[0].content", "staff EMP-123456 here", "EMP-123456"
        ; "standalone in a value"
    )]
    #[test_case(
        r"\d{6}", &["badge"],
        "messages[0].content", "my badge: 123456", "123456"
        ; "keyword in the value text"
    )]
    #[test_case(
        r"\d{6}", &["badge"],
        "badge", "123456", "123456"
        ; "keyword is the key"
    )]
    #[test_case(
        r"\d{6}", &["badge"],
        "user.badge", "123456", "123456"
        ; "keyword is the last key segment"
    )]
    #[test_case(
        r"\d{6}", &["badge"],
        "badge.number", "123456", "123456"
        ; "keyword is an earlier key segment"
    )]
    #[test_case(
        r"\d{6}", &["badge"],
        "badge[2]", "123456", "123456"
        ; "array index is stripped from the key"
    )]
    #[test_case(
        r"EMP-\d{6}", &[],
        "id", "EMP%2D123456", "EMP%2D123456"
        ; "url-encoded value spans the original bytes"
    )]
    fn structured_detects(
        pattern: &str,
        keywords: &[&str],
        context: &str,
        value: &str,
        expected_value: &str,
    ) {
        // The value sits after a 7-byte document prefix, so a span that is
        // not shifted by the offset reads the wrong bytes.
        let document = format!("{{\"k\": \"{value}\"}}");
        let offset = 7;
        let det = make_detector("LBL", pattern, keywords, Country::International);
        let matches = det.mark_piis_structured(&[ContextFragment {
            context,
            value,
            offset,
        }]);
        assert_eq!(matches.len(), 1, "{matches:?}");
        assert_eq!(matches[0].label(), "LBL");
        assert_eq!(&document[matches[0].start..matches[0].end], expected_value);
    }

    #[test_case("employee", "123456" ; "key is not a keyword")]
    #[test_case("badges", "123456" ; "keyword is a prefix of the key")]
    #[test_case("", "123456" ; "empty key")]
    #[test_case("badge_number", "123456" ; "keyword is not a whole key segment")]
    fn structured_keyword_entry_does_not_detect(context: &str, value: &str) {
        let det = make_detector("LBL", r"\d{6}", &["badge"], Country::International);
        let matches = det.mark_piis_structured(&[ContextFragment {
            context,
            value,
            offset: 0,
        }]);
        assert!(matches.is_empty(), "{matches:?}");
    }

    #[test]
    fn structured_reports_one_match_per_span() {
        // The keyword is both the key and in the value text, so the value
        // pass and every key prefix find the same span.
        let det = make_detector("LBL", r"\d{6}", &["badge"], Country::International);
        let value = "badge 123456";
        let matches = det.mark_piis_structured(&[ContextFragment {
            context: "badge.badge",
            value,
            offset: 0,
        }]);
        assert_eq!(matches.len(), 1, "{matches:?}");
        assert_eq!(&value[matches[0].start..matches[0].end], "123456");
    }

    #[test]
    fn structured_spans_are_document_absolute_across_fragments() {
        let document = r#"{"a":"EMP-111111","b":"EMP-222222"}"#;
        let det = make_detector("LBL", r"EMP-\d{6}", &[], Country::International);
        let matches = det.mark_piis_structured(&[
            ContextFragment {
                context: "a",
                value: "EMP-111111",
                offset: 6,
            },
            ContextFragment {
                context: "b",
                value: "EMP-222222",
                offset: 23,
            },
        ]);
        let found: Vec<&str> = matches.iter().map(|m| &document[m.start..m.end]).collect();
        assert_eq!(found, ["EMP-111111", "EMP-222222"]);
    }

    #[test_case(Country::Us, &[Country::Fr], false ; "us entry excluded when only fr enabled")]
    #[test_case(Country::Fr, &[Country::Fr], true ; "fr entry included when fr enabled")]
    #[test_case(Country::International, &[Country::Fr], false ; "international entry excluded when not enabled")]
    #[test_case(Country::Us, &[Country::Us, Country::International], true ; "us entry included with us enabled")]
    fn country_filter(entry_country: Country, enabled: &[Country], should_detect: bool) {
        let def = UserPiiDefinition {
            label: "VAL".into(),
            pattern: r"VAL-\d{4}".into(),
            keywords: Vec::new(),
            country: entry_country,
        };
        let enabled_set: HashSet<Country> = enabled.iter().copied().collect();
        let det = UserDetector::new(&[def], &enabled_set).unwrap();
        assert_eq!(det.has_piis("see VAL-1234 here"), should_detect);
    }

    #[test_case("LBL", "[unterminated", &[] ; "invalid regex")]
    #[test_case("", r"\d+", &[] ; "empty label")]
    #[test_case("LBL", "", &[] ; "empty pattern")]
    fn rejects_invalid_definition(label: &str, pattern: &str, keywords: &[&str]) {
        let def = UserPiiDefinition {
            label: label.into(),
            pattern: pattern.into(),
            keywords: keywords.iter().map(|s| (*s).into()).collect(),
            country: Country::International,
        };
        assert!(UserDetector::new(&[def], &all_countries()).is_err());
    }
}
