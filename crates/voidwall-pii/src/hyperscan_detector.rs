use std::cell::RefCell;
use std::collections::HashSet;

use regex::Regex;
use vectorscan_rs::{BlockDatabase, BlockScanner, Flag, Pattern, Scan};

use crate::detector::Detector;
use crate::normalize::decode_for_detection;
use crate::validators::*;
use crate::{ContextFragment, PiiError, PiiKind, PiiMatch};

thread_local! {
    static V_DETECTION_CACHE: RefCell<Option<(usize, BlockScanner<'static>)>>
        = const { RefCell::new(None) };
}

struct PatternEntry {
    kind: PiiKind,
    validator: fn(&str) -> bool,
    /// Regex fallback for patterns that can't use SOM_LEFTMOST (e.g. email with UCP).
    /// When set, this pattern is excluded from the extraction DB and matched via regex instead.
    extraction_regex: Option<Regex>,
}

pub struct HyperscanDetector {
    entries: Vec<PatternEntry>,
    // SAFETY: Prototypes are declared before databases so they are dropped first.
    // Cloned into thread-local cache on first use per thread via hs_clone_scratch.
    extraction_prototype: Option<BlockScanner<'static>>,
    // Box'd for stable heap address — the &BlockDatabase refs inside the
    // prototypes (and all clones) point into these Boxes.
    extraction_db: Option<Box<BlockDatabase>>,
}

struct PatternDef {
    kind: PiiKind,
    expr: &'static str,
    validator: fn(&str) -> bool,
    needs_ucp: bool,
    /// If true, this pattern can't use SOM_LEFTMOST (too large with UCP).
    /// Falls back to regex extraction instead.
    som_fallback: bool,
}

fn build_patterns(enabled: &HashSet<PiiKind>) -> Vec<PatternDef> {
    let all: Vec<PatternDef> = vec![
        PatternDef {
            kind: PiiKind::Email,
            expr: r"[\w._%+-]+@[\w.-]+\.\w[\w-]*\w",
            validator: always_valid,
            needs_ucp: true,
            som_fallback: true,
        },
        PatternDef {
            kind: PiiKind::CreditCard,
            expr: r"\b(?:[0-9]{4}[-\s]?){3,4}[0-9]{1,4}\b",
            som_fallback: false,
            validator: luhn_check,
            needs_ucp: false,
        },
        PatternDef {
            kind: PiiKind::UsSsn,
            expr: r"\b\d{3}[-. ]\d{2}[-. ]\d{4}\b",
            som_fallback: false,
            validator: ssn_check,
            needs_ucp: false,
        },
        PatternDef {
            kind: PiiKind::GbNino,
            expr: r"\b[A-Za-z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-Da-d]\b",
            som_fallback: false,
            validator: nino_check,
            needs_ucp: false,
        },
        PatternDef {
            kind: PiiKind::Iban,
            expr: r"\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}(?:\s?[A-Z0-9]{4}){1,7}(?:\s?[A-Z0-9]{1,4})?\b",
            som_fallback: false,
            validator: iban_check,
            needs_ucp: false,
        },
        // Dutch BTW (VAT) number: NL + 9 digits + B + 2-digit sub-number.
        // Structurally unique, so detected without a keyword. The validator
        // enforces the sub-number range and case-insensitive letters.
        PatternDef {
            kind: PiiKind::NlBtw,
            expr: r"\b[Nn][Ll]\d{9}[Bb]\d{2}\b",
            som_fallback: false,
            validator: nl_btw_check,
            needs_ucp: false,
        },
        // Italian codice fiscale: 16-char structural mask (6 letters, 2 digits,
        // letter, 2 digits, letter, 3 digits, check letter). Structurally unique
        // and checksum-validated, so detected without a keyword.
        //
        // Detection is uppercase-only by design: codice fiscale is officially
        // rendered in uppercase, and a case-insensitive `[A-Za-z]{6}` prefix is a
        // hot, unanchored run of the most common character class — it forces
        // vectorscan to track a candidate at nearly every byte of clean text
        // (~13% throughput loss). Uppercase 6-letter runs are rare in prose, so
        // `[A-Z]{6}` stays cold. Lowercase CF is recovered by the keyword-context
        // detector when a "codice fiscale"/"CF" label is present.
        PatternDef {
            kind: PiiKind::ItCodiceFiscale,
            expr: r"\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b",
            som_fallback: false,
            validator: it_codice_fiscale_check,
            needs_ucp: false,
        },
        // Spanish DNI/NIF: 8 digits + control letter (mod-23), e.g. 12345678Z.
        // Structurally distinctive and checksum-validated, so detected without
        // a keyword. Uppercase-only letter keeps the pattern from matching the
        // letter half of running prose; the mod-23 validator filters the rest.
        PatternDef {
            kind: PiiKind::EsDni,
            expr: r"\b\d{8}[A-Z]\b",
            som_fallback: false,
            validator: es_dni_check,
            needs_ucp: false,
        },
        // Spanish NIE (foreigner ID): X/Y/Z + 7 digits + control letter,
        // e.g. X1234567L. The X/Y/Z literal prefix anchors detection; mod-23
        // checksum validates.
        PatternDef {
            kind: PiiKind::EsNie,
            expr: r"\b[XYZ]\d{7}[A-Z]\b",
            som_fallback: false,
            validator: es_nie_check,
            needs_ucp: false,
        },
        // Spanish CIF (legal-entity tax ID): org-type letter + 7 digits +
        // control char, e.g. A28015865. The restricted org-letter prefix plus
        // the weighted control checksum keep false positives low.
        PatternDef {
            kind: PiiKind::EsCif,
            expr: r"\b[ABCDEFGHJNPQRSUVW]\d{7}[0-9A-J]\b",
            som_fallback: false,
            validator: es_cif_check,
            needs_ucp: false,
        },
        // Polish NIP in its EU-VAT form: PL + 10 digits, e.g. PL7740001454.
        // The PL literal prefix anchors detection (cf. NlBtw); the weighted
        // mod-11 checksum validates. Bare 10-digit NIPs are keyword-gated in
        // the keyword-context detector. A Polish IBAN (PL + 26 digits) cannot
        // match — the trailing \b fails after 10 digits.
        PatternDef {
            kind: PiiKind::PlNip,
            expr: r"\b[Pp][Ll]\d{10}\b",
            som_fallback: false,
            validator: pl_nip_check,
            needs_ucp: false,
        },
        PatternDef {
            kind: PiiKind::IpAddress,
            expr: r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            som_fallback: false,
            validator: ip_check,
            needs_ucp: false,
        },
        PatternDef {
            kind: PiiKind::IpAddress,
            expr: r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|::",
            som_fallback: false,
            validator: always_valid,
            needs_ucp: false,
        },
        PatternDef {
            kind: PiiKind::UsItin,
            expr: r"\b9\d{2}-\d{2}-\d{4}\b",
            som_fallback: false,
            validator: itin_check,
            needs_ucp: false,
        },
        PatternDef {
            kind: PiiKind::CaSin,
            expr: r"\b\d{3}[-\s]\d{3}[-\s]\d{3}\b",
            som_fallback: false,
            validator: sin_check,
            needs_ucp: false,
        },
        PatternDef {
            kind: PiiKind::IePpsn,
            expr: r"\b\d{7}[A-Za-z]{1,2}\b",
            som_fallback: false,
            validator: ppsn_check,
            needs_ucp: false,
        },
        PatternDef {
            kind: PiiKind::MacAddress,
            expr: r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b",
            som_fallback: false,
            validator: always_valid,
            needs_ucp: false,
        },
        PatternDef {
            kind: PiiKind::MacAddress,
            expr: r"\b[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}\b",
            som_fallback: false,
            validator: always_valid,
            needs_ucp: false,
        },
        PatternDef {
            kind: PiiKind::MacAddress,
            expr: r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b",
            som_fallback: false,
            validator: always_valid,
            needs_ucp: false,
        },
        PatternDef {
            kind: PiiKind::GbDrivingLicence,
            expr: r"\b[A-Z9]{5}\d[0-6]\d[0-3]\d\d[A-Z9]{2}\d[A-Z]\d\b",
            som_fallback: false,
            validator: uk_dl_check,
            needs_ucp: false,
        },
        PatternDef {
            kind: PiiKind::Vin,
            expr: r"\b[A-HJ-NPR-Z0-9]{17}\b",
            som_fallback: false,
            validator: vin_check,
            needs_ucp: false,
        },
        PatternDef {
            kind: PiiKind::AwsAccessKey,
            expr: r"\bAKIA[0-9A-Z]{16}\b",
            som_fallback: false,
            validator: always_valid,
            needs_ucp: false,
        },
        // GithubToken: {36} and {22}_{59} fixed repetitions create long DFA
        // state chains. Use short prefix for detection; regex extraction
        // verifies exact length and structure. Fine-grained PATs are
        // `github_pat_<22 alphanumeric>_<59 alphanumeric>`.
        PatternDef {
            kind: PiiKind::GithubToken,
            expr: r"\bgh[opsu]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b",
            som_fallback: true,
            validator: always_valid,
            needs_ucp: false,
        },
        PatternDef {
            kind: PiiKind::GbPostcode,
            expr: r"\b[A-Za-z]{1,2}[0-9][0-9A-Za-z]?\s?[0-9][A-Za-z]{2}\b",
            som_fallback: false,
            validator: always_valid,
            needs_ucp: false,
        },
        // Bare street name: 1–4 leading capitalized words (or an ordinal like
        // `216th`) followed by an unambiguous street-type suffix and an optional
        // trailing compass direction (`Main Street West`). Keyword-less — the
        // suffix set is restricted to words that are almost never anything but a
        // street type. Excluded to protect precision (these collide with common
        // nouns / product names / surnames in real traffic): `Drive` (Google
        // Drive, hard drive), `Court` (Supreme Court), `Way` (Milky Way, no
        // way), `Hill`/`Green`/`Park`/`Bank` (surnames + common nouns),
        // `Close`/`Place`/`Drove`. The `[A-Z][a-z]…` leading token means
        // lowercase prose words naturally bound the match to the capitalized
        // street name. Labeled streets are also caught by the keyword-gated
        // STREET rule in KeywordContextDetector; resolve_overlaps dedupes the
        // same-span pair.
        PatternDef {
            kind: PiiKind::UsGbCaAuNzIeZaStreet,
            expr: r"\b(?:(?:[A-Z][a-z][A-Za-z'\-]*|\d{1,4}(?:st|nd|rd|th))\s+){1,4}(?:Road|Lane|Avenue|Boulevard|Crescent|Parkway|Motorway|Street|Highway|Freeway)(?:\s+(?:North|South|East|West|Northwest|Northeast|Southwest|Southeast|N|S|E|W|NW|NE|SW|SE))?\b",
            som_fallback: false,
            validator: always_valid,
            needs_ucp: false,
        },
        // US ZIP+4 (`12345-6789`) is structurally distinctive enough to detect
        // without a keyword — the 5+4 hyphenated shape is almost always a ZIP+4.
        // The bare 5-digit form stays keyword-gated in KeywordContextDetector
        // (too ambiguous to fire on its own).
        PatternDef {
            kind: PiiKind::UsZaPostalCode,
            expr: r"\b\d{5}-\d{4}\b",
            som_fallback: false,
            validator: us_zip_check,
            needs_ucp: false,
        },
        // CaPostalCode: 3 large character classes (~40 chars each) cause DFA
        // state explosion with SOM_LEFTMOST. Use short prefix for detection;
        // regex extraction verifies the full format.
        PatternDef {
            kind: PiiKind::CaPostalCode,
            expr: r"\b[ABCEGHJKLMNPRSTVWXYZabceghjklmnprstvwxyz][0-9][ABCEGHJKLMNPRSTVWXYZabceghjklmnprstvwxyz]\s?[0-9][ABCEGHJKLMNPRSTVWXYZabceghjklmnprstvwxyz][0-9]\b",
            som_fallback: true,
            validator: always_valid,
            needs_ucp: false,
        },
        // IeEircode: 1 letter + 2 digits (or "6W" for D6W routing key)
        // + 4 alphanumerics, optional space between routing key and unique id.
        // The validator enforces the routing-key format precisely.
        PatternDef {
            kind: PiiKind::IeEircode,
            expr: r"\b[A-Za-z](?:[0-9]{2}|6[Ww])\s?[A-Za-z0-9]{4}\b",
            som_fallback: true,
            validator: ie_eircode_check,
            needs_ucp: false,
        },
        // BitcoinAddress: bounded repetitions {25,34} and {39,59} of large char
        // classes cause DFA state explosion. Use minimum-length prefix for
        // detection; regex extraction verifies exact length and word boundary.
        PatternDef {
            kind: PiiKind::BitcoinAddress,
            expr: r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[ac-hj-np-z02-9]{39,59}\b",
            som_fallback: true,
            validator: always_valid,
            needs_ucp: false,
        },
        // EthereumAddress: {40} fixed repetition. Use short prefix for detection.
        PatternDef {
            kind: PiiKind::EthereumAddress,
            expr: r"\b0x[0-9a-fA-F]{40}\b",
            som_fallback: true,
            validator: always_valid,
            needs_ucp: false,
        },
        // InternationalPhoneNumber: E.164 with optional separators.
        // Trailing \b prevents matching a 15-digit prefix of a longer digit run.
        PatternDef {
            kind: PiiKind::InternationalPhoneNumber,
            expr: r"\+[1-9]\d{0,2}[\s\-.]?(?:\d[\s\-.]?){6,13}\d\b",
            som_fallback: false,
            validator: e164_check,
            needs_ucp: false,
        },
    ];

    all.into_iter()
        .filter(|p| enabled.contains(&p.kind))
        .collect()
}

impl HyperscanDetector {
    pub fn new(enabled: &HashSet<PiiKind>) -> Result<Self, PiiError> {
        let raw = build_patterns(enabled);

        let mut entries = Vec::with_capacity(raw.len());
        let mut extraction_patterns = Vec::with_capacity(raw.len());

        for (id, pdef) in raw.iter().enumerate() {
            let extraction_regex = if pdef.som_fallback {
                Some(Regex::new(pdef.expr).map_err(PiiError::RegexCompilation)?)
            } else {
                None
            };

            entries.push(PatternEntry {
                kind: pdef.kind,
                validator: pdef.validator,
                extraction_regex,
            });

            let id = id as u32;
            let base_flags = if pdef.needs_ucp {
                Flag::UTF8 | Flag::UCP
            } else {
                Flag::UTF8
            };

            // Extraction: SOM_LEFTMOST to get start-of-match.
            // Patterns with som_fallback use regex extraction instead, but we
            // still need a placeholder in the extraction DB to keep IDs aligned.
            if !pdef.som_fallback {
                extraction_patterns.push(Pattern::new(
                    pdef.expr.as_bytes().to_vec(),
                    base_flags | Flag::SOM_LEFTMOST,
                    Some(id),
                ));
            }
        }

        if extraction_patterns.is_empty() {
            return Ok(Self {
                entries,
                extraction_prototype: None,
                extraction_db: None,
            });
        }

        let extraction_db = Box::new(
            BlockDatabase::new(extraction_patterns)
                .map_err(|e| PiiError::HyperscanCompilation(format!("extraction db: {e}")))?,
        );
        let extraction_prototype = {
            let scanner = BlockScanner::new(&extraction_db).expect("extraction scratch alloc");
            // SAFETY: Same invariants as detection_prototype above.
            unsafe { std::mem::transmute::<BlockScanner<'_>, BlockScanner<'static>>(scanner) }
        };

        Ok(Self {
            entries,
            extraction_prototype: Some(extraction_prototype),
            extraction_db: Some(extraction_db),
        })
    }

    #[cfg(test)]
    fn new_all() -> Result<Self, PiiError> {
        let enabled =
            PiiKind::enabled_for_countries(&crate::Country::all().iter().copied().collect());
        Self::new(&enabled)
    }

    fn with_detection_scanner<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&mut BlockScanner<'static>) -> R,
    {
        let db = self.extraction_db.as_ref()?;
        let proto = self.extraction_prototype.as_ref()?;
        let db_key = &**db as *const BlockDatabase as usize;
        Some(V_DETECTION_CACHE.with(|cell| {
            let mut opt = cell.borrow_mut();
            if opt.as_ref().is_none_or(|(k, _)| *k != db_key) {
                *opt = Some((db_key, proto.clone()));
            }
            f(&mut opt.as_mut().unwrap().1)
        }))
    }
}

impl Detector for HyperscanDetector {
    fn has_piis(&self, input: &str) -> bool {
        let decoded = decode_for_detection(input);
        let input: &str = match &decoded {
            Some((s, _)) => s.as_str(),
            None => input,
        };

        // Phase 1: SOM_LEFTMOST extraction patterns — validate before accepting
        let mut found = false;
        self.with_detection_scanner(|scanner: &mut BlockScanner<'static>| {
            let _ = scanner.scan(input.as_bytes(), |id, from, to, _flags| {
                let entry = &self.entries[id as usize];
                let start = from as usize;
                let end = to as usize;
                if start > input.len()
                    || end > input.len()
                    || start >= end
                    || !input.is_char_boundary(start)
                    || !input.is_char_boundary(end)
                {
                    return Scan::Continue;
                }
                let candidate = &input[start..end];
                if (entry.validator)(candidate) {
                    found = true;
                    return Scan::Terminate;
                }
                Scan::Continue
            });
        });
        if found {
            return true;
        }

        // Phase 2: Regex fallback for patterns that can't use SOM_LEFTMOST
        for entry in &self.entries {
            if let Some(ref re) = entry.extraction_regex {
                for m in re.find_iter(input) {
                    if (entry.validator)(m.as_str()) {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn mark_piis(&self, input: &str) -> Vec<PiiMatch> {
        let decoded = decode_for_detection(input);
        let offset_map: Option<&Vec<usize>>;
        let input: &str = match &decoded {
            Some((s, m)) => {
                offset_map = Some(m);
                s.as_str()
            }
            None => {
                offset_map = None;
                input
            }
        };

        let mut results = Vec::new();

        // Phase 1: SOM_LEFTMOST extraction for patterns in the extraction DB
        let mut raw: Vec<(u32, u64, u64)> = Vec::new();
        self.with_detection_scanner(|scanner: &mut BlockScanner<'static>| {
            let _ = scanner.scan(input.as_bytes(), |id, from, to, _flags| {
                raw.push((id, from, to));
                Scan::Continue
            });
        });

        for (id, from, to) in raw {
            let entry = &self.entries[id as usize];
            let start = from as usize;
            let end = to as usize;
            if start > input.len()
                || end > input.len()
                || start >= end
                || !input.is_char_boundary(start)
                || !input.is_char_boundary(end)
            {
                continue;
            }
            let candidate = &input[start..end];
            if (entry.validator)(candidate) {
                results.push(PiiMatch {
                    kind: entry.kind,
                    start,
                    end,
                    user_label: None,
                });
            }
        }

        // Phase 2: Regex fallback for patterns that can't use SOM_LEFTMOST
        for entry in &self.entries {
            if let Some(ref re) = entry.extraction_regex {
                for m in re.find_iter(input) {
                    let candidate = m.as_str();
                    if (entry.validator)(candidate) {
                        results.push(PiiMatch {
                            kind: entry.kind,
                            start: m.start(),
                            end: m.end(),
                            user_label: None,
                        });
                    }
                }
            }
        }

        // Deduplicate: Hyperscan may report overlapping/subsumed matches.
        // Sort by (start, longest first) then remove matches subsumed by a previous one.
        results.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        results.dedup_by(|a, b| {
            // b is the earlier element (already kept). Remove a if it overlaps b with same kind.
            a.kind == b.kind && a.start >= b.start && a.end <= b.end
        });

        // Remap match positions from the decoded string back to the original input.
        if let Some(map) = offset_map {
            for m in &mut results {
                m.start = map[m.start];
                m.end = map[m.end];
            }
        }

        results
    }

    fn mark_piis_structured(&self, fragments: &[ContextFragment<'_>]) -> Vec<PiiMatch> {
        let mut results = Vec::new();
        for f in fragments {
            for mut m in self.mark_piis(f.value) {
                m.start += f.offset;
                m.end += f.offset;
                results.push(m);
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

    static DETECTOR: LazyLock<HyperscanDetector> =
        LazyLock::new(|| HyperscanDetector::new_all().unwrap());

    // --- Detection with span verification ---

    // Unicode edge cases — detection still succeeds
    // RTL mark (U+200F) surrounds the email; it is a formatting char, not \w,
    // so the email pattern still anchors correctly on the ASCII characters.
    #[test_case("contact \u{200F}user@example.com\u{200F} please", PiiKind::Email, "user@example.com" ; "email rtl marks surrounding")]
    // Cyrillic 'а' (U+0430) looks identical to Latin 'a'.  With vectorscan UCP
    // and regex-crate Unicode mode, \w matches Unicode letters, so the homoglyph
    // domain is still detected.
    #[test_case("user@ex\u{0430}mple.com", PiiKind::Email, "user@ex\u{0430}mple.com" ; "email cyrillic homoglyph in domain")]
    // Zero-width space (U+200B) is stripped before scanning; the reported span
    // covers the full original bytes including the invisible character.
    #[test_case("user\u{200B}@example.com", PiiKind::Email, "user\u{200B}@example.com" ; "email zwsp stripped before matching")]
    #[test_case("SSN: 123\u{200B}-45-6789", PiiKind::UsSsn, "123\u{200B}-45-6789" ; "ssn zwsp stripped before matching")]
    #[test_case("card: 4111\u{200B}1111\u{200B}1111\u{200B}1111", PiiKind::CreditCard, "4111\u{200B}1111\u{200B}1111\u{200B}1111" ; "credit card zwsp stripped before matching")]
    #[test_case("contact us at user@example.com for info", PiiKind::Email, "user@example.com" ; "email basic")]
    #[test_case("SSN: 123%2D45%2D6789", PiiKind::UsSsn, "123%2D45%2D6789" ; "ssn percent encoded")]
    #[test_case("SSN: 123-45-6789", PiiKind::UsSsn, "123-45-6789" ; "ssn")]
    #[test_case("SSN: 078.05.1120", PiiKind::UsSsn, "078.05.1120" ; "ssn dot separators")]
    #[test_case("SSN: 078 05 1120", PiiKind::UsSsn, "078 05 1120" ; "ssn space separators")]
    #[test_case("my ssn is 078-05-1120 ok", PiiKind::UsSsn, "078-05-1120" ; "ssn span woolworth")]
    // 219-09-9999: SSA pamphlet fabricated number, from ssa.gov/history/ssn/misused.html
    #[test_case("SSN: 219-09-9999", PiiKind::UsSsn, "219-09-9999" ; "ssn ssa pamphlet")]
    // 457-55-5462: LifeLock CEO Todd Davis (publicly advertised)
    #[test_case("SSN: 457-55-5462", PiiKind::UsSsn, "457-55-5462" ; "ssn lifelock ceo")]
    #[test_case("NINO: AB 12 34 56 C", PiiKind::GbNino, "AB 12 34 56 C" ; "nino with spaces")]
    #[test_case("NINO: AB123456C", PiiKind::GbNino, "AB123456C" ; "nino no spaces")]
    #[test_case("nino: ab 12 34 56 c", PiiKind::GbNino, "ab 12 34 56 c" ; "nino lowercase")]
    // CE987654B: Valid prefix CE (no invalid letters)
    #[test_case("NINO: CE 98 76 54 B", PiiKind::GbNino, "CE 98 76 54 B" ; "nino ce prefix spaces")]
    #[test_case("NINO: CE987654B", PiiKind::GbNino, "CE987654B" ; "nino ce prefix no spaces")]
    // JY555555D: Valid prefix JY
    #[test_case("NINO: JY555555D", PiiKind::GbNino, "JY555555D" ; "nino jy prefix")]
    #[test_case("IBAN: GB29 NWBK 6016 1331 9268 19", PiiKind::Iban, "GB29 NWBK 6016 1331 9268 19" ; "iban gb")]
    #[test_case("IBAN: DE89 3704 0044 0532 0130 00", PiiKind::Iban, "DE89 3704 0044 0532 0130 00" ; "iban de")]
    #[test_case("server at 192.168.1.1 is down", PiiKind::IpAddress, "192.168.1.1" ; "ipv4")]
    #[test_case("IP: 10.0.0.255 ok", PiiKind::IpAddress, "10.0.0.255" ; "ipv4 span")]
    #[test_case("ITIN: 912-70-1234", PiiKind::UsItin, "912-70-1234" ; "itin")]
    #[test_case("my ITIN is 900-94-5678 ok", PiiKind::UsItin, "900-94-5678" ; "itin span")]
    // CA SIN: 130-692-544 from Straight Line International, 810-620-716 from TNAADO
    #[test_case("SIN: 130-692-544", PiiKind::CaSin, "130-692-544" ; "sin hyphens straightline")]
    #[test_case("SIN: 130 692 544", PiiKind::CaSin, "130 692 544" ; "sin spaces straightline")]
    #[test_case("SIN: 810-620-716", PiiKind::CaSin, "810-620-716" ; "sin tnaado")]
    #[test_case("SIN: 810 620 716", PiiKind::CaSin, "810 620 716" ; "sin tnaado spaces")]
    // IE PPSN: 1234567T from Wikipedia, 1234567FA new format, 7654321G and 5555555N computed
    #[test_case("PPSN: 1234567T", PiiKind::IePpsn, "1234567T" ; "ppsn wikipedia old")]
    #[test_case("PPSN: 1234567TW", PiiKind::IePpsn, "1234567TW" ; "ppsn wikipedia old w")]
    #[test_case("PPSN: 1234567FA", PiiKind::IePpsn, "1234567FA" ; "ppsn wikipedia new format")]
    #[test_case("PPSN: 7654321G", PiiKind::IePpsn, "7654321G" ; "ppsn computed 1")]
    #[test_case("PPSN: 5555555N", PiiKind::IePpsn, "5555555N" ; "ppsn computed 2")]
    #[test_case("MAC: 00:1A:2B:3C:4D:5E", PiiKind::MacAddress, "00:1A:2B:3C:4D:5E" ; "mac colon")]
    #[test_case("MAC: 00-1A-2B-3C-4D-5E", PiiKind::MacAddress, "00-1A-2B-3C-4D-5E" ; "mac hyphen")]
    #[test_case("MAC: 001A.2B3C.4D5E", PiiKind::MacAddress, "001A.2B3C.4D5E" ; "mac cisco dot")]
    #[test_case("MAC: aa:bb:cc:dd:ee:ff", PiiKind::MacAddress, "aa:bb:cc:dd:ee:ff" ; "mac lowercase")]
    #[test_case("DL: JONES901157A99Y1", PiiKind::GbDrivingLicence, "JONES901157A99Y1" ; "uk driving licence")]
    #[test_case("VIN: 1HGBH41JXMN109186", PiiKind::Vin, "1HGBH41JXMN109186" ; "vin")]
    #[test_case("vehicle 1HGBH41JXMN109186 registered", PiiKind::Vin, "1HGBH41JXMN109186" ; "vin span")]
    #[test_case("card: 4111 1111 1111 1111", PiiKind::CreditCard, "4111 1111 1111 1111" ; "credit card")]
    // Stripe test cards (https://docs.stripe.com/testing)
    #[test_case("card: 4242424242424242", PiiKind::CreditCard, "4242424242424242" ; "stripe visa")]
    #[test_case("card: 4000056655665556", PiiKind::CreditCard, "4000056655665556" ; "stripe visa debit")]
    #[test_case("card: 2223003122003222", PiiKind::CreditCard, "2223003122003222" ; "stripe mastercard 2 series")]
    #[test_case("card: 5105105105105100", PiiKind::CreditCard, "5105105105105100" ; "stripe mastercard prepaid")]
    #[test_case("card: 378282246310005", PiiKind::CreditCard, "378282246310005" ; "stripe amex")]
    #[test_case("card: 36227206271667", PiiKind::CreditCard, "36227206271667" ; "stripe diners club")]
    #[test_case("card: 6200000000000047", PiiKind::CreditCard, "6200000000000047" ; "stripe unionpay debit")]
    #[test_case("card: 6205500000000000004", PiiKind::CreditCard, "6205500000000000004" ; "stripe unionpay 19 digit")]
    #[test_case("card: 4000002500001001", PiiKind::CreditCard, "4000002500001001" ; "stripe cartes bancaires visa")]
    #[test_case("card: 5555050360000080", PiiKind::CreditCard, "5555050360000080" ; "stripe eftpos mastercard")]
    #[test_case("key: AKIAIOSFODNN7EXAMPLE", PiiKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE" ; "aws access key")]
    #[test_case("token: gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12", PiiKind::GithubToken, "gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12" ; "github oauth token")]
    #[test_case("token: ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH12", PiiKind::GithubToken, "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH12" ; "github pat token")]
    #[test_case("token: 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", PiiKind::GithubToken, "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" ; "github fine grained pat")]
    // GB postcodes: real landmarks
    #[test_case("postcode: SW1A 1AA", PiiKind::GbPostcode, "SW1A 1AA" ; "gb postcode buckingham palace")]
    #[test_case("postcode: EC1A1BB", PiiKind::GbPostcode, "EC1A1BB" ; "gb postcode barbican")]
    // SW1A 2AA: Houses of Parliament
    #[test_case("postcode: SW1A 2AA", PiiKind::GbPostcode, "SW1A 2AA" ; "gb postcode parliament")]
    // W1A 1AB: BBC Broadcasting House
    #[test_case("postcode: W1A 1AB", PiiKind::GbPostcode, "W1A 1AB" ; "gb postcode bbc")]
    // M1 1AE: Manchester city centre
    #[test_case("postcode: M1 1AE", PiiKind::GbPostcode, "M1 1AE" ; "gb postcode manchester")]
    // EH1 1YZ: Edinburgh
    #[test_case("postcode: EH1 1YZ", PiiKind::GbPostcode, "EH1 1YZ" ; "gb postcode edinburgh")]
    #[test_case("postal code: M5V 3L9", PiiKind::CaPostalCode, "M5V 3L9" ; "ca postal code with space")]
    #[test_case("postal code: K1A0B1", PiiKind::CaPostalCode, "K1A0B1" ; "ca postal code no space")]
    // US ZIP+4 detected structurally (no keyword needed).
    #[test_case("Tampa, FL, 33604-6258 USA", PiiKind::UsZaPostalCode, "33604-6258" ; "us zip+4 in address no keyword")]
    #[test_case("ship to 90210-1234", PiiKind::UsZaPostalCode, "90210-1234" ; "us zip+4 bare")]
    // Eircode: real Dublin / Cork / Donegal codes from Wikipedia and eircode.ie.
    #[test_case("eircode: D02 X285", PiiKind::IeEircode, "D02 X285" ; "ie eircode dublin 2")]
    #[test_case("Eircode D02X285", PiiKind::IeEircode, "D02X285" ; "ie eircode dublin no space")]
    #[test_case("delivery: T12 N5CY", PiiKind::IeEircode, "T12 N5CY" ; "ie eircode cork")]
    #[test_case("address: D6W FD93", PiiKind::IeEircode, "D6W FD93" ; "ie eircode d6w special")]
    #[test_case("Eircode F92 AB12", PiiKind::IeEircode, "F92 AB12" ; "ie eircode donegal")]
    #[test_case("send to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf Na", PiiKind::BitcoinAddress, "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf" ; "bitcoin legacy p2pkh")]
    #[test_case("wallet: 0x1234567890abcdef1234567890abcdef12345678", PiiKind::EthereumAddress, "0x1234567890abcdef1234567890abcdef12345678" ; "ethereum address")]
    #[test_case("BTW: NL123456789B01", PiiKind::NlBtw, "NL123456789B01" ; "nl btw vat number")]
    // NL000099998B57: official Belastingdienst (NL tax authority) example number
    #[test_case("VAT NL000099998B57 applies", PiiKind::NlBtw, "NL000099998B57" ; "nl btw belastingdienst example")]
    #[test_case("btw nl123456789b01", PiiKind::NlBtw, "nl123456789b01" ; "nl btw lowercase")]
    // Spanish DNI/NIE/CIF — keyword-less, checksum-validated.
    #[test_case("DNI: 12345678Z", PiiKind::EsDni, "12345678Z" ; "es dni keyword")]
    #[test_case("12345678Z is on file", PiiKind::EsDni, "12345678Z" ; "es dni no keyword")]
    #[test_case("NIE: X1234567L", PiiKind::EsNie, "X1234567L" ; "es nie x prefix")]
    #[test_case("residencia Y1234567X vigente", PiiKind::EsNie, "Y1234567X" ; "es nie y prefix no keyword")]
    #[test_case("CIF: A28015865", PiiKind::EsCif, "A28015865" ; "es cif telefonica")]
    #[test_case("empresa B67338921 registrada", PiiKind::EsCif, "B67338921" ; "es cif no keyword")]
    #[test_case("CIF P2800000H del organismo", PiiKind::EsCif, "P2800000H" ; "es cif letter control")]
    // Polish NIP in EU-VAT form — keyword-less, checksum-validated.
    // PL7740001454 (PKN Orlen) and PL5250007738 (PKO BP) are real published NIPs.
    #[test_case("VAT: PL7740001454", PiiKind::PlNip, "PL7740001454" ; "pl nip vat keyword")]
    #[test_case("invoice PL5250007738 issued", PiiKind::PlNip, "PL5250007738" ; "pl nip vat no keyword")]
    #[test_case("vat pl7740001454", PiiKind::PlNip, "pl7740001454" ; "pl nip vat lowercase")]
    #[test_case("CF: RSSMRA80A01H501U", PiiKind::ItCodiceFiscale, "RSSMRA80A01H501U" ; "it codice fiscale rome")]
    #[test_case("Codice fiscale RSSMRA85T10A562S valido", PiiKind::ItCodiceFiscale, "RSSMRA85T10A562S" ; "it codice fiscale a562")]
    // Keyword-less detection is uppercase-only (see build_patterns); a bare
    // uppercase CF with no keyword is still detected here.
    #[test_case("RSSMRA80A01H501U is on file", PiiKind::ItCodiceFiscale, "RSSMRA80A01H501U" ; "it codice fiscale no keyword uppercase")]
    #[test_case("or call +1 415 555 1234.", PiiKind::InternationalPhoneNumber, "+1 415 555 1234" ; "intl phone us spaces")]
    #[test_case("ring +44 20 7946 0958 today", PiiKind::InternationalPhoneNumber, "+44 20 7946 0958" ; "intl phone uk spaces")]
    #[test_case("number: +1-415-555-1234", PiiKind::InternationalPhoneNumber, "+1-415-555-1234" ; "intl phone hyphens")]
    #[test_case("dial +14155551234 now", PiiKind::InternationalPhoneNumber, "+14155551234" ; "intl phone no separators")]
    #[test_case("DE office: +49 30 12345678", PiiKind::InternationalPhoneNumber, "+49 30 12345678" ; "intl phone de spaces")]
    #[test_case("Casablanca: +212 522 123456", PiiKind::InternationalPhoneNumber, "+212 522 123456" ; "intl phone morocco 3 digit cc")]
    #[test_case("Moscow: +7 495 1234567", PiiKind::InternationalPhoneNumber, "+7 495 1234567" ; "intl phone russia 1 digit cc")]
    #[test_case("freephone +800 12345678", PiiKind::InternationalPhoneNumber, "+800 12345678" ; "intl phone uifn service code")]
    #[test_case("They live at Station Road these days", PiiKind::UsGbCaAuNzIeZaStreet, "Station Road" ; "street bare road no keyword")]
    #[test_case("meet me on School Lane tomorrow", PiiKind::UsGbCaAuNzIeZaStreet, "School Lane" ; "street bare lane no keyword")]
    #[test_case("the office at Portsmouth Road, London", PiiKind::UsGbCaAuNzIeZaStreet, "Portsmouth Road" ; "street bare road comma")]
    #[test_case("moved to 216th Lane last year", PiiKind::UsGbCaAuNzIeZaStreet, "216th Lane" ; "street bare ordinal lane")]
    #[test_case("near Sunset Boulevard downtown", PiiKind::UsGbCaAuNzIeZaStreet, "Sunset Boulevard" ; "street bare boulevard")]
    #[test_case("a flat on Cavendish Crescent", PiiKind::UsGbCaAuNzIeZaStreet, "Cavendish Crescent" ; "street bare crescent")]
    #[test_case("the shop on High Street closed", PiiKind::UsGbCaAuNzIeZaStreet, "High Street" ; "street bare street suffix")]
    #[test_case("delivery to Main Street West please", PiiKind::UsGbCaAuNzIeZaStreet, "Main Street West" ; "street bare trailing direction")]
    #[test_case("just off Portland Road South", PiiKind::UsGbCaAuNzIeZaStreet, "Portland Road South" ; "street bare road south")]
    fn detects_pii(input: &str, kind: PiiKind, expected_span: &str) {
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

    #[test]
    fn detects_iban_no_spaces() {
        let detector = &*DETECTOR;
        let matches = detector.mark_piis("IBAN: GB29NWBK60161331926819");
        let iban_matches: Vec<_> = matches.iter().filter(|m| m.kind == PiiKind::Iban).collect();
        assert_eq!(iban_matches.len(), 1);
    }

    // --- Rejection tests ---

    // U+202E (RIGHT-TO-LEFT OVERRIDE) inserted between '@' and the domain is not
    // a word character, so the domain half of the email pattern cannot match.
    // Unlike zero-width spaces (which are stripped), RLO is a display-semantic
    // character and is not normalised away.
    #[test_case("user@\u{202E}moc.elpmaxe", PiiKind::Email ; "email bidi rlo evades")]
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
    #[test_case("key: AKIAIOSFODNN7EXAMPL", PiiKind::AwsAccessKey ; "aws access key too short")]
    #[test_case("not a key: BKIAIOSFODNN7EXAMPLE1", PiiKind::AwsAccessKey ; "aws access key wrong prefix")]
    #[test_case("BTW: NL123456789B00", PiiKind::NlBtw ; "nl btw sub number zero")]
    #[test_case("DNI: 12345678A", PiiKind::EsDni ; "es dni wrong control letter")]
    #[test_case("NIE: X1234567A", PiiKind::EsNie ; "es nie wrong control letter")]
    #[test_case("CIF: A28015860", PiiKind::EsCif ; "es cif wrong control digit")]
    #[test_case("CIF: P28000008", PiiKind::EsCif ; "es cif p needs letter control")]
    #[test_case("CF: RSSMRA80A01H501Z", PiiKind::ItCodiceFiscale ; "it codice fiscale wrong check char")]
    #[test_case("CF: RSSMRA85T10A562X", PiiKind::ItCodiceFiscale ; "it codice fiscale wrong check char a562")]
    #[test_case("BTW: NL12345678B01", PiiKind::NlBtw ; "nl btw too few digits")]
    #[test_case("VAT: PL7740001455", PiiKind::PlNip ; "pl nip vat wrong check digit")]
    #[test_case("VAT: PL1234567890", PiiKind::PlNip ; "pl nip vat remainder ten")]
    #[test_case("VAT: PL774000145", PiiKind::PlNip ; "pl nip vat nine digits")]
    #[test_case("IBAN PL61109010140000071219812874 on file", PiiKind::PlNip ; "pl nip not matched inside iban")]
    #[test_case("0x1234567890abcdef1234567890abcdef1234567", PiiKind::EthereumAddress ; "ethereum too short")]
    #[test_case("0x1234567890abcdef1234567890abcdef123456789", PiiKind::EthereumAddress ; "ethereum too long")]
    #[test_case("eircode: D2W X285", PiiKind::IeEircode ; "ie eircode invalid w not at d6")]
    #[test_case("eircode: 102 X285", PiiKind::IeEircode ; "ie eircode invalid digit first")]
    #[test_case("see version +1.2.3 today", PiiKind::InternationalPhoneNumber ; "intl phone too few digits")]
    #[test_case("call +1 234", PiiKind::InternationalPhoneNumber ; "intl phone below 8 digits")]
    #[test_case("ext +0 1234567890", PiiKind::InternationalPhoneNumber ; "intl phone leading zero country code")]
    #[test_case("call +9 9999999 today", PiiKind::InternationalPhoneNumber ; "intl phone all nines no valid cc")]
    #[test_case("call +89 12345678 today", PiiKind::InternationalPhoneNumber ; "intl phone unassigned 2 digit cc")]
    #[test_case("call +210 12345678 today", PiiKind::InternationalPhoneNumber ; "intl phone unassigned 3 digit cc")]
    #[test_case("call +999 12345678 today", PiiKind::InternationalPhoneNumber ; "intl phone reserved 999")]
    #[test_case("please walk down the road slowly", PiiKind::UsGbCaAuNzIeZaStreet ; "street lowercase prose no cap")]
    #[test_case("we went the long way home", PiiKind::UsGbCaAuNzIeZaStreet ; "street excluded suffix way")]
    fn rejects_invalid_pii(input: &str, kind: PiiKind) {
        let detector = &*DETECTOR;
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
    #[test_case("12345@example.com", "12345@example.com" ; "numeric local part")]
    #[test_case("user@my-company.co.uk", "user@my-company.co.uk" ; "hyphenated domain")]
    #[test_case("user@xn--nxasmq6b.com", "user@xn--nxasmq6b.com" ; "punycode domain")]
    #[test_case("user@xn--80akhbyknj4f.xn--p1ai", "user@xn--80akhbyknj4f.xn--p1ai" ; "punycode domain cyrillic")]
    #[test_case("user%40example.com", "user%40example.com" ; "url encoded at sign")]
    #[test_case("first.last%40domain.org", "first.last%40domain.org" ; "url encoded with dots")]
    #[test_case("user&#64;example.com", "user&#64;example.com" ; "html decimal entity at sign")]
    #[test_case("user&#x40;example.com", "user&#x40;example.com" ; "html hex entity at sign")]
    #[test_case("user&#X40;example.com", "user&#X40;example.com" ; "html hex entity uppercase at sign")]
    #[test_case("user&commat;example.com", "user&commat;example.com" ; "html named entity at sign")]
    // URL-encoded local part
    #[test_case("user%2Btag@example.com", "user%2Btag@example.com" ; "url encoded plus in local part")]
    #[test_case("user%2Ename@example.com", "user%2Ename@example.com" ; "url encoded dot in local part")]
    // URL-encoded host part
    #[test_case("user@example%2Ecom", "user@example%2Ecom" ; "url encoded dot in host")]
    #[test_case("user@sub%2Edomain%2Ecom", "user@sub%2Edomain%2Ecom" ; "url encoded multiple dots in host")]
    // Fully URL-encoded email
    #[test_case("user%2Btag%40example%2Ecom", "user%2Btag%40example%2Ecom" ; "fully url encoded email")]
    // HTML entities in local part
    #[test_case("user&#43;tag@example.com", "user&#43;tag@example.com" ; "html decimal entity plus in local part")]
    #[test_case("user&#x2B;tag@example.com", "user&#x2B;tag@example.com" ; "html hex entity plus in local part")]
    // HTML entities in host part
    #[test_case("user@example&#46;com", "user@example&#46;com" ; "html decimal entity dot in host")]
    #[test_case("user@example&#x2E;com", "user@example&#x2E;com" ; "html hex entity dot in host")]
    #[test_case("user@example&period;com", "user@example&period;com" ; "html named entity dot in host")]
    // Fully HTML-encoded email
    #[test_case("user&#43;tag&#64;example&#46;com", "user&#43;tag&#64;example&#46;com" ; "fully html encoded email")]
    fn detects_email_variant(input: &str, expected_span: &str) {
        let detector = &*DETECTOR;
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
        let detector = &*DETECTOR;
        let matches = detector.mark_piis("admin@localhost");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn detects_multiple_emails_in_text() {
        let detector = &*DETECTOR;
        let matches =
            detector.mark_piis("contact alice@example.com or bob+list@domain.org for info");
        let email_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.kind == PiiKind::Email)
            .collect();
        assert_eq!(email_matches.len(), 2);
    }

    // --- IPv6 variant tests ---

    #[test_case("host: 2001:0db8:85a3:0000:0000:8a2e:0370:7334" ; "ipv6 full")]
    #[test_case("host: ::1" ; "ipv6 compressed")]
    #[test_case("host: fe80::1" ; "ipv6 with collapse")]
    fn detects_ipv6_variant(input: &str) {
        let detector = &*DETECTOR;
        let ip_matches: Vec<_> = detector
            .mark_piis(input)
            .into_iter()
            .filter(|m| m.kind == PiiKind::IpAddress)
            .collect();
        assert_eq!(ip_matches.len(), 1);
    }

    #[test]
    fn has_piis_short_circuits() {
        let detector = &*DETECTOR;
        assert!(detector.has_piis("user@example.com"));
        assert!(!detector.has_piis("no pii here"));
    }

    #[test]
    fn no_false_positives_on_clean_text() {
        let detector = &*DETECTOR;
        let matches = detector.mark_piis("The quick brown fox jumps over the lazy dog.");
        assert!(matches.is_empty());
    }

    #[test]
    fn itin_does_not_overlap_with_ssn() {
        let detector = &*DETECTOR;
        let matches = detector.mark_piis("number: 912-70-1234");
        assert!(matches.iter().all(|m| m.kind != PiiKind::UsSsn));
        assert!(matches.iter().any(|m| m.kind == PiiKind::UsItin));
    }

    // --- Thread-safety ---

    #[test]
    fn thread_safe_concurrent_scanning() {
        use std::thread;

        let detector = &*DETECTOR;
        thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    assert!(detector.has_piis("user@example.com"));
                    let m = detector.mark_piis("SSN: 123-45-6789");
                    assert!(!m.is_empty());
                });
            }
        });
    }

    // --- mark_piis_structured ---

    #[test_case("user@example.com", PiiKind::Email ; "email")]
    #[test_case("123-45-6789", PiiKind::UsSsn ; "us ssn")]
    #[test_case("GB82 WEST 1234 5698 7654 32", PiiKind::Iban ; "iban")]
    fn structured_detects_in_fragment_value(value: &str, kind: PiiKind) {
        let detector = &*DETECTOR;
        let frags = [ContextFragment {
            context: "field",
            value,
            offset: 100,
        }];
        let matches = detector.mark_piis_structured(&frags);
        assert!(
            matches.iter().any(|m| m.kind == kind),
            "expected {kind:?} in {matches:?}"
        );

        // Offsets are document-absolute (value's offset added in).
        let m = matches.iter().find(|m| m.kind == kind).unwrap();
        assert_eq!(m.end - m.start, value.len());
        assert!(m.start >= 100, "expected start >= 100, got {}", m.start);
    }

    #[test]
    fn structured_offset_is_document_absolute() {
        let detector = &*DETECTOR;
        // Simulate: `{"a":"user@example.com"}` — value starts at byte 6 in the doc.
        let frags = [ContextFragment {
            context: "a",
            value: "user@example.com",
            offset: 6,
        }];
        let matches = detector.mark_piis_structured(&frags);
        let email = matches.iter().find(|m| m.kind == PiiKind::Email).unwrap();
        assert_eq!(email.start, 6);
        assert_eq!(email.end, 6 + "user@example.com".len());
    }

    #[test]
    fn structured_collects_across_fragments() {
        let detector = &*DETECTOR;
        let frags = [
            ContextFragment {
                context: "a",
                value: "user@example.com",
                offset: 10,
            },
            ContextFragment {
                context: "b",
                value: "123-45-6789",
                offset: 200,
            },
        ];
        let matches = detector.mark_piis_structured(&frags);
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::UsSsn));
    }
}
