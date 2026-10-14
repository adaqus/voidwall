//! The run report. It holds labels, kind names, and counts only, never text from
//! the dataset.

use std::io::{self, Write};

use crate::label::Label;
use crate::language::EvalLanguage;
use crate::score::{Aggregate, Prf, ratio};

/// What the reader saw, beside the scores.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub rows_scored: u64,
    pub parse_errors: u64,
    /// Rows whose language is none of the six, or that have none and no `AI4P_LANG`.
    pub skipped_unsupported_language: u64,
    /// Rows in a supported language other than `AI4P_LANG`.
    pub skipped_other_language: u64,
}

pub fn write_report(
    out: &mut impl Write,
    agg: &Aggregate,
    counts: Counts,
    lang: Option<EvalLanguage>,
    supported_only: bool,
) -> io::Result<()> {
    writeln!(
        out,
        "\n=== AI4Privacy openpii300k eval: voidwall-pii regex engine ==="
    )?;
    writeln!(
        out,
        "language={} supported_only={}",
        lang.map_or("all", EvalLanguage::code),
        if supported_only { "yes" } else { "no" },
    )?;
    writeln!(
        out,
        "rows scored={}, parse errors={}, skipped: unsupported language={}, other language={}",
        counts.rows_scored,
        counts.parse_errors,
        counts.skipped_unsupported_language,
        counts.skipped_other_language,
    )?;

    let pct = |v: f64| format!("{:.1}%", v * 100.0);
    writeln!(
        out,
        "\n{:<14} {:>7} {:>9} {:>8} {:>8} {:>8} {:>8}",
        "label", "n", "supported", "det R", "det P", "typed R", "typed P"
    )?;
    writeln!(out, "{}", "-".repeat(68))?;
    for (label, s) in &agg.per_label {
        let supported = label.is_supported();
        if supported_only && !supported {
            continue;
        }
        let (det_p, typed_p) = agg
            .label_precision(label, supported_only)
            .map_or(("—".to_string(), "—".to_string()), |(d, t)| {
                (pct(d), pct(t))
            });
        writeln!(
            out,
            "{:<14} {:>7} {:>9} {:>8} {:>8} {:>8} {:>8}",
            label.as_str(),
            s.annotations,
            if supported { "yes" } else { "no" },
            pct(ratio(s.detected, s.annotations)),
            det_p,
            pct(ratio(s.typed, s.annotations)),
            typed_p,
        )?;
    }

    let micro = agg.micro(supported_only);
    writeln!(
        out,
        "\n--- Micro ({}) --- annotations={} predictions={}",
        if supported_only {
            "supported labels"
        } else {
            "all labels"
        },
        micro.annotations,
        micro.predictions,
    )?;
    writeln!(
        out,
        "{:<10} {:>7} {:>7} {:>7} {:>7}",
        "", "P", "R", "F1", "F2"
    )?;
    let row = |out: &mut dyn Write, name: &str, m: Prf| {
        writeln!(
            out,
            "{name:<10} {:>7.3} {:>7.3} {:>7.3} {:>7.3}",
            m.precision, m.recall, m.f1, m.f2
        )
    };
    row(out, "detection", micro.detection)?;
    row(out, "typed", micro.typed)?;

    if let Some((det, typed)) = agg.macro_recall() {
        let n = agg.per_label.keys().filter(|l| l.is_supported()).count();
        writeln!(out, "\n--- Macro recall (supported labels: {n}) ---")?;
        writeln!(out, "detection {det:.3}")?;
        writeln!(out, "typed     {typed:.3}")?;
    }

    let unknown: Vec<(&Label, u64)> = agg
        .per_label
        .iter()
        .filter(|(l, _)| matches!(l, Label::Unknown(_)))
        .map(|(l, s)| (l, s.annotations))
        .collect();
    if !unknown.is_empty() {
        writeln!(
            out,
            "\n--- Labels outside the openpii300k vocabulary (unsupported) ---"
        )?;
        for (l, n) in unknown {
            writeln!(out, "  {:<20} {n}", l.as_str())?;
        }
    }

    write_legend(out)
}

fn write_legend(out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "\n--- Legend ---")?;
    for line in [
        "det, detection  a prediction counts when its span overlaps an annotation, whatever its kind",
        "typed           the prediction's kind must also be one that maps to the annotation's label",
        "R, recall       share of annotations that a prediction overlaps",
        "P, precision    share of predictions that overlap an annotation; per label, a prediction",
        "                counts toward every label its kind maps to",
        "F1              harmonic mean of P and R",
        "F2              like F1, but R weighs twice as much as P: 5·P·R / (4·P + R)",
        "n               annotations of the label",
        "supported       Voidwall has at least one PII kind that maps to the label",
        "—               no counted prediction of a kind that maps to the label",
        "micro           counts pooled over all labels before the ratio",
        "macro recall    mean of the per-label recall over the supported labels",
    ] {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::row::{MaskSpan, Row};
    use crate::score::{annotations, predict, score};

    fn report(agg: &Aggregate, supported_only: bool) -> String {
        let mut out = Vec::new();
        write_report(&mut out, agg, Counts::default(), None, supported_only).unwrap();
        String::from_utf8(out).unwrap()
    }

    fn sample() -> Aggregate {
        let scanner = EvalLanguage::En.build_scanner().unwrap();
        let text = "Reach me at user@example.com from Springfield.";
        let row = Row {
            source_text: text.into(),
            privacy_mask: vec![
                MaskSpan {
                    label: "EMAIL".into(),
                    start: 12,
                    end: 28,
                    value: "user@example.com".into(),
                },
                MaskSpan {
                    label: "CITY".into(),
                    start: 34,
                    end: 45,
                    value: "Springfield".into(),
                },
                MaskSpan {
                    label: "NEWLABEL".into(),
                    start: 0,
                    end: 5,
                    value: "Reach".into(),
                },
            ],
            language: None,
        };
        let mut agg = Aggregate::default();
        agg.add(score(&annotations(&row), &predict(&scanner, text)));
        agg
    }

    #[test]
    fn report_holds_no_dataset_text() {
        let out = report(&sample(), false);
        assert!(out.contains("EMAIL"), "{out}");
        for value in ["user@example.com", "Springfield", "Reach me"] {
            assert!(!out.contains(value), "report leaks {value:?}:\n{out}");
        }
    }

    #[test]
    fn unknown_label_is_named() {
        let out = report(&sample(), false);
        assert!(out.contains("outside the openpii300k vocabulary"), "{out}");
        assert!(out.contains("NEWLABEL"), "{out}");
    }

    #[test]
    fn legend_explains_both_variants() {
        let out = report(&sample(), false);
        let legend = out.split("--- Legend ---").nth(1).expect("legend present");
        assert!(legend.contains("det, detection"), "{out}");
        assert!(legend.contains("typed"), "{out}");
    }

    #[test]
    fn legend_is_the_same_in_both_modes_and_names_no_variable() {
        let legend = |supported_only| {
            report(&sample(), supported_only)
                .split_once("--- Legend ---")
                .expect("legend present")
                .1
                .to_string()
        };
        assert_eq!(legend(true), legend(false));
        assert!(!legend(true).contains("SUPPORTED_ONLY"), "{}", legend(true));
    }

    /// Three rows with injected predictions, one case of each scoring rule.
    /// Spans are character offsets; no scanner runs.
    fn golden() -> Aggregate {
        use crate::score::{Annotation, Prediction};
        use voidwall_pii::PiiKind::*;
        let a = |label: &str, start, end| Annotation {
            label: crate::label::Label::parse(label),
            start,
            end,
        };
        let p = |kind, start, end| Prediction { kind, start, end };
        let mut agg = Aggregate::default();
        agg.add(score(
            &[a("EMAIL", 0, 10), a("TEL", 20, 30), a("PASSPORT", 40, 49)],
            &[
                p(Email, 0, 10),  // p1: typed hit on EMAIL
                p(Iban, 20, 30),  // p2: hit on TEL, wrong kind
                p(Email, 60, 70), // p3: overlaps nothing, FP
            ],
        ));
        agg.add(score(
            &[
                a("GIVENNAME1", 0, 5),
                a("LASTNAME1", 6, 12),
                a("TEL", 20, 35),
            ],
            &[
                p(PersonName, 0, 12),                // p4: one prediction, two annotations
                p(InternationalPhoneNumber, 20, 27), // p5, p6: two predictions,
                p(UsPhoneNumber, 28, 35),            //         one annotation
            ],
        ));
        agg.add(score(
            &[
                a("CITY", 0, 8),
                a("STREET", 10, 30),
                a("BUILDING", 25, 35),
                a("NEWLABEL", 40, 45),
                a("EMAIL", 50, 60),
            ],
            &[
                p(PersonName, 0, 8),             // p7: on unsupported CITY only
                p(UsGbCaAuNzIeZaStreet, 20, 35), // p8: on STREET and BUILDING
            ],
        ));
        agg
    }

    fn golden_report(supported_only: bool) -> String {
        let counts = Counts {
            rows_scored: 3,
            ..Counts::default()
        };
        let mut out = Vec::new();
        write_report(&mut out, &golden(), counts, None, supported_only).unwrap();
        String::from_utf8(out).unwrap()
    }

    fn with_legend(body: &str) -> String {
        let mut legend = Vec::new();
        write_legend(&mut legend).unwrap();
        format!("{body}{}", String::from_utf8(legend).unwrap())
    }

    // Annotations (n, detected, typed):
    //   EMAIL 2,1,1 (a1 by p1; the EMAIL in row 3 missed)   TEL 2,2,1 (p2 wrong kind; p5+p6)
    //   PASSPORT 1,0,0   GIVENNAME1 1,1,1   LASTNAME1 1,1,1 (both by p4)   STREET 1,1,1 (p8)
    //   CITY 1,1,0 (p7)   BUILDING 1,1,0 (p8)   NEWLABEL 1,0,0
    // Predictions: 8; det TP 7 (all but p3); typed TP 5 (p1 p4 p5 p6 p8); FP 1 (p3).
    // Per-label P, from the predictions of the kinds the label accepts:
    //   EMAIL {p1 typed, p3 FP} 1/2, 1/2   TEL {p5, p6} 2/2, 2/2   STREET {p8} 1/1, 1/1
    //   name labels {p4 typed, p7 untyped} 2/2, 1/2   others: no accepted kind seen, "—"
    // Micro: det P 7/8 = .875, R 8/11 = .727, F1 112/141 = .794, F2 70/93 = .753
    //        typed P 5/8 = .625, R 5/11 = .455, F1 50/95 = .526, F2 25/52 = .481
    // Macro over the 6 supported labels:
    //   det (.5 + 1 + 0 + 1 + 1 + 1) / 6 = .750   typed (.5 + .5 + 0 + 1 + 1 + 1) / 6 = .667
    #[test]
    fn golden_report_over_all_labels() {
        let expected = "
=== AI4Privacy openpii300k eval: voidwall-pii regex engine ===
language=all supported_only=no
rows scored=3, parse errors=0, skipped: unsupported language=0, other language=0

label                n supported    det R    det P  typed R  typed P
--------------------------------------------------------------------
BUILDING             1        no   100.0%        —     0.0%        —
CITY                 1        no   100.0%        —     0.0%        —
EMAIL                2       yes    50.0%    50.0%    50.0%    50.0%
GIVENNAME1           1       yes   100.0%   100.0%   100.0%    50.0%
LASTNAME1            1       yes   100.0%   100.0%   100.0%    50.0%
PASSPORT             1       yes     0.0%        —     0.0%        —
STREET               1       yes   100.0%   100.0%   100.0%   100.0%
TEL                  2       yes   100.0%   100.0%    50.0%   100.0%
NEWLABEL             1        no     0.0%        —     0.0%        —

--- Micro (all labels) --- annotations=11 predictions=8
                 P       R      F1      F2
detection    0.875   0.727   0.794   0.753
typed        0.625   0.455   0.526   0.481

--- Macro recall (supported labels: 6) ---
detection 0.750
typed     0.667

--- Labels outside the openpii300k vocabulary (unsupported) ---
  NEWLABEL             1
";
        assert_eq!(golden_report(false), with_legend(expected));
    }

    // CITY, BUILDING, and NEWLABEL leave the table and the totals. p7 is on CITY
    // only, so it is neither TP nor FP: 7 predictions, det TP 6, typed TP 5, FP 1.
    // Name labels: {p4 typed} 1/1, 1/1.
    // Micro: annotations 2+2+1+1+1+1 = 8, detected 6, typed 5.
    //   det P 6/7 = .857, R 6/8 = .750, F1 36/45 = .800, F2 10/13 = .769
    //   typed P 5/7 = .714, R 5/8 = .625, F1 50/75 = .667, F2 25/39 = .641
    #[test]
    fn golden_report_over_supported_labels() {
        let expected = "
=== AI4Privacy openpii300k eval: voidwall-pii regex engine ===
language=all supported_only=yes
rows scored=3, parse errors=0, skipped: unsupported language=0, other language=0

label                n supported    det R    det P  typed R  typed P
--------------------------------------------------------------------
EMAIL                2       yes    50.0%    50.0%    50.0%    50.0%
GIVENNAME1           1       yes   100.0%   100.0%   100.0%   100.0%
LASTNAME1            1       yes   100.0%   100.0%   100.0%   100.0%
PASSPORT             1       yes     0.0%        —     0.0%        —
STREET               1       yes   100.0%   100.0%   100.0%   100.0%
TEL                  2       yes   100.0%   100.0%    50.0%   100.0%

--- Micro (supported labels) --- annotations=8 predictions=7
                 P       R      F1      F2
detection    0.857   0.750   0.800   0.769
typed        0.714   0.625   0.667   0.641

--- Macro recall (supported labels: 6) ---
detection 0.750
typed     0.667

--- Labels outside the openpii300k vocabulary (unsupported) ---
  NEWLABEL             1
";
        assert_eq!(golden_report(true), with_legend(expected));
    }

    #[test]
    fn supported_only_omits_unsupported_labels_from_the_table() {
        let out = report(&sample(), true);
        assert!(!out.lines().any(|l| l.starts_with("CITY")), "{out}");
        assert!(out.lines().any(|l| l.starts_with("EMAIL")), "{out}");
        assert!(out.contains("Micro (supported labels)"), "{out}");
    }
}
