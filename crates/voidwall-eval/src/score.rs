//! Span-overlap scoring of one row, and the totals over a run.

use std::collections::{BTreeMap, HashMap};

use voidwall_pii::{PiiKind, Scanner, resolve_overlaps};

use crate::label::Label;
use crate::row::{CharIndex, Row, resolve_annotation};

/// A resolved scanner match, in character offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prediction {
    pub kind: PiiKind,
    pub start: usize,
    pub end: usize,
}

/// An annotation, in character offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    pub label: Label,
    pub start: usize,
    pub end: usize,
}

/// The scanner's resolved matches for `text`, the set the regex PII guard reports.
pub fn predict(scanner: &Scanner, text: &str) -> Vec<Prediction> {
    let index = CharIndex::new(text);
    resolve_overlaps(scanner.mark_piis(text))
        .into_iter()
        .map(|m| Prediction {
            kind: m.kind,
            start: index.char_at(m.start),
            end: index.char_at(m.end),
        })
        .collect()
}

pub fn annotations(row: &Row) -> Vec<Annotation> {
    let chars: Vec<char> = row.source_text.chars().collect();
    row.privacy_mask
        .iter()
        .map(|m| {
            let (start, end) = resolve_annotation(&row.source_text, &chars, m);
            Annotation {
                label: Label::parse(&m.label),
                start,
                end,
            }
        })
        .collect()
}

fn overlaps(a: (usize, usize), b: (usize, usize)) -> bool {
    a.0 < b.1 && b.0 < a.1 || (a.0 == a.1 && b.0 <= a.0 && a.0 < b.1)
}

#[derive(Debug, PartialEq, Eq)]
pub struct AnnotationResult {
    pub label: Label,
    /// Some prediction overlaps it.
    pub detected: bool,
    /// Some prediction of an accepted kind overlaps it.
    pub typed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PredictionResult {
    pub kind: PiiKind,
    /// Overlaps an annotation.
    pub detected: bool,
    /// Overlaps an annotation whose label accepts its kind.
    pub typed: bool,
    /// Overlaps a supported annotation.
    pub detected_supported: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RowOutcome {
    pub annotations: Vec<AnnotationResult>,
    pub predictions: Vec<PredictionResult>,
}

pub fn score(annotations: &[Annotation], predictions: &[Prediction]) -> RowOutcome {
    let annotation_results = annotations
        .iter()
        .map(|a| {
            let hits = predictions
                .iter()
                .filter(|p| overlaps((p.start, p.end), (a.start, a.end)));
            let (mut detected, mut typed) = (false, false);
            for p in hits {
                detected = true;
                typed |= a.label.accepts(p.kind);
            }
            AnnotationResult {
                label: a.label.clone(),
                detected,
                typed,
            }
        })
        .collect();

    let prediction_results = predictions
        .iter()
        .map(|p| {
            let hits = annotations
                .iter()
                .filter(|a| overlaps((p.start, p.end), (a.start, a.end)));
            let mut r = PredictionResult {
                kind: p.kind,
                detected: false,
                typed: false,
                detected_supported: false,
            };
            for a in hits {
                r.detected = true;
                r.typed |= a.label.accepts(p.kind);
                r.detected_supported |= a.label.is_supported();
            }
            r
        })
        .collect();

    RowOutcome {
        annotations: annotation_results,
        predictions: prediction_results,
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LabelStat {
    pub annotations: u64,
    pub detected: u64,
    pub typed: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct KindStat {
    tp: u64,
    typed_tp: u64,
    fp: u64,
    /// TPs that overlap a supported annotation.
    sup_tp: u64,
}

/// Counts over every scored row.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Aggregate {
    pub per_label: BTreeMap<Label, LabelStat>,
    per_kind: HashMap<PiiKind, KindStat>,
    predictions: u64,
    det_tp: u64,
    typed_tp: u64,
    fp: u64,
    /// Predictions that overlap a supported annotation.
    sup_det_tp: u64,
    /// Typed TPs are always on a supported annotation: an unsupported label
    /// accepts no kind.
    sup_typed_tp: u64,
}

/// Precision, recall, F1, and F2 for one variant.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Prf {
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub f2: f64,
}

impl Prf {
    fn new(precision: f64, recall: f64) -> Self {
        Prf {
            precision,
            recall,
            f1: f_beta(1.0, precision, recall),
            f2: f_beta(2.0, precision, recall),
        }
    }
}

/// `(1 + β²)·P·R / (β²·P + R)`: recall weighs `beta` times as much as precision.
/// 0 when P and R are both 0.
fn f_beta(beta: f64, precision: f64, recall: f64) -> f64 {
    let b2 = beta * beta;
    let den = b2 * precision + recall;
    if den == 0.0 {
        0.0
    } else {
        (1.0 + b2) * precision * recall / den
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Totals {
    pub annotations: u64,
    pub predictions: u64,
    pub detection: Prf,
    pub typed: Prf,
}

pub fn ratio(num: u64, den: u64) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

impl Aggregate {
    pub fn add(&mut self, outcome: RowOutcome) {
        for a in outcome.annotations {
            let stat = self.per_label.entry(a.label).or_default();
            stat.annotations += 1;
            stat.detected += u64::from(a.detected);
            stat.typed += u64::from(a.typed);
        }
        for p in outcome.predictions {
            self.predictions += 1;
            let stat = self.per_kind.entry(p.kind).or_default();
            if p.detected {
                self.det_tp += 1;
                stat.tp += 1;
                self.sup_det_tp += u64::from(p.detected_supported);
                stat.sup_tp += u64::from(p.detected_supported);
                if p.typed {
                    self.typed_tp += 1;
                    self.sup_typed_tp += 1;
                    stat.typed_tp += 1;
                }
            } else {
                self.fp += 1;
                stat.fp += 1;
            }
        }
    }

    /// Micro totals. With `supported_only`, unsupported annotations leave the
    /// recall, and a prediction that overlaps only unsupported annotations is
    /// neither a true nor a false positive.
    pub fn micro(&self, supported_only: bool) -> Totals {
        let labels = self
            .per_label
            .iter()
            .filter(|(l, _)| !supported_only || l.is_supported());
        let (mut annotations, mut detected, mut typed) = (0, 0, 0);
        for (_, s) in labels {
            annotations += s.annotations;
            detected += s.detected;
            typed += s.typed;
        }
        let (det_tp, typed_tp, predictions) = if supported_only {
            (
                self.sup_det_tp,
                self.sup_typed_tp,
                self.sup_det_tp + self.fp,
            )
        } else {
            (self.det_tp, self.typed_tp, self.predictions)
        };
        Totals {
            annotations,
            predictions,
            detection: Prf::new(ratio(det_tp, predictions), ratio(detected, annotations)),
            typed: Prf::new(ratio(typed_tp, predictions), ratio(typed, annotations)),
        }
    }

    /// Mean per-label recall over the supported labels seen, as (detection, typed).
    pub fn macro_recall(&self) -> Option<(f64, f64)> {
        let supported: Vec<&LabelStat> = self
            .per_label
            .iter()
            .filter(|(l, _)| l.is_supported())
            .map(|(_, s)| s)
            .collect();
        if supported.is_empty() {
            return None;
        }
        let n = supported.len() as f64;
        let det = supported
            .iter()
            .map(|s| ratio(s.detected, s.annotations))
            .sum::<f64>()
            / n;
        let typed = supported
            .iter()
            .map(|s| ratio(s.typed, s.annotations))
            .sum::<f64>()
            / n;
        Some((det, typed))
    }

    /// Precision for one label, as (detection, typed). A prediction counts toward
    /// every label that accepts its kind. With `supported_only`, a prediction that
    /// overlaps only unsupported annotations is neither a true nor a false positive.
    /// `None` when no such prediction exists.
    pub fn label_precision(&self, label: &Label, supported_only: bool) -> Option<(f64, f64)> {
        let (mut tp, mut typed_tp, mut fp) = (0, 0, 0);
        for (kind, s) in &self.per_kind {
            if label.accepts(*kind) {
                tp += if supported_only { s.sup_tp } else { s.tp };
                typed_tp += s.typed_tp;
                fp += s.fp;
            }
        }
        let den = tp + fp;
        (den > 0).then(|| (ratio(tp, den), ratio(typed_tp, den)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::label::Ai4pLabel;
    use crate::language::EvalLanguage;
    use crate::row::MaskSpan;
    use test_case::test_case;

    fn ann(label: &str, start: usize, end: usize) -> Annotation {
        Annotation {
            label: Label::parse(label),
            start,
            end,
        }
    }

    fn pred(kind: PiiKind, start: usize, end: usize) -> Prediction {
        Prediction { kind, start, end }
    }

    #[test]
    fn overlap_is_a_true_positive() {
        let o = score(&[ann("EMAIL", 5, 20)], &[pred(PiiKind::Email, 10, 25)]);
        assert!(o.annotations[0].detected && o.annotations[0].typed);
        assert!(o.predictions[0].detected && o.predictions[0].typed);
    }

    #[test]
    fn no_overlap_is_a_false_positive_and_a_miss() {
        let o = score(&[ann("EMAIL", 0, 5)], &[pred(PiiKind::Email, 5, 9)]);
        assert!(!o.annotations[0].detected);
        assert!(!o.predictions[0].detected);
    }

    #[test]
    fn right_span_wrong_kind_counts_for_detection_only() {
        let o = score(&[ann("TEL", 0, 10)], &[pred(PiiKind::Iban, 0, 10)]);
        assert!(o.annotations[0].detected && !o.annotations[0].typed);
        assert!(o.predictions[0].detected && !o.predictions[0].typed);
    }

    #[test]
    fn unsupported_annotation_marks_prediction_as_not_supported() {
        let o = score(&[ann("CITY", 0, 6)], &[pred(PiiKind::PersonName, 0, 6)]);
        assert!(o.predictions[0].detected && !o.predictions[0].detected_supported);
    }

    #[test]
    fn overlapping_raw_matches_are_scored_once() {
        // A scanner can return the same span from two detectors; `predict`
        // resolves them to one prediction.
        let scanner = EvalLanguage::En.build_scanner().unwrap();
        let text = "Contact: user@example.com";
        let raw = scanner.mark_piis(text).len();
        let preds = predict(&scanner, text);
        assert!(preds.len() <= raw);
        assert_eq!(preds.len(), 1);
    }

    #[test]
    fn multibyte_text_before_the_value_still_overlaps() {
        let scanner = EvalLanguage::En.build_scanner().unwrap();
        let text = "Grüße 😀 — mail: user@example.com";
        let start = text.chars().count() - "user@example.com".chars().count();
        let row = Row {
            source_text: text.into(),
            privacy_mask: vec![MaskSpan {
                label: "EMAIL".into(),
                start,
                end: start + 16,
                value: "user@example.com".into(),
            }],
            language: None,
        };
        let o = score(&annotations(&row), &predict(&scanner, text));
        assert!(o.annotations[0].typed, "{o:?}");
        assert!(o.predictions.iter().all(|p| p.typed));
    }

    /// Two rows with known totals:
    /// - EMAIL hit with EMAIL (typed TP)
    /// - TEL hit with IBAN (detection TP only)
    /// - CITY hit with PERSON_NAME (overlaps an unsupported label only)
    /// - PASSPORT missed
    /// - one PERSON_NAME overlapping nothing (FP)
    fn sample() -> Aggregate {
        let mut agg = Aggregate::default();
        agg.add(score(
            &[ann("EMAIL", 0, 10), ann("TEL", 20, 30), ann("CITY", 40, 45)],
            &[
                pred(PiiKind::Email, 0, 10),
                pred(PiiKind::Iban, 20, 30),
                pred(PiiKind::PersonName, 40, 45),
            ],
        ));
        agg.add(score(
            &[ann("PASSPORT", 0, 9)],
            &[pred(PiiKind::PersonName, 50, 55)],
        ));
        agg
    }

    // (P, R) → (F1, F2). F1 = 2PR / (P + R); F2 = 5PR / (4P + R).
    #[test_case(1.0, 0.5, 2.0 / 3.0, 5.0 / 9.0; "recall low: F2 below F1")]
    #[test_case(0.5, 1.0, 2.0 / 3.0, 5.0 / 6.0; "precision low: F2 above F1")]
    #[test_case(0.5, 0.5, 0.5, 0.5; "equal P and R")]
    #[test_case(1.0, 1.0, 1.0, 1.0; "perfect")]
    #[test_case(1.0, 0.0, 0.0, 0.0; "no recall")]
    #[test_case(0.0, 1.0, 0.0, 0.0; "no precision")]
    #[test_case(0.0, 0.0, 0.0, 0.0; "nothing")]
    fn f_scores(p: f64, r: f64, f1: f64, f2: f64) {
        assert_eq!(
            Prf::new(p, r),
            Prf {
                precision: p,
                recall: r,
                f1,
                f2
            }
        );
    }

    fn assert_prf(m: Prf, p: f64, r: f64, f1: f64, f2: f64) {
        for (name, got, want) in [
            ("P", m.precision, p),
            ("R", m.recall, r),
            ("F1", m.f1, f1),
            ("F2", m.f2, f2),
        ] {
            assert!((got - want).abs() < 1e-15, "{name}: {got} != {want}");
        }
    }

    #[test]
    fn micro_over_all_labels() {
        let t = sample().micro(false);
        assert_eq!((t.annotations, t.predictions), (4, 4));
        // detection: 3 of 4 predictions overlap; 3 of 4 annotations hit.
        assert_prf(t.detection, 0.75, 0.75, 0.75, 0.75);
        // typed: 1 of 4 predictions, 1 of 4 annotations.
        assert_prf(t.typed, 0.25, 0.25, 0.25, 0.25);
    }

    #[test]
    fn micro_over_supported_labels() {
        let t = sample().micro(true);
        // CITY leaves; the PERSON_NAME on CITY is neither TP nor FP.
        assert_eq!((t.annotations, t.predictions), (3, 3));
        assert_prf(t.detection, 2.0 / 3.0, 2.0 / 3.0, 2.0 / 3.0, 2.0 / 3.0);
        assert_prf(t.typed, 1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0);
    }

    #[test]
    fn macro_recall_over_supported_labels() {
        // EMAIL 1/1 both; TEL 1/1 detection, 0/1 typed; PASSPORT 0/1.
        let (det, typed) = sample().macro_recall().unwrap();
        assert_eq!(det, 2.0 / 3.0);
        assert_eq!(typed, 1.0 / 3.0);
    }

    #[test]
    fn label_precision_attributes_by_accepted_kind() {
        let agg = sample();
        assert_eq!(
            agg.label_precision(&Label::Known(Ai4pLabel::Email), false),
            Some((1.0, 1.0))
        );
        // PERSON_NAME: one TP on CITY (not typed), one FP.
        assert_eq!(
            agg.label_precision(&Label::Known(Ai4pLabel::GivenName1), false),
            Some((0.5, 0.0))
        );
        // No prediction of a TEL kind.
        assert_eq!(
            agg.label_precision(&Label::Known(Ai4pLabel::Tel), false),
            None
        );
        assert_eq!(
            agg.label_precision(&Label::Known(Ai4pLabel::City), false),
            None
        );
    }

    #[test]
    fn supported_only_label_precision_skips_predictions_on_unsupported_labels() {
        // The PERSON_NAME on CITY is neither TP nor FP; the other one is an FP.
        assert_eq!(
            sample().label_precision(&Label::Known(Ai4pLabel::GivenName1), true),
            Some((0.0, 0.0))
        );
        // A PERSON_NAME on CITY only: no prediction left to count.
        let mut agg = Aggregate::default();
        agg.add(score(
            &[ann("CITY", 0, 6)],
            &[pred(PiiKind::PersonName, 0, 6)],
        ));
        let name = Label::Known(Ai4pLabel::GivenName1);
        assert_eq!(agg.label_precision(&name, false), Some((1.0, 0.0)));
        assert_eq!(agg.label_precision(&name, true), None);
    }

    mod differential {
        //! `score` and `Aggregate` against a reference coded from the spec text, on
        //! random rows. The reference shares only `Label::accepts` and
        //! `Label::is_supported` with the harness; `label.rs` tests those.

        use super::*;
        use crate::report::{Counts, write_report};
        use proptest::prelude::*;

        type Rows = Vec<(Vec<Annotation>, Vec<Prediction>)>;

        /// Supported labels, unsupported ones, and one outside the vocabulary.
        const LABELS: &[&str] = &[
            "EMAIL",
            "TEL",
            "GIVENNAME1",
            "LASTNAME1",
            "STREET",
            "SECADDRESS",
            "IDCARD",
            "SOCIALNUMBER",
            "PASSPORT",
            "CITY",
            "BUILDING",
            "NEWLABEL",
        ];
        /// Kinds with one label, with several, and with none.
        const KINDS: &[PiiKind] = &[
            PiiKind::Email,
            PiiKind::PersonName,
            PiiKind::InternationalPhoneNumber,
            PiiKind::UsPhoneNumber,
            PiiKind::UsGbCaAuNzIeZaStreet,
            PiiKind::GbAddress,
            PiiKind::NlBsn,
            PiiKind::UsSsn,
            PiiKind::Iban,
        ];

        fn span() -> impl Strategy<Value = (usize, usize)> {
            (0usize..40, 1usize..8).prop_map(|(s, len)| (s, s + len))
        }

        fn rows() -> impl Strategy<Value = Rows> {
            let a = (prop::sample::select(LABELS), span()).prop_map(|(l, (s, e))| ann(l, s, e));
            let p = (prop::sample::select(KINDS), span()).prop_map(|(k, (s, e))| pred(k, s, e));
            prop::collection::vec(
                (
                    prop::collection::vec(a, 0..6),
                    prop::collection::vec(p, 0..6),
                ),
                0..6,
            )
        }

        fn aggregate(rows: &Rows) -> Aggregate {
            let mut agg = Aggregate::default();
            for (anns, preds) in rows {
                agg.add(score(anns, preds));
            }
            agg
        }

        fn report(agg: &Aggregate, supported_only: bool) -> String {
            let mut out = Vec::new();
            write_report(&mut out, agg, Counts::default(), None, supported_only).unwrap();
            String::from_utf8(out).unwrap()
        }

        fn hit(p: &Prediction, a: &Annotation) -> bool {
            p.start < a.end && a.start < p.end
        }

        fn frac(num: u64, den: u64) -> f64 {
            if den == 0 {
                0.0
            } else {
                num as f64 / den as f64
            }
        }

        fn prf(tp: u64, predictions: u64, matched: u64, annotations: u64) -> Prf {
            let (p, r) = (frac(tp, predictions), frac(matched, annotations));
            let f1 = if p + r == 0.0 {
                0.0
            } else {
                2.0 * p * r / (p + r)
            };
            let f2 = if 4.0 * p + r == 0.0 {
                0.0
            } else {
                5.0 * p * r / (4.0 * p + r)
            };
            Prf {
                precision: p,
                recall: r,
                f1,
                f2,
            }
        }

        struct RefPrediction {
            kind: PiiKind,
            hit: bool,
            typed: bool,
            only_unsupported: bool,
        }

        #[derive(Default)]
        struct Reference {
            /// (annotations, detected, typed)
            per_label: BTreeMap<Label, (u64, u64, u64)>,
            predictions: Vec<RefPrediction>,
        }

        impl Reference {
            fn new(rows: &Rows) -> Self {
                let mut r = Reference::default();
                for (anns, preds) in rows {
                    for a in anns {
                        let on: Vec<_> = preds.iter().filter(|p| hit(p, a)).collect();
                        let e = r.per_label.entry(a.label.clone()).or_default();
                        e.0 += 1;
                        e.1 += u64::from(!on.is_empty());
                        e.2 += u64::from(on.iter().any(|p| a.label.accepts(p.kind)));
                    }
                    for p in preds {
                        let on: Vec<_> = anns.iter().filter(|a| hit(p, a)).collect();
                        r.predictions.push(RefPrediction {
                            kind: p.kind,
                            hit: !on.is_empty(),
                            typed: on.iter().any(|a| a.label.accepts(p.kind)),
                            only_unsupported: !on.is_empty()
                                && on.iter().all(|a| !a.label.is_supported()),
                        });
                    }
                }
                r
            }

            /// Under `SUPPORTED_ONLY`, a prediction on unsupported annotations only
            /// is neither TP nor FP.
            fn counted(&self, supported_only: bool) -> impl Iterator<Item = &RefPrediction> {
                self.predictions
                    .iter()
                    .filter(move |p| !(supported_only && p.only_unsupported))
            }

            fn micro(&self, supported_only: bool) -> Totals {
                let (mut n, mut det, mut typed) = (0, 0, 0);
                for (l, s) in &self.per_label {
                    if !supported_only || l.is_supported() {
                        n += s.0;
                        det += s.1;
                        typed += s.2;
                    }
                }
                let counted: Vec<_> = self.counted(supported_only).collect();
                let den = counted.len() as u64;
                let tp = counted.iter().filter(|p| p.hit).count() as u64;
                let typed_tp = counted.iter().filter(|p| p.typed).count() as u64;
                Totals {
                    annotations: n,
                    predictions: den,
                    detection: prf(tp, den, det, n),
                    typed: prf(typed_tp, den, typed, n),
                }
            }

            fn macro_recall(&self) -> Option<(f64, f64)> {
                let s: Vec<_> = self
                    .per_label
                    .iter()
                    .filter(|(l, _)| l.is_supported())
                    .map(|(_, s)| s)
                    .collect();
                let n = s.len() as f64;
                (!s.is_empty()).then(|| {
                    (
                        s.iter().map(|s| frac(s.1, s.0)).sum::<f64>() / n,
                        s.iter().map(|s| frac(s.2, s.0)).sum::<f64>() / n,
                    )
                })
            }

            fn label_precision(&self, label: &Label, supported_only: bool) -> Option<(f64, f64)> {
                let mine: Vec<_> = self
                    .counted(supported_only)
                    .filter(|p| label.accepts(p.kind))
                    .collect();
                let den = mine.len() as u64;
                (den > 0).then(|| {
                    (
                        frac(mine.iter().filter(|p| p.hit).count() as u64, den),
                        frac(mine.iter().filter(|p| p.typed).count() as u64, den),
                    )
                })
            }
        }

        fn every_label() -> Vec<Label> {
            Ai4pLabel::ALL
                .iter()
                .map(|l| Label::Known(*l))
                .chain([Label::parse("NEWLABEL")])
                .collect()
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(2000))]

            #[test]
            fn aggregate_equals_reference(rows in rows()) {
                let agg = aggregate(&rows);
                let r = Reference::new(&rows);

                let per_label: BTreeMap<_, _> = agg
                    .per_label
                    .iter()
                    .map(|(l, s)| (l.clone(), (s.annotations, s.detected, s.typed)))
                    .collect();
                prop_assert_eq!(per_label, r.per_label.clone());

                let (am, rm) = (agg.macro_recall(), r.macro_recall());
                prop_assert_eq!(am.is_some(), rm.is_some());
                if let (Some(a), Some(b)) = (am, rm) {
                    prop_assert!((a.0 - b.0).abs() < 1e-12 && (a.1 - b.1).abs() < 1e-12);
                }

                for supported_only in [false, true] {
                    prop_assert_eq!(agg.micro(supported_only), r.micro(supported_only));
                    for label in every_label() {
                        prop_assert_eq!(
                            agg.label_precision(&label, supported_only),
                            r.label_precision(&label, supported_only),
                            "{:?} supported_only={}", label, supported_only
                        );
                    }
                }
            }

            /// A prediction that overlaps nothing changes precision only.
            #[test]
            fn false_positive_changes_precision_only(mut rows in rows(), kind in prop::sample::select(KINDS)) {
                let before = aggregate(&rows);
                match rows.first_mut() {
                    Some(row) => row.1.push(pred(kind, 1000, 1005)),
                    None => rows.push((vec![], vec![pred(kind, 1000, 1005)])),
                }
                let after = aggregate(&rows);
                prop_assert_eq!(&after.per_label, &before.per_label);
                prop_assert_eq!(after.macro_recall(), before.macro_recall());
                for supported_only in [false, true] {
                    let (b, a) = (before.micro(supported_only), after.micro(supported_only));
                    prop_assert_eq!(a.annotations, b.annotations);
                    prop_assert_eq!(a.predictions, b.predictions + 1);
                    prop_assert_eq!(a.detection.recall, b.detection.recall);
                    prop_assert_eq!(a.typed.recall, b.typed.recall);
                    prop_assert!(a.detection.precision <= b.detection.precision);
                    prop_assert!(a.typed.precision <= b.typed.precision);
                }
            }

            /// An unsupported annotation that no prediction overlaps leaves the
            /// SUPPORTED_ONLY report as it was.
            #[test]
            fn unsupported_annotation_leaves_supported_only_report(mut rows in rows()) {
                let before = report(&aggregate(&rows), true);
                match rows.first_mut() {
                    Some(row) => row.0.push(ann("CITY", 1000, 1005)),
                    None => rows.push((vec![ann("CITY", 1000, 1005)], vec![])),
                }
                prop_assert_eq!(report(&aggregate(&rows), true), before);
            }
        }
    }
}
