//! Running a token classifier over one unit: one inference per window, and
//! each token's pooled probabilities, kept once per window that holds it.

use std::ops::Range;

use crate::decode::{Boundaries, Span, decode};
use crate::labels::Labels;
use crate::load::TokenWorker;
use crate::run::{Cancel, RunError, ids};

/// What one run of a token worker found: one record per token per window that
/// holds it, in window order. Special tokens have none.
#[derive(Debug)]
pub struct TokenProbs {
    /// Pooled slots per record: [`Labels::slots`].
    slots: usize,
    /// The bytes of the unit each record's token covers.
    bytes: Vec<Range<usize>>,
    /// `bytes.len() × slots` probabilities, record after record.
    pooled: Vec<f32>,
    /// The start probability of each record.
    start: Vec<f32>,
}

/// One token as one window saw it.
#[derive(Debug, PartialEq)]
pub struct TokenRecord<'a> {
    /// The bytes of the unit the token covers. Never a character offset.
    pub bytes: Range<usize>,
    /// The token's probability per entity type, in [`Labels::types`] order,
    /// then `O`. They sum to 1.
    pub pooled: &'a [f32],
    /// The probability that the token starts an entity: its `B-` and `S-`
    /// labels summed.
    pub start: f32,
}

impl TokenProbs {
    pub(crate) fn new(slots: usize) -> Self {
        Self {
            slots,
            bytes: Vec::new(),
            pooled: Vec::new(),
            start: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Pooled slots per record: the entity types, then `O`.
    pub(crate) fn slots(&self) -> usize {
        self.slots
    }

    pub fn records(&self) -> impl Iterator<Item = TokenRecord<'_>> {
        self.bytes
            .iter()
            .zip(self.pooled.chunks_exact(self.slots))
            .zip(&self.start)
            .map(|((bytes, pooled), &start)| TokenRecord {
                bytes: bytes.clone(),
                pooled,
                start,
            })
    }

    fn push(&mut self, labels: &Labels, bytes: Range<usize>, logits: &[f32]) {
        let at = self.pooled.len();
        self.pooled.resize(at + self.slots, 0.0);
        self.start.push(labels.pool(logits, &mut self.pooled[at..]));
        self.bytes.push(bytes);
    }

    /// Adds a record with pooled probabilities made by hand.
    #[cfg(test)]
    pub(crate) fn push_pooled(&mut self, bytes: Range<usize>, pooled: &[f32], start: f32) {
        assert_eq!(pooled.len(), self.slots);
        self.pooled.extend_from_slice(pooled);
        self.start.push(start);
        self.bytes.push(bytes);
    }
}

impl TokenWorker {
    /// The model's labels, read from `id2label` at load.
    pub fn labels(&self) -> &Labels {
        &self.head.labels
    }

    /// Runs every window of `text` and returns each token's pooled
    /// probabilities. A text that is empty or holds only whitespace runs no
    /// inference and returns no record. Windows run in order, and the first
    /// failure ends the run. A cancel ends it with [`RunError::Cancelled`].
    pub fn run(&mut self, text: &str, cancel: &Cancel) -> Result<TokenProbs, RunError> {
        if cancel.is_cancelled() {
            return Err(RunError::Cancelled);
        }
        let labels = std::sync::Arc::clone(&self.head.labels);
        let mut probs = TokenProbs::new(labels.slots());
        if text.trim().is_empty() {
            return Ok(probs);
        }
        let encoding = self
            .tokenizer
            .encode(text, false)
            .map_err(|_| RunError::Tokenizer)?;
        let width = self.width as usize;
        for span in self.windowing.spans(encoding.len())? {
            if cancel.is_cancelled() {
                return Err(RunError::Cancelled);
            }
            let window = self.window(&encoding, span)?;
            // Row j of the logits is token j of the window; padding comes after.
            let logits = self.infer(&ids(&window), cancel)?;
            let tokens = window
                .get_offsets()
                .iter()
                .zip(window.get_special_tokens_mask());
            for (row, (&(start, end), &special)) in logits.chunks_exact(width).zip(tokens) {
                if special == 0 {
                    probs.push(&labels, start..end, row);
                }
            }
            #[cfg(test)]
            if self.cancel_after == Some(self.inferences) {
                cancel.cancel();
            }
        }
        Ok(probs)
    }

    /// Runs every window of `text` and decodes its entities into trimmed
    /// spans, in text order. No span crosses one of `boundaries`, byte
    /// positions of `text`. A blank text runs no inference and has no span.
    pub fn spans(
        &mut self,
        text: &str,
        boundaries: &Boundaries,
        cancel: &Cancel,
    ) -> Result<Vec<Span>, RunError> {
        let probs = self.run(text, cancel)?;
        Ok(decode(text, &probs, boundaries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::AdapterKind;
    use crate::fixtures::{Fixture, TRIGGER, TokenizerFixture, write_config};
    use crate::load::{LoadError, LoadSettings, load};
    use crate::run::uncancelled;
    use std::num::NonZeroUsize;
    use test_case::test_case;

    const LABELS: [&str; 3] = ["O", "B-SECRET", "I-SECRET"];

    /// A token worker over a fixture, written to a fresh directory.
    struct Case {
        model: Fixture,
        labels: Vec<&'static str>,
        config: bool,
        max_tokens: usize,
        max_body_size: usize,
    }

    impl Default for Case {
        /// The trigger token model, `[CLS] $A [SEP]`: window 4, overlap 1, stride 3.
        fn default() -> Self {
            Self {
                model: Fixture {
                    tokens: true,
                    trigger: true,
                    width: 3,
                    ..Fixture::default()
                },
                labels: LABELS.to_vec(),
                config: true,
                max_tokens: 6,
                max_body_size: 1 << 20,
            }
        }
    }

    impl Case {
        fn load(&self) -> Result<Vec<TokenWorker>, LoadError> {
            let dir = tempfile::tempdir().unwrap();
            let settings = LoadSettings {
                adapter: AdapterKind::TokenClassifier,
                model_path: self.model.write(dir.path()),
                tokenizer_path: TokenizerFixture {
                    special_tokens: true,
                    ..TokenizerFixture::default()
                }
                .write(dir.path()),
                config_path: self.config.then(|| write_config(dir.path(), &self.labels)),
                max_tokens: self.max_tokens,
                overlap_tokens: Some(1),
                max_body_size: NonZeroUsize::new(self.max_body_size).unwrap(),
                workers: NonZeroUsize::new(2).unwrap(),
            };
            load(&settings).map(|w| w.into_tokens())
        }

        fn worker(&self) -> TokenWorker {
            let mut worker = self.load().unwrap().pop().unwrap();
            worker.inferences = 0; // the smoke inference is not part of a run
            worker
        }
    }

    #[test]
    fn a_token_classifier_loads_with_its_labels() {
        let workers = Case::default().load().unwrap();
        assert_eq!(workers.len(), 2);
        assert_eq!(workers[0].labels().types(), ["SECRET"]);
    }

    #[test]
    fn a_token_classifier_needs_a_config() {
        let err = Case {
            config: false,
            ..Case::default()
        }
        .load()
        .err()
        .unwrap();
        assert!(matches!(err, LoadError::ConfigMissing(_)), "got: {err}");
        assert!(err.to_string().contains("token_classifier"));
    }

    #[test]
    fn a_bad_config_stops_the_load() {
        let err = Case {
            labels: vec!["B-SECRET", "I-SECRET", "S-SECRET"],
            ..Case::default()
        }
        .load()
        .err()
        .unwrap();
        assert!(matches!(err, LoadError::Id2Label { .. }), "got: {err}");
    }

    #[test]
    fn the_output_width_must_equal_the_label_count() {
        let err = Case {
            labels: vec!["O", "B-SECRET", "I-SECRET", "B-OTHER", "I-OTHER"],
            ..Case::default()
        }
        .load()
        .err()
        .unwrap();
        assert!(
            matches!(
                err,
                LoadError::LabelCount {
                    labels: 5,
                    found: 3,
                    ..
                }
            ),
            "got: {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains('5') && msg.contains('3'), "got: {msg}");
    }

    #[test]
    fn a_rank_two_output_is_refused() {
        let err = Case {
            model: Fixture {
                width: 3,
                ..Fixture::default()
            },
            ..Case::default()
        }
        .load()
        .err()
        .unwrap();
        assert!(
            matches!(
                err,
                LoadError::OutputRank {
                    found: 2,
                    expected: 3
                }
            ),
            "got: {err}"
        );
        assert!(err.to_string().contains("rank 2"));
    }

    #[test]
    fn a_text_classifier_refuses_a_token_model() {
        let dir = tempfile::tempdir().unwrap();
        let settings = LoadSettings {
            adapter: AdapterKind::TextClassifier,
            model_path: Fixture {
                tokens: true,
                ..Fixture::default()
            }
            .write(dir.path()),
            tokenizer_path: TokenizerFixture::default().write(dir.path()),
            config_path: None,
            max_tokens: 16,
            overlap_tokens: None,
            max_body_size: NonZeroUsize::MIN,
            workers: NonZeroUsize::MIN,
        };
        let err = load(&settings).err().unwrap();
        assert!(
            matches!(
                err,
                LoadError::OutputRank {
                    found: 3,
                    expected: 2
                }
            ),
            "got: {err}"
        );
    }

    #[test]
    fn a_window_with_too_few_output_rows_is_an_error() {
        // The smoke input has 3 tokens + 2 special: 5 rows are kept. A window
        // of 4 tokens + 2 special returns 5 rows for 6.
        let mut worker = Case {
            model: Fixture {
                max_output_tokens: Some(5),
                ..Case::default().model
            },
            ..Case::default()
        }
        .worker();
        let err = worker
            .run("voidwall smoke test trigger", &uncancelled())
            .unwrap_err();
        assert!(
            matches!(&err, RunError::OutputShape { found, expected }
                if *found == [1, 5, 3] && *expected == [1, 6, 3]),
            "got: {err}"
        );
        assert!(err.to_string().contains("[1, 5, 3]"));
    }

    /// The bytes of each record, as text.
    fn record_texts<'a>(text: &'a str, probs: &TokenProbs) -> Vec<&'a str> {
        probs.records().map(|r| &text[r.bytes]).collect()
    }

    #[test]
    fn a_token_is_recorded_once_per_window_that_holds_it() {
        let mut worker = Case::default().worker();
        // 6 tokens, window 4, stride 3: [0, 4), [2, 6). Tokens 2 and 3 are in both.
        let text = "voidwall smoke test trigger voidwall smoke";
        let probs = worker.run(text, &uncancelled()).unwrap();
        assert_eq!(worker.inferences, 2);
        assert_eq!(
            record_texts(text, &probs),
            [
                "voidwall", "smoke", "test", "trigger", // window 1
                "test", "trigger", "voidwall", "smoke", // window 2
            ]
        );
        let windows: Vec<_> = probs.records().map(|r| r.bytes).collect();
        assert_eq!(windows[2..4], windows[4..6], "same bytes in both windows");
    }

    #[test]
    fn records_hold_each_tokens_pooled_probabilities() {
        let mut worker = Case::default().worker();
        let probs = worker
            .run(&format!("voidwall {TRIGGER}"), &uncancelled())
            .unwrap();
        let records: Vec<_> = probs.records().collect();
        assert_eq!(records.len(), 2);
        for record in &records {
            assert_eq!(record.pooled.len(), 2); // SECRET, O
            assert!((record.pooled.iter().sum::<f32>() - 1.0).abs() < 1e-6);
        }
        // Logits [2, 0, 0]: O = e² / (e² + 2).
        let outside = 2f32.exp() / (2f32.exp() + 2.0);
        assert!((records[0].pooled[1] - outside).abs() < 1e-6, "{records:?}");
        assert!((records[0].start - (1.0 - outside) / 2.0).abs() < 1e-6);
        // Logits [-8, 10, 0]: B-SECRET wins.
        assert!(
            records[1].pooled[0] > 0.99 && records[1].start > 0.99,
            "{records:?}"
        );
    }

    #[test]
    fn a_fixed_length_model_records_no_padding_row() {
        // 2 tokens + 2 special, padded to 6: the 2 padding rows record nothing.
        let text = format!("voidwall {TRIGGER}");
        let mut fixed = Case {
            model: Fixture {
                fixed_seq: Some(6),
                ..Case::default().model
            },
            ..Case::default()
        }
        .worker();
        assert_eq!(fixed.layout.fixed_seq, Some(6));
        let padded = fixed.run(&text, &uncancelled()).unwrap();
        let plain = Case::default().worker().run(&text, &uncancelled()).unwrap();
        assert_eq!(record_texts(&text, &padded), ["voidwall", TRIGGER]);
        assert_eq!(
            padded.records().collect::<Vec<_>>(),
            plain.records().collect::<Vec<_>>()
        );
    }

    #[test_case("" ; "empty")]
    #[test_case(" \n\t \n" ; "whitespace only")]
    fn blank_text_runs_no_inference(text: &str) {
        let mut worker = Case::default().worker();
        assert!(worker.run(text, &uncancelled()).unwrap().is_empty());
        assert!(
            worker
                .spans(text, &Boundaries::default(), &uncancelled())
                .unwrap()
                .is_empty()
        );
        assert_eq!(worker.inferences, 0);
    }

    #[test]
    fn a_run_decodes_into_trimmed_spans() {
        // B-SECRET wins every trigger token, each with start probability ≈ 1,
        // so the two triggers are two spans. O wins every other token.
        let mut worker = Case::default().worker();
        let text = format!("voidwall ({TRIGGER}). smoke \"{TRIGGER}\"");
        let spans = worker
            .spans(&text, &Boundaries::default(), &uncancelled())
            .unwrap();
        let found: Vec<_> = spans
            .iter()
            .map(|s| (&text[s.bytes.clone()], s.ty))
            .collect();
        assert_eq!(found, [(TRIGGER, 0), (TRIGGER, 0)]);
        assert!(spans.iter().all(|s| s.confidence > 0.99), "{spans:?}");
    }

    #[test]
    fn offsets_are_bytes_not_characters() {
        let mut worker = Case::default().worker();
        // "zażółć" is 6 characters and 10 bytes; the tokenizer does not know it.
        let text = "zażółć trigger";
        let probs = worker.run(text, &uncancelled()).unwrap();
        let bytes: Vec<_> = probs.records().map(|r| r.bytes).collect();
        assert_eq!(bytes, [0..10, 11..18]);
        assert_eq!(record_texts(text, &probs), ["zażółć", "trigger"]);
    }

    #[test]
    fn the_window_limit_stops_the_run_before_any_inference() {
        // stride 3, max_body_size 6: limit 2. 8 tokens need 3 windows.
        let mut worker = Case {
            max_body_size: 6,
            ..Case::default()
        }
        .worker();
        let err = worker
            .run(
                "voidwall smoke test voidwall smoke test voidwall trigger",
                &uncancelled(),
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                RunError::WindowLimit {
                    windows: 3,
                    limit: 2
                }
            ),
            "got: {err}"
        );
        assert_eq!(worker.inferences, 0);
    }

    /// 9 tokens, window 4, stride 3: three windows.
    const THREE_WINDOWS: &str = "voidwall smoke test voidwall smoke test voidwall smoke trigger";

    #[test]
    fn a_run_cancelled_before_it_starts_runs_no_inference() {
        let mut worker = Case::default().worker();
        let cancel = Cancel::new().unwrap();
        cancel.cancel();
        let err = worker.run(THREE_WINDOWS, &cancel).unwrap_err();
        assert!(matches!(err, RunError::Cancelled), "got: {err}");
        assert_eq!(worker.inferences, 0);
    }

    #[test]
    fn a_run_cancelled_between_windows_starts_no_further_window() {
        let mut worker = Case::default().worker();
        worker.cancel_after = Some(1);
        let err = worker
            .run(THREE_WINDOWS, &Cancel::new().unwrap())
            .unwrap_err();
        assert!(matches!(err, RunError::Cancelled), "got: {err}");
        assert_eq!(worker.inferences, 1, "no window started after the cancel");
    }

    #[test]
    fn a_token_worker_can_move_to_its_thread() {
        fn assert_send<T: Send>() {}
        assert_send::<TokenWorker>();
    }

    /// The worker count [`int8_rss_probe`] loads; unset, the probe does nothing.
    const PROBE_WORKERS: &str = "VOIDWALL_INT8_PROBE_WORKERS";

    /// The real INT8 PII model loads, its `UINT8` embedding found and its
    /// INT8 weights shared: six workers keep at most 1.2× the memory of one.
    /// `PII_MODEL_DIR` holds `onnx/model_quantized.onnx`, `tokenizer.json`
    /// and `config.json`. Each count loads in a fresh process, so memory
    /// freed by one load cannot hide in the other's.
    ///
    /// ```text
    /// PII_MODEL_DIR=<dir> cargo test -p voidwall-ml --release -- --ignored int8
    /// ```
    #[test]
    #[ignore = "needs the INT8 PII model; set PII_MODEL_DIR"]
    fn the_int8_pii_model_loads_with_shared_weights() {
        assert!(
            std::env::var_os("PII_MODEL_DIR").is_some(),
            "set PII_MODEL_DIR to the PII model directory"
        );
        let rss_kib = |workers: usize| -> f64 {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "--nocapture"])
                .arg("token::tests::int8_rss_probe")
                .env(PROBE_WORKERS, workers.to_string())
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success(),
                "{workers} workers: {stdout}{}",
                String::from_utf8_lossy(&out.stderr)
            );
            stdout
                .lines()
                .find_map(|l| l.strip_prefix("RSS_KIB "))
                .expect("the probe prints its RSS")
                .parse()
                .unwrap()
        };
        let (one, six) = (rss_kib(1), rss_kib(6));
        eprintln!(
            "RSS after load: 1 worker {:.0} MiB, 6 workers {:.0} MiB ({:.2}×)",
            one / 1024.0,
            six / 1024.0,
            six / one
        );
        assert!(six <= 1.2 * one, "6 workers keep {:.2}× of 1", six / one);
    }

    /// Loads the INT8 PII model with [`PROBE_WORKERS`] workers, runs one
    /// placeholder text with non-ASCII characters, and prints the RSS.
    #[test]
    #[ignore = "a child of the_int8_pii_model_loads_with_shared_weights"]
    fn int8_rss_probe() {
        let Some(workers) = std::env::var(PROBE_WORKERS).ok() else {
            return;
        };
        let dir = std::path::PathBuf::from(std::env::var_os("PII_MODEL_DIR").unwrap());
        let settings = LoadSettings {
            adapter: AdapterKind::TokenClassifier,
            model_path: dir.join("onnx/model_quantized.onnx"),
            tokenizer_path: dir.join("tokenizer.json"),
            config_path: Some(dir.join("config.json")),
            max_tokens: 512,
            overlap_tokens: Some(128),
            max_body_size: NonZeroUsize::new(1 << 20).unwrap(),
            workers: NonZeroUsize::new(workers.parse().unwrap()).unwrap(),
        };
        let mut loaded = load(&settings).unwrap().into_tokens();
        let rss = std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))
            .and_then(|v| v.split_whitespace().next())
            .unwrap()
            .to_owned();

        // D3: the real tokenizer's offsets are bytes on character boundaries.
        let text = "Zażółć gęślą jaźń: Jan Kowalski, ul. Przykładowa 1, 00-000 Warszawa.";
        let probs = loaded[0].run(text, &uncancelled()).unwrap();
        assert!(!probs.is_empty());
        for record in probs.records() {
            assert!(
                text.is_char_boundary(record.bytes.start)
                    && text.is_char_boundary(record.bytes.end)
                    && record.bytes.end <= text.len(),
                "offsets {:?} are not byte positions on character boundaries",
                record.bytes
            );
        }
        let last = probs.records().last().unwrap().bytes;
        assert_eq!(last.end, text.len(), "the last token ends at the last byte");
        println!("RSS_KIB {rss}");
    }
}
