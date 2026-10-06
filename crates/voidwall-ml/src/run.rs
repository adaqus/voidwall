//! Scoring one unit: its tokens, cut into overlapping windows, one inference
//! per window, and the highest window score.

use std::fmt;
use std::num::NonZeroUsize;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};

use ort::session::RunOptions;
use ort::value::Tensor;
use tokenizers::Encoding;

use crate::load::{LoadError, Worker};

/// The overlap when the load request names none, unless `max_tokens / 2` is lower.
const DEFAULT_OVERLAP: usize = 128;

/// The overlap between windows when the load request names none:
/// `min(128, max_tokens / 2)`, so the default always meets [`check_overlap`].
pub fn default_overlap(max_tokens: usize) -> usize {
    DEFAULT_OVERLAP.min(max_tokens / 2)
}

/// Checks the bound on an overlap the operator sets: at most `max_tokens / 2`.
pub fn check_overlap(max_tokens: usize, overlap: usize) -> Result<(), LoadError> {
    let bound = max_tokens / 2;
    if overlap > bound {
        return Err(LoadError::OverlapTooLarge { overlap, bound });
    }
    Ok(())
}

/// Stops one run from another thread. Share it through an `Arc`.
///
/// A run checks the flag before it tokenizes and before each window, and
/// ONNX Runtime checks its own terminate flag between graph nodes, so a
/// cancelled run stops within about one node.
pub struct Cancel {
    options: RunOptions,
    cancelled: AtomicBool,
}

impl Cancel {
    /// Fresh options for one job. Cancelling is final: a job that needs to run
    /// again takes a new `Cancel`.
    pub fn new() -> Result<Self, RunError> {
        Ok(Self {
            options: RunOptions::new().map_err(|e| RunError::Inference(e.to_string()))?,
            cancelled: AtomicBool::new(false),
        })
    }

    /// Stops the run. The flag is set first: ONNX Runtime's flag is sticky,
    /// so a cancel that lands between a check and the next inference still
    /// stops that inference at its first node.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        // A failed terminate leaves the flag, which still stops the next window.
        let _ = self.options.terminate();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// A `Cancel` nobody cancels, for tests that only score.
#[cfg(test)]
pub(crate) fn uncancelled() -> Cancel {
    Cancel::new().expect("fresh run options")
}

/// Why scoring one unit failed. No variant carries the unit's text or its
/// token IDs.
#[derive(Debug)]
pub enum RunError {
    /// The run was cancelled through its [`Cancel`]. Not a failure: nobody
    /// waits for the score any more.
    Cancelled,
    /// The tokenizer failed. Its message is dropped, because it may quote the input.
    Tokenizer,
    WindowLimit {
        windows: usize,
        limit: usize,
    },
    /// ONNX Runtime's message. ONNX Runtime sees token IDs only, never text.
    Inference(String),
    OutputShape {
        found: Vec<i64>,
        width: i64,
    },
    NonFinite,
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("the run was cancelled"),
            Self::Tokenizer => f.write_str("the tokenizer could not encode the unit"),
            Self::WindowLimit { windows, limit } => {
                write!(f, "the unit needs {windows} windows; the limit is {limit}")
            }
            Self::Inference(reason) => write!(f, "the inference failed: {reason}"),
            Self::OutputShape { found, width } => write!(
                f,
                "the output has shape {found:?}; [1, {width}] is required"
            ),
            Self::NonFinite => {
                f.write_str("the inference returned a non-finite output (NaN or infinity)")
            }
        }
    }
}

impl std::error::Error for RunError {}

/// How one load cuts a unit's tokens into windows.
///
/// ```text
/// window = max_tokens − special tokens     stride = window − overlap
/// tokens 0 ───────────────────────────────────────────────────────── n
///        [0, window)
///                 [stride, stride + window)
///                                                    [n − window, n)   ← the last ends at n
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Windowing {
    window: usize,
    stride: usize,
    /// `ceil(max_body_size / stride)`.
    limit: usize,
}

impl Windowing {
    /// `special` is the number of special tokens the tokenizer adds to one sequence.
    pub(crate) fn new(
        max_tokens: usize,
        special: usize,
        overlap: Option<usize>,
        max_body_size: NonZeroUsize,
    ) -> Result<Self, LoadError> {
        let overlap = match overlap {
            Some(overlap) => {
                check_overlap(max_tokens, overlap)?;
                overlap
            }
            None => default_overlap(max_tokens),
        };
        let window = max_tokens.saturating_sub(special);
        if window <= overlap {
            return Err(LoadError::WindowTooShort { window, overlap });
        }
        let stride = window - overlap;
        Ok(Self {
            window,
            stride,
            limit: max_body_size.get().div_ceil(stride),
        })
    }

    /// The token ranges of the windows of a unit of `n` tokens, or
    /// [`RunError::WindowLimit`] when it needs more windows than the limit.
    /// A unit that fits in one window, the empty unit included, has one.
    pub(crate) fn spans(self, n: usize) -> Result<impl Iterator<Item = Range<usize>>, RunError> {
        let windows = if n <= self.window {
            1
        } else {
            1 + (n - self.window).div_ceil(self.stride)
        };
        if windows > self.limit {
            return Err(RunError::WindowLimit {
                windows,
                limit: self.limit,
            });
        }
        Ok((0..windows).map(move |i| {
            if i + 1 == windows {
                n.saturating_sub(self.window)..n
            } else {
                i * self.stride..i * self.stride + self.window
            }
        }))
    }
}

/// The `input_ids` and `attention_mask` of one window. With a fixed sequence
/// length `n` the window is padded to `n` with `pad_id` under mask 0 (or cut
/// to `n`, which only the smoke input can need).
pub(crate) fn window_inputs(
    ids: &[i64],
    fixed_seq: Option<usize>,
    pad_id: i64,
) -> (Vec<i64>, Vec<i64>) {
    let mut ids = ids.to_vec();
    let mut mask = vec![1; ids.len()];
    if let Some(n) = fixed_seq {
        ids.resize(n, pad_id);
        mask.resize(n, 0);
    }
    (ids, mask)
}

/// The tokens `span` of an encoding without special tokens, as an encoding of
/// its own, so the post-processor can add the special tokens to it.
fn chunk(encoding: &Encoding, span: Range<usize>) -> Encoding {
    Encoding::new(
        encoding.get_ids()[span.clone()].to_vec(),
        encoding.get_type_ids()[span.clone()].to_vec(),
        encoding.get_tokens()[span.clone()].to_vec(),
        encoding.get_word_ids()[span.clone()].to_vec(),
        encoding.get_offsets()[span.clone()].to_vec(),
        encoding.get_special_tokens_mask()[span.clone()].to_vec(),
        encoding.get_attention_mask()[span].to_vec(),
        Vec::new(),
        Default::default(),
    )
}

impl Worker {
    /// The unit's score, in the adapter's score range: the highest score of
    /// its windows. Windows run in order, and the first failure ends the run.
    /// A cancel ends it with [`RunError::Cancelled`].
    pub fn score(&mut self, text: &str, cancel: &Cancel) -> Result<f32, RunError> {
        if cancel.is_cancelled() {
            return Err(RunError::Cancelled);
        }
        let encoding = self
            .tokenizer
            .encode(text, false)
            .map_err(|_| RunError::Tokenizer)?;
        let mut best = 0.0f32;
        for span in self.windowing.spans(encoding.len())? {
            if cancel.is_cancelled() {
                return Err(RunError::Cancelled);
            }
            let ids = self.window_ids(&encoding, span)?;
            let logits = self.infer(&ids, cancel)?;
            best = best.max((self.window_score)(&logits));
            #[cfg(test)]
            if self.cancel_after == Some(self.inferences) {
                cancel.cancel();
            }
        }
        Ok(best)
    }

    /// The token IDs of one window, special tokens added.
    pub(crate) fn window_ids(
        &self,
        encoding: &Encoding,
        span: Range<usize>,
    ) -> Result<Vec<i64>, RunError> {
        let window = self
            .tokenizer
            .post_process(chunk(encoding, span), None, true)
            .map_err(|_| RunError::Tokenizer)?;
        Ok(window.get_ids().iter().map(|&id| i64::from(id)).collect())
    }

    /// One inference on one window: returns its logits once they have shape
    /// `[1, width]` and are all finite. The load's smoke inference runs this too.
    /// A run error after a cancel is [`RunError::Cancelled`], whatever ONNX
    /// Runtime's message says.
    pub(crate) fn infer(&mut self, ids: &[i64], cancel: &Cancel) -> Result<Vec<f32>, RunError> {
        #[cfg(test)]
        {
            self.inferences += 1;
        }
        let failed = |e: ort::Error| RunError::Inference(e.to_string());
        let (ids, mask) = window_inputs(ids, self.layout.fixed_seq, self.pad_id);
        let len = ids.len();
        let shape = [1usize, len];
        let mut inputs = ort::inputs![
            "input_ids" => Tensor::from_array((shape, ids)).map_err(failed)?,
            "attention_mask" => Tensor::from_array((shape, mask)).map_err(failed)?,
        ];
        if self.layout.token_type_ids {
            let zeros = Tensor::from_array((shape, vec![0i64; len])).map_err(failed)?;
            inputs.push(("token_type_ids".into(), zeros.into()));
        }
        let outputs = self
            .session
            .run_with_options(inputs, &cancel.options)
            .map_err(|e| {
                if cancel.is_cancelled() {
                    RunError::Cancelled
                } else {
                    failed(e)
                }
            })?;
        let (out_shape, values) = outputs[0].try_extract_tensor::<f32>().map_err(failed)?;
        if **out_shape != [1, self.width] {
            return Err(RunError::OutputShape {
                found: out_shape.to_vec(),
                width: self.width,
            });
        }
        if !values.iter().all(|v| v.is_finite()) {
            return Err(RunError::NonFinite);
        }
        Ok(values.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{Adapter, AdapterKind, TextClassifier};
    use crate::fixtures::{Fixture, PAD_ID, TRIGGER_ID, TokenizerFixture};
    use crate::load::{LoadSettings, load};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use test_case::test_case;

    fn windowing(window: usize, overlap: usize, max_body_size: usize) -> Windowing {
        Windowing::new(
            window,
            0,
            Some(overlap),
            NonZeroUsize::new(max_body_size).unwrap(),
        )
        .unwrap()
    }

    fn spans(w: Windowing, n: usize) -> Vec<Range<usize>> {
        w.spans(n).unwrap().collect()
    }

    #[test_case(512, 128 ; "long window")]
    #[test_case(64, 32 ; "short window")]
    #[test_case(10, 5 ; "shortest window")]
    fn the_default_overlap(max_tokens: usize, expected: usize) {
        assert_eq!(default_overlap(max_tokens), expected);
    }

    #[test_case(16, 8, None ; "at the bound")]
    #[test_case(16, 0, None ; "no overlap")]
    #[test_case(16, 9, Some(&["9", "8"][..]) ; "above the bound")]
    fn the_overlap_is_bounded(max_tokens: usize, overlap: usize, named: Option<&[&str]>) {
        match (check_overlap(max_tokens, overlap), named) {
            (Ok(()), None) => {}
            (Err(err), Some(parts)) => {
                assert!(matches!(err, LoadError::OverlapTooLarge { .. }));
                let msg = err.to_string();
                assert!(parts.iter().all(|p| msg.contains(p)), "got: {msg}");
            }
            (result, _) => panic!("unexpected: {result:?}"),
        }
    }

    #[test]
    fn a_window_not_longer_than_the_overlap_is_refused() {
        // max_tokens 16, 8 special tokens: the window of 8 equals the overlap of 8.
        let err = Windowing::new(16, 8, Some(8), NonZeroUsize::MIN).unwrap_err();
        assert!(
            matches!(
                err,
                LoadError::WindowTooShort {
                    window: 8,
                    overlap: 8
                }
            ),
            "got: {err}"
        );
    }

    #[test_case(0, &[(0, 0)] ; "empty unit")]
    #[test_case(3, &[(0, 3)] ; "shorter than the window")]
    #[test_case(8, &[(0, 8)] ; "exactly one window")]
    #[test_case(9, &[(0, 8), (1, 9)] ; "one token more")]
    #[test_case(14, &[(0, 8), (6, 14)] ; "two full windows")]
    #[test_case(15, &[(0, 8), (6, 14), (7, 15)] ; "last window aligned to the end")]
    #[test_case(20, &[(0, 8), (6, 14), (12, 20)] ; "three full windows")]
    fn a_unit_is_cut_into_windows(n: usize, expected: &[(usize, usize)]) {
        // window 8, overlap 2: stride 6.
        let expected: Vec<_> = expected.iter().map(|&(start, end)| start..end).collect();
        assert_eq!(spans(windowing(8, 2, 1 << 20), n), expected);
    }

    #[test_case(8, 0 ; "no overlap")]
    #[test_case(8, 3 ; "some overlap")]
    #[test_case(8, 4 ; "overlap at the bound")]
    #[test_case(510, 128 ; "a real window")]
    fn windows_cover_every_token_with_the_stride(window: usize, overlap: usize) {
        let w = windowing(window, overlap, 1 << 20);
        let stride = window - overlap;
        for n in [window + 1, 3 * window, 10 * window + 7] {
            let spans = spans(w, n);
            assert_eq!(spans.last().unwrap().end, n);
            assert!(spans.iter().all(|s| s.len() == window));
            for pair in spans.windows(2) {
                let step = pair[1].start - pair[0].start;
                assert!(step <= stride && pair[1].start <= pair[0].end);
            }
            for pair in spans[..spans.len() - 1].windows(2) {
                assert_eq!(pair[1].start - pair[0].start, stride);
            }
        }
    }

    #[test]
    fn the_window_limit_is_met_and_exceeded() {
        // stride 6, max_body_size 12: limit ceil(12 / 6) = 2.
        let w = windowing(8, 2, 12);
        assert_eq!(spans(w, 14).len(), 2);
        let err = w.spans(15).err().unwrap();
        assert!(matches!(
            err,
            RunError::WindowLimit {
                windows: 3,
                limit: 2
            }
        ));
        let msg = err.to_string();
        assert!(msg.contains('3') && msg.contains('2'), "got: {msg}");
    }

    #[test]
    fn a_window_is_padded_to_a_fixed_length() {
        let (ids, mask) = window_inputs(&[1, 2, 3, 4, 5], Some(16), 11);
        assert_eq!(ids.len(), 16);
        assert_eq!(&ids[..5], &[1, 2, 3, 4, 5]);
        assert!(ids[5..].iter().all(|&id| id == 11));
        assert_eq!(&mask[..5], &[1; 5]);
        assert!(mask[5..].iter().all(|&m| m == 0));
    }

    #[test]
    fn a_window_of_a_dynamic_model_is_not_padded() {
        assert_eq!(
            window_inputs(&[1, 2, 3, 4, 5], None, 11),
            (vec![1, 2, 3, 4, 5], vec![1; 5])
        );
    }

    #[test]
    fn a_tokenizer_can_be_shared_by_workers() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<tokenizers::Tokenizer>();
    }

    #[test]
    fn a_cancel_can_be_shared_with_another_thread() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Cancel>();
    }

    /// A test case: a fixture model and tokenizer with the run's settings.
    struct Case {
        model: Fixture,
        tokenizer: TokenizerFixture,
        max_tokens: usize,
        overlap: Option<usize>,
        max_body_size: usize,
    }

    impl Default for Case {
        /// The trigger model, `[CLS] $A [SEP]`: window 4, overlap 1, stride 3.
        fn default() -> Self {
            Self {
                model: Fixture {
                    trigger: true,
                    ..Fixture::default()
                },
                tokenizer: TokenizerFixture {
                    special_tokens: true,
                    ..TokenizerFixture::default()
                },
                max_tokens: 6,
                overlap: Some(1),
                max_body_size: 1 << 20,
            }
        }
    }

    impl Case {
        fn worker(&self) -> Worker {
            let dir = tempfile::tempdir().unwrap();
            let settings = LoadSettings {
                adapter: AdapterKind::TextClassifier,
                model_path: self.model.write(dir.path()),
                tokenizer_path: self.tokenizer.write(dir.path()),
                max_tokens: self.max_tokens,
                overlap_tokens: self.overlap,
                max_body_size: NonZeroUsize::new(self.max_body_size).unwrap(),
                workers: NonZeroUsize::MIN,
            };
            let mut worker = load(&settings).unwrap().pop().unwrap();
            worker.inferences = 0; // the smoke inference is not part of a run
            worker
        }
    }

    /// The score of a window that holds the trigger once: logits `[-9.5, 9.5]`.
    fn trigger_score() -> f32 {
        TextClassifier::window_score(&[-9.5, 9.5])
    }

    /// The score of a window without the trigger: logits `[0.5, -0.5]`.
    fn plain_score() -> f32 {
        TextClassifier::window_score(&[0.5, -0.5])
    }

    #[test]
    fn a_chunk_gets_the_special_tokens() {
        let worker = Case::default().worker();
        let encoding = worker
            .tokenizer
            .encode("voidwall smoke test trigger", false)
            .unwrap();
        // [CLS] 9, smoke 2, test 3, [SEP] 10.
        assert_eq!(
            worker.window_ids(&encoding, 1..3).unwrap(),
            vec![9, 2, 3, 10]
        );
    }

    #[test]
    fn a_short_unit_runs_one_inference() {
        let mut worker = Case::default().worker();
        assert_eq!(
            worker.score("voidwall smoke", &uncancelled()).unwrap(),
            plain_score()
        );
        assert_eq!(worker.inferences, 1);
    }

    #[test]
    fn an_empty_unit_runs_one_inference_on_the_special_tokens() {
        let mut worker = Case::default().worker();
        assert_eq!(worker.score("", &uncancelled()).unwrap(), plain_score());
        assert_eq!(worker.inferences, 1);
    }

    #[test]
    fn a_long_unit_scores_its_highest_window() {
        let mut worker = Case::default().worker();
        // 8 tokens, window 4, stride 3: [0, 4), [3, 7), [4, 8). Only the last
        // holds the trigger.
        let text = "voidwall smoke test voidwall smoke test voidwall trigger";
        assert_eq!(worker.score(text, &uncancelled()).unwrap(), trigger_score());
        assert_eq!(worker.inferences, 3);
        assert!(trigger_score() > 0.9 && plain_score() < 0.5);
    }

    #[test]
    fn truncation_in_the_tokenizer_file_does_not_apply() {
        let mut worker = Case {
            tokenizer: TokenizerFixture {
                special_tokens: true,
                truncate_and_pad: true,
                ..TokenizerFixture::default()
            },
            ..Case::default()
        }
        .worker();
        // The file truncates at 2 tokens; the trigger is the 4th.
        assert_eq!(
            worker
                .score("voidwall smoke test trigger", &uncancelled())
                .unwrap(),
            trigger_score()
        );
    }

    #[test]
    fn a_fixed_length_model_scores_padded_windows() {
        let mut worker = Case {
            model: Fixture {
                trigger: true,
                fixed_seq: Some(6),
                ..Fixture::default()
            },
            tokenizer: TokenizerFixture {
                special_tokens: true,
                truncate_and_pad: true,
                ..TokenizerFixture::default()
            },
            ..Case::default()
        }
        .worker();
        assert_eq!(worker.pad_id, i64::from(PAD_ID));
        // 2 tokens + 2 special, padded to 6 under mask 0.
        assert_eq!(
            worker.score("voidwall trigger", &uncancelled()).unwrap(),
            trigger_score()
        );
        assert_eq!(
            worker.score("voidwall", &uncancelled()).unwrap(),
            plain_score()
        );
    }

    #[test]
    fn the_window_limit_stops_the_run_before_any_inference() {
        // stride 3, max_body_size 6: limit 2.
        let mut worker = Case {
            max_body_size: 6,
            ..Case::default()
        }
        .worker();
        // 7 tokens: [0, 4), [3, 7). The limit is met.
        assert!(
            worker
                .score(
                    "voidwall smoke test voidwall smoke test trigger",
                    &uncancelled()
                )
                .is_ok()
        );
        worker.inferences = 0;
        // 8 tokens need 3 windows.
        let err = worker
            .score(
                "voidwall smoke test voidwall smoke test voidwall trigger",
                &uncancelled(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            RunError::WindowLimit {
                windows: 3,
                limit: 2
            }
        ));
        assert_eq!(worker.inferences, 0);
    }

    /// A word the tokenizer does not know, so it is never in any error.
    const MARKER: &str = "zebra";

    fn plain_case(model: Fixture) -> Case {
        Case {
            model,
            tokenizer: TokenizerFixture::default(),
            max_tokens: 16,
            overlap: None,
            ..Case::default()
        }
    }

    #[test]
    fn a_nan_logit_is_an_error() {
        // The trigger's row is NaN; the smoke text does not hold it.
        let mut worker = plain_case(Fixture {
            nan_row: Some(TRIGGER_ID),
            ..Fixture::default()
        })
        .worker();
        let err = worker
            .score(&format!("{MARKER} trigger"), &uncancelled())
            .unwrap_err();
        assert!(matches!(err, RunError::NonFinite), "got: {err}");
        assert!(err.to_string().contains("non-finite"));
        assert!(!err.to_string().contains(MARKER));
    }

    #[test]
    fn a_failed_inference_is_an_error_without_the_text() {
        // The smoke input has 3 tokens; this unit has 4.
        let mut worker = plain_case(Fixture {
            mask_reshaped_to: Some(3),
            ..Fixture::default()
        })
        .worker();
        let err = worker
            .score(&format!("voidwall smoke {MARKER} test"), &uncancelled())
            .unwrap_err();
        assert!(matches!(err, RunError::Inference(_)), "got: {err}");
        assert!(!err.to_string().contains(MARKER), "got: {err}");
    }

    #[test]
    fn no_run_error_carries_the_unit_text() {
        let mut limited = Case {
            max_body_size: 3,
            ..Case::default()
        }
        .worker();
        let text = format!("voidwall smoke test {MARKER} voidwall smoke test");
        let errors = [
            limited.score(&text, &uncancelled()).unwrap_err(),
            RunError::Tokenizer,
            RunError::OutputShape {
                found: vec![1, 3],
                width: 2,
            },
        ];
        for err in errors {
            let msg = err.to_string();
            assert!(
                !msg.contains(MARKER) && !msg.contains("voidwall"),
                "got: {msg}"
            );
        }
    }

    /// 9 tokens, window 4, stride 3: [0, 4), [3, 7), [5, 9). Three windows.
    const THREE_WINDOWS: &str = "voidwall smoke test voidwall smoke test voidwall smoke trigger";

    /// The default case on a model whose run is slow enough to cancel mid-way.
    fn slow_case() -> Case {
        Case {
            model: Fixture {
                trigger: true,
                slow: Some(600),
                ..Fixture::default()
            },
            ..Case::default()
        }
    }

    #[test]
    fn a_run_cancelled_before_it_starts_runs_no_inference() {
        let mut worker = Case::default().worker();
        let cancel = Cancel::new().unwrap();
        cancel.cancel();
        let err = worker.score(THREE_WINDOWS, &cancel).unwrap_err();
        assert!(matches!(err, RunError::Cancelled), "got: {err}");
        assert_eq!(worker.inferences, 0);
    }

    #[test]
    fn a_run_cancelled_during_an_inference_stops_at_a_node() {
        let mut worker = slow_case().worker();
        let started = Instant::now();
        worker.score(THREE_WINDOWS, &uncancelled()).unwrap();
        let full = started.elapsed();
        assert_eq!(worker.inferences, 3);
        worker.inferences = 0;

        let cancel = Arc::new(Cancel::new().unwrap());
        let canceller = {
            let cancel = Arc::clone(&cancel);
            std::thread::spawn(move || {
                std::thread::sleep(full / 2);
                cancel.cancel();
                Instant::now()
            })
        };
        let err = worker.score(THREE_WINDOWS, &cancel).unwrap_err();
        let returned = Instant::now();
        let cancelled_at = canceller.join().unwrap();

        assert!(matches!(err, RunError::Cancelled), "got: {err}");
        let lag = returned.saturating_duration_since(cancelled_at);
        // Which window the cancel lands in depends on timing; that no window
        // starts after it is checked without timing, between windows.
        assert!(lag < full / 4, "lag {lag:?}, full run {full:?}");
    }

    #[test]
    fn a_run_cancelled_between_windows_starts_no_further_window() {
        let mut worker = Case::default().worker();
        worker.cancel_after = Some(1);
        let err = worker
            .score(THREE_WINDOWS, &Cancel::new().unwrap())
            .unwrap_err();
        assert!(matches!(err, RunError::Cancelled), "got: {err}");
        assert_eq!(worker.inferences, 1, "no window started after the cancel");
    }

    #[test]
    fn a_session_scores_normally_after_a_cancelled_run() {
        let mut worker = slow_case().worker();
        let cancel = Arc::new(Cancel::new().unwrap());
        let canceller = {
            let cancel = Arc::clone(&cancel);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                cancel.cancel();
            })
        };
        let err = worker.score(THREE_WINDOWS, &cancel).unwrap_err();
        canceller.join().unwrap();
        assert!(matches!(err, RunError::Cancelled), "got: {err}");

        let after = worker.score(THREE_WINDOWS, &uncancelled()).unwrap();
        let fresh = slow_case()
            .worker()
            .score(THREE_WINDOWS, &uncancelled())
            .unwrap();
        assert_eq!(after, fresh);
        assert_eq!(after, trigger_score());
    }
}
