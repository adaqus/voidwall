//! The model guard, and the worker pool it owns.
//!
//! One guard per `[guards.<name>]` section. It loads its model into N
//! `voidwall_ml` workers at startup and gives each one its own OS thread:
//! inference is CPU-bound and must never run on the tokio runtime. `detect`
//! hands the units to a pool thread over a bounded channel and awaits the
//! reply on a oneshot, the same shape as the regex PII guard's scanner pool.
//!
//! When the engine abandons the guard, dropping the `detect` future cancels
//! the job's run: the worker stops within about one graph node and takes the
//! next job. A cancelled run is not a failure and produces no reply.
//!
//! A `text_classifier` guard reports one spanless finding per unit. A
//! `token_classifier` guard reports one finding per decoded span, mapped back
//! to the unit's bytes through [`UnitText`].

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{SendTimeoutError, Sender};
use tracing::{debug, error, info};
use voidwall_ml::{Cancel, LoadSettings, OnnxRuntime, RunError, TokenWorker, Worker, Workers};
use voidwall_pii::PiiKind;

use crate::config::ModelGuardConfig;
use crate::error::Error;
use crate::scanner::LogRateLimiter;

use super::finding::Finding;
use super::guard::{DetectFuture, Guard, GuardInput, Interest};
use super::unit::{Unit, UnitId};
use super::unit_text::UnitText;

/// How long a submit waits for a free channel slot before giving up.
const SEND_TIMEOUT: Duration = Duration::from_secs(1);

static CHANNEL_FULL_LIMITER: LogRateLimiter = LogRateLimiter::new(1_000);

/// What turns a unit score into a finding. Shared by every worker thread.
struct Verdict {
    guard: Arc<str>,
    /// The guard's single label.
    kind: Arc<str>,
    /// `None` when the label has no threshold: the guard then reports nothing.
    threshold: Option<f32>,
}

/// What turns a token classifier's spans into findings. Shared by every
/// worker thread.
struct SpanVerdict {
    guard: Arc<str>,
    /// Per entity type of the model, in `Labels::types` order: the rule of a
    /// type the guard reports, or `None` for a type absent from `labels` or
    /// without a threshold.
    rules: Vec<Option<SpanRule>>,
}

/// How one reported label keeps a span.
struct SpanRule {
    kind: Arc<str>,
    /// A span whose confidence is below this gives no finding.
    threshold: f32,
    /// The kinds the span's text must validate as, when the label has
    /// `validate_as`. Validation never empties the list.
    validate_as: Option<Vec<PiiKind>>,
}

/// One message's work: its units, the subset this guard was asked to score,
/// and the handle that stops its run.
struct ModelJob {
    units: Arc<[Unit]>,
    selected: Vec<UnitId>,
    cancel: Arc<Cancel>,
}

/// Cancels a job's run when the `detect` future that owns it is dropped. On
/// a normal finish the job is done, so the cancel touches nothing.
struct CancelOnDrop(Arc<Cancel>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

type Reply = Result<Vec<Finding>, Error>;
type WorkItem = (ModelJob, tokio::sync::oneshot::Sender<Reply>);

/// N OS threads, each owning one loaded worker.
///
/// No explicit shutdown: the pool sits behind a boxed guard inside the
/// engine, so `Drop` closes the channel and joins every thread.
struct ModelPool {
    guard: Arc<str>,
    sender: Option<Sender<WorkItem>>,
    handles: Vec<JoinHandle<()>>,
    /// Jobs a worker started to score, so tests can see a skipped job.
    #[cfg(test)]
    started: Arc<std::sync::atomic::AtomicUsize>,
}

impl ModelPool {
    /// One thread per worker, each running `run` with the shared verdict. The
    /// channel holds four jobs per thread, to absorb short bursts while still
    /// applying backpressure.
    fn new<W, V>(
        guard: Arc<str>,
        workers: Vec<W>,
        verdict: Arc<V>,
        run: fn(&mut W, &V, &ModelJob) -> Option<Reply>,
    ) -> Result<Self, Error>
    where
        W: Send + 'static,
        V: Send + Sync + 'static,
    {
        let (sender, receiver) = crossbeam_channel::bounded::<WorkItem>(workers.len() * 4);
        let mut handles = Vec::with_capacity(workers.len());
        #[cfg(test)]
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        for (thread_id, mut worker) in workers.into_iter().enumerate() {
            let rx = receiver.clone();
            let verdict = Arc::clone(&verdict);
            let name = Arc::clone(&guard);
            #[cfg(test)]
            let started = Arc::clone(&started);
            let handle = std::thread::Builder::new()
                .name(format!("model-{guard}-{thread_id}"))
                .spawn(move || {
                    debug!(guard = %name, thread_id, "model thread started");
                    while let Ok((job, reply_tx)) = rx.recv() {
                        // Nobody waits for this job any more: skip it.
                        if reply_tx.is_closed() {
                            continue;
                        }
                        #[cfg(test)]
                        started.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if let Some(reply) = run(&mut worker, &verdict, &job) {
                            let _ = reply_tx.send(reply);
                        }
                    }
                    debug!(guard = %name, thread_id, "model thread exiting");
                })
                .map_err(|e| {
                    Error::Config(format!(
                        "guards.{guard}: failed to spawn a model thread: {e}"
                    ))
                })?;
            handles.push(handle);
        }

        Ok(Self {
            guard,
            sender: Some(sender),
            handles,
            #[cfg(test)]
            started,
        })
    }

    /// Submit a job and await its findings.
    ///
    /// A full channel blocks the caller (on the tokio blocking pool) for up to
    /// [`SEND_TIMEOUT`], so backpressure reaches the HTTP layer instead of a
    /// burst being rejected at once.
    async fn submit(&self, job: ModelJob) -> Reply {
        let failure = |detail: &str| Error::Inference {
            guard: Arc::clone(&self.guard),
            detail: detail.into(),
        };
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| failure("the model pool is shut down"))?
            .clone();

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let item = (job, reply_tx);
        let send_result =
            tokio::task::spawn_blocking(move || sender.send_timeout(item, SEND_TIMEOUT))
                .await
                .map_err(|_| failure("the blocking send task panicked"))?;

        match send_result {
            Ok(()) => {}
            Err(SendTimeoutError::Timeout(_)) => {
                if let Some(dropped) = CHANNEL_FULL_LIMITER.should_log() {
                    error!(dropped, guard = %self.guard, "model pool channel full");
                }
                return Err(failure("the model pool is overloaded"));
            }
            Err(SendTimeoutError::Disconnected(_)) => {
                error!(guard = %self.guard, "all model threads are dead");
                return Err(failure("all model threads are dead"));
            }
        }

        reply_rx
            .await
            .map_err(|_| failure("a model thread died while scoring"))?
    }
}

impl Drop for ModelPool {
    fn drop(&mut self) {
        self.sender.take();
        for handle in self.handles.drain(..) {
            if let Err(e) = handle.join() {
                error!(?e, guard = %self.guard, "model thread panicked during shutdown");
            }
        }
        info!(guard = %self.guard, "model pool shut down");
    }
}

/// Score the selected units on a worker thread. The first failure ends the
/// job: the message's outcome is then `on_error`'s, whatever the other units
/// score. `None` is a cancelled job: nobody waits for it, so it has no reply,
/// and it is never an error.
fn score_job(worker: &mut Worker, verdict: &Verdict, job: &ModelJob) -> Option<Reply> {
    let mut findings = Vec::new();
    for id in &job.selected {
        let Some(unit) = job.units.get(id.index()) else {
            continue;
        };
        let score = match worker.score(UnitText::new(&unit.content).text(), &job.cancel) {
            Ok(score) => score,
            Err(e) => return run_error(&verdict.guard, e).map(Err),
        };
        if verdict.threshold.is_some_and(|t| score >= t) {
            findings.push(Finding::whole_unit(
                *id,
                &*verdict.kind,
                Arc::clone(&verdict.guard),
                score,
            ));
        }
    }
    Some(Ok(findings))
}

/// Decode the selected units' spans on a worker thread, as [`score_job`]
/// does for scores. A span gives a finding when its type has a rule, its
/// confidence meets the threshold, and its text passes `validate_as`. A span
/// that fails is dropped without a trace: its text is never logged, counted,
/// or returned.
fn span_job(worker: &mut TokenWorker, verdict: &SpanVerdict, job: &ModelJob) -> Option<Reply> {
    let mut findings = Vec::new();
    for id in &job.selected {
        let Some(unit) = job.units.get(id.index()) else {
            continue;
        };
        let text = UnitText::new(&unit.content);
        let spans = match worker.spans(text.text(), text.boundaries(), &job.cancel) {
            Ok(spans) => spans,
            Err(e) => return run_error(&verdict.guard, e).map(Err),
        };
        for span in spans {
            let Some(Some(rule)) = verdict.rules.get(span.ty) else {
                continue;
            };
            if span.confidence < rule.threshold {
                continue;
            }
            if let Some(kinds) = &rule.validate_as
                && !voidwall_pii::validate_as(kinds, &text.text()[span.bytes.clone()])
            {
                continue;
            }
            // A decoded span lies on character boundaries inside one segment,
            // so it always maps; a miss is a bug, reported without the text.
            let Some(source) = text.source(span.bytes) else {
                return Some(Err(Error::Inference {
                    guard: Arc::clone(&verdict.guard),
                    detail: "a span did not map back to the unit's bytes".into(),
                }));
            };
            findings.push(Finding::spanned_with_confidence(
                *id,
                &*rule.kind,
                Arc::clone(&verdict.guard),
                source,
                span.confidence,
            ));
        }
    }
    Some(Ok(findings))
}

/// A run error as the error the handlers act on, or `None` for a cancelled
/// run: nobody waits for it, so it is never an error. Neither variant carries
/// the unit's text: `RunError` never holds it.
fn run_error(guard: &Arc<str>, e: RunError) -> Option<Error> {
    let guard = Arc::clone(guard);
    match e {
        RunError::Cancelled => None,
        RunError::WindowLimit { windows, limit } => Some(Error::WindowLimit {
            guard,
            windows,
            limit,
        }),
        other @ (RunError::Tokenizer
        | RunError::Inference(_)
        | RunError::OutputShape { .. }
        | RunError::NonFinite) => Some(Error::Inference {
            guard,
            detail: other.to_string(),
        }),
    }
}

/// A guard that runs one model over the units its surface admits.
pub(crate) struct ModelGuard {
    name: Arc<str>,
    interest: Interest,
    pool: ModelPool,
}

impl ModelGuard {
    /// Load the guard's model into `threads` workers and start one thread per
    /// worker. A load failure names the guard and stops the start.
    pub(crate) fn new(
        runtime: &OnnxRuntime,
        name: &str,
        config: &ModelGuardConfig,
        max_body_size: usize,
        threads: NonZeroUsize,
    ) -> Result<Self, Error> {
        let config_error = |detail: String| Error::Config(format!("guards.{name}: {detail}"));
        let max_body_size = NonZeroUsize::new(max_body_size)
            .ok_or_else(|| config_error("max_body_size must be at least 1".into()))?;
        let settings = LoadSettings {
            adapter: config.adapter,
            model_path: config.model_path.clone(),
            tokenizer_path: config.tokenizer_path.clone(),
            config_path: config.config_path.clone(),
            max_tokens: config.max_tokens,
            overlap_tokens: config.overlap_tokens,
            max_body_size,
            workers: threads,
        };

        let started = Instant::now();
        let workers =
            voidwall_ml::load(runtime, &settings).map_err(|e| config_error(e.to_string()))?;
        info!(
            guard = name,
            threads = threads.get(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "model guard loaded"
        );

        let guard: Arc<str> = Arc::from(name);
        let pool = match workers {
            Workers::Classifier(workers) => {
                // Validation guarantees exactly one label for `text_classifier`.
                let kind: Arc<str> = Arc::from(config.labels[0].as_str());
                let verdict = Verdict {
                    guard: Arc::clone(&guard),
                    threshold: config.thresholds.get(&*kind).copied(),
                    kind,
                };
                ModelPool::new(Arc::clone(&guard), workers, Arc::new(verdict), score_job)?
            }
            Workers::Token(workers) => {
                // `load` returns at least one worker; all share one label set.
                let types = workers[0].labels().types();
                let rules = types
                    .iter()
                    .map(|ty| span_rule(config, ty))
                    .collect::<Result<_, String>>()
                    .map_err(config_error)?;
                let verdict = SpanVerdict {
                    guard: Arc::clone(&guard),
                    rules,
                };
                ModelPool::new(Arc::clone(&guard), workers, Arc::new(verdict), span_job)?
            }
        };
        Ok(Self {
            name: guard,
            interest: Interest::from_model_surface(&config.surface),
            pool,
        })
    }
}

/// The rule of one entity type of the model: `None` when the guard does not
/// report the type, because `labels` leaves it out or it has no threshold.
fn span_rule(config: &ModelGuardConfig, ty: &str) -> Result<Option<SpanRule>, String> {
    if !config.labels.iter().any(|label| label == ty) {
        return Ok(None);
    }
    let Some(&threshold) = config.thresholds.get(ty) else {
        return Ok(None);
    };
    let validate_as = config
        .validate_as
        .as_ref()
        .and_then(|table| table.get(ty))
        .map(|names| {
            names
                .iter()
                .map(|name| {
                    // Validation already refused a name that is not a kind.
                    PiiKind::from_label(name)
                        .ok_or_else(|| format!("validate_as.{ty}: '{name}' is not a PII kind"))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    Ok(Some(SpanRule {
        kind: Arc::from(ty),
        threshold,
        validate_as,
    }))
}

impl Guard for ModelGuard {
    fn name(&self) -> &Arc<str> {
        &self.name
    }

    fn interest(&self) -> &Interest {
        &self.interest
    }

    fn detect<'a>(&'a self, input: GuardInput<'a>) -> DetectFuture<'a> {
        let units = Arc::clone(input.units);
        let selected = input.selected.to_vec();
        Box::pin(async move {
            let cancel = Arc::new(Cancel::new().map_err(|e| Error::Inference {
                guard: Arc::clone(&self.name),
                detail: e.to_string(),
            })?);
            // Dropped with this future, so an abandoned guard stops its run.
            let _armed = CancelOnDrop(Arc::clone(&cancel));
            let job = ModelJob {
                units,
                selected,
                cancel,
            };
            self.pool.submit(job).await
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ModelGuardSurface, OnError};
    use crate::engine::unit::{UnitContent, Units};
    use crate::structured::OwnedContextFragment;
    use bytes::Bytes;
    use std::collections::BTreeMap;
    use std::path::Path;
    use test_case::test_case;
    use voidwall_ml::AdapterKind;
    use voidwall_ml::fixtures::{Fixture, TRIGGER_ID, TokenizerFixture, runtime, write_config};

    const KIND: &str = "PROMPT_INJECTION";

    /// A guard config over a fixture model written to `dir`.
    fn config(dir: &Path, fixture: Fixture, threshold: Option<f32>) -> ModelGuardConfig {
        ModelGuardConfig {
            adapter: AdapterKind::TextClassifier,
            model_path: fixture.write(dir),
            tokenizer_path: TokenizerFixture::default().write(dir),
            config_path: None,
            max_tokens: 16,
            overlap_tokens: None,
            threads: None,
            labels: vec![KIND.into()],
            thresholds: threshold
                .map(|t| BTreeMap::from([(KIND.to_owned(), t)]))
                .unwrap_or_default(),
            validate_as: None,
            class: None,
            surface: ModelGuardSurface::default(),
        }
    }

    fn trigger_fixture() -> Fixture {
        Fixture {
            trigger: true,
            ..Fixture::default()
        }
    }

    fn guard_with(dir: &Path, fixture: Fixture, threshold: Option<f32>) -> ModelGuard {
        ModelGuard::new(
            runtime(),
            "injection",
            &config(dir, fixture, threshold),
            1_048_576,
            NonZeroUsize::new(2).unwrap(),
        )
        .expect("the fixture loads")
    }

    /// Run `detect` over every unit.
    async fn detect(guard: &ModelGuard, units: Units) -> Reply {
        let units = units.into_shared();
        let selected: Vec<UnitId> = units.iter().map(|u| u.id).collect();
        guard
            .detect(GuardInput {
                units: &units,
                selected: &selected,
                on_error: OnError::FailClose,
            })
            .await
    }

    fn plain(texts: &[&[u8]]) -> Units {
        let mut units = Units::new();
        for text in texts {
            units.push_body(UnitContent::PlainText(Bytes::copy_from_slice(text)));
        }
        units
    }

    #[tokio::test]
    async fn a_unit_above_the_threshold_gives_one_spanless_finding() {
        let dir = tempfile::tempdir().unwrap();
        let guard = guard_with(dir.path(), trigger_fixture(), Some(0.9));

        let findings = detect(&guard, plain(&[b"voidwall trigger test"]))
            .await
            .unwrap();

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.kind.as_str(), KIND);
        assert_eq!(&*finding.guard, "injection");
        assert!(finding.span.is_none());
        assert!(finding.confidence.is_some_and(|c| c > 0.99), "{finding:?}");
    }

    /// A threshold equal to the unit score is met; one just above it is not.
    #[tokio::test]
    async fn a_threshold_is_met_at_or_above_it() {
        let dir = tempfile::tempdir().unwrap();
        let unit = || plain(&[b"voidwall"]);
        let all = guard_with(dir.path(), trigger_fixture(), Some(0.0));
        let score = detect(&all, unit()).await.unwrap()[0].confidence.unwrap();

        let at = guard_with(dir.path(), trigger_fixture(), Some(score));
        assert_eq!(detect(&at, unit()).await.unwrap().len(), 1);

        let above = guard_with(dir.path(), trigger_fixture(), Some(score + 0.01));
        assert!(detect(&above, unit()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_clean_unit_gives_no_finding() {
        let dir = tempfile::tempdir().unwrap();
        let guard = guard_with(dir.path(), trigger_fixture(), Some(0.9));
        let findings = detect(&guard, plain(&[b"voidwall smoke test"]))
            .await
            .unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn two_units_above_the_threshold_give_two_findings() {
        let dir = tempfile::tempdir().unwrap();
        let guard = guard_with(dir.path(), trigger_fixture(), Some(0.9));
        let findings = detect(&guard, plain(&[b"trigger", b"test", b"smoke trigger"]))
            .await
            .unwrap();
        let units: Vec<usize> = findings.iter().map(|f| f.unit.index()).collect();
        assert_eq!(units, vec![0, 2]);
    }

    #[tokio::test]
    async fn a_label_without_a_threshold_reports_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let guard = guard_with(dir.path(), trigger_fixture(), None);
        let findings = detect(&guard, plain(&[b"trigger"])).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn an_invalid_utf8_byte_does_not_hide_the_unit() {
        let dir = tempfile::tempdir().unwrap();
        let guard = guard_with(dir.path(), trigger_fixture(), Some(0.9));
        let findings = detect(&guard, plain(&[b"voidwall \xff trigger"]))
            .await
            .unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn a_structured_unit_is_scored_as_its_values() {
        let dir = tempfile::tempdir().unwrap();
        let guard = guard_with(dir.path(), trigger_fixture(), Some(0.9));
        let fragment = |context: &str, value: &str, offset| OwnedContextFragment {
            context: context.into(),
            value: value.into(),
            offset,
        };
        let mut units = Units::new();
        units.push_body(UnitContent::Structured {
            fragments: vec![
                fragment("messages.1.content", "trigger", 40),
                fragment("messages.0.content", "voidwall test", 10),
            ],
        });
        // The key "trigger" alone does not score: keys are not part of the text.
        units.push_body(UnitContent::Structured {
            fragments: vec![fragment("trigger", "voidwall", 2)],
        });

        let findings = detect(&guard, units).await.unwrap();

        let units: Vec<usize> = findings.iter().map(|f| f.unit.index()).collect();
        assert_eq!(units, vec![0]);
    }

    const MARKER: &str = "voidwall smoke";

    #[tokio::test]
    async fn a_nan_output_is_an_inference_failure_without_the_text() {
        let dir = tempfile::tempdir().unwrap();
        let fixture = Fixture {
            nan_row: Some(TRIGGER_ID),
            ..Fixture::default()
        };
        let guard = guard_with(dir.path(), fixture, Some(0.9));

        let err = detect(&guard, plain(&[format!("{MARKER} trigger").as_bytes()]))
            .await
            .unwrap_err();

        assert!(matches!(err, Error::Inference { .. }), "got: {err}");
        assert_eq!(err.scan_reason(), "inference_failure");
        let msg = err.to_string();
        assert!(msg.contains("injection"), "must name the guard: {msg}");
        assert!(!msg.contains(MARKER), "must not carry the text: {msg}");
    }

    #[tokio::test]
    async fn a_unit_past_the_window_limit_is_a_window_limit_error() {
        let dir = tempfile::tempdir().unwrap();
        // max_tokens 16, overlap 8: stride 8, so 8 bytes allow one window.
        let guard = ModelGuard::new(
            runtime(),
            "injection",
            &config(dir.path(), trigger_fixture(), Some(0.9)),
            8,
            NonZeroUsize::MIN,
        )
        .unwrap();
        let long = format!("{MARKER} ").repeat(10);

        let err = detect(&guard, plain(&[long.as_bytes()])).await.unwrap_err();

        assert!(matches!(err, Error::WindowLimit { .. }), "got: {err}");
        assert_eq!(err.scan_reason(), "window_limit");
        assert!(!err.to_string().contains(MARKER));
    }

    #[test]
    fn a_bad_model_fails_naming_the_guard_and_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path(), Fixture::default(), Some(0.9));
        std::fs::write(&config.model_path, b"not an onnx model").unwrap();

        let err = ModelGuard::new(
            runtime(),
            "injection",
            &config,
            1_048_576,
            NonZeroUsize::MIN,
        )
        .err()
        .expect("a bad model must fail");

        let msg = err.to_string();
        assert!(msg.contains("guards.injection"), "got: {msg}");
        assert!(
            msg.contains(&config.model_path.display().to_string()),
            "got: {msg}"
        );
    }

    #[tokio::test]
    async fn dropping_the_guard_joins_every_thread() {
        let dir = tempfile::tempdir().unwrap();
        let guard = guard_with(dir.path(), trigger_fixture(), Some(0.9));
        detect(&guard, plain(&[b"test"])).await.unwrap();
        let handles = guard.pool.handles.len();
        assert_eq!(handles, 2);
        // Drop joins; a thread that never exits would hang the test here.
        drop(guard);
    }

    // --- An abandoned guard cancels its run ---

    /// 40 tokens: window 16, stride 8, so four windows.
    fn long_unit() -> Units {
        plain(&["voidwall smoke test trigger ".repeat(10).as_bytes()])
    }

    /// One token: about a sixteenth of one long window's work.
    fn short_unit() -> Units {
        plain(&[b"voidwall"])
    }

    /// One worker on a model slow enough to abandon mid-run.
    fn slow_guard(dir: &Path) -> ModelGuard {
        let fixture = Fixture {
            slow: Some(300),
            ..trigger_fixture()
        };
        ModelGuard::new(
            runtime(),
            "injection",
            &config(dir, fixture, Some(0.9)),
            1_048_576,
            NonZeroUsize::MIN,
        )
        .expect("the slow fixture loads")
    }

    /// How long the guard takes on the long unit.
    async fn full_run(guard: &ModelGuard) -> Duration {
        let started = Instant::now();
        detect(guard, long_unit()).await.unwrap();
        started.elapsed()
    }

    #[tokio::test]
    async fn an_abandoned_inference_frees_the_worker_within_a_node() {
        let dir = tempfile::tempdir().unwrap();
        let guard = slow_guard(dir.path());
        let full = full_run(&guard).await;

        let abandoned = tokio::time::timeout(full / 2, detect(&guard, long_unit())).await;
        assert!(abandoned.is_err(), "the long run must still be running");
        let dropped = Instant::now();
        let findings = detect(&guard, short_unit()).await.unwrap();

        let freed = dropped.elapsed();
        assert!(findings.is_empty());
        assert!(freed < full / 4, "freed after {freed:?}; full run {full:?}");
    }

    #[tokio::test]
    async fn a_queued_job_of_an_abandoned_message_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let guard = slow_guard(dir.path());
        let full = full_run(&guard).await;
        let started = || {
            guard
                .pool
                .started
                .load(std::sync::atomic::Ordering::Relaxed)
        };
        assert_eq!(started(), 1);

        // The first job takes the only worker; the second, sent later, waits
        // in the queue and is abandoned there.
        let queued = async {
            tokio::time::sleep(full / 8).await;
            tokio::time::timeout(full / 4, detect(&guard, long_unit())).await
        };
        let (running, queued) = tokio::join!(detect(&guard, long_unit()), queued);

        assert_eq!(running.unwrap().len(), 1);
        assert!(queued.is_err(), "the queued job must be abandoned");
        detect(&guard, short_unit()).await.unwrap();
        assert_eq!(started(), 3, "the queued job never started");
    }

    #[test]
    fn a_cancelled_run_maps_to_no_error() {
        let guard: Arc<str> = Arc::from("injection");
        assert!(run_error(&guard, RunError::Cancelled).is_none());
        assert!(matches!(
            run_error(&guard, RunError::NonFinite),
            Some(Error::Inference { .. })
        ));
    }

    #[tokio::test]
    async fn a_cancelled_run_is_not_an_error() {
        use crate::engine::test_guard::TestGuard;
        use crate::engine::{BlockPolicy, Engine};

        let dir = tempfile::tempdir().unwrap();
        let guard = slow_guard(dir.path());
        let full = full_run(&guard).await;
        let blocker = TestGuard::new("blocker", "EMAIL").with_delay(full / 4);
        let engine = Engine::with_guards(vec![Box::new(blocker), Box::new(guard)]);

        let mut result = engine
            .guard(
                long_unit().into_shared(),
                &engine.select(None),
                BlockPolicy::AnyFinding,
                OnError::FailClose,
            )
            .await;

        assert_eq!(result.kinds(), vec!["EMAIL".to_string()]);
        assert!(result.take_error().is_none(), "a cancelled run is no error");
        let dropped = Instant::now();
        let mut next = engine
            .guard(
                short_unit().into_shared(),
                &engine.select(Some(&["injection"])),
                BlockPolicy::AnyFinding,
                OnError::FailClose,
            )
            .await;
        assert!(next.take_error().is_none());
        let freed = dropped.elapsed();
        assert!(freed < full / 4, "freed after {freed:?}; full run {full:?}");
    }

    // --- token_classifier ---

    /// Every word but the trigger: label 0 wins it, with e² / (e² + 2) ≈ 0.787.
    const WORD: &str = "WORD";
    /// The trigger: label 1 wins it, with about 1.0.
    const SECRET: &str = "SECRET";
    /// The confidence of a word that is not the trigger.
    const WORD_CONFIDENCE: f32 = 0.787;
    /// Placeholder card numbers: the first passes the Luhn check, the second
    /// differs in its check digit.
    const CARD: &str = "4111111111111111";
    const CARD_BAD: &str = "4111111111111112";

    /// A token classifier guard over the fixture token model: `[CLS] $A [SEP]`,
    /// width 3, with `id2label` mapping IDs 0, 1, 2.
    struct TokenCase {
        model: Fixture,
        id2label: [&'static str; 3],
        labels: &'static [&'static str],
        thresholds: &'static [(&'static str, f32)],
        validate_as: Vec<(&'static str, &'static [&'static str])>,
    }

    impl Default for TokenCase {
        fn default() -> Self {
            Self {
                model: Fixture {
                    tokens: true,
                    trigger: true,
                    width: 3,
                    ..Fixture::default()
                },
                id2label: ["B-WORD", "B-SECRET", "O"],
                labels: &[WORD, SECRET],
                thresholds: &[(WORD, 0.4), (SECRET, 0.4)],
                validate_as: Vec::new(),
            }
        }
    }

    impl TokenCase {
        fn config(&self, dir: &Path) -> ModelGuardConfig {
            let owned = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
            ModelGuardConfig {
                adapter: AdapterKind::TokenClassifier,
                model_path: self.model.write(dir),
                tokenizer_path: TokenizerFixture {
                    special_tokens: true,
                    ..TokenizerFixture::default()
                }
                .write(dir),
                config_path: Some(write_config(dir, &self.id2label)),
                max_tokens: 16,
                overlap_tokens: None,
                threads: None,
                labels: owned(self.labels),
                thresholds: self
                    .thresholds
                    .iter()
                    .map(|(label, t)| (label.to_string(), *t))
                    .collect(),
                validate_as: (!self.validate_as.is_empty()).then(|| {
                    self.validate_as
                        .iter()
                        .map(|(label, kinds)| (label.to_string(), owned(kinds)))
                        .collect()
                }),
                class: None,
                surface: ModelGuardSurface::default(),
            }
        }

        fn guard(&self, dir: &Path) -> ModelGuard {
            ModelGuard::new(
                runtime(),
                "pii_ml",
                &self.config(dir),
                1_048_576,
                NonZeroUsize::MIN,
            )
            .expect("the token fixture loads")
        }

        async fn detect(&self, units: Units) -> Reply {
            let dir = tempfile::tempdir().unwrap();
            detect(&self.guard(dir.path()), units).await
        }
    }

    /// Each finding as (kind, span start, span end).
    fn located(findings: &[Finding]) -> Vec<(&str, usize, usize)> {
        findings
            .iter()
            .map(|f| {
                let span = f.span.expect("a token finding has a span");
                (f.kind.as_str(), span.start, span.end)
            })
            .collect()
    }

    fn structured(values: &[(&str, usize)]) -> Units {
        let mut units = Units::new();
        units.push_body(UnitContent::Structured {
            fragments: values
                .iter()
                .map(|&(value, offset)| OwnedContextFragment {
                    context: "k".into(),
                    value: value.into(),
                    offset,
                })
                .collect(),
        });
        units
    }

    #[tokio::test]
    async fn a_token_classifier_finds_two_values_with_spans_and_confidences() {
        let findings = TokenCase::default()
            .detect(plain(&[b"voidwall trigger"]))
            .await
            .unwrap();
        assert_eq!(located(&findings), [(WORD, 0, 8), (SECRET, 9, 16)]);
        assert!(findings.iter().all(|f| &*f.guard == "pii_ml"));
        let confidence = |i: usize| findings[i].confidence.unwrap();
        assert!(
            (confidence(0) - WORD_CONFIDENCE).abs() < 1e-3,
            "{findings:?}"
        );
        assert!(confidence(1) > 0.99, "{findings:?}");
    }

    #[tokio::test]
    async fn a_span_below_its_labels_threshold_gives_no_finding() {
        let case = TokenCase {
            thresholds: &[(WORD, 0.8), (SECRET, 0.4)],
            ..TokenCase::default()
        };
        let findings = case.detect(plain(&[b"voidwall trigger"])).await.unwrap();
        assert_eq!(located(&findings), [(SECRET, 9, 16)]);
    }

    #[tokio::test]
    async fn a_threshold_of_zero_lets_every_span_through() {
        let case = TokenCase {
            thresholds: &[(WORD, 0.0)],
            ..TokenCase::default()
        };
        let findings = case.detect(plain(&[b"voidwall smoke test"])).await.unwrap();
        assert_eq!(
            located(&findings),
            [(WORD, 0, 8), (WORD, 9, 14), (WORD, 15, 19)]
        );
    }

    #[test_case(&[SECRET], &[(SECRET, 0.4)] ; "a type absent from labels")]
    #[test_case(&[WORD, SECRET], &[(SECRET, 0.4)] ; "a label without a threshold")]
    #[test_case(&[SECRET, "PHONE_NUMBER"], &[(SECRET, 0.4), ("PHONE_NUMBER", 0.0)] ; "a label the model does not have")]
    #[tokio::test]
    async fn only_labels_with_a_threshold_report(
        labels: &'static [&'static str],
        thresholds: &'static [(&'static str, f32)],
    ) {
        let case = TokenCase {
            labels,
            thresholds,
            ..TokenCase::default()
        };
        let findings = case.detect(plain(&[b"voidwall trigger"])).await.unwrap();
        assert_eq!(located(&findings), [(SECRET, 9, 16)]);
    }

    /// Every word is a `PAYMENT_CARD` span; only a card number that passes
    /// one of the listed kinds' validators is reported.
    #[test_case(&["CREDIT_CARD"], &[(17, 33)] ; "a card that fails the luhn check is dropped")]
    #[test_case(&["US_SSN", "CREDIT_CARD"], &[(17, 33)] ; "any listed kind may accept")]
    #[test_case(&["US_SSN"], &[] ; "a kind that rejects both")]
    #[tokio::test]
    async fn validate_as_keeps_only_spans_a_listed_kind_accepts(
        kinds: &'static [&'static str],
        expected: &[(usize, usize)],
    ) {
        let case = TokenCase {
            id2label: ["B-PAYMENT_CARD", "B-SECRET", "O"],
            labels: &["PAYMENT_CARD"],
            thresholds: &[("PAYMENT_CARD", 0.4)],
            validate_as: vec![("PAYMENT_CARD", kinds)],
            ..TokenCase::default()
        };
        let body = format!("{CARD_BAD} {CARD}");
        let findings = case.detect(plain(&[body.as_bytes()])).await.unwrap();
        let spans: Vec<_> = located(&findings)
            .into_iter()
            .map(|(_, s, e)| (s, e))
            .collect();
        assert_eq!(spans, expected);
        // A dropped span leaves nothing behind: a finding holds no text.
        assert!(!format!("{findings:?}").contains(CARD_BAD));
    }

    #[tokio::test]
    async fn a_span_after_an_invalid_byte_is_the_values_bytes_in_the_body() {
        let case = TokenCase {
            labels: &[SECRET],
            ..TokenCase::default()
        };
        // The text is "voidwall \u{FFFD} trigger": the trigger is at 13..20
        // there and at 11..18 in the body.
        let findings = case
            .detect(plain(&[b"voidwall \xff trigger"]))
            .await
            .unwrap();
        assert_eq!(located(&findings), [(SECRET, 11, 18)]);
    }

    #[tokio::test]
    async fn a_span_in_a_json_value_is_its_document_absolute_range() {
        let case = TokenCase {
            labels: &[SECRET],
            ..TokenCase::default()
        };
        // {"a":"voidwall","b":"test trigger"}: the second value starts at 21.
        let findings = case
            .detect(structured(&[("voidwall", 6), ("test trigger", 21)]))
            .await
            .unwrap();
        assert_eq!(located(&findings), [(SECRET, 26, 33)]);
    }

    /// IO labels have no `B-`, so neighbouring words of one type merge, but
    /// never across the join of two values.
    #[tokio::test]
    async fn two_values_of_one_type_in_neighbouring_fragments_are_two_spans() {
        let case = TokenCase {
            id2label: ["WORD", "SECRET", "O"],
            labels: &[WORD],
            thresholds: &[(WORD, 0.4)],
            ..TokenCase::default()
        };
        let findings = case
            .detect(structured(&[("test voidwall", 2), ("smoke", 30)]))
            .await
            .unwrap();
        assert_eq!(located(&findings), [(WORD, 2, 15), (WORD, 30, 35)]);
    }

    #[tokio::test]
    async fn a_token_classifier_failure_names_the_guard_without_the_text() {
        let case = TokenCase {
            model: Fixture {
                nan_row: Some(TRIGGER_ID),
                ..TokenCase::default().model
            },
            ..TokenCase::default()
        };
        let err = case
            .detect(plain(&[format!("{MARKER} trigger").as_bytes()]))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Inference { .. }), "got: {err}");
        let msg = err.to_string();
        assert!(msg.contains("pii_ml"), "must name the guard: {msg}");
        assert!(!msg.contains(MARKER), "must not carry the text: {msg}");
    }

    #[test]
    fn a_bad_config_json_fails_naming_the_guard_and_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let config = TokenCase::default().config(dir.path());
        let path = config.config_path.clone().unwrap();
        std::fs::write(&path, br#"{ "label2id": {} }"#).unwrap();

        let err = ModelGuard::new(runtime(), "pii_ml", &config, 1_048_576, NonZeroUsize::MIN)
            .err()
            .expect("a config without id2label must fail");

        let msg = err.to_string();
        assert!(msg.contains("guards.pii_ml"), "got: {msg}");
        assert!(msg.contains(&path.display().to_string()), "got: {msg}");
    }
}
