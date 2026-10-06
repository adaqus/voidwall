//! The model guard, and the worker pool it owns.
//!
//! One guard per `[guards.<name>]` section. It loads its model into N
//! `voidwall_ml::Worker`s at startup and gives each one its own OS thread:
//! inference is CPU-bound and must never run on the tokio runtime. `detect`
//! hands the units to a pool thread over a bounded channel and awaits the
//! reply on a oneshot, the same shape as the regex PII guard's scanner pool.
//!
//! When the engine abandons the guard, dropping the `detect` future cancels
//! the job's run: the worker stops within about one graph node and takes the
//! next job. A cancelled run is not a failure and produces no reply.

use std::borrow::Cow;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{SendTimeoutError, Sender};
use tracing::{debug, error, info};
use voidwall_ml::{Cancel, LoadSettings, RunError, Worker};

use crate::config::ModelGuardConfig;
use crate::error::Error;
use crate::scanner::LogRateLimiter;

use super::finding::Finding;
use super::guard::{DetectFuture, Guard, GuardInput, Interest};
use super::unit::{Unit, UnitContent, UnitId};

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
    /// One thread per worker. The channel holds four jobs per thread, to absorb
    /// short bursts while still applying backpressure.
    fn new(workers: Vec<Worker>, verdict: Arc<Verdict>) -> Result<Self, Error> {
        let guard = Arc::clone(&verdict.guard);
        let (sender, receiver) = crossbeam_channel::bounded::<WorkItem>(workers.len() * 4);
        let mut handles = Vec::with_capacity(workers.len());
        #[cfg(test)]
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        for (thread_id, mut worker) in workers.into_iter().enumerate() {
            let rx = receiver.clone();
            let verdict = Arc::clone(&verdict);
            #[cfg(test)]
            let started = Arc::clone(&started);
            let handle = std::thread::Builder::new()
                .name(format!("model-{guard}-{thread_id}"))
                .spawn(move || {
                    debug!(guard = %verdict.guard, thread_id, "model thread started");
                    while let Ok((job, reply_tx)) = rx.recv() {
                        // Nobody waits for this job any more: skip it.
                        if reply_tx.is_closed() {
                            continue;
                        }
                        #[cfg(test)]
                        started.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if let Some(reply) = score_job(&mut worker, &verdict, &job) {
                            let _ = reply_tx.send(reply);
                        }
                    }
                    debug!(guard = %verdict.guard, thread_id, "model thread exiting");
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
        let score = match worker.score(&unit_text(&unit.content), &job.cancel) {
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

/// The one text a model guard scores for a unit.
///
/// Plain text is decoded lossily, so one invalid byte cannot hide the rest. A
/// JSON unit's values are joined with newlines in document order, keys left
/// out; API-aware decoders replace this in the decoder phases.
fn unit_text(content: &UnitContent) -> Cow<'_, str> {
    match content {
        UnitContent::PlainText(bytes) => String::from_utf8_lossy(bytes),
        UnitContent::Structured { fragments } => {
            let mut ordered: Vec<_> = fragments.iter().collect();
            ordered.sort_by_key(|f| f.offset);
            let values: Vec<&str> = ordered.iter().map(|f| f.value.as_str()).collect();
            Cow::Owned(values.join("\n"))
        }
    }
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
            max_tokens: config.max_tokens,
            overlap_tokens: config.overlap_tokens,
            max_body_size,
            workers: threads,
        };

        let started = Instant::now();
        let workers = voidwall_ml::load(&settings).map_err(|e| config_error(e.to_string()))?;
        info!(
            guard = name,
            threads = threads.get(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "model guard loaded"
        );

        // Validation guarantees exactly one label for every built adapter.
        let kind: Arc<str> = Arc::from(config.labels[0].as_str());
        let verdict = Arc::new(Verdict {
            guard: Arc::from(name),
            threshold: config.thresholds.get(&*kind).copied(),
            kind,
        });
        Ok(Self {
            name: Arc::clone(&verdict.guard),
            interest: Interest::from_model_surface(&config.surface),
            pool: ModelPool::new(workers, verdict)?,
        })
    }
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
    use crate::engine::unit::Units;
    use crate::structured::OwnedContextFragment;
    use bytes::Bytes;
    use std::collections::BTreeMap;
    use std::path::Path;
    use voidwall_ml::AdapterKind;
    use voidwall_ml::fixtures::{Fixture, TRIGGER_ID, TokenizerFixture};

    const KIND: &str = "PROMPT_INJECTION";

    /// A guard config over a fixture model written to `dir`.
    fn config(dir: &Path, fixture: Fixture, threshold: Option<f32>) -> ModelGuardConfig {
        ModelGuardConfig {
            adapter: AdapterKind::TextClassifier,
            model_path: fixture.write(dir),
            tokenizer_path: TokenizerFixture::default().write(dir),
            max_tokens: 16,
            overlap_tokens: None,
            threads: None,
            labels: vec![KIND.into()],
            thresholds: threshold
                .map(|t| BTreeMap::from([(KIND.to_owned(), t)]))
                .unwrap_or_default(),
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

    #[test]
    fn structured_values_are_joined_in_document_order() {
        let content = UnitContent::Structured {
            fragments: vec![
                OwnedContextFragment {
                    context: "b".into(),
                    value: "second".into(),
                    offset: 20,
                },
                OwnedContextFragment {
                    context: "a".into(),
                    value: "first".into(),
                    offset: 5,
                },
            ],
        };
        assert_eq!(unit_text(&content), "first\nsecond");
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

        let err = ModelGuard::new("injection", &config, 1_048_576, NonZeroUsize::MIN)
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
}
