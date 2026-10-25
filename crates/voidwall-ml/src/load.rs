//! Loading one model guard's model into N workers.

use std::fmt;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ort::session::Session;
use ort::session::builder::{GraphOptimizationLevel, PrepackedWeights, SessionBuilder};
use tokenizers::Tokenizer;

use crate::OnnxRuntime;
use crate::adapter::{Adapter, AdapterKind, TextClassifier};
use crate::checks::{self, InputLayout};
use crate::labels::Labels;
use crate::model_file::ModelFile;
use crate::run::{Cancel, RunError, Windowing};

/// What one load needs. `voidwall` builds it from a model guard's configuration.
#[derive(Debug, Clone)]
pub struct LoadSettings {
    pub adapter: AdapterKind,
    pub model_path: PathBuf,
    pub tokenizer_path: PathBuf,
    /// The model's `config.json`, which holds `id2label`. A `token_classifier`
    /// load needs it; a `text_classifier` load ignores it.
    pub config_path: Option<PathBuf>,
    /// The longest input the adapter feeds the model, in tokens.
    pub max_tokens: usize,
    /// Tokens shared by neighbouring windows. `None` means
    /// [`default_overlap`](crate::default_overlap); a value above
    /// `max_tokens / 2` fails the load.
    pub overlap_tokens: Option<usize>,
    /// The largest body ingest admits, in bytes. A unit may need at most
    /// `ceil(max_body_size / stride)` windows.
    pub max_body_size: NonZeroUsize,
    /// How many sessions to load. Each is meant for one worker thread.
    pub workers: NonZeroUsize,
}

mod sealed {
    pub trait Sealed {}
}

/// What a worker makes of each window's output. The build ships the set, so
/// the trait is sealed.
pub trait Head: sealed::Sealed {
    /// True when the model scores every token, so a window's output is
    /// `[1, n, width]` rather than `[1, width]`.
    #[doc(hidden)]
    const PER_TOKEN: bool;
}

/// The head of a classifier worker: one score per window, kept by
/// [`Worker::score`].
#[derive(Clone)]
pub struct Classifier {
    /// The adapter's [`Adapter::window_score`].
    pub(crate) window_score: fn(&[f32]) -> f32,
}

impl sealed::Sealed for Classifier {}
impl Head for Classifier {
    const PER_TOKEN: bool = false;
}

/// The head of a token worker: probabilities per token, returned by
/// [`TokenWorker::run`](crate::TokenWorker).
#[derive(Clone)]
pub struct Tokens {
    pub(crate) labels: Arc<Labels>,
}

impl sealed::Sealed for Tokens {}
impl Head for Tokens {
    const PER_TOKEN: bool = true;
}

/// A worker of a `token_classifier` load.
pub type TokenWorker = Worker<Tokens>;

/// The workers of one load, of the kind its adapter runs. A classifier worker
/// has no per-token run and a token worker has no score, so a guard cannot
/// call the wrong one.
pub enum Workers {
    Classifier(Vec<Worker>),
    Token(Vec<TokenWorker>),
}

#[cfg(test)]
impl Workers {
    pub(crate) fn into_classifiers(self) -> Vec<Worker> {
        match self {
            Self::Classifier(workers) => workers,
            Self::Token(_) => panic!("expected classifier workers"),
        }
    }

    pub(crate) fn into_tokens(self) -> Vec<TokenWorker> {
        match self {
            Self::Token(workers) => workers,
            Self::Classifier(_) => panic!("expected token workers"),
        }
    }
}

/// One loaded session, ready for one worker thread. The guard in `voidwall`
/// owns the thread.
pub struct Worker<H: Head = Classifier> {
    pub(crate) session: Session,
    pub(crate) layout: InputLayout,
    /// Shared by every worker of one load.
    pub(crate) tokenizer: Arc<Tokenizer>,
    pub(crate) pad_id: i64,
    pub(crate) windowing: Windowing,
    pub(crate) width: i64,
    pub(crate) head: H,
    /// Inferences run, so tests can see how many windows a run took.
    #[cfg(test)]
    pub(crate) inferences: usize,
    /// Cancel the run once this many inferences have returned, so a test can
    /// land a cancel between two windows.
    #[cfg(test)]
    pub(crate) cancel_after: Option<usize>,
}

/// Why a load failed. No variant carries input text: a load sees none.
#[derive(Debug)]
pub enum LoadError {
    AdapterNotBuilt(AdapterKind),
    ModelUnreadable {
        path: PathBuf,
        reason: String,
    },
    TokenizerUnreadable {
        path: PathBuf,
        reason: String,
    },
    ConfigMissing(AdapterKind),
    ConfigUnreadable {
        path: PathBuf,
        reason: String,
    },
    Id2Label {
        path: PathBuf,
        reason: String,
    },
    EmbeddingTableNotFound,
    TokenizerTooLarge {
        highest_id: u32,
        rows: i64,
    },
    Session {
        path: PathBuf,
        reason: String,
    },
    Staging {
        dir: PathBuf,
        reason: String,
    },
    MissingInput(&'static str),
    UnknownInput(String),
    InputType {
        name: String,
        found: String,
    },
    InputRank {
        name: String,
        rank: usize,
    },
    FixedSequence {
        fixed: usize,
        max_tokens: usize,
    },
    OverlapTooLarge {
        overlap: usize,
        bound: usize,
    },
    WindowTooShort {
        window: usize,
        overlap: usize,
    },
    OutputCount(usize),
    OutputType(String),
    OutputRank {
        found: usize,
        expected: usize,
    },
    OutputWidth {
        expected: i64,
        found: i64,
    },
    LabelCount {
        path: PathBuf,
        labels: i64,
        found: i64,
    },
    SmokeInference(String),
    SmokeNonFinite,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AdapterNotBuilt(kind) => write!(f, "adapter `{}` is not built", kind.name()),
            Self::ModelUnreadable { path, reason } => {
                write!(
                    f,
                    "model {} is not a readable ONNX model: {reason}",
                    path.display()
                )
            }
            Self::TokenizerUnreadable { path, reason } => {
                write!(
                    f,
                    "tokenizer {} is not a readable tokenizer: {reason}",
                    path.display()
                )
            }
            Self::ConfigMissing(kind) => {
                write!(f, "adapter `{}` needs the model's config.json", kind.name())
            }
            Self::ConfigUnreadable { path, reason } => {
                write!(
                    f,
                    "config {} is not a readable JSON file: {reason}",
                    path.display()
                )
            }
            Self::Id2Label { path, reason } => {
                write!(
                    f,
                    "config {} has no valid id2label: {reason}",
                    path.display()
                )
            }
            Self::EmbeddingTableNotFound => f.write_str(
                "embedding table not found: no `Gather` node reads `input_ids` directly \
                 from an initializer",
            ),
            Self::TokenizerTooLarge { highest_id, rows } => write!(
                f,
                "the tokenizer can produce token ID {highest_id}, but the model's embedding \
                 table has {rows} rows"
            ),
            Self::Session { path, reason } => {
                write!(
                    f,
                    "ONNX Runtime could not load model {}: {reason}",
                    path.display()
                )
            }
            Self::Staging { dir, reason } => write!(
                f,
                "could not stage the model graph in temp directory {}: {reason}",
                dir.display()
            ),
            Self::MissingInput(name) => write!(f, "the model has no `{name}` input"),
            Self::UnknownInput(name) => write!(
                f,
                "the model has input `{name}`; only `input_ids`, `attention_mask`, and \
                 `token_type_ids` are fed"
            ),
            Self::InputType { name, found } => {
                write!(
                    f,
                    "input `{name}` has element type {found}; i64 is required"
                )
            }
            Self::InputRank { name, rank } => {
                write!(f, "input `{name}` has rank {rank}; rank 2 is required")
            }
            Self::FixedSequence { fixed, max_tokens } => write!(
                f,
                "the model fixes the sequence dimension at {fixed}, but max_tokens is \
                 {max_tokens}; they must be equal"
            ),
            Self::OverlapTooLarge { overlap, bound } => write!(
                f,
                "overlap_tokens is {overlap}; it must be at most max_tokens / 2 = {bound}"
            ),
            Self::WindowTooShort { window, overlap } => write!(
                f,
                "the window of {window} tokens (max_tokens minus the tokenizer's special \
                 tokens) is not longer than the overlap of {overlap} tokens"
            ),
            Self::OutputCount(n) => write!(f, "the model has {n} outputs; exactly 1 is required"),
            Self::OutputType(found) => {
                write!(f, "the output has element type {found}; f32 is required")
            }
            Self::OutputRank { found, expected } => {
                write!(
                    f,
                    "the output has rank {found}; rank {expected} is required"
                )
            }
            Self::OutputWidth { expected, found } => write!(
                f,
                "the adapter needs output width {expected}; the model's is {}",
                width(*found)
            ),
            Self::LabelCount {
                path,
                labels,
                found,
            } => write!(
                f,
                "id2label in config {} has {labels} labels, but the model's output width is \
                 {}; they must be equal",
                path.display(),
                width(*found)
            ),
            Self::SmokeInference(reason) => write!(f, "the smoke inference failed: {reason}"),
            Self::SmokeNonFinite => {
                f.write_str("the smoke inference returned a non-finite output (NaN or infinity)")
            }
        }
    }
}

/// A dimension as an error names it: `-1` is a dynamic one.
fn width(dim: i64) -> String {
    if dim < 0 {
        "dynamic".to_owned()
    } else {
        dim.to_string()
    }
}

impl std::error::Error for LoadError {}

/// Loads `settings.workers` sessions of one model that share one copy of its
/// weights, and returns them only when every check passed on every one.
pub fn load(runtime: &OnnxRuntime, settings: &LoadSettings) -> Result<Workers, LoadError> {
    match settings.adapter {
        AdapterKind::TextClassifier => {
            load_classifier::<TextClassifier>(runtime, settings).map(Workers::Classifier)
        }
        AdapterKind::TokenClassifier => load_tokens(runtime, settings).map(Workers::Token),
        AdapterKind::TextMultilabelClassifier => Err(LoadError::AdapterNotBuilt(settings.adapter)),
    }
}

fn load_classifier<A: Adapter>(
    runtime: &OnnxRuntime,
    settings: &LoadSettings,
) -> Result<Vec<Worker>, LoadError> {
    let head = Classifier {
        window_score: A::window_score,
    };
    load_with(runtime, settings, head, A::OUTPUT_WIDTH)
}

/// The output width is the number of labels in `id2label`.
fn load_tokens(
    runtime: &OnnxRuntime,
    settings: &LoadSettings,
) -> Result<Vec<TokenWorker>, LoadError> {
    let path = settings
        .config_path
        .as_deref()
        .ok_or(LoadError::ConfigMissing(settings.adapter))?;
    let labels = Labels::read(path)?;
    let width = labels.len() as i64;
    let head = Tokens {
        labels: Arc::new(labels),
    };
    load_with(runtime, settings, head, width).map_err(|e| match e {
        // Only the output check gives this error; the labels set the width.
        LoadError::OutputWidth { expected, found } => LoadError::LabelCount {
            path: path.to_owned(),
            labels: expected,
            found,
        },
        e => e,
    })
}

fn load_with<H: Head + Clone + Send + Sync>(
    runtime: &OnnxRuntime,
    settings: &LoadSettings,
    head: H,
    width: i64,
) -> Result<Vec<Worker<H>>, LoadError> {
    // Cheap checks first: nothing is loaded into ONNX Runtime until they pass.
    let (tokenizer, pad_id) = read_tokenizer(settings)?;
    let special = tokenizer
        .get_post_processor()
        .map_or(0, |p| tokenizers::PostProcessor::added_tokens(p, false));
    let windowing = Windowing::new(
        settings.max_tokens,
        special,
        settings.overlap_tokens,
        settings.max_body_size,
    )?;
    let model = ModelFile::read(&settings.model_path)?;
    checks::check_tokenizer(&tokenizer, model.embedding_rows)?;
    // Removed when this function returns; the sessions no longer need it then.
    let staged = model.stage_in(&std::env::temp_dir())?;
    let graph = staged.path();

    // One session first, so a model that breaks the contract fails after one
    // session load rather than N.
    let prepacked = PrepackedWeights::new();
    let first = new_session(runtime, settings, &model, &graph, &prepacked)?;
    let layout = checks::check_inputs(first.inputs(), settings.max_tokens)?;
    let rank = if H::PER_TOKEN { 3 } else { 2 };
    checks::check_output(first.outputs(), rank, width)?;
    let ids = checks::smoke_input(&tokenizer, layout.fixed_seq)?;

    let tokenizer = Arc::new(tokenizer);
    let worker = |session: Session| Worker {
        session,
        layout,
        tokenizer: Arc::clone(&tokenizer),
        pad_id,
        windowing,
        width,
        head: head.clone(),
        #[cfg(test)]
        inferences: 0,
        #[cfg(test)]
        cancel_after: None,
    };
    let first = worker(first);
    let workers = std::thread::scope(|scope| {
        let smoke = |mut worker: Worker<H>| worker.smoke(&ids).map(|()| worker);
        let mut handles = vec![scope.spawn(move || smoke(first))];
        handles.extend((1..settings.workers.get()).map(|_| {
            let (model, graph, prepacked, worker) = (&model, &graph, &prepacked, &worker);
            scope.spawn(move || {
                let session = new_session(runtime, settings, model, graph, prepacked)?;
                smoke(worker(session))
            })
        }));
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect::<Result<Vec<_>, _>>()
    })?;
    Ok(workers)
}

/// Reads the tokenizer with truncation and padding off, and returns the pad ID
/// it was configured with (0 when it has none).
fn read_tokenizer(settings: &LoadSettings) -> Result<(Tokenizer, i64), LoadError> {
    let unreadable = |reason: String| LoadError::TokenizerUnreadable {
        path: settings.tokenizer_path.clone(),
        reason,
    };
    let mut tokenizer =
        Tokenizer::from_file(&settings.tokenizer_path).map_err(|e| unreadable(e.to_string()))?;
    // `tokenizer.json` may bake in truncation or padding; the adapter does both itself.
    let pad_id = tokenizer.get_padding().map_or(0, |p| i64::from(p.pad_id));
    tokenizer
        .with_truncation(None)
        .map_err(|e| unreadable(e.to_string()))?;
    tokenizer.with_padding(None);
    Ok((tokenizer, pad_id))
}

/// The options of every worker session: one intra-op thread, every graph
/// optimization, CPU only.
fn session_options(runtime: &OnnxRuntime) -> ort::Result<SessionBuilder> {
    Ok(Session::builder(runtime.environment())?
        .with_intra_threads(1)?
        .with_optimization_level(GraphOptimizationLevel::Level3)?)
}

/// A session of the model file as it is on disk, with a worker's options but
/// no shared or prepacked weights, so a test can compare a worker with it.
#[cfg(test)]
pub(crate) fn plain_session(path: &Path) -> ort::Result<Session> {
    session_options(crate::fixtures::runtime())?.commit_from_file(path)
}

/// One session over the shared weights: the staged weight-free graph, every
/// initializer from the single read as an override, one shared prepacked
/// container, and the options of [`session_options`].
fn new_session(
    runtime: &OnnxRuntime,
    settings: &LoadSettings,
    model: &ModelFile,
    graph: &Path,
    prepacked: &PrepackedWeights,
) -> Result<Session, LoadError> {
    let failed = |reason: String| LoadError::Session {
        path: settings.model_path.clone(),
        reason,
    };
    let mut builder = session_options(runtime)
        .map_err(|e| failed(e.to_string()))?
        .with_prepacked_weights(prepacked)
        .map_err(|e| failed(e.to_string()))?;
    for weight in &model.initializers {
        builder = builder
            .with_initializer(&weight.name, weight.value.clone())
            .map_err(|e| failed(e.to_string()))?;
    }
    builder
        .commit_from_file(graph)
        .map_err(|e| failed(e.to_string()))
}

impl<H: Head> Worker<H> {
    /// Runs one inference on the smoke input through the same path a run uses.
    fn smoke(&mut self, ids: &[i64]) -> Result<(), LoadError> {
        // Nobody cancels the smoke inference.
        let cancel = Cancel::new().map_err(|e| LoadError::SmokeInference(e.to_string()))?;
        self.infer(ids, &cancel).map(drop).map_err(|e| match e {
            RunError::NonFinite => LoadError::SmokeNonFinite,
            RunError::Inference(reason) => LoadError::SmokeInference(reason),
            other => LoadError::SmokeInference(other.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Fixture, ROWS, runtime, write_tokenizer};
    use ort::value::Tensor;

    fn settings(dir: &std::path::Path, fixture: &Fixture, workers: usize) -> LoadSettings {
        LoadSettings {
            adapter: AdapterKind::TextClassifier,
            model_path: fixture.write(dir),
            tokenizer_path: write_tokenizer(dir, ROWS as u32 - 1),
            config_path: None,
            max_tokens: 16,
            overlap_tokens: None,
            max_body_size: NonZeroUsize::new(1 << 20).unwrap(),
            workers: NonZeroUsize::new(workers).unwrap(),
        }
    }

    fn load_fixture(fixture: Fixture) -> Result<Vec<Worker>, LoadError> {
        let dir = tempfile::tempdir().unwrap();
        load(runtime(), &settings(dir.path(), &fixture, 2)).map(Workers::into_classifiers)
    }

    #[test]
    fn a_good_model_loads_n_workers() {
        let dir = tempfile::tempdir().unwrap();
        let workers = load(runtime(), &settings(dir.path(), &Fixture::default(), 3))
            .unwrap()
            .into_classifiers();
        assert_eq!(workers.len(), 3);
    }

    #[test]
    fn a_fixed_length_model_loads_and_runs_its_smoke_input() {
        let workers = load_fixture(Fixture {
            fixed_seq: Some(16),
            ..Fixture::default()
        })
        .unwrap();
        assert_eq!(workers[0].layout.fixed_seq, Some(16));
    }

    #[test]
    fn a_model_with_token_type_ids_loads() {
        let workers = load_fixture(Fixture {
            token_type_ids: true,
            ..Fixture::default()
        })
        .unwrap();
        assert!(workers.iter().all(|w| w.layout.token_type_ids));
    }

    #[test]
    fn a_multilabel_adapter_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut settings = settings(dir.path(), &Fixture::default(), 1);
        settings.adapter = AdapterKind::TextMultilabelClassifier;
        let msg = load(runtime(), &settings).err().unwrap().to_string();
        assert!(
            msg.contains("text_multilabel_classifier") && msg.contains("not built"),
            "got: {msg}"
        );
    }

    #[test]
    fn a_tokenizer_file_that_does_not_parse_names_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let settings = settings(dir.path(), &Fixture::default(), 1);
        std::fs::write(&settings.tokenizer_path, b"{ not json").unwrap();
        let err = load(runtime(), &settings).err().unwrap();
        assert!(matches!(err, LoadError::TokenizerUnreadable { .. }));
        assert!(
            err.to_string()
                .contains(&settings.tokenizer_path.display().to_string())
        );
    }

    #[test]
    fn a_tokenizer_larger_than_the_model_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut settings = settings(dir.path(), &Fixture::default(), 1);
        settings.tokenizer_path = write_tokenizer(dir.path(), 40);
        assert!(matches!(
            load(runtime(), &settings),
            Err(LoadError::TokenizerTooLarge {
                highest_id: 40,
                rows: ROWS
            })
        ));
    }

    #[test]
    fn a_non_finite_output_fails_the_smoke_inference() {
        let err = load_fixture(Fixture {
            nan_bias: true,
            ..Fixture::default()
        })
        .err()
        .unwrap();
        assert!(matches!(err, LoadError::SmokeNonFinite));
        assert!(err.to_string().contains("non-finite"));
    }

    #[test]
    fn a_model_that_fails_only_when_it_runs_fails_the_smoke_inference() {
        let err = load_fixture(Fixture {
            fails_at_run: true,
            ..Fixture::default()
        })
        .err()
        .unwrap();
        assert!(matches!(err, LoadError::SmokeInference(_)), "got: {err}");
        assert!(err.to_string().contains("smoke inference"));
    }

    #[test]
    fn a_contract_failure_stops_the_load() {
        let err = load_fixture(Fixture {
            width: 3,
            ..Fixture::default()
        })
        .err()
        .unwrap();
        assert!(matches!(
            err,
            LoadError::OutputWidth {
                expected: 2,
                found: 3
            }
        ));
    }

    #[test]
    fn a_worker_answers_like_the_unmodified_model() {
        let dir = tempfile::tempdir().unwrap();
        let settings = settings(dir.path(), &Fixture::default(), 1);
        let mut plain = Session::builder(runtime().environment())
            .unwrap()
            .commit_from_file(&settings.model_path)
            .unwrap();
        let mut worker = load(runtime(), &settings)
            .unwrap()
            .into_classifiers()
            .pop()
            .unwrap();
        assert_eq!(logits(&mut worker.session), logits(&mut plain));
    }

    /// The logits of one fixed input.
    fn logits(session: &mut Session) -> Vec<f32> {
        let ids = Tensor::from_array(([1usize, 3], vec![1i64, 2, 3])).unwrap();
        let mask = Tensor::from_array(([1usize, 3], vec![1i64, 1, 1])).unwrap();
        let outputs = session
            .run(ort::inputs!["input_ids" => ids, "attention_mask" => mask])
            .unwrap();
        outputs[0].try_extract_tensor::<f32>().unwrap().1.to_vec()
    }

    #[test]
    fn a_weight_that_feeds_only_constant_nodes_loads() {
        let dir = tempfile::tempdir().unwrap();
        let fixture = Fixture {
            folded_weight: true,
            ..Fixture::default()
        };
        let settings = settings(dir.path(), &fixture, 2);
        let mut plain = Session::builder(runtime().environment())
            .unwrap()
            .commit_from_file(&settings.model_path)
            .unwrap();
        let mut worker = load(runtime(), &settings)
            .unwrap()
            .into_classifiers()
            .pop()
            .unwrap();
        assert_eq!(logits(&mut worker.session), logits(&mut plain));
    }

    #[test]
    fn a_stripped_weight_without_its_override_fails_the_session() {
        let dir = tempfile::tempdir().unwrap();
        let settings = settings(dir.path(), &Fixture::default(), 1);
        let mut model = ModelFile::read(&settings.model_path).unwrap();
        let staged = model.stage_in(dir.path()).unwrap();
        // The fixture's embedding is its only stripped initializer.
        model.initializers.retain(|w| w.name != "embedding");
        let result = new_session(
            runtime(),
            &settings,
            &model,
            &staged.path(),
            &PrepackedWeights::new(),
        );
        assert!(matches!(result, Err(LoadError::Session { .. })));
    }

    /// A parallel load keeps one copy of the weights. The startup peak adds only
    /// the mapped file pages of the read, which the kernel can drop.
    /// Run alone: `cargo test -p voidwall-ml --release -- --ignored peak_memory`.
    #[test]
    #[ignore = "builds a 256 MiB model; run on demand"]
    fn peak_memory_stays_near_one_copy_of_the_weights() {
        const ROWS: i64 = 2 * 1024 * 1024; // × 32 f32 = 256 MiB
        let weights = (ROWS * 32 * 4) as f64;
        let dir = tempfile::tempdir().unwrap();
        let mut settings = settings(
            dir.path(),
            &Fixture {
                rows: ROWS,
                ..Fixture::default()
            },
            4,
        );
        settings.max_tokens = 512;

        let status = |key: &str| -> f64 {
            let text = std::fs::read_to_string("/proc/self/status").unwrap();
            let line = text.lines().find(|l| l.starts_with(key)).unwrap();
            let kib: f64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
            kib * 1024.0
        };
        // Reset the high-water mark, so building the fixture does not count.
        std::fs::write("/proc/self/clear_refs", "5").unwrap();
        let (rss, anon) = (status("VmRSS:"), status("RssAnon:"));
        let workers = load(runtime(), &settings).unwrap().into_classifiers();
        let peak = (status("VmHWM:") - rss) / weights;
        let kept = (status("RssAnon:") - anon) / weights;
        eprintln!(
            "{} workers: peak {peak:.2}× the weights (anonymous + mapped file), kept {kept:.2}× (anonymous)",
            workers.len()
        );
        assert!(kept < 1.2, "kept {kept:.2}× the weights");
        assert!(peak < 2.3, "peak {peak:.2}× the weights");
    }

    #[test]
    fn a_worker_can_move_to_its_thread() {
        fn assert_send<T: Send>() {}
        assert_send::<Worker>();
    }
}
