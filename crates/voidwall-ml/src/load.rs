//! Loading one model guard's model into N workers.

use std::fmt;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use ort::session::Session;
use ort::session::builder::{GraphOptimizationLevel, PrepackedWeights};
use ort::value::Tensor;
use tokenizers::Tokenizer;

use crate::adapter::{Adapter, AdapterKind, TextClassifier};
use crate::checks::{self, InputLayout};
use crate::model_file::ModelFile;

/// What one load needs. `voidwall` builds it from a model guard's configuration.
#[derive(Debug, Clone)]
pub struct LoadSettings {
    pub adapter: AdapterKind,
    pub model_path: PathBuf,
    pub tokenizer_path: PathBuf,
    /// The longest input the adapter feeds the model, in tokens.
    pub max_tokens: usize,
    /// How many sessions to load. Each is meant for one worker thread.
    pub workers: NonZeroUsize,
}

/// One loaded session, ready for one worker thread. The guard in `voidwall`
/// owns the thread.
pub struct Worker {
    session: Session,
    layout: InputLayout,
}

/// Why a load failed. No variant carries input text: a load sees none.
#[derive(Debug)]
pub enum LoadError {
    AdapterNotBuilt(AdapterKind),
    ModelUnreadable { path: PathBuf, reason: String },
    TokenizerUnreadable { path: PathBuf, reason: String },
    EmbeddingTableNotFound,
    TokenizerTooLarge { highest_id: u32, rows: i64 },
    Session { path: PathBuf, reason: String },
    Staging { dir: PathBuf, reason: String },
    MissingInput(&'static str),
    UnknownInput(String),
    InputType { name: String, found: String },
    InputRank { name: String, rank: usize },
    FixedSequence { fixed: usize, max_tokens: usize },
    OutputCount(usize),
    OutputType(String),
    OutputRank(usize),
    OutputWidth { expected: i64, found: i64 },
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
            Self::OutputCount(n) => write!(f, "the model has {n} outputs; exactly 1 is required"),
            Self::OutputType(found) => {
                write!(f, "the output has element type {found}; f32 is required")
            }
            Self::OutputRank(rank) => write!(f, "the output has rank {rank}; rank 2 is required"),
            Self::OutputWidth { expected, found } => {
                let found = if *found < 0 {
                    "dynamic".to_owned()
                } else {
                    found.to_string()
                };
                write!(
                    f,
                    "the adapter needs output width {expected}; the model's is {found}"
                )
            }
            Self::SmokeInference(reason) => write!(f, "the smoke inference failed: {reason}"),
            Self::SmokeNonFinite => {
                f.write_str("the smoke inference returned a non-finite output (NaN or infinity)")
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// Loads `settings.workers` sessions of one model that share one copy of its
/// weights, and returns them only when every check passed on every one.
pub fn load(settings: &LoadSettings) -> Result<Vec<Worker>, LoadError> {
    match settings.adapter {
        AdapterKind::TextClassifier => load_with::<TextClassifier>(settings),
        AdapterKind::TextMultilabelClassifier => Err(LoadError::AdapterNotBuilt(settings.adapter)),
    }
}

fn load_with<A: Adapter>(settings: &LoadSettings) -> Result<Vec<Worker>, LoadError> {
    // Cheap checks first: nothing is loaded into ONNX Runtime until they pass.
    let (tokenizer, pad_id) = read_tokenizer(settings)?;
    let model = ModelFile::read(&settings.model_path)?;
    checks::check_tokenizer(&tokenizer, model.embedding_rows)?;
    // Removed when this function returns; the sessions no longer need it then.
    let staged = model.stage_in(&std::env::temp_dir())?;
    let graph = staged.path();

    // One session first, so a model that breaks the contract fails after one
    // session load rather than N.
    let prepacked = PrepackedWeights::new();
    let first = new_session(settings, &model, &graph, &prepacked)?;
    let layout = checks::check_inputs(first.inputs(), settings.max_tokens)?;
    checks::check_output(first.outputs(), A::OUTPUT_WIDTH)?;
    let (ids, mask) = checks::smoke_input(&tokenizer, pad_id, layout.fixed_seq)?;
    drop(tokenizer);

    let first = Worker {
        session: first,
        layout,
    };
    let workers = std::thread::scope(|scope| {
        let smoke =
            |mut worker: Worker| worker.smoke(&ids, &mask, A::OUTPUT_WIDTH).map(|()| worker);
        let mut handles = vec![scope.spawn(move || smoke(first))];
        handles.extend((1..settings.workers.get()).map(|_| {
            let (model, graph, prepacked) = (&model, &graph, &prepacked);
            scope.spawn(move || {
                let session = new_session(settings, model, graph, prepacked)?;
                smoke(Worker { session, layout })
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

/// One session over the shared weights: the staged weight-free graph, every
/// initializer from the single read as an override, one shared prepacked
/// container, one intra-op thread, CPU only.
fn new_session(
    settings: &LoadSettings,
    model: &ModelFile,
    graph: &Path,
    prepacked: &PrepackedWeights,
) -> Result<Session, LoadError> {
    let failed = |reason: String| LoadError::Session {
        path: settings.model_path.clone(),
        reason,
    };
    let mut builder = Session::builder()
        .map_err(|e| failed(e.to_string()))?
        .with_intra_threads(1)
        .map_err(|e| failed(e.to_string()))?
        .with_optimization_level(GraphOptimizationLevel::Level3)
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

impl Worker {
    /// Runs one inference and checks that it returns `[1, width]` finite values.
    fn smoke(&mut self, ids: &[i64], mask: &[i64], width: i64) -> Result<(), LoadError> {
        let failed = |e: ort::Error| LoadError::SmokeInference(e.to_string());
        let shape = [1usize, ids.len()];
        let mut inputs = ort::inputs![
            "input_ids" => Tensor::from_array((shape, ids.to_vec())).map_err(failed)?,
            "attention_mask" => Tensor::from_array((shape, mask.to_vec())).map_err(failed)?,
        ];
        if self.layout.token_type_ids {
            let zeros = Tensor::from_array((shape, vec![0i64; ids.len()])).map_err(failed)?;
            inputs.push(("token_type_ids".into(), zeros.into()));
        }
        let outputs = self.session.run(inputs).map_err(failed)?;
        let (out_shape, values) = outputs[0].try_extract_tensor::<f32>().map_err(failed)?;
        if **out_shape != [1, width] {
            return Err(LoadError::SmokeInference(format!(
                "the output has shape {:?}; [1, {width}] is required",
                &**out_shape
            )));
        }
        if !values.iter().all(|v| v.is_finite()) {
            return Err(LoadError::SmokeNonFinite);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Fixture, ROWS, write_tokenizer};

    fn settings(dir: &std::path::Path, fixture: &Fixture, workers: usize) -> LoadSettings {
        LoadSettings {
            adapter: AdapterKind::TextClassifier,
            model_path: fixture.write(dir),
            tokenizer_path: write_tokenizer(dir, ROWS as u32 - 1),
            max_tokens: 16,
            workers: NonZeroUsize::new(workers).unwrap(),
        }
    }

    fn load_fixture(fixture: Fixture) -> Result<Vec<Worker>, LoadError> {
        let dir = tempfile::tempdir().unwrap();
        load(&settings(dir.path(), &fixture, 2))
    }

    #[test]
    fn a_good_model_loads_n_workers() {
        let dir = tempfile::tempdir().unwrap();
        let workers = load(&settings(dir.path(), &Fixture::default(), 3)).unwrap();
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
        let msg = load(&settings).err().unwrap().to_string();
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
        let err = load(&settings).err().unwrap();
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
            load(&settings),
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
        let mut plain = Session::builder()
            .unwrap()
            .commit_from_file(&settings.model_path)
            .unwrap();
        let mut worker = load(&settings).unwrap().pop().unwrap();
        let logits = |session: &mut Session| {
            let ids = Tensor::from_array(([1usize, 3], vec![1i64, 2, 3])).unwrap();
            let mask = Tensor::from_array(([1usize, 3], vec![1i64, 1, 1])).unwrap();
            let outputs = session
                .run(ort::inputs!["input_ids" => ids, "attention_mask" => mask])
                .unwrap();
            outputs[0].try_extract_tensor::<f32>().unwrap().1.to_vec()
        };
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
        let result = new_session(&settings, &model, &staged.path(), &PrepackedWeights::new());
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
        let workers = load(&settings).unwrap();
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
