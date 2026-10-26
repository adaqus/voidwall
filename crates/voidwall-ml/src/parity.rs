//! Parity with the Python reference on real models.
//!
//! `parity/reference.py` writes one `reference.json` per model; see
//! `parity/README.md`. The test needs model files, which the repository never
//! holds, so it is ignored by default:
//!
//! ```text
//! VOIDWALL_PARITY_DIR=<dir> cargo test -p voidwall-ml --release -- --ignored parity
//! ```
//!
//! `<dir>` holds one directory per model, each with `model.onnx`,
//! `tokenizer.json`, and `reference.json`; a `token_classifier` model also
//! has its `config.json`. A `token_classifier` directory that also holds
//! `model_quantized.onnx` gets the INT8 check.

use std::num::NonZeroUsize;
use std::ops::Range;
use std::path::{Path, PathBuf};

use ort::session::Session;
use ort::value::Tensor;
use serde::Deserialize;

use crate::adapter::AdapterKind;
use crate::decode::Boundaries;
use crate::fixtures::runtime;
use crate::load::{Head, LoadSettings, TokenWorker, Worker, load, plain_session};
use crate::run::{uncancelled, window_inputs};

/// The largest score difference from the reference that parity accepts.
const TOLERANCE: f64 = 1e-4;
/// The largest pooled probability or confidence difference from the
/// reference that token classifier parity accepts. Wider than [`TOLERANCE`]:
/// the fp32 PII model's ONNX export alone differs from PyTorch 2.14 by 1.41e-4.
const TOKEN_TOLERANCE: f64 = 2e-4;
/// The lowest score the known attack prompt may get.
const ATTACK_SCORE: f32 = 0.9;

/// The adapter a reference was made for. A reference without one predates
/// `token_classifier` and is a `text_classifier` reference.
#[derive(Deserialize)]
struct Header {
    adapter: Option<AdapterKind>,
}

#[derive(Deserialize)]
struct Reference {
    max_tokens: usize,
    overlap: usize,
    units: Vec<Unit>,
}

#[derive(Deserialize)]
struct Unit {
    id: String,
    text: String,
    known_attack: bool,
    windows: Vec<Vec<i64>>,
    score: f64,
}

/// The model directories of `VOIDWALL_PARITY_DIR` that hold `file` and a
/// `reference.json`. Fails when there is none, so no test passes unchecked.
fn model_dirs(file: &str) -> Vec<PathBuf> {
    let Some(dir) = std::env::var_os("VOIDWALL_PARITY_DIR") else {
        panic!("set VOIDWALL_PARITY_DIR; see crates/voidwall-ml/parity/README.md");
    };
    let mut models: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("VOIDWALL_PARITY_DIR is not a readable directory")
        .map(|entry| entry.expect("read VOIDWALL_PARITY_DIR").path())
        .filter(|path| path.join(file).is_file() && path.join("reference.json").is_file())
        .collect();
    models.sort();
    assert!(
        !models.is_empty(),
        "no directory with a {file} and a reference.json in VOIDWALL_PARITY_DIR"
    );
    models
}

#[test]
#[ignore = "needs real models; see crates/voidwall-ml/parity/README.md"]
fn scores_match_the_python_reference() {
    let models = model_dirs("reference.json");
    let failures: Vec<String> = models.iter().flat_map(|m| check_model(m)).collect();
    assert!(
        failures.is_empty(),
        "parity failed:\n{}",
        failures.join("\n")
    );
}

/// Checks one model against its reference and returns what failed.
fn check_model(dir: &Path) -> Vec<String> {
    let name = dir.file_name().unwrap().to_string_lossy().into_owned();
    let json = std::fs::read(dir.join("reference.json")).expect("read reference.json");
    let header: Header = serde_json::from_slice(&json).expect("parse reference.json");
    match header.adapter.unwrap_or(AdapterKind::TextClassifier) {
        AdapterKind::TextClassifier => check_classifier(dir, &name, &json),
        AdapterKind::TokenClassifier => check_tokens(dir, &name, &json),
        other => panic!("{name}: no parity check for `{}`", other.name()),
    }
}

/// The token IDs of each window of `text`, special tokens added.
fn window_ids<H: Head>(worker: &Worker<H>, text: &str) -> Vec<Vec<i64>> {
    let encoding = worker.tokenizer.encode(text, false).unwrap();
    worker
        .windowing
        .spans(encoding.len())
        .unwrap()
        .map(|span| worker.window_ids(&encoding, span).unwrap())
        .collect()
}

fn check_classifier(dir: &Path, name: &str, json: &[u8]) -> Vec<String> {
    let reference: Reference = serde_json::from_slice(json).expect("parse reference.json");
    let settings = LoadSettings {
        adapter: AdapterKind::TextClassifier,
        model_path: dir.join("model.onnx"),
        tokenizer_path: dir.join("tokenizer.json"),
        config_path: None,
        max_tokens: reference.max_tokens,
        overlap_tokens: Some(reference.overlap),
        max_body_size: NonZeroUsize::new(1 << 20).unwrap(),
        workers: NonZeroUsize::MIN,
    };
    let mut worker = load(runtime(), &settings)
        .unwrap_or_else(|e| panic!("{name}: {e}"))
        .into_classifiers()
        .pop()
        .unwrap();

    let mut failures = Vec::new();
    let mut max_delta = 0.0f64;
    for unit in &reference.units {
        if window_ids(&worker, &unit.text) != unit.windows {
            failures.push(format!("{name}/{}: window token IDs differ", unit.id));
        }

        let score = worker
            .score(&unit.text, &uncancelled())
            .unwrap_or_else(|e| panic!("{name}/{}: {e}", unit.id));
        let delta = (f64::from(score) - unit.score).abs();
        max_delta = max_delta.max(delta);
        if delta > TOLERANCE {
            failures.push(format!(
                "{name}/{}: score {score} vs reference {} (delta {delta:.2e})",
                unit.id, unit.score
            ));
        }
        if (score >= 0.5) != (unit.score >= 0.5) {
            failures.push(format!(
                "{name}/{}: score {score} is on the other side of 0.5 from {}",
                unit.id, unit.score
            ));
        }
        if unit.known_attack {
            eprintln!("{name}: known attack scores {score}");
            if score < ATTACK_SCORE {
                failures.push(format!(
                    "{name}/{}: known attack scores {score}, below {ATTACK_SCORE}",
                    unit.id
                ));
            }
        }
    }
    eprintln!(
        "{name}: {} units, max score delta {max_delta:.2e}",
        reference.units.len()
    );
    failures
}

#[derive(Deserialize)]
struct TokenReference {
    max_tokens: usize,
    overlap: usize,
    units: Vec<TokenUnit>,
}

#[derive(Deserialize)]
struct TokenUnit {
    id: String,
    text: String,
    windows: Vec<Vec<i64>>,
    /// One per non-special token per window, in window order.
    records: Vec<RefRecord>,
    spans: Vec<RefSpan>,
}

/// Offsets in the reference are characters, as Python counts them.
#[derive(Deserialize)]
struct RefRecord {
    chars: [usize; 2],
    pooled: Vec<f64>,
    start: f64,
}

#[derive(Deserialize)]
struct RefSpan {
    chars: [usize; 2],
    #[serde(rename = "type")]
    ty: String,
    confidence: f64,
}

/// The byte range of the characters `chars` of `text`.
fn bytes_of(text: &str, chars: [usize; 2]) -> Range<usize> {
    let mut at = text.char_indices().map(|(i, _)| i).chain([text.len()]);
    let start = at
        .nth(chars[0])
        .expect("a character offset inside the text");
    let end = if chars[1] == chars[0] {
        start
    } else {
        at.nth(chars[1] - chars[0] - 1)
            .expect("a character offset inside the text")
    };
    start..end
}

fn check_tokens(dir: &Path, name: &str, json: &[u8]) -> Vec<String> {
    let reference: TokenReference = serde_json::from_slice(json).expect("parse reference.json");
    let settings = LoadSettings {
        adapter: AdapterKind::TokenClassifier,
        model_path: dir.join("model.onnx"),
        tokenizer_path: dir.join("tokenizer.json"),
        config_path: Some(dir.join("config.json")),
        max_tokens: reference.max_tokens,
        overlap_tokens: Some(reference.overlap),
        max_body_size: NonZeroUsize::new(1 << 20).unwrap(),
        workers: NonZeroUsize::MIN,
    };
    let mut worker = load(runtime(), &settings)
        .unwrap_or_else(|e| panic!("{name}: {e}"))
        .into_tokens()
        .pop()
        .unwrap();
    let types = worker.labels().types().to_vec();

    let mut failures = Vec::new();
    let mut max_delta = 0.0f64;
    let (mut records, mut spans) = (0, 0);
    for unit in &reference.units {
        let id = &unit.id;
        if window_ids(&worker, &unit.text) != unit.windows {
            failures.push(format!("{name}/{id}: window token IDs differ"));
        }

        let probs = worker
            .run(&unit.text, &uncancelled())
            .unwrap_or_else(|e| panic!("{name}/{id}: {e}"));
        if probs.len() != unit.records.len() {
            failures.push(format!(
                "{name}/{id}: {} records vs reference {}",
                probs.len(),
                unit.records.len()
            ));
        }
        for (i, (got, want)) in probs.records().zip(&unit.records).enumerate() {
            if got.bytes != bytes_of(&unit.text, want.chars) {
                failures.push(format!("{name}/{id}: record {i} covers other bytes"));
            }
            let delta = got
                .pooled
                .iter()
                .zip(&want.pooled)
                .chain([(&got.start, &want.start)])
                .map(|(&g, &w)| (f64::from(g) - w).abs())
                .fold(0.0, f64::max);
            max_delta = max_delta.max(delta);
            if got.pooled.len() != want.pooled.len() || delta > TOKEN_TOLERANCE {
                failures.push(format!(
                    "{name}/{id}: record {i} probabilities differ (delta {delta:.2e})"
                ));
            }
        }
        records += unit.records.len();

        let found: Vec<_> = worker
            .spans(&unit.text, &Boundaries::default(), &uncancelled())
            .unwrap_or_else(|e| panic!("{name}/{id}: {e}"))
            .into_iter()
            .map(|s| (s.bytes, types[s.ty].as_str(), f64::from(s.confidence)))
            .collect();
        let expected: Vec<_> = unit
            .spans
            .iter()
            .map(|s| (bytes_of(&unit.text, s.chars), s.ty.as_str(), s.confidence))
            .collect();
        let shape = |spans: &[(Range<usize>, &str, f64)]| {
            spans
                .iter()
                .map(|(b, t, _)| format!("{b:?} {t}"))
                .collect::<Vec<_>>()
        };
        if shape(&found) != shape(&expected) {
            failures.push(format!(
                "{name}/{id}: spans {:?} vs reference {:?}",
                shape(&found),
                shape(&expected)
            ));
        } else {
            for ((bytes, ty, got), (_, _, want)) in found.iter().zip(&expected) {
                let delta = (got - want).abs();
                max_delta = max_delta.max(delta);
                if delta > TOKEN_TOLERANCE {
                    failures.push(format!(
                        "{name}/{id}: {ty} at {bytes:?} confidence {got} vs reference {want}"
                    ));
                }
            }
        }
        spans += expected.len();
    }
    eprintln!(
        "{name}: {} units, {records} records, {spans} spans, max probability delta {max_delta:.2e}",
        reference.units.len()
    );
    failures
}

/// The INT8 file a `token_classifier` model directory may hold beside its
/// fp32 `model.onnx`.
const INT8_MODEL: &str = "model_quantized.onnx";

/// An INT8 worker is checked against a plain session of its own file, not
/// against Python: the ONNX Runtime build linked here and the Python wheel
/// round some fp32 operations apart, and dynamic quantization turns that into
/// whole quantization steps (`voidwall-internal/research/pii-model/int8-gap.md`).
/// So this checks only what the load adds: the staged graph, the shared
/// weights, and the prepacked weights.
#[test]
#[ignore = "needs real models; see crates/voidwall-ml/parity/README.md"]
fn quantized_logits_match_a_plain_session() {
    let failures: Vec<String> = model_dirs(INT8_MODEL)
        .iter()
        .flat_map(|m| check_int8(m))
        .collect();
    assert!(
        failures.is_empty(),
        "INT8 check failed:\n{}",
        failures.join("\n")
    );
}

/// Runs every window of the reference's texts through an INT8 worker and a
/// plain session, and returns the windows whose logits differ in any bit.
fn check_int8(dir: &Path) -> Vec<String> {
    let name = dir.file_name().unwrap().to_string_lossy().into_owned();
    let json = std::fs::read(dir.join("reference.json")).expect("read reference.json");
    let reference: TokenReference = serde_json::from_slice(&json).expect("parse reference.json");
    let settings = LoadSettings {
        adapter: AdapterKind::TokenClassifier,
        model_path: dir.join(INT8_MODEL),
        tokenizer_path: dir.join("tokenizer.json"),
        config_path: Some(dir.join("config.json")),
        max_tokens: reference.max_tokens,
        overlap_tokens: Some(reference.overlap),
        max_body_size: NonZeroUsize::new(1 << 20).unwrap(),
        workers: NonZeroUsize::MIN,
    };
    let mut worker = load(runtime(), &settings)
        .unwrap_or_else(|e| panic!("{name}: {e}"))
        .into_tokens()
        .pop()
        .unwrap();
    let mut plain = plain_session(&settings.model_path).unwrap_or_else(|e| panic!("{name}: {e}"));

    let mut failures = Vec::new();
    let mut windows = 0;
    for unit in &reference.units {
        for (i, ids) in window_ids(&worker, &unit.text).iter().enumerate() {
            let got = worker
                .infer(ids, &uncancelled())
                .unwrap_or_else(|e| panic!("{name}/{}: {e}", unit.id));
            let want = plain_logits(&mut plain, &worker, ids);
            let same = got.len() == want.len()
                && got
                    .iter()
                    .zip(&want)
                    .all(|(g, w)| g.to_bits() == w.to_bits());
            if !same {
                let delta = got
                    .iter()
                    .zip(&want)
                    .map(|(g, w)| (g - w).abs())
                    .fold(0.0f32, f32::max);
                failures.push(format!(
                    "{name}/{} window {i}: logits differ from the plain session (max {delta:.2e})",
                    unit.id
                ));
            }
            windows += 1;
        }
    }
    eprintln!(
        "{name} INT8: {} units, {windows} windows, logits bit-identical to a plain session: {}",
        reference.units.len(),
        failures.is_empty()
    );
    failures
}

/// The logits of one window from `session`, fed as `worker` feeds its own.
fn plain_logits(session: &mut Session, worker: &TokenWorker, ids: &[i64]) -> Vec<f32> {
    let (ids, mask) = window_inputs(ids, worker.layout.fixed_seq, worker.pad_id);
    let shape = [1usize, ids.len()];
    let mut inputs = ort::inputs![
        "input_ids" => Tensor::from_array((shape, ids.clone())).unwrap(),
        "attention_mask" => Tensor::from_array((shape, mask)).unwrap(),
    ];
    if worker.layout.token_type_ids {
        let zeros = Tensor::from_array((shape, vec![0i64; ids.len()])).unwrap();
        inputs.push(("token_type_ids".into(), zeros.into()));
    }
    let outputs = session.run(inputs).unwrap();
    outputs[0].try_extract_tensor::<f32>().unwrap().1.to_vec()
}

#[test]
fn reference_character_offsets_become_bytes() {
    let text = "zażółć x";
    assert_eq!(bytes_of(text, [0, 6]), 0..10);
    assert_eq!(bytes_of(text, [7, 8]), 11..12);
    assert_eq!(bytes_of(text, [3, 3]), 4..4);
    assert_eq!(bytes_of(text, [8, 8]), 12..12);
}
