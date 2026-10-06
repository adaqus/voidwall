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
//! `tokenizer.json`, and `reference.json`.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::adapter::AdapterKind;
use crate::load::{LoadSettings, load};

/// The largest score difference from the reference that parity accepts.
const TOLERANCE: f64 = 1e-4;
/// The lowest score the known attack prompt may get.
const ATTACK_SCORE: f32 = 0.9;

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

#[test]
#[ignore = "needs real models; see crates/voidwall-ml/parity/README.md"]
fn scores_match_the_python_reference() {
    let Some(dir) = std::env::var_os("VOIDWALL_PARITY_DIR") else {
        panic!("set VOIDWALL_PARITY_DIR; see crates/voidwall-ml/parity/README.md");
    };
    let mut models: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("VOIDWALL_PARITY_DIR is not a readable directory")
        .map(|entry| entry.expect("read VOIDWALL_PARITY_DIR").path())
        .filter(|path| path.join("reference.json").is_file())
        .collect();
    models.sort();
    assert!(
        !models.is_empty(),
        "no directory with a reference.json in VOIDWALL_PARITY_DIR"
    );

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
    let reference: Reference = serde_json::from_slice(
        &std::fs::read(dir.join("reference.json")).expect("read reference.json"),
    )
    .expect("parse reference.json");
    let settings = LoadSettings {
        adapter: AdapterKind::TextClassifier,
        model_path: dir.join("model.onnx"),
        tokenizer_path: dir.join("tokenizer.json"),
        max_tokens: reference.max_tokens,
        overlap_tokens: Some(reference.overlap),
        max_body_size: NonZeroUsize::new(1 << 20).unwrap(),
        workers: NonZeroUsize::MIN,
    };
    let mut worker = load(&settings)
        .unwrap_or_else(|e| panic!("{name}: {e}"))
        .pop()
        .unwrap();

    let mut failures = Vec::new();
    let mut max_delta = 0.0f64;
    for unit in &reference.units {
        let encoding = worker.tokenizer.encode(unit.text.as_str(), false).unwrap();
        let windows: Vec<Vec<i64>> = worker
            .windowing
            .spans(encoding.len())
            .unwrap()
            .map(|span| worker.window_ids(&encoding, span).unwrap())
            .collect();
        if windows != unit.windows {
            failures.push(format!("{name}/{}: window token IDs differ", unit.id));
        }

        let score = worker
            .score(&unit.text)
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
