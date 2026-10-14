//! Scores the `voidwall-pii` regex engine against the AI4Privacy openpii300k
//! dataset. See `openspec/specs/evaluation/spec.md`. Run it with
//! `docker/ctl ai4p-eval`, which fetches the dataset first.
//!
//! Environment:
//! - `DATASET`: JSONL file, or a directory of `*.jsonl` (default `.cache/ai4privacy`).
//! - `AI4P_LANG`: `en`, `nl`, `fr`, `de`, `it`, `es`, or the English name. Unset scores
//!   all six.
//! - `MAX_ROWS`: stop after this many scored rows.
//! - `SUPPORTED_ONLY=1`: leave unsupported labels out of the table and the totals.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::{SyncSender, channel, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread;

use voidwall_pii::Scanner;

use voidwall_eval::language::EvalLanguage;
use voidwall_eval::report::{Counts, write_report};
use voidwall_eval::row::Row;
use voidwall_eval::score::{Aggregate, annotations, predict, score};

#[derive(Debug, PartialEq, Eq)]
struct Config {
    dataset: PathBuf,
    lang: Option<EvalLanguage>,
    max_rows: Option<u64>,
    supported_only: bool,
}

impl Config {
    fn from_env(var: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let var = |k: &str| var(k).filter(|v| !v.is_empty());
        let lang = match var("AI4P_LANG") {
            Some(v) => Some(EvalLanguage::parse(&v).ok_or_else(|| {
                format!(
                    "unknown AI4P_LANG={v:?}; use one of en, nl, fr, de, it, es, \
                     or English, Dutch, French, German, Italian, Spanish"
                )
            })?),
            None => None,
        };
        let max_rows = var("MAX_ROWS")
            .map(|v| {
                v.parse()
                    .map_err(|_| format!("MAX_ROWS={v:?} is not a whole number"))
            })
            .transpose()?;
        Ok(Config {
            dataset: PathBuf::from(var("DATASET").unwrap_or_else(|| ".cache/ai4privacy".into())),
            lang,
            max_rows,
            supported_only: var("SUPPORTED_ONLY").as_deref() == Some("1"),
        })
    }
}

/// A file is taken as given; a directory gives its `*.jsonl` children, sorted.
fn dataset_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        return Err(format!(
            "DATASET {} does not exist; run `docker/ctl ai4p-eval` to fetch it",
            path.display()
        ));
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("{} holds no *.jsonl file", path.display()));
    }
    Ok(files)
}

/// Which scanner a row is scored with, or why it is skipped.
enum Route {
    Score(EvalLanguage),
    UnsupportedLanguage,
    OtherLanguage,
}

fn route(row_language: Option<&str>, want: Option<EvalLanguage>) -> Route {
    match (row_language.map(EvalLanguage::parse), want) {
        (Some(Some(l)), Some(w)) if l != w => Route::OtherLanguage,
        (Some(Some(l)), _) => Route::Score(l),
        (Some(None), _) | (None, None) => Route::UnsupportedLanguage,
        (None, Some(w)) => Route::Score(w),
    }
}

/// Streams rows to the workers. Builds each language's scanner when a row
/// first needs it.
fn read_rows(
    files: &[PathBuf],
    cfg: &Config,
    jobs: SyncSender<(Row, Arc<Scanner>)>,
) -> Result<Counts, String> {
    let mut counts = Counts::default();
    let mut scanners: [Option<Arc<Scanner>>; 6] = Default::default();
    for file in files {
        let reader = BufReader::new(
            File::open(file).map_err(|e| format!("cannot open {}: {e}", file.display()))?,
        );
        for line in reader.lines() {
            if cfg.max_rows.is_some_and(|max| counts.rows_scored >= max) {
                return Ok(counts);
            }
            let line = line.map_err(|e| format!("cannot read {}: {e}", file.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            let Ok(row) = serde_json::from_str::<Row>(&line) else {
                counts.parse_errors += 1;
                continue;
            };
            let lang = match route(row.language.as_deref(), cfg.lang) {
                Route::Score(l) => l,
                Route::UnsupportedLanguage => {
                    counts.skipped_unsupported_language += 1;
                    continue;
                }
                Route::OtherLanguage => {
                    counts.skipped_other_language += 1;
                    continue;
                }
            };
            let scanner = match &scanners[lang.index()] {
                Some(s) => Arc::clone(s),
                None => {
                    let s =
                        Arc::new(lang.build_scanner().map_err(|e| {
                            format!("cannot build the {} scanner: {e}", lang.code())
                        })?);
                    scanners[lang.index()] = Some(Arc::clone(&s));
                    s
                }
            };
            if jobs.send((row, scanner)).is_err() {
                return Err("every worker stopped".into());
            }
            counts.rows_scored += 1;
        }
    }
    Ok(counts)
}

/// One reader thread streams rows through a bounded channel to `workers`
/// workers. The calling thread aggregates the outcomes.
fn run(cfg: &Config, files: &[PathBuf], workers: usize) -> Result<(Aggregate, Counts), String> {
    let (job_tx, job_rx) = sync_channel::<(Row, Arc<Scanner>)>(workers * 4);
    let job_rx = Arc::new(Mutex::new(job_rx));
    let (out_tx, out_rx) = channel();

    thread::scope(|s| {
        for _ in 0..workers {
            let job_rx = Arc::clone(&job_rx);
            let out_tx = out_tx.clone();
            s.spawn(move || {
                loop {
                    // The guard drops at the end of this statement, so a worker
                    // holds the lock only while it waits for the next row.
                    let job = job_rx.lock().map(|rx| rx.recv());
                    let Ok(Ok((row, scanner))) = job else { break };
                    let outcome = score(&annotations(&row), &predict(&scanner, &row.source_text));
                    drop(row);
                    if out_tx.send(outcome).is_err() {
                        break;
                    }
                }
            });
        }
        drop(out_tx);
        let reader = s.spawn(move || read_rows(files, cfg, job_tx));

        let mut agg = Aggregate::default();
        for outcome in out_rx {
            agg.add(outcome);
        }
        let counts = reader
            .join()
            .map_err(|_| "the reader thread panicked".to_string())??;
        Ok((agg, counts))
    })
}

fn main() -> ExitCode {
    let result = Config::from_env(|k| std::env::var(k).ok()).and_then(|cfg| {
        let files = dataset_files(&cfg.dataset)?;
        let workers = thread::available_parallelism().map_or(1, |n| n.get());
        let (agg, counts) = run(&cfg, &files, workers)?;
        write_report(
            &mut std::io::stdout().lock(),
            &agg,
            counts,
            cfg.lang,
            cfg.supported_only,
        )
        .map_err(|e| format!("cannot write the report: {e}"))
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ai4privacy-eval: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use test_case::test_case;

    fn cfg(vars: &[(&str, &str)]) -> Result<Config, String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_env(|k| map.get(k).cloned())
    }

    #[test]
    fn defaults() {
        assert_eq!(
            cfg(&[]).unwrap(),
            Config {
                dataset: PathBuf::from(".cache/ai4privacy"),
                lang: None,
                max_rows: None,
                supported_only: false,
            }
        );
    }

    #[test]
    fn every_variable_is_read() {
        assert_eq!(
            cfg(&[
                ("DATASET", "x.jsonl"),
                ("AI4P_LANG", "French"),
                ("MAX_ROWS", "200"),
                ("SUPPORTED_ONLY", "1"),
            ])
            .unwrap(),
            Config {
                dataset: PathBuf::from("x.jsonl"),
                lang: Some(EvalLanguage::Fr),
                max_rows: Some(200),
                supported_only: true,
            }
        );
    }

    #[test_case("LANG", "en"; "the locale variable is not read")]
    #[test_case("LANGUAGE", "en"; "the gettext variable is not read")]
    #[test_case("AI4P_LANG", ""; "empty means all six")]
    fn language_unset(k: &str, v: &str) {
        assert_eq!(cfg(&[(k, v)]).unwrap().lang, None);
    }

    #[test_case("AI4P_LANG", "pt")]
    #[test_case("AI4P_LANG", "en_US.UTF-8")]
    #[test_case("MAX_ROWS", "ten")]
    #[test_case("MAX_ROWS", "-1")]
    fn invalid_values_are_rejected(k: &str, v: &str) {
        assert!(cfg(&[(k, v)]).is_err());
    }

    #[test]
    fn missing_dataset_is_an_error() {
        assert!(dataset_files(Path::new("/nonexistent/ai4p.jsonl")).is_err());
    }

    #[test_case(Some("English"), None, Some(EvalLanguage::En))]
    #[test_case(Some("English"), Some(EvalLanguage::En), Some(EvalLanguage::En))]
    #[test_case(None, Some(EvalLanguage::De), Some(EvalLanguage::De))]
    #[test_case(None, None, None; "no language at all")]
    #[test_case(Some("Polish"), None, None; "unsupported language")]
    fn route_picks_the_scanner(
        row: Option<&str>,
        want: Option<EvalLanguage>,
        expect: Option<EvalLanguage>,
    ) {
        let got = match route(row, want) {
            Route::Score(l) => Some(l),
            _ => None,
        };
        assert_eq!(got, expect);
    }

    #[test]
    fn route_skips_other_language() {
        assert!(matches!(
            route(Some("French"), Some(EvalLanguage::En)),
            Route::OtherLanguage
        ));
    }

    #[test]
    fn run_counts_rows_and_stops_at_max_rows() {
        let dir = std::env::temp_dir().join(format!("voidwall-eval-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("rows.jsonl");
        let row = r#"{"source_text":"mail user@example.com","privacy_mask":[{"label":"EMAIL","start":5,"end":21,"value":"user@example.com"}],"language":"English"}"#;
        let polish = r#"{"source_text":"x","privacy_mask":[],"language":"Polish"}"#;
        let lines = [row, "not json", row, polish, row];
        std::fs::write(&file, lines.join("\n")).unwrap();

        let all = Config {
            dataset: file.clone(),
            lang: None,
            max_rows: None,
            supported_only: false,
        };
        let (agg, counts) = run(&all, std::slice::from_ref(&file), 4).unwrap();
        assert_eq!(counts.rows_scored, 3);
        assert_eq!(counts.parse_errors, 1);
        assert_eq!(counts.skipped_unsupported_language, 1);
        assert_eq!(agg.micro(false).detection.recall, 1.0);

        let capped = Config {
            max_rows: Some(2),
            ..all
        };
        let (_, counts) = run(&capped, std::slice::from_ref(&file), 4).unwrap();
        assert_eq!(counts.rows_scored, 2);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Real scanner, English. Five scored rows:
    /// 1. an email, character offsets
    /// 2. multi-byte text before an email, and an IBAN no annotation covers (FP)
    /// 3. an email with byte offsets
    /// 4. `privacy_mask` as a JSON string: CITY (missed, unsupported) and an email
    /// 5. a name the engine does not detect (missed)
    ///
    /// Then a Polish row (skipped) and a line that is not JSON (parse error).
    const FIXTURE: &str = r#"{"source_text": "Mail user@example.com today", "privacy_mask": [{"label": "EMAIL", "start": 5, "end": 21, "value": "user@example.com"}], "language": "English"}
{"source_text": "Grüße 😀 — pay GB82 WEST 1234 5698 7654 32, mail anna@example.org", "privacy_mask": [{"label": "EMAIL", "start": 48, "end": 64, "value": "anna@example.org"}], "language": "English"}
{"source_text": "Café: bob@example.net", "privacy_mask": [{"label": "EMAIL", "start": 7, "end": 22, "value": "bob@example.net"}], "language": "English"}
{"source_text": "From Zurich, eve@example.com", "privacy_mask": "[{\"label\": \"CITY\", \"start\": 5, \"end\": 11, \"value\": \"Zurich\"}, {\"label\": \"EMAIL\", \"start\": 13, \"end\": 28, \"value\": \"eve@example.com\"}]", "language": "English"}
{"source_text": "Ref Qzxv here", "privacy_mask": [{"label": "GIVENNAME1", "start": 4, "end": 8, "value": "Qzxv"}], "language": "English"}
{"source_text": "x", "privacy_mask": [], "language": "Polish"}
not json"#;

    /// Writes `lines` to a fresh file and runs it with `workers`.
    fn run_lines(name: &str, lines: &[&str], workers: usize) -> (Aggregate, Counts) {
        let dir = std::env::temp_dir().join(format!(
            "voidwall-eval-{name}-{}-{workers}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("rows.jsonl");
        std::fs::write(&file, lines.join("\n")).unwrap();
        let cfg = Config {
            dataset: file.clone(),
            lang: None,
            max_rows: None,
            supported_only: false,
        };
        let out = run(&cfg, std::slice::from_ref(&file), workers).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        out
    }

    fn fixture() -> Vec<&'static str> {
        FIXTURE.lines().collect()
    }

    #[test]
    fn end_to_end_fixture_counts() {
        use voidwall_eval::label::{Ai4pLabel, Label};
        use voidwall_eval::score::LabelStat;

        let (agg, counts) = run_lines("e2e", &fixture(), 4);
        assert_eq!(
            counts,
            Counts {
                rows_scored: 5,
                parse_errors: 1,
                skipped_unsupported_language: 1,
                skipped_other_language: 0,
            }
        );
        let stat = |annotations, detected, typed| LabelStat {
            annotations,
            detected,
            typed,
        };
        let expected = [
            (Ai4pLabel::City, stat(1, 0, 0)),
            (Ai4pLabel::Email, stat(4, 4, 4)),
            (Ai4pLabel::GivenName1, stat(1, 0, 0)),
        ];
        assert_eq!(
            agg.per_label.clone().into_iter().collect::<Vec<_>>(),
            expected.map(|(l, s)| (Label::Known(l), s)).to_vec()
        );
        // Five predictions: four emails (typed TPs) and the IBAN (FP).
        // P 4/5, R 4/6: F1 = 8/11, F2 = 20/29 in both variants.
        let m = agg.micro(false);
        assert_eq!((m.annotations, m.predictions), (6, 5));
        for v in [m.detection, m.typed] {
            assert_eq!((v.precision, v.recall), (4.0 / 5.0, 4.0 / 6.0));
            assert!((v.f1 - 8.0 / 11.0).abs() < 1e-15, "{v:?}");
            assert!((v.f2 - 20.0 / 29.0).abs() < 1e-15, "{v:?}");
        }
        assert_eq!(
            agg.label_precision(&Label::Known(Ai4pLabel::Email), false),
            Some((1.0, 1.0))
        );
    }

    #[test]
    fn workers_and_row_order_do_not_change_the_result() {
        let one = run_lines("one", &fixture(), 1);
        assert_eq!(run_lines("many", &fixture(), 8), one);
        let mut reversed = fixture();
        reversed.reverse();
        assert_eq!(run_lines("reversed", &reversed, 8), one);
    }

    #[test]
    fn a_dataset_written_twice_doubles_counts_and_keeps_ratios() {
        let (once, c1) = run_lines("once", &fixture(), 4);
        let (twice, c2) = run_lines("twice", &[fixture(), fixture()].concat(), 4);
        assert_eq!(c2.rows_scored, 2 * c1.rows_scored);
        assert_eq!(c2.parse_errors, 2 * c1.parse_errors);
        for (label, s) in &once.per_label {
            let t = twice.per_label[label];
            assert_eq!(
                (t.annotations, t.detected, t.typed),
                (2 * s.annotations, 2 * s.detected, 2 * s.typed)
            );
            for supported_only in [false, true] {
                assert_eq!(
                    twice.label_precision(label, supported_only),
                    once.label_precision(label, supported_only)
                );
            }
        }
        for supported_only in [false, true] {
            let (a, b) = (once.micro(supported_only), twice.micro(supported_only));
            assert_eq!(
                (b.annotations, b.predictions),
                (2 * a.annotations, 2 * a.predictions)
            );
            assert_eq!((b.detection, b.typed), (a.detection, a.typed));
        }
        assert_eq!(twice.macro_recall(), once.macro_recall());
    }
}
