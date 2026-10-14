//! Writes the regex engine's spans for the PII Masking Benchmark (piimb). See
//! `openspec/specs/evaluation/spec.md`. Run it with `docker/ctl piimb-eval`, which
//! fetches the benchmark and scores the spans with piimb's own metric code.
//!
//! Usage: `piimb-spans <test_sentences.jsonl> <task>...`
//!
//! Reads the file line by line and keeps the rows of the named tasks. For each, writes
//! one JSON line to stdout: `uid`, `task_name`, and `entities` (`start`, `end`, `label`)
//! in character offsets of the sentence. The output holds no sentence text.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::process::ExitCode;

use serde::{Deserialize, Serialize};
use voidwall_eval::language::EvalLanguage;
use voidwall_eval::score::predict;
use voidwall_pii::Scanner;

/// A row of `test_sentences.jsonl`. Unknown fields, ground truth among them, are ignored.
#[derive(Debug, Deserialize)]
struct Sentence {
    uid: String,
    task_name: String,
    text: String,
}

#[derive(Debug, Serialize)]
struct Span {
    start: usize,
    end: usize,
    label: &'static str,
}

#[derive(Debug, Serialize)]
struct Spans<'a> {
    uid: &'a str,
    task_name: &'a str,
    entities: Vec<Span>,
}

/// The output line for `line`, or `None` when its task is not one of `tasks`.
fn spans_line(scanner: &Scanner, tasks: &[String], line: &str) -> Result<Option<String>, String> {
    let row: Sentence = serde_json::from_str(line).map_err(|e| format!("bad row: {e}"))?;
    if !tasks.contains(&row.task_name) {
        return Ok(None);
    }
    let entities = predict(scanner, &row.text)
        .into_iter()
        .map(|p| Span {
            start: p.start,
            end: p.end,
            label: p.kind.label(),
        })
        .collect();
    let out = Spans {
        uid: &row.uid,
        task_name: &row.task_name,
        entities,
    };
    serde_json::to_string(&out)
        .map(Some)
        .map_err(|e| format!("cannot write a row: {e}"))
}

fn run(path: &str, tasks: &[String]) -> Result<(), String> {
    let scanner = EvalLanguage::En
        .build_scanner()
        .map_err(|e| format!("cannot build the en scanner: {e}"))?;
    let reader = BufReader::new(File::open(path).map_err(|e| format!("cannot open {path}: {e}"))?);
    let mut out = BufWriter::new(std::io::stdout().lock());
    for (n, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("cannot read {path}: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(spans) =
            spans_line(&scanner, tasks, &line).map_err(|e| format!("{path} line {}: {e}", n + 1))?
        {
            writeln!(out, "{spans}").map_err(|e| format!("cannot write: {e}"))?;
        }
    }
    out.flush().map_err(|e| format!("cannot write: {e}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((path, tasks)) if !tasks.is_empty() => run(path, tasks),
        _ => Err("usage: piimb-spans <test_sentences.jsonl> <task>...".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("piimb-spans: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use voidwall_pii::resolve_overlaps;

    fn scanner() -> Scanner {
        EvalLanguage::En.build_scanner().unwrap()
    }

    fn row(task: &str, text: &str) -> String {
        serde_json::json!({
            "uid": "t:1_s0",
            "task_name": task,
            "text": text,
            "entities": [],
            "language": "en",
        })
        .to_string()
    }

    fn tasks() -> Vec<String> {
        vec!["ai4privacy-en".into(), "privy".into()]
    }

    fn entities(out: &str) -> Vec<(usize, usize, String)> {
        let v: serde_json::Value = serde_json::from_str(out).unwrap();
        v["entities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["start"].as_u64().unwrap() as usize,
                    e["end"].as_u64().unwrap() as usize,
                    e["label"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn row_of_another_task_is_skipped() {
        let line = row("gretel", "Contact: user@example.com");
        assert_eq!(spans_line(&scanner(), &tasks(), &line).unwrap(), None);
    }

    #[test]
    fn kept_row_names_its_uid_and_task() {
        let out = spans_line(&scanner(), &tasks(), &row("privy", "no pii here"))
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["uid"], "t:1_s0");
        assert_eq!(v["task_name"], "privy");
        assert_eq!(v["entities"], serde_json::json!([]));
    }

    #[test]
    fn multibyte_text_before_a_value_gives_character_offsets() {
        let text = "Grüße 😀 — mail: user@example.com";
        let start = text.chars().count() - "user@example.com".chars().count();
        let out = spans_line(&scanner(), &tasks(), &row("ai4privacy-en", text))
            .unwrap()
            .unwrap();
        assert_eq!(
            entities(&out),
            vec![(start, start + 16, "EMAIL".to_string())]
        );
        assert_ne!(
            start,
            text.find("user@").unwrap(),
            "test needs bytes != chars"
        );
    }

    #[test]
    fn overlapping_matches_are_resolved() {
        let s = scanner();
        let text = "Address: 10 Downing Street, London SW1A 2AA";
        let raw = s.mark_piis(text);
        let resolved = resolve_overlaps(raw.clone());
        assert!(
            resolved.len() < raw.len(),
            "test needs overlapping raw matches"
        );
        let out = spans_line(&s, &tasks(), &row("ai4privacy-en", text))
            .unwrap()
            .unwrap();
        let spans = entities(&out);
        assert_eq!(spans.len(), resolved.len());
        for (i, a) in spans.iter().enumerate() {
            for b in &spans[i + 1..] {
                assert!(a.1 <= b.0 || b.1 <= a.0, "spans overlap: {spans:?}");
            }
        }
    }

    #[test]
    fn output_holds_no_sentence_text() {
        let text = "Write to user@example.com about Downing Street";
        let out = spans_line(&scanner(), &tasks(), &row("ai4privacy-en", text))
            .unwrap()
            .unwrap();
        assert!(!entities(&out).is_empty(), "{out}");
        for word in ["user@example.com", "example", "Write", "Downing"] {
            assert!(!out.contains(word), "output leaks {word:?}: {out}");
        }
    }

    #[test]
    fn a_line_that_is_not_json_is_an_error() {
        assert!(spans_line(&scanner(), &tasks(), "not json").is_err());
    }
}
