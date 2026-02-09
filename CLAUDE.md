# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`pii` is a Rust library for detecting Personally Identifiable Information (PII) in text. Uses Rust edition 2024.

## Build Commands

- **Build:** `cargo build | tail -n 100`
- **Test all:** `cargo test | tail -n 100`
- **Test single:** `cargo test <test_name>`
- **Check (fast compile check):** `cargo check | tail -n 100`
- **Lint:** `cargo clippy`
- **Format:** `cargo fmt`
- **Benchmarks:** `cargo bench --bench pii_benchmark --quiet`

## Architecture

Library crate (no `main.rs`). Two detection modes:

- **`has_piis(input)`** — returns `bool`, short-circuits on first PII found (across detectors)
- **`mark_piis(input)`** — returns `Vec<PiiMatch>` with byte-offset spans, runs all detectors

### Key Types

- `Scanner` — public entry point, holds a chain of `Box<dyn Detector>`. Constructed via `Scanner::new()` which pre-compiles all patterns.
- `Detector` trait (`detector.rs`) — interface for all detectors: `has_piis()` + `mark_piis()`
- `RegexDetector` (`regex_detector.rs`) — structured PII detection via compiled regexes (email, phone, credit card with Luhn validation)
- `PiiKind` / `PiiMatch` — defined in `lib.rs`, re-exported at crate root

### Detector Chain

Detectors are stored as `Vec<Box<dyn Detector>>` in `Scanner`. In `has_piis` mode, iteration short-circuits on the first detector that returns `true`. In `mark_piis` mode, all detectors run and results are concatenated. New detector types (e.g., unstructured/NLP-based) plug in by implementing the `Detector` trait.

### Adding a New Detector — Checklist

When adding a new detector or PII type, update **all** of the following:

1. Implement the `Detector` trait and register it in `Scanner::new()`
2. Add the new variant to `PiiKind`
3. Add unit tests
4. **Update benchmarks** (`benches/pii_benchmark.rs`):
   - Add a corpus constant (e.g., `SSN_TEXT`) with realistic embedded PII
   - Add an entry in the `per_detector` benchmark group
   - Add the new PII type into `MIXED_PII_TEXT` so throughput and comparison benchmarks cover it
