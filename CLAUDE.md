# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`pii` is a Rust library for detecting Personally Identifiable Information (PII) in text. Uses Rust edition 2024.

**Primary use case:** embedded inside a tokio-based HTTP reverse proxy. The proxy shares a single `Scanner` across async tasks via `Arc<Scanner>`. Requests are mostly small (~3 KB) but may include large attachments (e.g. PDFs, up to tens of MB). The library stays sync and runtime-agnostic — the caller decides scheduling (inline for small requests, `spawn_blocking` for large ones).

Currently the library supports English-speaking countries only. Other countries and languages are going to be added, hence all decisions should be made in context of scalability when number of regular expressions to handle grows.

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

### Responsibility Boundary

The library handles **text-based PII detection only**. Binary format handling (PDF, DOCX, images) is **not** the library's responsibility. The HTTP proxy is responsible for: parsing `multipart/form-data`, extracting text from binary attachments (via external tools like `pdftotext`), and passing the extracted UTF-8 text as `&[u8]` to the scanner.

### Key Types

- `Scanner` — public entry point, holds a chain of `Box<dyn Detector + Send + Sync>`. Constructed via `Scanner::new()` or `Scanner::builder()`. Thread-safe (`Send + Sync`) for sharing via `Arc`.
- `Detector` trait (`detector.rs`) — interface for all detectors: `has_piis()` + `mark_piis()`
- `RegexDetector` (`regex_detector.rs`) — structured PII detection via compiled regexes (email, phone, credit card with Luhn validation)
- `PiiKind` / `PiiMatch` — defined in `lib.rs`, re-exported at crate root

### Detector Chain

Detectors are stored as `Vec<Box<dyn Detector + Send + Sync>>` in `Scanner`. In `has_piis` mode, iteration short-circuits on the first detector that returns `true`. In `mark_piis` mode, all detectors run and results are concatenated. New detector types (e.g., unstructured/NLP-based) plug in by implementing the `Detector` trait (which requires `Send + Sync`).

### Thread Safety

- `Scanner` is `Send + Sync` — safe to wrap in `Arc` and share across tokio tasks/threads.
- The `Detector` trait requires `Send + Sync`. All concrete detectors must satisfy this.
- Concurrency is handled at the caller level (e.g. `Arc<Scanner>` across tokio tasks with `spawn_blocking` for large inputs).

### Dependencies

Two regex engines are used:
- 'vectorscan' crate for fast and scalable checking of PII presence (called hyperscan sometimes, but vectorscan is used, which is a fork of hyperscan)
- `regex` crate - when vectorscan's regular expressions support is not sufficient

### Why Vectorscan (benchmark at 83 patterns)

At 83 patterns, `RegexSet` degrades catastrophically (5s on clean 1MB vs 2ms at 33 patterns). Vectorscan scales much better: 16ms detect, 18ms all-matches on clean 1MB. On typical 2KB proxy requests: vectorscan detect 23µs (108 MB/s) vs regex 164µs (15 MB/s).

Do not use Chimera. The PCRE fallback negates Hyperscan's performance advantage
(~1 MB/s vs 40-108 MB/s) and none of the current patterns require backreferences
or lookaround.

### Two-Detector Design: HyperscanDetector vs KeywordContextDetector

**HyperscanDetector** — PII types with structurally unique patterns (email, SSN, credit card). Vectorscan handles both detection and extraction. Uses `SOM_LEFTMOST` to get match start positions. The full match *is* the PII span.

**KeywordContextDetector** — PII types that are ambiguous without context (phone numbers, passport numbers, TFN, etc.). Patterns have the form `keyword + separator + (value)` where only the capture group is the PII. Vectorscan handles detection (`SINGLEMATCH`), then the `regex` crate extracts capture groups. Vectorscan cannot report capture group positions — it only reports full match boundaries — so regex extraction is required.

**Scaling:** Two-phase approach in KeywordContextDetector scales well. Vectorscan scans all patterns in one pass regardless of count. Regex extraction only runs for patterns vectorscan confirmed as present (typically 0–5 per input since input is usually in one language). Memory cost is ~1–5 KB per compiled `Regex`, negligible even at 2,000 patterns.

**Pattern compatibility constraint:** Each keyword pattern string is currently shared verbatim between vectorscan (detection) and the regex crate (extraction). Patterns must be valid in both dialects. If non-Latin language support requires syntax only one engine supports, split into separate `detection_expr` / `extraction_expr` per pattern.

### Adding a New Detector — Checklist

When adding a new detector or PII type, update **all** of the following:

1. Implement the `Detector` trait and register it in `Scanner::new()`
2. Add the new variant to `PiiKind`
3. Add unit tests — **add `#[test_case]` entries to the existing parametrized test functions first** (`detects_pii`, `rejects_invalid_pii` in `hyperscan_detector.rs`; `detects_with_keyword`, `no_detection_without_keyword`, `rejects_invalid_with_keyword` in `keyword_context_detector.rs`). Only create a new standalone test function if the existing parametrized functions genuinely cannot cover the case (e.g. a different assertion shape is required).
4. **Update benchmarks** (`benches/pii_benchmark.rs`):
   - Add a corpus constant (e.g., `SSN_TEXT`) with realistic embedded PII
   - Add an entry in the `per_detector` benchmark group
   - Add the new PII type into `MIXED_PII_TEXT` so throughput and comparison benchmarks cover it
