# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`pii` is a Rust library for detecting Personally Identifiable Information (PII) in text. Uses Rust edition 2024.

**Primary use case:** embedded inside a tokio-based HTTP reverse proxy. The proxy shares a single `Scanner` across async tasks via `Arc<Scanner>`. Requests are mostly small (~3 KB) but may include large attachments (e.g. PDFs, up to tens of MB). The library stays sync and runtime-agnostic — the caller decides scheduling (inline for small requests, `spawn_blocking` for large ones).

The library supports English and French. More countries and languages will be added, hence all decisions should be made in context of scalability when number of regular expressions to handle grows.

## Build Commands

- **Build:** `cargo build | tail -n 20`
- **Test all:** `cargo test | tail -n 20`
- **Test single:** `cargo test <test_name>`
- **Check (fast compile check):** `cargo check | tail -n 20`

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

### Adding a New Language + Country — Checklist

Distilled from the French (`Language::Fr`, `Country::Fr`) implementation.

#### Files to modify

1. **`src/lib.rs`** — Add `Country` variant + `Country::all()`, `Language` variant + `Language::all()`, new `PiiKind` variants with `label()`, `country()`, and `ALL` entries.
2. **`src/validators.rs`** — Add country-specific validators with unit tests.
3. **`src/keyword_context_detector.rs`** — Add `Language::NewLang` patterns for new PII types AND translated keywords for existing international types (`UsPhoneNumber`, `PassportNumber`, `DateOfBirth`, `PreciseGeolocation`, `SwiftBic`, `Imei`). Add `#[test_case]` entries to `detects_with_keyword`, `no_detection_without_keyword`, `rejects_invalid_with_keyword`.
4. **`benches/pii_benchmark.rs`** — Add corpus constants, `per_pii_kind` entries, and samples in `MIXED_PII_TEXT`.

#### Validate with real-world examples

After implementing validators and patterns, search the web for documented real examples and add them as additional test cases. This catches algorithm bugs that synthetic test data may miss.

1. **Find documented examples** — Search for official government documentation, Wikipedia articles, and open-source validator repos (e.g., `github.com/rechtlogisch/steuer-id`, `gist.github.com/jensens` for AT SVNR, `sozialversicherungsnummer.ch` for CH AHV). Look for pages like `kryptografie.de` that show worked check-digit calculations.
2. **Verify programmatically** — Before adding examples as test values, verify them independently with a script (e.g., Python) that reimplements the check-digit algorithm. Never trust a web source without cross-checking.
3. **Add to validator unit tests** (`src/validators.rs`) — Add the verified real examples as additional `#[test]` cases, citing the source in a comment (e.g., `// From sozialversicherungsnummer.ch`).
4. **Add to keyword detector tests** (`src/keyword_context_detector.rs`) — Add `#[test_case]` entries using the real values with different keyword variants (long keyword, short keyword, alternative keywords).
5. **Test boundary/edge cases** — Use real-world knowledge to add tests for boundaries: check-digit-is-zero, upper/lower range limits for postal codes, off-by-one invalid checksums, real city postal codes (Berlin 10115, Vienna 1010, Zürich 8001).

### Writing unit tests
1. ALWAYS try to merge similar test cases using test_case macro. ALWAYS.
2. Implement also tests for false positives. The crate should not detect PIIs when they are not real PIIs.

#### Known pitfalls

**Keyword substring overlap (duplicate matches).** Vectorscan finds literal byte substrings. "téléphone" contains "phone", "passeport" contains "passport", "numéro IMEI" contains "IMEI". When both English and foreign patterns exist for the same `PiiKind`, the English pattern fires too (keyword found as substring), producing duplicate matches. **Prevention:** Don't add bare English words to foreign-language keyword alternations if the English pattern already has them. In tests, use exclusively-foreign keywords (e.g. `"rappel"` not `"téléphone"`, `"identifiant bancaire"` not `"code SWIFT"`).

**`luhn_check` has a hardcoded 13–19 digit range.** Write type-specific Luhn validators for other lengths (e.g. `siren_luhn_check` for 9-digit SIREN, `siret_luhn_check` for 14-digit SIRET).

**`dob_check` and new month names.** Add new language month names to the `month_from_name` closure in `dob_check`. Use `to_lowercase()` (not `to_ascii_lowercase()`) so non-ASCII names like "février" match.

**Complex patterns may silently fail in vectorscan's multi-pattern database** even if they compile and work in isolation. A month-name DOB pattern with 12+ alternations worked alone but didn't fire alongside 50+ other patterns. **Workaround:** Keep one combined pattern tuple with both simple (numeric) and complex (month-name) alternations in the regex. Vectorscan fires on the ASCII keyword, then the regex crate handles value extraction including complex alternations.

**Shared keywords across countries cause DFA bloat.** When a new country shares keywords with an existing one (e.g. DE and AT both use "Adresse", "Postfach"), do NOT add separate vectorscan patterns with duplicate keyword prefixes. Each additional pattern enlarges the vectorscan DFA, slowing *all* scans — even inputs with no matching content (e.g. US-only text regresses ~4%). **Solution:** Use a combined `PiiKind` variant with a multi-country prefix (e.g. `DeAtAddress` with label `"DE_AT_ADDRESS"`) and widen the value regex to accept both countries (e.g. `\d{4,5}` for 4-digit AT / 5-digit DE PLZ). One pattern, one DFA entry, one validator that accepts both formats. This scales naturally: when CH addresses arrive, rename to `DeAtChAddress` with `\d{4,5}` still covering all three. The label will be `DE_AT_CH_ADDRESS`.

**Always verify checksum/validation test data with a script.** Compute expected check digits independently before writing test values.
