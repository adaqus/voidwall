# Steps to Enterprise-Grade PII Detection Library

Here's what's missing for enterprise use.

---

## 1. API Completeness & Flexibility

**Configurable Scanner** — Currently all detectors are hardcoded in `Scanner::new()`. Enterprises need:
- [done] Builder pattern: `Scanner::builder().with_detector(EmailDetector).without(PiiKind::IpAddress).build()`
- Selective PII types: scan only for what's needed (GDPR vs HIPAA vs PCI-DSS have different requirements)
- [done] Blocklist and allowlist of PIIs in library's configuration
- Custom detector registration: plug in domain-specific detectors (e.g., internal employee IDs)

**[done] Redaction API** — `mark_piis()` returns spans, but enterprises need built-in redaction:
- `redact(input, strategy)` with strategies: mask (`***`), hash, replace with type label (`[EMAIL]`), partial mask (`j***@example.com`)
- Consistent, tested redaction avoids every consumer reimplementing it incorrectly

**[rejected] Confidence Scores** — Not all matches are equally certain. Add a confidence field to `PiiMatch` (e.g., a 9-digit passport number without context is low confidence; an email is high confidence). | Rejected because confidence scere poorly matches the way PIIs are detected (with regular expressions)

**[done] Overlapping Match Resolution** — Multiple detectors can return overlapping spans today. Add deduplication/priority logic.

---

## 2. Performance & Scalability

**[done] Lazy/Static Regex Compilation** — `Scanner::new()` recompiles all regexes every time. Use `LazyLock` or `OnceLock` for singleton compiled patterns. This matters when scanners are created frequently.

**[rejected] Streaming / Chunked Processing** — Large documents (logs, database dumps) shouldn't require loading everything into a single `&str`. Add:
- `scan_reader(impl Read)` for streaming input
- Chunked processing with boundary handling (PII spanning chunk boundaries) | streaming slows down vectorscan

**[rejected] Parallelism** — For large inputs, run detectors in parallel across chunks using `rayon`. Gate behind a `parallel` feature flag. | Paralellism is suboptimal in vectorscan

**Allocation Reduction** — `mark_piis()` returns `Vec<PiiMatch>` via `flat_map().collect()`. Consider a callback/visitor pattern or an iterator-based API to avoid intermediate allocations.

**[done] Regex Performance** — Consider `regex::RegexSet` optimizations or switching hot paths to `aho-corasick` for keyword matching in `KeywordContextDetector` (faster than regex for literal prefix matching). | achieved using vectorscan

---

## 3. Correctness & Coverage

**[done] International Phone Numbers** — Currently US-centric (3-3-4 format). Add E.164 format support and country-specific patterns (UK, EU, APAC). This is a major gap for international enterprises.

**[done] Passport Refinement** — The generic 9-digit pattern is too broad. Add country-specific passport formats or require keyword context (like the keyword context detector approach).

**Additional PII Types:**
- [done] Dates of birth (with keyword context)
- [done] Physical addresses
- [done] postal codes
- [done] Names (requires NLP/dictionary approach — consider optional feature flag)
- Medical record numbers (HIPAA)
- [done] Bank account numbers (country-specific)
- [done] Cryptocurrency wallet addresses
- [done] AWS keys, API tokens, secrets (common in log scanning)

Source of potential PIIs to implement support for: https://learn.microsoft.com/en-us/purview/sit-sensitive-information-type-entity-definitions

**[done] Unicode & Encoding** — Test with more Unicode edge cases: RTL text, zero-width characters inserted to evade detection, homoglyph attacks (Cyrillic 'а' vs Latin 'a' in emails).

---

## 4. Error Handling & Observability

**[done] Replace `.unwrap()` with proper error handling** — `Scanner::new()` uses `.unwrap()` on regex compilation. Return `Result<Scanner, PiiError>` so callers can handle initialization failures gracefully. This is a hard requirement for production use.

**[done] Structured Error Types** — Define `PiiError` enum with variants for regex compilation failure, invalid configuration, etc.

**Logging/Tracing** — Add optional `tracing` integration (behind a feature flag) so enterprises can observe:
- Which detectors fired
- How long each detector took
- How many candidates were rejected by validation

**[rejected] Metrics** — Expose detection statistics: matches per type, false-positive rejection rates, processing time per detector. | This will be a responsibility of HTTP Proxy

---

## 5. Safety & Security

**Input Size Limits** — Regex engines can exhibit catastrophic backtracking. Add configurable input size limits and timeouts (the `regex` crate has built-in protections, but defense-in-depth matters).

**Fuzzing** — Add `cargo-fuzz` targets to find panics, hangs, or incorrect spans on adversarial input. This is critical for a security-sensitive library.

**ReDoS Resistance Audit** — Systematically audit all regex patterns for catastrophic backtracking potential. The Rust `regex` crate is resistant by design (no backtracking), but verify no patterns cause excessive state explosion.

**Constant-Time Considerations** — Some validation functions (Luhn, mod-11) process sensitive data. Document whether timing side-channels matter for your threat model.

---

## 6. API Design & Ergonomics

**[rejected] `#[non_exhaustive]` on `PiiKind`** — Adding new PII types is a breaking change today. Mark the enum `#[non_exhaustive]` so new variants can be added in minor versions.
| the library will be used only internally for now

**[done] `Display` / `Serialize` for `PiiKind`** — Implement `Display`, and optionally `serde::Serialize`/`Deserialize` behind a feature flag for JSON/structured logging.

**[done] `Send + Sync`** — Ensure `Scanner` is `Send + Sync` (it likely is, but explicitly test/document it). Required for use in async runtimes and thread pools.

**Lifetime-free API** — The current `&str` API is good. Consider also offering an owned-input variant for async pipelines.

---

## 7. Testing & CI

**Property-Based Testing** — Use `proptest` or `quickcheck` to generate random inputs and verify:
- Spans are always valid UTF-8 boundaries
- `start < end` invariant holds
- `has_piis()` agrees with `!mark_piis().is_empty()`

**Regression Test Corpus** — Maintain a file-based test corpus of real-world PII patterns (anonymized) that runs on every CI build.

**Benchmarks in CI** — Run benchmarks in CI with `criterion`'s comparison mode to catch performance regressions.

**MSRV Policy** — Document and test minimum supported Rust version. Pin it in `Cargo.toml` via `rust-version = "1.85"`.

---

## 8. Packaging & Distribution

**[rejected] Feature Flags** — Gate optional functionality:
- `serde` — serialization support
- `parallel` — rayon-based parallelism
- `tracing` — observability integration
- `redact` — redaction utilities
| Rejected because this is internal library that will be used in HTTP Proxy, so all features that are needed are known upfront.

**Documentation** — Add `#![deny(missing_docs)]` and write rustdoc for all public types. Add a `README.md` with usage examples, and doc-tests that compile-check examples.

**MSRV + CI Matrix** — Test on stable, beta, nightly, and MSRV.

**Changelog** — Maintain a `CHANGELOG.md` for enterprise adopters tracking breaking changes.

---

## Priority Ranking

| Priority | Status | Change | Impact |
|----------|--------|--------|--------|
| **P0** | Done | Error handling (remove `.unwrap()`) | Production safety |
| **P0** | Rejected | `#[non_exhaustive]` on `PiiKind` | Semver compatibility |
| **P0** | Done | Configurable scanner (builder pattern) | Usability |
| **P1** | Done | Redaction API | Core enterprise need |
| **P1** | Done | International phone numbers | Global coverage |
| **P1** |       | Fuzzing targets | Security |
| **P1** | Done | Static regex compilation | Performance |
| **P1** | Done | `Send + Sync` guarantee | Async compatibility |
| **P2** | Rejected | Streaming API | Large input handling |
| **P2** | Rejected | Feature flags + serde | Ecosystem integration |
| **P2** |       | Tracing/metrics | Observability |
| **P2** |       | Property-based testing | Correctness confidence |
| **P3** | Rejected | Parallel processing | Throughput |
| **P3** |       | Additional PII types | Coverage breadth |
| **P3** | Rejected | Confidence scores | Detection quality |

The P0 items are prerequisites for publishing to crates.io as a production library. P1 items address the most common enterprise requirements. P2/P3 items differentiate from competitors and handle scale.
