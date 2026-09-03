# PII Crate Instructions

`voidwall-pii` is a synchronous Rust library for detecting PII in text. It uses Rust edition 2024.
The proxy runs scanners on dedicated OS threads through `ScannerPool`; never call a
scanner directly from a Tokio async task.

The crate supports the keyword languages listed by `Language::all()` in `src/lib.rs`.
Treat that function, `Country::all()`, and `PiiKind::ALL` as the current inventory instead
of copying totals into documentation.

## Build

Run commands from the workspace root:

```bash
cargo check -p voidwall-pii
cargo test -p voidwall-pii
cargo test -p voidwall-pii <name>
cargo clippy -p voidwall-pii --all-targets
```

## Responsibility

The crate detects text PII only. Callers parse formats such as JSON, CSV, multipart data,
PDF, DOCX, and images, then pass UTF-8 text or structured fragments to the scanner.

## Scanner

- `Scanner` is the public entry point. `Scanner::new()` enables all supported countries
  and languages; `Scanner::builder()` configures a subset.
- `has_piis` short-circuits when a detector finds a match.
- `mark_piis` and `mark_piis_structured` return raw `PiiMatch` spans from every detector.
- `Detector` requires `Send + Sync` and defines the three scan methods.

`ScannerBuilder::build` constructs the detector chain in this order:

1. `HyperscanDetector` for structurally identifiable values.
2. `KeywordContextDetector` for values that require nearby language or key context.
3. `UserDetector` when custom definitions are configured.
4. `DictionaryDetector` when `PersonName` is enabled.

The order lets cheap Vectorscan detectors short-circuit `has_piis` before the name
gazetteer. `mark_piis` order is output-neutral because callers resolve overlaps.

## Pattern Engines

Vectorscan performs scalable multi-pattern detection. The `regex` crate is used where
Vectorscan cannot provide the required extraction behavior, especially keyword capture
groups. Do not use Chimera; its PCRE fallback removes the performance advantage and the
current patterns do not require it.

Keyword-context expressions are shared by Vectorscan detection and Rust regex extraction.
Keep patterns valid in both dialects. If a required expression cannot be shared, design
separate detection and extraction expressions explicitly.

## Adding Detectors And PII Kinds

When adding a detector or PII kind:

1. Implement `Detector` and register it in `ScannerBuilder::build` when a new detector is
   required.
2. Add the `PiiKind` variant and update all inventory and mapping methods in `src/lib.rs`.
3. Extend existing parameterized tests before creating standalone test functions.
4. Update `benches/pii_benchmark.rs` with a realistic corpus, a per-kind benchmark entry,
   and a mixed-input sample.
5. If a new kind can produce an equal-span match with another kind, update the appropriate
   priority group in `src/overlap.rs`.

Use the `add-pii` skill for any new language, country, country-specific PII kind, or
keyword-context pattern. It is the authoritative workflow for research, validators,
patterns, tests, benchmarks, and known pitfalls.

## Overlap Resolution

`mark_piis` and `mark_piis_structured` return raw matches. Callers that need one
non-overlapping result set must call `resolve_overlaps`, which applies these rules:

1. Deduplicate matches with the same span and kind.
2. Drop a strictly contained span in favor of the containing span.
3. For equal spans with different kinds, use `PRIORITY_GROUPS` in `src/overlap.rs`.
4. For partial overlap, keep the longer span; ties use priority and then `PiiKind` order.

The same value at different byte offsets remains separate matches. Do not duplicate the
priority inventory in instructions; `src/overlap.rs` is the source of truth.

Never log matched PII text while debugging overlap behavior. Log kind names and spans only.
