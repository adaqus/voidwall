## Context

See `proposal.md` for the motivation and `specs/evaluation/spec.md` for the requirements.

The removed harness (`git show b478e5c^:crates/voidwall/benches/ai4privacy_eval.rs`) is the
reference. It drove `POST /v1/redact` and recovered spans by diffing the redacted text.
`voidwall-pii` gives each match as `PiiMatch { kind, start, end }` in byte offsets, so the
new harness needs no span recovery.

`voidwall-pii` has no map from a language to its countries. `ScannerBuilder` takes
`languages` and `countries` separately, and defaults each to "all" when empty.

The Hyperscan, keyword-context, and user detectors keep their scratch space in
`thread_local!`, so one `Scanner` can serve several threads.

## Goals / Non-Goals

**Goals:**

- Measure the regex engine with the same match set the regex PII guard reports.
- Make it impossible to add a `PiiKind` and forget the label mapping.

**Non-Goals:**

- Measuring the proxy, structured parsing, or ML guards.
- The mini10k dataset, the precision band, the per-kind false-positive breakdown,
  `DUMP_MISSES`, `ENFORCE`, and a skill. The old harness had them; this change does not.
- The checksum validation toggle (`docs/backlog.md` §1.3).

## Decisions

### Link `voidwall-pii`, not the proxy

The target is the engine. In-process calls give exact spans and need no running service.
`remove-configurable-actions` rejected this alternative because the old harness scored the
product. That goal changed, so the rejection no longer applies.

*Alternatives:* spans on `/v1/scan` (new API surface, scores the product); running
`Engine` from the `voidwall` lib (pulls in the proxy crate and its config).

### A new crate, `crates/voidwall-eval`

It keeps `serde_json` and about 1,500 lines of eval code out of the PII library, and it
depends on `voidwall-pii` only. It is a normal workspace member, so
`cargo clippy --workspace --all-targets` and `cargo test --workspace` cover it.

*Alternative:* a feature-gated `[[bin]]` inside `voidwall-pii`, like `build_names_fst`.
Rejected by the user.

### The mapping is code, and the compiler checks it

- `enum Ai4pLabel` lists the 27 labels of the openpii300k vocabulary. Parsing a label
  returns `Label::Known(Ai4pLabel)` or `Label::Unknown(Box<str>)`, so an unknown label is a
  value the report must handle, not a string that falls through a `match`.
- `fn labels_for(kind: PiiKind) -> &'static [Ai4pLabel]` matches on every `PiiKind` with
  no wildcard arm. A new `PiiKind` does not compile until someone decides its labels, or
  decides it has none.
- Typed match is `labels_for(kind).contains(&label)`. A label is supported when some
  `PiiKind` maps to it. A unit test checks that the derived supported set equals the
  spec's table, and that the unsupported set equals the spec's list.
- `PiiKind::Custom` maps to no label. The harness never configures user PII.

*Alternative:* a TOML mapping file. Rejected by the user; it loses the exhaustiveness check.

### Language → countries is a `const` table in the harness

The table in the spec lives in `voidwall-eval`, not in `voidwall-pii`. The scanner has no
use for it, and the proxy configures countries itself.

The harness builds one `Scanner` per language it meets, once. A row picks its scanner by
its `language` field. openpii300k writes the full English name (`"English"`), so the parser
accepts the code and the full name, case-insensitively.

### Offsets meet in characters

Each row converts the resolved byte spans to character offsets once, with one pass over
`char_indices`. Annotations keep their character offsets. The old `resolve_gt` fallbacks
come over unchanged: trust the offsets when the slice equals `value`, then try them as
byte offsets, then search for `value`, then clamp.

### Threads, not async

`std::thread::scope` starts `available_parallelism()` workers. One reader thread streams
lines into a bounded `std::sync::mpsc::sync_channel`. Each worker scores rows and sends a
per-row outcome to the aggregator. There is no Tokio and no HTTP client.

### Runner

`docker/ctl ai4p-eval` ports the old `cmd_eval`, minus the mini10k branch and `SCHEMA`. It
fetches into `.cache/ai4privacy/` and runs
`cargo run --release -p voidwall-eval --bin ai4privacy-eval`. The harness reads the
dataset path and the other options from the environment.

The language variable is `AI4P_LANG`, not `LANG`. `LANG` is the POSIX locale variable,
so a shell already holds `en_US.UTF-8` or `C` in it, and gettext uses `LANGUAGE`. No
operating system sets `AI4P_LANG`, so an unset variable means "all six languages" and
needs no special case.

## Risks / Trade-offs

- [Per-label precision counts one prediction toward several labels, for example
  `GB_ADDRESS` toward STREET and SECADDRESS] → This is the old rule. The micro totals count
  each prediction once.
- [AI4Privacy holds fabricated values that fail real checksums, so a validator-backed kind
  shows low recall] → Accepted. The precision band and the validation toggle stay out of
  scope.
- [Unannotated real PII in a row shows as a false positive] → Accepted; raw precision only.
- [`docker/ctl compile` now also builds the harness] → A few seconds of build time. The
  image copies only the `voidwall` binary.
- [A change in the dataset's label vocabulary] → An unknown label is named in the report,
  never dropped in silence.
