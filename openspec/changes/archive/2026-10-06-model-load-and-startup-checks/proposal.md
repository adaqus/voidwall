## Why

A model guard needs a loaded model before it can score anything, and a bad model must stop
startup rather than fail on live traffic. This change builds the load path and the startup
checks in `voidwall-ml` on their own, before S6 adds tokenizing, windows, and scores, so the
review of weight sharing and model checks stays separate from the review of inference.

## What Changes

- `voidwall_ml::LoadSettings`, owned by `voidwall-ml`, with the fields this step uses:
  `adapter`, `model_path`, `tokenizer_path`, `max_tokens`, and `workers` (the number of
  sessions to load). `overlap_tokens` and `max_body_size` arrive with S6; the label count
  arrives when a step uses it.
- Trait `Adapter`, which a contributor implements per adapter. In this step it holds only
  the load side: the output width the adapter expects and the input the smoke inference
  feeds. `run` and tokenizing arrive with S6.
- `text_classifier` implements the load side (output width 2). `text_multilabel_classifier`
  is refused by `load()` with an error that names the adapter as not built.
- `load()` loads N sessions that share one copy of the weights (B2): the `.onnx` file is
  memory-mapped and decoded once without copying the weight bytes, every initializer is
  copied once into a tensor all sessions share, and one `PrepackedWeights` container serves
  all N sessions. Each session parses a copy of the graph whose weights of 1 KiB or more
  carry no data, so creating a session does not copy the weights. That graph is staged in
  a private temp directory (`TMPDIR`) during the load, so startup needs a writable temp
  directory. Each session has one intra-op thread,
  the CPU provider, and graph optimization `Level3`. The N sessions load in parallel.
- `load()` rejects a model when any of these checks fails:
  - `input_ids` and `attention_mask` are present; no input other than those and
    `token_type_ids`; every input is `Int64` with rank 2
  - exactly one output, `Float32`, rank 2, last dimension equal to the adapter's width
  - a fixed sequence dimension N is accepted only when `max_tokens = N`
  - the embedding table that `input_ids` feeds through a `Gather` node is found, and every
    token ID the tokenizer can produce is below its row count
  - one smoke inference per session runs and returns shape `[1, width]` with finite values
- `token_type_ids`, when the model has it, is accepted and fed with zeros.
- New dependencies in `voidwall-ml`: `prost` (with Rust types generated once from
  `onnx.proto` and checked in, so no `protoc` is needed at build time), `tokenizers`, and
  `half` with `ort`'s `half` feature (Float16 and BFloat16 weights are shared as owned
  tensors), `memmap2` and `bytes` (the read that does not copy), and `tempfile` (the
  staged graph).
- `tokenizers` uses the `onig` regex engine, which compiles Oniguruma (BSD-2-Clause) into
  the binary. The repository vendors Oniguruma's `COPYING` under `licenses/oniguruma/`, and
  the image ships it with the other license files.
- Tests build tiny ONNX fixture models in Rust with the same protobuf types. No binary
  model files and no Python enter the repository.

Nothing in `voidwall` calls `load()` yet. The guard, its worker threads, and the config
fields that feed `LoadSettings` arrive with S7, and the "parses but does not run" rule stays
until then.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `model-runtime`: adds how a model is loaded (shared weights, N sessions, parallel load)
  and which checks reject a model at load.
- `distribution`: adds Oniguruma's license to what the image ships.

## Impact

- Code: `crates/voidwall-ml/` only (new load, check, and adapter modules; generated ONNX
  protobuf types; the generator script). No change in `crates/voidwall/`.
- Image: `licenses/oniguruma/COPYING`, copied by the existing `COPY licenses/` step.
- Dependencies: `prost`, `tokenizers`, `half`, `memmap2`, `bytes`, `tempfile`, and their transitive crates. The license gate and the
  generated notices cover them.
- Behavior seen by an operator: none in this step, because no guard calls `load()`. From
  S7 on, a model guard's startup needs a writable temp directory.
- Docs: `ARCHITECTURE.md` §5 for the crate's new public API.
