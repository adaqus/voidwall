## Why

S5 loads a model into N checked workers, but a worker cannot score text yet. This change
adds the run side of `text_classifier`: tokenizing, overlapping windows, and one score per
unit. It keeps the review of inference separate from S7, which wires the workers into a
guard. A parity harness proves that the Rust path gives the same scores as a Python
reference on real models before any guard uses them.

## What Changes

- `LoadSettings` gets two fields:
  - `max_body_size`: the window limit is derived from it.
  - `overlap_tokens: Option<usize>`: `None` means the default `min(128, max_tokens / 2)`,
    which `voidwall-ml` applies. `load()` rejects a value above `max_tokens / 2`. The bound
    check is public, so S7's config validation can use the same rule.
- A `Worker` gets a public run method that takes one unit's text and returns its score in
  `0.0..=1.0`, or an error.
- Tokenizing uses Rust `tokenizers` with the model's `tokenizer.json`, truncation and
  padding off (#6).
- Windows (#2):
  - The window is `max_tokens` minus the special tokens the tokenizer adds.
  - A unit longer than one window is split into overlapping windows of token IDs, with
    stride = window − overlap. Each window gets the special tokens.
  - A unit that fits in one window runs exactly one inference. An empty unit runs one
    window that holds only the special tokens.
  - When the model has a fixed sequence dimension N, each window is padded to N with the
    tokenizer's pad ID under attention mask 0.
- Score (#1): each window's 2 logits give `softmax[1]`. The unit score is the maximum over
  its windows.
- Window limit (#2): `ceil(max_body_size / stride)`. A unit that needs more windows fails
  with a window-limit error before any inference runs. S7 maps it to 413 under `on_error`.
- An inference failure, a wrong output shape, or a NaN or infinite logit is an error,
  never a score. No run error carries input text.
- `trait Adapter` gets its run side: the per-window score from the logits.
  `TextClassifier` implements it as `softmax[1]`. Windows and the maximum are shared code.
- Parity harness:
  - A Python script in `crates/voidwall-ml/parity/` tokenizes with Python `tokenizers` and
    runs the PyTorch model on those IDs. It writes a reference file with the token IDs and
    scores of a fixed text set that is checked in.
  - A Rust `#[ignore]` test reads the model directory and the reference file through an
    environment variable. It needs identical token IDs, a score delta of at most 1e-4, and
    no flip at 0.5.
  - A known attack prompt must score at least 0.9 on Wolf and on PIGuard.
  - No model file enters the repository.
- S5 load fix, found by the parity run: a weight that feeds only constant nodes stays in
  the graph each session parses, because ONNX Runtime's constant folding reads it from
  there and not from the shared copy. Without this PIGuard does not load.

Nothing in `voidwall` calls the run method yet. The guard, its threads, the
`overlap_tokens` config field, and the 413 mapping arrive with S7.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `model-runtime`: adds how a `text_classifier` worker scores a unit (tokenizing, windows,
  padding, score, window limit, invalid output), the overlap bound at load, and parity with
  the Python reference. Amends the weight-sharing requirement: weights that feed constant
  nodes keep their data in the graph.

## Impact

- Code: `crates/voidwall-ml/` only. `LoadSettings` gets new fields, `Worker` gets a run
  method, and new modules hold the windows and the run error. No change in
  `crates/voidwall/`.
- New repository files: `crates/voidwall-ml/parity/` (Python reference script, its pinned
  requirements, the text set, and a README). They are not part of the build or the image.
- Dependencies: one Rust dev-dependency, `serde_json` (already in the workspace lock), for
  the parity test to read its reference. The parity script needs Python `tokenizers`, `torch`, and
  `transformers` (model forward pass only) on the machine that makes the references.
- Behavior seen by an operator: none in this step.
- Docs: `ARCHITECTURE.md` §5 (the crate now scores).
