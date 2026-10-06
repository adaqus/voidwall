## 1. Preconditions

- [x] 1.1 Confirm that `tokenizers::Tokenizer` is `Send + Sync`, so one `Arc<Tokenizer>` can be shared by all workers (design Risks). Verify: a compile-time assertion in a test passes; if it fails, stop and ask the user before cloning per worker.
- [x] 1.2 Confirm how to cut a chunk from an `Encoding` without special tokens and pass it to `Tokenizer::post_process` in `tokenizers` 0.22.2 (D3). Verify: a scratch test on the `[CLS] $A [SEP]` fixture tokenizer gives `[CLS] ids[a..b] [SEP]` for a chunk.

## 2. Fixtures (D6)

- [x] 2.1 Add the fixture tokenizer variants: a `TemplateProcessing` post-processor (`[CLS] $A [SEP]`), and a file that sets truncation and padding. Verify: unit test — `added_tokens(false)` is 2 for the first variant and 0 for the plain one.
- [x] 2.2 Add the fixture model knob for a trigger token whose embedding row pushes logit 1 high. Verify: unit test — with plain `ort`, a sequence holding the trigger scores above 0.9 and one without it scores below 0.5.

## 3. Load settings and the window rule (D1, D2)

- [x] 3.1 Add `overlap_tokens: Option<usize>` and `max_body_size: NonZeroUsize` to `LoadSettings`; add public `default_overlap` and `check_overlap`, and `LoadError::OverlapTooLarge` and `LoadError::WindowTooShort`. Verify: `#[test_case]` tests for the default overlap (512 → 128, 64 → 32), the bound (16/8 passes, 16/9 fails naming 9 and 8), and a window not longer than the overlap failing at load.
- [x] 3.2 Implement the private `Windowing { window, stride, limit }`, built once in `load()` from the tokenizer's special-token count, and its `spans(n)`. Verify: `#[test_case]` tests for `n = 0`, `n = window`, `n = window + 1`, and a many-window `n`: spans cover every token, each start is `stride` after the one before it except the last, the last ends at `n`; the limit met passes and the limit exceeded gives `WindowLimit` naming both numbers.

## 4. Adapter run side (D4)

- [x] 4.1 Add `fn window_score(logits: &[f32]) -> f32` to `trait Adapter`; implement `softmax[1]` as `sigmoid(l1 − l0)` for `TextClassifier`. Verify: unit tests — equal logits give 0.5; a large difference gives 0.0 or 1.0 and never NaN.

## 5. Worker run (D1, D3)

- [x] 5.1 Add `RunError` with a `Display` that carries no input text, and keep the tokenizer as `Arc<Tokenizer>`, the pad ID, the `Windowing`, and the window-score function in `Worker`. Verify: `cargo clippy -p voidwall-ml --all-targets` has no warning; the `Worker` is still `Send` (existing test).
- [x] 5.2 Implement one per-window inference function (feed `input_ids`, `attention_mask`, zero `token_type_ids` when present; pad to `fixed_seq` with the pad ID under mask 0; check shape `[1, width]` and finite logits) and make S5's smoke inference call it. Verify: the existing load tests still pass; a new test shows a fixed-length model gets 16 positions with 11 padded at mask 0, and a dynamic model gets 5.
- [x] 5.3 Implement `Worker::score`: encode without special tokens, `spans(n)?` before any inference, post-process each chunk, run, take the maximum. Verify: unit tests — a short unit runs one inference; an empty unit runs one inference on the special tokens; truncation in the tokenizer file does not apply (a unit longer than its truncation length still reaches the trigger); the trigger in one of several windows gives the unit score of that window; NaN bias → `NonFinite`; run-time failure → `Inference`; `WindowLimit` returns before any inference runs.
- [x] 5.4 Check that no `RunError` text holds the unit's text. Verify: a test runs the error cases on a unit with a marker string and asserts that no `Display` output contains it.

## 6. Parity harness (D5)

- [x] 6.1 Write `crates/voidwall-ml/parity/`: `reference.py` (Python `tokenizers` + PyTorch forward pass, its own window code), `requirements.txt` with pinned versions, `texts.jsonl` (benign, the known attack, empty, non-ASCII, 2 to 5 window units with an attack across a window edge; no PII values), and `README.md`. Verify: `python -I reference.py` writes a `reference.json` for Wolf fp32 and for PIGuard fp32 from the local models.
- [x] 6.2 Write the `#[ignore]` parity test that reads `VOIDWALL_PARITY_DIR` and fails when it is unset. Verify: without the variable the `--ignored` run fails with a message naming it.
- [x] 6.3 Keep inline, in the graph each session parses, every weight that feeds a constant-only node, transitively (D7). Verify: a fixture with a 1 KiB weight that feeds only a `ReduceSum` fails to load before the fix and loads after it, with the same logits as the unmodified model; `large_initializers_leave_the_parsed_graph` still passes for the default fixture.
- [x] 6.4 Run the parity test on Wolf fp32 and PIGuard fp32. Verify: window token IDs equal, every unit score within 1e-4, no flip at 0.5, the known attack ≥ 0.9; record the max score delta of each model in this task. If a check fails, stop and report the numbers to the user. Result (2026-10-06, `max_tokens` 512, overlap 128, 21 units, transformers 5.9.0 reference): Wolf fp32 max delta 3.9e-7, known attack 0.949; PIGuard fp32 max delta 5.3e-7, known attack 0.99993; token IDs equal and no flip for both.

## 7. Docs and final checks

- [x] 7.1 Update `ARCHITECTURE.md` §5: the crate now scores (window rule, `Worker::score`, `RunError`), and the crates table loses "no scoring yet". Verify: the text matches D1 to D4.
- [x] 7.2 Run the workspace gates. Verify: `cargo test --workspace`, `cargo clippy --workspace --all-targets`, `cargo deny check licenses`, and `openspec validate text-classifier-adapter --strict` pass.
- [x] 7.3 Review the diff against the spec delta with the `code-review` skill. Verify: every spec scenario maps to a passing test, and no finding is open.
