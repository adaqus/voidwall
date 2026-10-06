## 1. Preconditions and dependencies

- [x] 1.1 Confirm in `ort` rc.13 that `DynValue` (the type behind `with_initializer`'s `Arc`) is `Send + Sync`, and that `PrepackedWeights` and `Session` can cross `std::thread::scope` threads (design Risks). Verify: a scratch compile check passes; if it fails, stop and ask the user.
- [x] 1.2 Add `prost`, `tokenizers` (smallest feature set that loads `tokenizer.json`), and dev dependency `tempfile` to `crates/voidwall-ml/Cargo.toml`. Verify: `cargo check -p voidwall-ml` and `cargo deny check licenses` pass; if a new license is not on the allowlist, stop and ask the user.

## 2. ONNX protobuf types (D5)

- [x] 2.1 Vendor `proto/onnx.proto` from a pinned ONNX tag with its license header, and write `scripts/gen-onnx-proto.sh` that runs `prost-build` and writes `src/onnx_proto.rs`. Verify: running the script twice gives no diff.
- [x] 2.2 Check in `src/onnx_proto.rs` with a "generated, do not edit" header; allow unused-code lints on that module only. Verify: `cargo clippy -p voidwall-ml --all-targets` has no warning.

## 3. Test fixtures (D8)

- [x] 3.1 Write the fixture model builder (test-only) with knobs for every bad case in D8, and the `WordLevel` test tokenizer writer, both into a temp dir. Verify: a test loads the good fixture with plain `ort` `commit_from_file` and runs it, returning shape `[1, 2]`.

## 4. Model file parse (D4)

- [x] 4.1 Implement `model_file.rs`: one read, decode `ModelProto`, build one `Arc<DynValue>` per initializer, reject external data and an undecodable file as unreadable. Verify: unit test — the parsed initializer names equal the fixture's initializer list ("every weight is shared" scenario); a non-ONNX file gives an error naming the model path.
- [x] 4.2 Implement the embedding search: the `Gather` whose index input is `input_ids`, its data initializer's dims[0]. Verify: unit tests — good fixture gives the fixture's row count; the cast-before-`Gather` fixture gives `EmbeddingTableNotFound`.

## 5. Checks (D3, D6)

- [x] 5.1 Add `LoadSettings`, `LoadError` (hand-written `Display`, no input text), trait `Adapter` with `OUTPUT_WIDTH`, and `TextClassifier` (width 2). Verify: `cargo check -p voidwall-ml`.
- [x] 5.2 Tokenizer checks: an unparseable tokenizer file is an error naming the path; highest ID from `get_vocab(true)` must be below the row count. Verify: `#[test_case]` tests — fitting tokenizer passes; oversize tokenizer fails naming both numbers; garbage file fails naming the path.
- [x] 5.3 Tensor contract on session #1: required inputs, no unknown input, `Int64` rank 2, one output, `Float32`, rank 2, width; fixed sequence dimension vs `max_tokens`. Verify: one `#[test_case]` per spec scenario (missing `attention_mask`, `position_ids`, `Int32`, rank 1, two outputs, width 3, `Float16`, fixed 16 vs 16 passes, fixed 16 vs 32 fails, dynamic passes), each asserting the error names what the scenario says.
- [x] 5.4 Smoke input and inference: fixed short text, special tokens on, truncation and padding off; pad to a fixed N with mask 0; `token_type_ids` zeros when present; check shape `[1, width]` and finite values. Verify: tests — `token_type_ids` fixture loads; NaN fixture fails naming the non-finite output; run-time-failure fixture fails naming the smoke inference.

## 6. Load (D2, D4, D6, D7)

- [x] 6.1 Implement `load()`: adapter match (`TextMultilabelClassifier` → `AdapterNotBuilt`), cheap checks first, session #1 + tensor contract, then sessions #2..N committed in parallel with `std::thread::scope`, every session with all initializers, the shared `PrepackedWeights`, 1 intra-op thread, `Level3`, and a smoke inference. Verify: tests — good fixture with N = 3 returns 3 workers; multilabel fails naming the adapter as not built.
- [x] 6.2 Export `AdapterKind`, `LoadSettings`, `Adapter`, `TextClassifier`, `Worker`, `load`, `LoadError` from `lib.rs`; `Worker` is `Send`. Verify: a compile-time `fn assert_send<T: Send>()` test for `Worker`.

## 7. Oniguruma license

- [x] 7.1 Vendor `licenses/oniguruma/COPYING` from the `onig_sys` version in `Cargo.lock` (69.9.3, Oniguruma 6.9.10) and name Oniguruma in the Dockerfile's license comment. Verify: `sha256sum` matches the registry copy; a `FROM scratch` build with the repo's `.dockerignore` exports `/usr/share/doc/voidwall/oniguruma/COPYING` byte for byte.

## 8. Weights outside the parsed graph (D4, B2)

- [x] 8.1 Add `bytes` and `memmap2`; regenerate `src/onnx_proto.rs` with `raw_data` as `bytes::Bytes`. Verify: two script runs give no diff; `cargo deny check licenses` passes.
- [x] 8.2 Rewrite `ModelFile::read`: mmap, zero-copy decode, each initializer copied once into an owned tensor, the stripped graph (data removed and pointed at an empty placeholder for every initializer of 1 KiB or more), map dropped. Verify: unit test — the stripped graph's large initializers hold no data and are marked external; small ones keep theirs.
- [x] 8.3 Stage the stripped graph and the empty placeholder in a `TempDir` under `TMPDIR`, removed when the load ends; commit every session from that file with `with_initializer` for all initializers. Verify: tests — the staged files exist and are removed on drop; an unwritable temp directory fails naming it; the loaded worker's output equals plain `ort` on the unmodified fixture; a stripped tensor left without its override fails the session.
- [x] 8.4 Peak-memory check: an `#[ignore]` test loads a fixture with a 256 MiB embedding into 4 workers in parallel. Verify: kept anonymous growth < 1.2× the weights and the `VmHWM` growth < 2.3× (measured: 1.03× kept, 2.00× peak).

## 9. Docs and final checks

- [x] 9.1 Update `ARCHITECTURE.md` §5 with the crate's load API and the B2 layout. Verify: the text names `LoadSettings`, `Adapter`, `load`, and states that `voidwall` owns the threads.
- [x] 9.2 Run `cargo test --workspace`, `cargo clippy --workspace --all-targets`, and `cargo deny check licenses`. Verify: all pass with no warning.
- [x] 9.3 Run `openspec validate model-load-and-startup-checks --strict`. Verify: it passes.
