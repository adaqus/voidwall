## Context

See proposal.md (Why). Facts that shape the approach:

- `voidwall-ml` today holds `AdapterKind`, the CPU check, and `onnx_runtime_version()`. It
  depends on `ort` `=2.0.0-rc.13` (`default-features = false`, `std`) and `serde`. It
  cannot depend on `voidwall`.
- `add-voidwall-ml-crate` (S4) created the `model-runtime` and `distribution`
  capabilities. This change adds requirements to both.
- In `ort` rc.13, `Session::run` takes `&mut self`, so one session serves one thread.
  `SessionBuilder` has `with_initializer(name, Arc<DynValue>)`,
  `with_prepacked_weights(&PrepackedWeights)`, `with_intra_threads`, and
  `with_optimization_level`. `PrepackedWeights` is `Clone` and `Send + Sync`; `Session` is
  `Send`.
- Research (all agreed): `voidwall-internal/research/voidwall-ml/session-layout-research.md`
  (#3, B1), `startup-checks-research.md` (#7), `crate-api-research.md` (#11),
  `tokenizer-parity-research.md` (#6), `threads-and-provider-config-research.md` (#8), and
  `implementation-steps.md` (S5 row and the fixed-sequence decision).

## Goals / Non-Goals

**Goals:**

- One public load entry point that returns N ready workers or a precise error.
- One copy of the weights per load, whatever N is.
- Every check from #7 runs before the load returns, so a model that loads also runs.
- A contributor adds an adapter's load side by implementing one trait and adding one enum
  arm.

**Non-Goals:**

- No tokenizing of real input, no windows, no scores, no `run` method. These are S6.
- No worker threads, channels, or guard in `voidwall`; no config field; no change to the
  "parses but does not run" rule. These are S7.
- No cancellation of a run. This is S8.
- No check of class order or label meaning; the ONNX file does not carry them.
- No measurement of parallel load time or load peak memory. The numbers in the research
  stay the reference.

## Decisions

### D1. Module layout

```
crates/voidwall-ml/
├── Cargo.toml          + prost, bytes, memmap2, tokenizers, half, tempfile
├── proto/onnx.proto    vendored from onnx/onnx at a pinned tag (license header kept)
├── scripts/gen-onnx-proto.sh   regenerates src/onnx_proto.rs (needs protoc; dev only)
└── src/
    ├── lib.rs          pub use AdapterKind, LoadSettings, Adapter, Worker, load, LoadError
    ├── adapter.rs      AdapterKind (unchanged) + trait Adapter + TextClassifier
    ├── onnx_proto.rs   generated prost types, checked in, header says "generated"
    ├── model_file.rs   one mapped read: shared tensors, stripped graph, embedding rows
    ├── checks.rs       tensor contract, sequence dimension, tokenizer vs rows, smoke
    └── load.rs         LoadSettings, Worker, load(), LoadError
```

### D2. Public API

```rust
pub struct LoadSettings {
    pub adapter: AdapterKind,
    pub model_path: PathBuf,
    pub tokenizer_path: PathBuf,
    pub max_tokens: usize,
    pub workers: NonZeroUsize,
}

pub fn load(settings: &LoadSettings) -> Result<Vec<Worker>, LoadError>;

/// One loaded session. `Send`, not `Clone`: one worker per OS thread.
pub struct Worker { /* session, input layout */ }
```

- `workers` is `NonZeroUsize`, so a request for 0 workers cannot be written (CLAUDE.md:
  make invalid states unrepresentable). `voidwall` rejects `threads = 0` in its config in
  S7, before it builds `LoadSettings`.
- `Worker` carries what S6's `run` needs later (session, whether `token_type_ids` is
  present, the fixed sequence dimension if any). In this step it has no public method.
- `LoadError` is a crate enum with a hand-written `Display` and `std::error::Error`
  (the workspace does not use `thiserror`). Every variant names the file, input, output, or number that
  failed. No variant carries input text, because the load sees none.
- Alternatives rejected: returning an async pool (agreed in #11 that `voidwall` owns
  threads); plain function arguments (agreed in #11).

### D3. Trait `Adapter`, load side only

```rust
pub trait Adapter {
    /// The last dimension the model's single output must have.
    const OUTPUT_WIDTH: i64;
}
pub struct TextClassifier;
impl Adapter for TextClassifier { const OUTPUT_WIDTH: i64 = 2; }
```

- `load()` matches on `AdapterKind`: `TextClassifier` → generic load with `TextClassifier`;
  `TextMultilabelClassifier` → `LoadError::AdapterNotBuilt`. The match is exhaustive, so a
  new variant fails to compile until it picks an arm.
- The smoke input is shared code, not a trait item: the tokenizer encodes a fixed short
  ASCII text with special tokens, truncation and padding off. With a fixed sequence
  dimension N, the IDs are padded to N with attention mask 0. The pad ID is the
  tokenizer's padding ID if it has one, else 0. S6 owns real padding; the smoke input only
  needs a valid shape.
- Alternative rejected: defining `run` now (user chose load only). S6 adds it to the same
  trait.

### D4. Read the model once; give ONNX Runtime a graph without the weights (B2)

User decision (2026-10-06), replacing the B1 layout of the first apply. Under B1 every
session parsed the full file, so each session being created held its own transient copy of
the weights.

```
.onnx ──mmap──► ModelProto (raw_data borrows the map, no copy)
                   │
                   ├─ each initializer ──► owned tensor (Vec<T>) ──► Arc, shared by all sessions
                   │
                   └─ graph for ONNX Runtime: every initializer of ≥ 1 KiB has its data
                      removed and points at an empty placeholder file
                                │
          TempDir (TMPDIR) ◄────┘  model.onnx + voidwall-shared-weights (0 bytes)
                │
                └─► each session: commit_from_file(model.onnx) + with_initializer(all)
                    TempDir removed when load() returns
```

- The file is memory-mapped (`memmap2`) and decoded with prost, whose `raw_data` is a
  `bytes::Bytes` slice of the map (`Bytes::from_owner`), so the decode copies no weight
  data. Each initializer is copied once into an owned `Vec<T>` and built with
  `Tensor::from_array`: ONNX Runtime takes an override only over memory the caller owns
  ("Buffer containing the initializer must be owned by the user"). The map is dropped
  when the read ends.
- The graph each session parses has every initializer of at least 1 KiB (ONNX's own
  `size_threshold` default) stripped of its data and marked external, pointing at an
  empty placeholder. Every initializer, stripped or not, is supplied with
  `with_initializer`, so ONNX Runtime never reads the placeholder. A stripped tensor
  without its override fails the load (it would read past the empty placeholder), so
  weight sharing for every tensor of 1 KiB or more cannot be lost quietly.
- The graph and the placeholder are staged in a private `tempfile::TempDir` under
  `std::env::temp_dir()` (honours `TMPDIR`), removed when `load()` returns (user
  decision). An unwritable temp directory fails the load with `LoadError::Staging`,
  which names the directory. An operator with a read-only root filesystem mounts a
  tmpfs on `/tmp` or sets `TMPDIR`.
- Tested on 2026-10-06 against ONNX Runtime 1.28.0 (fixture with a 256 MiB embedding,
  4 sessions):

  | Layout | Kept (anonymous) | Startup peak |
  |---|---|---|
  | B1 (`commit_from_memory` of the full file) | ~1× | ~4× |
  | Stripped graph from memory + `with_external_initializer` | ~5×: ONNX Runtime copies an external initializer into each session | ~5× |
  | **Stripped graph from a staged file + `with_initializer`** | **1.03×** | **2.00×** (1× anonymous + 1× mapped file pages, which the kernel can drop) |

  Also found: stripping every initializer fails, because shape inference needs the
  values of small constants (axes, reshape shapes), so those stay inline; a model loaded
  from bytes resolves external paths against the working directory and refuses absolute
  ones; `with_external_initializer_file_in_memory` reads the in-memory file before
  overrides apply.
- The embedding search reads the same decoded graph: the `Gather` node whose index input
  is `input_ids`; its data input names an initializer; dims[0] is the row count. For an
  int8 model the data input is `…_quantized`, still an initializer with dims[0] rows. No
  match → `LoadError::EmbeddingTableNotFound` (user decision).
- External data in the operator's own file is still rejected as unreadable, and so are
  sparse initializers.
- Alternatives rejected: B1 (per-session copy of the weights at load); memfd files instead
  of a temp directory (relies on how ONNX Runtime resolves `/proc/self/fd` paths); a plain
  read plus `into_iter` (about 2× anonymous during the read, user chose the mmap read).

### D5. Generated protobuf types checked in

- `proto/onnx.proto` is vendored at a pinned ONNX tag. `scripts/gen-onnx-proto.sh` runs
  `prost-build` once (developer only, needs `protoc`) and writes `src/onnx_proto.rs`. The
  build depends on `prost` only (user decision). `TensorProto.raw_data` is generated as
  `bytes::Bytes`, so a decode from the map borrows it (D4).
- Only the messages the load reads are needed, but the whole file is generated so a later
  regeneration is a mechanical diff. Unused-code lints are allowed on that module only.
- Alternatives rejected: `prost-build` in `build.rs` (needs `protoc` everywhere);
  rust-protobuf v3 (user chose prost).

### D6. Check order

```
read tokenizer.json ─► read + decode .onnx ─► embedding rows ─► tokenizer max ID < rows
        │                                                              │
        └──────────────────── fail fast, nothing loaded ◄──────────────┘
                                         │ pass
                                         ▼
     commit session #1 ─► tensor contract (inputs, output, width, seq dim)
                                         │ pass
                                         ▼
     commit sessions #2..N in parallel ─► smoke inference on each of N sessions
```

- Cheap checks run before any session exists. The tensor contract is read from session #1
  (`ort` reports names, element types, and shapes with `-1` for a dynamic dimension), so a
  wrong model fails after one session load, not N.
- Sessions #2..N commit in parallel with `std::thread::scope`, one scoped thread per
  session; each builds and smoke-tests its own session and returns it. Session #1's smoke
  inference runs in the same parallel phase.
- The tokenizer's highest ID is the largest ID in `get_vocab(true)` (added tokens
  included). The rule is "highest ID < rows", not "vocab size ≤ rows", because added
  tokens can leave gaps.
- The fixed sequence dimension is the second dimension of `input_ids`. All inputs must
  agree on it; a disagreement fails the smoke inference, so no separate rule is needed.
- A fixed batch dimension other than 1 is not a separate rule either: the smoke inference
  with batch 1 fails on it.

### D7. Session settings

Each session: `with_intra_threads(1)`, `with_optimization_level(Level3)`, CPU provider
only (no provider registered), `with_prepacked_weights(&shared)`. The inter-op thread pool
is not used for a sequential graph and stays at its default. All fixed in this phase (#8).

### D8. Fixture models built in Rust

- A test helper in `voidwall-ml` builds a small `ModelProto` with the generated types:
  `input_ids [batch, seq] Int64` → `Gather(embedding [rows, 4])` → `ReduceMean` over seq →
  `MatMul [4, width]` + `Add` bias → `logits [batch, width] Float32`, with
  `attention_mask` as an input that a `Cast`/`Mul` path consumes. A builder sets each knob
  a bad case needs: drop an input, add an input, change a dtype or rank, add an output,
  change width, Float16 output, fixed seq dimension, `token_type_ids`, cast before `Gather`,
  a NaN-producing graph (e.g. `Log` of a negative constant), and a graph that fails only at
  run time (a `Reshape` to an impossible shape).
- A test tokenizer is built in Rust as a `WordLevel` tokenizer with a few tokens and saved
  as `tokenizer.json` into a temp dir; a variant has an ID above the fixture's rows.
- Files go to a per-test temp directory. No binary file and no Python enter the repo
  (user decision). Dev dependency: `tempfile`, already used by `voidwall`.

## Risks / Trade-offs

- [`DynValue` may not be `Sync`, so an `Arc<DynValue>` cannot cross scoped threads] →
  Confirm at the start of apply. Building the values once per thread is not a fallback,
  because it copies the weights. If `DynValue` is not `Sync`, stop and ask the user before
  choosing another load order.
- [Parallel commit raises the load peak] → Each session's working memory is allocated at
  once. Accepted: the research measured about 3.9 GB peak for 12 Wolf sessions loaded in
  sequence; the image's memory guidance comes with S7.
- [Startup needs a writable temp directory] → The staged graph holds no weights and lives
  only for the load. A read-only root filesystem needs a tmpfs `/tmp` or `TMPDIR`.
- [A parser bug drops an initializer name] → For a stripped tensor (≥ 1 KiB) the load
  fails. For a small inline one, sharing stops quietly, which costs at most a few KiB per
  session; answers stay correct (#7).
- [The file changes while it is mapped] → The read would see torn data or fault. The map
  lives only for the read; the operator mounts models read-only.
- [The embedding search misses a valid model that casts `input_ids`] → The load fails with
  a clear error (user decision). Widening the search is a later change.
- [The tokenizer check does not catch a same-size tokenizer with another pipeline] →
  Covered by the S6 parity harness, not here.
- [`tokenizers` pulls in many crates] → Default features off where the crate allows; the
  license gate and notices cover what remains.

## Migration Plan

None. No caller exists yet, and no operator-visible behavior changes. Rollback is a revert
of the crate's new modules and dependencies.
