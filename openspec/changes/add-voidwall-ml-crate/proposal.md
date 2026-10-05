## Why

Model guards need ONNX Runtime, and ONNX Runtime brings a supply-chain, licensing, and
CPU-floor question that has nothing to do with inference. This change answers those
questions on their own, before S5 adds any model logic, so the review of the archive,
the notices, and the image stays separate from the review of the adapters.

Today the image ships no license notices at all, although the binary links 155
third-party Rust crates whose licenses require them.

## What Changes

- New workspace crate `crates/voidwall-ml`. It depends on `ort` `=2.0.0-rc.13` and on
  `serde`. It has no inference logic.
- `config::Adapter` moves out of `crates/voidwall/src/config.rs` into `voidwall-ml` as
  `AdapterKind`, with its `Deserialize` derive and `score_range`. `voidwall`'s config uses
  it directly. The TOML key `adapter = "text_classifier"` does not change.
- `voidwall-ml` exposes the ONNX Runtime version that is linked. A unit test asserts
  `1.28.0`, which proves the static archive links.
- A fetch script downloads pyke's prebuilt ONNX Runtime 1.28.0 archive, checks its SHA-256
  against the pinned `dist.tsv` value, runs `gh attestation verify --owner pykeio`
  (`GH_TOKEN`), and extracts `libonnxruntime.a`. A mismatch fails the script.
- Every Cargo build links that verified archive: `.cargo/config.toml` sets `ORT_LIB_PATH`
  and `ORT_SKIP_DOWNLOAD=1`. `ort`'s own download path is never used, also not for dev
  builds.
- `docker/ctl compile` runs the fetch script, the license gate, and the notices generator
  before `cargo build --release`. The Dockerfile copies the binary and the notices.
- The repository vendors ONNX Runtime's `LICENSE` and `ThirdPartyNotices.txt` (tag
  v1.28.0) and the Apache-2.0 text of `pykeio/ort-artifacts`.
- `cargo-about` generates one notices file for every Rust crate linked into `voidwall`.
  The notices also point to Eigen's upstream source (MPL-2.0).
- `cargo-deny` (`deny.toml`) fails the build on a crate license that is not allowed. The
  allowlist does not block MIT or Apache-2.0 for Voidwall's own, still undecided, license.
- New GitHub Actions workflow: fetch and verify the archive, then `cargo deny check
  licenses`, `cargo check`, `cargo clippy -D warnings`, and `cargo test --workspace`.
- At startup the binary checks the x86-64-v3 CPU features and refuses to start, naming the
  missing features, on an older CPU. The docs state the CPU floor.

## Capabilities

### New Capabilities

- `model-runtime`: how ONNX Runtime is obtained, verified, and linked, and the minimum CPU
  the binary needs.
- `distribution`: what the image ships besides the binary (license notices) and the license
  gate on dependencies.

### Modified Capabilities

None. The `adapter` key, its accepted values, and its unknown-value diagnostic do not
change. The existing `configuration` scenarios are the regression check for the move.

## Impact

- Code: new `crates/voidwall-ml/`; `crates/voidwall/src/config.rs` (enum moves out);
  `crates/voidwall/src/main.rs` (CPU check); root `Cargo.toml` (workspace member).
- Build: `.cargo/config.toml`, fetch script, `docker/ctl`, `docker/Dockerfile.voidwall`,
  `.dockerignore`, `.gitignore`, `deny.toml`, `about.toml` and template,
  `.github/workflows/`.
- Tools a developer needs: `gh` with `GH_TOKEN`, `xz`, `cargo-about`, `cargo-deny`.
- Image: the binary grows from 23.5 MB to 51.1 MB (ONNX Runtime is linked); license files under
  `/usr/share/doc/voidwall/`.
- Platform: the binary refuses to start on a CPU below x86-64-v3 (Intel Haswell or later,
  any AMD Ryzen), even with no model guard configured.
- Docs: `ARCHITECTURE.md` §5 crate table, `CLAUDE.md`/`AGENTS.md` workspace layout and
  build steps, CPU floor in the operator docs.
