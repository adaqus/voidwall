## Context

See proposal.md (Why). Facts that shape the approach:

- The release binary is built on the host (`docker/ctl compile`). `docker/Dockerfile.voidwall`
  only copies `target/release/voidwall` and `echo-server` into `debian:trixie-slim`.
  `.dockerignore` allows only those two files and `docker/`.
- The repository has no CI.
- `config::Adapter` lives in `crates/voidwall/src/config.rs` with `TextClassifier`,
  `TextMultilabelClassifier`, and `score_range()`. Threshold validation uses `score_range`.
- `voidwall-ml` cannot depend on `voidwall` (`ARCHITECTURE.md` §5). `voidwall-pii` already
  exports serde-derived enums that `voidwall`'s config uses directly; this follows the same
  shape.
- Research: `voidwall-internal/research/voidwall-ml/ort-release-and-linking-research.md`
  (#4, #5) and `crate-api-research.md` (#11). The pinned archive is
  `https://cdn.pyke.io/0/pyke:ort-rs/ms@1.28.0/x86_64-unknown-linux-gnu.tar.lzma2`,
  SHA-256 `e454f710f8a49f53aa5b4ff51e3454ae1835777e431c6c35c5255ce6f205fd68`.

## Goals / Non-Goals

**Goals:**

- One link path for ONNX Runtime: the verified archive, on every machine and in CI.
- The image carries every license notice the binary's contents require.
- An older CPU gets a clear startup error instead of an illegal-instruction crash.

**Non-Goals:**

- No `Adapter` trait, `LoadSettings`, session, or tokenizer. These are S5 and S6.
- No ONNX Runtime call from the `voidwall` binary yet. The library is still linked in:
  `voidwall-ml` pulls in the archive member with `OrtGetApiBase`, and its static
  constructors come with it. Measured: the release binary grows from 23.5 MB to 51.1 MB.
- No choice of Voidwall's own license.
- No container hardening and no multi-stage Docker build.

## Decisions

### D1. Crate layout

```
crates/voidwall-ml/
├── Cargo.toml        ort = "=2.0.0-rc.13" (default-features = false), serde
└── src/
    ├── lib.rs        pub use; onnx_runtime_version()
    ├── adapter.rs    enum AdapterKind + score_range (moved, doc comments kept)
    └── cpu.rs        x86-64-v3 feature check
```

- `ort` is pinned with `=` because an rc has no semver promise. `default-features = false`
  drops `download-binaries` and its HTTP/TLS dependencies, which the verified path never
  uses. The exact feature set is confirmed at apply time against rc.13.
- `onnx_runtime_version()` returns the version string ONNX Runtime reports through its C
  API base (`GetVersionString`). A unit test asserts `"1.28.0"`. A test that calls into
  ONNX Runtime forces the static library into the test binary, which proves the archive
  links. Alternative rejected: build success only — the linker may drop unused objects, so
  it proves nothing.
- `AdapterKind` keeps the same variants, serde names, and `score_range`. `config.rs`
  imports it; the TOML tests for the `adapter` key stay in `config.rs`.

### D2. Fetch and verify on the host

A script `docker/fetch-ort.sh` does, and fails on any error:

```
1. skip if .ort/1.28.0/libonnxruntime.a exists and its stamp records the verified hash
2. curl the pinned URL to a temp file
3. sha256sum == pinned hash          ─┐ exit non-zero, extract nothing
4. gh attestation verify --owner pykeio ─┘ (GH_TOKEN)
5. xz --format=raw --lzma2=dict=64MiB -d | tar -x  → .ort/1.28.0/
6. write the stamp
```

- The URL and hash are constants in the script, copied from `ort-sys` rc.13
  `build/download/dist.tsv`. Bumping `ort` means bumping both.
- `.cargo/config.toml` sets `ORT_LIB_PATH` (relative to the workspace root) and
  `ORT_SKIP_DOWNLOAD=1` under `[env]`. Every `cargo` command therefore uses the verified
  archive, and a build without it fails in `ort-sys`'s build script instead of downloading.
- `.ort/` is in `.gitignore`.
- Alternative rejected: multi-stage Dockerfile that builds inside Docker. It needs a Rust
  and Vectorscan toolchain image and a build secret for `GH_TOKEN`, and today's flow
  builds on the host.

### D3. Notices

| File in `/usr/share/doc/voidwall/` | Source |
|---|---|
| `THIRD-PARTY-RUST-CRATES.html` (name fixed at apply) | `cargo about generate`, from `Cargo.lock`, at build time |
| `onnxruntime/LICENSE`, `onnxruntime/ThirdPartyNotices.txt` | vendored in `licenses/onnxruntime/`, tag v1.28.0 |
| `pyke-ort-artifacts/LICENSE` | vendored in `licenses/pyke-ort-artifacts/` (Apache-2.0) |
| `EIGEN-SOURCE.txt` | vendored in `licenses/`: names Eigen, MPL-2.0, and its upstream source URL |

- Vendored files are committed, so a review sees them and the image build needs no network.
- `cargo-about` needs `about.toml` (accepted licenses, same set as `deny.toml`) and a
  template. The generated file goes to `target/notices/`, which `.dockerignore` allows.
- `docker/ctl compile` order: fetch archive → `cargo deny check licenses` →
  `cargo about generate` → `cargo build --release`.

### D4. License gate

- `deny.toml` runs only the `licenses` check. Its allowlist is the set the current graph
  uses (MIT, Apache-2.0, Unlicense, ISC, Zlib, BSL-1.0, and whatever `cargo deny` reports
  on first run, each one reviewed). MIT and Apache-2.0 stay on the list.
- Workspace crates have no `license` field. They get `publish = false` and `deny.toml`
  sets `[licenses.private] ignore = true`, so the gate checks third-party crates only.

### D5. CI

GitHub Actions workflow `.github/workflows/ci.yml` on push and pull request:

```
checkout → install toolchain + native deps (Vectorscan build) + cargo-deny
→ docker/fetch-ort.sh   (GH_TOKEN = github.token)
→ cargo deny check licenses
→ cargo check --workspace
→ cargo clippy --workspace --all-targets -- -D warnings
→ cargo test --workspace
```

The archive is cached by its hash so CI does not download it on every run; the script
still checks the hash of a cached copy.

### D6. CPU check

- `voidwall_ml::cpu` checks, with `std::is_x86_feature_detected!`, the x86-64-v3 set:
  `avx`, `avx2`, `bmi1`, `bmi2`, `f16c`, `fma`, `lzcnt`, `movbe`, `xsave`, plus the v2 set
  (`sse3`, `ssse3`, `sse4.1`, `sse4.2`, `popcnt`, `cmpxchg16b`).
- The core is a pure function that takes a "has feature" predicate and returns the
  missing names, so a unit test can feed it a CPU that lacks features.
- The check runs from the binary's ELF `.preinit_array`, not from `main`. ONNX Runtime's
  static constructors run AVX code (protobuf's `OnShutdownRun`, `vxorps`) before `main`,
  so on a CPU without AVX a check in `main` never runs: the process dies with SIGILL,
  exit 132, and no log line. `.preinit_array` runs before every constructor of the
  executable. On failure the function prints one line to stderr and exits with code 1.
  It runs before argument parsing, so it covers `--config`, `--validate`, and `--help`.
- The `.preinit_array` entry is a typed `static` of `extern "C" fn()` in
  `crates/voidwall/src/main.rs`, under `#[used]` and `#[unsafe(link_section)]`. The
  function uses only `cpuid`, `eprintln!`, and `process::exit`, since std has not run its
  own setup yet. It must stay in the binary crate: a shared library ignores
  `.preinit_array`, and the linker can drop the static from a library crate without notice.
- Alternative rejected: docs only. A CPU without AVX dies at start with exit 132 and no
  message. A CPU with AVX but no AVX2 (Sandy Bridge, Ivy Bridge) starts normally, and may
  fail later on a model run. Both were checked under qemu.
- The check lives in `voidwall-ml` because the floor comes from ONNX Runtime.
- The pyke archive exists only for x86-64 Linux, so the crate targets x86-64 only. This is
  an architecture limit, not OS-conditional code.

## Risks / Trade-offs

- [The `.preinit_array` check is moved into a library crate and vanishes without notice]
  → a comment on the static says why it must stay in `main.rs`; the manual qemu check
  (task 3.3) shows whether it still runs first.
- [ONNX Runtime may run AVX2/FMA code without a `cpuid` check during inference] → the
  floor refuses such CPUs at start; untested before S5 has a model to run.
- [Every developer now needs `gh`, a GitHub token, and `xz` before `cargo test`] → the
  build error names the fetch script; `CLAUDE.md`/`AGENTS.md` build steps say to run it
  once.
- [`ort` rc API changes] → exact pin; the version test fails if the linked library changes.
- [A license file in `licenses/` drifts from the pinned ONNX Runtime tag] → the files and
  the pinned URL/hash are bumped in one diff; the script header names the tag.
- [The CPU check cannot run on real old hardware in CI] → unit test with a fake predicate;
  one manual check under `qemu-x86_64 -cpu Nehalem` during apply.

## Migration Plan

Developers run `docker/fetch-ort.sh` once (with `GH_TOKEN`) and install `cargo-deny` and
`cargo-about`. Rollback is a revert of the change; no data or config migrates.
