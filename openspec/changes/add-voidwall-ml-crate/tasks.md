## 1. Verified ONNX Runtime archive

- [x] 1.1 Write `docker/fetch-ort.sh` (D2): pinned URL and SHA-256, hash check, `gh attestation verify --owner pykeio`, raw LZMA2 extract to `.ort/1.28.0/`, stamp file, skip when the stamp matches. Verify: a clean run extracts `libonnxruntime.a`; a second run skips the download.
- [x] 1.2 Negative control: run the hash and attestation steps on a random file. Verify: the script exits non-zero and `.ort/` gets no new file.
- [x] 1.3 Add `.cargo/config.toml` `[env]` with `ORT_LIB_PATH` (relative) and `ORT_SKIP_DOWNLOAD=1`; add `.ort/` to `.gitignore`. Verify: with `.ort/` moved away, `cargo check -p voidwall-ml` fails and `~/.cache/ort.pyke.io` stays empty.

## 2. `voidwall-ml` crate

- [x] 2.1 Create `crates/voidwall-ml` (D1), add it to the workspace members, `publish = false` on all workspace crates. `ort = "=2.0.0-rc.13"` with `default-features = false` and the smallest feature set that builds. Verify: `cargo check --workspace` passes; `cargo tree -p voidwall-ml` shows no `ureq`/download dependency.
- [x] 2.2 Add `onnx_runtime_version()` and a unit test asserting `"1.28.0"`. Verify: `cargo test -p voidwall-ml` passes.
- [x] 2.3 Move `config::Adapter` to `voidwall_ml::AdapterKind` with its doc comments, `Deserialize`, and `score_range`; update `config.rs` and its tests. Verify: `cargo test -p voidwall config` passes, including the unknown-adapter diagnostic and threshold-range tests, with no TOML change.

## 3. CPU floor

- [x] 3.1 Add `voidwall_ml::cpu` (D6) with a pure function over a feature predicate, and `#[test_case]` tests: all present → none missing; one and several missing → those names. Verify: `cargo test -p voidwall-ml cpu` passes.
- [x] 3.2 Run the check from the binary's `.preinit_array` (D6), before every static constructor and before argument parsing: one stderr line naming x86-64-v3 and the missing features, exit code 1. Verify: `voidwall --validate docker/voidwall.toml` still exits 0 on the dev machine; `readelf -S` shows a `.preinit_array` section.
- [x] 3.3 Manual check: run the release binary under `qemu-x86_64 -cpu Nehalem`. Verify: it prints the missing features and exits 1 before reading the config.

## 4. License gate and notices

- [x] 4.1 Add `deny.toml` (licenses check only, `[licenses.private] ignore = true`), with an allowlist built from the current graph and each entry reviewed; MIT and Apache-2.0 on it. Verify: `cargo deny check licenses` passes; adding a test entry that removes one used license makes it fail and name the crate.
- [x] 4.2 Add `about.toml` and a template for `cargo about generate` writing to `target/notices/`. Verify: the generated file lists `ort`, `serde`, and `tokio` with their license texts.
- [x] 4.3 Vendor `licenses/onnxruntime/LICENSE` and `ThirdPartyNotices.txt` from tag v1.28.0, `licenses/pyke-ort-artifacts/LICENSE`, and `licenses/EIGEN-SOURCE.txt`. Verify: the ONNX Runtime files match the tag byte for byte (`sha256sum` against the raw GitHub files).

## 5. Build and image

- [x] 5.1 Update `docker/ctl compile`: fetch → `cargo deny check licenses` → `cargo about generate` → `cargo build --release`. Verify: `docker/ctl compile` succeeds from a clean `target/`.
- [x] 5.2 Update `docker/Dockerfile.voidwall` and `.dockerignore` to copy the notices and vendored licenses into `/usr/share/doc/voidwall/`. Verify: `docker run --rm --entrypoint ls <image> -R /usr/share/doc/voidwall` lists every file from the distribution spec.
- [x] 5.3 Verify the image still starts with the shipped config. Verify: `docker/ctl start`, then `curl :9090/readyz` answers 200.

## 6. CI

- [ ] 6.1 Add `.github/workflows/ci.yml` (D5): native deps, fetch with `GH_TOKEN: ${{ github.token }}`, cache keyed by the archive hash, then deny, check, clippy `-D warnings`, test. Verify: the workflow run on a pushed branch is green.

## 7. Docs and final checks

- [x] 7.1 Update `ARCHITECTURE.md` §5 crate table, `openspec/config.yaml` context, `CLAUDE.md` and `AGENTS.md` (three workspace members, run `docker/fetch-ort.sh` once, needed tools), and state the x86-64-v3 floor in the operator docs under `docs/`. Verify: `grep -rn "two members" CLAUDE.md AGENTS.md` finds nothing.
- [x] 7.2 Run `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`. Verify: both pass.
- [x] 7.3 Run `openspec validate add-voidwall-ml-crate --strict`. Verify: it passes.
