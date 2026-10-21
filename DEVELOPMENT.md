# Development

This file covers building, testing, and running Voidwall from source. For what Voidwall
does, see [README.md](README.md). For the rules a pull request must follow, see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Requirements

Only Linux on x86-64 is supported. The CPU must be x86-64-v3 or later (Intel Haswell or
later, any AMD Ryzen); the binary refuses to start below it.

### Build and Test

You need these to run `cargo check`, `cargo test`, and `cargo clippy`.

| Tool | Why |
|---|---|
| Rust, latest stable, with `clippy` | Edition 2024 workspace. CI uses the latest stable toolchain |
| C and C++ compiler (`gcc`/`g++` or `clang`) | `vectorscan-rs-sys`, `onig_sys`, `aws-lc-sys`, `tikv-jemalloc-sys` compile C/C++ code |
| `cmake` | Builds Vectorscan from source |
| Boost headers (`libboost-dev`) | Vectorscan build |
| `patch` | Vectorscan build applies patches |
| `pkg-config`, OpenSSL headers (`libssl-dev`) | `native-tls`, used by test HTTP clients |
| `gh` 2.49 or later, logged in or with `GH_TOKEN` | `docker/fetch-ort.sh` verifies the ONNX Runtime build attestation |
| `curl`, `xz`, `tar`, `sha256sum` | `docker/fetch-ort.sh` downloads, checks, and unpacks ONNX Runtime |

On Ubuntu or Debian:

```bash
sudo apt-get install -y build-essential cmake libboost-dev patch pkg-config libssl-dev \
    curl xz-utils
```

Install `gh` from <https://cli.github.com>, then run `gh auth login`.

Fetch the verified ONNX Runtime archive once, before the first build. Every build links
it, and a build without it fails:

```bash
docker/fetch-ort.sh
cargo test --workspace
```

### Release Build and Docker Image

`docker/ctl compile` builds the release binary, runs the license gate, and writes the
crate notices. `docker/ctl start` also starts the dev stack.

| Tool | Why |
|---|---|
| `cargo-deny` | License gate (`deny.toml`). Also runs in CI |
| `cargo-about` | Generates the crate license notices (`about.toml`) |
| Docker with the Compose plugin | Builds the image and starts the dev stack |

```bash
cargo install --locked cargo-deny
cargo install --locked --features cli cargo-about
```

### Optional, Per Task

| Tool | Needed when |
|---|---|
| [k6](https://grafana.com/docs/k6/latest/set-up/install-k6/) | Load and soak tests (`crates/voidwall/benches/`, `docker/ctl soak`) |
| Python 3 | Generating load-test payloads (`benches/generate_payloads.py`) |
| Python 3 with `crates/voidwall-ml/parity/requirements.txt` | Model parity checks against the Python reference. See `crates/voidwall-ml/parity/README.md` |
| `protoc` | Regenerating `src/onnx_proto.rs` with `crates/voidwall-ml/scripts/gen-onnx-proto.sh`. Normal builds do not need it |
| `qemu-user` (`qemu-x86_64`) | Manual check of the CPU floor: run the binary with `-cpu Nehalem` and see it exit 1 |
| [OpenSpec](https://github.com/Fission-AI/OpenSpec) CLI (Node.js) | Proposing, validating, and archiving changes under `openspec/` |

## `docker/ctl` Commands

| Command | Does |
|---|---|
| `docker/ctl compile` | Fetches ONNX Runtime, runs the license gate, writes the notices, and builds the release binaries |
| `docker/ctl fetch_models` | Downloads the dev stack's model files into `models/` and verifies their SHA-256. Skips files that already match. `models/wolf-small/` holds Wolf Defender Prompt-Injection Detector Small v2 (fp32, about 600 MB) for `[guards.prompt_injection]`. `models/bards-v2/` holds bards.ai's EU PII anonimization multilang v2 (INT8, about 340 MB) for `[guards.pii_ml]`, and a `LICENSE` the script writes, because the model repository has none. About 940 MB in all |
| `docker/ctl start [CONFIG]` | Runs `compile` and `fetch_models`, then starts Voidwall, the echo server, Prometheus, and Grafana. Voidwall reads `CONFIG`, a path from the current directory (default `docker/voidwall.toml`) |
| `docker/ctl stop` | Stops all containers |
| `docker/ctl start_echo_server` | Builds and starts only the echo server, from `tools/echo-server/` |
| `docker/ctl soak` | Runs the k6 soak test against the running stack. Set `DURATION` (default `30m`), `PEAK_VUS` (default `100`), and `CYCLES` (default `1`) |
| `docker/ctl ai4p-eval` | Scores the regex PII engine against AI4Privacy openpii300k and prints recall, precision, F1, and F2. Needs no running stack. Fetches the dataset into `.cache/ai4privacy/` and skips cached files. Set `AI4P_LANG` (`en`, `nl`, `fr`, `de`, `it`, `es`, or the English name; default all six, about 630 MB on the first run), `DATASET` (a local JSONL file or directory; fetches nothing), `MAX_ROWS` (default all), and `SUPPORTED_ONLY=1` (leave out labels Voidwall has no kind for) |
| `docker/ctl piimb-eval` | Scores the regex PII engine on the four English tasks of the PII Masking Benchmark (piimb) with the benchmark's own metric code, and prints character-level F2, F1, precision, and recall per task and their average. Needs `python3` 3.11 or later and no running stack. Fetches the test data and the metric code into `.cache/piimb/<revision>/` and installs pinned Python packages into `.cache/piimb/venv`, skipping what is cached. Set `PIIMB_REVISION` (benchmark revision; default the pinned commit; a branch name is fetched once and not refreshed, so delete `.cache/piimb/<name>/` to refresh it) and `PIIMB_TASK` (`ai4privacy-en`, `gretel`, `nemotron-pii`, or `privy`: one task only, not a full benchmark result) |
| `docker/ctl parity` | Runs the parity checks of wolf-small (`text_classifier`) and bards v2 (`token_classifier`): makes a new Python reference for each with `crates/voidwall-ml/parity/reference.py`, then runs the ignored Rust parity test against both, and the INT8 check of bards v2 against a plain ONNX Runtime session. Exits 0 only when all of them pass. Needs `python3` 3.11 or later and no running stack. Runs `fetch_models`, fetches the fp32 files into `.cache/parity/` and verifies their SHA-256 (wolf-small's PyTorch files, about 560 MB; bards v2's PyTorch weights and fp32 ONNX export, about 2.5 GB), and installs `crates/voidwall-ml/parity/requirements.txt` into `.cache/parity/venv` with CPU `torch`, skipping what is cached. Set `PARITY_MAX_TOKENS` (default `2048` for wolf-small, `512` for bards v2) and `PARITY_OVERLAP` (default `64` and `128`); each overrides both models |
