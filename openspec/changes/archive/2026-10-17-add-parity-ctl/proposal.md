## Why

The `text_classifier` parity check has five manual steps (`crates/voidwall-ml/parity/README.md`).
The operator builds the model directories, the Python environment, and the reference by
hand. A wrong input gives a false result: a reference built from an older download of
wolf-small differed from the correct one by up to 0.91, although the code was correct.
A check that is hard to run is not run, for example before a merge of a
`transformers` bump in `parity/requirements.txt`.

## What Changes

- Add `docker/ctl parity`. It runs the parity check for wolf-small from start to end,
  with no manual step:
  1. It runs `docker/fetch-models.sh`, which fetches and verifies `model.onnx` and
     `tokenizer.json` at the pinned revision `bcab2eff97bcabd7227849639e2d0d7a61b46c92`.
  2. It fetches `config.json` and `model.safetensors` at the same revision into
     `.cache/parity/`, and verifies each file against a pinned SHA-256.
  3. It makes a Python virtual environment in `.cache/parity/venv` from
     `crates/voidwall-ml/parity/requirements.txt`, with `torch` from the CPU wheel index
     (`https://download.pytorch.org/whl/cpu`). It makes the environment again only when the
     pins change.
  4. It runs `reference.py` and writes a new `reference.json` on every run. It never uses a
     reference from an earlier run.
  5. It runs `cargo test -p voidwall-ml --release -- --ignored parity`.
- The window settings are 2048 tokens with an overlap of 64, the values in
  `docker/voidwall.toml`. `PARITY_MAX_TOKENS` and `PARITY_OVERLAP` override them.
- The command needs `python3` 3.11 or later on the host, and stops with an error when it is
  not there. This is the same check as `docker/ctl piimb-eval`.
- The command runs on the host, not in a container.
- Only wolf-small is in scope. PIGuard and other models keep the manual steps.
- Document it in `DEVELOPMENT.md` (`docker/ctl` table row), in the Run section of
  `crates/voidwall-ml/parity/README.md`, and in the usage comment at the top of
  `docker/ctl`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `model-runtime`: adds requirements for the `docker/ctl parity` runner of the parity check.
  The existing requirement "Scores match the Python reference on the shipped candidates"
  does not change.

## Impact

- **`docker/ctl`:** a new `parity` subcommand. Other subcommands do not change.
- **`docker/fetch-models.sh`:** no change. The runner calls it.
- **`crates/voidwall-ml`:** no change to code. The runner calls the existing ignored test
  `parity::scores_match_the_python_reference` and the existing `parity/reference.py`.
- **New host requirement, for this command only:** `python3` 3.11 or later with the `venv`
  module.
- **Downloads:** about 560 MB for `model.safetensors` and the CPU `torch` wheel, into
  `.cache/parity/`. They are never committed and never go into the image.
- **Docs:** `DEVELOPMENT.md`, `crates/voidwall-ml/parity/README.md`.
- **Unchanged:** the proxy, its API, its configuration, its metrics, the image, CI, and the
  other `docker/ctl` subcommands.
