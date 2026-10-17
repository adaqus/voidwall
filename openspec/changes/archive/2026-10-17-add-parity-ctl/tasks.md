## 1. Inputs

- [x] 1.1 Check that `reference.py` runs on a model directory that holds only `config.json`
  and `model.safetensors` at revision `bcab2eff97bcabd7227849639e2d0d7a61b46c92`. Check:
  with `--max-tokens 2048 --overlap 64`, the result has the same token IDs as the current
  wolf-small reference and a score difference of 0.0 on every unit. If it fails, stop and
  report which file `from_pretrained` needs.

## 2. Runner

- [x] 2.1 Add the download-and-verify function and the fetch of `config.json` and
  `model.safetensors` into `.cache/parity/hf/wolf-small/` with the SHA-256 pins from
  design.md. Check: a second run prints that both files are already verified and downloads
  nothing; a file with one changed byte is downloaded again; a wrong pinned hash stops the
  run with a non-zero status, names the file, and leaves no file under its real name.
- [x] 2.2 Add the `python3` 3.11+ check and the venv in `.cache/parity/venv`: `torch` from
  the CPU index first, then `requirements.txt` from PyPI, then the marker. Check:
  `pip freeze` in the venv shows `torch==2.13.0+cpu` and the other pins of
  `requirements.txt`; a second run does not make the venv again; a changed
  `requirements.txt` makes it again; `PATH` without `python3` stops the run with status 2
  and the 3.11 message.
- [x] 2.3 Add the run directory: `fetch-models.sh`, the two symbolic links, the deletion of
  the old `reference.json`, `reference.py` with `PARITY_MAX_TOKENS` (default 2048) and
  `PARITY_OVERLAP` (default 64) through `reference.json.part`, then the ignored Rust test
  with `VOIDWALL_PARITY_DIR=.cache/parity/run`. Check: `docker/ctl parity` exits with
  status 0 and prints `wolf-small: 21 units`; `reference.json` records 2048 and 64;
  `PARITY_MAX_TOKENS=512 PARITY_OVERLAP=128 docker/ctl parity` records 512 and 128;
  `PARITY_OVERLAP=4096` exits with a non-zero status and leaves no `reference.json`.
- [x] 2.4 Add `parity` to the dispatch and to `usage`. Check: `docker/ctl` with no argument
  lists `parity`.

## 3. Documentation

- [x] 3.1 Add `docker/ctl parity` and its two env vars to the usage comment at the top of
  `docker/ctl`.
- [x] 3.2 Add a `docker/ctl parity` row to the `docker/ctl` table in `DEVELOPMENT.md`: what
  it checks, the `python3` 3.11+ requirement, the downloads into `.cache/parity/`, and the
  two env vars.
- [x] 3.3 In the Run section of `crates/voidwall-ml/parity/README.md`, name
  `docker/ctl parity` as the way to check wolf-small, and keep the manual steps for other
  models.

## 4. Verification

- [x] 4.1 Run `shellcheck docker/ctl` if it is installed, `cargo clippy --workspace
  --all-targets`, and `cargo test --workspace`. Check: no new warning, all tests pass.
- [x] 4.2 Delete `.cache/parity/` and run `docker/ctl parity` from a clean state. Check:
  exit status 0.
- [x] 4.3 Review the diff against `specs/model-runtime/spec.md` with the `code-review`
  skill.
