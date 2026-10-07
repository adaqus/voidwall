## 1. Parity on Wolf Defender Small v2

- [x] 1.1 Download the Hugging Face model directory (`config.json`, `model.safetensors`,
  `tokenizer.json`, `tokenizer_config.json`) at revision `bcab2eff…` into a parity
  working directory outside the repository, and the fp32 ONNX and `tokenizer.json` into
  `$VOIDWALL_PARITY_DIR/wolf-small/`. Verify the ONNX and tokenizer hashes from design D2.
- [x] 1.2 Write `reference.json` with `reference.py` at `--max-tokens 2048 --overlap 64`.
- [x] 1.3 Run the ignored parity test against `wolf-small`. Done when every window's token
  IDs match, every unit score is within 1e-4, none crosses 0.5, and the known attack scores
  at least 0.9. If it fails, stop and ask before continuing.

## 2. Fetch script and subcommand

- [x] 2.1 Add `models/` to `.gitignore`. Check: `git check-ignore models/wolf-small/model.onnx`
  succeeds.
- [x] 2.2 Add a fetch script under `docker/` that downloads the three files of design D2 at
  the pinned revision into `models/wolf-small/`, verifies each SHA-256, skips a file that
  already matches, and leaves no partial file on failure. Check: a first run downloads and
  verifies; a second run downloads nothing; a corrupted local file is fetched again; a wrong
  pinned hash fails with an error naming the file.
- [x] 2.3 Add the `fetch_models` subcommand to `docker/ctl` (usage text, dispatch) and call
  it from `cmd_start` before `docker compose up`.

## 3. Dev stack

- [x] 3.1 Mount `../models/wolf-small` at `/opt/voidwall/models/wolf-small` read-only on the
  `voidwall` service in `docker/docker-compose.yml`.
- [x] 3.2 Replace the commented `[guards.injection]` example in `docker/voidwall.toml` with
  the `[guards.prompt_injection]` section of design D5. Check:
  `voidwall --validate` passes on a copy of `docker/voidwall.toml` whose model and
  tokenizer paths point at the files in `models/wolf-small/`.
- [x] 3.3 Run `docker/ctl start`. Check: `/readyz` reaches 200; a benign request through
  `:8082` is forwarded; a known prompt-injection body gets a 403 whose `kinds` is
  `["PROMPT_INJECTION"]`.

## 4. Docs

- [x] 4.1 Add `docker/ctl fetch_models` to the command table in `README.md`, and note that
  `start` runs it and downloads about 600 MB on first run.
