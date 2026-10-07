## Why

The dev stack that `docker/ctl start` runs has no model guard: the `[guards.injection]`
example in `docker/voidwall.toml` is commented out, and nothing fetches a model. Model
guards (S4 to S8) are built, but no one can see one work end to end without setting it up
by hand. Wolf Defender Prompt-Injection Detector Small v2 is the chosen model for local
development.

## What Changes

- New `docker/ctl fetch_models` subcommand. It downloads Wolf Defender Small v2 from
  Hugging Face (`patronus-studio/wolf-defender-prompt-injection-small`, revision
  `bcab2eff97bcabd7227849639e2d0d7a61b46c92`) into `models/wolf-small/`: the fp32 ONNX
  model, `tokenizer.json`, and `LICENSE`. It needs no Hugging Face token. Each file is
  checked against a pinned SHA-256, and a file that already matches is not downloaded
  again.
- `docker/ctl start` runs `fetch_models` before it starts the containers.
- `models/` is gitignored.
- `docker/docker-compose.yml` mounts `models/wolf-small/` read-only into the `voidwall`
  container.
- `docker/voidwall.toml` declares `[guards.prompt_injection]`: adapter `text_classifier`,
  label `PROMPT_INJECTION`, threshold `0.5`, `max_tokens = 2048`, `overlap_tokens = 64`.
  The threshold, window, and overlap are the values on the model card.
- The parity harness runs on Wolf Defender Small v2 at this revision.

Out of scope:

- The Docker image. It does not change, and no model ships in it. Distribution and the
  choice of a shipped model are postponed.
- Smooth-Max window aggregation. The adapter keeps "the unit score is the highest window
  score". The open question is recorded in
  `voidwall-internal/research/voidwall-ml/backlog.md`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

None. The change touches only the dev tooling (`docker/ctl`, the dev compose file, and the
dev config). No Voidwall behavior changes, so the change sets `skip_specs: true`.

## Impact

- `docker/ctl`, a new fetch script under `docker/`, `docker/docker-compose.yml`,
  `docker/voidwall.toml`, `.gitignore`, `README.md` (the `docker/ctl` command table).
- `docker/ctl start` downloads about 600 MB on first run.
- The dev stack answers `/readyz` with 503 until the model has loaded.
- The dev stack now blocks request bodies that the model scores at 0.5 or above. The k6
  soak test can get 403s on payloads that look like attacks; this is accepted.
- No Rust code changes.
