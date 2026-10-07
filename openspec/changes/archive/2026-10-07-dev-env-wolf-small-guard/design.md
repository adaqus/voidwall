## Context

- `docker/ctl start` runs `compile` and then `docker compose up`. The compose file mounts
  only `docker/voidwall.toml`. The image holds the binaries and license files and no model
  (`.dockerignore` lets in only `target/release/*`, `target/notices/`, `licenses/`, and
  `docker/`).
- `docker/fetch-ort.sh` is the pattern for a pinned, verified download: a pinned URL and
  SHA-256, `curl`, `sha256sum`, a skip when the file already matches, and a temp
  directory so a failed download leaves nothing behind.
- The `text_classifier` loader rejects a model whose output is not `Float32`
  (`model-runtime` spec). The vendor's fp16 ONNX export is therefore not usable.
- Model card values (revision `bcab2eff`): threshold `0.5`, 2,048-token windows, 64-token
  overlap, `id2label` `{0: benign, 1: injection}`, aggregation "normalized Smooth-Max".

## Goals / Non-Goals

**Goals:**

- `docker/ctl start` on a fresh clone brings up a dev stack with a working prompt-injection
  guard, with no token and no manual step.
- The downloaded files are exactly the pinned ones.

**Non-Goals:**

- Any change to the image or to Rust code.
- Any change to window aggregation.

## Decisions

### D1. Use the vendor's fp32 ONNX export

Download `onnx/onnx_fp32/model.onnx` from the model repository.

- Rejected: our own export, hosted by us. The vendor's fp32 export did not exist when the
  research ran; now it does, so there is nothing to host.
- Rejected: `onnx/onnx_fp16/model_fp16.onnx`. The loader rejects a `Float16` output, and
  the research measured fp16 as slower and less accurate than fp32 on CPU.

### D2. Pin the revision and the hashes; no token

Repository `patronus-studio/wolf-defender-prompt-injection-small`, revision
`bcab2eff97bcabd7227849639e2d0d7a61b46c92`. The repository is public and not gated, so the
download needs no Hugging Face token.

| Source path | Local path | Size | SHA-256 |
|---|---|---|---|
| `onnx/onnx_fp32/model.onnx` | `models/wolf-small/model.onnx` | 563,140,601 B | `49455de2407c134dd136c64ca38d67ca17f8426e99fe5c6e286d69af9932993f` |
| `tokenizer.json` | `models/wolf-small/tokenizer.json` | 34,363,287 B | `7e426c3929b44e6ab4c931770b5f22b913280633f5a1c67c81e9ad64decef55c` |
| `LICENSE` | `models/wolf-small/LICENSE` | 11,358 B | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |

Only these files are fetched. The repository's `l2/` directory is GPL-3.0-only or
commercial and is never downloaded. The root `LICENSE` is Apache-2.0.

### D3. Files live in `models/wolf-small/`, gitignored, mounted read-only

`models/` is added to `.gitignore`. The compose file mounts `../models/wolf-small` at
`/opt/voidwall/models/wolf-small` read-only.

### D4. A separate `fetch_models` subcommand, also run by `start`

`docker/ctl fetch_models` runs a fetch script in `docker/`, in the style of
`fetch-ort.sh`. `cmd_start` calls it before `docker compose up`. A file whose hash already
matches is skipped, so a second `start` downloads nothing. A hash mismatch stops with an
error that names the file.

### D5. Guard settings come from the model card

```toml
[guards.prompt_injection]
adapter = "text_classifier"
model_path = "/opt/voidwall/models/wolf-small/model.onnx"
tokenizer_path = "/opt/voidwall/models/wolf-small/tokenizer.json"
max_tokens = 2048
labels = ["PROMPT_INJECTION"]
overlap_tokens = 64

[guards.prompt_injection.thresholds]
PROMPT_INJECTION = 0.5
```

`threads` keeps its default. The surface keeps its default, the body alone.

### D6. Window aggregation stays max

The adapter's unit score stays the highest window score. The card's "normalized
Smooth-Max" is not defined, so it cannot be built correctly yet. Max is never below a
weighted mean of the same scores, so the dev stack errs on the strict side. Details:
`voidwall-internal/research/voidwall-ml/backlog.md`.

## Risks / Trade-offs

- [v2 weights were never parity-checked; the July research tested v1] → Run the parity
  harness on this revision before the guard is enabled. If it fails, stop and ask.
- [Long bodies can block more often than the card reports, because of D6] → Accepted for
  local development.
- [The k6 soak test can get 403s on payloads that look like attacks] → Accepted.
- [The vendor can delete or rewrite the revision] → The pinned hashes make the fetch fail
  with a clear error instead of loading other weights.
- [About 600 MB on the first `start`] → Downloaded once; later runs skip matching files.
- [The dev stack is not ready until the model loads] → `/readyz` answers 503 until then,
  as the `model-runtime` spec states.
