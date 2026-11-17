# Measurement notes (tasks 6.1 and 6.2)

## Task 6.1: throughput, 2026-11-17

Setup: the `http_api` bench (`crates/voidwall/benches/k6/http_api.js`), 50 VUs, 20 s per run,
one binary start per config, run by hand on ports 18083 and 19090 as in Phase 1a. The base
binary is the Phase 1a commit (439ff86); the new binary is this change. Both are
`cargo build --release` on the same machine (12 CPUs), the base binary first and then the
new one, with nothing else building.

- Config A: `benches/configs/http_api.toml` (the `pii` guard, all countries, 4 scanner
  threads). Only the scan view is built.
- Config B: config A and `[builtin_guards.invisible_text]`. The decoded view is built too.

New payloads (`generate_payloads.py`, written after the old ones, which stay byte-identical):

- `encoded_*`: clean words, every eighth token a base64 or hex run of 3 to 6 clean words.
  Every run is kept.
- `longwords_*`: camel-case identifiers of 15 or more letters and random runs of 20 to 40
  letters and digits. Almost every token is a candidate run that is not kept: the most work
  the run search does on plain text.

The first sweep missed the 5% limit on `longwords` (−5.2% in config A, −6.3% in config B).
Two changes followed, neither of which changes a decision: the first 3 decoded bytes of a
run are checked before the rest is decoded (`may_keep`, with a unit test over 200,000
random runs that compares it with the full decoding), and the run search reads byte classes
only for a run of 15 or more characters. The table is the final sweep with the final binary.

| Config | Type | Size | Corpus | Base req/s | New req/s | Change | Base p99 | New p99 |
|---|---|---|---|---|---|---|---|---|
| A | text | small | pii | 108095.1 | 107876.1 | -0.2% | 1.47 ms | 1.46 ms |
| A | text | medium | pii | 21389.9 | 21044.5 | -1.6% | 4.92 ms | 5.01 ms |
| A | text | large | pii | 235.2 | 230.8 | -1.9% | 220.37 ms | 226.42 ms |
| A | text | small | unicode | 100270.1 | 99803.6 | -0.5% | 1.53 ms | 1.54 ms |
| A | text | medium | unicode | 5762.6 | 5643.3 | -2.1% | 13.7 ms | 13.98 ms |
| A | text | large | unicode | 50.2 | 50.4 | +0.4% | 1033.29 ms | 1024.93 ms |
| A | text | small | encoded | 112110.5 | 109995.6 | -1.9% | 1.38 ms | 1.39 ms |
| A | text | medium | encoded | 23541.4 | 25953.1 | +10.2% | 4.49 ms | 4.84 ms |
| A | text | large | encoded | 244.0 | 292.2 | +19.8% | 212.12 ms | 177.86 ms |
| A | text | small | longwords | 110440.5 | 108961.3 | -1.3% | 1.4 ms | 1.43 ms |
| A | text | medium | longwords | 23976.9 | 23332.0 | -2.7% | 4.4 ms | 5.18 ms |
| A | text | large | longwords | 259.6 | 254.7 | -1.9% | 198.41 ms | 203.05 ms |
| A | json | small | pii | 106474.5 | 105869.3 | -0.6% | 1.45 ms | 1.45 ms |
| A | json | medium | pii | 20314.3 | 20042.6 | -1.3% | 5.18 ms | 5.26 ms |
| A | json | large | pii | 233.9 | 230.6 | -1.4% | 220.85 ms | 224.69 ms |
| A | json | small | unicode | 99384.2 | 99266.9 | -0.1% | 1.52 ms | 1.52 ms |
| A | json | medium | unicode | 5803.0 | 5689.5 | -2.0% | 13.6 ms | 13.87 ms |
| A | json | large | unicode | 50.8 | 51.0 | +0.4% | 1020.53 ms | 1012.72 ms |
| A | json | small | encoded | 109296.8 | 108152.0 | -1.0% | 1.43 ms | 1.4 ms |
| A | json | medium | encoded | 22437.4 | 24774.2 | +10.4% | 4.7 ms | 5.02 ms |
| A | json | large | encoded | 241.8 | 287.8 | +19.0% | 213.67 ms | 180.78 ms |
| A | json | small | longwords | 108283.1 | 107438.1 | -0.8% | 1.42 ms | 1.44 ms |
| A | json | medium | longwords | 23257.3 | 22800.2 | -2.0% | 4.59 ms | 5.49 ms |
| A | json | large | longwords | 257.7 | 252.0 | -2.2% | 199.7 ms | 205.18 ms |
| A | csv | small | pii | 71225.1 | 71662.9 | +0.6% | 1.85 ms | 1.84 ms |
| A | csv | medium | pii | 2212.9 | 2237.7 | +1.1% | 35.27 ms | 34.83 ms |
| A | csv | large | pii | 25.0 | 25.0 | +0.0% | 5534.92 ms | 5521.1 ms |
| B | text | medium | encoded | 23270.1 | 24776.8 | +6.5% | 4.55 ms | 5.27 ms |
| B | text | large | encoded | 242.5 | 279.6 | +15.3% | 212.52 ms | 187.64 ms |
| B | text | medium | longwords | 23840.8 | 22811.7 | -4.3% | 4.45 ms | 5.49 ms |
| B | text | large | longwords | 259.8 | 250.3 | -3.7% | 198.29 ms | 207.5 ms |
| B | json | medium | encoded | 22356.1 | 24006.8 | +7.4% | 4.71 ms | 5.49 ms |
| B | json | large | encoded | 240.4 | 276.0 | +14.8% | 215.52 ms | 192.07 ms |
| B | json | medium | longwords | 23151.2 | 22349.0 | -3.5% | 4.62 ms | 5.59 ms |
| B | json | large | longwords | 257.3 | 247.9 | -3.7% | 200.22 ms | 209.65 ms |

Every row is within 5% of the base; the worst is −4.3% (long words, both views). The
fallback of D10 (`spawn_blocking`) is not needed. The `encoded` corpus is faster: the
scanner reads the decoded text, which is shorter than the runs. The p99 of a medium body
of long words rises by about 1 ms (+18% to +23%); the p99 of large bodies moves by less
than 5%. Run-to-run noise on one row is about ±3% (`pii` text medium was −2.1%, −5.0% and
−1.6% in three sweeps).

## Task 6.2: the Phase 0 corpus, 2026-11-17

Cases: every row of `attack_pii.jsonl` (105), the rows of `attack_injection.jsonl` with
the transforms `plain`, the seven base64 transforms and `hex_wrapped` (1,548),
`benign.jsonl` (92) and every row of `benign_transformed.jsonl` (1,456): 3,201 rows, each
through `/v1/scan?direction=request` with the image config (guards `pii`,
`invisible_text`, `prompt_injection`, `pii_ml`; model paths to the local copies of the
image models).

- *Base*: the base binary, raw text.
- *New*: the new binary, raw text. The binary decodes on its own.
- *Prototype 2b*: the base binary, on the text after the Phase 0 prototype limited to the
  rules of 2b: its Phase 1 step without homoglyph folding, one layer, no start offsets, no
  glued-prefix trims, no short-run chains, no `%xx` or entities, the `=` and JWT rules of
  D3, the keep rule of D5 (Latin and Common approximated with `unicodedata`: a `LATIN`
  name, or category P, S or Z), and no space around a decoded text. Harness: `proto2b.py`,
  `run62.py` and `report62.py` in the job's temporary folder, not kept in the repository.

No row had an error.

### PII values (6 detected in plain form; expected kind found)

| Transform | Base | New | Prototype 2b |
|---|---|---|---|
| b64 | 0/6 | 6/6 | 6/6 |
| b64_glued | 0/6 | 0/6 | 0/6 |
| b64url_md_image | 0/6 | 5/6 | 5/6 |
| b64_nested | 0/6 | 0/6 | 0/6 |
| hex | 0/6 | 6/6 | 6/6 |

Every other transform is the same in the three columns. `b64_glued` and `b64_nested` are
part 2c. In `b64url_md_image` one value misses in both, as in Phase 0 (PESEL in a URL,
which only `pii_ml` reports in this config).

### Injections (125 prompts flagged `PROMPT_INJECTION` in plain form)

| Transform | PI base | PI new | PI prototype 2b | Blocked base | Blocked new | Blocked prototype 2b |
|---|---|---|---|---|---|---|
| plain | 100% | 100% | 100% | 100% | 100% | 100% |
| b64_whole | 74% | 99% | 99% | 99% | 99% | 99% |
| b64_wrapped | 100% | 100% | 100% | 100% | 100% | 100% |
| b64_embedded | 82% | 98% | 98% | 99% | 98% | 98% |
| b64_glued | 99% | 99% | 99% | 99% | 99% | 99% |
| b64url_in_url | 99% | 100% | 100% | 99% | 100% | 100% |
| b64_nested | 82% | 98% | 98% | 100% | 100% | 100% |
| b64_per_word | 100% | 100% | 100% | 100% | 100% | 100% |
| hex_wrapped | 100% | 100% | 100% | 100% | 100% | 100% |

`b64_nested` rises with one layer: after the first decoding the model reads the inner
base64 next to its wrapper sentence, and flags it.

### The check

- Encoded attack cases that the prototype flags (expected kind, or `PROMPT_INJECTION`)
  and the proxy does not: **0**.
- Injection cases that the proxy flags and the prototype does not: 0. The proxy and the
  limited prototype give the same result on every row, so there is no difference to
  explain.

### Benign rows (1,548)

- **New blocks: 2.** Both are the deepset prompt "How many cigarettes did Helmut Schmidt
  smoke in one day?" in base64, alone (`b64_whole`) and inside a message
  (`b64_embedded`). The plain prompt is blocked as `PERSON_NAME` by `pii` and `pii_ml`,
  before and after this change; the decoded prompt now gets the same verdict. Decided
  correct with the user on 2026-11-17.
- **Blocks gone: 228.** All are base64 or hex rows that were blocked as `AUTH_SECRET`
  (`pii_ml` on the raw run) or `PROMPT_INJECTION` (the model reacting to the encoding),
  and whose decoded text is clean; plus four constructed messages in `benign.jsonl`.
- **Kinds changed on a row that stays blocked: 91.** `AUTH_SECRET` and `PROMPT_INJECTION`
  on the raw run give way to the kinds of the decoded text. Of the 40 benign rows that
  newly carry `PERSON_NAME`, all 40 carry it in plain form too.
