# Measurement notes (tasks 1.2, 9.1 and 9.2)

Setup: the `http_api` sweep of `crates/voidwall/benches/run.sh`, with `configs/http_api.toml`
(the `pii` guard, all countries, 4 scanner threads), k6 `http_api.js`, 50 VUs, 20 s per run,
one binary start per run. Run by hand on ports 18083 and 19090, because the dev stack held
the ports of `run.sh`. Machine: 12 CPUs, the dev stack idle.

## Base commit (a7dc84b), 2026-11-17

| Content type | Size | Corpus | req/s | p99 |
|---|---|---|---|---|
| text | small | pii | 105126 | 0.91 ms |
| text | medium | pii | 21009 | 3.76 ms |
| text | large | pii | 233.6 | 221 ms |
| json | small | pii | 103686 | 0.92 ms |
| json | medium | pii | 20043 | 3.94 ms |
| json | large | pii | 231.9 | 223 ms |
| csv | small | pii | 68213 | 1.33 ms |
| csv | medium | pii | 2192 | 24.1 ms |
| csv | large | pii | 24.9 | 5452 ms |
| text | small | unicode | 97588 | 0.99 ms |
| text | medium | unicode | 5171 | 16.8 ms |
| text | large | unicode | 47.9 | 1451 ms |
| json | small | unicode | 93476 | 1.05 ms |
| json | medium | unicode | 2070 | 49.4 ms |
| json | large | unicode | 43.0 | 1788 ms |

A `cargo check` may have overlapped the last unicode runs. Task 9.2 runs the base binary and
the new binary again, one after the other, and compares those two runs.

## Base and new binary, back to back (task 9.2), 2026-11-17

The same sweep, the base binary and then the new one, with nothing else building.

| Content type | Size | Corpus | Base req/s | New req/s | Change |
|---|---|---|---|---|---|
| text | small | pii | 107310 | 108664 | +1.3% |
| text | medium | pii | 21404 | 21573 | +0.8% |
| text | large | pii | 236.7 | 236.1 | −0.3% |
| json | small | pii | 106614 | 106912 | +0.3% |
| json | medium | pii | 20736 | 20278 | −2.2% |
| json | large | pii | 234.7 | 234.8 | 0.0% |
| csv | small | pii | 70725 | 71433 | +1.0% |
| csv | medium | pii | 2244 | 2242 | −0.1% |
| csv | large | pii | 25.3 | 25.1 | −0.8% |
| text | small | unicode | 101615 | 99488 | −2.1% |
| text | medium | unicode | 5886 | 5745 | −2.4% |
| text | large | unicode | 50.9 | 49.4 | −2.9% |
| json | small | unicode | 100255 | 99307 | −0.9% |
| json | medium | unicode | 5972 | 5808 | −2.8% |
| json | large | unicode | 51.2 | 51.0 | −0.4% |

Every row is within 5% of the base. The fallback of D10 is not needed. The p99 latencies
move by less than 3%. The first base run above was disturbed for the unicode rows (json
medium 2,070 req/s then, 5,972 now).

## Phase 0 corpus (task 9.1), 2026-11-17

Every row of the four Phase 0 corpus files (6,125 cases), raw text only, through
`/v1/scan?direction=request`: once with the base binary and the image config of the base
commit, once with the new binary and the new image config (`invisible_text` added). Model
paths point at the local copies of the image models. No prototype. No errors.

PII values (6 values detected in plain form), expected kind found:

| Transform | Base | New | Prototype normalized (proposal) |
|---|---|---|---|
| unicode_tags | 0/6 | 5/6 | 5 |
| emoji_smuggling | 0/6 | 6/6 | 6 |
| zero_width | 5/6 | 6/6 | 6 |
| zwj | 5/6 | 6/6 | — |
| soft_hyphen | 1/6 | 6/6 | 6 |
| full_width | 4/6 | 6/6 | 6 |

Injections (125 prompts flagged in plain form), blocked by any kind and flagged
`PROMPT_INJECTION`:

| Transform | Blocked base | Blocked new | PI base | PI new |
|---|---|---|---|---|
| unicode_tags | 23% | 100% | 23% | 23% |
| emoji_smuggling | 98% | 100% | 98% | 98% |
| deletion_chars | 59% | 54% | 52% | 52% |
| zero_width | 84% | 85% | 84% | 84% |
| diacritics | 98% | 99% | 98% | 98% |

Every other row, Tier A2 and B included, is the same in both runs. On `deletion_chars`, 7
prompts lose a `PERSON_NAME` that the decoy letters made in the raw text; the
`PROMPT_INJECTION` rate is the same.

Benign prompts (48 deepset prompts not blocked in plain form, × 25 transforms): new blocks
are 33 `unicode_tags` and 2 `emoji_smuggling` cases, all `INVISIBLE_TEXT`, which the task
expects. No other new block. 9 `deletion_chars` cases are no longer blocked (a false
`PERSON_NAME` on the decoy letters is gone). The 92 constructed benign messages: 19 blocked
in both runs.
