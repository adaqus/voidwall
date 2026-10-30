# Hidden Context Guard

The `hidden_context` guard blocks a response that repeats text the operator put in the
model's context and the user must never see: a canary planted in the system prompt, an
internal codename, a line of the prompt itself. It covers the word-for-word case of
OWASP LLM08:2026 Hidden Context Exposure.

See `openspec/specs/hidden-context-guard/spec.md` for the full specification.

## Example

Plant a canary in the system prompt, and list it as a marker:

```toml
[builtin_guards.hidden_context]
markers = ["vw-canary-5c1f9e27a04b", "Project Bluefin"]
```

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | A present section is on unless it sets `enabled = false`. |
| `markers` | `[]` | Text that must never leave in a response. Plain text, not patterns. |

The section has no `surface` key, and the schema rejects one. The image's default
configuration does not declare the guard.

## What it scans

The guard scans the body of a response and nothing else. It never scans a request, a
URL path, a query string, or a header value, also when the route names headers for
scanning. A request that carries a marker — the system message the canary was planted
in — is forwarded. No setting changes this.

| Entry point | Scanned |
|---|---|
| Reverse proxy | The upstream response body, when `reverse_proxy.response.scan` is true. |
| `POST /v1/scan` | The posted body, with `?direction=response` only. See [api-docs.md](api-docs.md). |
| LiteLLM route | The payload with `input_type` `response` only. |

A route that names no guard runs every enabled guard. A route with `guards = [...]`
runs this guard only when the list holds `hidden_context`.

## How a marker matches

- A marker matches anywhere in the text, with no word boundary: `bluefin` matches
  `bluefins`.
- A marker matches without regard to case, by Unicode simple case folding: `Project
  Bluefin` matches `project BLUEFIN`, and `Żubr` matches `ŻUBR`. No setting changes this.
- A marker is plain text: `a.b` matches `a.b` and not `axb`.
- In a JSON, CSV, or TSV body, each value is matched on its own. A marker split across two
  values does not match. Keys are not matched.

## What it reports

A match reports the kind `HIDDEN_CONTEXT`, for every marker. The guard reports at most one
finding per unit, however many markers the unit holds and however many times, so
`/v1/scan` counts a body that holds a marker twice as `matches_count` 1.

A finding blocks the response as any detection does: a generic route answers the fixed
403 with `"kinds": ["HIDDEN_CONTEXT"]`, and an `openai-chat` route answers the fixed 400
with `code` `content_filter`. On a stream in hold-back mode, no byte of a marker reaches
the client, also when the marker arrives split across two events.

A marker never leaves Voidwall. It is not in a log line, a metric label, an error
response, or a validation message. A detection counts in `voidwall_detections_total`
with `guard="hidden_context"`. The guard is not a PII guard, so the `voidwall_pii_*`
families do not count it.

## Validation (at startup)

Each rule stops the start. A message names a marker by its position, such as
`markers[2]`, and never quotes it.

- An enabled section must hold at least one marker. A disabled section may hold none.
- A marker must not be empty.
- The section holds at most 64 markers.
- Two markers must not be equal without regard to case: `Bluefin` and `BLUEFIN` are one
  marker.
- A marker's longest possible match, in bytes, must not be longer than
  `stream_holdback_bytes` (default 512). Case folding can make a match longer than the
  marker: `k` also matches the 3-byte Kelvin sign `K` (U+212A), so 30 `k` characters can match 90
  bytes. The bound is what keeps every byte of a marker in the hold-back until it is
  scanned whole.
- All markers together must compile into one regex. With the default hold-back this
  always holds; a very large `stream_holdback_bytes` and many long markers can pass it.

## Choosing a marker

- **Use a long, random canary.** Matching has no word boundary, so a short common word
  matches inside ordinary answers and blocks them. A canary such as
  `vw-canary-5c1f9e27a04b` never occurs by chance.
- **The guard catches word-for-word leaks only.** A paraphrased, translated, or encoded
  leak — the prompt in other words, in another language, or in Base64 — passes. Follow
  the OWASP advice too: keep secrets out of the model's context, and do not rely on the
  prompt to hide them.
