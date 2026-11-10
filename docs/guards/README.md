# Guards

A guard is one detection concern, such as personal data or prompt injection. It reads
the parts of a message that it is given, and it reports findings. A finding has a kind,
such as `EMAIL` or `PROMPT_INJECTION`. A guard never blocks or changes a message itself.

A finding blocks the message. There is no other action: Voidwall does not redact,
rewrite, or tag a message, and it has no "warn only" mode. For the answer that a block
gives, see [api-reference.md](../api-reference.md#a-detection).

## Kinds of guards

| Guard | Declared in | Finds | Page |
|---|---|---|---|
| `pii` | `[builtin_guards.pii]` | Personal data and secrets, with regular expressions, keywords, and checks | [pii-regex.md](pii-regex.md) |
| `hidden_context` | `[builtin_guards.hidden_context]` | Text from the model's context, such as a canary, in a response | [hidden-context.md](hidden-context.md) |
| Model guard | `[guards.<name>]` | What its ONNX model finds, for example prompt injection or names | [model-guards.md](model-guards.md) |

A built-in guard has a fixed name. A model guard has the name that you give its section.
You can declare many model guards. Each loads its own model.

To add a guard of your own, see [custom-guard.md](custom-guard.md).

## The guards of the image

The config of the image declares three guards:

| Name | Type | Finds |
|---|---|---|
| `pii` | Built-in | Personal data and secrets of all countries and languages |
| `prompt_injection` | Model guard, `text_classifier` | Prompt injection, with the Wolf Defender Prompt-Injection Detector Small v2 model |
| `pii_ml` | Model guard, `token_classifier` | Personal data with no fixed shape, such as names and postal addresses, with the bards.ai EU PII anonimization multilang v2 model |

The `hidden_context` guard is built in, but the image does not declare it. To see the
config of the image, run `docker run --rm ghcr.io/adaqus/voidwall --print-config`.

## What a guard reads

Voidwall cuts a message into units: the body, the URL path, the query string, and each
header value that the route names. A guard gets only the units its `surface` admits.

| Guard | Default surface | Directions |
|---|---|---|
| `pii` | Body, URL path, query string, header values | Requests and responses |
| `hidden_context` | Response body only. It has no `surface` key. | Responses only |
| Model guard | Body only, because each unit costs one model run | Requests and responses |

Some more rules:

- A header value is a unit only when the route lists the header in `headers`. By
  default a route lists none.
- A body is read only when its content type is in `content_types`. A route with
  `format = "openai-chat"` reads each message, tool, and choice of the body as its own
  unit.
- `reverse_proxy.request.scan` and `reverse_proxy.response.scan` turn off a whole
  direction.
- A route runs every enabled guard, unless its `guards` key lists the guards to run. An
  empty list runs none.
- The HTTP API runs every enabled guard. `/v1/scan` takes the direction from its
  `direction` parameter, and the LiteLLM route from `input_type`.

## When a guard fails

A guard can fail: a model run can fail, or a unit can be too long for a model guard. A
message that Voidwall cannot inspect follows `on_error`. Under `fail_close`, the default,
it is blocked with an error status. Under `fail_open`, it is forwarded.

On the reverse proxy, a finding always blocks. When one guard reports a finding and
another guard fails, the message is blocked for the finding, under both values of
`on_error`. The HTTP API differs: under `fail_close` it answers the error status, also
when another guard reported a finding. Under `fail_open` it reports the findings of the
guards that did not fail.

## Findings in the metrics

Findings never put a detected value in a log, a metric, or an answer. They give kind
names and counts only.

- `voidwall_detections_total{guard="..."}` counts the findings of each guard.
- `voidwall_blocked_total` counts the messages that the reverse proxy blocks. The HTTP
  API blocks nothing, so it does not count here.
- `voidwall_pii_detections_total{pii_kind="..."}` and `voidwall_pii_blocked_total`
  count only PII: the findings of `pii`, and of a model guard with `class = "pii"`.

## Two guards, one kind

Two guards can report kinds of the same name, such as `PERSON_NAME` from `pii` and from
`pii_ml`. Voidwall keeps the findings of both. The kind appears one time in `kinds`, and
`matches_count` counts the findings of both guards. See
[model-guards.md](model-guards.md#two-guards-that-report-one-kind).
