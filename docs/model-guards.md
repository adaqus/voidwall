# Model Guards

A `[guards.<name>]` section declares a guard that runs one ONNX model on the CPU. You
choose `<name>`. It is the guard's name in findings, in logs, and in the `guard` label of
`voidwall_detections_total`. One section holds everything the guard needs: there is no
separate model section, and two guards never share a loaded model.

The image ships only the default models. To run another model, mount its files as a
volume and point the guard at them.

`voidwall --validate` checks every rule below and that each named file exists. It does
not load a model. The model, the tokenizer, and `config.json` are checked when the guard
loads at startup, and a guard that fails to load stops the start. The messages are in
[config-validation.md](config-validation.md#model-guard-rules).

## Adapters

`adapter` names the code path that runs the model. The adapter owns the tensor contract
and the reading of the output. Configuration cannot change either.

| Adapter | Model | Findings |
|---|---|---|
| `text_classifier` | A sequence classifier with one `Float32` output of shape `[1, 2]`. Class 1 is the class the guard reports. | One finding for a unit whose score is at or above the threshold. No span. The confidence is the highest window score. |
| `token_classifier` | A Hugging Face token classifier with one `Float32` output of shape `[1, tokens, labels]`, and a `config.json` whose `id2label` holds exactly one `O`. The other labels have the prefix `B-`, `I-`, or `S-`, or no prefix. | One finding for each span. The finding holds the span's byte range in the unit and its confidence. |

Both adapters need `tokenizer.json` and the ONNX inputs `input_ids` and `attention_mask`
(`token_type_ids` is optional). An input longer than `max_tokens` is cut into
overlapping windows.

## Fields

| Field | Required | Meaning |
|---|---|---|
| `adapter` | yes | `text_classifier` or `token_classifier` |
| `model_path` | yes | The ONNX file |
| `tokenizer_path` | yes | The model's `tokenizer.json` |
| `config_path` | `token_classifier` only | The model's `config.json`, the source of `id2label`. A `text_classifier` guard must not set it |
| `max_tokens` | yes | The longest window the adapter gives the model, special tokens included. At least 10 |
| `overlap_tokens` | no | Tokens that two neighbouring windows share. Default: 128 or `max_tokens / 2`, whichever is smaller. At most `max_tokens / 2` |
| `threads` | no | Worker threads, each with its own model session. Default: the CPUs divided by the number of model guards. At least 1 |
| `labels` | yes | The finding kinds the guard reports. Not empty, no duplicates. See [Labels](#labels) |
| `thresholds` | no | Per label, the lowest score or confidence that gives a finding, from 0.0 to 1.0. A label with no threshold reports nothing |
| `validate_as` | no | `token_classifier` only. See [validate_as](#validate_as) |
| `class` | no | `"pii"` is the only value. See [class](#class) |
| `surface` | no | What the guard scans: `body` (default `true`), `url_path`, `query_params`, `headers` (each default `false`). Each unit costs one model run |

## Labels

For `text_classifier`, `labels` holds exactly one entry, the name of class 1.

For `token_classifier`, `labels` holds the model's own type names, without the `B-`,
`I-`, or `S-` prefix. A span of a type that is not in `labels` gives no finding.

A label is not checked against `id2label`. A label that the model does not have, for
example a misspelled one, loads and reports nothing.

## How a token classifier finds spans

The decoder is fixed. Configuration sets no decoder option.

1. The guard makes one text per unit. A plain-text body is decoded as UTF-8, with each
   invalid byte sequence replaced by U+FFFD. A JSON body gives its string values in
   document order, joined with a newline. Keys are not part of the text.
2. For each token, the probabilities of `B-`, `I-`, and `S-` of one type are added
   together. A token that two windows hold counts once per window.
3. The text is cut into words. Each word gets the type with the highest mean
   probability. A word of type `O` is in no span.
4. Neighbouring words of one type merge into one span, unless a new entity starts, a
   blank line or other text is between them, or they are in two different JSON values.
5. The span's confidence is the mean of its words' highest probabilities.
6. Whitespace, `, . ; : ! ?`, and quotes are removed from both edges of the span, and
   `) ] }` from its end. A span that becomes empty is dropped.

The finding's span is the byte range of the trimmed span in the unit. For a JSON body,
the range is in the body, inside one string value.

A threshold of 0.0 keeps every span that the decoder gives for the label.

## validate_as

`[guards.<name>.validate_as]` maps a label to a list of PII kind names of the built-in
PII guard, such as `CREDIT_CARD`. A span of that label gives a finding only when the
validator of at least one pattern of one listed kind accepts the trimmed span. A label
that is not in `validate_as` is not validated.

```toml
[guards.pii_ml.validate_as]
PAYMENT_CARD = ["CREDIT_CARD"]   # keep a card number only when it passes the Luhn check
```

Validation fails at startup when a key is not in `labels`, when a list is empty, when a
name is not a PII kind, or when every pattern of a listed kind accepts every value.

A validator was written for the text its pattern matches, and the pattern gives the
shape. A span has no such shape, so some validators accept more than their patterns
match. `CREDIT_CARD` checks the shape too: digits in groups with one dash or ASCII whitespace
between them, and nothing else. `IP_ADDRESS` accepts almost every span, so it is a poor
choice for `validate_as`. `docs/backlog.md` §3 lists the other loose validators.

## class

`class = "pii"` makes the guard a PII guard for metrics:

- `voidwall_pii_detections_total` counts its findings, with its label as `pii_kind`.
- `voidwall_pii_blocked_total` counts a message it blocks.

A guard with no `class` counts only in `voidwall_detections_total` and
`voidwall_blocked_total`. `class` does not change what the guard finds or what happens to
the message.

## Two guards that report one kind

The built-in PII guard and a model guard can both report a kind of one name, such as
`PERSON_NAME`. The engine keeps the findings of both and does not resolve overlaps
between them. The kind appears once in a `kinds` list, `matches_count` counts the
findings of both guards, and `voidwall_pii_detections_total` increments once for the kind.
The `guards` array of a `/v1/scan` response shows each guard's share: its own
`matches_count` and `kinds`.

A detection blocks the message. The reverse proxy answers as soon as one guard reports a
finding, so its `kinds` can hold only the kinds of the guards that ended first. The REST
API waits for every guard.

## Examples

A prompt injection classifier:

```toml
[guards.prompt_injection]
adapter = "text_classifier"
model_path = "/opt/voidwall/models/wolf-small/model.onnx"
tokenizer_path = "/opt/voidwall/models/wolf-small/tokenizer.json"
max_tokens = 2048
overlap_tokens = 64
labels = ["PROMPT_INJECTION"]

[guards.prompt_injection.thresholds]
PROMPT_INJECTION = 0.5
```

A PII token classifier, shortened from `docker/voidwall.toml`:

```toml
[guards.pii_ml]
adapter = "token_classifier"
class = "pii"
model_path = "/opt/voidwall/models/bards-v2/onnx/model_quantized.onnx"
tokenizer_path = "/opt/voidwall/models/bards-v2/tokenizer.json"
config_path = "/opt/voidwall/models/bards-v2/config.json"
max_tokens = 512
overlap_tokens = 128
labels = ["PERSON_NAME", "POSTAL_ADDRESS", "PAYMENT_CARD"]

[guards.pii_ml.thresholds]
PERSON_NAME = 0.4
POSTAL_ADDRESS = 0.4
PAYMENT_CARD = 0.0

[guards.pii_ml.validate_as]
PAYMENT_CARD = ["CREDIT_CARD"]
```
