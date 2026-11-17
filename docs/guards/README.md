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
| `invisible_text` | `[builtin_guards.invisible_text]` | Text hidden in Unicode tag characters or variation selectors, in a request | [invisible-text.md](invisible-text.md) |
| Model guard | `[guards.<name>]` | What its ONNX model finds, for example prompt injection or names | [model-guards.md](model-guards.md) |

A built-in guard has a fixed name. A model guard has the name that you give its section.
You can declare many model guards. Each loads its own model.

To add a guard of your own, see [custom-guard.md](custom-guard.md).

## Default guards of the Docker image

The Docker image holds a default config and the models for it. This config declares
four guards, and they run when you start the image with no config of your own:

| Name | Type | Finds |
|---|---|---|
| `pii` | Built-in, regex | Personal data and secrets of all countries and languages |
| `invisible_text` | Built-in | Text hidden in Unicode tag characters or variation selectors |
| `prompt_injection` | Model guard, `text_classifier` | Prompt injection, with the Wolf Defender Prompt-Injection Detector Small v2 model |
| `pii_ml` | Model guard, `token_classifier` | Personal data with no fixed shape, such as names and postal addresses, with the bards.ai EU PII anonimization multilang v2 model |

The `hidden_context` guard is built in, but the default config does not declare it. To
see the default config, run `docker run --rm ghcr.io/adaqus/voidwall --print-config`.

## What a guard reads

Voidwall cuts a message into units: the body, the URL path, the query string, and each
header value that the route names. A guard gets only the units its `surface` admits.

| Guard | Default surface | Directions |
|---|---|---|
| `pii` | Body, URL path, query string, header values | Requests and responses |
| `hidden_context` | Response body only. It has no `surface` key. | Responses only |
| `invisible_text` | Body, URL path, query string, header values. It has no `surface` key. | Requests only |
| Model guard | Body only, because each unit costs one model run | Requests and responses |

Some more rules:

- A header value is a unit only when the route lists the header in `headers`. By
  default a route lists none.
- A body is read only when its content type is in `content_types`. A route with
  `format = "openai-chat"` reads each message, tool, and choice of the body as its own
  unit.
- A guard reads each JSON string value as a JSON parser reads it. Voidwall decodes each
  escape sequence one time, `\uXXXX` included. So `a\u0040example.com` is read as
  `a@example.com`, and `\n` is a newline. This applies to every JSON body, in both
  directions, and to each event of a stream.
- JSON inside a string value, such as the `arguments` of a tool call, is decoded one
  layer only. An escape of the inner document stays as text.
- A JSON body in which one object holds the same key two times does not parse. Two keys
  are the same when they are equal after their escapes are decoded. The body then gets
  the answer of a body that does not parse.
- `reverse_proxy.request.scan` and `reverse_proxy.response.scan` turn off a whole
  direction.
- A route runs every enabled guard, unless its `guards` key lists the guards to run. An
  empty list runs none. A list that leaves out `invisible_text` lets text hidden in tags
  and selectors reach the guards it names.
- In a request, a guard reads the [scan view](#the-scan-view) or the raw text, by its
  `scan_view` key.
- The HTTP API runs every enabled guard. `/v1/scan` takes the direction from its
  `direction` parameter, and the LiteLLM route from `input_type`.

## The scan view

Text can hide from a guard behind invisible or decorative Unicode: a soft hyphen between
two digits, a backspace after a decoy letter, full-width or underlined letters, or a
sentence in tag characters. A model reads through all of these. So, for a request,
Voidwall builds a scan view of each unit: the text with these characters normalized. A
guard that reads the scan view finds `GB82WEST1234­5698765432`, with a soft hyphen in it,
as an IBAN.

The scan view is for the guards only. The forwarded message does not change: the
upstream gets the bytes the client sent. Normalization never blocks a message by itself.
A message is blocked only when a guard reports a finding.

### Which guards read it

| Guard | Reads in a request | Key |
|---|---|---|
| `pii` | The scan view | `builtin_guards.pii.scan_view`, default `true` |
| Model guard, `token_classifier` | The scan view | `guards.<name>.scan_view`, default `true` |
| Model guard, `text_classifier` | The raw text | `guards.<name>.scan_view`, default `false` |
| `invisible_text` | The raw text. It has no `scan_view` key. | — |
| `hidden_context` | Responses only. It has no `scan_view` key. | — |

A `text_classifier`, such as the prompt injection model, reads the raw text by default.
Such a model already flags most of these tricks, and it also flags clean text that uses
them. Set `scan_view = true` to give it the scan view instead. A response is always read
as raw text, whatever `scan_view` says.

### The steps

The scan view is the result of six steps. Each step works on the result of the step
before it.

1. These characters are removed: the soft hyphen U+00AD, the combining grapheme joiner
   U+034F, U+061C, the zero-width space U+200B, U+200E, U+200F, the bidi controls U+202A
   to U+202E and U+2066 to U+2069, the word joiner U+2060, U+2061 to U+2064, and U+FEFF.
2. A backspace deletes the character before it. The other control characters U+0000 to
   U+001F are removed, except tab, line feed, and carriage return.
3. A run of tag characters becomes a space, its ASCII text, and a space. An emoji flag
   stays. A run of two or more variation selectors that holds UTF-8 text becomes a space,
   that text, and a space; any other run of selectors is removed. One selector stays.
4. Full-width ASCII, such as `ｉｇｎｏｒｅ`, becomes ASCII, and the ideographic space
   U+3000 becomes a space.
5. A zero-width joiner or non-joiner between two ASCII characters is removed. In an emoji
   or in Persian text, it stays.
6. A combining mark after an ASCII character other than a space is removed. An
   overline, underline, or strike-through mark after any letter or number is removed. A
   keycap, such as 1️⃣, stays.

The regex PII guard then applies its own step, as before: it removes U+200B to U+200D
and decodes percent-encoding and HTML entities.

A span in the scan view names the bytes of the raw message. A removed character inside
a value is inside its span. A value decoded from tags or selectors spans the whole run.

### Limits

- Response units are not normalized.
- Look-alike letters, such as a Cyrillic `а` in a Latin word, are not folded.
- A hidden character written as percent-encoding or as an HTML entity, such as `%C2%AD`,
  is decoded after the scan view is built, so it stays.
- JSON keys and CSV column names are not normalized.
- A run of tags or selectors that is split by a character that stays, such as a visible
  letter, is decoded piece by piece. The `invisible_text` guard reports a split run of
  selectors.
- Text can hide in emoji flags: each flag holds up to six letters or digits in tags, and
  the scan view keeps it unchanged.
- A header value with a byte that is not printable ASCII is not scanned at all.
- U+180E, U+2028, U+2029, U+007F, the C1 controls, and the Hangul fillers stay.

### Side effects in the scan view

- A letter written with a separate accent mark, such as `e` and U+0301, loses the mark.
  The name dictionary of the `pii` guard can then miss a name that it holds only with the
  accent. A precomposed letter, such as `é`, does not change.
- Full-width punctuation in Japanese or Chinese text becomes ASCII punctuation.
- A text hidden in reversed order with a bidi override loses the override, so a guard
  that reads the scan view sees the reversed text. The `text_classifier` default keeps
  the raw text, with the override in it.

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
