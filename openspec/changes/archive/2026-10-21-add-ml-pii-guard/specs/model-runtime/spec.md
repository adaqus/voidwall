## ADDED Requirements

### Requirement: A token classifier reads its labels from the model's config

A `token_classifier` load SHALL read `id2label` from the `config.json` named in the load
request. The load SHALL fail with an error that names the file when:
- the file does not parse as JSON;
- it has no `id2label` object;
- its keys are not exactly the integers `0` to `n − 1`.

Each label SHALL be `O`, or a type name with one of the prefixes `B-`, `I-`, `S-`, or a
type name with no prefix. Exactly one label SHALL be `O`; otherwise the load SHALL fail
naming the file. The entity types of the model SHALL be the distinct type names, with
their prefixes removed.

#### Scenario: A BIO model loads

- **WHEN** `id2label` holds `O`, `B-PERSON_NAME` and `I-PERSON_NAME`
- **THEN** the load succeeds and the model has one entity type, `PERSON_NAME`

#### Scenario: The config has no id2label

- **WHEN** the named `config.json` has no `id2label` object
- **THEN** the load fails with an error naming the config path

#### Scenario: The ids have a gap

- **WHEN** `id2label` has the keys `0`, `1` and `3`
- **THEN** the load fails with an error naming the config path

#### Scenario: There is no O label

- **WHEN** no label of `id2label` is `O`
- **THEN** the load fails with an error naming the config path

### Requirement: A token classifier's output has one score per label for every token

A `token_classifier` load SHALL fail unless the model has exactly one output, with element
type `Float32`, rank 3, and a last dimension equal to the number of entries in `id2label`.
The error SHALL name both numbers when the widths differ. Every smoke inference SHALL
return shape `[1, n, width]`, where `n` is the number of tokens of its input.

#### Scenario: The output width matches the labels

- **WHEN** `id2label` has 71 entries and the output's last dimension is 71
- **THEN** the output check passes

#### Scenario: The output width differs from the labels

- **WHEN** `id2label` has 71 entries and the output's last dimension is 69
- **THEN** the load fails with an error naming 71 and 69

#### Scenario: A token classifier output is rank 2

- **WHEN** a `token_classifier` load reads a model whose output has rank 2
- **THEN** the load fails with an error naming the output rank

### Requirement: A token classifier labels each word by its mean pooled probability

For each window, a `token_classifier` worker SHALL turn every token's logits into
probabilities with softmax. It SHALL then add the probabilities of all labels of one type
together, so `B-`, `I-` and `S-` count as one type and `O` as its own.

A token's pooled probabilities SHALL be recorded at the first non-whitespace character of
the token's text, and summed with every other token recorded there. That includes the
same token seen by two overlapping windows. Special tokens SHALL record nothing.

A word SHALL be a run of characters that holds no whitespace and none of
`, ; | " < > ( ) [ ] { } * ^`. The characters `( [ { < " ' « „` SHALL be removed from a
word's start and `) ] } > " ' » . , ; : ! ?` from its end; a word left empty SHALL be
skipped. A word's probabilities SHALL be the sum over its characters, divided by the number
of records in it. A word that holds no record SHALL be skipped. The word's type SHALL be the
type of the highest probability. A word whose type is `O` SHALL give no span.

#### Scenario: A token in two windows

- **WHEN** a token lies in the overlap of two windows, which predict different
  probabilities for it
- **THEN** its word is labelled from the mean of the two predictions

#### Scenario: A word predicted as outside every entity

- **WHEN** a word's highest pooled probability is `O`
- **THEN** that word is in no span

### Requirement: Neighbouring words of one type merge into one span

A labelled word SHALL extend the span before it when all of these hold:
- the span has the same type;
- the text between them consists only of the characters ` , - / . ( )` (it may be empty);
- that text holds no blank line (`\n\n`);
- the word's start probability is below 0.5. The start probability is the summed
  probability of the `B-` and `S-` labels recorded at the word's first character with a
  record, divided by the number of those records.

Otherwise the word SHALL start a new span. The confidence of a span SHALL be the mean, over
its words, of each word's highest pooled probability, in `0.0..=1.0`.

#### Scenario: A two-word name

- **WHEN** two neighbouring words are both labelled `PERSON_NAME`, are separated by one
  space, and the second has a start probability of 0.1
- **THEN** they form one span whose confidence is the mean of the two words' probabilities

#### Scenario: A new entity starts

- **WHEN** two neighbouring words are both labelled `PERSON_NAME`, and the second has a
  start probability of 0.8
- **THEN** they form two spans

#### Scenario: A blank line separates two words

- **WHEN** two words of one type are separated by a blank line
- **THEN** they form two spans

### Requirement: A token classifier's spans are trimmed at their edges

Before a span is returned, a `token_classifier` worker SHALL remove these characters:
- from both of its edges: whitespace, `, . ; : ! ?`, and `" ' “ ” ‘ ’ « » „`;
- from its end only: `) ] }`.

A span left empty SHALL be dropped. The returned span SHALL be the trimmed one.

#### Scenario: A closing bracket after a value

- **WHEN** a span's text is a value followed by `).`
- **THEN** the returned span holds the value without `).`

#### Scenario: An opening bracket is kept

- **WHEN** a span's text starts with `(`
- **THEN** the `(` stays in the returned span

### Requirement: A token classifier finds nothing in blank text

A `token_classifier` worker SHALL return no span for a text that is empty or holds only
whitespace, and SHALL run no inference for it.

#### Scenario: A whitespace-only unit

- **WHEN** a unit's text holds only spaces and newlines
- **THEN** the worker returns no span and runs no inference

### Requirement: Token classifier spans match the Python reference

A parity check SHALL compare a fp32 `token_classifier` worker with a reference made by
Python `tokenizers`, the PyTorch model, and a Python copy of the decoder, fed the same token
IDs. The text set SHALL hold short texts, texts of several windows, non-ASCII text, and
texts with values of several entity types, using placeholder values only. For the fp32
`bardsai/eu-pii-anonimization-multilang-v2` model:
- every token ID SHALL equal the reference;
- every pooled probability SHALL be within 2e-4 of the reference;
- the returned spans and their types SHALL equal the reference.

#### Scenario: The PII model matches

- **WHEN** the parity check runs on the fp32 PII model
- **THEN** token IDs and spans equal the reference, and every pooled probability is within
  2e-4 of it

### Requirement: An INT8 worker computes what a plain session computes

A check SHALL run every window of the token classifier parity text set through a
`token_classifier` worker of the INT8 PII model, and through a plain ONNX Runtime session
of the same file with the worker's session options and no shared or prepacked weights.
Every logit of the worker SHALL equal the plain session's, bit for bit.

The INT8 worker SHALL NOT be checked against Python. The ONNX Runtime build Voidwall links
and the Python wheel of the same version round some fp32 operations apart, and dynamic
quantization turns such a difference into a full quantization step: on the parity text
set, pooled probabilities differ by up to 0.276 and 1 of 78 spans differs.

#### Scenario: The INT8 PII model matches a plain session

- **WHEN** the check runs on `onnx/model_quantized.onnx` of the PII model
- **THEN** every logit of every window equals the plain session's

### Requirement: The parity runner uses pinned files of the PII model

The runner SHALL use the PII model at revision `5e61416e77675881185767fc0c67759d48b35592`
only. It SHALL get the INT8 `onnx/model_quantized.onnx`, `tokenizer.json` and `config.json`
through `docker/fetch-models.sh`. It SHALL get the fp32 `onnx/model.onnx` and
`model.safetensors` at the same revision into `.cache/parity/`. It SHALL verify every file
against a pinned SHA-256 before it uses the file. A file whose SHA-256 is not the pinned
value SHALL stop the run with a non-zero exit status, before any reference is made.

#### Scenario: A PII model file does not match its pin

- **WHEN** a fetched file of the PII model has a SHA-256 that is not its pinned value
- **THEN** the run stops with a non-zero exit status, names the file, and makes no reference

## MODIFIED Requirements

### Requirement: Only built adapters load

A load SHALL succeed only for an adapter whose load side is built. `text_classifier` and
`token_classifier` SHALL load. `text_multilabel_classifier` SHALL fail the load with an
error that names the adapter as not built.

#### Scenario: A multilabel adapter is refused

- **WHEN** a load names `text_multilabel_classifier`
- **THEN** the load fails with an error naming `text_multilabel_classifier` as not built

#### Scenario: A token classifier loads

- **WHEN** a load names `token_classifier` with a model, a tokenizer and a config that meet
  its contract
- **THEN** the load succeeds

### Requirement: The model's output matches the adapter's width

For `text_classifier`, a load SHALL fail unless the model has exactly one output, with
element type `Float32`, rank 2, and a fixed last dimension equal to the adapter's width. The
width of `text_classifier` SHALL be 2. Each failure SHALL produce an error that names the
rule the output breaks. The output of `token_classifier` follows "A token classifier's
output has one score per label for every token".

#### Scenario: The model has two outputs

- **WHEN** a model has two outputs
- **THEN** the load fails with an error naming the output count

#### Scenario: The output has the wrong width

- **WHEN** a `text_classifier` model's output has last dimension 3
- **THEN** the load fails with an error naming the expected width 2 and the found width 3

#### Scenario: The output is half precision

- **WHEN** a model's output has element type `Float16`
- **THEN** the load fails with an error naming the output element type

### Requirement: One smoke inference runs on each session

After the checks above pass, the load SHALL run one inference on each of the N sessions,
with batch size 1. Each inference SHALL return only finite values. For `text_classifier`
the shape SHALL be `[1, width]`; for `token_classifier` it SHALL be `[1, n, width]`, where `n`
is the number of tokens of the smoke input. A session whose inference fails, returns another
shape, or returns a NaN or infinite value SHALL fail the load with an error that names the
failure.

#### Scenario: The smoke inference succeeds

- **WHEN** every session's smoke inference returns finite values of the adapter's shape
- **THEN** the load succeeds

#### Scenario: The model fails only when it runs

- **WHEN** a model passes the tensor checks but its inference fails at run time
- **THEN** the load fails with an error naming the smoke inference

#### Scenario: The model returns a non-finite value

- **WHEN** a model's smoke inference returns a NaN
- **THEN** the load fails with an error naming the non-finite output

### Requirement: Invalid inference output is an error, never a score

A run SHALL fail, and SHALL return neither a score nor a span, when:
- an inference fails;
- an output does not have the adapter's shape: `[1, width]` for `text_classifier`,
  `[1, n, width]` for `token_classifier` with `n` the window's token count;
- a logit is NaN or infinite.

No run error SHALL carry the unit's text or any part of it.

#### Scenario: A NaN logit

- **WHEN** a window's inference returns a NaN logit
- **THEN** the run fails with an error naming the non-finite output

#### Scenario: An inference fails

- **WHEN** a window's inference fails
- **THEN** the run fails with an inference error that does not contain the unit's text

#### Scenario: A token classifier output with the wrong token count

- **WHEN** a `token_classifier` window of 20 tokens returns an output for 19 tokens
- **THEN** the run fails with an error naming the output shape

### Requirement: The parity runner is docker/ctl parity

`docker/ctl parity` SHALL run the parity check for the wolf-small model and for the PII model
`bardsai/eu-pii-anonimization-multilang-v2` from start to end, with no manual step: for each
model it SHALL get the model files, make the Python reference, and run the ignored Rust
parity test against that reference. It SHALL also run the INT8 check of the PII model. It
SHALL exit with status zero only when the parity tests of both models and the INT8 check
pass. It SHALL run on the host, not in a container. It SHALL check no
other model.

#### Scenario: The check passes

- **WHEN** `docker/ctl parity` runs on a host that meets its requirements, the workers of
  both models match their references, and the INT8 worker matches its plain session
- **THEN** the command prints the parity test results and exits with status zero

#### Scenario: The check fails

- **WHEN** `docker/ctl parity` runs and the parity test of either model, or the INT8 check,
  fails
- **THEN** the command exits with a non-zero status

### Requirement: The parity runner has default window settings

The runner SHALL make each model's reference with that model's window and overlap in
`docker/voidwall.toml`: 2048 and 64 tokens for wolf-small, 512 and 128 tokens for the PII
model. `PARITY_MAX_TOKENS` SHALL override the window length and `PARITY_OVERLAP` SHALL
override the overlap, for both models.

#### Scenario: Default run

- **WHEN** `docker/ctl parity` runs with `PARITY_MAX_TOKENS` and `PARITY_OVERLAP` unset
- **THEN** the wolf-small reference records a window of 2048 tokens and an overlap of 64,
  and the PII model reference records 512 and 128

#### Scenario: Overridden window

- **WHEN** `PARITY_MAX_TOKENS=512 PARITY_OVERLAP=128 docker/ctl parity` runs
- **THEN** both references record a window of 512 tokens and an overlap of 128 tokens
