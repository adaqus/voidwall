## ADDED Requirements

### Requirement: The overlap between windows is bounded at load

A load request SHALL carry an optional overlap, in tokens. When it is absent, the overlap
SHALL be `min(128, max_tokens / 2)`. When it is present and above `max_tokens / 2`, the
load SHALL fail with an error that names the overlap and the bound. The window of a load
is `max_tokens` minus the number of special tokens the tokenizer adds to one sequence.
When the window is not longer than the overlap, the load SHALL fail with an error that
names the window and the overlap.

#### Scenario: The default overlap

- **WHEN** a model is loaded with `max_tokens` 512 and no overlap
- **THEN** the overlap is 128

#### Scenario: The default overlap of a short window

- **WHEN** a model is loaded with `max_tokens` 64 and no overlap
- **THEN** the overlap is 32

#### Scenario: An overlap at the bound

- **WHEN** a model is loaded with `max_tokens` 16 and an overlap of 8
- **THEN** the load succeeds

#### Scenario: An overlap above the bound

- **WHEN** a model is loaded with `max_tokens` 16 and an overlap of 9
- **THEN** the load fails with an error naming the overlap 9 and the bound 8

#### Scenario: The window is not longer than the overlap

- **WHEN** the tokenizer adds so many special tokens that the window is not longer than
  the overlap
- **THEN** the load fails with an error naming the window and the overlap

### Requirement: A unit is tokenized with the model's tokenizer as written

A worker SHALL tokenize a unit's text with the tokenizer file of its load, with its
normalizer, pre-tokenizer, and post-processor as written in that file. Truncation and
padding set in the tokenizer file SHALL NOT apply.

#### Scenario: The tokenizer file sets truncation

- **WHEN** the tokenizer file sets truncation at a length shorter than the unit
- **THEN** every token of the unit is scored

#### Scenario: Token IDs match the reference tokenizer

- **WHEN** the parity check tokenizes its text set
- **THEN** every window's token IDs equal those of the reference tokenizer

### Requirement: A long unit is split into overlapping windows

A unit whose tokens, without special tokens, fit in one window SHALL run exactly one
inference. A longer unit SHALL be split into windows of the window length. Each window
but the last SHALL start `stride = window − overlap` tokens after the one before it; the
last window SHALL end at the unit's last token, and SHALL start at most `stride` tokens
after the one before it. Each window SHALL be made from the unit's token IDs,
not from text decoded back from them, and SHALL get the tokenizer's special tokens. A unit
with no tokens SHALL run one inference on the special tokens alone.

#### Scenario: A short unit

- **WHEN** a unit's tokens fit in one window
- **THEN** the worker runs one inference

#### Scenario: A long unit

- **WHEN** a unit has more tokens than one window
- **THEN** the worker runs one inference per window, each window but the last starts
  `stride` tokens after the one before it, the last window ends at the unit's last token,
  and every token is in at least one window

#### Scenario: An empty unit

- **WHEN** a unit's text is empty
- **THEN** the worker runs one inference on the special tokens alone and returns its score

### Requirement: A window is padded to a fixed sequence dimension

When the model fixes the sequence dimension at N, each window SHALL be padded to N tokens
with the tokenizer's pad ID, or 0 when the tokenizer has none, and the padded positions
SHALL have attention mask 0. With a dynamic sequence dimension, a window SHALL NOT be
padded.

#### Scenario: A fixed-length model

- **WHEN** a model fixes the sequence dimension at 16 and a window holds 5 tokens
- **THEN** the inference gets 16 positions, the last 11 with the pad ID and attention
  mask 0

#### Scenario: A dynamic-length model

- **WHEN** a model has a dynamic sequence dimension and a window holds 5 tokens
- **THEN** the inference gets 5 positions

### Requirement: The unit score is the highest window score

For `text_classifier`, the score of one window SHALL be `softmax(logits)[1]` over its two
logits, in `0.0..=1.0`. The score of a unit SHALL be the highest score of its windows.

#### Scenario: One window holds the attack

- **WHEN** a unit has several windows and one of them scores 0.97 while the others score
  below 0.1
- **THEN** the unit score is 0.97

#### Scenario: Equal logits

- **WHEN** a window's two logits are equal
- **THEN** its score is 0.5

### Requirement: A unit that needs too many windows fails before inference

The window limit of a load SHALL be `ceil(max_body_size / stride)`, where `max_body_size`
is given in the load request. A unit that needs more windows than the limit SHALL fail
with a window-limit error before any inference runs. That error SHALL be distinct from an
inference failure and SHALL name the window count and the limit.

#### Scenario: The limit is exceeded

- **WHEN** a unit needs more windows than the limit
- **THEN** the run fails with a window-limit error naming both numbers, and no inference
  runs

#### Scenario: The limit is met

- **WHEN** a unit needs exactly as many windows as the limit
- **THEN** the run scores the unit

### Requirement: Invalid inference output is an error, never a score

A run SHALL fail, and SHALL NOT return a score, when an inference fails, when an output
does not have shape `[1, width]`, or when a logit is NaN or infinite. No run error SHALL
carry the unit's text or any part of it.

#### Scenario: A NaN logit

- **WHEN** a window's inference returns a NaN logit
- **THEN** the run fails with an error naming the non-finite output

#### Scenario: An inference fails

- **WHEN** a window's inference fails
- **THEN** the run fails with an inference error that does not contain the unit's text

### Requirement: Scores match the Python reference on the shipped candidates

A parity check SHALL compare the worker's scores with a reference made by Python
`tokenizers` and the PyTorch model, fed the same token IDs, on a text set that includes
short prompts, a known attack prompt, and units of several windows. For the fp32 Wolf and
PIGuard models, every unit score SHALL be within 1e-4 of the reference, no unit SHALL fall
on the other side of 0.5 from the reference, and the known attack prompt SHALL score at
least 0.9.

#### Scenario: Wolf and PIGuard match

- **WHEN** the parity check runs on the fp32 Wolf model and on the fp32 PIGuard model
- **THEN** every unit score is within 1e-4 of the reference, none crosses 0.5, and the
  known attack prompt scores at least 0.9

## MODIFIED Requirements

### Requirement: A model loads as N sessions that share one copy of the weights

Loading a model SHALL produce the requested number of workers, N. A worker count of 0
SHALL NOT be expressible in a load request. Each worker
SHALL own one ONNX Runtime session with one intra-op thread, the CPU execution provider,
and graph optimization level 3. The model file SHALL be read once per load, and every
weight it holds SHALL be given to all N sessions from that one read, so the N sessions
share one copy of the weights and one copy of the packed weights. The graph each session
parses SHALL carry no data for any weight of 1 KiB or more, except a weight that feeds a
node whose inputs are all weights or outputs of such nodes, which ONNX Runtime evaluates
once at load from the graph itself; ONNX Runtime SHALL get every other weight of 1 KiB or
more only from the shared copy, so creating a session SHALL NOT copy it. That graph
SHALL be written to a private directory under the process temp directory (`TMPDIR`, else
`/tmp`) for the length of the load and removed when the load ends; when it cannot be
written, the load SHALL fail with an error that names the temp directory. The first session
SHALL load and pass the tensor checks alone; the other N−1 sessions SHALL then load in
parallel. The operator SHALL supply an ordinary `.onnx` file; no converted format
SHALL be needed.

#### Scenario: A good model loads N workers

- **WHEN** a model that passes every load check is loaded with N = 3
- **THEN** the load returns 3 workers

#### Scenario: Every weight in the file is shared

- **WHEN** a model is loaded
- **THEN** every weight the model file holds is given to each session from the single read
  of the file

#### Scenario: The temp directory is not writable

- **WHEN** the weight-free graph cannot be written under the temp directory
- **THEN** the load fails with an error naming that directory

#### Scenario: Sessions parse a graph without the large weights

- **WHEN** a model with a weight of 1 KiB or more is loaded
- **THEN** the graph handed to each session holds no data for that weight, and the
  session's output equals the output of the unmodified model

#### Scenario: A weight that only feeds constant nodes stays in the graph

- **WHEN** a model has a weight of 1 KiB or more whose only path into the graph is a node
  whose inputs are all weights
- **THEN** the graph handed to each session keeps that weight's data, and the load succeeds
