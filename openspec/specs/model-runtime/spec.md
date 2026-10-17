# model-runtime Specification

## Purpose
States how the ONNX Runtime that model guards run on is obtained, verified, and linked,
and the minimum CPU the binary needs because of it.

## Requirements

### Requirement: ONNX Runtime comes only from the verified pinned archive

The build SHALL link ONNX Runtime 1.28.0 statically from pyke's prebuilt archive for
`x86_64-unknown-linux-gnu`. Before Cargo sees the archive, the build SHALL check its
SHA-256 against the pinned value and SHALL verify its build attestation against the
`pykeio` owner. A mismatch in either check SHALL fail the build. Every build, including a
developer's `cargo test`, SHALL link this verified archive, and no build SHALL download
ONNX Runtime by itself.

#### Scenario: The archive matches

- **WHEN** the fetch step downloads the archive and both the hash and the attestation match
- **THEN** the archive is extracted and the workspace builds and links against it

#### Scenario: The archive is tampered with

- **WHEN** the fetch step is given a file whose SHA-256 differs from the pinned value
- **THEN** the step exits non-zero and nothing is extracted

#### Scenario: The archive is missing

- **WHEN** a Cargo build runs before the verified archive is extracted
- **THEN** the build fails instead of downloading ONNX Runtime

#### Scenario: The linked version is the pinned one

- **WHEN** the crate's tests ask the linked ONNX Runtime for its version
- **THEN** the version is `1.28.0`

### Requirement: The binary refuses to start below the minimum CPU

The binary SHALL check at startup, before it loads configuration, that the CPU supports
the x86-64-v3 feature set. On a CPU that lacks any of these features, the binary SHALL
NOT start: it SHALL print an error naming the minimum CPU level and each missing feature,
and SHALL exit non-zero. The check SHALL run whether or not a model guard is configured,
and in both `--config` and `--validate` modes.

#### Scenario: The CPU meets the floor

- **WHEN** the binary starts on a CPU with every x86-64-v3 feature
- **THEN** the check passes and startup continues

#### Scenario: The CPU lacks a feature

- **WHEN** the binary starts on a CPU that lacks one or more x86-64-v3 features
- **THEN** it prints an error naming x86-64-v3 and each missing feature
- **AND** it exits non-zero without loading the configuration

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

### Requirement: Only built adapters load

A load SHALL succeed only for an adapter whose load side is built. `text_classifier` SHALL
load. `text_multilabel_classifier` SHALL fail the load with an error that names the
adapter as not built.

#### Scenario: A multilabel adapter is refused

- **WHEN** a load names `text_multilabel_classifier`
- **THEN** the load fails with an error naming `text_multilabel_classifier` as not built

### Requirement: Unreadable artifacts fail the load

A model file that does not parse as an ONNX model, or a tokenizer file that does not parse
as a tokenizer, SHALL fail the load with an error that names the file that failed.

#### Scenario: The model file is not ONNX

- **WHEN** the model path points to a file that does not parse as an ONNX model
- **THEN** the load fails with an error naming the model path

#### Scenario: The tokenizer file is not a tokenizer

- **WHEN** the tokenizer path points to a file that does not parse as a tokenizer
- **THEN** the load fails with an error naming the tokenizer path

### Requirement: The model's inputs match the adapter's contract

A load SHALL fail when the model's inputs break any of these rules:

- inputs named `input_ids` and `attention_mask` are present
- no input has a name other than `input_ids`, `attention_mask`, and `token_type_ids`
- every input has element type `Int64` and rank 2

An input named `token_type_ids` SHALL be accepted, and every inference SHALL feed it with
zeros. Each failure SHALL produce an error that names the input and the rule it breaks.

#### Scenario: A required input is missing

- **WHEN** a model has no `attention_mask` input
- **THEN** the load fails with an error naming `attention_mask`

#### Scenario: An unknown input is present

- **WHEN** a model has an input named `position_ids`
- **THEN** the load fails with an error naming `position_ids`

#### Scenario: An input has the wrong element type

- **WHEN** a model's `input_ids` input has element type `Int32`
- **THEN** the load fails with an error naming `input_ids` and its element type

#### Scenario: An input has the wrong rank

- **WHEN** a model's `input_ids` input has rank 1
- **THEN** the load fails with an error naming `input_ids` and its rank

#### Scenario: A model with token type IDs loads

- **WHEN** a model that passes every other check also has a `token_type_ids` input
- **THEN** the load succeeds, and the smoke inference feeds `token_type_ids` with zeros

### Requirement: The model's output matches the adapter's width

A load SHALL fail unless the model has exactly one output, with element type `Float32`,
rank 2, and a fixed last dimension equal to the adapter's width. The width of
`text_classifier` SHALL be 2. Each failure SHALL produce an error that names the rule the
output breaks.

#### Scenario: The model has two outputs

- **WHEN** a model has two outputs
- **THEN** the load fails with an error naming the output count

#### Scenario: The output has the wrong width

- **WHEN** a `text_classifier` model's output has last dimension 3
- **THEN** the load fails with an error naming the expected width 2 and the found width 3

#### Scenario: The output is half precision

- **WHEN** a model's output has element type `Float16`
- **THEN** the load fails with an error naming the output element type

### Requirement: A fixed sequence dimension must equal max_tokens

When the sequence dimension of the model's inputs is fixed at N, a load SHALL succeed only
when `max_tokens` equals N. A dynamic sequence dimension SHALL be accepted for any
`max_tokens`.

#### Scenario: Fixed dimension equals max_tokens

- **WHEN** a model's inputs have a fixed sequence dimension of 16 and `max_tokens` is 16
- **THEN** the load succeeds

#### Scenario: Fixed dimension differs from max_tokens

- **WHEN** a model's inputs have a fixed sequence dimension of 16 and `max_tokens` is 32
- **THEN** the load fails with an error naming the fixed dimension 16 and `max_tokens` 32

#### Scenario: Dynamic dimension

- **WHEN** a model's inputs have a dynamic sequence dimension
- **THEN** the sequence dimension check passes for any `max_tokens`

### Requirement: Every token ID the tokenizer produces fits the embedding table

A load SHALL find the embedding table as the data input of the `Gather` node that reads
`input_ids` directly. When no such table is found, the load SHALL fail. When the highest
token ID the tokenizer can produce, added tokens included, is at or above the table's row
count, the load SHALL fail with an error that names both numbers.

#### Scenario: The tokenizer fits the model

- **WHEN** the tokenizer's highest token ID is below the embedding table's row count
- **THEN** the tokenizer check passes

#### Scenario: The tokenizer is larger than the model

- **WHEN** the tokenizer can produce a token ID at or above the embedding table's row count
- **THEN** the load fails with an error naming the highest token ID and the row count

#### Scenario: No embedding table is found

- **WHEN** `input_ids` does not feed a `Gather` node directly
- **THEN** the load fails with an error stating that the embedding table was not found

### Requirement: One smoke inference runs on each session

After the checks above pass, the load SHALL run one inference on each of the N sessions,
with batch size 1. Each inference SHALL return shape `[1, width]` with only finite values.
A session whose inference fails, returns another shape, or returns a NaN or infinite value
SHALL fail the load with an error that names the failure.

#### Scenario: The smoke inference succeeds

- **WHEN** every session's smoke inference returns finite values of shape `[1, width]`
- **THEN** the load succeeds

#### Scenario: The model fails only when it runs

- **WHEN** a model passes the tensor checks but its inference fails at run time
- **THEN** the load fails with an error naming the smoke inference

#### Scenario: The model returns a non-finite value

- **WHEN** a model's smoke inference returns a NaN
- **THEN** the load fails with an error naming the non-finite output

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

### Requirement: A run can be cancelled from another thread

Every run of a unit SHALL take a cancel handle, and another thread SHALL be able to cancel
the run through it. When the handle is cancelled before the run starts, the run SHALL NOT
tokenize the unit and SHALL NOT run an inference. When the handle is cancelled while a
window's inference runs, ONNX Runtime SHALL stop that inference at its next graph node,
and the run SHALL NOT start another window. When the handle is cancelled between two
windows, the run SHALL NOT start the next window. A cancelled run SHALL return a cancelled
result, which is distinct from every failure and SHALL NOT carry a score. A session whose
run was cancelled SHALL score the next unit as if no cancel had happened.

#### Scenario: Cancelled before the run

- **WHEN** the handle is cancelled and then the unit is run
- **THEN** the run returns the cancelled result and no inference runs

#### Scenario: Cancelled during an inference

- **WHEN** another thread cancels the handle while a window's inference runs
- **THEN** the run returns the cancelled result long before the inference would have
  ended

#### Scenario: Cancelled between windows

- **WHEN** the handle is cancelled after one window's inference returns and before the
  next starts
- **THEN** the run returns the cancelled result and the next window does not start

#### Scenario: The session runs again after a cancel

- **WHEN** a run on a session was cancelled, and the same session then scores a unit with
  a new handle
- **THEN** the score equals the score of the same unit on a session that was never
  cancelled

### Requirement: An abandoned model guard frees its worker

When the engine abandons a model guard, the guard SHALL cancel its run. A worker SHALL
NOT start a job whose result nobody waits for any more, and SHALL stop scoring the
remaining units of a cancelled job. The worker SHALL then take the next job.

A cancelled run SHALL NOT be a failure. It SHALL NOT increment `voidwall_errors_total`,
SHALL NOT count as `inference_failure`, and SHALL NOT write an error log. Its result is
discarded.

#### Scenario: A block abandons a long inference

- **WHEN** a model guard with one worker is scoring a long unit, and another guard's
  finding blocks the message
- **THEN** the worker takes its next job within the stop lag of one graph node, not when
  the abandoned inference would have ended

#### Scenario: A queued job of an abandoned message

- **WHEN** a model guard's job is still waiting in the queue when the engine abandons the
  guard
- **THEN** the worker skips the job without tokenizing or running an inference

#### Scenario: A cancelled run is not counted as an error

- **WHEN** the engine abandons a model guard while its inference runs
- **THEN** `voidwall_errors_total` does not increment and no error is logged for that
  guard

### Requirement: The parity runner is docker/ctl parity

`docker/ctl parity` SHALL run the parity check for the wolf-small model from start to end,
with no manual step: it SHALL get the model files, make the Python reference, and run the
ignored Rust parity test against that reference. It SHALL exit with status zero only when
the parity test passes. It SHALL run on the host, not in a container. It SHALL check no
model other than wolf-small.

#### Scenario: The check passes

- **WHEN** `docker/ctl parity` runs on a host that meets its requirements, and the worker
  matches the reference
- **THEN** the command prints the parity test result and exits with status zero

#### Scenario: The check fails

- **WHEN** `docker/ctl parity` runs and the parity test fails
- **THEN** the command exits with a non-zero status

### Requirement: The parity runner uses pinned model files

The runner SHALL use the wolf-small files at revision
`bcab2eff97bcabd7227849639e2d0d7a61b46c92` only. It SHALL get `model.onnx` and
`tokenizer.json` through `docker/fetch-models.sh`. It SHALL get `config.json` and
`model.safetensors` at the same revision into `.cache/parity/`, and SHALL verify each file
against a pinned SHA-256 before it uses the file. A file whose SHA-256 is not the pinned
value SHALL stop the run with a non-zero exit status, before the reference is made.

#### Scenario: A downloaded file does not match its pin

- **WHEN** a fetched `config.json` or `model.safetensors` has a SHA-256 that is not its
  pinned value
- **THEN** the run stops with a non-zero exit status, names the file, and makes no
  reference

### Requirement: The parity reference is made again on every run

Every run of `docker/ctl parity` SHALL make a new `reference.json` with
`crates/voidwall-ml/parity/reference.py` before the parity test runs. The parity test
SHALL NOT use a reference from an earlier run.

#### Scenario: A pinned Python package changes

- **WHEN** a version in `crates/voidwall-ml/parity/requirements.txt` changes and
  `docker/ctl parity` runs
- **THEN** the reference that the parity test uses was made with the new version

### Requirement: The parity runner has default window settings

The runner SHALL make the reference with a window of 2048 tokens and an overlap of 64
tokens, the values of the wolf-small guard in `docker/voidwall.toml`.
`PARITY_MAX_TOKENS` SHALL override the window length and `PARITY_OVERLAP` SHALL override
the overlap.

#### Scenario: Default run

- **WHEN** `docker/ctl parity` runs with `PARITY_MAX_TOKENS` and `PARITY_OVERLAP` unset
- **THEN** the reference records a window of 2048 tokens and an overlap of 64 tokens

#### Scenario: Overridden window

- **WHEN** `PARITY_MAX_TOKENS=512 PARITY_OVERLAP=128 docker/ctl parity` runs
- **THEN** the reference records a window of 512 tokens and an overlap of 128 tokens

### Requirement: The parity runner needs python3 3.11 or later

The runner SHALL stop with a non-zero exit status and a message that names the requirement
when the host has no `python3`, or has a `python3` older than 3.11. It SHALL install the
Python packages of `crates/voidwall-ml/parity/requirements.txt` into a virtual environment
under `.cache/parity/`, never into the host Python.

#### Scenario: No python3 on the host

- **WHEN** `docker/ctl parity` runs on a host with no `python3`
- **THEN** the command stops with a non-zero exit status and states that it needs
  `python3` 3.11 or later

#### Scenario: python3 is too old

- **WHEN** `docker/ctl parity` runs on a host whose `python3` is 3.10
- **THEN** the command stops with a non-zero exit status and names the version it found
