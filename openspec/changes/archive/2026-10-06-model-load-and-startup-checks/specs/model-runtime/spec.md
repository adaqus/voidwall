## ADDED Requirements

### Requirement: A model loads as N sessions that share one copy of the weights

Loading a model SHALL produce the requested number of workers, N. A worker count of 0
SHALL NOT be expressible in a load request. Each worker
SHALL own one ONNX Runtime session with one intra-op thread, the CPU execution provider,
and graph optimization level 3. The model file SHALL be read once per load, and every
weight it holds SHALL be given to all N sessions from that one read, so the N sessions
share one copy of the weights and one copy of the packed weights. The graph each session
parses SHALL carry no data for any weight of 1 KiB or more; ONNX Runtime SHALL get those
weights only from the shared copy, so creating a session SHALL NOT copy them. That graph
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
