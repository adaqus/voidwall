## ADDED Requirements

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
