## REMOVED Requirements

### Requirement: The harness is a separate tool, not part of the proxy

**Reason**: The harness is deleted with `POST /v1/redact`, its only transport. The
`ai4privacy-eval` binary, the `eval` cargo feature, and its optional HTTP client
dependency go with it.
**Migration**: None. A default build already carried none of this. The roadmap's Model
Evaluation Framework phase ships the replacement.

### Requirement: The harness drives the running proxy over HTTP

**Reason**: The harness posts to `/v1/redact`, which no longer exists. `/v1/scan` cannot
substitute: it answers with a deduplicated kind set that carries no offsets, so span-level
scoring is impossible against it.
**Migration**: None until the replacement framework ships. Detection quality is not
measurable in the meantime.

### Requirement: Spans are recovered by diffing the redacted body

**Reason**: Recovery depends on the `type_label` strategy producing the original text with
each detected span replaced by a bracketed kind token. Redaction is deleted, so there is no
redacted body to diff.
**Migration**: None. The replacement framework must obtain spans directly rather than
reconstruct them.

### Requirement: Scoring is span-level overlap

**Reason**: Scoring has no predictions to score once span recovery is gone.
**Migration**: None. The definition of a true positive, a false positive, and a false
negative is worth carrying into the replacement framework unchanged.

### Requirement: Two metric variants are reported

**Reason**: The report is deleted with the harness that produces it.
**Migration**: None.

### Requirement: Precision is reported as a band

**Reason**: The report is deleted with the harness that produces it.
**Migration**: None. The reason the band existed — real detections the dataset does not
annotate — still applies and should be carried forward.

### Requirement: A per-kind false-positive breakdown is emitted

**Reason**: The report is deleted with the harness that produces it.
**Migration**: None.

### Requirement: The runner is docker/ctl eval

**Reason**: The subcommand invokes a binary that no longer exists.
**Migration**: `docker/ctl` no longer accepts `eval`. Its other subcommands are unchanged.

### Requirement: The dataset is fetched on demand and cached

**Reason**: The fetch exists to feed the harness.
**Migration**: None. Anything already cached under `.cache/ai4privacy` stays on disk; it is
gitignored and is not deleted by this change.

### Requirement: Rows are streamed, not buffered

**Reason**: The streaming reader is part of the deleted harness.
**Migration**: None. Streaming rather than buffering is a constraint the replacement
framework should keep.
