---
name: code-review
description: Review Voidwall changes for correctness, security, regressions, OpenSpec compliance, and missing tests. Use after implementation or when asked to review a diff, branch, pull request, or working tree. Review only; do not edit files.
---

# Review Voidwall Changes

Perform a read-only, diff-focused review. Do not edit files, update task checkboxes, or
commit changes.

## Scope

1. Inspect the working tree and determine the intended change.
2. Read applicable `AGENTS.md` files and any OpenSpec change artifacts.
3. Review changed code and its call sites, tests, configuration, and documentation.
4. Run focused read-only checks when they can confirm or reject a finding.

Never expose PII values while reviewing logs, fixtures, eval data, errors, or command
output. Refer to PII by kind, span, count, or a safe placeholder.

## Project Checks

- PII values never enter logs, metrics, error responses, tracing fields, or cache keys.
- Async code sends scanner work through `ScannerPool`; it never calls `pii::Scanner`
  directly on a Tokio runtime thread.
- Proxy consumers call `pii::resolve_overlaps` before counting, redacting, reporting,
  or incrementing detection metrics.
- Action precedence remains block, redact, header, with block short-circuiting forwarding.
- Scanner and limit failures follow `on_error`, and error metrics record the outcome.
- Per-route overrides replace defaults rather than merging with them.
- New configuration fields have startup validation and valid and invalid tests.
- Detector changes update inventories, validators, parameterized tests, benchmarks, and
  overlap priorities when applicable.
- Request and response body buffers are not retained after scanning.
- Observable behavior matches the applicable OpenSpec delta and built specs.
- Tests cover regressions, boundary cases, error paths, and externally visible behavior.

## Output

List findings first, ordered by severity. Each finding must include a file and line
reference, the concrete failure mode, and why it matters. Do not report style preferences
unless they create a maintenance or correctness risk.

After findings, list open questions or assumptions. End with a short verification summary.
If there are no findings, state that directly and name any residual testing gaps.
