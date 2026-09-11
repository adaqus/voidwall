## REMOVED Requirements

### Requirement: No detection passes the message through untouched

**Reason**: The action engine is deleted. A clean scan forwards the message, and that is
now stated by the reverse-proxy capability alongside the block outcome that replaces it.
**Migration**: None. A message with no detection is still forwarded unchanged.

### Requirement: Detection metrics increment unconditionally

**Reason**: The requirement exists to say that a configured action list does not gate the
detection counter. There is no action list. The `metrics` capability already requires the
counter to increment once per resolved kind, and now states that blocking does not gate it
either.
**Migration**: None. The detection counter behaves as before.

### Requirement: Action precedence is block, then redact, then header

**Reason**: Two of the three actions are deleted, so there is no order to evaluate.
**Migration**: None. A detection blocks.

### Requirement: Block returns a configurable error response

**Reason**: The block response is fixed. `block_status`, `block_body`, and `block_headers`
are no longer configuration keys, and a file that carries one fails at startup.
**Migration**: Remove `block_status`, `block_body`, and `block_headers` from every
direction table. A blocked message answers 403 with a JSON body holding `error` and
`kinds`. A deployment that needs another status or shape must translate the 403 in front
of the proxy.

### Requirement: Block responses never carry a PII value

**Reason**: The `security` capability already requires that a block response lists kind
names and never the matched text. Keeping the rule in two places lets them drift.
**Migration**: None. The guarantee is unchanged and stated by `security`.

### Requirement: Redact forwards the mutated body

**Reason**: The redact action is deleted. The proxy no longer rewrites a message.
**Migration**: Remove `redact` from every action list. A detection that would have been
redacted now blocks the message.

### Requirement: Header action adds X-PII-Detected

**Reason**: The header action is deleted, and with it the `X-PII-Detected` response header.
**Migration**: Remove `header` from every action list. A consumer that read
`X-PII-Detected` to learn what was found must read `voidwall_pii_detections_total`, or
call `POST /v1/scan` directly.

### Requirement: Every kind list the engine emits is deterministically ordered

**Reason**: The lists this covered were the block body `kinds` array and the
`X-PII-Detected` header value. The header is deleted, and the block body derives its array
from the scan result, whose ordering the `pii-scanning` capability already requires.
**Migration**: None. The block body still lists kinds sorted, each kind once.

### Requirement: Redaction strategy is configurable

**Reason**: Redaction is deleted, so there is no strategy to select.
**Migration**: Remove `redact_strategy` and `mask_char` from every direction table and
from `[http_api]`.

### Requirement: Scanner failures follow the on_error policy

**Reason**: The requirement describes scanner and limit failures, not actions. It moves to
`pii-scanning`, which owns the scanner, and survives there unchanged in substance.
**Migration**: None. `fail_open` and `fail_close` behave as before, and
`voidwall_errors_total` still records the outcome taken.
