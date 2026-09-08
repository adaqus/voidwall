## REMOVED Requirements

### Requirement: A specialization is selected explicitly

**Reason**: The analytics specializations are retired. Voidwall inspects agent traffic
against LLM APIs, not web analytics beacons.
**Migration**: Remove `specialization` from every reverse-proxy route and drop
`?specialization=` from every HTTP API call. Bodies are scanned by the content-type router.

### Requirement: Two specializations ship with the proxy

**Reason**: The GA4 and Matomo adapters are deleted with the capability.
**Migration**: None. Neither name resolves, and a configuration naming one fails at startup.

### Requirement: A specialization is path-agnostic

**Reason**: Selection no longer exists, so path-agnostic selection has nothing to describe.
**Migration**: None.

### Requirement: The specialization owns the decode, scan, and encode loop

**Reason**: The decode, scan, and encode loop is deleted. A body reaches the scanner through
the content-type router instead.
**Migration**: A form-encoded or JSON body is scanned as structured content where the
content-type router recognises it, and as plain text otherwise.

### Requirement: The scan handle scans one field value at a time

**Reason**: The per-field scan handle is deleted. It cost one scanner-pool round trip per
field, which does not survive the move to an engine that scans a batch of units.
**Migration**: None. Structured bodies are scanned in one pass that carries a key path per
fragment.

### Requirement: Nested encodings are decoded recursively

**Reason**: Recursive decoding belonged to the specialization adapters.
**Migration**: A nested encoding inside a field value is scanned as raw text.

### Requirement: Recursion is bounded

**Reason**: The bound guarded recursion that no longer happens.
**Migration**: None.

### Requirement: Field allowlists live in code

**Reason**: The GA4 and Matomo field allowlists are deleted with their adapters.
**Migration**: Every field of a recognised structured body is scanned. There is no allowlist.

### Requirement: Operator-acknowledged channels are not redacted

**Reason**: The exemption applied to named GA4 and Matomo fields that no longer exist.
**Migration**: A field previously exempt is now scanned and redacted like any other. An
operator who needs it left alone must exclude the route or the direction from scanning.

### Requirement: The specialization replaces query and body scanning only

**Reason**: There is no specialization to replace query and body scanning.
**Migration**: None. The URL path, the query, the body, and the request headers all follow
the default scan configuration.

### Requirement: A decode failure falls back to raw scanning

**Reason**: There is no decoder, so there is no decode failure to fall back from.
**Migration**: None.

### Requirement: An unsupported content type falls through silently

**Reason**: Content-type handling is the router's alone.
**Migration**: None.

### Requirement: A specialization failure is logged at a bounded rate and always counted

**Reason**: The failure category no longer exists, and
`voidwall_specialization_errors_total` is removed with it.
**Migration**: Remove any alert or dashboard panel that queries
`voidwall_specialization_errors_total`.
