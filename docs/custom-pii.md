# User-Defined PII — Worked Example

Operator-supplied regex definitions under `[[pii.custom]]` run alongside the
built-in detectors. Matches surface with the operator's chosen `label` in
metrics (`pii_kind` counter), block responses (`kinds` list), the
`X-PII-Detected` header, and `[LABEL]`-style redaction output.

See `openspec/specs/custom-pii/spec.md` for the full specification.

## Example

Use `detect` to narrow built-in coverage to a known-good set, and
`[[pii.custom]]` to add organization-specific identifiers. The two fields are
independent — `detect`/`ignore` apply only to built-in kinds.

```toml
[pii]
countries = ["International", "Us"]
languages = ["En"]

# Built-in kinds to detect (closed set). Custom entries below run independently
# and are NOT controlled by this list.
detect = [
    "Email",
    "CreditCard",
    "UsSsn",
]

# User-defined entries. Labels must be unique, non-empty, and must not collide
# with any built-in PiiKind label (e.g. "EMAIL", "US_SSN").
[[pii.custom]]
label   = "EMPLOYEE_ID"
pattern = 'EMP-\d{6}'

[[pii.custom]]
label    = "PROJECT_CODE"
pattern  = '[A-Z]{3}-\d{3}'
keywords = ["project code", "proj id"]   # keyword-context mode
country  = "International"                # default
```

Alternative: use `ignore` to opt out of specific built-in kinds while still
using custom entries:

```toml
[pii]
countries = ["International", "Us"]
ignore = ["IpAddress"]

[[pii.custom]]
label   = "EMPLOYEE_ID"
pattern = 'EMP-\d{6}'
```

## `CUSTOM` is reserved

The literal `"Custom"` (the marker variant for user-defined PII) must **not**
appear in `detect` or `ignore`. User entries are enabled by their presence in
config — there is no on/off toggle via `detect`/`ignore`. Startup validation
rejects configs that list `"Custom"` in either field.

## Validation (at startup)

- `label` non-empty, unique across `[[pii.custom]]`, and non-colliding with
  any built-in `PiiKind` label (full namespace, independent of `detect`/`ignore`).
- `pattern` non-empty; regex compilation is enforced by the `pii` crate.
  Invalid regex fails fast with the offending entry's label in the error.
- Total entries capped at 64.
- Pattern dialect: must compile in both the `regex` crate and vectorscan —
  no backreferences or lookaround.
- `country` entries outside the scanner's enabled country set are silently
  dropped at build time (the entry stays in config but never matches).

## Keyword-context mode

When `keywords` is non-empty, a match requires one of the keywords to appear
just before the pattern (with a permissive separator). The reported span
covers only the value, not the keyword — redaction preserves the keyword
text. This is useful when the pattern alone would be too broad (e.g. a
three-letter prefix is too common to treat every occurrence as PII).
