## Why

`/v1/scan` reports one `matches_count` over every guard, but `kinds` lists each kind
once. When two guards report the same kind for the same value, such as the regex `pii`
guard and the `pii_ml` model guard both reporting `PERSON_NAME` for one name, the count is
higher than the kind list suggests, and a caller cannot see why.

## What Changes

- `/v1/scan` returns a new top-level field `guards`: an array of objects, one for each
  guard that reported at least one finding, sorted by guard name.
- Each object holds `name` (the guard's configured name), `matches_count` (that guard's
  findings), and `kinds` (that guard's kinds, sorted, each kind once).
- A scan with no findings returns `guards` as an empty array. The field is always present.
- `detected`, `matches_count`, and `kinds` at the top level do not change.
- `docs/openapi.json` and the README example show the new field.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `http-api`: the `POST /v1/scan reports the detection` requirement gains the `guards`
  breakdown.

## Impact

- `crates/voidwall/src/http_api.rs`: `ScanResponse` and `build_scan_response`.
- `crates/voidwall/src/engine/finding.rs`: possibly a per-guard view over `ScanResult`.
- `docs/openapi.json`: regenerated.
- `README.md`: `/v1/scan` example output.
- Integration tests under `crates/voidwall/tests/`.
- The change is additive. A client that ignores unknown fields keeps working.
