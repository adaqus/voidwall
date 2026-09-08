## Context

See `proposal.md` — Why. The state that shapes the approach:

- `crates/voidwall/src/specialization/` holds a `Specialization` trait, two adapters, a
  dispatch layer, and `merge_with_default_scan`. Its only consumers are `reverse_proxy.rs`
  and `http_api.rs`, both of which branch on `Option<&'static dyn Specialization>` before
  the default scan path.
- `crates/voidwall/src/structured/` (`json.rs`, `csv.rs`, `OwnedContextFragment`) has **zero**
  references to the specialization module — verified. It carries the per-fragment key path
  that later work depends on.
- `config.rs` declares ten `Deserialize` structs and uses **no** `#[serde(flatten)]` —
  verified. Nothing blocks `deny_unknown_fields` on any of them.
- The Grafana dashboard at `docker/grafana/dashboards/voidwall.json` has **zero** references
  to the `specialization` label, and each of its four Voidwall panels aggregates with
  `sum(...)` or `sum(...) by (pii_kind)` — verified. No panel breaks when the label goes.
- `X-PII-Specialization` appears in no file under `openspec/specs/`. It exists in
  `http_api.rs` and the OpenAPI annotations only, which is why no delta names it as a
  requirement and the `http-api` delta covers it in a migration note instead.

## Goals / Non-Goals

**Goals:**

- Remove every specialization surface in one change, so no half-removed state exists between
  the deletion and the engine work that follows.
- Turn the removed `specialization` config key into a loud startup failure rather than a
  silent no-op.
- Leave `crates/voidwall/src/structured/` byte-identical.

**Non-Goals:**

- Any replacement for GA4 or Matomo decoding. Wire-format decoders for LLM APIs are later
  work and share no code with what this change deletes.
- Introducing the `Unit`, `Guard`, or `Engine` types. This change only removes the third
  scan granularity that would complicate them.
- Changing how the content-type router classifies a body. A form-encoded body is treated
  exactly as it is treated today on a route with no specialization.

## Decisions

### D1 — `deny_unknown_fields` on all ten config structs, not on `Route` alone

A route-only application would make the retired `specialization` key fail loudly and stop
there. Applying it to every struct is chosen instead.

- **Why:** a configuration that catches a typo in `[reverse_proxy.routes]` but ignores one in
  `[pii]` is harder to reason about than either extreme, and the proxy already refuses to
  start on invalid configuration — silent key-dropping is the outlier in that policy, not the
  rule.
- **Alternative rejected — `Route` only:** smaller blast radius, but leaves the same class of
  silent failure everywhere else, and would need revisiting the first time another key is
  retired.
- **Alternative rejected — keep `specialization: Option<String>` purely to reject it:** loud
  in exactly the case that matters and nothing else, but keeps a dead field in the struct
  with no removal date, and the deletion is the point of the change.
- **Cost, accepted:** a configuration that is valid today and carries a stray, misspelled, or
  forward-compatible key now fails at startup. Ten TOML files in this repository must
  re-validate.

### D2 — The `?specialization=` query parameter becomes ignored, not rejected

After removal, `POST /v1/scan?specialization=plausible` is answered `200` where it was
answered `400`. Axum's `Query` extractor ignores a parameter the target struct does not
declare, and that behaviour is left alone.

- **Why:** rejecting unknown query parameters is a cross-cutting HTTP policy affecting every
  endpoint and every parameter. It has nothing to do with retiring the analytics adapters,
  and adding it here would be the second piece of scope creep in a deletion change.
- **Trade-off:** the config surface becomes strict (D1) while the query surface stays lax.
  These are deliberately different: a configuration file is written once by an operator and
  read at startup, where a loud failure is cheap and correct; a query string arrives on every
  request from clients the proxy does not control, where rejecting unknown parameters breaks
  callers for no security gain.
- The `400` → `200` flip is stated in the `http-api` delta's migration note so it is not
  discovered in review.

### D3 — Drop the `specialization` metric label here, not in the change that follows

Removing the label changes `ActionContext` and the arity of `inc_detection` and
`inc_redacted`. The engine work that follows changes `action::execute`'s signature again, so
`ActionContext` changes shape in two consecutive changes.

- **Alternative rejected — hardcode the label to `"none"` and drop it later:** avoids one
  signature change, but leaves a metric label with exactly one possible value across a whole
  change, and every sample carrying it. A dead label is worse than a second signature edit.

### D4 — `merge_with_default_scan` is deleted, not kept

It lives in `specialization/mod.rs` and is called at two sites in `reverse_proxy.rs`, both
inside the specialization branch. With no specialization there is nothing to merge with the
default scan, so it has no remaining caller.

### D5 — Three requirements are replaced rather than edited

`openspec validate` refuses a `MODIFIED` block that drops a scenario, because archive would
silently lose it. Three requirements lose a scenario that describes retired behaviour, so
each is expressed as `REMOVED` plus `ADDED` under a new name:

| Capability | From | To |
|---|---|---|
| `configuration` | Reverse proxy routes are validated | Reverse proxy route identity and upstream are validated |
| `metrics` | The proxy publishes seven application metrics | The proxy publishes six application metrics |
| `metrics` | Label values are drawn from fixed sets | Metric label values are drawn from fixed sets |
| `security` | A PII value never reaches a log | A log line never carries a PII value |

The `security` rename is the one worth flagging: it is a foundational PII-safety requirement
and its normative text does not change at all. It is renamed only because its second scenario
covers a specialization decode failure and the tooling offers no way to drop a scenario in
place. The new name matches the wording already in `AGENTS.md`, and the replacement scenario
covers the scan-failure log path, which survives.

`security`'s metric requirement keeps its name: it loses one word from a list and no
scenario, so a plain `MODIFIED` covers it.

## Risks / Trade-offs

- **A deployed configuration carrying any stray key stops starting** → The failure is loud
  and names the key, which is the intent of D1. Call it out as **BREAKING** in the proposal
  and re-validate all ten repository TOML files as an explicit task.
- **A client still sending `?specialization=` silently loses adapter-quality detection** →
  The body is still scanned, so this is a detection-quality regression, not a bypass. A
  form-encoded GA4 body is scanned as raw text where it was previously scanned per field with
  a key path, which loses keyword-context signal on some fields. Accepted: the traffic shape
  is out of scope for the product.
- **Removing a label changes Prometheus series identity** → Old and new series coexist during
  a scrape-history window. Every dashboard panel aggregates the label away, so this is
  invisible there. An operator with a custom query grouping by `specialization` sees that
  group disappear; the `metrics` delta's migration note says so.
- **Deleting the three GA4 and Matomo load-test scenarios removes form-encoded and JSON
  coverage** → The `structured_scanning` scenario already covers structured bodies through
  the default path, which is the path that remains. No coverage of a surviving code path is
  lost.
- **A partial removal would leave the tree uncompilable in confusing ways** → The specialization
  branch is threaded through both handlers, so the deletion is done as one pass, with
  `cargo check --workspace` as the gate rather than a per-file checkpoint.

## Migration Plan

Operator-facing, in order:

1. Remove `specialization` from every reverse-proxy route.
2. Remove any other key the schema does not define; startup now names the first one it finds.
3. Stop sending `?specialization=` and stop reading `X-PII-Specialization`.
4. Remove any dashboard panel or alert querying `voidwall_specialization_errors_total`, and
   drop `specialization` from any custom query that groups or filters on it.

Rollback is the revert of a single commit. No data, schema, or on-disk state changes, so a
revert restores the previous behaviour exactly.
