## Context

See `proposal.md` — Why.

Three facts shape the approach:

1. `utoipa` and `tower-http` have exactly one user in the workspace each, both in
   `crates/voidwall/src/http_api.rs`. Nothing else imports them.
2. `build_openapi_spec` and its four helpers (`inject_known_pii_kinds`,
   `expand_supported_content_types`, `expand_content_map`, `encode_pointer_segment`) are
   private to `http_api.rs` and already produce the finished document as a `String`.
   Only the last hop — serving it from `ApiState` — is tied to the route.
3. The `demo` nginx service is the sole consumer of both deleted routes. It is also the
   only thing the permissive `CorsLayer` exists for; the comment at `http_api.rs:55`
   says so.

There is no CI pipeline in the repository, so a freshness check has to run inside
`cargo test`, not in a separate workflow step.

## Goals / Non-Goals

**Goals:**

- The public listener has exactly one route and one HTTP method.
- The OpenAPI document keeps its "cannot drift" property with no runtime route.
- Regenerating the document is one command a developer can discover from the test's
  failure message.

**Non-Goals:**

- Changing anything about how `POST /v1/scan` parses, scans, or answers.
- Adding authentication, rate limiting, or a route allowlist. The listener is still
  meant to sit behind a gateway.
- Touching the reverse proxy, the forward-proxy stub, or the admin listener.
- Serving the document from the admin listener instead. That would move the problem,
  not remove it.

## Decisions

### Keep generation, drop the route

The document is generated from the handler and the request and response types, so it
cannot drift. That property is worth more than the 85 lines it costs. The route is what
costs a public endpoint and a cross-origin layer, so only the route goes.

Alternatives rejected:

- *Delete the generation and describe the route in prose.* Two fewer dependencies, but a
  human then keeps the contract true by remembering to. With `utoipa` already vendored
  and working, the saving does not pay for the drift risk.
- *Hand-write `docs/openapi.json`.* Same drift risk, plus the hand-written document is
  harder to review than the annotations it replaces.
- *Move the route to the admin listener.* The admin listener is loopback by default, so
  the document would be no easier to reach than a file in the repository, and the admin
  surface would grow a route that is not an operational probe.

### The freshness test is an env-guarded unit test

A `#[cfg(test)]` test in `http_api.rs` calls `build_openapi_spec`, reads
`$CARGO_MANIFEST_DIR/../../docs/openapi.json`, and compares. This keeps every
generation helper private — no `pub` is added to make the document reachable from an
integration test or a second binary.

When `UPDATE_OPENAPI` is set in the environment, the test writes the file instead of
comparing, and its failure message names that command. This is the common Rust snapshot
idiom, and it needs no new binary, no new CLI flag, and no build script.

Alternatives rejected:

- *A `--emit-openapi` flag on the `voidwall` binary.* Adds permanent operator-visible
  CLI surface to solve a developer-workflow problem.
- *A `build.rs` that writes the file.* A build script cannot easily call code from the
  crate it is building.
- *A second binary, as with `echo-server`.* More build output and a second place for the
  generation code to be reached from.

### The generator is `#[cfg(test)]`, not merely private

With the route gone, `ApiDoc` and the five generator functions have no caller outside
the freshness test, so a normal build reports every one of them as dead code and
`cargo clippy --all-targets` fails. They carry `#[cfg(test)]` instead, which states the
truth — the document is generated at test time — and keeps the generator out of the
shipped binary.

This does not weaken the "cannot drift" property. The `#[utoipa::path]` annotation on
`scan_handler` still compiles in every build, so an annotation that stops compiling is
caught by an ordinary `cargo check`.

Alternative rejected: *`#[allow(dead_code)]` on the chain.* It keeps the generator in
the release binary and silences a signal that is telling the truth.

### Compare parsed values, not strings

The test compares `serde_json::Value` after parsing both sides, not the pretty-printed
strings. Whitespace, trailing newline, and key order then cannot cause a false failure,
and the checked-in file stays readable in a diff.

### Delete the demo rather than repair it

The demo page exists to render the deleted specification route and to call the deleted
info route. Its route picker already offers a single option. Repairing it means
hard-coding the kind list it used to fetch, which reintroduces by hand exactly the drift
the generated document avoids. The compose stack keeps `voidwall`, `echo-server`,
`prometheus`, and `grafana`.

### 404 needs no code

`axum` answers an unmatched path with 404 already. Deleting the two `.route(...)` calls
is the whole implementation; the integration tests prove the outcome rather than a
handler producing it. This matches how `/v1/redact` was retired.

## Risks / Trade-offs

- **A deployed client calls `/v1/info` or `/openapi.json` and starts getting 404.** →
  The proposal marks both **BREAKING**. The kind labels those callers wanted are in the
  `kinds` property description of `docs/openapi.json`, and the per-body answer is in the
  `kinds` array of a scan response.
- **A browser-based client loses cross-origin access to `POST /v1/scan`.** → Intended.
  A wildcard `Access-Control-Allow-Origin` on an unauthenticated listener let any page
  on the internet post bodies to it. Deployments that need browser access add the header
  at the gateway that supplies the authentication.
- **A developer changes a response type and forgets to regenerate.** → The test fails on
  the next `cargo test --workspace` and names the command that fixes it. With no CI, the
  test run is the only gate, so the failure message has to carry the instruction.
- **`docs/openapi.json` becomes a review artefact that shows up in unrelated diffs.** →
  Accepted. It changes only when the API surface changes, which is the point of having
  it.
- **`utoipa` stays for a document nobody fetches at runtime.** → Accepted, and it is the
  reason `tower-http` can still leave. The dependency cost is a build-time cost only;
  the `#[utoipa::path]` annotation is what makes the document unable to drift.

## Open Questions

- The `## Purpose` paragraph in `openspec/specs/http-api/spec.md` still describes
  redaction, left over from the change that removed it. A delta cannot fix a Purpose, and
  `CLAUDE.md` forbids hand-editing `openspec/specs/`. It stays stale until the project
  decides how to correct it. Answering this does not change these specs, this approach,
  or the tasks.
