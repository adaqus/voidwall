## 1. Trim the router and its handlers

- [x] 1.1 In `crates/voidwall/src/http_api.rs` `router()`, delete the `/v1/info` and
      `/openapi.json` routes and the whole `CorsLayer` block with its comment. Verify:
      `cargo check -p voidwall` compiles and reports the handlers as unused.
- [x] 1.2 Delete `info_handler` with its `#[utoipa::path]` block and doc comment, the
      `InfoResponse` struct, `kind_labels`, `language_labels`, and `openapi_handler`.
      Verify: `cargo clippy -p voidwall --all-targets` reports no dead-code warning.
- [x] 1.3 Remove the `openapi_spec` field from `ApiState` and the `build_openapi_spec`
      call from `build_state`. Verify: `cargo check -p voidwall`.
- [x] 1.4 Narrow `ApiDoc` to `paths(scan_handler)` and
      `components(schemas(ScanResponse, ErrorResponse))`, and reword its
      `info(description = ...)` so it describes one route. Verify:
      `cargo test -p voidwall --lib http_api` passes.
- [x] 1.5 Delete the imports the removals orphan: `axum::body::Body`, `HeaderValue`,
      `routing::get`, and `tower_http::cors::{Any, CorsLayer}`. Verify:
      `cargo clippy -p voidwall --all-targets` is warning-free.

## 2. Publish the OpenAPI document as a repository file

- [x] 2.1 Add an env-guarded freshness test to the `#[cfg(test)] mod tests` block in
      `http_api.rs`: call `build_openapi_spec`, read
      `$CARGO_MANIFEST_DIR/../../docs/openapi.json`, and compare the two as parsed
      `serde_json::Value`s, not as strings. When `UPDATE_OPENAPI` is set in the
      environment, write the file instead of comparing. The failure message must name
      `UPDATE_OPENAPI=1 cargo test -p voidwall --lib openapi`. Verify: the test fails
      before 2.2 and passes after it.
- [x] 2.2 Generate the file with
      `UPDATE_OPENAPI=1 cargo test -p voidwall --lib openapi`, then check
      `docs/openapi.json` in. Verify: the document holds exactly one path,
      `/v1/scan`, with a `post` operation, and no `/v1/info` key.
- [x] 2.3 Confirm the existing `openapi_spec_contains_examples_and_kind_labels` unit
      test still covers `build_openapi_spec`. Verify:
      `cargo test -p voidwall --lib http_api` passes with both tests.

## 3. Move the route tests to 404 proofs

- [x] 3.1 In `crates/voidwall/tests/http_api_integration.rs`, delete
      `info_endpoint_returns_kinds_and_languages` and `openapi_json_returns_valid_spec`,
      and the `/openapi.json tests` section header that only they sat under. Verify:
      `cargo test -p voidwall --test http_api_integration` compiles and passes.
- [x] 3.2 Add `retired_info_route_returns_404` and
      `retired_openapi_route_returns_404`, shaped like the existing
      `retired_redact_route_returns_404`. Verify: both assert 404 and pass.
- [x] 3.3 Add a test that sends `POST /v1/scan` with an `Origin` header and asserts the
      response carries no `access-control-allow-origin` header. Verify: the test passes
      and fails if the `CorsLayer` is restored.

## 4. Drop the unused dependency

- [x] 4.1 Remove `tower-http` from `crates/voidwall/Cargo.toml`. Verify:
      `cargo tree -p voidwall -i tower-http` reports the package is not in the graph,
      and `cargo check --workspace` passes.

## 5. Remove the demo service

- [x] 5.1 Delete the `demo` service block and its `8088:80` port mapping from
      `docker/docker-compose.yml`, and delete the `docker/demo/` directory. Verify:
      `docker compose -f docker/docker-compose.yml config` parses and lists only
      `voidwall`, `echo-server`, `prometheus`, and `grafana`.
- [x] 5.2 Remove the `Demo: http://localhost:8088` line from `docker/ctl` `cmd_start`.
      Verify: `docker/ctl start` prints five service lines and no demo line.

## 6. Update the documentation

- [x] 6.1 Rewrite `docs/api-docs.md`: drop the Swagger UI sections, the CORS paragraph,
      and the production note about port 8088; keep the stack-start steps and the
      service table with the demo row removed and the HTTP API row naming
      `POST /v1/scan` only; point readers at `docs/openapi.json` and say how to
      regenerate it. Verify: no occurrence of `8088`, `Swagger`, `v1/info`, or
      `openapi.json` as a URL remains in the file.
- [x] 6.2 Add one sentence to `ARCHITECTURE.md` § 4.7 stating that the listener sends no
      CORS header either, for the same reason it holds no credential check. Verify: the
      section reads consistently with the `security` spec delta.
- [x] 6.3 Move the "2.3 Demo page smoke test" entry in `docs/backlog.md` to the
      "Dropped as stale" section with a one-line reason. Verify: the numbered test-gap
      list has no gap in its numbering.

## 7. Verify the whole change

- [x] 7.1 Run `cargo test --workspace` and
      `cargo clippy --workspace --all-targets`. Verify: both are clean, warnings
      treated as errors.
- [x] 7.2 Run `docker/ctl start`, then confirm end to end: `POST /v1/scan` with a
      sample body answers 200 with a `kinds` array, `GET /v1/info` and
      `GET /openapi.json` answer 404, `http://localhost:8088` does not resolve, and
      `http://localhost:9090/metrics` still serves the counters. Verify: every check
      holds.
- [x] 7.3 Run `openspec validate trim-http-api-to-scan --strict`. Verify: it passes.
- [x] 7.4 Review the diff against the spec deltas with the `code-review` skill, then
      against `ARCHITECTURE.md`. Verify: no finding is left unaddressed.
