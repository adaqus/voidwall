## Why

The public Fly deployment served three unrelated things off one image: the marketing
site (the Rust binary's `ServeDir` fallback), the `/demo` playground (Fly `[[statics]]`),
and the public `/v1/*` API. A marketing copy edit redeployed the PII engine, and an engine
change redeployed the marketing site.

Phase 21 of the AI-guardrails pivot separates them. The marketing site moves to its own
`voidwall-website` repo and is served by nginx; the public proxy deployment is retired
outright — no public API, no public demo. That removes the only reason `fly-rate-limit`
exists: it protects an unauthenticated public endpoint that no longer exists.

## What Changes

- **BREAKING** — the `fly-rate-limit` cargo feature is removed, together with
  `crates/proxy/src/rate_limit.rs` and the `tower_governor` / `governor` dependencies.
  Nothing consumes it: it was enabled only by `docker/Dockerfile.fly`, which this change
  deletes.
- The `fly-landing` cargo feature and the `ServeDir("/srv/landing")` catch-all
  `fallback_service` are removed. This closes a live drift rather than changing behavior:
  `http-api` already requires the listener to serve four routes and "SHALL NOT" serve
  more, which the catch-all had been contradicting unspecced.
- Every Fly artifact is deleted: `fly.toml`, `fly.io/`, `docker/Dockerfile.fly`, and
  `docker/Dockerfile.fly.dockerignore`.
- `docker/landing/` moves to the `voidwall-website` repo with its history, and the
  `update-landing-piis` skill moves with it.
- `docker/demo/` stays as a local development tool, unchanged. It never depended on
  `Dockerfile.fly` — the compose path mounts files directly.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `http-api`: removes the requirement "Per-IP rate limiting is an opt-in build feature"
  and both its scenarios. No other requirement changes — the four-route requirement
  already describes the post-change behavior.

## Impact

**Code**

- `crates/proxy/src/rate_limit.rs` — deleted, with its `#[cfg(test)]` unit test.
- `crates/proxy/src/lib.rs` — the gated `pub mod rate_limit;` is dropped.
- `crates/proxy/src/http_api.rs` — both `#[cfg]` blocks and the `ServeDir` import go;
  `router` stops needing rebinding.
- `crates/proxy/Cargo.toml` — the `fly-rate-limit` and `fly-landing` features and the
  optional `tower_governor` / `governor` dependencies go. `tower-http` keeps
  `features = ["cors"]`; only its `fs` feature is dropped.

**Dependencies**

`tower_governor` and `governor` leave the tree. `Cargo.lock` is regenerated.

**Deployment**

The Fly app slot `voidwall` is reused: the nginx landing image replaces the proxy image,
so the anycast IP and the `voidwall.io` certificate survive and no DNS change is needed.
There is no `fly apps destroy` and no window where the site is dark. `/v1/*` and `/demo`
stop resolving on `voidwall.io`.

**Docs**

`ARCHITECTURE.md` drops `rate_limit` from its module list. `AGENTS.md` drops "the landing
page" from the OpenSpec exclusion list, since the page now lives in another repo.

**Not affected**

`docker/demo/`, the `demo` service in `docker/docker-compose.yml`, `docker/ctl`, CORS
(which is unconditional), and every scanning, action, or metrics behavior.
