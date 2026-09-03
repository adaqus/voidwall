## REMOVED Requirements

### Requirement: Per-IP rate limiting is an opt-in build feature

**Reason**: The rate limit existed only to protect the public, unauthenticated demo
endpoint on Fly from a noisy visitor. Phase 21 retires the public proxy deployment —
`voidwall.io` becomes a static marketing site and `/v1/*` no longer resolves on it — so
the limit protects nothing. The build feature, its middleware, and its dependencies are
removed rather than left as dead opt-in surface.

**Migration**: None for self-hosted deployments: the feature was off by default and the
requirement itself stated that self-hosted builds sit behind their own gateway. An
operator who wants a per-IP limit applies it at that gateway. No configuration key, no
default behavior, and no served route changes — a default-features build behaves exactly
as it did.

A per-IP rate limit SHALL be available behind the `fly-rate-limit` cargo feature, off
by default. When enabled, it SHALL allow about 3 requests per second per client with a
burst of 3. It SHALL identify the client by the `Fly-Client-IP` header, and SHALL
reject a request with 429 when that header is missing or malformed. It SHALL sit inside
the CORS layer, so a preflight does not consume a token.

#### Scenario: Feature is off

- **WHEN** the proxy is built with default features
- **THEN** no rate limit applies

#### Scenario: Header is missing under the feature

- **WHEN** the feature is on and a request carries no `Fly-Client-IP` header
- **THEN** the request is rejected rather than bucketed with every other caller
