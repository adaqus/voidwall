## Why

Every reverse proxy upstream client is plain HTTP, so an `https://` upstream passes
validation and then fails with 502 (backlog 1.4). An AnythingLLM user who runs a hosted
model (OpenAI, OpenRouter) through the Generic OpenAI provider cannot put Voidwall in
front of it without an extra LiteLLM hop. Voidwall is about to be introduced to the
AnythingLLM community, so the hosted-model case must work.

## What Changes

- The reverse proxy originates TLS to an `https://` upstream. It verifies the server
  certificate against the system root store. Verification cannot be turned off.
- An `https://` upstream negotiates HTTP/2 through ALPN and falls back to HTTP/1.1. An
  `http://` upstream stays HTTP/1.1.
- New route key `upstream_ca_path`: a PEM bundle of extra CA certificates for that
  route's upstream. Its certificates are added to the system roots; they do not replace
  them.
- Validation rejects `upstream_ca_path` on an `http://` upstream. Validation rejects two
  routes that name the same upstream with different `upstream_ca_path` values, or with
  the key on one and not on the other.
- At startup, a CA bundle that is missing or does not parse stops the start before any
  data-plane listener binds. `--validate` does not open the file.
- A TLS failure with the upstream, a certificate that does not verify included, answers
  the 502 that a failed upstream connection answers today.
- The license allowlist (`deny.toml`, `about.toml`) adds ISC, which `rustls-webpki`,
  `untrusted`, and `ring` carry.
- The Odysseus integration is out of scope. Reverse proxy TLS termination (backlog 1.1)
  is out of scope.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `reverse-proxy`: the proxy originates TLS to an `https://` upstream, with HTTP/2 by
  ALPN and an optional per-route CA bundle; a TLS failure answers 502.
- `configuration`: the new route key `upstream_ca_path` and its validation; a CA bundle
  that fails to load stops the start; validate mode does not open it.

## Impact

- Code: `crates/voidwall/src/reverse_proxy.rs` (client type and builder),
  `crates/voidwall/src/config.rs` (route key and validation),
  `crates/voidwall/src/server.rs` (build the upstream clients before the listener binds).
- Dependencies: `hyper-rustls` with `rustls` on the `ring` provider and
  `rustls-native-certs`. Dev dependency `rcgen` for a test CA.
- License gate: ISC added to `deny.toml` and `about.toml`.
- Image: no change. It already installs `ca-certificates`.
- Docs: `docs/configuration.md`, `docs/recipes/README.md` and `docs/recipes/anythingllm.md`
  lose the plain-HTTP-only notice; the AnythingLLM recipe shows a hosted model.
  `ARCHITECTURE.md` § 7 and `docs/dev/backlog.md` item 1.4 are updated.
- Metrics: none added or changed.
