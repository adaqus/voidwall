# Backlog — unbuilt work

This file holds unbuilt work.

Rules:

- A feature item here needs an OpenSpec change before the code. Use the
  `openspec-propose` workflow.
- A test, `pii`-crate, or documentation item does not. Take it directly.
- Nothing here has a spec under `openspec/specs/`. The specs describe built behaviour
  only.

---

## 1. Unbuilt features

Each item needs an OpenSpec proposal first.

### 1.1 Reverse proxy TLS termination

`crates/voidwall/src/tls.rs` is empty. `TlsConfig` parses, and validation rejects
`tls.enabled = true` in both proxy modes (`AppConfig::validate_tls_disabled`).

- Remove the rejection for `reverse_proxy.tls.enabled`.
- Build a `tokio_rustls::TlsAcceptor` from the configured certificate and key paths.
- Wrap the TCP listener with the acceptor when `reverse_proxy.tls.enabled` is true.

### 1.2 Forward proxy mode

`crates/voidwall/src/forward_proxy.rs` is empty. `ForwardProxyConfig` parses, and
validation rejects `forward_proxy.enabled = true` (`AppConfig::validate_forward_proxy_disabled`).

- Remove the rejection, and count the forward proxy again in the at-least-one-mode and
  port-conflict checks.

Handler:

- Parse the absolute-form URI from the request line.
- Run the reverse proxy pipeline: scan the request, forward, scan the response.
- Use one global `hyper-util` pooling client for every destination.
- Return 405 for CONNECT. There is no tunnel support.

TLS interception:

- Terminate the client TLS with the configured CA certificate and key.
- Generate a per-host certificate with `rcgen`, signed by that CA.
- Cache the generated certificates in a bounded LRU, keyed by hostname.
- Originate upstream TLS through `hyper-rustls`.
- Add integration tests for HTTP forwarding and the action pipeline.

### 1.3 Checksum validation toggle, eval only

`PiiGuardConfig` has no `validate` field. `config.rs:28`
`pub validate: Option<PathBuf>` is the unrelated `--validate <config>` CLI flag.

Warning: this switch turns off every detector validator. It exists for AI4Privacy
evaluation against fabricated ground truth. It inflates false positives.

- Add `validate: bool` to `ScannerBuilder`, default `true`.
- Thread it into `HyperscanDetector` and `KeywordContextDetector`. Gate every validator
  call site.
- Add `pub validate: bool` to `PiiGuardConfig`, default `true`. Chain it in
  `build_scanner`.
- Emit one `warn!` line at startup when the value is false.
- Unit-test both directions: a Luhn-failing card matches when the flag is off.

### 1.4 Reverse proxy upstream TLS

Every upstream client is `build_http()`, so an `https://` upstream passes validation and
fails at run time with 502. OpenAI, Azure OpenAI, and OpenRouter are not reachable, with
or without `format = "openai-chat"`.

- Build the upstream clients with a connector that originates TLS.

### 1.5 Duplicate JSON keys shift the flattened fragments

`structured::json::flatten_json` records the offset of every quoted string in the raw
bytes, then walks the parsed `Value`. A duplicate key keeps its first position in the
`Value` and takes the last value, so the raw bytes hold two strings more than the walk
consumes. Every fragment from the duplicate on reads the wrong bytes, and a value after
it can pass unscanned. An upstream that keeps the last value then sees what Voidwall
skipped. It affects every JSON body: `/v1/scan`, generic reverse proxy routes, the LiteLLM
route, and `format = "openai-chat"`. The leaf-count check of the Chat Completions decoder
does not catch it, because both walks count the same deduplicated `Value`.

The fix changes what a body with a duplicate key answers, so it needs a proposal. Two
ways:

- Reject a duplicate key as a body that does not parse.
- Recover offsets from a parser that sees every key, duplicates included.

---

## 2. Test gaps

No proposal needed.

### 2.1 Cross-mode end-to-end tests

- Start the binary with a test config. Drive every mode. Assert scan and block
  behaviour.
- Assert that config validation rejects every invalid case at startup.

### 2.2 Full load-test suite

- Compare the modes: reverse proxy, forward proxy, HTTP API. Blocked on § 1.2.
- Soak test: 30 minutes at 80% of the maximum rate. Watch memory, file descriptors, and
  p99 drift.

### 2.3 Redesign the k6 tests for model guards

- The dev stack that `docker/ctl start` runs has a `prompt_injection` model guard. The k6
  scripts in `crates/voidwall/benches/k6/` target `:8082` by default, so against that
  stack they measure model inference, not the proxy. Measured on 2026-10-07: a benign
  10 KB body takes 5.7 s alone, and up to 47 s with 24 requests in parallel, near k6's
  default 60 s timeout.
- `soak.js` expects 200, but its payload `benches/payloads/pii_medium.json` is blocked by
  the PII guard (403, kinds `EMAIL`, `US_ITIN`, `US_SSN`). This was so before the model
  guard was added.
- Decide which stack each script targets, which guards it runs, and what status each
  payload expects.

---

## 3. `pii` crate follow-ups

Read `crates/voidwall-pii/AGENTS.md` first. These came out of the Italian support review.

Correctness:

- English keywords for `ItPartitaIva` and `ItPostalCode` carry the wrong language tag.
- The `ItPartitaIva` keyword alternation includes a bare branch that is not scoped to a
  country.

Cleanup:

- `it_postal_check` duplicates `fr_postal_check`, `de_postal_check`, `at_postal_check`,
  and `ch_postal_check`.
- The Italian phone keyword alternation is duplicated verbatim.
- The ~50-branch English phone keyword alternation now has 11 verbatim copies. See the
  keyword detector Vectorscan size limit before adding a twelfth.
- `it_codice_fiscale_check` allocates a `String` it does not need.
- The `b.len() == 13` IT-prefix guard in `it_partita_iva_check` is redundant.

---

## 4. Documentation

- Document the offline FST build for `DictionaryDetector`: inputs, licences,
  normalization, and frequency handling.

