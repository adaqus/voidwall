# Backlog — unbuilt work

This file holds the work that `docs/history/tasks-phases-1-20.md` left unchecked when the project moved to
OpenSpec. That file is the former `TASKS.md`.

Rules:

- A feature item here needs an OpenSpec change before the code. Use the
  `openspec-propose` workflow.
- A test, `pii`-crate, or documentation item does not. Take it directly.
- Nothing here has a spec under `openspec/specs/`. The specs describe built behaviour
  only.

The section numbers point back into the history file.

---

## 1. Unbuilt features

Each item needs an OpenSpec proposal first.

### 1.1 Reverse proxy TLS termination — history § 5.2

`crates/voidwall/src/tls.rs` is empty. `TlsConfig` (`config.rs:426`) parses and validates,
then nothing reads it.

- Build a `tokio_rustls::TlsAcceptor` from the configured certificate and key paths.
- Wrap the TCP listener with the acceptor when `reverse_proxy.tls.enabled` is true.

### 1.2 Forward proxy mode — history § 9.1, § 9.2

`crates/voidwall/src/forward_proxy.rs` is empty. `main.rs:122` logs
`forward proxy mode is enabled but not yet implemented`. `ForwardProxyConfig`
(`config.rs:311`) parses and validates.

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

### 1.3 Checksum validation toggle, eval only — history § 19.1 to § 19.3

Phase 19 is unchecked end to end. `PiiGuardConfig` has no `validate` field. `config.rs:28`
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

---

## 2. Test gaps

No proposal needed.

### 2.1 Cross-mode end-to-end tests — history § 12.1

- Start the binary with a test config. Drive every mode. Assert scan and block
  behaviour.
- Assert that config validation rejects every invalid case at startup.

### 2.2 Full load-test suite — history § 10.1

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

## 3. `pii` crate follow-ups — history § 17.1, § 17.2

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

- Evaluation documentation, once the roadmap's Model Evaluation Framework phase
  ships a replacement for the retired AI4Privacy harness.
  History § 18.4.
- Document the offline FST build for `DictionaryDetector`: inputs, licences,
  normalization, and frequency handling. History § 20.12.
- Note the `--validate` flag in a README or quick-start. There is no README yet.
  History § 14.4.

---

## Dropped as stale

History § 13.4 carried two unchecked rows:

- `HTTP API /v1/scan: returns user label in kinds`
- `HTTP API /v1/redact: replaces matched value with [USER_LABEL]`

Both said *deferred — Phase 8 HTTP API mode not yet implemented*. Phase 8 shipped. The
second row is now permanently unbuildable: `/v1/redact` was removed with the action
layer, and nothing rewrites a message.
`http_api.rs:140` states that custom labels surface with their configured `label`. The
`custom-pii` and `http-api` specs cover this behaviour.

History § 16.10 carried a *Demo page smoke test* gap. The demo page is gone: it existed
to render `GET /openapi.json` and call `GET /v1/info`, and both routes were removed with
it.
