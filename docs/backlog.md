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

False positives on benign prompts. Found on 2026-10-20 by running `Scanner::new()` over
`databricks/databricks-dolly-15k` (revision `bdd27f4d`; numbers are line indices of
`databricks-dolly-15k.jsonl`, from 0):

- `SWIFT_BIC`: 11 of 11 hits are false. The keyword `swift` matches the singer ("Taylor
  Swift released", where `released` passes as a BIC with country `AS`). The keyword `bic`
  matches inside "aerobic" ("aerobic respiration", "aerobic exercise"). Prompts 304, 1173,
  1358, 2616, 6182, 8382, 11973, 14248.
- `ES_DNI`: 13 hits on memory sizes in one JVM GC log (`20519977K`), prompt 10834.
- `IE_EIRCODE`: 7 of 7 false: "U19 side", "A52 road", "S26 runs", "T11 100m", "C40 went".
  Prompts 11, 3426, 6321, 6922, 13242, 13618.
- `GB_POSTCODE`: 4 of 4 false: FM call signs `W250AP` and `W297CO`, and "T20Is". Prompts 9839,
  12284.
- `IP_ADDRESS`: "e::" in "are:: 66" (prompt 4208) and the version `0.11.0.0` (prompt 4727).
- `DE_AT_CH_ADDRESS`: one span across a tab-separated table of dates, prompt 12404.
- `US_GB_CA_AU_NZ_IE_ZA_STREET`: "to address any possible exploit path", prompt 12081.
- `PERSON_NAME` fires on 34% of the prompts. In a sample of 25, 11 are not people:
  "St Louis", "Kennedy High", "Red List", "Harry Potter", "Asian Nations", "The Masters".

`IP_ADDRESS` validators accept almost anything. Found on 2026-10-20 while building
`voidwall_pii::validate_as` (stage 1 of `add-ml-pii-guard`). `IP_ADDRESS` is the only kind
whose patterns mix a real validator with one that accepts every value:

- The IPv4 pattern uses `ip_check`. It returns true for any text without a dot. With dots,
  it checks only that each part is a number from 0 to 255, not that there are four parts.
- The IPv6 pattern uses `Check::Any`: its expression alone decides.

The regex guard is safe today, because its expressions give the shape. A model span has no
guaranteed shape, so `validate_as([IpAddress], …)` accepts "hello", "12345", "::" and
"1.2.3.4.5". For that reason the default `[guards.pii_ml]` sets no `validate_as` for
`IP_ADDRESS` (see `openspec/changes/add-ml-pii-guard/design.md` D10 and Risks).

- Make `ip_check` strict: exactly four dot-separated decimal octets, each 0–255.
- Give the IPv6 pattern a real validator, for example a parse with `std::net::Ipv6Addr`.
- A parse does not fix the Dolly false positive "e::" above: `Ipv6Addr` accepts it.
- Both changes can change what the regex guard reports. Run the `voidwall-pii` tests and
  the AI4Privacy eval before and after.
- After the fix, decide whether the default `[guards.pii_ml]` validates `IP_ADDRESS` again.

Luhn validators accept any text with enough digits. Found on 2026-10-20 in the same work.
Five validators keep only the digits of their input, then check the count and the Luhn sum.
Anything else in the text is ignored:

| Validator | Kinds | Digits |
|---|---|---|
| `sin_check` | `CA_SIN` | 9 |
| `imei_check` | `IMEI` | 15 |
| `siren_luhn_check` | `FR_SIREN` | 9 |
| `siret_luhn_check` | `FR_SIRET` | 14 |
| `ohip_check` | `CA_OHIP` | 10 |

`za_luhn13_check` and `it_partita_iva_check` already require digits only. `luhn_check`
(`CREDIT_CARD`) was fixed on 2026-10-21, before stage 6 of `add-ml-pii-guard` shipped the
default config: it calls `grouped_luhn` in `crates/voidwall-pii/src/validators.rs`.

The regex guard is safe today, for the same reason as the IP case: its expressions give
the shape. A model span has none, so a span with words around a valid number passes
`validate_as` for any of the five kinds, and two numbers run together pass about one time
in ten. The default `[guards.pii_ml]` validates none of them.

- Make the five validators call `grouped_luhn`, with the separators of their kinds'
  expressions and their digit counts, and delete their five copies of the Luhn sum.
- The match set should not change, because every expression already gives that shape.
  Run the `voidwall-pii` tests and the AI4Privacy eval before and after.
- This is not the general fix. A future validator can still count only the digits. The
  general fix checks a span against the whole pattern: its expression must match the
  whole span, then its check must accept it. That changes the `guard-configuration` spec,
  so it needs a proposal. Consider it if a third case appears.

---

## 4. Documentation

- Document the offline FST build for `DictionaryDetector`: inputs, licences,
  normalization, and frequency handling.

