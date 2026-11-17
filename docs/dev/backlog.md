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

### 1.6 A metric for the time Voidwall itself adds

`voidwall_request_duration_seconds` stops when the handler returns the response head. On a
reverse proxy route that time is mostly the upstream's: for a buffered reply, the whole
generation; for a hold-back stream, the generation up to the first released text. The
time Voidwall adds is hidden inside it, so no metric shows the cost of a guard.

- Add a histogram of the time each guard takes on one message, labelled by guard and the
  existing `mode`, `route`, and `direction`.
- Decide in the proposal whether a guard abandoned at a short-circuit records its time.

### 1.7 The REST API records no request duration

`openspec/specs/litellm-guardrail-api/spec.md` says the LiteLLM route records
`voidwall_request_duration_seconds` by the rules `/v1/scan` follows. No spec gives
`/v1/scan` such a rule, and no `http_api` handler records the histogram. Only the reverse
proxy does.

The proposal picks one:

- Record the histogram on `/v1/scan` and the LiteLLM route, with `mode="http_api"` and
  `route="global"`.
- Remove the histogram from the LiteLLM requirement.

### 1.8 Guardrail operations

No design yet.

- Model lifecycle and diagnostics
- Operational qualification
- Shadow mode

### 1.9 Ollama's own API streams pass unscanned

Ollama's own API (`/api/chat`, `/api/generate`) streams its answer by default, as
`application/x-ndjson`: one JSON object per line, each with a few tokens of text. The
type is not in `content_types`, so a generic route forwards the stream without a scan,
and personal data in the answer reaches the client. A request, and an answer with
`"stream": false`, are scanned. Tested with Ollama 0.40.16. Until this is built,
`docs/recipes/ollama.md` sends clients to the OpenAI-compatible API under `/v1`.

- Scan an NDJSON stream of Ollama's own API in hold-back or buffer mode, as an
  `openai-chat` route scans a Chat Completions stream.
- Decide in the proposal how a route selects this decoding, and what a block answers
  after the first byte.

### 1.10 Scan compressed response bodies

When response scan is on, the proxy sends `Accept-Encoding: identity` to the upstream.
A response body that is still compressed (a `Content-Encoding` other than `identity`),
and that the route would scan, is unscannable content: 422 under `fail_close`,
unscanned under `fail_open`. Found with
OpenAI, which compresses its JSON answers when the client asks for it.

- Decompress `gzip`, `br`, and `deflate` bodies, JSON and `text/event-stream`, and scan
  the decompressed text.
- Decide in the proposal: whether the client gets the compressed upstream bytes or the
  decompressed body, whether the body size limit applies to the decompressed size (a
  small compressed body can expand to a very large one), and which crates it adds.
- Then decide whether the proxy still sets `Accept-Encoding: identity`.

### 1.11 Escapes inside JSON that is nested in a string value

A tool call's `arguments` on a Chat Completions message is a JSON document inside a JSON
string. Voidwall scans it as one string. The OpenSpec change `decode-json-escapes` decodes
the escapes of the outer document only, so an escape of the inner document stays literal:
an e-mail address whose `@` is written as `\\u0040` inside `arguments` passes every guard
(measured 2026-11-16). The reader of the tool call decodes the inner document and sees the
address. It affects every string value that holds JSON, in both directions, on
`openai-chat` routes and on the LiteLLM route. In a stream, the inner escape can also be
split across deltas.

- Decide in the proposal which values are parsed as nested JSON: only the fields that
  the Chat Completions format defines as JSON (`function.arguments`), or any string value
  that parses as a JSON object or array.
- Decide what happens to a value that does not parse as JSON, and how deep the nesting
  goes.
- Phase 2 of the encoded-content plan (decode base64, hex and `%xx` runs) has the same
  nesting question; settle both together.

### 1.12 The scan view and the invisible text guard for responses

The OpenSpec change `normalize-hidden-unicode` builds the scan view for request units
only, and the `invisible_text` guard inspects requests only. A model's answer that hides
text in tag characters or variation selectors, or a value behind a soft hyphen, reaches
the client as it is.

- Normalize response-direction units, and let `invisible_text` inspect responses.
- In a stream, a tag run or a variation-selector run that is still open at the end of the
  scan window waits like the hold-back tail (agreed 2026-11-16).
- Decide in the proposal whether the `scan_view` defaults stay the same for responses.

### 1.13 Homoglyphs in the scan view

Phase 1b of the encoded-content plan. The OpenSpec change `normalize-hidden-unicode` does
not fold look-alike letters, so a word that mixes Latin with Cyrillic or Greek letters,
such as an e-mail address with a Cyrillic `а`, reaches the guards as written.

- Fold confusable letters in the scan view, for the guards that read it.
- Decide in the proposal which tokens are folded, so that ordinary Cyrillic and Greek text
  does not change. The Phase 0 prototype folded only tokens that mix scripts.

### 1.14 Hidden characters written as percent-encoding or HTML entities

The scan view of the OpenSpec change `normalize-hidden-unicode` runs before the regex
detectors decode percent-encoding and HTML entities (`decode_for_detection` in
`voidwall-pii`). A hidden character written as `%C2%AD` in a query string, or as `&shy;`
in a body, is decoded after the view was built, so it stays in the text the detectors
read (design D11). The model guards do not decode either form.

- Phase 2 of the encoded-content plan moves that decoding into the engine, in front of
  the scan view, so every guard that reads the view sees the decoded character.
- Then decide whether `decode_for_detection` keeps its own percent and entity step.

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
- `DE_AT_CH_ADDRESS`: one span across a tab-separated table of dates, prompt 12404.
- `US_GB_CA_AU_NZ_IE_ZA_STREET`: "to address any possible exploit path", prompt 12081.
- `PERSON_NAME` fires on 34% of the prompts. In a sample of 25, 11 are not people:
  "St Louis", "Kennedy High", "Red List", "Harry Potter", "Asian Nations", "The Masters".

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

The regex guard is safe today, because its expressions give the shape. A model span has
none, so a span with words around a valid number passes `validate_as` for any of the five
kinds, and two numbers run together pass about one time in ten. The default
`[guards.pii_ml]` validates none of them.

- Make the five validators call `grouped_luhn`, with the separators of their kinds'
  expressions and their digit counts, and delete their five copies of the Luhn sum.
- The match set should not change, because every expression already gives that shape.
  Run the `voidwall-pii` tests and the AI4Privacy eval before and after.
- This is not the general fix. A future validator can still count only the digits. The
  general fix checks a span against the whole pattern: its expression must match the
  whole span, then its check must accept it. That changes the `guard-configuration` spec,
  so it needs a proposal. Consider it if a third case appears.

`AZURE_AD_CLIENT_SECRET` is the most expensive secret pattern. Found on 2026-11-04 in the
benchmarks of the `add-secret-kinds` change (`benchmarks.md` in that change). Its
expression has no leading literal: the `Q~` marker sits at offset 4. One detector with only
this kind takes 18.8 µs on 10 KB of clean text; a pattern with a literal prefix takes about
5.3 µs. That is about 40% of the 22–27% that the secret kinds add to a clean-text scan.

- Replace the regex fallback with a small byte scanner in `HyperscanDetector`: find `Q~`,
  step back 4 bytes and check them, check that the byte before them is not a token
  character, then scan forward to the end of the run. Keep the current rules: 31 to 34
  tail characters, and a tail that does not end in `.`.
- Do not reuse the window method of `KeywordContextDetector`. Its window ends at the match
  end, so it cannot see that a run goes on, and it makes the value regex
  case-insensitive. Both would report values the current pattern rejects.
- The match set and the spans must not change, so that a future redaction cuts the same
  bytes. Add a differential test that runs the current regex and the new scanner over the
  same inputs and requires equal spans. Run the `voidwall-pii` tests before and after.
- Keep the scanner only if `secret_pattern_cost` and the `throughput_` groups show a gain.
  Run base and after back to back: one single run drifted by about 25%.

---

## 4. Documentation

- Document the offline FST build for `DictionaryDetector`: inputs, licences,
  normalization, and frequency handling.


---

## 5. Bugs

A bug fix that restores behaviour a spec already states needs no OpenSpec change. Take it
directly.

### 5.1 A scanned header value with a non-ASCII byte is not scanned

`push_scan_headers` (`crates/voidwall/src/reverse_proxy.rs`) builds a header unit only
when `HeaderValue::to_str` succeeds, and that fails on any byte outside printable ASCII.
The header is then dropped with no log line and no `on_error`, so every guard skips it.
The `guard-configuration` spec says that a named header's value is decoded into a unit in
both directions, with no exception. One non-ASCII byte in a scanned header hides the
rest of its value from detection. Found 2026-11-16 during the review of the OpenSpec
change `normalize-hidden-unicode`, by reading the code.

- Build the unit from the raw bytes, as for a body: the guards already read invalid
  UTF-8 with U+FFFD in its place.
- `headers.get` returns the first value only, so a second header line with the same name
  is not scanned either. Scan every value. Not tested yet.
- Add integration tests for a header value with a non-ASCII byte and for a repeated
  header, in both directions.
