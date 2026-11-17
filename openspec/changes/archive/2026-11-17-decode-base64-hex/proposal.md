## Why

An LLM reads base64 and hex, but no Voidwall guard does. An instruction or a PII value
written in base64 or hex in a request body reaches the upstream unread. Phase 0 measured
that guards which read decoded text flag more Tier A injections and block less benign
obfuscated text. This change is part 2b of Phase 2 of the encoded-content plan; it comes
first among the Phase 2 parts.

## What Changes

- The engine decodes base64, base64url and hex runs in **request body units**. The URL
  path, the query string and header values are not decoded. Responses are not decoded.
- A run is a candidate when it has 15 or more base64 or base64url characters, or 22 or
  more hex characters of even length. Hex is tried first. A run of decimal digits only is
  decoded only as hex, and only when the result is a number (as the Phase 0 prototype
  does), so a PESEL or phone number written in hex is found. A run that is part of a
  JWT-shaped token is not decoded, so `JWT` keeps firing.
- A decoded run is kept only when its bytes are valid UTF-8, it holds no control
  character other than tab, line feed and carriage return, and its normalized text has
  more than 3 characters, 95% or more of them ASCII or of the Latin or Common script
  (punctuation, symbols, emoji). Otherwise the run stays as it is.
- A kept run is replaced in place by its decoded text. Only one layer is decoded: an
  encoded run inside decoded text is not decoded again. In the scan view, runs are found
  after normalization, so base64 written in tag or full-width characters is decoded
  there.
- **BREAKING**: a guard with `scan_view = false` no longer reads the raw text of a
  request. It reads a new **decoded view**: the raw text with its kept runs decoded, and
  no Unicode normalization. The shipped prompt-injection model (`text_classifier`,
  `scan_view` false by default) therefore reads decoded base64 and hex by default.
- The scan view (`scan_view = true`, the default of `pii` and `token_classifier` guards)
  is built in this order: normalize the raw text as Phase 1a does, find and decode runs
  in the result, then normalize each decoded text.
- **BREAKING**: the `invisible_text` guard reads the decoded view instead of the raw
  text, so tag characters and variation selectors hidden in base64 or hex are reported.
- A span of a finding inside a decoded run names the bytes of the whole encoded run in the
  raw message.
- The decoder limits are fixed in code. There is no new configuration field.
- New metric family (name and labels proposed in `design.md`) that counts decoded runs by
  encoding. The Grafana dashboard gets a panel for it.
- Not in this change: `%xx` and HTML-entity decoding in the engine (part 2a), nested
  encodings and lenient decoding of runs glued to a word (part 2c), responses (part 2d),
  streams (part 2e), start offsets and trims for a run glued to a word (part 2c), and the
  values that a decoder already skips as `encoded_data` (`image_url`, `input_audio`,
  `file_data`). A `data:` URL written in message text is decoded like any other run.

## Capabilities

### New Capabilities

- `encoded-content-decoding`: which request runs are decoded, which results are kept, the
  decoded view, the order in the scan view, spans, and the limits.

### Modified Capabilities

- `hidden-unicode-normalization`: the scan view now also holds decoded runs, a guard that
  does not read the scan view reads the decoded view instead of the raw text, and the
  fixed-order requirement defines the normalization rather than the whole scan view.
- `guard-configuration`: `scan_view = false` selects the decoded view, not the raw text.
- `invisible-text-guard`: the guard reads the decoded view of a request.
- `metrics`: one more application metric family.

## Impact

- Specs: `hidden-unicode-normalization` "The rules apply in a fixed order" now says that
  the scan view of a body also holds decoded runs, and that `invisible_text` reads the
  decoded view.
- Code: `crates/voidwall/src/engine/` (a new decoder module next to `scan_view.rs`, the
  unit sets in `mod.rs`, the guard trait), `crates/voidwall/src/engine/invisible_text.rs`,
  `crates/voidwall/src/config.rs` (docs of `scan_view` only), `crates/voidwall/src/metrics.rs`
  and the handlers that record metrics.
- `docker/grafana/dashboards/voidwall.json`: a panel for the new family.
- Docs: `docs/guards/`, `docs/configuration.md`, `docs/dev/backlog.md` (the parts 2a, 2c,
  2d and 2e).
- No new dependency. No change to `voidwall-pii`.
- The forwarded message never changes.
- Benign base64 or hex text in a request body can now block, when it decodes to text that
  a guard reports.
