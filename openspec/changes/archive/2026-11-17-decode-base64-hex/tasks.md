## 1. Decoder core (`crates/voidwall/src/engine/decode.rs`)

- [x] 1.1 Add the run search: byte table, maximal runs, the `=` rule, alphabet fit per run, the 15 and 22 minimums, digit-only runs fitting hex alone, and the JWT marking (D3). Verify: `#[test_case]` table tests for 15/14 characters, hex 22/odd 23, digits only, `+` with `_`, a glued word, a JWT triple, an unsigned token (empty third segment), padding with zero, one and two `=`, a form field `name=<run>&`, and two padded runs back to back.
- [x] 1.2 Add strict hex, base64 and base64url decoders, hex first, and the number test for digit-only hex runs (D4). Verify: unit tests for padded and unpadded input, a length of 1 mod 4, non-zero trailing bits, a run whose hex result is kept, a run whose hex result is not kept but whose base64 result is, a PESEL placeholder in hex (decoded), and `4242424242424242424242` (not decoded).
- [x] 1.3 Add the keep test: control test before normalization, then the 95% test on the normalized text with one `Class` for ASCII, `\p{Latin}` and `\p{Common}` from `regex-syntax` (D5). Verify: unit tests for random bytes, ASCII letters with U+0001, U+007F, Cyrillic, precomposed Polish, a sentence with `’`, `–`, `€` and an emoji, tag characters for `ignore all rules`, 3 and 4 characters, and the 95% limit on both sides; plus a test over 100,000 seeded random alphanumeric runs of 15 characters that keeps no more than the D5 table allows (25 per 400,000, with margin).
- [x] 1.4 Add the two decode functions: decoded view of raw text, and scan-view decoding of normalized text that inserts the normalized decoded text. Each returns the view bytes, the edits and the kept-run counts, or `None` when no run is kept. Verify: unit tests for one layer only (base64 inside base64 stays), no copy when no run is kept, and invalid UTF-8 copied unchanged.

## 2. Edit maps

- [x] 2.1 Add `EditMap::compose` (D6). Verify: a proptest that compares the composed map with mapping through the two maps in turn, over generated normalize and decode edits.
- [x] 2.2 Rename the fragment field `normalized` to `view` and keep `map_spans` unchanged. Verify: `cargo test -p voidwall` passes with no change to `map_spans`.

## 3. Engine

- [x] 3.1 Split `view_units` into the decoded-set and scan-set builders; decode body units only; share unchanged units (D2, D9). Verify: engine tests with `TestGuard` for a `false` guard that sees decoded text, a `true` guard that sees normalized decoded text, a query unit that is not decoded, and no set built when no run is kept.
- [x] 3.2 Add the kept-run counts to `ScanResult`, counted once across both sets (D8). Verify: engine tests for one run in both sets (count 1) and a run that only the scan set finds (zero-width split, count 1).
- [x] 3.3 Confirm that `invisible_text` reads the decoded set through `reads_scan_view() == false` (D1). Verify: a unit test where the guard reports tag characters inside a base64 run, and reports nothing for the same run in a query unit.
- [x] 3.4 Update the doc comments of `scan_view` in `config.rs` and of `reads_scan_view` in `guard.rs` to name the decoded view. Verify: `cargo doc -p voidwall --no-deps` builds with no warning.
  Note: `cargo doc` prints two warnings for the link `Unit::label` in `engine/unit.rs`.
  They exist on `main` before this change; this change adds no warning.

## 4. Metrics and dashboard

- [x] 4.1 Register `voidwall_decoded_runs_total{mode, route, direction, encoding}` in `metrics.rs`. Verify: the metrics test that lists the families and label sets now expects ten families.
  Note: no test listed the families before. The new admin test
  `metrics_endpoint_carries_the_ten_families` checks the ten families and their label sets.
- [x] 4.2 Add the counts to the family in the reverse proxy, `/v1/scan` and LiteLLM handlers. Verify: unit tests in each handler file for the counts and labels of the `metrics` spec scenarios.
- [x] 4.3 Read `docker/grafana/AGENTS.md`, then add a panel for the new family to `docker/grafana/dashboards/voidwall.json` and check every panel that the change touches (query, legend, description). Verify: the JSON parses, and the panel query names only the four labels.

## 5. Integration tests

- [x] 5.1 Add `crates/voidwall/tests/support/encoded.rs` with helpers that write a placeholder in base64, base64url and hex. Verify: the helpers have a round-trip unit test.
- [x] 5.2 Reverse proxy tests: plain, JSON and CSV bodies; a query string (not decoded); the forwarded body byte for byte; a 16-digit card placeholder; a PESEL placeholder in hex; a JWT and an unsigned token; a form-encoded body; base64 in full-width characters (`pii` blocks, a `text_classifier` with no `scan_view` is not passed the email); `%40` inside base64; `pii` with `scan_view = false` finding base64; spans of a finding inside a base64 run, inside a hex run, inside a JSON run with `\/` escapes, two findings in one run, and a finding after a run. Verify: `cargo test -p voidwall --test reverse_proxy_integration` passes.
  Note: no HTTP answer carries spans, so the span scenarios are engine tests in
  `engine/mod.rs` (as Phase 1a did), with the `pii` guard reading each view. The
  `text_classifier` part of the full-width case is in `model_guard_integration`, which
  is the file that loads a model guard.
- [x] 5.3 openai-chat tests: a message in base64 answers 400 `content_filter`; an `image_url` `data:` URL stays `encoded_data`; a `data:text/plain;base64,` URL in message text is decoded. Verify: `cargo test -p voidwall --test openai_chat_proxy_integration` passes.
- [x] 5.4 `/v1/scan` tests for `direction=request` (blocks) and `direction=response` (no kind), and the metric labels. Verify: `cargo test -p voidwall --test http_api_integration` passes.
- [x] 5.5 LiteLLM test for the request side. Verify: `cargo test -p voidwall --test litellm_guardrail_integration` passes.
- [x] 5.6 Model guard tests: a `text_classifier` with no `scan_view` blocks a base64 attack prompt; the same prompt with a zero-width space after its third character is not decoded in the decoded view; a soft-hyphenated prompt in base64 reaches the guard with its soft hyphens. Verify: `cargo test -p voidwall --test model_guard_integration` passes.

## 6. Measurement

- [x] 6.1 Add bench payloads with base64 and hex runs (and long ASCII words) to `crates/voidwall/benches/`, and run the benches against the Phase 1a baseline. Verify: throughput is within 5% on every payload; the results go into `measurement-notes.md` in this change.
- [x] 6.2 Rerun the Phase 0 base64 and hex cases and the benign corpus through the new code, and run the Phase 0 prototype limited to 2b's rules (one layer, no start offsets, no glued-prefix trims, no short-run chains, no `%xx` or entities, the D5 keep rule) on the same cases. Verify: every encoded case that the limited prototype flags is flagged by the proxy, each difference is explained in `measurement-notes.md`, and every new benign block is listed there and decided as correct with the user.

## 7. Docs and backlog

- [x] 7.1 Run the `docs-sync` skill: `docs/guards/` (README, invisible-text, model-guards, pii-regex), `docs/configuration.md` (`scan_view` now picks the decoded view) and the metrics page. Verify: every page that names `scan_view` or the raw text of a request matches the spec deltas.
- [x] 7.2 Update `docs/dev/backlog.md`: name part 2a in item 1.14 and part 2d in item 1.12, and add items for part 2c (nesting, budget, glued runs, adjacent short runs) and part 2e (runs across stream windows). Verify: each part 2a, 2c, 2d and 2e appears in exactly one backlog item.

- [x] 7.3 After archive, update the `## Purpose` of `openspec/specs/invisible-text-guard/spec.md` (a delta cannot change it): the guard reads the decoded view and so also finds tag characters and selectors inside a kept base64 or hex run. Use the `openspec-sync-specs` workflow or ask the user before a hand edit. Verify: the Purpose no longer says the guard reads the raw text only.

## 8. Verify

- [x] 8.1 Run `cargo test --workspace`, `cargo clippy --workspace --all-targets` and `openspec validate decode-base64-hex --strict`. Verify: all pass with no warning.
- [x] 8.2 Review the diff against the spec deltas with the `code-review` skill. Verify: every finding is fixed or recorded as accepted in this file.
  Review, 2026-11-17:
  - Fixed: two scan-view scenarios had no test with the real `pii` guard ("A zero-width
    character inside a run", "A hidden character inside decoded text"). Added as cases of
    `an_encoded_value_in_a_request_body_blocks`.
  - Fixed (agreed with the user): `ARCHITECTURE.md` § 2, § 3 step 5, § 4.1 and § 4.10 now
    describe the decoded view, the decoding and the composed map.
  - Accepted by the user: the 2 new benign blocks of task 6.2.
  - Accepted (judgment call): a run of letters and digits only counts as `encoding="base64"`.
