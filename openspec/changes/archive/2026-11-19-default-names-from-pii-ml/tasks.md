## 1. Default config

- [x] 1.1 Add `ignore = ["PersonName"]` to `[builtin_guards.pii]` in `docker/voidwall.toml`
  and `docker/voidwall-image.toml`, with no new comment. Check: `cargo test -p voidwall
  --test image_config` passes, so the two guard sections are still equal.

## 2. Smoke test

- [x] 2.1 In `docker/smoke-test.sh`, add a `/v1/scan` of `Every Monday at 8am` that fails
  when `kinds` holds `PERSON_NAME`, and a `/v1/scan` of a sentence with a fictional full
  name that fails unless the `guards` entry named `pii_ml` holds `PERSON_NAME` and no
  entry named `pii` holds `PERSON_NAME`. Update the header comment.
  Check: `bash -n docker/smoke-test.sh` passes.
- [x] 2.2 Build a local image from `ghcr.io/adaqus/voidwall:0.8.0` with the new
  `docker/voidwall-image.toml` copied to `/etc/voidwall/voidwall.toml`, and run
  `docker/smoke-test.sh` on it. Check: every step passes.
- [x] 2.3 Run the two new scans on `ghcr.io/adaqus/voidwall:0.8.0` with its own config.
  Check: the `Every Monday at 8am` scan fails there, so the check catches the false
  positive.

## 3. Dictionary detector follow-up

- [x] 3.1 Remove the `Every Monday at 8am` case added to `not_detected` in
  `crates/voidwall-pii/src/dictionary_detector.rs`. Check: `git diff
  crates/voidwall-pii` is empty and `cargo test -p voidwall-pii` passes.
- [x] 3.2 Add the calendar-word false positive to section 3 of `docs/dev/backlog.md`:
  the cause (a given-name form beside a surname form), the scope found on 2026-11-18
  (English weekdays and months, German bare calendar nouns), and that the default config
  no longer runs regex names. Check: the entry names no detected value from real traffic.

## 4. Verification and docs

- [x] 4.1 Run `cargo test --workspace` and `cargo clippy --workspace --all-targets`.
  Check: both pass with no warnings.
- [x] 4.2 Run the `docs-sync` workflow for the default config change. Check: every
  `docs/` page that describes the default guards or `PERSON_NAME` says that only
  `pii_ml` reports names by default.
- [x] 4.3 Run `openspec validate default-names-from-pii-ml --strict`. Check: it passes.
