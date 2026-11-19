## 1. Default configs

- [x] 1.1 Remove `"PERSON_NAME"` from the `labels` of `[guards.pii_ml]` and the
  `PERSON_NAME = 0.4` line from `[guards.pii_ml.thresholds]` in `docker/voidwall.toml`,
  `docker/voidwall-image.toml` and `docker/anythingllm-to-lmstudio.toml`, with no comment
  in their place. Keep `ignore = ["PersonName"]` in `[builtin_guards.pii]`. Check:
  `grep -n PERSON_NAME docker/*.toml` prints nothing, and `cargo test -p voidwall --test
  image_config` passes, so the guard sections of the two default configs are still equal.
- [x] 1.2 Run `voidwall --validate` on each of the three files in the image. Check: all
  three pass.

## 2. Smoke test

- [x] 2.1 In `docker/smoke-test.sh`, turn the full-name check around: the `/v1/scan` of
  the full-name text fails when any `guards` entry holds `PERSON_NAME`, or when the answer
  is not a scan result. Keep the weekday check. Update the header comment and the `pass`
  message. Add a `/v1/scan` of a text with a fictional email address that fails unless
  the `guards` entry named `pii_ml` holds `EMAIL_ADDRESS`.
  Check: `bash -n docker/smoke-test.sh` passes.
- [x] 2.2 Build a local image from `ghcr.io/adaqus/voidwall:0.8.0` with the new
  `docker/voidwall-image.toml` copied to `/etc/voidwall/voidwall.toml`, and run
  `docker/smoke-test.sh` on it. Check: every step passes.
- [x] 2.3 Build a local image from `ghcr.io/adaqus/voidwall:0.8.0` with
  `git show HEAD:docker/voidwall-image.toml` (the config before this change) copied to
  `/etc/voidwall/voidwall.toml`, and run the full-name scan on it. Check: it reports
  `PERSON_NAME` from `pii_ml` there, so the new check fails on the old default.

## 3. Verification and docs

- [x] 3.1 Run `cargo test --workspace` and `cargo clippy --workspace --all-targets`.
  Check: both pass with no warnings.
- [x] 3.2 Run the `docs-sync` workflow for the default config change. Check: every
  `docs/` page that describes the default guards or `PERSON_NAME` says that no guard
  reports names by default, and how an operator turns them back on. At least
  `docs/quick-start.md`, `docs/guards/README.md`, `docs/guards/pii-regex.md`,
  `docs/recipes/README.md` and `docs/recipes/anythingllm.md`; no example output shows
  `PERSON_NAME` from a default config.
- [x] 3.3 In the calendar-word entry of `docs/dev/backlog.md`, add that since this change
  the default config also removes `PERSON_NAME` from the `pii_ml` labels. Check: the entry
  names no detected value from real traffic.
- [x] 3.4 Run `openspec validate default-no-person-name --strict`. Check: it passes.
