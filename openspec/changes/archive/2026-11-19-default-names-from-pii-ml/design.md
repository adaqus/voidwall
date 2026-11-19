## Context

`[builtin_guards.pii]` already takes `ignore`, a list of `PiiKind`s the scanner does not
build. With `PersonName` in it, the dictionary detector is not built and the
keyword-context name rules are off. `docker/anythingllm-to-lmstudio.toml` already uses
it. `crates/voidwall/tests/image_config.rs` keeps the guard sections of
`docker/voidwall.toml` and `docker/voidwall-image.toml` equal, so both files change
together. `docker/smoke-test.sh` runs on every image the release workflow builds.

## Goals / Non-Goals

**Goals:**

- The default config reports `PERSON_NAME` from the `pii_ml` guard only.
- The release smoke test proves both sides: the reported false positive passes, and a
  real name is still found.

**Non-Goals:**

- No change to the dictionary detector or its name data.
- No change to the `pii_ml` labels, thresholds, or surface.
- No config comment about where names come from. The user docs say it.

## Decisions

- **Config, not code.** `ignore = ["PersonName"]` uses an existing, tested field. The
  alternatives were a calendar-word stoplist in the dictionary detector or a rebuild of
  its name data. Both keep the regex guard's other homograph false positives, and both
  lose some true names too.
- **The check is in the smoke test.** The two scans need the `pii_ml` model, which only
  the image holds, so they cannot run in `cargo test`. The name text is fictional test
  data that `pii_ml` reports as `PERSON_NAME`; it is confirmed against the image before
  the script is final.
- **The name scan reads the kinds of each guard.** The `/v1/scan` `guards` array gives
  the kinds each guard reported. The check requires `PERSON_NAME` in the `pii_ml` entry
  and no `PERSON_NAME` in the `pii` entry. The top-level `kinds` list cannot show this,
  because the old config also puts `PERSON_NAME` there.
- **The dictionary bug goes to the backlog.** Operators who turn regex names back on
  still meet it. The failing unit test written during the investigation is removed,
  because a spec must describe built behavior.

## Risks / Trade-offs

- [Names in a URL path or query string are not detected by default] → Accepted. An
  operator can widen the `pii_ml` surface or remove the `ignore`.
- [An operator who turns off `pii_ml` loses all name detection] → The user docs state it
  (`docs-sync`).
- [Name recall per language is not measured; the regex guard is better on DE, FR, ES
  and NL documents across all kinds] → Accepted for now. On Gretel, `pii_ml` alone finds
  more names than the regex guard.
- [The smoke-test name scan depends on a model verdict] → The text is a plain full name
  in an English sentence. If a later model stops reporting it, the release check fails
  and shows it.
- [The `Every Monday at 8am` scan also depends on a model verdict: the spec states that
  `pii_ml` does not report this text] → It is what the reported false positive needs.
  If a later model reports it as `PERSON_NAME`, the release check fails and shows the
  same false positive coming back.

## Migration Plan

An operator who mounts their own config is not affected. An operator on the default
config who wants the regex names back removes `ignore = ["PersonName"]` from
`[builtin_guards.pii]`.
