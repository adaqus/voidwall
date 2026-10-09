# Pre-flight Config Validation

The `voidwall` binary exposes a `--validate` flag that loads, schema-checks,
semantic-checks, and compiles the PII scanner for a given TOML config — all
without binding any sockets or spawning scanner threads. Use it in CI/CD to
catch bad configs before they reach production.

See `openspec/specs/configuration/spec.md` for the full specification.

```
voidwall --validate /etc/voidwall/config.toml
```

`--validate` and `--config` are mutually exclusive; exactly one must be
provided.

## Exit codes and diagnostics

| Exit | Meaning |
|------|---------|
| `0`  | Config is valid. A single `config OK: <path>` line is written to stdout. |
| `1`  | Validation failed. A single diagnostic line is written to stderr, prefixed with a bracketed category tag. |
| `2`  | Usage error (clap — e.g. both or neither of `--validate` / `--config`). |

Diagnostic categories:

| Tag | Stage that failed |
|-----|-------------------|
| `[file]` | Config file could not be read from disk, or a `[guards.*]` `model_path` / `tokenizer_path` names no file. The message carries the path that was expected. |
| `[toml parse]` | File is not well-formed TOML. |
| `[schema]` | TOML parses but does not match the expected shape (missing field, unknown enum variant, wrong type). An `adapter` the build does not ship lands here: the build fixes the set of adapter names, so the schema states it. |
| `[semantic]` | `AppConfig::validate` rejected the config (e.g. duplicate `path_prefix`, invalid upstream URL, custom label collides with a built-in, `reverse_proxy.tls.enabled` or `forward_proxy.tls.enabled` set to true while TLS is not built). Every model guard rule lands here too — see below. |
| `[scanner build]` | Regex or vectorscan compilation failed. For `[[builtin_guards.pii.custom]]` entries the message cites the offending `label`. |

## Model guard rules

A `[guards.<name>]` section builds a model guard that loads its model at startup.
`--validate` checks the rules below and that the artifact files exist; it does not
load a model. A model that fails to load (not ONNX, a tensor contract the adapter
does not accept, a tokenizer larger than the embedding table, a failed smoke
inference) stops the real start with a non-zero exit and an error naming the guard.

These each fail the start with the `[semantic]` category, naming the guard:

| Rule | Message |
|------|---------|
| A guard name outside ASCII `[a-zA-Z0-9_-]` | `guards: '<name>' holds '<c>'; a guard name may hold only a-z, A-Z, 0-9, '_', and '-'` |
| An empty guard name | `guards: a guard name must not be empty` |
| A guard name over 64 characters | `guards: '<name>' is <n> characters; the limit is 64` |
| A guard name the build reserves | `guards: '<name>' is a reserved built-in guard name` |
| An empty `labels` list | `guards.<name>.labels: must not be empty; a guard that declares no label can report nothing` |
| A label listed more than once | `guards.<name>.labels: duplicate label '<label>'; each label names one kind` |
| A `text_classifier` with other than one label | `guards.<name>.labels: holds <n> labels; text_classifier takes exactly one, naming class 1 of the model's two outputs` |
| `adapter = "text_multilabel_classifier"` | `guards.<name>.adapter: 'text_multilabel_classifier' is not built` |
| `threads = 0` | `guards.<name>.threads: must be >= 1` |
| An `overlap_tokens` above `max_tokens / 2` | `guards.<name>: overlap_tokens is <n>; it must be at most max_tokens / 2 = <bound>` |
| A `max_tokens` below 10 | `guards.<name>.max_tokens: is <n>; the minimum is 10` |
| A `thresholds` key absent from `labels` | `guards.<name>.thresholds: '<kind>' is absent from labels, so it names a kind this guard does not declare` |
| A threshold outside the adapter's range | `guards.<name>.thresholds: '<kind>' is <score>, outside the adapter's score range 0..=1` |
| A surface that disables every target | `guards.<name>.surface: every target is disabled, so the guard can never be called` |

A missing artifact carries `[file]` instead, and names the path:

```
guards.<name>.model_path: no file at '<path>'
```

A `labels` entry is **not** checked against a vocabulary of finding kinds: the
build has no closed set to check one against, so a label is whatever the
operator writes. Its *shape* is still checked — the list must be non-empty and
its entries distinct, and a `text_classifier` takes exactly one label. A label with no threshold is valid and reports nothing — that
absence is the only detection-layer off switch, which is why a threshold key
absent from `labels` is an error rather than a silently disabled kind.

Validation never reads, parses, or executes an artifact. It asks whether the
path is a file and nothing more; the tensor contract is checked when the guard
loads its model at startup.

## Pre-commit hook

Catches issues locally before the operator pushes. Install via
[pre-commit](https://pre-commit.com) or drop the script directly in
`.git/hooks/pre-commit`.

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: voidwall-validate
        name: voidwall --validate
        entry: voidwall --validate
        language: system
        files: ^config/voidwall\.toml$
        pass_filenames: true
```

Raw `.git/hooks/pre-commit` variant:

```bash
#!/usr/bin/env bash
set -euo pipefail

for f in $(git diff --cached --name-only --diff-filter=ACM); do
    case "$f" in
        config/voidwall.toml)
            voidwall --validate "$f"
            ;;
    esac
done
```

## What `--validate` does *not* check

Environment-specific preconditions are intentionally excluded — they depend
on the machine running the proxy, not on the config itself:

- Listen-address availability (a port being free right now)
- Model and tokenizer artifact *contents* (only that a file is at the path)
- Upstream reachability
- Filesystem permissions on metric/log sinks

A successful `--validate` guarantees only that the config is well-formed,
semantically consistent, and that the scanner will build. Runtime binding
errors are surfaced at proxy startup.
