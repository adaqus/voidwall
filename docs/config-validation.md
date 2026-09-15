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
| `[file]` | Config file could not be read from disk. |
| `[toml parse]` | File is not well-formed TOML. |
| `[schema]` | TOML parses but does not match the expected shape (missing field, unknown enum variant, wrong type). |
| `[semantic]` | `AppConfig::validate` rejected the config (e.g. duplicate `path_prefix`, invalid upstream URL, custom label collides with a built-in). |
| `[scanner build]` | Regex or vectorscan compilation failed. For `[[builtin_guards.pii.custom]]` entries the message cites the offending `label`. |

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
- TLS cert/key file *contents* (only that the path field is present)
- Upstream reachability
- Filesystem permissions on metric/log sinks

A successful `--validate` guarantees only that the config is well-formed,
semantically consistent, and that the scanner will build. Runtime binding
errors are surfaced at proxy startup.
