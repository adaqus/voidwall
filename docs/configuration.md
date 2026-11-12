# Configuration

Voidwall reads one TOML file at startup. It checks the whole file before it starts. A
file with an error stops the start, and the message names the key.

The image holds a config file at `/etc/voidwall/voidwall.toml`. To see it, run:

```bash
docker run --rm ghcr.io/adaqus/voidwall --print-config
```

The image file sets some keys to values other than the defaults below. For example, it
sets `admin.listen` to `0.0.0.0:9090`, so that the port can be published from the
container.

## Command line

| Flag | What it does |
|---|---|
| `--config <path>` | Load the file and run. The `VOIDWALL_CONFIG` environment variable gives the same path. The image sets it. |
| `--validate <path>` | Check the file and exit. Nothing starts. See [Validation](#validation). |
| `--print-config` | Print the file that `--config` names, unchanged, and exit. |
| `--version` | Print the version and exit. |

## How to read the tables

- A key is written as its full path. `<name>` is a name you choose. `[]` marks one entry
  of an array of tables, such as one `[[reverse_proxy.routes]]` entry.
- "Required" means that a section without the key does not start.
- "None" means that the key is optional and has no value when it is absent.
- Write the top-level keys before the first `[section]`. TOML gives a key that comes
  after a section header to that section, and Voidwall then rejects it as unknown.
- A key that Voidwall does not know stops the start.

## Top-level keys

| Key | Type | Default | Description |
|---|---|---|---|
| `max_body_size` | integer, bytes | `1048576` | The largest body that Voidwall reads for inspection. A larger body follows `on_error`. Under `fail_close` it gets 413. |
| `content_types` | array of strings | See the description | The content types whose body is inspected. A body of another type is not inspected, and this is not an error. Parameters such as `charset` are ignored. Default: `application/json`, `text/plain`, `text/html`, `application/x-www-form-urlencoded`, `text/csv`, `application/csv`, `text/x-csv`, `text/tab-separated-values`, `text/tsv`. A route with `format = "openai-chat"` ignores this list. |
| `on_error` | `"fail_close"` or `"fail_open"` | `"fail_close"` | What to do when a message cannot be inspected: it is too large, it does not parse, or a guard fails. `fail_close` blocks the message. `fail_open` forwards it. A detection always blocks, under both values. |
| `shutdown_timeout_secs` | integer, seconds | `30` | How long Voidwall waits for open requests to finish when it stops. |
| `upstream_timeout_secs` | integer, seconds, 1 to 3600 | `300` | How long one upstream exchange can take, from the request until the response headers arrive. When the response is scanned, this time also covers the read of its body. A longer exchange gets 504. |
| `stream_idle_timeout_secs` | integer, seconds, 1 to 3600 | `60` | On an `openai-chat` route, the longest gap between two reads of a stream. |
| `stream_holdback_bytes` | integer, bytes, at least 1 | `512` | On an `openai-chat` route in `holdback` mode, the newest stream text that Voidwall holds until a scan clears it. At most `max_body_size`. |
| `stream_context_bytes` | integer, bytes, at least 1 | `512` | How much text that was already sent each stream scan also covers. At most `max_body_size`. |
| `stream_scan_bytes` | integer, bytes, at least 1 | `256` | How much new stream text starts the next scan. At most `stream_holdback_bytes`. |

## Built-in guards

A built-in guard runs only when its section is in the file. A section that is in the file
is on, unless it sets `enabled = false`. A section that is off must still be correct.

### `[builtin_guards.pii]`

The regex PII guard. See [guards/pii-regex.md](guards/pii-regex.md).

| Key | Type | Default | Description |
|---|---|---|---|
| `builtin_guards.pii.enabled` | boolean | `true` | Turns the guard off without removing its section. |
| `builtin_guards.pii.countries` | array of strings | `[]`, all countries | The countries whose PII kinds the guard finds, such as `"Us"` or `"Pl"`. `"International"` holds the kinds that belong to no country, such as e-mail addresses. |
| `builtin_guards.pii.languages` | array of strings | `[]`, all languages | The languages of the keywords that some kinds need near a value, such as `"En"` or `"De"`. |
| `builtin_guards.pii.scanner_threads` | integer, at least 1 | See the description | The threads that run the scanner. Default: the CPU count, at most 4, on up to 8 CPUs. On more than 8 CPUs, half the CPU count. |
| `builtin_guards.pii.detect` | array of strings | None | Find only these kinds. Write a kind by its variant name, such as `"Email"` or `"UsSsn"`. You cannot set it together with `ignore`. |
| `builtin_guards.pii.ignore` | array of strings | None | Find every kind except these. The names are the same as for `detect`. |
| `builtin_guards.pii.surface.url_path` | boolean | `true` | Give the guard the URL path. |
| `builtin_guards.pii.surface.query_params` | boolean | `true` | Give the guard the query string. |
| `builtin_guards.pii.surface.body` | boolean | `true` | Give the guard the body. |
| `builtin_guards.pii.surface.headers` | boolean | `true` | Give the guard the header values that the route names in `headers`. |

At least one `surface` key must be `true`.

### `[[builtin_guards.pii.custom]]`

Your own PII rules, at most 64 of them. See
[guards/pii-regex.md](guards/pii-regex.md#example).

| Key | Type | Default | Description |
|---|---|---|---|
| `builtin_guards.pii.custom[].label` | string | Required | The kind that a match reports. It must be unique, and it must not be the label of a built-in kind. |
| `builtin_guards.pii.custom[].pattern` | string | Required | The regular expression of the value. It must not use backreferences or lookaround. |
| `builtin_guards.pii.custom[].keywords` | array of strings | `[]` | When the list has entries, a match needs one of them just before the value. |
| `builtin_guards.pii.custom[].country` | string | `"International"` | The country of the rule. The rule runs only when `countries` includes this country. |

### `[builtin_guards.hidden_context]`

Blocks a response that holds text the user must never see. See
[guards/hidden-context.md](guards/hidden-context.md).

| Key | Type | Default | Description |
|---|---|---|---|
| `builtin_guards.hidden_context.enabled` | boolean | `true` | Turns the guard off without removing its section. |
| `builtin_guards.hidden_context.markers` | array of strings | `[]` | The text to find, as plain text and without regard to case. At most 64 markers. When the guard is on, it needs at least 1. Each marker must not be empty, must not repeat another marker, and must fit in `stream_holdback_bytes`. |

This guard scans the response body only. It has no `surface` key.

## Model guards: `[guards.<name>]`

A guard that runs one ONNX model. `<name>` is the name of the guard in findings, logs, and
metrics. It holds only `a-z`, `A-Z`, `0-9`, `_`, and `-`, at most 64 characters, and it
must not be `pii` or `hidden_context`. See [guards/model-guards.md](guards/model-guards.md).

| Key | Type | Default | Description |
|---|---|---|---|
| `guards.<name>.adapter` | `"text_classifier"` or `"token_classifier"` | Required | How the model is run. A `text_classifier` gives one score for each input. A `token_classifier` finds spans. |
| `guards.<name>.model_path` | path | Required | The ONNX model file. |
| `guards.<name>.tokenizer_path` | path | Required | The Hugging Face `tokenizer.json` file. |
| `guards.<name>.config_path` | path | None | The model's `config.json`, which holds its labels. A `token_classifier` needs it. A `text_classifier` must not set it. |
| `guards.<name>.max_tokens` | integer, at least 10 | Required | The longest input the model gets, in tokens. A longer input is cut into windows that overlap. |
| `guards.<name>.overlap_tokens` | integer | `128`, at most `max_tokens / 2` | The tokens that two windows next to each other share. At most `max_tokens / 2`. |
| `guards.<name>.threads` | integer, at least 1 | See the description | The threads that run the model, one model session each. Default: the CPU count divided by the number of model guards, at least 1. |
| `guards.<name>.labels` | array of strings | Required | The kinds that the guard can report. The list must not be empty or repeat a label. A `text_classifier` takes exactly one label, for class 1 of the model. A `token_classifier` takes the model's own type names. |
| `guards.<name>.thresholds` | table, label to number | `{}` | The lowest score that gives a finding, for each label, from 0 to 1. A label with no threshold reports nothing. Each key must be in `labels`. |
| `guards.<name>.validate_as` | table, label to array of strings | None | `token_classifier` only. For each label, the PII kinds that a span must pass a check of, such as `PAYMENT_CARD = ["CREDIT_CARD"]`. A span that fails is dropped. |
| `guards.<name>.class` | `"pii"` | None | The class of the findings. `"pii"` also counts them in the `voidwall_pii_*` metrics. It does not change detection or the outcome. |
| `guards.<name>.surface.url_path` | boolean | `false` | Give the guard the URL path. |
| `guards.<name>.surface.query_params` | boolean | `false` | Give the guard the query string. |
| `guards.<name>.surface.body` | boolean | `true` | Give the guard the body. |
| `guards.<name>.surface.headers` | boolean | `false` | Give the guard the header values that the route names in `headers`. |

A model guard scans only the body by default, because each unit it gets costs one model
run. At least one `surface` key must be `true`.

## Reverse proxy: `[reverse_proxy]`

| Key | Type | Default | Description |
|---|---|---|---|
| `reverse_proxy.enabled` | boolean | `false` | Start the reverse proxy. |
| `reverse_proxy.listen` | string, address | `"0.0.0.0:8082"` | The address the reverse proxy listens on. |
| `reverse_proxy.request.scan` | boolean | `true` | Inspect requests. |
| `reverse_proxy.response.scan` | boolean | `true` | Inspect responses. When `true`, Voidwall sends each request to the upstream with `Accept-Encoding: identity`, in place of the client's value, because it cannot scan a compressed body. A compressed response body that the route would scan is content that Voidwall cannot inspect, and it follows `on_error`. |

At least one of `reverse_proxy.enabled` and `http_api.enabled` must be `true`.

### `[[reverse_proxy.routes]]`

A request goes to the route whose `path_prefix` is the longest prefix of its path. A
request that matches no route gets 404.

| Key | Type | Default | Description |
|---|---|---|---|
| `reverse_proxy.routes[].path_prefix` | string | Required | The path prefix of the route. Two routes must not have the same prefix. |
| `reverse_proxy.routes[].upstream` | string, URL | Required | The server that gets the request, such as `http://ollama:11434` or `https://api.openai.com`. See [HTTPS upstreams](#https-upstreams). |
| `reverse_proxy.routes[].upstream_ca_path` | string, path | None | A PEM file of CA certificates that the `https://` upstream can chain to. They are added to the system roots. Only an `https://` upstream can set it. Two routes with the same `upstream` must set the same value, or both leave it out. |
| `reverse_proxy.routes[].guards` | array of strings | None, all enabled guards | The guards that run on this route. `[]` runs none, and the traffic passes without inspection. Each name must be an enabled guard. |
| `reverse_proxy.routes[].headers` | array of strings | `[]` | The header names whose values are inspected, in both directions. A header that is not in the list is never inspected. |
| `reverse_proxy.routes[].format` | `"openai-chat"` | None | Decode the bodies as OpenAI Chat Completions, and answer in the OpenAI error shape. Without it, a body is inspected by its content type. |
| `reverse_proxy.routes[].stream` | `"holdback"` or `"buffer"` | `"holdback"` | How a route with `format = "openai-chat"` scans a stream. `holdback` sends the stream while it runs, and holds the newest text until a scan clears it. `buffer` reads the whole stream before it sends any of it. Only a route with `format = "openai-chat"` can set it. |

### HTTPS upstreams

Voidwall connects to an `https://` upstream over TLS. It verifies the certificate and the
host name of the upstream. It trusts the system root certificates. The image has the
Debian `ca-certificates` package, so a public provider, such as OpenAI or OpenRouter,
needs no more setup. You cannot turn verification off.

If the upstream has a certificate from a private CA, such as a company gateway, set
`upstream_ca_path` on its routes. Mount the PEM file into the container. Voidwall reads
the file at startup. If the file is missing or holds no certificate, Voidwall does not
start. `--validate` does not read the file.

Voidwall offers HTTP/2 and HTTP/1.1, and uses the version that the upstream selects. An
`http://` upstream gets HTTP/1.1.

A TLS failure, such as a certificate that does not verify, gets the same 502 as an
upstream that cannot be reached. The log tells the cause.

The `SSL_CERT_FILE` and `SSL_CERT_DIR` variables replace the system roots. They do not
add to them. To add a CA, use `upstream_ca_path`.

## HTTP API: `[http_api]`

See [api-reference.md](api-reference.md).

| Key | Type | Default | Description |
|---|---|---|---|
| `http_api.enabled` | boolean | `false` | Start the HTTP API. |
| `http_api.listen` | string, address | `"0.0.0.0:8083"` | The address the HTTP API listens on. |
| `http_api.scan.enabled` | boolean | `true` | Serve `POST /v1/scan`. |
| `http_api.litellm.enabled` | boolean | `true` | Serve `POST /beta/litellm_basic_guardrail_api`. |

When `http_api.enabled` is `true`, at least one route must be on. A route that is off
answers 404.

## Admin server: `[admin]`

The admin server always runs.

| Key | Type | Default | Description |
|---|---|---|---|
| `admin.listen` | string, address | `"127.0.0.1:9090"` | The address the admin server listens on. It must not be the address of another listener. |
| `admin.metrics_path` | string | `"/metrics"` | The path of the Prometheus metrics. |
| `admin.health_path` | string | `"/healthz"` | The path of the liveness check. |
| `admin.ready_path` | string | `"/readyz"` | The path of the readiness check. It answers 503 until every guard has loaded. |

## Keys of features that are not built

The forward proxy and TLS are not built. These keys parse. Each `enabled = true` stops
the start.

| Key | Type | Default | Description |
|---|---|---|---|
| `forward_proxy.enabled` | boolean | `false` | Must be `false`. |
| `forward_proxy.listen` | string, address | `"0.0.0.0:8084"` | Not used. |
| `forward_proxy.request.scan` | boolean | `true` | Not used. |
| `forward_proxy.response.scan` | boolean | `true` | Not used. |
| `forward_proxy.tls.enabled` | boolean | `false` | Must be `false`. |
| `forward_proxy.tls.cert_path` | string | None | Not used. |
| `forward_proxy.tls.key_path` | string | None | Not used. |
| `reverse_proxy.tls.enabled` | boolean | `false` | Must be `false`. Terminate TLS in front of Voidwall. |
| `reverse_proxy.tls.cert_path` | string | None | Not used. |
| `reverse_proxy.tls.key_path` | string | None | Not used. |

## Validation

`voidwall --validate <path>` checks a config file and exits. It binds no port, starts no
thread, and loads no model. It does compile the PII scanner. Use it in CI, before you
deploy a file.

```bash
docker run --rm -v "$PWD/voidwall.toml:/etc/voidwall/voidwall.toml:ro" \
    ghcr.io/adaqus/voidwall --validate /etc/voidwall/voidwall.toml
```

You cannot give `--validate` and `--config` together on the command line. A path from
`VOIDWALL_CONFIG` does not count: `--validate` checks its own path, so it works in the
image.

See `openspec/specs/configuration/spec.md` for the full specification.

### Exit codes and messages

| Exit | Meaning |
|------|---------|
| `0`  | The file is correct. Voidwall writes `config OK: <path>` to stdout. |
| `1`  | The file is not correct. Voidwall writes one message to stderr. The message starts with a category tag. |
| `2`  | The command line is not correct, for example both `--validate` and `--config`, or neither. |

| Tag | What failed |
|-----|-------------|
| `[file]` | Voidwall cannot read the file, or a `model_path`, `tokenizer_path`, or `config_path` names no file. The message gives the path. |
| `[toml parse]` | The file is not correct TOML. |
| `[schema]` | The TOML does not have the expected shape: a key is missing or unknown, or a value has the wrong type or is not in its set. Examples: an unknown `adapter`, `format`, `stream`, or `class`; a `stream_idle_timeout_secs` or `upstream_timeout_secs` outside 1 to 3600; a `stream_*_bytes` key below 1. |
| `[semantic]` | The keys have the correct shape but break a rule: two routes with the same `path_prefix`, an upstream that is not a URL, an `upstream_ca_path` that is empty or on an `http://` upstream, two routes of one upstream with different `upstream_ca_path` values, a custom label that is a built-in label, an `enabled = true` for TLS or the forward proxy, a `stream` without `format = "openai-chat"`, a stream key above its bound, or a model guard rule from the next table. |
| `[scanner build]` | A pattern does not compile. For a `[[builtin_guards.pii.custom]]` entry, the message gives its `label`. |

### Model guard rules

`--validate` checks these rules and that each file exists. It does not load a model. A
model that fails to load stops the real start, and the message names the guard. A model
fails to load, for example, when the file is not ONNX or its inputs and outputs do not
fit the adapter.

Each rule fails with the `[semantic]` tag and names the guard:

| Rule | Message |
|------|---------|
| A guard name outside ASCII `[a-zA-Z0-9_-]` | `guards: '<name>' holds '<c>'; a guard name may hold only a-z, A-Z, 0-9, '_', and '-'` |
| An empty guard name | `guards: a guard name must not be empty` |
| A guard name over 64 characters | `guards: '<name>' is <n> characters; the limit is 64` |
| A guard name of a built-in guard | `guards: '<name>' is a reserved built-in guard name` |
| An empty `labels` list | `guards.<name>.labels: must not be empty; a guard that declares no label can report nothing` |
| A label in the list two times | `guards.<name>.labels: duplicate label '<label>'; each label names one kind` |
| A `text_classifier` with other than one label | `guards.<name>.labels: holds <n> labels; text_classifier takes exactly one, naming class 1 of the model's two outputs` |
| `adapter = "text_multilabel_classifier"` | `guards.<name>.adapter: 'text_multilabel_classifier' is not built` |
| A `token_classifier` without `config_path` | `guards.<name>.config_path: token_classifier needs the model's config.json, the source of its id2label` |
| A `text_classifier` with `config_path` | `guards.<name>.config_path: text_classifier reads no config.json; only token_classifier takes one` |
| A `text_classifier` with `validate_as`, also an empty table | `guards.<name>.validate_as: text_classifier reports no span to validate; only token_classifier takes validate_as` |
| A `validate_as` key that is not in `labels` | `guards.<name>.validate_as: '<label>' is absent from labels, so it names a kind this guard does not declare` |
| An empty `validate_as` list | `guards.<name>.validate_as.<label>: must not be empty; a span validated as no kind always fails` |
| A `validate_as` name that is not a PII kind | `guards.<name>.validate_as.<label>: '<kind>' is not a PII kind` |
| A `validate_as` kind with no check that can reject a value | `guards.<name>.validate_as.<label>: '<kind>' has no validator that can reject a value, so it would accept every span` |
| `threads = 0` | `guards.<name>.threads: must be >= 1` |
| An `overlap_tokens` above `max_tokens / 2` | `guards.<name>: overlap_tokens is <n>; it must be at most max_tokens / 2 = <bound>` |
| A `max_tokens` below 10 | `guards.<name>.max_tokens: is <n>; the minimum is 10` |
| A `thresholds` key that is not in `labels` | `guards.<name>.thresholds: '<kind>' is absent from labels, so it names a kind this guard does not declare` |
| A threshold outside 0 to 1 | `guards.<name>.thresholds: '<kind>' is <score>, outside the adapter's score range 0..=1` |
| A surface with every key `false` | `guards.<name>.surface: every target is disabled, so the guard can never be called` |

A missing file has the `[file]` tag instead, and gives the path:

```
guards.<name>.model_path: no file at '<path>'
```

Validation does not compare a label with a list of known kinds, because there is no such
list: a label is the text you write. It also does not compare a `token_classifier` label
with the types in the model's `config.json`. A label that the model does not have loads,
and reports nothing.

### Pre-commit hook

To check the file before each commit, use [pre-commit](https://pre-commit.com), or put a
script in `.git/hooks/pre-commit`.

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

`.git/hooks/pre-commit`:

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

### What validation does not check

These depend on the machine, not on the file:

- Whether a listen port is free
- The contents of a model or tokenizer file, only that the file exists
- Whether an upstream answers
- File system permissions

A file that passes `--validate` has the correct shape and keeps every rule, and its PII
scanner builds. Voidwall reports an error at bind time or load time when it starts.
