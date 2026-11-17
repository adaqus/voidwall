# Invisible Text Guard

The `invisible_text` guard blocks a request that carries text hidden in Unicode tag
characters or in variation selectors. A person does not see this text, but a model can
read it, so it can carry a hidden instruction ("ASCII smuggling", "emoji smuggling"). The
guard does not decode the tags or selectors. It blocks the request, so no other guard,
such as a prompt injection model that reads the decoded view, gets the hidden
instruction.

See `openspec/specs/invisible-text-guard/spec.md` for the full specification.

## Example

The config of the image declares the guard with an empty section:

```toml
[builtin_guards.invisible_text]
```

The section has one key, `enabled`. See
[configuration.md](../configuration.md#builtin_guardsinvisible_text). A `surface` key, a
`scan_view` key, or any other key fails the start.

## What it reports

The guard reports a unit that holds one of these:

- A Unicode tag character, U+E0000 to U+E007F, that is not part of an emoji flag. An
  emoji flag is U+1F3F4 (waving black flag), then one to six tags for ASCII letters or
  digits, then the cancel tag U+E007F, such as the flag of England or of California.
- A variation selector, U+FE00 to U+FE0F or U+E0100 to U+E01EF, that does not come
  directly after a letter, a number, a punctuation mark, or a symbol. For example, a
  selector after another selector, after a mark, after an invisible character, or at the
  start of the text.

These pass, because they are normal text:

- Emoji flags, such as the subdivision flags of England, Scotland, and Wales.
- An emoji with its presentation selector, such as ❤️, and keycaps, such as 1️⃣.
- A CJK character with an ideographic variation selector.
- Other invisible characters, such as a zero-width joiner in an emoji, a zero-width
  non-joiner in Persian text, or a soft hyphen in German text. The
  [scan view](README.md#the-scan-view) handles these for the guards that read it.

The guard reports the kind `INVISIBLE_TEXT`, at most one finding per unit, with no span.
`/v1/scan` counts a body that holds tags and selectors as `matches_count` 1.

A finding blocks the request as any detection does: a generic route answers the fixed
403 with `"kinds": ["INVISIBLE_TEXT"]`, and an `openai-chat` route answers the fixed 400
with `code` `content_filter`. The hidden characters, and the text they stand for, never
appear in a log line, a metric, or an answer.

## What it scans

The guard scans every unit of a request: the body, the URL path, the query string, and
each header value that the route names. It reads the
[decoded view](README.md#encoded-runs-and-the-decoded-view), never the scan view: the raw
text with the base64 and hex runs of a body decoded. So it also finds tags and selectors
that are written inside a base64 or hex run of a body. A run in the URL path, the query
string, or a header value is not decoded. In a JSON, CSV, or TSV body it reads each value
on its own, after JSON escapes are decoded, so a tag written as `󠁩` is found. It
does not read keys or column names.

| Entry point | Scanned |
|---|---|
| Reverse proxy | Every request unit, on a route that runs the guard. |
| `POST /v1/scan` | The posted body, with no `direction` or `?direction=request`. |
| LiteLLM route | The payload with `input_type` `request`. |

The guard never scans a response. No setting changes this.

Because the guard reads every unit kind, a route that runs it builds the URL path, the
query string, and the named header units of every request.

## A route with its own guard list

A route that names no guard runs every enabled guard. A route with `guards = [...]` runs
this guard only when the list holds `invisible_text`. A route that lists only
`prompt_injection` lets text in tags and selectors reach the injection model as it is.
Add `invisible_text` to the list, as in
[recipes/README.md](../recipes/README.md#keep-personal-data-on-a-local-model).
