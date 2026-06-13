#!/usr/bin/env python3
"""Delete flawed rows from an AI4Privacy JSONL cache file.

Each row is a JSON object with `source_text` (input) and `target_text`
(expected redaction). Give a file and a fragment; every row whose input OR
expected contains that fragment (substring, case-sensitive) is listed, and
deleted only after you confirm.

Usage:
    scripts/prune_ai4privacy_rows.py <file.jsonl> <fragment>

Example:
    scripts/prune_ai4privacy_rows.py .cache/ai4privacy/1english_openpii_30k.jsonl 79HN36345
"""

import json
import os
import sys
import tempfile

CONTEXT = 40  # chars of context shown around the matched fragment


def snippet(text: str, fragment: str) -> str:
    i = text.find(fragment)
    if i < 0:
        return ""
    start = max(0, i - CONTEXT)
    end = min(len(text), i + len(fragment) + CONTEXT)
    s = text[start:end].replace("\n", "\\n")
    return f"{'…' if start else ''}{s}{'…' if end < len(text) else ''}"


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip())
        return 2

    path, fragment = sys.argv[1], sys.argv[2]
    if not fragment:
        print("error: empty fragment", file=sys.stderr)
        return 2
    if not os.path.isfile(path):
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2

    matches = []  # (line_no, field, snippet)
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()

    for n, line in enumerate(lines, 1):
        line = line.rstrip("\n")
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"warning: line {n}: skipping unparseable JSON ({e})", file=sys.stderr)
            continue
        src = row.get("source_text", "")
        tgt = row.get("target_text", "")
        if fragment in src:
            matches.append((n, "input", snippet(src, fragment)))
        elif fragment in tgt:
            matches.append((n, "expected", snippet(tgt, fragment)))

    if not matches:
        print(f"No rows match {fragment!r}.")
        return 0

    print(f"Rows matching {fragment!r} in {path}:\n")
    for n, field, snip in matches:
        print(f"  line {n:>6} [{field:>8}]: {snip}")
    print()

    reply = input(f"Delete {len(matches)} row(s)? [y/N] ").strip().lower()
    if reply not in ("y", "yes"):
        print("Aborted; nothing deleted.")
        return 1

    drop = {n for n, _, _ in matches}
    kept = [line for i, line in enumerate(lines, 1) if i not in drop]

    # Write atomically: temp file in the same dir, then rename over the original.
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.writelines(kept)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise

    print(f"Deleted {len(matches)} row(s); {len(kept)} remain.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
