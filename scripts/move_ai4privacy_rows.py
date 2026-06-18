#!/usr/bin/env python3
"""Move flawed AI4Privacy rows out of a JSONL cache into a deleted-rows file.

Non-interactive sibling of `prune_ai4privacy_rows.py`, for autonomous sweeps.
Every row whose `source_text` (input) OR `target_text` (expected) contains
<fragment> (substring, case-sensitive) is appended verbatim to <deleted.jsonl>
and removed from <dataset.jsonl> (atomic rewrite). Rows are preserved in the
deleted file, never discarded, so a sweep is reversible.

Safety:
  --dry-run   list matches + count, change nothing (use to verify a fragment).
  --max N     refuse the move when more than N rows match (guards against an
              over-broad fragment that would also remove rows that should stay).

Usage:
    scripts/move_ai4privacy_rows.py <dataset.jsonl> <deleted.jsonl> <fragment> [--max N] [--dry-run]

Exit codes:
    0  moved, or nothing matched, or dry-run listed
    2  bad arguments / missing dataset
    3  refused: match count exceeds --max (nothing moved)
"""

import argparse
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
    ap = argparse.ArgumentParser(add_help=True, description=__doc__)
    ap.add_argument("dataset")
    ap.add_argument("deleted")
    ap.add_argument("fragment")
    ap.add_argument("--max", type=int, default=None,
                    help="refuse if more than N rows match")
    ap.add_argument("--dry-run", action="store_true",
                    help="list matches without moving anything")
    args = ap.parse_args()

    if not args.fragment:
        print("error: empty fragment", file=sys.stderr)
        return 2
    if not os.path.isfile(args.dataset):
        print(f"error: no such file: {args.dataset}", file=sys.stderr)
        return 2

    with open(args.dataset, encoding="utf-8") as f:
        lines = f.readlines()

    matches = []  # (line_no, field, snippet)
    for n, line in enumerate(lines, 1):
        stripped = line.rstrip("\n")
        if not stripped:
            continue
        try:
            row = json.loads(stripped)
        except json.JSONDecodeError as e:
            print(f"warning: line {n}: skipping unparseable JSON ({e})", file=sys.stderr)
            continue
        src = row.get("source_text", "")
        tgt = row.get("target_text", "")
        if args.fragment in src:
            matches.append((n, "input", snippet(src, args.fragment)))
        elif args.fragment in tgt:
            matches.append((n, "expected", snippet(tgt, args.fragment)))

    if not matches:
        print(f"No rows match {args.fragment!r}.")
        return 0

    print(f"Rows matching {args.fragment!r} in {args.dataset}:\n")
    for n, field, snip in matches:
        print(f"  line {n:>6} [{field:>8}]: {snip}")
    print()

    if args.max is not None and len(matches) > args.max:
        print(f"Refused: {len(matches)} rows match but --max is {args.max}; "
              f"nothing moved. Narrow the fragment.", file=sys.stderr)
        return 3

    if args.dry_run:
        print(f"Dry run: {len(matches)} row(s) would move to {args.deleted}.")
        return 0

    drop = {n for n, _, _ in matches}
    moved = [line if line.endswith("\n") else line + "\n"
             for i, line in enumerate(lines, 1) if i in drop]
    kept = [line for i, line in enumerate(lines, 1) if i not in drop]

    # Append moved rows to the deleted file first (create file + parent dir if absent).
    os.makedirs(os.path.dirname(args.deleted) or ".", exist_ok=True)
    with open(args.deleted, "a", encoding="utf-8") as out:
        out.writelines(moved)

    # Rewrite the dataset atomically: temp file in the same dir, then rename.
    d = os.path.dirname(os.path.abspath(args.dataset))
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.writelines(kept)
        os.replace(tmp, args.dataset)
    except BaseException:
        os.unlink(tmp)
        raise

    print(f"Moved {len(matches)} row(s) to {args.deleted}; {len(kept)} remain.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
