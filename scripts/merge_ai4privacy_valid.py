#!/usr/bin/env python3
"""Merge per-category AI4Privacy eval files into one combined dataset.

For every `<basename>.<CATEGORY>.valid.jsonl` in the moved dir, prefer the
audited `<basename>.<CATEGORY>.clean.jsonl` from the audited dir when it exists
(the honest, validity-checked set); otherwise fall back to the `.valid.jsonl`.
Each source row lives in exactly one category file, so concatenation produces a
duplicate-free set.

The IDCARD category has no honest English eval set (no supported English country
issues a national ID card whose spec any value satisfies — see the
`ai4privacy-audit` skill). Its spans nonetheless ride along inside rows
contributed by *other* categories, so they are stripped from every row's
`privacy_mask` at span granularity. Pass --keep-idcard to skip that.

Output is `<basename>.valid.merged.jsonl` in the moved dir, so the
`*.valid.jsonl` glob never re-includes it.

Usage:
    scripts/merge_ai4privacy_valid.py
    scripts/merge_ai4privacy_valid.py --moved-dir .cache/ai4privacy-moved \
        --audited-dir .cache/ai4privacy-audited --strip-category IDCARD
"""

import argparse
import glob
import json
import os
import sys


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True, description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--moved-dir", default=".cache/ai4privacy-moved",
                    help="dir holding the per-category *.valid.jsonl files")
    ap.add_argument("--audited-dir", default=".cache/ai4privacy-audited",
                    help="dir holding the audited *.clean.jsonl counterparts")
    ap.add_argument("--out", default=None,
                    help="output path (default: <moved-dir>/<basename>.valid.merged.jsonl)")
    ap.add_argument("--strip-category", default="IDCARD",
                    help="privacy_mask label to strip from every row (default: IDCARD)")
    ap.add_argument("--keep-idcard", action="store_true",
                    help="do not strip any category; merge spans as-is")
    args = ap.parse_args()

    valids = sorted(
        f for f in glob.glob(os.path.join(args.moved_dir, "*.valid.jsonl"))
        if not f.endswith(".valid.merged.jsonl")
    )
    if not valids:
        print(f"error: no *.valid.jsonl files in {args.moved_dir}", file=sys.stderr)
        return 2

    # basename = filename with .<CATEGORY>.valid.jsonl stripped (same for every file).
    basename = os.path.basename(valids[0])[:-len(".valid.jsonl")].rsplit(".", 1)[0]
    out = args.out or os.path.join(args.moved_dir, f"{basename}.valid.merged.jsonl")

    rows, report = [], []
    for vf in valids:
        cat_stem = os.path.basename(vf)[:-len(".valid.jsonl")]          # e.g. ...30k.BOD
        category = cat_stem.rsplit(".", 1)[-1]                          # e.g. BOD
        clean = os.path.join(args.audited_dir, cat_stem + ".clean.jsonl")
        src = clean if os.path.isfile(clean) else vf
        n = sum(1 for line in open(src) if line.strip())
        with open(src) as fh:
            rows.extend(line if line.endswith("\n") else line + "\n"
                        for line in fh if line.strip())
        report.append((category, "clean" if src == clean else "valid", n))

    removed = affected = 0
    if not args.keep_idcard:
        stripped = []
        for line in rows:
            o = json.loads(line)
            pm = o.get("privacy_mask", [])
            kept = [s for s in pm if s.get("label") != args.strip_category]
            if len(kept) != len(pm):
                affected += 1
                removed += len(pm) - len(kept)
            o["privacy_mask"] = kept
            stripped.append(json.dumps(o, ensure_ascii=False) + "\n")
        rows = stripped

    with open(out, "w") as fh:
        fh.writelines(rows)

    print(f"{'CATEGORY':16} {'SOURCE':6} ROWS")
    for cat, src, n in report:
        print(f"{cat:16} {src:6} {n}")
    if not args.keep_idcard:
        print(f"\nstripped {args.strip_category} spans: {removed} from {affected} row(s)")
    print(f"merged {len(report)} file(s) -> {out} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
