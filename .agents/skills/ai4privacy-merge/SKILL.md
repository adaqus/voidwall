---
name: ai4privacy-merge
description: Merge the per-category AI4Privacy eval files in .cache/ai4privacy-moved/ into one combined dataset, preferring each category's audited *.clean.jsonl over its *.valid.jsonl when one exists, and stripping the IDCARD category from every row. Use when asked to build/refresh the merged English eval set (e.g. for `DATASET=…valid.merged.jsonl docker/ctl eval`).
---

Build one combined AI4Privacy eval file from the per-category pieces, using the
honest audited set where available and dropping the out-of-scope IDCARD category.

# Merge per-category eval files into one honest dataset

Three rules, all handled by `scripts/merge_ai4privacy_valid.py`:

1. **One row per category file → concatenate.** Each `*.valid.jsonl` in
   `.cache/ai4privacy-moved/` holds the rows the sweep assigned to that category;
   a row lives in exactly one file, so concatenation is duplicate-free.
2. **Prefer the audited clean set.** For category `<CAT>`, if
   `.cache/ai4privacy-audited/<basename>.<CAT>.clean.jsonl` exists, use it instead
   of the `.valid.jsonl` — it is the validity-checked honest set produced by the
   `ai4privacy-audit` skill. Categories with no clean file fall back to `.valid.jsonl`.
3. **Strip IDCARD.** IDCARD has no honest English eval set (no supported English
   country issues a national ID card whose spec any value satisfies — see
   `ai4privacy-audit`). But IDCARD-labeled spans ride along inside rows contributed
   by *other* categories, so the eval would still report IDCARD. The script removes
   every `label == "IDCARD"` span from each row's `privacy_mask` at **span**
   granularity (file-level exclusion is not enough).

## Step 1 — Run the merge

```bash
scripts/merge_ai4privacy_valid.py
```

Defaults: reads `.cache/ai4privacy-moved/*.valid.jsonl` (excluding the merged
output) and `.cache/ai4privacy-audited/*.clean.jsonl`, writes
`.cache/ai4privacy-moved/<basename>.valid.merged.jsonl`.

Useful flags:
- `--keep-idcard` — merge spans as-is, do not strip any category.
- `--strip-category <LABEL>` — strip a different label instead of `IDCARD`.
- `--moved-dir` / `--audited-dir` / `--out` — override the default paths.

## Step 2 — Report

The script prints, per category, whether the `clean` or `valid` source was used
and its row count, the count of stripped IDCARD spans, and the final path + total
row count. Relay that summary.

To evaluate the result: point the eval at the single merged file —
`DATASET=.cache/ai4privacy-moved/<basename>.valid.merged.jsonl docker/ctl eval`
(a single file, not the directory, which globs every `*.jsonl`).
