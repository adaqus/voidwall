---
name: ai4privacy-eval
description: Evaluate Voidwall's PII redaction for one category against a given AI4Privacy JSONL file (via `docker/ctl eval`), then investigate why values that should have been detected were missed and propose a fix. Use when asked to evaluate/check a category's detection quality against a specific dataset file, or to investigate why a category's recall is low.
---

Evaluate redaction for dataset file $ARGUMENTS[0] and category $ARGUMENTS[1].

# Evaluate a dataset file and investigate misses

Purpose: run the eval against **one dataset file**, then dig into why the
category's missed values were not detected and **propose a fix**. This skill does
not edit ground truth and does not delete rows. Be concise.

## Step 1 — Resolve arguments

- `dataset` = `$ARGUMENTS[0]` — path to the JSONL file to evaluate. Used as
  `DATASET`. Must be a **file**, not a directory (a directory globs every
  `*.jsonl`, e.g. both `*.valid` and `*.deleted` under `.cache/ai4privacy-moved`).
- `category` = `$ARGUMENTS[1]` — the AI4Privacy ground-truth label to focus on
  (e.g. `PASSPORT`, `IDCARD`, `TEL`, `SOCIALNUMBER`, `STREET`). Used as
  `DUMP_MISSES`. For the moved files the category is in the filename
  (`1english_openpii_30k.STREET.valid.jsonl` → `STREET`).

If either is missing, ask the user for it before continuing. Do not guess.

## Step 2 — Precondition: proxy must be running

The eval hits the proxy HTTP API. If it's down, every row errors and is counted
as a miss. Make sure it's up first:

```bash
docker/ctl start    # builds + starts; safe to re-run, also picks up code changes
```

If the eval report later shows "every request failed", the proxy isn't running.

## Step 3 — Run the eval

```bash
DATASET=<dataset> DUMP_MISSES=<CATEGORY> DUMP_CONTEXT=1 docker/ctl eval
```

- `DUMP_CONTEXT=1` prints the full input row and the ground-truth redaction under
  each missed value.
- Add `DUMP_CONTEXT_LIMIT=<n>` to cap how many distinct missed values get the
  full-row dump (default 80). The `value × count` summary always prints regardless.

The whole file is scanned, so this can take a few minutes. Misses print under
`--- DUMP_MISSES=<CATEGORY>: detection misses (value × count) ---` as:

```
   <count> × <missed value>
**************************************************
         input:    <full input row>
**************************************************
         expected: <full row with GT redaction>
```

Report the category's `det R` / `typed R` from the per-category table and the
miss count. If the section says `(none — every <CATEGORY> GT span was detected)`,
recall is clean — report that and stop.

## Step 4 — Investigate why values were missed

Work from the `value × count` summary: prioritize the highest-count values (they
share a root cause) and a couple of representative low-count ones. For each, read
its `input` and `expected` rows and find the **detection signal that should have
fired but didn't**. Check, in order:

- **Keyword-gated vs structural.** Most of these categories live in the
  keyword-context detector (`crates/pii/src/keyword_context_detector.rs`), which
  needs a trigger word near the value; a few are structural
  (`crates/pii/src/hyperscan_detector.rs`), which match on format alone. Read
  `crates/pii/CLAUDE.md` for the two-detector split if unsure which applies.
- **Missing keyword** — for a keyword-gated category, is there a trigger word in
  the input we simply don't list? (label synonym, abbreviation, emoji/icon label,
  another language's word).
- **Separator / wrapper** — is the value adjacent to a colon, bracket, quote,
  dash, or other separator the pattern doesn't skip between keyword and value?
- **Format variant** — is this a valid real-world format the detector's pattern
  doesn't cover (length, grouping, prefix, country variant)?
- **Validator rejection** — is the value valid but rejected by a check in
  `crates/pii/src/validators.rs` (checksum, length, date validity)? Confirm the
  value really is valid against the real-world spec before blaming the validator.

State the root cause for the dominant pattern(s) in one or two sentences, citing
the file/line of the relevant keyword list, pattern, or validator.

## Step 5 — Propose a fix

For the root cause(s) you found, propose a concrete change: add a keyword, allow a
separator, broaden a pattern to a format variant, add a country tuple, or relax a
validator. Note the precision tradeoff if one exists. Point at the exact place to
change (file + the list/pattern/validator). For pattern/keyword/format work,
reference `crates/pii/CLAUDE.md` and the **add-pii** skill (keyword-context rules,
required test cases, overlap/validation pitfalls).

Present the proposal and stop. Do not implement unless the user asks.

## Step 6 — (Optional) Implement, if the user asks

If the user confirms the fix:
- Follow `crates/pii/CLAUDE.md` and the **add-pii** skill. Add `#[test_case]`
  coverage for the exact missed value(s).
- `cargo test -p pii` must pass, then `docker/ctl start` to rebuild + restart so
  the new detection is live.
- Re-run the Step 3 command once; the fixed value(s) should no longer appear as a
  miss. Report the before/after recall, then stop.
