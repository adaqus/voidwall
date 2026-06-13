---
name: ai4privacy-eval
description: Verify PII detection for one language + category against the AI4Privacy dataset, then triage and fix a single miss — either improve the detector or delete the row as flawed (wrong expected redaction, invalid value, or no detectable signal). Use when asked to verify/check/triage a category's detection quality against AI4Privacy, or to investigate why a category's recall is low.
---

Verify PII detection for language $ARGUMENTS[0] and category $ARGUMENTS[1].

# Verify a category against AI4Privacy and fix one miss

Handle **a single miss** per invocation: surface one miss, decide fix-or-delete
with the user, act, re-verify, then stop. Do not loop to the next miss — the user
re-invokes this skill to continue. Be concise.

## Step 1 — Resolve arguments

- `language` = `$ARGUMENTS[0]` (e.g. `en`, `fr`, `de`). Used as `LANG`.
- `category` = `$ARGUMENTS[1]` — the AI4Privacy ground-truth label (e.g.
  `PASSPORT`, `IDCARD`, `TEL`, `SOCIALNUMBER`). Used as `DUMP_MISSES`.

If either is missing, ask the user for it before continuing. Do not guess.

## Step 2 — Precondition: proxy must be running

The eval hits the proxy HTTP API. If it's down, every row errors and is counted
as a miss. Make sure it's up first:

```bash
docker/ctl start    # builds + starts; safe to re-run, also picks up code changes
```

If the eval report later shows "every request failed", the proxy isn't running.

## Step 3 — Run the eval, one miss at a time

```bash
LANG=<language> DUMP_MISSES=<CATEGORY> DUMP_CONTEXT=1 DUMP_CONTEXT_LIMIT=1 docker/ctl eval
```

- `DUMP_CONTEXT=1` prints the full input row and the ground-truth redaction.
- `DUMP_CONTEXT_LIMIT=1` caps the dump to a single distinct missed value.

The whole dataset is scanned, so this can take a few minutes. The miss prints
under `--- DUMP_MISSES=<CATEGORY>: detection misses (value × count) ---` as:

```
   <count> × <missed value>
**************************************************
         input:    <full input row>
**************************************************
         expected: <full row with GT redaction>
```

If the section says `(none — every <CATEGORY> GT span was detected)`, recall is
clean — report that and stop.

## Step 4 — Triage the miss: fix or delete

Read the input and the expected redaction. Decide which case applies.

**Suggest FIX (real detector gap)** when the value is a genuine, valid instance of
the category AND there is a usable detection signal Voidwall missed — a keyword
present in the input that we don't match, a separator/wrapper we don't skip, or a
valid format variant we don't cover.

**Suggest DELETE (flawed row)** when any of these hold:
- **Wrong expected redaction** — `expected` masks the wrong span, mislabels the
  category, or leaves the value unmasked.
- **Invalid value** — the redacted value is not valid for the category. *Validate
  it yourself*: check format and any checksum against the real-world spec and the
  crate's own rules in `crates/pii/src/validators.rs` (e.g. Luhn for cards, date
  validity, country ID checksums, passport shape). A value the spec rejects is
  garbage ground truth.
- **Redaction not possible** — the category is keyword-gated (it lives in
  `crates/pii/src/keyword_context_detector.rs`, not the structural
  `hyperscan_detector.rs`) and **no triggering keyword** appears near the value in
  the input, so there is no safe signal to detect on. Detecting it would require
  an unsafe bare-format match. (Read `crates/pii/CLAUDE.md` for the two-detector
  split if unsure which applies.)

State your suggestion in one or two sentences with the reason.

## Step 5 — Confirm with the user

Ask the user (via AskUserQuestion) to confirm your suggestion or pick the other
action. Offer: **Fix detection** / **Delete row**. Honor their choice even if it
differs from your suggestion.

## Step 6 — If DELETE: remove the row

Use the prune script with a fragment that uniquely identifies the row:

```bash
scripts/prune_ai4privacy_rows.py <dataset-file> "<fragment>"
```

- `<dataset-file>` is the JSONL under `.cache/ai4privacy/` (e.g.
  `.cache/ai4privacy/1english_openpii_30k.jsonl` — `ls .cache/ai4privacy/` to find it).
- Start with the missed value as the fragment. If the script lists more rows than
  the one flawed row, narrow it with a longer unique slice of the input. The
  script lists matches and asks its own confirmation before deleting.

## Step 7 — If FIX: implement the improvement

- For keyword/pattern/format changes in the `pii` crate, follow
  `crates/pii/CLAUDE.md` and the **add-pii** skill (keyword-context pattern rules,
  required test cases, overlap/validation pitfalls). Add `#[test_case]` coverage
  for the exact missed value.
- If the fix approach is ambiguous (e.g. broaden a keyword list vs. add a country
  tuple, precision tradeoffs), ask the user which they prefer before coding.
- After the change: `cargo test -p pii` must pass, then rebuild + restart the
  proxy with `docker/ctl start` so the new detection is live.

## Step 8 — Re-verify, then stop

Re-run the Step 3 command once to confirm the action worked:
- After a **fix**: the value should no longer appear as a miss.
- After a **delete**: the flawed row is gone; a different distinct miss may now show.

Report the result, then **stop**. Do not continue to the next miss — the user
re-invokes this skill when they want to triage another one.
