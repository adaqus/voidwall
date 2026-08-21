---
name: ai4privacy-sweep
description: Autonomously sweep AI4Privacy detection misses for one language + category and sort rows into sibling files — clearly-flawed rows (wrong expected redaction, invalid value, or no detectable signal) into a deleted-rows file, and confidently-good rows the detector merely misses into a valid-rows file. Unlike ai4privacy-eval it does NOT ask per miss and never edits the detector — it sorts only rows it is sure about, leaves uncertain ones in place, and stops after 100 misses. Use to bulk-clean a category's ground truth.
---

Autonomously triage AI4Privacy detection misses for the language and category named in
the user's request, sorting clearly-flawed rows into a deleted-rows file and
confidently-good rows into a valid-rows file.

# Sweep a category's misses and sort the sure ones

This is the **non-interactive** sibling of `ai4privacy-eval`. Per miss it applies
the same triage, but:

- **Never asks during row triage.** Decide each row yourself.
- **Never fixes.** It does not touch the detector. A miss that would need a
  detector fix lands in the valid-rows file (the GT is good; the detector is
  what falls short), not deleted.
- **Binary sort — every examined miss moves out of the dataset.** It is a
  plain if/else:
  - **if** you are confident the row is flawed → move it to the deleted-rows
    file;
  - **else** → move it to the valid-rows file.
  Deletion is the only side that needs confidence. The valid-rows file is just
  "not confidently flawed" — anything you would not delete goes there, so no
  judgement call is needed to send a row to valid. Both files live **outside**
  the dataset directory (see Step 5) so the eval never re-reads moved rows.
- **Bounded.** Examine at most **100 misses** per invocation, then stop and
  checkpoint. The user re-invokes to continue.

Be concise. Do not narrate every row — report totals at the end.

## Step 1 — Resolve arguments

- `language` = the language named in the request (e.g. `en`, `fr`, `de`). Used as `LANG`.
- `category` = the category named in the request — the AI4Privacy label (e.g. `PASSPORT`,
  `IDCARD`, `TEL`). Used as `DUMP_MISSES`.

If either is missing, ask the user once for it, then proceed. Do not guess.

## Step 2 — Precondition: proxy must be running

```bash
docker/ctl start
```

If the eval later reports "every request failed", the proxy isn't running.

## Step 3 — Capture up to 100 misses in one eval pass

Run the eval **once**, writing the miss rows to a file (do not re-run per miss —
each pass rescans the whole dataset and takes minutes):

```bash
LANG=<language> DUMP_MISSES=<CATEGORY> \
  DUMP_CONTEXT_FILE=/tmp/ai4p_sweep_misses.txt DUMP_CONTEXT_LIMIT=100 \
  docker/ctl eval
```

`DUMP_CONTEXT_FILE` captures the whole input row + expected redaction per missed
value; `DUMP_CONTEXT_LIMIT=100` caps it at 100 distinct missed values. The whole
dataset is scanned, so this takes a few minutes.

Read `/tmp/ai4p_sweep_misses.txt`. Each miss is one group:

```
<count> × <value>
**************************************************************************************************** (100 *)
  input:    <full input row, may span lines>
-------------------------------------------------- (50 -)
  expected: <full expected redaction, may span lines>
**************************************************************************************************** (100 *)
```

If the eval prints `(none — every <CATEGORY> GT span was detected)`, recall is
clean — report that and stop.

## Step 4 — Triage each miss: delete-or-valid

**Ground truth is `privacy_mask`, not `target_text`.** Each dataset row has a
`privacy_mask` field — a list of `{"value", "start", "end", "label"}` spans — and
the eval derives misses from it. Judge each miss against `source_text` +
`privacy_mask`, **not** against `target_text` (or the dump's `expected`, which is
just a rendering of it). `target_text` can mask a value under the wrong token
(e.g. a DRIVERLICENSE value rendered as `[IDCARD]`) or merge spans, so it both
hides in-scope rows and tells you nothing about span integrity.

For each missed value, find the span(s) in the row's `privacy_mask` with
`label == <CATEGORY>`. The span's `start`/`end` locate the value exactly in
`source_text` (`source_text[start:end]`) — no bounded-token guessing. Keyword
proximity = scan `source_text[start-40:start]`.

Walk the groups in order, up to 100. For each, decide **delete vs. valid**. Only
the delete side needs confidence — **delete when one of these clearly holds**
(these are the DELETE criteria from `ai4privacy-eval`):

- **Corrupted span** — the annotation itself is broken:
  `value != source_text[start:end]`, or `value` carries a leaked placeholder
  token (e.g. `DRIVERLICENSE_D(…`, `USERNAME_G(…`, `PASSPORT_B(…` — pattern
  `[A-Z][A-Z_]*_[A-Z]\(`), or merged JSON/newline junk (`\n`, `{`, `}`, `":`).
  Garbage GT.
- **Invalid value** — the value is not valid for the category. *Validate it
  yourself* against the real-world spec and the crate's rules in
  `crates/pii/src/validators.rs` (Luhn for cards, date validity, country ID
  checksums, passport shape, etc.). A value the spec rejects is garbage GT.
- **Redaction not possible** — the category is keyword-gated (it lives in
  `crates/pii/src/keyword_context_detector.rs`, not the structural
  `crates/pii/src/hyperscan_detector.rs`) and **no triggering keyword** appears
  in `source_text[start-40:start]` before the span. With no safe signal,
  detecting it would require an unsafe bare-format match. (See
  `crates/pii/AGENTS.md` for the detector chain if unsure which applies.)

**Otherwise the row is valid** — move it to the valid-rows file. This covers the
clear detector-fix candidates (valid value AND a usable signal: a nearby keyword,
a separator/wrapper, or a valid format variant) **and** every case you are not
confident enough to delete. No positive proof of validity is needed: if you would
not delete it, it goes to valid.

A row may carry several spans of the category. If **any** span is valid (keyword
near, clean), the row is not confidently flawed → **valid**; only delete a row
when **all** its category spans are flawed (corrupted / invalid / no keyword).

## Step 5 — Move the row to its destination file

The dataset JSONL is under `.cache/ai4privacy/` (`ls .cache/ai4privacy/` to find
it, e.g. `1english_openpii_30k.jsonl`).

**The destination files must NOT live in `.cache/ai4privacy/`.** The eval globs
every `*.jsonl` in that directory and filters by each row's `language` field, so
a moved row left in there is re-read and resurfaces forever. Put both
destinations in the sibling `.cache/ai4privacy-moved/` directory instead (the
move script creates it on first move):

- `.cache/ai4privacy-moved/<dataset-basename>.<CATEGORY>.deleted.jsonl` — for flawed rows;
- `.cache/ai4privacy-moved/<dataset-basename>.<CATEGORY>.valid.jsonl` — for everything else.

**Scope the destination by category.** The dataset is a single shared
multi-PII file, so naming the destinations only by dataset basename would
intermix categories into one undifferentiated pile and lose provenance. Always
put `<CATEGORY>` (the `DUMP_MISSES` value, e.g. `PASSPORT`, `POSTCODE`) in the
filename. For `.cache/ai4privacy/1english_openpii_30k.jsonl` sweeping
`PASSPORT` the files are
`1english_openpii_30k.PASSPORT.deleted.jsonl` /
`1english_openpii_30k.PASSPORT.valid.jsonl`.
`move_ai4privacy_rows.py` takes the destination as its second argument, so the
same command moves to either file — only the destination differs.

(Caveat — known leak: moving a row out of the shared dataset also removes its
*other* categories' GT from every future eval. Category-scoped filenames keep
provenance but do not fix this; a different category's sweep will not re-see a
row already swept for this one.)

**Precision matters: move only the specific row(s) you judged.** The same value
can appear in several rows. Identify the row by a fragment unique to it — not the
bare value if that value also occurs in other rows.

1. Pick a fragment: take a distinctive slice of `source_text` around the span
   (`source_text[start:end]` plus a neighbouring key/label, like
   `"Patient_ID": "32BV67680"`), not just the bare value. The move script
   matches `source_text`/`target_text` substrings — build the fragment from
   `source_text`, since `target_text` may not contain the value as the
   category's token.
2. Dry-run to confirm it hits only the intended row(s) (point it at whichever
   destination this row belongs to):

   ```bash
   # flawed row:
   scripts/move_ai4privacy_rows.py .cache/ai4privacy/<basename>.jsonl .cache/ai4privacy-moved/<basename>.<CATEGORY>.deleted.jsonl "<fragment>" --dry-run
   # valid row:
   scripts/move_ai4privacy_rows.py .cache/ai4privacy/<basename>.jsonl .cache/ai4privacy-moved/<basename>.<CATEGORY>.valid.jsonl "<fragment>" --dry-run
   ```

   If it lists more rows than intended, narrow the fragment and dry-run again.
3. Move for real, with `--max` as a backstop equal to the number of rows you
   intend to move:

   ```bash
   scripts/move_ai4privacy_rows.py .cache/ai4privacy/<basename>.jsonl .cache/ai4privacy-moved/<basename>.<CATEGORY>.deleted.jsonl "<fragment>" --max <n>
   scripts/move_ai4privacy_rows.py .cache/ai4privacy/<basename>.jsonl .cache/ai4privacy-moved/<basename>.<CATEGORY>.valid.jsonl   "<fragment>" --max <n>
   ```

   `--max` makes the script refuse (exit 3) rather than over-move if the
   fragment is broader than expected.

Count each move. Track `examined`, `deleted`, `valid`.

## Step 6 — Checkpoint and stop

After 100 misses (or the list is exhausted), append a one-line record to
`.cache/ai4privacy/sweep_progress.log` so the user sees where it finished:

```
<ISO-timestamp> lang=<language> cat=<CATEGORY> examined=<n> deleted=<n> valid=<n> remaining=<dataset row count>
```

Then report a short summary: how many examined, deleted, moved-to-valid, and the
paths to both the deleted-rows and valid-rows files. **Stop.** Do not re-run the
eval or continue — the user re-invokes to sweep the next batch.
