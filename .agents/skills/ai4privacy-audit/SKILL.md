---
name: ai4privacy-audit
description: Rigorously audit an already-swept AI4Privacy *.valid.jsonl for fake or broken ground truth, sorting every row into an audited .clean honest precision/recall set or a .invalid set of confirmed-fabricated rows. Validates each value against the spec of the countries the pii crate actually supports for the language: a category in scope for ≥1 supported country is checked against that country's spec; a category no supported country has is removed wholesale. Unlike ai4privacy-sweep it keeps EVERY genuinely-valid value the detector merely misses (keyword-less, loose-structure, no nearby trigger) — those are real recall gaps. The final .clean set combines the audited-valid misses with the detector's already-hit (valid-by-construction) rows. Use to finalize a category's ground truth into a distortion-free eval dataset.
---

Audit the valid-rows file named in the user's request, validating every category span and
sorting every row into the audited `.clean` set (honest eval set) or the
`.invalid` set (fabricated/broken GT), so `.clean` measures the detector's real
recall and precision.

# Finalize a category's ground truth into an honest eval set

This is the **second-stage, validity-only** sibling of `ai4privacy-sweep`. Sweep
bulk-sorts the raw dataset; this audits sweep's `*.valid.jsonl` output more
meticulously. It shares sweep's mechanics but has a different burden of proof:

- **Burden of proof is on KEEP — for validity only.** A row stays unless you can
  positively confirm its category spans are fake or broken. "Probably a real PII"
  → **keep**. Never remove on suspicion. (Exception: a category with no
  supported-country spec for the language — see **country scope** below — is
  removed wholesale; "keep on doubt" does not apply there.)
- **Country scope first — validate against the countries the crate actually
  supports for this language.** The dataset's category label (`IDCARD`,
  `PASSPORT`, …) is country-agnostic, but the crate only detects PII for the
  countries in its `Country` enum. Before triaging, decide the category's scope
  (Step 3.5):
  - **The category must exist for at least one supported country of the row's
    language.** If it does, those countries' real-world specs define validity:
    validate every value against them (+ `validators.rs`) and remove a value only
    when it fails **every** candidate country's spec.
  - **If no supported country of that language has the category at all, the
    category is out of scope — remove every value for it** (→ `.invalid`). Such
    values are fictional for the supported countries, not recall gaps, so keeping
    them would distort recall downward. (E.g. for English, neither the US nor GB
    issues a national ID card; only South Africa does — so `IDCARD` is validated
    against `ZaId`, and a value valid for no supported country is removed.)
- **Detectability is irrelevant.** A valid value (valid for a supported country,
  per the scope rule above) with **no nearby keyword** or a **loose structure**
  the crate can't safely match is a **legitimate recall miss** and **must stay**.
  Removing it would manufacture fake 100% recall — the opposite of the goal. This
  is the one place sweep is wrong for this purpose: sweep's "keyword-gated, no
  keyword → delete" rule (its criterion #3) is **dropped here**.
- **Never fixes.** It does not touch the detector.
- **Binary sort — every examined miss moves to one of two files.**
  - **if** you are confident the span is **fake/broken** (corrupted, or fails the
    spec/validator) → move to the `.invalid` file;
  - **else** → move to the `.clean` file (the honest eval set).
  Only the `.invalid` side needs confidence.
- **`.clean` is the complete honest valid set, not just the audited misses.** Two
  kinds of rows belong in `.clean`: (a) the misses you triage and confirm valid,
  and (b) the rows the detector already **hits**, which are valid by construction
  (the detector only fires when the value passes the country validator). The (b)
  rows never appear in the miss dump, so **Step 7 folds them in at the end** — once
  no misses remain, the input file holds only detected-valid rows, and they are
  appended to `.clean` and the input is drained. The honest set lives entirely in
  `.clean`; the input ends empty.
- **Bounded.** Examine at most **100 misses** per invocation, then checkpoint and
  stop. The user re-invokes to continue.

Be concise. Do not narrate every row — report totals at the end.

## Step 1 — Resolve arguments

- `input` = the path to the `*.valid.jsonl` named in the request, e.g.
  `.cache/ai4privacy-moved/1english_openpii_30k.PASSPORT.valid.jsonl`.
- `category` = the category named in the request, if given; otherwise parse it from the filename — the
  token between the dataset basename and `.valid.jsonl`
  (`1english_openpii_30k.PASSPORT.valid.jsonl` → `PASSPORT`). This token is
  already the canonical `DUMP_MISSES` label sweep used; pass it through verbatim.
- `basename` = the dataset basename, i.e. the filename with `.<CATEGORY>.valid.jsonl`
  stripped (`1english_openpii_30k`).
- `language` = derive from `basename` if obvious (`1english…` → `en`); used only
  to narrow the eval. Optional — the input is a single file, so `LANG` just
  filters by each row's `language` field.

If `input` is missing, ask the user once. Do not guess.

## Step 2 — Precondition: proxy must be running

```bash
docker/ctl start
```

If the eval later reports "every request failed", the proxy isn't running.

## Step 3 — Capture up to 100 misses in one eval pass

Run the eval **once** against the input file, dumping the missed rows:

```bash
DATASET=<input> DUMP_MISSES=<CATEGORY> \
  DUMP_CONTEXT_FILE=/tmp/ai4p_audit_misses.txt DUMP_CONTEXT_LIMIT=100 \
  LANG=<language> docker/ctl eval
```

(Drop `LANG` if the basename gives no clear language.) The misses are dumped in
the same grouped format `ai4privacy-sweep` documents in its Step 3 — read
`/tmp/ai4p_audit_misses.txt`.

Any value that **fails the validator is necessarily a miss** (the crate rejected
it), so this pass surfaces every removal candidate. Rows the detector now *hits*
won't dump — they are **valid by construction** (the detector only fires when the
value passes the country validator) and are not triaged here; **Step 7** folds
them into `.clean` once the misses are exhausted.

If the section prints `(none — every <CATEGORY> GT span was detected)`, there are
no misses left to triage — skip Steps 4–6 and go straight to **Step 7 (finalize)**.

## Step 3.5 — Resolve the category's country scope

Do this **once, before triaging**, and it decides the whole audit.

1. List the supported countries for the row's `language`. Read the `Country` and
   `PiiKind` enums in `crates/voidwall-pii/src/lib.rs`. For English the supported countries
   are `Us, Gb, Au, Nz, Ca, Ie, Za` (+ `International`); other languages map to
   their own subset.
2. Map the dataset `<CATEGORY>` to the `PiiKind` variant(s) that represent it for
   those countries. A category counts as **in scope** if **at least one** supported
   country has a matching `PiiKind` (e.g. `IDCARD` → only `ZaId`, because among the
   English countries only South Africa issues a national ID card; `US`/`GB` have
   none).
3. Record the outcome:
   - **In scope** → note the candidate country validator(s) in
     `crates/voidwall-pii/src/validators.rs` (e.g. `ZaId` → `za_luhn13_check`). Step 4 will
     validate every value against them.
   - **Out of scope** (no supported country has the category) → **every value is
     invalid**. Skip per-value validation: move **all** rows to `.invalid` and
     leave `.clean` empty. Report this and stop.

## Step 4 — Triage each miss: invalid-or-clean

**Ground truth is `privacy_mask`, not `target_text`** — same rule as
`ai4privacy-sweep` Step 4. For each missed value, find the span(s) in the row's
`privacy_mask` with `label == <CATEGORY>`; `source_text[start:end]` locates the
value exactly.

Walk the groups in order, up to 100. **Move a span to `.invalid` only when you are
confident one of these holds:**

- **Corrupted span** — the annotation is broken: `value != source_text[start:end]`,
  a leaked placeholder token (pattern `[A-Z][A-Z_]*_[A-Z]\(`, e.g.
  `PASSPORT_B(…`), or merged JSON/newline junk (`\n`, `{`, `}`, `":`).
- **Invalid value** — the value is not valid for the category **for any in-scope
  country** (Step 3.5). **Validate it yourself, rigorously**, against each
  candidate country's real-world spec **and** the crate's checks in
  `crates/voidwall-pii/src/validators.rs` (Luhn for cards, date validity, country ID
  checksums, passport shape, length). A value that fails **every** in-scope
  country's spec is fabricated GT. This is the meticulous check sweep skipped — do
  not pass a value to `.clean` without confirming it is valid for at least one
  in-scope country.

**Everything else is clean** → move to the `.clean` file. This **explicitly
includes** valid values with no nearby keyword and valid values with a loose
format the detector can't safely match — they are real recall gaps and belong in
the honest set. No detectability test. If you are not confident a value is
fake/broken, it is clean.

Row-level rule: a row may carry several category spans. Move the row to `.invalid`
**only when ALL** its `<CATEGORY>` spans are corrupted/invalid. If **any** span is
a genuine valid value, the row is clean.

## Step 5 — Move the row to its destination file

Destinations live in a new sibling dir, **`.cache/ai4privacy-audited/`** (the move
script creates it on first write), so the eval — which globs `.cache/ai4privacy/`
— never re-reads them:

- `.cache/ai4privacy-audited/<basename>.<CATEGORY>.clean.jsonl` — passed audit (honest eval set);
- `.cache/ai4privacy-audited/<basename>.<CATEGORY>.invalid.jsonl` — fabricated/broken GT.

Use the **same `scripts/move_ai4privacy_rows.py`** and the **same fragment
precision** discipline as `ai4privacy-sweep` Step 5 — the source is the **input
`*.valid.jsonl`**, the destination is whichever file the row belongs to:

1. Build a distinctive fragment from `source_text` around the span (value plus a
   neighbouring key/label), not the bare value.
2. Dry-run against the chosen destination:

   ```bash
   scripts/move_ai4privacy_rows.py <input> .cache/ai4privacy-audited/<basename>.<CATEGORY>.invalid.jsonl "<fragment>" --dry-run
   scripts/move_ai4privacy_rows.py <input> .cache/ai4privacy-audited/<basename>.<CATEGORY>.clean.jsonl   "<fragment>" --dry-run
   ```

   Narrow the fragment until it hits only the intended row(s).
3. Move for real with `--max <n>` (the row count you intend) as an over-move
   backstop:

   ```bash
   scripts/move_ai4privacy_rows.py <input> .cache/ai4privacy-audited/<basename>.<CATEGORY>.invalid.jsonl "<fragment>" --max <n>
   scripts/move_ai4privacy_rows.py <input> .cache/ai4privacy-audited/<basename>.<CATEGORY>.clean.jsonl   "<fragment>" --max <n>
   ```

Count each move. Track `examined`, `invalid`, `clean`.

## Step 6 — Checkpoint and stop

After 100 misses (or the list is exhausted), append a one-line record to
`.cache/ai4privacy/audit_progress.log`:

```
<ISO-timestamp> input=<basename>.<CATEGORY> examined=<n> invalid=<n> clean=<n> remaining=<input row count>
```

Then report a short summary: examined, moved-to-invalid, moved-to-clean, and the
paths to both audited files. **Stop.** Do not re-run the eval — the user
re-invokes to audit the next batch.

If this batch left misses unexamined (you hit the 100 cap), stop here — the input
still holds untriaged misses, so do **not** run Step 7 yet.

## Step 7 — Finalize: fold detected-valid rows into `.clean`

Run this **only when the miss list is exhausted** — i.e. Step 3 printed
`(none — every <CATEGORY> GT span was detected)`, or the last batch examined fewer
than 100 misses and moved them all. At that point every row still in the input is
detected by the crate, hence valid by construction, and belongs in the honest set.

1. **Confirm there are no misses left.** Re-run the Step 3 eval; it must print
   `(none — …)`. If misses remain, you are not done — go back to Step 4.
2. **Append the remaining input rows to `.clean` and drain the input:**

   ```bash
   cat <input> >> .cache/ai4privacy-audited/<basename>.<CATEGORY>.clean.jsonl
   : > <input>
   ```

3. **Verify the partition.** `.clean` + `.invalid` row counts must equal the
   original `*.valid.jsonl` count, and the input must now be empty.

Report the final totals: `.clean` (= audited-valid misses + detected-valid rows),
`.invalid`, and confirm the input is drained. To measure honest recall/precision,
point the eval's `DATASET` at the `.clean.jsonl` file (a single file, not the
audited dir, which globs every `*.jsonl`). `.clean` is now the complete honest
eval set — this is also what `ai4privacy-merge` prefers over `*.valid.jsonl`.
