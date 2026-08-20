# Names gazetteer — source data & provenance

Inputs for the offline `build_names_fst` tool (`crates/pii/tools/build_names_fst.rs`),
which emits the committed artifact `crates/pii/data/names.fst` used by the
`DictionaryDetector` (`PersonName`). Coverage: English (US) given names +
surnames, multilingual given names **and surnames** (Wikidata), plus Italian and
Spanish surnames (merged into the single artifact).

The **raw source files in this directory are git-ignored** (large, re-fetchable);
only `names.fst` is committed. Download/regenerate the sources below, then rebuild.

## Sources

| File (place here) | Source | License |
|---|---|---|
| `ssa/yob*.txt` | US SSA, national given names — <https://www.ssa.gov/oact/babynames/names.zip> (unzip) | **Public domain** (US gov work) |
| `wikidata/given.txt` | Multilingual given names — Wikidata CC0 `en` labels of `P31 ∈ {Q12308941 male, Q11879590 female, Q3409032 unisex}` given name (fetch script below) | Wikidata **CC0** |
| `wikidata/surname.txt` | Multilingual surnames — Wikidata CC0 `en` labels of `P31 = Q101352` family name (fetch script below) | Wikidata **CC0** |
| `Names_2010Census.csv` | US Census Bureau, *Frequently Occurring Surnames 2010* — <https://www2.census.gov/topics/genealogy/2010surnames/names.zip> (unzip) | **Public domain** (US gov work) |
| `it/cognomi.txt` | Italian surnames — `filippotoso/nomi-cognomi-italiani` | scraped list — **licensing exception granted** (see below) |
| `es/apellidos.txt` | Spanish surnames — INE *Apellidos más frecuentes* set, accents restored from Wikidata CC0 family-name labels (`P31=Q101352` ∧ `P407=Q1321`) | INE **open data** + Wikidata **CC0** |
| `google-10000-english.txt` | `first20hours/google-10000-english` — <https://raw.githubusercontent.com/first20hours/google-10000-english/master/google-10000-english.txt> | **MIT** |
| `english-words.txt` | `dwyl/english-words` `words_alpha.txt` — <https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt> (full English dictionary; used to drop Wikidata surname homographs) | **Unlicense** (public domain) |
| `{de,fr,it,es,nl,pl}/common.txt` | Common words (top 10k) per supported language — `oprogramador/most-common-words-by-language` (`src/resources/{german,french,italian,spanish,dutch,polish}.txt`) | **MIT** |

The English/Spanish/word sources are license-clean (public domain / open / CC0 / MIT).
The **Italian** list is a scraped phone-book-derived gazetteer kept under an
explicit project licensing exception: its long tail recovers materially more
LASTNAME recall than the license-clean Wikidata Italian set (+4.7pp vs +1.0pp).
Do **not** use scraped/leaked *person* dumps
(e.g. `philipperemy/name-dataset`, derived from a Facebook leak) for any other
category.

### Wikidata multilingual names (given + surname)
SSA / US-Census cover only US names, so the eval's foreign names (`Sündüz`,
`Olexandr`, `Génesis`, `Lipperini`…) were missed. The Wikidata CC0 name labels
add that tail license-clean. Fetch both lists with:

```bash
crates/pii/tools/fetch_wikidata_names.sh    # writes wikidata/{given,surname}.txt
```

The script pulls one `en` label per name entity. Given names (~100k entities)
fit in one query per `P31` type. The family-name set (~690k) cannot — WDQS
full-scans the `P31` set per request and the 60s timeout truncates responses
over ~35k rows, so the script partitions by `MD5(IRI)` hex prefix and recursively
splits any bucket that comes back short. It is idempotent (cached per bucket) and
retries; re-run after an interrupt to resume.

**Given names are precision-safe as-is.** They are entities explicitly typed as
names, so they carry few word homographs: adding ~80k forms lifted GIVENNAME
recall +9–12pp while precision held (`P_adj` 0.967→0.966, +28 FP for +438 TP).

**The broad set needs homograph exclusion.** The family-name set (~690k) is far
broader and collides with ordinary words: ~3% are English words (`stone`,
`field`, `power`), and others are common words in the languages the proxy serves
(`Steuer` = DE "tax", `le maire` = FR). Added raw they fire on caps alone and
drop `P_adj` to 0.948 — the same failure the Census tail below 1000 shows. The
build tool therefore drops Wikidata given/surname forms that are (a) in
`english-words.txt`, or (b) in any supported-language `common.txt`, or (c)
multi-word (`le maire` / `la roche` — particle phrases that collide with ordinary
phrases; the high-value missed names are all single-token). See
`load_name_list_excluding` + `is_single_token`. Legit word-surnames (`Brown`,
`Hill`) survive via the unfiltered Census source. This restores `P_adj` to 0.964
while keeping the recall gain (LASTNAME +11–14pp) and keeps non-English clean
text clean. Gating via `ALSO_COMMON_WORD` instead was tried and is strictly worse
— it over-gates legit names (recall ↓) and the kept homographs still fire when
promoted (precision ↓).

### Why INE + Wikidata for Spanish
INE publishes the authoritative frequency-ranked surname set but **accent-stripped**
(`GARCIA`), while `normalize` keeps accents (NFC) — so real text `García` would
miss a stripped key. Accents are therefore restored from accented Wikidata CC0
labels (a fold→accented token map); surnames with no accented variant are genuinely
unaccented and kept as-is. This gives INE's coverage with correct accents.

### File formats expected by the tool
- SSA `yob*.txt`: lines `Name,Sex,Count` (counts summed across files/sexes).
- Census `Names_2010Census.csv`: header row, then `name,rank,count,…`; the
  `ALL OTHER NAMES` aggregate row is skipped.
- `it/cognomi.txt`, `es/apellidos.txt`: one surname per line (every form kept; no
  count filter). `es/apellidos.txt` must carry accents (see above).
- `wikidata/{given,surname}.txt`: one name per line (`IS_GIVEN` / `IS_SURNAME`).
  Single-token forms only; forms present in the homograph-exclusion set
  (`english-words.txt` ∪ every `*/common.txt`) are dropped. Normalized, accents kept.
- `google-10000-english.txt`, `{de,fr,it,es,nl,pl}/common.txt`: one word per line.
  These must be *common-vocabulary* lists (curated, proper-noun-free) — a raw
  corpus-frequency list would include frequent surnames (`García`, `Rossi`) and
  wrongly gate/exclude them. The lists exclude surnames, so `García`/`Esposito`
  stay un-gated while real homographs (`Costa`, `Forte`, `Sole`) are flagged.
  `google-10000` + `it/es` gate `ALSO_COMMON_WORD`; all six also feed the Wikidata
  homograph exclusion.
- `english-words.txt`: one English dictionary word per line. A **dictionary**
  list, not corpus-frequency, so it is proper-noun-free (`García`/`Rossi` absent)
  — used only to drop Wikidata homographs, never to gate.

## Build

```bash
cargo run -p pii --features build-names-fst --bin build_names_fst
```

Defaults: reads this dir, writes `../names.fst`. Override with `NAMES_DATA_DIR` /
`NAMES_FST_OUT` (or positional args). The tool prints the final entry count and
artifact size.

## Normalization (build == query)

Each form is normalized **lowercase (Unicode-correct) → NFC** and forms shorter
than 2 chars are dropped. The detector applies the **identical** normalization at
query time — see `DictionaryDetector` — or lookups silently miss.

## Coverage band (reproducibility knobs)

| Env var | Default | Meaning |
|---|---:|---|
| `SURNAME_MIN_COUNT` | `1000` | keep Census surnames with `count ≥ N` |
| `GIVEN_MIN_COUNT` | `0` | keep SSA given names with summed `count ≥ N` (0 = all) |

Default band = Census surnames with **≥1000 occurrences** (~25k forms) + all SSA
given names (~106k). The Census tail below ~1000 is dominated by word-like /
foreign rare surnames (`Steuer`, `Leipzig`, `Found`, `Siren`…) that, lowercased,
collide with ordinary words and wreck precision; the surnames we care about are
far more frequent (Smith 2.4M, Lopez 874k, Kowalski 18k). Record any change here
so the artifact stays reproducible.

The IT (~37k) and ES (~26k) surname lists, the Wikidata given-name list (~60k
after exclusion), and the Wikidata surname list (~500k after exclusion) carry no
occurrence counts and are added in full (no `MIN_COUNT` knob) — recall-first. The
total artifact is ~660k entries / ~3.5 MB.

## Value bitmask

The FST value per key is a `u64` OR of: `IS_GIVEN` (`1<<0`), `IS_SURNAME` (`1<<1`),
`ALSO_COMMON_WORD` (`1<<2`). `ALSO_COMMON_WORD` is auto-derived by intersecting the
name set with the common-word lists (EN `google-10000-english.txt` + IT/ES
`{it,es}/common.txt`) — not hand-curated. These constants must match
`DictionaryDetector` (`docs/history/tasks-phases-1-20.md` § 20.2).

## Reproducibility

Same inputs + same coverage band → **byte-identical** `names.fst` (sorted
`BTreeMap` keys + deterministic `fst` build). Verify:

```bash
cargo run -p pii --features build-names-fst --bin build_names_fst -- "$PWD" /tmp/a.fst
cargo run -p pii --features build-names-fst --bin build_names_fst -- "$PWD" /tmp/b.fst
sha256sum /tmp/a.fst /tmp/b.fst   # hashes must match
```
