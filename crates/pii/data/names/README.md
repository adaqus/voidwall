# English names gazetteer — source data & provenance

Inputs for the offline `build_names_fst` tool (`crates/pii/tools/build_names_fst.rs`),
which emits the committed artifact `crates/pii/data/names_en.fst` used by the
`DictionaryDetector` (`PersonName`, English).

The **raw source files in this directory are git-ignored** (large, re-fetchable);
only `names_en.fst` is committed. Download the sources below, then rebuild.

## Sources (all license-clean — public domain / permissive)

| File (place here) | Source | License |
|---|---|---|
| `ssa/yob*.txt` | US SSA, national given names — <https://www.ssa.gov/oact/babynames/names.zip> (unzip) | **Public domain** (US gov work) |
| `Names_2010Census.csv` | US Census Bureau, *Frequently Occurring Surnames 2010* — <https://www2.census.gov/topics/genealogy/2010surnames/names.zip> (unzip) | **Public domain** (US gov work) |
| `google-10000-english.txt` | `first20hours/google-10000-english` — <https://raw.githubusercontent.com/first20hours/google-10000-english/master/google-10000-english.txt> | **MIT** |

Do **not** use scraped/leaked dumps (e.g. `philipperemy/name-dataset`, derived
from a Facebook leak) — legal/ethical risk.

### File formats expected by the tool
- SSA `yob*.txt`: lines `Name,Sex,Count` (counts summed across files/sexes).
- Census `Names_2010Census.csv`: header row, then `name,rank,count,…`; the
  `ALL OTHER NAMES` aggregate row is skipped.
- `google-10000-english.txt`: one lowercase word per line.

## Build

```bash
cargo run -p pii --features build-names-fst --bin build_names_fst
```

Defaults: reads this dir, writes `../names_en.fst`. Override with `NAMES_DATA_DIR` /
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

## Value bitmask

The FST value per key is a `u64` OR of: `IS_GIVEN` (`1<<0`), `IS_SURNAME` (`1<<1`),
`ALSO_COMMON_WORD` (`1<<2`). `ALSO_COMMON_WORD` is auto-derived by intersecting the
name set with `google-10000-english.txt` — not hand-curated. These constants must
match `DictionaryDetector` (TASKS.md 20.2).

## Reproducibility

Same inputs + same coverage band → **byte-identical** `names_en.fst` (sorted
`BTreeMap` keys + deterministic `fst` build). Verify:

```bash
cargo run -p pii --features build-names-fst --bin build_names_fst -- "$PWD" /tmp/a.fst
cargo run -p pii --features build-names-fst --bin build_names_fst -- "$PWD" /tmp/b.fst
sha256sum /tmp/a.fst /tmp/b.fst   # hashes must match
```
