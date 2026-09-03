//! Offline gazetteer build tool — produces `data/names.fst` from the source
//! name lists (EN/IT/ES + multilingual Wikidata names). **Build-time only**; not
//! compiled into the proxy image (gated behind the `build-names-fst` feature).
//!
//! Run:
//! ```text
//! cargo run -p voidwall-pii --features build-names-fst --bin build_names_fst
//! ```
//!
//! Inputs (download per `data/names/README.md`, default dir `<crate>/data/names`):
//!   - `ssa/*.txt`              US SSA national given names  (`Name,Sex,Count`)
//!   - `Names_2010Census.csv`   US Census 2010 surnames      (`name,rank,count,…`)
//!   - `it/cognomi.txt`         Italian surnames             (one surname per line)
//!   - `es/apellidos.txt`       Spanish surnames, accented   (one surname per line)
//!   - `wikidata/{given,surname}.txt`  Multilingual Wikidata names, one per line
//!     (fetch with `tools/fetch_wikidata_names.sh`)
//!   - `google-10000-english.txt`  EN common-word list (one word per line)
//!   - `english-words.txt`      Full EN dictionary (Wikidata homograph exclusion)
//!   - `{de,fr,it,es,nl,pl}/common.txt`  Per-language common-word lists
//!
//! Output (committed): `<crate>/data/names.fst` — an `fst::Map` whose value is
//! the `u64` flag bitmask below.
//!
//! Override paths with env vars (or positional args): `NAMES_DATA_DIR`, `NAMES_FST_OUT`.
//! Coverage knobs: `SURNAME_MIN_COUNT` (default 100), `GIVEN_MIN_COUNT` (default 0).

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter};
use std::path::{Path, PathBuf};

use fst::MapBuilder;

// Imported from the crate so the artifact and the detector can never drift
// (single source of truth in src/dictionary_detector.rs):
//   - flag bitmask: the FST value for each key is the OR of these bits;
//   - `normalize`: the canonical lowercase + NFC key normalization, applied
//     identically here (build) and at query time (or lookups silently miss).
use voidwall_pii::dictionary_detector::flags::{ALSO_COMMON_WORD, IS_GIVEN, IS_SURNAME};
use voidwall_pii::dictionary_detector::normalize;

/// Drop name forms shorter than this (initials, stray single letters).
const MIN_NAME_LEN: usize = 2;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut args = std::env::args().skip(1);

    let data_dir = args
        .next()
        .or_else(|| std::env::var("NAMES_DATA_DIR").ok())
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join("data/names"));
    let out_path = args
        .next()
        .or_else(|| std::env::var("NAMES_FST_OUT").ok())
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join("data/names.fst"));

    // Surnames below this Census 2010 occurrence count are dropped. The Census
    // tail (100–~1000) is dominated by word-like / foreign rare surnames
    // (Steuer, Leipzig, Found, Siren…) that, lowercased, collide with ordinary
    // words and wreck precision; the names we care about are far more frequent
    // (Smith 2.4M, Lopez 874k, Kowalski 18k). 1000 keeps those and cuts the noise.
    let surname_min: u64 = env_num("SURNAME_MIN_COUNT", 1000);
    let given_min: u64 = env_num("GIVEN_MIN_COUNT", 0);

    eprintln!("data dir : {}", data_dir.display());
    eprintln!("out      : {}", out_path.display());
    eprintln!("surname_min_count = {surname_min}, given_min_count = {given_min}");

    // 1. Common-word lists → set of normalized words. A name form present here
    //    gets ALSO_COMMON_WORD (auto-derived, not hand-curated), so a bare hit
    //    on it is suppressed unless corroborated. EN + IT + ES so that surnames
    //    which are also ordinary IT/ES words (`Costa`, `Forte`, `Sole`) are
    //    homograph-gated the same way English ones (`Will`, `Rose`) are.
    let mut common = load_common_words(&data_dir.join("google-10000-english.txt"));
    common.extend(load_common_words(&data_dir.join("it/common.txt")));
    common.extend(load_common_words(&data_dir.join("es/common.txt")));
    eprintln!("common words loaded: {}", common.len());

    // Homograph-exclusion set for the broad Wikidata name lists. A Wikidata form
    // present here is dropped (not gated): gating via ALSO_COMMON_WORD was tried
    // and is strictly worse — it over-gates legit names (recall ↓) while the kept
    // homographs still fire when promoted (precision ↓). Only the Wikidata lists
    // are filtered; the curated EN/IT/ES sources vouch for their own entries.
    //
    // It unions: (1) the full English **dictionary** (`english-words.txt` —
    // proper-noun-free, so `stone`/`brown` but not `García`/`Rossi`), and (2) the
    // common-word list of every **supported language**. Both are needed: the broad
    // multilingual set collides with ordinary words in each language the proxy
    // serves — `Steuer` (DE "tax"), `le maire` (FR) — and those fire on caps alone
    // in that language's clean text. The per-language lists are the same curated,
    // surname-free `oprogramador` lists used for gating, so real surnames survive.
    let mut wd_exclude = load_common_words(&data_dir.join("english-words.txt"));
    for lang in ["de", "fr", "it", "es", "nl", "pl"] {
        wd_exclude.extend(load_common_words(&data_dir.join(lang).join("common.txt")));
    }
    eprintln!("wikidata exclusion words: {}", wd_exclude.len());

    // 2./3. Accumulate flags per normalized form across both sources.
    let mut forms: BTreeMap<String, u64> = BTreeMap::new();

    let given = load_ssa_given(&data_dir.join("ssa"), given_min, &mut forms);
    eprintln!("given-name forms : {given}");

    // Multilingual given names from Wikidata CC0 (instances of male/female/unisex
    // given name). License-clean, one normalized form per line; extends SSA's
    // US-centric coverage to the foreign given names the eval misses (Sündüz,
    // Olexandr, Génesis…). Word homographs are dropped (see `wd_exclude`).
    let (wd_given, wd_given_dropped) = load_name_list_excluding(
        &data_dir.join("wikidata/given.txt"),
        IS_GIVEN,
        &wd_exclude,
        &mut forms,
    );
    eprintln!("WD given forms   : {wd_given} (dropped {wd_given_dropped} homographs)");

    // Multilingual surnames from Wikidata CC0 (instances of family name). Word
    // homographs are dropped (see `wd_exclude` above); legit word-surnames
    // (`Brown`, `Hill`) survive via the Census source, which is unfiltered.
    let (wd_surname, wd_surname_dropped) = load_name_list_excluding(
        &data_dir.join("wikidata/surname.txt"),
        IS_SURNAME,
        &wd_exclude,
        &mut forms,
    );
    eprintln!("WD surname forms : {wd_surname} (dropped {wd_surname_dropped} homographs)");

    let surname = load_census_surnames(
        &data_dir.join("Names_2010Census.csv"),
        surname_min,
        &mut forms,
    );
    eprintln!("surname forms    : {surname}");

    // IT/ES surnames (plain one-per-line lists, not frequency-ranked, so no
    // count filter). Accented forms pass through `normalize` (NFC) unchanged.
    let it_surname = load_surname_list(&data_dir.join("it/cognomi.txt"), &mut forms);
    eprintln!("IT surname forms : {it_surname}");
    let es_surname = load_surname_list(&data_dir.join("es/apellidos.txt"), &mut forms);
    eprintln!("ES surname forms : {es_surname}");

    // Tag homographs of common words.
    let mut common_flagged = 0usize;
    for (key, flags) in forms.iter_mut() {
        if common.contains(key) {
            *flags |= ALSO_COMMON_WORD;
            common_flagged += 1;
        }
    }

    // 4. Build the FST. BTreeMap already yields keys in lexicographic byte
    //    order (keys are normalized lowercase), which is what `fst` requires.
    let file = File::create(&out_path).expect("create output fst");
    let mut builder = MapBuilder::new(BufWriter::new(file)).expect("init MapBuilder");
    for (key, flags) in &forms {
        builder
            .insert(key, *flags)
            .expect("insert key (must be sorted+unique)");
    }
    builder.finish().expect("finish fst");

    let both = forms
        .values()
        .filter(|f| **f & (IS_GIVEN | IS_SURNAME) == (IS_GIVEN | IS_SURNAME))
        .count();
    let size = fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);

    eprintln!("---");
    eprintln!("total entries        : {}", forms.len());
    eprintln!("  given|surname both : {both}");
    eprintln!("  also-common-word   : {common_flagged}");
    eprintln!(
        "artifact size        : {size} bytes ({:.2} MB)",
        size as f64 / 1_048_576.0
    );
    eprintln!("wrote {}", out_path.display());
}

fn env_num(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn open_lines(path: &Path) -> BufReader<File> {
    let f = File::open(path).unwrap_or_else(|e| {
        panic!(
            "open {} : {e}\n(download the source data — see data/names/README.md)",
            path.display()
        )
    });
    BufReader::new(f)
}

/// Read a one-word-per-line frequency list into a set of normalized words.
fn load_common_words(path: &Path) -> HashSet<String> {
    let mut set = HashSet::new();
    for line in open_lines(path).lines().map_while(Result::ok) {
        let w = normalize(&line);
        if w.len() >= MIN_NAME_LEN {
            set.insert(w);
        }
    }
    set
}

/// Read every `*.txt` in the SSA dir (`Name,Sex,Count`), summing counts per
/// normalized name across sexes/years, then OR `IS_GIVEN` for names ≥ `min`.
fn load_ssa_given(dir: &Path, min: u64, forms: &mut BTreeMap<String, u64>) -> usize {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let entries = fs::read_dir(dir).unwrap_or_else(|e| {
        panic!(
            "read SSA dir {} : {e}\n(unzip names.zip here — see data/names/README.md)",
            dir.display()
        )
    });
    let mut files = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("txt") {
            continue;
        }
        files += 1;
        for line in open_lines(&path).lines().map_while(Result::ok) {
            let mut it = line.split(',');
            let (Some(name), Some(_sex), Some(cnt)) = (it.next(), it.next(), it.next()) else {
                continue;
            };
            let key = normalize(name);
            if key.len() < MIN_NAME_LEN {
                continue;
            }
            *counts.entry(key).or_insert(0) += cnt.trim().parse::<u64>().unwrap_or(0);
        }
    }
    assert!(
        files > 0,
        "no .txt files in {} — unzip SSA names.zip there",
        dir.display()
    );

    let mut kept = 0;
    for (name, total) in counts {
        if total >= min {
            *forms.entry(name).or_insert(0) |= IS_GIVEN;
            kept += 1;
        }
    }
    kept
}

/// A normalized key is a single name token if it holds no internal separator.
/// Multi-word Wikidata entries (`le maire`, `la roche`) collide with ordinary
/// foreign-language phrases ("le maire" = the mayor) and are the dominant false
/// positive once the broad set is added; the high-value missed names are all
/// single-token, so we keep only those. (Multi-word native names still come from
/// the curated EN/IT/ES sources, which are not filtered.) Hyphenated forms are
/// excluded too — they would never match anyway, since the detector keys windows
/// with space-joined tokens.
fn is_single_token(key: &str) -> bool {
    !key.bytes().any(|b| b == b' ' || b == b'-')
}

/// Load a one-name-per-line Wikidata list, OR-ing `flag` (`IS_GIVEN`/`IS_SURNAME`)
/// for each single-token form ≥ `MIN_NAME_LEN` that is **not** in `exclude`. The
/// exclusion drops cross-language word homographs (`stone`, `Steuer`) that would
/// otherwise fire on caps alone and wreck precision. Returns `(kept, dropped)`.
fn load_name_list_excluding(
    path: &Path,
    flag: u64,
    exclude: &HashSet<String>,
    forms: &mut BTreeMap<String, u64>,
) -> (usize, usize) {
    let (mut kept, mut dropped) = (0, 0);
    for line in open_lines(path).lines().map_while(Result::ok) {
        let key = normalize(&line);
        if key.len() < MIN_NAME_LEN || !is_single_token(&key) {
            continue;
        }
        if exclude.contains(&key) {
            dropped += 1;
            continue;
        }
        *forms.entry(key).or_insert(0) |= flag;
        kept += 1;
    }
    (kept, dropped)
}

/// Read a one-surname-per-line list (IT/ES gazetteers), OR `IS_SURNAME` for each
/// normalized form ≥ `MIN_NAME_LEN`. Unlike the Census source these lists carry
/// no occurrence counts, so every entry is kept.
fn load_surname_list(path: &Path, forms: &mut BTreeMap<String, u64>) -> usize {
    let mut kept = 0;
    for line in open_lines(path).lines().map_while(Result::ok) {
        let key = normalize(&line);
        if key.len() < MIN_NAME_LEN {
            continue;
        }
        *forms.entry(key).or_insert(0) |= IS_SURNAME;
        kept += 1;
    }
    kept
}

/// Read the Census 2010 surname CSV (`name,rank,count,…`); OR `IS_SURNAME` for
/// surnames with `count` ≥ `min`. Skips the header and the `ALL OTHER NAMES` row.
fn load_census_surnames(path: &Path, min: u64, forms: &mut BTreeMap<String, u64>) -> usize {
    let mut kept = 0;
    for (i, line) in open_lines(path).lines().map_while(Result::ok).enumerate() {
        if i == 0 {
            continue; // header: name,rank,count,prop100k,...
        }
        let mut it = line.split(',');
        let (Some(name), Some(_rank), Some(cnt)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if name.eq_ignore_ascii_case("ALL OTHER NAMES") {
            continue;
        }
        let count: u64 = cnt.trim().parse().unwrap_or(0);
        if count < min {
            continue;
        }
        let key = normalize(name);
        if key.len() < MIN_NAME_LEN {
            continue;
        }
        *forms.entry(key).or_insert(0) |= IS_SURNAME;
        kept += 1;
    }
    kept
}
