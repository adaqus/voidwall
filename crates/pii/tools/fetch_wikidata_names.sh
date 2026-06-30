#!/usr/bin/env bash
#
# Fetch the Wikidata CC0 name gazetteers consumed by `build_names_fst`:
#   data/names/wikidata/given.txt    — multilingual given names
#   data/names/wikidata/surname.txt  — multilingual surnames
#
# Source: `en` rdfs:label of every entity that is an instance (P31) of a
# given-name / family-name class. License: Wikidata CC0.
#
# Why bucketing: the family-name set (~690k entities) cannot be pulled in one
# WDQS query — the engine full-scans the P31 set per request and the 60s server
# timeout truncates any response larger than ~35k rows. We therefore partition
# by MD5(entity-IRI) hex prefix (uniform, deterministic). A single-hex bucket
# (~37k) rides the timeout edge, so a bucket that comes back short or as an HTTP
# error is recursively split into its sixteen 2-hex children (~2.3k each, which
# always complete). Given names (~100k entities) fit in one query per P31 type.
#
# Robust + idempotent: each bucket is validated (TSV header, no HTML error,
# plausible row count) and retried; completed buckets are cached and skipped on
# re-run. Re-running after an interrupt resumes where it stopped.
#
# Usage: crates/pii/tools/fetch_wikidata_names.sh
# Then rebuild: cargo run -p pii --features build-names-fst --bin build_names_fst

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$SCRIPT_DIR/../data/names/wikidata"
CACHE="$OUT_DIR/.cache"           # raw per-bucket TSV cache
mkdir -p "$CACHE"

ENDPOINT='https://query.wikidata.org/sparql'
UA='voidwall-pii-gazetteer/1.0 (https://github.com/; adaqus@gmail.com)'
# A single-hex MD5 bucket holds ~37k rows when complete; below this we treat the
# response as timeout-truncated and split it.
FULL_MIN=34000

# Run one SPARQL query → TSV on stdout. Returns non-zero on transport error.
sparql() { curl -s -G "$ENDPOINT" --data-urlencode "query=$1" \
  -H 'Accept: text/tab-separated-values' -A "$UA" --max-time 90; }

# A TSV is valid if it has the `?l` header, carries no nginx/HTML error page, and
# has at least `$2` data rows.
valid_tsv() { local f="$1" min="$2"
  head -1 "$f" 2>/dev/null | grep -q '^?l' \
    && ! grep -qi '<html\|timeout\|Bad Gateway' "$f" \
    && [ "$(grep -c '@en' "$f")" -ge "$min" ]; }

# Fetch instances of P31=$2 whose MD5(IRI) starts with prefix $3 (empty = all),
# into cache file $1. Retries on transport/validation failure.
fetch_into() { local out="$1" p31="$2" pfx="$3" min="${4:-1}" t=0 q filt=""
  [ -s "$out" ] && valid_tsv "$out" "$min" && return 0
  [ -n "$pfx" ] && filt="FILTER(STRSTARTS(MD5(STR(?i)),\"$pfx\"))"
  q="SELECT ?l WHERE { ?i wdt:P31 wd:$p31 . $filt ?i rdfs:label ?l . FILTER(LANG(?l)=\"en\") }"
  while [ $t -lt 4 ]; do
    sparql "$q" > "$out"
    valid_tsv "$out" "$min" && return 0
    t=$((t+1)); sleep 5
  done
  return 1
}

# Fetch a whole P31 class by MD5 bucketing: try each single-hex bucket; split any
# that won't reach FULL_MIN into 2-hex children. Concatenate raw labels to $1.
fetch_class() { local dest="$1" p31="$2" h sh f
  : > "$dest"
  for h in 0 1 2 3 4 5 6 7 8 9 a b c d e f; do
    f="$CACHE/${p31}_$h.tsv"
    if fetch_into "$f" "$p31" "$h" "$FULL_MIN"; then
      grep '@en' "$f" >> "$dest"
    else
      echo "  bucket $h short — splitting into 2-hex children"
      for sh in 0 1 2 3 4 5 6 7 8 9 a b c d e f; do
        f="$CACHE/${p31}_$h$sh.tsv"
        if fetch_into "$f" "$p31" "$h$sh" 1; then
          grep '@en' "$f" >> "$dest"
        else
          echo "  WARN: child $h$sh failed after retries (skipped)"
        fi
      done
    fi
    echo "  ${p31} progress: $(grep -c '@en' "$dest") rows"
  done
}

# Normalize raw `"Label"@en` TSV rows → unique, NFC-lowercased, Latin-letter name
# forms, one per line. (Mirrors `normalize` + the build tool's length floor.)
clean() { python3 - "$@" <<'PY'
import sys, re, unicodedata
seen = set()
for path in sys.argv[2:]:
    for ln in open(path, encoding="utf-8"):
        m = re.match(r'^"(.*)"@en$', ln.rstrip("\n"))
        if not m: continue
        n = m.group(1)
        if not (2 <= len(n) <= 30): continue
        if not re.fullmatch(r"[A-Za-zÀ-ÖØ-öø-ÿ'’\-\. ]+", n): continue
        seen.add(unicodedata.normalize("NFC", n.strip().lower()))
with open(sys.argv[1], "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(seen)) + "\n")
print(f"  wrote {len(seen)} -> {sys.argv[1]}")
PY
}

echo "== given names (Q12308941 male, Q11879590 female, Q3409032 unisex) =="
: > "$CACHE/given.raw"
for q in Q12308941 Q11879590 Q3409032; do
  f="$CACHE/$q.tsv"
  fetch_into "$f" "$q" "" 1 && grep '@en' "$f" >> "$CACHE/given.raw" \
    || echo "  WARN: $q failed"
done
clean "$OUT_DIR/given.txt" "$CACHE/given.raw"

echo "== surnames (Q101352 family name) =="
fetch_class "$CACHE/surname.raw" Q101352
clean "$OUT_DIR/surname.txt" "$CACHE/surname.raw"

echo "done. rebuild: cargo run -p pii --features build-names-fst --bin build_names_fst"
