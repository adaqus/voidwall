---
name: update-landing-piis
description: Sync the marketing landing page (docker/landing) with the current PII coverage — the supported PII-type / country / language counts and the language + country lists shown on the page, derived from the enums in the `pii` crate (crates/pii/src/lib.rs). Use ONLY when the user explicitly asks to update/refresh the landing page stats. Do NOT invoke automatically after add-pii or after any change to PII types, countries, or languages — it is a manual, user-triggered step.
---

# Update the landing page coverage stats

The landing page advertises how many PII types / languages / countries Voidwall
supports, plus the language and country lists. Those numbers and lists are
**hand-maintained JSX** and drift out of sync whenever the `pii` crate gains a
new PII type, country, or language. This skill regenerates them from the
single source of truth: the enums in `crates/pii/src/lib.rs`.

## Source of truth

| What | Enum / array in `crates/pii/src/lib.rs` |
| --- | --- |
| Built-in PII types | `PiiKind::ALL` (does **not** include the `Custom` marker) |
| Countries | `Country::all()` — **exclude `Country::International`**; it is not a country |
| Languages | `Language::all()` |

Never count by reading the page or from memory — always re-derive from the enums.

## What this skill touches (and what it must not)

Edit only the PII/country/language facts in these two files, then rebuild:

- `docker/landing/src/03-metrics.jsx` — the top metrics strip.
- `docker/landing/src/05-coverage.jsx` — the "Detection coverage" section.

Leave the **Specializations** and **Formats** metrics, and everything else on the
page, alone — they are not derived from the `pii` enums. Match existing JSX style.

## Step 1 — Extract ground truth from the enums

Run from the workspace root:

```bash
LIB=crates/pii/src/lib.rs

# Built-in PII type count (PiiKind::ALL, excludes Custom):
awk '/const ALL: &\[PiiKind\] = &\[/,/^    \];/' "$LIB" | grep -c 'PiiKind::'

# Country count (excludes International — the "- 1"):
echo $(( $(awk '/pub fn all\(\) -> &.static \[Country\]/,/^    }/' "$LIB" | grep -c 'Country::') - 1 ))

# Language count:
awk '/pub fn all\(\) -> &.static \[Language\]/,/^    }/' "$LIB" | grep -c 'Language::'

# Ordered Country variants (first is International — drop it for the count, keep
# it as the leading chip in the coverage list):
awk '/pub fn all\(\) -> &.static \[Country\]/,/^    }/' "$LIB" | grep -oP 'Country::\K\w+'

# Ordered Language variants:
awk '/pub fn all\(\) -> &.static \[Language\]/,/^    }/' "$LIB" | grep -oP 'Language::\K\w+'

# Full built-in PII label list (SCREAMING_SNAKE, for completeness-checking the
# coverage groups; CUSTOM is the marker — ignore it):
awk '/pub const fn label/,/^    }$/' "$LIB" | grep -oP '=> "\K[^"]+' | grep -v '^CUSTOM$'
```

Cross-check: the PII count from `PiiKind::ALL` must equal the label-list length
(minus `CUSTOM`). If they differ, a variant is missing from `ALL` or `label()` —
stop and fix the enum first; the page would be wrong either way.

## Step 2 — Display-name maps

The enums use ISO-style codes; the page shows full names. Maintain these maps.
If Step 1 surfaces a code not listed here, add it (research the standard
English name + native language name) rather than guessing inline.

**Country code → display name** (order follows `Country::all()`):

| Code | Display name |
| --- | --- |
| `International` | International |
| `Us` | United States |
| `Gb` | Great Britain |
| `Au` | Australia |
| `Nz` | New Zealand |
| `Ca` | Canada |
| `Ie` | Ireland |
| `Za` | South Africa |
| `Fr` | France |
| `De` | Germany |
| `At` | Austria |
| `Ch` | Switzerland |
| `Nl` | Netherlands |
| `It` | Italy |

**Language code → `[code, native name, English name]`:**

| Code | Chip code | Native | English |
| --- | --- | --- | --- |
| `En` | EN | English | English |
| `Fr` | FR | Français | French |
| `De` | DE | Deutsch | German |
| `Nl` | NL | Nederlands | Dutch |
| `It` | IT | Italiano | Italian |

## Step 3 — Update `03-metrics.jsx`

The metrics array (`function Metrics`) holds `[number, suffix, label, sub]` rows.
Update three rows from Step 1:

- **PII types** row → first field = the PII count.
- **Languages** row → first field = the language count; `sub` = English names joined
  with `", "` (e.g. `"English, French, German, Dutch, Italian"`).
- **Countries** row → first field = the country count (excl. International); `sub` =
  a short representative list ending in `…` (e.g. `"USA, UK, France, Germany…"`) —
  this is an abbreviated teaser, not the full list, so keep it short.

## Step 4 — Update `05-coverage.jsx`

1. **Heading** — the `<h2>` reads `<N> PII types.<br/>And growing.`. Set `<N>` to
   the PII count from Step 1.
2. **Top-of-file comment** — update the `// … PII types organized by category …`
   line if its number drifted (keep it approximate, e.g. "100+").
3. **`languages` array** — regenerate fully from Step 1 + the language map:
   one `[chipCode, nativeName]` entry per `Language::all()` variant, in enum order.
4. **`countries` array** — regenerate fully from Step 1 + the country map:
   `"International"` first, then every other `Country::all()` variant's display
   name, in enum order. This list is complete (the "+ more soon" chip is rendered
   separately in the JSX — leave it).
5. **`groups` array (the PII-type cards)** — these are a **curated, human-friendly
   sample** ("Here are examples…"), not a 1:1 dump of all labels, and the `hot`
   boolean is an editorial highlight. Do **not** mechanically expand it to every
   label. Instead, using the full label list from Step 1:
   - Ensure every **country and PII category newly added** since the last sync is
     represented by at least one entry in the most fitting group (`Identity &
     Contact`, `National IDs`, `Travel & Driving`, `Health & Tax`, `Financial &
     Crypto`, `Tech & Secrets`). Use the same `["Label", hot]` shape and the
     existing `"CC - Name"` convention for country-scoped items (e.g.
     `["IT - Codice Fiscale", false]`).
   - Leave existing curated entries and their `hot` flags as they are unless a
     type was removed from the enum (then drop it).
   - If unsure whether a brand-new category warrants a card entry, surface it to
     the user rather than silently adding or skipping.

## Step 5 — Rebuild and verify

The served page is the pre-rendered `docker/landing/index.html`; editing the JSX
alone does not update it. Rebuild:

```bash
docker/landing/build.sh
```

This needs Docker (it transpiles the JSX and pre-renders with headless Chromium —
see `docker/landing/README.md`). If Docker is unavailable, say so and stop with the
JSX edits made, rather than leaving `index.html` silently stale.

Verify before finishing:

- The PII number in `03-metrics.jsx` equals the heading number in `05-coverage.jsx`
  equals the Step-1 PII count.
- `languages` / `countries` array lengths match the Step-1 counts (countries =
  count + 1 for the leading "International" chip).
- `git diff docker/landing/index.html` shows the new numbers rendered.
