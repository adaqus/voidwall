---
name: add-pii-language-country
description: Add support for a new language and/or country to the `pii` crate (crates/pii). Use when asked to add a new country's PII types (e.g. national ID, postcode, phone, passport) or to add detection/keywords for a new language. Use also when language or country is already supported, but new PII type is added. Covers the full checklist, real-world validation, keyword-context pattern rules, test requirements, and known pitfalls.
---

# Adding a New Language + Country to the `pii` crate

Distilled from the French (`Language::Fr`, `Country::Fr`) implementation. Read
`crates/pii/CLAUDE.md` first for the crate's architecture (two-detector design,
overlap resolution, detector chain). This skill is the authoritative workflow for
the language/country task and is self-contained for it.

## Step 0: Determine scope before touching code

Do this first, every time — before reading source or editing anything.

**1. Confirm the target language and country.** If the invocation did not name them
explicitly, ask the user which country and which language to add (use `AskUserQuestion`).
Do not guess or assume from context. A country and its keyword language are separate
choices — confirm both (e.g. Switzerland uses German, French, and Italian; Belgium uses
Dutch and French). Resolve each to the ISO 3166-1 alpha-2 `Country` variant and the
`Language` variant you will add.

**2. Research which PII types the country uses.** Once the country is fixed, search the
web to determine which PII types belong to it — do not invent the list from memory.

- Search official government / tax / health-authority pages and Wikipedia for the
  country's national identifiers: national ID number, tax ID, social-security/health
  number, passport/ID-card number, driver's licence, postal code, phone format,
  company/VAT registration number, bank account/IBAN specifics.
- For each candidate, capture its **format** (length, character set, separators) and
  whether it carries a **checksum** (e.g. 11-test, Luhn, mod-97) — you will need this for
  the validator and for sourcing real examples later.
- Cross-check against the existing `PiiKind` variants in `src/lib.rs`. Skip anything
  already covered internationally (e.g. `Iban`, `CreditCard`, `Email`, `SwiftBic`,
  `Imei`) unless the country needs a stricter, country-scoped variant.
- **Check the list for consistency with the countries already implemented.** Look at the
  per-country `PiiKind` variants in `src/lib.rs` (the `country()` match arms) and note
  which categories recur across most of them — national ID, tax ID, passport/ID-card
  number, driver's licence, postal code, phone number. If a category is present for
  almost every existing country but missing from your candidate list, that is a red flag:
  re-research it for the new country before dropping it. Most countries have a national
  ID, so a proposed list without one almost certainly has a gap. Only omit a recurring
  category when you can confirm the country genuinely has no equivalent.
- Present the researched candidate list back to the user (use `AskUserQuestion`,
  `multiSelect`) and let them confirm the final scope before implementing. Note which
  candidates have checksums so the user understands validation strength.

Only after the country, language, and confirmed PII-type list are settled do you proceed
to the files below.

## Files to modify

1. **`src/lib.rs`** — Add `Country` variant + `Country::all()`, `Language` variant +
   `Language::all()`, new `PiiKind` variants with `label()`, `country()`, and `ALL` entries.
2. **`src/validators.rs`** — Add country-specific validators with unit tests.
3. **`src/keyword_context_detector.rs`** — Add `Language::NewLang` patterns for new PII
   types AND translated keywords for existing international types (`UsPhoneNumber`,
   `PassportNumber`, `DateOfBirth`, `PreciseGeolocation`, `SwiftBic`, `Imei`). Add
   `#[test_case]` entries to `detects_with_keyword`, `no_detection_without_keyword`,
   `rejects_invalid_with_keyword`.
4. **`benches/pii_benchmark.rs`** — Add corpus constants, `per_pii_kind` entries, and
   samples in `MIXED_PII_TEXT`.

If the new kind can produce equal-span matches with an existing kind, also add it to a
priority group in `overlap.rs` (see the "Overlap resolution" section of
`crates/pii/CLAUDE.md`). Containment cases (a wider kind whose match strictly contains a
narrower one, e.g. address ⊃ postcode) are handled by generic rules and need no priority entry.

## Validate with real-world examples

After implementing validators and patterns, search the web for documented real examples
and add them as additional test cases. This catches algorithm bugs that synthetic test
data may miss.

1. **Find documented examples** — Search official government docs, Wikipedia, and
   open-source validator repos (e.g. `github.com/rechtlogisch/steuer-id`,
   `gist.github.com/jensens` for AT SVNR, `sozialversicherungsnummer.ch` for CH AHV).
   Look for pages like `kryptografie.de` that show worked check-digit calculations.
2. **Verify programmatically** — Before adding examples as test values, verify them
   independently with a script (e.g. Python) that reimplements the check-digit algorithm.
   Never trust a web source without cross-checking.
3. **Add to validator unit tests** (`src/validators.rs`) — Add the verified real examples
   as additional `#[test]` cases, citing the source in a comment
   (e.g. `// From sozialversicherungsnummer.ch`).
4. **Add to keyword detector tests** (`src/keyword_context_detector.rs`) — Add
   `#[test_case]` entries using the real values with different keyword variants (long
   keyword, short keyword, alternative keywords).
5. **Test boundary/edge cases** — Use real-world knowledge to add tests for boundaries:
   check-digit-is-zero, upper/lower range limits for postal codes, off-by-one invalid
   checksums, real city postal codes (Berlin 10115, Vienna 1010, Zürich 8001).

## Adding keyword-context patterns

When adding or extending patterns in `keyword_context_detector.rs`, follow these rules.
Past detection bugs trace directly to violations.

**1. Plurals are mandatory.** Every value-bearing keyword must accept its plural form.
The keyword/value separator class is `[\s:.#/\-"=,\]\\]` with `*?` (lazy zero-or-more);
anything outside that class — including letters like `s` and `_` — between the keyword and
the value blocks the match. Without an explicit suffix, `phone_number: 555…` matches but
`phone_numbers: 555…` does not.

Suffix shape per language:
- **English**: typically `s?`, occasionally `(?:s|es)?` (e.g. `phone_numbers?`,
  `passport(?:s|es)?`, `fax(?:es)?`).
- **French**: typically `s?` (e.g. `num[eé]ros?`, `passeports?`); `(?:s|x)?` only for the
  rare `-x` plurals (e.g. `bureau(?:x)?`).
- **German**: per-keyword — `Nummer` → `Nummern` so use `(?:n)?`; `Telefon` → `Telefone`
  so use `e?`; compounds usually pluralize on the final element only. Do **not**
  blanket-apply `s?` to German keywords.

Suffix groups must admit *only* the legitimate plural ending — never widen to arbitrary
letters. `phoned`, `phoning`, `Telefonate` must still not match.

**2. Test rows for every new keyword.** Each new pattern must ship with `#[test_case]`
rows covering all of:
- singular form (e.g. `phone_number: 555-1234`)
- plural form (e.g. `phone_numbers: 555-1234`)
- camelCase (e.g. `phoneNumber: 555-1234`)
- snake_case (e.g. `phone_number: 555-1234`)
- kebab-case (e.g. `phone-number: 555-1234`)
- JSON `"key":"value"` shape (e.g. `"phone_number":"555-1234"`)

Add these rows to the existing parametrized test functions (`detects_with_keyword`, etc.) —
only fall back to a standalone test when the assertion shape genuinely differs.

**3. Country/language tagging must match the kind.** A pattern's `Language::*` tag has to
align with the kind's `applicable_countries()`. A French keyword on a US-only kind will
silently fail under country filtering and mislead operators reading the patterns.

**4. When adding a new-language tuple for an existing kind, audit for substring overlap
with the existing pattern's keywords.** Many country-specific PII kinds (e.g. `AtSvnr`,
`DePersonalausweis`, `FrNir`) start with a single local-language tuple. Structured payloads
(JSON / CSV / URL-encoded) often pair English keys with local-language values, so a second
tuple in `Language::En` is the natural fix. But the new tuple is **purely additive**: it
must drop every keyword alternation whose substring is already matched (case-insensitively)
by the existing pattern's keywords. Vectorscan finds literal substrings, and the dedup in
`mark_piis_on` only collapses repeats *within* a single pattern — two patterns matching the
same input produce duplicate `PiiMatch` entries.

Concretely, the German `AtSvnr` pattern already matches the bare `SVNR` token, so the
English `AtSvnr` pattern must drop `svnr`, `at svnr`, `austrian svnr`, `svnr numbers?`, etc.
(anywhere "svnr" appears in the input the German pattern fires). The English pattern keeps
only phrases the existing pattern does **not** subsume — e.g.
`austrian social security number`, `at insurance number`. This is the inverse of the
substring-overlap pitfall below.

## Writing unit tests

1. ALWAYS try to merge similar test cases using the `test_case` macro. ALWAYS.
2. Implement also tests for false positives. The crate should not detect PIIs when they are
   not real PIIs.
3. Do not change expected values in failing test cases unless you are able to prove
   (e.g. using a Python script) that the expected values are incorrect.

## Known pitfalls

**Keyword substring overlap (duplicate matches).** Vectorscan finds literal byte
substrings. "téléphone" contains "phone", "passeport" contains "passport", "numéro IMEI"
contains "IMEI". When both English and foreign patterns exist for the same `PiiKind`, the
English pattern fires too (keyword found as substring), producing duplicate matches.
**Prevention:** Don't add bare English words to foreign-language keyword alternations if the
English pattern already has them. In tests, use exclusively-foreign keywords
(e.g. `"rappel"` not `"téléphone"`, `"identifiant bancaire"` not `"code SWIFT"`).

**`luhn_check` has a hardcoded 13–19 digit range.** Write type-specific Luhn validators for
other lengths (e.g. `siren_luhn_check` for 9-digit SIREN, `siret_luhn_check` for 14-digit SIRET).

**`dob_check` and new month names.** Add new language month names to the `month_from_name`
closure in `dob_check`. Use `to_lowercase()` (not `to_ascii_lowercase()`) so non-ASCII names
like "février" match.

**Complex patterns may silently fail in vectorscan's multi-pattern database** even if they
compile and work in isolation. A month-name DOB pattern with 12+ alternations worked alone
but didn't fire alongside 50+ other patterns. **Workaround:** Keep one combined pattern tuple
with both simple (numeric) and complex (month-name) alternations in the regex. Vectorscan
fires on the ASCII keyword, then the regex crate handles value extraction including complex
alternations.

**Shared keywords across countries cause DFA bloat.** When a new country shares keywords
with an existing one (e.g. DE and AT both use "Adresse", "Postfach"), do NOT add separate
vectorscan patterns with duplicate keyword prefixes. Each additional pattern enlarges the
vectorscan DFA, slowing *all* scans — even inputs with no matching content (e.g. US-only
text regresses ~4%). **Solution:** Use a combined `PiiKind` variant with a multi-country
prefix (e.g. `DeAtAddress` with label `"DE_AT_ADDRESS"`) and widen the value regex to accept
both countries (e.g. `\d{4,5}` for 4-digit AT / 5-digit DE PLZ). One pattern, one DFA entry,
one validator that accepts both formats. This scales naturally: when CH addresses arrive,
rename to `DeAtChAddress` with `\d{4,5}` still covering all three. The label will be
`DE_AT_CH_ADDRESS`.

**Always verify checksum/validation test data with a script.** Compute expected check digits
independently before writing test values.

## Verify when done

- `cargo test -p pii 2>&1 | tail -n 20` — all tests pass, including the new real-example cases.
- `cargo clippy -p pii --all-targets 2>&1 | tail -n 20` — no warnings.
- Confirm new `PiiKind` variants appear in `country()`, `label()`, and `ALL`, and that
  `Country::all()` / `Language::all()` include the new entries.
