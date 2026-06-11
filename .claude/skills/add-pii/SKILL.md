---
name: add-pii
description: Add support for a new language and/or country to the `pii` crate (crates/pii). Use when asked to add a new country's PII types (e.g. national ID, postcode, phone, passport) or to add detection/keywords for a new language. Use also when language or country is already supported, but new PII type is added. Covers the full checklist, real-world validation, keyword-context pattern rules, test requirements, and known pitfalls.
---

Add support for language $ARGUMENTS[0] and country $ARGUMENTS[1].

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
- plain text (e.g. `call 555-1234`)

Add these rows to the existing parametrized test functions (`detects_with_keyword`, etc.) —
only fall back to a standalone test when the assertion shape genuinely differs.

**3. A pattern's `Language::*` tag must match the language of the KEYWORD TEXT — not the
kind's country.** `enabled_languages` is filtered **independently** of country selection
(`ScannerBuilder`), and the shipped example config uses `languages = ["En"]`. So the tag
decides whether the keyword survives language filtering, regardless of which country the
value belongs to. Two consequences:

- A foreign keyword on the wrong-language kind still misleads operators (a French keyword
  tagged `Language::De`), and a keyword whose tag is absent from a deployment's
  `languages` list is silently dropped.
- **English structured-key keywords belong in `Language::En`, even for a country-specific
  kind.** Structured payloads pair English keys with local values, so `pesel_number`,
  `nip_number`, `regon_number` are *English* keywords for Polish kinds and must live in the
  `Language::En` tuple — putting them in the `Language::Pl` tuple makes
  `{"pesel_number":"…"}` undetectable under `languages=["En"]` even though the kind is
  enabled. The native structured key (`numer_pesel`) and the bare native token (`pesel`)
  stay in the `Language::Pl` tuple. The two are extraction-disjoint: a bare token cannot
  cross the `_` in the English compound (the separator class excludes `_`), so they do not
  double-fire. **Verify with an En-only test:** build
  `KeywordContextDetector::new(&kinds, &[Language::En])` and assert each English key is
  detected and each bare native keyword is not.

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

**4a. A prefix-phrase branch whose stem also appears bare in the same alternation is
dead — omit it.** Patterns are unanchored and only the capture group is the returned span,
so `regon(?:u|…)?` already matches inside `numer REGON: 610188201` (the engine starts at
`regon`, the captured span is identical). Adding `numery?[\s_-]?regon|` alongside the bare
`regon` stem contributes zero recall and just adds states to the DFA. Keep the prefix branch
only when its stem is **not** independently present (e.g. `numer identyfikacji podatkowej`
has no bare stem). Some existing tuples (Es/It) carry these dead branches as legacy — don't
copy that.

**5. Connector words between keyword and value are English-only today.** Each pattern's
keyword/value gap is `(?:\s+is\s+|[\s:.#/\-\x22=,\]\\]*?)` — a language-neutral *separator
class* (colon, `=`, slash, quotes, whitespace…) that covers all structured payloads
(JSON/CSV/URL), plus one hardcoded natural-language copula, the English `\s+is\s+`. Dutch
gets this for free because Dutch "is" == English "is". **No other language's copula is
matched.** So a prose sentence like `"… il CAP è 00184 …"` (Italian *è*), `"… mon CAP est
75008 …"` (French *est*), or `"… die PLZ ist 10115 …"` (German *ist*) does **not** detect —
the copula sits between keyword and value and isn't in the separator class.

Practical consequence for this skill: when writing natural-sentence `#[test_case]` rows for
a new language, **do not** put the native copula between the keyword and the value (the test
will fail). Keep the value adjacent to the keyword, e.g. `"Il mio CAP 00184 si trova a
Roma."` not `"Il mio CAP è 00184."`. This matches how the existing FR/DE/NL sentence tests
are written.

**Planned general approach (not yet implemented — `<<C>>` placeholder).** When we generalize
connectors, the design is: make the copula a property of `Language` and expand it per
pattern at build time, so each language carries only its *own* copulas in the vectorscan DFA
(adding a connector to every pattern of every language would bloat the DFA and slow all
scans — see "shared-keyword DFA bloat" below).

- Add `Language::connector_words(&self) -> &'static str` returning a small regex word-branch,
  e.g. `En | Nl => "is|are"`, `Fr => "est|sont"`, `De => "ist|sind"`, `It => "è|sono"`.
  Keep each set tiny — one or two copulas; every entry is paid for across all that language's
  patterns.
- Write patterns with a `<<C>>` placeholder where the connector goes
  (`…(?:keyword…)<<C>>(value)`), and in `KeywordContextDetector::new` expand it for the
  pattern's `Language` before compiling:
  `raw.replace("<<C>>", &format!(r"(?:\s+(?:{})\s+|[\s:.#/\-\x22=,\]\\]*?)", lang.connector_words()))`.
  The expansion flows into both the detection string and the derived `value_regex`, keeping
  the vectorscan and `regex`-crate dialects in sync.
- Watch-outs when implementing: keep the `\s+…\s+` word framing (so `is` matches the word,
  not the `is` inside `this`); vectorscan's caseless flag is ASCII-only, so a sentence-initial
  non-ASCII copula like `È` won't fold — spell casing explicitly (`(?:è|È)`) or accept
  lowercase-only; re-run the bench suite to confirm no DFA regression.

Until that lands, adding a language adds **no** native connector support — only the
separator class and English `is`.

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

**Month names need abbreviation support where the language uses them.** Anywhere month
names appear — both the `month_from_name` closure in `dob_check` *and* the month-name
alternation in the DOB extraction regex (`keyword_context_detector.rs`) — add the
language's common abbreviations alongside the full names (e.g. de `Mär`/`Mrz`/`Okt`/`Dez`,
fr `janv`/`févr`/`déc`, nl `mrt`/`okt`). The two must stay in sync: `dob_check` only ever
validates the string the extraction regex captured, so an abbreviation added to the
validator alone is inert — the regex must capture it first, and the regex match is wasted
if the validator then rejects it. List the longer form before the shorter in the regex
alternation (`septembre|sept`, `M[aä]rz|M[aä]r`) so the full name is preferred. Cover each
new abbreviation with a `#[test_case]` row in `detects_with_keyword`.

**Complex patterns may silently fail in vectorscan's multi-pattern database** even if they
compile and work in isolation. A month-name DOB pattern with 12+ alternations worked alone
but didn't fire alongside 50+ other patterns. **Workaround:** Keep one combined pattern tuple
with both simple (numeric) and complex (month-name) alternations in the regex. Vectorscan
fires on the ASCII keyword, then the regex crate handles value extraction including complex
alternations.

**A detection-override token class for a non-ASCII language must be an explicit
letter+diacritic class, never `\S`.** When a language's month names (or any value token)
carry non-ASCII letters, it is tempting to widen the override's generic token to `\S{3,14}`.
In vectorscan UTF-8 mode `\S` is a near-universal multi-byte class that compiles to far more
NFA/DFA states than a bounded letter class, and it admits digit/punctuation junk tokens that
then trigger pointless regex-crate extraction. Use the ASCII range plus the language's
diacritics spelled out in **both** cases (vectorscan's caseless flag is ASCII-only), e.g.
Polish `[A-Za-ząćęłńóśźżĄĆĘŁŃÓŚŹŻ]{3,14}`. This keeps the keyword DB off the DFA-size cliff
while matching every real month name.

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

**Unanchored keyword-less patterns with a common-class prefix regress throughput on
*all* inputs.** A keyword-less `HyperscanDetector` pattern (`hyperscan_detector.rs`) that
begins with an unanchored run of a common character class — e.g. the codice fiscale mask
`\b[A-Za-z]{6}\d{2}[A-Za-z]…` — forces vectorscan to track a candidate match at nearly
every byte of clean text, because letters are the most common characters and there is no
literal to accelerate on. The codice fiscale pattern cost ~13% clean-input throughput.
Switching to `som_fallback: true` (regex-crate extraction) is *worse* — the regex engine
also has no literal to anchor on. **Prevention:** give the pattern a literal anchor
(cf. `NlBtw` → `NL…`, `AwsAccessKey` → `AKIA…`, `EthereumAddress` → `0x…`), or restrict the
leading class so it stays cold on prose. National ID codes are canonically uppercase, so
`[A-Z]{6}…` (uppercase-only) almost never matches running text while still catching every
real value; recover lowercase/lenient forms with a keyword-context pattern instead of a hot
keyword-less one. If the value cannot be anchored or narrowed at all, make it keyword-gated
(move it to `keyword_context_detector.rs`) rather than keyword-less.

**Only the full-scanner benchmarks surface new-pattern regressions.** `throughput_mark_piis`
and `throughput_has_piis` build via `Scanner::new()` (all kinds/languages) and *will* show a
new pattern's cost on clean inputs. The per-detector benches
(`throughput_hyperscan_detector`, `throughput_keyword_detector`) use hardcoded 5-kind subsets
that exclude anything you add, so a green per-detector bench does **not** mean no regression —
always check the clean-input rows of the full-scanner groups.

**Always verify checksum/validation test data with a script.** Compute expected check digits
independently before writing test values.

## Verify when done

- `cargo test -p pii 2>&1 | tail -n 20` — all tests pass, including the new real-example cases.
- `cargo clippy -p pii --all-targets 2>&1 | tail -n 20` — no warnings.
- Confirm new `PiiKind` variants appear in `country()`, `label()`, and `ALL`, and that
  `Country::all()` / `Language::all()` include the new entries.
- If any English structured-key keyword was added (`<kind>_number` etc.), add an En-only
  language test (see rule 3) so the `languages=["En"]` config keeps detecting it.
- If you appended to `PRIORITY_GROUPS` in `overlap.rs`, update (or delete in favour of a
  pointer to `overlap.rs`) the now-stale "Currently:" enumeration in `crates/pii/CLAUDE.md`
  so the doc and code don't drift.
- `cargo bench throughput  --bench pii_benchmark` - after every other task is finished, run 
  benchmark for baseline before changes and compare with changed codebase (do not run the
  command in paraller e.g. with tests as this will skew benchmark result).
