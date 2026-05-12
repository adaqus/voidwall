//! Integration-level false-positive corpus.
//!
//! Each `#[test_case]` is a *near-miss*: text that resembles a specific PII
//! type closely enough that a regression in pattern compilation, validators,
//! or detector wiring could plausibly start matching it. All entries must
//! produce zero matches via the public `Scanner::mark_piis` API.
//!
//! This complements the per-detector `rejects_invalid_*` unit tests by:
//!  - Going through the full `Scanner` pipeline so cross-detector regressions
//!    surface (a new pattern firing on text another detector correctly
//!    ignored).
//!  - Wrapping near-miss values in realistic surrounding context the way
//!    real proxy traffic arrives.
//!
//! Coverage goal: at least one near-miss per supported `PiiKind`. When adding
//! a new kind to `PiiKind`, add a near-miss here too — the file is the
//! tripwire that catches an over-eager pattern from leaking into production.
//!
//! When a real misfire shows up in production logs, fuzzing, or code review,
//! distill the surrounding text to a short string and add it. If a legitimate
//! detector improvement makes an entry start matching, **move** the entry
//! rather than relaxing the assertion.
//!
//! Each case label is `<pii kind>: <reason>` so a failure report immediately
//! says which detector's contract was violated.

use std::sync::LazyLock;

use pii::Scanner;
use test_case::test_case;

static SCANNER: LazyLock<Scanner> = LazyLock::new(|| Scanner::new().expect("scanner build"));

// =============================================================================
// International (no keyword required — pattern fires on shape alone)
// =============================================================================

// --- Email ---
#[test_case("contact us at user@ for help" ; "email: truncated at at-sign")]
#[test_case("write to user@example for details" ; "email: missing tld")]
#[test_case("see user.example.com for the address" ; "email: dotted domain without at-sign")]
// --- Credit card ---
// 16 digits that fail Luhn (typical order/tracking ids).
#[test_case("Order #1234567890123456 confirmed today" ; "credit card: 16 digits non-luhn")]
// One-digit flip of Stripe test card 4242424242424242.
#[test_case("ref 4242 4242 4242 4243 invalid" ; "credit card: off-by-one luhn")]
// --- IBAN ---
// Mod-97 wrong by one digit (valid GB IBAN ends in 19, not 18).
#[test_case("iban GB29 NWBK 6016 1331 9268 18 fail" ; "iban: wrong checksum")]
// --- IP address ---
#[test_case("server 256.0.0.1 unreachable today" ; "ip address: ipv4 octet over 255")]
#[test_case("address 999.1.1.1 logged in audit" ; "ip address: ipv4 octet 999")]
// --- MAC address ---
// 5 pairs only; the regex requires exactly 6.
#[test_case("hex AA:BB:CC:DD:EE incomplete pair" ; "mac address: only 5 pairs")]
// --- VIN ---
// VIN forbids the letters I, O, and Q (to avoid digit confusion).
#[test_case("vin 1HGBH41JXMN10918I logged" ; "vin: contains forbidden i")]
#[test_case("vin 1HGBH41JXMN10918Q logged" ; "vin: contains forbidden q")]
// --- AWS access key ---
// Pattern is case-sensitive on the AKIA prefix.
#[test_case("token akia1234567890ABCDEF lower" ; "aws access key: lowercase prefix")]
#[test_case("token AKIA1234567890 short stub" ; "aws access key: too short")]
// --- GitHub token ---
#[test_case("token ghp_TooShortAbc123 fragment" ; "github token: too short")]
#[test_case("token ghx_abcdefghijklmnopqrstuvwxyz1234567890 unknown" ; "github token: unknown prefix letter")]
// --- Bitcoin address ---
// Valid prefixes are 1, 3, or bc1.
#[test_case("addr 9abcdefghijkmnopqrstuvwxyz12345 invalid" ; "bitcoin address: invalid leading char")]
// --- Ethereum address ---
// Needs exactly 40 hex chars after 0x.
#[test_case("addr 0xabcdef0123 too short for eth" ; "ethereum address: too short")]
// --- US SSN ---
// Area numbers 000, 666, and 900-999 are not assigned.
#[test_case("ssn 000-12-3456 from form" ; "us ssn: area 000")]
#[test_case("ssn 666-12-3456 from form" ; "us ssn: area 666")]
#[test_case("ssn 900-12-3456 from form" ; "us ssn: area in 900-999 range")]
// Group "00" and serial "0000" are reserved.
#[test_case("ssn 123-00-3456 from form" ; "us ssn: group 00")]
#[test_case("ssn 123-45-0000 from form" ; "us ssn: serial 0000")]
// --- US ITIN ---
// ITIN second group must be 50-65, 70-88, 90-92, or 94-99.
#[test_case("itin 912-49-1234 from form" ; "us itin: group 49 invalid")]
#[test_case("itin 912-66-1234 from form" ; "us itin: group 66 invalid")]
// --- GB NINO ---
// Prefix BG is unallocated; first letter must not be D/F/I/Q/U/V.
#[test_case("nino BG 12 34 56 A from form" ; "gb nino: invalid prefix bg")]
#[test_case("nino DA 12 34 56 A from form" ; "gb nino: forbidden first letter d")]
// --- GB driving licence ---
// 16-char shape match with month=13 (validator rejects months outside 1-12 or 51-62).
#[test_case("license JONES913015AA9Y1 expired" ; "gb driving licence: month 13 invalid")]
// --- CA SIN ---
// Fails SIN's Luhn-style check.
#[test_case("sin 123-456-789 from form" ; "ca sin: wrong luhn")]
// --- IE PPSN ---
// 7 digits + wrong check letter (correct check letter for 1234567 is T).
#[test_case("ppsn 1234567Z from form" ; "ie ppsn: wrong check letter")]
// --- IE Eircode ---
// 7-char shape requires letter + (digit-digit | 6W) + 4 alnum; "9X" breaks it.
#[test_case("ref Z9X ABCD invalid eircode" ; "ie eircode: invalid routing key")]
// --- GB postcode ---
// Postcode must lead with 1-2 letters; "1A 2B 3C" leads with a digit.
#[test_case("zone 1A 2B 3C unrelated id" ; "gb postcode: digit-led shape")]
// --- CA postal code ---
// First letter must not be D, F, I, O, Q, U. Avoid the canonical
// "letter-digit-letter digit-letter-digit" shape because it overlaps
// with the GB postcode regex; use trailing "0D0" so GB's required
// "[0-9][A-Za-z]{2}" inward code fails too.
#[test_case("box D0D 0D0 entry note" ; "ca postal code: forbidden leading letter")]
// =============================================================================
// International (keyword-context detectors — value must follow keyword)
// =============================================================================

// --- US phone number ---
#[test_case("Phone support is unavailable today." ; "us phone: keyword without digits")]
#[test_case("phone us: 555-12" ; "us phone: too few digits")]
// --- Passport number (generic 9-digit) ---
#[test_case("Passport-style photo required for application." ; "passport: keyword without digits")]
#[test_case("passport: 12345" ; "passport: too few digits")]
// --- US passport (new format: A/X/Y/Z + 8 digits) ---
#[test_case("US passport: B12345678 issued" ; "us passport new: forbidden leading letter")]
// --- SWIFT/BIC ---
// 8-char shape match but country code (chars 4..6) is "XX" — not a valid ISO country.
#[test_case("BIC: ABCDXXEF reference" ; "swift bic: invalid country code")]
#[test_case("SWIFT routing instructions are attached." ; "swift bic: keyword without code")]
// --- IMEI ---
// 15 digits but Luhn fails on the sequential test value.
#[test_case("IMEI: 123456789012345 logged" ; "imei: 15 digits non-luhn")]
#[test_case("IMEI lookup is currently disabled." ; "imei: keyword without digits")]
// --- US EIN ---
// Prefix 69 is unassigned (the IRS list jumps from 68 to 71).
#[test_case("EIN: 69-1234567 reported" ; "us ein: unassigned prefix 69")]
// --- US ABA routing ---
// 9-digit shape with weighted-sum checksum failure.
#[test_case("routing number 123456788 attached" ; "us aba routing: bad checksum")]
// --- GB UTR ---
// 10-digit shape with wrong leading check digit.
#[test_case("UTR: 1234567890 reference" ; "gb utr: wrong check digit")]
// --- GB sort code ---
#[test_case("sort code: 12-34 partial" ; "gb sort code: only 4 digits")]
// --- Precise geolocation ---
// Latitude 91 is out of [-90, 90].
#[test_case("GPS coordinates: 91.0000, 0.0000 logged" ; "geolocation: latitude out of range")]
// --- US alien number ---
// Pattern requires A-prefix + 7-9 digits.
#[test_case("A-Number: A12345 stub" ; "us alien number: too few digits")]
// --- US USCIS receipt ---
// 13-char shape but center code "ABC" is not in the USCIS list.
#[test_case("Receipt number ABC1234567890 issued" ; "us uscis receipt: unknown center code")]
// --- ZA ID ---
// 13 digits with month "00" (validator requires 1-12). All-zero would also
// pass Luhn, so include a 1 to break the credit-card detector that fires
// on any 13–19 Luhn-valid digit run.
#[test_case("SA ID: 0000000001000 form" ; "za id: invalid month 00")]
// --- US driver's license ---
#[test_case("DL: ABC12345 issued" ; "us drivers license: 3 letter prefix breaks regex")]
// --- NZ NHI number ---
// 3 letters + 4 digits with wrong check digit.
#[test_case("NHI: ABC1234 patient" ; "nz nhi: wrong check digit")]
// --- NZ driver licence ---
// "driver licence" also keys US_DRIVERS_LICENSE; need digit count to fail
// both `[A-Z]{2}\d{6}` (NZ) and `[A-Za-z]{1,2}\d{4,14}` (US).
#[test_case("nz driver licence: AB123 partial" ; "nz driver licence: 3 digits fail both nz and us")]
// --- IE driver number ---
#[test_case("Irish driver number: 12345 partial" ; "ie driver number: too few digits")]
// --- ZA tax reference ---
// First digit must be in {0,1,2,3,9}; 4 is not allowed.
#[test_case("SARS: 4123456789 reference" ; "za tax reference: invalid leading digit")]
// --- ZA driver's license ---
// Same shape as ZaId; same care needed to also fail the credit-card Luhn.
#[test_case("South African driver's licence: 0000000001000 sample" ; "za drivers license: invalid month 00")]
// --- US/ZA postal code ---
// 4-digit "0000" fails US (needs 5) and ZA (range 1..=9999).
#[test_case("zip: 0000 stub" ; "us za postal code: zero outside both formats")]
// --- AU driver's license ---
#[test_case("NSW licence: 0000000 invalid" ; "au drivers license: all zeros")]
// --- AU ABN ---
// 11 ones — weighted checksum mod 89 is 11, not 0.
#[test_case("ABN: 11 111 111 111 fake" ; "au abn: bad mod-89 checksum")]
// --- CA OHIP ---
// 10 digits non-Luhn.
#[test_case("OHIP: 1234567890 card" ; "ca ohip: non-luhn 10 digits")]
// --- GB phone number ---
#[test_case("phone uk: 12345 stub" ; "gb phone: too few digits")]
// --- AU phone number ---
// 8 digits after national prefix; AU mobile/landline needs 9.
#[test_case("phone aus: 0123 4567 partial" ; "au phone: too few digits")]
// --- NZ phone number ---
// Second digit "0" not in [2-9].
#[test_case("phone nz: 0 0123 invalid" ; "nz phone: subscriber starts with 0")]
// --- IE phone number ---
#[test_case("phone ie: 0 0123 invalid" ; "ie phone: subscriber starts with 0")]
// --- ZA phone number ---
#[test_case("phone za: 0 0123 invalid" ; "za phone: subscriber starts with 0")]
// --- AWS secret key ---
#[test_case("AWS secret access key=shortvalue123 stub" ; "aws secret key: too short")]
// --- GB/ZA passport number ---
#[test_case("British passport: 12345 partial" ; "gb za passport: too few digits")]
// --- AU passport number ---
#[test_case("Australian passport: 12345 partial" ; "au passport: missing leading letter")]
// --- CA passport number ---
#[test_case("Canadian passport: 12345 partial" ; "ca passport: missing letters")]
// --- NZ passport number ---
#[test_case("nz passport: 1234567 partial" ; "nz passport: missing leading letter")]
// --- IE passport number ---
// IE wants 2 letters + 7 digits. AU (`[A-Za-z]\d{7}`) and NZ
// (`[A-Za-z]{1,2}\d{6,7}`) keyword-match on plain "passport" too, so the
// value must fail all three shapes — 3 letters does it.
#[test_case("Irish passport: ABC1234 partial" ; "ie passport: 3 letter prefix breaks all shapes")]
// --- DE passport number ---
// 9 chars with a forbidden letter (Q is excluded from [CFGHJKLMNPRTVWXYZ]).
// "Reisepass" also keys the generic 9-digit PassportNumber detector, so the
// value must contain a letter to fail that pattern simultaneously.
#[test_case("deutscher Reisepass: CFGHJKLMQ invalid" ; "de passport: forbidden letter q")]
// --- Date of birth ---
// dob_check tries DD/MM/YYYY *and* MM/DD/YYYY before rejecting, so a
// single-axis invalid like "01/13/1990" still parses as Jan 13. Use values
// where both orderings fail.
#[test_case("DOB: 32/13/1990 form" ; "date of birth: day 32 and month 13")]
#[test_case("DOB: 99/99/1990 form" ; "date of birth: day and month both invalid")]
#[test_case("Date of birth must be provided on the form." ; "date of birth: keyword without date")]
// --- AU bank account (BSB) ---
#[test_case("BSB: 12-34 partial" ; "au bank account: only 4 digits")]
// --- CA bank account ---
#[test_case("transit number: 12 partial" ; "ca bank account: too few digits")]
// --- GB address ---
// Address keyword + value with no GB postcode at the end.
#[test_case("Postal address: PO Box 100 short" ; "gb address: missing postcode")]
// --- Person name ---
#[test_case("first name field is required on the form" ; "person name: keyword followed by lowercase")]
#[test_case("Print the cardholder name in block letters." ; "person name: keyword followed by article")]
// =============================================================================
// FR — France
// =============================================================================
// --- FR NIR (sécurité sociale) ---
// Mod-97 checksum failure (off-by-one from a valid example).
#[test_case("numéro de sécurité sociale: 185057800608499 invalide" ; "fr nir: bad checksum")]
// --- FR SIRET ---
// 14-digit non-Luhn.
#[test_case("SIRET: 12345678901234 fictif" ; "fr siret: non-luhn 14 digits")]
// --- FR SIREN ---
// 9-digit non-Luhn.
#[test_case("SIREN: 123456789 fictif" ; "fr siren: non-luhn 9 digits")]
// --- FR passport number ---
#[test_case("passeport français: 1234 partiel" ; "fr passport: missing letters")]
// --- FR CNI ---
#[test_case("CNI: 12345 partiel" ; "fr cni: too few digits")]
// --- FR driver's license ---
#[test_case("permis de conduire: 12345 partiel" ; "fr drivers license: too few digits")]
// --- FR phone number ---
#[test_case("téléphone: 0 12 34 partiel" ; "fr phone: too few digits")]
// --- FR postal code ---
// 99999 is above the FR range (01000..=98999).
#[test_case("code postal: 99999 invalide" ; "fr postal code: above range")]
// --- FR NIF (SPI) ---
// 13 digits but first digit 4 is not in {0,1,2,3}.
#[test_case("NIF: 4123456789012 invalide" ; "fr nif: invalid leading digit")]
// --- FR/CH address ---
#[test_case("domicile: rue inconnue ailleurs" ; "fr ch address: missing postal code")]
// --- FR/CH boîte postale ---
#[test_case("BP: 12345 Paris seul" ; "fr ch boite postale: missing postal code")]
// =============================================================================
// DE — Germany
// =============================================================================
// --- DE Steuer-ID ---
// 11-digit shape with bad MOD 11,10 checksum.
#[test_case("Steuer-ID: 12345678901 falsch" ; "de steuer id: bad checksum")]
// --- DE Personalausweis ---
// 10-char shape with wrong check digit.
#[test_case("Personalausweis: A123456789 falsch" ; "de personalausweis: bad check digit")]
// --- DE phone number ---
#[test_case("Telefonnummer: 0123 zu kurz" ; "de phone: too few digits")]
// --- DE postal code ---
// 00500 = 500, below DE range (1000..=99999).
#[test_case("PLZ: 00500 Leipzig?" ; "de postal code: below range")]
// --- DE/AT/CH address ---
#[test_case("Adresse: Hauptstraße 1, ohne PLZ angegeben" ; "de at ch address: missing postal code")]
// --- DE/AT/CH Postfach ---
#[test_case("Postfach: 123 ohne weiteres" ; "de at ch postfach: missing city and postal code")]
// --- DE Packstation ---
#[test_case("Packstation: 123 nichts weiter angegeben" ; "de packstation: missing city")]
// =============================================================================
// AT — Austria
// =============================================================================
// --- AT SVNR ---
// 10-digit shape with bad checksum (digit at position 3 is the check).
#[test_case("SVNR: 1234567890 falsch" ; "at svnr: bad checksum")]
// --- AT phone number ---
#[test_case("Rufnummer: 0 0123 ungültig" ; "at phone: too few digits")]
// --- AT postal code ---
// 0500 = 500, below AT range (1010..=9992) AND below CH range (1000..=9658).
#[test_case("Postleitzahl: 0500 ungültig" ; "at postal code: below range")]
// =============================================================================
// CH — Switzerland
// =============================================================================
// --- CH AHV ---
// Starts with 756 but EAN-13 check digit is wrong (last digit should be 2, not 0).
#[test_case("AHV-Nummer: 756.0000.0000.00 falsch" ; "ch ahv: bad check digit")]
// --- CH phone number ---
#[test_case("Telefonnummer: 0 12 zu kurz für CH" ; "ch phone: too few digits")]
// --- CH postal code ---
// 9999 above CH range (1000..=9658) AND above AT range (1010..=9992).
#[test_case("Postleitzahl: 9999 zu hoch" ; "ch postal code: above range")]
// =============================================================================
// Generic non-PII text that resembles structured data (cross-detector tripwire)
// =============================================================================
#[test_case("rustc 1.78.0 (9b00956e5 2024-04-29)" ; "generic: rustc version banner")]
#[test_case("commit 8b7e3c8a4f2d4e9bb6a81c2d3e4f5a6b12345678 deployed" ; "generic: 40-char lowercase git sha")]
#[test_case("doc _id 507f1f77bcf86cd799439011 missing" ; "generic: mongo objectid")]
#[test_case("uuid 550e8400-e29b-41d4-a716-446655440000 logged" ; "generic: uuid v4")]
#[test_case("Revenue: $1,234,567.89 this quarter" ; "generic: formatted currency")]
#[test_case("[2024-01-15 12:34:56] INFO request handled" ; "generic: timestamped log line")]
#[test_case("schedule '0 0 * * *' for nightly compaction" ; "generic: cron expression")]
#[test_case("HTTP/1.1 404 Not Found on port 8080" ; "generic: http status and port")]
// =============================================================================
// Matomo tracking protocol — near-miss PII inside user-controlled fields
// =============================================================================
// Matomo (formerly Piwik) tracking pings expose several free-form fields whose
// content is set by the instrumented site or by the visitor: page titles,
// search terms, custom dimensions/variables, ecommerce metadata, referrer
// URLs. Realistic proxy traffic puts text resembling PII inside these fields
// all the time. Each case below places a known near-miss value (one that
// already appears elsewhere in this file as a unit-tested non-match) inside
// one of those fields:
//   action_name | dimension* | _cvar JSON | e_c/e_a/e_n/e_v | ec_*
//   url= search term | url= path | urlref
//
// Two encoding shapes occur in real traffic: the literal value (when the
// proxy decodes the body) and the URL-encoded form (when it doesn't). The
// keyword-context separator class accepts `","` and `/` but not `%` or `&`,
// so the literal-JSON cases force the validator to do the rejection while
// the parameter-boundary cases also confirm the encoding break is enough.

// --- action_name ---
#[test_case("idsite=1&rec=1&action_name=Contact user@ for support team" ; "email: truncated in matomo action_name")]
#[test_case("idsite=1&rec=1&action_name=first name field required on form" ; "person name: lowercase article in matomo action_name")]
#[test_case("idsite=1&rec=1&action_name=Lookup ITIN 912-49-1234 status" ; "us itin: invalid group in matomo action_name")]
// --- Custom dimensions ---
#[test_case("idsite=1&rec=1&dimension1=order_1234567890123456_pending" ; "credit card: non-luhn 16 digits in matomo dimension")]
#[test_case("idsite=1&rec=1&dimension2=ssn 000-12-3456 lookup" ; "us ssn: area 000 in matomo dimension")]
#[test_case("idsite=1&rec=1&dimension3=VIN-1HGBH41JXMN10918I-test" ; "vin: forbidden letter i in matomo dimension")]
// --- Custom variables (`_cvar` JSON: separator class accepts `","`, so the
// keyword-value pairing fires and the validator must reject the value) ---
#[test_case(r#"idsite=1&rec=1&_cvar={"1":["iban","GB29 NWBK 6016 1331 9268 18"]}"# ; "iban: bad checksum in matomo cvar")]
#[test_case(r#"idsite=1&rec=1&_cvar={"1":["BIC","ABCDXXEF"]}"# ; "swift bic: invalid country in matomo cvar")]
#[test_case(r#"idsite=1&rec=1&_cvar={"1":["numéro de sécurité sociale","185057800608499"]}"# ; "fr nir: bad checksum in matomo cvar")]
// --- Custom event parameters (keyword in `e_n=`, value in `e_v=`; the
// `&e_v=` boundary between them breaks the keyword-value pairing — the
// validator catches the bad value as a backstop) ---
#[test_case("idsite=1&rec=1&e_c=device&e_a=lookup&e_n=IMEI&e_v=123456789012345" ; "imei: non-luhn in matomo event value")]
#[test_case("idsite=1&rec=1&e_c=user&e_a=signup&e_n=DOB&e_v=32/13/1990" ; "date of birth: invalid in matomo event value")]
// --- Ecommerce parameters ---
#[test_case("idsite=1&rec=1&ec_id=ORDER-1234567890123456&revenue=99.95" ; "credit card: non-luhn 16 digits in matomo ec_id")]
#[test_case(r#"idsite=1&rec=1&ec_items=[["1234567890123456","Widget","cat",9.99,1]]"# ; "credit card: non-luhn sku in matomo ec_items")]
// --- Search term inside `url=` ---
#[test_case("idsite=1&rec=1&url=https://shop.example.com/search?q=000-12-3456" ; "us ssn: area 000 in matomo url search term")]
#[test_case("idsite=1&rec=1&url=https://example.com/?search=256.0.0.1" ; "ip address: octet over 255 in matomo url search term")]
// --- Path inside `url=` (separator class accepts `/`, so `zip/0000` pairs
// and the validator rejects 0000 as out of range for both US and ZA) ---
#[test_case("idsite=1&rec=1&url=https://example.com/zip/0000/index.html" ; "us za postal: zero in matomo url path")]
// --- urlref ---
#[test_case("idsite=1&rec=1&urlref=https://referrer.example.com/?user=user@" ; "email: truncated in matomo urlref")]
#[test_case("idsite=1&rec=1&urlref=https://example.com/auth?token=ghx_abcdefghijklmnopqrstuvwxyz1234567890" ; "github token: unknown prefix in matomo urlref")]
// =============================================================================
// Google Analytics 4 (Measurement Protocol) — near-miss PII inside user fields
// =============================================================================
// GA4's Measurement Protocol (`/g/collect`, `/mp/collect`) carries the same
// kinds of user-controlled fields as Matomo, just under different keys:
//   dt              page title              (← matomo action_name)
//   up.<prop>       user property           (← matomo dimension / cvar)
//   ep.<param>      event parameter         (← matomo e_n/e_v)
//   pr<N>           ecommerce item (`~`-separated tag-value pairs)
//   dl              document location       (← matomo url= search and path)
//   dr              document referrer       (← matomo urlref)
//
// Unlike Matomo's `&e_v=` boundary, GA4 puts the keyword and value inside the
// same `key.subkey=value` parameter, so the `=` separator IS in the
// keyword-context separator class — pairing fires and the validator must
// reject the value (stronger test than the Matomo event-param cases).

// --- dt (page title) ---
#[test_case("v=2&tid=G-AB12CD34EF&en=page_view&dt=Contact user@ for support team" ; "email: truncated in ga4 dt")]
#[test_case("v=2&tid=G-AB12CD34EF&en=page_view&dt=first name field required on form" ; "person name: lowercase article in ga4 dt")]
#[test_case("v=2&tid=G-AB12CD34EF&en=page_view&dt=Lookup ITIN 912-49-1234 status" ; "us itin: invalid group in ga4 dt")]
// --- up.<prop> (user property) ---
#[test_case("v=2&tid=G-AB12CD34EF&en=login&up.iban=GB29 NWBK 6016 1331 9268 18" ; "iban: bad checksum in ga4 user property")]
#[test_case("v=2&tid=G-AB12CD34EF&en=login&up.bic=ABCDXXEF" ; "swift bic: invalid country in ga4 user property")]
#[test_case("v=2&tid=G-AB12CD34EF&en=login&up.vin=1HGBH41JXMN10918I" ; "vin: forbidden letter i in ga4 user property")]
// --- ep.<param> (event parameter — `=` separator pairs the keyword with
// the value, so the validator does the rejection) ---
#[test_case("v=2&tid=G-AB12CD34EF&en=device_check&ep.imei=123456789012345" ; "imei: non-luhn in ga4 event parameter")]
#[test_case("v=2&tid=G-AB12CD34EF&en=signup&ep.dob=32/13/1990" ; "date of birth: invalid in ga4 event parameter")]
#[test_case("v=2&tid=G-AB12CD34EF&en=identity&ep.securite_sociale=185057800608499" ; "fr nir: bad checksum in ga4 event parameter")]
// --- pr<N> (ecommerce item, `~`-separated tag-value pairs:
// id=item_id, nm=item_name, ca=category, pr=price, qt=quantity) ---
#[test_case("v=2&tid=G-AB12CD34EF&en=purchase&pr1=id1234567890123456~nmWidget~caShoes~pr9.99~qt1" ; "credit card: non-luhn 16-digit sku in ga4 item")]
#[test_case("v=2&tid=G-AB12CD34EF&en=purchase&pr2=id4242424242424243~nmGadget~caApparel~pr19.99~qt2" ; "credit card: off-by-one luhn sku in ga4 item")]
// --- dl search query ---
#[test_case("v=2&tid=G-AB12CD34EF&en=view_search_results&dl=https://shop.example.com/search?q=000-12-3456" ; "us ssn: area 000 in ga4 dl search term")]
#[test_case("v=2&tid=G-AB12CD34EF&en=view_search_results&dl=https://example.com/?search=256.0.0.1" ; "ip address: octet over 255 in ga4 dl search term")]
// --- dl path ---
#[test_case("v=2&tid=G-AB12CD34EF&en=page_view&dl=https://example.com/zip/0000/index.html" ; "us za postal: zero in ga4 dl path")]
// --- dr (document referrer) ---
#[test_case("v=2&tid=G-AB12CD34EF&en=page_view&dr=https://referrer.example.com/?user=user@" ; "email: truncated in ga4 dr")]
#[test_case("v=2&tid=G-AB12CD34EF&en=page_view&dr=https://example.com/auth?token=ghx_abcdefghijklmnopqrstuvwxyz1234567890" ; "github token: unknown prefix in ga4 dr")]
// --- Trivial inputs ---
#[test_case("" ; "trivial: empty")]
#[test_case("   \t\n  " ; "trivial: whitespace only")]
#[test_case("Hello, welcome to our customer support page." ; "trivial: prose greeting")]
fn does_not_match(input: &str) {
    let matches = SCANNER.mark_piis(input);
    assert!(
        matches.is_empty(),
        "unexpected matches for {input:?}: {:?}",
        matches
            .iter()
            .map(|m| (m.label(), m.start, m.end, &input[m.start..m.end]))
            .collect::<Vec<_>>(),
    );

    // has_piis is allowed to short-circuit on a different detector than
    // mark_piis runs to completion. They must still agree on "no PII".
    assert!(
        !SCANNER.has_piis(input),
        "has_piis returned true while mark_piis was empty for {input:?}",
    );
}
