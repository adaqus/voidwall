# Structured PII Types for English-Speaking Countries

This document catalogs all structured, pattern-detectable PII types relevant to
English-speaking countries (US, UK, Canada, Australia, New Zealand, Ireland,
South Africa). Each entry is assessed for regex detectability, validation
strength, and false-positive risk.

## Implementation Status Legend

- IMPLEMENTED — detected by `RegexDetector` (no keyword context needed)
- IMPLEMENTED (keyword context) — detected by `KeywordContextDetector` (requires keyword prefix)
- CANDIDATE — structured enough for reliable detection, not yet implemented
- NOT RECOMMENDED — too many false positives, not implemented

---

## 1. Government / Tax IDs

### 1.1 US Social Security Number (SSN) — IMPLEMENTED

| Field | Value |
|-------|-------|
| Countries | United States |
| Format | `NNN-NN-NNNN` (3-2-4 hyphenated) |
| Example | `078-05-1120` |
| Checksum | None (rule-based validation) |
| Validation | Area not 000/666/900-999, group not 00, serial not 0000 |
| False-positive risk | Low |
| Distinguishable | Yes — the 3-2-4 hyphen pattern is unusual |

### 1.2 US Individual Taxpayer Identification Number (ITIN) — IMPLEMENTED

| Field | Value |
|-------|-------|
| Countries | United States |
| Format | `9NN-NN-NNNN` (same visual format as SSN, always starts with 9) |
| Example | `912-55-1234` |
| Checksum | None |
| Validation | Starts with 9; digits 4-5 restricted to: 50-65, 70-88, 90-92, 94-99 |
| False-positive risk | Low |
| Distinguishable | Yes — SSN excludes area 900-999, so no overlap |

### 1.3 US Employer Identification Number (EIN) — IMPLEMENTED (keyword context)

| Field | Value |
|-------|-------|
| Countries | United States |
| Format | `NN-NNNNNNN` (2-7 hyphenated) |
| Example | `12-3456789` |
| Checksum | None |
| Validation | First 2 digits are IRS campus codes (known set) |
| False-positive risk | Medium |
| Distinguishable | Moderately — the 2-7 split is less common but not unique |

### 1.4 Canada Social Insurance Number (SIN) — IMPLEMENTED

| Field | Value |
|-------|-------|
| Countries | Canada |
| Format | `NNN-NNN-NNN` or `NNN NNN NNN` (3-3-3) |
| Example | `046-454-286` |
| Checksum | Luhn algorithm |
| Validation | First digit indicates region (1-7, 9); Luhn check digit |
| False-positive risk | Low |
| Distinguishable | Yes — 3-3-3 format differs from SSN (3-2-4); Luhn eliminates ~90% of random matches |

### 1.5 Australia Tax File Number (TFN) — IMPLEMENTED (keyword context)

| Field | Value |
|-------|-------|
| Countries | Australia |
| Format | `NNN NNN NNN` (9 digits, space-separated 3-3-3) |
| Example | `123 456 782` |
| Checksum | Weighted mod-11 (weights: 1, 4, 3, 7, 5, 8, 6, 9, 10) |
| Validation | Weighted sum divisible by 11 |
| False-positive risk | Low |
| Distinguishable | Partially — same 3-3-3 format as Canadian SIN; differentiation requires running both Luhn and mod-11 checks |

### 1.6 New Zealand IRD Number — IMPLEMENTED (keyword context)

| Field | Value |
|-------|-------|
| Countries | New Zealand |
| Format | `NN-NNN-NNN` or `NNN-NNN-NNN` (8 or 9 digits, hyphenated) |
| Example | `49-098-576` |
| Checksum | Weighted mod-11 (weights: 3, 2, 7, 6, 5, 4, 3, 2; secondary weights if check digit = 10) |
| Validation | Range restricted to 10,000,000–150,000,000; mod-11 check digit |
| False-positive risk | Low |
| Distinguishable | Yes — range restriction plus check digit is robust |

### 1.7 Ireland Personal Public Service Number (PPSN) — IMPLEMENTED

| Field | Value |
|-------|-------|
| Countries | Ireland |
| Format | `NNNNNNNLA` or `NNNNNNNL` (7 digits + 1-2 letters) |
| Example | `1234567TA` |
| Checksum | Mod-23 check character |
| Validation | Digits weighted by position (8,7,6,5,4,3,2), sum mod 23 maps to check letter (1=A..0=W) |
| False-positive risk | Low |
| Distinguishable | Yes — the 7-digits-then-letter pattern is unique among structured IDs |

### 1.8 UK National Insurance Number (NINO) — IMPLEMENTED

| Field | Value |
|-------|-------|
| Countries | United Kingdom |
| Format | `LL NN NN NN L` (2 letters, 6 digits, 1 letter A-D) |
| Example | `AB 12 34 56 C` |
| Checksum | None (rule-based) |
| Validation | Prefix letter restrictions; prohibited prefixes BG/GB/NK/KN/TN/NT/ZZ; suffix A-D only |
| False-positive risk | Low |
| Distinguishable | Yes — letter-digit-letter structure is distinctive |

### 1.9 South Africa ID Number — IMPLEMENTED

| Field | Value |
|-------|-------|
| Countries | South Africa |
| Format | `YYMMDDSSSSCCZ` (13 digits, no separators) |
| Example | `8001015009087` |
| Checksum | Luhn algorithm |
| Validation | Embedded DOB (month 01-12, day 01-31); gender digit range; citizenship 0 or 1; Luhn check |
| False-positive risk | Low |
| Distinguishable | Yes — 13 digits with embedded valid date is highly distinctive |

### 1.10 UK Unique Taxpayer Reference (UTR) — IMPLEMENTED (keyword context)

| Field | Value |
|-------|-------|
| Countries | United Kingdom |
| Format | `NNNNNNNNNN` (10 bare digits) |
| Checksum | Mod-11 |
| Validation | First digit is check digit with weighted positions |
| False-positive risk | High |
| Distinguishable | No — overlaps with phone numbers, reference codes; needs keyword context |

---

## 2. Financial Identifiers

### 2.1 Credit Card Number — IMPLEMENTED

| Field | Value |
|-------|-------|
| Countries | International |
| Format | 13-19 digits (typically 16), optional spaces/hyphens in groups of 4 |
| Example | `4111 1111 1111 1111` |
| Checksum | Luhn algorithm |
| False-positive risk | Low |

### 2.2 IBAN — IMPLEMENTED

| Field | Value |
|-------|-------|
| Countries | International (primarily Europe, Middle East) |
| Format | 2-letter country code + 2 check digits + up to 30 alphanumeric chars |
| Example | `GB29 NWBK 6016 1331 9268 19` |
| Checksum | MOD-97 (ISO 7064) |
| False-positive risk | Low |

### 2.3 SWIFT/BIC Code — IMPLEMENTED (keyword context)

| Field | Value |
|-------|-------|
| Countries | International |
| Format | 8 or 11 alphanumeric chars: `BBBBCCLL[BBB]` |
| Example | `COBADEFFXXX` |
| Checksum | None |
| Validation | Positions 1-4 letters (bank), 5-6 letters (ISO country), 7-8 alphanumeric (location), 9-11 optional (branch) |
| False-positive risk | Medium |
| Distinguishable | Moderately — strict positional letter/alphanum rules; country code validation helps |

### 2.4 US ABA Routing Number — IMPLEMENTED (keyword context)

| Field | Value |
|-------|-------|
| Countries | United States |
| Format | 9 bare digits |
| Checksum | Weighted: `3(d1+d4+d7) + 7(d2+d5+d8) + 1(d3+d6+d9) mod 10 = 0` |
| False-positive risk | High |
| Distinguishable | No — overlaps with SSN, SIN, phone numbers, ZIP+4 |

### 2.5 UK Sort Code — IMPLEMENTED (keyword context)

| Field | Value |
|-------|-------|
| Countries | United Kingdom |
| Format | `NN-NN-NN` (6 digits, 2-2-2 hyphenated) |
| Checksum | None standalone |
| False-positive risk | High |
| Distinguishable | No — matches dates, version numbers, scores |

---

## 3. Healthcare

### 3.1 UK NHS Number — IMPLEMENTED (keyword context)

| Field | Value |
|-------|-------|
| Countries | United Kingdom (England, Wales, Isle of Man) |
| Format | `NNN NNN NNNN` (10 digits, 3-3-4 spaced) |
| Example | `943 476 5919` |
| Checksum | Mod-11 (weights: 10, 9, 8, 7, 6, 5, 4, 3, 2; remainder 10 = invalid number) |
| Validation | Check digit = 11 - remainder; if 11 then 0; if 10 then number is never issued |
| False-positive risk | Low-Medium |
| Distinguishable | Moderately — 10 digits could overlap with phone numbers; mod-11 check provides strong filtering |

### 3.2 Australia Medicare Number — IMPLEMENTED (keyword context)

| Field | Value |
|-------|-------|
| Countries | Australia |
| Format | `NNNN NNNNN N` (10 digits, 4-5-1) |
| Example | `2123 45670 1` |
| Checksum | Weighted mod-10 (weights: 1, 3, 7, 9, 1, 3, 7, 9 on first 8 digits) |
| Validation | First digit must be 2-6; checksum on digits 1-8 equals digit 9 |
| False-positive risk | Low-Medium |
| Distinguishable | Moderately — first-digit restriction (2-6) plus checksum; the 4-5-1 display format is somewhat distinctive |

---

## 4. Contact / Network Identifiers

### 4.1 Email Address — IMPLEMENTED

| Field | Value |
|-------|-------|
| Countries | International |
| Format | `local@domain.tld` with Unicode support |
| False-positive risk | Low |

### 4.2 Phone Number — IMPLEMENTED

| Field | Value |
|-------|-------|
| Countries | US-centric (3-3-4 digit pattern with optional +1) |
| Format | `(NNN) NNN-NNNN`, `NNN-NNN-NNNN`, `+1 NNN NNN NNNN`, etc. |
| False-positive risk | Low |

### 4.3 IP Address (IPv4 + IPv6) — IMPLEMENTED

| Field | Value |
|-------|-------|
| Countries | International |
| Format | IPv4: `N.N.N.N` (octets 0-255); IPv6: full and `::` compressed forms |
| False-positive risk | Low |

### 4.4 MAC Address — IMPLEMENTED

| Field | Value |
|-------|-------|
| Countries | International |
| Format | 6 pairs of hex digits separated by colons, hyphens, or dots |
| Examples | `00:1A:2B:3C:4D:5E`, `00-1A-2B-3C-4D-5E`, `001A.2B3C.4D5E` |
| Checksum | None |
| Validation | Consistent separator; valid hex characters |
| False-positive risk | Low |
| Distinguishable | Yes — hex pairs with uniform separators are rare in natural text |

---

## 5. Document Numbers

### 5.1 Passport Number (Generic 9-digit) — IMPLEMENTED (needs rework)

| Field | Value |
|-------|-------|
| Countries | US, UK (legacy format) |
| Format | `NNNNNNNNN` (9 bare digits) |
| Checksum | None |
| False-positive risk | **High** — matches any 9-digit number |
| Note | Should be replaced with country-specific patterns |

### 5.2 US Passport Number (Next Generation) — IMPLEMENTED (keyword context, replaces 5.1)

| Field | Value |
|-------|-------|
| Countries | United States |
| Format | `LNNNNNNNN` (1 letter from {A, X, Y, Z} + 8 digits) |
| Example | `A12345678` |
| Checksum | None |
| False-positive risk | Low |
| Distinguishable | Yes — letter prefix restricted to A/X/Y/Z followed by exactly 8 digits |

### 5.3 US Driver's License Number — IMPLEMENTED (keyword context)

| Field | Value |
|-------|-------|
| Countries | United States (state-specific formats) |
| Format | Letter prefix + digits; varies by state |
| Examples | `B1234568` (CA), `W123456789012` (FL), `S530-4000-0001` (IL), `AB123456` (OH) |
| Checksum | None (no universal checksum across states) |
| Covered formats | 1 letter + 7-14 digits (CA, MA, VA, FL, MI, MN, MD, WI, NJ); 2 letters + 4-8 digits (OH); hyphenated variants (IL, MI) |
| Validation | Letter prefix (1-2 chars) followed by 4-14 digits; structural validation only |
| False-positive risk | Low (with keyword context) |
| Distinguishable | Moderately — letter-prefix formats are distinctive; all-numeric state formats (TX, NY, CO) are excluded due to high overlap |
| Note | Only covers letter-prefix formats; all-numeric state formats are not detected |

### 5.4 UK Driving Licence Number — IMPLEMENTED

| Field | Value |
|-------|-------|
| Countries | United Kingdom |
| Format | 16 characters: `SSSSSYMMDDYA99X9` |
| Example | `JONES910054JJ9AA` |
| Checksum | None (structural validation via embedded DOB and name) |
| Structure | Positions 1-5: surname (padded with 9); position 6: decade of birth year; positions 7-8: month (01-12, +50 for female); positions 9-10: day of birth; position 11: year unit; positions 12-13: initials; positions 14-16: check/random |
| Validation | Embedded date must be valid; name positions must be alpha or 9 |
| False-positive risk | Low |
| Distinguishable | Yes — 16-char alpha-numeric pattern with embedded DOB is unique |

---

## 6. Vehicle Identification

### 6.1 VIN (Vehicle Identification Number) — IMPLEMENTED

| Field | Value |
|-------|-------|
| Countries | International (mandatory in US, CA, EU, AU, NZ, ZA) |
| Format | 17 alphanumeric characters; letters I, O, Q excluded |
| Example | `1HGBH41JXMN109186` |
| Checksum | Mod-11 (mandatory in North America); transliteration table converts letters to digits, weighted by position |
| Validation | Position 9 is check digit; character set excludes I, O, Q |
| False-positive risk | Low |
| Distinguishable | Yes — 17 chars with excluded letters is highly specific |

---

## 7. Device Identifiers

### 7.1 IMEI (International Mobile Equipment Identity) — IMPLEMENTED (keyword context)

| Field | Value |
|-------|-------|
| Countries | International |
| Format | 15 digits, sometimes displayed as `NNNNNNNN-NNNNNN-N` |
| Example | `353456789012345` |
| Checksum | Luhn algorithm |
| Validation | First 8 digits are TAC (Type Allocation Code); Luhn on all 15 |
| False-positive risk | Medium |
| Distinguishable | Partially — overlaps with credit card digit range (13-19 digits); must ensure mutual exclusion with CC detection |

---

## 8. Location Data

### 8.1 Precise Geolocation (Latitude/Longitude) — IMPLEMENTED (keyword context)

| Field | Value |
|-------|-------|
| Countries | International |
| Format | Decimal lat/lon pair: `-NN.NNNN,NN.NNNN` (comma-separated, optional space) |
| Example | `40.7128,-74.0060` |
| Checksum | None |
| Validation | Latitude -90 to 90, longitude -180 to 180; minimum 4 decimal places (~11m precision) |
| False-positive risk | Medium |
| Distinguishable | Moderately — decimal number pairs are common; keyword context and precision requirement reduce false positives |
| Note | CCPA/CPRA lists "precise geolocation" as sensitive personal information |

---

## Implementation Status Summary

### Tier 1 — `RegexDetector` (no keyword context needed)

| PII Type | Country | Checksum | Status |
|----------|---------|----------|--------|
| Canada SIN | CA | Luhn | IMPLEMENTED |
| Ireland PPSN | IE | Mod-23 | IMPLEMENTED |
| South Africa ID | ZA | Luhn | IMPLEMENTED |
| MAC Address | Intl. | None | IMPLEMENTED |
| UK Driving Licence | UK | Structural | IMPLEMENTED |
| VIN | Intl. | Mod-11 | IMPLEMENTED |
| US ITIN | US | None | IMPLEMENTED |

### Tier 2 — `KeywordContextDetector` (keyword prefix required)

| PII Type | Country | Checksum | Status |
|----------|---------|----------|--------|
| Australia TFN | AU | Mod-11 | IMPLEMENTED (keyword context) |
| NZ IRD Number | NZ | Mod-11 | IMPLEMENTED (keyword context) |
| UK NHS Number | UK | Mod-11 | IMPLEMENTED (keyword context) |
| AU Medicare | AU | Mod-10 | IMPLEMENTED (keyword context) |
| US Passport (new) | US | None | IMPLEMENTED (keyword context) |
| SWIFT/BIC | Intl. | None | IMPLEMENTED (keyword context) |
| US EIN | US | None | IMPLEMENTED (keyword context) |
| IMEI | Intl. | Luhn | IMPLEMENTED (keyword context) |
| Precise Geolocation | Intl. | None | IMPLEMENTED (keyword context) |
| US Driver's License | US | None | IMPLEMENTED (keyword context) |

### Tier 3 — `KeywordContextDetector` (high false-positive risk without keywords)

| PII Type | Country | Checksum | Status |
|----------|---------|----------|--------|
| UK UTR | UK | Mod-11 | IMPLEMENTED (keyword context) |
| US ABA Routing | US | Weighted mod-10 | IMPLEMENTED (keyword context) |
| UK Sort Code | UK | None | IMPLEMENTED (keyword context) |
| Passport (generic) | Various | None | IMPLEMENTED (RegexDetector, `\d{9}`) |
