# New Countries & Languages to Implement

Steps 1 & 2 can be done in parallel (independent language additions). Step 3 (Mexico) follows naturally after Step 1. Steps 4-5 build on the languages from 1-2. Steps 6-7 (BE+NL) are independent and can be interleaved. Steps 8-11 are lower priority and can be scheduled later.

| Step | Implemented | Country/Language | Type | Key PII Types to Add | Depends On | Effort | Rationale |
|------|-------|-----------------|------|---------------------|------------|--------|-----------|
| **1** |     | `Language::Es` (Spanish) | Language | Spanish keywords for all international types (Phone, Passport, DOB, Geolocation, SWIFT/BIC, IMEI) + US-specific types (SSN, ITIN, EIN, Drivers License) | — | Low | Serves US (~42M speakers) and is prerequisite for MX |
| **2** |     | `Language::It` (Italian) | Language | Italian keywords for all international types + CH-specific types (AHV, Phone, Postal Code, Address, Postfach) | — | Low | Completes 3 of 4 Swiss languages; independent of Step 1 |
| **3** |     | `Country::Mx` (Mexico) | Country | CURP (18-char, check digit), RFC (12-13 char, check digit), NSS (11-digit, Luhn), Phone (+52, 10 digits), Postal Code (5 digits), Physical Address | Step 1 | Medium | 130M population; CURP/RFC have strong structure, low false positives |
| **4** |     | `Country::Es` (Spain) | Country | DNI/NIE (8 digits + letter, check letter), Phone (+34, 9 digits), Postal Code (5 digits), Passport, Physical Address | Step 1 | Medium | 47M population; DNI has checksum; reuses `Language::Es` |
| **5** |     | `Country::It` (Italy) | Country | Codice Fiscale (16-char, check char), Phone (+39, 9-10 digits), Postal Code (5 digits), Passport, Physical Address | Step 2 | Medium | 60M population; Codice Fiscale is highly structured |
| **6** |     | `Country::Be` (Belgium) | Country | National Number/Rijksregister (11 digits, mod 97), Phone (+32, 8-9 digits), Postal Code (4 digits) | — | **Low** | All 3 official languages (FR, NL, DE) already supported (2 of 3 exist now; NL needed for full coverage) |
| **7** |     | `Country::Nl` (Netherlands) + `Language::Nl` | Country + Language | BSN (9 digits, 11-test), Phone (+31, 9 digits), Postal Code (4 digits + 2 letters), Passport | — | Medium | 17M population; BSN has strong checksum; NL language also enables BE (Step 6) |
| **8** |     | `Country::Pt` (Portugal) + `Language::Pt` | Country + Language | NIF (9 digits, check digit), CC/Cartao Cidadao (12 digits), Phone (+351, 9 digits), Postal Code (4+3) | — | Medium | 10M population; foundation for BR Portuguese later |
| **9** |     | `Country::Br` (Brazil) | Country | CPF (11 digits, 2 check digits), CNPJ (14 digits, 2 check digits), Phone (+55, 10-11 digits), Postal Code (8 digits) | Step 8 | Medium | 215M population; CPF/CNPJ have strong checksums; reuses `Language::Pt` |
| **10** |    | `Country::Se` (Sweden) + `Language::Sv` | Country + Language | Personnummer (10/12 digits, Luhn), Phone (+46, 7-9 digits), Postal Code (5 digits) | — | Medium | Personnummer is well-structured with Luhn check |
| **11** |    | `Country::Pl` (Poland) + `Language::Pl` | Country + Language | PESEL (11 digits, check digit), NIP (10 digits, check digit), Phone (+48, 9 digits), Postal Code (xx-xxx) | — | Medium | 38M population; PESEL/NIP have strong checksums |
