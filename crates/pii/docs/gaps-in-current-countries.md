# Gaps in Current Countries

| Implemented | Country | Missing PII Type | Format | Checksum | Priority | Notes |
|-----|---------|-----------------|--------|----------|----------|-------|
|     | **US** | Spanish keywords for existing types | — | — | High | ~42M native speakers; keywords for SSN, ITIN, Phone, DOB, Passport, Drivers License, etc. |
| Yes | **ZA** | Passport Number | 9 digits | No | Medium | Common travel/immigration document |
| Yes | **ZA** | Drivers License | 13 digits | Yes (check digit) | Medium | Common ID in ZA context |
| Yes | **ZA** | Postal Code | 4 digits | No | Low | Simple pattern, may have false positives without keyword context |
| Yes | **AU** | Drivers License | Varies by state (6-10 chars) | No | Medium | Format differs per state — complex |
| Yes | **AU** | ABN (Business Number) | 11 digits | Yes (mod 89) | Low | Business identifier, less personal PII |
|  | **NZ** | Bank Account | 15-16 digits (xx-xxxx-xxxxxxx-xx) | No | Low | Standard NZ bank account format |
|  | **CA** | Drivers License | Varies by province | No | Medium | Province-dependent format — complex |
|  | **CA** | Provincial Health Cards (beyond OHIP) | Varies by province | Varies | Low | Each province has its own format |
|  | **GB** | Bank Account Number | 8 digits | No | Low | Usually paired with Sort Code (already detected) |
|  | **FR** | RIB (Bank Account) | 23 digits | Yes (mod 97) | Low | French domestic bank account format |
|  | **DE** | Drivers License | 11 chars (alphanumeric) | Yes (check digit) | Medium | EU-format since 2013 |
|  | **CH** | Italian keywords for existing types | — | — | Medium | ~8% of CH population (~700k in Ticino) |
