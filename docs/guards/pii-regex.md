# Regex PII Guard

The `pii` guard finds personal data and secrets with regular expressions, keyword rules,
checks such as checksums, and a dictionary of names. It runs no model, so it is fast and
gives the same result each time. It runs on its own CPU threads.

The guard runs when the config file holds a `[builtin_guards.pii]` section. The config
of the image holds one. Every key of the section is in
[configuration.md](../configuration.md#builtin_guardspii).

## Choose what it finds

```toml
[builtin_guards.pii]
countries = ["International", "Us", "Gb"]
languages = ["En"]
```

- `countries` selects the kinds of these countries. `International` holds the kinds that
  belong to no country, such as e-mail addresses, card numbers, and cloud keys. An empty
  list selects all countries. If you list countries without `International`, and do not
  set `detect`, Voidwall logs a warning at startup. The warning names the kinds and the
  custom rules that are then never found.
- `languages` selects the keyword languages. Some kinds need a keyword near the value,
  for example "passport" before a passport number, because the value alone has no
  shape that is safe to match. An empty list selects all languages: `En`, `Fr`, `De`,
  `Nl`, `It`, `Es`, `Pl`.
- `detect` keeps only the kinds that you list. `ignore` removes the kinds that you list.
  You can set one of them, not both.

```toml
[builtin_guards.pii]
countries = ["International", "Us"]
ignore = ["IpAddress", "MacAddress"]
```

### Names and labels

A kind has two names:

- The **name** is what `detect` and `ignore` take, such as `UsSsn`.
- The **label** is what a finding reports in `kinds`, in metrics, and in a 403, such as
  `US_SSN`.

The [table of kinds](#kinds) gives both, and the country of each kind. A kind of a
country that `countries` does not select is never found, also when `detect` lists it.

## What it reads

The guard reads the parts of a message that its `surface` admits: the URL path, the query
string, the body, and the header values that the route names. All four are on by default.

A body is read only when its content type is in `content_types`. A JSON, CSV, or TSV body
is read value by value:

- In JSON, each string value is read on its own. The key path of the value, such as
  `user.passport`, counts as the text before it. So `{"user": {"passport": "..."}}`
  can match a passport number that needs the keyword "passport".
- In CSV and TSV, each cell is read on its own, and its column name counts as the text
  before it. A file with no header row is read as plain text.
- A body that does not parse follows `on_error`.

## Overlapping matches

Two rules can match the same text, for example a number that has the shape of two
kinds. The guard keeps one non-overlapping set of matches:

- A match inside a longer match is dropped.
- For two matches of the same text, a fixed priority picks one kind.
- For two matches that partly overlap, the longer one stays.

`matches_count`, `kinds`, and the metrics come from this set. The same value at two
places in a message counts two times.

The guard resolves only its own matches. When a model guard reports a kind of the same
name, such as `PERSON_NAME`, both findings stay. See
[model-guards.md](model-guards.md#two-guards-that-report-one-kind).

## Custom rules

`[[builtin_guards.pii.custom]]` adds a rule of your own: a regular expression and the
label that its match reports. The label appears in `kinds`, in a 403, and in the
`pii_kind` metric label, as a built-in label does. See
`openspec/specs/custom-pii/spec.md` for the full specification.

### Example

```toml
[builtin_guards.pii]
countries = ["International", "Us"]
languages = ["En"]
detect = ["Email", "CreditCard", "UsSsn"]

[[builtin_guards.pii.custom]]
label   = "EMPLOYEE_ID"
pattern = 'EMP-\d{6}'

[[builtin_guards.pii.custom]]
label    = "PROJECT_CODE"
pattern  = '[A-Z]{3}-\d{3}'
keywords = ["project code", "proj id"]
```

With this config, `Badge EMP-123456 was found` reports `EMPLOYEE_ID`, and
`project code ABC-123` reports `PROJECT_CODE`. `ABC-123` alone reports nothing, because
the rule needs a keyword.

`detect` and `ignore` apply only to built-in kinds. A custom rule runs because it is in
the file, so `Custom` is not a name that `detect` or `ignore` can take.

### Keywords

When `keywords` has entries, a match needs one of them just before the value. Spaces and
punctuation can be between the keyword and the value. The match covers only the value,
not the keyword. Use keywords when the pattern alone matches too much text.

In a JSON or CSV body, the key path or the column name counts as the text before the
value. `{"user": {"badge": "123456"}}` matches the keyword `badge`. The key must spell
the keyword exactly: `badge_number` does not match `badge`, so list each key form that
you expect.

### Rules for a custom entry

Each of these stops the start:

- `label` is empty, is the label of a built-in kind, or is the label of another entry.
- `pattern` is empty or does not compile. The pattern must compile in two engines, the
  Rust `regex` crate and Vectorscan, so it cannot use backreferences or lookaround.
- The section has more than 64 entries.

An entry whose `country` is not in `countries` stays in the file, but it never runs.

## Kinds

Every built-in kind. `country` and `countries` take the values of the Country column.

| Name | Label | Country |
|---|---|---|
| `Email` | `EMAIL` | `International` |
| `UsPhoneNumber` | `US_PHONE_NUMBER` | `International` |
| `CreditCard` | `CREDIT_CARD` | `International` |
| `UsSsn` | `US_SSN` | `Us` |
| `GbNino` | `GB_NINO` | `Gb` |
| `Iban` | `IBAN` | `International` |
| `PassportNumber` | `PASSPORT_NUMBER` | `International` |
| `IpAddress` | `IP_ADDRESS` | `International` |
| `UsItin` | `US_ITIN` | `Us` |
| `CaSin` | `CA_SIN` | `Ca` |
| `IePpsn` | `IE_PPSN` | `Ie` |
| `ZaId` | `ZA_ID` | `Za` |
| `MacAddress` | `MAC_ADDRESS` | `International` |
| `GbDrivingLicence` | `GB_DRIVING_LICENCE` | `Gb` |
| `Vin` | `VIN` | `International` |
| `AuTfn` | `AU_TFN` | `Au` |
| `NzIrdNumber` | `NZ_IRD_NUMBER` | `Nz` |
| `GbNhsNumber` | `GB_NHS_NUMBER` | `Gb` |
| `AuMedicare` | `AU_MEDICARE` | `Au` |
| `UsPassportNew` | `US_PASSPORT_NEW` | `Us` |
| `SwiftBic` | `SWIFT_BIC` | `International` |
| `UsEin` | `US_EIN` | `Us` |
| `Imei` | `IMEI` | `International` |
| `GbUtr` | `GB_UTR` | `Gb` |
| `UsAbaRouting` | `US_ABA_ROUTING` | `Us` |
| `GbSortCode` | `GB_SORT_CODE` | `Gb` |
| `PreciseGeolocation` | `PRECISE_GEOLOCATION` | `International` |
| `UsDriversLicense` | `US_DRIVERS_LICENSE` | `Us` |
| `UsAlienNumber` | `US_ALIEN_NUMBER` | `Us` |
| `UsUscisReceiptNumber` | `US_USCIS_RECEIPT_NUMBER` | `Us` |
| `NzNhiNumber` | `NZ_NHI_NUMBER` | `Nz` |
| `NzDriverLicence` | `NZ_DRIVER_LICENCE` | `Nz` |
| `IeDriverNumber` | `IE_DRIVER_NUMBER` | `Ie` |
| `CaDriversLicense` | `CA_DRIVERS_LICENSE` | `Ca` |
| `ZaTaxReference` | `ZA_TAX_REFERENCE` | `Za` |
| `CaOhip` | `CA_OHIP` | `Ca` |
| `GbPhoneNumber` | `GB_PHONE_NUMBER` | `Gb` |
| `AuPhoneNumber` | `AU_PHONE_NUMBER` | `Au` |
| `NzPhoneNumber` | `NZ_PHONE_NUMBER` | `Nz` |
| `IePhoneNumber` | `IE_PHONE_NUMBER` | `Ie` |
| `ZaPhoneNumber` | `ZA_PHONE_NUMBER` | `Za` |
| `AwsAccessKey` | `AWS_ACCESS_KEY` | `International` |
| `GithubToken` | `GITHUB_TOKEN` | `International` |
| `AwsSecretKey` | `AWS_SECRET_KEY` | `International` |
| `GbZaPassportNumber` | `GB_ZA_PASSPORT_NUMBER` | `Gb` |
| `AuPassportNumber` | `AU_PASSPORT_NUMBER` | `Au` |
| `CaPassportNumber` | `CA_PASSPORT_NUMBER` | `Ca` |
| `NzPassportNumber` | `NZ_PASSPORT_NUMBER` | `Nz` |
| `IePassportNumber` | `IE_PASSPORT_NUMBER` | `Ie` |
| `DateOfBirth` | `DATE_OF_BIRTH` | `International` |
| `GbPostcode` | `GB_POSTCODE` | `Gb` |
| `CaPostalCode` | `CA_POSTAL_CODE` | `Ca` |
| `BitcoinAddress` | `BITCOIN_ADDRESS` | `International` |
| `EthereumAddress` | `ETHEREUM_ADDRESS` | `International` |
| `AuBankAccount` | `AU_BANK_ACCOUNT` | `Au` |
| `CaBankAccount` | `CA_BANK_ACCOUNT` | `Ca` |
| `FrNir` | `FR_NIR` | `Fr` |
| `FrSiret` | `FR_SIRET` | `Fr` |
| `FrSiren` | `FR_SIREN` | `Fr` |
| `FrPassportNumber` | `FR_PASSPORT_NUMBER` | `Fr` |
| `FrCni` | `FR_CNI` | `Fr` |
| `FrDriversLicense` | `FR_DRIVERS_LICENSE` | `Fr` |
| `FrPhoneNumber` | `FR_PHONE_NUMBER` | `Fr` |
| `FrPostalCode` | `FR_POSTAL_CODE` | `Fr` |
| `FrNif` | `FR_NIF` | `Fr` |
| `FrChAddress` | `FR_CH_ADDRESS` | `Fr` |
| `FrChBoitePostale` | `FR_CH_BOITE_CASE_POSTALE` | `Fr` |
| `DeSteuerId` | `DE_STEUER_ID` | `De` |
| `DePersonalausweis` | `DE_PERSONALAUSWEIS` | `De` |
| `DePassportNumber` | `DE_PASSPORT_NUMBER` | `De` |
| `DePhoneNumber` | `DE_PHONE_NUMBER` | `De` |
| `DePostalCode` | `DE_POSTAL_CODE` | `De` |
| `AtSvnr` | `AT_SVNR` | `At` |
| `AtPhoneNumber` | `AT_PHONE_NUMBER` | `At` |
| `AtPostalCode` | `AT_POSTAL_CODE` | `At` |
| `ChAhv` | `CH_AHV` | `Ch` |
| `ChPhoneNumber` | `CH_PHONE_NUMBER` | `Ch` |
| `ChPostalCode` | `CH_POSTAL_CODE` | `Ch` |
| `PersonName` | `PERSON_NAME` | `International` |
| `DeAtChAddress` | `DE_AT_CH_ADDRESS` | `De` |
| `DeAtChPostfach` | `DE_AT_CH_POSTFACH` | `De` |
| `DePackstation` | `DE_PACKSTATION` | `De` |
| `ZaDriversLicense` | `ZA_DRIVERS_LICENSE` | `Za` |
| `UsZaPostalCode` | `US_ZA_POSTAL_CODE` | `Us` |
| `AuDriversLicense` | `AU_DRIVERS_LICENSE` | `Au` |
| `AuAbn` | `AU_ABN` | `Au` |
| `IeEircode` | `IE_EIRCODE` | `Ie` |
| `NlBsn` | `NL_BSN` | `Nl` |
| `NlBtw` | `NL_BTW` | `Nl` |
| `NlPostalCode` | `NL_POSTAL_CODE` | `Nl` |
| `NlPhoneNumber` | `NL_PHONE_NUMBER` | `Nl` |
| `NlPassportNumber` | `NL_PASSPORT_NUMBER` | `Nl` |
| `NlDriversLicense` | `NL_DRIVERS_LICENSE` | `Nl` |
| `ItCodiceFiscale` | `IT_CODICE_FISCALE` | `It` |
| `ItPartitaIva` | `IT_PARTITA_IVA` | `It` |
| `ItPostalCode` | `IT_POSTAL_CODE` | `It` |
| `ItPhoneNumber` | `IT_PHONE_NUMBER` | `It` |
| `ItPassportNumber` | `IT_PASSPORT_NUMBER` | `It` |
| `ItDriversLicense` | `IT_DRIVERS_LICENSE` | `It` |
| `EsDni` | `ES_DNI` | `Es` |
| `EsNie` | `ES_NIE` | `Es` |
| `EsCif` | `ES_CIF` | `Es` |
| `EsNuss` | `ES_NUSS` | `Es` |
| `EsPassportNumber` | `ES_PASSPORT_NUMBER` | `Es` |
| `EsPostalCode` | `ES_POSTAL_CODE` | `Es` |
| `EsPhoneNumber` | `ES_PHONE_NUMBER` | `Es` |
| `PlPesel` | `PL_PESEL` | `Pl` |
| `PlNip` | `PL_NIP` | `Pl` |
| `PlRegon` | `PL_REGON` | `Pl` |
| `PlIdCard` | `PL_ID_CARD` | `Pl` |
| `PlPassportNumber` | `PL_PASSPORT_NUMBER` | `Pl` |
| `PlPhoneNumber` | `PL_PHONE_NUMBER` | `Pl` |
| `PlPostalCode` | `PL_POSTAL_CODE` | `Pl` |
| `PlDriversLicense` | `PL_DRIVERS_LICENSE` | `Pl` |
| `GbAddress` | `GB_ADDRESS` | `Gb` |
| `InternationalPhoneNumber` | `PHONE_NUMBER` | `International` |
| `SecondaryAddress` | `SECONDARY_ADDRESS` | `International` |
| `UsGbCaAuNzIeZaStreet` | `US_GB_CA_AU_NZ_IE_ZA_STREET` | `International` |
| `OpenAiApiKey` | `OPENAI_API_KEY` | `International` |
| `AnthropicApiKey` | `ANTHROPIC_API_KEY` | `International` |
| `SlackToken` | `SLACK_TOKEN` | `International` |
| `StripeSecretKey` | `STRIPE_SECRET_KEY` | `International` |
| `GoogleApiKey` | `GOOGLE_API_KEY` | `International` |
| `GitlabToken` | `GITLAB_TOKEN` | `International` |
| `HuggingFaceToken` | `HUGGINGFACE_TOKEN` | `International` |
| `NpmToken` | `NPM_TOKEN` | `International` |
| `PypiToken` | `PYPI_TOKEN` | `International` |
| `AzureAdClientSecret` | `AZURE_AD_CLIENT_SECRET` | `International` |
| `SupabaseSecretKey` | `SUPABASE_SECRET_KEY` | `International` |
| `OpenRouterApiKey` | `OPENROUTER_API_KEY` | `International` |
| `PerplexityApiKey` | `PERPLEXITY_API_KEY` | `International` |
| `XaiApiKey` | `XAI_API_KEY` | `International` |
| `FirecrawlApiKey` | `FIRECRAWL_API_KEY` | `International` |
| `GroqApiKey` | `GROQ_API_KEY` | `International` |
| `ReplicateApiToken` | `REPLICATE_API_TOKEN` | `International` |
| `PrivateKey` | `PRIVATE_KEY` | `International` |
| `Jwt` | `JWT` | `International` |
| `UrlCredentials` | `URL_CREDENTIALS` | `International` |
