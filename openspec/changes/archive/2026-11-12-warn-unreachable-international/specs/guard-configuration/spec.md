## ADDED Requirements

### Requirement: Countries without International warn rather than stop the start

When the `pii` guard is enabled, `builtin_guards.pii.countries` lists at least one
country but not `International`, and `detect` is not set, the proxy SHALL log one
warning at startup and SHALL continue. The warning SHALL name, once each and in sorted
order:

- every built-in kind whose country is `International`, except a kind that `ignore`
  lists and except `CUSTOM`;
- the label of every `[[builtin_guards.pii.custom]]` entry whose `country` is
  `International`.

The proxy SHALL NOT log the warning when `countries` is empty or absent, when it lists
`International`, when `detect` is set, when the `pii` guard is disabled, or when the
warning would name nothing. Validate mode SHALL NOT log it.

#### Scenario: Countries omit International

- **WHEN** the `pii` guard sets `countries = ["Us"]`
- **THEN** the proxy starts and logs one warning that names `EMAIL`, `CREDIT_CARD`,
  `IBAN`, and `IP_ADDRESS`, and does not name `US_SSN` or `CUSTOM`

#### Scenario: An ignored kind is not named

- **WHEN** the `pii` guard sets `countries = ["Us"]` and `ignore = ["Email"]`
- **THEN** the warning does not name `EMAIL` and names `IBAN`

#### Scenario: A custom rule of International is named

- **WHEN** the `pii` guard sets `countries = ["Us"]`, one custom rule has no `country`,
  and another sets `country = "Us"`
- **THEN** the warning names the first rule's label and not the second one's

#### Scenario: Every country is selected

- **WHEN** the `pii` guard omits `countries` or sets `countries = []`
- **THEN** the proxy logs no such warning

#### Scenario: International is listed

- **WHEN** the `pii` guard sets `countries = ["International", "Us"]`
- **THEN** the proxy logs no such warning

#### Scenario: detect names the kinds

- **WHEN** the `pii` guard sets `countries = ["Us"]` and `detect = ["UsSsn"]`
- **THEN** the proxy logs no such warning

#### Scenario: The guard is disabled

- **WHEN** the `pii` section sets `countries = ["Us"]` and `enabled = false`
- **THEN** the proxy logs no such warning

#### Scenario: Validate mode

- **WHEN** the proxy runs `--validate` on a config whose `pii` guard sets
  `countries = ["Us"]`
- **THEN** it prints the success line and logs no such warning
