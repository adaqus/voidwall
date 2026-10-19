## ADDED Requirements

### Requirement: A reverse proxy route's format is validated

A reverse proxy route MAY set `format`. Its only valid value SHALL be the string
`openai-chat`. A route without `format` SHALL keep the generic body scan. Any other value,
or a value that is not a string, SHALL fail config loading with the `schema` category,
and the proxy SHALL NOT start.

#### Scenario: format is absent

- **WHEN** a route sets no `format`
- **THEN** validation passes and the route scans bodies generically

#### Scenario: format is openai-chat

- **WHEN** a route sets `format = "openai-chat"`
- **THEN** validation passes and the route decodes bodies as Chat Completions

#### Scenario: An unknown format

- **WHEN** a route sets `format = "anthropic-messages"`
- **THEN** loading fails with the `schema` category and the proxy does not start

#### Scenario: format is not a string

- **WHEN** a route sets `format = true`
- **THEN** loading fails with the `schema` category and the proxy does not start
