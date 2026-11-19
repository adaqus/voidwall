## MODIFIED Requirements

### Requirement: The image starts with a default configuration

The image SHALL ship a config file at `/etc/voidwall/voidwall.toml` and SHALL set
`VOIDWALL_CONFIG` to that path, so the image starts with no argument and no mounted
file. The file SHALL enable the REST API and SHALL NOT enable the reverse proxy. It
SHALL declare the guards of `docker/voidwall.toml` with the same settings: the regex
`pii` guard, the `invisible_text` guard, the `prompt_injection` guard on wolf-small, and
the `pii_ml` guard on bards-v2, with their model paths under `/opt/voidwall/models/`.
The regex `pii` guard SHALL ignore `PERSON_NAME`, and the `pii_ml` guard SHALL NOT list
`PERSON_NAME` in its `labels`, so no guard reports `PERSON_NAME`. The check on
`Every Monday at 8am` guards against the regex `pii` guard's calendar-word false
positive, in case an operator turns regex names back on.

The file SHALL hold two commented blocks of reverse proxy routes. The LM Studio block
SHALL name the upstream `http://host.docker.internal:1234`, and the Ollama block SHALL
name the upstream `http://host.docker.internal:11434`. Each block SHALL hold a
`/v1/chat/completions` route with `format = "openai-chat"` and a `/` route with the
generic format, both to its upstream.

#### Scenario: The image starts with no argument

- **WHEN** the image runs with no argument and no mounted file
- **THEN** `/readyz` answers 200 once the guards have loaded
- **AND** a `/v1/scan` request whose text is a known prompt injection answers with a
  `PROMPT_INJECTION` finding
- **AND** a `/v1/scan` request whose text holds a tag run answers with an
  `INVISIBLE_TEXT` finding
- **AND** a `/v1/scan` request whose text is `Every Monday at 8am` answers with no
  `PERSON_NAME` finding
- **AND** a `/v1/scan` request whose text holds a person's name answers with no
  `PERSON_NAME` finding from any guard
- **AND** a `/v1/scan` request whose text holds an email address answers with an
  `EMAIL_ADDRESS` finding from the `pii_ml` guard
- **AND** nothing listens on the reverse proxy port

#### Scenario: The operator turns on the LM Studio block

- **WHEN** the default config has `reverse_proxy.enabled = true` and the LM Studio block
  uncommented
- **THEN** `voidwall --validate` on the file passes

#### Scenario: The operator turns on the Ollama block

- **WHEN** the default config has `reverse_proxy.enabled = true` and the Ollama block
  uncommented
- **THEN** `voidwall --validate` on the file passes

#### Scenario: The operator copies the default config out

- **WHEN** the operator runs the image with `--print-config`
- **THEN** stdout is byte for byte `/etc/voidwall/voidwall.toml`
