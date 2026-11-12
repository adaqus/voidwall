# Changelog

All notable changes to Voidwall. Each section lists the conventional commits of
one release, grouped by type.

## [0.5.2] - 2026-11-12

### Documentation

- Name v0.5.1 in the docs tag and image pin examples

### Build

- **deps:** Bump axum from 0.8.8 to 0.8.9
- **deps:** Bump lazy_static from 1.5.0 to 1.5.1
- **deps:** Bump test-case from 3.4.0 to 3.4.1
- **deps:** Bump reqwest from 0.12.28 to 0.13.5
- **deps:** Allow the Zlib license, with deny.toml and about.toml
- **deps:** Bump serde_json from 1.0.149 to 1.0.154
- **deps:** Turn off the default features of reqwest
- **deps:** Bump torch to 2.15.0 and transformers to 5.22.1 in parity

### CI

- **deps:** Bump taiki-e/install-action from 2.87.32 to 2.90.0

## [0.5.1] - 2026-11-10

### Bug Fixes

- **api:** Answer an oversize body with the JSON 413

### Documentation

- Add user docs rules and the docs-sync skill
- **openspec:** Archive add-hidden-context-guard
- Move internal docs to docs/dev and add the docs index
- Add the configuration, API, and guards reference
- Add the about, quick start, hardware, and OWASP pages
- Add the LiteLLM and AnythingLLM recipes and shorten the README
- Add the Ollama recipe
- Move the LM Studio steps to their own recipe and clarify guard pages
- Move the LM Studio steps to their own recipe and clarify the Ollama setup
- Describe the project as alpha and state what is tested
- Describe the project as alpha in CONTRIBUTING

### Chores

- Update prompt injection thresholds

## [0.5.0] - 2026-11-05

### Features

- **BREAKING** **pii:** Report only public IP addresses as IP_ADDRESS

### Bug Fixes

- **pii:** Stop matching IPv6 inside code paths such as std::cell
- **pii:** Stop matching IPv6 inside code paths such as std::cell
- **image:** Leave IP_ADDRESS to the regex PII guard in the default pii_ml config

## [0.4.0] - 2026-11-04

### Features

- **BREAKING** **pii:** Add 20 secret kinds and a known-sample deny list

### Chores

- Increase prompt injection threshold for anythingllm experimental config

## [0.3.0] - 2026-10-31

### Features

- **guard:** Add the hidden_context guard for OWASP LLM08

### Bug Fixes

- **pii:** Apply custom regex rules to JSON and CSV bodies

### Build

- **deps:** Bump transformers in /crates/voidwall-ml/parity
- **deps:** Bump crossbeam-channel from 0.5.15 to 0.5.17
- **deps:** Bump regex from 1.12.3 to 1.13.1
- **deps:** Bump memmap2 from 0.9.11 to 0.9.12
- **deps:** Bump tokio-util from 0.7.18 to 0.7.20
- **deps:** Bump criterion from 0.5.1 to 0.8.2

### CI

- **deps:** Bump taiki-e/install-action from 2.87.30 to 2.87.32

## [0.2.0] - 2026-10-28

### Features

- **api:** Add a per-guard breakdown to the /v1/scan response

### Build

- **deps:** Bump rustls from 0.23.45 to 0.23.46

## [0.1.2] - 2026-10-27

### Bug Fixes

- **release:** Regenerate the OpenAPI document when cutting a release

## [0.1.1] - 2026-10-27

### Documentation

- **openspec:** Archive release-cpu-image
- **readme:** Quick start with docker run and /v1/scan

### Build

- **docker:** Run the image as non-root UID 65532

## [0.1.0] - 2026-10-27

### Features

- **release:** Ship the models and a default config in the image
- **release:** Remove temporary image build trigger

### Bug Fixes

- Stop the start when a listener cannot bind

### Documentation

- **parity:** Update the torch delta and pin for torch 2.14.1

### Tests

- Fix the port race in the startup integration tests
- Fix the port race in the model guard integration tests

### Build

- **deps:** Bump ort to 2.0.0-rc.15
- **deps:** Remove unused rcgen
- **deps:** Bump test-case from 3.3.1 to 3.4.0
- **deps:** Bump futures-util from 0.3.32 to 0.3.34
- **deps:** Remove unused rustls and tokio-rustls
- **deps:** Bump tokenizers to 0.23.2 and transformers to 5.20.2
- **deps:** Bump torch in /crates/voidwall-ml/parity

### CI

- Enforce Conventional Commits
- Cancel pending check builds superseded by a newer push
- **deps:** Bump actions/checkout from 5.1.0 to 7.0.1
- **deps:** Bump actions/cache from 4.3.0 to 6.1.0
- **deps:** Bump taiki-e/install-action from 2.87.24 to 2.87.30

