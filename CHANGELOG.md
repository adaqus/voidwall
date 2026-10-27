# Changelog

All notable changes to Voidwall. Each section lists the conventional commits of
one release, grouped by type.

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

