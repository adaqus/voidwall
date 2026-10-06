## ADDED Requirements

### Requirement: The image ships Oniguruma's license

The image SHALL ship Oniguruma's `COPYING` file, unchanged from the copy bundled in the
`onig_sys` crate version that `Cargo.lock` pins, under `/usr/share/doc/voidwall/oniguruma/`.
Oniguruma is C code compiled into the binary through `onig_sys`, under BSD-2-Clause. The
crate declares its license as MIT, so neither the license gate nor the generated crate
notices carry Oniguruma's own text.

#### Scenario: The Oniguruma license is in the image

- **WHEN** the image is built
- **THEN** `/usr/share/doc/voidwall/oniguruma/COPYING` exists and is byte for byte the
  `oniguruma/COPYING` of the pinned `onig_sys` crate
