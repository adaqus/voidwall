//! Shared code of the `voidwall-eval` binaries: `ai4privacy-eval` scores the regex
//! engine against AI4Privacy openpii300k; `piimb-spans` writes its spans for the PII
//! Masking Benchmark.

pub mod label;
pub mod language;
pub mod report;
pub mod row;
pub mod score;
