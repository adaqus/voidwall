//! Matomo specialization stub. The real decoder lands in TASKS.md § 16.4 —
//! this file exists in 16.1 only so the registry can hand out a stable
//! `&'static dyn Specialization` for the name `"matomo"`.

use super::{ProcessFuture, ScanHandle, Specialization, SpecializationError};

pub struct MatomoSpecialization;

impl Specialization for MatomoSpecialization {
    fn name(&self) -> &'static str {
        "matomo"
    }

    fn process<'a>(
        &'a self,
        _query: Option<&'a str>,
        _body: Option<&'a [u8]>,
        _body_content_type: Option<&'a str>,
        _scan: &'a ScanHandle<'a>,
    ) -> ProcessFuture<'a> {
        Box::pin(async move {
            Err(SpecializationError::Decode {
                reason: "matomo specialization not yet implemented (phase 16.4)".into(),
            })
        })
    }
}
