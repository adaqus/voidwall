//! GA4 specialization stub. The real decoder lands in TASKS.md § 16.3 —
//! this file exists in 16.1 only so the registry can hand out a stable
//! `&'static dyn Specialization` for the name `"ga4"`.

use super::{ProcessFuture, ScanHandle, Specialization, SpecializationError};

pub struct Ga4Specialization;

impl Specialization for Ga4Specialization {
    fn name(&self) -> &'static str {
        "ga4"
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
                reason: "ga4 specialization not yet implemented (phase 16.3)".into(),
            })
        })
    }
}
