use crate::PiiMatch;

pub trait Detector {
    /// Returns `true` as soon as any PII is found in the input.
    ///
    /// Default implementation delegates to `mark_piis`, but detectors should
    /// override this for efficiency (e.g. using `Regex::is_match`).
    fn has_piis(&self, input: &str) -> bool {
        !self.mark_piis(input).is_empty()
    }

    /// Returns all PII matches found in the input with their byte-offset spans.
    fn mark_piis(&self, input: &str) -> Vec<PiiMatch>;
}
