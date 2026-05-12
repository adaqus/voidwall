use crate::{ContextFragment, PiiMatch};

pub trait Detector: Send + Sync {
    /// Returns `true` as soon as any PII is found in the input.
    ///
    /// Default implementation delegates to `mark_piis`, but detectors should
    /// override this for efficiency (e.g. using `Regex::is_match`).
    fn has_piis(&self, input: &str) -> bool {
        !self.mark_piis(input).is_empty()
    }

    /// Returns all PII matches found in the input with their byte-offset spans.
    fn mark_piis(&self, input: &str) -> Vec<PiiMatch>;

    /// Scans structured (parsed) input — a sequence of context/value
    /// fragments produced by callers that have already parsed JSON, CSV, or
    /// similar formats. Returned `PiiMatch` spans are document-absolute,
    /// using the per-fragment `offset`.
    ///
    /// Default implementation is a no-op: detectors that benefit from
    /// structural context (e.g. keyword-context detectors) override this;
    /// purely pattern-based detectors can leave the default in place if
    /// they have no use for context.
    fn mark_piis_structured(&self, _fragments: &[ContextFragment<'_>]) -> Vec<PiiMatch> {
        Vec::new()
    }
}
