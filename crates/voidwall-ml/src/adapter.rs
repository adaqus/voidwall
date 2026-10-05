use std::ops::RangeInclusive;

use serde::Deserialize;

/// The code path that runs one model guard's model.
///
/// An adapter owns the runtime, the preprocessing, the tensor contract, the
/// output interpretation, and whether the guard's findings carry spans. The
/// build ships the set, so configuration picks one by name and can override
/// none of it — which is also why an unknown name is a schema failure rather
/// than a rule configuration checks.
///
/// There is no `runtime` key anywhere: ONNX is the only runtime, so the key
/// could only be written wrong.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    /// One score for the whole input, over a single label.
    TextClassifier,
    /// One score per label, for several labels at once.
    TextMultilabelClassifier,
}

impl AdapterKind {
    /// The scores this adapter produces. A threshold outside it could never be
    /// met or could never be missed, so it is rejected at startup.
    pub fn score_range(self) -> RangeInclusive<f32> {
        match self {
            Self::TextClassifier | Self::TextMultilabelClassifier => 0.0..=1.0,
        }
    }
}
