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
    /// The name configuration selects this adapter by, as `adapter = "..."`.
    pub fn name(self) -> &'static str {
        match self {
            Self::TextClassifier => "text_classifier",
            Self::TextMultilabelClassifier => "text_multilabel_classifier",
        }
    }

    /// The scores this adapter produces. A threshold outside it could never be
    /// met or could never be missed, so it is rejected at startup.
    pub fn score_range(self) -> RangeInclusive<f32> {
        match self {
            Self::TextClassifier | Self::TextMultilabelClassifier => 0.0..=1.0,
        }
    }
}

/// The code path of one [`AdapterKind`]. A contributor adds an adapter by
/// implementing this trait and giving its kind an arm in [`crate::load`].
///
/// This holds the load side only: what the model's tensors must look like for
/// the adapter to run it.
pub trait Adapter {
    /// The last dimension the model's single output must have.
    const OUTPUT_WIDTH: i64;
}

/// [`AdapterKind::TextClassifier`]: a binary head, two logits per input.
pub struct TextClassifier;

impl Adapter for TextClassifier {
    const OUTPUT_WIDTH: i64 = 2;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::IntoDeserializer;
    use serde::de::value::{Error, StrDeserializer};
    use test_case::test_case;

    #[test_case(AdapterKind::TextClassifier ; "text classifier")]
    #[test_case(AdapterKind::TextMultilabelClassifier ; "text multilabel classifier")]
    fn the_name_is_the_config_name(kind: AdapterKind) {
        let name: StrDeserializer<Error> = kind.name().into_deserializer();
        assert_eq!(AdapterKind::deserialize(name).unwrap(), kind);
    }
}
