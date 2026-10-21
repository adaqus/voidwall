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
    /// One label per token, so findings carry spans. The labels come from the
    /// model's `config.json`.
    TokenClassifier,
}

impl AdapterKind {
    /// The name configuration selects this adapter by, as `adapter = "..."`.
    pub fn name(self) -> &'static str {
        match self {
            Self::TextClassifier => "text_classifier",
            Self::TextMultilabelClassifier => "text_multilabel_classifier",
            Self::TokenClassifier => "token_classifier",
        }
    }

    /// The scores this adapter produces. A threshold outside it could never be
    /// met or could never be missed, so it is rejected at startup.
    pub fn score_range(self) -> RangeInclusive<f32> {
        match self {
            Self::TextClassifier | Self::TextMultilabelClassifier | Self::TokenClassifier => {
                0.0..=1.0
            }
        }
    }
}

/// The code path of one [`AdapterKind`]. A contributor adds an adapter by
/// implementing this trait and giving its kind an arm in [`crate::load`].
///
/// It holds what differs between adapters: the width of the model's output
/// and how one window's output becomes a score. Tokenizing, windows, and the
/// maximum over windows are shared code.
pub trait Adapter {
    /// The last dimension the model's single output must have.
    const OUTPUT_WIDTH: i64;

    /// The score of one window, in the adapter's score range, from its
    /// `OUTPUT_WIDTH` logits. The run checks that every logit is finite first.
    fn window_score(logits: &[f32]) -> f32;
}

/// [`AdapterKind::TextClassifier`]: a binary head, two logits per input.
/// Class 1 is the class its single label names.
pub struct TextClassifier;

impl Adapter for TextClassifier {
    const OUTPUT_WIDTH: i64 = 2;

    /// `softmax(logits)[1]`, written as `sigmoid(l1 − l0)`: for finite logits it
    /// needs no max-shift and cannot become NaN.
    fn window_score(logits: &[f32]) -> f32 {
        1.0 / (1.0 + (logits[0] - logits[1]).exp())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::IntoDeserializer;
    use serde::de::value::{Error, StrDeserializer};
    use test_case::test_case;

    #[test_case(AdapterKind::TextClassifier ; "text classifier")]
    #[test_case(AdapterKind::TextMultilabelClassifier ; "text multilabel classifier")]
    #[test_case(AdapterKind::TokenClassifier ; "token classifier")]
    fn the_name_is_the_config_name(kind: AdapterKind) {
        let name: StrDeserializer<Error> = kind.name().into_deserializer();
        assert_eq!(AdapterKind::deserialize(name).unwrap(), kind);
    }

    #[test_case([0.0, 0.0], 0.5 ; "equal logits")]
    #[test_case([3.0, 3.0], 0.5 ; "equal non-zero logits")]
    #[test_case([-1e30, 1e30], 1.0 ; "class 1 far ahead")]
    #[test_case([1e30, -1e30], 0.0 ; "class 0 far ahead")]
    fn the_text_classifier_scores_softmax_one(logits: [f32; 2], expected: f32) {
        let score = TextClassifier::window_score(&logits);
        assert!(!score.is_nan());
        assert_eq!(score, expected);
    }

    #[test]
    fn the_text_classifier_score_equals_softmax() {
        let (l0, l1) = (0.3f32, 1.7f32);
        let softmax = l1.exp() / (l0.exp() + l1.exp());
        assert!((TextClassifier::window_score(&[l0, l1]) - softmax).abs() < 1e-6);
    }
}
