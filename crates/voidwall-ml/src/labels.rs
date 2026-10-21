//! A token classifier's labels, read from `id2label` in the model's
//! `config.json`, and the pooling of one token's logits into one probability
//! per entity type.

use std::collections::BTreeSet;
use std::path::Path;

use crate::load::LoadError;

/// The label of tokens outside every entity.
const OUTSIDE: &str = "O";

/// The labels of one token classifier.
///
/// A token's pooled probabilities have one slot per entity type, in
/// [`Labels::types`] order, then one slot for `O`.
#[derive(Debug, PartialEq)]
pub struct Labels {
    /// The distinct entity type names, prefixes removed, sorted.
    types: Vec<String>,
    /// For each label ID, its pooled slot.
    slot: Vec<usize>,
    /// For each label ID, whether it starts an entity: `B-` or `S-`.
    starts: Vec<bool>,
}

impl Labels {
    /// Reads `id2label` from the `config.json` at `path`.
    pub(crate) fn read(path: &Path) -> Result<Self, LoadError> {
        let text = std::fs::read_to_string(path).map_err(|e| LoadError::ConfigUnreadable {
            path: path.to_owned(),
            reason: e.to_string(),
        })?;
        let json: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| LoadError::ConfigUnreadable {
                path: path.to_owned(),
                reason: e.to_string(),
            })?;
        Self::from_config(&json).map_err(|reason| LoadError::Id2Label {
            path: path.to_owned(),
            reason,
        })
    }

    fn from_config(json: &serde_json::Value) -> Result<Self, String> {
        let id2label = json
            .get("id2label")
            .and_then(serde_json::Value::as_object)
            .ok_or("there is no `id2label` object")?;

        let mut labels: Vec<Option<&str>> = vec![None; id2label.len()];
        for (key, label) in id2label {
            // Only the canonical decimal form: "01" or "+1" is not an ID.
            let id = key
                .parse::<usize>()
                .ok()
                .filter(|id| id.to_string() == *key && *id < labels.len())
                .ok_or_else(|| {
                    format!(
                        "key `{key}` is not an ID from 0 to {}",
                        labels.len().saturating_sub(1)
                    )
                })?;
            let label = label
                .as_str()
                .ok_or_else(|| format!("the label of ID {id} is not a string"))?;
            labels[id] = Some(label);
        }
        // n distinct keys, each below n: every ID is present.
        let labels: Vec<&str> = labels.into_iter().flatten().collect();

        let outside = labels.iter().filter(|&&l| l == OUTSIDE).count();
        if outside != 1 {
            return Err(format!(
                "{outside} labels are `{OUTSIDE}`; exactly one is required"
            ));
        }

        let parsed = labels
            .iter()
            .map(|label| Label::parse(label))
            .collect::<Result<Vec<_>, _>>()?;
        let types: Vec<String> = parsed
            .iter()
            .filter_map(|label| match *label {
                Label::Entity { ty, .. } => Some(ty),
                Label::Outside => None,
            })
            .collect::<BTreeSet<&str>>()
            .into_iter()
            .map(str::to_owned)
            .collect();
        let slot = parsed
            .iter()
            .map(|label| match *label {
                Label::Entity { ty, .. } => types.partition_point(|t| t.as_str() < ty),
                Label::Outside => types.len(),
            })
            .collect();
        let starts = parsed
            .iter()
            .map(|label| matches!(label, Label::Entity { starts: true, .. }))
            .collect();
        Ok(Self {
            types,
            slot,
            starts,
        })
    }

    /// The entity type names, prefixes removed, sorted. `O` is not one.
    pub fn types(&self) -> &[String] {
        &self.types
    }

    /// The slots of one token's pooled probabilities: the types, then `O`.
    pub fn slots(&self) -> usize {
        self.types.len() + 1
    }

    /// The number of labels, which is the model's output width.
    pub(crate) fn len(&self) -> usize {
        self.slot.len()
    }

    /// Adds one token's probabilities, the softmax of its finite `logits`,
    /// to `pooled`: each label's probability goes to its type's slot. Returns
    /// the token's start probability, the sum over its `B-` and `S-` labels.
    pub(crate) fn pool(&self, logits: &[f32], pooled: &mut [f32]) -> f32 {
        let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let sum: f32 = logits.iter().map(|l| (l - max).exp()).sum();
        let mut start = 0.0;
        for (id, l) in logits.iter().enumerate() {
            let p = (l - max).exp() / sum;
            pooled[self.slot[id]] += p;
            if self.starts[id] {
                start += p;
            }
        }
        start
    }
}

/// One label of `id2label`.
enum Label<'a> {
    Outside,
    /// `ty` is the type name without its prefix; `starts` is true for `B-` and `S-`.
    Entity {
        ty: &'a str,
        starts: bool,
    },
}

impl<'a> Label<'a> {
    fn parse(label: &'a str) -> Result<Self, String> {
        if label == OUTSIDE {
            return Ok(Self::Outside);
        }
        let (ty, starts) = if let Some(ty) = label.strip_prefix("B-").or(label.strip_prefix("S-")) {
            (ty, true)
        } else if let Some(ty) = label.strip_prefix("I-") {
            (ty, false)
        } else {
            (label, false)
        };
        if ty.is_empty() {
            return Err(format!("label `{label}` has a prefix but no type name"));
        }
        Ok(Self::Entity { ty, starts })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    fn labels(id2label: &[(&str, &str)]) -> Result<Labels, String> {
        let map: serde_json::Map<String, serde_json::Value> = id2label
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::from(*v)))
            .collect();
        Labels::from_config(&serde_json::json!({ "id2label": map }))
    }

    #[test]
    fn a_bio_model_has_one_type() {
        let labels = labels(&[("0", "O"), ("1", "B-PERSON_NAME"), ("2", "I-PERSON_NAME")]).unwrap();
        assert_eq!(labels.types(), ["PERSON_NAME"]);
        assert_eq!(labels.slot, [1, 0, 0]);
        assert_eq!(labels.starts, [false, true, false]);
    }

    #[test]
    fn types_are_sorted_and_o_takes_the_last_slot() {
        let labels = labels(&[
            ("0", "S-PHONE"),
            ("1", "I-EMAIL"),
            ("2", "O"),
            ("3", "B-EMAIL"),
            ("4", "ADDRESS"),
        ])
        .unwrap();
        assert_eq!(labels.types(), ["ADDRESS", "EMAIL", "PHONE"]);
        assert_eq!(labels.slots(), 4);
        assert_eq!(labels.slot, [2, 1, 3, 1, 0]);
        assert_eq!(labels.starts, [true, false, false, true, false]);
    }

    #[test]
    fn io_labels_have_no_prefix_and_never_start() {
        let labels = labels(&[("0", "O"), ("1", "PERSON_NAME")]).unwrap();
        assert_eq!(labels.types(), ["PERSON_NAME"]);
        assert_eq!(labels.starts, [false, false]);
    }

    #[test_case(&[("0", "O"), ("1", "B-X"), ("3", "I-X")], &["key `3`"] ; "a gap in the ids")]
    #[test_case(&[("0", "O"), ("01", "B-X")], &["key `01`"] ; "a non canonical id")]
    #[test_case(&[("0", "O"), ("one", "B-X")], &["key `one`"] ; "a non numeric id")]
    #[test_case(&[("0", "B-X"), ("1", "I-X")], &["0 labels", "`O`"] ; "no o label")]
    #[test_case(&[("0", "O"), ("1", "O")], &["2 labels", "`O`"] ; "two o labels")]
    #[test_case(&[("0", "O"), ("1", "B-")], &["`B-`"] ; "a prefix without a type")]
    fn bad_labels_are_refused(id2label: &[(&str, &str)], named: &[&str]) {
        let msg = labels(id2label).unwrap_err();
        assert!(named.iter().all(|p| msg.contains(p)), "got: {msg}");
    }

    #[test_case(serde_json::json!({ "label2id": { "O": 0 } }) ; "no id2label")]
    #[test_case(serde_json::json!({ "id2label": ["O"] }) ; "id2label not an object")]
    fn a_config_without_an_id2label_object_is_refused(json: serde_json::Value) {
        assert!(Labels::from_config(&json).unwrap_err().contains("id2label"));
    }

    #[test]
    fn a_label_that_is_not_a_string_is_refused() {
        let json = serde_json::json!({ "id2label": { "0": "O", "1": 7 } });
        assert!(Labels::from_config(&json).unwrap_err().contains("ID 1"));
    }

    fn read_error(contents: &str) -> (std::path::PathBuf, LoadError) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, contents).unwrap();
        let err = Labels::read(&path).unwrap_err();
        (path, err)
    }

    #[test_case("{ not json", true ; "not json")]
    #[test_case(r#"{ "label2id": {} }"#, false ; "no id2label")]
    #[test_case(r#"{ "id2label": { "0": "O", "1": "B-X", "3": "I-X" } }"#, false ; "a gap in the ids")]
    #[test_case(r#"{ "id2label": { "0": "B-X", "1": "I-X" } }"#, false ; "no o label")]
    fn a_bad_config_names_its_path(contents: &str, unreadable: bool) {
        let (path, err) = read_error(contents);
        assert_eq!(
            matches!(err, LoadError::ConfigUnreadable { .. }),
            unreadable,
            "got: {err}"
        );
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "got: {err}"
        );
    }

    #[test]
    fn a_missing_config_names_its_path() {
        let path = Path::new("/nonexistent/config.json");
        let err = Labels::read(path).unwrap_err();
        assert!(matches!(err, LoadError::ConfigUnreadable { .. }));
        assert!(err.to_string().contains("/nonexistent/config.json"));
    }

    #[test]
    fn pooling_sums_each_types_labels() {
        // O, B-A, I-A, B-B: the softmax of [0, ln 2, ln 3, ln 4] is [1, 2, 3, 4] / 10.
        let labels = labels(&[("0", "O"), ("1", "B-A"), ("2", "I-A"), ("3", "B-B")]).unwrap();
        let logits = [0.0, 2f32.ln(), 3f32.ln(), 4f32.ln()];
        let mut pooled = vec![0.0; labels.slots()];
        let start = labels.pool(&logits, &mut pooled);
        let expected = [0.5, 0.4, 0.1]; // A, B, O
        for (got, want) in pooled.iter().zip(expected) {
            assert!((got - want).abs() < 1e-6, "{pooled:?}");
        }
        assert!((start - 0.6).abs() < 1e-6, "start {start}");
    }

    #[test]
    fn pooling_adds_to_what_is_there() {
        let labels = labels(&[("0", "O"), ("1", "B-A")]).unwrap();
        let mut pooled = vec![1.0, 1.0];
        labels.pool(&[0.0, 0.0], &mut pooled);
        assert_eq!(pooled, [1.5, 1.5]);
    }

    #[test]
    fn pooling_large_logits_stays_finite() {
        let labels = labels(&[("0", "O"), ("1", "B-A")]).unwrap();
        let mut pooled = vec![0.0; 2];
        let start = labels.pool(&[1e30, -1e30], &mut pooled);
        assert_eq!(pooled, [0.0, 1.0]);
        assert_eq!(start, 0.0);
    }
}
