//! Tiny ONNX models and tokenizers, built in code for the load tests.
//!
//! The good model is a bag-of-embeddings classifier:
//!
//! ```text
//! input_ids [batch, seq] ─► Gather(embedding [ROWS, HIDDEN]) ─► × mask ─► ReduceSum(seq)
//!                                                                       │
//!                         logits [batch, width] ◄─ Add(bias) ◄─ MatMul(weight [HIDDEN, width])
//! ```
//!
//! Each field of [`Fixture`] bends one part of it into a bad case, or, for
//! [`Fixture::slow`], makes a run take longer. [`Fixture::tokens`] drops the
//! `ReduceSum`, so the model is a token classifier with logits
//! `[batch, seq, width]`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use prost::Message;
use tokenizers::models::wordlevel::WordLevel;
use tokenizers::pre_tokenizers::whitespace::Whitespace;
use tokenizers::processors::template::TemplateProcessing;
use tokenizers::{PaddingParams, Tokenizer, TruncationParams};

use crate::onnx_proto::{
    AttributeProto, GraphProto, ModelProto, NodeProto, OperatorSetIdProto, TensorProto,
    TensorShapeProto, TypeProto, ValueInfoProto, tensor_proto, tensor_shape_proto, type_proto,
};

/// Rows of the fixture's embedding table.
pub const ROWS: i64 = 16;
const HIDDEN: i64 = 32;
/// The width of [`Fixture::slow`]'s chain.
const SLOW_WIDTH: i64 = 2048;

/// The token that [`Fixture::trigger`] makes score high, and its ID.
pub const TRIGGER: &str = "trigger";
pub const TRIGGER_ID: u32 = 8;
const CLS_ID: u32 = 9;
const SEP_ID: u32 = 10;
/// The pad ID of a tokenizer written with [`TokenizerFixture::truncate_and_pad`].
pub const PAD_ID: u32 = 11;

/// One fixture model. `Fixture::default()` passes every load check.
#[derive(Clone)]
pub struct Fixture {
    /// Rows of the embedding table.
    pub rows: i64,
    pub attention_mask: bool,
    pub token_type_ids: bool,
    /// An extra input the contract does not allow.
    pub extra_input: Option<&'static str>,
    pub input_ids_type: tensor_proto::DataType,
    pub input_ids_rank_one: bool,
    /// A fixed sequence dimension in place of `seq`.
    pub fixed_seq: Option<i64>,
    pub width: i64,
    pub second_output: bool,
    pub float16_output: bool,
    /// `input_ids` is cast before the `Gather`, so the embedding search misses it.
    pub cast_before_gather: bool,
    /// The bias is NaN, so every logit is NaN.
    pub nan_bias: bool,
    /// A reshape that the load accepts and the first run rejects.
    pub fails_at_run: bool,
    /// Every token but [`TRIGGER_ID`] gives logits `[0.5, -0.5]` (score 0.27);
    /// each [`TRIGGER_ID`] adds `[-10, 10]`, so a window holding it scores 1.0.
    pub trigger: bool,
    /// The embedding row of this token ID is NaN, so only a unit holding it
    /// gives NaN logits; the smoke input does not.
    pub nan_row: Option<u32>,
    /// The attention mask is reshaped to `[1, n]`, so a run fails on any
    /// sequence length but `n`. The plain tokenizer's smoke input has 3 tokens.
    pub mask_reshaped_to: Option<i64>,
    /// A 1 KiB weight of zeros whose only consumer is a `ReduceSum`, added to
    /// the logits: ONNX Runtime constant-folds it at load, from the graph.
    pub folded_weight: bool,
    /// Logits for every token, `[batch, seq, width]`: no `ReduceSum`. With
    /// [`Fixture::trigger`], every token but [`TRIGGER_ID`] gives logits
    /// `[2, 0, …]`, which label 0 wins, and [`TRIGGER_ID`] gives
    /// `[-8, 10, 0, …]`, which label 1 wins.
    pub tokens: bool,
    /// The output keeps at most this many tokens, so a longer window returns
    /// too few rows.
    pub max_output_tokens: Option<i64>,
    /// A chain of this many `MatMul` nodes over the masked embeddings, widened
    /// to [`SLOW_WIDTH`] and multiplied by an identity, summed, times 0, and
    /// added to the logits. Scores do not change; a run takes longer with each
    /// node, so a test can cancel a run in progress.
    pub slow: Option<usize>,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            rows: ROWS,
            attention_mask: true,
            token_type_ids: false,
            extra_input: None,
            input_ids_type: tensor_proto::DataType::Int64,
            input_ids_rank_one: false,
            fixed_seq: None,
            width: 2,
            second_output: false,
            float16_output: false,
            cast_before_gather: false,
            nan_bias: false,
            fails_at_run: false,
            trigger: false,
            nan_row: None,
            mask_reshaped_to: None,
            folded_weight: false,
            tokens: false,
            max_output_tokens: None,
            slow: None,
        }
    }
}

impl Fixture {
    pub fn model(&self) -> ModelProto {
        let seq = match self.fixed_seq {
            Some(n) => Dim::Fixed(n),
            None => Dim::Named("seq"),
        };
        let int64 = tensor_proto::DataType::Int64;

        let mut inputs = vec![if self.input_ids_rank_one {
            value_info("input_ids", self.input_ids_type, &[seq])
        } else {
            value_info(
                "input_ids",
                self.input_ids_type,
                &[Dim::Named("batch"), seq],
            )
        }];
        if self.attention_mask {
            inputs.push(value_info(
                "attention_mask",
                int64,
                &[Dim::Named("batch"), seq],
            ));
        }
        if self.token_type_ids {
            inputs.push(value_info(
                "token_type_ids",
                int64,
                &[Dim::Named("batch"), seq],
            ));
        }
        if let Some(name) = self.extra_input {
            inputs.push(value_info(name, int64, &[Dim::Named("batch"), seq]));
        }

        let mut nodes = Vec::new();
        let ids = if self.cast_before_gather {
            nodes.push(node(
                "Cast",
                &["input_ids"],
                &["ids_cast"],
                vec![int_attr("to", 6)],
            ));
            "ids_cast"
        } else {
            "input_ids"
        };
        nodes.push(node("Gather", &["embedding", ids], &["embedded"], vec![]));
        let masked = if self.attention_mask {
            nodes.push(node(
                "Cast",
                &["attention_mask"],
                &["mask_f"],
                vec![int_attr("to", 1)],
            ));
            let mask_f = if self.mask_reshaped_to.is_some() {
                nodes.push(node(
                    "Reshape",
                    &["mask_f", "mask_shape"],
                    &["mask_fixed"],
                    vec![],
                ));
                "mask_fixed"
            } else {
                "mask_f"
            };
            nodes.push(node(
                "Unsqueeze",
                &[mask_f, "last_axis"],
                &["mask_3d"],
                vec![],
            ));
            nodes.push(node("Mul", &["embedded", "mask_3d"], &["masked"], vec![]));
            "masked"
        } else {
            "embedded"
        };
        let mut pooled = if self.tokens { masked } else { "pooled" };
        if !self.tokens {
            nodes.push(node(
                "ReduceSum",
                &[masked, "seq_axis"],
                &[pooled],
                vec![int_attr("keepdims", 0)],
            ));
        }
        if self.fails_at_run {
            // [batch, HIDDEN] cannot become [-1, 3]; the symbolic batch hides that at load.
            nodes.push(node("Reshape", &[pooled, "shape_by_3"], &["by_3"], vec![]));
            nodes.push(node(
                "Reshape",
                &["by_3", "shape_back"],
                &["reshaped_back"],
                vec![],
            ));
            pooled = "reshaped_back";
        }
        nodes.push(node("MatMul", &[pooled, "weight"], &["projected"], vec![]));
        // The name of the logits before an optional final `Slice`.
        let out = if self.max_output_tokens.is_some() {
            "unsliced"
        } else {
            "logits"
        };
        let logits = if self.float16_output {
            "logits_f32"
        } else {
            out
        };
        let (head, logits) = match self.slow {
            Some(_) => ("unslowed", logits),
            None => (logits, logits),
        };
        if self.folded_weight {
            nodes.push(node("Add", &["projected", "bias"], &["biased"], vec![]));
            nodes.push(node(
                "ReduceSum",
                &["fold_table"],
                &["folded"],
                vec![int_attr("keepdims", 0)],
            ));
            nodes.push(node("Add", &["biased", "folded"], &[head], vec![]));
        } else {
            nodes.push(node("Add", &["projected", "bias"], &[head], vec![]));
        }
        if let Some(chain) = self.slow {
            nodes.push(node("MatMul", &[masked, "slow_widen"], &["slow_0"], vec![]));
            for i in 0..chain {
                let (from, to) = (format!("slow_{i}"), format!("slow_{}", i + 1));
                nodes.push(node("MatMul", &[&from, "slow_identity"], &[&to], vec![]));
            }
            nodes.push(node(
                "ReduceSum",
                &[&format!("slow_{chain}")],
                &["slow_sum"],
                vec![int_attr("keepdims", 0)],
            ));
            nodes.push(node(
                "Mul",
                &["slow_sum", "slow_zero"],
                &["slow_term"],
                vec![],
            ));
            nodes.push(node("Add", &[head, "slow_term"], &[logits], vec![]));
        }
        if self.float16_output {
            nodes.push(node(
                "Cast",
                &["logits_f32"],
                &[out],
                vec![int_attr("to", 10)],
            ));
        }
        if self.max_output_tokens.is_some() {
            nodes.push(node(
                "Slice",
                &[out, "slice_start", "slice_end", "seq_axis"],
                &["logits"],
                vec![],
            ));
        }

        let out_type = if self.float16_output {
            tensor_proto::DataType::Float16
        } else {
            tensor_proto::DataType::Float
        };
        let out_dims = if self.tokens {
            let out_seq = match self.max_output_tokens {
                Some(_) => Dim::Named("kept"),
                None => seq,
            };
            vec![Dim::Named("batch"), out_seq, Dim::Fixed(self.width)]
        } else {
            vec![Dim::Named("batch"), Dim::Fixed(self.width)]
        };
        let mut outputs = vec![value_info("logits", out_type, &out_dims)];
        if self.second_output {
            nodes.push(node("Identity", &["logits"], &["logits_copy"], vec![]));
            outputs.push(value_info("logits_copy", out_type, &out_dims));
        }

        let trigger_row = TRIGGER_ID as usize * HIDDEN as usize;
        let nan_row = self.nan_row.map(|id| id as usize * HIDDEN as usize);
        let embedding = |i: usize| match self.trigger {
            _ if nan_row.is_some_and(|row| (row..row + HIDDEN as usize).contains(&i)) => f32::NAN,
            // Only the trigger's row is non-zero, in its first column.
            true if i == trigger_row => 10.0,
            true => 0.0,
            false => (i % 7) as f32 * 0.1,
        };
        let weight = |i: usize| match self.trigger {
            // Only the first hidden column projects: -1 to logit 0, +1 to logit 1.
            true if i == 0 => -1.0,
            true if i == 1 => 1.0,
            true => 0.0,
            false => (i % 5) as f32 * 0.2 - 0.4,
        };
        let bias = |i: usize| match (self.nan_bias, self.trigger) {
            (true, _) => f32::NAN,
            (false, true) if self.tokens => [2.0, 0.0][usize::from(i > 0)],
            (false, true) => [0.5, -0.5][i % 2],
            (false, false) => 0.1,
        };
        let mut initializer = vec![
            float_tensor("embedding", &[self.rows, HIDDEN], embedding),
            float_tensor("weight", &[HIDDEN, self.width], weight),
            float_tensor("bias", &[self.width], bias),
            int64_tensor("last_axis", &[1], &[-1]),
            int64_tensor("seq_axis", &[1], &[1]),
            int64_tensor("shape_by_3", &[2], &[-1, 3]),
            int64_tensor("shape_back", &[2], &[-1, HIDDEN]),
        ];
        if self.folded_weight {
            initializer.push(float_tensor("fold_table", &[256], |_| 0.0));
        }
        if self.slow.is_some() {
            let width = SLOW_WIDTH as usize;
            // Each hidden column goes to the column of the same index, so values stay finite.
            initializer.push(float_tensor("slow_widen", &[HIDDEN, SLOW_WIDTH], |i| {
                f32::from(u8::from(i / width == i % width))
            }));
            initializer.push(float_tensor(
                "slow_identity",
                &[SLOW_WIDTH, SLOW_WIDTH],
                |i| f32::from(u8::from(i / width == i % width)),
            ));
            initializer.push(float_tensor("slow_zero", &[], |_| 0.0));
        }
        if let Some(n) = self.max_output_tokens {
            initializer.push(int64_tensor("slice_start", &[1], &[0]));
            initializer.push(int64_tensor("slice_end", &[1], &[n]));
        }
        if let Some(n) = self.mask_reshaped_to {
            initializer.push(int64_tensor("mask_shape", &[2], &[1, n]));
        }

        ModelProto {
            ir_version: Some(8),
            opset_import: vec![OperatorSetIdProto {
                domain: Some(String::new()),
                version: Some(17),
            }],
            producer_name: Some("voidwall-ml fixtures".into()),
            graph: Some(GraphProto {
                name: Some("fixture".into()),
                node: nodes,
                initializer,
                input: inputs,
                output: outputs,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Writes the model into `dir` and returns its path.
    pub fn write(&self, dir: &Path) -> PathBuf {
        let path = dir.join("model.onnx");
        std::fs::write(&path, self.model().encode_to_vec()).expect("write fixture model");
        path
    }

    /// The names of the model's initializers, in file order.
    pub fn initializer_names(&self) -> Vec<String> {
        self.model()
            .graph
            .expect("fixture has a graph")
            .initializer
            .into_iter()
            .map(|t| t.name.expect("fixture initializers are named"))
            .collect()
    }
}

/// Writes a `config.json` whose `id2label` maps ID `i` to `labels[i]`, and
/// returns its path.
pub fn write_config(dir: &Path, labels: &[&str]) -> PathBuf {
    let id2label: serde_json::Map<String, serde_json::Value> = labels
        .iter()
        .enumerate()
        .map(|(id, label)| (id.to_string(), (*label).into()))
        .collect();
    let path = dir.join("config.json");
    let json = serde_json::json!({ "id2label": id2label });
    std::fs::write(&path, json.to_string()).expect("write fixture config");
    path
}

/// Writes a word-level tokenizer whose highest ID is `highest_id` and returns its path.
pub fn write_tokenizer(dir: &Path, highest_id: u32) -> PathBuf {
    TokenizerFixture {
        highest_id,
        ..TokenizerFixture::default()
    }
    .write(dir)
}

/// One word-level fixture tokenizer: `[UNK]` 0, `voidwall` 1, `smoke` 2,
/// `test` 3, [`TRIGGER`] 8, `[CLS]` 9, `[SEP]` 10, `[PAD]` 11, and `highest`.
pub struct TokenizerFixture {
    /// The ID of the token `highest`.
    pub highest_id: u32,
    /// A `[CLS] $A [SEP]` post-processor, so each sequence gets 2 special tokens.
    pub special_tokens: bool,
    /// The file sets truncation at 2 tokens and padding with [`PAD_ID`].
    pub truncate_and_pad: bool,
}

impl Default for TokenizerFixture {
    fn default() -> Self {
        Self {
            highest_id: ROWS as u32 - 1,
            special_tokens: false,
            truncate_and_pad: false,
        }
    }
}

impl TokenizerFixture {
    /// Writes the tokenizer into `dir` and returns its path.
    pub fn write(&self, dir: &Path) -> PathBuf {
        let mut vocab: HashMap<String, u32> = ["[UNK]", "voidwall", "smoke", "test"]
            .iter()
            .enumerate()
            .map(|(i, t)| (t.to_string(), i as u32))
            .collect();
        vocab.extend([
            (TRIGGER.to_owned(), TRIGGER_ID),
            ("[CLS]".to_owned(), CLS_ID),
            ("[SEP]".to_owned(), SEP_ID),
            ("[PAD]".to_owned(), PAD_ID),
        ]);
        vocab.insert("highest".into(), self.highest_id);
        let model = WordLevel::builder()
            .vocab(vocab.into_iter().collect())
            .unk_token("[UNK]".into())
            .build()
            .expect("build word-level model");
        let mut tokenizer = Tokenizer::new(model);
        tokenizer.with_pre_tokenizer(Some(Whitespace {}));
        if self.special_tokens {
            let template = TemplateProcessing::builder()
                .try_single("[CLS] $A [SEP]")
                .expect("single template")
                .special_tokens(vec![("[CLS]", CLS_ID), ("[SEP]", SEP_ID)])
                .build()
                .expect("build template");
            tokenizer.with_post_processor(Some(template));
        }
        if self.truncate_and_pad {
            tokenizer
                .with_truncation(Some(TruncationParams {
                    max_length: 2,
                    ..TruncationParams::default()
                }))
                .expect("set truncation");
            tokenizer.with_padding(Some(PaddingParams {
                pad_id: PAD_ID,
                pad_token: "[PAD]".into(),
                ..PaddingParams::default()
            }));
        }
        let path = dir.join("tokenizer.json");
        tokenizer
            .save(&path, false)
            .expect("write fixture tokenizer");
        path
    }
}

#[derive(Clone, Copy)]
enum Dim {
    Named(&'static str),
    Fixed(i64),
}

fn value_info(name: &str, ty: tensor_proto::DataType, dims: &[Dim]) -> ValueInfoProto {
    let dim = dims
        .iter()
        .map(|d| tensor_shape_proto::Dimension {
            value: Some(match *d {
                Dim::Named(s) => tensor_shape_proto::dimension::Value::DimParam(s.into()),
                Dim::Fixed(n) => tensor_shape_proto::dimension::Value::DimValue(n),
            }),
            ..Default::default()
        })
        .collect();
    ValueInfoProto {
        name: Some(name.into()),
        r#type: Some(TypeProto {
            value: Some(type_proto::Value::TensorType(type_proto::Tensor {
                elem_type: Some(ty as i32),
                shape: Some(TensorShapeProto { dim }),
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn node(op: &str, inputs: &[&str], outputs: &[&str], attribute: Vec<AttributeProto>) -> NodeProto {
    NodeProto {
        op_type: Some(op.into()),
        input: inputs.iter().map(|s| s.to_string()).collect(),
        output: outputs.iter().map(|s| s.to_string()).collect(),
        attribute,
        ..Default::default()
    }
}

fn int_attr(name: &str, value: i64) -> AttributeProto {
    AttributeProto {
        name: Some(name.into()),
        r#type: Some(crate::onnx_proto::attribute_proto::AttributeType::Int as i32),
        i: Some(value),
        ..Default::default()
    }
}

fn float_tensor(name: &str, dims: &[i64], value: impl Fn(usize) -> f32) -> TensorProto {
    let count = dims.iter().product::<i64>() as usize;
    TensorProto {
        name: Some(name.into()),
        dims: dims.to_vec(),
        data_type: Some(tensor_proto::DataType::Float as i32),
        raw_data: Some(
            (0..count)
                .flat_map(|i| value(i).to_le_bytes())
                .collect::<Vec<u8>>()
                .into(),
        ),
        ..Default::default()
    }
}

fn int64_tensor(name: &str, dims: &[i64], values: &[i64]) -> TensorProto {
    TensorProto {
        name: Some(name.into()),
        dims: dims.to_vec(),
        data_type: Some(tensor_proto::DataType::Int64 as i32),
        int64_data: values.to_vec(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::AdapterKind;
    use crate::load::{LoadSettings, Worker, load};
    use crate::run::uncancelled;
    use ort::session::Session;
    use ort::value::Tensor;
    use std::num::NonZeroUsize;
    use std::time::Instant;
    use test_case::test_case;
    use tokenizers::PostProcessor;

    #[test]
    fn the_good_fixture_runs_in_plain_ort() {
        let dir = tempfile::tempdir().unwrap();
        let path = Fixture::default().write(dir.path());
        let mut session = Session::builder().unwrap().commit_from_file(&path).unwrap();
        let ids = Tensor::from_array(([1usize, 3], vec![1i64, 2, 3])).unwrap();
        let mask = Tensor::from_array(([1usize, 3], vec![1i64, 1, 1])).unwrap();
        let outputs = session
            .run(ort::inputs!["input_ids" => ids, "attention_mask" => mask])
            .unwrap();
        let (shape, logits) = outputs["logits"].try_extract_tensor::<f32>().unwrap();
        assert_eq!(&**shape, &[1, 2]);
        assert!(logits.iter().all(|v| v.is_finite()));
    }

    #[test_case(false, 0 ; "no post-processor")]
    #[test_case(true, 2 ; "cls and sep")]
    fn the_tokenizer_adds_its_special_tokens(special_tokens: bool, added: usize) {
        let dir = tempfile::tempdir().unwrap();
        let path = TokenizerFixture {
            special_tokens,
            ..TokenizerFixture::default()
        }
        .write(dir.path());
        let tokenizer = Tokenizer::from_file(path).unwrap();
        let count = tokenizer
            .get_post_processor()
            .map_or(0, |p| p.added_tokens(false));
        assert_eq!(count, added);
    }

    #[test]
    fn the_trigger_token_scores_high() {
        let dir = tempfile::tempdir().unwrap();
        let path = Fixture {
            trigger: true,
            ..Fixture::default()
        }
        .write(dir.path());
        let mut session = Session::builder().unwrap().commit_from_file(&path).unwrap();
        let mut score = |ids: Vec<i64>| {
            let shape = [1usize, ids.len()];
            let mask = Tensor::from_array((shape, vec![1i64; ids.len()])).unwrap();
            let ids = Tensor::from_array((shape, ids)).unwrap();
            let outputs = session
                .run(ort::inputs!["input_ids" => ids, "attention_mask" => mask])
                .unwrap();
            let (_, l) = outputs["logits"].try_extract_tensor::<f32>().unwrap();
            1.0 / (1.0 + (l[0] - l[1]).exp())
        };
        assert!(score(vec![1, i64::from(TRIGGER_ID), 3]) > 0.9);
        assert!(score(vec![1, 2, 3]) < 0.5);
    }

    fn worker(model: Fixture) -> Worker {
        let dir = tempfile::tempdir().unwrap();
        let settings = LoadSettings {
            adapter: AdapterKind::TextClassifier,
            model_path: model.write(dir.path()),
            tokenizer_path: TokenizerFixture::default().write(dir.path()),
            config_path: None,
            max_tokens: 16,
            overlap_tokens: None,
            max_body_size: NonZeroUsize::new(1 << 20).unwrap(),
            workers: NonZeroUsize::MIN,
        };
        load(&settings).unwrap().into_classifiers().pop().unwrap()
    }

    /// Same score as the model without the chain, and a run that takes longer.
    #[test]
    fn the_slow_chain_changes_the_time_and_not_the_score() {
        let text = "voidwall smoke test trigger ".repeat(3);
        let base = Fixture {
            trigger: true,
            ..Fixture::default()
        };
        let mut fast = worker(base.clone());
        let mut slow = worker(Fixture {
            slow: Some(200),
            ..base
        });

        let started = Instant::now();
        let fast_score = fast.score(&text, &uncancelled()).unwrap();
        let fast_time = started.elapsed();
        let started = Instant::now();
        let slow_score = slow.score(&text, &uncancelled()).unwrap();
        let slow_time = started.elapsed();

        assert_eq!(slow_score, fast_score);
        assert!(
            slow_time >= 4 * fast_time,
            "slow {slow_time:?} vs fast {fast_time:?}"
        );
    }
}
