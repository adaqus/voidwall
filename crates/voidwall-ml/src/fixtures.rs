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
//! Each field of [`Fixture`] bends one part of it into a bad case.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use prost::Message;
use tokenizers::Tokenizer;
use tokenizers::models::wordlevel::WordLevel;
use tokenizers::pre_tokenizers::whitespace::Whitespace;

use crate::onnx_proto::{
    AttributeProto, GraphProto, ModelProto, NodeProto, OperatorSetIdProto, TensorProto,
    TensorShapeProto, TypeProto, ValueInfoProto, tensor_proto, tensor_shape_proto, type_proto,
};

/// Rows of the fixture's embedding table.
pub const ROWS: i64 = 16;
const HIDDEN: i64 = 32;

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
            nodes.push(node(
                "Unsqueeze",
                &["mask_f", "last_axis"],
                &["mask_3d"],
                vec![],
            ));
            nodes.push(node("Mul", &["embedded", "mask_3d"], &["masked"], vec![]));
            "masked"
        } else {
            "embedded"
        };
        let mut pooled = "pooled";
        nodes.push(node(
            "ReduceSum",
            &[masked, "seq_axis"],
            &[pooled],
            vec![int_attr("keepdims", 0)],
        ));
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
        let logits = if self.float16_output {
            "logits_f32"
        } else {
            "logits"
        };
        nodes.push(node("Add", &["projected", "bias"], &[logits], vec![]));
        if self.float16_output {
            nodes.push(node(
                "Cast",
                &["logits_f32"],
                &["logits"],
                vec![int_attr("to", 10)],
            ));
        }

        let out_type = if self.float16_output {
            tensor_proto::DataType::Float16
        } else {
            tensor_proto::DataType::Float
        };
        let mut outputs = vec![value_info(
            "logits",
            out_type,
            &[Dim::Named("batch"), Dim::Fixed(self.width)],
        )];
        if self.second_output {
            nodes.push(node("Identity", &["logits"], &["logits_copy"], vec![]));
            outputs.push(value_info(
                "logits_copy",
                out_type,
                &[Dim::Named("batch"), Dim::Fixed(self.width)],
            ));
        }

        let bias = if self.nan_bias { f32::NAN } else { 0.1 };
        let initializer = vec![
            float_tensor("embedding", &[self.rows, HIDDEN], |i| (i % 7) as f32 * 0.1),
            float_tensor("weight", &[HIDDEN, self.width], |i| {
                (i % 5) as f32 * 0.2 - 0.4
            }),
            float_tensor("bias", &[self.width], |_| bias),
            int64_tensor("last_axis", &[1], &[-1]),
            int64_tensor("seq_axis", &[1], &[1]),
            int64_tensor("shape_by_3", &[2], &[-1, 3]),
            int64_tensor("shape_back", &[2], &[-1, HIDDEN]),
        ];

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

/// Writes a word-level tokenizer whose highest ID is `highest_id` and returns its path.
pub fn write_tokenizer(dir: &Path, highest_id: u32) -> PathBuf {
    let mut vocab: HashMap<String, u32> = ["[UNK]", "voidwall", "smoke", "test"]
        .iter()
        .enumerate()
        .map(|(i, t)| (t.to_string(), i as u32))
        .collect();
    vocab.insert("highest".into(), highest_id);
    let model = WordLevel::builder()
        .vocab(vocab.into_iter().collect())
        .unk_token("[UNK]".into())
        .build()
        .expect("build word-level model");
    let mut tokenizer = Tokenizer::new(model);
    tokenizer.with_pre_tokenizer(Some(Whitespace {}));
    let path = dir.join("tokenizer.json");
    tokenizer
        .save(&path, false)
        .expect("write fixture tokenizer");
    path
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
    use ort::session::Session;
    use ort::value::Tensor;

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
}
