//! The checks a model passes before its load returns.
//!
//! ONNX Runtime reports names, element types, and shapes, with `-1` for a
//! dynamic dimension. It does not report what the classes mean, so class order
//! stays with the docs and the parity harness.

use ort::value::{Outlet, Shape, TensorElementType, ValueType};
use tokenizers::Tokenizer;

use crate::load::LoadError;

/// The inputs every adapter feeds.
const REQUIRED_INPUTS: [&str; 2] = ["input_ids", "attention_mask"];
/// Accepted when the model has it, and fed with zeros.
const TOKEN_TYPE_IDS: &str = "token_type_ids";

/// The text the smoke inference encodes. Short and ASCII, so any tokenizer
/// turns it into a few tokens.
const SMOKE_TEXT: &str = "voidwall smoke test";

/// How a model's inputs are fed, as its load found them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InputLayout {
    pub token_type_ids: bool,
    /// The sequence length every input is fixed at, if the model fixes one.
    pub fixed_seq: Option<usize>,
}

/// Checks the inputs, and that a fixed sequence dimension equals `max_tokens`.
pub(crate) fn check_inputs(inputs: &[Outlet], max_tokens: usize) -> Result<InputLayout, LoadError> {
    for required in REQUIRED_INPUTS {
        if !inputs.iter().any(|i| i.name() == required) {
            return Err(LoadError::MissingInput(required));
        }
    }
    if let Some(unknown) = inputs
        .iter()
        .find(|i| !REQUIRED_INPUTS.contains(&i.name()) && i.name() != TOKEN_TYPE_IDS)
    {
        return Err(LoadError::UnknownInput(unknown.name().to_owned()));
    }

    let mut fixed_seq = None;
    for input in inputs {
        let name = input.name().to_owned();
        let (ty, shape) = tensor(input.dtype()).ok_or_else(|| LoadError::InputType {
            name: name.clone(),
            found: "a non-tensor value".into(),
        })?;
        if ty != TensorElementType::Int64 {
            return Err(LoadError::InputType {
                name,
                found: ty.to_string(),
            });
        }
        if shape.len() != 2 {
            return Err(LoadError::InputRank {
                name,
                rank: shape.len(),
            });
        }
        if input.name() == REQUIRED_INPUTS[0] {
            fixed_seq = usize::try_from(shape[1]).ok();
        }
    }

    if let Some(fixed) = fixed_seq
        && fixed != max_tokens
    {
        return Err(LoadError::FixedSequence { fixed, max_tokens });
    }
    Ok(InputLayout {
        token_type_ids: inputs.iter().any(|i| i.name() == TOKEN_TYPE_IDS),
        fixed_seq,
    })
}

/// Checks that the model has one `Float32` output of rank `rank` whose last
/// dimension is `width`: `[_, width]` or `[_, _, width]`.
pub(crate) fn check_output(outputs: &[Outlet], rank: usize, width: i64) -> Result<(), LoadError> {
    let [output] = outputs else {
        return Err(LoadError::OutputCount(outputs.len()));
    };
    let (ty, shape) =
        tensor(output.dtype()).ok_or_else(|| LoadError::OutputType("a non-tensor value".into()))?;
    if ty != TensorElementType::Float32 {
        return Err(LoadError::OutputType(ty.to_string()));
    }
    if shape.len() != rank {
        return Err(LoadError::OutputRank {
            found: shape.len(),
            expected: rank,
        });
    }
    if shape[rank - 1] != width {
        return Err(LoadError::OutputWidth {
            expected: width,
            found: shape[rank - 1],
        });
    }
    Ok(())
}

/// Checks that every ID the tokenizer can produce has a row in the embedding table.
pub(crate) fn check_tokenizer(tokenizer: &Tokenizer, rows: i64) -> Result<(), LoadError> {
    // The highest ID, not the vocabulary size: added tokens can leave gaps.
    let highest_id = tokenizer.get_vocab(true).into_values().max().unwrap_or(0);
    if i64::from(highest_id) >= rows {
        return Err(LoadError::TokenizerTooLarge { highest_id, rows });
    }
    Ok(())
}

/// Token IDs for the smoke inference, cut to a fixed sequence length when the
/// model has one. The run pads them as it pads any window.
pub(crate) fn smoke_input(
    tokenizer: &Tokenizer,
    fixed_seq: Option<usize>,
) -> Result<Vec<i64>, LoadError> {
    let encoding = tokenizer
        .encode(SMOKE_TEXT, true)
        .map_err(|e| LoadError::SmokeInference(format!("the tokenizer failed: {e}")))?;
    let mut ids: Vec<i64> = encoding.get_ids().iter().map(|&id| i64::from(id)).collect();
    if let Some(n) = fixed_seq {
        ids.truncate(n);
    }
    Ok(ids)
}

fn tensor(ty: &ValueType) -> Option<(TensorElementType, &Shape)> {
    match ty {
        ValueType::Tensor { ty, shape, .. } => Some((*ty, shape)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Fixture, ROWS, write_tokenizer};
    use crate::onnx_proto::tensor_proto::DataType;
    use ort::session::Session;
    use test_case::test_case;

    /// A fixture as ONNX Runtime loads it, for its inputs and outputs.
    fn session(fixture: &Fixture) -> Session {
        let dir = tempfile::tempdir().unwrap();
        Session::builder()
            .unwrap()
            .commit_from_file(fixture.write(dir.path()))
            .unwrap()
    }

    fn inputs_error(fixture: Fixture, max_tokens: usize) -> String {
        check_inputs(session(&fixture).inputs(), max_tokens)
            .unwrap_err()
            .to_string()
    }

    #[test_case(Fixture { attention_mask: false, ..Fixture::default() }, &["attention_mask"] ; "missing attention mask")]
    #[test_case(Fixture { extra_input: Some("position_ids"), ..Fixture::default() }, &["position_ids"] ; "unknown input")]
    #[test_case(Fixture { input_ids_type: DataType::Int32, ..Fixture::default() }, &["input_ids", "i32"] ; "wrong element type")]
    #[test_case(Fixture { input_ids_rank_one: true, ..Fixture::default() }, &["input_ids", "rank 1"] ; "wrong rank")]
    fn a_bad_input_is_rejected(fixture: Fixture, named: &[&str]) {
        let msg = inputs_error(fixture, 512);
        for part in named {
            assert!(msg.contains(part), "`{part}` missing from: {msg}");
        }
    }

    #[test]
    fn token_type_ids_are_accepted() {
        let fixture = Fixture {
            token_type_ids: true,
            ..Fixture::default()
        };
        let layout = check_inputs(session(&fixture).inputs(), 512).unwrap();
        assert_eq!(
            layout,
            InputLayout {
                token_type_ids: true,
                fixed_seq: None
            }
        );
    }

    #[test_case(None, 32, Ok(None) ; "dynamic accepts any max_tokens")]
    #[test_case(Some(16), 16, Ok(Some(16)) ; "fixed equal to max_tokens")]
    #[test_case(Some(16), 32, Err(&["16", "32"]) ; "fixed differs from max_tokens")]
    fn the_sequence_dimension_is_checked(
        fixed: Option<i64>,
        max_tokens: usize,
        expected: Result<Option<usize>, &[&str]>,
    ) {
        let fixture = Fixture {
            fixed_seq: fixed,
            ..Fixture::default()
        };
        let result = check_inputs(session(&fixture).inputs(), max_tokens);
        match (result, expected) {
            (Ok(layout), Ok(seq)) => assert_eq!(layout.fixed_seq, seq),
            (Err(err), Err(named)) => {
                assert!(matches!(err, LoadError::FixedSequence { .. }));
                let msg = err.to_string();
                assert!(named.iter().all(|p| msg.contains(p)), "got: {msg}");
            }
            (result, _) => panic!("unexpected: {result:?}"),
        }
    }

    #[test_case(Fixture::default(), None ; "good output")]
    #[test_case(Fixture { second_output: true, ..Fixture::default() }, Some(&["2 outputs"][..]) ; "two outputs")]
    #[test_case(Fixture { width: 3, ..Fixture::default() }, Some(&["width 2", "3"][..]) ; "wrong width")]
    #[test_case(Fixture { float16_output: true, ..Fixture::default() }, Some(&["f16"][..]) ; "half precision")]
    fn the_output_is_checked(fixture: Fixture, named: Option<&[&str]>) {
        let result = check_output(session(&fixture).outputs(), 2, 2);
        match named {
            None => result.unwrap(),
            Some(parts) => {
                let msg = result.unwrap_err().to_string();
                assert!(parts.iter().all(|p| msg.contains(p)), "got: {msg}");
            }
        }
    }

    #[test_case(ROWS as u32 - 1, None ; "highest ID below the rows")]
    #[test_case(ROWS as u32, Some(&["16", "16"][..]) ; "highest ID equal to the rows")]
    #[test_case(40, Some(&["40", "16"][..]) ; "highest ID above the rows")]
    fn the_tokenizer_must_fit_the_embedding_table(highest_id: u32, named: Option<&[&str]>) {
        let dir = tempfile::tempdir().unwrap();
        let tokenizer = Tokenizer::from_file(write_tokenizer(dir.path(), highest_id)).unwrap();
        let result = check_tokenizer(&tokenizer, ROWS);
        match named {
            None => result.unwrap(),
            Some(parts) => {
                let msg = result.unwrap_err().to_string();
                assert!(parts.iter().all(|p| msg.contains(p)), "got: {msg}");
            }
        }
    }

    #[test]
    fn the_smoke_input_is_cut_to_a_fixed_length() {
        let dir = tempfile::tempdir().unwrap();
        let tokenizer = Tokenizer::from_file(write_tokenizer(dir.path(), 4)).unwrap();
        assert_eq!(smoke_input(&tokenizer, None).unwrap(), vec![1, 2, 3]);
        assert_eq!(smoke_input(&tokenizer, Some(5)).unwrap(), vec![1, 2, 3]);
        assert_eq!(smoke_input(&tokenizer, Some(2)).unwrap(), vec![1, 2]);
    }
}
