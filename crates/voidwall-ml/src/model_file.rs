//! The one read of a model file.
//!
//! Every session of a load runs on the weights decoded here (B2). The file is
//! memory-mapped and decoded without copying its weight bytes; each
//! initializer is copied once into a tensor that all sessions share. ONNX
//! Runtime parses a copy of the graph whose large initializers carry no data,
//! so creating a session never copies the weights again.
//!
//! That graph names its stripped weights as external data in a placeholder
//! file. ONNX Runtime resolves the placeholder next to the graph file and
//! requires it to exist, but takes every value from the overrides, so the
//! graph and an empty placeholder are staged in a private temp directory for
//! the length of the load.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use half::{bf16, f16};
use memmap2::Mmap;
use ort::value::{DynValue, PrimitiveTensorElementType, Tensor};
use prost::Message;

use crate::load::LoadError;
use crate::onnx_proto::{ModelProto, StringStringEntryProto, TensorProto, tensor_proto};

/// Initializers at least this large leave the graph ONNX Runtime parses. This
/// is the `size_threshold` default of ONNX's own external-data conversion.
/// Smaller ones stay inline: shape inference needs the values of small
/// constants such as axes and reshape shapes.
const STRIP_THRESHOLD: usize = 1024;

/// The external-data location a stripped initializer names: an empty
/// placeholder. A stripped initializer without its override therefore fails
/// the session instead of loading data from somewhere.
const STRIPPED_LOCATION: &str = "voidwall-shared-weights";
/// The staged graph's file name.
const GRAPH_FILE: &str = "model.onnx";

/// One initializer, decoded once and shared by every session.
pub(crate) struct SharedWeight {
    pub name: String,
    pub value: Arc<DynValue>,
}

/// The weight-free graph and its placeholder on disk. Dropping it removes both.
pub(crate) struct StagedGraph {
    dir: tempfile::TempDir,
}

impl StagedGraph {
    /// The graph file every session loads.
    pub fn path(&self) -> PathBuf {
        self.dir.path().join(GRAPH_FILE)
    }
}

/// What a load needs from the model file.
pub(crate) struct ModelFile {
    /// The graph every session parses: the model with its large initializers'
    /// data removed.
    pub graph_bytes: Vec<u8>,
    /// Every initializer of the main graph, decoded once.
    pub initializers: Vec<SharedWeight>,
    /// Rows of the embedding table that `input_ids` feeds.
    pub embedding_rows: i64,
}

impl ModelFile {
    pub fn read(path: &Path) -> Result<Self, LoadError> {
        let unreadable = |reason: String| LoadError::ModelUnreadable {
            path: path.to_owned(),
            reason,
        };
        let file = File::open(path).map_err(|e| unreadable(e.to_string()))?;
        // SAFETY: the map lives only for this read and is never written. A file
        // changed by another process meanwhile gives torn data, not unsoundness
        // in this process's memory; operators mount models read-only.
        let map = unsafe { Mmap::map(&file) }.map_err(|e| unreadable(e.to_string()))?;
        // `raw_data` decodes as slices of the map, so no weight bytes are copied.
        let mut model =
            ModelProto::decode(Bytes::from_owner(map)).map_err(|e| unreadable(e.to_string()))?;
        let graph = model
            .graph
            .as_mut()
            .ok_or_else(|| unreadable("the model has no graph".into()))?;
        if let Some(sparse) = graph.sparse_initializer.first() {
            let name = sparse
                .values
                .as_ref()
                .and_then(|v| v.name.as_deref())
                .unwrap_or("");
            return Err(unreadable(format!(
                "sparse initializer `{name}` is not supported"
            )));
        }

        let embedding_rows = embedding_rows(&graph.node, &graph.initializer)
            .ok_or(LoadError::EmbeddingTableNotFound)?;
        let mut initializers = Vec::with_capacity(graph.initializer.len());
        for tensor in &mut graph.initializer {
            let name = tensor.name.clone().unwrap_or_default();
            let (value, size) = decode(tensor)
                .map_err(|reason| unreadable(format!("initializer `{name}`: {reason}")))?;
            if size >= STRIP_THRESHOLD {
                strip(tensor);
            }
            initializers.push(SharedWeight {
                name,
                value: Arc::new(value),
            });
        }
        // Dropping the model releases the last slices of the map, which unmaps it.
        let graph_bytes = model.encode_to_vec();
        Ok(Self {
            graph_bytes,
            initializers,
            embedding_rows,
        })
    }
}

impl ModelFile {
    /// Writes the weight-free graph and an empty placeholder into a new
    /// private directory under `parent`.
    pub fn stage_in(&self, parent: &Path) -> Result<StagedGraph, LoadError> {
        let failed = |e: std::io::Error| LoadError::Staging {
            dir: parent.to_owned(),
            reason: e.to_string(),
        };
        let dir = tempfile::Builder::new()
            .prefix("voidwall-model-")
            .tempdir_in(parent)
            .map_err(failed)?;
        std::fs::write(dir.path().join(GRAPH_FILE), &self.graph_bytes).map_err(failed)?;
        std::fs::write(dir.path().join(STRIPPED_LOCATION), b"").map_err(failed)?;
        Ok(StagedGraph { dir })
    }
}

/// Removes an initializer's data and marks it external, so ONNX Runtime takes
/// its value only from the override.
fn strip(tensor: &mut TensorProto) {
    tensor.raw_data = None;
    tensor.float_data = Vec::new();
    tensor.int32_data = Vec::new();
    tensor.int64_data = Vec::new();
    tensor.double_data = Vec::new();
    tensor.uint64_data = Vec::new();
    tensor.data_location = Some(tensor_proto::DataLocation::External as i32);
    tensor.external_data = vec![StringStringEntryProto {
        key: Some("location".into()),
        value: Some(STRIPPED_LOCATION.into()),
    }];
}

/// The row count of the initializer a `Gather` node reads `input_ids` from.
///
/// Only a `Gather` that reads `input_ids` directly counts: a model that casts or
/// reshapes the IDs first is not covered, and its load fails.
fn embedding_rows(
    nodes: &[crate::onnx_proto::NodeProto],
    initializers: &[TensorProto],
) -> Option<i64> {
    let table = nodes.iter().find_map(|n| {
        let is_gather =
            n.op_type.as_deref() == Some("Gather") && n.domain.as_deref().unwrap_or("").is_empty();
        (is_gather && n.input.get(1).map(String::as_str) == Some("input_ids"))
            .then(|| n.input.first())
            .flatten()
    })?;
    initializers
        .iter()
        .find(|t| t.name.as_ref() == Some(table))
        .and_then(|t| t.dims.first().copied())
}

/// Decodes one initializer into a tensor ONNX Runtime can take as an override.
///
/// ONNX Runtime takes an override only over memory the caller owns, so each
/// tensor is built from its own `Vec`. Returns the tensor and its size in bytes.
fn decode(tensor: &TensorProto) -> Result<(DynValue, usize), String> {
    use tensor_proto::DataType as D;
    if tensor.data_location == Some(tensor_proto::DataLocation::External as i32) {
        return Err("its data is in an external file, which is not supported".into());
    }
    let dims = &tensor.dims;
    let raw = tensor.raw_data.as_deref();
    // `onnx.proto` keeps every type narrower than 32 bits in `int32_data`, one
    // value per entry, and the unsigned 32- and 64-bit types in `uint64_data`.
    let int32 = &tensor.int32_data;
    let raw_type = tensor.data_type.unwrap_or(0);
    match D::try_from(raw_type) {
        Ok(D::Float) => owned(dims, raw, f32::from_le_bytes, || tensor.float_data.clone()),
        Ok(D::Double) => owned(dims, raw, f64::from_le_bytes, || tensor.double_data.clone()),
        Ok(D::Int64) => owned(dims, raw, i64::from_le_bytes, || tensor.int64_data.clone()),
        Ok(D::Int32) => owned(dims, raw, i32::from_le_bytes, || int32.clone()),
        Ok(D::Int16) => owned(dims, raw, i16::from_le_bytes, || {
            narrow(int32, |v| v as i16)
        }),
        Ok(D::Uint16) => owned(dims, raw, u16::from_le_bytes, || {
            narrow(int32, |v| v as u16)
        }),
        Ok(D::Int8) => owned(dims, raw, i8::from_le_bytes, || narrow(int32, |v| v as i8)),
        Ok(D::Uint8) => owned(dims, raw, u8::from_le_bytes, || narrow(int32, |v| v as u8)),
        Ok(D::Bool) => owned(
            dims,
            raw,
            |[b]: [u8; 1]| b != 0,
            || narrow(int32, |v| v != 0),
        ),
        Ok(D::Float16) => owned(
            dims,
            raw,
            |b| f16::from_bits(u16::from_le_bytes(b)),
            || narrow(int32, |v| f16::from_bits(v as u16)),
        ),
        Ok(D::Bfloat16) => owned(
            dims,
            raw,
            |b| bf16::from_bits(u16::from_le_bytes(b)),
            || narrow(int32, |v| bf16::from_bits(v as u16)),
        ),
        Ok(D::Uint32) => owned(dims, raw, u32::from_le_bytes, || {
            tensor.uint64_data.iter().map(|&v| v as u32).collect()
        }),
        Ok(D::Uint64) => owned(dims, raw, u64::from_le_bytes, || tensor.uint64_data.clone()),
        _ => Err(format!("data type {raw_type} is not supported")),
    }
}

/// One owned tensor from `raw_data` when the file has it, else from the typed field.
fn owned<T, const N: usize>(
    dims: &[i64],
    raw: Option<&[u8]>,
    from_le: impl Fn([u8; N]) -> T,
    typed: impl FnOnce() -> Vec<T>,
) -> Result<(DynValue, usize), String>
where
    T: PrimitiveTensorElementType + Clone + std::fmt::Debug + 'static,
{
    let count = dims
        .iter()
        .try_fold(1usize, |acc, &d| {
            usize::try_from(d).ok().and_then(|d| acc.checked_mul(d))
        })
        .ok_or("its shape is invalid")?;
    let data: Vec<T> = match raw {
        Some(bytes) => bytes
            .chunks_exact(N)
            .map(|c| from_le(c.try_into().expect("chunks_exact yields N bytes")))
            .collect(),
        None => typed(),
    };
    if data.len() != count || raw.is_some_and(|b| b.len() % N != 0) {
        return Err(format!(
            "holds {} values; its shape needs {count}",
            data.len()
        ));
    }
    let size = count * size_of::<T>();
    Tensor::from_array((dims.to_vec(), data))
        .map(|t| (t.into_dyn(), size))
        .map_err(|e| e.to_string())
}

fn narrow<T>(values: &[i32], convert: impl Fn(i32) -> T) -> Vec<T> {
    values.iter().map(|&v| convert(v)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Fixture, ROWS};

    fn read(fixture: &Fixture) -> Result<ModelFile, LoadError> {
        let dir = tempfile::tempdir().unwrap();
        ModelFile::read(&fixture.write(dir.path()))
    }

    #[test]
    fn every_initializer_in_the_file_is_decoded() {
        let fixture = Fixture::default();
        let file = read(&fixture).unwrap();
        let names: Vec<_> = file.initializers.iter().map(|w| w.name.clone()).collect();
        assert_eq!(names, fixture.initializer_names());
    }

    #[test]
    fn raw_and_typed_initializers_keep_their_values() {
        let file = read(&Fixture::default()).unwrap();
        let get = |name: &str| {
            &file
                .initializers
                .iter()
                .find(|w| w.name == name)
                .unwrap()
                .value
        };
        let (shape, bias) = get("bias").try_extract_tensor::<f32>().unwrap();
        assert_eq!((&**shape, bias), (&[2i64][..], &[0.1f32, 0.1][..]));
        let (_, by_3) = get("shape_by_3").try_extract_tensor::<i64>().unwrap();
        assert_eq!(by_3, &[-1, 3]);
    }

    #[test]
    fn large_initializers_leave_the_parsed_graph() {
        let file = read(&Fixture::default()).unwrap();
        let graph = ModelProto::decode(file.graph_bytes.as_slice())
            .unwrap()
            .graph
            .unwrap();
        for tensor in &graph.initializer {
            let name = tensor.name.as_deref().unwrap();
            let external =
                tensor.data_location == Some(tensor_proto::DataLocation::External as i32);
            let has_data = tensor.raw_data.is_some()
                || !tensor.float_data.is_empty()
                || !tensor.int64_data.is_empty();
            // The fixture's embedding is 2 KiB; every other initializer is small.
            let large = name == "embedding";
            assert_eq!((external, has_data), (large, !large), "{name}");
        }
    }

    #[test]
    fn the_graph_is_staged_with_its_placeholder_and_removed_after() {
        let file = read(&Fixture::default()).unwrap();
        let parent = tempfile::tempdir().unwrap();
        let staged = file.stage_in(parent.path()).unwrap();
        let dir = staged.path().parent().unwrap().to_owned();
        assert_eq!(std::fs::read(staged.path()).unwrap(), file.graph_bytes);
        assert_eq!(std::fs::read(dir.join(STRIPPED_LOCATION)).unwrap(), b"");
        drop(staged);
        assert!(!dir.exists());
    }

    #[test]
    fn an_unwritable_temp_directory_is_named() {
        let file = read(&Fixture::default()).unwrap();
        let missing = Path::new("/nonexistent/voidwall-tmp");
        let err = file.stage_in(missing).err().unwrap();
        assert!(matches!(err, LoadError::Staging { .. }));
        assert!(
            err.to_string().contains("/nonexistent/voidwall-tmp"),
            "got: {err}"
        );
    }

    #[test]
    fn the_embedding_table_is_found() {
        assert_eq!(read(&Fixture::default()).unwrap().embedding_rows, ROWS);
    }

    #[test]
    fn a_cast_before_the_gather_hides_the_embedding_table() {
        let fixture = Fixture {
            cast_before_gather: true,
            ..Fixture::default()
        };
        assert!(matches!(
            read(&fixture),
            Err(LoadError::EmbeddingTableNotFound)
        ));
    }

    #[test]
    fn a_file_that_is_not_onnx_names_the_model_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("model.onnx");
        std::fs::write(&path, b"not a model").unwrap();
        let err = ModelFile::read(&path).err().unwrap();
        assert!(matches!(err, LoadError::ModelUnreadable { .. }));
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "got: {err}"
        );
    }

    #[test]
    fn external_data_is_refused() {
        let tensor = TensorProto {
            name: Some("w".into()),
            data_type: Some(tensor_proto::DataType::Float as i32),
            data_location: Some(tensor_proto::DataLocation::External as i32),
            ..Default::default()
        };
        assert!(decode(&tensor).unwrap_err().contains("external"));
    }

    #[test]
    fn half_precision_initializers_decode_from_both_fields() {
        let one = f16::from_f32(1.5);
        let from_raw = TensorProto {
            dims: vec![1],
            data_type: Some(tensor_proto::DataType::Float16 as i32),
            raw_data: Some(one.to_bits().to_le_bytes().to_vec().into()),
            ..Default::default()
        };
        let from_typed = TensorProto {
            raw_data: None,
            int32_data: vec![i32::from(one.to_bits())],
            ..from_raw.clone()
        };
        for tensor in [from_raw, from_typed] {
            let (value, _) = decode(&tensor).unwrap();
            assert_eq!(value.try_extract_tensor::<f16>().unwrap().1, &[one]);
        }
    }

    #[test]
    fn a_size_mismatch_is_refused() {
        let tensor = TensorProto {
            dims: vec![3],
            data_type: Some(tensor_proto::DataType::Float as i32),
            float_data: vec![1.0, 2.0],
            ..Default::default()
        };
        assert!(
            decode(&tensor)
                .unwrap_err()
                .contains("holds 2 values; its shape needs 3")
        );
    }
}
