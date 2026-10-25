//! ONNX Runtime integration and the model adapters.
//!
//! This crate cannot depend on `voidwall`: an adapter loads a model and
//! returns scores, and `voidwall` turns scores into findings.

pub mod adapter;
mod checks;
pub mod cpu;
mod decode;
// Tiny models and tokenizers built in code. `voidwall`'s tests use them
// through the `test-fixtures` feature; the release binary never carries them.
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixtures;
mod labels;
mod load;
mod model_file;
// Generated from `proto/onnx.proto` and not edited by hand, so its lints are
// off; the load reads only part of it.
#[allow(dead_code, clippy::all)]
mod onnx_proto;
#[cfg(test)]
mod parity;
mod run;
mod token;

pub use adapter::{Adapter, AdapterKind, TextClassifier};
pub use decode::{Boundaries, Span};
pub use labels::Labels;
pub use load::{
    Classifier, Head, LoadError, LoadSettings, TokenWorker, Tokens, Worker, Workers, load,
};
pub use run::{Cancel, RunError, check_overlap, default_overlap};
pub use token::{TokenProbs, TokenRecord};

use std::ffi::CStr;
use std::fmt;

/// The ONNX Runtime environment every session is built in.
///
/// A process gets one: `ort` refuses a second environment, even after the
/// first is dropped. Build it once at startup and pass it to every [`load`].
pub struct OnnxRuntime(ort::environment::Environment);

impl OnnxRuntime {
    pub fn new() -> Result<Self, RuntimeError> {
        ort::init()
            .build()
            .map(Self)
            .map_err(|e| RuntimeError(e.to_string()))
    }

    pub(crate) fn environment(&self) -> &ort::environment::Environment {
        &self.0
    }
}

/// ONNX Runtime did not build its environment, for example because the
/// process already built one.
#[derive(Debug)]
pub struct RuntimeError(String);

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ONNX Runtime could not build its environment: {}",
            self.0
        )
    }
}

impl std::error::Error for RuntimeError {}

/// The version of the ONNX Runtime linked into this build, as ONNX Runtime
/// itself reports it.
pub fn onnx_runtime_version() -> String {
    // SAFETY: `OrtGetApiBase` is ONNX Runtime's entry point and never returns
    // null; `GetVersionString` returns a static, NUL-terminated string.
    let version = unsafe { ((*ort::sys::OrtGetApiBase()).GetVersionString)() };
    unsafe { CStr::from_ptr(version) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_linked_onnx_runtime_is_the_pinned_one() {
        assert_eq!(onnx_runtime_version(), "1.28.0");
    }
}
