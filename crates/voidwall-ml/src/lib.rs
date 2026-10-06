//! ONNX Runtime integration and the model adapters.
//!
//! This crate cannot depend on `voidwall`: an adapter loads a model and
//! returns scores, and `voidwall` turns scores into findings.

pub mod adapter;
mod checks;
pub mod cpu;
// Tiny models and tokenizers built in code. `voidwall`'s tests use them
// through the `test-fixtures` feature; the release binary never carries them.
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixtures;
mod load;
mod model_file;
// Generated from `proto/onnx.proto` and not edited by hand, so its lints are
// off; the load reads only part of it.
#[allow(dead_code, clippy::all)]
mod onnx_proto;
#[cfg(test)]
mod parity;
mod run;

pub use adapter::{Adapter, AdapterKind, TextClassifier};
pub use load::{LoadError, LoadSettings, Worker, load};
pub use run::{Cancel, RunError, check_overlap, default_overlap};

use std::ffi::CStr;

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
