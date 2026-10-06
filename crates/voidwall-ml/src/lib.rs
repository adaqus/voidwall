//! ONNX Runtime integration and the model adapters.
//!
//! This crate cannot depend on `voidwall`: an adapter loads a model and
//! returns scores, and `voidwall` turns scores into findings.

pub mod adapter;
mod checks;
pub mod cpu;
#[cfg(test)]
mod fixtures;
mod load;
mod model_file;
// Generated from `proto/onnx.proto` and not edited by hand, so its lints are
// off; the load reads only part of it.
#[allow(dead_code, clippy::all)]
mod onnx_proto;

pub use adapter::{Adapter, AdapterKind, TextClassifier};
pub use load::{LoadError, LoadSettings, Worker, load};

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
