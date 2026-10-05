//! ONNX Runtime integration and the model adapters.
//!
//! This crate cannot depend on `voidwall`: an adapter loads a model and
//! returns scores, and `voidwall` turns scores into findings.

pub mod adapter;
pub mod cpu;

pub use adapter::AdapterKind;

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
