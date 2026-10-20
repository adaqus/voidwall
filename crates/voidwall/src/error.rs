use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Unified error type for all fallible operations in voidwall.
#[derive(Debug)]
pub enum Error {
    /// Configuration file could not be read or parsed.
    Config(String),

    /// PII scanner initialization or runtime failure.
    Scanner(String),

    /// A model guard failed at run time: its pool, its tokenizer, ONNX
    /// Runtime, or an invalid output. `detail` goes to the log only.
    Inference { guard: Arc<str>, detail: String },

    /// A unit needs more windows than a model guard's window limit.
    WindowLimit {
        guard: Arc<str>,
        windows: usize,
        limit: usize,
    },

    /// Proxy I/O or upstream errors.
    Proxy(String),

    /// Generic I/O errors.
    Io(std::io::Error),

    /// The upstream exchange did not finish within `upstream_timeout_secs`.
    UpstreamTimeout,

    /// The upstream response body under response scan exceeds `max_body_size`.
    ResponseTooLarge,

    /// Request body exceeds configured `max_body_size`.
    BodyTooLarge,

    /// Request body does not parse as the content type it declares.
    BodyParse,

    /// Request content type is not in the scannable allow-list.
    UnsupportedContentType,

    /// The body parses, but holds content Voidwall cannot inspect, such as a
    /// content part of an unknown type. The body never names the content.
    UnscannableContent,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Config(msg) => write!(f, "configuration error: {msg}"),
            Error::Scanner(msg) => write!(f, "scanner error: {msg}"),
            Error::Inference { guard, detail } => {
                write!(f, "model guard '{guard}' failed: {detail}")
            }
            Error::WindowLimit {
                guard,
                windows,
                limit,
            } => write!(
                f,
                "model guard '{guard}': the unit needs {windows} windows; the limit is {limit}"
            ),
            Error::Proxy(msg) => write!(f, "proxy error: {msg}"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::UpstreamTimeout => write!(f, "upstream timed out"),
            Error::ResponseTooLarge => write!(f, "upstream response body too large"),
            Error::BodyTooLarge => write!(f, "request body too large"),
            Error::BodyParse => write!(f, "body parse failed"),
            Error::UnsupportedContentType => write!(f, "unsupported content type"),
            Error::UnscannableContent => write!(f, "{UNSCANNABLE_CONTENT}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl Error {
    /// The `reason` label of `voidwall_errors_total` for an error that
    /// follows `on_error`. A variant no specific reason covers counts as a
    /// scanner failure.
    pub fn scan_reason(&self) -> &'static str {
        match self {
            Error::Inference { .. } => "inference_failure",
            Error::WindowLimit { .. } => "window_limit",
            Error::UnscannableContent => "unscannable_content",
            _ => "scanner_failure",
        }
    }
}

// --- From conversions ---

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::Config(e.to_string())
    }
}

impl From<voidwall_pii::PiiError> for Error {
    fn from(e: voidwall_pii::PiiError) -> Self {
        Error::Scanner(e.to_string())
    }
}

impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        Error::Proxy(e.to_string())
    }
}

impl From<hyper_util::client::legacy::Error> for Error {
    fn from(e: hyper_util::client::legacy::Error) -> Self {
        Error::Proxy(e.to_string())
    }
}

// --- IntoResponse for HTTP error responses ---

/// The fixed `error` text of every 500. The failure details go to the log only.
pub const INTERNAL_ERROR: &str = "internal error";

/// The fixed `error` text of every 502. The failure details go to the log only.
pub const UPSTREAM_ERROR: &str = "upstream error";

/// The fixed `error` text of every 504. The failure details go to the log only.
pub const UPSTREAM_TIMEOUT: &str = "upstream timeout";

/// The fixed `error` text of a window-limit 413. The guard and the window
/// counts go to the log only.
pub const WINDOW_LIMIT_ERROR: &str = "tokenized content too long to scan";

/// The fixed `error` text of a 422. It never names what could not be scanned.
pub const UNSCANNABLE_CONTENT: &str = "unscannable content";

const BODY_TOO_LARGE: &str = "request body too large";
const BODY_PARSE_FAILED: &str = "body parse failed";
const UNSUPPORTED_CONTENT_TYPE: &str = "unsupported content type";

impl Error {
    /// The status and the fixed message of the answer this error makes. Both
    /// answer shapes read it, so their text cannot drift apart.
    fn status_and_message(&self) -> (StatusCode, &'static str) {
        match self {
            Error::Config(_) | Error::Scanner(_) | Error::Inference { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, INTERNAL_ERROR)
            }
            Error::Proxy(_) | Error::Io(_) | Error::ResponseTooLarge => {
                (StatusCode::BAD_GATEWAY, UPSTREAM_ERROR)
            }
            Error::UpstreamTimeout => (StatusCode::GATEWAY_TIMEOUT, UPSTREAM_TIMEOUT),
            Error::BodyTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, BODY_TOO_LARGE),
            Error::WindowLimit { .. } => (StatusCode::PAYLOAD_TOO_LARGE, WINDOW_LIMIT_ERROR),
            Error::BodyParse => (StatusCode::BAD_REQUEST, BODY_PARSE_FAILED),
            Error::UnsupportedContentType => {
                (StatusCode::UNSUPPORTED_MEDIA_TYPE, UNSUPPORTED_CONTENT_TYPE)
            }
            Error::UnscannableContent => (StatusCode::UNPROCESSABLE_ENTITY, UNSCANNABLE_CONTENT),
        }
    }

    /// The answer in the OpenAI error shape, for a route with
    /// `format = "openai-chat"`: the status and message of
    /// [`IntoResponse::into_response`], under `error` with a `type`, a null
    /// `param`, and a `code`. It never carries a detail of the failure.
    pub fn into_openai_response(self) -> Response {
        let (status, _) = self.status_and_message();
        (status, axum::Json(self.openai_body())).into_response()
    }

    /// The body of [`Error::into_openai_response`]. A stream stopped after its
    /// first byte carries it in its error event.
    pub fn openai_body(&self) -> serde_json::Value {
        let (_, message) = self.status_and_message();
        let (kind, code) = match self {
            Error::BodyParse => (INVALID_REQUEST, "malformed_body"),
            Error::BodyTooLarge => (INVALID_REQUEST, "body_too_large"),
            Error::WindowLimit { .. } => (INVALID_REQUEST, "content_too_long"),
            Error::UnscannableContent => (INVALID_REQUEST, "unscannable_content"),
            // The reverse proxy never answers it; listed so the match stays
            // exhaustive.
            Error::UnsupportedContentType => (INVALID_REQUEST, "unsupported_content_type"),
            Error::Config(_) | Error::Scanner(_) | Error::Inference { .. } => {
                (SERVER_ERROR, "internal_error")
            }
            Error::Proxy(_) | Error::Io(_) | Error::ResponseTooLarge => {
                (SERVER_ERROR, "upstream_error")
            }
            Error::UpstreamTimeout => (SERVER_ERROR, "upstream_timeout"),
        };
        json!({
            "error": { "message": message, "type": kind, "param": null, "code": code }
        })
    }
}

/// The OpenAI `error.type` of an answer the client caused.
pub const INVALID_REQUEST: &str = "invalid_request_error";

/// The OpenAI `error.type` of an answer Voidwall or the upstream caused.
const SERVER_ERROR: &str = "server_error";

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, message) = self.status_and_message();
        let body = json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use test_case::test_case;

    #[test_case(Error::Config("bad toml".into()), "configuration error", "bad toml")]
    #[test_case(Error::Scanner("pool dead".into()), "scanner error", "pool dead")]
    #[test_case(Error::Proxy("upstream refused".into()), "proxy error", "upstream refused")]
    #[test_case(Error::UpstreamTimeout, "upstream timed out", "")]
    #[test_case(Error::ResponseTooLarge, "upstream response body too large", "")]
    #[test_case(Error::BodyTooLarge, "request body too large", "")]
    #[test_case(Error::BodyParse, "body parse failed", "")]
    #[test_case(Error::UnsupportedContentType, "unsupported content type", "")]
    fn display(err: Error, expected_prefix: &str, expected_detail: &str) {
        let msg = err.to_string();
        assert!(msg.contains(expected_prefix));
        if !expected_detail.is_empty() {
            assert!(msg.contains(expected_detail));
        }
    }

    #[test]
    fn display_io() {
        let err = Error::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe"));
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn from_io_error() {
        let err: Error = std::io::Error::new(std::io::ErrorKind::NotFound, "not found").into();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn from_toml_error() {
        let err: Error = toml::from_str::<toml::Value>("invalid = [")
            .unwrap_err()
            .into();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn from_pii_error() {
        let err: Error = voidwall_pii::PiiError::InvalidConfiguration("bad".into()).into();
        assert!(matches!(err, Error::Scanner(_)));
    }

    #[test]
    fn error_source() {
        use std::error::Error as StdError;
        let io = Error::Io(std::io::Error::other("oops"));
        assert!(io.source().is_some());
        assert!(Error::Config("bad".into()).source().is_none());
    }

    #[test_case(Error::Config("msg".into()), StatusCode::INTERNAL_SERVER_ERROR, "internal error")]
    #[test_case(Error::Scanner("msg".into()), StatusCode::INTERNAL_SERVER_ERROR, "internal error")]
    #[test_case(Error::Proxy("msg".into()), StatusCode::BAD_GATEWAY, "upstream error")]
    #[test_case(
        Error::BodyTooLarge,
        StatusCode::PAYLOAD_TOO_LARGE,
        "request body too large"
    )]
    #[test_case(
        Error::UnsupportedContentType,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported content type"
    )]
    #[test_case(Error::BodyParse, StatusCode::BAD_REQUEST, "body parse failed")]
    #[tokio::test]
    async fn into_response(err: Error, expected_status: StatusCode, expected_body: &str) {
        let response = err.into_response();
        assert_eq!(response.status(), expected_status);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], expected_body);
    }

    #[test_case(Error::UpstreamTimeout, StatusCode::GATEWAY_TIMEOUT, r#"{"error":"upstream timeout"}"# ; "timeout")]
    #[test_case(Error::ResponseTooLarge, StatusCode::BAD_GATEWAY, r#"{"error":"upstream error"}"# ; "oversize response")]
    #[tokio::test]
    async fn an_upstream_limit_error_answers_an_exact_body(
        err: Error,
        expected_status: StatusCode,
        expected_body: &str,
    ) {
        let response = err.into_response();
        assert_eq!(response.status(), expected_status);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes, expected_body.as_bytes());
    }

    #[tokio::test]
    async fn unscannable_content_answers_422_with_a_fixed_body() {
        let err = Error::UnscannableContent;
        assert_eq!(err.scan_reason(), "unscannable_content");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], br#"{"error":"unscannable content"}"#);
    }

    // --- The OpenAI error shape: one case per row of the spec's table ---

    #[test_case(Error::BodyParse, StatusCode::BAD_REQUEST, "body parse failed", "invalid_request_error", "malformed_body" ; "malformed body")]
    #[test_case(Error::BodyTooLarge, StatusCode::PAYLOAD_TOO_LARGE, "request body too large", "invalid_request_error", "body_too_large" ; "oversize body")]
    #[test_case(window_limit_error(), StatusCode::PAYLOAD_TOO_LARGE, "tokenized content too long to scan", "invalid_request_error", "content_too_long" ; "window limit")]
    #[test_case(Error::UnscannableContent, StatusCode::UNPROCESSABLE_ENTITY, "unscannable content", "invalid_request_error", "unscannable_content" ; "unscannable content")]
    #[test_case(Error::Scanner("pool dead".into()), StatusCode::INTERNAL_SERVER_ERROR, "internal error", "server_error", "internal_error" ; "scanner failure")]
    #[test_case(inference_error(), StatusCode::INTERNAL_SERVER_ERROR, "internal error", "server_error", "internal_error" ; "inference failure")]
    #[test_case(Error::Proxy("refused".into()), StatusCode::BAD_GATEWAY, "upstream error", "server_error", "upstream_error" ; "upstream failure")]
    #[test_case(Error::ResponseTooLarge, StatusCode::BAD_GATEWAY, "upstream error", "server_error", "upstream_error" ; "oversize response")]
    #[test_case(Error::UpstreamTimeout, StatusCode::GATEWAY_TIMEOUT, "upstream timeout", "server_error", "upstream_timeout" ; "upstream timeout")]
    #[tokio::test]
    async fn the_openai_shape_answers_the_table_row(
        err: Error,
        status: StatusCode,
        message: &str,
        kind: &str,
        code: &str,
    ) {
        let response = err.into_openai_response();
        assert_eq!(response.status(), status);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json,
            json!({"error": {"message": message, "type": kind, "param": null, "code": code}}),
            "exactly four keys under `error`, and no other top-level key"
        );
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        for detail in ["pool dead", "refused", "injection", "Gemm", "2746"] {
            assert!(!text.contains(detail), "body leaks {detail}: {text}");
        }
    }

    fn inference_error() -> Error {
        Error::Inference {
            guard: Arc::from("injection"),
            detail: "Gemm: Invalid bias shape".into(),
        }
    }

    fn window_limit_error() -> Error {
        Error::WindowLimit {
            guard: Arc::from("injection"),
            windows: 2746,
            limit: 2745,
        }
    }

    #[test_case(inference_error(), StatusCode::INTERNAL_SERVER_ERROR, INTERNAL_ERROR ; "inference")]
    #[test_case(window_limit_error(), StatusCode::PAYLOAD_TOO_LARGE, WINDOW_LIMIT_ERROR ; "window limit")]
    #[tokio::test]
    async fn a_model_guard_error_answers_a_fixed_body(
        err: Error,
        expected_status: StatusCode,
        expected_error: &str,
    ) {
        let response = err.into_response();
        assert_eq!(response.status(), expected_status);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json, serde_json::json!({ "error": expected_error }));
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        for detail in ["injection", "Gemm", "2746", "2745"] {
            assert!(!text.contains(detail), "body leaks {detail}: {text}");
        }
    }

    #[test_case(inference_error(), "inference_failure" ; "inference")]
    #[test_case(window_limit_error(), "window_limit" ; "window limit")]
    #[test_case(Error::Scanner("pool dead".into()), "scanner_failure" ; "scanner")]
    fn scan_reason(err: Error, expected: &str) {
        assert_eq!(err.scan_reason(), expected);
    }

    #[test]
    fn a_model_guard_error_display_names_the_guard() {
        assert!(inference_error().to_string().contains("injection"));
        let msg = window_limit_error().to_string();
        assert!(msg.contains("injection") && msg.contains("2746") && msg.contains("2745"));
    }

    #[tokio::test]
    async fn into_response_io() {
        let err = Error::Io(std::io::Error::other("reset"));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "upstream error");
    }
}
