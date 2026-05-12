use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Unified error type for all fallible operations in pii-proxy.
#[derive(Debug)]
pub enum Error {
    /// Configuration file could not be read or parsed.
    Config(String),

    /// PII scanner initialization or runtime failure.
    Scanner(String),

    /// Proxy I/O or upstream errors.
    Proxy(String),

    /// Generic I/O errors.
    Io(std::io::Error),

    /// Request body exceeds configured `max_body_size`.
    BodyTooLarge,

    /// Request content type is not in the scannable allow-list.
    UnsupportedContentType,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Config(msg) => write!(f, "configuration error: {msg}"),
            Error::Scanner(msg) => write!(f, "scanner error: {msg}"),
            Error::Proxy(msg) => write!(f, "proxy error: {msg}"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::BodyTooLarge => write!(f, "request body too large"),
            Error::UnsupportedContentType => write!(f, "unsupported content type"),
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

impl From<pii::PiiError> for Error {
    fn from(e: pii::PiiError) -> Self {
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

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Error::Config(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            Error::Scanner(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            Error::Proxy(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            Error::Io(e) => (StatusCode::BAD_GATEWAY, e.to_string()),
            Error::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large".to_string(),
            ),
            Error::UnsupportedContentType => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported content type".to_string(),
            ),
        };

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
    #[test_case(Error::BodyTooLarge, "request body too large", "")]
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
        let err: Error = pii::PiiError::InvalidConfiguration("bad".into()).into();
        assert!(matches!(err, Error::Scanner(_)));
    }

    #[test]
    fn error_source() {
        use std::error::Error as StdError;
        let io = Error::Io(std::io::Error::other("oops"));
        assert!(io.source().is_some());
        assert!(Error::Config("bad".into()).source().is_none());
    }

    #[test_case(Error::Config("msg".into()), StatusCode::INTERNAL_SERVER_ERROR, "msg")]
    #[test_case(Error::Scanner("msg".into()), StatusCode::BAD_GATEWAY, "msg")]
    #[test_case(Error::Proxy("msg".into()), StatusCode::BAD_GATEWAY, "msg")]
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
    #[tokio::test]
    async fn into_response(err: Error, expected_status: StatusCode, expected_body: &str) {
        let response = err.into_response();
        assert_eq!(response.status(), expected_status);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], expected_body);
    }

    #[tokio::test]
    async fn into_response_io() {
        let err = Error::Io(std::io::Error::other("reset"));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }
}
