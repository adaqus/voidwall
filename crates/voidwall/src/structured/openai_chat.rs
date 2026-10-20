//! OpenAI Chat Completions bodies on a reverse proxy route with
//! `format = "openai-chat"`.
//!
//! [`decode_request`] and [`decode_response`] classify the whole document with
//! [`chat_completions`](super::chat_completions), whose tables hold every field
//! rule. A top-level key the tables do not list is scanned.

use serde_json::Value;

use super::chat_completions::{Decoded, Selection};
use super::json::flatten_json;
use crate::error::Error;

/// Decode a Chat Completions request. A body that is not a JSON object with a
/// `messages` array is [`Error::BodyParse`]. A classification that does not
/// line up with the flattened fragments is [`Error::Scanner`].
pub fn decode_request(raw: &[u8]) -> Result<Decoded, Error> {
    let document: Value = serde_json::from_slice(raw).map_err(|_| Error::BodyParse)?;
    let Value::Object(request) = &document else {
        return Err(Error::BodyParse);
    };
    if !request.get("messages").is_some_and(Value::is_array) {
        return Err(Error::BodyParse);
    }
    let mut selection = Selection::new();
    selection.request(request);
    let fragments = flatten_json(raw).map_err(|_| Error::BodyParse)?;
    selection.into_decoded(fragments)
}

/// Decode a Chat Completions response. A JSON value that is not an object is
/// scanned whole, as one unit. A body that does not parse is
/// [`Error::BodyParse`].
pub fn decode_response(raw: &[u8]) -> Result<Decoded, Error> {
    let document: Value = serde_json::from_slice(raw).map_err(|_| Error::BodyParse)?;
    let mut selection = Selection::new();
    match &document {
        Value::Object(response) => selection.response(response),
        other => selection.text(other),
    }
    let fragments = flatten_json(raw).map_err(|_| Error::BodyParse)?;
    selection.into_decoded(fragments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(br#"["messages"]"# ; "not an object")]
    #[test_case(br#"{"model": "m", "input": "hello"}"# ; "no messages")]
    #[test_case(br#"{"messages": "hello"}"# ; "messages is not an array")]
    #[test_case(br#"{"messages": ["# ; "not json")]
    fn a_request_that_is_not_chat_completions_is_a_parse_error(raw: &[u8]) {
        assert!(matches!(decode_request(raw), Err(Error::BodyParse)));
    }

    #[test]
    fn a_request_is_cut_into_its_units() {
        let raw = br#"{"model":"m","messages":[{"role":"user","content":"a"}],"user":"b"}"#;
        let decoded = decode_request(raw).unwrap();
        let values: Vec<Vec<&str>> = decoded
            .units
            .iter()
            .map(|u| u.iter().map(|f| f.value.as_str()).collect())
            .collect();
        assert_eq!(values, vec![vec!["a"], vec!["b"]]);
    }

    #[test]
    fn a_json_array_response_is_scanned_whole_as_one_unit() {
        let decoded = decode_response(br#"["a", {"b": "c"}]"#).unwrap();
        assert_eq!(decoded.units.len(), 1);
        let values: Vec<&str> = decoded.units[0].iter().map(|f| f.value.as_str()).collect();
        assert_eq!(values, vec!["a", "c"]);
    }

    #[test]
    fn an_unparseable_response_is_a_parse_error() {
        assert!(matches!(
            decode_response(b"{not json"),
            Err(Error::BodyParse)
        ));
    }

    #[test]
    fn a_response_reads_its_choices() {
        let raw =
            br#"{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"a"}}]}"#;
        let decoded = decode_response(raw).unwrap();
        assert_eq!(decoded.units.len(), 1);
        assert_eq!(decoded.units[0][0].context, "choices[0].message.content");
    }

    // --- Fixtures ---

    #[test]
    fn the_full_request_fixture_decodes() {
        let raw = include_bytes!(
            "../../tests/fixtures/openai-chat/openai-python-3.5.0-request-full.json"
        );
        let decoded = decode_request(raw).expect("fixture decodes");
        assert_eq!(decoded.unknown_parts, 0);
        assert_eq!(decoded.encoded_values, 1, "the one inline image");
    }

    /// Responses as LM Studio 0.4.26 sent them. The integration tests serve
    /// the same files from a stub upstream.
    #[test_case(include_bytes!("../../tests/fixtures/openai-chat/lmstudio-0.4.26-response.json") ; "plain answer")]
    #[test_case(include_bytes!("../../tests/fixtures/openai-chat/lmstudio-0.4.26-response-tool-call.json") ; "tool call")]
    #[test_case(include_bytes!("../../tests/fixtures/openai-chat/lmstudio-0.4.26-error-flat.json") ; "flat error")]
    #[test_case(include_bytes!("../../tests/fixtures/openai-chat/lmstudio-0.4.26-error-object.json") ; "error object")]
    fn each_response_fixture_decodes(raw: &[u8]) {
        let decoded = decode_response(raw).expect("fixture decodes");
        assert!(!decoded.units.is_empty());
        assert_eq!((decoded.unknown_parts, decoded.encoded_values), (0, 0));
    }
}
