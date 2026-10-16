//! LiteLLM Generic Guardrail API payload.
//!
//! LiteLLM posts one payload per call it guards, on the request side and on
//! the response side. [`decode`] reads the fields this module names and
//! classifies their entries with [`chat_completions`](super::chat_completions):
//!
//! - request: `structured_messages`, `tools`, and `tool_calls`, and `texts`
//!   only when `structured_messages` is missing;
//! - response: `texts` and `tool_calls`.
//!
//! `images` holds image URLs, never scanned: a `data:` URL is counted as base64
//! data. LiteLLM copies every `image_url.url` of the messages into it, so on
//! the request side it is ignored when `structured_messages` exists, as
//! `texts` is.
//! `request_data` and `request_headers` are not fields of [`GuardrailRequest`],
//! so no code path can scan them, and another top-level field is ignored.

use serde::Deserialize;
use serde_json::Value;
use utoipa::ToSchema;

use super::OwnedContextFragment;
use super::chat_completions::Selection;
use super::json::flatten_json;
use crate::error::Error;

/// The side of the call LiteLLM is guarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum InputType {
    /// The call before it reaches the model.
    Request,
    /// The model's answer.
    Response,
}

impl InputType {
    /// The `direction` metric label.
    pub fn direction(self) -> &'static str {
        match self {
            InputType::Request => "request",
            InputType::Response => "response",
        }
    }
}

/// A LiteLLM Generic Guardrail API payload. Only the fields Voidwall reads are
/// listed; any other field, including `request_data` and `request_headers`, is
/// accepted and ignored.
#[derive(Deserialize, ToSchema)]
#[schema(example = json!({
    "input_type": "request",
    "structured_messages": [
        {"role": "system", "content": "You are a support agent."},
        {"role": "user", "content": "My email is jane@example.com"}
    ],
    "litellm_call_id": "a1b2c3d4",
}))]
pub struct GuardrailRequest {
    /// Which side of the call the payload carries.
    input_type: InputType,
    /// Request side: the call's messages in OpenAI Chat Completions format.
    #[schema(value_type = Option<Vec<Object>>)]
    structured_messages: Option<Vec<Value>>,
    /// Request side: tool definitions in OpenAI Chat Completions format.
    #[schema(value_type = Option<Vec<Object>>)]
    tools: Option<Vec<Value>>,
    /// Both sides: tool calls in OpenAI Chat Completions format.
    #[schema(value_type = Option<Vec<Object>>)]
    tool_calls: Option<Vec<Value>>,
    /// Response side: the model's text. Request side: read only when
    /// `structured_messages` is missing.
    #[schema(value_type = Option<Vec<String>>)]
    texts: Option<Vec<Value>>,
    /// Image URLs. Never scanned; each `data:` URL is counted in
    /// `voidwall_unscanned_total`. Request side: read only when
    /// `structured_messages` is missing.
    #[schema(value_type = Option<Vec<String>>)]
    images: Option<Vec<Value>>,
}

/// A decoded payload: one fragment group per scanned entry, and what was left
/// out. `Debug` is not derived, because the fragments hold the scanned text.
pub struct Decoded {
    pub input_type: InputType,
    /// One group per top-level entry that has a kept fragment. Each group
    /// becomes one body unit.
    pub units: Vec<Vec<OwnedContextFragment>>,
    /// Content parts of an unknown type. They are not in `units`.
    pub unknown_parts: usize,
    /// Base64 values left out without a scan.
    pub encoded_values: usize,
}

/// Decode a LiteLLM payload. A body that is not a JSON object with an
/// `input_type` of `request` or `response` is [`Error::BodyParse`].
pub fn decode(raw: &[u8]) -> Result<Decoded, Error> {
    let payload: GuardrailRequest = serde_json::from_slice(raw).map_err(|_| Error::BodyParse)?;
    let selection = classify(&payload);
    let (unknown_parts, encoded_values) = (selection.unknown_parts(), selection.encoded_values());
    let fragments = flatten_json(raw).map_err(|_| Error::BodyParse)?;
    Ok(Decoded {
        input_type: payload.input_type,
        units: selection.into_unit_fragments(fragments),
        unknown_parts,
        encoded_values,
    })
}

fn classify(payload: &GuardrailRequest) -> Selection {
    let request = payload.input_type == InputType::Request;
    let mut selection = Selection::new();

    if request {
        for (i, message) in entries(&payload.structured_messages) {
            selection.message("structured_messages", i, message);
        }
        for (i, tool) in entries(&payload.tools) {
            selection.tool("tools", i, tool);
        }
    }
    // LiteLLM fills `texts` and `images` from the messages, so with the
    // messages present they would only repeat them.
    if !request || payload.structured_messages.is_none() {
        for (i, text) in entries(&payload.texts) {
            selection.text("texts", i, text);
        }
        for (_, image) in entries(&payload.images) {
            selection.image_url(image);
        }
    }
    for (i, call) in entries(&payload.tool_calls) {
        selection.tool_call("tool_calls", i, call);
    }
    selection
}

fn entries(field: &Option<Vec<Value>>) -> impl Iterator<Item = (usize, &Value)> {
    field.iter().flatten().enumerate()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use test_case::test_case;

    fn decode_json(payload: Value) -> Decoded {
        decode(&serde_json::to_vec(&payload).unwrap()).expect("decodes")
    }

    /// Every kept fragment path, in unit order.
    fn paths(decoded: &Decoded) -> Vec<&str> {
        decoded
            .units
            .iter()
            .flatten()
            .map(|f| f.context.as_str())
            .collect()
    }

    // --- The envelope ---

    #[test_case(br#"{"texts": ["x"]}"# ; "missing input_type")]
    #[test_case(br#"{"input_type": "both", "texts": ["x"]}"# ; "unknown input_type")]
    #[test_case(br#"["request"]"# ; "not an object")]
    #[test_case(br#"{"input_type": "request""# ; "not json")]
    fn a_malformed_envelope_is_a_parse_error(raw: &[u8]) {
        assert!(matches!(decode(raw), Err(Error::BodyParse)));
    }

    #[test]
    fn an_unknown_top_level_field_is_ignored() {
        let decoded = decode_json(json!({
            "input_type": "request",
            "future_field": "x",
            "request_data": {"user_api_key_user_email": "x"},
            "request_headers": {"x-user": "x"},
        }));
        assert!(decoded.units.is_empty());
    }

    #[test_case("request", InputType::Request, "request")]
    #[test_case("response", InputType::Response, "response")]
    fn input_type_maps_to_the_direction(raw: &str, expected: InputType, direction: &str) {
        let decoded = decode_json(json!({"input_type": raw}));
        assert_eq!(decoded.input_type, expected);
        assert_eq!(decoded.input_type.direction(), direction);
    }

    /// Payloads in the shape LiteLLM v1.105.1 posts. The integration tests
    /// post the same files to a running server.
    #[test_case(include_bytes!("../../tests/fixtures/litellm/v1.105.1-request-tools.json"), InputType::Request ; "request with tools")]
    #[test_case(include_bytes!("../../tests/fixtures/litellm/v1.105.1-response.json"), InputType::Response ; "response")]
    #[test_case(include_bytes!("../../tests/fixtures/litellm/v1.105.1-request-inline-image.json"), InputType::Request ; "request with an inline image")]
    fn each_fixture_parses_with_the_envelope(raw: &[u8], input_type: InputType) {
        let payload: GuardrailRequest = serde_json::from_slice(raw).expect("fixture parses");
        assert_eq!(payload.input_type, input_type);
    }

    // --- The request side and the response side ---

    #[test]
    fn texts_is_ignored_when_structured_messages_exist() {
        let decoded = decode_json(json!({
            "input_type": "request",
            "structured_messages": [{"role": "user", "content": "a"}],
            "texts": ["b"],
        }));
        assert_eq!(paths(&decoded), vec!["structured_messages[0].content"]);
    }

    #[test]
    fn texts_is_the_fallback_when_structured_messages_is_missing() {
        let decoded = decode_json(json!({"input_type": "request", "texts": ["a", "b"]}));
        assert_eq!(paths(&decoded), vec!["texts[0]", "texts[1]"]);
    }

    #[test]
    fn the_response_side_reads_texts_and_tool_calls_only() {
        let decoded = decode_json(json!({
            "input_type": "response",
            "structured_messages": [{"role": "user", "content": "a"}],
            "tools": [{"type": "function", "function": {"name": "b"}}],
            "texts": ["c"],
            "tool_calls": [{"id": "call_1", "type": "function", "function": {"arguments": "d"}}],
        }));
        assert_eq!(
            paths(&decoded),
            vec!["texts[0]", "tool_calls[0].function.arguments"]
        );
    }

    #[test]
    fn the_request_side_reads_tools_and_tool_calls() {
        let decoded = decode_json(json!({
            "input_type": "request",
            "structured_messages": [],
            "tools": [{"type": "function", "function": {"name": "a"}}],
            "tool_calls": [{"type": "function", "function": {"arguments": "b"}}],
        }));
        assert_eq!(
            paths(&decoded),
            vec!["tools[0].function.name", "tool_calls[0].function.arguments"]
        );
    }

    #[test_case("request" ; "request")]
    #[test_case("response" ; "response")]
    fn each_data_url_image_is_counted_and_never_scanned(input_type: &str) {
        let decoded = decode_json(json!({
            "input_type": input_type,
            "images": ["data:image/png;base64,AAAA", "https://example.com/a.png", "data:image/png;base64,BBBB"],
        }));
        assert!(decoded.units.is_empty());
        assert_eq!(decoded.encoded_values, 2);
    }

    #[test]
    fn images_is_ignored_when_structured_messages_exist() {
        let image = "data:image/png;base64,AAAA";
        let decoded = decode_json(json!({
            "input_type": "request",
            "structured_messages": [{"role": "user", "content": [
                {"type": "image_url", "image_url": {"url": image}},
            ]}],
            "images": [image],
        }));
        assert_eq!(decoded.encoded_values, 1, "the inline image counts once");
    }

    #[test]
    fn unknown_parts_are_counted() {
        let decoded = decode_json(json!({
            "input_type": "request",
            "structured_messages": [{"role": "user", "content": [
                {"type": "hologram"},
                {"type": "text", "text": "a"},
            ]}],
        }));
        assert_eq!(decoded.unknown_parts, 1);
        assert_eq!(
            paths(&decoded),
            vec!["structured_messages[0].content[1].text"]
        );
    }

    // --- Units ---

    #[test]
    fn each_top_level_entry_is_one_unit_with_absolute_offsets() {
        let raw = br#"{"input_type":"request","structured_messages":[{"role":"system","content":"aa"},{"role":"user","content":[{"type":"text","text":"bb"},{"type":"text","text":"cc"}]},{"role":"assistant"}],"tools":[{"type":"function","function":{"name":"dd"}}]}"#;
        let decoded = decode(raw).unwrap();

        // The assistant message keeps nothing, so it is no unit.
        assert_eq!(decoded.units.len(), 3);
        let contexts: Vec<Vec<&str>> = decoded
            .units
            .iter()
            .map(|u| u.iter().map(|f| f.context.as_str()).collect())
            .collect();
        assert_eq!(
            contexts,
            vec![
                vec!["structured_messages[0].content"],
                vec![
                    "structured_messages[1].content[0].text",
                    "structured_messages[1].content[1].text"
                ],
                vec!["tools[0].function.name"],
            ]
        );
        for fragment in decoded.units.iter().flatten() {
            let at = &raw[fragment.offset..fragment.offset + fragment.value.len()];
            assert_eq!(at, fragment.value.as_bytes(), "{}", fragment.context);
        }
    }
}
