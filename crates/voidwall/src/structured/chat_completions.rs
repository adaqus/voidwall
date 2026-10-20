//! Chat Completions shapes: which fields of a request, a response, a message,
//! a content part, a tool, and a tool call are scanned.
//!
//! The classifier walks a parsed document in document order and records one
//! decision per string leaf: the entry it belongs to, or skip. It never copies
//! a value: the fragments come from [`flatten_json`] over the same bytes, in the
//! same order, so offsets and key paths match `/v1/scan`, and [`Selection`]
//! pairs each fragment with its decision by position. No key path is matched,
//! so a key that holds `.` or `[` cannot be taken for another key.
//!
//! Every field rule is in the tables below. A key a table does not list is
//! unknown, and every string under it is scanned, so nothing unknown passes
//! unseen. Field reasoning: `voidwall-internal/research/chat-completions-field-map.md`.
//!
//! [`flatten_json`]: super::json::flatten_json

use serde_json::{Map, Value};

use super::OwnedContextFragment;
use crate::error::Error;

/// What the classifier does with one field.
#[derive(Debug, Clone, Copy)]
enum Rule {
    /// Keep every string at or under the field.
    Scan,
    /// Keep nothing.
    Skip,
    /// A known object: apply its field rules. A key it does not list is
    /// scanned. A value that is not an object is scanned.
    Object(&'static [Field]),
    /// An array of known objects. A value that is not an array is scanned.
    Each(&'static [Field]),
    /// A message: its field rules when its `role` is known, else every string
    /// in it is scanned. A value that is not an object is scanned.
    Message(&'static [Field]),
    /// A message's `content`: an array of content parts, or anything else
    /// (a string) scanned whole.
    Content,
    /// Base64 data: count a string and keep nothing. Any other value is
    /// scanned.
    Encoded,
    /// An `image_url.url`: a `data:` URL is base64 data, any other URL is
    /// skipped, because the bytes are not in the payload.
    ImageUrl,
    /// A top-level array cut into one entry per item, each classified by the
    /// rule. A value that is not an array is one entry, scanned. Used only in
    /// [`REQUEST`] and [`RESPONSE`].
    Entries(&'static Rule),
}

type Field = (&'static str, Rule);

/// The roles a message can carry. A message with another role, or none, is
/// scanned whole.
const KNOWN_ROLES: &[&str] = &[
    "developer",
    "system",
    "user",
    "assistant",
    "tool",
    "function",
];

/// The top-level fields of a request. `messages`, `tools`, and `functions`
/// are one entry per item; every other kept key is one entry.
const REQUEST: &[Field] = &[
    ("messages", Rule::Entries(&Rule::Message(MESSAGE))),
    ("tools", Rule::Entries(&Rule::Object(TOOL))),
    ("functions", Rule::Entries(&Rule::Object(FUNCTION))),
    (
        "response_format",
        Rule::Object(&[("type", Rule::Skip), ("json_schema", Rule::Scan)]),
    ),
    ("prediction", Rule::Object(&[("content", Rule::Content)])),
    ("metadata", Rule::Scan),
    ("safety_identifier", Rule::Scan),
    ("user", Rule::Scan),
    ("prompt_cache_key", Rule::Scan),
    (
        "web_search_options",
        Rule::Object(&[("user_location", Rule::Scan)]),
    ),
    ("model", Rule::Skip),
    ("stop", Rule::Skip),
    ("tool_choice", Rule::Skip),
    ("function_call", Rule::Skip),
    ("modalities", Rule::Skip),
    ("audio", Rule::Skip),
    ("stream", Rule::Skip),
    ("stream_options", Rule::Skip),
    ("temperature", Rule::Skip),
    ("top_p", Rule::Skip),
    ("n", Rule::Skip),
    ("seed", Rule::Skip),
    ("max_tokens", Rule::Skip),
    ("max_completion_tokens", Rule::Skip),
    ("logit_bias", Rule::Skip),
    ("logprobs", Rule::Skip),
    ("top_logprobs", Rule::Skip),
    ("frequency_penalty", Rule::Skip),
    ("presence_penalty", Rule::Skip),
    ("parallel_tool_calls", Rule::Skip),
    ("reasoning_effort", Rule::Skip),
    ("verbosity", Rule::Skip),
    ("service_tier", Rule::Skip),
    ("store", Rule::Skip),
    ("moderation", Rule::Skip),
    ("prompt_cache_options", Rule::Skip),
    ("prompt_cache_retention", Rule::Skip),
];

/// The top-level fields of a response. `choices` is one entry per choice;
/// every other kept key, such as an `error` object, is one entry.
const RESPONSE: &[Field] = &[
    ("choices", Rule::Entries(&Rule::Object(CHOICE))),
    ("id", Rule::Skip),
    ("object", Rule::Skip),
    ("created", Rule::Skip),
    ("model", Rule::Skip),
    ("system_fingerprint", Rule::Skip),
    ("service_tier", Rule::Skip),
    ("usage", Rule::Skip),
];

const CHOICE: &[Field] = &[
    ("index", Rule::Skip),
    ("finish_reason", Rule::Skip),
    ("logprobs", Rule::Skip),
    ("message", Rule::Message(RESPONSE_MESSAGE)),
];

const MESSAGE: &[Field] = &[
    ("role", Rule::Skip),
    ("content", Rule::Content),
    ("name", Rule::Scan),
    ("refusal", Rule::Scan),
    ("tool_calls", Rule::Each(TOOL_CALL)),
    ("function_call", Rule::Object(FUNCTION_CALL)),
    ("tool_call_id", Rule::Skip),
    ("audio", Rule::Object(&[("id", Rule::Skip)])),
];

/// [`MESSAGE`], with the fields only a response message carries:
/// `annotations`, and the audio output.
const RESPONSE_MESSAGE: &[Field] = &[
    ("role", Rule::Skip),
    ("content", Rule::Content),
    ("name", Rule::Scan),
    ("refusal", Rule::Scan),
    ("tool_calls", Rule::Each(TOOL_CALL)),
    ("function_call", Rule::Object(FUNCTION_CALL)),
    ("tool_call_id", Rule::Skip),
    ("annotations", Rule::Scan),
    (
        "audio",
        Rule::Object(&[
            ("id", Rule::Skip),
            ("expires_at", Rule::Skip),
            ("data", Rule::Encoded),
            ("transcript", Rule::Scan),
        ]),
    ),
];

const FUNCTION_CALL: &[Field] = &[("name", Rule::Scan), ("arguments", Rule::Scan)];

/// One entry of the deprecated `functions` array.
const FUNCTION: &[Field] = &[
    ("name", Rule::Scan),
    ("description", Rule::Scan),
    ("parameters", Rule::Scan),
];

const TOOL_CALL: &[Field] = &[
    ("id", Rule::Skip),
    ("type", Rule::Skip),
    ("function", Rule::Object(FUNCTION_CALL)),
    (
        "custom",
        Rule::Object(&[("name", Rule::Scan), ("input", Rule::Scan)]),
    ),
];

const TOOL: &[Field] = &[
    ("type", Rule::Skip),
    (
        "function",
        Rule::Object(&[
            ("name", Rule::Scan),
            ("description", Rule::Scan),
            ("parameters", Rule::Scan),
            ("strict", Rule::Skip),
        ]),
    ),
    (
        "custom",
        Rule::Object(&[
            ("name", Rule::Scan),
            ("description", Rule::Scan),
            (
                "format",
                Rule::Object(&[
                    ("type", Rule::Skip),
                    (
                        "grammar",
                        Rule::Object(&[("definition", Rule::Scan), ("syntax", Rule::Skip)]),
                    ),
                ]),
            ),
        ]),
    ),
];

/// The content part types, each with its field rules. A part of another type
/// is unscannable.
const PARTS: &[(&str, &[Field])] = &[
    ("text", &[("type", Rule::Skip), ("text", Rule::Scan)]),
    ("refusal", &[("type", Rule::Skip), ("refusal", Rule::Scan)]),
    (
        "image_url",
        &[
            ("type", Rule::Skip),
            (
                "image_url",
                Rule::Object(&[("url", Rule::ImageUrl), ("detail", Rule::Skip)]),
            ),
        ],
    ),
    (
        "input_audio",
        &[
            ("type", Rule::Skip),
            (
                "input_audio",
                Rule::Object(&[("data", Rule::Encoded), ("format", Rule::Skip)]),
            ),
        ],
    ),
    (
        "file",
        &[
            ("type", Rule::Skip),
            (
                "file",
                Rule::Object(&[
                    ("file_data", Rule::Encoded),
                    ("file_id", Rule::Skip),
                    ("filename", Rule::Scan),
                ]),
            ),
        ],
    ),
];

/// A decoded body: one fragment group per scanned entry, and what was left
/// out. `Debug` is not derived, because the fragments hold the scanned text.
pub struct Decoded {
    /// One group per entry that has a kept fragment. Each group becomes one
    /// body unit.
    pub units: Vec<Vec<OwnedContextFragment>>,
    /// Content parts of an unknown type. They are not in `units`.
    pub unknown_parts: usize,
    /// Base64 values left out without a scan.
    pub encoded_values: usize,
}

/// One decision per string leaf of the classified document, in document
/// order, and what was left out.
///
/// A caller classifies the whole document, top-level key by top-level key in
/// document order, and hands every key it does not read to [`Selection::skip`],
/// so the decisions line up with the fragments of [`flatten_json`].
///
/// [`flatten_json`]: super::json::flatten_json
#[derive(Debug, Default)]
pub struct Selection {
    /// The entry each string leaf belongs to, or `None` when it is skipped.
    leaves: Vec<Option<usize>>,
    /// Entries opened so far. An entry that keeps no leaf yields no unit.
    entries: usize,
    unknown_parts: usize,
    encoded_values: usize,
}

impl Selection {
    pub fn new() -> Self {
        Self::default()
    }

    /// Classify a Chat Completions request object.
    pub fn request(&mut self, request: &Map<String, Value>) {
        self.top_level(REQUEST, request);
    }

    /// Classify a Chat Completions response object.
    pub fn response(&mut self, response: &Map<String, Value>) {
        self.top_level(RESPONSE, response);
    }

    /// Classify one message as a new entry.
    pub fn message(&mut self, message: &Value) {
        self.entry(Rule::Message(MESSAGE), message);
    }

    /// Classify the `delta` of a stream chunk as a new entry, by the field
    /// rules of a response message. A delta carries its role in the first
    /// chunk only, so the role is not checked.
    pub fn delta(&mut self, delta: &Value) {
        self.entry(Rule::Object(RESPONSE_MESSAGE), delta);
    }

    /// Classify one tool definition as a new entry.
    pub fn tool(&mut self, tool: &Value) {
        self.entry(Rule::Object(TOOL), tool);
    }

    /// Classify one tool call as a new entry.
    pub fn tool_call(&mut self, call: &Value) {
        self.entry(Rule::Object(TOOL_CALL), call);
    }

    /// Keep every string of `text`, as a new entry.
    pub fn text(&mut self, text: &Value) {
        self.entry(Rule::Scan, text);
    }

    /// Count an image URL as base64 data when it is a `data:` URL. Any other
    /// URL is skipped, because the bytes are not in the payload. Nothing is
    /// kept.
    pub fn image_url(&mut self, url: &Value) {
        if url.as_str().is_some_and(is_data_url) {
            self.encoded_values += 1;
        }
        self.skip(url);
    }

    /// Keep no string of `value`.
    pub fn skip(&mut self, value: &Value) {
        self.mark(None, value);
    }

    /// Content parts whose type is not known. They are never kept.
    pub fn unknown_parts(&self) -> usize {
        self.unknown_parts
    }

    /// Base64 values left out without a scan.
    pub fn encoded_values(&self) -> usize {
        self.encoded_values
    }

    /// Keep the selected fragments, grouped by entry in classification order.
    /// An entry with no kept fragment yields no group.
    ///
    /// The fragments must be the [`flatten_json`] output of the document this
    /// selection classified. A fragment count that differs from the number of
    /// string leaves classified is [`Error::Scanner`]: the pairing would be
    /// wrong, so nothing is kept.
    ///
    /// [`flatten_json`]: super::json::flatten_json
    pub fn into_unit_fragments(
        self,
        fragments: Vec<OwnedContextFragment>,
    ) -> Result<Vec<Vec<OwnedContextFragment>>, Error> {
        if fragments.len() != self.leaves.len() {
            return Err(Error::Scanner(format!(
                "classified {} string leaves, the flattener found {}",
                self.leaves.len(),
                fragments.len()
            )));
        }
        let mut units = vec![Vec::new(); self.entries];
        for (fragment, leaf) in fragments.into_iter().zip(self.leaves) {
            if let Some(entry) = leaf {
                units[entry].push(fragment);
            }
        }
        units.retain(|u| !u.is_empty());
        Ok(units)
    }

    /// [`Selection::into_unit_fragments`], with the counts of what was left
    /// out.
    pub fn into_decoded(self, fragments: Vec<OwnedContextFragment>) -> Result<Decoded, Error> {
        let (unknown_parts, encoded_values) = (self.unknown_parts, self.encoded_values);
        Ok(Decoded {
            units: self.into_unit_fragments(fragments)?,
            unknown_parts,
            encoded_values,
        })
    }

    fn top_level(&mut self, fields: &[Field], map: &Map<String, Value>) {
        for (key, value) in map {
            match (rule_for(fields, key), value) {
                (Rule::Skip, _) => self.skip(value),
                (Rule::Entries(rule), Value::Array(items)) => {
                    for item in items {
                        self.entry(*rule, item);
                    }
                }
                (rule, _) => self.entry(rule, value),
            }
        }
    }

    fn entry(&mut self, rule: Rule, value: &Value) {
        let entry = self.entries;
        self.entries += 1;
        self.apply(entry, rule, value);
    }

    fn apply(&mut self, entry: usize, rule: Rule, value: &Value) {
        match (rule, value) {
            (Rule::Skip, _) => self.skip(value),
            (Rule::Object(fields), Value::Object(map)) => self.fields(entry, fields, map),
            (Rule::Message(fields), Value::Object(map)) if has_known_role(map) => {
                self.fields(entry, fields, map)
            }
            (Rule::Each(fields), Value::Array(items)) => {
                for item in items {
                    self.apply(entry, Rule::Object(fields), item);
                }
            }
            (Rule::Content, Value::Array(parts)) => {
                for part in parts {
                    self.part(entry, part);
                }
            }
            (Rule::Encoded, Value::String(_)) => {
                self.encoded_values += 1;
                self.leaves.push(None);
            }
            (Rule::ImageUrl, Value::String(url)) => {
                if is_data_url(url) {
                    self.encoded_values += 1;
                }
                self.leaves.push(None);
            }
            // `Scan`, and any value whose shape its rule does not expect.
            _ => self.mark(Some(entry), value),
        }
    }

    fn fields(&mut self, entry: usize, fields: &[Field], map: &Map<String, Value>) {
        for (key, value) in map {
            self.apply(entry, rule_for(fields, key), value);
        }
    }

    fn part(&mut self, entry: usize, part: &Value) {
        let fields = part
            .get("type")
            .and_then(Value::as_str)
            .and_then(|t| PARTS.iter().find(|(name, _)| *name == t))
            .map(|&(_, fields)| fields);
        match (fields, part) {
            (Some(fields), Value::Object(map)) => self.fields(entry, fields, map),
            _ => {
                self.unknown_parts += 1;
                self.skip(part);
            }
        }
    }

    /// Record `leaf` for every string at or under `value`, in document order.
    fn mark(&mut self, leaf: Option<usize>, value: &Value) {
        match value {
            Value::String(_) => self.leaves.push(leaf),
            Value::Array(items) => items.iter().for_each(|item| self.mark(leaf, item)),
            Value::Object(map) => map.values().for_each(|item| self.mark(leaf, item)),
            _ => {}
        }
    }
}

/// The rule a table gives `key`. A key the table does not list is scanned.
fn rule_for(fields: &[Field], key: &str) -> Rule {
    fields
        .iter()
        .find(|(name, _)| *name == key)
        .map_or(Rule::Scan, |&(_, rule)| rule)
}

fn has_known_role(message: &Map<String, Value>) -> bool {
    message
        .get("role")
        .and_then(Value::as_str)
        .is_some_and(|r| KNOWN_ROLES.contains(&r))
}

fn is_data_url(url: &str) -> bool {
    url.get(..5)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("data:"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structured::json::flatten_json;
    use serde_json::json;
    use test_case::test_case;

    #[derive(Clone, Copy)]
    enum Shape {
        Message,
        Tool,
        ToolCall,
    }

    /// Classify `entry` as the only element of `array` and return the kept
    /// paths, with the unknown-part and encoded-data counts.
    fn classify(shape: Shape, array: &str, entry: Value) -> (Vec<String>, usize, usize) {
        let mut doc = Map::new();
        doc.insert(array.to_string(), json!([entry.clone()]));
        let raw = serde_json::to_vec(&doc).unwrap();
        let mut selection = Selection::new();
        match shape {
            Shape::Message => selection.message(&entry),
            Shape::Tool => selection.tool(&entry),
            Shape::ToolCall => selection.tool_call(&entry),
        }
        let (unknown, encoded) = (selection.unknown_parts(), selection.encoded_values());
        let paths = selection
            .into_unit_fragments(flatten_json(&raw).unwrap())
            .unwrap()
            .into_iter()
            .flatten()
            .map(|f| f.context)
            .collect();
        (paths, unknown, encoded)
    }

    fn kept(shape: Shape, entry: Value) -> Vec<String> {
        let array = match shape {
            Shape::Message => "structured_messages",
            Shape::Tool => "tools",
            Shape::ToolCall => "tool_calls",
        };
        classify(shape, array, entry).0
    }

    fn call(fields: Value) -> Value {
        json!({ "id": "call_1", "type": "function", "function": fields })
    }

    // --- The request-side list: each field is scanned ---

    #[test_case(Shape::Message, json!({"role": "user", "content": "x"}), "structured_messages[0].content" ; "content string")]
    #[test_case(Shape::Message, json!({"role": "user", "content": [{"type": "text", "text": "x"}]}), "structured_messages[0].content[0].text" ; "text part")]
    #[test_case(Shape::Message, json!({"role": "assistant", "content": [{"type": "refusal", "refusal": "x"}]}), "structured_messages[0].content[0].refusal" ; "refusal part")]
    #[test_case(Shape::Message, json!({"role": "user", "content": [{"type": "file", "file": {"filename": "x"}}]}), "structured_messages[0].content[0].file.filename" ; "file part filename")]
    #[test_case(Shape::Message, json!({"role": "user", "name": "x"}), "structured_messages[0].name" ; "name")]
    #[test_case(Shape::Message, json!({"role": "assistant", "refusal": "x"}), "structured_messages[0].refusal" ; "refusal")]
    #[test_case(Shape::Message, json!({"role": "assistant", "tool_calls": [call(json!({"name": "x"}))]}), "structured_messages[0].tool_calls[0].function.name" ; "message tool call function name")]
    #[test_case(Shape::Message, json!({"role": "assistant", "tool_calls": [call(json!({"arguments": "x"}))]}), "structured_messages[0].tool_calls[0].function.arguments" ; "message tool call function arguments")]
    #[test_case(Shape::Message, json!({"role": "assistant", "tool_calls": [{"type": "custom", "custom": {"name": "x"}}]}), "structured_messages[0].tool_calls[0].custom.name" ; "message tool call custom name")]
    #[test_case(Shape::Message, json!({"role": "assistant", "tool_calls": [{"type": "custom", "custom": {"input": "x"}}]}), "structured_messages[0].tool_calls[0].custom.input" ; "message tool call custom input")]
    #[test_case(Shape::Message, json!({"role": "assistant", "function_call": {"name": "x"}}), "structured_messages[0].function_call.name" ; "function call name")]
    #[test_case(Shape::Message, json!({"role": "assistant", "function_call": {"arguments": "x"}}), "structured_messages[0].function_call.arguments" ; "function call arguments")]
    #[test_case(Shape::Tool, json!({"type": "function", "function": {"name": "x"}}), "tools[0].function.name" ; "tool function name")]
    #[test_case(Shape::Tool, json!({"type": "function", "function": {"description": "x"}}), "tools[0].function.description" ; "tool function description")]
    #[test_case(Shape::Tool, json!({"type": "function", "function": {"parameters": {"properties": {"a": {"description": "x"}}}}}), "tools[0].function.parameters.properties.a.description" ; "tool function parameters string")]
    #[test_case(Shape::Tool, json!({"type": "custom", "custom": {"name": "x"}}), "tools[0].custom.name" ; "tool custom name")]
    #[test_case(Shape::Tool, json!({"type": "custom", "custom": {"description": "x"}}), "tools[0].custom.description" ; "tool custom description")]
    #[test_case(Shape::Tool, json!({"type": "custom", "custom": {"format": {"type": "grammar", "grammar": {"definition": "x", "syntax": "lark"}}}}), "tools[0].custom.format.grammar.definition" ; "tool custom grammar definition")]
    #[test_case(Shape::ToolCall, call(json!({"name": "x"})), "tool_calls[0].function.name" ; "tool call function name")]
    #[test_case(Shape::ToolCall, call(json!({"arguments": "x"})), "tool_calls[0].function.arguments" ; "tool call function arguments")]
    #[test_case(Shape::ToolCall, json!({"type": "custom", "custom": {"name": "x"}}), "tool_calls[0].custom.name" ; "tool call custom name")]
    #[test_case(Shape::ToolCall, json!({"type": "custom", "custom": {"input": "x"}}), "tool_calls[0].custom.input" ; "tool call custom input")]
    fn a_listed_field_is_scanned(shape: Shape, entry: Value, path: &str) {
        assert_eq!(kept(shape, entry), vec![path.to_string()]);
    }

    // --- The skip list: each field is left out ---

    #[test_case(Shape::Message, json!({"role": "user"}) ; "role")]
    #[test_case(Shape::Message, json!({"role": "tool", "tool_call_id": "call_1"}) ; "tool call id")]
    #[test_case(Shape::Message, json!({"role": "assistant", "tool_calls": [{"id": "call_1", "type": "function"}]}) ; "message tool call id and type")]
    #[test_case(Shape::ToolCall, json!({"id": "call_1", "type": "function"}) ; "tool call id and type")]
    #[test_case(Shape::Message, json!({"role": "assistant", "audio": {"id": "audio_1"}}) ; "audio id")]
    #[test_case(Shape::Message, json!({"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://example.com/a.png", "detail": "high"}}]}) ; "image url detail and https url")]
    #[test_case(Shape::Message, json!({"role": "user", "content": [{"type": "file", "file": {"file_id": "file_1"}}]}) ; "file id")]
    #[test_case(Shape::Tool, json!({"type": "function", "function": {"strict": true}}) ; "function strict")]
    #[test_case(Shape::Tool, json!({"type": "code_interpreter"}) ; "a tool with only a type")]
    fn a_skipped_field_is_left_out(shape: Shape, entry: Value) {
        assert_eq!(kept(shape, entry), Vec::<String>::new());
    }

    // --- The generic rule ---

    #[test_case(Shape::Message, json!({"role": "assistant", "reasoning_content": "x"}), "structured_messages[0].reasoning_content" ; "unknown message field")]
    #[test_case(Shape::Tool, json!({"type": "function", "extra": {"note": "x"}}), "tools[0].extra.note" ; "unknown tool field")]
    #[test_case(Shape::ToolCall, json!({"type": "function", "function": {"name": "f", "thought": "x"}}), "tool_calls[0].function.thought" ; "unknown nested tool call field")]
    fn an_unknown_field_is_scanned(shape: Shape, entry: Value, path: &str) {
        assert!(kept(shape, entry).contains(&path.to_string()));
    }

    #[test_case(json!({"role": "narrator", "content": "x", "tool_call_id": "y"}) ; "unknown role")]
    #[test_case(json!({"content": "x", "tool_call_id": "y"}) ; "no role")]
    fn a_message_with_an_unknown_role_is_scanned_whole(message: Value) {
        let mut paths = kept(Shape::Message, message);
        paths.sort();
        assert!(paths.contains(&"structured_messages[0].content".to_string()));
        assert!(paths.contains(&"structured_messages[0].tool_call_id".to_string()));
    }

    #[test_case(json!({"type": "hologram", "text": "x"}) ; "unknown type")]
    #[test_case(json!({"text": "x"}) ; "no type")]
    #[test_case(json!("x") ; "not an object")]
    fn an_unknown_part_is_counted_and_never_kept(part: Value) {
        let message = json!({"role": "user", "content": [part, {"type": "text", "text": "y"}]});
        let (paths, unknown, _) = classify(Shape::Message, "structured_messages", message);
        assert_eq!(unknown, 1);
        assert_eq!(paths, vec!["structured_messages[0].content[1].text"]);
    }

    // --- Encoded data ---

    #[test_case(json!({"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}) ; "image data url")]
    #[test_case(json!({"type": "image_url", "image_url": {"url": "DATA:image/png;base64,AAAA"}}) ; "image data url upper case")]
    #[test_case(json!({"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}}) ; "input audio data")]
    #[test_case(json!({"type": "file", "file": {"file_data": "AAAA"}}) ; "file data")]
    fn encoded_data_is_counted_and_never_kept(part: Value) {
        let message = json!({"role": "user", "content": [part]});
        let (paths, unknown, encoded) = classify(Shape::Message, "structured_messages", message);
        assert_eq!((paths.len(), unknown, encoded), (0, 0, 1));
    }

    #[test]
    fn an_https_image_url_is_not_counted() {
        let message = json!({"role": "user", "content": [
            {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}}
        ]});
        let (_, _, encoded) = classify(Shape::Message, "structured_messages", message);
        assert_eq!(encoded, 0);
    }

    // --- Leaf-order pairing ---

    /// Classify `doc` as a request or a response and return the kept
    /// `(path, value)` pairs of each unit, with the unknown-part and
    /// encoded-data counts.
    fn top(doc: &Value, response: bool) -> (Vec<Vec<(String, String)>>, usize, usize) {
        let raw = serde_json::to_vec(doc).unwrap();
        let mut selection = Selection::new();
        let map = doc.as_object().unwrap();
        if response {
            selection.response(map);
        } else {
            selection.request(map);
        }
        let (unknown, encoded) = (selection.unknown_parts(), selection.encoded_values());
        let units = selection
            .into_unit_fragments(flatten_json(&raw).unwrap())
            .unwrap()
            .into_iter()
            .map(|u| u.into_iter().map(|f| (f.context, f.value)).collect())
            .collect();
        (units, unknown, encoded)
    }

    fn paths(units: &[Vec<(String, String)>]) -> Vec<&str> {
        units.iter().flatten().map(|(p, _)| p.as_str()).collect()
    }

    #[test]
    fn a_top_level_key_and_a_message_are_two_units() {
        let doc = json!({
            "messages": [{"role": "user", "content": "a"}],
            "metadata": {"k": "b"},
        });
        let (units, _, _) = top(&doc, false);
        assert_eq!(
            units,
            vec![
                vec![("messages[0].content".to_string(), "a".to_string())],
                vec![("metadata.k".to_string(), "b".to_string())],
            ]
        );
    }

    #[test]
    fn a_top_level_key_that_holds_a_dot_or_a_bracket_is_scanned() {
        let doc = json!({
            "messages": [],
            "a.b": "first",
            "x[0].y": {"z": "second"},
        });
        let (units, _, _) = top(&doc, false);
        let values: Vec<&str> = units.iter().flatten().map(|(_, v)| v.as_str()).collect();
        assert_eq!(values, vec!["first", "second"]);
    }

    #[test]
    fn a_leaf_count_that_differs_from_the_fragments_is_a_scanner_error() {
        let mut selection = Selection::new();
        selection.text(&json!("x"));
        assert!(matches!(
            selection.into_unit_fragments(Vec::new()),
            Err(Error::Scanner(_))
        ));
    }

    // --- The request: each listed field is scanned ---

    /// A request with a skipped `model` first and one clean message, then
    /// `key` set to `value`.
    fn request_with(key: &str, value: Value) -> Value {
        let mut doc = json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]});
        doc[key] = value;
        doc
    }

    #[test_case("messages", json!([{"role": "system", "content": "x"}]), &["messages[0].content"] ; "system message")]
    #[test_case("messages", json!([{"role": "assistant", "tool_calls": [{"id": "c", "type": "function", "function": {"arguments": "x"}}]}]), &["messages[0].tool_calls[0].function.arguments"] ; "replayed tool call")]
    #[test_case("tools", json!([{"type": "function", "function": {"parameters": {"properties": {"a": {"description": "x"}}}}}]), &["tools[0].function.parameters.properties.a.description"] ; "tool parameter schema")]
    #[test_case("functions", json!([{"name": "x", "description": "y", "parameters": {"properties": {"a": {"description": "z"}}}}]), &["functions[0].name", "functions[0].description", "functions[0].parameters.properties.a.description"] ; "deprecated functions")]
    #[test_case("response_format", json!({"type": "json_schema", "json_schema": {"name": "x", "schema": {"description": "y"}}}), &["response_format.json_schema.name", "response_format.json_schema.schema.description"] ; "response format schema")]
    #[test_case("prediction", json!({"content": "x"}), &["prediction.content"] ; "prediction content string")]
    #[test_case("prediction", json!({"content": [{"type": "text", "text": "x"}]}), &["prediction.content[0].text"] ; "prediction content parts")]
    #[test_case("metadata", json!({"k": "x"}), &["metadata.k"] ; "metadata")]
    #[test_case("safety_identifier", json!("x"), &["safety_identifier"] ; "safety identifier")]
    #[test_case("user", json!("x"), &["user"] ; "user")]
    #[test_case("prompt_cache_key", json!("x"), &["prompt_cache_key"] ; "prompt cache key")]
    #[test_case("web_search_options", json!({"user_location": {"approximate": {"city": "x"}}}), &["web_search_options.user_location.approximate.city"] ; "user location")]
    #[test_case("chat_template_kwargs", json!({"k": "x"}), &["chat_template_kwargs.k"] ; "unknown top level key")]
    fn a_listed_request_field_is_scanned(key: &str, value: Value, expected: &[&str]) {
        let (units, _, _) = top(&request_with(key, value), false);
        let mut want = vec!["messages[0].content"];
        if key == "messages" {
            want.clear();
        }
        want.extend_from_slice(expected);
        assert_eq!(paths(&units), want);
    }

    #[test_case("model", json!("x") ; "model")]
    #[test_case("stop", json!(["x"]) ; "stop")]
    #[test_case("tool_choice", json!({"type": "function", "function": {"name": "x"}}) ; "tool choice")]
    #[test_case("function_call", json!({"name": "x"}) ; "top level function call")]
    #[test_case("modalities", json!(["text"]) ; "modalities")]
    #[test_case("audio", json!({"voice": "x", "format": "wav"}) ; "audio")]
    #[test_case("stream", json!("x") ; "stream")]
    #[test_case("stream_options", json!({"include_usage": "x"}) ; "stream options")]
    #[test_case("response_format", json!({"type": "json_object"}) ; "response format type")]
    #[test_case("temperature", json!("x") ; "temperature")]
    #[test_case("top_p", json!("x") ; "top p")]
    #[test_case("n", json!("x") ; "n")]
    #[test_case("seed", json!("x") ; "seed")]
    #[test_case("max_tokens", json!("x") ; "max tokens")]
    #[test_case("max_completion_tokens", json!("x") ; "max completion tokens")]
    #[test_case("logit_bias", json!({"50256": "x"}) ; "logit bias")]
    #[test_case("logprobs", json!("x") ; "logprobs")]
    #[test_case("top_logprobs", json!("x") ; "top logprobs")]
    #[test_case("frequency_penalty", json!("x") ; "frequency penalty")]
    #[test_case("presence_penalty", json!("x") ; "presence penalty")]
    #[test_case("parallel_tool_calls", json!("x") ; "parallel tool calls")]
    #[test_case("reasoning_effort", json!("x") ; "reasoning effort")]
    #[test_case("verbosity", json!("x") ; "verbosity")]
    #[test_case("service_tier", json!("x") ; "service tier")]
    #[test_case("store", json!("x") ; "store")]
    #[test_case("moderation", json!("x") ; "moderation")]
    #[test_case("prompt_cache_options", json!({"k": "x"}) ; "prompt cache options")]
    #[test_case("prompt_cache_retention", json!("x") ; "prompt cache retention")]
    fn a_skipped_request_field_is_left_out(key: &str, value: Value) {
        let (units, _, _) = top(&request_with(key, value), false);
        assert_eq!(paths(&units), vec!["messages[0].content"]);
    }

    #[test]
    fn an_unknown_part_in_prediction_is_counted_and_never_kept() {
        let doc = request_with(
            "prediction",
            json!({"content": [{"type": "hologram", "text": "x"}, {"type": "text", "text": "y"}]}),
        );
        let (units, unknown, _) = top(&doc, false);
        assert_eq!(unknown, 1);
        assert_eq!(
            paths(&units),
            vec!["messages[0].content", "prediction.content[1].text"]
        );
    }

    // --- The response ---

    fn response_with(message: Value) -> Value {
        json!({
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 1,
            "model": "m",
            "system_fingerprint": "fp",
            "service_tier": "default",
            "choices": [{"index": 0, "finish_reason": "stop", "message": message}],
            "usage": {"prompt_tokens": 1, "note": "x"},
        })
    }

    #[test_case(json!({"role": "assistant", "content": "x"}), "choices[0].message.content" ; "content")]
    #[test_case(json!({"role": "assistant", "tool_calls": [{"id": "c", "type": "function", "function": {"arguments": "x"}}]}), "choices[0].message.tool_calls[0].function.arguments" ; "tool calls")]
    #[test_case(json!({"role": "assistant", "function_call": {"arguments": "x"}}), "choices[0].message.function_call.arguments" ; "function call")]
    #[test_case(json!({"role": "assistant", "refusal": "x"}), "choices[0].message.refusal" ; "refusal")]
    #[test_case(json!({"role": "assistant", "annotations": [{"url_citation": {"title": "x"}}]}), "choices[0].message.annotations[0].url_citation.title" ; "annotations")]
    #[test_case(json!({"role": "assistant", "audio": {"id": "a", "expires_at": 1, "transcript": "x"}}), "choices[0].message.audio.transcript" ; "audio transcript")]
    #[test_case(json!({"role": "assistant", "reasoning_content": "x"}), "choices[0].message.reasoning_content" ; "reasoning trace")]
    fn a_listed_response_field_is_scanned(message: Value, path: &str) {
        let (units, _, _) = top(&response_with(message), true);
        assert_eq!(paths(&units), vec![path]);
    }

    #[test]
    fn audio_data_in_a_response_is_counted_and_never_kept() {
        let message = json!({"role": "assistant", "audio": {"id": "a", "data": "AAAA"}});
        let (units, unknown, encoded) = top(&response_with(message), true);
        assert_eq!((paths(&units).len(), unknown, encoded), (0, 0, 1));
    }

    #[test]
    fn logprobs_and_the_metadata_fields_are_left_out() {
        let mut doc =
            response_with(json!({"role": "assistant", "audio": {"id": "a", "expires_at": "x"}}));
        doc["choices"][0]["logprobs"] = json!({"content": [{"token": "x", "top_logprobs": []}]});
        doc["usage"] = json!({"note": "x"});
        let (units, _, _) = top(&doc, true);
        assert!(units.is_empty(), "kept: {:?}", paths(&units));
    }

    #[test_case(json!({"error": {"message": "x", "type": "invalid_request"}}), &["error.message", "error.type"] ; "an error object")]
    #[test_case(json!({"error": "x"}), &["error"] ; "a flat error string")]
    #[test_case(json!({"choices": [], "stats": {"note": "x"}}), &["stats.note"] ; "a vendor key")]
    fn an_unknown_top_level_response_key_is_scanned(doc: Value, expected: &[&str]) {
        let (units, _, _) = top(&doc, true);
        assert_eq!(paths(&units), expected);
    }

    #[test]
    fn a_response_message_with_an_unknown_role_is_scanned_whole() {
        let message = json!({"role": "narrator", "content": "x", "tool_call_id": "y"});
        let (units, _, _) = top(&response_with(message), true);
        assert_eq!(
            paths(&units),
            vec![
                "choices[0].message.role",
                "choices[0].message.content",
                "choices[0].message.tool_call_id"
            ]
        );
    }

    #[test]
    fn each_choice_is_one_unit() {
        let doc = json!({"choices": [
            {"message": {"role": "assistant", "content": "a"}},
            {"message": {"role": "assistant", "content": "b"}},
        ]});
        let (units, _, _) = top(&doc, true);
        assert_eq!(units.len(), 2);
    }

    /// The response message table extends the request one: every field rule
    /// of a request message also holds in a response message.
    #[test]
    fn the_response_message_table_holds_every_message_field() {
        for (key, _) in MESSAGE {
            assert!(
                RESPONSE_MESSAGE.iter().any(|(k, _)| k == key),
                "{key} is missing from RESPONSE_MESSAGE"
            );
        }
    }
}
