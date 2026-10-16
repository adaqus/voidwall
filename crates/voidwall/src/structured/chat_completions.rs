//! Chat Completions message shapes: which fields of a message, a content part,
//! a tool, and a tool call are scanned.
//!
//! The classifier walks a parsed entry and records the key paths to keep. It
//! never copies a value: the fragments come from [`flatten_json`] over the same
//! bytes, so offsets and key paths match `/v1/scan`, and [`Selection`] picks the
//! kept ones out. Both sides build a path with [`push_path_segment`].
//!
//! Every field rule is in the tables below. A key a table does not list is
//! unknown, and every string under it is scanned, so nothing unknown passes
//! unseen. Field reasoning: `voidwall-internal/research/chat-completions-field-map.md`.
//!
//! [`flatten_json`]: super::json::flatten_json

use std::collections::HashMap;

use serde_json::{Map, Value};

use super::OwnedContextFragment;
use super::json::{PathSegment, push_path_segment};

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
    /// A message's `content`: an array of content parts, or anything else
    /// (a string) scanned whole.
    Content,
    /// Base64 data: count a string and keep nothing. Any other value is
    /// scanned.
    Encoded,
    /// An `image_url.url`: a `data:` URL is base64 data, any other URL is
    /// skipped, because the bytes are not in the payload.
    ImageUrl,
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

const FUNCTION_CALL: &[Field] = &[("name", Rule::Scan), ("arguments", Rule::Scan)];

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

/// One top-level entry with something kept: its root path, such as
/// `structured_messages[2]`, and the paths under it to keep.
#[derive(Debug)]
struct Entry {
    root: String,
    kept: Vec<String>,
}

/// The key paths to scan, entry by entry, and what was left out.
#[derive(Debug, Default)]
pub struct Selection {
    entries: Vec<Entry>,
    unknown_parts: usize,
    encoded_values: usize,
}

impl Selection {
    pub fn new() -> Self {
        Self::default()
    }

    /// Classify `array[index]` as a message.
    pub fn message(&mut self, array: &str, index: usize, message: &Value) {
        let role = message.get("role").and_then(Value::as_str);
        let rule = if role.is_some_and(|r| KNOWN_ROLES.contains(&r)) {
            Rule::Object(MESSAGE)
        } else {
            Rule::Scan
        };
        self.entry(array, index, rule, message);
    }

    /// Classify `array[index]` as a tool definition.
    pub fn tool(&mut self, array: &str, index: usize, tool: &Value) {
        self.entry(array, index, Rule::Object(TOOL), tool);
    }

    /// Classify `array[index]` as a tool call.
    pub fn tool_call(&mut self, array: &str, index: usize, call: &Value) {
        self.entry(array, index, Rule::Object(TOOL_CALL), call);
    }

    /// Keep every string of `array[index]`.
    pub fn text(&mut self, array: &str, index: usize, text: &Value) {
        self.entry(array, index, Rule::Scan, text);
    }

    /// Count an image URL as base64 data when it is a `data:` URL. Any other
    /// URL is skipped, because the bytes are not in the payload.
    pub fn image_url(&mut self, url: &Value) {
        if url.as_str().is_some_and(is_data_url) {
            self.encoded_values += 1;
        }
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
    pub fn into_unit_fragments(
        self,
        fragments: Vec<OwnedContextFragment>,
    ) -> Vec<Vec<OwnedContextFragment>> {
        let index: HashMap<&str, usize> = self
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| (e.root.as_str(), i))
            .collect();
        let mut units = vec![Vec::new(); self.entries.len()];
        for fragment in fragments {
            let Some(&i) = entry_root(&fragment.context).and_then(|r| index.get(r)) else {
                continue;
            };
            if self.entries[i]
                .kept
                .iter()
                .any(|kept| is_at_or_under(&fragment.context, kept))
            {
                units[i].push(fragment);
            }
        }
        units.retain(|u| !u.is_empty());
        units
    }

    fn entry(&mut self, array: &str, index: usize, rule: Rule, value: &Value) {
        let mut root = String::new();
        push_path_segment(&mut root, PathSegment::Key(array));
        push_path_segment(&mut root, PathSegment::Index(index));
        let mut kept = Vec::new();
        self.apply(&mut kept, root.clone(), rule, value);
        if !kept.is_empty() {
            self.entries.push(Entry { root, kept });
        }
    }

    fn apply(&mut self, kept: &mut Vec<String>, path: String, rule: Rule, value: &Value) {
        match (rule, value) {
            (Rule::Skip, _) => {}
            (Rule::Object(fields), Value::Object(map)) => self.fields(kept, &path, fields, map),
            (Rule::Each(fields), Value::Array(items)) => {
                for (i, item) in items.iter().enumerate() {
                    let child = child(&path, PathSegment::Index(i));
                    self.apply(kept, child, Rule::Object(fields), item);
                }
            }
            (Rule::Content, Value::Array(parts)) => {
                for (i, part) in parts.iter().enumerate() {
                    self.part(kept, child(&path, PathSegment::Index(i)), part);
                }
            }
            (Rule::Encoded, Value::String(_)) => self.encoded_values += 1,
            (Rule::ImageUrl, Value::String(url)) => {
                if is_data_url(url) {
                    self.encoded_values += 1;
                }
            }
            // `Scan`, and any value whose shape its rule does not expect.
            _ => kept.push(path),
        }
    }

    fn fields(
        &mut self,
        kept: &mut Vec<String>,
        path: &str,
        fields: &[Field],
        map: &Map<String, Value>,
    ) {
        for (key, value) in map {
            let rule = fields
                .iter()
                .find(|(name, _)| name == key)
                .map_or(Rule::Scan, |&(_, rule)| rule);
            self.apply(kept, child(path, PathSegment::Key(key)), rule, value);
        }
    }

    fn part(&mut self, kept: &mut Vec<String>, path: String, part: &Value) {
        let fields = part
            .get("type")
            .and_then(Value::as_str)
            .and_then(|t| PARTS.iter().find(|(name, _)| *name == t))
            .map(|&(_, fields)| fields);
        match (fields, part) {
            (Some(fields), Value::Object(map)) => self.fields(kept, &path, fields, map),
            _ => self.unknown_parts += 1,
        }
    }
}

fn child(path: &str, segment: PathSegment<'_>) -> String {
    let mut child = path.to_owned();
    push_path_segment(&mut child, segment);
    child
}

/// The top-level entry a fragment path belongs to: everything up to the first
/// array index, such as `tools[3]`.
fn entry_root(path: &str) -> Option<&str> {
    path.find(']').map(|end| &path[..=end])
}

/// True when `path` is `prefix` or a path below it.
fn is_at_or_under(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '[']))
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
            Shape::Message => selection.message(array, 0, &entry),
            Shape::Tool => selection.tool(array, 0, &entry),
            Shape::ToolCall => selection.tool_call(array, 0, &entry),
        }
        let (unknown, encoded) = (selection.unknown_parts(), selection.encoded_values());
        let paths = selection
            .into_unit_fragments(flatten_json(&raw).unwrap())
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

    // --- Path matching ---

    #[test_case("a[0].b", "a[0].b", true ; "equal")]
    #[test_case("a[0].b.c", "a[0].b", true ; "child key")]
    #[test_case("a[0].b[1]", "a[0].b", true ; "child index")]
    #[test_case("a[0].bc", "a[0].b", false ; "sibling with a longer name")]
    #[test_case("a[0]", "a[0].b", false ; "parent")]
    fn is_at_or_under_respects_segment_boundaries(path: &str, prefix: &str, expected: bool) {
        assert_eq!(is_at_or_under(path, prefix), expected);
    }
}
