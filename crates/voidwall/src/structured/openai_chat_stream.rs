//! Chat Completions stream chunks on a reverse proxy route with
//! `format = "openai-chat"`.
//!
//! [`decode_chunk`] reads the `data:` payload of one event. Each kept string
//! under `choices[].delta` becomes a [`Piece`] of a joined text: the text of
//! one field of one choice, in arrival order. A piece carries the key path the
//! same field has under `choices[].message` in a buffered response —
//! `choices[0].message.content`, and for a tool call the tool call's own
//! `index`, `choices[0].message.tool_calls[1].function.arguments` — so the
//! path is the join key and gives a scan the same keyword context.
//!
//! The field rules come from [`chat_completions`](super::chat_completions):
//! `choices[].delta.X` is read by the rule of `choices[].message.X`, so a key
//! the rules do not know, such as `reasoning_content`, is scanned. Every other
//! kept string of a chunk is a unit of its own event, read by the response
//! rules of its top-level key.

use std::collections::HashMap;

use serde_json::{Map, Value};

use super::OwnedContextFragment;
use super::chat_completions::{Decoded, Selection};
use super::json::flatten_json;
use crate::error::Error;

/// One string of a delta: a piece of the joined text at `path`, of choice
/// `choice`. `Debug` is not derived, because the text is scanned content.
pub struct Piece {
    pub path: String,
    pub choice: u64,
    pub text: String,
}

/// What one chunk carries. `Debug` is not derived, because it holds scanned
/// content.
#[derive(Default)]
pub struct Chunk {
    /// The kept strings under `choices[].delta`, in document order.
    pub pieces: Vec<Piece>,
    /// The other kept strings, one group per entry, scanned with this event.
    pub units: Vec<Vec<OwnedContextFragment>>,
    /// Content parts of an unknown type. They are in neither list.
    pub unknown_parts: usize,
    /// Base64 values left out without a scan.
    pub encoded_values: usize,
    /// The choices that sent a `finish_reason`.
    pub finished: Vec<u64>,
}

impl Chunk {
    fn add_pieces(&mut self, choice: u64, decoded: Decoded) {
        self.count(&decoded);
        self.pieces
            .extend(decoded.units.into_iter().flatten().map(|f| Piece {
                path: f.context,
                choice,
                text: f.value,
            }));
    }

    fn add_units(&mut self, decoded: Decoded) {
        self.count(&decoded);
        self.units.extend(decoded.units);
    }

    fn count(&mut self, decoded: &Decoded) {
        self.unknown_parts += decoded.unknown_parts;
        self.encoded_values += decoded.encoded_values;
    }
}

/// Decode the `data:` payload of one event other than `[DONE]`. A payload
/// that is not JSON is [`Error::BodyParse`]. A JSON value that is not an
/// object is one unit, scanned whole.
pub fn decode_chunk(data: &str) -> Result<Chunk, Error> {
    let document: Value = serde_json::from_str(data).map_err(|_| Error::BodyParse)?;
    let mut chunk = Chunk::default();
    let Value::Object(mut map) = document else {
        let mut selection = Selection::new();
        selection.text(&document);
        chunk.add_units(selection.into_decoded(flatten_json(data.as_bytes())?)?);
        return Ok(chunk);
    };

    if let Some(Value::Array(choices)) = map.get_mut("choices") {
        for (position, choice) in choices.iter_mut().enumerate() {
            let Value::Object(choice) = choice else {
                continue;
            };
            let index = choice
                .get("index")
                .and_then(Value::as_u64)
                .unwrap_or(position as u64);
            if choice.get("finish_reason").is_some_and(|r| !r.is_null()) {
                chunk.finished.push(index);
            }
            let Some(delta) = choice.remove("delta") else {
                continue;
            };
            delta_pieces(index, delta, &mut chunk)?;
        }
    }

    // What is left — the top-level keys, and each choice without its delta —
    // is read by the response rules.
    let raw = to_vec(&map)?;
    let mut selection = Selection::new();
    selection.response(&map);
    chunk.add_units(selection.into_decoded(flatten_json(&raw)?)?);
    Ok(chunk)
}

/// Add the pieces of the delta of choice `index`. A tool call is keyed by its
/// own `index`, so the chunks of one call join whatever their position.
fn delta_pieces(index: u64, delta: Value, chunk: &mut Chunk) -> Result<(), Error> {
    let message = format!("choices[{index}].message");
    let Value::Object(mut fields) = delta else {
        chunk.add_pieces(index, classify(&message, delta, Selection::text)?);
        return Ok(());
    };
    let tool_calls = fields.remove("tool_calls");
    chunk.add_pieces(
        index,
        classify(&message, Value::Object(fields), Selection::delta)?,
    );
    match tool_calls {
        Some(Value::Array(calls)) => {
            for (position, call) in calls.into_iter().enumerate() {
                let call_index = call
                    .get("index")
                    .and_then(Value::as_u64)
                    .unwrap_or(position as u64);
                let path = format!("{message}.tool_calls[{call_index}]");
                chunk.add_pieces(index, classify(&path, call, Selection::tool_call)?);
            }
        }
        // Not an array: the rule scans it, as on a buffered response.
        Some(other) => {
            let path = format!("{message}.tool_calls");
            chunk.add_pieces(index, classify(&path, other, Selection::text)?);
        }
        None => {}
    }
    Ok(())
}

/// Classify `value` with `rule`, as the only value of a document whose one key
/// is `path`, so each fragment's key path starts with `path`.
fn classify(path: &str, value: Value, rule: fn(&mut Selection, &Value)) -> Result<Decoded, Error> {
    let mut document = Map::new();
    document.insert(path.to_string(), value);
    let raw = to_vec(&document)?;
    let mut selection = Selection::new();
    rule(&mut selection, &document[path]);
    selection.into_decoded(flatten_json(&raw)?)
}

fn to_vec(map: &Map<String, Value>) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(map).map_err(|e| Error::Scanner(format!("chunk serialization: {e}")))
}

/// The joined texts of a stream, each whole: one per key path, in order of
/// first arrival.
#[derive(Default)]
pub struct Joined {
    ids: HashMap<String, usize>,
    texts: Vec<(String, String)>,
}

impl Joined {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `piece` to the text at its path.
    pub fn push(&mut self, piece: Piece) {
        match self.ids.get(&piece.path) {
            Some(&id) => self.texts[id].1.push_str(&piece.text),
            None => {
                self.ids.insert(piece.path.clone(), self.texts.len());
                self.texts.push((piece.path, piece.text));
            }
        }
    }

    /// The `(path, text)` pairs, in order of first arrival.
    pub fn into_texts(self) -> Vec<(String, String)> {
        self.texts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structured::sse::{DONE, SseFramer};
    use serde_json::json;
    use test_case::test_case;

    /// Decode `chunks` and return the joined texts and the paths of the
    /// per-event units.
    fn decode(chunks: &[Value]) -> (Vec<(String, String)>, Vec<String>) {
        let mut joined = Joined::new();
        let mut units = Vec::new();
        for c in chunks {
            let chunk = decode_chunk(&c.to_string()).unwrap();
            chunk.pieces.into_iter().for_each(|p| joined.push(p));
            units.extend(chunk.units.into_iter().flatten().map(|f| f.context));
        }
        (joined.into_texts(), units)
    }

    fn delta(index: u64, delta: Value) -> Value {
        json!({
            "id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 1, "model": "m",
            "system_fingerprint": "fp", "service_tier": "default",
            "choices": [{"index": index, "delta": delta, "logprobs": null, "finish_reason": null}],
        })
    }

    fn texts(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(p, t)| (p.to_string(), t.to_string()))
            .collect()
    }

    #[test_case(
        &[json!({"role": "assistant", "content": "ja"}), json!({"content": "ne"})],
        &[("choices[0].message.content", "jane")] ;
        "content"
    )]
    #[test_case(
        &[json!({"refusal": "I can"}), json!({"refusal": "not"})],
        &[("choices[0].message.refusal", "I cannot")] ;
        "refusal"
    )]
    #[test_case(
        &[json!({"reasoning_content": "The user "}), json!({"reasoning_content": "asks"})],
        &[("choices[0].message.reasoning_content", "The user asks")] ;
        "reasoning_content"
    )]
    #[test_case(
        &[
            json!({"tool_calls": [{"index": 1, "id": "call_1", "type": "function", "function": {"name": "look", "arguments": ""}}]}),
            json!({"tool_calls": [{"index": 1, "function": {"name": "up", "arguments": "{\"a\":"}}]}),
            json!({"tool_calls": [{"index": 1, "function": {"arguments": "1}"}}]}),
        ],
        &[
            ("choices[0].message.tool_calls[1].function.name", "lookup"),
            ("choices[0].message.tool_calls[1].function.arguments", "{\\\"a\\\":1}"),
        ] ;
        "tool call name and arguments by index"
    )]
    #[test_case(
        &[json!({"role": "assistant", "content": null}), json!({})],
        &[] ;
        "role and empty deltas carry no text"
    )]
    fn delta_strings_join_by_choice_and_field(deltas: &[Value], expected: &[(&str, &str)]) {
        let chunks: Vec<Value> = deltas.iter().map(|d| delta(0, d.clone())).collect();
        let (joined, units) = decode(&chunks);
        assert_eq!(joined, texts(expected));
        assert!(units.is_empty(), "the metadata keys are skipped: {units:?}");
    }

    #[test]
    fn two_interleaved_choices_join_apart() {
        let chunks = [
            delta(0, json!({"content": "a"})),
            delta(1, json!({"content": "x"})),
            delta(0, json!({"content": "b"})),
            delta(1, json!({"content": "y"})),
        ];
        let (joined, _) = decode(&chunks);
        assert_eq!(
            joined,
            texts(&[
                ("choices[0].message.content", "ab"),
                ("choices[1].message.content", "xy"),
            ])
        );
    }

    #[test]
    fn each_piece_carries_its_choice() {
        let chunk = decode_chunk(
            &json!({"choices": [
                {"index": 0, "delta": {"content": "a"}},
                {"index": 1, "delta": {"reasoning_content": "b"}},
            ]})
            .to_string(),
        )
        .unwrap();
        let choices: Vec<u64> = chunk.pieces.iter().map(|p| p.choice).collect();
        assert_eq!(choices, [0, 1]);
    }

    #[test_case(json!(null), &[] ; "no finish_reason")]
    #[test_case(json!("stop"), &[2] ; "a finish_reason")]
    fn a_finish_reason_is_reported_by_choice(reason: Value, expected: &[u64]) {
        let mut chunk = delta(2, json!({}));
        chunk["choices"][0]["finish_reason"] = reason;
        assert_eq!(decode_chunk(&chunk.to_string()).unwrap().finished, expected);
    }

    #[test]
    fn a_choice_without_a_delta_still_reports_its_finish_reason() {
        let chunk = json!({"choices": [{"index": 0, "finish_reason": "stop"}]});
        assert_eq!(decode_chunk(&chunk.to_string()).unwrap().finished, [0]);
    }

    #[test_case(json!({"choices": [], "error": {"message": "x", "type": "t"}}), &["error.message", "error.type"] ; "an error object")]
    #[test_case(json!({"choices": [], "stats": {"note": "x"}}), &["stats.note"] ; "an unknown top-level key")]
    #[test_case(json!({"choices": [{"index": 0, "delta": {}, "extra": "x"}]}), &["choices[0].extra"] ; "an unknown choice key")]
    fn another_kept_key_is_a_unit_of_its_event(chunk: Value, expected: &[&str]) {
        let (joined, units) = decode(&[chunk]);
        assert!(joined.is_empty());
        assert_eq!(units, expected);
    }

    #[test]
    fn the_skipped_keys_are_left_out() {
        let mut chunk = delta(0, json!({}));
        chunk["choices"][0]["logprobs"] = json!({"content": [{"token": "x", "top_logprobs": []}]});
        chunk["choices"][0]["finish_reason"] = json!("x");
        chunk["usage"] = json!({"note": "x"});
        chunk["id"] = json!("x");
        chunk["model"] = json!("x");
        let (joined, units) = decode(&[chunk]);
        assert!(joined.is_empty() && units.is_empty(), "kept: {units:?}");
    }

    #[test]
    fn a_payload_that_is_not_json_is_a_parse_error() {
        assert!(matches!(decode_chunk("{not json"), Err(Error::BodyParse)));
    }

    #[test]
    fn a_json_value_that_is_not_an_object_is_one_unit() {
        let chunk = decode_chunk(r#"["a", {"b": "c"}]"#).unwrap();
        assert!(chunk.pieces.is_empty());
        assert_eq!(chunk.units.len(), 1);
        assert_eq!(chunk.units[0].len(), 2);
    }

    #[test]
    fn audio_data_in_a_delta_is_counted_and_never_kept() {
        let chunk =
            decode_chunk(&delta(0, json!({"audio": {"id": "a", "data": "AAAA"}})).to_string())
                .unwrap();
        assert_eq!(chunk.encoded_values, 1);
        assert!(chunk.pieces.is_empty());
    }

    #[test]
    fn the_recorded_stream_joins_to_its_reasoning_text() {
        let input = include_bytes!("../../tests/fixtures/openai-chat/lmstudio-0.4.26-stream.txt");
        let mut framer = SseFramer::new();
        let mut joined = Joined::new();
        for event in framer.push(input) {
            let data = event.data.unwrap();
            if data == DONE {
                continue;
            }
            let chunk = decode_chunk(&data).unwrap();
            assert!(chunk.units.is_empty());
            chunk.pieces.into_iter().for_each(|p| joined.push(p));
        }
        assert_eq!(
            joined.into_texts(),
            texts(&[(
                "choices[0].message.reasoning_content",
                "*   User's question: \\\"Where is my order 4471?\\\"\\n    *   User's persona: Customer.\\n    *   My persona: Support",
            )])
        );
    }
}
