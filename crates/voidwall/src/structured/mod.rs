//! Structured body parsing for content-aware PII scanning.
//!
//! Each parser produces a `Vec<OwnedContextFragment>` — context/value/offset
//! triples that the scanner can pair with `voidwall_pii::ContextFragment` for
//! `Scanner::mark_piis_structured`. The byte offsets are document-absolute, so
//! a span from one fragment is directly comparable with a span from another.
//! Overlap resolution and the resolved match count are defined over those
//! spans, so fragment-local offsets would make two unrelated values look like
//! they overlap.
//!
//! Submodules:
//! - [`json`] — `application/json` flattener
//! - [`csv`] — `text/csv` and `text/tab-separated-values` parser
//! - [`chat_completions`] — the fields of Chat Completions messages and tools
//!   to scan, selected from the [`json`] fragments
//! - [`litellm`] — the LiteLLM Generic Guardrail API payload
//! - [`openai_chat`] — OpenAI Chat Completions bodies on a reverse proxy route
//! - [`sse`] — `text/event-stream` framer
//! - [`openai_chat_stream`] — Chat Completions stream chunks and the joined
//!   text of each choice and field
//! - (future) per-format dispatch keyed off Content-Type

pub mod chat_completions;
pub mod csv;
pub mod json;
pub mod litellm;
pub mod openai_chat;
pub mod openai_chat_stream;
pub mod sse;

/// One context/value/offset triple emitted by a structured-body parser. Owned
/// so the raw body buffer can be released before the scanner runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedContextFragment {
    pub context: String,
    pub value: String,
    pub offset: usize,
}
