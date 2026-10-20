//! An incremental `text/event-stream` framer.
//!
//! [`SseFramer::push`] takes the body as it arrives, in reads of any size, and
//! returns each event once its blank line has arrived. An event keeps its raw
//! bytes, line endings and comments included, so a caller that forwards
//! `raw` sends exactly what the upstream sent: the `raw` of every event, in
//! order, joined with the rest [`SseFramer::finish`] returns, is the input.
//!
//! Lines end with CRLF, LF, or CR, as the SSE format states. A CR at the end
//! of a read waits for the next one, because an LF may follow it.

use bytes::{Bytes, BytesMut};

/// The `data:` payload that ends a Chat Completions stream.
pub const DONE: &str = "[DONE]";

/// One event: its raw bytes and its `data:` lines, joined.
pub struct SseEvent {
    /// The bytes of the event as they arrived, up to and including its blank
    /// line.
    pub raw: Bytes,
    /// The values of its `data:` lines, joined with `\n`. `None` when it has
    /// no `data:` line, such as a comment.
    pub data: Option<String>,
}

/// Splits a stream body into events.
#[derive(Default)]
pub struct SseFramer {
    /// The bytes of the event not yet complete.
    buf: BytesMut,
    /// Where the next line of `buf` starts.
    line_start: usize,
    /// The data of the lines of `buf` read so far.
    data: Option<String>,
}

impl SseFramer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one read of the body and return the events it completes.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        self.buf.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some((line_end, next)) = self.next_line_end() {
            let empty = line_end == self.line_start;
            if !empty {
                self.read_line(line_end);
            }
            self.line_start = next;
            if empty {
                let raw = self.buf.split_to(next).freeze();
                self.line_start = 0;
                events.push(SseEvent {
                    raw,
                    data: self.data.take(),
                });
            }
        }
        events
    }

    /// End the stream and return the bytes of an event without its blank
    /// line, if any. A last line without a line end is read too.
    pub fn finish(mut self) -> Option<SseEvent> {
        if self.buf.is_empty() {
            return None;
        }
        // A CR at the very end is a line end after all.
        while let Some((line_end, next)) = self.next_line_end_at_eof() {
            if line_end > self.line_start {
                self.read_line(line_end);
            }
            self.line_start = next;
        }
        if self.line_start < self.buf.len() {
            self.read_line(self.buf.len());
        }
        Some(SseEvent {
            raw: self.buf.freeze(),
            data: self.data,
        })
    }

    /// The end of the next complete line and where the line after it starts.
    /// `None` when no line end has arrived, or when the read ends in a CR.
    fn next_line_end(&self) -> Option<(usize, usize)> {
        let rest = &self.buf[self.line_start..];
        let at = rest.iter().position(|b| *b == b'\n' || *b == b'\r')?;
        let end = self.line_start + at;
        match (self.buf[end], self.buf.get(end + 1)) {
            (b'\r', Some(b'\n')) => Some((end, end + 2)),
            (b'\r', None) => None,
            _ => Some((end, end + 1)),
        }
    }

    /// [`Self::next_line_end`], where a CR at the end of the buffer ends a
    /// line.
    fn next_line_end_at_eof(&self) -> Option<(usize, usize)> {
        self.next_line_end().or_else(|| {
            (self.buf.last() == Some(&b'\r') && self.line_start < self.buf.len())
                .then(|| (self.buf.len() - 1, self.buf.len()))
        })
    }

    /// Read the field of the line `[line_start, line_end)`. Only `data` is
    /// kept; `event`, `id`, `retry`, and comments stay in the raw bytes.
    fn read_line(&mut self, line_end: usize) {
        let line = &self.buf[self.line_start..line_end];
        if line.first() == Some(&b':') {
            return;
        }
        let (field, value) = match line.iter().position(|b| *b == b':') {
            Some(colon) => {
                let value = &line[colon + 1..];
                (&line[..colon], value.strip_prefix(b" ").unwrap_or(value))
            }
            None => (line, &line[line.len()..]),
        };
        if field != b"data" {
            return;
        }
        let value = String::from_utf8_lossy(value);
        match &mut self.data {
            Some(data) => {
                data.push('\n');
                data.push_str(&value);
            }
            None => self.data = Some(value.into_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    /// Push `input` in reads of `step` bytes and return every event,
    /// including what `finish` returns.
    fn frame(input: &[u8], step: usize) -> Vec<SseEvent> {
        let mut framer = SseFramer::new();
        let mut events: Vec<SseEvent> = input
            .chunks(step.max(1))
            .flat_map(|c| framer.push(c))
            .collect();
        events.extend(framer.finish());
        events
    }

    fn data(events: &[SseEvent]) -> Vec<Option<&str>> {
        events.iter().map(|e| e.data.as_deref()).collect()
    }

    fn joined(events: &[SseEvent]) -> Vec<u8> {
        events.iter().flat_map(|e| e.raw.to_vec()).collect()
    }

    #[test_case(b"data: a\n\ndata: b\n\n", &[Some("a"), Some("b")] ; "two events")]
    #[test_case(b"data: a\ndata: b\n\n", &[Some("a\nb")] ; "multi-line data")]
    #[test_case(b"data: a\r\n\r\ndata: b\r\n\r\n", &[Some("a"), Some("b")] ; "crlf")]
    #[test_case(b"data: a\r\rdata: b\r\r", &[Some("a"), Some("b")] ; "cr")]
    #[test_case(b": keep-alive\n\ndata: a\n\n", &[None, Some("a")] ; "a comment")]
    #[test_case(b"event: delta\nid: 7\nretry: 100\ndata: a\n\n", &[Some("a")] ; "event id and retry")]
    #[test_case(b"data:a\n\n", &[Some("a")] ; "no space after the colon")]
    #[test_case(b"data:  a\n\n", &[Some(" a")] ; "only one space is stripped")]
    #[test_case(b"data\n\n", &[Some("")] ; "a field without a colon")]
    #[test_case(b"data: {\"x\":1}\n\ndata: [DONE]\n\n", &[Some("{\"x\":1}"), Some(DONE)] ; "done")]
    #[test_case(b"data: a\n\ndata: b", &[Some("a"), Some("b")] ; "a last event without its blank line")]
    #[test_case(b"\n\ndata: a\n\n", &[None, None, Some("a")] ; "blank lines first")]
    fn events_are_framed(input: &[u8], expected: &[Option<&str>]) {
        for step in [1, 2, 3, 7, input.len()] {
            let events = frame(input, step);
            assert_eq!(data(&events), expected, "reads of {step} bytes");
            assert_eq!(joined(&events), input, "reads of {step} bytes");
        }
    }

    #[test]
    fn a_frame_split_across_reads_completes_on_the_read_with_its_blank_line() {
        let mut framer = SseFramer::new();
        assert!(framer.push(b"data: hel").is_empty());
        assert!(framer.push(b"lo\n").is_empty());
        let events = framer.push(b"\ndata: x");
        assert_eq!(data(&events), [Some("hello")]);
        assert_eq!(&events[0].raw[..], b"data: hello\n\n");
    }

    #[test]
    fn a_cr_at_the_end_of_a_read_waits_for_the_next_one() {
        let mut framer = SseFramer::new();
        assert!(framer.push(b"data: a\r\n\r").is_empty());
        let events = framer.push(b"\ndata: b\r\n\r\n");
        assert_eq!(data(&events), [Some("a"), Some("b")]);
        assert_eq!(&events[0].raw[..], b"data: a\r\n\r\n");
    }

    #[test]
    fn the_recorded_stream_frames_into_its_events() {
        let input = include_bytes!("../../tests/fixtures/openai-chat/lmstudio-0.4.26-stream.txt");
        for step in [1, 13, 4096] {
            let events = frame(input, step);
            assert_eq!(events.len(), 39);
            assert_eq!(events.last().unwrap().data.as_deref(), Some(DONE));
            assert_eq!(joined(&events), input);
        }
    }

    #[test]
    fn finish_returns_nothing_after_a_complete_event() {
        let mut framer = SseFramer::new();
        assert_eq!(framer.push(b"data: a\n\n").len(), 1);
        assert!(framer.finish().is_none());
    }
}
