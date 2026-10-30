//! The hold-back window of a stream on an `openai-chat` route.
//!
//! [`Holdback`] decides which upstream events a scan clears for the client.
//! It never scans, reads, or writes: the driver hands it each event with the
//! pieces of joined text it carries, asks which texts are due for a scan and
//! the window to scan, hands back the findings, and forwards what
//! [`Holdback::release`] returns.
//!
//! ```text
//!    p − C                       p                         s     e
//!      │◀──────── C ────────────▶│◀──────────── L ───────────────▶│
//!      │                         │                    │◀─── R ───▶│
//!  ────┼─────────────────────────┼────────────────────┼───────────┤
//!      │ released, kept as       │ held back          │ tail      │
//!      │ left context            │                    │           │
//!      └──────────── one scan covers [p − C, e] ──────────────────┘
//! ```
//!
//! Per joined text: `e` is the end of the received text, `p` the release
//! point. A scan runs once `K` bytes of new text arrived, and at the end.
//! After a scan, `p` moves to `e − L`, but not past the start of a finding
//! that waits, and then down to the end of an event. A spanned finding that
//! ends in the tail (the last [`TAIL_BYTES`]) waits for more text; one outside
//! it is settled and stops the stream. A finding without a span waits one
//! scan of its text and holds the whole text meanwhile; it is settled when
//! the next scan reports the same kind from the same guard again. At the end
//! nothing waits: a finding without a span still waiting in an open text
//! stops the stream.
//!
//! A text closes when an event carries text for another text of its choice,
//! or when its choice sends `finish_reason`: the choice has moved on, so the
//! text will not grow and would otherwise hold its last `L` bytes, and every
//! event after them, until the end. A closed text is scanned and released as
//! at the end; a finding without a span that waits and is not reported again
//! by that scan is dropped, also when the stream ends before it. A closed text that gets text again opens again
//! and goes on as the same text.
//!
//! Events go out whole and in arrival order. An event goes out once every
//! text byte it carries is released, and an event that carries no text goes
//! out with the next one that does, or at the end. So no byte reaches the
//! client before a scan has cleared text, and a stop before then can still
//! answer as a buffered response would.

use bytes::Bytes;
use std::collections::{HashMap, VecDeque};

use crate::engine::Finding;
use crate::structured::openai_chat_stream::Piece;

/// The tail, in bytes: the longest text that, appended after a match, turns
/// it into a non-match.
///
/// Measured over every positive case of the `voidwall-pii` tests: each case's
/// text was cut at the end of its match and extended with suffixes of up to
/// four characters (ASCII letters, digits, punctuation, line ends, and Unicode
/// spaces) and longer realistic ones. A match counts as turned only when the
/// extended text holds no match at or after its start, because a match that
/// gives way to a longer one still blocks. Most patterns end in `\b`, so the
/// next byte decides (one byte). The longest is a `PersonName` match that ends
/// one byte before `.A`, which turns it (two bytes). A custom definition with
/// keywords adds nothing on the right: the keywords come before the value.
pub const TAIL_BYTES: usize = 2;

/// The window sizes, from configuration.
#[derive(Debug, Clone, Copy)]
pub struct WindowSizes {
    /// `L`: text kept back behind the newest text.
    pub holdback: usize,
    /// `C`: already-sent text each scan covers.
    pub context: usize,
    /// `K`: new text that starts the next scan.
    pub step: usize,
}

/// Identifies one joined text.
pub type TextId = usize;

/// The text of one scan: the window of a joined text, and its key path.
pub struct ScanWindow {
    pub path: String,
    pub text: String,
}

/// One joined text: the text of one field of one choice.
struct Text {
    path: String,
    choice: u64,
    /// Whether its choice moved on: until it gets text again, it is scanned
    /// and released as at the end of the stream.
    closed: bool,
    /// The text from `base` to `end`. Text before `p − C` is dropped.
    buf: String,
    base: usize,
    /// `e`: the end of the received text.
    end: usize,
    /// `p`: the end of the released text.
    released: usize,
    /// `e` at the last scan.
    scanned_to: usize,
    /// Where the last scan's window started.
    scan_start: usize,
    /// The spanned findings of the last scan that wait in the tail.
    waiting: Vec<Finding>,
    /// The findings without a span of the last scan, waiting for the next.
    pending: Vec<Finding>,
    /// The ends of the pieces of the events not yet released.
    boundaries: VecDeque<usize>,
}

struct Pending {
    raw: Bytes,
    /// For each text the event carries bytes of, the end of its last piece.
    marks: Vec<(TextId, usize)>,
}

/// The hold-back state of one stream.
pub struct Holdback {
    sizes: WindowSizes,
    texts: Vec<Text>,
    ids: HashMap<String, TextId>,
    events: VecDeque<Pending>,
    ended: bool,
}

impl Holdback {
    pub fn new(sizes: WindowSizes) -> Self {
        Self {
            sizes,
            texts: Vec::new(),
            ids: HashMap::new(),
            events: VecDeque::new(),
            ended: false,
        }
    }

    /// Add one upstream event, the pieces of text it carries, and the
    /// choices that sent `finish_reason` in it.
    pub fn push_event(&mut self, raw: Bytes, pieces: Vec<Piece>, finished: &[u64]) {
        let mut marks: Vec<(TextId, usize)> = Vec::new();
        for piece in pieces.into_iter().filter(|p| !p.text.is_empty()) {
            let id = self.text_id(piece.path, piece.choice);
            let text = &mut self.texts[id];
            text.closed = false;
            text.buf.push_str(&piece.text);
            text.end += piece.text.len();
            let end = text.end;
            if text.boundaries.back() != Some(&end) {
                text.boundaries.push_back(end);
            }
            match marks.iter_mut().find(|(t, _)| *t == id) {
                Some(mark) => mark.1 = end,
                None => marks.push((id, end)),
            }
        }
        self.close_moved_on(&marks, finished);
        self.events.push_back(Pending { raw, marks });
    }

    /// Close each text whose choice moved on in this event: the choice sent
    /// `finish_reason`, or carried text for another of its texts and none
    /// for this one.
    fn close_moved_on(&mut self, marks: &[(TextId, usize)], finished: &[u64]) {
        let fed: Vec<u64> = marks.iter().map(|&(id, _)| self.texts[id].choice).collect();
        for (id, text) in self.texts.iter_mut().enumerate() {
            let has_text = marks.iter().any(|&(m, _)| m == id);
            if finished.contains(&text.choice) || (!has_text && fed.contains(&text.choice)) {
                text.closed = true;
            }
        }
    }

    fn text_id(&mut self, path: String, choice: u64) -> TextId {
        if let Some(&id) = self.ids.get(&path) {
            return id;
        }
        let id = self.texts.len();
        self.ids.insert(path.clone(), id);
        self.texts.push(Text {
            path,
            choice,
            closed: false,
            buf: String::new(),
            base: 0,
            end: 0,
            released: 0,
            scanned_to: 0,
            scan_start: 0,
            waiting: Vec::new(),
            pending: Vec::new(),
            boundaries: VecDeque::new(),
        });
        id
    }

    /// Mark the stream as ended. Every later scan is a final one: nothing
    /// waits.
    pub fn end(&mut self) {
        self.ended = true;
    }

    /// The texts due for a scan: `K` new bytes since the last scan, or any
    /// new byte once the stream ended, or a closed text not yet all out.
    pub fn due(&self) -> Vec<TextId> {
        let step = if self.ended { 1 } else { self.sizes.step };
        (0..self.texts.len())
            .filter(|&id| {
                let text = &self.texts[id];
                text.end - text.scanned_to >= step || (text.closed && !text.is_out())
            })
            .collect()
    }

    /// The window to scan for text `id`: the text not yet released, and up to
    /// `C` bytes of released text before it.
    pub fn window(&mut self, id: TextId) -> ScanWindow {
        let context = self.sizes.context;
        let text = &mut self.texts[id];
        let mut start = text.released.saturating_sub(context).max(text.base);
        while !text.buf.is_char_boundary(start - text.base) {
            start += 1;
        }
        text.scan_start = start;
        text.scanned_to = text.end;
        ScanWindow {
            path: text.path.clone(),
            text: text.buf[start - text.base..].to_string(),
        }
    }

    /// Apply the findings of the scan of the last [`Holdback::window`] of
    /// text `id`. A finding's span is relative to the window start. Return
    /// the settled findings, with their spans moved to the text's offsets:
    /// any one of them stops the stream. With none, move the release point.
    pub fn apply(&mut self, id: TextId, findings: Vec<Finding>) -> Vec<Finding> {
        let holdback = self.sizes.holdback;
        let text = &mut self.texts[id];
        // A closed text is scanned as at the end of the stream.
        let ended = self.ended || text.closed;
        let tail_start = text.end.saturating_sub(TAIL_BYTES);

        let mut settled = Vec::new();
        let mut waiting = Vec::new();
        let mut spanless = Vec::new();
        for mut finding in findings {
            match &mut finding.span {
                Some(span) => {
                    span.start += text.scan_start;
                    span.end += text.scan_start;
                    if !ended && span.end > tail_start {
                        waiting.push(finding);
                    } else {
                        settled.push(finding);
                    }
                }
                None => spanless.push(finding),
            }
        }
        if ended {
            settled.append(&mut spanless);
            // The scan at a close is the next scan of a finding that waits:
            // one it does not report again is dropped, also when the stream
            // ended in the same read. At the end of the stream, a finding
            // still waiting in an open text stops it.
            if text.closed {
                text.pending.clear();
            }
        } else {
            let (confirmed, new): (Vec<Finding>, Vec<Finding>) = spanless
                .into_iter()
                .partition(|f| text.pending.iter().any(|p| same_report(p, f)));
            settled.extend(confirmed);
            text.pending = new;
        }
        text.waiting = waiting;
        if !settled.is_empty() || !text.pending.is_empty() {
            return settled;
        }

        let mut target = if ended {
            text.end
        } else {
            text.end.saturating_sub(holdback)
        };
        if let Some(first) = text
            .waiting
            .iter()
            .filter_map(|f| f.span)
            .map(|s| s.start)
            .min()
        {
            target = target.min(first);
        }
        text.release_to(target, ended, self.sizes.context);
        settled
    }

    /// End the stream for the texts the final scans did not cover: a finding
    /// still waiting is settled. Return the settled findings; with none,
    /// release every text.
    pub fn settle_rest(&mut self) -> Vec<Finding> {
        let mut settled = Vec::new();
        for text in &mut self.texts {
            settled.append(&mut text.waiting);
            settled.append(&mut text.pending);
        }
        if settled.is_empty() {
            let context = self.sizes.context;
            for text in &mut self.texts {
                let end = text.end;
                text.release_to(end, true, context);
            }
        }
        settled
    }

    /// The events cleared for the client, in arrival order.
    pub fn release(&mut self) -> Vec<Bytes> {
        let mut cut = 0;
        for (i, event) in self.events.iter().enumerate() {
            if event.marks.is_empty() {
                continue;
            }
            if event
                .marks
                .iter()
                .all(|&(id, end)| end <= self.texts[id].released)
            {
                cut = i + 1;
            } else {
                break;
            }
        }
        if self.ended && self.texts.iter().all(|t| t.released == t.end) {
            cut = self.events.len();
        }
        self.events.drain(..cut).map(|e| e.raw).collect()
    }

    /// Every event still held, cleared or not, for a stream that is no
    /// longer scanned.
    pub fn release_all(&mut self) -> Vec<Bytes> {
        self.events.drain(..).map(|e| e.raw).collect()
    }
}

impl Text {
    /// Whether the whole text is released and no finding waits.
    fn is_out(&self) -> bool {
        self.released == self.end && self.waiting.is_empty() && self.pending.is_empty()
    }

    /// Move the release point towards `target`: to the end of the last piece
    /// at or before it, never back. At the end of the stream, to `target`
    /// itself. Drop the text no later window can need.
    fn release_to(&mut self, target: usize, ended: bool, context: usize) {
        let mut point = self.released;
        if ended {
            point = point.max(target);
        }
        while let Some(&end) = self.boundaries.front() {
            if end > target {
                break;
            }
            point = point.max(end);
            self.boundaries.pop_front();
        }
        self.released = point;

        let keep_from = point.saturating_sub(context);
        if keep_from > self.base {
            let mut cut = keep_from - self.base;
            while !self.buf.is_char_boundary(cut) {
                cut -= 1;
            }
            self.buf.drain(..cut);
            self.base += cut;
        }
    }
}

/// Whether two findings without a span are the same report: the same kind
/// from the same guard.
fn same_report(a: &Finding, b: &Finding) -> bool {
    a.kind == b.kind && a.guard == b.guard
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Span, UnitId};

    const SIZES: WindowSizes = WindowSizes {
        holdback: 16,
        context: 8,
        step: 4,
    };

    const PATH: &str = "choices[0].message.content";

    const REASONING: &str = "choices[0].message.reasoning_content";

    fn piece(text: &str) -> Vec<Piece> {
        piece_of(PATH, text)
    }

    /// A piece of the text at `path` of choice 0.
    fn piece_of(path: &str, text: &str) -> Vec<Piece> {
        vec![Piece {
            path: path.to_string(),
            choice: 0,
            text: text.to_string(),
        }]
    }

    /// A piece of the content of choice 1.
    fn other(text: &str) -> Vec<Piece> {
        vec![Piece {
            path: "choices[1].message.content".to_string(),
            choice: 1,
            text: text.to_string(),
        }]
    }

    fn raw(n: usize) -> Bytes {
        Bytes::from(format!("data: {n}\n\n"))
    }

    fn spanned(kind: &'static str, start: usize, end: usize) -> Finding {
        Finding::spanned(UnitId(0), kind, "pii", Span::new(start, end))
    }

    fn spanless(kind: &'static str) -> Finding {
        Finding::whole_unit(UnitId(0), kind, "model", 0.9)
    }

    /// Scan every due text, reporting `findings(window)` for each, and return
    /// the settled findings.
    fn scan(hold: &mut Holdback, findings: impl Fn(&ScanWindow) -> Vec<Finding>) -> Vec<Finding> {
        let mut settled = Vec::new();
        for id in hold.due() {
            let window = hold.window(id);
            settled.extend(hold.apply(id, findings(&window)));
        }
        settled
    }

    /// The spans of `needle` in the window, relative to the window start.
    fn find(window: &ScanWindow, needle: &str, kind: &'static str) -> Vec<Finding> {
        window
            .text
            .match_indices(needle)
            .map(|(i, m)| spanned(kind, i, i + m.len()))
            .collect()
    }

    fn kinds(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.kind.as_str()).collect()
    }

    // --- 3.2: the release gate ---

    #[test]
    fn a_short_reply_is_held_until_the_end() {
        let mut hold = Holdback::new(SIZES);
        for (i, t) in ["Hello", " there", "."].iter().enumerate() {
            hold.push_event(raw(i), piece(t), &[]);
            assert!(scan(&mut hold, |_| Vec::new()).is_empty());
            assert!(hold.release().is_empty(), "nothing before the end");
        }
        hold.push_event(raw(9), Vec::new(), &[]);
        hold.end();
        assert!(scan(&mut hold, |_| Vec::new()).is_empty());
        assert!(hold.settle_rest().is_empty());
        assert_eq!(hold.release(), vec![raw(0), raw(1), raw(2), raw(9)]);
    }

    #[test]
    fn text_older_than_the_holdback_is_released_by_whole_events() {
        let mut hold = Holdback::new(SIZES);
        let mut released = Vec::new();
        for i in 0..10 {
            hold.push_event(raw(i), piece("abcd"), &[]);
            scan(&mut hold, |_| Vec::new());
            released.extend(hold.release());
        }
        // 40 bytes in, 16 held back: the events up to byte 24 are out.
        assert_eq!(released, (0..6).map(raw).collect::<Vec<_>>());
    }

    #[test]
    fn a_scan_runs_after_step_bytes_and_covers_the_context() {
        let mut hold = Holdback::new(SIZES);
        hold.push_event(raw(0), piece("abc"), &[]);
        assert!(hold.due().is_empty(), "3 of 4 bytes");
        hold.push_event(raw(1), piece("d"), &[]);
        assert_eq!(hold.due(), vec![0]);
        let window = hold.window(0);
        assert_eq!(
            (hold.texts[0].scan_start, window.text.as_str()),
            (0, "abcd")
        );

        // Release to 24 of 40 bytes, then the window starts 8 bytes before it.
        let mut hold = Holdback::new(SIZES);
        for i in 0..10 {
            hold.push_event(raw(i), piece("abcd"), &[]);
            scan(&mut hold, |_| Vec::new());
            hold.release();
        }
        hold.push_event(raw(10), piece("wxyz"), &[]);
        let window = hold.window(0);
        assert_eq!(hold.texts[0].scan_start, 24 - 8);
        assert_eq!(window.text.len(), 44 - 16);
    }

    #[test]
    fn a_value_inside_the_holdback_never_reaches_the_client() {
        let mut hold = Holdback::new(SIZES);
        let mut released = Vec::new();
        for i in 0..8 {
            hold.push_event(raw(i), piece("....."), &[]);
            scan(&mut hold, |_| Vec::new());
            released.extend(hold.release());
        }
        assert!(!released.is_empty(), "the client has some events");
        let sent = released.len();

        // The value arrives in two events after them.
        hold.push_event(raw(100), piece("jane@exa"), &[]);
        hold.push_event(raw(101), piece("mple.com and more"), &[]);
        let settled = scan(&mut hold, |w| find(w, "jane@example.com", "EMAIL"));
        assert_eq!(kinds(&settled), ["EMAIL"]);
        let out = hold.release();
        assert!(
            !out.contains(&raw(100)) && !out.contains(&raw(101)),
            "{} events after the first {sent}",
            out.len()
        );
    }

    #[test]
    fn a_keyword_before_the_value_is_in_the_window() {
        // The keyword is released, and the window still holds it.
        let mut hold = Holdback::new(SIZES);
        let mut released = Vec::new();
        for (i, t) in ["SSN:", "............", ".....", "....."]
            .iter()
            .enumerate()
        {
            hold.push_event(raw(i), piece(t), &[]);
            scan(&mut hold, |_| Vec::new());
            released.extend(hold.release());
        }
        assert_eq!(released.first(), Some(&raw(0)), "the keyword is out");
        hold.push_event(raw(10), piece("123-45-6789 ok"), &[]);
        let settled = scan(&mut hold, |w| {
            // A keyword-gated value: found only when the keyword is in view.
            if w.text.contains("SSN:") {
                find(w, "123-45-6789", "US_SSN")
            } else {
                Vec::new()
            }
        });
        assert_eq!(kinds(&settled), ["US_SSN"]);
    }

    // --- 3.3: the tail and findings without a span ---

    #[test]
    fn a_value_that_is_not_complete_yet_waits_in_the_tail() {
        let mut hold = Holdback::new(SIZES);
        // A number whose first digits match a kind alone.
        hold.push_event(raw(0), piece("ref 123456789"), &[]);
        let settled = scan(&mut hold, |w| find(w, "123456789", "SHORT_NUMBER"));
        assert!(settled.is_empty(), "the match ends in the tail");
        assert!(hold.release().is_empty());

        // The next chunk completes a number that matches no kind.
        hold.push_event(raw(1), piece("0123 is the order"), &[]);
        let settled = scan(&mut hold, |w| {
            if w.text.contains("1234567890123") {
                Vec::new()
            } else {
                find(w, "123456789", "SHORT_NUMBER")
            }
        });
        assert!(settled.is_empty());
        hold.end();
        assert!(scan(&mut hold, |_| Vec::new()).is_empty());
        assert!(hold.settle_rest().is_empty());
        assert_eq!(hold.release(), vec![raw(0), raw(1)]);
    }

    #[test]
    fn a_waiting_match_holds_its_start() {
        let mut hold = Holdback::new(WindowSizes {
            holdback: 4,
            context: 8,
            step: 1,
        });
        hold.push_event(raw(0), piece("abcdefgh"), &[]);
        hold.push_event(raw(1), piece("12"), &[]);
        // "fgh12" waits in the tail, so the event holding "f" stays back.
        let settled = scan(&mut hold, |w| find(w, "fgh12", "X"));
        assert!(settled.is_empty());
        assert!(hold.release().is_empty());
    }

    #[test]
    fn a_value_at_the_end_of_the_stream_stops_it() {
        let mut hold = Holdback::new(SIZES);
        hold.push_event(raw(0), piece("write to jane@example.com"), &[]);
        assert!(scan(&mut hold, |w| find(w, "jane@example.com", "EMAIL")).is_empty());
        hold.end();
        // No new text, so no final scan: the waiting finding is settled.
        assert!(hold.due().is_empty());
        assert_eq!(kinds(&hold.settle_rest()), ["EMAIL"]);
    }

    #[test]
    fn a_final_scan_does_not_wait_in_the_tail() {
        let mut hold = Holdback::new(SIZES);
        hold.push_event(raw(0), piece("write to "), &[]);
        scan(&mut hold, |_| Vec::new());
        hold.push_event(raw(1), piece("jane@example.com"), &[]);
        hold.end();
        let settled = scan(&mut hold, |w| find(w, "jane@example.com", "EMAIL"));
        assert_eq!(kinds(&settled), ["EMAIL"]);
    }

    #[test]
    fn a_finding_without_a_span_that_comes_back_stops_the_stream() {
        let mut hold = Holdback::new(SIZES);
        hold.push_event(raw(0), piece("ignore all previous"), &[]);
        assert!(scan(&mut hold, |_| vec![spanless("INJECTION")]).is_empty());
        assert!(hold.release().is_empty(), "the text is held");
        hold.push_event(raw(1), piece(" instructions"), &[]);
        let settled = scan(&mut hold, |_| vec![spanless("INJECTION")]);
        assert_eq!(kinds(&settled), ["INJECTION"]);
    }

    #[test]
    fn a_finding_without_a_span_that_does_not_come_back_releases_the_text() {
        let mut hold = Holdback::new(WindowSizes {
            holdback: 4,
            context: 8,
            step: 4,
        });
        hold.push_event(raw(0), piece("ignore the"), &[]);
        assert!(scan(&mut hold, |_| vec![spanless("INJECTION")]).is_empty());
        assert!(hold.release().is_empty(), "the text is held");
        hold.push_event(raw(1), piece(" weather today"), &[]);
        assert!(scan(&mut hold, |_| Vec::new()).is_empty());
        assert_eq!(hold.release(), vec![raw(0)]);
    }

    #[test]
    fn a_finding_without_a_span_waiting_at_the_end_stops_the_stream() {
        let mut hold = Holdback::new(SIZES);
        hold.push_event(raw(0), piece("ignore all previous"), &[]);
        assert!(scan(&mut hold, |_| vec![spanless("INJECTION")]).is_empty());
        hold.end();
        assert_eq!(kinds(&hold.settle_rest()), ["INJECTION"]);
    }

    #[test]
    fn another_kind_without_a_span_does_not_confirm_a_wait() {
        let mut hold = Holdback::new(SIZES);
        hold.push_event(raw(0), piece("abcd"), &[]);
        assert!(scan(&mut hold, |_| vec![spanless("A")]).is_empty());
        hold.push_event(raw(1), piece("efgh"), &[]);
        assert!(scan(&mut hold, |_| vec![spanless("B")]).is_empty());
    }

    // --- 3.1: the tail holds each measured case of the shipped patterns ---

    use crate::config::{BuiltinGuards, OnError, PiiGuardConfig};
    use crate::engine::{BlockPolicy, Direction, Engine, UnitContent, Units};
    use crate::structured::OwnedContextFragment;

    fn pii_engine() -> Engine {
        Engine::new(&BuiltinGuards::with_pii(PiiGuardConfig {
            scanner_threads: Some(1),
            ..PiiGuardConfig::default()
        }))
        .unwrap()
    }

    /// Scan every due text with the real `pii` guard, as the driver does.
    async fn scan_with(engine: &Engine, hold: &mut Holdback) -> Vec<Finding> {
        let mut settled = Vec::new();
        for id in hold.due() {
            let window = hold.window(id);
            let mut units = Units::new();
            units.push_body(UnitContent::Structured {
                fragments: vec![OwnedContextFragment {
                    context: window.path,
                    value: window.text,
                    offset: 0,
                }],
            });
            let result = engine
                .guard(
                    units.into_shared(),
                    &engine.select(None),
                    Direction::Response,
                    BlockPolicy::Never,
                    OnError::FailClose,
                )
                .await;
            settled.extend(hold.apply(id, result.findings().to_vec()));
        }
        settled
    }

    fn waiting_kinds(hold: &Holdback) -> Vec<&str> {
        hold.texts[0]
            .waiting
            .iter()
            .map(|f| f.kind.as_str())
            .collect()
    }

    /// One byte: a pattern that ends in `\b` matches at the end of the text,
    /// and the next digit turns it.
    #[tokio::test]
    async fn a_match_the_next_byte_turns_waits_in_the_tail() {
        let engine = pii_engine();
        let mut hold = Holdback::new(SIZES);
        hold.push_event(raw(0), piece("my number is 123-45-6789"), &[]);
        assert!(scan_with(&engine, &mut hold).await.is_empty());
        assert_eq!(waiting_kinds(&hold), ["US_SSN"]);

        hold.push_event(raw(1), piece("0, not a social"), &[]);
        assert!(scan_with(&engine, &mut hold).await.is_empty());
        assert!(waiting_kinds(&hold).is_empty(), "the match is gone");
    }

    /// Two bytes: a name that ends one byte before the end, which `.A`
    /// turns.
    #[tokio::test]
    async fn a_match_two_bytes_turn_waits_in_the_tail() {
        let engine = pii_engine();
        let mut hold = Holdback::new(SIZES);
        hold.push_event(raw(0), piece("postcode: 1011 ABa."), &[]);
        let settled = scan_with(&engine, &mut hold).await;
        assert!(
            !kinds(&settled).contains(&"PERSON_NAME"),
            "{:?}",
            kinds(&settled)
        );
        assert_eq!(waiting_kinds(&hold), ["PERSON_NAME"]);

        // One byte is below the scan step, so the final scan reads it.
        hold.push_event(raw(1), piece("A"), &[]);
        hold.end();
        let settled = scan_with(&engine, &mut hold).await;
        assert!(
            !kinds(&settled).contains(&"PERSON_NAME"),
            "the match is gone"
        );
    }

    /// The stream scans text in its JSON-escaped form, where a line end or a
    /// quote is two bytes. When a scan of a match and part of a two-character
    /// suffix settles a finding, the match and the whole suffix must stop the
    /// stream too; otherwise the tail is too short for the escaped form.
    #[tokio::test]
    async fn the_tail_holds_in_the_escaped_form() {
        // Each character as the chunk decoder hands it over.
        let units: Vec<String> = [
            '\n', '\r', '\t', '"', '\\', '\u{1}', '.', ' ', '-', 'A', 'a', '0',
        ]
        .iter()
        .map(|c| {
            let quoted = serde_json::to_string(&c.to_string()).unwrap();
            quoted[1..quoted.len() - 1].to_string()
        })
        .collect();
        let bases = [
            "my number is 123-45-6789",
            "postcode: 1011 ABa",
            "postcode: 1011 ABa.",
            "write to jane@example.com",
        ];
        let engine = pii_engine();
        let mut early = Vec::new();
        let mut escaped_settled = 0;
        for (b, base) in bases.iter().enumerate() {
            for first in &units {
                let mut hold = Holdback::new(SIZES);
                hold.push_event(raw(0), piece(&format!("{base}{first}")), &[]);
                if scan_with(&engine, &mut hold).await.is_empty() {
                    continue;
                }
                escaped_settled += usize::from(first.len() > 1);
                for second in &units {
                    let mut hold = Holdback::new(SIZES);
                    hold.push_event(raw(0), piece(&format!("{base}{first}{second}")), &[]);
                    hold.end();
                    if scan_with(&engine, &mut hold).await.is_empty() {
                        early.push(format!("base {b} + {first:?} + {second:?}"));
                    }
                }
            }
        }
        assert!(escaped_settled > 0, "no escaped character was checked");
        assert!(
            early.is_empty(),
            "settled before the suffix turned it: {early:?}"
        );
    }

    // --- Events ---

    #[test]
    fn an_event_without_text_goes_out_with_the_next_one_that_has_text() {
        let mut hold = Holdback::new(WindowSizes {
            holdback: 2,
            context: 8,
            step: 1,
        });
        hold.push_event(raw(0), piece(""), &[]);
        assert!(hold.release().is_empty(), "nothing is out before a scan");
        hold.push_event(raw(1), piece("abcd"), &[]);
        hold.push_event(raw(2), Vec::new(), &[]);
        hold.push_event(raw(3), piece("efgh"), &[]);
        scan(&mut hold, |_| Vec::new());
        assert_eq!(hold.release(), vec![raw(0), raw(1)]);
    }

    #[test]
    fn two_texts_each_hold_their_own_events() {
        let mut hold = Holdback::new(WindowSizes {
            holdback: 4,
            context: 8,
            step: 1,
        });
        hold.push_event(raw(0), piece("abcdefgh"), &[]);
        hold.push_event(raw(1), other("ab"), &[]);
        hold.push_event(raw(2), piece("ijkl"), &[]);
        scan(&mut hold, |_| Vec::new());
        // Event 1's text is inside the other text's hold-back.
        assert_eq!(hold.release(), vec![raw(0)]);
    }

    #[test]
    fn the_window_drops_text_no_scan_needs() {
        let mut hold = Holdback::new(SIZES);
        for i in 0..100 {
            hold.push_event(raw(i), piece("abcd"), &[]);
            scan(&mut hold, |_| Vec::new());
            hold.release();
        }
        let text = &hold.texts[0];
        assert!(
            text.buf.len() <= SIZES.context + SIZES.holdback + SIZES.step,
            "{} bytes kept",
            text.buf.len()
        );
    }

    // --- 8.1: a text closes when its choice moves on ---

    fn email(window: &ScanWindow) -> Vec<Finding> {
        find(window, "jane@example.com", "EMAIL")
    }

    #[test]
    fn content_after_a_reasoning_trace_releases_the_trace() {
        let mut hold = Holdback::new(SIZES);
        let mut released = Vec::new();
        for i in 0..5 {
            hold.push_event(raw(i), piece_of(REASONING, "........"), &[]);
            scan(&mut hold, |_| Vec::new());
            released.extend(hold.release());
        }
        assert!(
            !released.contains(&raw(4)),
            "the trace's last bytes are held"
        );
        hold.push_event(raw(10), piece("ab"), &[]);
        assert!(scan(&mut hold, |_| Vec::new()).is_empty());
        released.extend(hold.release());
        assert_eq!(released, (0..5).map(raw).collect::<Vec<_>>());
    }

    #[test]
    fn tool_call_arguments_after_the_name_release_the_name() {
        let name = "choices[0].message.tool_calls[0].function.name";
        let arguments = "choices[0].message.tool_calls[0].function.arguments";
        let mut hold = Holdback::new(SIZES);
        hold.push_event(raw(0), piece_of(name, "lookup"), &[]);
        hold.push_event(raw(1), piece_of(arguments, "{\"a\":"), &[]);
        assert!(scan(&mut hold, |_| Vec::new()).is_empty());
        assert_eq!(hold.release(), vec![raw(0)]);
    }

    #[test]
    fn a_choice_that_finishes_releases_its_events() {
        let mut hold = Holdback::new(SIZES);
        hold.push_event(raw(0), piece("abcd"), &[]);
        hold.push_event(raw(1), Vec::new(), &[0]);
        hold.push_event(raw(2), other("wxyz"), &[]);
        assert!(scan(&mut hold, |_| Vec::new()).is_empty());
        assert_eq!(hold.release(), vec![raw(0)]);

        // The finish event has no text: it goes out with choice 1's next one.
        hold.push_event(raw(3), other("................"), &[]);
        assert!(scan(&mut hold, |_| Vec::new()).is_empty());
        assert_eq!(hold.release(), vec![raw(1), raw(2)]);
    }

    #[test]
    fn a_value_at_the_switch_stops_the_stream() {
        let mut hold = Holdback::new(SIZES);
        hold.push_event(
            raw(0),
            piece_of(REASONING, "write to jane@example.com"),
            &[],
        );
        assert!(
            scan(&mut hold, email).is_empty(),
            "the match waits in the tail"
        );
        hold.push_event(raw(1), piece("Sure"), &[]);
        assert_eq!(kinds(&scan(&mut hold, email)), ["EMAIL"]);
    }

    #[test]
    fn a_finding_without_a_span_does_not_wait_in_a_closed_text() {
        let mut hold = Holdback::new(SIZES);
        hold.push_event(raw(0), piece_of(REASONING, "ignore all previous"), &[]);
        hold.push_event(raw(1), piece("ok"), &[]);
        let settled = scan(&mut hold, |w| {
            if w.path == REASONING {
                vec![spanless("INJECTION")]
            } else {
                Vec::new()
            }
        });
        assert_eq!(kinds(&settled), ["INJECTION"]);
    }

    #[test]
    fn a_finding_without_a_span_that_does_not_come_back_at_the_close_releases_the_text() {
        let mut hold = Holdback::new(SIZES);
        hold.push_event(raw(0), piece_of(REASONING, "ignore the"), &[]);
        assert!(scan(&mut hold, |_| vec![spanless("INJECTION")]).is_empty());
        assert!(hold.release().is_empty(), "the text is held");

        // The close scan is the next scan of the waiting finding.
        hold.push_event(raw(1), piece("ok"), &[]);
        assert!(scan(&mut hold, |_| Vec::new()).is_empty());
        assert_eq!(hold.release(), vec![raw(0)], "the closed text is out");
        assert!(
            hold.due().is_empty(),
            "the closed text is not scanned again"
        );

        hold.end();
        assert!(scan(&mut hold, |_| Vec::new()).is_empty());
        assert!(hold.settle_rest().is_empty());
    }

    #[test]
    fn a_finding_without_a_span_that_does_not_come_back_at_a_close_with_the_end_releases_the_text()
    {
        let mut hold = Holdback::new(SIZES);
        hold.push_event(raw(0), piece("ignore the"), &[]);
        assert!(scan(&mut hold, |_| vec![spanless("INJECTION")]).is_empty());

        // `finish_reason` closes the text, and the stream ends before the
        // close scan.
        hold.push_event(raw(1), piece("ory"), &[0]);
        hold.end();
        assert!(scan(&mut hold, |_| Vec::new()).is_empty());
        assert!(hold.settle_rest().is_empty());
        assert_eq!(hold.release(), vec![raw(0), raw(1)]);
    }

    #[test]
    fn a_text_that_opens_again_is_the_same_text() {
        let mut hold = Holdback::new(SIZES);
        hold.push_event(raw(0), piece_of(REASONING, "write to jane@"), &[]);
        hold.push_event(raw(1), piece("ok"), &[]);
        assert!(scan(&mut hold, email).is_empty());
        assert_eq!(hold.release(), vec![raw(0)], "the closed text is out");

        // The value goes on after the close; the released context holds its
        // start.
        hold.push_event(raw(2), piece_of(REASONING, "example.com and more"), &[]);
        assert_eq!(kinds(&scan(&mut hold, email)), ["EMAIL"]);
    }

    #[test]
    fn an_event_with_text_for_two_texts_closes_neither() {
        let mut hold = Holdback::new(SIZES);
        let mut pieces = piece_of(REASONING, "abcd");
        pieces.extend(piece("efgh"));
        hold.push_event(raw(0), pieces, &[]);
        assert!(hold.texts.iter().all(|t| !t.closed));
    }
}
