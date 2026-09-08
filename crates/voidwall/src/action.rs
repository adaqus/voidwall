use axum::http::HeaderMap;
use bytes::Bytes;

use crate::config::{Action, DirectionConfig};
use crate::engine::{Finding, ScanResult, Unit, UnitId, UnitKind};
use crate::metrics;
use crate::scanner::RedactWith;

// ---------------------------------------------------------------------------
// ActionSet — parsed, validated set of actions for a direction
// ---------------------------------------------------------------------------

/// A pre-validated set of actions for a single direction (request or response).
///
/// Built from a `DirectionConfig` at startup. The proxy uses one `ActionSet` per
/// direction per mode.
#[derive(Debug, Clone)]
pub struct ActionSet {
    pub block: bool,
    pub redact: bool,
    pub header: bool,
    /// HTTP status code for block responses.
    pub block_status: u16,
    /// Optional custom body for block responses.
    pub block_body: Option<String>,
    /// Additional headers to include in block responses.
    pub block_headers: Vec<(String, String)>,
}

impl ActionSet {
    /// Build an `ActionSet` from a validated `DirectionConfig`.
    pub fn from_direction_config(config: &DirectionConfig) -> Self {
        Self {
            block: config.actions.contains(&Action::Block),
            redact: config.actions.contains(&Action::Redact),
            header: config.actions.contains(&Action::Header),
            block_status: config.block_status,
            block_body: config.block_body.clone(),
            block_headers: config.block_headers.clone(),
        }
    }

    /// Returns `true` if no actions are configured (scanning is disabled).
    pub fn is_empty(&self) -> bool {
        !self.block && !self.redact && !self.header
    }
}

// ---------------------------------------------------------------------------
// ActionContext — identifies where the action is being applied
// ---------------------------------------------------------------------------

/// Context for metric labels when executing actions.
pub struct ActionContext<'a> {
    pub mode: &'a str,
    pub route: &'a str,
    pub direction: &'a str,
}

// ---------------------------------------------------------------------------
// ActionOutcome — result of executing the action pipeline
// ---------------------------------------------------------------------------

/// The outcome of running the action pipeline on a scan result.
pub enum ActionOutcome {
    /// PII detected and block action is enabled. Return this error response.
    Block {
        status: u16,
        body: Bytes,
        headers: HeaderMap,
    },
    /// PII detected, request/response should be forwarded (possibly mutated).
    Forward {
        /// The redacted body, when the body unit was rewritten.
        body: Option<Bytes>,
        extra_headers: HeaderMap,
        /// Replacement bytes per unit, produced by the redact action. Empty
        /// when redact is not configured or nothing carried a byte span. The
        /// caller maps each entry back to the field its unit came from.
        redacted: Vec<(UnitId, Bytes)>,
    },
    /// No PII detected, forward unchanged.
    Pass,
}

// ---------------------------------------------------------------------------
// Execute
// ---------------------------------------------------------------------------

/// Execute the action pipeline on a scan result.
///
/// Metrics are always incremented when PII is detected, regardless of actions.
/// Precedence: block → redact → header.
pub fn execute(
    scan_result: &ScanResult,
    units: &[Unit],
    redact_strategy: Option<&RedactWith>,
    action_set: &ActionSet,
    ctx: &ActionContext<'_>,
) -> ActionOutcome {
    if !scan_result.detected() {
        return ActionOutcome::Pass;
    }

    // The kind list is sorted and holds each kind once, so every list built
    // below — the detection counter, the block body, the header — is ordered
    // and counts a kind once however many findings, or guards, reported it.
    let kinds = scan_result.kinds();

    // Always increment detection metrics unconditionally when PII is detected.
    for kind in &kinds {
        metrics::inc_detection(kind, ctx.mode, ctx.route, ctx.direction);
    }

    // 1. Block — short-circuit
    if action_set.block {
        metrics::inc_blocked(ctx.mode, ctx.route, ctx.direction);

        let body = build_block_body(&action_set.block_body, &kinds);
        let headers = build_block_headers(&action_set.block_headers);

        return ActionOutcome::Block {
            status: action_set.block_status,
            body,
            headers,
        };
    }

    // 2. Redact — produce the replacement bytes from the findings
    let mut redacted = Vec::new();
    if action_set.redact {
        for kind in &kinds {
            metrics::inc_redacted(kind, ctx.mode, ctx.route, ctx.direction);
        }
        if let Some(strategy) = redact_strategy {
            redacted = redact_units(units, scan_result.findings(), strategy);
        }
    }

    let forward_body = redacted
        .iter()
        .find(|(id, _)| {
            units
                .get(id.index())
                .is_some_and(|u| u.kind == UnitKind::Body)
        })
        .map(|(_, bytes)| bytes.clone());

    // 3. Header — add X-PII-Detected
    let mut extra_headers = HeaderMap::new();
    if action_set.header {
        let kinds_value = kinds.join(",");
        if let Ok(value) = kinds_value.parse() {
            extra_headers.insert("x-pii-detected", value);
        }
    }

    ActionOutcome::Forward {
        body: forward_body,
        extra_headers,
        redacted,
    }
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Replace every spanned finding in the units it points at, and return the
/// replacement bytes per unit.
///
/// This reads the units and does not mutate them: an abandoned guard's worker
/// may still hold a clone of the shared units, so exclusive access is not
/// guaranteed. A unit with no spanned finding produces no entry.
///
/// Replacement length is fixed per kind (equal to the kind label length) so it
/// leaks nothing about the original value's length. `Char` repeats the mask
/// char `label.len()` times (EMAIL → `*****`); `TypeLabel` writes `[LABEL]`.
/// Replacements run back-to-front so byte offsets stay valid.
///
/// Both callers of this are here: `execute`, for the proxy modes, and the
/// `/v1/redact` handler, which builds no action set. One implementation, so
/// the two cannot drift.
pub(crate) fn redact_units(
    units: &[Unit],
    findings: &[Finding],
    strategy: &RedactWith,
) -> Vec<(UnitId, Bytes)> {
    let mut replaced = Vec::new();

    for unit in units {
        let mut spans: Vec<(usize, usize, &str)> = findings
            .iter()
            .filter(|f| f.unit == unit.id)
            .filter_map(|f| f.span.map(|s| (s.start, s.end, f.kind.as_str())))
            .collect();
        if spans.is_empty() {
            continue;
        }
        // The scanned content must be UTF-8 to rewrite it. JSON requires it,
        // and a CSV body that flattened had every cell validated.
        let Some(source) = unit.content.source_str() else {
            continue;
        };

        // Sort by start descending so a replacement cannot invalidate the
        // offsets of the ones still to come.
        spans.sort_unstable_by_key(|(start, _, _)| std::cmp::Reverse(*start));
        let mut text = source.to_string();
        let mut prev_start = usize::MAX;
        for (start, end, label) in spans {
            if end > prev_start {
                continue;
            }
            let replacement = match strategy {
                RedactWith::Char(c) => c.to_string().repeat(label.len()),
                RedactWith::TypeLabel => format!("[{label}]"),
            };
            text.replace_range(start..end, &replacement);
            prev_start = start;
        }
        replaced.push((unit.id, Bytes::from(text)));
    }

    replaced
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the block response body. Uses custom body if provided, otherwise
/// a default JSON listing detected PII kinds (never the matched values).
fn build_block_body(custom_body: &Option<String>, kinds: &[String]) -> Bytes {
    match custom_body {
        Some(template) => Bytes::from(template.clone()),
        None => {
            let json = serde_json::json!({
                "error": "PII detected",
                "kinds": kinds,
            });
            Bytes::from(json.to_string())
        }
    }
}

/// Convert block header config into an HTTP `HeaderMap`.
fn build_block_headers(headers: &[(String, String)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            name.parse::<axum::http::HeaderName>(),
            value.parse::<axum::http::HeaderValue>(),
        ) {
            map.insert(name, value);
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Span, UnitContent, Units};
    use std::sync::Arc;
    use test_case::test_case;

    const GUARD: &str = "test_guard";

    // "email: user@example.com, ssn: 123-45-6789"
    //         ^7            ^23        ^30    ^41
    const SAMPLE: &str = "email: user@example.com, ssn: 123-45-6789";

    fn ctx() -> ActionContext<'static> {
        ActionContext {
            mode: "reverse_proxy",
            route: "/api",
            direction: "request",
        }
    }

    fn body_units(text: &str) -> Arc<[Unit]> {
        let mut units = Units::new();
        units.push_body(UnitContent::text(text.to_string()));
        units.into_shared()
    }

    fn no_pii() -> ScanResult {
        ScanResult::default()
    }

    /// Two spanned findings over `SAMPLE`, so redaction has something to do.
    fn pii_with_spans() -> ScanResult {
        ScanResult::new(vec![
            Finding::spanned(UnitId(0), "EMAIL", GUARD, Span::new(7, 23)),
            Finding::spanned(UnitId(0), "US_SSN", GUARD, Span::new(30, 41)),
        ])
    }

    /// A finding with no byte span — nothing for redaction to replace.
    fn pii_without_spans() -> ScanResult {
        ScanResult::new(vec![Finding::whole_unit(UnitId(0), "EMAIL", GUARD, 0.9)])
    }

    fn action_set(block: bool, redact: bool, header: bool) -> ActionSet {
        ActionSet {
            block,
            redact,
            header,
            block_status: 403,
            block_body: None,
            block_headers: vec![],
        }
    }

    fn run(
        scan_result: &ScanResult,
        units: &[Unit],
        set: &ActionSet,
        ctx: &ActionContext<'_>,
    ) -> ActionOutcome {
        execute(
            scan_result,
            units,
            Some(&RedactWith::TypeLabel),
            set,
            ctx,
        )
    }

    // --- Pass: no PII always yields Pass regardless of actions ---

    #[test_case(false, false, false ; "empty actions")]
    #[test_case(true, false, false  ; "block configured")]
    #[test_case(false, true, false  ; "redact configured")]
    #[test_case(false, false, true  ; "header configured")]
    #[test_case(true, true, true    ; "all configured")]
    fn no_pii_returns_pass(block: bool, redact: bool, header: bool) {
        let units = body_units(SAMPLE);
        let outcome = run(&no_pii(), &units, &action_set(block, redact, header), &ctx());
        assert!(matches!(outcome, ActionOutcome::Pass));
    }

    // --- Block precedence: block wins regardless of other flags ---

    #[test_case(true, false, false ; "block only")]
    #[test_case(true, true, false  ; "block + redact")]
    #[test_case(true, false, true  ; "block + header")]
    #[test_case(true, true, true   ; "block + redact + header")]
    fn block_takes_precedence(block: bool, redact: bool, header: bool) {
        let units = body_units(SAMPLE);
        let outcome = run(
            &pii_with_spans(),
            &units,
            &action_set(block, redact, header),
            &ctx(),
        );
        assert!(matches!(outcome, ActionOutcome::Block { .. }));
    }

    #[test]
    fn block_default_body_contains_kinds() {
        let units = body_units(SAMPLE);
        let outcome = run(
            &pii_with_spans(),
            &units,
            &action_set(true, false, false),
            &ctx(),
        );
        if let ActionOutcome::Block { status, body, .. } = outcome {
            assert_eq!(status, 403);
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"], "PII detected");
            let kinds = json["kinds"].as_array().unwrap();
            assert!(kinds.iter().any(|k| k == "EMAIL"));
            assert!(kinds.iter().any(|k| k == "US_SSN"));
        } else {
            panic!("expected Block");
        }
    }

    #[test]
    fn block_custom_status_body_headers() {
        let set = ActionSet {
            block: true,
            redact: false,
            header: false,
            block_status: 451,
            block_body: Some(r#"{"error": "policy"}"#.into()),
            block_headers: vec![("X-Blocked-By".into(), "voidwall".into())],
        };
        let units = body_units(SAMPLE);
        let outcome = run(&pii_with_spans(), &units, &set, &ctx());
        if let ActionOutcome::Block {
            status,
            body,
            headers,
        } = outcome
        {
            assert_eq!(status, 451);
            assert_eq!(body, Bytes::from(r#"{"error": "policy"}"#));
            assert_eq!(headers.get("x-blocked-by").unwrap(), "voidwall");
        } else {
            panic!("expected Block");
        }
    }

    // --- Redact ---

    #[test]
    fn redact_forwards_redacted_body() {
        let units = body_units(SAMPLE);
        let outcome = run(
            &pii_with_spans(),
            &units,
            &action_set(false, true, false),
            &ctx(),
        );
        if let ActionOutcome::Forward {
            body,
            extra_headers,
            redacted,
        } = outcome
        {
            let body = body.unwrap();
            let text = std::str::from_utf8(&body).unwrap();
            assert_eq!(text, "email: [EMAIL], ssn: [US_SSN]");
            assert!(extra_headers.is_empty());
            assert_eq!(redacted.len(), 1);
            assert_eq!(redacted[0].0, UnitId(0));
        } else {
            panic!("expected Forward");
        }
    }

    #[test]
    fn redact_no_redacted_body_forwards_none() {
        let units = body_units(SAMPLE);
        let outcome = run(
            &pii_without_spans(),
            &units,
            &action_set(false, true, false),
            &ctx(),
        );
        if let ActionOutcome::Forward { body, redacted, .. } = outcome {
            assert!(body.is_none());
            assert!(redacted.is_empty());
        } else {
            panic!("expected Forward");
        }
    }

    #[test]
    fn redact_reads_the_scanned_content_without_mutating_it() {
        let units = body_units(SAMPLE);
        let findings = pii_with_spans();
        let replaced = redact_units(&units, findings.findings(), &RedactWith::TypeLabel);

        assert_eq!(replaced.len(), 1);
        assert_eq!(&replaced[0].1[..], b"email: [EMAIL], ssn: [US_SSN]");
        // The unit still holds what was scanned.
        assert_eq!(units[0].content.source_str(), Some(SAMPLE));
    }

    #[test]
    fn redact_char_mask_uses_the_kind_label_length() {
        let units = body_units(SAMPLE);
        let findings = pii_with_spans();
        let replaced = redact_units(&units, findings.findings(), &RedactWith::Char('*'));
        let text = std::str::from_utf8(&replaced[0].1).unwrap();
        // EMAIL is 5 characters, US_SSN is 6.
        assert_eq!(text, "email: *****, ssn: ******");
    }

    #[test]
    fn redact_rewrites_each_unit_it_has_a_span_for() {
        let mut units = Units::new();
        units.push_body(UnitContent::text("body user@example.com".into()));
        units.push_path("/users/other@example.com".into());
        units.push_query("clean=1".into());
        let units = units.into_shared();

        let findings = vec![
            Finding::spanned(UnitId(0), "EMAIL", GUARD, Span::new(5, 21)),
            Finding::spanned(UnitId(1), "EMAIL", GUARD, Span::new(7, 24)),
        ];
        let replaced = redact_units(&units, &findings, &RedactWith::TypeLabel);

        assert_eq!(replaced.len(), 2, "the clean query produces no entry");
        assert_eq!(&replaced[0].1[..], b"body [EMAIL]");
        assert_eq!(&replaced[1].1[..], b"/users/[EMAIL]");
    }

    #[test]
    fn redact_leaves_a_structured_document_valid() {
        let raw = Bytes::from_static(br#"{"phone":"555-123-4567"}"#);
        let mut units = Units::new();
        units.push_body(UnitContent::Structured {
            fragments: Vec::new(),
            raw,
        });
        let units = units.into_shared();

        // Document-absolute span over the value, inside the quotes.
        let findings = vec![Finding::spanned(
            UnitId(0),
            "US_PHONE_NUMBER",
            GUARD,
            Span::new(10, 22),
        )];
        let replaced = redact_units(&units, &findings, &RedactWith::TypeLabel);
        let value: serde_json::Value = serde_json::from_slice(&replaced[0].1).unwrap();
        assert_eq!(value["phone"], "[US_PHONE_NUMBER]");
    }

    #[test]
    fn redact_skips_content_that_is_not_utf8() {
        let mut units = Units::new();
        units.push_body(UnitContent::PlainText(Bytes::from_static(&[0xff, 0xfe])));
        let units = units.into_shared();
        let findings = vec![Finding::spanned(UnitId(0), "EMAIL", GUARD, Span::new(0, 1))];
        assert!(redact_units(&units, &findings, &RedactWith::TypeLabel).is_empty());
    }

    // --- Header ---

    #[test]
    fn header_adds_x_pii_detected() {
        let units = body_units(SAMPLE);
        let outcome = run(
            &pii_with_spans(),
            &units,
            &action_set(false, false, true),
            &ctx(),
        );
        if let ActionOutcome::Forward {
            body,
            extra_headers,
            ..
        } = outcome
        {
            assert!(body.is_none());
            let val = extra_headers
                .get("x-pii-detected")
                .unwrap()
                .to_str()
                .unwrap();
            assert_eq!(val, "EMAIL,US_SSN");
        } else {
            panic!("expected Forward");
        }
    }

    // --- Redact + Header ---

    #[test]
    fn redact_and_header_combined() {
        let units = body_units(SAMPLE);
        let outcome = run(
            &pii_with_spans(),
            &units,
            &action_set(false, true, true),
            &ctx(),
        );
        if let ActionOutcome::Forward {
            body,
            extra_headers,
            ..
        } = outcome
        {
            assert!(body.is_some());
            assert!(extra_headers.get("x-pii-detected").is_some());
        } else {
            panic!("expected Forward");
        }
    }

    // --- Empty actions with PII still records detections, returns Forward ---

    #[test]
    fn pii_with_empty_actions_returns_forward() {
        let units = body_units(SAMPLE);
        let outcome = run(
            &pii_with_spans(),
            &units,
            &action_set(false, false, false),
            &ctx(),
        );
        if let ActionOutcome::Forward {
            body,
            extra_headers,
            redacted,
        } = outcome
        {
            assert!(body.is_none());
            assert!(extra_headers.is_empty());
            assert!(redacted.is_empty());
        } else {
            panic!("expected Forward (metrics-only)");
        }
    }

    // --- Deterministic kind order ---

    /// Findings arriving in a jumbled kind order, as two guards over one unit
    /// would produce before the engine sorts them.
    fn three_kinds() -> ScanResult {
        ScanResult::new(vec![
            Finding::spanned(UnitId(0), "US_SSN", "guard_b", Span::new(0, 1)),
            Finding::spanned(UnitId(0), "EMAIL", "guard_a", Span::new(2, 3)),
            Finding::spanned(UnitId(0), "IBAN_CODE", "guard_b", Span::new(4, 5)),
        ])
    }

    #[test]
    fn block_body_names_the_kinds_in_sorted_order() {
        let units = body_units(SAMPLE);
        let outcome = run(&three_kinds(), &units, &action_set(true, false, false), &ctx());
        let ActionOutcome::Block { body, .. } = outcome else {
            panic!("expected Block");
        };
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["kinds"],
            serde_json::json!(["EMAIL", "IBAN_CODE", "US_SSN"])
        );
    }

    #[test]
    fn the_header_names_the_kinds_in_sorted_order() {
        let units = body_units(SAMPLE);
        let outcome = run(&three_kinds(), &units, &action_set(false, false, true), &ctx());
        let ActionOutcome::Forward { extra_headers, .. } = outcome else {
            panic!("expected Forward");
        };
        assert_eq!(
            extra_headers.get("x-pii-detected").unwrap(),
            "EMAIL,IBAN_CODE,US_SSN"
        );
    }

    #[test]
    fn the_same_content_scanned_twice_lists_the_kinds_the_same_way() {
        let units = body_units(SAMPLE);
        let body_of = || {
            let outcome = run(&three_kinds(), &units, &action_set(true, false, false), &ctx());
            match outcome {
                ActionOutcome::Block { body, .. } => body,
                _ => panic!("expected Block"),
            }
        };
        assert_eq!(body_of(), body_of());
    }

    // --- Detection counter ---

    #[test]
    fn the_detection_counter_increments_once_per_kind() {
        // A route label of its own, so a parallel test cannot move the counter
        // under this one.
        let ctx = ActionContext {
            mode: "reverse_proxy",
            route: "detections-once-per-kind",
            direction: "request",
        };
        let counter = metrics::DETECTIONS_TOTAL.with_label_values(&[
            "EMAIL",
            ctx.mode,
            ctx.route,
            ctx.direction,
        ]);
        let before = counter.get();

        // Four findings of one kind, from two different guards.
        let result = ScanResult::new(vec![
            Finding::spanned(UnitId(0), "EMAIL", "guard_a", Span::new(0, 1)),
            Finding::spanned(UnitId(0), "EMAIL", "guard_a", Span::new(2, 3)),
            Finding::spanned(UnitId(0), "EMAIL", "guard_b", Span::new(4, 5)),
            Finding::spanned(UnitId(0), "EMAIL", "guard_b", Span::new(6, 7)),
        ]);
        let units = body_units(SAMPLE);
        run(&result, &units, &action_set(false, false, false), &ctx);

        assert_eq!(counter.get(), before + 1);
    }

    // --- Direction contexts ---

    #[test_case("reverse_proxy", "/api", "request"  ; "reverse proxy request")]
    #[test_case("reverse_proxy", "/api", "response" ; "reverse proxy response")]
    #[test_case("forward_proxy", "global", "request"  ; "forward proxy request")]
    #[test_case("forward_proxy", "global", "response" ; "forward proxy response")]
    fn direction_contexts_produce_forward(mode: &str, route: &str, direction: &str) {
        let ctx = ActionContext {
            mode,
            route,
            direction,
        };
        let units = body_units(SAMPLE);
        let outcome = run(&pii_with_spans(), &units, &action_set(false, false, true), &ctx);
        assert!(matches!(outcome, ActionOutcome::Forward { .. }));
    }

    // --- ActionSet construction from DirectionConfig ---

    #[test_case(&[Action::Redact, Action::Header], true, false, true ; "redact+header")]
    #[test_case(&[Action::Block], false, true, false ; "block only")]
    #[test_case(&[], false, false, false ; "empty")]
    fn from_direction_config(
        actions: &[Action],
        expect_redact: bool,
        expect_block: bool,
        expect_header: bool,
    ) {
        let config = DirectionConfig {
            actions: actions.to_vec(),
            redact_strategy: if actions.contains(&Action::Redact) {
                Some(crate::config::RedactStrategy::TypeLabel)
            } else {
                None
            },
            mask_char: None,
            block_status: 403,
            block_body: None,
            block_headers: vec![],
        };
        let set = ActionSet::from_direction_config(&config);
        assert_eq!(set.redact, expect_redact);
        assert_eq!(set.block, expect_block);
        assert_eq!(set.header, expect_header);
    }

    #[test]
    fn is_empty_true_for_no_actions() {
        assert!(action_set(false, false, false).is_empty());
    }

    #[test_case(true, false, false ; "block")]
    #[test_case(false, true, false ; "redact")]
    #[test_case(false, false, true ; "header")]
    fn is_empty_false_with_any_action(block: bool, redact: bool, header: bool) {
        assert!(!action_set(block, redact, header).is_empty());
    }

    // --- Block body/header helpers ---

    #[test]
    fn build_block_body_default_json() {
        let body = build_block_body(&None, &["EMAIL".into()]);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["kinds"][0], "EMAIL");
    }

    #[test]
    fn build_block_body_custom() {
        let body = build_block_body(&Some("custom".into()), &["EMAIL".into()]);
        assert_eq!(body, Bytes::from("custom"));
    }

    #[test]
    fn build_block_headers_works() {
        let map = build_block_headers(&[("Content-Type".into(), "application/json".into())]);
        assert_eq!(map.get("content-type").unwrap(), "application/json");
    }
}
