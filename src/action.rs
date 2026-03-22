use axum::http::HeaderMap;
use bytes::Bytes;

use crate::config::{Action, DirectionConfig};
use crate::metrics;
use crate::scanner::ScanResult;

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
        body: Option<Bytes>,
        extra_headers: HeaderMap,
        scan_result: ScanResult,
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
    scan_result: ScanResult,
    action_set: &ActionSet,
    ctx: &ActionContext<'_>,
) -> ActionOutcome {
    if !scan_result.detected {
        return ActionOutcome::Pass;
    }

    // Always increment detection metrics unconditionally when PII is detected.
    for kind in &scan_result.kinds {
        metrics::inc_detection(kind, ctx.mode, ctx.route, ctx.direction);
    }

    // 1. Block — short-circuit
    if action_set.block {
        metrics::inc_blocked(ctx.mode, ctx.route, ctx.direction);

        let body = build_block_body(&action_set.block_body, &scan_result.kinds);
        let headers = build_block_headers(&action_set.block_headers);

        return ActionOutcome::Block {
            status: action_set.block_status,
            body,
            headers,
        };
    }

    // 2. Redact — collect mutated body
    let forward_body = if action_set.redact {
        for kind in &scan_result.kinds {
            metrics::inc_redacted(kind, ctx.mode, ctx.route, ctx.direction);
        }
        scan_result.redacted_body.clone()
    } else {
        None
    };

    // 3. Header — add X-PII-Detected
    let mut extra_headers = HeaderMap::new();
    if action_set.header {
        let kinds_value = scan_result.kinds.join(",");
        if let Ok(value) = kinds_value.parse() {
            extra_headers.insert("x-pii-detected", value);
        }
    }

    ActionOutcome::Forward {
        body: forward_body,
        extra_headers,
        scan_result,
    }
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
    use test_case::test_case;

    fn ctx() -> ActionContext<'static> {
        ActionContext {
            mode: "reverse_proxy",
            route: "/api",
            direction: "request",
        }
    }

    fn no_pii() -> ScanResult {
        ScanResult {
            detected: false,
            kinds: vec![],
            matches_count: 0,
            redacted_body: None,
            redacted_url: None,
            redacted_query: None,
            redacted_headers: None,
        }
    }

    fn pii_with_redaction() -> ScanResult {
        ScanResult {
            detected: true,
            kinds: vec!["EMAIL".into(), "US_SSN".into()],
            matches_count: 2,
            redacted_body: Some(Bytes::from("email: [EMAIL], ssn: [US_SSN]")),
            redacted_url: None,
            redacted_query: None,
            redacted_headers: None,
        }
    }

    fn pii_no_redaction() -> ScanResult {
        ScanResult {
            detected: true,
            kinds: vec!["EMAIL".into()],
            matches_count: 1,
            redacted_body: None,
            redacted_url: None,
            redacted_query: None,
            redacted_headers: None,
        }
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

    // --- Pass: no PII always yields Pass regardless of actions ---

    #[test_case(false, false, false ; "empty actions")]
    #[test_case(true, false, false  ; "block configured")]
    #[test_case(false, true, false  ; "redact configured")]
    #[test_case(false, false, true  ; "header configured")]
    #[test_case(true, true, true    ; "all configured")]
    fn no_pii_returns_pass(block: bool, redact: bool, header: bool) {
        let outcome = execute(no_pii(), &action_set(block, redact, header), &ctx());
        assert!(matches!(outcome, ActionOutcome::Pass));
    }

    // --- Block precedence: block wins regardless of other flags ---

    #[test_case(true, false, false ; "block only")]
    #[test_case(true, true, false  ; "block + redact")]
    #[test_case(true, false, true  ; "block + header")]
    #[test_case(true, true, true   ; "block + redact + header")]
    fn block_takes_precedence(block: bool, redact: bool, header: bool) {
        let outcome = execute(
            pii_with_redaction(),
            &action_set(block, redact, header),
            &ctx(),
        );
        assert!(matches!(outcome, ActionOutcome::Block { .. }));
    }

    #[test]
    fn block_default_body_contains_kinds() {
        let outcome = execute(
            pii_with_redaction(),
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
            block_headers: vec![("X-Blocked-By".into(), "pii-proxy".into())],
        };
        let outcome = execute(pii_with_redaction(), &set, &ctx());
        if let ActionOutcome::Block {
            status,
            body,
            headers,
        } = outcome
        {
            assert_eq!(status, 451);
            assert_eq!(body, Bytes::from(r#"{"error": "policy"}"#));
            assert_eq!(headers.get("x-blocked-by").unwrap(), "pii-proxy");
        } else {
            panic!("expected Block");
        }
    }

    // --- Redact ---

    #[test]
    fn redact_forwards_redacted_body() {
        let outcome = execute(
            pii_with_redaction(),
            &action_set(false, true, false),
            &ctx(),
        );
        if let ActionOutcome::Forward {
            body,
            extra_headers,
            ..
        } = outcome
        {
            let body = body.unwrap();
            let text = std::str::from_utf8(&body).unwrap();
            assert!(text.contains("[EMAIL]"));
            assert!(text.contains("[US_SSN]"));
            assert!(extra_headers.is_empty());
        } else {
            panic!("expected Forward");
        }
    }

    #[test]
    fn redact_no_redacted_body_forwards_none() {
        let outcome = execute(pii_no_redaction(), &action_set(false, true, false), &ctx());
        if let ActionOutcome::Forward { body, .. } = outcome {
            assert!(body.is_none());
        } else {
            panic!("expected Forward");
        }
    }

    // --- Header ---

    #[test]
    fn header_adds_x_pii_detected() {
        let outcome = execute(
            pii_with_redaction(),
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
            assert!(val.contains("EMAIL"));
            assert!(val.contains("US_SSN"));
        } else {
            panic!("expected Forward");
        }
    }

    // --- Redact + Header ---

    #[test]
    fn redact_and_header_combined() {
        let outcome = execute(pii_with_redaction(), &action_set(false, true, true), &ctx());
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
        let outcome = execute(
            pii_with_redaction(),
            &action_set(false, false, false),
            &ctx(),
        );
        if let ActionOutcome::Forward {
            body,
            extra_headers,
            ..
        } = outcome
        {
            assert!(body.is_none());
            assert!(extra_headers.is_empty());
        } else {
            panic!("expected Forward (metrics-only)");
        }
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
        let outcome = execute(pii_with_redaction(), &action_set(false, false, true), &ctx);
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
