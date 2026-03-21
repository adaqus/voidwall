use lazy_static::lazy_static;
use prometheus::{
    self, HistogramVec, IntCounterVec, histogram_opts, opts, register_histogram_vec,
    register_int_counter_vec,
};

lazy_static! {
    /// PII detections by kind, mode, route, and direction.
    pub static ref DETECTIONS_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("pii_proxy_detections_total", "Total PII detections"),
        &["pii_kind", "mode", "route", "direction"]
    )
    .unwrap();

    /// Requests/responses blocked due to PII detection.
    pub static ref BLOCKED_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("pii_proxy_blocked_total", "Total blocked requests/responses"),
        &["mode", "route", "direction"]
    )
    .unwrap();

    /// PII instances redacted.
    pub static ref REDACTED_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("pii_proxy_redacted_total", "Total redacted PII instances"),
        &["pii_kind", "mode", "route", "direction"]
    )
    .unwrap();

    /// Total HTTP requests processed.
    pub static ref REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("pii_proxy_requests_total", "Total HTTP requests"),
        &["mode", "route", "method", "status"]
    )
    .unwrap();

    /// Request processing duration in seconds.
    pub static ref REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        histogram_opts!(
            "pii_proxy_request_duration_seconds",
            "Request processing duration in seconds"
        ),
        &["mode", "route"]
    )
    .unwrap();

    /// Errors with fail-open/fail-close outcome.
    pub static ref ERRORS_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("pii_proxy_errors_total", "Total errors by outcome and reason"),
        &["outcome", "reason"]
    )
    .unwrap();
}

/// Record a PII detection for the given kind, mode, route, and direction.
pub fn inc_detection(pii_kind: &str, mode: &str, route: &str, direction: &str) {
    DETECTIONS_TOTAL
        .with_label_values(&[pii_kind, mode, route, direction])
        .inc();
}

/// Record a blocked request or response.
pub fn inc_blocked(mode: &str, route: &str, direction: &str) {
    BLOCKED_TOTAL
        .with_label_values(&[mode, route, direction])
        .inc();
}

/// Record a redacted PII instance.
pub fn inc_redacted(pii_kind: &str, mode: &str, route: &str, direction: &str) {
    REDACTED_TOTAL
        .with_label_values(&[pii_kind, mode, route, direction])
        .inc();
}

/// Record a completed request.
pub fn inc_request(mode: &str, route: &str, method: &str, status: &str) {
    REQUESTS_TOTAL
        .with_label_values(&[mode, route, method, status])
        .inc();
}

/// Observe request duration in seconds.
pub fn observe_duration(mode: &str, route: &str, duration_secs: f64) {
    REQUEST_DURATION_SECONDS
        .with_label_values(&[mode, route])
        .observe(duration_secs);
}

/// Record an error with its outcome (passed/blocked) and reason.
pub fn inc_error(outcome: &str, reason: &str) {
    ERRORS_TOTAL
        .with_label_values(&[outcome, reason])
        .inc();
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case("Email", "reverse_proxy", "/api", "request" ; "email on reverse proxy request")]
    #[test_case("PhoneNumber", "forward_proxy", "global", "response" ; "phone on forward proxy response")]
    #[test_case("IpAddress", "rest_api", "global", "request" ; "ip on rest api request")]
    fn inc_detection_increments(pii_kind: &str, mode: &str, route: &str, direction: &str) {
        let before = DETECTIONS_TOTAL
            .with_label_values(&[pii_kind, mode, route, direction])
            .get();
        inc_detection(pii_kind, mode, route, direction);
        let after = DETECTIONS_TOTAL
            .with_label_values(&[pii_kind, mode, route, direction])
            .get();
        assert_eq!(after, before + 1);
    }

    #[test_case("forward_proxy", "global", "request" ; "forward proxy request")]
    #[test_case("reverse_proxy", "/payments", "response" ; "reverse proxy response")]
    fn inc_blocked_increments(mode: &str, route: &str, direction: &str) {
        let before = BLOCKED_TOTAL
            .with_label_values(&[mode, route, direction])
            .get();
        inc_blocked(mode, route, direction);
        let after = BLOCKED_TOTAL
            .with_label_values(&[mode, route, direction])
            .get();
        assert_eq!(after, before + 1);
    }

    #[test_case("Email", "reverse_proxy", "/api", "request" ; "email redacted request")]
    #[test_case("PhoneNumber", "forward_proxy", "global", "response" ; "phone redacted response")]
    fn inc_redacted_increments(pii_kind: &str, mode: &str, route: &str, direction: &str) {
        let before = REDACTED_TOTAL
            .with_label_values(&[pii_kind, mode, route, direction])
            .get();
        inc_redacted(pii_kind, mode, route, direction);
        let after = REDACTED_TOTAL
            .with_label_values(&[pii_kind, mode, route, direction])
            .get();
        assert_eq!(after, before + 1);
    }

    #[test_case("rest_api", "global", "POST", "200" ; "rest api post 200")]
    #[test_case("reverse_proxy", "/api", "GET", "403" ; "reverse proxy get 403")]
    fn inc_request_increments(mode: &str, route: &str, method: &str, status: &str) {
        let before = REQUESTS_TOTAL
            .with_label_values(&[mode, route, method, status])
            .get();
        inc_request(mode, route, method, status);
        let after = REQUESTS_TOTAL
            .with_label_values(&[mode, route, method, status])
            .get();
        assert_eq!(after, before + 1);
    }

    #[test_case("reverse_proxy", "/api", 0.042 ; "reverse proxy duration")]
    #[test_case("rest_api", "global", 1.5 ; "rest api duration")]
    fn observe_duration_records(mode: &str, route: &str, secs: f64) {
        let before = REQUEST_DURATION_SECONDS
            .with_label_values(&[mode, route])
            .get_sample_count();
        observe_duration(mode, route, secs);
        let after = REQUEST_DURATION_SECONDS
            .with_label_values(&[mode, route])
            .get_sample_count();
        assert_eq!(after, before + 1);
    }

    #[test_case("passed", "scanner_failure" ; "fail open scanner")]
    #[test_case("blocked", "body_too_large" ; "fail close body size")]
    fn inc_error_increments(outcome: &str, reason: &str) {
        let before = ERRORS_TOTAL
            .with_label_values(&[outcome, reason])
            .get();
        inc_error(outcome, reason);
        let after = ERRORS_TOTAL
            .with_label_values(&[outcome, reason])
            .get();
        assert_eq!(after, before + 1);
    }

    #[test]
    fn different_labels_are_independent() {
        let email_before = DETECTIONS_TOTAL
            .with_label_values(&["Email", "reverse_proxy", "/test-independent", "request"])
            .get();
        let phone_before = DETECTIONS_TOTAL
            .with_label_values(&["PhoneNumber", "reverse_proxy", "/test-independent", "request"])
            .get();

        inc_detection("Email", "reverse_proxy", "/test-independent", "request");

        let email_after = DETECTIONS_TOTAL
            .with_label_values(&["Email", "reverse_proxy", "/test-independent", "request"])
            .get();
        let phone_after = DETECTIONS_TOTAL
            .with_label_values(&["PhoneNumber", "reverse_proxy", "/test-independent", "request"])
            .get();

        assert_eq!(email_after, email_before + 1);
        assert_eq!(phone_after, phone_before);
    }

    #[test]
    fn direction_labels_are_independent() {
        let req_before = DETECTIONS_TOTAL
            .with_label_values(&["Email", "reverse_proxy", "/test-direction", "request"])
            .get();
        let resp_before = DETECTIONS_TOTAL
            .with_label_values(&["Email", "reverse_proxy", "/test-direction", "response"])
            .get();

        inc_detection("Email", "reverse_proxy", "/test-direction", "request");

        let req_after = DETECTIONS_TOTAL
            .with_label_values(&["Email", "reverse_proxy", "/test-direction", "request"])
            .get();
        let resp_after = DETECTIONS_TOTAL
            .with_label_values(&["Email", "reverse_proxy", "/test-direction", "response"])
            .get();

        assert_eq!(req_after, req_before + 1);
        assert_eq!(resp_after, resp_before);
    }
}
