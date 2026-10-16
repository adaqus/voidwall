use lazy_static::lazy_static;
use prometheus::{
    self, Gauge, HistogramVec, IntCounterVec, histogram_opts, opts, register_gauge,
    register_histogram_vec, register_int_counter_vec,
};

lazy_static! {
    /// PII detections by kind, mode, route, and direction.
    pub static ref DETECTIONS_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("voidwall_pii_detections_total", "Total PII detections"),
        &["pii_kind", "mode", "route", "direction"]
    )
    .unwrap();

    /// Requests/responses blocked due to PII detection.
    pub static ref BLOCKED_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("voidwall_pii_blocked_total", "Total blocked requests/responses"),
        &["mode", "route", "direction"]
    )
    .unwrap();

    /// Messages in which a guard reported findings, by guard, mode, route, and
    /// direction. One increment per guard per message, however many findings.
    /// The guard name comes from configuration, never from a request.
    pub static ref GUARD_DETECTIONS_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!(
            "voidwall_detections_total",
            "Total messages in which a guard reported findings"
        ),
        &["guard", "mode", "route", "direction"]
    )
    .unwrap();

    /// Messages the proxy stopped: a detection, or a fail_close error.
    pub static ref MESSAGES_BLOCKED_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("voidwall_blocked_total", "Total messages the proxy stopped"),
        &["mode", "route", "direction"]
    )
    .unwrap();

    /// Total HTTP requests processed.
    pub static ref REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("voidwall_requests_total", "Total HTTP requests"),
        &["mode", "route", "method", "status"]
    )
    .unwrap();

    /// Request processing duration in seconds.
    pub static ref REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        histogram_opts!(
            "voidwall_request_duration_seconds",
            "Request processing duration in seconds"
        ),
        &["mode", "route"]
    )
    .unwrap();

    /// Errors with fail-open/fail-close outcome.
    pub static ref ERRORS_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("voidwall_errors_total", "Total errors by outcome and reason"),
        &["outcome", "reason"]
    )
    .unwrap();

    /// Values a decoder skipped on purpose without a scan, by reason.
    pub static ref UNSCANNED_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!(
            "voidwall_unscanned_total",
            "Total values skipped without a scan, by reason"
        ),
        &["mode", "route", "direction", "reason"]
    )
    .unwrap();

    // --- Process metrics ---

    pub static ref PROCESS_RSS_BYTES: Gauge = register_gauge!(
        "process_resident_memory_bytes",
        "Resident memory size in bytes"
    )
    .unwrap();

    pub static ref PROCESS_VSIZE_BYTES: Gauge = register_gauge!(
        "process_virtual_memory_bytes",
        "Virtual memory size in bytes"
    )
    .unwrap();

    pub static ref PROCESS_CPU_SECONDS: Gauge = register_gauge!(
        "process_cpu_seconds_total",
        "Total user and system CPU time spent in seconds"
    )
    .unwrap();

    pub static ref PROCESS_OPEN_FDS: Gauge = register_gauge!(
        "process_open_fds",
        "Number of open file descriptors"
    )
    .unwrap();

    pub static ref PROCESS_THREADS: Gauge = register_gauge!(
        "process_threads",
        "Number of OS threads in the process"
    )
    .unwrap();
}

/// Record a PII detection.
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

/// Record a message in which `guard` reported findings.
pub fn inc_guard_detection(guard: &str, mode: &str, route: &str, direction: &str) {
    GUARD_DETECTIONS_TOTAL
        .with_label_values(&[guard, mode, route, direction])
        .inc();
}

/// Record a message the proxy stopped, whatever stopped it.
pub fn inc_message_blocked(mode: &str, route: &str, direction: &str) {
    MESSAGES_BLOCKED_TOTAL
        .with_label_values(&[mode, route, direction])
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
    ERRORS_TOTAL.with_label_values(&[outcome, reason]).inc();
}

/// Why a decoder skipped a value without a scan. The `reason` label of
/// `voidwall_unscanned_total` comes from this fixed set only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnscannedReason {
    /// A base64 value: an inline image, audio, or file.
    EncodedData,
}

impl UnscannedReason {
    pub fn as_str(self) -> &'static str {
        match self {
            UnscannedReason::EncodedData => "encoded_data",
        }
    }
}

/// Record `count` values skipped without a scan.
pub fn inc_unscanned(
    mode: &str,
    route: &str,
    direction: &str,
    reason: UnscannedReason,
    count: u64,
) {
    UNSCANNED_TOTAL
        .with_label_values(&[mode, route, direction, reason.as_str()])
        .inc_by(count);
}

/// Update process metrics from /proc/self. Called on each /metrics scrape.
pub fn update_process_metrics() {
    let page_size = procfs::page_size();

    if let Ok(me) = procfs::process::Process::myself() {
        if let Ok(stat) = me.stat() {
            PROCESS_RSS_BYTES.set((stat.rss as f64) * (page_size as f64));
            PROCESS_VSIZE_BYTES.set(stat.vsize as f64);
            let ticks_per_sec = procfs::ticks_per_second() as f64;
            let cpu_secs = (stat.utime as f64 + stat.stime as f64) / ticks_per_sec;
            PROCESS_CPU_SECONDS.set(cpu_secs);
            PROCESS_THREADS.set(stat.num_threads as f64);
        }

        if let Ok(fds) = me.fd_count() {
            PROCESS_OPEN_FDS.set(fds as f64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case("Email", "reverse_proxy", "/api", "request" ; "email on reverse proxy request")]
    #[test_case("UsPhoneNumber", "forward_proxy", "global", "response" ; "phone on forward proxy response")]
    #[test_case("IpAddress", "http_api", "global", "request" ; "ip on http api request")]
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

    #[test_case("pii", "reverse_proxy", "/api", "request" ; "pii guard on reverse proxy request")]
    #[test_case("injection", "http_api", "global", "request" ; "configured guard on http api")]
    fn inc_guard_detection_increments(guard: &str, mode: &str, route: &str, direction: &str) {
        let before = GUARD_DETECTIONS_TOTAL
            .with_label_values(&[guard, mode, route, direction])
            .get();
        inc_guard_detection(guard, mode, route, direction);
        let after = GUARD_DETECTIONS_TOTAL
            .with_label_values(&[guard, mode, route, direction])
            .get();
        assert_eq!(after, before + 1);
    }

    #[test_case("reverse_proxy", "/api", "request" ; "reverse proxy request")]
    #[test_case("reverse_proxy", "/payments", "response" ; "reverse proxy response")]
    fn inc_message_blocked_increments(mode: &str, route: &str, direction: &str) {
        let before = MESSAGES_BLOCKED_TOTAL
            .with_label_values(&[mode, route, direction])
            .get();
        inc_message_blocked(mode, route, direction);
        let after = MESSAGES_BLOCKED_TOTAL
            .with_label_values(&[mode, route, direction])
            .get();
        assert_eq!(after, before + 1);
    }

    #[test_case("http_api", "global", "POST", "200" ; "http api post 200")]
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
    #[test_case("http_api", "global", 1.5 ; "http api duration")]
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
        let before = ERRORS_TOTAL.with_label_values(&[outcome, reason]).get();
        inc_error(outcome, reason);
        let after = ERRORS_TOTAL.with_label_values(&[outcome, reason]).get();
        assert_eq!(after, before + 1);
    }

    #[test]
    fn inc_unscanned_increments_with_four_labels() {
        let labels = ["http_api", "/test-unscanned", "request", "encoded_data"];
        let before = UNSCANNED_TOTAL.with_label_values(&labels).get();
        inc_unscanned(
            "http_api",
            "/test-unscanned",
            "request",
            UnscannedReason::EncodedData,
            2,
        );
        assert_eq!(UNSCANNED_TOTAL.with_label_values(&labels).get(), before + 2);
    }

    #[test]
    fn different_labels_are_independent() {
        let email_before = DETECTIONS_TOTAL
            .with_label_values(&["Email", "reverse_proxy", "/test-independent", "request"])
            .get();
        let phone_before = DETECTIONS_TOTAL
            .with_label_values(&[
                "UsPhoneNumber",
                "reverse_proxy",
                "/test-independent",
                "request",
            ])
            .get();

        inc_detection("Email", "reverse_proxy", "/test-independent", "request");

        let email_after = DETECTIONS_TOTAL
            .with_label_values(&["Email", "reverse_proxy", "/test-independent", "request"])
            .get();
        let phone_after = DETECTIONS_TOTAL
            .with_label_values(&[
                "UsPhoneNumber",
                "reverse_proxy",
                "/test-independent",
                "request",
            ])
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
