//! Per-IP rate limiting for the public Fly.io demo deployment.
//!
//! Compiled only when the `fly-rate-limit` feature is enabled — self-hosted
//! deployments are expected to sit behind their own gateway and don't need
//! this. The Fly demo is unauthenticated, so we cap each client at 3 req/s
//! to keep a single visitor from soaking up the small Fly machine.
//!
//! Client identification: we trust `Fly-Client-IP`, which Fly's edge sets to
//! the real client address before the request reaches our binary. The peer
//! address is the Fly proxy itself, so falling back to it would bucket every
//! caller together — we'd rather 500-equivalent (reject) than mis-bucket, so
//! a missing or malformed header yields a `429`.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Request;
use axum::http::HeaderName;
use governor::middleware::NoOpMiddleware;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::KeyExtractor;
use tower_governor::{GovernorError, GovernorLayer};

const FLY_CLIENT_IP: HeaderName = HeaderName::from_static("fly-client-ip");

#[derive(Clone, Copy, Debug, Default)]
pub struct FlyClientIpExtractor;

impl KeyExtractor for FlyClientIpExtractor {
    type Key = IpAddr;

    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        req.headers()
            .get(&FLY_CLIENT_IP)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<IpAddr>().ok())
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

/// Build the per-IP rate-limit layer. 3 req/s sustained, burst of 3.
///
/// `period` is the spacing between token replenishments and `burst_size` is
/// the bucket capacity, so 333 ms × 3 tokens ≈ 3 req/s. tower_governor spawns
/// a background task to evict idle IP entries; we keep its default cadence.
pub fn layer() -> GovernorLayer<FlyClientIpExtractor, NoOpMiddleware> {
    let config = GovernorConfigBuilder::default()
        .period(Duration::from_millis(333))
        .burst_size(3)
        .key_extractor(FlyClientIpExtractor)
        .finish()
        .expect("rate-limit config is statically valid");

    GovernorLayer {
        config: Arc::new(config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[test]
    fn extracts_fly_client_ip_header() {
        let req = Request::builder()
            .header("fly-client-ip", "203.0.113.42")
            .body(())
            .unwrap();
        assert_eq!(
            FlyClientIpExtractor.extract(&req).unwrap(),
            "203.0.113.42".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn rejects_missing_header() {
        let req = Request::builder().body(()).unwrap();
        assert!(matches!(
            FlyClientIpExtractor.extract(&req),
            Err(GovernorError::UnableToExtractKey)
        ));
    }

    #[test]
    fn rejects_malformed_header() {
        let req = Request::builder()
            .header("fly-client-ip", "not-an-ip")
            .body(())
            .unwrap();
        assert!(matches!(
            FlyClientIpExtractor.extract(&req),
            Err(GovernorError::UnableToExtractKey)
        ));
    }
}
