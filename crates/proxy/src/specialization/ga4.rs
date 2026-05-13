//! GA4 specialization. Decodes Google Analytics 4 traffic shapes
//! (`/g/collect` browser tracker — short keys in URL query or form-encoded
//! POST body — and `/mp/collect` Measurement Protocol — JSON body), scans
//! the declared allowlist of integrator-controlled fields, and re-encodes
//! the result so redaction labels live at the right encoding layer.
//!
//! Source of truth for the allowlists is DESIGN.md § "Specializations →
//! ga4". The mapping below mirrors that table; field families are grouped
//! into `field_treatment()` so the dispatch is in one place.

use bytes::Bytes;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde_json::Value;

use super::{
    AggregatedScan, ProcessFuture, ProcessedPart, ProcessedRequest, ScanHandle, Specialization,
    SpecializationError,
};

pub struct Ga4Specialization;

/// Max depth for recursive URL decoding of `dl`/`dr`. Three layers is plenty
/// — analytics URLs rarely embed even one inner URL, and pathological
/// payloads that try to exhaust scanner budget shouldn't get to keep going.
const URL_RECURSION_LIMIT: u8 = 3;

/// Maximum number of form pairs we'll parse out of a single query/body
/// string. Bounds memory regardless of payload shape.
const MAX_FORM_PAIRS: usize = 4096;

/// How a particular GA4 short-key form field should be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormFieldTreatment {
    /// Field is scanned as a flat string. `context` is the field name.
    Flat,
    /// Field's value is itself a URL — its inner query parameters are
    /// scanned individually, and the path component scanned flat.
    RecursiveUrl,
    /// Field is opaque (auto-generated ID, version stamp, …) — pass through
    /// without scanning.
    Skip,
    /// Field is not in the allowlist. Pass through unchanged.
    Unknown,
}

fn form_field_treatment(name: &str) -> FormFieldTreatment {
    // Recursive-URL fields first — short list.
    if matches!(name, "dl" | "dr") {
        return FormFieldTreatment::RecursiveUrl;
    }

    // Custom event params and user properties: `ep.<anything>` /
    // `up.<anything>` / `ep[...]` / `up[...]` variants seen in the wild.
    if has_ep_or_up_prefix(name) {
        return FormFieldTreatment::Flat;
    }

    match name {
        // Flat-scan allowlist per DESIGN.md.
        "dt" | "uid" | "en" | "cu" | "cm" | "cs" | "_uip" | "ip_override" => {
            FormFieldTreatment::Flat
        }
        // Opaque identifiers / platform diagnostics — never scanned.
        "v" | "tid" | "cid" | "_s" | "_et" | "_p" | "_z" | "gtm" | "sid" | "seg" | "sct" => {
            FormFieldTreatment::Skip
        }
        _ => FormFieldTreatment::Unknown,
    }
}

/// True when `name` starts with the GA4 custom-param prefix `ep.` / `up.`
/// (the dot-form gtag.js emits) or `ep[…]` / `up[…]` (occasionally seen
/// when integrators use bracket syntax). The prefix must be at least
/// `ep.X` / `up.X` so we don't match a bare `ep`/`up` key.
fn has_ep_or_up_prefix(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.len() < 4 {
        return false;
    }
    let prefix = &bytes[..3];
    matches!(prefix, b"ep." | b"up." | b"ep[" | b"up[")
}

/// True when this JSON event-params key should be re-decoded as a URL on
/// top of the flat scan that all string leaves receive.
fn json_param_is_url(name: &str) -> bool {
    matches!(name, "page_location" | "link_url")
}

// ---------------------------------------------------------------------------
// Specialization impl
// ---------------------------------------------------------------------------

impl Specialization for Ga4Specialization {
    fn name(&self) -> &'static str {
        "ga4"
    }

    fn process<'a>(
        &'a self,
        query: Option<&'a str>,
        body: Option<&'a [u8]>,
        body_content_type: Option<&'a str>,
        scan: &'a ScanHandle<'a>,
    ) -> ProcessFuture<'a> {
        Box::pin(async move {
            let mut aggregated = AggregatedScan::default();

            // 1. Query string — always processed as GA4 form-encoded data
            //    if present. /g/collect (GET) puts the entire payload here;
            //    /mp/collect carries only `api_secret`/`measurement_id` here.
            let processed_query = if let Some(q) = query {
                let bytes = process_form_str(q, scan, &mut aggregated).await?;
                Some(ProcessedPart {
                    bytes,
                    content_type: None,
                })
            } else {
                None
            };

            // 2. Body — routed by content-type.
            let processed_body = if let Some(raw) = body {
                if raw.is_empty() {
                    None
                } else {
                    let body_kind = classify_body(body_content_type)?;
                    match body_kind {
                        BodyKind::Form => {
                            let s = std::str::from_utf8(raw).map_err(|_| {
                                SpecializationError::Decode {
                                    reason: "invalid_form_encoding".into(),
                                }
                            })?;
                            let bytes = process_form_str(s, scan, &mut aggregated).await?;
                            Some(ProcessedPart {
                                bytes,
                                content_type: Some("application/x-www-form-urlencoded".to_string()),
                            })
                        }
                        BodyKind::Json => {
                            let bytes = process_json_body(raw, scan, &mut aggregated).await?;
                            Some(ProcessedPart {
                                bytes,
                                content_type: Some("application/json".to_string()),
                            })
                        }
                    }
                }
            } else {
                None
            };

            Ok(ProcessedRequest {
                query: processed_query,
                body: processed_body,
                scan_result: aggregated,
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Body content-type classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    Form,
    Json,
}

fn classify_body(content_type: Option<&str>) -> Result<BodyKind, SpecializationError> {
    let Some(ct) = content_type else {
        return Err(SpecializationError::UnsupportedContentType);
    };
    let media_type = ct
        .split(';')
        .next()
        .unwrap_or(ct)
        .trim()
        .to_ascii_lowercase();
    if media_type == "application/x-www-form-urlencoded" {
        return Ok(BodyKind::Form);
    }
    if media_type == "application/json"
        || media_type == "text/json"
        || (media_type.starts_with("application/") && media_type.ends_with("+json"))
    {
        return Ok(BodyKind::Json);
    }
    Err(SpecializationError::UnsupportedContentType)
}

// ---------------------------------------------------------------------------
// Form-encoded processing
// ---------------------------------------------------------------------------

/// Process a `application/x-www-form-urlencoded` string (either a query
/// string or a form body). Iterates pairs, dispatches each to the
/// appropriate field handler, and re-emits the form-encoded representation
/// with redacted values substituted in.
async fn process_form_str(
    input: &str,
    scan: &ScanHandle<'_>,
    aggregated: &mut AggregatedScan,
) -> Result<Bytes, SpecializationError> {
    let pairs = parse_form_pairs(input)?;
    let mut out = String::with_capacity(input.len() + 32);

    for (idx, pair) in pairs.iter().enumerate() {
        if idx > 0 {
            out.push('&');
        }

        // Key passes through verbatim.
        out.push_str(&form_encode(&pair.key));

        if !pair.has_value {
            continue;
        }
        out.push('=');

        let new_value = process_form_value(&pair.key, &pair.value, scan, aggregated, 0).await?;
        out.push_str(&form_encode(&new_value));
    }

    Ok(Bytes::from(out))
}

/// Per-field dispatch. `depth` is the URL-recursion depth (0 at the outer
/// form layer, +1 each time we recurse into a `dl`/`dr` value).
fn process_form_value<'a>(
    name: &'a str,
    value: &'a str,
    scan: &'a ScanHandle<'a>,
    aggregated: &'a mut AggregatedScan,
    depth: u8,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<String, SpecializationError>> + Send + 'a>,
> {
    Box::pin(async move {
        match form_field_treatment(name) {
            FormFieldTreatment::Flat => scan_flat(name, value, scan, aggregated).await,
            FormFieldTreatment::RecursiveUrl => {
                if depth >= URL_RECURSION_LIMIT {
                    return Err(SpecializationError::RecursionLimit);
                }
                process_recursive_url(name, value, scan, aggregated, depth + 1).await
            }
            FormFieldTreatment::Skip | FormFieldTreatment::Unknown => Ok(value.to_string()),
        }
    })
}

/// Scan a single value as flat text, calling `ScanHandle::scan` with the
/// field name as context. Merges the result into `aggregated` and returns
/// the redacted replacement (or the original value when redaction is off
/// or there was nothing to redact).
async fn scan_flat(
    context: &str,
    value: &str,
    scan: &ScanHandle<'_>,
    aggregated: &mut AggregatedScan,
) -> Result<String, SpecializationError> {
    let result = scan.scan(context, value).await.map_err(|_| {
        // Scanner failures during a per-field scan are surfaced as decode
        // errors so the proxy falls back to default scanning — the
        // alternative is to silently swallow the failure, which would hide
        // real issues. dispatch() will increment the error counter.
        SpecializationError::Decode {
            reason: "scanner_error".into(),
        }
    })?;
    aggregated.merge_field(&result);
    Ok(result.redacted.unwrap_or_else(|| value.to_string()))
}

/// Recursive URL treatment for `dl` / `dr`. Splits the URL into prefix,
/// path, query and fragment; scans the path flat; iterates query pairs and
/// scans each as a flat string under context `"{name}.{inner_key}"` (so
/// keyword detectors still see something meaningful), then reassembles the
/// URL. Boxed because it may recurse into itself for nested `dl`/`dr`
/// inside the inner query.
fn process_recursive_url<'a>(
    name: &'a str,
    value: &'a str,
    scan: &'a ScanHandle<'a>,
    aggregated: &'a mut AggregatedScan,
    depth: u8,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<String, SpecializationError>> + Send + 'a>,
> {
    Box::pin(async move {
        let parts = split_url(value);

        // Path part scanned flat. `path` already includes the scheme+authority
        // prefix when one is present (we don't have to special-case that — the
        // scanner doesn't care, and re-encoding is a verbatim pass-through).
        let new_path = if !parts.path.is_empty() {
            scan_flat(name, &parts.path, scan, aggregated).await?
        } else {
            parts.path.to_string()
        };

        // Query part: iterate pairs. Unlike the outer transport, inner pairs
        // aren't subject to GA4's allowlist — the leak is already on the
        // outer page and inner field names are operator-defined. All inner
        // values are scanned flat, except inner keys that are themselves
        // `dl`/`dr`, which recurse (with a depth cap) so URL-in-URL nesting
        // still gets unwrapped.
        let new_query = if let Some(q) = parts.query {
            let pairs = parse_form_pairs(q)?;
            let mut buf = String::with_capacity(q.len() + 32);
            for (i, pair) in pairs.iter().enumerate() {
                if i > 0 {
                    buf.push('&');
                }
                buf.push_str(&form_encode(&pair.key));
                if !pair.has_value {
                    continue;
                }
                buf.push('=');
                let ctx = format!("{name}.{}", pair.key);
                let new_value = if matches!(pair.key.as_str(), "dl" | "dr") {
                    if depth >= URL_RECURSION_LIMIT {
                        return Err(SpecializationError::RecursionLimit);
                    }
                    process_recursive_url(&ctx, &pair.value, scan, aggregated, depth + 1).await?
                } else {
                    scan_flat(&ctx, &pair.value, scan, aggregated).await?
                };
                buf.push_str(&form_encode(&new_value));
            }
            Some(buf)
        } else {
            None
        };

        // Reassemble: path + ?query + #fragment.
        let mut out = new_path;
        if let Some(q) = new_query {
            out.push('?');
            out.push_str(&q);
        }
        if let Some(f) = parts.fragment {
            out.push('#');
            out.push_str(f);
        }
        Ok(out)
    })
}

// ---------------------------------------------------------------------------
// Form parsing
// ---------------------------------------------------------------------------

struct FormPair {
    key: String,
    value: String,
    has_value: bool,
}

fn parse_form_pairs(input: &str) -> Result<Vec<FormPair>, SpecializationError> {
    let mut pairs = Vec::new();
    if input.is_empty() {
        return Ok(pairs);
    }
    for raw in input.split('&') {
        if raw.is_empty() {
            continue;
        }
        if pairs.len() >= MAX_FORM_PAIRS {
            return Err(SpecializationError::Decode {
                reason: "invalid_form_encoding".into(),
            });
        }
        let (key_raw, value_raw, has_value) = match raw.find('=') {
            Some(idx) => (&raw[..idx], &raw[idx + 1..], true),
            None => (raw, "", false),
        };
        let key = form_decode(key_raw)?;
        let value = if has_value {
            form_decode(value_raw)?
        } else {
            String::new()
        };
        pairs.push(FormPair {
            key,
            value,
            has_value,
        });
    }
    Ok(pairs)
}

/// Decode a form-encoded segment: `+` → space, `%HH` → byte, otherwise
/// verbatim. Rejects invalid UTF-8.
fn form_decode(input: &str) -> Result<String, SpecializationError> {
    // Replace `+` with space before percent-decoding (form rules).
    let with_spaces = input.replace('+', " ");
    let decoded = percent_decode_str(&with_spaces)
        .decode_utf8()
        .map_err(|_| SpecializationError::Decode {
            reason: "invalid_form_encoding".into(),
        })?;
    Ok(decoded.into_owned())
}

/// Encode a string for inclusion in a form-encoded payload. Encodes
/// everything outside the unreserved set; encodes space as `%20` (not `+`)
/// to keep encoding round-trippable through both form and URL decoders.
fn form_encode(input: &str) -> String {
    /// Percent-encode everything that isn't an unreserved character per
    /// RFC 3986 (alphanumeric + `-_.~`). `NON_ALPHANUMERIC` starts from
    /// "encode every byte" and `remove` whitelists the unreserved set.
    const SET: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    utf8_percent_encode(input, SET).to_string()
}

// ---------------------------------------------------------------------------
// URL splitting
// ---------------------------------------------------------------------------

struct UrlParts<'a> {
    /// Scheme + authority + path. May be a relative path.
    path: String,
    query: Option<&'a str>,
    fragment: Option<&'a str>,
}

/// Split a URL into path (incl. scheme+authority if present), query, and
/// fragment. Doesn't validate the URL — accepts anything `dl` ever
/// realistically holds. We split on the *first* `?` and the *first* `#`
/// after that (so query is delimited by `?…[#…]`).
fn split_url(url: &str) -> UrlParts<'_> {
    let (without_fragment, fragment) = match url.find('#') {
        Some(i) => (&url[..i], Some(&url[i + 1..])),
        None => (url, None),
    };
    let (path, query) = match without_fragment.find('?') {
        Some(i) => (&without_fragment[..i], Some(&without_fragment[i + 1..])),
        None => (without_fragment, None),
    };
    UrlParts {
        path: path.to_string(),
        query,
        fragment,
    }
}

// ---------------------------------------------------------------------------
// JSON body processing
// ---------------------------------------------------------------------------

async fn process_json_body(
    raw: &[u8],
    scan: &ScanHandle<'_>,
    aggregated: &mut AggregatedScan,
) -> Result<Bytes, SpecializationError> {
    let mut root: Value = serde_json::from_slice(raw).map_err(|_| SpecializationError::Decode {
        reason: "invalid_json".into(),
    })?;

    // GA4 Measurement Protocol top-level is always an object.
    if !root.is_object() {
        return Err(SpecializationError::Decode {
            reason: "unexpected_shape".into(),
        });
    }

    scan_json_root(&mut root, scan, aggregated).await?;

    let out = serde_json::to_vec(&root).map_err(|_| SpecializationError::Decode {
        reason: "json_serialize_failed".into(),
    })?;
    Ok(Bytes::from(out))
}

/// Walk the GA4 MP JSON tree according to DESIGN.md's allowlist.
async fn scan_json_root(
    root: &mut Value,
    scan: &ScanHandle<'_>,
    aggregated: &mut AggregatedScan,
) -> Result<(), SpecializationError> {
    let Some(obj) = root.as_object_mut() else {
        return Ok(());
    };

    // Iterate the object's keys with a snapshot of names so we can mutate
    // values in place under each named branch. The Map iteration order is
    // preserved (preserve_order feature is on).
    let keys: Vec<String> = obj.keys().cloned().collect();
    for key in keys {
        let Some(value) = obj.get_mut(&key) else {
            continue;
        };
        match key.as_str() {
            "client_id" | "user_id" | "ip_override" => {
                scan_string_leaf(value, &key, scan, aggregated).await?;
            }
            "user_data" | "user_location" => {
                // Every string leaf under these objects is scanned.
                scan_all_string_leaves(value, &key, scan, aggregated).await?;
            }
            "user_properties" => {
                // user_properties.<name>.value → scan string leaves of value.
                if let Some(props) = value.as_object_mut() {
                    let prop_keys: Vec<String> = props.keys().cloned().collect();
                    for prop_key in prop_keys {
                        let Some(prop) = props.get_mut(&prop_key) else {
                            continue;
                        };
                        if let Some(prop_obj) = prop.as_object_mut()
                            && let Some(v) = prop_obj.get_mut("value")
                        {
                            let ctx = format!("user_properties.{prop_key}.value");
                            scan_all_string_leaves(v, &ctx, scan, aggregated).await?;
                        }
                    }
                }
            }
            "events" => {
                if let Some(events) = value.as_array_mut() {
                    for (i, event) in events.iter_mut().enumerate() {
                        scan_event(event, i, scan, aggregated).await?;
                    }
                }
            }
            // Skipped fields (diagnostics, consent, message metadata):
            // pass through unchanged.
            _ => {}
        }
    }
    Ok(())
}

async fn scan_event(
    event: &mut Value,
    idx: usize,
    scan: &ScanHandle<'_>,
    aggregated: &mut AggregatedScan,
) -> Result<(), SpecializationError> {
    let Some(obj) = event.as_object_mut() else {
        return Ok(());
    };

    if let Some(name) = obj.get_mut("name") {
        let ctx = format!("events[{idx}].name");
        scan_string_leaf(name, &ctx, scan, aggregated).await?;
    }

    if let Some(params) = obj.get_mut("params")
        && let Some(params_obj) = params.as_object_mut()
    {
        let param_keys: Vec<String> = params_obj.keys().cloned().collect();
        for param_key in param_keys {
            let Some(param_value) = params_obj.get_mut(&param_key) else {
                continue;
            };
            match param_key.as_str() {
                "items" => {
                    if let Some(items) = param_value.as_array_mut() {
                        for (item_idx, item) in items.iter_mut().enumerate() {
                            let ctx = format!("events[{idx}].params.items[{item_idx}]");
                            scan_all_string_leaves(item, &ctx, scan, aggregated).await?;
                        }
                    }
                }
                key if json_param_is_url(key) => {
                    // URL-shaped param: flat scan with optional recursive
                    // URL handling on top. Flat-scan first so a leaked
                    // value (e.g. `?email=…`) is caught even if URL parsing
                    // misses it.
                    let ctx = format!("events[{idx}].params.{param_key}");
                    scan_string_with_url_recursion(param_value, &ctx, scan, aggregated).await?;
                }
                _ => {
                    let ctx = format!("events[{idx}].params.{param_key}");
                    scan_all_string_leaves(param_value, &ctx, scan, aggregated).await?;
                }
            }
        }
    }

    Ok(())
}

/// Scan every string leaf under `value`, using a dot-joined path prefix
/// for context. Numeric/bool/null leaves are skipped.
fn scan_all_string_leaves<'a>(
    value: &'a mut Value,
    context: &'a str,
    scan: &'a ScanHandle<'a>,
    aggregated: &'a mut AggregatedScan,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SpecializationError>> + Send + 'a>>
{
    Box::pin(async move {
        match value {
            Value::String(s) => {
                let new = scan_flat(context, s, scan, aggregated).await?;
                if new != *s {
                    *s = new;
                }
                Ok(())
            }
            Value::Array(arr) => {
                for (i, item) in arr.iter_mut().enumerate() {
                    let ctx = format!("{context}[{i}]");
                    scan_all_string_leaves(item, &ctx, scan, aggregated).await?;
                }
                Ok(())
            }
            Value::Object(obj) => {
                let keys: Vec<String> = obj.keys().cloned().collect();
                for k in keys {
                    let Some(v) = obj.get_mut(&k) else { continue };
                    let ctx = format!("{context}.{k}");
                    scan_all_string_leaves(v, &ctx, scan, aggregated).await?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    })
}

/// Scan a single Value as a string leaf if it's a string; ignore otherwise.
async fn scan_string_leaf(
    value: &mut Value,
    context: &str,
    scan: &ScanHandle<'_>,
    aggregated: &mut AggregatedScan,
) -> Result<(), SpecializationError> {
    if let Value::String(s) = value {
        let new = scan_flat(context, s, scan, aggregated).await?;
        if new != *s {
            *s = new;
        }
    }
    Ok(())
}

/// Like `scan_string_leaf`, but if the string is URL-shaped also recursively
/// scans its query parameters (and rewrites the URL accordingly).
/// Flat-scan runs first; recursive treatment runs against the *original*
/// value when the flat scan didn't fire any redactions. If the flat scan
/// already redacted everything, the URL recursion is skipped — there's
/// nothing left to scan inside.
async fn scan_string_with_url_recursion(
    value: &mut Value,
    context: &str,
    scan: &ScanHandle<'_>,
    aggregated: &mut AggregatedScan,
) -> Result<(), SpecializationError> {
    let Value::String(s) = value else {
        return Ok(());
    };

    let flat_result = scan
        .scan(context, s)
        .await
        .map_err(|_| SpecializationError::Decode {
            reason: "scanner_error".into(),
        })?;
    let flat_redacted = flat_result.redacted.clone();
    aggregated.merge_field(&flat_result);
    if let Some(red) = flat_redacted {
        *s = red;
        return Ok(());
    }

    // No flat match — try URL recursion on the raw value.
    let parts = split_url(s);
    if parts.query.is_none() {
        return Ok(());
    }
    let new_url = process_recursive_url(context, s, scan, aggregated, 1).await?;
    if new_url != *s {
        *s = new_url;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{OnError, PiiConfig};
    use crate::scanner::{RedactWith, ScannerPool};
    use std::sync::{Arc, LazyLock};
    use test_case::test_case;

    // One shared pool keeps the all-countries scanner build cost off the
    // per-test budget. Tests never mutate scanner state, so sharing is safe.
    static POOL: LazyLock<Arc<ScannerPool>> = LazyLock::new(|| {
        Arc::new(
            ScannerPool::new(&PiiConfig {
                countries: pii::Country::all().to_vec(),
                languages: pii::Language::all().to_vec(),
                scanner_threads: Some(1),
                detect: None,
                ignore: None,
                custom: Vec::new(),
            })
            .expect("pool should start"),
        )
    });

    fn redact_handle() -> ScanHandle<'static> {
        ScanHandle::new(&POOL, true, Some(RedactWith::TypeLabel), OnError::FailOpen)
    }

    fn scan_only_handle() -> ScanHandle<'static> {
        ScanHandle::new(&POOL, false, None, OnError::FailOpen)
    }

    async fn run_spec(
        handle: &ScanHandle<'_>,
        query: Option<&str>,
        body: Option<&[u8]>,
        body_ct: Option<&str>,
    ) -> Result<ProcessedRequest, SpecializationError> {
        Ga4Specialization
            .process(query, body, body_ct, handle)
            .await
    }

    fn body_str(pr: &ProcessedRequest) -> String {
        std::str::from_utf8(&pr.body.as_ref().expect("body present").bytes)
            .unwrap()
            .to_string()
    }

    fn query_str(pr: &ProcessedRequest) -> String {
        std::str::from_utf8(&pr.query.as_ref().expect("query present").bytes)
            .unwrap()
            .to_string()
    }

    // -----------------------------------------------------------------------
    // Form-field treatment classifier
    // -----------------------------------------------------------------------

    #[test_case("dt", FormFieldTreatment::Flat ; "dt flat")]
    #[test_case("uid", FormFieldTreatment::Flat ; "uid flat")]
    #[test_case("en", FormFieldTreatment::Flat ; "en flat")]
    #[test_case("cu", FormFieldTreatment::Flat ; "cu flat")]
    #[test_case("cm", FormFieldTreatment::Flat ; "cm flat")]
    #[test_case("cs", FormFieldTreatment::Flat ; "cs flat")]
    #[test_case("_uip", FormFieldTreatment::Flat ; "uip flat")]
    #[test_case("ip_override", FormFieldTreatment::Flat ; "ip_override flat")]
    #[test_case("ep.notes", FormFieldTreatment::Flat ; "ep dot flat")]
    #[test_case("ep.foo_bar", FormFieldTreatment::Flat ; "ep dot snake flat")]
    #[test_case("up.tier", FormFieldTreatment::Flat ; "up dot flat")]
    #[test_case("up[account]", FormFieldTreatment::Flat ; "up bracket flat")]
    #[test_case("dl", FormFieldTreatment::RecursiveUrl ; "dl recursive")]
    #[test_case("dr", FormFieldTreatment::RecursiveUrl ; "dr recursive")]
    #[test_case("v", FormFieldTreatment::Skip ; "v skip")]
    #[test_case("tid", FormFieldTreatment::Skip ; "tid skip")]
    #[test_case("cid", FormFieldTreatment::Skip ; "cid skip")]
    #[test_case("_s", FormFieldTreatment::Skip ; "s skip")]
    #[test_case("_et", FormFieldTreatment::Skip ; "et skip")]
    #[test_case("_p", FormFieldTreatment::Skip ; "p skip")]
    #[test_case("_z", FormFieldTreatment::Skip ; "z skip")]
    #[test_case("gtm", FormFieldTreatment::Skip ; "gtm skip")]
    #[test_case("sid", FormFieldTreatment::Skip ; "sid skip")]
    #[test_case("seg", FormFieldTreatment::Skip ; "seg skip")]
    #[test_case("sct", FormFieldTreatment::Skip ; "sct skip")]
    #[test_case("foo", FormFieldTreatment::Unknown ; "unknown foo")]
    #[test_case("ep", FormFieldTreatment::Unknown ; "ep bare unknown")]
    #[test_case("up", FormFieldTreatment::Unknown ; "up bare unknown")]
    #[test_case("ep.", FormFieldTreatment::Unknown ; "ep dot only unknown")]
    fn form_field_treatment_dispatch(key: &str, expected: FormFieldTreatment) {
        assert_eq!(form_field_treatment(key), expected);
    }

    // -----------------------------------------------------------------------
    // Form parsing & encoding round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn parse_form_pairs_handles_value_no_value_and_decoding() {
        let pairs = parse_form_pairs("a=b&flag&user=jane.doe%40example.com").unwrap();
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0].key, "a");
        assert_eq!(pairs[0].value, "b");
        assert!(pairs[0].has_value);
        assert_eq!(pairs[1].key, "flag");
        assert!(!pairs[1].has_value);
        assert_eq!(pairs[2].value, "jane.doe@example.com");
    }

    // Critical for the redaction-label round-trip: `[EMAIL]` inside a
    // form-encoded payload must come out as `%5BEMAIL%5D`.
    #[test_case("[EMAIL]", "%5BEMAIL%5D" ; "brackets")]
    #[test_case("a b", "a%20b" ; "space")]
    #[test_case("safe-._~", "safe-._~" ; "unreserved untouched")]
    fn form_encode_cases(input: &str, expected: &str) {
        assert_eq!(form_encode(input), expected);
    }

    // -----------------------------------------------------------------------
    // Content-type classification
    // -----------------------------------------------------------------------

    #[test_case(Some("application/json"), Ok(BodyKind::Json) ; "json canonical")]
    #[test_case(Some("application/json; charset=utf-8"), Ok(BodyKind::Json) ; "json with charset")]
    #[test_case(Some("application/vnd.api+json"), Ok(BodyKind::Json) ; "json structured suffix")]
    #[test_case(Some("text/json"), Ok(BodyKind::Json) ; "legacy text json")]
    #[test_case(Some("application/x-www-form-urlencoded"), Ok(BodyKind::Form) ; "form encoded")]
    #[test_case(Some("APPLICATION/JSON"), Ok(BodyKind::Json) ; "uppercase normalized")]
    fn classify_body_supported(ct: Option<&str>, expected: Result<BodyKind, ()>) {
        let got = classify_body(ct);
        match (got, expected) {
            (Ok(g), Ok(e)) => assert_eq!(g, e),
            (got, expected) => panic!("classify({ct:?}) = {got:?}; expected {expected:?}"),
        }
    }

    #[test_case(Some("image/gif") ; "gif")]
    #[test_case(Some("text/plain") ; "plain")]
    #[test_case(None ; "missing")]
    fn classify_body_unsupported(ct: Option<&str>) {
        assert!(matches!(
            classify_body(ct),
            Err(SpecializationError::UnsupportedContentType)
        ));
    }

    // -----------------------------------------------------------------------
    // Field-level: query/form transport
    //
    // Each case: a complete query string, a substring that *must not* appear
    // in the re-encoded output, and an optional substring that *must* appear.
    // -----------------------------------------------------------------------

    #[test_case(
        "v=2&tid=G-X&cid=1.1&en=login&dt=Order%20for%20jane.doe%40example.com&uid=jane.doe%40example.com",
        "jane.doe@example.com",
        Some("%5BEMAIL%5D")
        ; "dt and uid flat scan"
    )]
    #[test_case(
        "v=2&tid=G-X&cid=1.1&en=cart&ep.user_email=jane.doe%40example.com&ep.note=hi",
        "jane.doe@example.com",
        Some("ep.note=hi")
        ; "ep custom param scanned"
    )]
    #[test_case(
        "v=2&tid=G-X&cid=1.1&en=pv&up.contact_phone=phone%3A%205551234567",
        "5551234567",
        None
        ; "up custom param scanned"
    )]
    #[test_case(
        "v=2&tid=G-X&cid=1.1&en=signup&_uip=10.0.0.255",
        "10.0.0.255",
        None
        ; "uip ip scanned"
    )]
    #[tokio::test]
    async fn query_redaction(query: &str, forbidden: &str, expected: Option<&str>) {
        let h = redact_handle();
        let pr = run_spec(&h, Some(query), None, None).await.unwrap();
        let out = query_str(&pr);
        assert!(!out.contains(forbidden), "leaked `{forbidden}` in {out}");
        // The raw (un-percent-encoded) email shouldn't appear either when
        // the input contained the encoded form.
        if forbidden.contains('@') {
            let encoded = forbidden.replace('@', "%40");
            assert!(!out.contains(&encoded), "leaked encoded form in {out}");
        }
        if let Some(must) = expected {
            assert!(out.contains(must), "missing `{must}` in {out}");
        }
    }

    // Recursive URL fields: `dl`/`dr` carry an inner URL that gets parsed,
    // its query params scanned individually, and re-encoded. The redaction
    // label sits inside the inner URL, then the inner URL is itself
    // percent-encoded as the outer form's value — so `[EMAIL]` shows up as
    // `%255BEMAIL%255D` (doubly-encoded) in the outer transport. This
    // matches DESIGN.md § "Specializations" — "doubly-encoded for the
    // inner URL layer of `dl`/`dr`".
    #[test_case(
        "dl",
        "https://shop.example.com/order?email=jane.doe@example.com",
        &["jane.doe@example.com", "jane.doe%40example.com"]
        ; "dl with inner email"
    )]
    #[test_case(
        "dr",
        "https://shop.example.com/checkout?email=jane.doe@example.com&card=4111111111111111",
        &["jane.doe@example.com", "4111111111111111"]
        ; "dr with email and card"
    )]
    #[tokio::test]
    async fn recursive_url_redaction(field: &str, inner_url: &str, forbidden: &[&str]) {
        let h = redact_handle();
        let q = format!(
            "v=2&tid=G-X&cid=1.1&en=page_view&{field}={}",
            form_encode(inner_url)
        );
        let pr = run_spec(&h, Some(&q), None, None).await.unwrap();
        let out = query_str(&pr);
        for f in forbidden {
            assert!(!out.contains(f), "leaked `{f}` in {out}");
        }
        // Doubly-encoded: inner layer turns `[` → `%5B`, outer layer turns
        // that `%` → `%25`, so the brackets surface as `%255B…%255D`.
        assert!(
            out.contains("%255B"),
            "expected doubly-encoded redaction label in {out}"
        );
    }

    // False-positive regression: opaque ids stay opaque even when their
    // values resemble PII shapes.
    #[test_case("v=2&tid=G-X&cid=4111111111111111&en=page_view" ; "cid card shape")]
    #[test_case("v=2&tid=G-XXXXXXXX&_s=42&_et=1234&gtm=2u123" ; "platform diagnostics")]
    #[test_case("v=2&tid=G-X&cid=1.1&_p=1234567890&_z=abcdef" ; "noise params")]
    #[tokio::test]
    async fn opaque_fields_dont_trigger_pii(query: &str) {
        let h = scan_only_handle();
        let pr = run_spec(&h, Some(query), None, None).await.unwrap();
        assert_eq!(
            pr.scan_result.matches_count, 0,
            "opaque fields must not trigger PII; got {:?}",
            pr.scan_result.kinds
        );
    }

    // -----------------------------------------------------------------------
    // JSON body — one parameterized test covers every allowlisted leaf path.
    //
    // Each case: full JSON body, raw PII substring that must vanish from the
    // re-encoded output. We always assert the body re-parses as valid JSON.
    // -----------------------------------------------------------------------

    #[test_case(
        r#"{"client_id":"1.1","user_id":"jane.doe@example.com","events":[]}"#,
        "jane.doe@example.com"
        ; "user_id email"
    )]
    #[test_case(
        r#"{"client_id":"contact us at user@example.com","events":[]}"#,
        "user@example.com"
        ; "client_id email"
    )]
    #[test_case(
        r#"{"client_id":"1.1","user_data":{"email_address":"jane.doe@example.com"},"events":[]}"#,
        "jane.doe@example.com"
        ; "user_data email_address"
    )]
    #[test_case(
        r#"{"client_id":"1.1","user_data":{"phone_number":"phone: +1 555 123 4567"},"events":[]}"#,
        "+1 555 123 4567"
        ; "user_data phone"
    )]
    #[test_case(
        r#"{"client_id":"1.1","user_data":{"address":{"street":"contact us at user@example.com"}},"events":[]}"#,
        "user@example.com"
        ; "user_data nested address"
    )]
    #[test_case(
        r#"{"client_id":"1.1","user_properties":{"fav":{"value":"IBAN: GB29 NWBK 6016 1331 9268 19"}},"events":[]}"#,
        "GB29 NWBK 6016 1331 9268 19"
        ; "user_properties value iban"
    )]
    #[test_case(
        r#"{"client_id":"1.1","ip_override":"IP: 10.0.0.255 ok","events":[]}"#,
        "10.0.0.255"
        ; "ip_override"
    )]
    #[test_case(
        r#"{"client_id":"1.1","user_location":{"city":"Vorname: Hans"},"events":[]}"#,
        "Vorname: Hans"
        ; "user_location city"
    )]
    #[test_case(
        r#"{"client_id":"1.1","events":[{"name":"contact us at user@example.com","params":{}}]}"#,
        "user@example.com"
        ; "events name"
    )]
    #[test_case(
        r#"{"client_id":"1.1","events":[{"name":"view_search_results","params":{"search_term":"looking for jane.doe@example.com"}}]}"#,
        "jane.doe@example.com"
        ; "events params search_term"
    )]
    #[test_case(
        r#"{"client_id":"1.1","events":[{"name":"purchase","params":{"transaction_id":"order-jane.doe@example.com-2026"}}]}"#,
        "jane.doe@example.com"
        ; "events params transaction_id"
    )]
    #[test_case(
        r#"{"client_id":"1.1","events":[{"name":"purchase","params":{"coupon":"promo for user@example.com"}}]}"#,
        "user@example.com"
        ; "events params coupon"
    )]
    #[test_case(
        r#"{"client_id":"1.1","events":[{"name":"exception","params":{"description":"AuthError\nIP: 10.0.0.255 ok"}}]}"#,
        "10.0.0.255"
        ; "events params description multiline"
    )]
    #[test_case(
        r#"{"client_id":"1.1","events":[{"name":"click","params":{"link_url":"https://partner.example.com/redir?email=user@example.com"}}]}"#,
        "user@example.com"
        ; "events params link_url"
    )]
    #[test_case(
        r#"{"client_id":"1.1","events":[{"name":"page_view","params":{"page_location":"https://app.example.com/users/user@example.com"}}]}"#,
        "user@example.com"
        ; "events params page_location"
    )]
    #[test_case(
        r#"{"client_id":"1.1","events":[{"name":"form_submit","params":{"form_destination":"https://app.example.com/checkout?email=user@example.com"}}]}"#,
        "user@example.com"
        ; "events params form_destination"
    )]
    #[test_case(
        r#"{"client_id":"1.1","events":[{"name":"purchase","params":{"items":[{"item_id":"SKU","item_name":"Vorname: Hans"}]}}]}"#,
        "Hans"
        ; "events params items item_name"
    )]
    #[test_case(
        r#"{"client_id":"1.1","events":[{"name":"newsletter_signup","params":{"email":"user@example.com"}}]}"#,
        "user@example.com"
        ; "events params custom_named_email"
    )]
    #[tokio::test]
    async fn json_field_redacted(body: &str, forbidden: &str) {
        let h = redact_handle();
        let pr = run_spec(&h, None, Some(body.as_bytes()), Some("application/json"))
            .await
            .unwrap();
        let out = body_str(&pr);
        assert!(!out.contains(forbidden), "leaked `{forbidden}` in {out}");
        // Output must remain valid JSON.
        let _: Value = serde_json::from_str(&out).expect("redacted JSON is valid");
    }

    #[tokio::test]
    async fn json_multiple_events_partial_pii_preserves_clean_event() {
        let h = redact_handle();
        let body = br#"{
            "client_id":"1.1",
            "events":[
                {"name":"page_view","params":{"page_title":"Pricing"}},
                {"name":"view_search_results","params":{"search_term":"phone: 5551234567"}}
            ]
        }"#;
        let pr = run_spec(&h, None, Some(body), Some("application/json"))
            .await
            .unwrap();
        let out = body_str(&pr);
        assert!(!out.contains("5551234567"));
        assert!(out.contains("Pricing"));
    }

    #[tokio::test]
    async fn json_numeric_and_bool_leaves_skipped() {
        let h = scan_only_handle();
        let body = br#"{"client_id":"1.1","timestamp_micros":1234567890123,"non_personalized_ads":true,"events":[{"name":"x","params":{"value":42.5,"flag":false}}]}"#;
        let pr = run_spec(&h, None, Some(body), Some("application/json"))
            .await
            .unwrap();
        assert_eq!(pr.scan_result.matches_count, 0);
    }

    // -----------------------------------------------------------------------
    // Error paths
    // -----------------------------------------------------------------------

    enum ExpectedErr {
        DecodeReason(&'static str),
        Unsupported,
    }

    #[test_case(b"{not json", Some("application/json"), ExpectedErr::DecodeReason("invalid_json") ; "malformed json")]
    #[test_case(b"[1, 2, 3]", Some("application/json"), ExpectedErr::DecodeReason("unexpected_shape") ; "top level array")]
    #[test_case(b"<gif>", Some("image/gif"), ExpectedErr::Unsupported ; "unsupported content type")]
    #[tokio::test]
    async fn body_error_paths(body: &[u8], ct: Option<&str>, expected: ExpectedErr) {
        let h = scan_only_handle();
        let err = run_spec(&h, None, Some(body), ct).await.unwrap_err();
        match (expected, err) {
            (ExpectedErr::DecodeReason(want), SpecializationError::Decode { reason }) => {
                assert_eq!(reason, want);
            }
            (ExpectedErr::Unsupported, SpecializationError::UnsupportedContentType) => {}
            (_, other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn recursion_limit_hits_when_dl_nests_dl() {
        // 5-deep dl-in-dl synthesizes well past the 3-layer limit.
        let h = scan_only_handle();
        let mut inner = String::from("http://leaf.example/");
        for _ in 0..5 {
            inner = format!("http://x.example/?dl={}", form_encode(&inner));
        }
        let q = format!("v=2&tid=G-X&cid=1.1&en=pv&dl={}", form_encode(&inner));
        let err = run_spec(&h, Some(&q), None, None).await.unwrap_err();
        assert!(matches!(err, SpecializationError::RecursionLimit));
    }

    // -----------------------------------------------------------------------
    // Pass-through paths
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn clean_query_round_trips_verbatim() {
        let h = redact_handle();
        let q = "v=2&tid=G-X&cid=1234567890.1234567890&en=page_view&dt=Pricing";
        let pr = run_spec(&h, Some(q), None, None).await.unwrap();
        assert_eq!(pr.scan_result.matches_count, 0);
        assert!(pr.body.is_none());
        assert_eq!(query_str(&pr), q);
    }

    #[tokio::test]
    async fn form_body_pii_in_ep_email() {
        let h = redact_handle();
        let body = b"ep.email=jane.doe%40example.com&ep.note=ok";
        let pr = run_spec(
            &h,
            Some("v=2&tid=G-X&cid=1.1&en=signup"),
            Some(body),
            Some("application/x-www-form-urlencoded"),
        )
        .await
        .unwrap();
        let out = body_str(&pr);
        assert!(!out.contains("jane.doe@example.com"));
        assert!(!out.contains("jane.doe%40example.com"));
        assert!(out.contains("%5BEMAIL%5D"));
    }

    // Protocol-evolution regression: if GA4 ships a new tracker field
    // we haven't allowlisted yet, it must round-trip verbatim through the
    // re-encoded output. The cost is that PII in the new field goes
    // undetected until the allowlist is updated — explicit deal per
    // DESIGN.md ("Adding a field requires a code change").
    #[tokio::test]
    async fn unknown_form_fields_round_trip_verbatim() {
        let h = redact_handle();
        let q = "v=2&tid=G-X&cid=1.1&en=page_view&new_field_alpha=hello%20world&dt=Home&new_field_beta=path%2Fwith%2Fslash";
        let pr = run_spec(&h, Some(q), None, None).await.unwrap();
        let out = query_str(&pr);
        let pairs = parse_form_pairs(&out).unwrap();
        let by_key = |k: &str| {
            pairs
                .iter()
                .find(|p| p.key == k)
                .unwrap_or_else(|| panic!("missing `{k}` in output: {out}"))
        };
        assert_eq!(by_key("new_field_alpha").value, "hello world");
        assert_eq!(by_key("new_field_beta").value, "path/with/slash");
        // Known fields still present and unaffected.
        assert_eq!(by_key("dt").value, "Home");
        assert_eq!(by_key("v").value, "2");
        assert_eq!(by_key("tid").value, "G-X");
    }

    // JSON top-level evolution: any new key the GA4 MP schema grows
    // (beyond `client_id`, `user_id`, `user_data`, `user_properties`,
    // `ip_override`, `user_location`, `events`, …) must pass through.
    // Note: keys *under* `events[].params` are walked as a generic JSON
    // tree by design, so new custom params are scanned automatically —
    // this test only covers the top-level allowlist.
    #[tokio::test]
    async fn unknown_top_level_json_keys_round_trip() {
        let h = redact_handle();
        let body = br#"{
            "client_id":"1.1",
            "events":[{"name":"page_view","params":{}}],
            "future_top_field":"future-value",
            "future_object":{"nested":"value"},
            "future_number":42
        }"#;
        let pr = run_spec(&h, None, Some(body), Some("application/json"))
            .await
            .unwrap();
        let parsed: Value = serde_json::from_str(&body_str(&pr)).unwrap();
        assert_eq!(
            parsed["future_top_field"],
            Value::String("future-value".into())
        );
        assert_eq!(
            parsed["future_object"],
            serde_json::json!({"nested": "value"})
        );
        assert_eq!(parsed["future_number"], serde_json::json!(42));
        assert_eq!(parsed["client_id"], Value::String("1.1".into()));
    }
}
