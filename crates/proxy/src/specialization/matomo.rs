//! Matomo specialization. Decodes Matomo / Piwik tracker traffic — GET
//! query string, POST `application/x-www-form-urlencoded` body, and bulk
//! POST JSON body (`{"requests": ["?…", …], "token_auth": "…"}`) — scans
//! the declared allowlist of integrator-controlled fields, and re-encodes
//! the result so redaction labels live at the right encoding layer (key
//! point: brackets in `[EMAIL]` end up as `%5B…%5D` after the outer
//! form-encoding pass; values nested inside a URL like `url=` come out
//! doubly-encoded as `%255B…%255D`).
//!
//! Source of truth for the allowlists is DESIGN.md § "Specializations →
//! matomo" and the integration scenarios in
//! `crates/proxy/tests/matomo_integration.rs`. The mapping below mirrors
//! the table from DESIGN.md; field families are grouped into
//! `field_treatment()` so the dispatch is in one place.

use bytes::Bytes;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde_json::Value;

use super::{
    AggregatedScan, ProcessFuture, ProcessedPart, ProcessedRequest, ScanHandle, Specialization,
    SpecializationError,
};
use crate::metrics;

pub struct MatomoSpecialization;

const SPEC_NAME: &str = "matomo";

/// Max depth for recursive URL decoding of `url`/`urlref`/`link`/`download`/
/// `cra_ru`. Three layers is plenty — Matomo URLs rarely embed even one
/// inner URL, and pathological payloads that try to exhaust scanner budget
/// shouldn't get to keep going.
const URL_RECURSION_LIMIT: u8 = 3;

/// Maximum number of form pairs we'll parse out of a single query/body
/// string. Bounds memory regardless of payload shape.
const MAX_FORM_PAIRS: usize = 4096;

/// How a particular Matomo form field should be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormFieldTreatment {
    /// Scanned as a flat string. `context` is the field name.
    Flat,
    /// Value is itself a URL — inner query parameters scanned individually,
    /// path component scanned flat. Inner values re-encoded once; the
    /// outer form-encode then yields doubly-encoded redaction labels.
    RecursiveUrl,
    /// Value is itself JSON — string leaves scanned, JSON re-emitted.
    /// Malformed inner JSON falls back to a flat scan of the raw value.
    JsonValue,
    /// Auto-generated identifier / capability flag — pass through without
    /// scanning.
    Skip,
    /// Not in the allowlist. Pass through unchanged.
    Unknown,
}

fn form_field_treatment(name: &str) -> FormFieldTreatment {
    // Recursive-URL fields first — short list.
    if matches!(name, "url" | "urlref" | "link" | "download" | "cra_ru") {
        return FormFieldTreatment::RecursiveUrl;
    }

    // JSON-value fields.
    if matches!(name, "cvar" | "_cvar" | "ec_items") {
        return FormFieldTreatment::JsonValue;
    }

    // Custom dimensions: `dimension` followed by one or more digits.
    if is_dimension(name) {
        return FormFieldTreatment::Flat;
    }

    match name {
        "action_name" | "uid" | "cip" | "e_c" | "e_a" | "e_n" | "e_v" | "search" | "search_cat"
        | "cra" | "cra_st" | "c_n" | "c_p" | "c_i" | "ec_id" => FormFieldTreatment::Flat,
        // Opaque identifiers, capability flags, and platform diagnostics —
        // never scanned. Matches DESIGN.md's "Skipped" list.
        "idsite" | "rec" | "apiv" | "_id" | "rand" | "revenue" | "idgoal" | "res" | "h" | "m"
        | "s" | "fla" | "qt" | "realp" | "wma" | "dir" | "java" | "cookie" | "pv_id" | "gt_ms" => {
            FormFieldTreatment::Skip
        }
        _ => FormFieldTreatment::Unknown,
    }
}

/// True when `name` matches `^dimension\d+$` (the custom-dimension family).
fn is_dimension(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("dimension") else {
        return false;
    };
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
}

// ---------------------------------------------------------------------------
// Specialization impl
// ---------------------------------------------------------------------------

impl Specialization for MatomoSpecialization {
    fn name(&self) -> &'static str {
        SPEC_NAME
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

            // 1. Query string — Matomo GET puts the entire payload here.
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
                    match classify_body(body_content_type)? {
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
                            let bytes = process_bulk_json(raw, scan, &mut aggregated).await?;
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

/// Process a single `application/x-www-form-urlencoded` string (either a
/// query string or a form body). Iterates pairs, dispatches each to the
/// appropriate field handler, and re-emits form-encoded output with
/// redacted values substituted in.
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
/// form layer, +1 each time we recurse into a URL field's value).
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
            FormFieldTreatment::JsonValue => {
                process_json_value_field(name, value, scan, aggregated).await
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
        // Scanner failures during a per-field scan surface as decode errors so
        // the proxy falls back to default scanning — the alternative is to
        // silently swallow them, which would hide real issues. `dispatch()`
        // increments the error counter on the Err return.
        SpecializationError::Decode {
            reason: "scanner_error".into(),
        }
    })?;
    aggregated.merge_field(&result);
    Ok(result.redacted.unwrap_or_else(|| value.to_string()))
}

/// Recursive URL treatment for `url`, `urlref`, `link`, `download`,
/// `cra_ru`. Splits the URL into path, query, and fragment; scans the path
/// flat; iterates query pairs and scans each as a flat string under context
/// `"{name}.{inner_key}"` (so keyword detectors still see something
/// meaningful), then reassembles the URL. Boxed because it may recurse into
/// itself when an inner key is also one of the recursive-URL fields.
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
        // prefix when one is present — the scanner doesn't care, and
        // re-encoding is a verbatim pass-through.
        let new_path = if !parts.path.is_empty() {
            scan_flat(name, &parts.path, scan, aggregated).await?
        } else {
            parts.path.to_string()
        };

        // Query part: iterate pairs. Unlike the outer transport, inner pairs
        // aren't subject to Matomo's allowlist — the leak is already on the
        // outer page and inner field names are operator-defined. All inner
        // values are scanned flat. Inner keys that are themselves
        // recursive-URL fields recurse (with a depth cap) so URL-in-URL
        // nesting still gets unwrapped.
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
                let new_value = if matches!(
                    pair.key.as_str(),
                    "url" | "urlref" | "link" | "download" | "cra_ru"
                ) {
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

/// Process a JSON-value field (`cvar`, `_cvar`, `ec_items`). Parses the
/// value as JSON, walks string leaves, scans each, and re-emits the JSON.
/// Malformed inner JSON falls back to a flat scan of the raw value (and
/// increments `pii_proxy_specialization_errors_total{reason="invalid_inner_json"}`).
async fn process_json_value_field(
    name: &str,
    value: &str,
    scan: &ScanHandle<'_>,
    aggregated: &mut AggregatedScan,
) -> Result<String, SpecializationError> {
    let parsed: Result<Value, _> = serde_json::from_str(value);
    let mut root = match parsed {
        Ok(v) => v,
        Err(_) => {
            metrics::inc_specialization_error(SPEC_NAME, "invalid_inner_json");
            return scan_flat(name, value, scan, aggregated).await;
        }
    };

    scan_all_string_leaves(&mut root, name, scan, aggregated).await?;

    match serde_json::to_string(&root) {
        Ok(s) => Ok(s),
        Err(_) => {
            // Re-serialization failure is unexpected (we just parsed it).
            // Fall back to the raw value so downstream forwarding still works.
            metrics::inc_specialization_error(SPEC_NAME, "invalid_inner_json");
            Ok(value.to_string())
        }
    }
}

/// Walk every string leaf under `value`, scanning each with `ScanHandle`
/// under a dot-joined path context. Numeric/bool/null leaves are skipped.
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

// ---------------------------------------------------------------------------
// Bulk JSON body processing
// ---------------------------------------------------------------------------

/// Process the bulk-tracking JSON envelope:
/// `{"requests": ["?idsite=1&...", ...], "token_auth": "..."}`.
///
/// Each entry in `requests` is a query string with a leading `?`. We strip
/// the `?`, treat the remainder as a flat form payload, and re-emit the
/// envelope with each entry's redacted query string in place. `token_auth`
/// is preserved verbatim and not scanned (operator credential, not subject
/// PII).
async fn process_bulk_json(
    raw: &[u8],
    scan: &ScanHandle<'_>,
    aggregated: &mut AggregatedScan,
) -> Result<Bytes, SpecializationError> {
    let mut root: Value = serde_json::from_slice(raw).map_err(|_| SpecializationError::Decode {
        reason: "invalid_bulk_json".into(),
    })?;

    let obj = root.as_object_mut().ok_or(SpecializationError::Decode {
        reason: "invalid_bulk_json".into(),
    })?;

    if let Some(requests) = obj.get_mut("requests")
        && let Some(arr) = requests.as_array_mut()
    {
        for entry in arr.iter_mut() {
            let Value::String(s) = entry else { continue };
            let trimmed = s.strip_prefix('?').unwrap_or(s);
            let processed = process_form_str(trimmed, scan, aggregated).await?;
            let processed_str = std::str::from_utf8(&processed)
                .map(|x| x.to_string())
                .map_err(|_| SpecializationError::Decode {
                    reason: "invalid_form_encoding".into(),
                })?;
            // Preserve the original `?` prefix if there was one — Matomo's
            // bulk consumers tolerate either form, but emitting the same
            // shape we received keeps the round-trip minimal.
            let new_entry = if s.starts_with('?') {
                format!("?{processed_str}")
            } else {
                processed_str
            };
            *s = new_entry;
        }
    }

    let out = serde_json::to_vec(&root).map_err(|_| SpecializationError::Decode {
        reason: "invalid_bulk_json".into(),
    })?;
    Ok(Bytes::from(out))
}

// ---------------------------------------------------------------------------
// Form parsing & encoding
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
    let with_spaces = input.replace('+', " ");
    let decoded = percent_decode_str(&with_spaces)
        .decode_utf8()
        .map_err(|_| SpecializationError::Decode {
            reason: "invalid_form_encoding".into(),
        })?;
    Ok(decoded.into_owned())
}

/// Encode a string for inclusion in a form-encoded payload. Encodes
/// everything outside the RFC 3986 unreserved set; encodes space as `%20`
/// (not `+`) to keep encoding round-trippable through both form and URL
/// decoders.
fn form_encode(input: &str) -> String {
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
/// fragment. Doesn't validate the URL — accepts anything Matomo's URL
/// fields ever realistically hold. Splits on the *first* `#` and the
/// *first* `?` before that.
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{OnError, PiiConfig};
    use crate::scanner::{RedactWith, ScannerPool};
    use serde_json::json;
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
        MatomoSpecialization
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

    #[test_case("url", FormFieldTreatment::RecursiveUrl ; "url recursive")]
    #[test_case("urlref", FormFieldTreatment::RecursiveUrl ; "urlref recursive")]
    #[test_case("link", FormFieldTreatment::RecursiveUrl ; "link recursive")]
    #[test_case("download", FormFieldTreatment::RecursiveUrl ; "download recursive")]
    #[test_case("cra_ru", FormFieldTreatment::RecursiveUrl ; "cra_ru recursive")]
    #[test_case("cvar", FormFieldTreatment::JsonValue ; "cvar json")]
    #[test_case("_cvar", FormFieldTreatment::JsonValue ; "_cvar json")]
    #[test_case("ec_items", FormFieldTreatment::JsonValue ; "ec_items json")]
    #[test_case("action_name", FormFieldTreatment::Flat ; "action_name flat")]
    #[test_case("uid", FormFieldTreatment::Flat ; "uid flat")]
    #[test_case("cip", FormFieldTreatment::Flat ; "cip flat")]
    #[test_case("e_c", FormFieldTreatment::Flat ; "e_c flat")]
    #[test_case("e_a", FormFieldTreatment::Flat ; "e_a flat")]
    #[test_case("e_n", FormFieldTreatment::Flat ; "e_n flat")]
    #[test_case("e_v", FormFieldTreatment::Flat ; "e_v flat")]
    #[test_case("search", FormFieldTreatment::Flat ; "search flat")]
    #[test_case("search_cat", FormFieldTreatment::Flat ; "search_cat flat")]
    #[test_case("cra", FormFieldTreatment::Flat ; "cra flat")]
    #[test_case("cra_st", FormFieldTreatment::Flat ; "cra_st flat")]
    #[test_case("c_n", FormFieldTreatment::Flat ; "c_n flat")]
    #[test_case("c_p", FormFieldTreatment::Flat ; "c_p flat")]
    #[test_case("c_i", FormFieldTreatment::Flat ; "c_i flat")]
    #[test_case("ec_id", FormFieldTreatment::Flat ; "ec_id flat")]
    #[test_case("dimension1", FormFieldTreatment::Flat ; "dimension1 flat")]
    #[test_case("dimension42", FormFieldTreatment::Flat ; "dimension42 flat")]
    #[test_case("dimension999", FormFieldTreatment::Flat ; "dimension999 flat")]
    #[test_case("idsite", FormFieldTreatment::Skip ; "idsite skip")]
    #[test_case("rec", FormFieldTreatment::Skip ; "rec skip")]
    #[test_case("apiv", FormFieldTreatment::Skip ; "apiv skip")]
    #[test_case("_id", FormFieldTreatment::Skip ; "id skip")]
    #[test_case("rand", FormFieldTreatment::Skip ; "rand skip")]
    #[test_case("revenue", FormFieldTreatment::Skip ; "revenue skip")]
    #[test_case("idgoal", FormFieldTreatment::Skip ; "idgoal skip")]
    #[test_case("res", FormFieldTreatment::Skip ; "res skip")]
    #[test_case("h", FormFieldTreatment::Skip ; "h skip")]
    #[test_case("m", FormFieldTreatment::Skip ; "m skip")]
    #[test_case("s", FormFieldTreatment::Skip ; "s skip")]
    #[test_case("pv_id", FormFieldTreatment::Skip ; "pv_id skip")]
    #[test_case("gt_ms", FormFieldTreatment::Skip ; "gt_ms skip")]
    #[test_case("dimension", FormFieldTreatment::Unknown ; "dimension bare unknown")]
    #[test_case("dimensionA", FormFieldTreatment::Unknown ; "dimension alpha unknown")]
    #[test_case("dimension1a", FormFieldTreatment::Unknown ; "dimension trailing alpha unknown")]
    #[test_case("foo", FormFieldTreatment::Unknown ; "foo unknown")]
    #[test_case("cra_rl", FormFieldTreatment::Unknown ; "cra_rl unknown")]
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
        "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&action_name=Order%20for%20jane.doe%40example.com&uid=jane.doe%40example.com",
        "jane.doe@example.com",
        Some("%5BEMAIL%5D")
        ; "action_name and uid flat"
    )]
    #[test_case(
        "idsite=1&rec=1&apiv=1&cip=10.0.0.255",
        "10.0.0.255",
        None
        ; "cip flat"
    )]
    #[test_case(
        "idsite=1&rec=1&apiv=1&e_c=newsletter&e_a=submit&e_n=user%40example.com&e_v=1",
        "user@example.com",
        Some("e_v=1")
        ; "event params flat"
    )]
    #[test_case(
        "idsite=1&rec=1&apiv=1&search=looking%20for%20jane.doe%40example.com&search_cat=help",
        "jane.doe@example.com",
        Some("search_cat=help")
        ; "search and search_cat flat"
    )]
    #[test_case(
        "idsite=1&rec=1&apiv=1&cra=AuthError%20for%20user%40example.com",
        "user@example.com",
        None
        ; "cra flat"
    )]
    #[test_case(
        "idsite=1&rec=1&apiv=1&cra=AuthError&cra_st=email%3D%20jane.doe%40example.com",
        "jane.doe@example.com",
        None
        ; "cra_st flat"
    )]
    #[test_case(
        "idsite=1&rec=1&apiv=1&c_n=ContactForm&c_p=phone%3A%205551234567&c_i=keystroke",
        "5551234567",
        Some("c_n=ContactForm")
        ; "heatmap content piece flat"
    )]
    #[test_case(
        "idsite=1&rec=1&apiv=1&dimension5=user%40example.com",
        "user@example.com",
        None
        ; "dimension5 flat"
    )]
    #[test_case(
        "idsite=1&rec=1&apiv=1&dimension999=phone%3A%205551234567",
        "5551234567",
        None
        ; "dimension999 flat"
    )]
    #[test_case(
        "idsite=1&rec=1&apiv=1&ec_id=order-jane.doe%40example.com-2026",
        "jane.doe@example.com",
        None
        ; "ec_id flat"
    )]
    #[tokio::test]
    async fn query_redaction(query: &str, forbidden: &str, expected: Option<&str>) {
        let h = redact_handle();
        let pr = run_spec(&h, Some(query), None, None).await.unwrap();
        let out = query_str(&pr);
        assert!(!out.contains(forbidden), "leaked `{forbidden}` in {out}");
        if forbidden.contains('@') {
            let encoded = forbidden.replace('@', "%40");
            assert!(!out.contains(&encoded), "leaked encoded form in {out}");
        }
        if let Some(must) = expected {
            assert!(out.contains(must), "missing `{must}` in {out}");
        }
    }

    // Recursive URL fields: `url`/`urlref`/`link`/`download`/`cra_ru` carry
    // an inner URL whose query params are parsed and scanned individually.
    // Redaction label sits inside the inner URL, then the inner URL is
    // itself form-encoded as the outer transport's value — so `[EMAIL]`
    // shows up as `%255BEMAIL%255D` (doubly-encoded).
    #[test_case(
        "url",
        "https://shop.example.com/order?email=jane.doe@example.com",
        &["jane.doe@example.com", "jane.doe%40example.com"]
        ; "url with inner email"
    )]
    #[test_case(
        "urlref",
        "https://shop.example.com/checkout?email=jane.doe@example.com&card=4111111111111111",
        &["jane.doe@example.com", "4111111111111111"]
        ; "urlref with email and card"
    )]
    #[test_case(
        "link",
        "https://partner.example.com/redir?email=user@example.com",
        &["user@example.com", "user%40example.com"]
        ; "link outlink with email"
    )]
    #[test_case(
        "download",
        "https://shop.example.com/inv.pdf?for=user@example.com&token=gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12",
        &["user@example.com", "gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12"]
        ; "download with email and token"
    )]
    #[test_case(
        "cra_ru",
        "https://cdn.example.com/app.js?token=gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12",
        &["gho_abcdefghijklmnopqrstuvwxyzABCDEFGH12"]
        ; "cra_ru with token"
    )]
    #[tokio::test]
    async fn recursive_url_redaction(field: &str, inner_url: &str, forbidden: &[&str]) {
        let h = redact_handle();
        let q = format!("idsite=1&rec=1&apiv=1&{field}={}", form_encode(inner_url));
        let pr = run_spec(&h, Some(&q), None, None).await.unwrap();
        let out = query_str(&pr);
        for f in forbidden {
            assert!(!out.contains(f), "leaked `{f}` in {out}");
        }
        // Doubly-encoded: inner `[` → `%5B`, outer `%` → `%25`. Redaction
        // labels surface as `%255B…%255D`.
        assert!(
            out.contains("%255B"),
            "expected doubly-encoded redaction label in {out}"
        );
    }

    // URL path leak (no inner query): `url` value's path contains PII (e.g.
    // SPA routes embedding the email). Flat scan of the path catches it.
    #[tokio::test]
    async fn recursive_url_path_only() {
        let h = redact_handle();
        let inner = "https://app.example.com/users/user@example.com/profile";
        let q = format!("idsite=1&rec=1&apiv=1&url={}", form_encode(inner));
        let pr = run_spec(&h, Some(&q), None, None).await.unwrap();
        let out = query_str(&pr);
        assert!(!out.contains("user@example.com"));
        assert!(!out.contains("user%40example.com"));
    }

    // JSON-value fields: `cvar`, `_cvar`, `ec_items`. The form value is a
    // JSON document; each string leaf is scanned and substituted.
    #[test_case(
        "_cvar",
        r#"{"1":["customer","jane.doe@example.com"],"2":["plan","gold"]}"#,
        "jane.doe@example.com"
        ; "_cvar visit scope"
    )]
    #[test_case(
        "cvar",
        r#"{"1":["tax_id","SSN: 123-45-6789"]}"#,
        "123-45-6789"
        ; "cvar page scope"
    )]
    #[test_case(
        "ec_items",
        r#"[["SKU-1","Custom engraving — Vorname: Hans","gifts",99.0,1]]"#,
        "Hans"
        ; "ec_items array"
    )]
    #[tokio::test]
    async fn json_value_field_redaction(field: &str, raw_json: &str, forbidden: &str) {
        let h = redact_handle();
        let q = format!("idsite=1&rec=1&apiv=1&{field}={}", form_encode(raw_json));
        let pr = run_spec(&h, Some(&q), None, None).await.unwrap();
        let out = query_str(&pr);
        // After form-decoding the field value back, the embedded JSON
        // shouldn't contain the raw PII anywhere.
        let decoded = percent_decode_str(&out).decode_utf8().unwrap();
        assert!(
            !decoded.contains(forbidden),
            "leaked `{forbidden}` in decoded query: {decoded}"
        );
    }

    // False-positive regression: opaque ids stay opaque even when their
    // values resemble PII shapes.
    #[test_case("idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&rand=4111111111111111" ; "rand card shape")]
    #[test_case("idsite=1&rec=1&apiv=1&_id=4111111111111111" ; "id card shape")]
    #[test_case("idsite=1&rec=1&apiv=1&revenue=42.00&res=1920x1080&h=14&m=22&s=09" ; "platform diagnostics")]
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
    // Form body
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn form_body_pii_in_action_name() {
        let h = redact_handle();
        let body = b"idsite=1&rec=1&apiv=1&action_name=Order%20for%20jane.doe%40example.com";
        let pr = run_spec(
            &h,
            None,
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

    // -----------------------------------------------------------------------
    // Bulk JSON body
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn bulk_redacts_pii_across_multiple_requests() {
        let h = redact_handle();
        let payload = json!({
            "requests": [
                "?idsite=1&rec=1&apiv=1&url=https%3A%2F%2Fshop.example.com%2F&action_name=Home",
                "?idsite=1&rec=1&apiv=1&ec_id=order-user%40example.com&revenue=9",
                "?idsite=1&rec=1&apiv=1&action_name=SSN%3A%20123-45-6789%20found",
            ],
            "token_auth": "33dc3f2536d3025974cccb4b4d2d98f4",
        });
        let body = serde_json::to_vec(&payload).unwrap();
        let pr = run_spec(&h, None, Some(&body), Some("application/json"))
            .await
            .unwrap();
        let out = body_str(&pr);
        assert!(!out.contains("user@example.com"));
        assert!(!out.contains("user%40example.com"));
        assert!(!out.contains("123-45-6789"));
        // Clean parts survive.
        assert!(out.contains("Home"));
        // token_auth preserved verbatim.
        assert!(out.contains("33dc3f2536d3025974cccb4b4d2d98f4"));
    }

    #[tokio::test]
    async fn bulk_preserves_clean_entry_alongside_dirty() {
        let h = redact_handle();
        let payload = json!({
            "requests": [
                "?idsite=1&rec=1&apiv=1&action_name=Pricing",
                "?idsite=1&rec=1&apiv=1&uid=user%40example.com",
            ],
            "token_auth": "tok",
        });
        let body = serde_json::to_vec(&payload).unwrap();
        let pr = run_spec(&h, None, Some(&body), Some("application/json"))
            .await
            .unwrap();
        let out = body_str(&pr);
        assert!(out.contains("Pricing"));
        assert!(!out.contains("user@example.com"));
    }

    // -----------------------------------------------------------------------
    // Per-field fallback behaviour
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn cvar_malformed_inner_json_falls_back_to_flat_scan() {
        // Malformed JSON should not block the whole request — the field
        // falls back to a flat scan of the raw value, other fields are
        // unaffected, and the metric increments under
        // `reason="invalid_inner_json"`.
        let before = metrics::SPECIALIZATION_ERRORS_TOTAL
            .with_label_values(&[SPEC_NAME, "invalid_inner_json"])
            .get();

        let h = redact_handle();
        // The malformed JSON itself contains PII so we can verify the
        // fallback flat scan still catches it.
        let bad = "{not json — user@example.com";
        let q = format!(
            "idsite=1&rec=1&apiv=1&cvar={}&action_name=Home",
            form_encode(bad)
        );
        let pr = run_spec(&h, Some(&q), None, None).await.unwrap();
        let out = query_str(&pr);
        // Other fields still pass through.
        assert!(out.contains("action_name=Home"));
        // Flat-scan fallback caught the email leak.
        assert!(!out.contains("user@example.com"));
        assert!(!out.contains("user%40example.com"));

        let after = metrics::SPECIALIZATION_ERRORS_TOTAL
            .with_label_values(&[SPEC_NAME, "invalid_inner_json"])
            .get();
        assert_eq!(
            after,
            before + 1,
            "invalid_inner_json should have incremented exactly once"
        );
    }

    #[tokio::test]
    async fn url_value_without_scheme_falls_back_to_flat_scan() {
        // A non-URL value in `url=` is still processed by the URL handler —
        // the splitter degenerates path=value/query=None, which then runs a
        // flat scan of the raw value. Behaviour is equivalent to a fallback.
        let h = redact_handle();
        let q = format!(
            "idsite=1&rec=1&apiv=1&url={}",
            form_encode("contact us at user@example.com")
        );
        let pr = run_spec(&h, Some(&q), None, None).await.unwrap();
        let out = query_str(&pr);
        assert!(!out.contains("user@example.com"));
        assert!(!out.contains("user%40example.com"));
    }

    // -----------------------------------------------------------------------
    // Error paths
    // -----------------------------------------------------------------------

    enum ExpectedErr {
        DecodeReason(&'static str),
        Unsupported,
    }

    #[test_case(b"{not json", Some("application/json"), ExpectedErr::DecodeReason("invalid_bulk_json") ; "malformed bulk json")]
    #[test_case(b"[1, 2, 3]", Some("application/json"), ExpectedErr::DecodeReason("invalid_bulk_json") ; "top level array")]
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
    async fn form_invalid_percent_encoding_decodes_error() {
        // `%ZZ` is not a valid percent-encoded sequence. parse_form_pairs
        // surfaces the failure as `invalid_form_encoding`.
        let h = scan_only_handle();
        // Outer query is fine (form encoding is byte-level — invalid `%ZZ`
        // sequences are tolerated by the percent_decode crate), so we hit
        // this path via a body with explicitly invalid UTF-8 after decode.
        let body = b"action_name=%FF%FE";
        let err = run_spec(
            &h,
            None,
            Some(body),
            Some("application/x-www-form-urlencoded"),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, SpecializationError::Decode { ref reason } if reason == "invalid_form_encoding"),
            "expected invalid_form_encoding, got {err:?}"
        );
    }

    #[tokio::test]
    async fn recursion_limit_hits_when_url_nests_url() {
        // 5-deep url-in-url synthesizes well past the 3-layer limit.
        let h = scan_only_handle();
        let mut inner = String::from("http://leaf.example/");
        for _ in 0..5 {
            inner = format!("http://x.example/?url={}", form_encode(&inner));
        }
        let q = format!("idsite=1&rec=1&apiv=1&url={}", form_encode(&inner));
        let err = run_spec(&h, Some(&q), None, None).await.unwrap_err();
        assert!(matches!(err, SpecializationError::RecursionLimit));
    }

    // -----------------------------------------------------------------------
    // Pass-through paths
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn clean_query_round_trips_verbatim() {
        let h = redact_handle();
        let q = "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url=https%3A%2F%2Fshop.example.com%2Fpricing&action_name=Pricing&res=1920x1080";
        let pr = run_spec(&h, Some(q), None, None).await.unwrap();
        assert_eq!(pr.scan_result.matches_count, 0);
        assert!(pr.body.is_none());
        // The re-encoded query must be byte-identical to the input when no
        // PII fired: same key order, same encoding.
        assert_eq!(query_str(&pr), q);
    }

    // Protocol-evolution regression: if Matomo ships a new tracker field
    // we haven't allowlisted yet, it must round-trip verbatim through the
    // re-encoded output instead of being dropped or causing the spec to
    // fail. The cost is that PII in the new field goes undetected until
    // the allowlist is updated — explicit deal per DESIGN.md.
    #[tokio::test]
    async fn unknown_form_fields_round_trip_verbatim() {
        let h = redact_handle();
        // Two synthetic unknown fields placed between known fields. Use
        // values that exercise form-encoding (`+`, `%2F`, spaces) so we
        // confirm the round-trip is structurally sound, not just naive.
        let q = "idsite=1&new_field_alpha=hello%20world&action_name=Home&new_field_beta=path%2Fwith%2Fslash&rec=1";
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
        assert_eq!(by_key("action_name").value, "Home");
        assert_eq!(by_key("idsite").value, "1");
        assert_eq!(by_key("rec").value, "1");
    }

    // Bulk envelope: any new top-level JSON key (beyond `requests` and
    // `token_auth`) must also pass through. Matomo's bulk endpoint has
    // historically grown new envelope fields; we don't want to lose them.
    #[tokio::test]
    async fn unknown_bulk_envelope_keys_round_trip() {
        let h = redact_handle();
        let payload = json!({
            "requests": ["?idsite=1&action_name=Home"],
            "token_auth": "tok",
            "future_envelope_field": "future-value",
            "future_object": {"nested": "value"},
        });
        let body = serde_json::to_vec(&payload).unwrap();
        let pr = run_spec(&h, None, Some(&body), Some("application/json"))
            .await
            .unwrap();
        let parsed: Value = serde_json::from_str(&body_str(&pr)).unwrap();
        assert_eq!(parsed["future_envelope_field"], json!("future-value"));
        assert_eq!(parsed["future_object"], json!({"nested": "value"}));
        assert_eq!(parsed["token_auth"], json!("tok"));
    }

    // -----------------------------------------------------------------------
    // Canonical regression — the user-reported issue
    // -----------------------------------------------------------------------
    //
    // Matomo payload with `url=` containing a URL-encoded email and a
    // `dimension2` containing a URL-encoded phone number. Redacted output
    // must be valid form-encoded data: brackets in `[EMAIL]`/`[PHONE_NUMBER]`
    // percent-encoded as `%5B`/`%5D`. Round-tripping the output through a
    // form-decoder must yield the redaction labels intact.

    #[tokio::test]
    async fn canonical_demo_payload_redacts_with_encoded_brackets() {
        let h = redact_handle();
        let inner = "https://app.example.com/account?email=jane.doe@example.com";
        let phone = "phone: 5551234567";
        let q = format!(
            "idsite=1&rec=1&apiv=1&_id=a1b2c3d4e5f6a7b8&url={}&dimension2={}",
            form_encode(inner),
            form_encode(phone)
        );
        let pr = run_spec(&h, Some(&q), None, None).await.unwrap();
        let out = query_str(&pr);

        // No raw PII anywhere.
        assert!(!out.contains("jane.doe@example.com"));
        assert!(!out.contains("jane.doe%40example.com"));
        assert!(!out.contains("5551234567"));

        // Brackets are properly form-encoded. dimension2 is at the outer
        // layer, so it sees one round of form-encoding (`%5B`). url's inner
        // value is doubly form-encoded (`%255B`).
        assert!(
            out.contains("%5B"),
            "outer-layer redaction label should be percent-encoded: {out}"
        );
        assert!(
            out.contains("%255B"),
            "inner-URL redaction label should be doubly-encoded: {out}"
        );

        // Round-trip through a form decoder reveals the literal labels
        // again. Parsing each pair and decoding values:
        let pairs = parse_form_pairs(&out).unwrap();
        let dim2_pair = pairs
            .iter()
            .find(|p| p.key == "dimension2")
            .expect("dimension2 present");
        assert!(
            dim2_pair.value.contains("[PHONE_NUMBER]")
                || dim2_pair.value.contains("[US_PHONE_NUMBER]"),
            "dimension2 decoded value should hold a redaction label, got: {}",
            dim2_pair.value
        );
        let url_pair = pairs.iter().find(|p| p.key == "url").expect("url present");
        // Inner layer: decode once more to reach the original placement.
        // url_pair.value is already form-decoded once → it is the inner URL
        // with form-encoded inner params. Splitting and decoding the email
        // param value reveals `[EMAIL]`.
        let inner_parts = split_url(&url_pair.value);
        let inner_pairs = parse_form_pairs(inner_parts.query.unwrap_or("")).unwrap();
        let email_pair = inner_pairs
            .iter()
            .find(|p| p.key == "email")
            .expect("email inner present");
        assert_eq!(
            email_pair.value, "[EMAIL]",
            "inner email value should be the literal redaction label"
        );
    }
}
