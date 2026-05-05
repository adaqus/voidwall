//! CSV/TSV body parser.
//!
//! The `csv` crate parses the first row to extract header names and validate
//! the document. A small linear scan over the raw bytes recovers
//! document-absolute byte offsets for every cell — `csv::ByteRecord` exposes
//! record-level positions but not per-field positions in the original input.
//! Both passes iterate fields in the same order, so they pair up by index.
//!
//! Quoted fields have their surrounding quotes stripped from the value. Inner
//! escape sequences (`""`) are kept literal so `value.len()` continues to
//! match the source byte span used for redaction.

use csv::ReaderBuilder;

use super::OwnedContextFragment;
use crate::error::Error;

/// Parse CSV/TSV with the given delimiter.
///
/// Returns `Ok(None)` when no header row is detected (caller falls back to
/// flat text scanning). Returns `Ok(Some(_))` with one fragment per data
/// cell, context formatted as `column_name[row_index]` (0-based, excluding
/// the header row).
pub fn flatten_csv(raw: &[u8], delimiter: u8) -> Result<Option<Vec<OwnedContextFragment>>, Error> {
    let mut reader = ReaderBuilder::new()
        .delimiter(delimiter)
        .has_headers(false)
        .flexible(true)
        .from_reader(raw);

    let mut header_record = csv::ByteRecord::new();
    let has_first = reader
        .read_byte_record(&mut header_record)
        .map_err(|e| Error::Scanner(format!("invalid CSV: {e}")))?;
    if !has_first || header_record.is_empty() {
        return Ok(None);
    }

    let headers: Vec<String> = (0..header_record.len())
        .map(|i| {
            std::str::from_utf8(&header_record[i])
                .map(str::to_owned)
                .map_err(|e| Error::Scanner(format!("invalid UTF-8 in CSV header: {e}")))
        })
        .collect::<Result<_, _>>()?;

    if !looks_like_header(&headers) {
        return Ok(None);
    }

    let positions = scan_field_positions(raw, delimiter)?;
    if positions.len() < 2 {
        return Ok(Some(Vec::new()));
    }

    let mut frags = Vec::new();
    for (row_idx, fields) in positions[1..].iter().enumerate() {
        for (col_idx, &(start, end)) in fields.iter().enumerate() {
            if col_idx >= headers.len() {
                break;
            }
            let bytes = &raw[start..end];
            let text = std::str::from_utf8(bytes)
                .map_err(|e| Error::Scanner(format!("invalid UTF-8 in CSV cell: {e}")))?
                .to_owned();
            frags.push(OwnedContextFragment {
                context: format!("{}[{row_idx}]", headers[col_idx]),
                value: text,
                offset: start,
            });
        }
    }
    Ok(Some(frags))
}

/// At least one field must be non-empty and non-numeric for the row to be
/// treated as a header. Empty cells contribute neither way.
fn looks_like_header(headers: &[String]) -> bool {
    headers.iter().any(|h| {
        let trimmed = h.trim();
        !trimmed.is_empty() && trimmed.parse::<f64>().is_err()
    })
}

/// Walk raw bytes and emit `(content_start, content_end)` ranges for every
/// field in every record, in document order. For quoted fields, content
/// excludes the surrounding quotes; doubled-quote escapes (`""`) are not
/// decoded so offsets stay aligned with the raw bytes.
fn scan_field_positions(raw: &[u8], delimiter: u8) -> Result<Vec<Vec<(usize, usize)>>, Error> {
    let mut records: Vec<Vec<(usize, usize)>> = Vec::new();
    let mut current: Vec<(usize, usize)> = Vec::new();
    let n = raw.len();
    let mut i = 0usize;

    while i < n {
        let (content_start, content_end, mut next_i) = if raw[i] == b'"' {
            let cs = i + 1;
            let mut j = cs;
            loop {
                if j >= n {
                    return Err(Error::Scanner("unterminated quoted CSV field".into()));
                }
                if raw[j] == b'"' {
                    if j + 1 < n && raw[j + 1] == b'"' {
                        j += 2;
                        continue;
                    }
                    break;
                }
                j += 1;
            }
            (cs, j, j + 1)
        } else {
            let cs = i;
            let mut j = i;
            while j < n && raw[j] != delimiter && raw[j] != b'\n' && raw[j] != b'\r' {
                j += 1;
            }
            (cs, j, j)
        };

        current.push((content_start, content_end));

        if next_i >= n {
            records.push(std::mem::take(&mut current));
            break;
        }
        match raw[next_i] {
            d if d == delimiter => {
                next_i += 1;
                if next_i == n {
                    // Trailing delimiter — empty final field.
                    current.push((next_i, next_i));
                    records.push(std::mem::take(&mut current));
                    break;
                }
                i = next_i;
            }
            b'\n' => {
                records.push(std::mem::take(&mut current));
                i = next_i + 1;
            }
            b'\r' => {
                let mut after = next_i + 1;
                if after < n && raw[after] == b'\n' {
                    after += 1;
                }
                records.push(std::mem::take(&mut current));
                i = after;
            }
            other => {
                return Err(Error::Scanner(format!(
                    "unexpected byte 0x{other:02x} after CSV field"
                )));
            }
        }
    }

    if !current.is_empty() {
        records.push(current);
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify each fragment's `offset` actually points at its `value` in `raw`.
    fn check_offsets(raw: &[u8], frags: &[OwnedContextFragment]) {
        for f in frags {
            let slice = &raw[f.offset..f.offset + f.value.len()];
            let actual = std::str::from_utf8(slice).expect("utf-8 slice");
            assert_eq!(
                actual, f.value,
                "fragment {f:?} offset does not point to value bytes",
            );
        }
    }

    #[test]
    fn basic_csv_with_headers() {
        let raw = b"phone,name\n555-1234,John\n555-5678,Jane";
        let frags = flatten_csv(raw, b',').unwrap().unwrap();
        let contexts: Vec<&str> = frags.iter().map(|f| f.context.as_str()).collect();
        let values: Vec<&str> = frags.iter().map(|f| f.value.as_str()).collect();
        assert_eq!(contexts, vec!["phone[0]", "name[0]", "phone[1]", "name[1]"]);
        assert_eq!(values, vec!["555-1234", "John", "555-5678", "Jane"]);
        check_offsets(raw, &frags);
    }

    #[test]
    fn tsv_tab_delimiter() {
        let raw = b"phone\tname\n555-1234\tJohn";
        let frags = flatten_csv(raw, b'\t').unwrap().unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].context, "phone[0]");
        assert_eq!(frags[0].value, "555-1234");
        assert_eq!(frags[1].context, "name[0]");
        assert_eq!(frags[1].value, "John");
        check_offsets(raw, &frags);
    }

    #[test]
    fn no_headers_all_numeric_returns_none() {
        // First row is all numeric → no headers.
        let raw = b"123,456\n789,012";
        assert!(flatten_csv(raw, b',').unwrap().is_none());
    }

    #[test]
    fn no_headers_single_numeric_column_returns_none() {
        let raw = b"123\n456\n789";
        assert!(flatten_csv(raw, b',').unwrap().is_none());
    }

    #[test]
    fn empty_input_returns_none() {
        assert!(flatten_csv(b"", b',').unwrap().is_none());
    }

    #[test]
    fn empty_cells_emit_empty_value_fragments() {
        let raw = b"a,b,c\n,x,";
        let frags = flatten_csv(raw, b',').unwrap().unwrap();
        assert_eq!(frags.len(), 3);
        assert_eq!(frags[0].context, "a[0]");
        assert_eq!(frags[0].value, "");
        assert_eq!(frags[1].context, "b[0]");
        assert_eq!(frags[1].value, "x");
        assert_eq!(frags[2].context, "c[0]");
        assert_eq!(frags[2].value, "");
        check_offsets(raw, &frags);
    }

    #[test]
    fn quoted_fields_strip_outer_quotes() {
        let raw = br#""phone","name"
"555-1234","John"
"#;
        let frags = flatten_csv(raw, b',').unwrap().unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].context, "phone[0]");
        assert_eq!(frags[0].value, "555-1234");
        assert_eq!(frags[1].context, "name[0]");
        assert_eq!(frags[1].value, "John");
        // Offsets must point inside the quotes, not at them.
        check_offsets(raw, &frags);
    }

    #[test]
    fn quoted_field_containing_delimiter() {
        // Delimiter inside quotes is part of the value, not a separator.
        let raw = br#"name,note
"Smith, John","ok"
"#;
        let frags = flatten_csv(raw, b',').unwrap().unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].context, "name[0]");
        assert_eq!(frags[0].value, "Smith, John");
        assert_eq!(frags[1].context, "note[0]");
        assert_eq!(frags[1].value, "ok");
        check_offsets(raw, &frags);
    }

    #[test]
    fn single_row_headers_only_no_data() {
        let raw = b"phone,name";
        let frags = flatten_csv(raw, b',').unwrap().unwrap();
        assert!(frags.is_empty());
    }

    #[test]
    fn single_row_with_trailing_newline_no_data() {
        let raw = b"phone,name\n";
        let frags = flatten_csv(raw, b',').unwrap().unwrap();
        assert!(frags.is_empty());
    }

    #[test]
    fn crlf_line_endings() {
        let raw = b"phone,name\r\n555-1234,John\r\n";
        let frags = flatten_csv(raw, b',').unwrap().unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].value, "555-1234");
        assert_eq!(frags[1].value, "John");
        check_offsets(raw, &frags);
    }

    #[test]
    fn ragged_row_extra_field_ignored() {
        // Row has more cells than headers — extras dropped.
        let raw = b"a,b\n1,2,3";
        let frags = flatten_csv(raw, b',').unwrap().unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].context, "a[0]");
        assert_eq!(frags[1].context, "b[0]");
    }

    #[test]
    fn unterminated_quoted_field_errors() {
        let raw = br#"a,b
"unterminated,1"#;
        assert!(flatten_csv(raw, b',').is_err());
    }

    #[test]
    fn multiple_data_rows_get_distinct_row_indexes() {
        let raw = b"k\nv0\nv1\nv2";
        let frags = flatten_csv(raw, b',').unwrap().unwrap();
        let contexts: Vec<&str> = frags.iter().map(|f| f.context.as_str()).collect();
        assert_eq!(contexts, vec!["k[0]", "k[1]", "k[2]"]);
        assert_eq!(frags[0].value, "v0");
        assert_eq!(frags[1].value, "v1");
        assert_eq!(frags[2].value, "v2");
        check_offsets(raw, &frags);
    }

    #[test]
    fn utf8_multibyte_value() {
        let raw = "k\ncafé".as_bytes();
        let frags = flatten_csv(raw, b',').unwrap().unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].value, "café");
        check_offsets(raw, &frags);
    }

    #[test]
    fn header_with_at_least_one_non_numeric_qualifies() {
        // "1,phone" has one numeric and one non-numeric field — still a header.
        let raw = b"1,phone\n2,555-1234";
        let frags = flatten_csv(raw, b',').unwrap().unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].context, "1[0]");
        assert_eq!(frags[0].value, "2");
        assert_eq!(frags[1].context, "phone[0]");
        assert_eq!(frags[1].value, "555-1234");
    }
}
