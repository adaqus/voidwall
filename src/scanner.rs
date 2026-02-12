use std::collections::HashSet;
use std::io::{self, Read, Write};

use crate::detector::Detector;
use crate::keyword_context_detector::KeywordContextDetector;
use crate::regex_detector::RegexDetector;
use crate::{Country, Language, PiiError, PiiKind, PiiMatch, RedactWith};

/// Maximum byte length of any single PII token we need to detect.
/// Overlap between chunks is set to this value so that PII spanning
/// a chunk boundary is never missed.
const MAX_PII_SPAN: usize = 256;

/// Default chunk size used by the `Read`-based streaming methods.
const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Input size threshold above which parallel scanning is used.
#[cfg(feature = "parallel")]
const PARALLEL_THRESHOLD: usize = 128 * 1024;

/// Chunk size for parallel scanning.
#[cfg(feature = "parallel")]
const PARALLEL_CHUNK_SIZE: usize = 64 * 1024;

/// Splits `input` into overlapping chunks for parallel processing.
///
/// Returns `(chunk_abs_start, owned_start, chunk_slice)` tuples where:
/// - `chunk_abs_start` is the byte offset of the chunk slice in the original input
/// - `owned_start` is the byte offset where the "owned" (non-overlap) region begins
/// - `chunk_slice` is the slice of input for this chunk
///
/// The first chunk has no overlap prefix. Subsequent chunks include an
/// `overlap`-byte prefix (adjusted to UTF-8 char boundaries) so that PII
/// spanning a chunk boundary is not missed.
#[cfg(feature = "parallel")]
fn split_overlapping_chunks(
    input: &str,
    chunk_size: usize,
    overlap: usize,
) -> Vec<(usize, usize, &str)> {
    let mut chunks = Vec::new();
    let len = input.len();
    let mut owned_start: usize = 0;

    while owned_start < len {
        let owned_end = (owned_start + chunk_size).min(len);
        // Adjust to char boundary
        let owned_end = if owned_end < len {
            let mut b = owned_end;
            while b > owned_start && !input.is_char_boundary(b) {
                b -= 1;
            }
            b
        } else {
            owned_end
        };

        // Compute overlap prefix start
        let chunk_abs_start = if owned_start == 0 {
            0
        } else {
            let raw = owned_start.saturating_sub(overlap);
            let mut b = raw;
            while b < owned_start && !input.is_char_boundary(b) {
                b += 1;
            }
            b
        };

        chunks.push((
            chunk_abs_start,
            owned_start,
            &input[chunk_abs_start..owned_end],
        ));
        owned_start = owned_end;
    }

    chunks
}

pub struct Scanner {
    detectors: Vec<Box<dyn Detector + Send + Sync>>,
    #[cfg(feature = "parallel")]
    thread_pool: rayon::ThreadPool,
}

pub struct ScannerBuilder {
    countries: HashSet<Country>,
    languages: HashSet<Language>,
    #[cfg(feature = "parallel")]
    thread_count: usize,
}

/// Incrementally scans text chunk-by-chunk for PII.
///
/// Created via [`Scanner::chunked_scanner`]. Feed arbitrary chunks of text
/// with [`has_piis_chunk`](ChunkedScanner::has_piis_chunk) or
/// [`mark_piis_chunk`](ChunkedScanner::mark_piis_chunk). The scanner
/// maintains an overlap window so PII spanning chunk boundaries is detected.
pub struct ChunkedScanner<'a> {
    scanner: &'a Scanner,
    overlap: String,
    absolute_offset: usize,
}

impl Scanner {
    /// Creates a scanner with all countries and languages enabled.
    pub fn new() -> Result<Self, PiiError> {
        Self::builder().build()
    }

    pub fn builder() -> ScannerBuilder {
        ScannerBuilder {
            countries: HashSet::new(),
            languages: HashSet::new(),
            #[cfg(feature = "parallel")]
            thread_count: 0,
        }
    }

    /// Returns `true` if any PII is detected in the data from `reader`.
    ///
    /// Reads the input in chunks, short-circuiting as soon as PII is found.
    /// When the `parallel` feature is enabled and the input exceeds 128 KB,
    /// chunks are scanned in parallel using rayon.
    pub fn has_piis(&self, reader: impl Read) -> io::Result<bool> {
        #[cfg(feature = "parallel")]
        {
            let mut input = String::new();
            io::BufReader::new(reader).read_to_string(&mut input)?;
            if input.len() >= PARALLEL_THRESHOLD {
                return Ok(self.has_piis_parallel(&input));
            }
            self.has_piis_sequential(input.as_bytes())
        }
        #[cfg(not(feature = "parallel"))]
        self.has_piis_sequential(reader)
    }

    /// Returns all PII matches found in the data from `reader`.
    ///
    /// Match offsets are absolute byte positions from the start of the stream.
    /// When the `parallel` feature is enabled and the input exceeds 128 KB,
    /// chunks are scanned in parallel using rayon.
    pub fn mark_piis(&self, reader: impl Read) -> io::Result<Vec<PiiMatch>> {
        #[cfg(feature = "parallel")]
        {
            let mut input = String::new();
            io::BufReader::new(reader).read_to_string(&mut input)?;
            if input.len() >= PARALLEL_THRESHOLD {
                return Ok(self.mark_piis_parallel(&input));
            }
            self.mark_piis_sequential(input.as_bytes())
        }
        #[cfg(not(feature = "parallel"))]
        self.mark_piis_sequential(reader)
    }

    fn has_piis_sequential(&self, reader: impl Read) -> io::Result<bool> {
        let mut chunked = self.chunked_scanner();
        let mut buf_reader = io::BufReader::with_capacity(DEFAULT_CHUNK_SIZE, reader);
        let mut buf = vec![0u8; DEFAULT_CHUNK_SIZE];

        loop {
            let n = buf_reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let chunk = std::str::from_utf8(&buf[..n])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if chunked.has_piis_chunk(chunk) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn mark_piis_sequential(&self, reader: impl Read) -> io::Result<Vec<PiiMatch>> {
        let mut chunked = self.chunked_scanner();
        let mut buf_reader = io::BufReader::with_capacity(DEFAULT_CHUNK_SIZE, reader);
        let mut buf = vec![0u8; DEFAULT_CHUNK_SIZE];
        let mut all_matches = Vec::new();

        loop {
            let n = buf_reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let chunk = std::str::from_utf8(&buf[..n])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            all_matches.extend(chunked.mark_piis_chunk(chunk));
        }
        Ok(all_matches)
    }

    /// Creates a [`ChunkedScanner`] for manually feeding text chunks.
    pub fn chunked_scanner(&self) -> ChunkedScanner<'_> {
        ChunkedScanner {
            scanner: self,
            overlap: String::new(),
            absolute_offset: 0,
        }
    }

    /// Internal: run has_piis on a string slice.
    fn has_piis_internal(&self, input: &str) -> bool {
        self.detectors.iter().any(|d| d.has_piis(input))
    }

    /// Redacts all PII found in `reader`, writing the result to `writer`.
    ///
    /// Non-PII text is passed through unchanged. PII regions are replaced
    /// according to the given `strategy`.
    pub fn redact(
        &self,
        reader: impl Read,
        writer: &mut impl Write,
        strategy: &RedactWith,
    ) -> io::Result<()> {
        let mut input = String::new();
        io::BufReader::new(reader).read_to_string(&mut input)?;

        let mut matches = self.mark_piis_internal(&input);
        matches.sort_by_key(|m| m.start);

        let mut cursor = 0;
        for m in &matches {
            if m.start < cursor {
                continue;
            }
            writer.write_all(&input.as_bytes()[cursor..m.start])?;
            let replacement = strategy.apply(m.kind, &input[m.start..m.end]);
            writer.write_all(replacement.as_bytes())?;
            cursor = m.end;
        }
        writer.write_all(&input.as_bytes()[cursor..])?;
        Ok(())
    }

    /// Internal: run mark_piis on a string slice.
    fn mark_piis_internal(&self, input: &str) -> Vec<PiiMatch> {
        self.detectors
            .iter()
            .flat_map(|d| d.mark_piis(input))
            .collect()
    }

    #[cfg(feature = "parallel")]
    fn has_piis_parallel(&self, input: &str) -> bool {
        use rayon::prelude::*;
        let chunks = split_overlapping_chunks(input, PARALLEL_CHUNK_SIZE, MAX_PII_SPAN);
        self.thread_pool.install(|| {
            chunks
                .par_iter()
                .any(|&(_, _, chunk)| self.has_piis_internal(chunk))
        })
    }

    #[cfg(feature = "parallel")]
    fn mark_piis_parallel(&self, input: &str) -> Vec<PiiMatch> {
        use rayon::prelude::*;
        let chunks = split_overlapping_chunks(input, PARALLEL_CHUNK_SIZE, MAX_PII_SPAN);
        let mut results: Vec<PiiMatch> = self.thread_pool.install(|| {
            chunks
                .par_iter()
                .flat_map_iter(|&(chunk_abs_start, owned_start, chunk)| {
                    let overlap_len = owned_start - chunk_abs_start;
                    self.mark_piis_internal(chunk)
                        .into_iter()
                        .filter(move |m| m.end > overlap_len)
                        .map(move |m| PiiMatch {
                            kind: m.kind,
                            start: chunk_abs_start + m.start,
                            end: chunk_abs_start + m.end,
                        })
                })
                .collect()
        });
        results.sort_by_key(|m| m.start);
        results
    }
}

impl<'a> ChunkedScanner<'a> {
    /// Returns `true` if any PII is found in the current chunk
    /// (including overlap from the previous chunk).
    pub fn has_piis_chunk(&mut self, chunk: &str) -> bool {
        let combined = self.combined(chunk);
        let found = self.scanner.has_piis_internal(&combined);
        self.advance(chunk);
        found
    }

    /// Returns PII matches found in the current chunk, with byte offsets
    /// adjusted to absolute positions from the start of the stream.
    ///
    /// Matches that fall entirely within the overlap region (i.e. already
    /// reported in the previous chunk) are filtered out.
    pub fn mark_piis_chunk(&mut self, chunk: &str) -> Vec<PiiMatch> {
        let overlap_len = self.overlap.len();
        let combined = self.combined(chunk);
        let raw = self.scanner.mark_piis_internal(&combined);

        // The absolute offset of the start of `combined` in the stream.
        let combined_abs_start = self.absolute_offset - overlap_len;

        // Filter out matches that end within the overlap (already reported).
        // Adjust offsets to absolute positions.
        let matches = raw
            .into_iter()
            .filter(|m| m.end > overlap_len)
            .map(|m| PiiMatch {
                kind: m.kind,
                start: combined_abs_start + m.start,
                end: combined_abs_start + m.end,
            })
            .collect();

        self.advance(chunk);
        matches
    }

    /// Redacts PII in the given chunk, returning the redacted text.
    ///
    /// Maintains an internal overlap buffer to catch PII spanning chunk
    /// boundaries. Call [`finish_redaction`](Self::finish_redaction) after
    /// the last chunk to flush the remaining buffer.
    ///
    /// **Note:** Do not mix `redact_chunk`/`finish_redaction` calls with
    /// `mark_piis_chunk`/`has_piis_chunk` on the same `ChunkedScanner`
    /// instance, as they use the overlap buffer with different semantics.
    pub fn redact_chunk(&mut self, chunk: &str, strategy: &RedactWith) -> String {
        let combined = self.combined(chunk);
        let matches = self.scanner.mark_piis_internal(&combined);

        let safe_end = Self::safe_boundary(&combined, MAX_PII_SPAN);
        let result = Self::build_redacted(&combined, &matches, 0, safe_end, strategy);

        self.overlap = combined[safe_end..].to_string();
        self.absolute_offset += chunk.len();
        result
    }

    /// Flushes the remaining overlap buffer, redacting any PII found.
    ///
    /// Must be called after the last [`redact_chunk`](Self::redact_chunk) to
    /// ensure all text is emitted.
    pub fn finish_redaction(&mut self, strategy: &RedactWith) -> String {
        let overlap = std::mem::take(&mut self.overlap);
        let matches = self.scanner.mark_piis_internal(&overlap);
        Self::build_redacted(&overlap, &matches, 0, overlap.len(), strategy)
    }

    /// Finds the largest char-boundary position at or before `text.len() - tail`.
    fn safe_boundary(text: &str, tail: usize) -> usize {
        let raw = text.len().saturating_sub(tail);
        // Walk forward to a char boundary (floor_char_boundary is nightly-only).
        let mut boundary = raw;
        while boundary > 0 && !text.is_char_boundary(boundary) {
            boundary -= 1;
        }
        boundary
    }

    /// Builds redacted output for `text[start..end]`, replacing PII with the strategy.
    fn build_redacted(
        text: &str,
        matches: &[PiiMatch],
        start: usize,
        end: usize,
        strategy: &RedactWith,
    ) -> String {
        let mut sorted: Vec<&PiiMatch> = matches
            .iter()
            .filter(|m| m.end > start && m.start < end)
            .collect();
        sorted.sort_by_key(|m| m.start);

        let mut result = String::new();
        let mut cursor = start;
        for m in sorted {
            let m_start = m.start.max(start);
            let m_end = m.end.min(end);
            if m_start < cursor {
                continue;
            }
            result.push_str(&text[cursor..m_start]);
            result.push_str(&strategy.apply(m.kind, &text[m_start..m_end]));
            cursor = m_end;
        }
        result.push_str(&text[cursor..end]);
        result
    }

    /// Build the combined string: overlap + chunk.
    fn combined(&self, chunk: &str) -> String {
        let mut combined = String::with_capacity(self.overlap.len() + chunk.len());
        combined.push_str(&self.overlap);
        combined.push_str(chunk);
        combined
    }

    /// Advance the overlap window and absolute offset after processing a chunk.
    fn advance(&mut self, chunk: &str) {
        self.absolute_offset += chunk.len();

        // Keep at most MAX_PII_SPAN bytes of trailing context for overlap.
        let full = format!("{}{}", self.overlap, chunk);
        if full.len() > MAX_PII_SPAN {
            // Find a char boundary at or after the split point.
            let mut boundary = full.len() - MAX_PII_SPAN;
            while !full.is_char_boundary(boundary) {
                boundary += 1;
            }
            self.overlap = full[boundary..].to_string();
        } else {
            self.overlap = full;
        }
    }
}

impl ScannerBuilder {
    /// Set the countries whose PII types should be detected.
    ///
    /// If not called (or called with an empty iterator), all countries are
    /// enabled by default.
    pub fn countries(mut self, countries: impl IntoIterator<Item = Country>) -> Self {
        self.countries = countries.into_iter().collect();
        self
    }

    /// Set the keyword languages to use.
    ///
    /// If not called (or called with an empty iterator), all languages are
    /// enabled by default.
    pub fn languages(mut self, languages: impl IntoIterator<Item = Language>) -> Self {
        self.languages = languages.into_iter().collect();
        self
    }

    /// Set the number of threads for the parallel scanning thread pool.
    ///
    /// Only available with the `parallel` feature. A value of `0` (the
    /// default) lets rayon choose based on available CPUs.
    #[cfg(feature = "parallel")]
    pub fn thread_count(mut self, count: usize) -> Self {
        self.thread_count = count;
        self
    }

    /// Build the scanner, compiling all selected patterns.
    pub fn build(self) -> Result<Scanner, PiiError> {
        let countries = if self.countries.is_empty() {
            Country::all().iter().copied().collect()
        } else {
            self.countries
        };

        let languages = if self.languages.is_empty() {
            Language::all().iter().copied().collect()
        } else {
            self.languages
        };

        let enabled_kinds = PiiKind::enabled_for_countries(&countries);

        Ok(Scanner {
            detectors: vec![
                Box::new(RegexDetector::new(&enabled_kinds)?),
                Box::new(KeywordContextDetector::new(&enabled_kinds, &languages)?),
            ],
            #[cfg(feature = "parallel")]
            thread_pool: {
                let mut builder = rayon::ThreadPoolBuilder::new();
                if self.thread_count > 0 {
                    builder = builder.num_threads(self.thread_count);
                }
                builder.build().expect("failed to create rayon thread pool")
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_piis_detects_email() {
        let scanner = Scanner::new().unwrap();
        assert!(
            scanner
                .has_piis("email me at test@example.com".as_bytes())
                .unwrap()
        );
    }

    #[test]
    fn has_piis_returns_false_for_clean_text() {
        let scanner = Scanner::new().unwrap();
        assert!(
            !scanner
                .has_piis("nothing sensitive here".as_bytes())
                .unwrap()
        );
    }

    #[test]
    fn mark_piis_finds_multiple_types() {
        let scanner = Scanner::new().unwrap();
        let input = "email: user@test.com, phone: 555-123-4567, card: 4111 1111 1111 1111";
        let matches = scanner.mark_piis(input.as_bytes()).unwrap();

        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::PhoneNumber));
        assert!(kinds.contains(&PiiKind::CreditCard));
    }

    #[test]
    fn mark_piis_returns_correct_spans() {
        let scanner = Scanner::new().unwrap();
        let input = "hello user@test.com world";
        let matches = scanner.mark_piis(input.as_bytes()).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(&input[matches[0].start..matches[0].end], "user@test.com");
    }

    #[test]
    fn builder_all_countries_matches_new() {
        let scanner_new = Scanner::new().unwrap();
        let scanner_builder = Scanner::builder().build().unwrap();
        let input = "email: user@test.com, SSN: 123-45-6789, NINO: AB 12 34 56 C, \
                     phone: 555-123-4567, card: 4111 1111 1111 1111";
        let matches_new = scanner_new.mark_piis(input.as_bytes()).unwrap();
        let matches_builder = scanner_builder.mark_piis(input.as_bytes()).unwrap();
        assert_eq!(matches_new.len(), matches_builder.len());
    }

    #[test]
    fn builder_single_country_us() {
        let scanner = Scanner::builder()
            .countries([Country::Us, Country::International])
            .build()
            .unwrap();
        // US SSN should be detected
        let input = "SSN: 123-45-6789 and NINO: AB 12 34 56 C";
        let matches = scanner.mark_piis(input.as_bytes()).unwrap();
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::UsSsn));
        // GB NINO should NOT be detected
        assert!(!kinds.contains(&PiiKind::GbNino));
    }

    #[test]
    fn builder_single_country_gb() {
        let scanner = Scanner::builder()
            .countries([Country::Gb, Country::International])
            .build()
            .unwrap();
        let input = "SSN: 123-45-6789 and NINO: AB 12 34 56 C";
        let matches = scanner.mark_piis(input.as_bytes()).unwrap();
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::GbNino));
        assert!(!kinds.contains(&PiiKind::UsSsn));
    }

    #[test]
    fn builder_international_only() {
        let scanner = Scanner::builder()
            .countries([Country::International])
            .build()
            .unwrap();
        let input = "email: user@test.com, SSN: 123-45-6789, card: 4111 1111 1111 1111";
        let matches = scanner.mark_piis(input.as_bytes()).unwrap();
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::CreditCard));
        assert!(!kinds.contains(&PiiKind::UsSsn));
    }

    #[test]
    fn builder_excludes_unselected_countries() {
        let scanner = Scanner::builder().countries([Country::Us]).build().unwrap();
        // Input with US SSN + GB NINO + GB UTR
        let input = "SSN: 123-45-6789, NINO: AB 12 34 56 C, UTR: 5555555555";
        let matches = scanner.mark_piis(input.as_bytes()).unwrap();
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::UsSsn));
        assert!(!kinds.contains(&PiiKind::GbNino));
        assert!(!kinds.contains(&PiiKind::GbUtr));
    }

    #[test]
    fn builder_empty_countries_defaults_to_all() {
        let scanner = Scanner::builder()
            .countries(std::iter::empty::<Country>())
            .build()
            .unwrap();
        let input = "SSN: 123-45-6789 and NINO: AB 12 34 56 C";
        let matches = scanner.mark_piis(input.as_bytes()).unwrap();
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::UsSsn));
        assert!(kinds.contains(&PiiKind::GbNino));
    }

    #[test]
    fn builder_empty_languages_defaults_to_all() {
        let scanner = Scanner::builder()
            .languages(std::iter::empty::<Language>())
            .build()
            .unwrap();
        // keyword-based detection should still work
        let input = "phone: 555-123-4567";
        let matches = scanner.mark_piis(input.as_bytes()).unwrap();
        let kinds: Vec<PiiKind> = matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::PhoneNumber));
    }

    // --- ChunkedScanner tests ---

    #[test]
    fn chunked_scanner_detects_pii_within_single_chunk() {
        let scanner = Scanner::new().unwrap();
        let mut chunked = scanner.chunked_scanner();
        assert!(chunked.has_piis_chunk("email me at test@example.com"));
    }

    #[test]
    fn chunked_scanner_mark_piis_absolute_offsets() {
        let scanner = Scanner::new().unwrap();
        let mut chunked = scanner.chunked_scanner();

        let chunk1 = "no pii here at all. ";
        let chunk2 = "email me at test@example.com ok";

        let m1 = chunked.mark_piis_chunk(chunk1);
        assert!(m1.is_empty());

        let m2 = chunked.mark_piis_chunk(chunk2);
        assert_eq!(m2.len(), 1);
        assert_eq!(m2[0].kind, PiiKind::Email);

        // Offset should be absolute (relative to stream start)
        let full = format!("{}{}", chunk1, chunk2);
        assert_eq!(&full[m2[0].start..m2[0].end], "test@example.com");
    }

    #[test]
    fn chunked_scanner_pii_spanning_boundary() {
        let scanner = Scanner::new().unwrap();
        let mut chunked = scanner.chunked_scanner();

        // Split an email across two chunks
        let chunk1 = "contact us at test@";
        let chunk2 = "example.com for info";

        let m1 = chunked.mark_piis_chunk(chunk1);
        // Might or might not find partial match — either way is fine
        let _ = m1;

        let m2 = chunked.mark_piis_chunk(chunk2);
        // The overlap should catch the email spanning the boundary
        assert!(!m2.is_empty());
        assert_eq!(m2[0].kind, PiiKind::Email);

        let full = format!("{}{}", chunk1, chunk2);
        assert_eq!(&full[m2[0].start..m2[0].end], "test@example.com");
    }

    #[test]
    fn chunked_scanner_no_duplicate_matches() {
        let scanner = Scanner::new().unwrap();
        let mut chunked = scanner.chunked_scanner();

        // Feed a small chunk that fits entirely in overlap
        let chunk1 = "test@example.com";
        let chunk2 = " and more text here";

        let m1 = chunked.mark_piis_chunk(chunk1);
        assert_eq!(m1.len(), 1);

        // The email is now in the overlap, but should NOT be re-reported
        let m2 = chunked.mark_piis_chunk(chunk2);
        let email_matches: Vec<_> = m2.iter().filter(|m| m.kind == PiiKind::Email).collect();
        assert!(email_matches.is_empty());
    }

    #[test]
    fn chunked_scanner_multiple_chunks_multiple_piis() {
        let scanner = Scanner::new().unwrap();
        let mut chunked = scanner.chunked_scanner();

        let mut all_matches = Vec::new();
        all_matches.extend(chunked.mark_piis_chunk("Email: user@test.com and "));
        all_matches.extend(chunked.mark_piis_chunk("SSN: 123-45-6789 done"));

        let kinds: Vec<PiiKind> = all_matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&PiiKind::Email));
        assert!(kinds.contains(&PiiKind::UsSsn));
    }

    // --- Redaction tests ---

    #[test]
    fn redact_replaces_email_with_char_mask() {
        let scanner = Scanner::new().unwrap();
        let mut out = Vec::new();
        scanner
            .redact(
                "email me at test@example.com please".as_bytes(),
                &mut out,
                &crate::RedactWith::Char('*'),
            )
            .unwrap();
        let result = String::from_utf8(out).unwrap();
        assert_eq!(result, "email me at **************** please");
    }

    #[test]
    fn redact_replaces_with_type_label() {
        let scanner = Scanner::new().unwrap();
        let mut out = Vec::new();
        scanner
            .redact(
                "email me at test@example.com please".as_bytes(),
                &mut out,
                &crate::RedactWith::TypeLabel,
            )
            .unwrap();
        let result = String::from_utf8(out).unwrap();
        assert_eq!(result, "email me at [EMAIL] please");
    }

    #[test]
    fn redact_preserves_non_pii_text() {
        let scanner = Scanner::new().unwrap();
        let input = "nothing sensitive here at all";
        let mut out = Vec::new();
        scanner
            .redact(input.as_bytes(), &mut out, &crate::RedactWith::Char('*'))
            .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), input);
    }

    #[test]
    fn redact_handles_multiple_pii_types() {
        let scanner = Scanner::new().unwrap();
        let input = "email: user@test.com, SSN: 123-45-6789";
        let mut out = Vec::new();
        scanner
            .redact(input.as_bytes(), &mut out, &crate::RedactWith::TypeLabel)
            .unwrap();
        let result = String::from_utf8(out).unwrap();
        assert!(result.contains("[EMAIL]"));
        assert!(result.contains("[US_SSN]"));
        assert!(!result.contains("user@test.com"));
        assert!(!result.contains("123-45-6789"));
    }

    #[test]
    fn redact_writes_to_vec() {
        let scanner = Scanner::new().unwrap();
        let mut out: Vec<u8> = Vec::new();
        scanner
            .redact(
                "test@example.com".as_bytes(),
                &mut out,
                &crate::RedactWith::Char('#'),
            )
            .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "################");
    }

    #[test]
    fn chunked_redact_single_chunk() {
        let scanner = Scanner::new().unwrap();
        let input = "email me at test@example.com please";

        // Non-chunked
        let mut out = Vec::new();
        scanner
            .redact(input.as_bytes(), &mut out, &crate::RedactWith::Char('*'))
            .unwrap();
        let expected = String::from_utf8(out).unwrap();

        // Chunked (single chunk)
        let mut chunked = scanner.chunked_scanner();
        let mut result = chunked.redact_chunk(input, &crate::RedactWith::Char('*'));
        result.push_str(&chunked.finish_redaction(&crate::RedactWith::Char('*')));
        assert_eq!(result, expected);
    }

    #[test]
    fn chunked_redact_pii_spanning_boundary() {
        let scanner = Scanner::new().unwrap();
        let chunk1 = "contact us at test@";
        let chunk2 = "example.com for info";
        let strategy = crate::RedactWith::Char('*');

        let mut chunked = scanner.chunked_scanner();
        let mut result = String::new();
        result.push_str(&chunked.redact_chunk(chunk1, &strategy));
        result.push_str(&chunked.redact_chunk(chunk2, &strategy));
        result.push_str(&chunked.finish_redaction(&strategy));

        // The email should be fully redacted
        assert!(!result.contains("test@example.com"));
        assert!(result.contains("contact us at"));
        assert!(result.contains("for info"));
    }

    #[test]
    fn chunked_redact_finish_flushes() {
        let scanner = Scanner::new().unwrap();
        let strategy = crate::RedactWith::TypeLabel;

        let mut chunked = scanner.chunked_scanner();
        let r1 = chunked.redact_chunk("hello test@example.com", &strategy);
        let r2 = chunked.finish_redaction(&strategy);

        let result = format!("{}{}", r1, r2);
        assert!(result.contains("[EMAIL]"));
        assert!(!result.contains("test@example.com"));
    }

    #[test]
    fn chunked_redact_no_pii() {
        let scanner = Scanner::new().unwrap();
        let strategy = crate::RedactWith::Char('*');

        let mut chunked = scanner.chunked_scanner();
        let mut result = String::new();
        result.push_str(&chunked.redact_chunk("no sensitive data ", &strategy));
        result.push_str(&chunked.redact_chunk("in this text at all", &strategy));
        result.push_str(&chunked.finish_redaction(&strategy));

        assert_eq!(result, "no sensitive data in this text at all");
    }

    // Compile-time assertion that Scanner is Send + Sync.
    #[test]
    fn scanner_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Scanner>();
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_mark_piis_matches_sequential() {
        let scanner = Scanner::new().unwrap();
        // Build input larger than PARALLEL_THRESHOLD (128KB)
        let base = "Contact jane.doe@example.com or call (555) 123-4567. \
                     SSN: 123-45-6789. Card: 4111 1111 1111 1111. \
                     Nothing sensitive in this filler text that pads the input. ";
        let repetitions = (128 * 1024 / base.len()) + 10;
        let large_input: String = base.repeat(repetitions);
        assert!(large_input.len() >= 128 * 1024);

        // Sequential result: use the internal method on the whole string
        let mut sequential = scanner.mark_piis_internal(&large_input);
        sequential.sort_by_key(|m| (m.start, m.end));

        // Parallel result: goes through the public API which dispatches to parallel
        let mut parallel = scanner.mark_piis(large_input.as_bytes()).unwrap();
        parallel.sort_by_key(|m| (m.start, m.end));

        assert_eq!(
            sequential.len(),
            parallel.len(),
            "match count differs: sequential={}, parallel={}",
            sequential.len(),
            parallel.len()
        );
        for (s, p) in sequential.iter().zip(parallel.iter()) {
            assert_eq!(s, p, "mismatch: sequential={:?} parallel={:?}", s, p);
        }
    }
}
