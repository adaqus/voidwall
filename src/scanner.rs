use std::collections::HashSet;
use std::io::{self, Read};

use crate::detector::Detector;
use crate::keyword_context_detector::KeywordContextDetector;
use crate::regex_detector::RegexDetector;
use crate::{Country, Language, PiiError, PiiKind, PiiMatch};

/// Maximum byte length of any single PII token we need to detect.
/// Overlap between chunks is set to this value so that PII spanning
/// a chunk boundary is never missed.
const MAX_PII_SPAN: usize = 256;

/// Default chunk size used by the `Read`-based streaming methods.
const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

pub struct Scanner {
    detectors: Vec<Box<dyn Detector>>,
}

pub struct ScannerBuilder {
    countries: HashSet<Country>,
    languages: HashSet<Language>,
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
        }
    }

    /// Returns `true` if any PII is detected in the data from `reader`.
    ///
    /// Reads the input in chunks, short-circuiting as soon as PII is found.
    pub fn has_piis(&self, reader: impl Read) -> io::Result<bool> {
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

    /// Returns all PII matches found in the data from `reader`.
    ///
    /// Match offsets are absolute byte positions from the start of the stream.
    pub fn mark_piis(&self, reader: impl Read) -> io::Result<Vec<PiiMatch>> {
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

    /// Internal: run mark_piis on a string slice.
    fn mark_piis_internal(&self, input: &str) -> Vec<PiiMatch> {
        self.detectors
            .iter()
            .flat_map(|d| d.mark_piis(input))
            .collect()
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
}
