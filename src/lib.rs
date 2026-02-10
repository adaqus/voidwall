pub mod detector;
pub mod keyword_context_detector;
pub mod regex_detector;
pub mod scanner;

pub use scanner::Scanner;

/// Errors that can occur during PII scanner initialization.
#[derive(Debug)]
pub enum PiiError {
    /// A regular expression failed to compile.
    RegexCompilation(regex::Error),
}

impl std::fmt::Display for PiiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PiiError::RegexCompilation(e) => write!(f, "regex compilation failed: {e}"),
        }
    }
}

impl std::error::Error for PiiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PiiError::RegexCompilation(e) => Some(e),
        }
    }
}

/// Classification of detected PII types.
///
/// Country-specific variants are prefixed with an ISO 3166-1 alpha-2 code
/// (e.g. `Us`, `Gb`, `Au`). Variants without a country prefix are
/// internationally applicable or not tied to a specific country.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiKind {
    Email,
    PhoneNumber,
    CreditCard,
    UsSsn,
    GbNino,
    Iban,
    PassportNumber,
    IpAddress,
    UsItin,
    CaSin,
    IePpsn,
    ZaId,
    MacAddress,
    GbDrivingLicence,
    Vin,
    AuTfn,
    NzIrdNumber,
    GbNhsNumber,
    AuMedicare,
    UsPassportNew,
    SwiftBic,
    UsEin,
    Imei,
    GbUtr,
    UsAbaRouting,
    GbSortCode,
    PreciseGeolocation,
    UsDriversLicense,
    UsAlienNumber,
    UsUscisReceiptNumber,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiiMatch {
    pub kind: PiiKind,
    pub start: usize,
    pub end: usize,
}
