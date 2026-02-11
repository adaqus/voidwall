pub mod detector;
pub mod keyword_context_detector;
pub mod regex_detector;
pub mod scanner;

pub use scanner::{ChunkedScanner, Scanner, ScannerBuilder};

use std::collections::HashSet;

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

/// Country scope for PII types.
///
/// Each PII variant maps to exactly one country (or `International` for
/// types that are not country-specific).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Country {
    International,
    Us,
    Gb,
    Au,
    Nz,
    Ca,
    Ie,
    Za,
}

impl Country {
    pub fn all() -> &'static [Country] {
        &[
            Country::International,
            Country::Us,
            Country::Gb,
            Country::Au,
            Country::Nz,
            Country::Ca,
            Country::Ie,
            Country::Za,
        ]
    }
}

/// Language for keyword-context patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    En,
}

impl Language {
    pub fn all() -> &'static [Language] {
        &[Language::En]
    }
}

/// Classification of detected PII types.
///
/// Country-specific variants are prefixed with an ISO 3166-1 alpha-2 code
/// (e.g. `Us`, `Gb`, `Au`). Variants without a country prefix are
/// internationally applicable or not tied to a specific country.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

impl PiiKind {
    pub const fn country(&self) -> Country {
        match self {
            PiiKind::Email
            | PiiKind::CreditCard
            | PiiKind::Iban
            | PiiKind::IpAddress
            | PiiKind::MacAddress
            | PiiKind::Vin
            | PiiKind::PhoneNumber
            | PiiKind::PassportNumber
            | PiiKind::SwiftBic
            | PiiKind::Imei
            | PiiKind::PreciseGeolocation => Country::International,

            PiiKind::UsSsn
            | PiiKind::UsItin
            | PiiKind::UsPassportNew
            | PiiKind::UsEin
            | PiiKind::UsAbaRouting
            | PiiKind::UsDriversLicense
            | PiiKind::UsAlienNumber
            | PiiKind::UsUscisReceiptNumber => Country::Us,

            PiiKind::GbNino
            | PiiKind::GbDrivingLicence
            | PiiKind::GbNhsNumber
            | PiiKind::GbUtr
            | PiiKind::GbSortCode => Country::Gb,

            PiiKind::AuTfn | PiiKind::AuMedicare => Country::Au,

            PiiKind::NzIrdNumber => Country::Nz,

            PiiKind::CaSin => Country::Ca,

            PiiKind::IePpsn => Country::Ie,

            PiiKind::ZaId => Country::Za,
        }
    }

    const ALL: &[PiiKind] = &[
        PiiKind::Email,
        PiiKind::PhoneNumber,
        PiiKind::CreditCard,
        PiiKind::UsSsn,
        PiiKind::GbNino,
        PiiKind::Iban,
        PiiKind::PassportNumber,
        PiiKind::IpAddress,
        PiiKind::UsItin,
        PiiKind::CaSin,
        PiiKind::IePpsn,
        PiiKind::ZaId,
        PiiKind::MacAddress,
        PiiKind::GbDrivingLicence,
        PiiKind::Vin,
        PiiKind::AuTfn,
        PiiKind::NzIrdNumber,
        PiiKind::GbNhsNumber,
        PiiKind::AuMedicare,
        PiiKind::UsPassportNew,
        PiiKind::SwiftBic,
        PiiKind::UsEin,
        PiiKind::Imei,
        PiiKind::GbUtr,
        PiiKind::UsAbaRouting,
        PiiKind::GbSortCode,
        PiiKind::PreciseGeolocation,
        PiiKind::UsDriversLicense,
        PiiKind::UsAlienNumber,
        PiiKind::UsUscisReceiptNumber,
    ];

    /// Returns the set of `PiiKind` variants belonging to the given countries.
    pub(crate) fn enabled_for_countries(countries: &HashSet<Country>) -> HashSet<PiiKind> {
        PiiKind::ALL
            .iter()
            .copied()
            .filter(|k| countries.contains(&k.country()))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiiMatch {
    pub kind: PiiKind,
    pub start: usize,
    pub end: usize,
}
