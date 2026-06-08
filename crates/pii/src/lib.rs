pub mod detector;
pub mod keyword_context_detector;
pub(crate) mod normalize;
pub mod overlap;
pub mod scanner;
pub mod user_detector;
pub(crate) mod validators;

pub mod hyperscan_detector;

pub use overlap::resolve_overlaps;
pub use scanner::{Scanner, ScannerBuilder};
pub use user_detector::UserPiiDefinition;

use std::collections::HashSet;
use std::sync::Arc;

/// Errors that can occur during PII scanner initialization.
#[derive(Debug)]
pub enum PiiError {
    /// A regular expression failed to compile.
    RegexCompilation(regex::Error),
    /// A Hyperscan/Vectorscan pattern failed to compile.
    HyperscanCompilation(String),
    /// Builder configuration is inconsistent (e.g. PII kinds unreachable from
    /// the selected countries, or countries that contribute no enabled PII kinds).
    InvalidConfiguration(String),
}

impl std::fmt::Display for PiiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PiiError::RegexCompilation(e) => write!(f, "regex compilation failed: {e}"),
            PiiError::HyperscanCompilation(e) => {
                write!(f, "hyperscan compilation failed: {e}")
            }
            PiiError::InvalidConfiguration(e) => {
                write!(f, "invalid scanner configuration: {e}")
            }
        }
    }
}

impl std::error::Error for PiiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PiiError::RegexCompilation(e) => Some(e),
            PiiError::HyperscanCompilation(_) | PiiError::InvalidConfiguration(_) => None,
        }
    }
}

/// Country scope for PII types.
///
/// Each PII variant maps to exactly one country (or `International` for
/// types that are not country-specific).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize)]
pub enum Country {
    International,
    Us,
    Gb,
    Au,
    Nz,
    Ca,
    Ie,
    Za,
    Fr,
    De,
    At,
    Ch,
    Nl,
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
            Country::Fr,
            Country::De,
            Country::At,
            Country::Ch,
            Country::Nl,
        ]
    }
}

/// Language for keyword-context patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize)]
pub enum Language {
    En,
    Fr,
    De,
    Nl,
}

impl Language {
    pub fn all() -> &'static [Language] {
        &[Language::En, Language::Fr, Language::De, Language::Nl]
    }
}

/// Classification of detected PII types.
///
/// Country-specific variants are prefixed with an ISO 3166-1 alpha-2 code
/// (e.g. `Us`, `Gb`, `Au`). Variants without a country prefix are
/// internationally applicable or not tied to a specific country.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize)]
pub enum PiiKind {
    Email,
    UsPhoneNumber,
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
    NzNhiNumber,
    NzDriverLicence,
    IeDriverNumber,
    ZaTaxReference,
    CaOhip,
    GbPhoneNumber,
    AuPhoneNumber,
    NzPhoneNumber,
    IePhoneNumber,
    ZaPhoneNumber,
    AwsAccessKey,
    GithubToken,
    AwsSecretKey,
    GbZaPassportNumber,
    AuPassportNumber,
    CaPassportNumber,
    NzPassportNumber,
    IePassportNumber,
    DateOfBirth,
    GbAddress,
    GbPostcode,
    CaPostalCode,
    BitcoinAddress,
    EthereumAddress,
    AuBankAccount,
    CaBankAccount,
    FrNir,
    FrSiret,
    FrSiren,
    FrPassportNumber,
    FrCni,
    FrDriversLicense,
    FrPhoneNumber,
    FrPostalCode,
    FrNif,
    FrChAddress,
    FrChBoitePostale,
    DeSteuerId,
    DePersonalausweis,
    DePassportNumber,
    DePhoneNumber,
    DePostalCode,
    AtSvnr,
    AtPhoneNumber,
    AtPostalCode,
    ChAhv,
    ChPhoneNumber,
    ChPostalCode,
    PersonName,
    DeAtChAddress,
    DeAtChPostfach,
    DePackstation,
    ZaDriversLicense,
    UsZaPostalCode,
    AuDriversLicense,
    AuAbn,
    IeEircode,
    NlBsn,
    NlBtw,
    NlPostalCode,
    NlPhoneNumber,
    NlPassportNumber,
    NlDriversLicense,
    InternationalPhoneNumber,
    /// Marker for user-defined PII. The per-entry label lives in
    /// `PiiMatch::user_label`.
    Custom,
}

impl PiiKind {
    /// Returns a human-readable label for this PII kind.
    pub const fn label(&self) -> &'static str {
        match self {
            PiiKind::Email => "EMAIL",
            PiiKind::UsPhoneNumber => "US_PHONE_NUMBER",
            PiiKind::CreditCard => "CREDIT_CARD",
            PiiKind::UsSsn => "US_SSN",
            PiiKind::GbNino => "GB_NINO",
            PiiKind::Iban => "IBAN",
            PiiKind::PassportNumber => "PASSPORT_NUMBER",
            PiiKind::IpAddress => "IP_ADDRESS",
            PiiKind::UsItin => "US_ITIN",
            PiiKind::CaSin => "CA_SIN",
            PiiKind::IePpsn => "IE_PPSN",
            PiiKind::ZaId => "ZA_ID",
            PiiKind::MacAddress => "MAC_ADDRESS",
            PiiKind::GbDrivingLicence => "GB_DRIVING_LICENCE",
            PiiKind::Vin => "VIN",
            PiiKind::AuTfn => "AU_TFN",
            PiiKind::NzIrdNumber => "NZ_IRD_NUMBER",
            PiiKind::GbNhsNumber => "GB_NHS_NUMBER",
            PiiKind::AuMedicare => "AU_MEDICARE",
            PiiKind::UsPassportNew => "US_PASSPORT_NEW",
            PiiKind::SwiftBic => "SWIFT_BIC",
            PiiKind::UsEin => "US_EIN",
            PiiKind::Imei => "IMEI",
            PiiKind::GbUtr => "GB_UTR",
            PiiKind::UsAbaRouting => "US_ABA_ROUTING",
            PiiKind::GbSortCode => "GB_SORT_CODE",
            PiiKind::PreciseGeolocation => "PRECISE_GEOLOCATION",
            PiiKind::UsDriversLicense => "US_DRIVERS_LICENSE",
            PiiKind::UsAlienNumber => "US_ALIEN_NUMBER",
            PiiKind::UsUscisReceiptNumber => "US_USCIS_RECEIPT_NUMBER",
            PiiKind::NzNhiNumber => "NZ_NHI_NUMBER",
            PiiKind::NzDriverLicence => "NZ_DRIVER_LICENCE",
            PiiKind::IeDriverNumber => "IE_DRIVER_NUMBER",
            PiiKind::ZaTaxReference => "ZA_TAX_REFERENCE",
            PiiKind::CaOhip => "CA_OHIP",
            PiiKind::GbPhoneNumber => "GB_PHONE_NUMBER",
            PiiKind::AuPhoneNumber => "AU_PHONE_NUMBER",
            PiiKind::NzPhoneNumber => "NZ_PHONE_NUMBER",
            PiiKind::IePhoneNumber => "IE_PHONE_NUMBER",
            PiiKind::ZaPhoneNumber => "ZA_PHONE_NUMBER",
            PiiKind::AwsAccessKey => "AWS_ACCESS_KEY",
            PiiKind::GithubToken => "GITHUB_TOKEN",
            PiiKind::AwsSecretKey => "AWS_SECRET_KEY",
            PiiKind::GbZaPassportNumber => "GB_ZA_PASSPORT_NUMBER",
            PiiKind::AuPassportNumber => "AU_PASSPORT_NUMBER",
            PiiKind::CaPassportNumber => "CA_PASSPORT_NUMBER",
            PiiKind::NzPassportNumber => "NZ_PASSPORT_NUMBER",
            PiiKind::IePassportNumber => "IE_PASSPORT_NUMBER",
            PiiKind::DateOfBirth => "DATE_OF_BIRTH",
            PiiKind::GbPostcode => "GB_POSTCODE",
            PiiKind::CaPostalCode => "CA_POSTAL_CODE",
            PiiKind::BitcoinAddress => "BITCOIN_ADDRESS",
            PiiKind::EthereumAddress => "ETHEREUM_ADDRESS",
            PiiKind::AuBankAccount => "AU_BANK_ACCOUNT",
            PiiKind::CaBankAccount => "CA_BANK_ACCOUNT",
            PiiKind::FrNir => "FR_NIR",
            PiiKind::FrSiret => "FR_SIRET",
            PiiKind::FrSiren => "FR_SIREN",
            PiiKind::FrPassportNumber => "FR_PASSPORT_NUMBER",
            PiiKind::FrCni => "FR_CNI",
            PiiKind::FrDriversLicense => "FR_DRIVERS_LICENSE",
            PiiKind::FrPhoneNumber => "FR_PHONE_NUMBER",
            PiiKind::FrPostalCode => "FR_POSTAL_CODE",
            PiiKind::FrNif => "FR_NIF",
            PiiKind::FrChAddress => "FR_CH_ADDRESS",
            PiiKind::FrChBoitePostale => "FR_CH_BOITE_CASE_POSTALE",
            PiiKind::DeSteuerId => "DE_STEUER_ID",
            PiiKind::DePersonalausweis => "DE_PERSONALAUSWEIS",
            PiiKind::DePassportNumber => "DE_PASSPORT_NUMBER",
            PiiKind::DePhoneNumber => "DE_PHONE_NUMBER",
            PiiKind::DePostalCode => "DE_POSTAL_CODE",
            PiiKind::AtSvnr => "AT_SVNR",
            PiiKind::AtPhoneNumber => "AT_PHONE_NUMBER",
            PiiKind::AtPostalCode => "AT_POSTAL_CODE",
            PiiKind::ChAhv => "CH_AHV",
            PiiKind::ChPhoneNumber => "CH_PHONE_NUMBER",
            PiiKind::ChPostalCode => "CH_POSTAL_CODE",
            PiiKind::PersonName => "PERSON_NAME",
            PiiKind::DeAtChAddress => "DE_AT_CH_ADDRESS",
            PiiKind::DeAtChPostfach => "DE_AT_CH_POSTFACH",
            PiiKind::DePackstation => "DE_PACKSTATION",
            PiiKind::GbAddress => "GB_ADDRESS",
            PiiKind::ZaDriversLicense => "ZA_DRIVERS_LICENSE",
            PiiKind::UsZaPostalCode => "US_ZA_POSTAL_CODE",
            PiiKind::AuDriversLicense => "AU_DRIVERS_LICENSE",
            PiiKind::AuAbn => "AU_ABN",
            PiiKind::IeEircode => "IE_EIRCODE",
            PiiKind::NlBsn => "NL_BSN",
            PiiKind::NlBtw => "NL_BTW",
            PiiKind::NlPostalCode => "NL_POSTAL_CODE",
            PiiKind::NlPhoneNumber => "NL_PHONE_NUMBER",
            PiiKind::NlPassportNumber => "NL_PASSPORT_NUMBER",
            PiiKind::NlDriversLicense => "NL_DRIVERS_LICENSE",
            PiiKind::InternationalPhoneNumber => "PHONE_NUMBER",
            PiiKind::Custom => "CUSTOM",
        }
    }

    pub const fn country(&self) -> Country {
        match self {
            PiiKind::Email
            | PiiKind::CreditCard
            | PiiKind::Iban
            | PiiKind::IpAddress
            | PiiKind::MacAddress
            | PiiKind::Vin
            | PiiKind::UsPhoneNumber
            | PiiKind::PassportNumber
            | PiiKind::SwiftBic
            | PiiKind::Imei
            | PiiKind::PreciseGeolocation
            | PiiKind::PersonName
            | PiiKind::InternationalPhoneNumber => Country::International,

            PiiKind::UsSsn
            | PiiKind::UsItin
            | PiiKind::UsPassportNew
            | PiiKind::UsEin
            | PiiKind::UsAbaRouting
            | PiiKind::UsDriversLicense
            | PiiKind::UsAlienNumber
            | PiiKind::UsUscisReceiptNumber
            | PiiKind::UsZaPostalCode => Country::Us,

            PiiKind::GbNino
            | PiiKind::GbDrivingLicence
            | PiiKind::GbNhsNumber
            | PiiKind::GbUtr
            | PiiKind::GbSortCode
            | PiiKind::GbPhoneNumber
            | PiiKind::GbZaPassportNumber
            | PiiKind::GbPostcode
            | PiiKind::GbAddress => Country::Gb,

            PiiKind::AuTfn
            | PiiKind::AuMedicare
            | PiiKind::AuPhoneNumber
            | PiiKind::AuPassportNumber
            | PiiKind::AuBankAccount
            | PiiKind::AuDriversLicense
            | PiiKind::AuAbn => Country::Au,

            PiiKind::NzIrdNumber
            | PiiKind::NzNhiNumber
            | PiiKind::NzDriverLicence
            | PiiKind::NzPhoneNumber
            | PiiKind::NzPassportNumber => Country::Nz,

            PiiKind::CaSin
            | PiiKind::CaOhip
            | PiiKind::CaPassportNumber
            | PiiKind::CaPostalCode
            | PiiKind::CaBankAccount => Country::Ca,

            PiiKind::IePpsn
            | PiiKind::IeDriverNumber
            | PiiKind::IePhoneNumber
            | PiiKind::IePassportNumber
            | PiiKind::IeEircode => Country::Ie,

            PiiKind::ZaId
            | PiiKind::ZaTaxReference
            | PiiKind::ZaPhoneNumber
            | PiiKind::ZaDriversLicense => Country::Za,

            PiiKind::FrNir
            | PiiKind::FrSiret
            | PiiKind::FrSiren
            | PiiKind::FrPassportNumber
            | PiiKind::FrCni
            | PiiKind::FrDriversLicense
            | PiiKind::FrPhoneNumber
            | PiiKind::FrPostalCode
            | PiiKind::FrNif
            | PiiKind::FrChAddress
            | PiiKind::FrChBoitePostale => Country::Fr,

            PiiKind::DeSteuerId
            | PiiKind::DePersonalausweis
            | PiiKind::DePassportNumber
            | PiiKind::DePhoneNumber
            | PiiKind::DePostalCode
            | PiiKind::DeAtChAddress
            | PiiKind::DeAtChPostfach
            | PiiKind::DePackstation => Country::De,

            PiiKind::AtSvnr | PiiKind::AtPhoneNumber | PiiKind::AtPostalCode => Country::At,

            PiiKind::ChAhv | PiiKind::ChPhoneNumber | PiiKind::ChPostalCode => Country::Ch,

            PiiKind::NlBsn
            | PiiKind::NlBtw
            | PiiKind::NlPostalCode
            | PiiKind::NlPhoneNumber
            | PiiKind::NlPassportNumber
            | PiiKind::NlDriversLicense => Country::Nl,

            PiiKind::AwsAccessKey
            | PiiKind::GithubToken
            | PiiKind::AwsSecretKey
            | PiiKind::DateOfBirth
            | PiiKind::BitcoinAddress
            | PiiKind::EthereumAddress
            | PiiKind::Custom => Country::International,
        }
    }

    /// Returns all `PiiKind` variants (built-in and the `Custom` marker).
    pub fn all() -> &'static [PiiKind] {
        Self::ALL
    }

    const ALL: &[PiiKind] = &[
        PiiKind::Email,
        PiiKind::UsPhoneNumber,
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
        PiiKind::NzNhiNumber,
        PiiKind::NzDriverLicence,
        PiiKind::IeDriverNumber,
        PiiKind::ZaTaxReference,
        PiiKind::CaOhip,
        PiiKind::GbPhoneNumber,
        PiiKind::AuPhoneNumber,
        PiiKind::NzPhoneNumber,
        PiiKind::IePhoneNumber,
        PiiKind::ZaPhoneNumber,
        PiiKind::AwsAccessKey,
        PiiKind::GithubToken,
        PiiKind::AwsSecretKey,
        PiiKind::GbZaPassportNumber,
        PiiKind::AuPassportNumber,
        PiiKind::CaPassportNumber,
        PiiKind::NzPassportNumber,
        PiiKind::IePassportNumber,
        PiiKind::DateOfBirth,
        PiiKind::GbPostcode,
        PiiKind::CaPostalCode,
        PiiKind::BitcoinAddress,
        PiiKind::EthereumAddress,
        PiiKind::AuBankAccount,
        PiiKind::CaBankAccount,
        PiiKind::FrNir,
        PiiKind::FrSiret,
        PiiKind::FrSiren,
        PiiKind::FrPassportNumber,
        PiiKind::FrCni,
        PiiKind::FrDriversLicense,
        PiiKind::FrPhoneNumber,
        PiiKind::FrPostalCode,
        PiiKind::FrNif,
        PiiKind::FrChAddress,
        PiiKind::FrChBoitePostale,
        PiiKind::DeSteuerId,
        PiiKind::DePersonalausweis,
        PiiKind::DePassportNumber,
        PiiKind::DePhoneNumber,
        PiiKind::DePostalCode,
        PiiKind::AtSvnr,
        PiiKind::AtPhoneNumber,
        PiiKind::AtPostalCode,
        PiiKind::ChAhv,
        PiiKind::ChPhoneNumber,
        PiiKind::ChPostalCode,
        PiiKind::PersonName,
        PiiKind::DeAtChAddress,
        PiiKind::DeAtChPostfach,
        PiiKind::DePackstation,
        PiiKind::ZaDriversLicense,
        PiiKind::UsZaPostalCode,
        PiiKind::AuDriversLicense,
        PiiKind::AuAbn,
        PiiKind::IeEircode,
        PiiKind::NlBsn,
        PiiKind::NlBtw,
        PiiKind::NlPostalCode,
        PiiKind::NlPhoneNumber,
        PiiKind::NlPassportNumber,
        PiiKind::NlDriversLicense,
        PiiKind::GbAddress,
        PiiKind::InternationalPhoneNumber,
    ];

    /// Returns all countries this PII kind applies to.
    ///
    /// Most variants map to a single country, but combined variants like
    /// `DeAtAddress` apply to multiple countries.
    pub const fn applicable_countries(&self) -> &'static [Country] {
        match self {
            PiiKind::DeAtChAddress | PiiKind::DeAtChPostfach => {
                &[Country::De, Country::At, Country::Ch]
            }
            PiiKind::FrChAddress | PiiKind::FrChBoitePostale => &[Country::Fr, Country::Ch],
            PiiKind::GbZaPassportNumber => &[Country::Gb, Country::Za],
            PiiKind::UsZaPostalCode => &[Country::Us, Country::Za],
            _ => match self.country() {
                Country::International => &[Country::International],
                Country::Us => &[Country::Us],
                Country::Gb => &[Country::Gb],
                Country::Au => &[Country::Au],
                Country::Nz => &[Country::Nz],
                Country::Ca => &[Country::Ca],
                Country::Ie => &[Country::Ie],
                Country::Za => &[Country::Za],
                Country::Fr => &[Country::Fr],
                Country::De => &[Country::De],
                Country::At => &[Country::At],
                Country::Ch => &[Country::Ch],
                Country::Nl => &[Country::Nl],
            },
        }
    }

    /// Returns the set of `PiiKind` variants belonging to the given countries.
    pub(crate) fn enabled_for_countries(countries: &HashSet<Country>) -> HashSet<PiiKind> {
        PiiKind::ALL
            .iter()
            .copied()
            .filter(|k| {
                k.applicable_countries()
                    .iter()
                    .any(|c| countries.contains(c))
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiiMatch {
    pub kind: PiiKind,
    pub start: usize,
    pub end: usize,
    /// Label for user-defined PII entries. `None` for built-in kinds; for
    /// those, use `kind.label()`.
    pub user_label: Option<Arc<str>>,
}

/// A piece of structured input passed to `mark_piis_structured`.
///
/// `context` is the key path the value lives under (e.g. `user.phone_number`,
/// `phones[0]`, or a CSV column name). `value` is the raw text to scan.
/// `offset` is the byte position of `value` in the original document; returned
/// `PiiMatch` spans are document-absolute, so callers can use them directly
/// against the original bytes.
#[derive(Debug, Clone, Copy)]
pub struct ContextFragment<'a> {
    pub context: &'a str,
    pub value: &'a str,
    pub offset: usize,
}

impl PiiMatch {
    /// Returns the label for this match — the user-supplied label for
    /// `PiiKind::Custom`, otherwise the built-in label from `kind`.
    pub fn label(&self) -> &str {
        self.user_label
            .as_deref()
            .unwrap_or_else(|| self.kind.label())
    }
}
