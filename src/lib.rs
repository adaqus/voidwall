pub mod detector;
pub mod regex_detector;
pub mod scanner;

pub use scanner::Scanner;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiKind {
    Email,
    PhoneNumber,
    CreditCard,
    Ssn,
    Nino,
    Iban,
    PassportNumber,
    IpAddress,
    Itin,
    Sin,
    Ppsn,
    SouthAfricaId,
    MacAddress,
    UkDrivingLicence,
    Vin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiiMatch {
    pub kind: PiiKind,
    pub start: usize,
    pub end: usize,
}
