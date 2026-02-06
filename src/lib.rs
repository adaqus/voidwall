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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiiMatch {
    pub kind: PiiKind,
    pub start: usize,
    pub end: usize,
}
