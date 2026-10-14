//! AI4Privacy openpii300k labels and their mapping to `PiiKind`.

use voidwall_pii::PiiKind;

/// One label of the openpii300k vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ai4pLabel {
    Bod,
    Building,
    CardIssuer,
    City,
    Country,
    Date,
    DriverLicense,
    Email,
    GeoCoord,
    GivenName1,
    GivenName2,
    IdCard,
    Ip,
    LastName1,
    LastName2,
    LastName3,
    Pass,
    Passport,
    Postcode,
    SecAddress,
    Sex,
    SocialNumber,
    State,
    Street,
    Tel,
    Time,
    Title,
    Username,
}

impl Ai4pLabel {
    pub const ALL: &[Ai4pLabel] = &[
        Ai4pLabel::Bod,
        Ai4pLabel::Building,
        Ai4pLabel::CardIssuer,
        Ai4pLabel::City,
        Ai4pLabel::Country,
        Ai4pLabel::Date,
        Ai4pLabel::DriverLicense,
        Ai4pLabel::Email,
        Ai4pLabel::GeoCoord,
        Ai4pLabel::GivenName1,
        Ai4pLabel::GivenName2,
        Ai4pLabel::IdCard,
        Ai4pLabel::Ip,
        Ai4pLabel::LastName1,
        Ai4pLabel::LastName2,
        Ai4pLabel::LastName3,
        Ai4pLabel::Pass,
        Ai4pLabel::Passport,
        Ai4pLabel::Postcode,
        Ai4pLabel::SecAddress,
        Ai4pLabel::Sex,
        Ai4pLabel::SocialNumber,
        Ai4pLabel::State,
        Ai4pLabel::Street,
        Ai4pLabel::Tel,
        Ai4pLabel::Time,
        Ai4pLabel::Title,
        Ai4pLabel::Username,
    ];

    /// The label as the dataset writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            Ai4pLabel::Bod => "BOD",
            Ai4pLabel::Building => "BUILDING",
            Ai4pLabel::CardIssuer => "CARDISSUER",
            Ai4pLabel::City => "CITY",
            Ai4pLabel::Country => "COUNTRY",
            Ai4pLabel::Date => "DATE",
            Ai4pLabel::DriverLicense => "DRIVERLICENSE",
            Ai4pLabel::Email => "EMAIL",
            Ai4pLabel::GeoCoord => "GEOCOORD",
            Ai4pLabel::GivenName1 => "GIVENNAME1",
            Ai4pLabel::GivenName2 => "GIVENNAME2",
            Ai4pLabel::IdCard => "IDCARD",
            Ai4pLabel::Ip => "IP",
            Ai4pLabel::LastName1 => "LASTNAME1",
            Ai4pLabel::LastName2 => "LASTNAME2",
            Ai4pLabel::LastName3 => "LASTNAME3",
            Ai4pLabel::Pass => "PASS",
            Ai4pLabel::Passport => "PASSPORT",
            Ai4pLabel::Postcode => "POSTCODE",
            Ai4pLabel::SecAddress => "SECADDRESS",
            Ai4pLabel::Sex => "SEX",
            Ai4pLabel::SocialNumber => "SOCIALNUMBER",
            Ai4pLabel::State => "STATE",
            Ai4pLabel::Street => "STREET",
            Ai4pLabel::Tel => "TEL",
            Ai4pLabel::Time => "TIME",
            Ai4pLabel::Title => "TITLE",
            Ai4pLabel::Username => "USERNAME",
        }
    }

    /// A label is supported when at least one `PiiKind` maps to it.
    pub fn is_supported(self) -> bool {
        PiiKind::all()
            .iter()
            .any(|k| labels_for(*k).contains(&self))
    }
}

/// A dataset label: one the vocabulary knows, or one it does not.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Label {
    Known(Ai4pLabel),
    Unknown(Box<str>),
}

impl Label {
    pub fn parse(s: &str) -> Self {
        Ai4pLabel::ALL
            .iter()
            .copied()
            .find(|l| l.as_str() == s)
            .map_or_else(|| Label::Unknown(s.into()), Label::Known)
    }

    pub fn as_str(&self) -> &str {
        match self {
            Label::Known(l) => l.as_str(),
            Label::Unknown(s) => s,
        }
    }

    pub fn is_supported(&self) -> bool {
        matches!(self, Label::Known(l) if l.is_supported())
    }

    /// Whether a prediction of `kind` is the right kind for this label.
    pub fn accepts(&self, kind: PiiKind) -> bool {
        matches!(self, Label::Known(l) if labels_for(kind).contains(l))
    }
}

const NAMES: &[Ai4pLabel] = &[
    Ai4pLabel::GivenName1,
    Ai4pLabel::GivenName2,
    Ai4pLabel::LastName1,
    Ai4pLabel::LastName2,
    Ai4pLabel::LastName3,
];
const ADDRESS: &[Ai4pLabel] = &[Ai4pLabel::Street, Ai4pLabel::SecAddress];
const ID_AND_SOCIAL: &[Ai4pLabel] = &[Ai4pLabel::IdCard, Ai4pLabel::SocialNumber];

/// The labels a prediction of `kind` counts as the right kind for.
///
/// No wildcard arm: a new `PiiKind` does not compile until it is mapped here,
/// or mapped to no label.
pub fn labels_for(kind: PiiKind) -> &'static [Ai4pLabel] {
    match kind {
        PiiKind::Email => &[Ai4pLabel::Email],
        PiiKind::IpAddress => &[Ai4pLabel::Ip],
        PiiKind::PreciseGeolocation => &[Ai4pLabel::GeoCoord],
        PiiKind::DateOfBirth => &[Ai4pLabel::Bod],
        PiiKind::PersonName => NAMES,

        PiiKind::InternationalPhoneNumber
        | PiiKind::UsPhoneNumber
        | PiiKind::GbPhoneNumber
        | PiiKind::AuPhoneNumber
        | PiiKind::NzPhoneNumber
        | PiiKind::IePhoneNumber
        | PiiKind::ZaPhoneNumber
        | PiiKind::FrPhoneNumber
        | PiiKind::DePhoneNumber
        | PiiKind::AtPhoneNumber
        | PiiKind::ChPhoneNumber
        | PiiKind::NlPhoneNumber
        | PiiKind::ItPhoneNumber
        | PiiKind::EsPhoneNumber
        | PiiKind::PlPhoneNumber => &[Ai4pLabel::Tel],

        PiiKind::GbPostcode
        | PiiKind::IeEircode
        | PiiKind::CaPostalCode
        | PiiKind::UsZaPostalCode
        | PiiKind::FrPostalCode
        | PiiKind::DePostalCode
        | PiiKind::AtPostalCode
        | PiiKind::ChPostalCode
        | PiiKind::NlPostalCode
        | PiiKind::ItPostalCode
        | PiiKind::EsPostalCode
        | PiiKind::PlPostalCode => &[Ai4pLabel::Postcode],

        PiiKind::UsGbCaAuNzIeZaStreet => &[Ai4pLabel::Street],
        PiiKind::SecondaryAddress => &[Ai4pLabel::SecAddress],
        PiiKind::GbAddress | PiiKind::DeAtChAddress | PiiKind::FrChAddress => ADDRESS,

        PiiKind::PassportNumber
        | PiiKind::UsPassportNew
        | PiiKind::GbZaPassportNumber
        | PiiKind::AuPassportNumber
        | PiiKind::CaPassportNumber
        | PiiKind::NzPassportNumber
        | PiiKind::IePassportNumber
        | PiiKind::FrPassportNumber
        | PiiKind::DePassportNumber
        | PiiKind::NlPassportNumber
        | PiiKind::ItPassportNumber
        | PiiKind::EsPassportNumber
        | PiiKind::PlPassportNumber => &[Ai4pLabel::Passport],

        PiiKind::UsDriversLicense
        | PiiKind::GbDrivingLicence
        | PiiKind::NzDriverLicence
        | PiiKind::IeDriverNumber
        | PiiKind::CaDriversLicense
        | PiiKind::ZaDriversLicense
        | PiiKind::AuDriversLicense
        | PiiKind::FrDriversLicense
        | PiiKind::NlDriversLicense
        | PiiKind::ItDriversLicense
        | PiiKind::PlDriversLicense => &[Ai4pLabel::DriverLicense],

        PiiKind::PlIdCard
        | PiiKind::DePersonalausweis
        | PiiKind::EsDni
        | PiiKind::EsNie
        | PiiKind::FrCni => &[Ai4pLabel::IdCard],
        PiiKind::ItCodiceFiscale | PiiKind::ZaId | PiiKind::NlBsn => ID_AND_SOCIAL,

        PiiKind::UsSsn
        | PiiKind::UsItin
        | PiiKind::GbNino
        | PiiKind::CaSin
        | PiiKind::IePpsn
        | PiiKind::AuTfn
        | PiiKind::FrNir
        | PiiKind::EsNuss
        | PiiKind::PlPesel
        | PiiKind::ChAhv
        | PiiKind::AtSvnr
        | PiiKind::NzIrdNumber => &[Ai4pLabel::SocialNumber],

        PiiKind::CreditCard
        | PiiKind::Iban
        | PiiKind::MacAddress
        | PiiKind::Vin
        | PiiKind::GbNhsNumber
        | PiiKind::AuMedicare
        | PiiKind::SwiftBic
        | PiiKind::UsEin
        | PiiKind::Imei
        | PiiKind::GbUtr
        | PiiKind::UsAbaRouting
        | PiiKind::GbSortCode
        | PiiKind::UsAlienNumber
        | PiiKind::UsUscisReceiptNumber
        | PiiKind::NzNhiNumber
        | PiiKind::ZaTaxReference
        | PiiKind::CaOhip
        | PiiKind::AwsAccessKey
        | PiiKind::GithubToken
        | PiiKind::AwsSecretKey
        | PiiKind::BitcoinAddress
        | PiiKind::EthereumAddress
        | PiiKind::AuBankAccount
        | PiiKind::CaBankAccount
        | PiiKind::FrSiret
        | PiiKind::FrSiren
        | PiiKind::FrNif
        | PiiKind::FrChBoitePostale
        | PiiKind::DeSteuerId
        | PiiKind::DeAtChPostfach
        | PiiKind::DePackstation
        | PiiKind::AuAbn
        | PiiKind::NlBtw
        | PiiKind::ItPartitaIva
        | PiiKind::EsCif
        | PiiKind::PlNip
        | PiiKind::PlRegon
        | PiiKind::Custom => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test]
    fn every_label_parses_back() {
        for l in Ai4pLabel::ALL {
            assert_eq!(Label::parse(l.as_str()), Label::Known(*l));
        }
        assert_eq!(Ai4pLabel::ALL.len(), 28);
    }

    #[test_case("EMAIL", Label::Known(Ai4pLabel::Email))]
    #[test_case("CARDISSUER", Label::Known(Ai4pLabel::CardIssuer))]
    #[test_case("NEWLABEL", Label::Unknown("NEWLABEL".into()))]
    #[test_case("email", Label::Unknown("email".into()); "lowercase is not the vocabulary")]
    fn parse(s: &str, expect: Label) {
        assert_eq!(Label::parse(s), expect);
    }

    #[test_case(Ai4pLabel::Email, PiiKind::Email)]
    #[test_case(Ai4pLabel::Ip, PiiKind::IpAddress)]
    #[test_case(Ai4pLabel::GeoCoord, PiiKind::PreciseGeolocation)]
    #[test_case(Ai4pLabel::Bod, PiiKind::DateOfBirth)]
    #[test_case(Ai4pLabel::GivenName1, PiiKind::PersonName)]
    #[test_case(Ai4pLabel::LastName3, PiiKind::PersonName)]
    #[test_case(Ai4pLabel::Tel, PiiKind::InternationalPhoneNumber)]
    #[test_case(Ai4pLabel::Tel, PiiKind::FrPhoneNumber)]
    #[test_case(Ai4pLabel::Postcode, PiiKind::GbPostcode)]
    #[test_case(Ai4pLabel::Postcode, PiiKind::IeEircode)]
    #[test_case(Ai4pLabel::Postcode, PiiKind::UsZaPostalCode)]
    #[test_case(Ai4pLabel::Street, PiiKind::UsGbCaAuNzIeZaStreet)]
    #[test_case(Ai4pLabel::Street, PiiKind::GbAddress)]
    #[test_case(Ai4pLabel::SecAddress, PiiKind::GbAddress)]
    #[test_case(Ai4pLabel::SecAddress, PiiKind::SecondaryAddress)]
    #[test_case(Ai4pLabel::Passport, PiiKind::UsPassportNew)]
    #[test_case(Ai4pLabel::Passport, PiiKind::GbZaPassportNumber)]
    #[test_case(Ai4pLabel::DriverLicense, PiiKind::GbDrivingLicence)]
    #[test_case(Ai4pLabel::DriverLicense, PiiKind::IeDriverNumber)]
    #[test_case(Ai4pLabel::IdCard, PiiKind::NlBsn)]
    #[test_case(Ai4pLabel::SocialNumber, PiiKind::NlBsn)]
    #[test_case(Ai4pLabel::IdCard, PiiKind::ZaId)]
    #[test_case(Ai4pLabel::SocialNumber, PiiKind::ZaId)]
    #[test_case(Ai4pLabel::IdCard, PiiKind::ItCodiceFiscale)]
    #[test_case(Ai4pLabel::SocialNumber, PiiKind::ItCodiceFiscale)]
    #[test_case(Ai4pLabel::SocialNumber, PiiKind::UsSsn)]
    fn accepts(label: Ai4pLabel, kind: PiiKind) {
        assert!(Label::Known(label).accepts(kind));
    }

    #[test_case(Ai4pLabel::Tel, PiiKind::Email)]
    #[test_case(Ai4pLabel::Street, PiiKind::SecondaryAddress)]
    #[test_case(Ai4pLabel::IdCard, PiiKind::UsSsn)]
    #[test_case(Ai4pLabel::Postcode, PiiKind::DeAtChPostfach)]
    fn rejects(label: Ai4pLabel, kind: PiiKind) {
        assert!(!Label::Known(label).accepts(kind));
    }

    #[test]
    fn unknown_label_accepts_nothing() {
        let l = Label::Unknown("X".into());
        assert!(PiiKind::all().iter().all(|k| !l.accepts(*k)));
        assert!(!l.is_supported());
    }

    #[test]
    fn supported_and_unsupported_sets_match_the_spec() {
        use Ai4pLabel::*;
        let supported: Vec<Ai4pLabel> = Ai4pLabel::ALL
            .iter()
            .copied()
            .filter(|l| l.is_supported())
            .collect();
        let unsupported: Vec<Ai4pLabel> = Ai4pLabel::ALL
            .iter()
            .copied()
            .filter(|l| !l.is_supported())
            .collect();
        let mut expect_supported = vec![
            Email,
            Ip,
            GeoCoord,
            Bod,
            GivenName1,
            GivenName2,
            LastName1,
            LastName2,
            LastName3,
            Tel,
            Postcode,
            Street,
            SecAddress,
            Passport,
            DriverLicense,
            IdCard,
            SocialNumber,
        ];
        let mut expect_unsupported = vec![
            Pass, Title, CardIssuer, Country, City, State, Sex, Date, Time, Username, Building,
        ];
        expect_supported.sort();
        expect_unsupported.sort();
        assert_eq!(supported, expect_supported);
        assert_eq!(unsupported, expect_unsupported);
    }
}
