//! The six openpii300k languages and the scanner each one is scored with.

use voidwall_pii::{Country, Language, PiiError, Scanner};

/// A language the openpii300k train files cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalLanguage {
    En,
    Nl,
    Fr,
    De,
    It,
    Es,
}

impl EvalLanguage {
    pub const ALL: [EvalLanguage; 6] = [
        EvalLanguage::En,
        EvalLanguage::Nl,
        EvalLanguage::Fr,
        EvalLanguage::De,
        EvalLanguage::It,
        EvalLanguage::Es,
    ];

    /// Accepts the code (`fr`) or the English name (`French`), in any case. The
    /// dataset's `language` field holds the name; `AI4P_LANG` may hold either.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|l| s == l.code() || s == l.name())
    }

    pub fn code(self) -> &'static str {
        match self {
            EvalLanguage::En => "en",
            EvalLanguage::Nl => "nl",
            EvalLanguage::Fr => "fr",
            EvalLanguage::De => "de",
            EvalLanguage::It => "it",
            EvalLanguage::Es => "es",
        }
    }

    fn name(self) -> &'static str {
        match self {
            EvalLanguage::En => "english",
            EvalLanguage::Nl => "dutch",
            EvalLanguage::Fr => "french",
            EvalLanguage::De => "german",
            EvalLanguage::It => "italian",
            EvalLanguage::Es => "spanish",
        }
    }

    /// Index into a per-language array.
    pub fn index(self) -> usize {
        self as usize
    }

    fn keyword_language(self) -> Language {
        match self {
            EvalLanguage::En => Language::En,
            EvalLanguage::Nl => Language::Nl,
            EvalLanguage::Fr => Language::Fr,
            EvalLanguage::De => Language::De,
            EvalLanguage::It => Language::It,
            EvalLanguage::Es => Language::Es,
        }
    }

    /// Every supported country that uses the language, plus `International`.
    pub fn countries(self) -> &'static [Country] {
        use Country::*;
        match self {
            EvalLanguage::En => &[International, Us, Gb, Au, Nz, Ca, Ie, Za],
            EvalLanguage::Fr => &[International, Fr, Ch, Ca],
            EvalLanguage::De => &[International, De, At, Ch],
            EvalLanguage::Nl => &[International, Nl],
            EvalLanguage::It => &[International, It, Ch],
            EvalLanguage::Es => &[International, Es],
        }
    }

    pub fn build_scanner(self) -> Result<Scanner, PiiError> {
        Scanner::builder()
            .languages([self.keyword_language()])
            .countries(self.countries().iter().copied())
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;
    use voidwall_pii::PiiKind;

    #[test_case("en", EvalLanguage::En)]
    #[test_case("English", EvalLanguage::En)]
    #[test_case("nl", EvalLanguage::Nl)]
    #[test_case("Dutch", EvalLanguage::Nl)]
    #[test_case("FR", EvalLanguage::Fr)]
    #[test_case("french", EvalLanguage::Fr)]
    #[test_case("de", EvalLanguage::De)]
    #[test_case("GERMAN", EvalLanguage::De)]
    #[test_case("it", EvalLanguage::It)]
    #[test_case("Italian", EvalLanguage::It)]
    #[test_case("es", EvalLanguage::Es)]
    #[test_case("Spanish", EvalLanguage::Es)]
    fn parse(s: &str, expect: EvalLanguage) {
        assert_eq!(EvalLanguage::parse(s), Some(expect));
    }

    #[test_case("pt")]
    #[test_case("Polish")]
    #[test_case("")]
    #[test_case("en_US.UTF-8")]
    fn parse_unsupported(s: &str) {
        assert_eq!(EvalLanguage::parse(s), None);
    }

    #[test]
    fn index_is_dense() {
        for (i, l) in EvalLanguage::ALL.into_iter().enumerate() {
            assert_eq!(l.index(), i);
        }
    }

    #[test]
    fn french_scanner_covers_fr_and_international_only() {
        let scanner = EvalLanguage::Fr.build_scanner().unwrap();
        let kinds = |input: &str| -> Vec<PiiKind> {
            scanner.mark_piis(input).iter().map(|m| m.kind).collect()
        };
        assert!(kinds("Téléphone: 06 12 34 56 78").contains(&PiiKind::FrPhoneNumber));
        assert!(kinds("Contact: user@example.com").contains(&PiiKind::Email));
        assert!(!kinds("SSN: 123-45-6789").contains(&PiiKind::UsSsn));
    }
}
