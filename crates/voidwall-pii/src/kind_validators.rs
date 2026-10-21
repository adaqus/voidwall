//! Validation by kind: the checks of every pattern of a kind, reachable
//! without a scanner. A model guard checks a span it found against the kinds
//! an operator named.
//!
//! The table is read from the pattern tables the detectors compile, so a
//! pattern added to either detector is covered with no extra step.

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::validators::Check;
use crate::{PiiKind, hyperscan_detector, keyword_context_detector};

/// The checks of one kind's patterns.
#[derive(Default)]
struct KindChecks {
    /// Some pattern of the kind is `Check::Any`: its expression alone decides.
    any: bool,
    /// The function of each `Check::With` pattern. A function shared by two
    /// patterns is listed twice; that costs a call, never a different answer.
    functions: Vec<fn(&str) -> bool>,
}

/// Each kind's checks, built once.
static KIND_CHECKS: LazyLock<HashMap<PiiKind, KindChecks>> = LazyLock::new(|| {
    let mut table: HashMap<PiiKind, KindChecks> = HashMap::new();
    for (kind, check) in all_pattern_checks() {
        let checks = table.entry(kind).or_default();
        match check {
            Check::Any => checks.any = true,
            Check::With(function) => checks.functions.push(function),
        }
    }
    table
});

fn all_pattern_checks() -> impl Iterator<Item = (PiiKind, Check)> {
    hyperscan_detector::pattern_checks().chain(keyword_context_detector::pattern_checks())
}

/// Returns true when the check of any pattern of any of `kinds` accepts
/// `text`. The text is checked exactly as given. An empty `kinds` returns false.
pub fn validate_as(kinds: &[PiiKind], text: &str) -> bool {
    kinds.iter().any(|kind| {
        KIND_CHECKS.get(kind).is_some_and(|checks| {
            checks.any || checks.functions.iter().any(|function| function(text))
        })
    })
}

/// Returns true when some pattern of `kind` checks more than its expression,
/// that is, has a check that does not accept every value. A kind with no
/// pattern has none.
pub fn has_validator(kind: PiiKind) -> bool {
    KIND_CHECKS
        .get(&kind)
        .is_some_and(|checks| !checks.functions.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    // Placeholder card numbers: the first is the common Luhn-valid test
    // number, the second differs in its check digit.
    const CARD_LUHN_VALID: &str = "4111 1111 1111 1111";
    const CARD_LUHN_INVALID: &str = "4111 1111 1111 1112";

    #[test]
    fn every_kind_with_a_pattern_has_an_entry() {
        let missing: Vec<&str> = all_pattern_checks()
            .map(|(kind, _)| kind)
            .filter(|kind| !KIND_CHECKS.contains_key(kind))
            .map(|kind| kind.label())
            .collect();
        assert!(missing.is_empty(), "kinds without an entry: {missing:?}");
    }

    /// `UsDriversLicense` has two patterns with different checks: one takes
    /// a letter prefix, the other digits only. Each value passes one of them.
    #[test_case("AB1234" ; "letter prefix check")]
    #[test_case("123456" ; "numeric check")]
    fn a_kind_holds_the_check_of_each_of_its_patterns(text: &str) {
        assert!(validate_as(&[PiiKind::UsDriversLicense], text));
    }

    /// A function that accepts every probe is `Check::Any` in disguise.
    /// Probes are short odd strings that no real check accepts all of.
    #[test]
    fn every_check_function_rejects_some_probe() {
        let probes = ["", "x", "a.b", "0", "-"];
        for (kind, checks) in KIND_CHECKS.iter() {
            for function in &checks.functions {
                assert!(
                    probes.iter().any(|probe| !function(probe)),
                    "a check of {} accepts every probe; use Check::Any",
                    kind.label()
                );
            }
        }
    }

    #[test_case(&[PiiKind::CreditCard], CARD_LUHN_VALID, true ; "luhn valid card passes")]
    #[test_case(&[PiiKind::CreditCard], CARD_LUHN_INVALID, false ; "luhn failing card fails")]
    #[test_case(&[PiiKind::UsSsn], CARD_LUHN_VALID, false ; "first kind alone rejects")]
    #[test_case(&[PiiKind::UsSsn, PiiKind::CreditCard], CARD_LUHN_VALID, true ; "second kind accepts")]
    #[test_case(&[PiiKind::IpAddress], "x", true ; "kind with an expression only pattern accepts any text")]
    #[test_case(&[], CARD_LUHN_VALID, false ; "empty list")]
    #[test_case(&[PiiKind::Custom], CARD_LUHN_VALID, false ; "kind with no pattern")]
    fn validate_as_cases(kinds: &[PiiKind], text: &str, expected: bool) {
        assert_eq!(validate_as(kinds, text), expected);
    }

    #[test_case(PiiKind::CreditCard, true ; "credit card")]
    #[test_case(PiiKind::IpAddress, true ; "ip address")]
    #[test_case(PiiKind::Email, false ; "email accepts all")]
    #[test_case(PiiKind::UsPhoneNumber, false ; "phone accepts all")]
    #[test_case(PiiKind::Custom, false ; "no pattern")]
    fn has_validator_cases(kind: PiiKind, expected: bool) {
        assert_eq!(has_validator(kind), expected);
    }

    /// Recomputed from the raw pattern tables, not from the cached map.
    #[test]
    fn has_validator_matches_the_pattern_tables_for_every_kind() {
        for kind in PiiKind::all() {
            let expected = all_pattern_checks()
                .any(|(k, check)| k == *kind && matches!(check, Check::With(_)));
            assert_eq!(has_validator(*kind), expected, "{}", kind.label());
        }
    }
}
