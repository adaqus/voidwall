//! Overlap resolution for raw PII matches.
//!
//! See `CLAUDE.md` § "Overlap resolution" for the policy. The rules, in order:
//!
//! 1. Same span, same kind → dedupe.
//! 2. Span A strictly contains span B → drop B.
//! 3. Spans equal, kinds differ → keep higher-priority kind per `PRIORITY_GROUPS`.
//! 4. Partial overlap, neither contained → keep longer; tie-break by priority,
//!    then by `PiiKind` discriminant order.

use log::debug;

use crate::{PiiKind, PiiMatch};

/// Priority groups. Within each group, earlier index wins. Across groups,
/// no precedence is asserted — different families shouldn't produce
/// equal-span matches.
const PRIORITY_GROUPS: &[&[PiiKind]] = &[
    // Phone: country-scoped beats international.
    &[
        PiiKind::UsPhoneNumber,
        PiiKind::GbPhoneNumber,
        PiiKind::AuPhoneNumber,
        PiiKind::NzPhoneNumber,
        PiiKind::IePhoneNumber,
        PiiKind::ZaPhoneNumber,
        PiiKind::FrPhoneNumber,
        PiiKind::DePhoneNumber,
        PiiKind::AtPhoneNumber,
        PiiKind::ChPhoneNumber,
        PiiKind::InternationalPhoneNumber,
    ],
    // Passport: country-scoped beats generic.
    &[
        PiiKind::GbZaPassportNumber,
        PiiKind::AuPassportNumber,
        PiiKind::CaPassportNumber,
        PiiKind::NzPassportNumber,
        PiiKind::IePassportNumber,
        PiiKind::FrPassportNumber,
        PiiKind::DePassportNumber,
        PiiKind::PassportNumber,
    ],
];

/// Returns the priority rank of `kind` (lower = higher priority), or `None`
/// if the kind is not in any priority group.
fn priority_rank(kind: PiiKind) -> Option<(usize, usize)> {
    for (group_idx, group) in PRIORITY_GROUPS.iter().enumerate() {
        if let Some(pos) = group.iter().position(|&k| k == kind) {
            return Some((group_idx, pos));
        }
    }
    None
}

/// Compares two kinds by priority. Returns `Ordering::Less` when `a` should
/// win (be kept). Falls back to `PiiKind` discriminant order so the result
/// is deterministic even when no priority entry exists.
fn cmp_priority(a: PiiKind, b: PiiKind) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (priority_rank(a), priority_rank(b)) {
        (Some((g1, p1)), Some((g2, p2))) if g1 == g2 => p1.cmp(&p2),
        // If only one is in a group, the listed one wins. Cross-group matches
        // shouldn't occur in practice; we don't assert precedence either way.
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        // Neither in a group, or different groups: stable tie-break on
        // discriminant order.
        _ => (a as u32).cmp(&(b as u32)),
    }
}

/// Returns `true` if `a` should be kept and `b` dropped.
/// Caller must have verified that `a` and `b` overlap.
fn a_wins(a: &PiiMatch, b: &PiiMatch) -> bool {
    let a_len = a.end - a.start;
    let b_len = b.end - b.start;
    let a_contains_b = a.start <= b.start && a.end >= b.end && a_len > b_len;
    let b_contains_a = b.start <= a.start && b.end >= a.end && b_len > a_len;
    let same_span = a.start == b.start && a.end == b.end;

    if a_contains_b {
        return true;
    }
    if b_contains_a {
        return false;
    }
    if same_span {
        return cmp_priority(a.kind, b.kind).is_lt();
    }
    // Partial overlap: longer wins; tie-break by priority.
    if a_len != b_len {
        return a_len > b_len;
    }
    cmp_priority(a.kind, b.kind).is_lt()
}

fn overlaps(a: &PiiMatch, b: &PiiMatch) -> bool {
    a.start < b.end && b.start < a.end
}

/// Resolves overlaps in a set of raw matches and returns a non-overlapping
/// set with one kind per match.
///
/// See module docs for the rule order. Shadowed (dropped) matches are
/// emitted at `debug!` level so the priority list can be tuned against
/// real traffic.
pub fn resolve_overlaps(mut matches: Vec<PiiMatch>) -> Vec<PiiMatch> {
    if matches.len() < 2 {
        return matches;
    }

    // Sort by (start, -length, priority) so containing matches come first
    // and equal-span matches are seen in a stable order.
    matches.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
            .then_with(|| cmp_priority(a.kind, b.kind))
    });

    // Same span + same kind dedupe (rule 1). Keeps first occurrence.
    matches.dedup_by(|a, b| a.start == b.start && a.end == b.end && a.kind == b.kind);

    // Pairwise resolution. The set is small in practice (< 100 matches per
    // request), so O(n²) is fine and keeps the code simple.
    let mut kept: Vec<PiiMatch> = Vec::with_capacity(matches.len());
    'outer: for m in matches {
        let mut i = 0;
        while i < kept.len() {
            if overlaps(&kept[i], &m) {
                if a_wins(&kept[i], &m) {
                    debug!(
                        "shadowed: kind={} by kind={} at span={}..{}",
                        m.kind.label(),
                        kept[i].kind.label(),
                        m.start,
                        m.end,
                    );
                    continue 'outer;
                } else {
                    let dropped = kept.remove(i);
                    debug!(
                        "shadowed: kind={} by kind={} at span={}..{}",
                        dropped.kind.label(),
                        m.kind.label(),
                        dropped.start,
                        dropped.end,
                    );
                    continue;
                }
            }
            i += 1;
        }
        kept.push(m);
    }

    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    fn m(kind: PiiKind, start: usize, end: usize) -> PiiMatch {
        PiiMatch {
            kind,
            start,
            end,
            user_label: None,
        }
    }

    #[test]
    fn empty_input_returns_empty() {
        assert!(resolve_overlaps(vec![]).is_empty());
    }

    #[test]
    fn single_match_passes_through() {
        let input = vec![m(PiiKind::Email, 0, 10)];
        assert_eq!(resolve_overlaps(input.clone()), input);
    }

    #[test]
    fn same_span_same_kind_deduped() {
        let input = vec![
            m(PiiKind::Email, 0, 10),
            m(PiiKind::Email, 0, 10),
            m(PiiKind::Email, 0, 10),
        ];
        let out = resolve_overlaps(input);
        assert_eq!(out, vec![m(PiiKind::Email, 0, 10)]);
    }

    #[test]
    fn same_value_distinct_offsets_kept() {
        // "555-1234" appearing twice at different offsets stays as two matches.
        let input = vec![
            m(PiiKind::UsPhoneNumber, 0, 8),
            m(PiiKind::UsPhoneNumber, 50, 58),
        ];
        let out = resolve_overlaps(input.clone());
        assert_eq!(out, input);
    }

    #[test]
    fn containment_drops_inner() {
        // GB address (wider) contains GB postcode (narrower).
        let input = vec![
            m(PiiKind::GbAddress, 10, 80),
            m(PiiKind::GbPostcode, 70, 78),
        ];
        let out = resolve_overlaps(input);
        assert_eq!(out, vec![m(PiiKind::GbAddress, 10, 80)]);
    }

    #[test]
    fn containment_works_regardless_of_input_order() {
        let input = vec![
            m(PiiKind::GbPostcode, 70, 78),
            m(PiiKind::GbAddress, 10, 80),
        ];
        let out = resolve_overlaps(input);
        assert_eq!(out, vec![m(PiiKind::GbAddress, 10, 80)]);
    }

    #[test_case(PiiKind::UsPhoneNumber, PiiKind::InternationalPhoneNumber ; "us beats intl")]
    #[test_case(PiiKind::GbPhoneNumber, PiiKind::InternationalPhoneNumber ; "gb beats intl")]
    #[test_case(PiiKind::FrPhoneNumber, PiiKind::InternationalPhoneNumber ; "fr beats intl")]
    #[test_case(PiiKind::DePhoneNumber, PiiKind::InternationalPhoneNumber ; "de beats intl")]
    fn equal_span_phone_priority(winner: PiiKind, loser: PiiKind) {
        let input = vec![m(loser, 0, 12), m(winner, 0, 12)];
        let out = resolve_overlaps(input);
        assert_eq!(out, vec![m(winner, 0, 12)]);

        // Order-independent.
        let input = vec![m(winner, 0, 12), m(loser, 0, 12)];
        let out = resolve_overlaps(input);
        assert_eq!(out, vec![m(winner, 0, 12)]);
    }

    #[test_case(PiiKind::GbZaPassportNumber, PiiKind::PassportNumber ; "gb_za beats generic")]
    #[test_case(PiiKind::AuPassportNumber, PiiKind::PassportNumber ; "au beats generic")]
    #[test_case(PiiKind::FrPassportNumber, PiiKind::PassportNumber ; "fr beats generic")]
    #[test_case(PiiKind::DePassportNumber, PiiKind::PassportNumber ; "de beats generic")]
    fn equal_span_passport_priority(winner: PiiKind, loser: PiiKind) {
        let input = vec![m(loser, 5, 14), m(winner, 5, 14)];
        let out = resolve_overlaps(input);
        assert_eq!(out, vec![m(winner, 5, 14)]);
    }

    #[test]
    fn partial_overlap_longer_wins() {
        // Two matches partially overlap; neither contains the other.
        let input = vec![m(PiiKind::Email, 0, 10), m(PiiKind::CreditCard, 5, 25)];
        let out = resolve_overlaps(input);
        assert_eq!(out, vec![m(PiiKind::CreditCard, 5, 25)]);
    }

    #[test]
    fn partial_overlap_equal_length_falls_back_to_priority() {
        // Equal-length partial overlap of two phone kinds.
        let input = vec![
            m(PiiKind::InternationalPhoneNumber, 0, 10),
            m(PiiKind::UsPhoneNumber, 5, 15),
        ];
        let out = resolve_overlaps(input);
        assert_eq!(out, vec![m(PiiKind::UsPhoneNumber, 5, 15)]);
    }

    #[test]
    fn non_overlapping_matches_all_kept() {
        let input = vec![
            m(PiiKind::Email, 0, 10),
            m(PiiKind::CreditCard, 20, 35),
            m(PiiKind::UsSsn, 40, 51),
        ];
        let out = resolve_overlaps(input.clone());
        assert_eq!(out.len(), 3);
        for expected in &input {
            assert!(out.contains(expected));
        }
    }

    #[test]
    fn unrelated_kinds_with_overlap_use_longer_wins() {
        // Email and CreditCard share no priority group; partial overlap
        // resolves by longer-wins rule alone.
        let input = vec![m(PiiKind::Email, 0, 30), m(PiiKind::CreditCard, 25, 45)];
        let out = resolve_overlaps(input);
        assert_eq!(out, vec![m(PiiKind::Email, 0, 30)]);
    }

    #[test]
    fn three_way_chain_resolves_to_widest() {
        // Address ⊃ Postcode, and another phone match disjoint from both.
        let input = vec![
            m(PiiKind::GbAddress, 0, 50),
            m(PiiKind::GbPostcode, 40, 48),
            m(PiiKind::Email, 100, 120),
        ];
        let out = resolve_overlaps(input);
        assert_eq!(out.len(), 2);
        assert!(out.contains(&m(PiiKind::GbAddress, 0, 50)));
        assert!(out.contains(&m(PiiKind::Email, 100, 120)));
    }
}
