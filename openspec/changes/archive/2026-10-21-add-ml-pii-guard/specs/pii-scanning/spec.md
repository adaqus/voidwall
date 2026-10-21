## MODIFIED Requirements

### Requirement: Overlap resolution runs before every use of the matches

Overlap resolution SHALL be scoped to a kind vocabulary, not to a message. A vocabulary
SHALL be the set of kinds one guard produces. Two guards that report kinds of the same name
SHALL NOT share a vocabulary: the engine SHALL merge their findings and SHALL resolve nothing
between them.

The regex PII guard SHALL pass every match through `voidwall_pii::resolve_overlaps` before it
returns its findings. Every count, kind list, and metric of its findings SHALL derive from
the resolved set. The same value at two distinct byte offsets SHALL stay two matches.

Resolution SHALL NOT be applied twice over the same spans. Resolving each guard's findings
and then resolving the union is not the same as resolving the union, so if two guards are
ever built to produce one vocabulary, resolution SHALL move to the engine over their union
and the per-guard resolution SHALL be removed.

#### Scenario: Two detectors match overlapping spans

- **WHEN** two detectors report overlapping spans over the same bytes
- **THEN** the resolved set holds one match, and the count reflects the resolved set

#### Scenario: One value appears twice

- **WHEN** the same value appears at two distinct byte offsets
- **THEN** the resolved set holds two matches

#### Scenario: Findings are resolved once

- **WHEN** the engine merges the findings of the guards
- **THEN** it applies no further overlap resolution to spans a guard already resolved

#### Scenario: Two guards report a kind of the same name

- **WHEN** the regex PII guard and a model guard each report a `PERSON_NAME` finding over the
  same bytes of one unit
- **THEN** both findings are kept, the kind list holds `PERSON_NAME` once, and the match
  count counts both
