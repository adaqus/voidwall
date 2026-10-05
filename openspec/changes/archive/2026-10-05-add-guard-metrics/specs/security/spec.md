## MODIFIED Requirements

### Requirement: A PII value never reaches a metric

Every metric label SHALL hold a kind name, a guard name, a mode, a route, a direction, a
method, a status, an outcome, or a reason. No label SHALL ever hold a matched value. A
guard name SHALL be the name configuration gave the guard, never a value taken from a
request, a response, or a detection.

#### Scenario: A detection increments a counter

- **WHEN** the proxy increments the detection counter
- **THEN** the `pii_kind` label holds the kind name and no value

#### Scenario: A guard detection increments a counter

- **WHEN** the proxy increments `voidwall_detections_total`
- **THEN** the `guard` label holds the guard's configured name and no value
