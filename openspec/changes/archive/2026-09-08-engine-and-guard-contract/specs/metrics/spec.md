## MODIFIED Requirements

### Requirement: Detections increment once per resolved kind

The proxy SHALL increment `voidwall_pii_detections_total` once per kind in the resolved
finding set the detection engine returns. It SHALL increment once for a kind however
many findings, and however many guards, reported that kind. It SHALL do so whatever
action list is configured, including an empty one.

#### Scenario: PII detected with no action configured

- **WHEN** the action list for a direction is empty and PII is detected
- **THEN** the detection counter still increments

#### Scenario: One kind is found many times

- **WHEN** a scan returns four findings of the same kind
- **THEN** the counter for that kind increments by one

#### Scenario: Two guards report the same kind

- **WHEN** two guards each report a finding of the same kind in one message
- **THEN** the counter for that kind increments by one
