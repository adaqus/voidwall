## MODIFIED Requirements

### Requirement: The engine aggregates the guards and owns the stage order

One engine SHALL own every guard and SHALL be the only entry point for detection. For
each message it SHALL select the units, call every guard whose declared interest matches
at least one selected unit, await them all, and return the merged findings.

A guard whose declared interest matches no selected unit SHALL NOT be called.

The merged findings SHALL be returned in a stable order that does not depend on the
order in which the guards finished: by unit, then by span start, then by span end, then
by guard name, then by kind, with span-less findings last.

The engine SHALL stop waiting only when the caller's policy says a finding ends the scan.
Guards still running at that point SHALL be abandoned, and their findings SHALL NOT appear
in the result. A caller that reports a detection without stopping the message SHALL NOT
stop the engine early.

A guard error SHALL NOT end the scan. The engine SHALL keep waiting for the other guards,
and SHALL return the findings of the guards that succeeded together with the error.

#### Scenario: No guard is interested

- **WHEN** the selected units are of a kind no guard declares interest in
- **THEN** no guard is called and the result holds no findings

#### Scenario: Two guards run over the same message

- **WHEN** two guards both declare interest in the body and both report a finding
- **THEN** the result holds both findings in the stable order

#### Scenario: The same message is scanned twice

- **WHEN** the same message is scanned twice with the same configuration
- **THEN** the two results list their findings in the same order

#### Scenario: A blocking finding arrives first

- **WHEN** one guard reports a finding while another guard is still running, and the
  caller's policy says a finding ends the scan
- **THEN** the engine returns and the result carries no finding from the abandoned guard

#### Scenario: A reporting caller waits for every guard

- **WHEN** one guard reports a finding while another guard is still running, and the
  caller reports rather than blocks
- **THEN** the engine waits for the second guard and the result holds both findings

#### Scenario: A guard fails before another guard reports

- **WHEN** one guard returns an error while another guard is still running, and the second
  guard then reports a finding
- **THEN** the engine waits for the second guard and returns its finding together with the
  error

#### Scenario: A guard fails and no other guard reports

- **WHEN** one guard returns an error and every other guard reports nothing
- **THEN** the engine returns the error and no finding
