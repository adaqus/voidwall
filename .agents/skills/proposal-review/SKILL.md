---
name: proposal-review
description: Review the planning artifacts of a Voidwall OpenSpec change before implementation. Finds scenario gaps from the problem's point of view, inconsistencies inside the change, and conflicts with project rules. Use after openspec-propose or openspec-update-change, and before openspec-apply-change, or when asked to review a proposal, a design, or spec deltas. Review only; do not edit files.
---

# Review an OpenSpec Change Before Implementation

Perform a read-only review of one change in `openspec/changes/<name>/`. Do not edit
files, update task checkboxes, or commit changes. The author fixes findings with the
`openspec-update-change` workflow.

## Scope

1. Select the change. If the user names none, run `openspec list --json`; ask when more
   than one change is active.
2. Run `openspec validate <name> --strict`. A failure is a finding.
3. Read `proposal.md`, `design.md`, `tasks.md`, and every `specs/**/spec.md` delta.
4. For each MODIFIED, REMOVED, or RENAMED requirement, read the main spec in
   `openspec/specs/` that it changes.
5. Read `AGENTS.md`, `ARCHITECTURE.md`, `openspec/config.yaml`, and the `AGENTS.md` of
   each crate the change touches.
6. Read the code the design names when that confirms or rejects a finding. Do not review
   code style.

Never expose PII values in a finding. Refer to PII by kind or a safe placeholder.

Do the three checks below in order. Each check has a different source of truth.

## 1. Gaps: the Problem Decides

Do not start from the scenarios. Start from the problem the proposal solves.

1. In your own words, state the problem and what "solved" means.
2. Model the case space of that problem: the inputs and their shapes, the states the
   system can be in, the boundaries, the ways each step can fail, and the existing
   behavior the change meets. Derive the cases from this problem, not from a list.
3. Compare the model with the scenarios. A case that the solution must handle and that
   no scenario covers is a gap. Also report a case that the proposal leaves undecided,
   where two outcomes are both plausible.
4. Check each scenario on its own. Its WHEN states one case and its THEN states a
   result that a test can see. "Correctly" or "handles" is not a result.

For a MODIFIED requirement, the main spec is part of the case space: a scenario that the
delta drops without a stated reason is a gap.

## 2. Inconsistencies: the Change Itself Decides

Read the artifacts as one set of claims. Report each pair of claims that cannot both be
true, inside one artifact or between artifacts. Two scenarios can give different results
for the same case, the design can decide something that a requirement contradicts, or
the proposal can promise something that no requirement or task delivers. Also report a
thing that has two names, and a decision that only one artifact states.

## 3. Conflicts: the Project Decides

Compare the change with the project rules: `AGENTS.md`, `ARCHITECTURE.md`, the crate
`AGENTS.md` files, `openspec/config.yaml`, and the built specs in `openspec/specs/` that
the change does not modify. A conflict is a claim that breaks a rule, or a built
behavior that the change alters without a delta that says so.

The project rules also add cases to check 1. For example, a rule that applies to both
directions, to `openai-chat` routes, or to each `on_error` policy makes each of these a
case when the change touches that area.

## Agreement

The artifacts contain only what the user agreed to. When a requirement, default, or
scope item looks inferred rather than agreed, list it as an open question. Do not
present it as a defect, and do not propose a value for it.

## Output

Start with one paragraph: the problem and the case space as you modelled them in check 1.
The author can then correct your model before reading the findings.

List findings under the three headings: Gaps, Inconsistencies, Conflicts. In each
heading, order them by severity. Each finding gives the file and line, the problem, and
a concrete fix or the missing scenario in WHEN/THEN form.

After the findings, list open questions for the user. End with the `openspec validate`
result. If there are no findings, state that directly.
