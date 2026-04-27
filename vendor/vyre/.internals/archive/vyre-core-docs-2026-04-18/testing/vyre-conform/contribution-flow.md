# Contribution flow

## The path from idea to committed test

A test in vyre starts as an idea: "this behavior should be
verified." It ends as a committed function in the main
branch. The path between the two is the contribution flow,
and the flow is the same for every contributor regardless of
whether they are human or agent. This chapter is the map of
that path.

The flow has distinct stages with distinct purposes. At each
stage, the test is at a different maturity: from rough
sketch to final committed code. Knowing the stages lets
contributors plan their work and lets reviewers evaluate
progress.

## Stage 1 — Intent

The contributor has an idea for a test. The idea might be:

- "Add needs a test for the u64 overflow case."
- "I think V012 is not covered by the must-reject tests."
- "The new atomic op should have a cross-backend
  equivalence test."
- "The fuzzer found a crash; I should add it as a
  regression."

At this stage, the test is a thought, not code. The
contributor writes down the idea, usually as a note to
themselves or as a comment on an issue. The note includes:

- What is being tested (the subject).
- What is being verified (the property).
- Where the idea came from (a bug report, a code review, a
  fuzz finding, a personal insight).

The intent stage is short — minutes — but it is where the
contributor commits to a specific goal. Skipping this stage
produces tests that drift into unclear territory as they are
written.

## Stage 2 — Category and oracle

With intent clarified, the contributor applies the decision
tree from [writing/decision-tree.md](../writing/decision-tree.md).
They answer the nine questions in order and identify the
correct category for the test.

The contributor then consults [oracles](../oracles.md) to
pick the right oracle for the test's subject and property.
The oracle determines what the expected value will be and
where it comes from.

At the end of stage 2, the contributor has:

- A category directory for the test.
- An oracle kind for the test.
- A template to copy from.

## Stage 3 — Drafting

The contributor copies the template from
[writing/templates.md](../writing/templates.md) and fills
in the specifics. The draft has the correct shape, correct
naming, correct oracle declaration, and the inputs from the
spec table, archetype catalog, or wherever the test's values
come from.

At this stage, the draft is compilable code that runs. It
may pass, it may fail, and the contributor iterates on it
until the test passes on the current code (assuming the
current code is correct) or fails in the way that the test
was designed to catch (assuming the current code has the
bug the test was written for).

## Stage 4 — Self-review

Before submitting, the contributor runs through the
[review checklist](../discipline/review-checklist.md) on
their own test. Self-review catches the common mistakes
before the reviewer has to:

- Is the test in the correct category?
- Does it have an oracle declaration?
- Is the oracle the strongest applicable?
- Does the expected value come from the oracle?
- Does the name follow the convention?
- Does the test avoid the anti-patterns?
- Does it kill the relevant mutations?

A contributor who internalizes the checklist catches most
issues at this stage. A contributor who skips self-review
learns the checklist through reviewer pushback, which is
slower but still effective.

## Stage 5 — Local mutation gate

The contributor runs the mutation gate on the test to verify
it kills the expected mutations:

```bash
cargo xtask mutation-gate --op add --tests tests/integration/primitive_ops/add.rs
```

If mutations survive, the gate produces structured feedback:
"Your test passed when I changed X to Y. Strengthen it to
distinguish these." The contributor strengthens the test and
re-runs. Iteration continues until all relevant mutations are
killed.

The local gate run is the contributor's pre-commit check on
test strength. Failing the gate at submission time is
embarrassing; passing the gate before submission is fast and
routine.

## Stage 6 — Commit

The contributor commits the test with a descriptive message:

```
add(tests/primitive_ops/add): cover u64 overflow case

BinOp::Add on u64 inputs was not covered by the overflow
spec table row. Added test_add_u64_overflow_spec_table
that asserts u64::MAX + 1 wraps to 0.

Mutation gate: kills all ArithmeticMutations and
ConstantMutations applicable to the u64 path.
```

The commit includes the new test, any new spec table rows
it depends on, and any support utility additions. It does
not include unrelated changes.

## Stage 7 — Pull request

The contributor opens a PR with the commit. The PR
description explains:

- What is being added (one sentence).
- Why it is being added (the gap it closes).
- Verification steps performed.

A typical PR description:

```
## Add u64 overflow coverage for BinOp::Add

The hand-written primitive op suite for Add did not include
a test for u64 overflow wrapping. Added
test_add_u64_overflow_spec_table with the relevant spec
table row.

Verification:
- test_add_u64_overflow_spec_table passes
- cargo test -p vyre passes
- cargo xtask mutation-gate --op add reports 0 survivors
- cargo xtask coverage-check reports full variant coverage
```

## Stage 8 — Review

The reviewer applies the full review checklist. For each
checklist item, they record pass or fail. A fail is cited
with a link to the relevant chapter and a specific request
for change.

The review is not adversarial. The reviewer and the
contributor are both aiming for the same outcome — a
correct, disciplined test committed to the suite. The
reviewer's citations are informational, not judgmental.

If the checklist passes, the reviewer approves. If it fails,
the reviewer requests changes, and the contributor iterates.
Multiple rounds are normal, especially for contributors new
to the project.

## Stage 9 — CI

Once the reviewer approves, CI runs on the PR. Tier 1 (fast)
and Tier 2 (thorough) both run. Both must pass for the PR to
merge.

If CI fails, the contributor investigates using the debugging
chapters. A deterministic failure is a real problem; a flake
is a flake. Either is diagnosed and fixed.

## Stage 10 — Merge

With review approval and CI green, the PR merges to main.
The test is now part of vyre's suite, running on every
future commit, contributing to the project's quality
assurance.

The merge is not the end of the test's life. The test will
run thousands of times over years, possibly millions of
times. It may be the reason a future bug is caught. It may
be flagged in a daily audit if it drifts toward an
anti-pattern. It may eventually be migrated to the
generated tier. But for now, it is committed and working,
which is what matters.

## Variations on the flow

### Agent-authored tests

An agent contributing to vyre follows the same flow, with
the agent's process producing the test draft. The review
and CI stages are identical: an agent-authored test is
reviewed by a human or another agent against the same
checklist, and it passes the same CI gates before merging.

Agents are especially prone to specific anti-patterns
(tautology, doesn't-crash, hidden helpers), so agent-authored
PRs receive extra attention to those specific checklist
items. See [Part VI](../anti-patterns/README.md) for the
anti-pattern details.

### Generator-produced tests

Tests produced by the vyre-conform generator follow a
different flow because they are not individually committed.
The generator produces them at build time from the
specification. The contribution flow for generator output is:

1. A contributor updates the specification (OpSpec,
   archetype, oracle).
2. The specification change goes through its own review.
3. After the spec change merges, the generator's output
   changes automatically on subsequent CI runs.
4. The generated tests are verified by the mutation gate
   and the coverage checks just like hand-written tests.

The review happens on the spec, not on the generated tests.
The spec's review is the quality gate for generated
output.

### Regression contributions

A regression test added in response to a bug fix follows a
slightly different flow because the bug fix itself is
landing at the same time:

1. The bug is identified.
2. The minimal reproducer is found.
3. The regression test is drafted in
   `tests/regression/YYYY-MM-DD-description.rs`.
4. The code fix is drafted.
5. Both changes go into one PR, described as a fix.
6. The reviewer verifies that the regression test fails on
   the pre-fix code and passes on the post-fix code.
7. The PR merges.

The paired nature of the changes is what makes regression
tests trustworthy: the test is committed with the fix, not
after, so the guarantee that the fix stuck is in place
immediately.

## Summary

The contribution flow has ten stages: intent, category,
drafting, self-review, local mutation gate, commit, PR,
review, CI, merge. The same flow applies to every
contributor. Variations exist for agent-authored tests,
generator-produced tests, and regression contributions, but
the core discipline is consistent. Each stage has a
specific purpose, and skipping stages produces worse tests
without saving much time.

This concludes Part X. Part XI is the meta part: reflections
on what testing as design means, how we know our tests are
good, what post-mortem discipline looks like, and the long
game the book is playing.

Next: Part XI opens with [Testing as design](../meta/testing-as-design.md).
