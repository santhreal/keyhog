# The review checklist

## The point of a checklist

Reviewing tests well requires holding many rules in mind at
once: the oracle hierarchy, the naming convention, the
anti-patterns, the category boundaries, the template shapes.
A reviewer working from memory under time pressure forgets
something. A reviewer working from a checklist does not.

This chapter is the review checklist for vyre test changes.
Every pull request that adds or modifies a test is evaluated
against these eleven items before merging. A PR that fails any
item is sent back with the specific failure identified; it does
not merge until the failure is addressed. The checklist is not
negotiable — "I know the test is technically wrong but can we
merge anyway" is not a valid argument, because the suite's
quality is a function of every test that enters it.

The checklist is intentionally short. Eleven items is more than
a reviewer would remember by heart but few enough to scan in a
few minutes. It is also comprehensive: every important rule
from earlier chapters is represented, and a test that passes
all eleven items has cleared the discipline gates.

## The checklist

### 1. The test is in the correct category

Run [the decision tree](../writing/decision-tree.md) against
the test. If the test is in a different category than the tree
says it should be, the PR is sent back.

Common violations:
- A validation test placed in `tests/integration/primitive_ops/`
- An adversarial test placed in `tests/integration/lowering/`
- A property test placed in `tests/integration/ir_construction/`

The fix is always to move the test to the correct directory.
Moving is cheap; the tree is not.

### 2. The test has a doc comment stating its oracle

Every test function has a doc comment. The comment has at least
two lines: a description of the property being verified, and a
line declaring the oracle.

```rust
/// add(u32::MAX, 1) wraps to 0. Overflow behavior.
/// Oracle: SpecRow from vyre-conform::spec::tables::add (row 4).
#[test]
fn test_add_u32_max_plus_one_wraps_to_zero() { ... }
```

A test without this comment is rejected. The comment is not
optional — it is how reviewers evaluate the oracle and how
future maintainers understand the test's intent.

### 3. The oracle is the strongest applicable

Read the declared oracle. Check: is there a stronger oracle
that could apply? If yes, the PR is sent back with a request
to use the stronger oracle.

The hierarchy is: Law → SpecTable → ReferenceInterpreter →
CpuReference → Composition → ExternalCorpus → Property.

Common violations:
- A spec table oracle used when a law oracle would work
- A reference interpreter oracle used when a spec table row
  exists for the specific inputs
- A property oracle used when any of the stronger oracles apply

See [the oracle hierarchy](../oracles.md) for the rules.

### 4. The expected value comes from the oracle, not the code

Check: where does the expected value in the assertion come
from? It must come from the declared oracle, which must be
independent of the code under test.

Violations:
- Expected value is `f(a, b)` where `f` is the function under
  test (tautology)
- Expected value is the result of a helper that calls the
  function under test
- Expected value is "whatever the reference interpreter
  returns" when the reference interpreter shares the same CPU
  reference function as the backend (subtle tautology)

See [the tautology anti-pattern](../anti-patterns/tautology.md).

### 5. The test has a specific subject and property

The test name follows `test_<subject>_<property>[_<oracle>]`.
The doc comment states the subject and property explicitly.
Reading the test body shows what is being tested and what is
being asserted.

Violations:
- Generic names like `test_add` or `test_validate`
- Vague comments like "tests add" or "verifies validate"
- Test bodies where the subject is unclear

### 6. The test has one clear assertion

The test asserts one property. Multiple assertions on the same
observed value (e.g., asserting both equality and a side
property) are fine. Multiple assertions on different properties
are a kitchen sink (see [kitchen sink anti-pattern](../anti-patterns/kitchen-sink.md)).

The rule of thumb: if the test fails, the failure should point
at one thing. If the test could fail for more than one reason,
it is doing too much.

### 7. Helpers clarify, do not obscure

If the test uses helpers, the helpers have descriptive names
and do not hide the test's subject, inputs, or expected value.
A reader should be able to understand the test from the test
body alone.

Violations:
- Helpers named `run_test`, `check_result`, `build_case`
- Helpers that take configuration objects
- Helpers that wrap assertions in opaque "test passed/failed"
  results

See [the hidden helper anti-pattern](../anti-patterns/hidden-helpers.md).

### 8. Proptest has fixed seed and committed regression corpus

If the test uses `proptest!`, the config sets explicit case
count, shrink iterations, and failure persistence. The
regression corpus file is committed.

Violations:
- `proptest!` with no `ProptestConfig`
- No `proptest-regressions/` directory committed
- Ignored failures from past runs

See [seedless proptest](../anti-patterns/seedless-proptest.md)
and [seed discipline](seed-discipline.md).

### 9. The test name follows the convention

The name matches `test_<subject>_<property>` (or `regression_<name>`
for regression tests, or `bench_<name>` for benchmarks). The
name is descriptive and matches the naming convention in
Part V.

See [naming](../writing/naming.md).

### 10. The test is not a known anti-pattern

Read [Part VI](../anti-patterns/README.md). If the test matches
any anti-pattern chapter, the PR is sent back with the
specific anti-pattern named.

This item covers: tautology, kitchen sink, doesn't crash,
hidden helpers, seedless proptest, and any of the smells that
have risen to the level of a finding.

### 11. The test has a sensible failure message

When the test fails, the assertion produces a message that
identifies what went wrong. The default `assert_eq!` failure
message is acceptable for simple cases. For loops, iteration,
or multi-step tests, an explicit failure message is required.

```rust
// Acceptable — default message is clear
assert_eq!(result, 5u32);

// Required — loop needs explicit message
for (input, expected) in ADD_CASES {
    assert_eq!(
        run_add(input), *expected,
        "failed for input {:?}", input,
    );
}
```

## How a reviewer applies the checklist

The reviewer reads the PR and runs through the eleven items in
order. For each item, the reviewer decides: pass, fail, or
unclear. A pass moves on. A fail is cited in a review comment
with a link to the relevant chapter. An unclear is investigated
(by reading the test more carefully or by asking a question).

A PR that passes all eleven items is ready to merge on the
test discipline axis. The reviewer may still have other
feedback (on the non-test parts of the PR, on the commit
message, on the branching strategy), but the test discipline
is satisfied.

A PR that fails any item is sent back. The reviewer cites the
specific item and the specific chapter, and the contributor
fixes the item and re-submits. Repeat until all items pass.

## How a contributor uses the checklist

Before submitting a PR, the contributor runs through the
checklist themselves. This catches most issues before the
reviewer sees them, which saves one round of review and makes
the overall cycle faster.

Contributors who internalize the checklist produce tests that
pass review on the first pass almost always. Contributors who
treat review as "let the reviewer find the problems" waste
review time and learn the checklist slowly. The discipline is
cultural: we catch our own mistakes before we ship them.

## The checklist is short because it has to be

The checklist has eleven items. Not twenty, not fifty. Eleven
because that is the number a reviewer can hold in mind while
reading a PR. Adding items beyond eleven dilutes attention; a
reviewer glances at items fifteen through twenty without
thinking carefully. The budget of attention is limited.

When the discipline grows (new rules, new categories, new
invariants), the rules integrate into existing checklist items
rather than becoming new ones. "Oracle is the strongest
applicable" encompasses every oracle rule in the hierarchy;
adding a new oracle kind does not add a checklist item, it
adds a sub-rule under item 3.

The checklist is maintained when it stops working. If a class
of bug is slipping past the checklist into the suite, the
checklist has a gap and the gap is closed — by rewriting an
existing item to cover the gap, or rarely by adding an item
if the existing ones cannot absorb it.

## Summary

The review checklist is the eleven-item discipline gate every
PR passes through. Items cover category, oracle, naming,
assertions, helpers, seeds, anti-patterns, and failure
messages. A PR that passes all items is accepted on the test
discipline axis. A PR that fails any item is sent back with
specific feedback. The checklist is short because attention is
limited; new rules extend existing items rather than multiplying
items.

See [Appendix F](../appendices/F-review-checklist.md) for the
printable version.

Next: [The daily audit](daily-audit.md).
