# Testing the testers

## Who watches the watchers

A test suite verifies the code being tested. But who verifies
the suite? If the suite has bugs, the bugs silently reduce
the coverage, and nothing in the normal testing discipline
catches the reduction. A test that looks correct but asserts
nothing meaningful gives false confidence; a test that
should fire but does not leaves a gap. The suite is not
self-correcting.

This chapter is about the mechanisms vyre uses to test the
tests. The goal is to answer, with evidence, the question
"is our test suite actually good?" The answer is not a
single metric but a combination of signals that, together,
give a reasonable picture of the suite's health. Each signal
has its limits; the combination is stronger than any one
signal alone.

## The signals

### Signal 1 — Mutation score

The mutation score is the fraction of mutations in the
catalog that at least one test kills. A score of 100% means
every mutation is caught by some test; a score below 100%
means some mutations escape the suite's attention.

Mutation score is the single most important quality metric
for the test suite. Unlike line coverage, it cannot be
gamed by writing tests that execute code without asserting
anything meaningful. A test that executes a line but does
not assert anything about the line's behavior does not kill
the mutations that affect that line; the gate catches this
directly.

vyre tracks mutation score in CI. The target is 100% on
every op's sensitivity classes. A mutation score below the
target is a finding.

Mutation score has limits: it measures only what the
catalog contains. A bug class not represented in the
catalog is not scored. The catalog is expanded when new bug
classes are identified (see [post-mortem
discipline](post-mortem-discipline.md)).

### Signal 2 — Branch coverage

Branch coverage is the fraction of branches in the source
code that the suite exercises. vyre targets 100% branch
coverage on core modules and measures it via
`cargo-tarpaulin` or equivalent.

Branch coverage is easy to game (you can cover a branch
without asserting anything about its behavior) but is
still useful as a lower bound: a branch with 0% coverage is
definitely not being tested, and the gap is a finding even
if higher coverage does not prove quality.

vyre uses branch coverage as a guardrail. A PR that reduces
branch coverage on core modules is blocked; a PR that
maintains or improves coverage is accepted. The metric
does not directly measure quality but catches the worst
regressions.

### Signal 3 — Variant coverage

Variant coverage is the fraction of enum variants in vyre's
public types that the suite exercises. Every public enum
(`Expr`, `Node`, `BinOp`, `UnOp`, `AtomicOp`, `BufferAccess`,
`DataType`, `ValidationRule`) has a meta-test that
enumerates its variants and asserts each is covered.

Variant coverage is tighter than branch coverage because it
is about the type system's exhaustiveness. Adding a new
variant without adding coverage is a compile error (the
meta-test's match is non-exhaustive) or a test failure. This
is how vyre catches the specific failure mode of adding new
features without testing them.

Target: 100% variant coverage on every public enum. No
exceptions.

### Signal 4 — Audit pass rate

The daily audit reads ten random tests per day and evaluates
them against the review checklist. The audit's findings
(tests that failed the checklist) are tracked as a
running count.

A high audit pass rate (95%+ tests pass the audit without
being flagged) suggests the suite is healthy. A lower pass
rate suggests drift — tests are accumulating problems that
review is not catching. The trend over weeks and months is
more informative than the absolute number.

The audit is described in [daily-audit.md](../discipline/daily-audit.md).

### Signal 5 — Flake rate

The fraction of CI runs that produced a flaky failure (a
failure that did not reproduce on re-run). A healthy suite
has a flake rate near zero. A flake rate above a few percent
is a finding; a flake rate above ten percent is a crisis.

vyre tracks the flake rate per week and per month. When the
rate spikes, the cause is investigated — usually a specific
test or subsystem — and fixed before the flakes corrode the
suite's credibility.

See [flakiness.md](../discipline/flakiness.md).

### Signal 6 — Regression count

The rate at which new regression tests are added. A high
regression count is both bad (bugs are happening) and good
(bugs are being caught and converted into permanent tests).
A zero count over a long period is suspicious: either vyre
has no bugs (unlikely) or bugs are slipping past without
being turned into regressions.

The healthy pattern is a steady rate of new regressions
with a declining trend over time. New features produce new
bugs that produce new regression tests; as the suite
matures, the rate should decrease because features are
becoming more stable.

### Signal 7 — Cross-backend disagreement rate

The rate at which cross-backend tests find disagreements
between backends. Disagreements are findings, and the
findings are investigated. A low rate is healthy; a high
rate suggests a new backend has landed and needs more
work, or a driver update is causing drift.

### Signal 8 — Property test shrink quality

When a property test fails, proptest shrinks the failing
input to the minimal case. The shrink quality is the ratio
of original input size to shrunk input size. High ratios
(10:1 or better) mean proptest is finding minimal cases,
which are easy to debug. Low ratios mean the generator is
producing inputs that do not shrink well, which makes
debugging hard.

vyre measures shrink quality as a property of each
generator. Generators that shrink poorly are restructured
to shrink better.

## Combining the signals

No single signal is sufficient. A suite with 100% mutation
score but 50% branch coverage has gaps that mutation
testing does not expose. A suite with 100% branch coverage
but 60% mutation score has tests that execute code without
verifying it. A suite with high audit pass rate but high
flake rate is superficially healthy but actually corrosive.

The combination matters. A healthy vyre suite has:

- Mutation score >= 95% on declared sensitivity classes.
- Branch coverage >= 90% on core modules, 100% on critical
  paths.
- Variant coverage 100% on every public enum.
- Daily audit pass rate >= 95%.
- Flake rate < 1% per week.
- Regression count steady with declining trend.
- Cross-backend disagreement rate near zero.
- Property shrink quality good enough that failing cases
  are diagnosable.

Each of these is monitored. When any drifts outside the
target, the cause is investigated.

## The dashboard

vyre maintains a testing health dashboard that displays all
the signals together. The dashboard updates on every CI run
and shows trends over time. Anyone on the project can read
the dashboard and see at a glance whether the suite is
healthy.

The dashboard is not in this book because its specific
rendering is an implementation detail. The concept matters:
the suite's health is visible, not hidden, and anyone
looking at the project can evaluate the testing discipline
without having to re-run the whole suite.

## Meta-testing

Beyond the signals, vyre has meta-tests that verify
specific properties of the suite itself:

### The separability meta-test

Asserts that every validation rule can be triggered in
isolation. If two rules are coupled, the separability test
catches the coupling. See [validation.md](../categories/validation.md).

### The variant coverage meta-tests

Assert that every enum variant has a corresponding test in
the suite. Described in [testing-as-design.md](testing-as-design.md).

### The generator coverage meta-test

Asserts that the proptest generator produces inputs that
cover every variant of every relevant enum, and that the
validity rate is above the target. See [property-generators.md](../advanced/property-generators.md).

### The mutation catalog coverage meta-test

Asserts that every mutation class in the catalog is
represented in at least one op's sensitivity declaration.
A mutation class that no op cares about is a sign the
catalog has drifted from the spec.

### The oracle strength meta-test

Asserts that every test using a weaker oracle (property or
external corpus) has a documented reason for not using a
stronger oracle. This catches tests that drift to weaker
oracles over time.

### The regression age meta-test

Asserts that regression tests older than a specified age
still reproduce the bug they were meant to reproduce (by
running them against a version of the code where the fix is
reverted). This is expensive and runs nightly, but it
catches regression tests that have bit-rotted.

Meta-tests are tests about tests. They are part of the
suite and run like any other test, but their subjects are
the suite's own properties. A failing meta-test is a sign
the suite has drifted; the fix is a structural change, not
a normal bug fix.

## Summary

Testing the testers uses eight signals (mutation score,
branch coverage, variant coverage, audit pass rate, flake
rate, regression count, cross-backend disagreement rate,
shrink quality) and a set of meta-tests that verify
specific suite properties. No single signal is sufficient;
the combination gives a reasonable picture. The dashboard
makes the picture visible. Meta-tests catch structural
drift. The question "is our suite good?" has an answer
backed by evidence.

Next: [Post-mortem discipline](post-mortem-discipline.md).
