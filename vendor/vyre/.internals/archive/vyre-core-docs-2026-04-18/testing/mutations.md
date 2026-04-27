# Mutations and the adversarial mindset

## The question nobody asks loud enough

When you write a test and it passes, what have you learned? The
honest answer is: you have learned that this particular test, on
this particular version of the code, did not fail. You have not
learned that the code is correct. You have not learned that the
test is good. You have not learned that another test, for the same
property, would also pass. You have learned only that one specific
assertion on one specific run of one specific implementation did
not trip.

This is a weaker conclusion than most contributors realize. A
suite of a thousand passing tests feels like strong evidence of
correctness, but it is exactly as strong as the sum of the
individual "did not fail on this run" claims. If those thousand
tests were all tautologies, the evidence is zero. If half of them
could pass on a broken implementation, the evidence is half of
what it looked like. A suite is only as strong as the worst test
in it, because a single weak test creates a hiding place for bugs
in the code it was supposed to cover.

The question "what have I learned?" is hard to answer by looking
at the test's output. It is much easier to answer by looking at the
test's sensitivity: if I break the code under test, does the test
fail? If yes, the test has value. If no, the test is theater.

Mutation testing is the mechanical version of that question.

## What mutation testing is

Mutation testing grades a test suite by measuring how many of a
catalog of small deliberate changes to the source code cause tests
to fail. The technique is sixty years old, was refined in the
1970s, and has been available in production tools since the 1990s.
It has had surprisingly little uptake in mainstream software
engineering, largely because it is computationally expensive and
because most engineers who hear about it think "my tests are
already good" and stop listening. vyre does not think its tests are
already good. vyre takes mutation testing seriously.

The mechanics are simple. A mutation is a small, specific change
to the source: swap `+` for `-`, delete a branch, increment a
constant, remove a bounds check. The mutation is applied, the test
suite is run, and the result is recorded:

- If the suite fails after the mutation, the mutation is **killed**.
  This is the desirable outcome: the suite detected the broken code.
- If the suite passes after the mutation, the mutation is a
  **survivor**. This is a finding: the suite failed to detect a
  specific kind of bug.

Running a full mutation catalog against a suite produces a number
— the **mutation score** — which is the fraction of mutations
killed. A mutation score of 100% means every mutation in the
catalog was caught by at least one test. A mutation score of 80%
means 20% of the deliberate bugs would slip through unnoticed.

The mutation score is the most important quality number in vyre's
testing discipline. It is not the only number, but it is the number
that cannot be gamed. Line coverage can be gamed by writing tests
that execute code without asserting anything meaningful. Test count
can be gamed by writing many trivial tests. Mutation score cannot
be gamed because the grading criterion is external to the test
author: a mutation either kills a test or it does not, and the
mutation is defined in vyre-conform's catalog, not by the person
trying to inflate their number.

## Why this matters more for vyre than for most projects

Most software has a forgiving failure mode. A web app that renders
a button slightly wrong is a cosmetic bug. A data pipeline that
drops a row once a year is a data quality issue someone cleans up
later. A game that stutters on the second level is an
inconvenience. In each case, the cost of a missed bug is bounded.
The suite can afford to miss some bugs because the consequences
are absorbed by the surrounding system.

vyre has no forgiving failure mode. A miscompilation in vyre's
lowering corrupts user data silently. A nondeterminism bug breaks
vyre's central promise. A backend drift quietly turns cross-backend
portability into a lie. A validation gap lets malformed programs
crash the runtime. Each of these is unbounded in cost: a single
occurrence in production can undermine the project's credibility
for years. vyre cannot afford a suite that catches "most" bugs.
vyre needs a suite that catches substantially all of them, and
mutation testing is the only mechanism available that grades the
suite on that standard.

There is a second reason mutation testing matters specifically for
vyre. A significant fraction of vyre's tests are authored by
language models — either hand-prompted agents doing scoped
implementation work or generated tests from vyre-conform's
pipeline. Language models are prolific and fast but prone to a
specific failure mode: producing tests that look correct, compile
cleanly, pass on current code, and assert nothing meaningful.
Human reviewers catch some of this, but humans scale sub-linearly
and tire fast. A mutation gate catches it mechanically, at every
commit, forever, without tiring. The gate is the only component of
the pipeline that does not depend on a human being attentive.

## The mutation catalog

vyre's mutation catalog is the committed enumeration of every
mutation the gate knows how to apply. Living in
`vyre-conform/src/mutations/`, the catalog is organized into
classes:

- **Arithmetic mutations** swap arithmetic operators (`+` to `-`,
  `*` to `/`), change constants, and modify wrapping/saturating
  behavior. These catch off-by-one bugs, wrong-operator bugs, and
  overflow handling changes.
- **Comparison mutations** invert or shift comparison operators
  (`<` to `<=`, `==` to `!=`). These catch boundary bugs.
- **Bitwise mutations** swap bitwise operators and modify masks.
  These catch mask-related bugs and bitwise confusion.
- **Control flow mutations** delete branches, invert conditions,
  and modify loop bounds. These catch missing special cases.
- **Buffer access mutations** shift indices, swap reads for writes,
  and weaken atomic ordering. These catch memory access bugs and
  race conditions.
- **IR structural mutations** swap `BinOp` variants in op source,
  change `DataType` in signatures, remove validation rules, swap
  opcode-to-IR mappings, remove bounds checks in lowering, remove
  shift masks. These catch IR-level bugs that simple arithmetic
  mutations would miss.
- **Law mutations** falsely claim laws that do not hold, corrupt
  identity elements, swap distributivity directions. These catch
  lies in the op spec.
- **Lowering mutations** emit the wrong WGSL operator, change
  workgroup size computation, drop bounds checks. These catch
  lowering-level bugs.
- **Constant mutations** change literal values by small amounts or
  to zero. These catch magic-number bugs.

The catalog is not meant to be exhaustive — there are infinitely
many possible mutations — but it is meant to be *representative*
of the kinds of bugs that actually occur in GPU compute
infrastructure. Every entry in the catalog is justified by a real
class of bug, usually one that has appeared historically in some
GPU compiler or runtime.

The catalog grows. Every bug that reaches production in vyre adds
at least one mutation to the catalog. The rule is: if a bug
happened, and the existing catalog would not have caught a
mutation that produces the same bug, then the catalog has a gap
and the gap must be closed. This is the mechanism by which vyre's
test suite learns from its own failures without requiring the
author of the fix to remember to write extra tests.

See [Appendix C](appendices/C-mutation-operators.md) for the
complete current catalog.

## How the mutation gate works

The mutation gate is implemented in
`vyre-conform/src/harnesses/mutation.rs`. Its operation is:

1. Take a source file and a set of tests as inputs.
2. For each mutation in the catalog whose class is declared
   relevant to the source file's op (via `mutation_sensitivity` in
   the OpSpec), apply the mutation to the source.
3. Run the designated tests against the mutated source.
4. Record whether the tests failed (mutation killed) or passed
   (mutation survived).
5. Revert the source.
6. Emit a `GateReport` listing killed and surviving mutations,
   with structured feedback for each survivor.

The gate runs as part of CI. A PR that modifies a test or modifies
source code that a test covers must pass the gate before merging.
A PR that fails the gate is rejected with a list of surviving
mutations — the author knows exactly which classes of bugs their
change failed to catch and can strengthen the relevant tests.

The feedback the gate produces is not generic. It is specific:
"Your test passed when I changed `BinOp::Add` to `BinOp::Sub` in
`src/ops/primitive/add.rs`. Your assertion does not distinguish
these operations. Add an assertion that would fail under this
mutation." An agent or a human can act on this feedback directly,
strengthening the test without guessing what was weak about it.

Structured feedback is a load-bearing design choice. It is what
makes the gate usable as part of an agent-driven contribution
loop. A gate that rejects without feedback teaches the agent
nothing; the agent regenerates a similar wrong test next time. A
gate that rejects with specific feedback about which mutation
survived teaches the agent exactly what was missing, and the next
attempt is strictly better.

## The adversarial mindset

The technique of mutation testing is just the mechanical half. The
other half is a way of thinking about tests that makes mutation
testing natural rather than painful. This is the adversarial
mindset: the habit of reading your own test and asking "what is
the smallest change to the code that would still let this test
pass?"

A contributor in the adversarial mindset writes a test and then,
before committing, mentally runs the mutation catalog. Swap `+`
for `-`: would this test still pass? Invert the condition: would
the test still pass? Delete the branch: would the test still
pass? Each "yes" is a finding before the gate ever runs. Each
"yes" makes the test weaker. The contributor strengthens the test
until every mutation would cause it to fail.

This mindset is the difference between writing tests that feel
correct and writing tests that actually catch bugs. Contributors
who have internalized it produce tests that pass the gate on the
first try. Contributors who have not internalized it produce tests
that need multiple rounds of gate feedback before they converge.
Both converge eventually — the gate is relentless — but the first
group is three times faster.

The same mindset applies when reading other people's tests. A
reviewer looks at a proposed test and asks: what broken
implementation would pass this test? If there is any broken
implementation that would pass, the test is too weak, and the
review flags it before the gate has to. Human review is faster
than gate review (the gate is computationally expensive), so human
review catching weakness early is how the pipeline stays fast.

## Common patterns that the gate catches

After running the gate against thousands of tests, a few patterns
emerge as the most common ways weak tests hide bugs. Each of them
is a specific anti-pattern from Part VI, and each is caught by a
specific class of mutation.

**The weak assertion.** A test that calls vyre code and asserts
`matches!(result, Ok(_))` without checking the Ok value. The test
catches nothing about what the Ok value should be. Killed by any
mutation that changes the Ok value's contents without changing
its type.

**The tautology.** A test whose expected value comes from the code
under test. Killed by any mutation, because the expected value
changes with the code and the assertion always passes. (The gate
handles this specially: it detects tautologies by checking whether
the expected expression transitively calls the subject under test.)

**The missing branch.** A test for `BinOp::Add` that checks the
happy path but not the overflow case. Killed by a constant mutation
that changes the wrapping behavior — the happy-path test still
passes, but a dedicated overflow test would have failed.

**The missing mutation kill.** A test that exercises `BinOp::Add`
but would still pass if `Add` were changed to `Sub`. Killed by
the `ArithOpSwap` mutation. This is the most common finding, and
the fix is always "write a test that uses an input where `Add` and
`Sub` produce different results."

**The missing law.** An op that declares commutativity but no test
would detect a non-commutative implementation. Killed by the
`LawFalselyClaim` mutation. The fix is a test asserting the law
on specific inputs.

**The missing bounds check.** A lowering that emits a buffer
access without a bounds check, passing all correctness tests on
in-range inputs. Killed by the `LowerRemoveBoundsCheck` mutation
applied to a test that provides an out-of-range input. The fix is
an adversarial test.

Every finding is actionable. Every fix is mechanical. The gate
turns "my tests might be weak" into a concrete list of mutations
to handle, one at a time, until the list is empty.

## What mutation testing is not

Mutation testing does not prove the code is correct. It proves the
test suite catches a specific enumerated set of mutations. If the
catalog is missing a class of mutation, the suite can have a gap
for that class and still pass the gate. The catalog is the limit
of what the gate can catch.

Mutation testing does not prove the test suite is complete. A
suite that kills every mutation in the catalog can still miss
untested subjects entirely. The gate complements coverage testing;
it does not replace it.

Mutation testing does not prove the specification is correct.
If the spec says "Add wraps on overflow" and a test asserts the
wrapping behavior, and the implementation correctly wraps, and the
gate kills every relevant mutation, the test suite is consistent
with the spec. If the spec is wrong ("Add should saturate"), the
suite is not going to notice. Spec bugs are caught by review and
by user feedback, not by the gate.

Mutation testing is expensive. Running the full catalog against a
full suite takes substantial wall-clock time, because each mutation
requires a full compile-and-run cycle. vyre manages this expense
through caching (`layer8_feedback_loop.rs`), incremental runs (only
touching tests and sources changed in the current PR), and
parallelism (multiple mutations run simultaneously on separate
target directories). Even with these optimizations, the gate
takes seconds to minutes per PR. The cost is real and the cost is
worth it.

Mutation testing does not substitute for human judgment. Humans
are still responsible for deciding which oracles to use, which
archetypes apply, which tests are worth writing in the first
place, and which tests to delete when the suite has too many. The
gate enforces the floor; humans set the ceiling.

## Running the gate locally

To run the mutation gate on a test you are writing, with the
default mutation classes for the op you are testing:

```bash
cargo xtask mutation-gate --op add --tests tests/integration/primitive_ops/add.rs
```

The output lists killed and surviving mutations. Surviving
mutations come with structured feedback. Iterate the test until
the feedback is empty.

For a full-suite run, which is what CI does:

```bash
cargo xtask mutation-gate --all
```

This runs every test in the suite against every relevant mutation.
Expensive but periodic. See [Mutation testing at
scale](advanced/mutation-at-scale.md) for the caching discipline
that makes this practical.

## The gate is the floor

The gate sets the minimum quality a test must meet. It does not
set the maximum. A test that passes the gate is not automatically
a good test; it is a test that is not trivially bad. A strong test
goes beyond gate-passing by using the strongest applicable oracle,
by having a clear subject and property declaration, by using
specific inputs from the archetype catalog rather than random
inputs, and by reading well to a human who will encounter it five
years from now.

The gate ensures the floor. Discipline ensures the ceiling. This
book is how we teach the discipline, and Part VII is how we enforce
it.

Next: [Archetypes — the shapes of bad inputs](archetypes.md).
