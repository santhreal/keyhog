# What the generator will never replace

## Some tests are permanent

The previous chapter described migration: the process by
which hand-written tests for primitive ops are replaced by
generated tests when the generator's output strictly
exceeds the baseline. Migration moves responsibility from
contributors to the generator.

There are categories of tests where migration never happens
and never will. These are the tests that live in the
hand-written tier permanently. The categories exist because
the generator cannot produce the kinds of tests they
contain — not because of a temporary limitation in the
generator's capabilities, but because the nature of the
tests is fundamentally human-authored.

This chapter is about those categories: what they are, why
the generator cannot replace them, and what the permanence
means for vyre's maintenance model.

## Regression tests

Every fixed bug in vyre has a regression test in
`tests/regression/`. The file is named by date and
description, has a header recording the bug's symptom and
root cause, and contains the minimal reproducer as the test
body.

The generator cannot produce regression tests because it
cannot know which bugs have occurred. A bug is a historical
event: someone reported it, someone debugged it, someone
fixed it. The test is the record of that event. The
generator works from the current specification, not from
historical events, so it has no way to recreate the tests
that commemorate specific past failures.

Regression tests are permanently hand-written. They
accumulate monotonically. They are never deleted. They form
the compressed history of every bug vyre has caught, and
the history is not reproducible from the specification.

If a regression test covers behavior that the generator also
happens to cover, that is fine — the duplication is
intentional. The regression test catches the specific bug;
the generator's test catches the general class. Both are
valuable; neither replaces the other.

## Adversarial tests for specific incidents

Some adversarial tests commemorate specific incidents: a
crash reported by a user, an input that caused a panic in a
specific environment, a corner case discovered by a specific
tool. These tests look like ordinary adversarial tests —
hostile inputs, "did not panic" assertions — but they are
specific in a way that the generator's archetype-based
adversarial generation is not.

The generator can produce adversarial tests from the
archetype catalog (deeply nested programs, resource bombs,
malformed wire-format patterns). It cannot produce the specific
input that crashed vyre in a user's production environment
three months ago. That input lives in `tests/adversarial/panic_probes.rs`
as a permanent record.

These tests are hand-written forever. They grow as new
incidents happen; they never shrink.

## Property invariants with tailored generators

Property tests can be partially automated — the generator
can produce property tests for standard invariants with
standard generators. What it cannot do is produce property
tests whose invariants are specific to a subsystem and
whose generators are tailored to stress that subsystem.

For example: a property test for vyre's wire-format round-trip
identity is straightforward to generate. The invariant is
"for all valid Programs, encode-then-decode is identity,"
and the generator is `arb_program()`. Both are mechanical.

A property test for vyre's handling of workgroup memory
access patterns under high contention is not straightforward
to generate. The invariant is "for all Programs that use
workgroup memory with contended access, the result is
deterministic within scheduling variation." The generator
must produce Programs that specifically stress workgroup
memory contention, which is a tailored generator, not a
generic `arb_program()`. The author of the test has to think
about what "contended access" means and write a generator
that produces it.

These tests are hand-written forever, or at least until the
generator grows the ability to recognize "tailored
generator" as a specific output kind — which is not
currently planned and is not a priority.

## Benchmarks

Benchmarks are not correctness tests; they are performance
measurements. The generator produces correctness tests, not
benchmarks. Performance-focused tests use criterion, measure
wall-clock time, and compare against baselines.

Benchmarks are hand-written because the decisions they
encode are about what to measure: "how fast is dispatch for
a standard Program?" "How fast is validation for a
thousand-node Program?" "How fast is wire format encoding for a
canonical corpus?" These are human decisions about what
performance matters to vyre's users. The generator does not
have visibility into user performance requirements.

Benchmarks are permanently in `tests/benchmarks/`. They are
updated as vyre's performance targets evolve.

## Integration tests for specific subsystems

Some integration tests exercise specific subsystems in ways
that the generator does not cover. For example:

- **Tests that exercise a specific runtime configuration.**
  A test that runs with a specific feature flag, a specific
  backend combination, or a specific environmental setting
  is not producible from the specification alone.
- **Tests that stress the interaction between two
  subsystems.** A test that verifies the validator and the
  lowering agree on a specific case is exercising a
  cross-subsystem interaction that the generator does not
  model.
- **Tests that capture the result of a recent design
  decision.** A test added to pin down a specific behavior
  that a design review decided on is a human intent, not a
  spec derivation.

These tests sit in `tests/integration/` and are maintained
by contributors. They are in the gray zone — the generator
might eventually produce some of them, but not all, and the
ones it does not produce stay hand-written.

## Worked examples

The worked example for `BinOp::Add` in Part IV of this book
is a complete test suite for one op, with every decision
explained. The worked example has a didactic purpose: it is
what a new contributor reads to learn how to write tests for
vyre.

The worked example's tests are in `tests/integration/primitive_ops/add.rs`
and are hand-written because their purpose is to serve as
an instance of the process, not to provide unique coverage.
A contributor who follows the worked example to add tests
for a new op produces tests that look like the example.

The generator could produce functionally equivalent tests,
but the worked example's tests stay hand-written because
their value is educational. Deleting them would remove the
reference that contributors learn from.

## Override tests

Override tests are hand-written tests that catch bugs the
generator does not know about. They are tagged explicitly
so the migration process leaves them in place when an op's
other tests are migrated.

Override tests are created when:

- A bug is found that none of the existing archetypes
  would have caught.
- A contributor discovers a specific adversarial input the
  archetype catalog does not cover.
- The generator's output for an op is close to superseding
  the hand-written set but is missing a specific case the
  author wants to preserve.

Overrides can eventually be "promoted": when the generator
learns to produce an override's equivalent (by gaining a
new archetype or a new oracle), the override is dropped and
the equivalent generated test takes its place. The timing
is case-by-case.

## The maintenance model

Given these categories, vyre's test suite maintenance model
is:

- **Primitive op tests:** start hand-written; migrate to
  generated when the criterion is met. Overrides stay.
- **Integration tests for subsystems:** hand-written,
  possibly with some generation support; reviewed
  individually.
- **Validation tests:** start hand-written; the generator
  produces variants as the spec evolves, but the separability
  meta-test and per-rule must-reject/must-accept pairs stay
  hand-written.
- **Lowering tests:** the exhaustiveness meta-test forces
  new variants to have tests, which are hand-written
  initially; the generator produces coverage over time.
- **Wire format tests:** hand-written per wire tag; the generator
  produces round-trip property tests.
- **Adversarial tests:** mix of archetype-generated and
  incident-specific; incidents stay forever.
- **Property tests:** mix of standard and tailored; tailored
  stay forever.
- **Backend tests:** mix of generated and specific-case;
  specific cases for hard backend interactions stay
  hand-written.
- **Regression tests:** always hand-written, never deleted.
- **Benchmarks:** always hand-written.
- **Support utilities:** always hand-written.
- **Worked examples:** always hand-written for didactic
  value.

The model is stable. Changes to it happen through PRs against
this book, not through ad-hoc decisions.

## Why permanence matters

Permanent hand-written tests are the anchor that keeps the
suite from becoming fully automated. A fully automated suite
sounds appealing — no human maintenance, no contributor time
spent on tests, no review burden — but it has a failure
mode: when the automation has a gap, the suite has a gap,
and there is no human-authored backstop to catch what the
automation misses.

The permanent hand-written tests are the backstop. They are
not numerous, but they cover the cases where human judgment
is the only authority: "this specific bug must never return,"
"this specific adversarial input must not crash vyre," "this
specific performance must not regress." Automation can
amplify the suite's reach but cannot replace the backstop
entirely.

## Summary

Some categories of tests are permanently hand-written and
will never be replaced by the generator: regression tests,
specific adversarial incidents, tailored property tests,
benchmarks, some integration tests, worked examples, and
override tests. The generator amplifies the suite's reach
over the combinatorial space of primitive op correctness,
but the permanent hand-written categories are the backstop
that preserves institutional knowledge and catches bugs the
generator cannot anticipate.

Next: [Contribution flow](contribution-flow.md).
