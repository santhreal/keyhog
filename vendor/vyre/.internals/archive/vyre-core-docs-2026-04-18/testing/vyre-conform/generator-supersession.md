# When the generator supersedes you

## The migration criterion

The two-tier model of vyre's test suite allows hand-written
tests to be replaced by generated tests when the generator
has proven it can produce strictly stronger coverage for the
op in question. The replacement is called migration. This
chapter is about the criterion for migration, the process of
performing it, and the things to be careful about.

Migration is not automatic. It does not happen just because
the generator has grown new archetypes or new oracles.
Migration is a specific decision, made per op, after
evidence shows the generator's output for that op is at
least as strong as the hand-written tests plus strictly more.
The decision is a PR with a specific justification and a
review.

Why be careful? Because a wrong migration silently weakens
the suite. The hand-written tests are deleted; the generated
tests take over; nobody notices immediately that the
generator was missing something the hand-written set
covered. Months later, a bug that the hand-written set would
have caught reaches production, and the post-mortem reveals
the migration was the root cause.

The care is the price of moving responsibility from humans
to machines. Done carefully, migration reduces the
maintenance burden and scales the suite. Done carelessly, it
is a quiet quality regression.

## The criterion

The generator's output for an op supersedes the hand-written
tests when all of the following hold:

1. **Mutation kill parity plus more.** Every mutation killed
   by the hand-written set is also killed by the generated
   set, plus at least one additional mutation the
   hand-written set did not kill.
2. **Variant coverage parity plus more.** Every IR variant
   exercised by the hand-written set is exercised by the
   generated set, plus at least one additional variant.
3. **Input coverage parity plus more.** Every specific
   input tested by the hand-written set has an equivalent
   in the generated set, plus at least one additional
   input.
4. **Oracle parity plus strength.** Every oracle used by the
   hand-written set is used by the generated set, and the
   generator does not downgrade any oracle (using a weaker
   one where a stronger was available).
5. **No override tests.** The hand-written set contains no
   tests marked as overrides (tests that catch bugs the
   generator does not know about).

All five conditions must hold simultaneously for the
migration to proceed. Missing any one is a veto.

The first four conditions are mechanical: they can be
checked by running both suites and comparing the metrics.
The fifth is human: an override test is tagged explicitly by
its author, and the tag is a signal that the test should
not be migrated.

## The migration process

When the criterion holds for an op, migration proceeds as
follows:

### Step 1 — Verify the criterion

Run both suites with full instrumentation and compare:

```bash
cargo xtask compare-coverage --op add
```

The command reports:
- Mutations killed by hand-written set.
- Mutations killed by generated set.
- Variants exercised by each.
- Specific inputs covered by each.
- Oracle distribution across both.
- Override tests present (if any).

A successful comparison shows the generated set strictly
exceeding the hand-written set on every axis. If the report
shows any gap, migration is blocked until the gap is closed.

### Step 2 — Write the migration PR

The PR deletes the hand-written tests for the op from
`vyre/tests/integration/primitive_ops/<op>.rs` (or
significantly shrinks the file, keeping only override tests).
The commit message includes the comparison output from step
1 as evidence.

```
migrate(tests/primitive_ops/add): replace hand-written with generated

The generated tests for BinOp::Add from vyre-conform now strictly
exceed the hand-written tests on every axis:
  - Mutations killed: hand-written 47/47, generated 53/53
  - Variants exercised: hand-written 5, generated 12
  - Specific inputs: hand-written 15, generated 247
  - Oracle strength: both use spec_table and laws; generator
    does not downgrade any oracle.
  - No override tests in the hand-written set.

The hand-written tests in tests/integration/primitive_ops/add.rs
are deleted. The generated tests in
vyre-conform/tests_generated/primitive_ops/add/ take over.
```

### Step 3 — Review the migration

The reviewer checks:

- The comparison output is accurate and complete.
- The deleted tests do not include any that the reviewer
  recognizes as carrying unique intent (override tests that
  were not tagged).
- The generated tests for the op actually run in CI and
  pass.
- The criterion is met in both directions: the generated
  set does not weaken any coverage, just adds.

A reviewer who sees a concern can request keeping specific
hand-written tests with override tags. The contributor marks
the tests and the PR proceeds with the rest of the
migration.

### Step 4 — Merge

The PR merges. The op's hand-written tests are gone; the
op's generated tests take over. CI runs both tiers on every
commit, and the generated tests for the op are now the
source of coverage.

### Step 5 — Monitor

After the migration, the op's coverage is monitored for
regression. The mutation gate runs on both tiers on every
commit; if a previously-killed mutation starts surviving, the
monitoring catches it immediately.

If a regression happens, the fix is either to update the
generator to produce the missing coverage, or to re-add a
hand-written test with an override tag. Migration is not
irreversible; if the generator turns out to have a gap, the
hand-written tests can come back.

## Why some ops never migrate

Some ops have hand-written tests that the generator cannot
reproduce. These are usually tests that:

- **Exercise a specific historical bug.** The test is a
  regression test for a specific input that the generator
  would not know to hostilize. These tests live in
  `tests/regression/`, not in `tests/integration/primitive_ops/`,
  so they are outside the migration scope anyway.
- **Exercise an unusual composition.** A test that combines
  the op with other ops in a specific shape that the
  generator's archetypes do not cover. These can be
  migrated if the archetype is added to the generator; until
  then, they stay hand-written.
- **Exercise a recently-discovered edge case.** A test
  written in response to a recent bug, before the
  generator's knowledge has been updated. Usually
  short-lived as override tests; migrated once the generator
  catches up.

These cases are minority. For most primitive ops, the
generator eventually provides full coverage and migration
proceeds.

## Tracking which ops have migrated

The migration status of each op is tracked in a document
(usually `vyre-conform/MIGRATION_STATUS.md` or similar).
The document lists each op and its status:

- **Hand-written only** — the op has only hand-written
  tests; the generator does not yet produce superseding
  tests.
- **Both tiers** — the op has both hand-written and
  generated tests; migration has not happened.
- **Generated + overrides** — the op has been migrated; the
  generated tests are the primary, and a small number of
  override tests remain hand-written.
- **Generated only** — full migration; no hand-written
  tests for the op.

New ops start at "hand-written only" (no generated tests
yet). As the generator matures, ops move toward "generated
only." The document is updated per migration PR.

## The reverse case — un-migration

If a migration turns out to be premature (the generator
had a gap that was not caught during the comparison), the
op can be un-migrated. The un-migration PR restores the
hand-written tests (from git history or from scratch) and
adds override tags to prevent future re-migration without
careful review.

Un-migration is rare but possible. The existence of the
option is what makes migration safe: mistakes can be fixed
without a permanent quality loss.

## The generator's growth, and when migration becomes possible

A new op starts life as hand-written only: a contributor
authors the suite per the worked example in Part IV, and the
generator does not yet produce any tests for the op. The
contributor proves the op works with specific-input tests,
law tests, archetype instantiations, and cross-backend
checks. This is the baseline.

Over time, as the generator's infrastructure matures, it
learns to produce the kinds of tests the contributor wrote
by hand. The mutation gate runs across both tiers, and the
generator's output gradually catches up to the baseline.
When the generator's output strictly exceeds the baseline,
migration becomes possible.

The typical timeline for an op:

- **Day zero:** hand-written only. Contributor writes the
  suite for the op; the generator produces nothing.
- **Months later:** both tiers. The generator's
  infrastructure catches up; it now produces some tests for
  the op but not enough to supersede.
- **A year later:** both tiers, generator strictly
  exceeding. Migration is possible; the PR is written and
  reviewed.
- **Migration:** generated + overrides. The hand-written
  tests are deleted except for any overrides.
- **Steady state:** the op is maintained via the generator
  and the spec. New coverage comes from spec updates, not
  from hand-written test additions.

The timeline is not a schedule; it is a trajectory. Each op
moves along the trajectory at its own pace, driven by how
complex the op is and how much the generator has learned.
Some ops take years to migrate; some migrate faster. Both
are fine as long as the criterion is met before migration.

## Summary

Migration moves an op from hand-written to generated tests
when the generator's output strictly exceeds the
hand-written baseline on every axis. The process requires a
PR with a comparison report, a review, a merge, and
subsequent monitoring. Some ops never migrate because they
have override tests the generator cannot produce.
Un-migration is possible if a mistake is found. The
criterion is strict because wrong migration silently weakens
the suite.

Next: [What the generator will never replace](never-replaced.md).
