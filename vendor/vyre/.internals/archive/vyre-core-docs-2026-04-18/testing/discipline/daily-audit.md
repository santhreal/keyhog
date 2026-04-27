# The daily audit

## Why the audit exists

A test suite can pass every review, kill every mutation, and
still drift. Drift happens in small ways that no single review
catches: a new test that passes the checklist but sits at the
weaker end of its category; a helper that started clear and
accumulated edge cases; a regression test whose symptom
description has aged out of recognition; a proptest generator
that gradually stopped producing adversarial inputs. Each
individual change is acceptable. Collectively, the drift
accumulates until the suite is weaker than it was a year ago
and nobody noticed when.

The daily audit is the mechanism that catches drift. Every
day, someone reads ten random tests from the suite and
evaluates them against the current standard. Tests that fail
the audit are either strengthened or deleted. The audit is not
bug-hunting; it is calibration. It keeps the suite honest
against its own standard in a way that review cannot, because
review is focused on the current PR, and drift happens across
PRs.

This chapter describes the daily audit: what it is, why it is
non-optional, and how to do it.

## The rule

Every day, every working day, ten random tests are read and
evaluated against [the review checklist](review-checklist.md).
If any of the ten tests fail the checklist in a way that is
not immediately obvious as acceptable, the test is flagged. The
flagged tests are either strengthened (by writing a better
version and replacing the old) or deleted (if the old version
is not worth saving).

Ten is the number. Not five, not twenty. Ten is enough to see
trends over a month; five is noise; twenty is more work than
the audit warrants.

## How to run the audit

The audit is a script plus a human. The script selects ten
random tests from the suite and prints their file paths and
function names. The human reads each test and applies the
checklist.

```bash
cargo xtask audit-tests
```

The xtask command runs a random selection algorithm that
weights tests equally across categories (so the audit does not
over-sample the largest category). It prints the ten selected
tests in a format suitable for copying into a review document.

For each test, the auditor:

1. Opens the file and reads the test.
2. Runs through the eleven checklist items.
3. Records the result: PASS, FAIL, or UNCLEAR, with a note.
4. At the end of the ten, reviews the notes and decides what
   action to take on each FAIL or UNCLEAR.

The whole process takes fifteen to thirty minutes per day. The
cost is small; the calibration is significant.

## What "failing the audit" looks like

A test might fail the audit for any of the checklist reasons:

- The oracle is weaker than the strongest applicable.
- The test is a tautology that reviewers missed.
- The test name is generic in a way that hurts navigability.
- The test has drifted into kitchen sink territory (was split
  fine originally, has accumulated assertions).
- The test uses a helper that obscures intent.
- The proptest has a stale regression corpus.
- The test's doc comment does not match what the test does.

Each failure is a finding. The audit does not fix failures on
the spot; it records them and prioritizes them. At the end of
the audit session, the findings are filed as issues or as PRs
that fix the flagged tests.

## What "passing the audit" looks like

Most tests pass the audit. A test that follows the conventions
from earlier chapters is usually in good shape: it has an
oracle declaration, a clear name, a specific assertion, and no
anti-patterns.

When a test passes, the auditor records PASS with no note, and
the test is not touched. The test remains in the suite,
exercising its property, contributing to the overall
discipline.

## What the audit achieves over time

Over weeks and months, the audit produces:

- **A running count of tests that needed fixing.** If the
  count trends up, the review process is letting more through
  and needs strengthening. If the count trends down, the review
  process is catching most issues and the audit is a safety
  net.
- **A list of common drift patterns.** If many failing audits
  cite "stale proptest regression corpus," the project needs a
  better way to keep those fresh. If many cite "kitchen sink,"
  reviewers need a refresher on the split discipline.
- **A culture of quality.** Contributors who know the audit
  runs every day internalize the discipline because they know
  their tests will be read eventually. A tautology slipped past
  review is still a tautology; the audit catches it before it
  ages.

These are emergent effects. The audit's direct purpose is to
catch specific drifted tests, but its indirect purpose is to
shape the project's culture around tests.

## What the audit is not

The audit is not a bug hunt. The auditor reads tests for
discipline, not for bugs in the code being tested. If the
audit discovers a bug (a test that is wrong in a way that lets
a real code bug through), the bug is filed as a separate
issue. The audit's focus is the test, not the production code.

The audit is not a review replacement. Reviews happen on every
PR; the audit happens on tests in the suite regardless of when
they were added. The audit catches drift across PRs. The
review catches issues in a specific PR. Both are needed.

The audit is not a witch hunt. Tests that fail the audit are
flagged, not dismissed as bad work. Flags become fixes, not
blame. The contributor who wrote the test originally may not
even be on the project anymore; the audit does not care who
wrote the test, only whether the test meets the current
standard.

## Who does the audit

In small projects, one person rotates through the audit
duty — a different person each day or each week. In larger
projects, the audit is a shared responsibility with a rotating
schedule tracked in a document.

vyre's audit is documented in the project's operational notes
(not in this book, because the specifics change). The rule is
that the audit happens every working day, and the person on
audit duty is accountable for running it. If the audit is
skipped, it is logged, and a makeup audit runs the next day.

If the audit is skipped for more than a few days in a row, the
skip itself is a finding. The discipline of running the audit
daily is part of what keeps the suite honest. Gaps in the
audit schedule are tracked and explained.

## The audit and the mutation gate

The audit reads tests and evaluates them qualitatively. The
mutation gate runs tests and grades them mechanically. Both
tools catch different issues:

- The mutation gate catches tests that do not kill specific
  mutations. It cannot tell whether the test is a tautology
  that would survive mutation because the tautological
  expected value changes with the mutation. (Tautologies
  often do survive their own mutations.) It cannot tell
  whether the test name is bad.
- The audit catches tests that look wrong to a human reader.
  It cannot tell whether the test kills mutations; that is the
  gate's job.

Together, the audit and the gate cover each other's blind
spots. The gate is run constantly in CI. The audit is run
daily by a human. Both are essential.

## Summary

The daily audit reads ten random tests every day and evaluates
them against the review checklist. Tests that fail are
strengthened or deleted. The audit catches drift that reviews
miss and shapes a culture of test discipline. It is
non-optional, logged if skipped, and rotates among project
members. Together with the mutation gate, it keeps the suite
honest over time.

Next: [Seed discipline](seed-discipline.md).
