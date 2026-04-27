# The regression rule

## The rule, stated plainly

Files in `tests/regression/` are never deleted. When a file
in `tests/regression/` starts failing, the bug it records has
returned. The fix is to the code, not to the test. The
regression file stays; the code is changed to make it pass
again.

This is the rule. It has no exceptions worth defending in a
hurry. The rule exists because the alternative — letting
contributors delete regression tests — is how bugs quietly
return to production.

This chapter explains why the rule is so strict, what the
narrow exceptions look like, and how to apply the rule when
you are the one tempted to delete.

## Why the rule is strict

A regression test exists because a bug existed. The bug was
reported, diagnosed, fixed, and committed along with a test
that reproduces the bug. The test was not written speculatively;
it was written after the bug occurred, from the bug's actual
input. The test's presence is what ensures the fix stays stuck.

If the test is deleted, the guarantee that the fix stays stuck
is also deleted. Maybe the fix still holds and the test is
redundant with some other coverage. Maybe the fix does not
hold and deleting the test hides the fact. From outside the
code, the two cases look identical: the regression file is
gone, the suite is slightly smaller, everything else looks
the same.

The danger is that tests get deleted for comfort, not for
correctness. A contributor refactoring a module sees that a
regression test fails after their refactor. The obvious fix is
to update the test to match the new behavior. But that is
exactly the wrong move: the test failed because the refactor
changed the behavior that the regression was meant to preserve,
which means the refactor is unsafe. The right move is to
preserve the behavior in the refactor, or to reject the
refactor.

Without the rule, contributors take the easy path: delete or
edit the failing regression. The bug returns silently. Users
experience it. Trust in the suite erodes.

With the rule, contributors take the right path: fix the code
so the regression passes. The bug stays caught. Trust in the
suite grows.

## Narrow exceptions

The rule is "never delete" with two narrow exceptions. Each
requires explicit justification and review.

### Exception 1 — The bug was a misunderstanding

If a regression test was added for what seemed to be a bug but
was actually correct behavior misinterpreted, the test can be
removed. This is rare — bugs are usually bugs — but it does
happen, particularly for subtle floating-point cases or for
behaviors that turned out to be specified but not widely
understood.

The removal requires:

- A PR description explaining the misunderstanding: what was
  originally thought to be wrong, why that was wrong, what the
  actual correct behavior is, and why the regression test is
  no longer valid.
- A review that confirms the misunderstanding. At least one
  reviewer other than the contributor.
- An update to any documentation or spec that was based on
  the misunderstanding.
- The deletion itself, in a PR dedicated to the deletion (no
  unrelated changes).

The deletion is highly visible. Future readers of the git
history see the PR and can understand why the regression was
removed. The explanation is preserved in the commit message
and PR description.

### Exception 2 — The regression's preconditions no longer exist

If the bug was in code that has been entirely rewritten —
not refactored, but replaced — and the regression test can
no longer be built because the types it used are gone, the
test can be migrated to a new form that exercises the same
symptom on the new code.

"Migrated" means the old file is deleted and a new file is
added. The new file records the same bug's symptom, root
cause, and original fix, plus a note that the test has been
migrated and the old code is gone. The bug's history is
preserved; only the implementation of the test changes.

Migration requires:

- A PR that both deletes the old file and adds the new one.
  The deletion and the creation are atomic.
- A description explaining why migration was necessary and
  why a simple edit would not work.
- The new file's header comment mentions the migration and
  includes the original bug's date.

Migration is rare. Most "the code has been rewritten" cases
actually preserve enough structure that the regression test
can be adjusted rather than replaced. The migration exception
is reserved for cases where the adjustment would require
completely rewriting the test, at which point deleting and
recreating is honest.

## What is not an exception

Some things that look like exceptions but are not:

**"The test is redundant with other coverage."** A regression
test that duplicates coverage is fine. Redundancy in the
regression directory is defensive, not wasteful. The direct
regression test catches the specific bug; the general test
catches a class that includes the bug. Both are valuable; both
stay.

**"The test is slow."** A slow regression test is a
regression test that works. If it is truly too slow to run on
every CI invocation, mark it `#[ignore]` and run it in nightly
CI. Do not delete it.

**"The test is ugly."** Aesthetic complaints are not
justifications for deletion. A regression test does not have
to be beautiful; it has to be correct. If the test is
genuinely unreadable, rewrite the internals (preserving the
minimal reproducer and the assertion) in a follow-up PR, but
do not remove the file.

**"The test fails and I cannot figure out why."** A failing
regression test is a bug. Debug the bug. Do not delete the
test to make CI green. If the investigation is long, file an
issue, mark the test `#[ignore]` temporarily with a clear
comment and a link to the issue, and come back to it.
`#[ignore]` with a comment and a filed issue is a pause, not
a deletion.

**"The test is from before the current architecture."** If the
current architecture is compatible with the test's intent, the
test still applies, even if the mechanics have changed. Update
the test's internals to work with the new architecture; keep
the header comment and the assertion. If the architecture is
incompatible, use exception 2 (migration).

## How to handle a failing regression

Step-by-step, when a regression test fails:

1. **Do not rush to make the test pass.** The test failing is
   the signal that something changed. Before investigating the
   test, assume the code is wrong.
2. **Read the regression's header comment.** Understand the
   original bug: symptom, root cause, fix.
3. **Check what changed.** What PR introduced the failure? Is
   the change related to the original bug's area? If yes, the
   change likely regressed the bug and must be fixed.
4. **Reproduce locally.** Run the test on your machine with
   the latest code. Confirm the failure. Read the diff
   between the failing output and the expected.
5. **Diagnose.** Is the code wrong or is the test wrong? If
   the code produces the wrong value, the code is wrong. If
   the code produces the right value but the test expected a
   different value, the test might be wrong (but only if the
   original bug's fix is still correct under the new rules).
6. **Fix the code, preserving the regression.** The usual
   path: the code is wrong; update the code so the regression
   passes again. Commit the fix along with a note on the PR
   explaining what was broken.
7. **If the test itself is wrong** (exception 1 or 2), apply
   the exception rules from above. Remove or migrate the test
   with explicit justification in a dedicated PR.

The default path is step 6: fix the code. The exceptional path
is exceptions 1 or 2: explicit justification for removal or
migration. In practice, step 6 is chosen over 90% of the time.

## Regression tests and the review checklist

A PR that touches a file in `tests/regression/` is scrutinized
extra carefully by reviewers. The checklist's item 10
("the test is not a known anti-pattern") gains a sub-item:
"the PR does not delete a regression test without exception 1
or 2 justification."

If the PR deletes a regression test and the justification is
not clearly one of the exceptions, the PR is rejected until
either the deletion is reverted or the justification is
strengthened. The strict stance is the point.

## The cumulative value of the regression directory

Over time, the regression directory becomes the compressed
history of every bug vyre has caught. It is the most valuable
directory in the test suite, not because any individual
regression test is important, but because the collection is
the project's institutional memory for past failures.

A new contributor can read the regression directory and see
what kinds of bugs vyre has experienced. A maintainer
debugging a new issue can search the directory for similar
symptoms. A security reviewer can use the directory to
understand vyre's historical failure modes. The directory is
documentation in the most useful form: code that runs.

The rule's strictness is what makes the cumulative value
possible. A directory where files can be deleted at will is a
directory that shrinks over time. A directory where files are
never deleted is a directory that grows monotonically, and
the growth is the value.

## Summary

Files in `tests/regression/` are never deleted. The two
narrow exceptions (misunderstanding and migration) require
explicit justification and dedicated PRs. Failing regression
tests are fixed in the code, not in the test. The strict rule
prevents regressions from returning silently and builds the
project's institutional memory for past failures.

Next: [Flakiness](flakiness.md).
