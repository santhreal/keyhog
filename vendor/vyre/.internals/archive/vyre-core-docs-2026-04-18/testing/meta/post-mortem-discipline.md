# Post-mortem discipline

## When a bug reaches production

A bug reaches production. A user reports that vyre produced
wrong output for their program, or crashed on a specific
input, or silently drifted between backends. The bug is
confirmed, the code is fixed, the fix is committed. The
user is satisfied. The immediate incident is resolved.

What happens next is where vyre's testing discipline is
either validated or exposed. A project without post-mortem
discipline declares victory at the fix and moves on. A
project with discipline asks: why did the suite not catch
this, and how do we prevent the same class of bug from
slipping through again?

This chapter is about that second question. Post-mortem
discipline is how vyre learns from its bugs. Every bug that
reaches production is a failure of the suite as well as of
the code; both failures are worth examining, and both have
follow-up actions that improve the project's long-term
quality.

## The post-mortem ritual

For every bug that reaches production, vyre runs a
post-mortem. The ritual has these steps:

### Step 1 — Record the bug

The bug is documented with:

- A date.
- A symptom description (what the user experienced).
- A root cause description (what was actually broken).
- The fix (which commit, what it changed).
- A minimal reproducer.

This is the same information that goes into the regression
test header. The regression test is step 2.

### Step 2 — Add the regression test

A regression test is added to `tests/regression/` with the
minimal reproducer. The test would have failed before the
fix; it passes after the fix. This is the primary
protection against the specific bug returning.

Step 2 is non-negotiable. A bug fix without a regression
test is incomplete. PRs that fix bugs without adding
regressions are rejected at review.

### Step 3 — Ask why the suite missed it

The post-mortem's central question: why did the test suite
not catch this bug before it reached production?

Possible answers:

- **The specific input was not covered.** The suite exercised
  the subject, but none of the tests used this particular
  input. Action: add the input to the spec table, the
  archetype catalog, or the fuzz corpus.
- **The subject was not covered.** The code path involved
  had no tests. Action: add tests for the code path.
- **The oracle was too weak.** The tests exercised the
  subject but asserted only a weak property that did not
  distinguish correct from broken behavior. Action:
  strengthen the oracle.
- **The mutation was not in the catalog.** The bug
  corresponds to a class of mistake the mutation gate does
  not know about. Action: add the mutation class to the
  catalog.
- **The archetype was not in the registry.** The bug's
  input shape was not known to the archetype catalog.
  Action: add the archetype.
- **The invariant was not tested.** The bug violated an
  invariant that the suite had no direct test for. Action:
  add a property test for the invariant.

Each answer has a corresponding action. The post-mortem's
output is a list of actions, not just a single regression
test.

### Step 4 — Implement the actions

The actions from step 3 are implemented. This might mean
adding new entries to catalogs, updating oracles, adding
new test categories, or modifying the generator. Each
action is its own PR, linked to the post-mortem issue.

The scope of step 4 can be large. A single bug might
require several actions that take days to implement. The
cost is worth it because the actions collectively prevent
not just the specific bug but the class of bugs the
original was part of.

### Step 5 — Verify the suite would now catch it

After implementing the actions, verify that the suite
would now catch the specific bug. The verification is:

- Revert the fix on a branch.
- Run the suite.
- Confirm the suite fires on the now-re-introduced bug.
- Revert the revert; the fix stays.

The verification is the proof that the post-mortem actions
worked. A post-mortem that does not verify is a post-mortem
that might have missed something.

### Step 6 — Share the lessons

The post-mortem document is written up and shared with the
team. The write-up includes the chronology, the root cause,
the actions taken, and the lessons learned. The point is
not blame; it is for everyone to learn from the incident
and to know what to look out for in the future.

## The mutation catalog grows from post-mortems

The most common post-mortem output is a new mutation class
in the catalog. Every bug is an implicit mutation: the
correct code was changed in some specific way to produce
the bug. If the mutation gate had known about that specific
way, it would have applied it to the source and verified
that at least one test would catch it.

The rule: every bug adds a mutation class (or confirms an
existing one), unless the bug is clearly not amenable to
mutation-style representation (in which case it adds an
archetype or an invariant test).

Over time, the mutation catalog grows from post-mortems.
Each entry is justified by a real bug. The catalog is not
speculative; every entry has a story.

## The archetype catalog grows from post-mortems

The second most common output is a new archetype. If the
bug was caused by a specific input shape that the existing
archetypes did not cover, the shape becomes a new archetype.
Future tests for similar ops will instantiate the archetype
automatically.

The same rule: every bug adds an archetype or confirms an
existing one. The catalog grows monotonically, and each
entry is justified.

## The invariants grow from post-mortems

Rarely but significantly, a post-mortem reveals an
invariant that was implicit but not stated. "The Program
should behave consistently across backends" was an implicit
invariant before it became I3. "Validation should never
cause a panic in lowering" became I5 after a specific bug
showed the implicit assumption was being violated.

When a post-mortem reveals a new invariant, the invariant
is added to the formal catalog (I1..I15 and any additions).
The spec doc is updated. The invariants catalog in this
book gets a new entry. New property tests are written to
verify the invariant.

Invariant additions are architectural changes, not just
test additions. They reflect a deepening understanding of
what vyre promises and should be made explicit.

## What post-mortems are not

A post-mortem is not a blame exercise. The goal is to
improve the project, not to assign fault. Individual
engineers are not the subject; the suite, the process, and
the catalog are the subjects.

A post-mortem is not a compliance checkbox. It is a
substantive investigation that takes time and produces
actions. A post-mortem that is written in five minutes and
has no actions is not a post-mortem; it is a bug report
with a ritual wrapper.

A post-mortem is not a permanent addition to standing
process. Once a bug class has a mutation, an archetype, and
(if applicable) an invariant, future instances of the same
class are caught by the gate. The post-mortem for a caught
instance is trivial: "gate caught it, regression added,
done." The post-mortem's output is only substantial when
the bug was not caught.

## Cadence

Vyre runs post-mortems on every bug that reaches users,
regardless of severity. A small bug (wrong error message)
gets a small post-mortem; a large bug (wrong computation)
gets a thorough one. The threshold is "did users
experience this?" not "is this severity X or higher?"

Severity matters for prioritization of the fix and the
communication strategy. It does not matter for whether a
post-mortem happens. Every user-visible bug is a failure
of the suite, and every failure is worth examining.

## The post-mortem log

Vyre keeps a log of all post-mortems, typically in the
project's operational notes. The log is not part of this
book because its format and location are operational
details. The log's contents are:

- Date.
- Bug description.
- Root cause.
- Actions taken.
- Lessons learned.

The log accumulates. Over years, it becomes an honest
record of how vyre has learned. New contributors read the
log to understand the project's history with bugs, and
mature contributors consult it when debugging new issues to
see if similar patterns have appeared before.

## The feedback into the book

When this book is updated, some updates come from
post-mortems. A chapter gains a section because a
post-mortem revealed a gap in the book's coverage. A rule
gains teeth because a post-mortem showed contributors were
not following it. An anti-pattern gets a new example
because a post-mortem found a new instance.

The book is not static. Post-mortems feed into it. The
evolution is slow (the book is meant to be stable), but
when a post-mortem reveals that a chapter is wrong or
incomplete, the chapter is updated. The update is its own
PR with justification tied to the post-mortem.

## Summary

Post-mortem discipline asks why the suite missed a bug and
takes concrete actions to prevent the class from slipping
through again. Every bug gets a regression test, a mutation
catalog entry or archetype, and sometimes an invariant
addition. The catalogs grow monotonically from post-mortems.
The book itself is updated when post-mortems reveal gaps.
The process is how vyre learns.

Next: [The long game](the-long-game.md).
