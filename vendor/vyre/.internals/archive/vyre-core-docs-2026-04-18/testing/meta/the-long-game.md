# The long game

## What this book is for

This is the last chapter of the last part of the book. The
earlier chapters described the mechanics of testing vyre:
how to write a test, where to put it, how to review it, how
to run it, how to fix it when it fails. The mechanics are
useful, but mechanics alone are not the point.

The point is the long game. vyre's promise to its users is
that a Program written today produces byte-identical
results on every conformant backend, today and for every
future version, forever. The promise is only credible if
the test suite is strong enough to enforce it — not just
today, but forever. The mechanics in the earlier chapters
are what the suite looks like when it is doing its job.
This chapter is about why the suite has to keep doing its
job, for years, across contributors, across architectural
changes, across everything.

## The horizon

vyre is built for an unknown future. Today's backends are
wgpu; tomorrow's might be CUDA, Metal, Vulkan, a hardware-specific
backend for a GPU that does not exist yet. Today's
contributors are a small team; tomorrow's will include
vendors, researchers, contractors, and agents.
Today's spec is a few thousand lines; tomorrow's might be
tens of thousands. The suite has to scale with all of this
without losing coherence.

This book is the scaling tool. It is not the suite; it is
the reference that the suite's contributors consult. When
a new contributor joins — whether they arrive in a year,
five years, or twenty — they read this book and learn what
the suite is for, how it works, and what they must do to
keep it working. The book is the institutional knowledge
that outlives individual engineers.

For the book to serve this purpose, it has to be stable.
The chapters here describe permanent architectural
decisions, not temporary choices. The oracle hierarchy is
permanent. The ten test categories are permanent. The
review checklist is permanent. The fifteen invariants are
permanent. Changes to these would cascade through the
suite and require re-training every contributor; the cost
of a change is high enough that changes happen rarely, and
only with strong reasons.

Mechanisms that the book describes but that are not
architectural — specific commands, specific file paths,
specific config values — may change more freely. The
commands are in [running/](../running/) and are expected
to evolve as tooling improves. The architecture chapters
are more stable.

## How this book changes

The book changes in response to three kinds of events:

- **Post-mortems.** When a post-mortem reveals that the book
  missed a gap, the relevant chapter is updated. The update
  is specific and traceable to the post-mortem.
- **Architectural changes in vyre.** If vyre's architecture
  changes in a way that affects testing, the book is
  updated. For example, adding a new backend requires
  updating the backend chapter; adding a new category of
  test requires adding a new chapter to Part III.
- **Drift in the suite.** If the daily audit reveals that
  contributors are not following the book's guidance, the
  book may need to be clearer on the point being missed.
  The chapter is rewritten to be more explicit.

Changes do not happen silently. Every book update is a PR
with justification. Reviewers ask: is this change necessary?
Is the new wording clearer than the old? Does the change
contradict anything else in the book? A change that
contradicts another part of the book requires reconciling
both parts.

The review bar for book changes is high. The book is read
by more people than it is written by; small changes affect
many readers. A sloppy change to a paragraph is more
expensive than a sloppy change to a test, because the test
fails loudly and the paragraph just quietly confuses people.

## How the suite changes

The suite changes constantly, but the changes are
disciplined by the book. New tests follow the templates.
New categories appear only when the book is updated. New
invariants are debated before being added. The suite grows
monotonically in one sense (more tests, more coverage) and
adapts slowly in another (same shape, same patterns).

This tension — growth without drift — is the long game's
central challenge. A suite that grows without discipline
drifts into inconsistency. A suite that is disciplined but
does not grow becomes obsolete. Vyre aims for both: growth
constrained by discipline.

The constraint is the book. The discipline is what each
contributor brings when they write a test. Neither alone is
enough; together they produce a suite that can handle
vyre's ambition.

## What five years looks like

Imagine vyre in five years. Assume the project has
succeeded: multiple backends, many consumers, a healthy
contributor community, and a reputation for correctness.
What does the suite look like?

- **Primitive ops:** probably a hundred or more. Many more
  than the ten in the current spec. Each op's tests have
  been migrated from hand-written to generated; the
  hand-written baseline is preserved for the worked example
  in Part IV and for a handful of ops with complex
  semantics.
- **Test count:** probably millions. Generated tests cover
  the cross-product of ops, archetypes, and oracles. Hand-written
  tests are a few thousand, focused on regressions,
  adversarial specifics, and property invariants.
- **Mutation catalog:** several thousand entries. Each
  entry is justified by a bug or by a new class of
  possible failure. The catalog grows from post-mortems.
- **Archetype catalog:** also larger than today, with
  archetypes for new ops, new composition patterns, and
  new hardware features.
- **Backends:** probably several, each with a current
  conformance certificate. Cross-backend testing has been
  exercised across every pair.
- **CI cost:** substantial. Per-commit CI still runs under
  10 minutes, but nightly runs and release gating consume
  significant compute.
- **Contributor count:** dozens. Most never met each other.
  New contributors learn from the book.
- **Bugs found in production:** rare but not zero. Each one
  generates a post-mortem that updates the catalogs and
  sometimes the book.

The suite in five years looks different from today's suite
in scale but the same in shape. The disciplines are the
same; the volume is larger; the contributors are more
distributed. The book is updated in a handful of places but
still recognizably this book.

## What ten years looks like

Ten years is harder to predict. GPU compute may have
evolved in ways that require vyre to extend its IR
significantly. Hardware may have changed in ways that
require new mutation classes and new archetypes. The
contributor community may have grown beyond what a single
book can serve.

What stays stable:

- **The promise.** Byte-identical results on every
  conformant backend, today and forever. If this promise
  is broken, vyre has failed its mission regardless of
  what else is true.
- **The oracle hierarchy.** Law, spec table, reference
  interpreter, CPU reference, composition theorem,
  external corpus, property. The specific entries may
  expand but the idea of a hierarchy is permanent.
- **The two-tier suite.** Hand-written and generated, with
  the hand-written tier as the baseline.
- **Regression permanence.** Files in `tests/regression/`
  are never deleted.
- **Review discipline.** Every test passes a checklist
  before merging.

What might change:

- **The categories.** Part III might gain or lose
  categories as vyre's architecture evolves.
- **The archetype catalog.** New archetypes for new
  hardware features.
- **The mutation catalog.** New mutations for new failure
  modes.
- **The contribution flow.** As agents become more capable,
  the flow might be more automated at some stages.
- **The CI infrastructure.** Tools change; the principles
  do not.

## What twenty years looks like

Twenty years out, the book may have been rewritten. The
voice might be different, the tone might be updated, the
specific examples might have changed. What remains is the
thesis: vyre's value is its promise, and the promise
depends on the suite, and the suite depends on the
discipline this book teaches.

The thesis is the core. Everything else is implementation
of the thesis. Future contributors reading the thesis
should recognize it as the reason vyre exists, and the
recognition is what keeps vyre's identity stable across
decades.

## The writer's hope

This book was written because vyre is building toward the
kind of promise that most systems do not make. The promise
is expensive to keep — every optimization forgone, every
fast path blocked, every approximation forbidden is a cost
paid up front. The promise is what makes vyre valuable;
breaking it is what would make vyre forgettable.

The writer's hope is that future readers of this book will
understand why the costs are worth paying. They will read
the oracle chapter and see not a pedantic rule but a
safeguard against tautology. They will read the mutation
chapter and see not a tedious process but a mechanical
quality floor. They will read the regression rule chapter
and see not bureaucracy but institutional memory.

The hope is that they will then apply the discipline, not
because the book told them to, but because they understand
why the discipline exists and they want vyre to keep its
promise. A contributor who follows the rules from
obligation will slip. A contributor who follows the rules
from understanding will hold the line.

This book is written for the second kind of contributor.
If you have read this far, the book has served its
purpose: it has shown you why, and now the rest is up to
you.

## What comes next

When you finish this book, you have work to do:

- **Write tests that meet the standard.** Every test you
  write contributes to the suite. Do not write slop.
- **Read tests that others have written.** The daily audit
  is everyone's responsibility. Review tests critically;
  strengthen them when needed.
- **Run the suite often.** Feedback is fast when you run
  tests while you work. Do not wait for CI.
- **Follow the regression rule.** Never delete a regression
  test without a real exception. Fix the code, not the test.
- **Keep the book honest.** If you discover that a chapter
  is wrong, write a PR against the book. If the book
  contradicts reality, the book updates.
- **Teach the next contributor.** The book is the reference,
  but oral tradition matters too. When a new contributor
  joins, help them understand why the discipline exists,
  not just what the rules say.

These are not heavy obligations. They are the normal work
of maintaining a serious project. Done well, they produce
a suite that holds vyre's promise for as long as the
project exists.

## Summary

The long game is keeping vyre's promise for years, across
contributors, across architectural changes. The book is the
institutional knowledge that outlives individual engineers.
It changes slowly, in response to post-mortems and
architectural evolution. The suite grows without drifting
because the book constrains the growth. Future readers
will understand the discipline if they understand why it
exists, and they will hold the line if they want vyre to
keep its promise.

This is the end of the book. The appendices that follow are
reference material. Return to them as needed.

Go write good tests.
