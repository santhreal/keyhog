# Anti-patterns

Part VI is the catalog of shapes that look like tests but are
not. Each anti-pattern has a chapter: what it looks like, why it
fails, how to recognize it in code review, and what to replace
it with. Every pattern here is rejected on sight in vyre pull
requests. Knowing them is not optional.

Anti-patterns are not bugs in the test writer's reasoning —
they are recurring failure modes that appear even in
contributors who know better. A tired contributor writes a
tautology. A rushed contributor writes a kitchen sink. A
cautious contributor writes a doesn't-crash test that hides
behind the phrase "better than nothing." Each shape is
specifically dangerous because it passes the "does the test
look like a test?" visual check while failing the "does the
test actually verify anything?" semantic check.

The chapters in Part VI exist so that when you catch yourself
writing one of these shapes, you can name the pattern, see that
it is the same mistake others have made, and reach for the
known correction. Naming the pattern turns a gut feeling of
"something is off" into a specific diagnosis with a specific
remedy.

## The catalog

### The tautology test

The expected value is derived from the code under test. The
assertion always passes regardless of whether the code is
correct. See [tautology.md](tautology.md).

### The kitchen sink test

One test function verifies many different properties. When the
test fails, it is not clear which property broke. See
[kitchen-sink.md](kitchen-sink.md).

### The "doesn't crash" test

The assertion is "the function did not panic" for a subject that
has a stronger oracle available. The test catches nothing the
stronger oracle would have caught. See [doesnt-crash.md](doesnt-crash.md).

### The hidden helper test

The test's logic is wrapped in helpers that obscure what is
being verified. A reader cannot tell from the test body what
subject, what inputs, or what expected value are involved. See
[hidden-helpers.md](hidden-helpers.md).

### The seedless proptest

A proptest without a fixed seed. Failures are not reproducible
because each run generates different inputs, and the regression
corpus is not committed. See [seedless-proptest.md](seedless-proptest.md).

### Test smells

Subtler warning signs that appear before a test becomes an
outright anti-pattern. Tests that pass on broken code but are
not yet provably tautological; tests that could be stronger but
are not wrong; tests that feel like they are doing too much.
See [test-smells.md](test-smells.md).

## How reviewers use this chapter

When reviewing a pull request that touches tests, the reviewer
asks: do any of these patterns appear? If yes, the reviewer
names the pattern, cites the chapter, and asks the contributor
to correct it before merging. Naming the pattern is how the
review stays grounded in established discipline rather than
becoming a negotiation.

The review checklist in Part VII includes the anti-patterns as
explicit checks. "Does any test use a tautological oracle?" is
one of the eleven items on the checklist, and the reviewer
verifies it against Part VI's definition.

## How contributors use this chapter

When writing a test, read the chapter for your category and the
chapters for the anti-patterns your test might resemble. If
your test matches any anti-pattern, stop and rewrite. If you
catch yourself reaching for a pattern that is flagged here, the
catch is the win — you avoided committing a test that would
have been rejected at review.

Contributors who come from codebases with weaker testing
discipline sometimes find Part VI jarring. Patterns that were
acceptable elsewhere are rejected here. The discipline is
stricter because the stakes are higher: vyre's promise of
byte-identical results forever does not allow for "good
enough" tests.

## A note on tone

The anti-pattern chapters are written with the same opinionated
voice as the rest of the book. They call out specific shapes,
explain why each is wrong, and prescribe corrections. They do
not hedge. The reason: ambiguity here would let the patterns
slip back in, and the whole point of Part VI is to make the
patterns nameable and rejectable at sight.

If one of these chapters feels harsh about a test you have
written, the harshness is aimed at the pattern, not at you.
Fixing the test is cheap and the fix makes the suite stronger.
The chapter is harsh so the discipline holds; it is not
personal.

Begin at [The tautology test](tautology.md), which is the most
common and most important anti-pattern in vyre's experience.
