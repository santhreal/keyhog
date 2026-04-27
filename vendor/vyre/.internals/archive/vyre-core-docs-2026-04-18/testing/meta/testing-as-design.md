# Testing as design

## The claim

Writing tests shapes the code being tested. This claim is
not the same as "tests catch bugs" — tests catch bugs
regardless of when they are written. The claim is that tests
authored alongside the code being tested produce better code
than tests bolted on afterward. The quality difference is in
the design of the code: its interface, its separation of
concerns, its testability, its clarity.

This is not a religious TDD argument. vyre does not mandate
that tests be written first; contributors are free to write
code first if they prefer. The observation is empirical:
across vyre's history, the modules where tests were written
alongside the code have fewer bugs, cleaner interfaces, and
easier refactoring than the modules where tests were added
later. The observation generalizes because the reasons are
mechanical, not ideological.

This chapter is about those reasons. It is the closest thing
to a philosophy chapter in this book, and it is in Part XI
because the preceding parts teach the mechanics that make
testing-as-design practical. Without good oracles, good
categories, good discipline, testing-as-design would be just
a slogan.

## Why tests shape the code

### Tests force interface decisions early

A function that is hard to test usually has an unclear
interface. The author sat down to write a test, found that
they had to mock five dependencies, discovered that the
function's return type had no meaningful equality, realized
that the inputs came from a global state that the test could
not control. These obstacles are not testing problems; they
are design problems exposed by trying to test.

When the author responds to the obstacles by fixing the
design (simplifying the dependencies, adding meaningful
equality, removing the global state), the code improves.
When the author responds by adding mock infrastructure to
work around the obstacles, the code gets worse. The
difference is whether the test's difficulty is treated as
information about the design or as something to work around.

A developer who writes tests first (or alongside) encounters
these obstacles early, when the design is still fluid. They
fix the design. A developer who writes tests after the code
is done encounters the obstacles late, when the design is
crystallized, and they work around them. The work-arounds
accumulate.

### Tests force clarity about what the code does

To write a test, the author must answer: what does this code
do? The answer has to be precise enough to encode as an
assertion. "Returns the result of the calculation" is not
precise enough; "returns the sum modulo 2^32 of the two
inputs, with overflow wrapping" is. Writing the precise
answer down forces the author to clarify their own
understanding.

Authors who write tests often discover that their
understanding was vague and become specific as a result.
Authors who skip tests can stay vague, and the vagueness
ends up in the code: under-specified edge cases, ambiguous
error handling, inconsistent naming. The test is the
discipline that forces specificity.

### Tests force separation of concerns

A single function that does validation, transformation, and
output formatting is hard to test because the test has to
set up inputs for all three concerns at once. A test that
focuses on validation has to tolerate the output formatting
running. A test that focuses on transformation has to
tolerate the validation running.

When the author realizes this, the fix is to separate the
function into three smaller functions, each with its own
test. Each function is now simpler, more testable, and more
reusable. The separation is driven by testability but is
good design regardless of testing.

A function designed without tests does not have this
pressure, so it stays entangled. Tests later catch the
entanglement but cannot easily untangle it without rewriting
the function.

## What testing-as-design looks like in vyre

vyre's architecture is influenced by testing concerns in
several specific places:

### The reference interpreter exists for testing

The reference interpreter in `vyre-conform/src/reference/`
was built because the cross-backend tests need an oracle.
Without the reference interpreter, cross-backend tests would
compare backends against each other, which catches
disagreements but does not identify which backend is right.
With the reference interpreter as a ground truth, the tests
can tell which side is wrong.

The reference interpreter is not used at runtime. It exists
for testing. It is a design decision — "vyre has a reference
interpreter" — that was driven by testing needs and ended up
being valuable architecture in its own right. Documentation,
understanding, and onboarding all benefit from the reference
interpreter's existence.

### The spec is executable

The vyre-conform spec is not a document; it is a Rust data
structure (`OpSpec`, `SpecRow`, `DeclaredLaw`) that the
generator reads to produce tests. This design choice was
driven by the need to automate test generation, but it has
architectural consequences: the spec stays in sync with the
tests because both come from the same data; the build system
can validate the spec for consistency; contributors can
extend the spec by adding data, not by writing text.

A non-executable spec (a .md file describing vyre) would
have all of these as drawbacks: drifting, unvalidated,
harder to extend. The executable spec is better architecture
and was motivated by testing.

### The enum variants are exhaustively matched in tests

The coverage meta-tests in `tests/integration/lowering/` and
`tests/integration/wire_format/` use exhaustive match to force
tests for every new variant. This is a test pattern, but it
feeds back into design: adding a new Expr variant requires
adding a lowering and a test in the same PR, because the
meta-test's match is non-exhaustive until both are added.
The design constraint "new variants come with lowering and
tests" is enforced by the test pattern.

A project without the meta-test would have to remember to
add lowerings and tests manually. vyre enforces the rule
mechanically, which prevents the drift that haunts other
projects.

### The invariants are numbered and tracked

Invariants I1 through I15 are numbered, documented, and
traced through tests. Each invariant has at least one test
that proves it on specific inputs. The numbering and
tracking is a test discipline, but it also forces vyre's
architecture to be aware of its own invariants: every
feature is evaluated against the invariants before it lands.
A feature that would break I1 is rejected, not because of a
test but because of the invariant itself.

This discipline is how vyre keeps its promise. Without the
invariant tracking, the promise would be vague; with it,
the promise is a checklist.

## The observation, precisely

Testing-as-design works because tests expose design
problems early, force clarity, and drive separation of
concerns. It fails when tests are treated as a chore to be
completed after the real work is done: in that case, the
tests document the existing design rather than shaping it.

The practical recommendation for vyre contributors: when
you are writing a new feature, write at least one test
alongside the first meaningful draft of the code. Do not
wait until the code is "done"; use the test to verify your
understanding while you still have flexibility. The test
does not have to be complete; it has to exist.

This is not a mandate. Contributors who prefer to code
first and test after can do so. The suggestion is that they
try the alternative occasionally and observe the difference
in their own work. The difference is usually visible.

## What testing-as-design is not

- **It is not TDD orthodoxy.** vyre does not require tests
  to be written before code. It observes that tests written
  alongside code produce better code.
- **It is not testing as insurance.** Testing-as-design is
  about shaping the code, not about protecting it after the
  fact. Tests as insurance are also valuable but are a
  different concept.
- **It is not a replacement for thinking.** Testing-as-design
  does not absolve the contributor of the need to think
  carefully about architecture. It adds a tool for
  discovering architectural issues, but the discovery still
  requires attention.

## Summary

Tests shape the code being tested. Writing tests alongside
the code exposes design problems early and drives cleaner
interfaces, clearer specifications, and better separation
of concerns. vyre's architecture has specific features (the
reference interpreter, the executable spec, the
enum-exhaustiveness meta-tests, the invariant tracking)
that exist because testing needs drove them. Testing-as-design
is empirical, not ideological. Try it; observe your own
results.

Next: [Testing the testers](testing-the-testers.md).
