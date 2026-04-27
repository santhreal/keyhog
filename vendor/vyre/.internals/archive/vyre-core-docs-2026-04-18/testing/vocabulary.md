# Vocabulary

This chapter defines every term of art used in vyre's testing
discipline. The terms have single, precise meanings across the entire
project. When a chapter in this book uses one of these words, it
means exactly what this chapter says it means. When the vyre
codebase uses one of these words in a comment or a doc, it means the
same thing. When an agent or a contributor uses one of these words
in a pull request, the review checks whether they mean what this
chapter says.

Precision in vocabulary matters because ambiguity in vocabulary is
how tests quietly drift away from what they should be. If "oracle"
means one thing to one contributor and something slightly different
to another, both will write tests that feel correct but will not
agree when compared. The vocabulary defined here is the common
language that makes review and discipline possible.

## Test

A **test** is a named Rust function, usually annotated with
`#[test]` or inside a `proptest!` block, that exercises some part of
vyre and asserts at least one meaningful claim about the result.

A test is not a function that calls vyre code and checks nothing. A
test is not a function that calls vyre code and only checks that it
returned `Ok`. A test is not a function that calls vyre code with
its own output as the expected value. Each of these shapes is a
ritual that resembles a test, and each is rejected by this book. See
[Anti-patterns](anti-patterns/README.md) for the full list.

Every test has:
- A **subject**: the code being tested.
- A **property**: the claim being verified about that code.
- An **oracle**: the independent source of the expected value (see
  [Oracles](oracles.md)).
- An **assertion**: a direct comparison between the observed
  behavior of the subject and the oracle's expected value.

If a test is missing any of these, it is not a complete test. A
reviewer asked to evaluate the test should be able to identify each
of the four parts in one reading.

## Subject

The **subject** of a test is the unit of code whose behavior is
being checked. A subject can be a single function, a single op,
a single lowering rule, a single validation rule, a full pipeline,
or a system-level invariant. The subject is what the test would
detect a change in.

A test may have exactly one subject. A test with two subjects is a
kitchen sink test (see [the kitchen sink
anti-pattern](anti-patterns/kitchen-sink.md)) and must be split.
"The Program builder and the validator" is two subjects. "The
builder, assuming the validator is correct" is one subject, and
the test should be scoped accordingly.

The subject is not declared in a field or attribute. It is declared
in the test's name (see [Naming](writing/naming.md)) and in the
test's one-line doc comment.

## Property

A **property** is a claim about the subject's behavior that the
test verifies. Properties in vyre are always positive claims —
statements about what the subject should do, not statements about
what it should not do.

A property answers the question: what would failure look like? If
the test passes when the subject is wrong, the property is not
well-defined. If the test can pass on a broken subject without
anyone noticing, the property is too weak.

Example properties:

- "Add of `(u32::MAX, 1)` produces `0`."
- "Commutativity holds for Add on `(a, b)` and `(b, a)`."
- "Every backend agrees with the reference interpreter on this
  Program."
- "Validate rejects a Program that declares two buffers with the
  same name, with V001."

Non-examples of properties (too weak, rejected at review):

- "Add produces a value of type u32." (true for every implementation)
- "Validate does not panic." (true for most implementations,
  including wrong ones)
- "The program lowers." (does not verify what it lowers to)

A test's property must be stronger than "the code runs." It must
be specific enough that a wrong implementation can fail it.

## Oracle

An **oracle** is an independent source of truth for what the
expected value of a test should be. The definition is the subject
of an entire chapter ([Oracles](oracles.md)); this entry is the
one-line version.

Oracles in vyre are organized in a strict hierarchy from strongest
to weakest: law, specification table, reference interpreter, CPU
reference function, composition theorem, external corpus, property.
Every test declares its oracle. Every declared oracle is the
strongest applicable one for the test's property. The hierarchy is
enforced mechanically by the generator and by review.

Oracles never derive their expected values from the subject. That
is the cardinal rule. Violating it turns the test into a tautology.

## Assertion

An **assertion** is the direct comparison between the subject's
observed behavior and the oracle's expected value. In Rust, the
canonical assertion is `assert_eq!(observed, expected)`.

An assertion must be:

- **Direct:** comparing the actual result to the actual expected
  value, not through layers of helper functions that obscure the
  comparison.
- **Meaningful:** able to fail for a wrong implementation.
- **Scoped:** one test, one subject, one property, one assertion
  (or a small number of closely related assertions on the same
  observed value).

A test with ten assertions on ten different properties is a kitchen
sink test. A test with zero assertions is not a test. A test with
assertions that use `matches!` to accept a wide range of values is
usually too weak unless the weakness is the point (as in adversarial
tests where the point is "returned Err instead of panicking").

## Invariant

An **invariant** is a claim about vyre's behavior that must hold for
every input, every run, every backend, every version. vyre has
fifteen named invariants (I1 through I15), defined in
[The promises](the-promises.md) and cataloged in
[Appendix B](appendices/B-invariants-catalog.md).

Invariants are the promises vyre makes to its users. Tests exist
ultimately to prove invariants. A property in a specific test
(say, "Add of (0, 1) is 1") is an instance of an invariant (I1:
determinism, I3: backend equivalence, I8: reference agreement). The
test proves the instance; the suite as a whole proves the invariant.

When a test fails, the first question is: which invariant did this
instance violate? The answer tells you what category of bug was
caught and what the fix has to preserve.

## Mutation

A **mutation** is a small, specific change to vyre's source code
designed to test whether the test suite would catch such a change.
vyre's mutation catalog (`vyre-conform/src/mutations/`) enumerates
every kind of mutation considered: arithmetic operator swaps,
constant increments, control-flow deletions, buffer index shifts,
atomic ordering weakening, IR data type swaps, false law claims,
and more. The catalog is the enumeration of "ways vyre could be
broken that the suite should catch."

A mutation is **killed** by a test if, when the mutation is
applied to the source, the test fails. A mutation **survives** if
the test still passes on the mutated source. Surviving mutations
are findings: the suite has a gap.

The mutation gate (`vyre-conform/src/harnesses/mutation.rs`) runs
the mutation catalog against tests and reports the kill count and
the surviving mutations. A test's quality is measured by how many
mutations it kills, not by whether it passes on correct code. See
[Mutations and the adversarial mindset](mutations.md) for the full
treatment.

## Archetype

An **archetype** is a shape of input that is known to expose bugs
when fed to operations with matching signatures. vyre's archetype
catalog (`vyre-conform/src/archetypes/`) enumerates arithmetic
archetypes (identity pair, overflow pair, bit-pattern alternation),
structural archetypes (minimum program, maximum nesting, diamond
dataflow), composition archetypes (associativity triple,
commutativity swap), and backend archetypes (single op every
backend, resource saturation).

Archetypes are how tests find bugs without human contributors
having to invent adversarial inputs from scratch. When you write a
test for an op, you do not have to ask "what inputs will expose
bugs?" The archetype catalog answers that question for you. You
pick the archetypes that apply to your op's signature and
instantiate them. See [Archetypes](archetypes.md) for the full
catalog.

## Determinism

**Determinism** in vyre is the property that the same `ir::Program`
and the same inputs produce the same output bytes every time. It is
the strongest form of reproducibility: not "approximately equal" or
"equal within a tolerance," but byte-identical.

vyre's determinism is a specific kind: it is deterministic across
backends, across devices, across runs, across vyre versions. It is
not just "this run will produce the same bytes if I run it twice
on the same hardware." It is "this run will produce the same
bytes on any conformant hardware."

Determinism is invariant I1. It is the central promise of vyre. See
[the-promises.md](the-promises.md) for the full statement and
[advanced/floating-point.md](advanced/floating-point.md) for the
specific rules that preserve determinism in floating-point paths.

## Conformant backend

A **conformant backend** is an implementation of vyre's execution
model that has passed the full vyre-conform conformance suite and
holds a valid certificate. A conformant backend produces
byte-identical results to every other conformant backend for every
`ir::Program`.

"Conformant" is a technical claim, not a marketing claim. A backend
is conformant if and only if it currently holds a valid certificate
from a recent vyre-conform run. When the backend changes — even
from a driver update — the certificate is provisionally invalid
until re-run.

## Program

A **Program** is an `ir::Program` value: a buffer declaration list,
a workgroup size, and an entry node representing the computation to
be performed. Programs are vyre's unit of dispatch. A Program is
constructed by user code, validated by vyre, lowered to a backend
shader, and dispatched to the backend for execution.

In this book, "Program" with a capital P always refers to an
`ir::Program`. "program" lowercase refers to any Rust program in
general. The capitalization distinction is intentional and used
throughout vyre's docs.

## Op

An **op** (short for "operation") is a unit of computation that has
a semantic definition in `src/ops/primitive/<op>.rs`, a CPU
reference function, a signature, and an entry in vyre-conform's
OpSpec registry. Ops are the atoms from which Programs are built.

Ops in vyre are either **Category A** (compositional, lowering to
an inlined sequence of existing operations) or **Category C**
(hardware intrinsic, mapped 1:1 to a specific hardware instruction
with per-backend availability). There is no Category B; runtime
abstraction is forbidden. See vyre's vision and architecture docs
for the rationale.

## Oracle hierarchy

The **oracle hierarchy** is the ordered list of oracle kinds from
strongest to weakest: law, specification table, reference
interpreter, CPU reference function, composition theorem, external
corpus, property. Every test uses the strongest oracle in the
hierarchy that applies to its property. See [Oracles](oracles.md).

## Mutation gate

The **mutation gate** is the process of running the mutation
catalog against a test or a set of tests and rejecting any test
that does not kill the expected mutations. The gate is implemented
in `vyre-conform/src/harnesses/mutation.rs` and is invoked by CI on
every PR that touches tests. A test that passes the mutation gate
is accepted; a test that fails is rejected with structured feedback
identifying which mutations survived.

The gate is the single most important quality check in vyre's test
architecture. Everything else can be subjective, under-specified, or
delegated to human review. The mutation gate is mechanical, pass or
fail, not up for interpretation. See
[Mutations](mutations.md).

## Reference interpreter

The **reference interpreter** is a pure-Rust, obviously correct,
slow evaluator for `ir::Program` that lives in
`vyre-conform/src/reference/`. It handles every variant of every IR
enum, uses single-threaded sequential semantics for atomics, and
uses strict IEEE 754 for floats. It is the oracle for invariant I3
(backend equivalence) and the canonical definition of what every
Program means.

The reference interpreter is never optimized. Speed is not a goal.
Clarity is the goal: a reader must be able to read the interpreter
source and convince themselves it is correct. If the reference
interpreter disagrees with a CPU reference function, invariant I8
has been violated and the suite stops accepting work until the
disagreement is resolved.

## CPU reference function

A **CPU reference function** is the Rust function in
`src/ops/primitive/<op>.rs` that defines the semantics of a
primitive op in host code. Every op has one. The reference function
is what the op means — the GPU backend is required to produce the
same result, and the reference interpreter is required to agree
with the function bit-exactly.

The CPU reference function is the op-level oracle. It is weaker
than the reference interpreter for Program-level tests (because it
only covers one op) and stronger than property or corpus oracles
for op-level tests. See [Oracles](oracles.md) for when to use it.

## Specification table

A **specification table** is a committed list of `(inputs, expected,
rationale, source)` rows for an op, stored in
`vyre-conform/src/spec/tables/<op>.rs`. Each row pins down the
expected output for specific inputs, with a rationale explaining
why those inputs matter and a source declaring how the expected
value was determined (hand-written, derived from a law, from a
corpus, from a regression).

Specification tables are the canonical source for specific-input
tests. Tests that use a table row as their oracle are stronger
than property or corpus tests because each row has been authored
by a human with intent.

## Law

A **law** is a mathematical property that an op is declared to
satisfy for every input. Laws are drawn from the `Law` enum in
`vyre-conform/src/spec/laws.rs`: Commutative, Associative,
Identity(Value), Absorbing(Value), SelfInverse(Value), Idempotent,
Involutive, Distributive{over}, Bounded{min, max}, ZeroProduct,
Monotonic{direction}.

A law is declared on an op through a `DeclaredLaw` entry in the
op's `OpSpec`. The declaration carries a `Verification` provenance
(ExhaustiveU8, ExhaustiveU16, WitnessedU32{seed, count},
ExhaustiveFloat{typ}) that records how the law was verified. A
law without verification provenance is a compile error; a law with
a weaker verification than the op's domain requires is rejected at
review.

## Archetype, again

**Archetype** was defined earlier in this chapter, but because it
interacts with so many other terms, a second paragraph is useful.
An archetype is a *shape*, not a specific input. "Identity pair"
is an archetype. `(0, 0)` is an instance of that archetype for
BinOp::Add over u32. `(Value::F32(0.0), Value::F32(0.0))` is an
instance of the same archetype for a float op. The archetype
registry maps an op's signature to the concrete instances. See
[Archetypes](archetypes.md).

## Generated test

A **generated test** is a Rust test function emitted automatically
by vyre-conform's test generator from a specification entry, an
archetype, and an oracle. Generated tests live in
`vyre-conform/tests_generated/`, are not committed to git, and are
regenerated deterministically from the specification at build time.
Generated tests are tested and graded by the same discipline as
hand-written tests.

Generated tests are the mechanism by which vyre scales its test
suite to the combinatorial size of (op × archetype × oracle × input
class). Hand-written tests cannot cover this combinatorial space
without burning out contributors. Generated tests do cover it, but
only if the underlying specification and archetypes are correct —
which is why the spec and archetype catalogs are the load-bearing
human-written components of the system.

## Hand-written test

A **hand-written test** is a Rust test function authored by a human
(or by an agent under human review) and committed to `vyre/tests/`
directly. Hand-written tests are the baseline that generated tests
must strictly exceed, and the permanent home of anything the
generator cannot produce: regressions, adversarial specifics,
property invariants, benchmarks.

Both hand-written and generated tests pass through the same mutation
gate and the same review checklist. The provenance is different;
the quality standard is not.

## Regression test

A **regression test** is a hand-written test in
`vyre/tests/regression/` that reproduces a past bug. Each regression
test has a header comment recording the bug's date, symptom, root
cause, and fix commit. Regression tests are never deleted; once a
bug has been captured as a regression test, the test exists
forever, and if it starts failing, the bug has returned.

See [Regression tests](categories/regression.md) and [The regression
rule](discipline/regression-rule.md) for the discipline that
governs this category.

## Property test

A **property test** is a test that asserts an invariant over a
generated input space, usually via proptest. Property tests are
weaker than specific-input tests because they assert relations
rather than pinning down specific expected values, but they exercise
orders of magnitude more inputs. Every invariant in vyre has at
least one property test.

Proptest usage in vyre requires a fixed seed and a committed
regression corpus. See [Seed discipline](discipline/seed-discipline.md).

## Adversarial test

An **adversarial test** is a test whose inputs are deliberately
hostile: malformed IR, malformed wire-format bytes, OOM conditions, fault
injections, resource bombs. The assertion is always "graceful error
handling, no panic" — the test does not care what specific error
is returned, only that the runtime does not crash.

Adversarial tests are the main defense for invariant I11 (no
panic). See [Adversarial tests](categories/adversarial.md).

## Seed

A **seed** in vyre's testing vocabulary is the random seed used to
drive a property test's input generator. Seeds must be fixed and
committed so that CI failures can be reproduced later. A proptest
without a fixed seed is rejected at review. See [Seed
discipline](discipline/seed-discipline.md).

## Corpus

A **corpus** is a committed collection of inputs used as test
fixtures. vyre has several corpora: the wire-format round-trip corpus
(`tests/corpus/wire_format/`), the fuzzing corpus (`tests/corpus/fuzz/`),
the proptest regression corpus (`proptest-regressions/` at each
crate root), and the external conformance vectors
(`vyre-conform/corpus/`). Corpora are authoritative for their
specific inputs and are never edited without a review rationale.

## Flake

A **flake** is a test that fails nondeterministically — passes on
one run, fails on the next, passes again on the third. Flakes are
the most corrosive failure mode of a test suite because they
gradually teach engineers to ignore failures, which eventually
teaches engineers to ignore real bugs.

vyre treats flakes as P1 findings: a flake blocks merges until the
flake is either fixed or quarantined with an explicit label and an
expiration date. See [Flakiness](discipline/flakiness.md).

## Mutation catalog

The **mutation catalog** is the committed enumeration of all
mutations the mutation gate knows how to apply. Stored in
`vyre-conform/src/mutations/`. Additions to the catalog happen when
a new bug class is identified that existing mutations do not cover;
removals are rare and require review.

## Archetype catalog

The **archetype catalog** is the committed enumeration of all
archetypes the generator knows how to instantiate. Stored in
`vyre-conform/src/archetypes/`. Additions happen when a new class
of bug-triggering input is identified.

## Suite

The **suite** in this book refers collectively to every test that
runs as part of vyre's test discipline. The suite includes:

- Every hand-written test in `vyre/tests/`.
- Every generated test in `vyre-conform/tests_generated/` (produced
  at build time from the spec).
- Every property test, proptest regression corpus included.
- Every adversarial test, including fuzz corpora.
- Every regression test.
- Every benchmark baseline assertion.

The suite is what CI runs on every commit. "The suite passes" means
every test in the full suite passed on the target commit.

## Coverage

**Coverage** in vyre has two meanings, which must be kept distinct
by context:

- **Line coverage / branch coverage** (the traditional meaning): the
  fraction of source lines or branches exercised by the suite. vyre
  uses `cargo-tarpaulin` or equivalent to measure this, aims for
  100% branch coverage on core modules, and treats drops from the
  baseline as findings.
- **Variant coverage** (vyre-specific): the fraction of enum
  variants exercised by the suite. Every public enum in vyre has a
  meta-test that enumerates its variants and asserts a test exists
  for each. New variants without tests cause the meta-test to fail
  at compile time.

Both meanings are used in this book. Context disambiguates.

## Certificate

A **certificate** is a signed record that a specific backend at a
specific version has passed the full vyre-conform conformance
suite. Certificates are the formal artifact that makes "conformant
backend" a technical claim. See
[vyre-conform/two-tier-suite.md](vyre-conform/two-tier-suite.md).

## Gate

A **gate** in this book is any mechanical check that a test must
pass to be accepted. vyre has several gates: the mutation gate
(kills specific mutations), the coverage gate (variant coverage
meta-tests), the oracle gate (declared oracle is strongest
applicable), the compilation gate (cargo check passes), the lint
gate (clippy clean). A test that fails any gate is rejected before
review.

Gates are the mechanical component of review. Human reviewers
focus on the judgment calls that gates cannot automate. See
[Review checklist](discipline/review-checklist.md) for the human
half of the review.

## Part II continues

With vocabulary established, Part II continues with three more
chapters: [Oracles](oracles.md) (already written), [Mutations and
the adversarial mindset](mutations.md), and
[Archetypes](archetypes.md). Together these four chapters are the
conceptual toolkit used by every other chapter in the book.
