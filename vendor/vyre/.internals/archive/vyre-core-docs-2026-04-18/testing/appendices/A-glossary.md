# Appendix A — Glossary

Every term of art used in this book, defined concisely.
Cross-referenced to the chapters where each term is
discussed in depth and to vyre's main glossary for terms
that appear elsewhere in the project.

## Adversarial test

A test whose inputs are deliberately hostile (malformed,
resource-bombing, racing, unparseable) and whose assertion
is "did not panic, no undefined behavior." Lives in
`tests/adversarial/`. See [adversarial.md](../categories/adversarial.md).

## Algebraic law

A mathematical property declared on an op. Examples:
commutative, associative, identity, absorbing, self-inverse,
idempotent, involutive, distributive, bounded, zero-product,
monotonic. Each law has a checker in the algebra engine that
verifies the law holds for the op's reference function.

## Archetype

A shape of input known to expose bugs. Archetypes are
catalogued in `vyre-conform/src/archetypes/` and instantiated
per op based on signature match. See [archetypes.md](../archetypes.md)
and [Appendix D](D-archetypes.md).

## Backend

An implementation of vyre's execution model that takes a
Program, lowers it to a target shader language, and dispatches
it to hardware. wgpu is the current primary backend. A
conformant backend holds a certificate proving it passes
the full vyre-conform conformance suite.

## Baseline (performance)

A saved benchmark measurement used as a reference for
comparing subsequent runs. A regression is a benchmark
that exceeds its baseline by more than a configured
threshold.

## Baseline (test coverage)

The hand-written test suite, which serves as the reference
the generated tests must strictly exceed for migration to
occur.

## Benchmark

A performance measurement using criterion. Benchmarks are
not correctness tests. They compare current runtime against
a baseline and fail CI on regressions. See [benchmarks.md](../categories/benchmarks.md).

## IR wire format

vyre's binary serialization format for `ir::Program`. Not an
executable; wire format is decoded back to IR before
execution. Round-trip identity is invariant I4.

## Category (test)

One of the top-level directories in `vyre/tests/`: unit,
integration, adversarial, property, backend, regression,
benchmarks, support, corpus. Each category has a single
purpose. See [architecture.md](../architecture.md).

## Category A / Category C

The two allowed kinds of vyre operations. Category A are
compositional (inline at lowering). Category C are hardware
intrinsics with per-backend availability. No Category B;
runtime abstraction is forbidden.

## Checklist, review

The eleven-item list reviewers use to evaluate test-changing
PRs. See [review-checklist.md](../discipline/review-checklist.md)
and [Appendix F](F-review-checklist.md).

## Conformant backend

A backend that passes the full vyre-conform conformance
suite and holds a valid certificate. See [backend.md](../categories/backend.md).

## Corpus

A collection of committed test inputs. vyre has several:
fuzz corpus, regression corpus, external corpus. Each is
authoritative for its specific inputs.

## CPU reference function

The host-side Rust function in `src/ops/primitive/<op>.rs`
that defines what an op means. Used as an oracle for
op-level tests. See [oracles.md](../oracles.md) entry 4.

## Decision tree

The nine-question procedure for placing a new test in the
correct category. See [decision-tree.md](../writing/decision-tree.md).

## Determinism

The property that the same Program and inputs produce the
same output bytes on every run, backend, and device.
Invariant I1. The central promise of vyre.

## Differential fuzzing

A fuzzing technique that feeds inputs to two implementations
and reports disagreements. vyre's primary bug-finding
technique at scale. See [differential-fuzzing.md](../advanced/differential-fuzzing.md).

## Fuzz corpus

Inputs discovered by `cargo fuzz` runs that caused bugs.
Committed to `tests/corpus/fuzz/` and replayed by
`tests/adversarial/fuzz_corpus.rs`. Never edited by hand.

## Gate

A mechanical check that a test or a PR must pass. vyre has
multiple gates: mutation gate, coverage gate, oracle gate,
compilation gate, lint gate. Gates are pass/fail, not
interpretive.

## Generated test

A test produced by vyre-conform's test generator from the
executable specification. Lives in `vyre-conform/tests_generated/`,
not committed to git, regenerated deterministically.

## Hand-written test

A test authored by a contributor (human or agent) and
committed to `vyre/tests/`. The quality baseline the
generator must strictly exceed.

## Invariant

A claim about vyre's behavior that must hold for every
input, every run, every backend, every version. vyre has
fifteen numbered invariants (I1–I15). See [the-promises.md](../the-promises.md)
and [Appendix B](B-invariants-catalog.md).

## IR

vyre's intermediate representation. An `ir::Program` is a
buffer declaration list, a workgroup size, and an entry node.
The unit of dispatch.

## Law

See Algebraic law.

## Lowering

The translation from `ir::Program` to a backend shader
language (typically WGSL). Implemented in `src/lower/`.
Tested in `tests/integration/lowering/`.

## Mutation

A small, specific change to source code designed to verify
tests catch it. vyre's mutation catalog lives in
`vyre-conform/src/mutations/`. See [Appendix C](C-mutation-operators.md).

## Mutation gate

The process of running the mutation catalog against tests
and rejecting any test that does not kill expected
mutations. The quality floor of vyre's suite. See
[mutations.md](../mutations.md).

## Oracle

An independent source of truth for a test's expected
values. vyre has seven oracle kinds in a strict hierarchy:
law, spec table, reference interpreter, CPU reference,
composition theorem, external corpus, property. See
[oracles.md](../oracles.md).

## Override test

A hand-written test that catches bugs the generator does
not know about. Tagged explicitly so migration preserves
it.

## Post-mortem

The investigation that happens after a bug reaches users,
asking why the suite missed it and what actions to take.
See [post-mortem-discipline.md](../meta/post-mortem-discipline.md).

## Program

An `ir::Program` value. Vyre's unit of dispatch. Capitalized
to distinguish from generic "program."

## Property test

A test that asserts a universal claim over generated
inputs, using proptest. Lives in `tests/property/`. See
[property.md](../categories/property.md).

## Reference interpreter

A pure-Rust, obviously correct, slow evaluator for
`ir::Program` in `vyre-conform/src/reference/`. The oracle
for cross-backend tests and the definition of Program
semantics. See [oracles.md](../oracles.md) entry 3.

## Regression test

A permanent reproducer for a fixed bug. Lives in
`tests/regression/`. Never deleted. See [regression.md](../categories/regression.md)
and [the regression rule](../discipline/regression-rule.md).

## Seed (proptest)

The random seed used to drive a property test's input
generator. Must be fixed and committed for reproducibility.
See [seed-discipline.md](../discipline/seed-discipline.md).

## Shrink

The process by which proptest reduces a failing input to
its minimal form. Enables diagnosable failure output.

## Spec table

A committed list of `(inputs, expected, rationale, source)`
rows for an op in `vyre-conform/src/spec/tables/`. Used as
an oracle for specific-input tests.

## Subject (of a test)

The code being exercised by a test. Every test has exactly
one subject.

## Suite

The collection of all tests that run as part of vyre's
test discipline. Includes hand-written tests, generated
tests, property tests, adversarial tests, regression tests,
benchmarks.

## Tautology test

A test whose expected value is derived from the code under
test. Always passes regardless of correctness. Rejected at
review. See [tautology.md](../anti-patterns/tautology.md).

## Tier (suite)

One of hand-written or generated. The two-tier model is
described in [two-tier-suite.md](../vyre-conform/two-tier-suite.md).

## Tier (CI)

One of per-commit (Tier 1), per-PR release (Tier 2), or
nightly (Tier 3). See [continuous-integration.md](../running/continuous-integration.md).

## ULP

Unit in the last place. A measure of floating-point
precision. Approximate track tests assert results within a
declared ULP tolerance.

## Validation

The pass that checks a Program for well-formedness before
lowering. Implemented in `src/ir/validate/`. Rules are V001
through V020.

## Worked example

The complete test set for one op, walked through in Part
IV. The reference contributors copy from when writing
tests for new ops.

## Cross-references

Terms not defined in this glossary that appear in the book
are defined in vyre's main glossary at `docs/glossary.md`.
Examples: the specific meaning of "Conformance," the
distinction between "Node" and "Expr," the semantics of
specific `BinOp` variants.

When a term is ambiguous between this glossary and the main
glossary, this glossary's definition applies within the
testing book's context. For questions outside testing, the
main glossary applies.
