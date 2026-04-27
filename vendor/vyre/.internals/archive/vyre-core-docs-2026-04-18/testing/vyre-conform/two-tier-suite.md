# The two-tier suite

## Two tiers, one purpose

vyre's test suite is really two suites running as one. The
first tier is hand-written: the tests in `vyre/tests/` that
contributors author directly, review carefully, and commit to
git. The second tier is generated: the tests in
`vyre-conform/tests_generated/` that the vyre-conform
generator produces from the executable specification at build
time.

The two tiers do the same job — verifying vyre's correctness
against its specification — but they work at different scales
and with different strengths. Hand-written tests are the
baseline: a few thousand careful tests, each with a specific
intent and a reviewed oracle. Generated tests are the
superset: millions of mechanically produced tests covering
the combinatorial cross-product of (op × archetype × oracle
× input class).

Neither tier alone is sufficient. The hand-written tier is
too small to cover the combinatorial space; the generated
tier is too mechanical to capture the specific insights that
human contributors bring. Together they form a complete
test corpus: the hand-written tier sets the quality floor
and the generated tier provides exhaustive coverage above it.

This chapter describes the two-tier model, how the tiers
relate, and how they work together to form a single coherent
testing discipline.

## Why two tiers

A single-tier suite would have to choose:

- **All hand-written:** high quality per test, but
  insufficient volume. A contributor cannot hand-write
  enough tests to cover every (op × archetype × oracle ×
  input class) combination, and even if they could, the
  combinations would not be maintained as vyre evolves.
- **All generated:** high volume, but uncertain quality. A
  purely mechanical generator produces tests that follow
  rules but sometimes miss the specific insights that a
  human would contribute. A generated suite with no
  human-written counterpart would have nothing to compare
  itself against.

The two-tier model gets the best of both: humans write the
foundational tests that set the quality bar, and the
generator produces the volume that covers the combinatorial
space above the bar. The hand-written tier is the reference
the generated tier is compared against. When the generated
tier passes while the hand-written tier would have failed,
the generated tier has a gap that the hand-written tier
exposes. When the hand-written tier passes while the
generated tier would have failed, the hand-written tier has
a gap that the generated tier exposes.

## How the tiers interact

### The baseline rule

The hand-written tier is the baseline. The generated tier
must strictly exceed the hand-written tier for every op on
every metric:

- **Mutation kills.** The generated tests must kill every
  mutation that the hand-written tests kill, plus more.
- **Variant coverage.** The generated tests must exercise
  every enum variant the hand-written tests exercise, plus
  more.
- **Archetype instantiation.** The generated tests must
  instantiate every archetype the hand-written tests
  instantiate, plus more.
- **Input diversity.** The generated tests must cover every
  specific input the hand-written tests cover, plus more.

The word "strictly" is load-bearing. Equality is not enough:
if the generated tier matches the hand-written tier but
contributes no additional coverage, the generator is not
justifying its existence. The generator's value is in the
"plus more."

The generator's output is verified against the baseline as
part of CI. A PR that changes the generator must show that
the new output strictly exceeds the old on a reference set
of ops, not just that it runs.

### The migration rule

When the generated tier strictly exceeds the hand-written
tier for an op, the hand-written tests for that op can be
migrated to the generated set. Migration means:

1. The hand-written tests for the op are deleted.
2. The op's suite is now fully generated.
3. The suite is still verified on every CI invocation, but
   through the generator rather than from committed files.

Migration is not mandatory. An op can keep its hand-written
tests alongside the generated ones indefinitely. The
hand-written tests are then redundant with the generated
tests but still serve as documentation and as a sanity
check on the generator.

Some ops' tests are never migrated. Regression tests,
adversarial-specific tests, benchmarks, and property-test
invariants stay hand-written forever because the generator
cannot produce them. The migration rule applies specifically
to primitive op correctness tests, which are the tests
closest to what the generator handles.

### The override rule

Sometimes the hand-written tier has a test that the
generated tier does not produce, and the test cannot be
explained by any archetype or oracle in the generator's
knowledge. These tests are the "override" set: tests the
generator would not think to write on its own but that
humans have added because they catch specific bugs.

Override tests are committed to `vyre/tests/` like any other
hand-written test. They live alongside generated tests for
the same op and are not removed by migration. When the
generator's knowledge expands to include the override's
intent (a new archetype is added, a new mutation class is
recognized), the override can be migrated, but until then
it stays.

The override rule is what prevents the generator from
silently shrinking coverage. A test that catches a real bug
is never lost, even if the generator does not produce its
equivalent.

## The generator's process

The vyre-conform generator reads the executable specification
(OpSpecs, archetypes, oracles, mutation classes) and emits
Rust test functions. Each generated test:

- Has a provenance header identifying the tuple (op,
  archetype, oracle, seed).
- Has a name derived from the tuple.
- Uses the strongest applicable oracle per the hierarchy.
- Asserts a specific value from the chosen oracle.
- Has a doc comment matching the style of hand-written
  tests.

```rust
// GENERATED by vyre-gen-tests v1.0.0
// spec version: v0.3.0
// source tuple: op=add, archetype=A1_identity, oracle=spec_table, seed=0x1234
// DO NOT EDIT. Regenerate via `cargo xtask generate-tests`.

/// add(0, 0) == 0. Identity pair (archetype A1).
/// Oracle: SpecRow from vyre-conform::spec::tables::add (row 0).
#[test]
fn test_add_a1_identity_0_0_spec_table() {
    let program = build_single_binop(BinOp::Add, 0u32, 0u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 0u32);
}
```

The test looks indistinguishable from a hand-written one,
which is intentional: the generator's output must meet the
same standards as hand-written code, and the only
distinguishing feature is the provenance header.

## The generator's output location

Generated tests live in `vyre-conform/tests_generated/` and
are not committed to git. The directory is `.gitignore`d, and
the generator regenerates the directory from the
specification on every CI invocation. The principle is that
the test corpus is derived: given the specification and the
generator, the corpus is reproducible, which means committing
it is redundant.

```
vyre-conform/
├── tests_generated/      # .gitignore'd; rebuilt on every CI run
│   ├── primitive_ops/
│   │   ├── add/
│   │   ├── mul/
│   │   └── ...
│   ├── lowering/
│   └── ...
└── src/
    ├── generator/        # the generator code
    ├── spec/             # the executable spec
    └── ...
```

The test corpus in `tests_generated/` is versioned
transitively through the generator and the spec. When the
generator changes, the corpus regenerates; when the spec
changes, the corpus regenerates. The `git log` on the
generator and the spec is effectively the `git log` on the
corpus.

## How the two tiers run together

On every CI invocation:

1. The hand-written tests run via `cargo test -p vyre`.
2. The generator runs via `cargo xtask generate-tests`,
   producing the generated corpus in
   `vyre-conform/tests_generated/`.
3. The generated tests run via `cargo test -p vyre-conform --test generated_tests`.
4. Both tier outputs are collected and reported together.

If either tier fails, CI fails. The tiers are treated
equally: a hand-written failure and a generated failure are
both blockers.

The mutation gate runs across both tiers simultaneously. A
mutation that survives the hand-written tier might be killed
by the generated tier, and vice versa; the combined kill
rate is what matters.

## The value each tier contributes

### The hand-written tier contributes

- **Reviewed intent.** Each test has an oracle declaration,
  a rationale, a reviewed name. A human thought about what
  the test is supposed to verify and committed the thought.
- **Regression catches.** Tests in `tests/regression/` are
  the permanent record of past bugs. The generator does not
  produce these.
- **Adversarial specifics.** Tests in `tests/adversarial/`
  with specific hostile inputs (from bug reports, from fuzz
  findings) are hand-written. The generator does not know
  which specific inputs to hostilize.
- **Property invariants.** Property tests with tailored
  generators are hand-written. The generator does not write
  other generators.
- **Benchmarks.** Performance-focused tests are
  hand-written. The generator produces correctness tests,
  not performance measurements.
- **Worked examples.** The complete test sets for specific
  ops that demonstrate the pattern for contributors to
  follow. See Part IV of this book.

### The generated tier contributes

- **Combinatorial coverage.** Every (op × archetype × oracle
  × input class) combination is instantiated. No
  hand-written author can produce this volume.
- **Consistency.** Every generated test follows the same
  patterns, the same naming, the same assertion style. The
  consistency makes the suite navigable.
- **Responsiveness to spec changes.** When the spec adds a
  new OpSpec row, a new archetype, or a new mutation class,
  the generated tier picks up the change automatically.
- **Scale.** The generated tier is as large as the
  specification demands. A spec with a hundred ops and five
  hundred archetype-oracle combinations per op produces
  fifty thousand tests, all meeting the same quality
  standard.

Neither tier makes the other redundant. The generated tier
without the hand-written tier would be a volume of tests
with no reference against which to verify quality. The
hand-written tier without the generated tier would be a
thorough but tiny corpus that leaves most of the
specification unverified.

## Summary

vyre's test suite has two tiers: hand-written tests in
`vyre/tests/` and generated tests in
`vyre-conform/tests_generated/`. The hand-written tier is
the quality baseline; the generated tier must strictly
exceed it and provides combinatorial coverage above it.
Migration moves ops from hand-written to generated when the
generated strictly exceeds; override rules preserve
human-authored tests that the generator cannot produce.
Both tiers run together in CI and are graded by the same
mutation gate. Neither tier makes the other redundant.

Next: [When the generator supersedes you](generator-supersession.md).
