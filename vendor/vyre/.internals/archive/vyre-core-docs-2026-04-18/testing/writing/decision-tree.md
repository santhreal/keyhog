# The decision tree

## The question you answer before writing a test

You have a test in mind. You know what you want to verify. You
do not yet know where the test file should live, which category
it belongs to, or what shape it should take. Writing the test
badly at this point produces a test that looks right but sits in
the wrong place, and wrong-place tests are hard to find later
and hard to reason about.

This chapter is a decision tree. Nine questions, asked in
order, place any test in the correct category. Answer the first
question that applies and you have your answer. If none apply,
the test does not belong in vyre's suite, or the suite has a
gap the test is revealing.

The tree is not a replacement for the category chapters in
Part III. It is a routing tool. After the tree tells you which
category to use, read that category's chapter for the specific
rules.

## The tree

### Question 1 — Is the test for a specific past bug?

Every fixed bug in vyre gets a regression test. If the test you
are writing corresponds to a bug that was reported and fixed,
the answer is immediate:

**→ `tests/regression/YYYY-MM-DD-description.rs`**

See [Regression tests](../categories/regression.md) for the file
format and the header rules. Regression tests have a specific
shape: a header comment recording the bug, followed by the
minimal reproducer as the test body.

If the test is for a bug that was found but not yet fixed, stop
and fix the bug first. Regression tests for unfixed bugs are
not useful — they fail and stay failing, which trains everyone
to ignore them, which is worse than no test at all.

If the test is for a hypothetical bug that has not happened,
continue to question 2. Hypothetical-bug tests are not
regression tests; they are speculative tests and belong
elsewhere.

### Question 2 — Is the test about a specific primitive op's computational correctness?

If the subject is one primitive op (Add, Mul, Xor, etc.) and
the property is "the op produces the expected result for these
specific inputs," the answer is:

**→ `tests/integration/primitive_ops/<op>.rs`**

See [Primitive op integration tests](../categories/integration.md)
for the conventions. The key point: tests here exercise the
complete pipeline (build, validate, lower, dispatch) with
oracle-backed expected values. Use spec table rows, laws, or
the reference interpreter as oracles, in that priority order.

If the test is about multiple ops interacting, continue to
question 3.

### Question 3 — Is the test about IR construction, visiting, or composition?

If the subject is building Programs, visiting nodes, composing
sub-Programs, or encoding to the wire format, the answer is:

**→ `tests/integration/ir_construction/<concern>.rs`**

Compose tests go in `composition.rs`. Wire format specific
tests go in `wire_format.rs`. Visitor tests go in `visitors.rs`.
See [Integration tests](../categories/integration.md) for the
full structure.

### Question 4 — Is the test about validation rules?

If the subject is `validate()` and the property is "this rule
fires when it should" or "this rule does not fire when it
shouldn't," the answer is:

**→ `tests/integration/validation/<rule_family>.rs`**

Every rule has at least a must-reject and a must-accept test.
The separability meta-test in `tests/integration/validation/separability.rs`
iterates the `ValidationRule` enum at compile time and requires
every variant to have at least one test. See [Validation
tests](../categories/validation.md) for the full treatment.

### Question 5 — Is the test about lowering to WGSL?

If the subject is `lower::wgsl::lower()` and the property is
"this IR construct produces this WGSL construct" or "the
lowered output has this structural property (bounds check,
shift mask, valid syntax)," the answer is:

**→ `tests/integration/lowering/<concern>.rs`**

Variant coverage tests go in `expr_coverage.rs`, `node_coverage.rs`,
etc. Structural property tests go in `bounds_checks.rs` and
`shift_masks.rs`. Specific round-trip tests go in `roundtrip.rs`.
See [Lowering tests](../categories/lowering.md) for the
exhaustiveness meta-test pattern.

### Question 6 — Is the test about IR wire format encoding/decoding?

If the subject is the IR wire format codec — `Program::to_wire()` /
`Program::from_wire()` — the answer is:

**→ `tests/integration/wire_format/<concern>.rs`**

Encoder tests go in `encode.rs`. Decoder tests go in `decode.rs`.
Round-trip tests go in `roundtrip.rs`. Malformed input tests go in
`malformed.rs`. Per-variant exhaustiveness tests go in
`variant_coverage.rs`. See [Wire format tests](../categories/wire_format.md).

> The word "bytecode" is retired from vyre. Previous test guidance
> referenced `tests/integration/bytecode/`; that directory was renamed
> to `tests/integration/wire_format/` during the reconciliation pass.

### Question 7 — Is the input hostile and the assertion "did not panic"?

If the test's input is deliberately malformed, resource-exhausting,
or hostile, and the assertion is "the function returned
gracefully without panic, UB, or corruption," the answer is:

**→ `tests/adversarial/<class>.rs`**

Malformed IR goes in `malformed_ir.rs`. Malformed wire-format bytes in
`malformed_wire_format.rs`. Resource bombs in `resource_bombs.rs`.
Fuzz corpus replay in `fuzz_corpus.rs`. See [Adversarial
tests](../categories/adversarial.md).

The key distinction: adversarial tests do not assert specific
error behavior. They assert "did not panic." If the test wants
to assert a specific `ValidationRule` fires, the test is a
validation test (question 4), not an adversarial test.

### Question 8 — Is the test a forall property with random inputs?

If the test's claim is "for every input from some distribution,
some relation holds," and the test uses `proptest!` to generate
inputs, the answer is:

**→ `tests/property/<invariant>.rs`**

One file per invariant. Each file contains a proptest block
with a generator, a property assertion, and a fixed seed. Case
counts vary by CI tier. See [Property tests](../categories/property.md)
for the full discipline, including seed management and
regression corpus rules.

Property tests are not for specific inputs dressed up as
proptest. If your inputs are specific (e.g., 0xDEADBEEF), you
want an integration test, not a property test.

### Question 9 — Is the test about backend-to-backend agreement?

If the test's subject is multiple backends and the property is
"they agree on the same Program," the answer is:

**→ `tests/backend/<concern>.rs`**

Cross-backend equivalence goes in `wgpu_vs_cpu.rs` or
`wgpu_vs_reference_interp.rs` depending on the oracle.
Determinism across runs goes in `determinism_across_runs.rs`.
The meta-test for backend registry coverage is
`backend_registry.rs`. See [Backend tests](../categories/backend.md).

## When none of the questions apply

If you reached question 9 without finding a home for the test,
one of three things is true:

1. **The test is a benchmark, not a correctness test.** If the
   test measures performance, go to `tests/benchmarks/` and use
   criterion. See [Benchmarks](../categories/benchmarks.md).
2. **The test is a unit test with no Program involvement.** If
   the test exercises a single function in isolation, go to an
   inline `#[cfg(test)]` module in the source file. See [Unit
   tests](../categories/unit.md). The `tests/unit/` directory
   exists only for the rare cases where inline modules do not
   work.
3. **The test does not belong in vyre.** Maybe the test is for
   code in a dependency, in which case it belongs in that
   dependency's test suite. Maybe the test is for code that
   vyre does not own, in which case it belongs in the project
   that owns the code. Maybe the test is for a category that
   does not exist yet, in which case the suite has a gap and
   the gap is worth investigating — but the investigation
   happens in a PR against this book, not by quietly inventing
   a new directory.

## The tree as a flowchart

If you prefer a visual form:

```
Is this a fixed bug's reproducer?
├─ YES → tests/regression/
└─ NO ↓

Is this about a specific primitive op's correctness?
├─ YES → tests/integration/primitive_ops/<op>.rs
└─ NO ↓

Is this about IR construction or composition?
├─ YES → tests/integration/ir_construction/
└─ NO ↓

Is this about validation rules?
├─ YES → tests/integration/validation/
└─ NO ↓

Is this about WGSL lowering?
├─ YES → tests/integration/lowering/
└─ NO ↓

Is this about wire format conversion?
├─ YES → tests/integration/wire_format/
└─ NO ↓

Is the input hostile, assertion "did not panic"?
├─ YES → tests/adversarial/
└─ NO ↓

Is this a proptest forall claim?
├─ YES → tests/property/
└─ NO ↓

Is this about backend-to-backend agreement?
├─ YES → tests/backend/
└─ NO ↓

Is this a benchmark?
├─ YES → tests/benchmarks/
└─ NO ↓

Is this a unit test?
├─ YES → inline #[cfg(test)] module
└─ NO → the test does not belong here
```

Nine questions. One answer each. Linear traversal. Every test
has a place.

## Common mistakes in routing

Some mistakes recur in routing decisions. Each has a corrective:

**Mistake: "This is sort of a primitive op test and sort of an
integration test, so I'll put it in both."** Pick one. If the
subject is a specific op, it goes in `primitive_ops/`. If the
subject is composition or IR structure, it goes in
`ir_construction/`. Splitting tests across files makes them
harder to find.

**Mistake: "This is a proptest but it's also testing a specific
case, so I'll put it in integration."** A proptest goes in
`property/`. If the specific case deserves its own test, write
a separate specific-input test in `integration/` and a separate
proptest in `property/`. Do not use proptest as a fancy wrapper
around a specific-input test.

**Mistake: "This test catches a bug I might introduce later,
so it's a regression test."** No. Regression tests are for bugs
that have actually been fixed. Tests for hypothetical bugs are
speculative and belong in the category that matches the
property they verify, not in `regression/`.

**Mistake: "This validation test also exercises lowering, so
I'll put it in lowering."** If the assertion is on the
validator's output (error list), the test belongs in
`validation/`, even if the test incidentally invokes lowering
via shared helpers. The category is determined by the
assertion's subject, not by which functions the test happens
to call.

**Mistake: "I don't know which category applies, so I'll make
a new directory."** New directories in `tests/` require a PR
against this book first. The nine-question tree covers every
valid category; if you think your test needs a new category,
you have either misread the tree or discovered a gap worth
discussing. Either way, talk to a reviewer before creating the
directory.

## Summary

The decision tree is linear, mechanical, and exhaustive. Every
test has exactly one correct category, and the tree tells you
which one. Reaching the end without finding a match means the
test is not a vyre correctness test or the suite has a gap.
Neither outcome is resolved by ignoring the tree.

Next: [Templates](templates.md) — canonical skeletons for the
most common test shapes.
