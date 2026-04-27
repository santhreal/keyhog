# Integration tests

## The category where vyre's promise is tested

Integration tests are the largest category in vyre's suite and the
one that matters most for users. When a user writes an
`ir::Program` and runs it, they are invoking the full pipeline:
construction, validation, lowering, dispatch, and the backend's
execution of the generated shader. Every stage of that pipeline
has to work correctly, and the stages have to cooperate.
Integration tests are the category that exercises the full
pipeline end to end on specific inputs with oracle-backed expected
outputs.

The name "integration" is borrowed from the Rust ecosystem, where
tests outside the `src/` tree are called integration tests because
they compile against the crate as an external consumer and can
only use the public API. vyre's integration tests do both of those
things, but the name here is doing more work than that. These are
tests that integrate the pipeline stages — where unit tests look
at one function in isolation, integration tests look at the whole
machine.

## The five subcategories

Integration tests are subdivided into five subcategories, each
with a distinct subject:

- **`integration/primitive_ops/`** — tests for individual primitive
  ops (Add, Mul, Xor, etc.) exercised through a complete Program.
  One file per op. The bulk of per-op hand-written correctness
  coverage.
- **`integration/ir_construction/`** — tests for Program building,
  visiting, and encoding. Verifies that the IR data structures
  work correctly and that composition is well-behaved.
- **`integration/validation/`** — tests for the V001..V020
  validation rules. One must-reject and one must-accept per rule,
  plus the separability meta-test.
- **`integration/lowering/`** — tests for `lower::wgsl::lower()`.
  Covers every Expr, Node, BinOp, UnOp, AtomicOp, and BufferAccess
  variant, and verifies that lowered shaders have bounds checks
  and shift masks.
- **`integration/wire_format/`** — tests for wire format ↔ IR conversion
  and round-trip identity.

Each subcategory has its own chapter in Part III with the full
treatment. This chapter covers the conventions, patterns, and
discipline that apply across all of them.

## What every integration test has in common

Regardless of which subcategory it lives in, every integration
test shares the same structure:

1. **Construct** an `ir::Program` using builder APIs or direct
   construction.
2. **Optionally validate** the Program (depending on what the test
   is verifying).
3. **Optionally lower** the Program to a backend shader.
4. **Optionally dispatch** the lowered shader on a backend.
5. **Observe** the output.
6. **Assert** the output against an independent oracle.

A specific test may stop at any step depending on its subject. A
validation test stops at step 2. A lowering test stops at step 3.
A primitive op test goes all the way through step 6. The structure
is the same; the depth varies.

```rust
/// BinOp::Add of (u32::MAX, 1) wraps to 0.
/// Oracle: SpecRow from vyre-conform spec table (overflow behavior).
#[test]
fn test_add_u32_max_plus_one_wraps_to_zero() {
    // Step 1: construct
    let program = build_single_binop(
        BinOp::Add,
        Value::U32(u32::MAX),
        Value::U32(1),
    );

    // Step 2: validate
    validate(&program).expect("program is well-formed");

    // Step 3: lower
    let shader = wgsl::lower(&program).expect("lowering succeeds");

    // Step 4: dispatch
    let result = default_backend()
        .dispatch(&shader, &program.buffers)
        .expect("dispatch succeeds");

    // Step 5: observe
    let output = result.get_u32(0);

    // Step 6: assert
    assert_eq!(output, 0, "u32::MAX + 1 should wrap to 0");
}
```

Six steps, each doing one thing. The test is readable top to
bottom. A reader who has never seen this test before can understand
what it does without leaving the file, because every step is
inline and every expected value has a visible justification.

In practice, most tests do not write out all six steps explicitly —
they use helpers from `tests/support/` to collapse repeated
boilerplate:

```rust
/// BinOp::Add of (u32::MAX, 1) wraps to 0.
/// Oracle: SpecRow from vyre-conform spec table (overflow behavior).
#[test]
fn test_add_u32_max_plus_one_wraps_to_zero() {
    let program = build_single_binop(BinOp::Add, 0xFFFF_FFFFu32, 1u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 0u32, "u32::MAX + 1 should wrap to 0");
}
```

The second form is the idiomatic shape. The six steps are still
there, but the helpers (`build_single_binop`,
`run_on_default_backend`) compress them into a readable form. The
helpers are small and their names are descriptive; a reader who
does not know what `run_on_default_backend` does can infer it in
one sentence.

The rule for helper use is that the helper's name must tell the
reader what the helper does, at the level of abstraction the test
needs. `build_single_binop(op, a, b)` is fine because "build a
Program with one binary op" is exactly what the reader needs to
know. `build_test_case(config)` would be wrong because the reader
has to open `config` to figure out what the test is actually doing.
See [Support utilities](../writing/support-utilities.md) for the
full rule.

## Oracles in integration tests

Integration tests use the strongest oracle in the hierarchy that
applies to the subject. For primitive op tests, that is usually a
specification table row or an algebraic law. For composed
Program tests, it is usually the reference interpreter. For
validation tests, the "oracle" is the rule definition itself — the
test asserts the validator returns the expected `ValidationRule`
variant.

The hierarchy from [Oracles](../oracles.md) applies without
exception:

1. Algebraic law — strongest.
2. Specification table row.
3. Reference interpreter.
4. CPU reference function.
5. Composition theorem.
6. External corpus.
7. Property.

If more than one oracle applies to a test's property, the
strongest is used. If none of the first four apply, the test is
likely either a property test that belongs in `tests/property/` or
a test with an ambiguous subject that needs to be split.

## The density requirement

Each file in `integration/primitive_ops/` must have at least ten
tests for its op. This is a floor, not a target. The specific
tests required are:

- **Identity-pair tests (archetype A1)**: at least one.
- **Overflow-pair tests (archetype A2)**: at least one for ops
  whose type can overflow.
- **Power-of-two boundary tests (archetype A3)**: at least one for
  ops that are sensitive to bit-level boundaries.
- **Bit-pattern alternation tests (archetype A5)**: at least one.
- **Law tests**: at least one per declared law on the op.
- **Minimum program test (archetype S1)**: at least one.
- **Backend equivalence test (archetype X1)**: at least one.

For an op with three declared laws, that is a minimum of ten tests.
Ops with more complex signatures or more laws have more. The
point is that ten is the starting point; the actual number depends
on how much coverage the op's semantics require.

When the archetype catalog or the mutation gate indicates a test
is missing (a mutation survives that should be killed, or an
applicable archetype has not been instantiated), the count grows
until all findings are addressed.

## The composition tests

`integration/ir_construction/` contains composition tests —
tests that exercise Programs with more than one op. These are the
tests that verify invariant I2 (composition lowering commutes with
pipeline lowering).

A composition test builds a Program with multiple ops, runs it,
and asserts the output equals the sequential equivalent:

```rust
/// Sequential composition: Add then Mul produces the same result
/// as running Add to produce intermediate and then Mul on the
/// intermediate.
/// Oracle: reference interpreter.
#[test]
fn test_add_then_mul_equals_sequential() {
    let composed = build_program()
        .buffer("x", DataType::U32, 1)
        .buffer("y", DataType::U32, 1)
        .buffer("z", DataType::U32, 1)
        .buffer("out", DataType::U32, 1)
        .compute(|prog| {
            let tmp = prog.add(prog.load("x"), prog.load("y"));
            let result = prog.mul(tmp, prog.load("z"));
            prog.store("out", result);
        })
        .build();

    let inputs = [Value::U32(2), Value::U32(3), Value::U32(4)];
    let composed_result = run(&composed, &inputs).expect("dispatch");

    let reference_result = vyre_conform::reference::run(&composed, &inputs)
        .expect("reference interpreter");

    assert_eq!(composed_result, reference_result);
}
```

The oracle is the reference interpreter, which is an independent
implementation of Program semantics. The composed result agreeing
with the reference is the proof that the pipeline preserved
semantics through composition. If they disagree, either the
lowering is wrong or the reference interpreter is wrong, and the
suite's first job is to figure out which.

## The validation tests

Validation tests have a specific pattern that does not appear in
the other subcategories: they assert on the error list returned by
`validate()`, not on the output of running the Program. A
validation test never runs the Program; the whole point is that
the Program should be rejected before running.

```rust
/// V001: duplicate buffer names are rejected.
/// Oracle: V-rule definition in src/ir/validate.rs.
#[test]
fn test_v001_rejects_duplicate_buffer_name() {
    let mut program = Program::empty();
    program.buffers.push(BufferDecl::new("foo", DataType::U32, 16));
    program.buffers.push(BufferDecl::new("foo", DataType::U32, 16));

    let errors = validate(&program);
    assert_eq!(errors.len(), 1, "expected exactly one error");
    assert_eq!(errors[0].rule, ValidationRule::V001);
}

/// V001: distinct buffer names are accepted.
/// Oracle: V-rule definition in src/ir/validate.rs.
#[test]
fn test_v001_accepts_distinct_buffer_names() {
    let mut program = Program::empty();
    program.buffers.push(BufferDecl::new("foo", DataType::U32, 16));
    program.buffers.push(BufferDecl::new("bar", DataType::U32, 16));

    let errors = validate(&program);
    assert!(errors.is_empty(), "expected no errors, got {:?}", errors);
}
```

The must-reject asserts exactly one error with the expected rule.
The must-accept asserts no errors. Together, they pin down the rule's
behavior on both sides of the boundary and make the rule independently
triggerable (which the separability meta-test verifies across the
whole rule set).

See [Validation tests](validation.md) for the complete treatment of
this subcategory, including the separability audit.

## The lowering tests

Lowering tests exercise `lower::wgsl::lower()` — the conversion
from `ir::Program` to WGSL shader source. The tests verify that
every IR construct has a lowering, that the lowered output is
valid WGSL, and that safety properties (bounds checks, shift
masks) are preserved.

The most important lowering tests are the meta-tests that
enumerate IR enum variants:

```rust
/// Every Expr variant has a lowering test.
/// Oracle: compile-time exhaustiveness match.
#[test]
fn test_every_expr_variant_is_lowered() {
    // This match intentionally covers every variant.
    // Adding a new Expr variant requires adding a case here,
    // which forces a lowering test for the new variant.
    let covered: fn(&Expr) -> bool = |expr| match expr {
        Expr::Const(_) => test_lowering_of_const(),
        Expr::Load(_) => test_lowering_of_load(),
        Expr::BinOp { .. } => test_lowering_of_binop(),
        Expr::UnOp { .. } => test_lowering_of_unop(),
        Expr::Atomic { .. } => test_lowering_of_atomic(),
        Expr::Index { .. } => test_lowering_of_index(),
        Expr::Cast { .. } => test_lowering_of_cast(),
        // ... all variants
    };
    // The function is never called; the match is the test.
    let _ = covered;
}
```

The trick is that Rust's exhaustiveness checker enforces the
coverage at compile time. If someone adds a new `Expr` variant and
does not add a case to this match, the file does not compile.
The broken build is the finding: write the lowering test for the
new variant before the code compiles.

See [Lowering tests](lowering.md) for the full treatment of this
pattern and the specific tests required for each IR construct.

## The wire format tests

Wire format tests exercise the IR wire format ↔ IR conversion paths. Every
wire tag must have a `from_wire` test. Every IR shape with a wire format
representation must have a `to_wire` test. A corpus of
Programs is round-tripped to verify byte-identical encoding.

See [Wire format tests](wire_format.md).

## Discipline rules

A few discipline rules apply across all integration test
subcategories:

- **Every test has a one-line doc comment** stating what it
  verifies and which oracle it uses. Tests without this comment
  are rejected at review.
- **Every test asserts specific expected values**, not
  existence. `assert_eq!(result, 42)` is correct;
  `assert!(result > 0)` is usually wrong (too weak to catch real
  bugs).
- **Every test uses specific inputs** from the archetype catalog
  or from hand-written spec table rows. Random inputs belong in
  property tests, not integration tests.
- **Every test is standalone**: constructs its own Program, runs
  it, asserts. No shared mutable state between tests. No test
  depends on another test having run first.
- **Every test handles errors explicitly**: `expect("what this
  should succeed at")` with a clear message. No `.unwrap()`
  without context. No silent error swallowing.
- **Every test is fast enough to run in CI**: integration tests
  should complete in under a second each. A test that takes
  longer is doing too much or should be marked `#[ignore]` and
  run only in release CI.

## When integration tests are not enough

Integration tests are strong but they are not the whole suite.
They cover specific inputs; they do not cover the combinatorial
space of possible inputs. They cover the pipeline with specific
backends; they do not prove that every future backend will
behave correctly. They catch bugs introduced today; they do not
catch all possible future bugs.

Complement integration tests with:

- **Property tests** for universal claims over input spaces.
- **Backend tests** for cross-backend equivalence stress.
- **Adversarial tests** for hostile inputs.
- **Regression tests** for past bugs that integration tests did
  not catch the first time.

An integration test is a statement of fact about a specific input.
The suite as a whole is stronger than any single statement,
because the statements compose.

## Summary

Integration tests exercise the full pipeline on specific inputs
with independent oracles. They are the bulk of vyre's hand-written
correctness coverage and the category where invariants are
verified at the level a user cares about. Five subcategories
(primitive_ops, ir_construction, validation, lowering, wire_format)
split the work by subject. The next chapters cover each
subcategory in detail.

Next: [Validation tests](validation.md).
