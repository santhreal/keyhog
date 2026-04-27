# Building out the suite

## From one test to ten

The previous chapter wrote one test. This chapter writes the
other nine core tests for `BinOp::Add` and explains the
reasoning behind each. By the end of this chapter, the
hand-written integration test set for `Add` will be complete,
and the mutation gate in the next chapter will tell us whether
it is strong enough.

The nine additional tests cover:

1. The remaining spec table rows not yet covered.
2. The three declared laws on specific inputs.
3. A cross-backend equivalence sweep.
4. An overflow boundary.
5. A bit-pattern adversarial input.
6. A composition with another op.

We will add them in this order because each subsequent test
exercises a slightly larger surface area. The first few tests
are similar to the one from chapter 2; the later ones exercise
more infrastructure.

## Spec table row tests

The spec table has ten rows. The first test (`test_add_identity_zero_zero_spec_table`)
covered row 0. We add tests for each remaining row:

```rust
/// add(x, 0) == x for x = 0xDEADBEEF.
/// Oracle: SpecRow from vyre-conform::spec::tables::add (right identity).
#[test]
fn test_add_right_identity_dead_beef_plus_zero() {
    let program = build_single_binop(BinOp::Add, 0xDEADBEEFu32, 0u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 0xDEADBEEFu32, "add(0xDEADBEEF, 0) should equal 0xDEADBEEF");
}

/// add(0, x) == x for x = 0xCAFEBABE.
/// Oracle: SpecRow from vyre-conform::spec::tables::add (left identity).
#[test]
fn test_add_left_identity_zero_plus_cafe_babe() {
    let program = build_single_binop(BinOp::Add, 0u32, 0xCAFEBABEu32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 0xCAFEBABEu32, "add(0, 0xCAFEBABE) should equal 0xCAFEBABE");
}

/// add(1, 2) == 3. Basic arithmetic.
/// Oracle: SpecRow (hand-written, "basic addition").
#[test]
fn test_add_one_plus_two_equals_three() {
    let program = build_single_binop(BinOp::Add, 1u32, 2u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 3u32, "add(1, 2) should equal 3");
}

/// add(u32::MAX, 1) == 0. Wrapping overflow.
/// Oracle: SpecRow (hand-written, "overflow").
#[test]
fn test_add_u32_max_plus_one_wraps_to_zero() {
    let program = build_single_binop(BinOp::Add, u32::MAX, 1u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 0u32, "add(u32::MAX, 1) should wrap to 0");
}

/// add(u32::MAX, u32::MAX) == u32::MAX - 1. Double wrap.
/// Oracle: SpecRow (hand-written, "double overflow").
#[test]
fn test_add_u32_max_plus_u32_max_wraps() {
    let program = build_single_binop(BinOp::Add, u32::MAX, u32::MAX);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(
        result, u32::MAX - 1,
        "add(u32::MAX, u32::MAX) should wrap to u32::MAX - 1",
    );
}

/// add(0x80000000, 0x80000000) == 0. Sign-bit boundary.
/// Oracle: SpecRow (hand-written, "sign-bit boundary").
#[test]
fn test_add_sign_bit_boundary_wraps_to_zero() {
    let program = build_single_binop(BinOp::Add, 0x8000_0000u32, 0x8000_0000u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 0u32, "add(2^31, 2^31) should wrap to 0");
}

/// add(0x55555555, 0xAAAAAAAA) == 0xFFFFFFFF. Bit-pattern fill.
/// Oracle: SpecRow (hand-written, "bit-pattern alternation").
#[test]
fn test_add_bit_pattern_alternation() {
    let program = build_single_binop(
        BinOp::Add, 0x5555_5555u32, 0xAAAA_AAAAu32,
    );
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(
        result, 0xFFFF_FFFFu32,
        "add(0x55..., 0xAA...) should equal 0xFF...",
    );
}

/// add(0xDEADBEEF, 0xCAFEBABE) == 0xA9A8797D. Adversarial inputs.
/// Oracle: SpecRow (hand-written, "adversarial inputs").
#[test]
fn test_add_adversarial_dead_beef_plus_cafe_babe() {
    let program = build_single_binop(BinOp::Add, 0xDEADBEEFu32, 0xCAFEBABEu32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(
        result, 0xA9A8_797Du32,
        "add(0xDEADBEEF, 0xCAFEBABE) should equal 0xA9A8797D",
    );
}

/// add(i32::MAX as u32, 1) == 2^31. Unsigned interpretation.
/// Oracle: SpecRow (hand-written, "unsigned interpretation").
#[test]
fn test_add_unsigned_interpretation() {
    let program = build_single_binop(BinOp::Add, 2_147_483_647u32, 1u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(
        result, 2_147_483_648u32,
        "add(i32::MAX as u32, 1) should equal 2^31 = 2147483648",
    );
}
```

Nine more tests. Ten total. Each is a direct translation of a
spec table row into a test function. The pattern is uniform:
build, run, assert, with an oracle declaration in the doc
comment.

Reading these tests end to end, the reader sees exactly which
inputs have been verified and exactly what the expected outputs
are. Every expected value is a literal from the spec table.
Every oracle is declared. Every assertion has a failure message
that identifies the specific case.

## Law tests

The spec table covers specific inputs. Law tests cover
universal properties on specific inputs. For `Add`, we have
three declared laws, each of which deserves a test:

```rust
/// Commutativity: add(a, b) == add(b, a).
/// Oracle: DeclaredLaw::Commutative, verified ExhaustiveU8.
#[test]
fn test_add_commutative_dead_beef_cafe_babe() {
    let a = 0xDEADBEEFu32;
    let b = 0xCAFEBABEu32;

    let program_ab = build_single_binop(BinOp::Add, a, b);
    let program_ba = build_single_binop(BinOp::Add, b, a);

    let result_ab = run_on_default_backend(&program_ab).expect("dispatch ab");
    let result_ba = run_on_default_backend(&program_ba).expect("dispatch ba");

    assert_eq!(
        result_ab, result_ba,
        "add is commutative: add({:#x}, {:#x}) should equal add({:#x}, {:#x})",
        a, b, b, a,
    );
}

/// Associativity: add(add(a, b), c) == add(a, add(b, c)).
/// Oracle: DeclaredLaw::Associative, verified ExhaustiveU8.
#[test]
fn test_add_associative_triple() {
    let a = 0xDEADBEEFu32;
    let b = 0xCAFEBABEu32;
    let c = 0x5555_5555u32;

    // Left-associated: (a + b) + c
    let left = build_program()
        .compute(|p| {
            let ab = p.add(p.const_(a), p.const_(b));
            let abc = p.add(ab, p.const_(c));
            p.store("out", abc);
        })
        .build();

    // Right-associated: a + (b + c)
    let right = build_program()
        .compute(|p| {
            let bc = p.add(p.const_(b), p.const_(c));
            let abc = p.add(p.const_(a), bc);
            p.store("out", abc);
        })
        .build();

    let left_result = run_on_default_backend(&left).expect("dispatch left");
    let right_result = run_on_default_backend(&right).expect("dispatch right");

    assert_eq!(
        left_result, right_result,
        "add is associative: (a + b) + c should equal a + (b + c)",
    );
}

/// Identity on zero: add(x, 0) == x and add(0, x) == x.
/// Oracle: DeclaredLaw::Identity(Value::U32(0)), verified ExhaustiveU8.
///
/// This test exercises the identity law for a specific witness x.
/// It is distinct from the spec table tests for right and left
/// identity: those test specific rows (0 and x, with x = 0xDEADBEEF
/// and x = 0xCAFEBABE), while this test exercises the law with a
/// different witness and asserts against the law, not against a
/// table row.
#[test]
fn test_add_identity_zero_law_witness_12345678() {
    let x = 0x1234_5678u32;

    let right_identity = build_single_binop(BinOp::Add, x, 0u32);
    let left_identity = build_single_binop(BinOp::Add, 0u32, x);

    let right_result = run_on_default_backend(&right_identity).expect("dispatch");
    let left_result = run_on_default_backend(&left_identity).expect("dispatch");

    assert_eq!(right_result, x, "add(x, 0) should equal x");
    assert_eq!(left_result, x, "add(0, x) should equal x");
}
```

Three law tests. Each declares the law it is testing in the
comment. Each uses specific witness inputs to exercise the law.
Each asserts the law's prediction without deriving the expected
value from the code under test.

The commutativity test has a subtle detail worth noting: the
expected value is `result_ba`, not some literal. This looks like
deriving the expected from the code under test, but it is not.
The assertion is not "add(a, b) equals this specific value";
it is "add(a, b) equals add(b, a)". The law is the oracle, and
both sides of the assertion come from running the code. A bug
that breaks commutativity (but preserves the symmetry in some
other way) would not be caught by this test alone — but the
spec table tests cover specific values, which means commutativity
combined with specific-value tests pins down the behavior.

This is why law tests and spec table tests are complementary.
Alone, either could miss a class of bugs. Together, they cover
both the relation (commutativity) and the specific values.

The associativity test uses a more complex Program with two
ops composed. We introduce a `build_program()` builder helper
from `tests/support/programs.rs` that produces Programs with
multi-step computations. The helper is less common than
`build_single_binop` but is used whenever a test needs more than
one op in a Program.

## Cross-backend equivalence

One test exercises cross-backend equivalence:

```rust
/// BinOp::Add on every registered backend agrees with the reference
/// interpreter byte-for-byte.
/// Oracle: reference interpreter (for I3).
/// Skip: needs ≥ 1 backend plus the reference interpreter.
#[test]
fn test_add_cross_backend_reference_equivalence() {
    let program = build_single_binop(BinOp::Add, 0xDEADBEEFu32, 0xCAFEBABEu32);

    let reference = vyre_conform::reference::run(&program, &[])
        .expect("reference interpreter");

    for backend in vyre::runtime::registered_backends() {
        let observed = backend.run(&program, &[])
            .expect("backend dispatch");
        assert_eq!(
            observed, reference,
            "backend {} disagreed with reference interpreter",
            backend.name(),
        );
    }
}
```

The test is a single-op cross-backend sweep using the reference
interpreter as the oracle. It runs `Add` with our adversarial
bit-pattern inputs on every registered backend and verifies
every backend agrees with the reference interpreter. This
covers invariant I3 for `Add`.

The test does not skip on a single-backend environment because
it uses the reference interpreter as the oracle, and the
reference interpreter is always available. If only wgpu is
registered, the test still compares wgpu against the reference,
which is enough to catch a wgpu regression. If additional
backends are registered, the test compares each against the
reference, catching any drift.

## Composition test

One test exercises composition with another op:

```rust
/// Composition: (a + b) * c == add then mul.
/// Oracle: reference interpreter.
#[test]
fn test_add_composition_with_mul_matches_reference() {
    let program = build_program()
        .compute(|p| {
            let sum = p.add(p.const_(5u32), p.const_(7u32));
            let product = p.mul(sum, p.const_(3u32));
            p.store("out", product);
        })
        .build();

    let observed = run_on_default_backend(&program).expect("dispatch");
    let reference = vyre_conform::reference::run(&program, &[])
        .expect("reference interpreter");

    assert_eq!(
        observed, reference,
        "composition (a + b) * c should match reference interpreter",
    );
}
```

The test builds a Program with `Add` composed with `Mul` and
asserts the observed result matches the reference. The specific
arithmetic ((5 + 7) * 3 = 36) is easy to verify by hand, and
the reference interpreter is the independent oracle.

This test is in `tests/integration/primitive_ops/add.rs` rather
than `tests/integration/ir_construction/` because the subject
is still `Add` — we are verifying that `Add` composes correctly,
which is a property of `Add` as much as of composition itself.
A more general composition test (exercising a shape that does
not specifically focus on `Add`) would live in
`ir_construction/`.

## Summary of the suite so far

The hand-written integration suite for `Add` now has thirteen
tests:

- Ten spec table row tests
- Three law tests
- One cross-backend equivalence test
- One composition test

That is fifteen tests total. Wait — ten plus three plus one plus
one is fifteen, not thirteen. Let me recount: we had one
identity-zero test from chapter 2, plus nine more spec table
tests, plus three laws, plus the cross-backend, plus the
composition. That is 1 + 9 + 3 + 1 + 1 = 15 tests.

Fifteen tests is more than the ten minimum from the integration
tests chapter. The extras come from covering specific spec table
rows and adding the composition check. This is the expected
shape: the floor is ten, and real tests go beyond the floor for
ops with multiple laws or complex semantics.

The tests file is now about 200 lines of code plus comments.
Every test is independent. Every test has an oracle declared.
Every test can be invoked individually via `cargo test
<name_substring>`. The file reads top to bottom as a coherent
documentation of what `Add` must do.

## What remains

The tests cover the spec table, the laws, cross-backend
equivalence, and a composition case. They have not yet been
graded. In the next chapter, we introduce a deliberate bug into
the `Add` implementation and verify that the tests catch it.
Then we run the mutation gate and discover which mutations
survive, indicating which tests we still need to write.

Next: [Catching a deliberate bug](04-catching-a-bug.md).
