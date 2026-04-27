# Oracles in practice

## From theory to the test you are writing

The oracles chapter in Part II introduced the hierarchy and
explained why it exists. This chapter applies the hierarchy to
the specific situations a contributor encounters while writing
tests. When you sit down with a test in mind, you need to pick
an oracle, and this chapter walks through the picking.

The principle from Part II: always use the strongest applicable
oracle. The application in practice: ask the questions in order
and stop at the first applicable answer.

## The questions, in order

### Question 1 — Does a declared law cover your property?

If the subject has a declared law that implies the property you
are verifying, use the law. A law oracle is the strongest.

Examples:
- You are testing "add is commutative on these inputs." There
  is a declared `Commutative` law on `Add`. Use the law.
- You are testing "the identity element for add is zero." There
  is a declared `Identity(0)` law on `Add`. Use the law.
- You are testing "xor is self-inverse on these inputs." There
  is a declared `SelfInverse(0)` law on `Xor`. Use the law.
- You are testing "add(a, b) == 7 for a=3, b=4." No law covers
  this specific value. Move to question 2.

Law tests look like this:

```rust
/// Commutativity on specific witnesses.
/// Oracle: DeclaredLaw::Commutative on Add.
#[test]
fn test_add_commutative_on_dead_beef_cafe_babe() {
    let a = 0xDEADBEEFu32;
    let b = 0xCAFEBABEu32;
    let result_ab = run_on_default_backend(&build_single_binop(BinOp::Add, a, b))
        .expect("dispatch");
    let result_ba = run_on_default_backend(&build_single_binop(BinOp::Add, b, a))
        .expect("dispatch");
    assert_eq!(result_ab, result_ba);
}
```

The expected value is `result_ba`, which comes from running the
code. That is fine, because the oracle is the commutativity law,
which asserts the two sides should be equal. The test is not
asserting "the answer is X"; it is asserting "the two sides
agree."

### Question 2 — Is there a specification table row for the inputs?

If the inputs you are testing are in the specification table for
the op, use the table row. A spec table oracle is the next
strongest.

Examples:
- You are testing "add(1, 2) == 3." The spec table has a row
  for these inputs. Use the table.
- You are testing "add(u32::MAX, 1) == 0." The spec table has a
  row for overflow. Use the table.
- You are testing "add(0x1234, 0x5678) == 0x68AC." The spec
  table does not have this specific row. You can either add
  the row (with rationale) or move to question 3.

Spec table tests look like this:

```rust
/// add(u32::MAX, 1) == 0 (wrapping overflow).
/// Oracle: SpecRow from vyre-conform::spec::tables::add row 4.
#[test]
fn test_add_u32_max_plus_one_wraps_to_zero() {
    let program = build_single_binop(BinOp::Add, u32::MAX, 1u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 0u32, "u32::MAX + 1 should wrap to 0");
}
```

The expected value `0u32` is a literal, committed to the spec
table. The test asserts the literal.

### Question 3 — Is your test about a composed Program?

If the test exercises a Program with more than one op (a
composition, a loop, a conditional chain), the spec table does
not cover it because spec tables are per-op. The oracle is the
reference interpreter.

Examples:
- You are testing "(a + b) * c produces the expected value for
  a=5, b=7, c=3." No single-op table row covers this. Use the
  reference interpreter.
- You are testing "a loop that sums 1..10 produces 55." No
  table row covers this. Use the reference interpreter.

Reference interpreter tests look like this:

```rust
/// Sum of 1..10 via a loop is 55. Oracle: reference interpreter.
#[test]
fn test_loop_sum_one_to_ten() {
    let program = build_sum_loop(1, 10);

    let observed = run_on_default_backend(&program).expect("dispatch");
    let expected = vyre_conform::reference::run(&program, &[])
        .expect("reference interpreter");

    assert_eq!(observed, expected);
}
```

The expected value comes from the reference interpreter running
the same Program. If the reference interpreter is correct (which
I8 enforces), the test is correct.

### Question 4 — Is your test about a single op in isolation?

If the test exercises one op without going through a Program
(a unit test on the op's CPU reference function directly, for
example), the oracle is the CPU reference function for that op.
This is weaker than a spec table row because it uses the same
reference function the op dispatches to, so the test is really
about whether the wrapper around the reference function is
correct, not whether the reference function is correct.

CPU reference function tests are rarely used in vyre because
most single-op tests go through a Program (Program-level tests
are stronger). They come up occasionally when testing the
infrastructure that wraps ops, not the ops themselves.

### Question 5 — Is your test about a composition theorem?

If the subject is a composition pattern that the composition
theorems in vyre-conform prove something about, use the
composition theorem as the oracle.

Examples:
- You are testing "a composition of two commutative ops under
  pattern X is itself commutative." The composition theorem for
  X says so. Use the theorem.
- You are testing "an identity composition preserves the
  behavior of the composed op." The composition theorem for
  identity compositions says so. Use the theorem.

Composition theorem tests are rare. Most contributors will
never write one; they appear only when the test exercises a
composition pattern that is specifically proven by a theorem.
See [Property-based testing for GPU IR](../advanced/property-generators.md)
for the cases where composition theorems appear.

### Question 6 — Is your test about a past bug with known inputs?

If the test is reproducing a bug from the past with specific
inputs pulled from a bug report or a fuzz finding, the oracle
is the external source. Document the source in the test's
header comment.

External corpus tests live in `tests/regression/` with a header
comment citing the source. The oracle is whichever source
provided the inputs and the expected behavior.

### Question 7 — Is your test a universal claim over a distribution?

If the test's claim is "for every input in this distribution,
some relation holds," and the test uses proptest, the oracle is
the property itself. The assertion is the relation, not a
specific value.

Property tests look like this:

```rust
proptest! {
    #[test]
    fn wire_format_roundtrip_is_identity(program in arb_program()) {
        let bytes = Program::to_wire(&program);
        let decoded = Program::from_wire(&bytes).unwrap();
        prop_assert_eq!(program, decoded);
    }
}
```

The oracle is "round-trip is identity," and the test asserts
equality of the original and the decoded. No specific value is
pinned down; the claim is about the relation holding for all
inputs.

## When multiple questions apply

A single test can satisfy multiple questions. `test_add_commutative`
is about a declared law (question 1) but also happens to be a
single-op test (question 4). The rule is: use the strongest
oracle. In this case, question 1 (law) wins over question 4
(CPU reference), so the test uses the law oracle.

When in doubt, go with the earlier question's answer. The order
of the questions is the order of the hierarchy.

## When no question applies

If no question applies, you are probably testing something that
does not need a test, or testing a concern the suite has not
thought about yet.

- **"The code compiles."** Not a test. Covered by `cargo check`.
- **"The function does not panic."** This is an adversarial
  test, and the oracle is "did not panic." The oracle is weak
  (property-level) and the test belongs in `tests/adversarial/`.
- **"The output looks reasonable."** Too weak. Figure out what
  "reasonable" means precisely and translate it into a law, a
  spec table row, or a property. If you cannot, the test is not
  verifying anything.

## How to read a test's oracle choice

When reviewing a test, you can check the oracle choice in one
reading:

1. Find the declared oracle in the doc comment. It should be
   there.
2. Check that the declared oracle is applicable to the test. A
   `Commutative` oracle on an op that does not have a
   declared commutativity is wrong.
3. Check that the oracle is the strongest applicable. If the
   test uses a property oracle but a law or table row applies,
   the test should use the stronger oracle.
4. Check that the expected value comes from the oracle. A test
   that declares the spec table as oracle but uses a literal
   that is not in the table is wrong.

Any of these four checks failing is a review finding. The test
is rejected until the oracle is corrected.

## Summary

Pick oracles by walking the seven questions in order. Use the
first applicable answer. Declare the oracle in the test's doc
comment. Ensure the expected value comes from the declared
oracle. Reviewers check the declaration; the discipline is
mechanical. A test with a correct oracle is a test that catches
the bugs it is supposed to catch; a test with a wrong oracle is
a test that gives false confidence.

This concludes Part V. Part VI covers the shapes that look like
tests but are not — the anti-patterns to recognize and reject.

Next: [Anti-patterns overview](../anti-patterns/README.md).
