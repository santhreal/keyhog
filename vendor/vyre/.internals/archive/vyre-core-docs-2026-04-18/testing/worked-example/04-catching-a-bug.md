# Catching a deliberate bug

## Why we break the code

The tests pass. That is encouraging, but it is not proof the
tests are good. A test suite that passes on correct code is the
baseline requirement, not evidence of correctness. The real
question is: does this suite fail on wrong code? If we
deliberately introduce a bug into `Add` and the suite still
passes, the suite has failed at its job regardless of how many
green checks it produces.

This chapter takes the fifteen tests from the previous chapter
and tests them by breaking `Add` in specific ways. Each
deliberate bug is a mutation: a small, targeted change to the
implementation that represents a real class of failure. For
each mutation, we ask: does at least one test fail?

If yes, the suite caught the bug, and we learn the suite is
sensitive to that class of failure.

If no, the suite missed the bug, and we learn the suite has a
gap we need to fill.

Either answer is useful. The "no" answers are the ones that
improve the suite.

## Bug 1: Swap Add for Sub

The first deliberate bug swaps `wrapping_add` for `wrapping_sub`
in `Add`'s CPU reference function:

```rust
// src/ops/primitive/add.rs, BEFORE
pub fn add(args: &[Value]) -> Value {
    Value::U32(args[0].as_u32().wrapping_add(args[1].as_u32()))
}

// src/ops/primitive/add.rs, AFTER the deliberate bug
pub fn add(args: &[Value]) -> Value {
    Value::U32(args[0].as_u32().wrapping_sub(args[1].as_u32()))
}
```

This is the `ArithOpSwap { from: Add, to: Sub }` mutation from
the catalog. It represents a class of bug where the wrong
operator is used — a real bug that occurs historically when a
typo or a misremembered name leads to the wrong operation being
called.

We apply the change, run the suite, and expect every test that
asserts a specific non-trivial sum to fail. Let us trace the
expected failures:

- `test_add_identity_zero_zero_spec_table`: `sub(0, 0) = 0`,
  which equals the expected `0`. **Mutation survives this test**.
- `test_add_right_identity_dead_beef_plus_zero`: `sub(0xDEADBEEF,
  0) = 0xDEADBEEF`, which equals the expected. **Mutation
  survives this test**.
- `test_add_left_identity_zero_plus_cafe_babe`: `sub(0,
  0xCAFEBABE) = 0x3541_4542` (wrapping), which does NOT equal the
  expected `0xCAFEBABE`. **Mutation killed by this test.**
- `test_add_one_plus_two_equals_three`: `sub(1, 2) = 0xFFFFFFFF`
  (wrapping), which does NOT equal the expected `3`. **Mutation
  killed.**
- `test_add_u32_max_plus_one_wraps_to_zero`: `sub(u32::MAX, 1) =
  u32::MAX - 1`, does NOT equal `0`. **Mutation killed.**
- `test_add_u32_max_plus_u32_max_wraps`: `sub(u32::MAX, u32::MAX)
  = 0`, does NOT equal `u32::MAX - 1`. **Mutation killed.**
- `test_add_sign_bit_boundary_wraps_to_zero`: `sub(0x80000000,
  0x80000000) = 0`, which equals the expected. **Mutation
  survives this test.**
- `test_add_bit_pattern_alternation`: `sub(0x55555555,
  0xAAAAAAAA) = 0xAAAAAAAB` (wrapping), does NOT equal
  `0xFFFFFFFF`. **Mutation killed.**
- `test_add_adversarial_dead_beef_plus_cafe_babe`:
  `sub(0xDEADBEEF, 0xCAFEBABE) = 0x14130431`, does NOT equal
  `0xA9A8797D`. **Mutation killed.**
- `test_add_unsigned_interpretation`: `sub(2147483647, 1) =
  2147483646`, does NOT equal `2147483648`. **Mutation killed.**

Seven out of ten spec table tests killed the mutation. That
sounds reassuring until we notice that three survived: the
zero-zero case, the right-identity case with zero, and the
sign-bit boundary case. These survived because in each case,
`sub` happens to produce the same answer as `add` for the
specific inputs used.

The law tests:

- `test_add_commutative`: `sub(a, b)` is not equal to `sub(b,
  a)` in general, so this test fails because the implementation
  no longer satisfies commutativity. **Mutation killed.** The
  law test acted as a safety net for a case the specific-value
  tests happened not to catch.
- `test_add_associative_triple`: `sub` is not associative, and
  the left-associated and right-associated computations will
  produce different results. **Mutation killed.**
- `test_add_identity_zero_law_witness_12345678`: `sub(0x12345678,
  0) = 0x12345678`, equal to expected. But `sub(0, 0x12345678) =
  0xEDCBA988`, NOT equal to `0x12345678`. **Mutation killed.**

All three law tests killed the mutation. The law tests are
narrower than spec-table tests (each asserts one universal
property), but they catch the `ArithOpSwap` mutation reliably
because `sub` violates every one of `add`'s declared laws.

The cross-backend test: the wgpu backend would still use the
correct `Add` lowering, but the reference interpreter would use
the mutated CPU reference function. The mismatch causes the
test to fail. **Mutation killed.**

The composition test: `sub(5, 7) * 3 = 0xFFFFFFFE * 3 =
0xFFFFFFFA`, which the reference interpreter (also using the
mutated reference fn) would produce, so observed and reference
would agree. But wait — does the wgpu backend also use the
mutated reference? It uses a lowering that calls
`src/lower/wgsl/add.rs`, which does not touch `src/ops/primitive/add.rs`.
The wgpu result is still `(5 + 7) * 3 = 36`. The reference
interpreter now computes `(5 - 7) * 3 = 0xFFFFFFFA`. They
disagree. **Mutation killed.**

### What we learned

The mutation was killed by twelve of fifteen tests. Three tests
survived: `identity_zero_zero`, `right_identity_dead_beef`, and
`sign_bit_boundary`. These tests used inputs where `add` and
`sub` produce the same result, which is why they survived.

Twelve kills is enough to catch the mutation. But the fact that
three tests survived is information: those tests are weaker than
the others, and if we had *only* those three, the mutation would
have survived completely. This matters for the mutation gate,
which we will run in the next chapter.

## Bug 2: Wrong identity element

The second bug claims a wrong identity element. Suppose we
accidentally declare the identity of `Add` as `1` instead of `0`:

```rust
// vyre-conform/src/spec/ops/add.rs, BEFORE
laws: &[
    DeclaredLaw { law: Law::Identity(Value::U32(0)), ... },
    // ...
],

// AFTER the deliberate bug
laws: &[
    DeclaredLaw { law: Law::Identity(Value::U32(1)), ... },
    // ...
],
```

This is the `LawIdentityCorrupt` mutation. The implementation of
`Add` is unchanged. The lie is in the declaration: we are saying
`Add`'s identity is `1`, when actually it is `0`.

Which tests catch this? The spec table tests still pass,
because the spec table is unchanged. The cross-backend test
still passes. The composition test still passes.

The law test for identity (`test_add_identity_zero_law_witness_12345678`)
asserts `add(x, 0) == x` on a specific witness. The test does
not check the declaration; it checks the behavior on specific
inputs. The implementation still produces `add(x, 0) = x`, so
the assertion passes. The test also passes.

**The bug survives every test we have written so far.**

This is a real finding. The suite has a gap: lies in the
specification itself are not caught by tests that assert the
behavior directly. We need a mechanism that couples the
declaration to the verification, and that mechanism is the
algebra engine. The engine attempts to verify the declared law
against the implementation, and if the declared identity
element does not actually make the law hold, the verification
fails at build time.

In a properly configured vyre-conform build, this mutation
would not compile: the algebra engine would run at build time,
try `add(x, 1) == x` for some witness (say `x = 0`, so
`add(0, 1) = 1`, which does not equal `0`), detect the
violation, and emit a compile error saying "Law::Identity(1)
does not hold for BinOp::Add". The compile error is the test
that catches this bug.

So the bug is caught, but not by the runtime test suite — it is
caught by the compile-time algebra engine. This is the
separation of concerns we discussed in [Layer
enforcement](../oracles.md): laws are not runtime assertions
but build-time proofs. The mutation gate's `LawIdentityCorrupt`
class is specifically designed to catch this kind of mutation
through the build-time check.

The test suite alone would have missed this. The build-time
check catches it. Together they catch it.

## Bug 3: Remove the shift mask from Add's lowering

The third bug removes a defensive mask from `Add`'s lowering.
Wait — `Add` does not have a shift mask. Let us pick a different
lowering bug: swap the lowered WGSL operator from `+` to `-`.

```rust
// src/lower/wgsl/add.rs, BEFORE
fn emit_add(lhs: &str, rhs: &str) -> String {
    format!("({} + {})", lhs, rhs)
}

// src/lower/wgsl/add.rs, AFTER the deliberate bug
fn emit_add(lhs: &str, rhs: &str) -> String {
    format!("({} - {})", lhs, rhs)
}
```

This is a lowering bug, not an op-level bug. The CPU reference
function is unchanged; the reference interpreter is unchanged.
Only the WGSL lowering is wrong.

Which tests catch this? The spec table tests run the Program
on the default backend (wgpu), which uses the bugged lowering.
Every test that asserts a non-trivial sum fails, just like Bug
1 — except this time it is the wgpu backend that computes the
wrong result, while the reference interpreter (unchanged)
computes the correct result.

The cross-backend test explicitly catches this: the wgpu
backend would disagree with the reference interpreter, and the
assertion `assert_eq!(observed, reference)` would fire with a
clear message pointing at the backend.

The law tests catch it similarly: commutativity is preserved
(both `a + b` and `a - b` become `b - a` when swapped), but
associativity is not, and identity-on-zero is not (`add(x, 0)`
would become `sub(x, 0) = x`, which still holds; but `add(0, x)
= sub(0, x) = -x`, which does not equal `x`).

The composition test catches it: the wgpu backend produces the
wrong composed result, the reference interpreter produces the
correct one, they disagree.

All spec table tests except the same three (zero-zero,
right-identity-zero, sign-bit-boundary) fail. Total kills:
twelve out of fifteen.

### What we learned

The lowering bug is caught by most of the suite, but the same
three tests survive. These three tests are consistently weak
against the "swap add for sub" mutation class because their
inputs happen to produce the same result under either
operation.

## Bug 4: Constant zero in spec table

Suppose a typo in the spec table changes `test_add_unsigned_interpretation`'s
expected value from `2147483648` to `2147483647`:

```rust
// vyre-conform/src/spec/tables/add.rs, BEFORE
SpecRow {
    inputs: &[Value::U32(2147483647), Value::U32(1)],
    expected: Value::U32(2147483648),
    ...
},

// AFTER the typo
SpecRow {
    inputs: &[Value::U32(2147483647), Value::U32(1)],
    expected: Value::U32(2147483647),  // off by one
    ...
},
```

This is a bug in the *oracle*, not in the implementation. The
implementation is correct (`Add(2147483647, 1) = 2147483648`),
but the spec table now claims the expected is `2147483647`.

The test `test_add_unsigned_interpretation` uses a literal
value, not a spec table lookup (we did not implement the helper
that way; the literal is copied from the spec table row at
review time). So the test continues to assert
`assert_eq!(result, 2147483648u32)`, which matches the
implementation, and the test passes.

But the spec table itself is wrong. Any *other* consumer of the
spec table — the vyre-conform generator, a tool that audits the
table against the reference function — would catch the
inconsistency.

In fact, vyre-conform has an integrity check for spec tables:
at build time, it runs every row's inputs through the op's
reference function and asserts the reference's result equals
the declared expected. If they disagree, the build fails. In
our case, the build would fail with "spec table row for Add
inputs (2147483647, 1) declares expected 2147483647, but
reference function returns 2147483648; the spec table is
inconsistent with the reference function".

The build-time check catches this. The runtime test suite does
not. Again, the build-time check and the runtime suite are
complementary.

## What we have learned from the deliberate bugs

Four bugs, each in a different place:

1. Swap `add` for `sub` in the CPU reference function.
2. Claim a wrong identity element in the declaration.
3. Swap `+` for `-` in the WGSL lowering.
4. Introduce a typo in the spec table.

The runtime test suite caught bugs 1, 3 (for most tests) and
ignored bugs 2 and 4. The build-time checks caught bugs 2 and
4. Together, the runtime tests and the build-time checks catch
all four.

This is the division of labor in vyre's testing discipline. The
runtime tests verify behavior against declared oracles. The
build-time checks verify the oracles themselves are consistent
with the implementation. Neither alone is sufficient.

We also learned that three specific tests (zero-zero,
right-identity-zero, sign-bit-boundary) are weak against the
`ArithOpSwap` mutation class because their inputs are
degenerate — the mutation happens not to affect them. Those
tests are not wrong (they test real properties), but they do
not contribute to mutation killing for this specific class.

## The next step

The four deliberate bugs gave us a qualitative picture of the
suite's strength. The next chapter runs the mutation gate,
which does this systematically for every mutation in the
catalog and reports which mutations survive the current suite.
The gate is the mechanical version of what we just did by hand.

The bugs we hand-inspected are examples. The gate covers every
mutation class. If the gate reports zero survivors, the suite
is strong enough to ship. If it reports survivors, we write
more tests and run the gate again. Iteration continues until
the gate is clean.

Next: [Running the mutation gate](05-mutation-gate.md).
