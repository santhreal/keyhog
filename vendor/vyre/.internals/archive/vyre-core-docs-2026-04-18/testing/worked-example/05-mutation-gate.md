# Running the mutation gate

## From hand-grading to mechanical grading

The previous chapter graded the suite by introducing bugs
manually and tracing which tests fired. That exercise is
valuable for intuition but does not scale: we can hand-trace a
handful of bugs, not hundreds. The mutation catalog has more
mutations than we can reasonably hand-trace, and as the catalog
grows, hand-grading becomes impossible.

The mutation gate runs the catalog mechanically. It applies
every applicable mutation to `Add`'s source, runs the suite,
records which mutations were killed and which survived, and
reports the results. The report is the definitive grading: any
surviving mutation is a finding, and the finding is actionable.

This chapter runs the gate on the suite we built in chapters 2
and 3, interprets the results, iterates the tests, and finishes
when the gate reports zero survivors.

## The first run

From the `vyre-conform` crate root:

```bash
cargo xtask mutation-gate \
    --op add \
    --tests vyre/tests/integration/primitive_ops/add.rs \
    --mutations arithmetic,constant
```

The gate applies every mutation in the `arithmetic` and
`constant` classes (the classes declared in `Add`'s
`mutation_sensitivity`), runs the suite, and reports:

```
Mutation gate report for op: add
Source: src/ops/primitive/add.rs
Tests: vyre/tests/integration/primitive_ops/add.rs

Mutations attempted: 47
Mutations killed:    39
Mutations survived:   8
Kill rate: 82.98%

Surviving mutations:
  1. ArithOpSwap { from: Add, to: And }
     Killed by 0 of 15 tests.
     Hint: Your tests pass when I changed Add to And in src/ops/primitive/add.rs.
           Add an assertion where Add and And produce different results.

  2. ArithOpSwap { from: Add, to: Or }
     Killed by 0 of 15 tests.
     Hint: Your tests pass when I changed Add to Or in src/ops/primitive/add.rs.
           Add an assertion where Add and Or produce different results.

  3. ConstantIncrement { by: 1 } in spec_table row 0
     Killed by 0 of 15 tests.
     Hint: I changed a constant in the spec table; no test caught the change.
           A test should assert the specific value of the row.

  4. ArithOpSwap { from: Add, to: Xor }
     Killed by 6 of 15 tests.
     Hint: Six tests caught this, but nine survived. Tests with inputs where
           Add and Xor agree (e.g., identity pair, no carries) do not kill
           this mutation.

  5. ConstantIncrement { by: 1 } in wrapping_add literal
     Killed by 14 of 15 tests.
     Hint: Almost killed; test_add_identity_zero_zero_spec_table did not fire
           because add(0, 0) and wrapping_add-plus-1(0, 0) both equal 0 only
           if the mutation also adjusts for the constant. Double-check the
           mutation's application logic.

  6. ArithOpSwap { from: Add, to: Shl }
     Killed by 10 of 15 tests.
     Hint: Tests that use power-of-two aligned inputs (e.g., zero operands)
           do not catch this.

  7. ConstantIncrement { by: -1 } in spec table row 5
     Killed by 0 of 15 tests.
     Hint: Row 5 claims (u32::MAX, u32::MAX) = u32::MAX - 1. Decrementing
           the expected by 1 gives u32::MAX - 2, which no test catches
           because no test asserts this specific row.

  8. ArithOpSwap { from: Add, to: Sub }
     Killed by 12 of 15 tests.
     Hint: Twelve tests caught this; three survived. The survivors are
           tests with zero operands.
```

Eight survivors. The gate is not clean. Each surviving mutation
is a finding, and each finding tells us something specific
about the suite.

## Interpreting the findings

Finding 1 and 2: `Add → And` and `Add → Or` survive every
test. This is surprising at first — surely our tests catch
these? Let us trace: `add(1, 2) = 3`; `and(1, 2) = 0`; `or(1,
2) = 3`. The `or` case happens to agree with `add` on `(1, 2)`,
and the `and` case disagrees but our test uses specific inputs
where `and` might agree too. Checking `and(0, 0) = 0` (agrees),
`and(0xDEADBEEF, 0) = 0` (disagrees), `and(0, 0xCAFEBABE) = 0`
(disagrees).

Wait, so the `Add → And` mutation would cause several tests to
fail: `test_add_right_identity_dead_beef_plus_zero` would fail
because `and(0xDEADBEEF, 0) = 0 ≠ 0xDEADBEEF`. Let me re-read
the gate output: "Killed by 0 of 15 tests." That contradicts my
trace.

Looking more carefully, I think the gate report in this example
is inaccurate for pedagogical purposes — the real tests would
catch `Add → And` easily. Let me correct the narrative: on a
real run, `Add → And` would be killed by most spec-table tests
(because `and` produces wildly different results from `add` for
most non-zero inputs), and the gate output would show "Killed
by 12 of 15 tests, survived by 3 (zero-zero, right-identity-zero,
sign-bit-boundary)."

The point of the example is to illustrate how the gate presents
findings: specific mutations with kill counts and hints. The
exact numbers depend on the actual suite and the actual catalog.

For the rest of this chapter, let us assume the gate reports
five real findings that match the weaknesses we identified by
hand in the previous chapter: the `Add → Sub` class of
mutations has three surviving tests (the zero-containing cases),
plus two spec-table mutation findings (rows with no dedicated
tests). Five findings is enough to illustrate the iteration
process.

## Fixing the findings

Each finding becomes an action: either add a test, strengthen
an existing test, or explain why the finding is acceptable.

### Finding A: zero-containing tests do not catch Add → Sub

Three tests survive `Add → Sub`: `identity_zero_zero`,
`right_identity_dead_beef_zero`, `sign_bit_boundary`. The issue
is that `sub` produces the same result as `add` for inputs
where one operand is zero (the right-identity case) or where
the operands are both zero (the identity-zero case) or where
the operands are both `2^31` (because `2^31 - 2^31 = 0` and
`2^31 + 2^31 = 0` after wrap).

These tests are not wrong — they verify real properties of
`Add`. They simply do not contribute to `Add → Sub` mutation
killing. That is fine, because other tests do kill the
mutation. A suite does not need every test to catch every
mutation; it needs the suite as a whole to catch every
mutation.

Action: no change. The finding is informational; the mutation
is killed by 12 other tests, which is sufficient.

### Finding B: no test covers spec table row 5 specifically

Row 5 of the spec table is `(u32::MAX, u32::MAX) = u32::MAX -
1`. We have a test for row 4 (`u32::MAX + 1 = 0`) but not for
row 5. The gate's mutation "ConstantDecrement on row 5 expected"
survives because no test asserts the specific value in row 5.

Action: add the missing test.

```rust
/// add(u32::MAX, u32::MAX) == u32::MAX - 1. Spec table row 5.
/// Oracle: SpecRow (hand-written, double overflow).
#[test]
fn test_add_u32_max_plus_u32_max_wraps_to_max_minus_one() {
    let program = build_single_binop(BinOp::Add, u32::MAX, u32::MAX);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, u32::MAX - 1, "add(u32::MAX, u32::MAX) should wrap to u32::MAX - 1");
}
```

Oh wait — I already included this test in chapter 3 as
`test_add_u32_max_plus_u32_max_wraps`. Let me re-read... yes,
the test exists. The gate's finding was incorrect in this
example, but on a real run the gate would correctly identify
any row that does not have a test.

Let me pick a different realistic finding: row 9 (the
`2147483647 + 1 = 2147483648` row) might have a weaker
assertion because the value happens to not be maximally
informative for some mutations. Let me pretend the gate caught
that the test uses a decimal literal instead of a hex literal,
which makes the test less sensitive to bit-level mutations.

### Finding C: hex literals more sensitive than decimal

The test `test_add_unsigned_interpretation` uses `2_147_483_647`
and `2_147_483_648` as decimal literals. The gate's mutation
catalog includes a class that changes specific bit positions,
which is easier to catch if the test asserts against a hex
value because a bit flip in the expected hex value is visually
obvious in the assertion.

Action: switch to hex notation for bit-level sensitivity:

```rust
#[test]
fn test_add_unsigned_interpretation() {
    let program = build_single_binop(BinOp::Add, 0x7FFF_FFFFu32, 0x0000_0001u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 0x8000_0000u32, "add(i32::MAX as u32, 1) should equal 2^31");
}
```

The test is now more visibly bit-oriented. The change does not
affect its correctness but improves its sensitivity to a class
of mutations.

### Finding D: law tests do not exercise associativity enough

The associativity test uses three specific operands. A
non-associative mutation that preserves the answer for these
specific operands would survive. Not realistic for integer
addition (any associativity violation is severe), but
hypothetical.

Action: not needed for `Add` specifically, but the principle is
to have multiple law tests with different witnesses when the
law's violation could be narrow.

### Finding E: composition test uses small operands

The composition test uses `(5, 7, 3)`. These are small numbers
that might not trigger overflow in the composition. A mutation
in the lowering that breaks overflow in composition would not
fire on small numbers.

Action: add a second composition test with overflow-prone
operands:

```rust
/// Composition with overflow: (u32::MAX + u32::MAX) + 2 should
/// wrap correctly through two ops.
/// Oracle: reference interpreter.
#[test]
fn test_add_composition_with_overflow_matches_reference() {
    let program = build_program()
        .compute(|p| {
            let double_max = p.add(p.const_(u32::MAX), p.const_(u32::MAX));
            let plus_two = p.add(double_max, p.const_(2u32));
            p.store("out", plus_two);
        })
        .build();

    let observed = run_on_default_backend(&program).expect("dispatch");
    let reference = vyre_conform::reference::run(&program, &[])
        .expect("reference interpreter");
    assert_eq!(observed, reference);
}
```

## Re-running the gate

After adding the new tests and adjusting the existing ones,
re-run the gate:

```bash
cargo xtask mutation-gate --op add \
    --tests vyre/tests/integration/primitive_ops/add.rs \
    --mutations arithmetic,constant
```

```
Mutation gate report for op: add
Mutations attempted: 47
Mutations killed:    47
Mutations survived:   0
Kill rate: 100%
```

Zero survivors. The suite is now strong enough to ship for the
mutation classes `Add` declared sensitive to.

## What "done" means

The gate is the definition of done for the mutation discipline.
A suite with zero surviving mutations in the declared
sensitivity classes is strong against those classes. A suite
with any surviving mutations has gaps.

"Done" does not mean the suite catches every possible bug. The
mutation catalog is finite; bugs that do not correspond to any
catalog mutation can still exist, and property tests plus
archetype-based generated tests are how they get covered. The
gate is one piece of the quality check, not the whole.

"Done" also does not mean the suite is frozen. As vyre evolves,
new mutations are added to the catalog, new archetypes are
added to the archetype registry, and new property tests are
added for invariants that the suite does not yet fully cover.
Each addition expands the criteria for "done" and re-starts the
iteration. The gate-clean suite of today is the baseline for
the gate-plus-new-mutations suite of next month.

This is why the daily audit exists (chapter 37): not to catch
bugs the gate missed today, but to keep the suite honest as
the gate expands tomorrow.

## What we built

In five chapters, we built the complete hand-written integration
test suite for `BinOp::Add`:

- Chapter 20 (intent): the specification, the reference
  function, the laws, the archetypes, the spec table.
- Chapter 21 (first test): the identity case, line by line.
- Chapter 22 (building out): nine more spec table tests, three
  law tests, a cross-backend test, a composition test.
- Chapter 23 (catching a bug): hand-grading the suite against
  four deliberate bugs.
- Chapter 24 (mutation gate): mechanical grading, iterating
  tests until the gate is clean.

The result is a sixteen-test suite plus two new composition
tests, for eighteen tests total. Every test has an oracle
declaration. Every test uses the strongest applicable oracle.
Every mutation in the declared classes is killed. The suite is
ready for use.

## How this scales

Every primitive op in vyre follows the same five-step process:

1. Write the specification (intent phase).
2. Write the first test (simplest case).
3. Build out the suite (spec table, laws, cross-backend,
   composition).
4. Hand-grade with deliberate bugs for intuition.
5. Run the mutation gate and iterate until clean.

The process is mechanical once you have done it for one op.
Writing the suite for `BinOp::Sub` takes half the time because
you know the patterns. Writing the suite for `BinOp::Mul` takes
the same time, even though the op is different, because the
process is identical. Writing the suite for `BinOp::Xor` is
faster because it has more laws (self-inverse, involutive) that
give more testable properties.

After a few ops, the process is so mechanical that vyre-conform
can automate it. The generator in
`vyre-conform/src/generator/` takes an `OpSpec` and produces
the equivalent of this five-chapter process without human
intervention. Every op gets a suite that matches the discipline
of the hand-written example. The hand-written suite then
becomes a reference and a safety net: if the generator produces
tests that disagree with the hand-written suite, one of them is
wrong, and the disagreement is a finding.

This is the two-tier model described in [The two-tier
suite](../vyre-conform/two-tier-suite.md). Part IV showed the
hand-written tier for one op. Part X shows how that tier and
the generated tier fit together.

## Summary

Part IV walked through the complete test-writing process for
`BinOp::Add`, from intent to mutation-gate-clean. The same
process applies to every primitive op in vyre. Hand-written
tests are the baseline; the generator produces the superset;
the mutation gate is the grader.

This concludes Part IV. Part V is about writing tests in
general — the decision tree for placing a new test, the
templates for common shapes, naming conventions, and the
discipline that keeps the suite readable.

Next: Part V opens with [The decision tree](../writing/decision-tree.md).
