# The tautology test

## The shape

A tautology test is one whose expected value is derived from
the code being tested. The derivation can be direct, through a
helper, or through a chain of helpers, but the effect is the
same: the test asserts `f(x) == f(x)` under various disguises,
which is true for every possible implementation of `f`,
including wrong ones.

The direct form:

```rust
#[test]
fn test_add_two_plus_three() {
    let a = 2u32;
    let b = 3u32;
    let expected = a.wrapping_add(b);  // derived from code under test
    let program = build_single_binop(BinOp::Add, a, b);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, expected);
}
```

The expected value is computed by calling `wrapping_add`, which
is exactly the function the test is supposedly verifying. If
the implementation of `Add` is changed to compute
`wrapping_sub`, the test still passes — because both the
expected and the observed values are computed by the same (now
broken) function.

The indirect form:

```rust
fn expected_add(a: u32, b: u32) -> u32 {
    cpu::add(a, b)  // calls into the code under test
}

#[test]
fn test_add_two_plus_three() {
    let a = 2u32;
    let b = 3u32;
    let program = build_single_binop(BinOp::Add, a, b);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, expected_add(a, b));
}
```

The helper `expected_add` adds a layer of indirection but the
effect is identical: the expected value is computed by calling
`cpu::add`, which is exactly what is dispatched on the backend.
A reader who skims the test might miss the tautology, but the
test still cannot fail for any broken implementation as long as
the broken implementation is used consistently in both paths.

The subtle form:

```rust
#[test]
fn test_add_sample() {
    let reference = vyre_conform::reference::run(&program, &[]).unwrap();
    let observed = run_on_default_backend(&program).unwrap();
    assert_eq!(observed, reference);
}
```

This looks like a cross-backend test, and sometimes it is
legitimate. But if the reference interpreter and the default
backend both call into the same CPU reference function — which
they do for primitive ops in the current vyre architecture —
the test is only verifying that the two paths agree with each
other, not that either is correct. A bug in the shared CPU
reference function would pass this test.

The legitimate form of this test exists when the reference
interpreter and the default backend are truly independent —
when the backend has its own implementation that does not call
the CPU reference function. In that case, the comparison is
meaningful because the two sides of the assertion come from
different code paths. But for vyre's current backends, the
reference interpreter is the oracle for composed Programs, not
for individual primitive ops. Primitive op tests need spec
tables, not reference diff.

## Why it fails

A tautology test gives a false sense of security. Green check
marks in CI suggest the suite is working. Mutation testing
reveals that the green check marks mean nothing: every mutation
survives, because the test was never verifying anything. The
suite's reputation is destroyed the first time a tautology is
found in production code; from that point, every other test is
suspect until it has been re-verified.

A tautology test also wastes review time. A reviewer who
encounters a tautology must either:
- Catch it and reject the PR (wasting the reviewer's time),
- Miss it and let the tautology into the suite (which increases
  the mutation-gate-survivor count).

Either outcome is bad. The remedy is to catch tautologies at
write time, before review, by knowing the pattern.

## Why it happens

Tautologies are not written by malicious contributors. They are
written by contributors who are in a hurry, who do not yet
understand the oracle discipline, or who are under pressure to
hit a coverage number. The failure mode is:

1. Contributor sits down to write a test.
2. Contributor realizes they need an expected value.
3. Contributor does not want to compute the expected value by
   hand (it would take 30 seconds).
4. Contributor writes `let expected = f(a, b)` because that is
   faster.
5. Contributor reviews their own test, sees it "passes," and
   commits.

The shortcut in step 4 is the bug. The shortcut saves 30
seconds at write time and produces a test that is worth zero.
The test is worse than no test because zero tests is a known
state (the suite has no coverage for this case), while a
tautology is a hidden state (the suite pretends to have
coverage).

Another source is language models. An agent asked to write a
test will often produce a tautology because the shape of
`assert_eq!(observed, expected)` looks correct and the agent
does not immediately recognize that the expected must come
from an independent source. The fix is to prompt the agent
with explicit oracle requirements, and the mutation gate is the
mechanical defense that catches what the prompt misses.

## How to recognize it

The pattern is identifiable at a glance once you know it:

- **The expected value is the result of a function call** that
  looks like the code under test. `.wrapping_add`, `.checked_add`,
  `cpu::add`, any function whose name matches the op.
- **The assertion compares two values that were computed by the
  same codebase**, not against an independent ground truth.
- **The test would pass if the op's behavior changed** as long
  as both the expected and the observed sides change together.

If any of these signs are present, the test is tautological.

## How to fix it

Replace the derived expected with an independent one:

**For primitive op tests:** use a spec table row. The expected
value comes from the table, which is hand-written by a human
who decided what the correct answer is.

```rust
#[test]
fn test_add_two_plus_three() {
    let program = build_single_binop(BinOp::Add, 2u32, 3u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 5u32, "2 + 3 = 5");
}
```

The expected value is the literal `5u32`, committed to the
test. It does not come from calling `add`. If the implementation
changes, the test fails; the `5u32` does not change.

**For law tests:** use the law as the oracle. The expected is
the other side of the law's equation, which comes from running
the code — but the oracle is the law itself, not the specific
value.

```rust
#[test]
fn test_add_commutative() {
    let a = 2u32;
    let b = 3u32;
    let result_ab = run_on_default_backend(&build_single_binop(BinOp::Add, a, b))
        .expect("dispatch");
    let result_ba = run_on_default_backend(&build_single_binop(BinOp::Add, b, a))
        .expect("dispatch");
    assert_eq!(result_ab, result_ba);
}
```

The expected is `result_ba`, computed by running the code. But
the oracle is the commutativity law — the claim that the two
sides must be equal. A bug that broke commutativity while
preserving some other property would still be caught here,
because the assertion is about the relation, not about a
specific value.

This is subtle: the assertion uses a computed value, but the
oracle is not the computation. The oracle is the law, and the
law is what makes the computation's result authoritative. The
distinction is what makes this not a tautology.

**For composed Program tests:** use the reference interpreter.
The expected comes from running the Program through an
independent implementation.

```rust
#[test]
fn test_composition_matches_reference() {
    let program = build_complex_program();
    let observed = run_on_default_backend(&program).expect("dispatch");
    let reference = vyre_conform::reference::run(&program, &[])
        .expect("reference interpreter");
    assert_eq!(observed, reference);
}
```

The expected comes from the reference interpreter, which is a
separate implementation from the default backend. If the
default backend has a bug the reference interpreter does not
have, the test catches it. If the reference interpreter has a
bug the backend does not have, the test also catches it (and
invariant I8's check ensures the reference interpreter stays
correct).

## How the mutation gate catches it

The mutation gate has a specific class for this. A mutation
that rewrites the expected-value expression to `!expected`
(logical negation) or `expected + 1` should cause the test to
fail. If the test still passes, the test is not relying on the
expected value — which is a strong signal that the expected is
derived from the observed and both change together.

The gate cannot catch all tautologies directly — some
tautologies have an assertion that would change if either side
changed, which is not detectable without deeper analysis. But
the common forms are caught, and the uncommon forms are caught
by review.

## Summary

A tautology test's expected value comes from the code under
test. It passes for every implementation, including broken
ones. Fix by using an independent oracle: a spec table row, a
law, the reference interpreter, or a hand-computed literal. The
mutation gate catches common forms; review catches the rest.
Tautologies are the most dangerous anti-pattern because they
look correct and are useless.

Next: [The kitchen sink test](kitchen-sink.md).
