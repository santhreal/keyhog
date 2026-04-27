# The kitchen sink test

## The shape

A kitchen sink test is one function that verifies many
different properties in one place. It looks efficient — "why
write ten tests when one test can check all the cases?" — but
it fails in specific ways that the ten-test version does not.

```rust
#[test]
fn test_add_properties() {
    // Test identity
    let p1 = build_single_binop(BinOp::Add, 0u32, 0u32);
    assert_eq!(run_on_default_backend(&p1).unwrap(), 0u32);

    // Test overflow
    let p2 = build_single_binop(BinOp::Add, u32::MAX, 1u32);
    assert_eq!(run_on_default_backend(&p2).unwrap(), 0u32);

    // Test commutativity
    let p3 = build_single_binop(BinOp::Add, 5u32, 7u32);
    let p4 = build_single_binop(BinOp::Add, 7u32, 5u32);
    assert_eq!(
        run_on_default_backend(&p3).unwrap(),
        run_on_default_backend(&p4).unwrap(),
    );

    // Test associativity
    // ... many more assertions
}
```

One test function. Five or six properties. When the test fails,
the output says "test_add_properties failed" with the specific
assertion that tripped, but the failure's cause is harder to
diagnose because the function has been doing many things in
sequence.

## Why it fails

Several specific ways:

**Failure localization is weak.** When `test_add_properties`
fails, the maintainer sees one test failing but has to read the
test body to figure out which assertion fired. With ten
separate tests, the maintainer sees
`test_add_identity_zero_zero` or `test_add_overflow_u32_max`
failing by name, and the name tells them exactly what broke.

**Multiple assertions per test hide cascading failures.** The
first failing assertion in a kitchen sink test fires, and the
rest of the assertions never run. If the bug affects two
different properties, only the first is reported. Separate
tests run independently and report every failure, which gives
a more complete picture of what is broken.

**Shared state between assertions can hide bugs.** Variables
defined for one assertion leak into later assertions, and a
bug that depends on order is hard to reproduce when tests are
split. Kitchen sink tests often become order-dependent without
the author realizing, and the suite becomes fragile.

**The test name is vague.** `test_add_properties` does not
tell the reader what properties or what inputs. A reader
searching for "does the suite test identity?" cannot tell from
the name whether this test covers it.

**Mutation testing credit is muddled.** When a mutation causes
the kitchen sink test to fail, the gate credits the whole test
with killing the mutation. If the gate was meant to check which
specific property caught the mutation, the information is lost
because the test has multiple properties.

## How it happens

Kitchen sinks usually happen when:

- The contributor is trying to avoid writing "too many" tests.
  vyre's convention is that many small tests are better than
  few large ones, but contributors from other backgrounds
  sometimes resist.
- The contributor finds shared setup tempting. "If I'm already
  building a Program for one assertion, why not use it for
  five?" The setup is shared, but the test lost its focus.
- The contributor is porting tests from another framework where
  one test with many assertions was idiomatic. Rust tests are
  small; idioms from other languages do not translate.

## How to recognize it

Signs of a kitchen sink:

- **The test function body is longer than 30 lines.**
- **The test has multiple `assert_eq!` calls with different
  variables.**
- **The test's doc comment says "verifies multiple properties"
  or anything with "and" in it.**
- **The test name is a noun like `test_<subject>_properties`
  or `test_<subject>_behavior` with no specific property.**
- **Running the test takes visibly longer than its siblings
  (because it is doing more work).**

Any two of these signs and the test is probably a kitchen sink.

## How to fix it

Split the test. Each property gets its own function with its
own name and its own assertion. The shared setup is either
duplicated (fine for a few lines) or extracted into a helper in
`tests/support/programs.rs` (for longer setup).

```rust
/// add(0, 0) == 0. Identity case.
#[test]
fn test_add_identity_zero_zero() {
    let program = build_single_binop(BinOp::Add, 0u32, 0u32);
    assert_eq!(run_on_default_backend(&program).unwrap(), 0u32);
}

/// add(u32::MAX, 1) wraps to 0. Overflow.
#[test]
fn test_add_overflow_u32_max_plus_one() {
    let program = build_single_binop(BinOp::Add, u32::MAX, 1u32);
    assert_eq!(run_on_default_backend(&program).unwrap(), 0u32);
}

/// add is commutative on (5, 7).
#[test]
fn test_add_commutative_five_seven() {
    let p1 = build_single_binop(BinOp::Add, 5u32, 7u32);
    let p2 = build_single_binop(BinOp::Add, 7u32, 5u32);
    assert_eq!(
        run_on_default_backend(&p1).unwrap(),
        run_on_default_backend(&p2).unwrap(),
    );
}
```

The split version has three test functions where the kitchen
sink had one. When one breaks, you see exactly which. When
they run, each runs independently. When they are named, each
says what it does.

The cost of the split is three times as many function
declarations and a few more lines of code. The benefit is
diagnosable failures, independent runs, and clear names.
Always worth it.

## The one exception

A single test that iterates a list of similar cases using a
loop is acceptable when the cases are truly uniform and the
assertion is identical for each:

```rust
/// Unknown opcode bytes all return None.
#[test]
fn test_parse_unknown_bytes_return_none() {
    for byte in [0xFF, 0xAA, 0x7F, 0x42, 0x01] {
        assert_eq!(parse(byte), None, "byte {:#x} should return None", byte);
    }
}
```

This is not a kitchen sink because the property is the same
for every iteration — "this byte returns None." The loop is a
compact way to assert a uniform property on many cases. The
failure message includes the specific byte, so a failing run
tells you exactly which input broke the property.

The rule: a loop is fine if every iteration asserts the same
property. A loop is a kitchen sink if each iteration asserts a
different property. `for (property, value) in cases` is usually
a kitchen sink in disguise.

## Summary

Kitchen sink tests bundle multiple properties in one function.
They make failure localization weak, hide cascading failures,
and produce vague test names. Split them into one test per
property. The split costs a few lines and gains readability,
diagnosability, and independent execution.

Next: [The "doesn't crash" test](doesnt-crash.md).
