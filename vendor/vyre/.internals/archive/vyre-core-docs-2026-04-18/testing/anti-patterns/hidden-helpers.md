# The hidden helper test

## The shape

A hidden helper test is one whose logic has been wrapped in
helper functions so thoroughly that the test body is
uninformative. The reader can see that something is being
verified, but cannot tell what subject, what inputs, or what
expected value.

```rust
#[test]
fn test_add_case_one() {
    run_test_case(&ADD_TEST_CASES[0]);
}

#[test]
fn test_add_case_two() {
    run_test_case(&ADD_TEST_CASES[1]);
}
```

The reader sees `test_add_case_one` and knows it is testing
case one of something called `ADD_TEST_CASES`. To find out what
case one is, the reader has to open `ADD_TEST_CASES`, find
index zero, and read the case's fields. To find out what
`run_test_case` does, the reader has to open that function and
trace through it.

A reader debugging a failure in `test_add_case_one` spends most
of their time reading the indirection, not the test. A reader
auditing the suite for coverage cannot tell from the test body
which inputs are exercised. A reviewer evaluating the test
cannot tell whether the oracle is correct.

The test has been over-abstracted. The helpers that were
supposed to reduce boilerplate ended up reducing visibility.

## Why it fails

The visible-test principle: a test should tell its reader what
subject is being tested, what inputs are being used, and what
expected output is being asserted, without requiring the reader
to follow function calls into other files. When the test hides
these, it is not a test; it is a call to some opaque test
machinery.

Specific failure modes:

- **Reviewers cannot evaluate the oracle.** Without seeing the
  expected value in the test body, the reviewer cannot tell
  whether the oracle is the strongest applicable. An obscured
  oracle is effectively unreviewable.
- **Debugging is harder.** A failing test in the hidden helper
  form requires the maintainer to trace through the helper to
  find what the test was actually checking. The trace takes
  time that a visible test would not take.
- **Search is weaker.** `grep` for "0xDEADBEEF" finds every
  test that uses the value in an assertion. In a hidden helper
  test, the value is in a data structure elsewhere, and `grep`
  misses it.
- **Refactoring is scarier.** A change to the helper affects
  every test that uses it. Contributors become reluctant to
  touch the helper because the blast radius is unclear, and
  the helper ossifies.

## The specific shapes

### Over-abstracted test case struct

```rust
struct TestCase {
    op: BinOp,
    inputs: Vec<u32>,
    expected: u32,
    description: &'static str,
}

const ADD_TEST_CASES: &[TestCase] = &[
    TestCase {
        op: BinOp::Add,
        inputs: vec![0, 0],
        expected: 0,
        description: "identity pair",
    },
    // ... dozens more
];

fn run_test_case(case: &TestCase) {
    let program = build_program_from_case(case);
    let result = dispatch_program(&program);
    assert_eq!(result, case.expected, "{}: {:?}", case.description, case);
}

#[test]
fn test_add_identity_pair() {
    run_test_case(&ADD_TEST_CASES[0]);
}
```

The tests are short but the test body is just an index lookup.
Everything the test is doing is in `ADD_TEST_CASES[0]` and
`run_test_case`. To evaluate the test, the reader must open
both.

The temptation is real: the struct is compact, the helper is
reusable, and adding a new test is just adding a new entry. But
the compactness comes at the cost of visibility. The test is
not written for the struct's author; it is written for every
future reader, and the future reader has to reconstruct what
the test does.

### Helper functions that wrap assertions

```rust
fn assert_add_result(a: u32, b: u32, expected: u32) {
    let program = build_single_binop(BinOp::Add, a, b);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, expected);
}

#[test]
fn test_add() {
    assert_add_result(2, 3, 5);
    assert_add_result(0, 0, 0);
    assert_add_result(u32::MAX, 1, 0);
}
```

The helper saves three lines per assertion. The test has three
assertions instead of one, which is also a kitchen sink
problem. Worst of all, the test name is just `test_add`, which
tells the reader nothing about the specific properties being
verified.

The fix is to split the test (as per the kitchen sink
anti-pattern) and inline the assertions at their call sites.

### Builders that hide the test

```rust
#[test]
fn test_add() {
    AddTestBuilder::new()
        .with_inputs(2, 3)
        .expect_output(5)
        .run();
}
```

A builder pattern that reads as "configure the test, run the
test" hides every detail inside the builder's methods. What
does `run()` do? What assertions fire? What happens on failure?
The reader does not know without reading the builder.

The builder pattern is appropriate for production code where
construction is complex and the result is a long-lived object.
It is rarely appropriate for tests, where the construction is
usually simple and the result is checked once and discarded.

## How to recognize it

Signs of a hidden helper test:

- **The test body has no visible inputs or expected values.**
  Everything is in a struct, an index, or a builder.
- **The test's name does not match the specific case it
  verifies.** `test_add_case_one` is a name that says nothing.
- **Understanding what the test does requires opening other
  files.**
- **The test is compact but uninformative.**

## How to fix it

Inline the test. Put the inputs, the expected, and the
assertion in the test body.

```rust
/// add(0, 0) == 0. Identity.
/// Oracle: SpecRow from spec table (row 0).
#[test]
fn test_add_identity_zero_zero() {
    let program = build_single_binop(BinOp::Add, 0u32, 0u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 0u32, "add(0, 0) should equal 0");
}

/// add(2, 3) == 5. Basic arithmetic.
/// Oracle: SpecRow from spec table (row 3).
#[test]
fn test_add_two_plus_three_equals_five() {
    let program = build_single_binop(BinOp::Add, 2u32, 3u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 5u32, "add(2, 3) should equal 5");
}
```

The tests are slightly longer but each one is complete. A
reader sees the inputs and the expected values in the test
body. Each test has a specific name that describes its case.
Each test can be invoked individually.

The helpers that remain (`build_single_binop`,
`run_on_default_backend`) are the ones that clarify without
hiding — they abbreviate Program construction and dispatch, but
the inputs and expected are visible at the call site.

## The rule

A test must tell the reader what is being verified without
requiring the reader to leave the test file. Helpers may
abbreviate setup and teardown. Helpers may not hide the
subject, the inputs, or the expected value.

This rule is enforced at review. A test that requires the
reviewer to open another file to understand it is rejected
with the request to inline.

## Summary

Hidden helper tests hide the test's logic in helpers, structs,
or builders. The test body becomes uninformative. The fix is
to inline the inputs and expected values. Helpers that
abbreviate are fine; helpers that hide intent are not. A test
must be self-contained from the reader's perspective.

Next: [The seedless proptest](seedless-proptest.md).
