# The "doesn't crash" test

## The shape

```rust
#[test]
fn test_lower_runs() {
    let program = build_some_program();
    let _ = wgsl::lower(&program);
}
```

The test builds a Program, calls `lower`, and asserts nothing.
If `lower` panics, the test fails. If `lower` returns
`Err(SomeError)`, the test passes. If `lower` returns the wrong
`Ok(shader)`, the test passes. If `lower` silently drops half
the Program's content and produces a nonsense shader, the test
passes.

The variant:

```rust
#[test]
fn test_dispatch_runs() {
    let program = build_some_program();
    let result = run_on_default_backend(&program);
    assert!(result.is_ok());
}
```

This one asserts `is_ok`, which is slightly more than nothing —
the test fails if dispatch returns an error. But it still does
not assert what the result is, so a dispatch that succeeds with
wrong output passes the test.

Both forms share the same property: the test's assertion is
about existence rather than correctness. "Something happened"
is verified; "the thing that happened was the right thing" is
not.

## When "doesn't crash" is correct

Before explaining why this is an anti-pattern, it is worth
naming the cases where the pattern is appropriate:

- **Adversarial tests.** The whole point of adversarial tests
  is to assert "graceful rejection." The input is hostile; no
  specific output is expected; the test verifies the runtime
  survives. `assert!(result.is_err() || result.is_ok())` with
  a `catch_unwind` wrapper is exactly right for adversarial
  cases.
- **Fuzz corpus replay.** Inputs from the fuzz corpus are
  replayed with the assertion "did not panic." Same as
  adversarial tests.
- **Resource bomb tests.** A Program that consumes a large
  resource is tested to verify the runtime handles it
  gracefully. "Did not exceed memory envelope" is a legitimate
  assertion.

In these cases, "doesn't crash" is the correct oracle because
nothing stronger applies. The test's whole purpose is to verify
the runtime's robustness, and the assertion is aligned with the
purpose.

## When "doesn't crash" is wrong

The anti-pattern is using "doesn't crash" when a stronger
oracle is available. If the subject has a declared law, a spec
table row, a reference interpreter, or any form of expected
output, "doesn't crash" is too weak and must be replaced.

Examples of the pattern appearing in the wrong place:

```rust
// WRONG — the subject is a primitive op with a spec table
#[test]
fn test_add_runs() {
    let program = build_single_binop(BinOp::Add, 1u32, 2u32);
    let _ = run_on_default_backend(&program);
}

// RIGHT — use the spec table oracle
#[test]
fn test_add_one_plus_two_equals_three() {
    let program = build_single_binop(BinOp::Add, 1u32, 2u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 3u32);
}
```

The wrong version passes for every implementation of `Add`,
including one that returns `42` or `0xCAFE` or `rand()`. The
right version asserts the specific expected value from the
spec table and catches any bug that affects the output.

Another example:

```rust
// WRONG — validation test that does not check which rule fired
#[test]
fn test_validate_rejects_bad_program() {
    let program = build_bad_program();
    let errors = validate(&program);
    assert!(!errors.is_empty());
}

// RIGHT — assert the specific rule
#[test]
fn test_v001_rejects_duplicate_buffer_name() {
    let mut program = Program::empty();
    program.buffers.push(BufferDecl::new("foo", DataType::U32, 16));
    program.buffers.push(BufferDecl::new("foo", DataType::U32, 16));
    program.entry = Node::Return;

    let errors = validate(&program);
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].rule, ValidationRule::V001);
}
```

The wrong version passes for any validator that returns any
error, including the wrong error or a misleading error. The
right version asserts the specific rule and catches
misattribution.

## Why it fails

A "doesn't crash" test that could have used a stronger oracle
is a waste of test budget. The test runs, takes CI time, and
produces a green checkmark without verifying anything
meaningful. A contributor reading the suite assumes the test
covers what the name suggests, when actually the test covers
almost nothing.

More dangerously, a "doesn't crash" test can hide a
regression. Suppose the implementation of `Add` is quietly
broken (it returns 0 for all inputs). A "doesn't crash" test
passes because the implementation does not panic. A spec
table test fails because the output is wrong. The maintainer
sees a failure in the stronger test and a pass in the weaker
test and knows the bug exists. Without the stronger test, the
weaker test's pass is the only signal, and it says nothing.

## Why it happens

"Doesn't crash" tests are the laziest form of test. They happen
when:

- **The contributor is in a hurry** and wants to hit a coverage
  number without thinking about what to assert.
- **The contributor does not know what the expected output
  should be** and punts on the question.
- **The contributor is writing a smoke test** ("I just want to
  make sure this compiles and runs") without realizing the
  smoke test has escaped into the main suite.

The fix in each case is the same: stop and think about the
expected output, then assert it.

## How to recognize it

Signs of a "doesn't crash" test:

- **The test body has no `assert_eq!` or equivalent** that
  compares against a specific value.
- **The assertions are all existence checks:** `assert!(result.is_ok())`,
  `assert!(!errors.is_empty())`, `assert!(shader.len() > 0)`.
- **The test's doc comment says "runs" or "does not panic" or
  "works"** for a subject that should have a specific expected
  behavior.
- **Mutating the code under test still causes the test to
  pass** — which the mutation gate detects.

## How to fix it

Apply the decision tree from Part V. Determine the test's
category. Determine the oracle. Rewrite the test with a
concrete expected value from the oracle.

If the test truly has no stronger oracle available — if it is
for a subject where "did not panic" is the only meaningful
assertion — the test belongs in `tests/adversarial/`, not in
the category it currently lives in. Move the test and keep the
assertion. The test is not wrong; it is mislabeled.

If the stronger oracle requires work you do not want to do —
computing the expected value, adding a spec table row, writing
a law — do the work. The work is the point. A test that
skipped the work is a test that was not worth writing.

## Summary

"Doesn't crash" is the right assertion for adversarial,
fuzz corpus, and resource bomb tests. It is the wrong assertion
for primitive op correctness, validation rule tests, lowering
coverage, or any subject with a stronger oracle. Use the
strongest applicable oracle; if you cannot, the test either
belongs in adversarial or needs more thought.

Next: [The hidden helper test](hidden-helpers.md).
