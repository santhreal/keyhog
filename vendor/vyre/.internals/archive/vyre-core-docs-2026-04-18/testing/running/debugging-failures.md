# Debugging failures

## The first rule

When a test fails, the first question is not "what is wrong
with the test?" The first question is "what is the test
telling me?" The test is a statement about expected behavior,
and a failure is a signal that the behavior differs from the
expectation. The signal is useful only if you read it
carefully.

Contributors under time pressure want to make the failure go
away. The temptation is to edit the test until it passes,
or to add a catch-all, or to relax an assertion. These fixes
all work in the sense that CI turns green, but they all
leave the actual problem unresolved. The actual problem is
that the code does not match the specification, and the
specification is what users depend on.

This chapter is about debugging failures properly: reading
the signal, reproducing the failure, finding the root cause,
and fixing the code. The emphasis is on debugging, not on
test-maintenance triage. Test-maintenance (the case where
the test is wrong) is the minority of failures and is
handled at the end.

## The debug workflow

### Step 1 — Read the failure message

The failure message tells you which assertion fired and what
values were involved. Read it carefully. A typical message:

```
test test_add_overflow ... FAILED

---- test_add_overflow stdout ----
thread 'test_add_overflow' panicked at 'assertion `left == right` failed: u32::MAX + 1 should wrap to 0
  left: 4294967295
  right: 0', tests/integration/primitive_ops/add.rs:42:5
```

The message has:
- **The test name:** `test_add_overflow`.
- **The file and line:** `tests/integration/primitive_ops/add.rs:42`.
- **The assertion:** `left == right`.
- **The failure context:** `u32::MAX + 1 should wrap to 0`.
- **The actual values:** `left: 4294967295` (what the code
  produced), `right: 0` (what was expected).

From this, you know: the test expected 0, the code produced
`u32::MAX` (4294967295), and the expected behavior is
wrapping overflow. The bug is that the code is not wrapping;
it is saturating or returning the input unchanged.

### Step 2 — Reproduce locally

```bash
cargo test -p vyre test_add_overflow
```

Run the exact failing test on your machine. If it fails
locally with the same error, you have a clean reproducer. If
it passes locally, the failure is environment-specific, and
you have a different debugging problem (see [Debugging
flakes](debugging-flakes.md)).

Run with backtrace enabled:

```bash
RUST_BACKTRACE=1 cargo test -p vyre test_add_overflow
```

The backtrace shows the call stack at the point of failure,
which helps locate the code path involved.

### Step 3 — Isolate the problem

Once you have a reproducer, narrow the test to the smallest
case that still fails. If the failing test uses multiple
inputs, try just the first input. If the test composes
multiple operations, try just one operation. The goal is to
find the minimum conditions under which the bug fires.

```rust
#[test]
fn test_minimal_reproducer() {
    // Just the failing case, nothing else.
    let program = build_single_binop(BinOp::Add, u32::MAX, 1u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 0u32);
}
```

Copy the minimal reproducer into a scratch file or a debugger
script. Experiment with variations to understand the bug's
boundaries.

### Step 4 — Find the root cause

Walk the code path the test exercises. For a failing add
test:

1. The test calls `build_single_binop(BinOp::Add, u32::MAX, 1u32)`.
2. The builder constructs a Program with the add op.
3. `run_on_default_backend` dispatches the Program.
4. The default backend (wgpu) takes the Program.
5. The backend calls `lower::wgsl::lower()` to translate to
   WGSL.
6. The backend dispatches the lowered shader.
7. The shader runs on the GPU and produces an output.
8. The output is returned to the test.

The bug is somewhere in steps 5-7. Read the lowered WGSL to
see what operation is being performed. If the WGSL looks
correct, the bug might be in how wgpu compiles it. If the
WGSL looks wrong, the bug is in the lowering.

For this specific case, a likely root cause is that the
lowering emits `+` instead of a wrapping-explicit operation,
and the backend's WGSL compilation uses a mode that does not
wrap by default.

### Step 5 — Confirm the hypothesis

Once you have a hypothesis, confirm it before changing code.
Add a printf or an `eprintln!` to the lowering to see what
WGSL it produces for the failing case. Run the reproducer and
inspect the output:

```rust
// In src/lower/wgsl/add.rs temporarily
fn emit_add(lhs: &str, rhs: &str) -> String {
    let result = format!("{} + {}", lhs, rhs);
    eprintln!("LOWERING: emit_add produced: {}", result);
    result
}
```

Run the test. The eprintln output appears in the test output
and tells you what the lowering is actually emitting. If it
matches your hypothesis, you have confirmed the bug. If not,
your hypothesis is wrong and you need another.

### Step 6 — Fix the code

Once the root cause is confirmed, fix the code. For the
overflow case, the fix is to emit a wrapping-explicit
operation in the lowering:

```rust
fn emit_add(lhs: &str, rhs: &str) -> String {
    // Use explicit wrapping semantics to ensure u32 overflow
    // wraps as specified.
    format!("({} + {})", lhs, rhs)  // wgpu's u32 addition wraps by default; verify
}
```

The fix is small and targeted. Do not make unrelated changes;
if you notice other issues in the file, file them as
separate tasks and fix them separately.

### Step 7 — Verify the fix

Run the failing test again. It should pass.

```bash
cargo test -p vyre test_add_overflow
```

If it does, run the whole primitive_ops category to ensure
you did not break other tests:

```bash
cargo test -p vyre integration::primitive_ops
```

If that passes, run the full vyre suite:

```bash
cargo test -p vyre
```

Three tiers of verification. The fix is not complete until
all three pass.

### Step 8 — Add a regression test if applicable

If the bug was not already covered by the failing test (the
failing test was an existing test that started failing for
environmental reasons, or the bug is different from what the
test was checking), add a new regression test in
`tests/regression/` that captures the specific bug and its
fix.

If the failing test itself was the correct test for this bug
(as in the add overflow case), no additional regression is
needed — the existing test is the regression.

### Step 9 — Commit

The commit message includes:
- What was broken.
- What the fix does.
- How it was verified.

```
fix(lower/wgsl): wrap u32 addition instead of saturating

The WGSL lowering for BinOp::Add was emitting a saturating
addition on wgpu because of a miscompiled form. Replaced with
an explicit wrapping addition per the vyre specification.

Verified: test_add_overflow passes, full vyre suite passes,
mutation gate on add.rs reports zero surviving arithmetic
mutations.
```

The message is for future maintainers who need to understand
what changed and why.

## Common shapes of failure

Some failures follow common shapes that can be diagnosed
quickly once recognized:

### Assertion values are identical but the test fails

```
left: Value::U32(42)
right: Value::U32(42)
FAILED
```

This almost always means the values look the same in `Debug`
output but are different in some other way. Common causes:
floating-point with different NaN bit patterns, structs with
distinct but visually-identical hidden fields, or different
type tags on enum variants that print the same. Use
`to_bits()` or direct field comparison to see the actual
difference.

### Test passes in isolation but fails in the full suite

This is a state leakage issue. Some earlier test is modifying
global state that this test depends on. Common sources:
shared caches, lazy-initialized statics that get into bad
states, file system side effects. Debug by running the suite
with `--test-threads=1` and bisecting the test order to find
the interfering test.

### Test fails only on CI

Environment difference between local and CI. Common causes:
different OS (file paths, line endings), different CPU
(non-deterministic behavior from ordering), different GPU or
driver. Debug by running locally in a container that matches
CI's environment.

### Test fails with "dispatch error"

The backend could not run the Program. Read the error
message for details. Common causes: shader compilation
failure (the lowering produced invalid WGSL), resource
exhaustion (the Program tries to allocate too much), or
backend-specific limits.

### Test fails with a panic in production code

The panic itself is a bug: production code should not panic
on validated inputs. Investigate the panic and fix the
production code. If the panic is in a `expect` with a clear
message, the message points at the cause. If it is an
`unwrap` without context, add context and re-run to see
where exactly it fires.

## When the test is wrong

Occasionally the test is wrong and the code is right. The
signs:

- The code's output matches the specification, but the test
  expects something else.
- The test's expected value is outdated (a recent spec
  change has not propagated to the test).
- The test is hitting a case that the spec has decided to
  handle differently than originally specified.

In these cases, the fix is to update the test. But be
careful: the default assumption is that the code is wrong.
Updating the test is only correct if you can point at a
specific spec change or a specific review that agreed the
test's expectation was wrong. "It passes after I change the
expected value" is not a justification.

When you do update a test, do it with care. Document the
change in the commit message. If the test was a regression
test, consult [the regression rule](../discipline/regression-rule.md)
for the narrow exception rules.

## Summary

Debugging failures starts with reading the failure message
carefully. Reproduce locally, isolate to the minimal case,
find the root cause by walking the code path, confirm with
printf-style investigation, fix the code, verify at multiple
levels, and commit with a descriptive message. Common failure
shapes have common causes. Test-is-wrong is the exception,
not the default.

Next: [Debugging flakes](debugging-flakes.md).
