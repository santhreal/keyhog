# Adversarial tests

## The category where vyre is attacked

Most of vyre's test suite exercises the system with well-formed
inputs: Programs that pass validation, values within the declared
range, wire format that decodes cleanly, buffers that are the size
they say they are. These tests verify that vyre does the right
thing for the common case. They do not verify that vyre survives
the uncommon case.

The adversarial category is where vyre is attacked. Inputs are
deliberately hostile: malformed Programs, truncated wire format,
allocations that fail, buffer indices that lie, loops that
recurse, resources that exceed what the hardware can hold. The
goal is not to verify vyre produces the correct output for these
inputs — for many of them, no correct output is possible. The
goal is to verify vyre does not panic, does not produce
undefined behavior, does not corrupt memory, does not leak state,
and does not crash. Whatever vyre produces for an adversarial
input, it must produce it gracefully.

This category defends three invariants simultaneously:

- **I10 (bounded allocation):** hostile inputs do not cause
  unbounded memory growth.
- **I11 (no panic):** hostile inputs do not cause runtime panics.
- **I12 (no undefined behavior):** hostile inputs do not trigger
  undefined behavior in the lowered shader or the host runtime.

Together, these invariants are what let vyre be embedded in
production systems. A GPU compute library that crashes on
malformed input is a library that cannot be trusted with
user-provided data. A library that survives malformed input is a
library that can be shipped to a cloud service or a long-running
process without operational anxiety.

## The assertion rule

Every test in `tests/adversarial/` asserts exactly one thing:
the runtime survived. The specific form is "the function returned
a value or a structured error; it did not panic, deadlock, or
trigger undefined behavior." The test does not care what error
was returned. It cares that an error was returned instead of a
crash.

```rust
/// Deeply nested Program does not panic; returns a validation error.
/// Oracle: I11 (no panic).
#[test]
fn test_deeply_nested_program_does_not_panic() {
    let mut node = Node::Return;
    for _ in 0..10_000 {
        node = Node::If {
            cond: Expr::Const(true),
            then: Box::new(node),
            else_: None,
        };
    }

    let mut program = Program::empty();
    program.entry = node;

    // The assertion is that validate does not panic.
    // It may return an error (likely V016: max nesting exceeded),
    // but it must not panic, deadlock, or UB.
    let result = std::panic::catch_unwind(|| validate(&program));
    assert!(result.is_ok(), "validate panicked on deeply nested program");
}
```

The assertion is wrapped in `catch_unwind` explicitly to catch
panics. If the function panics, `catch_unwind` returns `Err` and
the assertion fails. If the function completes (whether with
`Ok`, `Err`, or any other value), the assertion passes.

The test does not assert which error is returned. The validator
likely returns V016 (max nesting exceeded), but the test does
not check. Checking the specific error would couple this
adversarial test to a specific rule's behavior, which belongs in
`validation/`, not here. The adversarial test's scope is strictly
"did not panic."

## The categories of adversarial input

The category is subdivided by the class of hostility:

```
tests/adversarial/
├── malformed_ir.rs        Corrupted Program structures
├── malformed_wire_format.rs  Truncated or invalid wire format
├── oom.rs                 Allocation exhaustion
├── resource_bombs.rs      Deeply nested, extremely wide
├── oob_indices.rs         Buffer access at boundaries
├── panic_probes.rs        Inputs engineered from past panics
└── fuzz_corpus.rs         Replay of inputs from fuzz corpus
```

Each file has a specific kind of input and a specific aspect of
the runtime it stresses.

### malformed_ir.rs

Tests that construct `ir::Program` values directly — not through
the builder API, which enforces some structural invariants — and
verify the validator rejects them or the lowering handles them
without panic. The malformed IR category is where programs that
could not be constructed through normal means but could in
principle exist (through direct `Program` field mutation,
deserialization of hand-crafted bytes, or memory corruption) are
tested.

```rust
/// IR with a buffer reference to an undeclared buffer does not panic.
/// Oracle: I11 (no panic).
#[test]
fn test_ir_with_undeclared_buffer_ref_does_not_panic() {
    let mut program = Program::empty();
    program.entry = Node::Store {
        buffer: BufferRef::Named("nonexistent".into()),
        index: Expr::Const(0),
        value: Expr::Const(0),
    };

    let result = std::panic::catch_unwind(|| {
        let _ = validate(&program);
        let _ = wgsl::lower(&program);
    });
    assert!(result.is_ok());
}
```

### malformed_wire_format.rs

Tests that decode wire format buffers with deliberate corruption:
truncated buffers, invalid opcodes, length mismatches, circular
references. The decoder must return an error without panicking.

### oom.rs

Tests that run with a test-only allocator that fails allocations
after N successful allocations. The tests verify the runtime
handles allocation failure gracefully: returns an error, does not
leak state, does not panic.

OOM testing requires a feature-flagged allocator that can inject
failures. The allocator is behind `#[cfg(feature = "oom-injection")]`
so it does not pollute production builds. The tests run only when
the feature is enabled, typically in a dedicated CI job.

### resource_bombs.rs

Tests with inputs designed to consume maximum resources: the
maximum allowed node count, maximum nesting depth, maximum
workgroup size, maximum dispatch dimensions. The tests verify the
validator rejects inputs beyond the limits and the pipeline
handles inputs at the limits without exhausting resources.

A resource bomb test's input is not specifically malformed — it
might even be valid. The hostility is in the resource consumption.
The assertion is that vyre stays within its declared envelope
even when pushed to the edges.

### oob_indices.rs

Tests that access buffer indices at boundaries and beyond:
`index = len - 1` (valid), `index = len` (out of range by one),
`index = len + 1` (out of range by two), `index = u32::MAX`
(extreme). The assertion is that the runtime handles each case
according to the specification: in-range indices succeed,
out-of-range indices are rejected by validation or return safe
default values at dispatch time, extreme indices never corrupt
memory.

The OOB category overlaps with validation tests, but the
distinction is that adversarial OOB tests focus on what happens
when an OOB index slips past validation (through a hand-crafted
Program, for example) and reaches the lowering or dispatch stage.
Validation tests verify the validator catches OOB; adversarial
tests verify the rest of the pipeline survives when it does not.

### panic_probes.rs

Tests with specific inputs that previously caused panics. Every
bug report that involved a panic produces a test in this file
when the bug is fixed. The test replays the exact input and
asserts no panic. These are regression tests for panic-class
bugs, and they live in `adversarial/` rather than `regression/`
because the assertion is specifically "no panic," not "correct
output."

### fuzz_corpus.rs

Tests that replay inputs from `tests/corpus/fuzz/`. The fuzz
corpus is a collection of inputs discovered by `cargo fuzz` runs
that caused panics, hangs, or undefined behavior in past versions
of vyre. Every entry in the corpus is a permanent regression
check: if any corpus entry ever panics again, the test fails.

The corpus is managed by the fuzzing discipline. Each fuzz run
produces new inputs that trigger bugs; the bugs are fixed; the
inputs are added to the corpus. The corpus grows as vyre's
defenses are strengthened. See [Running fuzzing](../running/fuzzing.md)
for the fuzzing workflow and [Differential fuzzing](../advanced/differential-fuzzing.md)
for the more sophisticated fuzzing techniques.

## The relationship with fuzz testing

Adversarial tests and fuzz testing are complementary. Adversarial
tests cover specific hand-crafted hostile inputs; fuzz testing
covers arbitrary random hostile inputs. The hand-crafted inputs
in `adversarial/` target known classes of attack (truncated
wire format, deeply nested Programs, OOM conditions); the random
inputs in fuzzing find attacks nobody thought of.

Fuzzing runs are not part of `cargo test`. They run separately,
via `cargo fuzz run`, and they produce findings over time. When a
fuzzer finds an input that panics, the input is minimized and
added to `tests/corpus/fuzz/`, which makes it part of `cargo
test` via `fuzz_corpus.rs`. So fuzzing feeds into the adversarial
category: fuzzing discovers new hostile inputs, and the corpus
freezes them as permanent regression tests.

## Catching panics explicitly

The `catch_unwind` pattern in adversarial tests looks heavy but
is necessary. A panic in a test normally propagates and fails
the test, which looks like the right behavior. But it only looks
right: a panicking test produces a failure, while a panicking
test with `catch_unwind` produces a more specific failure that
is diagnosable without running the test under a debugger.

```rust
// Less useful — the panic fails the test but the failure is
// a stack trace buried in test output.
#[test]
fn fails_obscurely_on_panic() {
    validate(&malformed_program());  // if this panics, the test fails
}

// More useful — the panic produces a clear failure with context.
#[test]
fn fails_clearly_on_panic() {
    let result = std::panic::catch_unwind(|| validate(&malformed_program()));
    assert!(
        result.is_ok(),
        "validate panicked on malformed program; this is invariant I11",
    );
}
```

The `catch_unwind` form produces an assertion message that
identifies the test as a panic check, which helps the person
diagnosing the failure understand what was violated and why it
matters. The pattern is worth the extra lines in every
adversarial test.

## What adversarial tests do not cover

Adversarial tests do not verify that malformed inputs produce
the right error message. That is not an invariant. Error messages
are implementation details, and coupling tests to specific error
strings creates brittle tests that fail on cosmetic changes.

Adversarial tests do not verify the runtime's response time on
malformed inputs. A deeply nested Program might take longer to
validate than a shallow one, and that is fine — the test cares
about correctness, not speed. If performance on malformed inputs
matters, it is a benchmark concern, not an adversarial test
concern.

Adversarial tests do not verify that malformed inputs are caught
at the earliest possible stage. It is fine if a malformed Program
is caught by the validator, or by the lowering, or by the
dispatcher. The test cares that it is caught somewhere along the
pipeline without panic; it does not care where.

## The pattern for adding a new adversarial test

When a new class of hostile input is identified — usually via a
bug report or a fuzz finding — the pattern is:

1. **Minimize the input.** Strip the input down to the smallest
   case that still exhibits the hostile behavior. This is the
   minimization discipline from [The minimizer](../advanced/mutation-at-scale.md).
2. **Add the minimized input to the appropriate file.** Pick the
   subcategory that matches the class of attack. If it does not
   fit an existing subcategory, the subcategory set is incomplete
   and may need extension.
3. **Assert no panic.** Use the `catch_unwind` pattern. Assert
   the function returned (regardless of whether it returned `Ok`
   or `Err`), not panicked.
4. **If the hostile behavior was a panic, commit a regression
   test in addition** to the adversarial test. The adversarial
   test asserts "does not panic"; the regression test in
   `tests/regression/` asserts the specific behavior the fix
   produces.
5. **Run the mutation gate** on the adversarial test to verify it
   catches the original mutation. An adversarial test that does
   not catch its own motivating bug when replayed is broken.

## The volume of adversarial tests

The adversarial category grows without a clear upper bound. Every
fuzzing run can discover new inputs. Every bug report can
contribute a panic probe. Every category of attack can be
extended. The suite absorbs the volume by treating each test as
small and cheap — adversarial tests are meant to be fast, because
each one does a minimal amount of work (construct input, call
function, check no panic). A thousand adversarial tests should
run in well under a minute.

When the category grows to the point where it is slow, the fix
is to split it into fast and slow subcategories, with the fast
ones running on every CI commit and the slow ones running on
release candidates. See [Suite performance](../discipline/suite-performance.md)
for the split discipline.

## Summary

Adversarial tests verify that vyre survives hostile inputs without
panic, undefined behavior, or resource exhaustion. Seven
subcategories cover the major classes of attack. Every test
asserts "graceful rejection," not specific error behavior. The
category cooperates with fuzz testing, which feeds the corpus
that the adversarial category replays. This is the category that
makes vyre safe to embed in production systems handling untrusted
input.

Next: [Property tests](property.md).
