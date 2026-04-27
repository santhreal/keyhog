# Support utilities

## The directory that helps without hiding

Every non-trivial test suite builds up helper functions that
reduce repetition. Factory functions for common test inputs.
Wrappers around pipeline invocation. Assertion helpers that
compare complex values. Without helpers, every test re-implements
the same setup boilerplate, and the suite becomes a wall of
noise that obscures what each test is actually verifying. With
helpers, tests become readable statements of intent: "build this
program, run it on the default backend, assert the result is
this value."

Helpers also introduce a risk. A helper that hides too much
becomes a black box — the reader cannot tell what the test is
doing without tracing through three levels of indirection. When
that happens, the helper is worse than the boilerplate it
replaced, because the boilerplate was legible and the helper is
not.

vyre's `tests/support/` directory holds the test utility code
and is governed by one rule: helpers exist to reduce boilerplate,
not to obscure test intent. This chapter explains what that rule
means in practice.

## The structure

```
tests/support/
├── mod.rs          Top-level module with re-exports
├── programs.rs     Factory functions for ir::Program values
├── backends.rs     Backend harness wrappers
├── oracles.rs      Oracle helpers (spec table lookup, law assertions)
└── fixtures.rs     Static test data (corpus entries, common values)
```

`mod.rs` re-exports the most commonly used items from the
submodules so tests can import `crate::support::*` and get what
they need. Submodules split helpers by concern: program
construction in `programs.rs`, backend interaction in
`backends.rs`, oracle lookups in `oracles.rs`, and static data
in `fixtures.rs`.

## programs.rs — the factory

`programs.rs` contains factory functions that construct common
`ir::Program` shapes. Factories reduce the boilerplate of
building a Program for a test that only cares about one or two
specific details.

```rust
/// Build the smallest legal Program for a binary op.
///
/// The Program has:
/// - Two input buffers named "a" and "b", each a single u32.
/// - One output buffer named "out", a single u32.
/// - An entry node that loads from a and b, applies the op,
///   and stores to out.
///
/// This is the canonical one-op Program used by primitive op
/// tests.
pub fn build_single_binop(op: BinOp, a: u32, b: u32) -> Program {
    let mut program = Program::empty();
    program.buffers.push(BufferDecl::new("a", DataType::U32, 1));
    program.buffers.push(BufferDecl::new("b", DataType::U32, 1));
    program.buffers.push(BufferDecl::new("out", DataType::U32, 1));
    program.buffers[0].initial = Some(vec![Value::U32(a)]);
    program.buffers[1].initial = Some(vec![Value::U32(b)]);
    program.entry = Node::Store {
        buffer: BufferRef::Named("out".into()),
        index: Expr::Const(Value::U32(0)),
        value: Expr::BinOp {
            op,
            lhs: Box::new(Expr::Load {
                buffer: BufferRef::Named("a".into()),
                index: Box::new(Expr::Const(Value::U32(0))),
            }),
            rhs: Box::new(Expr::Load {
                buffer: BufferRef::Named("b".into()),
                index: Box::new(Expr::Const(Value::U32(0))),
            }),
        },
    };
    program
}

/// Build a Program with an empty buffer.
///
/// Used by S15 archetype tests.
pub fn build_empty_buffer_program() -> Program {
    let mut program = Program::empty();
    program.buffers.push(BufferDecl::new("empty", DataType::U32, 0));
    program.entry = Node::Return;
    program
}

/// Build a Program with the maximum allowed node count.
///
/// Used by V017 boundary tests.
pub fn build_max_nodes_program() -> Program {
    // ... builds a chain of MAX_NODES operations
}
```

Each factory has a doc comment stating what it builds, what the
resulting Program looks like, and what tests use it. A reader
who sees `build_single_binop(BinOp::Add, 1u32, 2u32)` in a test
knows exactly what shape the Program has without leaving the
test file.

The factories are named descriptively: `build_single_binop`,
`build_empty_buffer_program`, `build_max_nodes_program`. The
name is the entire contract; the doc comment is the detail. A
factory name like `build_test_program()` or
`build_standard_program()` is too vague and is rejected at
review — the reader cannot tell what shape the Program has
without opening the factory.

## backends.rs — the runner

`backends.rs` contains helpers for running Programs on backends
and observing the results:

```rust
/// Run a Program on the default backend and return the output.
///
/// The default backend is whatever vyre::runtime::default_backend()
/// returns, typically wgpu if the `gpu` feature is enabled or
/// the reference interpreter otherwise.
pub fn run_on_default_backend(program: &Program) -> Result<Vec<u8>, RuntimeError> {
    let backend = vyre::runtime::default_backend();
    backend.run(program, &[])
}

/// Run a Program on every registered backend and return the
/// results keyed by backend name.
pub fn run_on_every_backend(program: &Program)
    -> Vec<(String, Result<Vec<u8>, RuntimeError>)>
{
    vyre::runtime::registered_backends()
        .iter()
        .map(|b| (b.name().to_string(), b.run(program, &[])))
        .collect()
}

/// Assert that a WGSL shader compiles on wgpu.
pub fn assert_shader_compiles(shader: &str) {
    // ... creates a wgpu device and attempts to compile the shader
}
```

Each helper wraps a common pattern. `run_on_default_backend` is
the most common: it dispatches a Program on whatever backend is
default and returns the output bytes. `run_on_every_backend` is
used by cross-backend tests. `assert_shader_compiles` is used by
lowering tests.

The helpers do not hide what is happening. They abbreviate.
`run_on_default_backend(&program)` is clearly "run this program,"
and nothing is obscured about what backend is being used or
what the result type is. The reader can guess the full
implementation without looking at it.

## oracles.rs — the comparisons

`oracles.rs` contains helpers for oracle-based assertions. The
helpers make it easier to use strong oracles without
re-implementing the comparison logic in every test.

```rust
/// Look up the expected value for an op on specific inputs from
/// the specification table.
///
/// Panics if no spec table row matches — which is the right
/// failure mode, because the test is asserting the inputs are
/// in the table.
pub fn spec_table_lookup(op: BinOp, inputs: &[Value]) -> Value {
    let table = vyre_conform::spec::tables::get(op);
    for row in table {
        if row.inputs == inputs {
            return row.expected.clone();
        }
    }
    panic!(
        "no spec table row for op {:?} with inputs {:?}",
        op, inputs,
    );
}

/// Assert that an op satisfies a declared law on specific inputs.
///
/// Uses the law checker from vyre-conform.
pub fn assert_law(law: Law, op: BinOp, inputs: &[Value]) {
    let result = vyre_conform::algebra::checker::verify(law, op, inputs);
    assert!(
        result.is_ok(),
        "op {:?} violated law {:?} on inputs {:?}: {:?}",
        op, law, inputs, result,
    );
}

/// Assert that a Program's output agrees with the reference
/// interpreter byte-for-byte.
pub fn assert_agrees_with_reference(program: &Program) {
    let observed = run_on_default_backend(program).expect("dispatch");
    let expected = vyre_conform::reference::run(program, &[])
        .expect("reference interpreter");
    assert_eq!(
        observed, expected,
        "default backend disagreed with reference interpreter",
    );
}
```

These helpers are load-bearing for the oracle discipline. A test
that uses `spec_table_lookup(op, inputs)` as its expected value
is provably using the spec table oracle — the reviewer can
verify this at a glance. A test that uses `assert_law` is
provably using the law oracle. Without the helpers, each test
would inline the oracle logic, and inconsistencies would creep
in.

The helpers are also the way the oracle hierarchy is mechanically
enforced. A reviewer can scan a test file for the helper names
and know which oracles are in use. A test that uses
`assert_eq!(result, 5)` without going through an oracle helper
is suspicious: where did the `5` come from? Was it derived from
the code? The helpers make the oracle explicit, and explicit
oracles are reviewable.

## fixtures.rs — the static data

`fixtures.rs` contains static test data that multiple tests
share:

```rust
/// Canonical test Programs used across the suite.
pub fn canonical_test_programs() -> Vec<Program> {
    vec![
        build_single_binop(BinOp::Add, 1u32, 2u32),
        build_single_binop(BinOp::Mul, 3u32, 5u32),
        build_loop_with_counter(10),
        build_diamond_dataflow(),
        // ... more
    ]
}

/// Known bit patterns used as adversarial inputs.
pub const BIT_PATTERNS: &[u32] = &[
    0x00000000, 0xFFFFFFFF, 0x55555555, 0xAAAAAAAA,
    0xF0F0F0F0, 0x0F0F0F0F, 0xDEADBEEF, 0xCAFEBABE,
    0x80000000, 0x7FFFFFFF,
];

/// Known overflow pairs for u32 addition.
pub const ADD_OVERFLOW_PAIRS: &[(u32, u32, u32)] = &[
    (u32::MAX, 1, 0),
    (u32::MAX, u32::MAX, u32::MAX - 1),
    (0x80000000, 0x80000000, 0),
    // ... more
];
```

The fixtures are constants or simple factory functions. They
exist to avoid repeating the same values in every test. When a
new test needs a canonical Program, it uses
`canonical_test_programs()` rather than building one from
scratch.

Fixtures should be small. A fixture that spans many files and
many layers of indirection is a symptom of over-engineering —
the test setup has grown into its own subsystem. The rule of
thumb: a fixture function is at most 50 lines. A fixture module
is at most 300 lines. Beyond that, the fixtures are doing too
much and need to be refactored into multiple narrower fixtures.

## The rule: helpers clarify, do not obscure

The governing rule of the `support/` directory is that helpers
exist to reduce boilerplate, not to obscure test intent. This is
easy to state and easy to violate. The pattern that violates it
is usually well-intentioned: a contributor sees repeated code
across tests, extracts a helper that captures the pattern, and
discovers that the helper hides details the tests were relying
on.

```rust
// BAD — helper hides critical details
pub fn run_test_case(case: &TestCase) -> TestResult {
    let program = case.build_program();
    let backend = case.select_backend();
    let result = backend.run(&program);
    case.validate_result(result)
}

#[test]
fn test_add() {
    let case = TestCase::new()
        .with_op(BinOp::Add)
        .with_inputs(1u32, 2u32);
    let result = run_test_case(&case);
    assert!(result.passed);
}
```

This test reads as "construct a test case, run it, assert it
passed." Nothing about the actual op, the actual inputs, the
actual expected output, or the actual comparison is visible in
the test body. The reader has to open `TestCase`,
`build_program`, `select_backend`, `run`, `validate_result`, and
`TestResult::passed` to figure out what is happening. The helper
has obscured everything.

```rust
// GOOD — helpers abbreviate, test intent is visible
#[test]
fn test_add_one_plus_two_equals_three() {
    let program = build_single_binop(BinOp::Add, 1u32, 2u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 3u32);
}
```

The second test uses the same `build_single_binop` helper, but
the op, inputs, backend invocation, and expected value are all
visible in the test body. The reader sees `BinOp::Add`, `1u32`,
`2u32`, `3u32` inline. The helper is reducing boilerplate (not
every test has to write out the full `Program` construction) but
it is not hiding what the test is checking.

The difference between the two forms is not the number of helper
calls — both have helper calls. The difference is whether the
test's subject, inputs, and expected output are visible at the
call site. Good helpers keep all three visible. Bad helpers hide
them behind configuration objects.

## When a helper is wrong

Signs that a helper is in the wrong shape:

- **The helper takes a "config" or "options" struct.** These
  hide the inputs behind a second layer of indirection. The
  reader has to know what fields the config has and what values
  the test is setting. Factor the helper into smaller helpers
  that take specific arguments.
- **The helper returns a "result" or "outcome" that must be
  introspected.** The reader cannot tell what the test is
  asserting because the assertion is on an opaque result type.
  Move the assertion into the test body using specific values.
- **The helper's name is generic.** `run_test`, `check_result`,
  `build_case` — names like these tell the reader nothing
  about what the helper does. Rename to something specific.
- **The helper has many parameters.** A helper with more than
  three or four parameters is hiding complexity. Split it into
  smaller helpers with fewer parameters each.
- **The helper has default parameters or builder methods.**
  Builders are for production code, not test helpers. A test
  that relies on builder defaults is fragile: a change to the
  defaults silently changes what the test exercises.

When any of these signs appear, the helper is rejected at
review. The reviewer asks the contributor to rewrite the helper
so the test's intent is visible at the call site.

## When a helper is right

A good helper:

- **Has a descriptive name that tells the reader what it does.**
  `build_single_binop` is good. `create_test` is not.
- **Takes specific arguments, not configuration objects.**
- **Returns a concrete type, not a wrapped opaque result.**
- **Is small — under 30 lines is typical, under 50 is the
  exception.**
- **Has a doc comment stating what it produces and how.**
- **Is used by many tests.** A helper used by one test is not
  reducing boilerplate; it is adding indirection.

## What does not belong in support/

The `support/` directory is for test utilities. It is not for:

- **Implementation code that should live in vyre itself.** If
  the helper is useful to non-test code, move it to vyre's
  source tree and re-export it.
- **Mocks and fakes.** vyre uses real backends and real
  reference interpreters, not mocks. If a test needs a fake
  backend, the fake goes in a dedicated file with a clear name,
  not in `support/`.
- **Trait implementations that only exist for tests.** These
  are usually a sign that the public API is missing a
  capability that tests happen to need; extend the public API
  instead.

## Summary

The `support/` directory holds the test utility code that
reduces boilerplate across tests. It has four files (`programs`,
`backends`, `oracles`, `fixtures`), each with a single concern.
Helpers exist to reduce repetition, not to hide test intent.
Tests using helpers should read as statements of intent with the
subject, inputs, and expected output visible at the call site.
Helpers that obscure intent are rejected at review. This is how
vyre keeps its test suite readable even as the suite grows.

This concludes Part III. Every category has now been covered in
depth.

Next: Part IV, the worked example. Five chapters walking through
the complete test set for `BinOp::Add` end to end. This is the
part of the book you will copy when you add your first primitive
op.
