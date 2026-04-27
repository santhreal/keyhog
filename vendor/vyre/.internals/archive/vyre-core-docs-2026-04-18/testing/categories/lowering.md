# Lowering tests

## What lowering is, and why it is load-bearing

Lowering is the translation from `ir::Program` to a backend shader
language. vyre's primary lowering target is WGSL (the WebGPU
shading language), implemented in `src/lower/wgsl/`. Lowering
takes a validated Program — a tree of nodes and expressions
referring to declared buffers with declared types — and produces
a text string containing WGSL source code that a GPU backend will
compile and dispatch.

The lowering is the compiler in vyre. Everything it produces must
preserve the semantics of the input, must be valid syntax for the
target language, must include the safety properties required by
the specification, and must produce byte-identical outputs across
every conformant backend. A bug in lowering is a miscompilation —
the most dangerous class of bug described in [A tour of what can
go wrong](../a-tour-of-what-can-go-wrong.md).

Lowering tests are the category that defends against
miscompilation. They verify that every construct the IR can
express has a correct lowering, that the lowered output is valid
WGSL, and that safety properties are not silently dropped. This
category is what makes lowering trustworthy, and trustworthy
lowering is what makes vyre's correctness promise real.

## The structure of the category

Lowering tests live in `tests/integration/lowering/` and are
organized by the concern each file addresses:

```
tests/integration/lowering/
├── expr_coverage.rs       One test per Expr variant
├── node_coverage.rs       One test per Node variant
├── binop_coverage.rs      One test per BinOp variant
├── unop_coverage.rs       One test per UnOp variant
├── atomic_coverage.rs     One test per AtomicOp variant
├── buffer_access.rs       One test per BufferAccess variant
├── wgsl_syntax.rs         Lowered output is valid WGSL
├── bounds_checks.rs       Every buffer access has a bounds check
├── shift_masks.rs         Every shift operation has a mask
├── roundtrip.rs           Specific Programs lower to specific shaders
└── meta_coverage.rs       Exhaustiveness meta-tests
```

The coverage files (the first six) are the largest by file count
and the most important. They exercise every enum variant that
appears in the IR and verify the lowering handles each one. The
exhaustiveness meta-tests ensure the coverage files keep up with
the IR as the IR grows.

## The exhaustiveness meta-test

The single most load-bearing test in this category is the
exhaustiveness meta-test, which uses Rust's match exhaustiveness
to force the test suite to keep up with the IR:

```rust
/// Every Expr variant has a lowering test.
///
/// This match is load-bearing. When a new Expr variant is added to
/// the IR, this match becomes non-exhaustive and fails to compile.
/// The broken build is the finding: the contributor must add a
/// lowering test for the new variant before the file can compile
/// again.
#[test]
fn every_expr_variant_is_tested() {
    // This match is the test. We never call the function; we only
    // use the match to enforce exhaustiveness at compile time.
    #[allow(dead_code)]
    fn exhaustive(expr: &Expr) {
        match expr {
            Expr::Const(_)        => verify(test_lowering_of_const),
            Expr::Load { .. }     => verify(test_lowering_of_load),
            Expr::BinOp { .. }    => verify(test_lowering_of_binop),
            Expr::UnOp { .. }     => verify(test_lowering_of_unop),
            Expr::Atomic { .. }   => verify(test_lowering_of_atomic),
            Expr::Index { .. }    => verify(test_lowering_of_index),
            Expr::Cast { .. }     => verify(test_lowering_of_cast),
            Expr::ThreadId        => verify(test_lowering_of_thread_id),
            Expr::WorkgroupId     => verify(test_lowering_of_workgroup_id),
            // ... all Expr variants
        }
    }
}

fn verify(_test_fn: fn()) {
    // This function does nothing. It exists to make the match
    // arms reference real test functions, which ensures those
    // functions compile and exist.
}
```

The match covers every variant of `Expr`. If a new variant is
added without updating the match, the file does not compile and
CI fails with a clear error: "non-exhaustive patterns in match
expression, add Expr::NewVariant arm". The fix is to add the
arm and, in doing so, reference a test function that exercises
lowering for the new variant. The contributor is forced to write
the test before the build can pass.

This pattern generalizes to every enum the lowering touches:
`Node`, `BinOp`, `UnOp`, `AtomicOp`, `BufferAccess`, `DataType`.
Each has its own exhaustiveness meta-test in `meta_coverage.rs`,
and each meta-test forces contributors to keep test coverage in
lockstep with the enum.

## A coverage test, in full

A variant coverage test is short and focused. It builds the
smallest Program that uses the target variant, lowers it, and
asserts the output contains the expected WGSL construct.

```rust
/// Expr::BinOp with BinOp::Add lowers to a WGSL addition.
/// Oracle: WGSL syntax — the lowered shader must contain the
/// binary '+' operator applied to two u32 values.
fn test_lowering_of_binop_add() {
    let program = build_single_binop(BinOp::Add, 1u32, 2u32);

    let shader = wgsl::lower(&program).expect("lowering succeeds");

    // The lowered shader must contain the addition operator.
    assert!(
        shader.contains("+ "),
        "lowered shader should contain '+ ' operator, got:\n{}",
        shader,
    );

    // The shader must be valid WGSL (compiles on wgpu's frontend).
    assert_shader_compiles(&shader);
}
```

The assertions are specific but not brittle. The test does not
assert the shader equals a specific string byte-for-byte — that
would fail on whitespace changes or identifier renaming and would
be rejected at review. Instead, the test asserts two things:

1. **The expected construct appears.** The `+ ` substring check
   is strong enough to catch a miscompilation that changed the
   operator (say, to `- `) but weak enough to survive formatting
   changes.
2. **The output is valid WGSL.** The `assert_shader_compiles`
   helper feeds the shader to wgpu's parser and asserts it
   compiles. If the lowering produced invalid syntax, this
   assertion fires.

Together, these two assertions verify that the lowering produces
syntactically valid output with the expected semantic construct.
The combination is strong enough to catch lowering bugs in
practice.

## The bounds check tests

Every buffer access in a vyre Program must have a bounds check in
the lowered shader. This is a safety property: without a bounds
check, an out-of-range access produces undefined behavior on the
backend, which can be a security vulnerability. The specification
requires the check; the lowering is responsible for emitting it;
the test category verifies it was emitted.

```rust
/// Every buffer access in lowered WGSL has a bounds check.
/// Oracle: I12 (no undefined behavior).
#[test]
fn test_buffer_access_has_bounds_check() {
    let program = build_program_with_buffer_access();
    let shader = wgsl::lower(&program).expect("lowering succeeds");

    // A bounds check is a comparison against the buffer length.
    // vyre's lowering emits these as 'if (index < length) {...}'
    // or equivalent constructs. The specific form may vary, but
    // the comparison must be present.
    assert!(
        shader.contains("< arrayLength") || shader.contains("< buffer_len"),
        "lowered shader must contain a bounds check, got:\n{}",
        shader,
    );
}
```

The assertion is structural: "some comparison against the array
length exists in the output." It does not pin down the exact
syntax the lowering uses, because that would be brittle. But it
is strong enough to catch the `LowerRemoveBoundsCheck` mutation
from the mutation catalog: if the lowering stops emitting the
bounds check, this test fails.

A stronger form of the test runs the Program with an
out-of-range index and asserts the runtime returns a safe value
(typically zero or the last valid element) instead of corrupting
memory. This is an integration test that straddles the lowering
and dispatch categories; it lives in `buffer_access.rs` and
exercises the end-to-end behavior.

## The shift mask tests

Shift operations on `u32` in WGSL are undefined for shift counts
greater than or equal to 32. vyre's specification says shift
counts are masked: `shl(x, n) == shl(x, n & 31)`. The lowering
must emit the mask; tests verify it was emitted.

```rust
/// Every shift in lowered WGSL has a mask on the shift count.
/// Oracle: I12 (no undefined behavior).
#[test]
fn test_shl_has_shift_mask() {
    let program = build_single_binop(BinOp::Shl, 1u32, 5u32);
    let shader = wgsl::lower(&program).expect("lowering succeeds");

    // The shift count must be masked with '& 31u' before use.
    assert!(
        shader.contains("& 31u") || shader.contains("&31u"),
        "lowered shader must mask shift count with '& 31u', got:\n{}",
        shader,
    );
}
```

Same pattern as the bounds check test. The assertion checks for
the mask's presence. The mutation `LowerRemoveShiftMask` deletes
the mask; a passing test kills the mutation.

## Roundtrip tests

The `roundtrip.rs` file contains tests that assert specific
Programs lower to specific expected shaders. These tests are
stronger than coverage tests because they pin down the exact
output, but they are more brittle because they fail on any
formatting change.

The trade-off is managed by keeping roundtrip tests few and
focused. A handful of canonical Programs (the smallest one, a
composed chain, a loop, a conditional, an atomic) have roundtrip
tests with expected shaders committed. Changes to the lowering
that modify the expected output require updating the roundtrip
tests in lockstep, which forces the contributor to confirm the
change is intentional and not an accidental regression.

Roundtrip tests are not a replacement for coverage tests. They
complement coverage by catching regressions that coverage tests
would miss (subtle changes in how a construct is emitted), and
they serve as documentation for what the lowering is supposed to
produce.

## WGSL validity

Every lowering test (coverage, bounds check, shift mask, roundtrip)
ends by asserting the lowered output is valid WGSL. The
`assert_shader_compiles` helper in `tests/support/backends.rs`
runs the shader through wgpu's parser (or a standalone WGSL
parser) and fails if it rejects the syntax.

```rust
pub fn assert_shader_compiles(shader: &str) {
    use wgpu::*;

    let instance = Instance::default();
    let adapter = pollster::block_on(instance.request_adapter(&Default::default()))
        .expect("adapter");
    let (device, _queue) = pollster::block_on(adapter.request_device(&Default::default(), None))
        .expect("device");

    // request_device gives us a parser; we only need the parse.
    let module = device.create_shader_module(ShaderModuleDescriptor {
        label: Some("vyre test shader"),
        source: ShaderSource::Wgsl(shader.into()),
    });

    // If the parse failed, wgpu panics with a diagnostic. If we
    // reach here, the shader is valid.
    drop(module);
}
```

The helper is expensive (it creates a wgpu device) but amortizes
across many tests per run. A cached device can be reused across
tests in the same test binary, which is what
`tests/support/backends.rs` actually does in practice.

The assertion of WGSL validity is not the same as the assertion
of semantic correctness. A shader can be syntactically valid and
still compute the wrong thing. Valid syntax is necessary but not
sufficient. The primitive op tests and backend tests verify
semantic correctness; lowering tests verify the structural
properties that must hold regardless of what the shader computes.

## The relationship with primitive op tests

Lowering tests and primitive op tests overlap in scope: both
exercise the lowering pipeline. The distinction is in their
oracles and what they assert.

- **Primitive op tests** (in `integration/primitive_ops/`)
  exercise the lowering end-to-end: build a Program, lower it,
  dispatch it, observe the output, assert against a spec table
  row or a law. The oracle is the op's expected computational
  result.
- **Lowering tests** (in `integration/lowering/`) exercise only
  the lowering step: build a Program, lower it, assert the
  lowered output has the expected properties (contains the
  expected construct, has bounds checks, is valid WGSL). The
  oracle is the lowered shader's structure.

Both are necessary. Primitive op tests would miss a bounds check
regression if the regression happened to not cause an observable
wrong answer (for example, if the missing check is on an index
that happens to be in range for all test inputs). Lowering tests
catch the structural regression regardless. Conversely, lowering
tests would miss a semantic regression where the structure is
preserved but the meaning changes (for example, if the lowering
emits `+` for `BinOp::Mul`). Primitive op tests catch the semantic
regression.

A PR that modifies lowering must pass both categories. If either
fires, the PR has a regression.

## Coverage meta-test cadence

The coverage meta-tests run on every CI invocation, not just
nightly, because they protect against the silent degradation of
adding IR variants without tests. A nightly-only meta-test would
let a gap exist for days. A per-commit meta-test forces the gap
to be closed at the PR where the new variant was introduced.

The cost is small: the meta-tests are exhaustiveness matches that
run at compile time, not at test execution time. A failing
meta-test is a compile error, not a test failure, and compile
errors are cheaper than test failures.

## When the lowering changes

A change to the lowering typically requires changes to the
lowering tests. The cases are:

- **New IR variant:** the exhaustiveness meta-test fires, the
  contributor adds a test for the new variant, the change
  lands.
- **Existing variant lowered differently:** the contributor
  updates the coverage test's assertion if the existing
  assertion no longer matches. The roundtrip test (if one exists
  for the affected construct) is updated too.
- **Optimization added:** the coverage test might continue to
  pass (the basic construct still appears), but the roundtrip
  test likely fails because the output shape changed. The
  contributor updates the roundtrip baseline and explains the
  change in the PR.
- **Lowering bug fixed:** a regression test is added to
  `tests/regression/` with a reference to the bug and a
  minimized reproducer. The fix plus the regression test land
  together.

Each of these is a PR-level change, not a quiet drift. The tests
make the change visible.

## Summary

Lowering tests verify that every IR construct has a correct
lowering, that lowered output is valid WGSL, and that safety
properties (bounds checks, shift masks) are preserved. Coverage
meta-tests enforce exhaustiveness at compile time. Roundtrip tests
pin down specific outputs as baselines. The category is the main
defense against miscompilation, and together with the primitive
op tests it forms the structural and semantic verification of
the pipeline's critical stage.

Next: [Wire format tests](wire_format.md).
