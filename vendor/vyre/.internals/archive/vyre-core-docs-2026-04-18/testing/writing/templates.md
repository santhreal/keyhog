# Templates

## Copy, fill in, commit

The decision tree in the previous chapter told you which
category your test belongs to. This chapter gives you the shape
to fill in. Each template is a canonical skeleton for one kind
of test. Copy it into your file, replace the placeholders with
specifics, adjust to taste, commit. The templates exist to
eliminate the "what should this look like" step and to enforce
consistency across the suite.

Templates are not laws. You may deviate when you have a good
reason. The reason must be articulable at review — "I used a
different shape because the template did not fit, and here is
why" is acceptable; "I just felt like it" is not.

## Template 1 — Primitive op specific-input test

For integration tests that verify a primitive op on specific
inputs with a spec table or law oracle.

```rust
/// <one-line description of property: "add(a, b) == c for a=..., b=...">
/// Oracle: <SpecRow from vyre-conform::spec::tables::<op> row N>
///         | <DeclaredLaw::<Law>, verified <Verification>>
#[test]
fn test_<op>_<property_description>() {
    let program = build_single_binop(BinOp::<Op>, <a>, <b>);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, <expected>, "<failure message>");
}
```

Fill in:
- `<op>`: the op under test (`add`, `xor`, `shl`, etc.)
- `<property_description>`: a short snake-case name for the
  property (`identity_zero`, `overflow_wraps`, `commutative`).
- `<a>`, `<b>`: the specific input values as Rust literals
  (e.g., `0xDEADBEEFu32`, `u32::MAX`).
- `<expected>`: the specific expected output from the oracle.
- Oracle line: the exact oracle, including the spec table row
  number or the declared law.
- Failure message: a clear sentence describing what should have
  been true.

Example:

```rust
/// add(0xDEADBEEF, 0) == 0xDEADBEEF. Right identity on Add.
/// Oracle: SpecRow from vyre-conform::spec::tables::add (row 1).
#[test]
fn test_add_right_identity_dead_beef_plus_zero() {
    let program = build_single_binop(BinOp::Add, 0xDEADBEEFu32, 0u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, 0xDEADBEEFu32, "add(0xDEADBEEF, 0) should equal 0xDEADBEEF");
}
```

## Template 2 — Law test

For integration tests that verify an algebraic law on specific
witnesses.

```rust
/// <law name>: <formal statement of the law on witnesses>.
/// Oracle: DeclaredLaw::<Law>, verified <Verification>.
#[test]
fn test_<op>_<law>_<witness_description>() {
    let <a> = <first witness>;
    let <b> = <second witness>;
    // ... more witnesses as needed

    let program_1 = build_...(<first expression>);
    let program_2 = build_...(<second expression>);

    let result_1 = run_on_default_backend(&program_1).expect("dispatch");
    let result_2 = run_on_default_backend(&program_2).expect("dispatch");

    assert_eq!(result_1, result_2, "<law name> violated on witnesses ...");
}
```

Example:

```rust
/// Commutativity: add(a, b) == add(b, a).
/// Oracle: DeclaredLaw::Commutative, verified ExhaustiveU8.
#[test]
fn test_add_commutative_dead_beef_cafe_babe() {
    let a = 0xDEADBEEFu32;
    let b = 0xCAFEBABEu32;

    let program_ab = build_single_binop(BinOp::Add, a, b);
    let program_ba = build_single_binop(BinOp::Add, b, a);

    let result_ab = run_on_default_backend(&program_ab).expect("dispatch ab");
    let result_ba = run_on_default_backend(&program_ba).expect("dispatch ba");

    assert_eq!(
        result_ab, result_ba,
        "add is commutative: add({:#x}, {:#x}) should equal add({:#x}, {:#x})",
        a, b, b, a,
    );
}
```

## Template 3 — Validation rule must-reject test

For validation tests that verify a rule fires when it should.

```rust
/// V<NNN>: <rule description>. Must-reject case.
/// Oracle: V<NNN> rule definition in src/ir/validate/<file>.rs.
#[test]
fn test_v<NNN>_rejects_<scenario>() {
    let mut program = Program::empty();
    // ... construct a Program that violates V<NNN> and no other rule
    program.entry = <violating node>;

    let errors = validate(&program);

    assert_eq!(
        errors.len(), 1,
        "expected exactly one error, got {:?}", errors,
    );
    assert_eq!(errors[0].rule, ValidationRule::V<NNN>);
}
```

And the must-accept complement:

```rust
/// V<NNN>: <rule description>. Must-accept case.
/// Oracle: V<NNN> rule definition in src/ir/validate/<file>.rs.
#[test]
fn test_v<NNN>_accepts_<scenario>() {
    let mut program = Program::empty();
    // ... the must-reject case with the violation removed
    program.entry = <well-formed node>;

    let errors = validate(&program);

    assert!(errors.is_empty(), "expected no errors, got {:?}", errors);
}
```

## Template 4 — Lowering variant coverage test

For lowering tests that verify a specific IR variant has a
lowering rule.

```rust
/// <Variant> lowers to WGSL.
/// Oracle: WGSL syntax — output contains the expected construct
/// and compiles on wgpu.
fn test_lowering_of_<variant>() {
    let program = <build minimal Program containing the variant>;

    let shader = wgsl::lower(&program).expect("lowering succeeds");

    assert!(
        shader.contains(<expected construct>),
        "lowered shader should contain {}, got:\n{}",
        <expected>, shader,
    );

    assert_shader_compiles(&shader);
}
```

The `test_lowering_of_<variant>` function is referenced from the
exhaustiveness meta-test in `expr_coverage.rs` or `node_coverage.rs`.
See [Lowering tests](../categories/lowering.md) for the
meta-test pattern.

## Template 5 — Cross-backend equivalence test

For backend tests that verify every backend agrees.

```rust
/// <description> on every registered backend.
/// Oracle: reference interpreter.
/// Skip: needs ≥ 1 backend (reference interpreter is always available).
#[test]
fn test_<subject>_backend_equiv() {
    let program = <build Program>;

    let reference = vyre_conform::reference::run(&program, &[])
        .expect("reference interpreter");

    for backend in vyre::runtime::registered_backends() {
        let observed = backend.run(&program, &[])
            .expect("backend dispatch");
        assert_eq!(
            observed, reference,
            "backend {} disagreed with reference interpreter",
            backend.name(),
        );
    }
}
```

## Template 6 — Adversarial test

For tests that verify hostile inputs do not panic.

```rust
/// <Hostile input description> does not panic.
/// Oracle: I11 (no panic).
#[test]
fn test_<class>_does_not_panic_on_<scenario>() {
    let input = <construct hostile input>;

    let result = std::panic::catch_unwind(|| {
        // call whatever vyre function is being stressed
        let _ = vyre::<function>(&input);
    });

    assert!(
        result.is_ok(),
        "vyre::<function> panicked on <scenario>",
    );
}
```

## Template 7 — Property test

For property tests with a proptest block.

```rust
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1_000,
        max_shrink_iters: 10_000,
        ..ProptestConfig::default()
    })]

    /// <invariant description>.
    /// Oracle: <I_N>.
    #[test]
    fn <invariant_name>(input in <generator>()) {
        // arrange
        let <var> = <compute from input>;

        // act
        let result = <function>(&<var>);

        // assert
        prop_assert_eq!(result, <expected from input>);
    }
}
```

Property test templates are more skeletal than other categories
because the specifics depend heavily on the invariant. See
[Property-based testing for GPU IR](../advanced/property-generators.md)
in Part VIII for deeper treatment.

## Template 8 — Regression test

For regression tests in `tests/regression/`.

```rust
//! Regression: YYYY-MM-DD — <short bug description>
//!
//! Symptom: <what went wrong from the user's perspective>
//!
//! Root cause: <what was actually broken>
//!
//! Fixed: commit <hash> — <short fix description>

use vyre::ir::<what you need>;
use crate::support::programs::<what you need>;
use crate::support::backends::run_on_default_backend;

/// <one-line test description tied to the bug above>.
#[test]
fn regression_<short_name>() {
    let program = <minimal reproducer>;
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(result, <correct post-fix value>);
}
```

## Template 9 — Benchmark

For criterion benchmarks in `tests/benchmarks/`.

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_<name>(c: &mut Criterion) {
    // Set up inputs outside the iteration loop.
    let <setup> = <compute>;

    c.bench_function("<name>", |b| {
        b.iter(|| {
            let result = <function>(black_box(&<setup>));
            black_box(result)
        });
    });
}

criterion_group!(benches, bench_<name>);
criterion_main!(benches);
```

## Template 10 — Unit test (inline)

For unit tests inline with source code.

```rust
// src/module.rs
pub fn <function>(<args>) -> <result> {
    // ...
}

#[cfg(test)]
mod tests {
    use super::*;

    /// <function> with <input class> returns <expected>.
    #[test]
    fn <function>_<property>() {
        let result = <function>(<specific input>);
        assert_eq!(result, <specific expected>);
    }
}
```

## When templates do not fit

Sometimes a test does not match any template. That is okay.
Templates are starting points, not constraints. The rule is:

- **If the template almost fits, use it and deviate where
  necessary.** A test that is 90% template and 10% custom is
  easier to review than a test that is 100% custom.
- **If no template fits at all, write from scratch and explain
  in the PR description why the templates did not apply.** The
  explanation helps reviewers and may reveal that the template
  library needs a new entry.
- **If multiple templates apply, pick the one that matches the
  primary subject.** A test that exercises lowering and backend
  equivalence equally can use either the lowering template or
  the backend template — pick the one that matches what the
  assertion is about.

## Templates are maintained

The template set in this chapter grows when new common shapes
emerge. If you find yourself writing a similar test many times
and no template covers it, propose a new template via a PR
against this book. New templates require:

- A name and a purpose statement.
- The template itself.
- At least two real tests in the suite that would use it.
- A placement in the template list ordered by frequency of use.

Adding a template does not retroactively rewrite existing tests.
Existing tests may use older shapes; the new template applies
to future tests.

## Summary

Templates are canonical skeletons for common test shapes. Ten
templates cover the vast majority of tests in vyre. Copy, fill
in, commit. Deviate with justification when a template almost
fits. Write from scratch only when no template fits at all.
Consistency across the suite is load-bearing for readability,
and templates are how consistency happens mechanically.

Next: [Naming](naming.md) — the `test_<subject>_<property>`
convention and why consistency in names matters.
