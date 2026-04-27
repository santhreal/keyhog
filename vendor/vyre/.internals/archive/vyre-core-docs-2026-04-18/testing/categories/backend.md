# Backend tests

## The category that proves cross-backend equivalence

vyre's strongest claim is backend equivalence: every conformant
backend produces byte-identical results from every Program. The
claim is invariant I3, and the backend test category is its
primary defense. Without this category, backends can drift from
each other silently, and vyre's promise of portability becomes
fiction.

Backend equivalence is the hardest property to test because it
requires running the same Program on multiple backends
simultaneously, comparing results, and asserting exact equality.
If only one backend is available in the test environment, the
comparison is impossible in the strict sense, and the test must
either skip or use the reference interpreter as an oracle. vyre's
backend category handles both cases explicitly.

This chapter describes the category's structure, the oracles it
uses, the skip rule for single-backend environments, and the
relationship between backend tests and the reference interpreter.

## The structure

```
tests/backend/
├── wgpu_vs_cpu.rs                 wgpu backend vs cpu reference fn
├── wgpu_vs_reference_interp.rs    wgpu backend vs reference interpreter
├── reference_cpu_agreement.rs     I8: reference interp agrees with cpu ref
├── determinism_across_runs.rs     I1: same run many times
├── cross_backend_smoke.rs         Every backend on every canonical Program
└── backend_registry.rs            Meta-test: every registered backend runs
```

Each file targets a specific aspect of backend equivalence.
`wgpu_vs_cpu.rs` and `wgpu_vs_reference_interp.rs` are the two
main cross-oracle files. `reference_cpu_agreement.rs` verifies
I8 (the invariant that the reference interpreter and the CPU
reference functions agree with each other). `determinism_across_runs.rs`
verifies I1. `cross_backend_smoke.rs` is a sweep that exercises
every registered backend on a canonical set of Programs.
`backend_registry.rs` is a meta-test that ensures every backend
registered with vyre is actually exercised.

## The cross-oracle pattern

A backend test's core pattern is: run a Program on a backend,
run the same Program through an oracle, diff the results, assert
byte-identical.

```rust
/// BinOp::Add on every backend agrees with the reference interpreter.
/// Oracle: reference interpreter.
#[test]
fn test_add_backend_equiv_reference_interp() {
    let program = build_single_binop(BinOp::Add, 0xDEADBEEFu32, 0xCAFEBABEu32);

    let reference_result = vyre_conform::reference::run(&program, &[])
        .expect("reference interpreter");

    for backend in vyre::runtime::registered_backends() {
        let backend_result = backend.run(&program, &[])
            .expect("backend dispatch");

        assert_eq!(
            backend_result, reference_result,
            "backend {} disagreed with reference interpreter",
            backend.name(),
        );
    }
}
```

The test iterates `registered_backends()`, which returns every
backend currently loaded into the runtime. The reference
interpreter runs on the host CPU; each registered backend runs
its own way. The assertion is strict equality.

`registered_backends()` is the key API. It is the mechanism by
which new backends are automatically covered: add a new backend
to the runtime registry, and every test in `backend/` that uses
`registered_backends()` starts exercising it with no test
changes required. This is how vyre keeps the test suite in sync
with the backend set.

## The skip rule

On a development machine with only one backend registered (just
wgpu, for example), cross-backend equivalence tests cannot make
the comparison they claim to make. Running the same Program on
"all backends" when there is only one backend is not a
cross-backend test — it's a single-backend test. The category
handles this by explicitly skipping when fewer than two backends
are available for cross-backend comparison:

```rust
/// Cross-backend agreement on BinOp::Add.
/// Oracle: majority backend output.
/// Skip: needs ≥ 2 backends.
#[test]
fn test_add_cross_backend_agreement() {
    let backends = vyre::runtime::registered_backends();
    if backends.len() < 2 {
        eprintln!("test_add_cross_backend_agreement: skipping — needs ≥ 2 backends");
        return;
    }

    let program = build_single_binop(BinOp::Add, 0xDEADBEEFu32, 0xCAFEBABEu32);
    let results: Vec<_> = backends.iter()
        .map(|b| (b.name(), b.run(&program, &[]).expect("dispatch")))
        .collect();

    let first_result = &results[0].1;
    for (name, result) in &results[1..] {
        assert_eq!(
            result, first_result,
            "backend {} disagreed with {}",
            name, results[0].0,
        );
    }
}
```

The skip is explicit: it prints a message to test output so the
reader knows the test was skipped and why. It does not silently
pass (which would hide missing coverage). It does not fail
(which would cause spurious failures on single-backend machines).
It skips, and the skip is observable.

In CI, backend tests run on machines with multiple backends
registered. The skip does not fire. On developer machines, the
skip might fire. That is fine — the developer can still run the
suite locally and get useful signal from every other test. The
cross-backend specific tests are covered by CI.

The rule: tests that require multiple backends use the skip
pattern. Tests that only need one backend (a single-backend test
with a strong oracle like the reference interpreter) do not need
the skip, because they are not cross-backend tests.

## The reference interpreter as an oracle

The reference interpreter from vyre-conform is not a runtime target and is
never registered as a vyre runtime backend. It is a test oracle. Backend tests
run a Program on a real GPU backend, run the same Program through the
vyre-conform reference interpreter, and compare the results.

With one registered GPU backend, reference-oracle tests can still run because
they are not cross-backend tests. Cross-backend tests still require at least two
real GPU backends and use the skip rule above when that condition is not met.
The reference interpreter's correctness is the foundation of the oracle chain —
which is why invariant I8 (the reference interpreter and CPU reference functions
agree) is tested specifically in `reference_cpu_agreement.rs`.

## I8: reference interpreter vs CPU reference

The reference interpreter is the authority on what a Program
means. Each op's CPU reference function in `src/ops/primitive/`
is also an authority on what that op means. If the two
authorities ever disagree, vyre's test oracles are broken and no
other test can be trusted.

Invariant I8 states that the reference interpreter and the CPU
reference functions agree exactly, for every op, on every input
in the op's domain.

```rust
/// The reference interpreter and cpu.rs reference functions agree
/// on every primitive op for a witnessed sample of inputs.
/// Oracle: I8 (reference agreement).
#[test]
fn test_reference_interp_agrees_with_cpu_refs() {
    for op in vyre::ops::primitive::all_ops() {
        // For each op, sample 10,000 random u32 pairs.
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        for _ in 0..10_000 {
            let a = rng.gen::<u32>();
            let b = rng.gen::<u32>();

            let cpu_result = op.cpu_reference(&[Value::U32(a), Value::U32(b)]);

            let program = build_single_op(op, &[Value::U32(a), Value::U32(b)]);
            let interp_result = vyre_conform::reference::run(&program, &[])
                .expect("reference interpreter");

            assert_eq!(
                interp_result[0], cpu_result,
                "reference interpreter disagreed with cpu reference for op {} on inputs ({}, {})",
                op.name(), a, b,
            );
        }
    }
}
```

The test iterates every op, samples 10,000 random input pairs,
runs each pair through both authorities, and asserts agreement.
A single disagreement is a P0 finding and blocks the entire
suite until resolved. This is not an exaggeration: if the
reference interpreter is wrong, every cross-backend test relying
on it is suspect, and if the CPU reference is wrong, every
specific-input test using it as an oracle is suspect.

The test runs on every CI invocation. If it fails, the fix comes
first — before new features, before bug fixes for other issues,
before anything.

## Determinism across runs

Invariant I1 (determinism) says the same Program run twice on
the same backend produces the same output. A dedicated test
verifies this:

```rust
/// Running the same Program many times produces byte-identical output.
/// Oracle: I1 (determinism).
#[test]
fn test_canonical_programs_are_deterministic_across_runs() {
    let programs = canonical_test_programs();

    for program in programs {
        let first_result = run_on_default_backend(&program).expect("dispatch");

        for run in 1..1000 {
            let result = run_on_default_backend(&program).expect("dispatch");
            assert_eq!(
                result, first_result,
                "run {} disagreed with first run for program {}",
                run, program.name(),
            );
        }
    }
}
```

The test runs each canonical Program 1,000 times and asserts
every run produces the same result. If the Program depends on
any nondeterministic factor — thread scheduling, memory layout,
atomic ordering that is not pinned down — some run will
eventually disagree, and the test catches it.

Running each Program 1,000 times might seem excessive, and for
most code it would be. For vyre's purpose, it is the minimum
that gives the test reasonable power to catch nondeterminism.
Nondeterminism often only fires occasionally; a 10-iteration
test might pass when a 1,000-iteration test would fail. The
cost is small (the Programs are simple) and the confidence gain
is significant.

## Backend registry meta-test

The meta-test ensures every backend registered in the runtime is
actually exercised by at least one test. Without this, a new
backend could be added to the registry and silently not covered
by anything:

```rust
/// Every registered backend appears in at least one backend test.
#[test]
fn test_every_registered_backend_is_exercised() {
    let backends: HashSet<&str> = vyre::runtime::registered_backends()
        .iter()
        .map(|b| b.name())
        .collect();

    let exercised: HashSet<&str> = collect_exercised_backends();

    let missing: Vec<_> = backends.difference(&exercised).collect();
    assert!(
        missing.is_empty(),
        "backends not exercised by any test: {:?}",
        missing,
    );
}
```

The helper `collect_exercised_backends()` scans the rest of the
category for uses of `backend.name()` and collects the names.
The test fails if any registered backend is not named by any
other test in the category. The fix is to add a test that
exercises the missing backend, which is usually trivial since
the backend tests use `registered_backends()` and should cover
any new backend automatically.

## The relationship with primitive op tests

Backend tests and primitive op tests both exercise backends, and
there is natural overlap. The distinction:

- **Primitive op tests** test individual ops end-to-end with
  strong oracles (spec tables, laws). They happen to run on
  whatever backend is default.
- **Backend tests** test cross-backend agreement on a corpus of
  Programs. They do not use specific expected values; they use
  cross-backend diffing as the oracle.

A primitive op test can fail when a backend is broken (because
the backend produces wrong output), but it reports the failure
as "the op test failed." A backend test reports the same failure
as "backends disagreed." The two perspectives are
complementary: the op test pins down that the op is wrong on
some backend; the backend test pins down that the disagreement
exists.

## What backend tests do not cover

Backend tests do not cover:

- **Single-op correctness.** That is the primitive op tests'
  job.
- **Performance.** That is benchmarks.
- **Validation.** That is validation tests.
- **Specific backend implementation details.** A test that
  relies on wgpu's internal behavior is not a vyre test; it is
  a wgpu test.
- **The reference interpreter's own correctness for complex
  compositions.** That is verified indirectly through
  primitive op tests and the I8 check; a direct verification
  would require an independent oracle for the reference
  interpreter itself, which does not exist.

## When a backend test fails

A backend test failure can mean several things:

- **A backend is wrong.** The most common case. The backend that
  produced the divergent output is broken. Fix by debugging the
  backend or the lowering that targets it.
- **The reference interpreter is wrong.** Rare but serious. If
  the reference interpreter is wrong, I8 should also fail, and
  the priority is I8 first.
- **The test is wrong.** The test built a Program that depends
  on a nondeterministic factor vyre does not forbid, and the
  failure is the test catching its own bug. The fix is to
  strengthen the Program or remove the dependence.

The triage order is: check I8 first, then check which backend
disagreed, then check whether the Program has any inputs that
could legitimately produce different results (they should not,
but the check is due diligence).

## Summary

Backend tests verify cross-backend equivalence (I3), determinism
(I1), and reference agreement (I8). Tests iterate
`registered_backends()` to automatically cover new backends. The
skip rule handles single-backend environments explicitly. I8 is
the foundation invariant; every other cross-backend test depends
on it. This category is what makes vyre's portability promise a
technical claim instead of a marketing one.

Next: [Regression tests](regression.md).
