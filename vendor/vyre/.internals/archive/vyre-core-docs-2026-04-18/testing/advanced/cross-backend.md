# Cross-backend equivalence in practice

## The easy cases work

A cross-backend test that compares `add(1, 2)` on wgpu and the
reference interpreter is easy: both produce `3`, the
assertion passes, the test is green. The easy cases work
because the operation is simple, the inputs are small, and
every reasonable implementation produces the same answer.

The easy cases do not prove anything. They catch trivial
bugs — a backend that returns `42` for everything — and they
establish that the infrastructure is plumbed correctly. What
they do not catch is the hard cases: the operations where
backends might legitimately disagree in subtle ways that pass
simple tests and fail real user code.

This chapter is about the hard cases. Cross-backend bugs in
production rarely involve simple arithmetic. They involve
platform-specific rounding, atomic ordering, workgroup size
variation, and other subtleties where two implementations
can each be "correct" in their own framework but still
produce different bytes. vyre's test suite catches these
cases specifically, because the easy cases are not enough.

## Platform-specific rounding

GPUs differ in how they round intermediate results. The IEEE
754 standard specifies the result of `a + b`, but not the
result of `a + b + c` when computed as a fused operation.
Backend A might compute `(a + b) + c` strictly; Backend B
might compute `a + (b + c)`; Backend C might fuse the two
additions into a single rounding step. Each is allowed by
the hardware's specification but produces different bit
patterns.

vyre's strict float track forbids these variations: the
lowering emits code that prevents the backends from fusing or
reordering. The test suite verifies this with specific inputs
where the unfused and fused paths would diverge:

```rust
/// Triple addition with strict rounding produces the
/// byte-identical result on every backend.
/// Oracle: cross-backend equivalence (I3).
#[test]
fn test_add_f32_triple_strict_cross_backend() {
    // Inputs chosen so that (a + b) + c differs from a fused
    // triple-add by more than 0 ULP.
    let a = 1.0e20f32;
    let b = -1.0e20f32;
    let c = 1.0f32;
    // Unfused: ((1e20 + -1e20) + 1) = (0 + 1) = 1.
    // Fused or reordered: (1e20 + (-1e20 + 1)) = (1e20 + -1e20) = 0.

    let program = build_triple_fadd(a, b, c);

    let mut first: Option<u32> = None;
    for backend in vyre::runtime::registered_backends() {
        let result = backend.run(&program, &[]).expect("dispatch");
        let bits = f32::from_ne_bytes(result).to_bits();
        match first {
            None => first = Some(bits),
            Some(f) => assert_eq!(
                bits, f,
                "backend {} produced {} bits, first produced {} bits",
                backend.name(), bits, f,
            ),
        }
    }

    // Additionally, verify the result is the strict (unfused) value.
    assert_eq!(first.unwrap(), 1.0f32.to_bits(), "expected strict result 1.0");
}
```

The inputs are chosen so that the fused and unfused paths
produce different answers, and the test asserts both that every
backend agrees and that the answer is the strict one. A
backend that fused the additions would fail both assertions.

## Atomic ordering differences

Different GPU backends have different default atomic ordering
semantics. WGSL's `atomicAdd` is relaxed ordering; CUDA's
default might be stronger. vyre's specification pins down the
ordering for each atomic operation, and the lowering emits
code that enforces the specified ordering regardless of the
backend's default.

Testing atomic ordering is harder than testing atomic
arithmetic because ordering is a consistency property, not a
value. A test that verifies "the sum is correct" does not
catch a bug where the sum is correct but intermediate reads
see stale values.

vyre's atomic ordering tests use specific patterns that expose
ordering bugs:

```rust
/// Release-Acquire ordering: a write with Release ordering
/// published before a value is visible to a read with Acquire
/// ordering that follows.
/// Oracle: sequential consistency.
#[test]
fn test_atomic_release_acquire_visibility() {
    // Build a Program where thread A writes to a flag with
    // Release ordering, and thread B reads the flag with
    // Acquire ordering. If B sees the flag set, it must also
    // see all writes that happened before the flag write.

    let program = build_release_acquire_program();
    let result = run_on_default_backend(&program).expect("dispatch");

    // The result is a count of "B saw the flag set but not
    // the preceding writes" events. A correct implementation
    // produces 0; an incorrect one produces nonzero.
    assert_eq!(result, 0, "release-acquire ordering was violated");
}
```

The test runs many iterations to expose the violation, since
ordering bugs are probabilistic.

## Workgroup size variation

GPUs have different preferred workgroup sizes. A vyre Program
that declares a workgroup size of 64 runs on every backend
that can accommodate that size, but different backends
schedule the threads differently. A backend that schedules all
64 threads in one warp behaves differently from one that
schedules 32 in each of two warps, even though both produce
the same output for a well-formed Program.

A bug in vyre might be masked by one backend's scheduling and
exposed by another. vyre tests specifically use workgroup
sizes that correspond to the minimum (1 thread), the typical
(32 or 64 threads), and the maximum supported by the backends,
to catch bugs that depend on scheduling.

```rust
/// Program runs correctly at minimum, typical, and maximum
/// workgroup sizes.
/// Oracle: reference interpreter.
#[test]
fn test_program_workgroup_size_variation() {
    for workgroup_size in [1, 32, 64, 256] {
        let program = build_program_with_workgroup_size(workgroup_size);
        let backend_result = run_on_default_backend(&program)
            .expect(&format!("dispatch at workgroup_size {}", workgroup_size));
        let reference = vyre_conform::reference::run(&program, &[])
            .expect("reference interpreter");
        assert_eq!(
            backend_result, reference,
            "workgroup_size {} disagreed with reference",
            workgroup_size,
        );
    }
}
```

The test iterates workgroup sizes and asserts the backend
agrees with the reference for each. A bug that fires only at
size 256 is caught.

## Driver version sensitivity

Backend behavior can change with driver updates. A test that
passed on driver version 24.1 might fail on 24.2 because the
driver's atomic implementation changed. vyre cannot prevent
driver changes, but it can detect them quickly: the CI run
captures the driver version and the test output, and a
failure that correlates with a driver change is investigated.

For backends where driver versions are captured (wgpu with
its backend information), the test run records the version
in its metadata. When a test starts failing, the maintainer
checks whether the driver changed between the passing and
failing runs. If yes, the failure is a driver regression,
which is a finding that goes upstream to the driver maintainer
and a workaround is added to vyre.

The workaround is usually a conditional: on this specific
driver version, avoid the problematic operation or use a
different lowering. The workaround is committed with a
regression test that catches the specific driver behavior.

## The role of the reference interpreter

Everything in this chapter assumes the reference interpreter
is correct. If the reference interpreter has a bug, every
backend test comparing against it also has the bug, and the
"backend disagreement" might actually be the reference
interpreter being wrong.

Invariant I8 (reference interpreter agrees with CPU reference
functions for every primitive op) is the protection against
this. A dedicated test runs every op through both the
reference interpreter and the CPU reference function on
thousands of random inputs. If they ever disagree, the suite
stops accepting work until the disagreement is resolved.

This is why I8 is a foundational invariant and its test runs
on every CI invocation. Without I8, the oracle for every
cross-backend test is suspect.

## Scaling to many backends

As vyre gains more backends (CUDA, Metal, Vulkan), the
cross-backend test suite scales with them. The key is that
tests are written to iterate over `registered_backends()`
rather than hardcoding backend names. Adding a new backend
to the registry automatically includes it in every test that
uses the iteration pattern.

```rust
for backend in vyre::runtime::registered_backends() {
    // test runs on every registered backend without code changes
}
```

The cost of adding a backend is:

- Implement the backend's lowering and dispatch.
- Register it in the runtime.
- Run the full cross-backend test suite and fix any
  disagreements.
- Commit the backend.

The tests themselves do not change. This is how vyre scales to
many backends without requiring maintainers to update every
test for every new backend.

## When a backend disagrees

A cross-backend failure indicates one of:

- **The disagreeing backend is wrong.** Most common case. The
  backend produced incorrect output; fix the backend or the
  lowering that targets it.
- **The reference interpreter is wrong.** Rare but serious.
  Verify I8 is still passing; if not, fix the reference
  interpreter first.
- **The test is wrong.** The test built a Program with
  intrinsic nondeterminism that vyre's spec does not forbid.
  Either strengthen the spec or rewrite the test to be
  deterministic.

The triage order is: check I8, then check the disagreeing
backend, then check the test. Most of the time, the backend
is wrong, and the fix is clear from the specific way the
outputs differ.

## Summary

Cross-backend equivalence is tested with specific patterns
that catch hard cases: platform-specific rounding, atomic
ordering, workgroup size variation, and driver version
differences. The reference interpreter is the oracle, and
invariant I8 protects the interpreter's correctness. Tests
iterate over `registered_backends()` to scale to new backends
without code changes. Disagreements are investigated with a
specific triage order: I8, then backend, then test.

This concludes Part VIII. Part IX covers the practical
workflow of running the suite.

Next: Part IX opens with [Local workflow](../running/local-workflow.md).
