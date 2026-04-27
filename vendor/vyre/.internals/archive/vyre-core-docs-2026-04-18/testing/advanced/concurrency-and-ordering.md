# Concurrency and ordering

## The hardest class of bugs

Concurrency bugs are the hardest class of bugs to find and the
hardest class to fix. They do not reproduce reliably. They
depend on timing that varies across machines. They pass all
the tests on the developer's laptop and fire once a week in
production. They are the bugs that make engineers doubt the
competence of their own suite.

vyre has a specific concurrency risk: atomic operations,
workgroup memory, and barriers. These are the GPU equivalents
of the host-side concurrency primitives, and they are
exercised by every Program that uses parallel dispatch. A bug
in how vyre lowers atomics, or in how the validator handles
barriers, or in how the backend schedules workgroups, produces
wrong results — and the wrong results are sporadic because
they depend on the GPU's internal scheduling.

This chapter is about testing concurrency in vyre. The
techniques are different from testing sequential code: you
cannot just run the test and compare the output to an expected
value, because the expected value depends on interleaving. You
test for properties that must hold regardless of interleaving,
and you stress the system enough to expose the cases where
the properties do not hold.

## What vyre concurrency looks like

A vyre Program that uses parallelism has:

- **Workgroups:** groups of threads that run together and can
  share workgroup memory.
- **Workgroup memory:** memory shared between threads in the
  same workgroup, accessed via `BufferAccess::Workgroup`.
- **Barriers:** synchronization points where all threads in a
  workgroup wait until all have reached the barrier.
- **Atomics:** operations that modify shared memory with
  guaranteed ordering semantics.

Each of these introduces opportunities for bugs. Workgroup
memory access without a barrier produces races. Barriers under
divergent control flow produce undefined behavior. Atomics
with weakened ordering produce visible-to-one-thread,
invisible-to-another inconsistencies.

The vyre specification pins down the correct behavior for each
case. Validation catches some mistakes (barriers under
divergent control are rejected by V010). Lowering handles
others (workgroup memory access is lowered with proper
synchronization). Backend behavior follows the GPU's own
specification for atomics.

Tests in this category verify that vyre's handling of each
concurrent case produces correct output regardless of how the
backend schedules threads.

## The test categories for concurrency

Concurrency tests are distributed across several existing
categories rather than concentrated in one. The reason is
that concurrency is a property of tests, not a test category.
A primitive op test, a validation test, a backend test, and a
property test can all exercise concurrency.

- **Primitive op tests** exercise atomic ops (`AtomicAdd`,
  `AtomicCompareExchange`) with specific inputs, checking that
  the final value matches the spec table oracle.
- **Validation tests** exercise the V-rules that catch
  barrier and atomic mistakes (V010, V013).
- **Backend tests** exercise cross-backend agreement on
  concurrent Programs, ensuring every backend produces the
  same result despite different scheduling.
- **Property tests** exercise invariants like "running the
  same concurrent Program N times produces the same output"
  (determinism, I1).
- **Adversarial tests** exercise hostile concurrent Programs
  (racing writes, unbounded contention) and verify graceful
  handling.

This chapter describes the specific patterns used in these
tests for concurrent subjects.

## The determinism stress test

The most important concurrency test in vyre is the
determinism stress test. It runs a concurrent Program many
times and asserts every run produces the same output.

```rust
/// Atomic add with 256 threads writing to one slot produces
/// the same sum every time.
/// Oracle: I1 (determinism).
#[test]
fn test_atomic_add_determinism_256_threads() {
    let program = build_atomic_add_program(256);

    let first_result = run_on_default_backend(&program).expect("dispatch");

    for run in 1..1000 {
        let result = run_on_default_backend(&program).expect("dispatch");
        assert_eq!(
            result, first_result,
            "run {} disagreed with first run (determinism violation)",
            run,
        );
    }
}
```

Running 1000 times sounds excessive. It is the minimum that
gives reasonable power to catch rare ordering bugs.
Nondeterminism often fires infrequently — a particular
scheduling that happens once in a thousand runs — and a
10-run test would miss it. Running 1000 times costs a minute
or two but catches the bugs that short runs miss.

The same pattern applies to barriers, workgroup memory, and
anything else where scheduling could matter. Build the Program,
run it a thousand times, assert every run produces the same
output. If the test fires, either the Program has a race (bug
in the test author's understanding) or the backend has a
scheduling-dependent bug (bug in vyre).

## The cross-backend concurrency test

Running a concurrent Program on multiple backends catches a
different class of bug: the backends might agree internally
but disagree with each other because of different atomic
semantics or different scheduling disciplines.

```rust
/// Atomic compare-exchange on every backend produces the same
/// final value.
/// Oracle: cross-backend agreement (I3).
#[test]
fn test_atomic_compare_exchange_cross_backend() {
    let program = build_cas_program();

    let results: Vec<_> = vyre::runtime::registered_backends()
        .iter()
        .map(|b| (b.name(), b.run(&program, &[])))
        .collect();

    let first_name = &results[0].0;
    let first_result = &results[0].1.as_ref().expect("backend 0 dispatch");
    for (name, result) in &results[1..] {
        let result = result.as_ref().expect("backend dispatch");
        assert_eq!(
            result, *first_result,
            "backend {} disagreed with {} on atomic CAS",
            name, first_name,
        );
    }
}
```

The assertion is byte equality across backends. If any
backend produces a different final value, the test fails and
the disagreement is investigated. Usually the disagreement
points at a backend that has incorrect atomic semantics or at
a vyre lowering that is wrong for one backend.

## The exhaustive interleaving test

For very small concurrent Programs (2-3 threads, simple
operations), it is possible to enumerate every possible
interleaving of operations and verify that every interleaving
produces a correct result. This is model checking in miniature.

```rust
/// Every interleaving of two threads incrementing a counter
/// produces the correct final value.
/// Oracle: sequential consistency.
#[test]
fn test_two_thread_increment_every_interleaving() {
    let interleavings = all_interleavings_for_two_threads();

    for interleaving in interleavings {
        let result = run_with_interleaving(&interleaving);
        assert_eq!(result, 2, "interleaving {:?} should produce 2", interleaving);
    }
}
```

The `all_interleavings_for_two_threads` helper uses a
test-only scheduler that enumerates every possible ordering.
The test then runs each ordering and asserts the result.

Exhaustive interleaving is expensive: the number of
interleavings grows factorially with the number of operations.
It is only practical for small tests. For larger concurrent
programs, the determinism stress test and cross-backend test
are the alternatives.

## Testing barriers

Barriers synchronize threads within a workgroup. The
specification says all threads in a workgroup must reach the
barrier before any can proceed past it. A correct barrier
implementation respects this; a broken one lets some threads
proceed early, which produces incorrect output.

Barrier tests verify:

- **Correct synchronization.** A Program that writes a value
  before a barrier and reads it after must see the written
  value on every thread. If the barrier is missing or broken,
  some threads see stale values.
- **Validation rejection under divergent control.** The V010
  rule rejects Programs where a barrier is reached from a
  conditional branch that is not uniformly taken. The test
  constructs a Program with a divergent barrier and asserts
  V010 fires.
- **Correct lowering.** The lowering must emit the correct
  backend-specific barrier instruction (e.g.,
  `workgroupBarrier()` in WGSL). The test lowers a Program
  with a barrier and asserts the output contains the expected
  construct.

Each of these is a specific test in the appropriate category.

## Testing atomics

Atomic operations are the fine-grained primitives for
concurrent memory access. vyre's atomics are `AtomicAdd`,
`AtomicCompareExchange`, `AtomicMin`, `AtomicMax`, and others.
Each has specific semantics defined in the specification.

Atomic tests verify:

- **Final value correctness.** A Program with N threads
  performing an atomic add must produce a final value equal
  to the sum of the increments. The test runs the Program
  and asserts the final value.
- **Atomicity.** Racing atomic writes must not produce torn
  or partially-updated values. Specific tests construct
  scenarios where a non-atomic would produce tearing and
  assert the atomic prevents it.
- **Ordering.** Atomic operations have memory ordering
  semantics (Relaxed, Acquire, Release, SeqCst). The tests
  verify that each ordering produces the expected visibility
  of operations to other threads.

These tests are complex because the assertions are about
invariants rather than specific values. The invariants are
stated in the specification; the tests instantiate the
invariants on specific Programs.

## Testing workgroup memory

Workgroup memory is shared between threads in a workgroup.
Access patterns include:

- **All threads read from the same slot** (uniform read). The
  test verifies every thread reads the same value.
- **All threads write to the same slot** (contended write).
  The test verifies the final value is one of the written
  values (not a torn value, not a stale value).
- **Each thread writes to its own slot** (uncontended). The
  test verifies each slot has the correct value.
- **Write-then-read across a barrier.** The test verifies
  the read after the barrier sees the write before it.

These patterns map to the S8-S10 structural archetypes. The
tests instantiate each archetype for workgroup memory
subjects.

## Scheduling exposure

The GPU backend's scheduling is opaque: vyre does not control
how threads are scheduled. The backend has its own policy, and
the policy may change between driver versions. This creates a
risk: a test that works on the current scheduling might fail
on a future one.

vyre's defense against this risk is determinism testing.
Running the same Program many times with different random
scheduling variations (by introducing micro-delays, varying
workgroup sizes, changing dispatch dimensions) exposes cases
where the backend's scheduling produces different results.
The test catches these before they reach users.

Stress-testing scheduling is imperfect because the test cannot
control the backend's internal scheduler. What it can do is
run many variations and verify they all produce the same
result. The variations are not exhaustive, but they are
enough to catch common bugs.

## Sanitizers

For concurrency bugs in host-side code (not GPU), vyre uses
sanitizers:

- **ThreadSanitizer (TSan)** catches data races in host code.
  A dedicated CI job builds vyre with `-Z sanitizer=thread`
  and runs the test suite. Any detected race is a P1 finding.
- **AddressSanitizer (ASan)** catches memory errors. Used for
  adversarial tests where hostile inputs might trigger buffer
  overflows.

Sanitizer jobs are slower than normal test runs (by a factor
of 2-5x), so they run in dedicated CI jobs rather than on
every commit.

For concurrency bugs in GPU code, sanitizers do not help
directly because the GPU backend's code is not instrumented.
The defense is determinism stress testing and cross-backend
diffing, which catch the observable consequences of races
even without detecting the races themselves.

## Summary

Concurrency testing in vyre uses determinism stress tests,
cross-backend tests, exhaustive interleaving for small cases,
and sanitizers for host-side code. The assertions are about
invariants (same Program → same output) rather than specific
values, because specific values depend on scheduling. Atomic,
barrier, and workgroup memory tests instantiate the V-rule
and archetype catalogs for the concurrent cases. The hardest
class of bugs requires the most careful test design.

Next: [Floating-point](floating-point.md).
