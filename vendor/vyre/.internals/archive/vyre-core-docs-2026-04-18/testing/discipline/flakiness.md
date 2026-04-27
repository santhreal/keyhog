# Flakiness

## The corrosive failure mode

A flaky test is one that fails sometimes and passes sometimes
without any change to the code. Flakiness is the most
corrosive failure mode a test suite can have. A flaky suite
does not catch fewer bugs than a non-flaky one — in fact, the
flakes are often pointing at real bugs. The corrosion comes
from what flakes teach engineers to do: ignore failures.

A suite with three flakes teaches the team that "test failed"
is not necessarily "something is broken." The team learns to
re-run CI when it fails, and to merge anyway if the re-run
passes. Over time, this habit extends to non-flaky failures:
"it failed once, but I don't know why, probably flaky, let's
merge." A real bug reaches production with a green checkmark
from a re-run that happened to pass.

The corrosion is not "flakes cause bugs" — it is "flakes
train engineers to ignore the signal the suite produces." Once
the signal is ignored, the suite might as well not exist.

This chapter is about how vyre treats flakes. The short answer:
flakes are P1 findings that block merging until they are
either fixed or explicitly quarantined. The long answer is the
rest of the chapter.

## What a flake is

A flake is a test whose outcome depends on something other than
the code under test. Specifically, a flake depends on:

- **Timing** — thread scheduling, wall-clock time, CPU speed,
  GC pauses. A test that sometimes passes and sometimes fails
  because of timing is usually testing the wrong thing.
- **Ordering** — test execution order, thread interleaving,
  map iteration order. A test that depends on ordering the
  runtime does not guarantee is fragile by construction.
- **Randomness** — a proptest with a seedless configuration,
  or any test using `rand::thread_rng()`. Each run uses
  different inputs, and some inputs happen to trigger the
  failure.
- **Environment** — available memory, available disk,
  available network, current directory, environment variables.
  A test that only passes when a specific condition holds
  externally is not self-contained.
- **State leakage** — global state from previous tests, files
  on disk, databases, caches. A test that passes in isolation
  but fails when run after another test has leakage.

Each source of flakiness is a specific thing to look for when
diagnosing. The fix depends on which source is the cause.

## vyre's policy on flakes

Flakes are P1 findings. A flake in vyre's suite blocks merges
until:

- **The flake is fixed** — the root cause is identified and
  the test is made deterministic.
- **The flake is quarantined** — marked with an explicit
  attribute that excludes it from CI blocking, with a
  description of why and when the fix will happen.

"We don't know why it flakes, just re-run CI" is not a valid
response. Flakes are either fixed or explicitly marked, and
the marking has an expiration.

## Fixing a flake — the usual case

Most flakes have identifiable causes, and fixing them is
mechanical once the cause is found. The diagnosis steps:

1. **Reproduce locally.** Run the test repeatedly (`cargo test
   -- <test_name> --test-threads=1 --exact` followed by many
   iterations) until it fails. If it never fails, the
   "flakiness" might be CI-specific, in which case step 2.
2. **Inspect the test for known flake sources.** Does it use
   `sleep`? Does it rely on ordering? Does it use `thread_rng`?
   Does it touch global state? Each is a candidate.
3. **Isolate the cause.** Remove or mock the suspected source.
   If the test stops flaking, the source is confirmed. If not,
   continue investigating.
4. **Fix the source.** Make the test deterministic: fix the
   seed, remove the timing dependency, isolate the state,
   sort the iteration.
5. **Re-run many times to confirm the fix.** Run the test 100
   or 1000 times in a loop. Zero failures over the loop is
   confirmation.
6. **Commit with a note.** The commit message explains what
   was flaky and what the fix was. Future readers can learn
   from the diagnosis.

Common fixes:

- **Timing dependencies** → replace with synchronization
  primitives (mutexes, barriers, channels). Never `thread::sleep`
  in a test; it is a signal the test is racing against itself.
- **Ordering dependencies** → sort outputs before assertion.
  Use `BTreeMap` instead of `HashMap` for iteration. Sort
  error lists when checking validation output.
- **Randomness** → fix the seed. See [Seed discipline](seed-discipline.md).
- **Environment dependencies** → mock the environment. Use
  `std::env::temp_dir()` for file operations. Do not read
  `HOME` or assume a specific working directory.
- **State leakage** → ensure tests do not share mutable state.
  Use `#[serial]` if a test truly cannot run in parallel. Reset
  global state in a fixture.

Each fix is small. The debugging is the hard part; the fix is
typically a handful of lines.

## Quarantining a flake

Sometimes a flake cannot be fixed quickly. The root cause may
be in a dependency, the test may be for a subsystem that is
being rewritten, or the fix may be known but not yet
implemented. In these cases, the test is quarantined rather
than allowed to block CI.

Quarantine uses an explicit attribute:

```rust
#[test]
#[vyre_testing::quarantine(
    reason = "flake root cause in dependency foo; tracking issue #123",
    expires = "2026-06-01",
)]
fn test_that_flakes() {
    // ...
}
```

The `quarantine` attribute excludes the test from CI's blocking
set. Its failures are reported but do not fail the build.
Attributes have a `reason` (a short explanation) and an
`expires` date (when the quarantine must be reconsidered).

The `expires` date is the key part. A quarantine is not
permanent; it is a temporary escape hatch with a deadline. When
the date passes, the quarantine is either:

- **Extended** with a new expiration, if the original fix has
  not been implemented and the reason is still valid.
- **Removed** (the test is fixed and re-enabled).
- **Converted to deletion** if the test is no longer relevant.

A quarantine that expires without action is itself a finding.
The expiration check runs in CI and reports any quarantines
past their date.

Quarantines are tracked in a list somewhere (the project's
issue tracker, or a dedicated file). New quarantines are
added; expired ones are reviewed. The list is small — ideally
zero entries — and any growth in the list is a signal that
flakes are being tolerated rather than fixed.

## The cultural rule

The cultural rule for flakes is: treat them as real bugs, not
as noise. When a test fails in CI, the default assumption is
that the test is catching a real problem, and the investigation
starts from that assumption. Only after investigation confirms
the failure is not caused by a real bug does the flake label
apply.

The opposite default — "failures are probably flakes" — is the
failure mode to avoid. Engineers who start from "probably
flaky" learn to miss real bugs. Engineers who start from
"probably a real bug" catch real bugs, and occasionally waste
time debugging a flake. The latter is the right trade-off; the
time wasted debugging a flake is less than the cost of a real
bug reaching production.

The cultural rule is reinforced by the P1 designation. A
flake blocks merging in the same way a real bug does. The
discipline is that the suite's signal is trusted — and the
suite's signal can only be trusted if flakes are eliminated
rather than accommodated.

## Specific sources vyre watches for

vyre's test suite has some specific flake sources that
contributors should be alert to:

### Timing in atomic tests

Tests that verify atomic operations often race. A test that
runs multiple threads and expects specific outcomes based on
scheduling is a flake waiting to happen. The fix is to use
synchronization (barriers, channels) rather than assumptions
about scheduling.

For determinism tests specifically, which run the same Program
many times and assert identical results, the flakiness source
is usually wrong: the flake means the Program is actually
nondeterministic, which is a bug in vyre, not in the test.

### GPU initialization order

Tests that interact with the GPU backend sometimes flake on
the first test after a fresh start because the backend is
still initializing. The fix is a test fixture that ensures the
backend is ready before the first test runs. vyre's
`tests/support/backends.rs` handles this for the suite, but
contributors adding new backend tests may need to ensure the
pattern is followed.

### Proptest with stale regression corpora

A proptest whose regression corpus has aged out — the corpus
file is stale, the seeds no longer apply, the test fails on
old seeds that no longer reproduce — is a form of flake. The
fix is to regenerate the corpus or update the test to match
the current behavior. See [Seed discipline](seed-discipline.md).

### Working-directory assumptions

Tests that read files assume a working directory. If the
working directory is different in CI than locally, the test
fails differently. The fix is to use `env!("CARGO_MANIFEST_DIR")`
to compute file paths relative to the crate root, not to the
current directory.

### Global allocator state

Tests with OOM injection use a feature-gated allocator. If the
allocator's state leaks between tests, a later test might
experience injected failures from an earlier test's setup.
The fix is to reset the allocator's state in a fixture at
test boundaries.

## Summary

Flakes are P1 findings that block merging until fixed or
quarantined with an expiration. The cultural rule is to treat
failures as real bugs by default. Common sources include
timing, ordering, randomness, environment, and state leakage.
Fixes are mechanical once the source is identified.
Quarantines are temporary, tracked, and expire. Never merge
past a flake with "re-run CI."

Next: [Suite performance](suite-performance.md).
