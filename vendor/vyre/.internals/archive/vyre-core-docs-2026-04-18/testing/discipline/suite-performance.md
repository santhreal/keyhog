# Suite performance

## A slow suite does not get run

Testing is a feedback loop. The loop works when engineers can
run the relevant tests quickly, observe the result, iterate on
the code, and run again. The loop breaks when "run the tests"
becomes "start the tests, go make coffee, come back in ten
minutes." Engineers who face a ten-minute test cycle run
tests less often. They push code without full testing. They
merge based on "it looked okay locally" instead of verified
passes. They lose the safety net the suite was supposed to
provide.

The performance of vyre's suite is not optional. A test suite
that takes half an hour to run is a suite that runs once per
commit at best, which means bugs introduced at 2pm are caught
at 2:30pm rather than at 2:01pm. The cost of a slow suite is
measured in delayed feedback, and delayed feedback is
measured in missed bugs.

This chapter is about keeping vyre's suite fast enough that
engineers run it voluntarily and reflexively.

## The targets

vyre's suite is organized into performance tiers:

- **Unit tests:** under 1 second total for the full set.
- **Integration tests (per-file):** under 5 seconds per file,
  under 60 seconds for the whole category.
- **Validation tests:** under 30 seconds for the whole
  category.
- **Lowering tests:** under 30 seconds for the whole category.
- **Wire format tests:** under 30 seconds for the whole category.
- **Adversarial tests:** under 60 seconds for the whole
  category.
- **Property tests (CI tier, 1k cases):** under 2 minutes for
  the whole category.
- **Backend tests:** under 2 minutes for the whole category.
- **Regression tests:** under 30 seconds for the whole
  category.

Total for `cargo test -p vyre`: under 5 minutes on a modern
development machine. Ideally under 3 minutes.

These targets are not arbitrary. They are calibrated to the
feedback loop: under 5 minutes is "I can run the suite before
pushing without losing focus." Over 5 minutes is "I'll run the
suite when I take a break." Over 15 minutes is "I'll rely on
CI."

## What makes a test slow

Slow tests usually have one of these causes:

- **GPU dispatch overhead.** Every test that dispatches a
  Program to a backend incurs setup cost. The cost amortizes
  across many dispatches in the same test, but a test that
  sets up a fresh backend, dispatches once, and tears down
  pays the full cost.
- **Compilation.** Lowering tests that invoke wgpu's shader
  parser pay a significant cost per invocation. A test that
  compiles many shaders in sequence is slow.
- **Proptest case counts.** A proptest at 10,000 cases takes
  roughly 10x as long as the same test at 1,000 cases. Higher
  case counts buy coverage at the cost of time.
- **I/O.** Tests that read files, write temp files, or make
  network calls are slow relative to in-memory tests. Even a
  small amount of I/O adds milliseconds per test, which
  multiplies across hundreds of tests.
- **Allocator churn.** Tests that allocate and free many
  small objects can be slow if the allocator has contention or
  fragmentation. Usually not a significant factor in vyre, but
  worth knowing.
- **Panic handlers and catch_unwind.** Tests that use
  `catch_unwind` pay a small cost per call, which adds up in
  adversarial categories that use it heavily.

## Making the suite faster

### Share expensive setup

A backend can be initialized once and reused across many tests
in the same test binary. vyre's `tests/support/backends.rs`
provides a lazy-static backend that initializes on first use
and is reused for the duration of the test process. Individual
tests do not incur the initialization cost on every invocation.

```rust
pub fn default_backend() -> &'static dyn Backend {
    static BACKEND: Lazy<Box<dyn Backend>> = Lazy::new(|| {
        Box::new(initialize_backend())
    });
    BACKEND.as_ref()
}
```

The `Lazy` wrapper ensures the initialization runs once and is
shared across all tests that call `default_backend`. A suite
that runs 500 tests pays the initialization cost once, not 500
times.

### Parallelize with `--test-threads`

Cargo runs tests in parallel by default, spawning a thread per
CPU. This works well for tests that are isolated. Tests that
share mutable state must use `#[serial]` to force serial
execution, but shared state is rare in vyre's suite.

For tests that are CPU-bound (lowering, validation),
parallelism scales roughly with core count. For tests that
are GPU-bound (dispatch), parallelism is limited by the
backend's capacity and may not scale much past a few threads.

### Batch dispatches

A test that dispatches multiple Programs can sometimes batch
them: build all the Programs, send them to the backend in one
call, wait for all results, assert on all results. Batching
amortizes the dispatch overhead across all the Programs.

Batching is rarely used in vyre because most tests dispatch
one Program and assert one result, which is already fast
enough. But for tests that need to stress-test many dispatches,
batching is the pattern.

### Avoid re-compiling shaders

The WGSL shader parser is slow. A test that lowers many
Programs and asserts each one compiles pays the parse cost
per shader. If the test only needs to verify that *some*
shaders compile (for example, an exhaustiveness test across
Expr variants), the test can sample rather than exhaustively
testing, and reach 95% coverage at 10% of the cost.

When exhaustiveness matters, the parse cost is the price of
correctness, and it is worth paying. When sampling is enough,
it is worth saving.

### Stream results instead of collecting

A proptest with 10,000 cases might allocate a large vector of
intermediate values if the test collects results before
asserting. Streaming — asserting on each case as it runs,
without storing — is memory-efficient and avoids the
allocation overhead. Proptest's built-in style is streaming;
tests that diverge from it by collecting should be revisited.

### Mark expensive tests `#[ignore]`

Tests that are legitimately expensive (fuzz runs, large
proptests, multi-second integration tests) are marked
`#[ignore]` so they are excluded from the default `cargo
test` invocation. CI runs them explicitly via `cargo test --
--ignored` in a dedicated job.

```rust
#[test]
#[ignore]
fn thorough_roundtrip_property() {
    // 100,000 case proptest; runs in 2 minutes.
}
```

The `#[ignore]` is not a way to hide slow tests; it is a way
to tier them. The dedicated CI job runs all `#[ignore]` tests
regularly (release CI runs them on every release candidate;
nightly CI runs them every night). The tier system keeps the
per-commit CI fast while preserving the full coverage.

### Avoid tests that wait for timeouts

A test that waits for a 5-second timeout to verify "the
function times out after 5 seconds" is slow by design. If the
timeout is important to verify, the verification can use a
shorter timeout (via a test-only config or feature flag) so
the test runs in milliseconds. Tests that wait for real
timeouts are in the wrong category — they belong in a
dedicated slow-test tier, not in the main suite.

## Measuring the suite

The xtask tooling includes a performance report:

```bash
cargo xtask test-perf
```

The report lists tests sorted by runtime. Tests at the top are
candidates for optimization. A report that shows a handful of
tests taking most of the time points at where the optimization
budget should be spent.

The report runs periodically (weekly, monthly) and is part of
the suite's health dashboard. If the total time trends up over
months, the suite is getting slower, and the trend is
addressed before it becomes painful.

## When to tolerate a slow test

Not every slow test needs to be optimized. Some tests are
legitimately expensive and deserve to be slow:

- **Property tests at high case counts.** These are slow by
  design, and the slow version is in the nightly tier where
  the cost is acceptable.
- **Fuzz tests.** Fuzz runs are expensive by construction.
  They run outside the main suite.
- **Cross-backend tests that iterate many backends.** Each
  backend has dispatch overhead; the total is proportional to
  the backend count. Tolerated because the coverage is
  valuable.
- **Benchmark tests.** Benchmarks are not tests; their
  slowness is measured, not optimized.

The rule: a slow test is tolerated when its slowness is
intrinsic to what the test verifies and when the slowness is
quarantined to a tier that does not block fast feedback.

## When to delete a slow test

Some slow tests are better deleted. Candidates:

- **Tests that duplicate faster coverage.** A slow integration
  test that exercises what a fast unit test already exercises
  is redundant.
- **Tests that were slow attempts at what property tests do
  better.** If a slow test generates many cases in a loop, it
  is a poorly-constructed proptest; rewrite as a proptest in
  the property category.
- **Tests that are slow because they measure timeouts or
  other side effects that are not vyre's concern.** These
  probably belong in a dependency's test suite, not vyre's.

Deletions require the same discipline as any other deletion:
PR with rationale, reviewer approval, no silent removal.

## Summary

A slow suite breaks the feedback loop. vyre's suite targets
under 5 minutes for the full per-commit run. Speed comes from
shared setup, parallelism, batching, sampling where
exhaustiveness is not needed, and tiering expensive tests as
`#[ignore]` for dedicated CI jobs. Slow tests are tolerated
when their slowness is intrinsic and tiered; they are deleted
when redundant.

This concludes Part VII. Part VIII covers advanced topics: the
techniques that apply in specific situations where the general
discipline is not enough.

Next: Part VIII opens with [Property-based testing for GPU
IR](../advanced/property-generators.md).
