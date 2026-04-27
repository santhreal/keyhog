# Benchmarks

## Benchmarks are not correctness tests

Before anything else: benchmarks do not verify correctness.
Benchmarks measure performance. A benchmark that passes does not
mean the code is right; it means the code is fast enough. A
benchmark that fails does not mean the code is broken; it means
the code got slower than a declared baseline. Correctness and
performance are distinct concerns, and this chapter is only about
performance. For correctness, see every other category in Part
III.

The reason this clarification matters is that benchmarks often
drift into becoming correctness tests by accident. A contributor
writes a benchmark that happens to produce a specific output,
hard-codes the expected output to make the benchmark
reproducible, and suddenly the benchmark is a correctness test
wearing performance clothing. vyre rejects this drift. Benchmarks
assert on performance; correctness tests assert on outputs. Each
test category has one job.

## What benchmarks are for

vyre cares about performance because vyre's users care about
performance. A GPU compute framework that produces correct
results slowly is a framework that will be replaced by a faster
one. Performance is not a nice-to-have for vyre; it is part of
the product. Benchmarks exist to ensure performance does not
degrade accidentally as the code evolves.

Specifically, benchmarks answer the question: "did this commit
make vyre slower than before?" If the answer is yes, the commit
has introduced a performance regression, and the regression is
either justified (with an explicit acknowledgment) or it is a
bug that must be fixed before the commit can land.

## The structure

```
tests/benchmarks/
├── construction.rs   Program building
├── validation.rs     validate() runtime
├── lowering.rs       lower::wgsl runtime
├── dispatch.rs       End-to-end dispatch
├── wire_format.rs   encode/decode runtime
└── workloads/
    ├── crypto.rs         Representative cryptographic workload
    ├── ml_inference.rs   Representative ML inference workload
    └── scientific.rs     Representative scientific computing workload
```

The top-level files benchmark individual pipeline stages. The
`workloads/` subdirectory benchmarks end-to-end workloads that
represent actual use cases. A user running vyre for a
cryptographic operation cares about `workloads/crypto.rs`'s
baseline, not the individual pipeline stage times.

Each file contains one or more `criterion::Benchmark` functions
registered with `criterion_group!` and `criterion_main!`. The
criterion crate is the industry standard for Rust benchmarking
and is used throughout vyre.

## A benchmark, in full

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use vyre::ir::{Program, BinOp};
use crate::support::programs::build_single_binop;
use crate::support::backends::run_on_default_backend;

fn bench_dispatch_single_add(c: &mut Criterion) {
    let program = build_single_binop(BinOp::Add, 1u32, 2u32);

    c.bench_function("dispatch_single_add", |b| {
        b.iter(|| {
            let result = run_on_default_backend(black_box(&program))
                .expect("dispatch");
            black_box(result)
        });
    });
}

criterion_group!(benches, bench_dispatch_single_add);
criterion_main!(benches);
```

The benchmark function takes a `&mut Criterion`, declares a
named benchmark (`"dispatch_single_add"`), and iterates the code
to be measured. `black_box` is used to prevent the compiler from
optimizing away the dispatch call — without it, the compiler
might notice the result is unused and skip the dispatch
entirely, producing a meaningless zero-time benchmark.

The benchmark is named uniquely across the suite. The name
appears in criterion's output and in the baseline files.
Changing the name breaks baseline comparison — criterion cannot
diff against a baseline for a benchmark it does not recognize.

## Baselines

Criterion saves benchmark results to `target/criterion/<benchmark>/baseline/`
after each run. A "baseline" is a recorded measurement that
subsequent runs compare against. vyre's CI saves baselines on
the main branch; PR builds compare their measurements against
the saved baselines.

The comparison produces a delta: "dispatch_single_add is 3%
slower than baseline." A delta within some threshold (typically
±5%) is noise and is ignored. A delta beyond the threshold is a
regression candidate and triggers review.

The threshold is configurable per benchmark. For benchmarks
that are intrinsically noisy (short-running functions dominated
by cache effects), the threshold is larger. For benchmarks that
are stable (long-running functions with predictable behavior),
the threshold is tighter. vyre's benchmarks use a 10% default
threshold and tighter values where appropriate.

## The regression policy

CI fails on any benchmark that regresses by more than the
configured threshold without an override label on the PR. The
policy is:

- **Regressions under the threshold**: noise, ignored.
- **Regressions over the threshold without override**: CI fails.
  The contributor must either improve the code to eliminate the
  regression or add an override label explaining why the
  regression is acceptable.
- **Regressions over the threshold with override**: CI passes.
  The override label records that the regression was
  intentional and reviewed. The baseline is updated after the
  PR merges.
- **Improvements over the threshold**: CI passes with a note.
  Improvements do not require justification, but the baseline
  is updated after the PR merges so future comparisons see the
  new faster baseline.

The override label mechanism is important because sometimes
performance regresses for the right reason. Adding a bounds
check slows down the code but fixes a security bug. Adding
strict IEEE 754 compliance slows down floating-point operations
but preserves determinism. These are worth paying for, and the
override label lets the regression land explicitly rather than
being silently rejected.

Override labels must be specific: the PR description explains
which benchmarks regressed, by how much, and why. A generic "perf
override" label with no explanation is rejected.

## What to benchmark

Benchmarks should cover the code paths that matter for users. A
benchmark for an internal helper that is called once per
dispatch and runs in nanoseconds is not valuable — the overall
dispatch is what the user experiences, and the helper's time is
dominated by the rest of the pipeline.

The criteria:

- **User-visible operations.** Dispatching a Program, encoding
  to wire format, validating a Program — these are operations the
  user directly invokes. Benchmarks here matter.
- **Hot paths in internal code.** If an internal function is
  called many times per operation and is known to be on the
  critical path, benchmark it. The rest of the suite will
  reveal whether changes to that function affect overall
  performance, but a direct benchmark is more sensitive.
- **End-to-end workloads.** Representative user workloads (a
  cryptographic operation, an ML inference pass, a scientific
  kernel) are benchmarked so the suite catches regressions that
  only appear in real use cases.
- **Regression-prone areas.** Code that has had performance
  bugs in the past is a candidate for dedicated benchmarks
  even if it is not strictly user-visible.

Not everything needs a benchmark. Over-benchmarking slows CI
(criterion runs are expensive) and produces noise that buries
real regressions. The rule of thumb: benchmark what the user
cares about, plus what the suite has caught regressions in
before, plus specific hot paths known to be critical.

## Criterion discipline

Using criterion correctly requires discipline:

- **`black_box` inputs and outputs.** Without it, the compiler
  optimizes away the work and produces zero-time measurements.
- **Set up the inputs outside the iteration loop.** Time spent
  building inputs is not the time under measurement; moving it
  outside the loop isolates the measurement to the actual work.
- **Use `bench_function`, not `bench`.** The older `bench` API
  is deprecated and produces different output.
- **Group related benchmarks with `criterion_group!`.** Grouping
  lets criterion report related benchmarks together and makes
  baseline comparison clearer.
- **Use `sample_size` to control variance.** The default sample
  size is 100; benchmarks with high variance need more samples
  for stable results.
- **Do not mix benchmarks with correctness assertions.** A
  benchmark that calls `assert_eq!` inside the loop is no
  longer a benchmark — it is a slow correctness test.

See criterion's own documentation for the full API. This chapter
covers the vyre-specific rules, not criterion's general
interface.

## Running benchmarks locally

```bash
cargo bench --bench dispatch
```

Runs just the `dispatch` benchmark file. Output is printed to
terminal and saved to `target/criterion/`. The criterion output
includes the current time, the baseline time (if a baseline
exists), and the delta.

For a comparison against a specific baseline:

```bash
cargo bench --bench dispatch -- --baseline main
```

Compares against the `main` baseline, which CI maintains.

For a full run of all benchmarks:

```bash
cargo bench
```

Expensive but comprehensive. Run before submitting a PR that
touches hot-path code to catch regressions early.

## Benchmarks in CI

CI runs benchmarks on every main-branch commit and saves a new
baseline. PR builds run the same benchmarks and compare against
the saved baseline. The comparison is reported on the PR and
blocks merging if a regression exceeds the threshold without an
override.

Benchmark runs are expensive, so CI uses a dedicated runner that
is not shared with correctness tests. The runner has a stable
CPU, disabled frequency scaling, and enough memory to avoid
paging. Without this, benchmark variance is too high to catch
small regressions.

See [Continuous integration](../running/continuous-integration.md)
for the CI runner configuration.

## When a benchmark is wrong

Benchmarks can be wrong. A benchmark might measure the wrong
thing, might have a loop that does not actually exercise the
code path, might have `black_box` in the wrong place. When a
benchmark produces suspicious results — either always-zero or
inexplicably fast — the benchmark itself is suspect, not the
code.

The fix for a wrong benchmark is to rewrite it and reset the
baseline. This is not a regression; it is a benchmark correction.
The PR description should explain the correction and cite the
evidence that the old benchmark was measuring something
unrelated.

A benchmark that is always wrong (no correction available) is
deleted. The category is not a museum; a benchmark that does not
do its job is not worth the CI cost.

## Summary

Benchmarks measure performance, not correctness. Criterion is
the library. Baselines are maintained by CI. Regressions over
threshold block merges without explicit override. Discipline in
writing benchmarks — `black_box`, no assertions, stable runners
— is what makes the measurements meaningful. This category is
how vyre stays fast as it grows.

Next: [Support utilities](support.md).
