# bench.md — criterion benchmarking

## What goes here

Tests that **measure** — latency, throughput, allocation counts,
GPU wall time — with statistical rigor. Benches are not tests in the
pass/fail sense; they are inputs to the regression-budget gate.

## Checklist — every bench suite covers

### Coverage

- [ ] Every public hot-path function has a criterion bench
- [ ] Every combinator / pass / transform has a bench over
  representative sizes (small / medium / large)
- [ ] Every async primitive has a bench + an overlap metric
- [ ] Every cache tier has a hit-rate bench and a miss-rate bench
- [ ] Every allocator / pool has an allocation-count bench via
  `stats_alloc`

### Baselines + budgets

- [ ] Every bench saves a baseline via `criterion --save-baseline
  <name>` after a green run
- [ ] `<crate>/benches/budgets.toml` declares a maximum-allowed
  regression per bench (e.g. "no worse than +5%")
- [ ] CI compares against the baseline and fails on any bench that
  exceeds its budget
- [ ] The budget file is in the repo so every reviewer sees when
  someone relaxes a budget (LAW 9 — weakening a budget to make CI
  green is evasion)

### Statistical rigor

- [ ] Warm-up ≥ 3 seconds (criterion default is 3, do not shrink)
- [ ] Measurement time ≥ 5 seconds for hot paths; longer for micro
  benches where nanosecond variance swamps the signal
- [ ] Outlier classification on
- [ ] Bench results committed to `benches/RESULTS.md` with the
  machine spec + commit hash so external readers can reproduce
- [ ] No "run once, print" micro benchmarks via `Instant::now` —
  that's not a benchmark, it's a vibe check

### What to measure

- [ ] Wall-clock time per call / per iteration
- [ ] Throughput (MB/s, ops/s, dispatches/s) where the unit makes
  sense
- [ ] Allocation count and bytes — use `stats_alloc` + a custom
  allocator so every bench reports both
- [ ] Cache hit rate when the function touches a cache
- [ ] 50th / 99th / 99.9th percentile latency for anything on a
  request path

## Template

```rust
//! Criterion benches for `<crate>`.
//!
//! See `../../.internals/skills/testing/bench.md` for the category contract.
//!
//! Run: `cargo bench -p <crate>`
//! Save baseline: `cargo bench -p <crate> -- --save-baseline v0.6`
//! Compare: `cargo bench -p <crate> -- --baseline v0.6`

use criterion::{criterion_group, criterion_main, Criterion};
use <crate>::*;

fn bench_dispatch(c: &mut Criterion) {
    let program = sample_program();
    let backend = WgpuBackend::acquire().unwrap();
    let inputs = sample_inputs(&program);

    c.bench_function("dispatch_small_program", |b| {
        b.iter(|| {
            backend
                .dispatch(&program, &inputs, &DispatchConfig::default())
                .unwrap()
        });
    });

    // Throughput version for larger inputs.
    let mut group = c.benchmark_group("dispatch_throughput");
    for size in [1 << 10, 1 << 16, 1 << 20] {
        let inputs = inputs_of_size(size);
        group.throughput(criterion::Throughput::Bytes(size as u64));
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(size),
            &inputs,
            |b, inputs| {
                b.iter(|| {
                    backend
                        .dispatch(&program, inputs, &DispatchConfig::default())
                        .unwrap()
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_dispatch);
criterion_main!(benches);
```

## Budget file

```toml
# <crate>/benches/budgets.toml
#
# Every criterion bench has a regression budget. CI compares
# against the v0.6 baseline and fails any bench that exceeds its
# budget. Tightening a budget is always OK; loosening one requires
# an explicit PR with a justification (LAW 9 — evasion prevention).

[dispatch_small_program]
max_regression = "5%"
baseline = "v0.6"

[dispatch_throughput]
max_regression = "5%"
baseline = "v0.6"

[cse_intern]
max_regression = "3%"   # micro-bench, tighter tolerance
baseline = "v0.6"
```

## Anti-patterns

- **Benchmarking with `--release=off`.** Debug builds are 10-100×
  slower and give worthless signal.
- **Comparing benches across machines without a note.** Bench
  numbers are machine-specific; every `RESULTS.md` entry names the
  machine.
- **"Improved" after a refactor with no baseline to compare against.**
  Always: save baseline → refactor → compare against baseline.
- **Benches that allocate every iteration.** A hot-path bench that
  builds a fresh program inside the `iter()` closure measures
  allocation, not dispatch. Construct once, clone (or `iter_ref`)
  inside the closure.
- **Criterion defaults on a hot loop.** Some workloads need more
  than 5 seconds to stabilize; override `measurement_time` when
  variance is high.

## Reproducibility

Every bench recipe in `benches/RESULTS.md` names:

- Commit hash
- Machine (CPU, GPU, RAM)
- Wgpu backend flavor (Vulkan / DX12 / Metal)
- Rustc version
- Flags used (`cargo bench` defaults unless overridden)

Without these a "3.7 ns per dispatch" number is a lie.
