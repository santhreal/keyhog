# Appendix E — Command reference

Every command relevant to running vyre's test suite, with
its purpose, its flags, and when to use it.

---

## cargo test

The basic test runner.

```bash
cargo test -p vyre
```

Runs every non-ignored test in the vyre crate. The default
invocation.

```bash
cargo test -p vyre <substring>
```

Runs tests whose names contain `<substring>`. Filters by
substring, not exact match.

```bash
cargo test -p vyre <exact_name> -- --exact
```

Runs only the test with exactly that name.

```bash
cargo test -p vyre -- --ignored
```

Runs ignored tests (marked `#[ignore]`, typically slow or
extended-run).

```bash
cargo test -p vyre -- --test-threads=1
```

Runs tests serially, for debugging parallelism issues.

```bash
cargo test -p vyre -- --nocapture
```

Shows `println!` and `eprintln!` output from passing tests
(by default, only failing tests' output is shown).

```bash
RUST_BACKTRACE=1 cargo test -p vyre <test_name>
```

Includes stack traces on panic. Set `RUST_BACKTRACE=full`
for even more detail.

---

## cargo bench

Runs criterion benchmarks.

```bash
cargo bench -p vyre
```

Runs every benchmark. Saves results to `target/criterion/`.

```bash
cargo bench -p vyre <substring>
```

Runs benchmarks matching the substring.

```bash
cargo bench -p vyre -- --baseline main
```

Compares results against the baseline saved under the name
"main."

```bash
cargo bench -p vyre -- --save-baseline my_baseline
```

Saves the current results as a named baseline for later
comparison.

---

## cargo fuzz

Runs fuzz targets.

```bash
cargo fuzz list
```

Lists the available fuzz targets.

```bash
cargo fuzz run <target>
```

Runs the fuzz target continuously until stopped.

```bash
cargo fuzz run <target> -- -runs=1000000
```

Runs the fuzz target for a fixed number of runs (one
million here), then stops.

```bash
cargo fuzz tmin <target> <crash_file>
```

Minimizes a crashing input to its smallest form.

```bash
cargo fuzz cmin <target>
```

Minimizes the corpus by removing redundant entries.

---

## cargo xtask

Custom workflow commands defined in the `xtask` crate.

```bash
cargo xtask --help
```

Lists available commands.

```bash
cargo xtask generate-tests [--op <op> | --all]
```

Generates tests from the vyre-conform specification.
Without arguments, generates all. With `--op`, generates
for a specific op.

```bash
cargo xtask mutation-gate [--op <op>] [--tests <path>]
```

Runs the mutation gate on the specified tests. Without
arguments, runs on the full suite (slow). With `--op`,
scoped to one op's tests.

```bash
cargo xtask coverage-check
```

Runs the coverage meta-tests: variant coverage, validation
rule coverage, mutation catalog coverage.

```bash
cargo xtask conform-verify
```

Runs the full vyre-conform pipeline: generate tests,
mutation-gate, coverage check, cargo test. Used as a
pre-commit smoke test.

```bash
cargo xtask compare-coverage --op <op>
```

Compares hand-written and generated test coverage for the
op. Used to determine migration readiness.

```bash
cargo xtask audit-tests
```

Selects ten random tests for the daily audit. Prints file
paths and test names.

```bash
cargo xtask quick-check --op <op>
```

Runs the minimal verification path for one op in under 10
seconds. Used for fast iteration.

```bash
cargo xtask test-perf
```

Reports test performance, sorted by runtime. Identifies
slow tests for optimization.

---

## cargo check and cargo clippy

```bash
cargo check --workspace
```

Fast compilation check without generating binaries.

```bash
cargo clippy --workspace
```

Runs the lint.

```bash
cargo clippy --workspace -- -D warnings
```

Treats all warnings as errors. Used in CI.

---

## cargo-mutants

External tool for running mutation tests directly (used by
the mutation gate internally).

```bash
cargo mutants --package vyre
```

Runs mutations across the vyre crate. Slow; usually invoked
via `cargo xtask mutation-gate` instead.

```bash
cargo mutants --package vyre --file src/ops/primitive/add.rs
```

Runs mutations on a specific file.

```bash
cargo mutants --package vyre --check
```

Checks what mutations would be applied without running
them. Useful for inspecting the catalog.

---

## Environment variables

Variables that affect test runs.

### PROPTEST_CASES

Overrides the proptest case count:

```bash
PROPTEST_CASES=100000 cargo test -p vyre property::wire_format_roundtrip
```

### PROPTEST_SEED

Fixes the proptest master seed for reproducibility:

```bash
PROPTEST_SEED=0xDEADBEEF cargo test -p vyre property::determinism
```

### RUST_BACKTRACE

Enables stack traces on panic:

```bash
RUST_BACKTRACE=1 cargo test -p vyre
```

### RUST_LOG

Enables logging at a specific level:

```bash
RUST_LOG=debug cargo test -p vyre
```

### CARGO_TARGET_DIR

Overrides the target directory, useful for mutation testing
to avoid contention:

```bash
CARGO_TARGET_DIR=target/mutation cargo test -p vyre
```

### PROPTEST_MAX_SHRINK_ITERS

Overrides the maximum number of shrink iterations:

```bash
PROPTEST_MAX_SHRINK_ITERS=100000 cargo test -p vyre
```

---

## Typical command sequences

### Fast development iteration

```bash
cargo test -p vyre test_add
```

Run the tests you are working on. Iterate until green.

### Pre-commit check

```bash
cargo check --workspace && \
cargo clippy --workspace && \
cargo test -p vyre && \
cargo xtask mutation-gate --op <op_you_changed>
```

Full fast check before committing.

### Pre-PR check

```bash
cargo test -p vyre -- --ignored && \
cargo xtask conform-verify
```

Runs the slower tests and the full conform pipeline.

### Debugging a specific failing test

```bash
RUST_BACKTRACE=1 cargo test -p vyre <test_name> -- --exact --nocapture
```

Full output, stack trace on panic, exact name match.

### Investigating a flake

```bash
for i in {1..100}; do
    cargo test -p vyre <test_name> -- --test-threads=1 2>&1 | tail -1
done
```

Runs 100 times serially to observe failure frequency.

### Running nightly-tier tests

```bash
PROPTEST_CASES=1000000 cargo test -p vyre -- --ignored
cargo fuzz run backend_vs_reference -- -runs=10000000
```

What nightly CI runs. Run locally only when specifically
investigating the nightly scope.
