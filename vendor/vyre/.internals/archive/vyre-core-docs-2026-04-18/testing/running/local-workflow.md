# Local workflow

## Running tests while you work

A contributor's relationship with the test suite is not
limited to "the suite runs in CI and I hope it passes." The
suite is a tool the contributor uses while writing code. Every
few minutes, the contributor makes a change, runs the
relevant tests, observes the result, and iterates. The tests
are feedback, and feedback shapes the code being written.

This chapter describes the local workflow for running vyre's
test suite effectively. The commands are simple; the
discipline of using them well is where the value lies.

## The basic command

```bash
cargo test -p vyre
```

Runs every test in the vyre crate that is not marked
`#[ignore]`. This is the default invocation and is what
`cargo test` does without any filters.

The command is fast enough to run reflexively after each
change. Under 5 minutes on a modern development machine, as
described in [Suite performance](../discipline/suite-performance.md).
Running it after every change is not wasteful; it is the
feedback loop working.

## Filtering by name

```bash
cargo test -p vyre test_add
```

Runs every test whose name contains "test_add" as a substring.
Useful when working on a specific op or a specific concern.
The filter is a substring match, so `test_add` matches
`test_add_identity_zero_zero`, `test_add_commutative`, and any
other test name containing the substring.

More specific filters:

```bash
cargo test -p vyre test_add_identity    # only tests about add's identity
cargo test -p vyre test_v001             # only V001 validation tests
cargo test -p vyre test_lowering_of     # only lowering tests
```

The filter supports any substring. When iterating on a
specific test or a specific category, filtering keeps the
test run focused and fast.

## Running a single test by exact name

```bash
cargo test -p vyre test_add_identity_zero_zero -- --exact
```

The `--exact` flag makes the filter an exact match rather
than a substring match. Useful when many tests share a
common prefix and you want exactly one.

## Running tests with the `--ignored` flag

Some tests are marked `#[ignore]` because they are slow. They
do not run by default but run when explicitly requested:

```bash
cargo test -p vyre -- --ignored
```

Runs every ignored test. Useful before submitting a PR that
touches hot-path code, to catch regressions that the default
run misses.

```bash
cargo test -p vyre test_thorough -- --ignored
```

Runs ignored tests matching the filter. Useful when you are
investigating a specific expensive test.

## Running with a specific feature

```bash
cargo test -p vyre --no-default-features --features reference-only
```

Runs tests with a specific feature configuration. Used when
testing behavior under feature flags (for example, the OOM
injection feature, which is not enabled by default).

```bash
cargo test -p vyre --features oom-injection tests/adversarial/oom
```

Combines feature flags with name filtering to run specific
tests in a specific feature configuration.

## Running with single-threaded execution

```bash
cargo test -p vyre -- --test-threads=1
```

Runs tests serially rather than in parallel. Useful when
debugging a test that might have state leakage from other
tests, or when running a test whose output would be garbled
by concurrent output.

Serial execution is slower (obviously) but more
deterministic. Flake investigations often start with
`--test-threads=1` to eliminate parallelism as a variable.

## Running property tests with higher case counts

Property tests default to 1,000 cases in per-commit CI. To
run locally with a higher count:

```bash
PROPTEST_CASES=10000 cargo test -p vyre property::wire_format_roundtrip
```

The `PROPTEST_CASES` environment variable overrides the
`ProptestConfig` default. Useful when investigating a suspected
bug that the 1,000-case run does not catch.

```bash
PROPTEST_CASES=100000 cargo test -p vyre property::wire_format_roundtrip
```

100,000 cases is the release-CI tier. Running this locally
takes a minute or two per test. Worth running before
submitting a PR that touches anything the test covers.

## Running with a specific seed

```bash
PROPTEST_SEED=0xDEADBEEF cargo test -p vyre property::wire_format_roundtrip
```

Runs the property test with a specific master seed. Useful
for reproducing a specific failing sequence from CI. Combine
with `RUST_BACKTRACE=1` to see the full stack trace on
failure.

## Running with backtrace

```bash
RUST_BACKTRACE=1 cargo test -p vyre test_something
```

Sets the backtrace environment variable so panics include
stack traces. The backtrace helps diagnose test failures that
are hidden behind cryptic assertion messages. Always useful
when investigating a failure.

```bash
RUST_BACKTRACE=full cargo test -p vyre test_something
```

The `full` setting produces the complete backtrace including
internal frames. Usually not needed; the default `1` is
sufficient.

## Running benchmarks

```bash
cargo bench -p vyre
```

Runs every benchmark using criterion. Output goes to
`target/criterion/` and the terminal. Benchmarks are not
tests; they measure performance. See [Benchmarks](../categories/benchmarks.md).

```bash
cargo bench -p vyre dispatch
```

Runs benchmarks whose names contain "dispatch". Useful when
working on dispatch performance and wanting fast feedback.

## Running fuzz targets

```bash
cargo fuzz run backend_vs_reference
```

Runs the `backend_vs_reference` fuzz target. The fuzzer runs
continuously until stopped (Ctrl-C). Useful for extended
fuzzing sessions when you are specifically looking for
cross-backend bugs.

See [Differential fuzzing](../advanced/differential-fuzzing.md)
for details.

## Running mutation tests

```bash
cargo xtask mutation-gate --op add --tests tests/integration/primitive_ops/add.rs
```

Runs the mutation gate on a specific op's tests. Useful after
writing or modifying tests to verify they kill the expected
mutations. See [Mutations](../mutations.md) for the full
treatment.

```bash
cargo xtask mutation-gate --all
```

Runs the mutation gate on the full suite. Expensive; usually
not run locally. Run in CI.

## A typical development cycle

While working on a feature or a bug fix, the cycle looks like:

1. Make a change to the code.
2. Run the filtered test set relevant to the change.
   ```
   cargo test -p vyre test_add
   ```
3. Observe the result. If green, continue. If red, investigate.
4. For ambiguous failures, run with backtrace.
   ```
   RUST_BACKTRACE=1 cargo test -p vyre test_add_specific
   ```
5. Iterate on the code until the focused tests pass.
6. Run the full suite before committing.
   ```
   cargo test -p vyre
   ```
7. Run mutation gate on the relevant tests if tests were
   touched.
   ```
   cargo xtask mutation-gate --op add --tests tests/integration/primitive_ops/add.rs
   ```
8. Commit and push.

The cycle repeats many times per day. Each iteration is a
few seconds of feedback (for filtered tests) or a few minutes
(for full suite runs). The cycle is the engine of development.

## Running tests in watch mode

For active development, a watch command rebuilds and reruns
tests on every file save:

```bash
cargo watch -x 'test -p vyre test_add'
```

Requires `cargo-watch` (install with `cargo install cargo-watch`).
The command reruns the filtered tests whenever any file in
the workspace changes. Useful for tight iteration on a
specific test.

## Summary

The local workflow is built on `cargo test -p vyre` with
filters, flags, and environment variables as needed. Run
filtered tests reflexively during development. Run the full
suite before committing. Use the mutation gate when touching
tests. Fuzz targets and benchmarks are available when needed.
The feedback loop is the engine; running it often is the
discipline.

Next: [Continuous integration](continuous-integration.md).
