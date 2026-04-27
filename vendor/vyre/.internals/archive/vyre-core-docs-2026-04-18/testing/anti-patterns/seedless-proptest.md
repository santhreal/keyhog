# The seedless proptest

## The shape

A seedless proptest is one that uses `proptest!` without fixing
the random seed and without committing the regression corpus.
On the surface it looks like a normal proptest; it passes most
of the time, it occasionally fails with a random input, and
each run uses a different set of inputs.

```rust
proptest! {
    #[test]
    fn wire_format_roundtrip_is_identity(program in arb_program()) {
        let bytes = Program::to_wire(&program);
        let decoded = Program::from_wire(&bytes).unwrap();
        prop_assert_eq!(program, decoded);
    }
}
```

No `ProptestConfig`. No explicit seed. No regression corpus
committed. The test uses proptest's defaults, which include a
new random seed on every run.

## Why it fails

The seedless proptest has three problems that are individually
small and collectively fatal.

**Failures are not reproducible.** When the test fails in CI,
proptest reports the failing input and a seed. The seed is
shrunk from the original random seed, so rerunning the test
locally with the same code produces a different seed and
potentially a different failing input. The maintainer cannot
reproduce the failure reliably, which makes debugging
impossible.

The reason is that proptest's default seeding uses a time-based
source. Every run generates a new seed. Even if the test fails
on a specific input this time, running it again tries different
inputs, and the original failure may not reappear.

**The regression corpus is not committed.** Proptest writes
failing cases to `proptest-regressions/<test_name>.txt`,
which is meant to be committed. The intent is that the next
run of the test first replays the failing cases from the
regression file before trying new ones. Without committing the
file, the regression replay is disabled, and each run starts
from scratch.

A seedless proptest without a committed regression corpus does
not accumulate learning. Every failure is forgotten after the
run ends. The test gets weaker over time relative to a
regression-replaying proptest, which gets stronger.

**CI flakes.** A proptest with random seeds can pass on one
run and fail on another for the same code. If the test
occasionally fails on pathological inputs that the seed happens
to generate, CI becomes flaky. Flakes are the most corrosive
failure mode of a test suite (see
[Flakiness](../discipline/flakiness.md)) because they teach
engineers to ignore failures, which eventually teaches them to
ignore real bugs. A seedless proptest is a flake waiting to
happen.

## How it happens

Seedless proptests are almost always written by contributors
who are familiar with proptest from elsewhere, where seedless
usage was acceptable. The proptest macro is easy to use; the
temptation is to just write the block and move on without
thinking about seed management.

Another source is language models that see the `proptest!`
macro in examples and reproduce the shape without the
surrounding configuration. The fix is the same in both cases:
make seed management explicit.

## How to recognize it

Signs of a seedless proptest:

- **The proptest block has no `#![proptest_config]` attribute.**
  Defaults are used, which means time-based seeding.
- **No `proptest-regressions/` directory is committed** in the
  crate.
- **CI has reported intermittent failures** for the test. Not
  deterministic; reproduces sometimes.
- **The failure message says "after N passing tests" followed
  by a case number that changes between runs.**

## How to fix it

Two changes. First, fix the seed explicitly in the proptest
config. Second, commit the regression corpus so that future
runs replay previous failures.

```rust
use proptest::prelude::*;
use proptest::test_runner::Config;

proptest! {
    #![proptest_config(Config {
        cases: 10_000,
        max_shrink_iters: 10_000,
        failure_persistence: Some(Box::new(
            proptest::test_runner::FileFailurePersistence::WithSource("regressions")
        )),
        ..Config::default()
    })]

    /// IR wire format round-trip is identity for every valid Program.
    /// Oracle: I4 (IR wire format round-trip identity).
    #[test]
    fn wire_format_roundtrip_is_identity(program in arb_program()) {
        let bytes = Program::to_wire(&program);
        let decoded = Program::from_wire(&bytes).unwrap();
        prop_assert_eq!(program, decoded);
    }
}
```

The `failure_persistence` setting tells proptest to write
failing cases to a file next to the test source. When the test
fails, proptest creates or updates a file named
`<test_name>.txt` in a `regressions` subdirectory. The
contributor commits the file. Future runs replay the failing
cases first, so the bug is caught immediately regardless of
seed, and the fix is verified against the original failing
input.

For the case count and shrink iterations, the values shown are
reasonable defaults. Per-commit CI uses 1,000 or 10,000 cases;
release CI uses 100,000; nightly uses 1,000,000. The specific
numbers depend on the test — slow tests use smaller counts,
fast tests use larger counts — but the count is always
explicit, never default.

For seed reproducibility, proptest supports setting a seed via
the `PROPTEST_SEED` environment variable or via
`Config::rng_seed`. The seed is not usually set in the
`ProptestConfig` because it would force every run to use the
same inputs, which defeats the purpose of random generation.
Instead, the seed is logged on failure so the maintainer can
reproduce the exact failing sequence by setting the environment
variable.

## The regression corpus in practice

Every proptest in vyre has a committed regression file at
`proptest-regressions/<test_name>.txt`. The file contains
seeds for past failing inputs. Proptest reads the file at the
start of each run and replays the seeds before generating new
cases. A test that fails on a new random input gets the input
added to the regression file; the next run (and every
subsequent run) replays that input.

Committing the regression file is non-negotiable. A PR that
adds a proptest without committing the corresponding regression
file is rejected. A PR that fails a proptest in CI must commit
the updated regression file along with the fix.

## The seedless proptest in adversarial categories

There is one case where a proptest may appear to be seedless:
when it is specifically exercising a claim of the form "for
any input, the code does not panic," and the test has no
preference about which inputs it generates. Even in this case,
the seed should be fixed (for reproducibility) and the
regression corpus committed (for replay).

The adversarial category uses property tests for some
subcategories (particularly `fuzz_corpus.rs`), and those tests
follow the same seed discipline as any other property test.
The "adversarial" label does not exempt a test from the seed
discipline.

## Summary

Seedless proptests produce non-reproducible failures, lose
their regression corpus, and create CI flakes. Fix by setting
explicit `ProptestConfig` with `failure_persistence` and by
committing the regression corpus. Every proptest in vyre
follows this discipline without exception.

Next: [Test smells](test-smells.md) — the subtler warning signs
that appear before a test becomes an outright anti-pattern.
