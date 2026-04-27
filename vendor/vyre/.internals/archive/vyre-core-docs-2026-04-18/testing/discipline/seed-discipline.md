# Seed discipline

## Reproducibility is not optional

A test suite that cannot reproduce its own failures is a test
suite that cannot be trusted. When CI reports a failure, the
maintainer must be able to rerun the exact same test with the
exact same inputs and observe the same result. If they cannot,
the failure becomes folklore: "it failed once, but we can't
reproduce it, so we merged anyway." Folklore failures are how
bugs reach production.

vyre's seed discipline is the set of rules that ensure every
failure is reproducible. The rules apply specifically to
property tests (proptest) but extend to anywhere vyre uses
randomness in testing: fuzz targets, generator-based tests,
and any helper that generates inputs.

## The rules

### Rule 1 — Every proptest has an explicit seed policy

A proptest block includes a `ProptestConfig` with explicit
settings for case count, shrink iterations, and failure
persistence. No proptest uses the defaults. Defaults are
time-based and produce different inputs on every run.

```rust
use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

proptest! {
    #![proptest_config(Config {
        cases: 10_000,
        max_shrink_iters: 10_000,
        failure_persistence: Some(Box::new(
            FileFailurePersistence::WithSource("regressions")
        )),
        ..Config::default()
    })]

    #[test]
    fn my_property(input in arb_input()) {
        // ...
    }
}
```

The case count, the shrink iterations, and the failure
persistence path are all explicit.

### Rule 2 — Failing cases are committed to the regression corpus

When a proptest fails, proptest writes the failing seed to a
file at `proptest-regressions/<module_path>.txt`. This file is
the regression corpus. It must be committed to git.

```
proptest-regressions/
├── tests/
│   └── property/
│       ├── wire_format_roundtrip.rs.txt
│       ├── determinism.rs.txt
│       └── validation_soundness.rs.txt
```

The format of each file is proptest's own format: one failing
case per line, with the seed and the shrunk input. Subsequent
runs of the proptest first replay every entry in the regression
file before generating new inputs. A previously-failing case
always runs first, which means if the test was ever broken,
the broken case runs every time until the fix is verified.

### Rule 3 — Failing PRs commit the updated regression corpus

When a proptest fails on a PR, the contributor commits two
things together: the fix for the bug, and the updated
regression file containing the failing case. Both must be in
the same commit (or at least the same PR).

Committing the fix without the regression file is a violation:
the suite has no permanent record of the failure, and a
regression would go unnoticed. Committing the regression file
without the fix is pointless: the test still fails. Both
changes are required.

### Rule 4 — The regression corpus is never edited by hand

Proptest manages the corpus file. Humans do not edit it
manually except to delete entries for bugs that have been
proven to be unreachable (a rare case requiring an explicit
justification in the deletion commit). Normal corpus growth
is exclusively through proptest's failure-persistence
mechanism.

Hand-editing the regression corpus is how subtle bugs get
introduced: a contributor removes a line they think is
obsolete, the corresponding bug returns six months later, and
the suite has no record because the corpus was edited.

### Rule 5 — CI can reproduce any past failure

The regression corpus enables CI to reproduce past failures on
demand. When someone asks "does bug X still exist?", the
answer is to set the `PROPTEST_SEED` environment variable to
the seed from the bug's corpus entry and rerun. The seed
deterministically produces the original failing input.

```bash
PROPTEST_SEED=0xDEADBEEF cargo test -p vyre property::wire_format_roundtrip
```

The seed makes the failure reproducible. The reproducibility
makes the bug debuggable.

### Rule 6 — Non-proptest randomness uses explicit seeds too

Helpers that use randomness outside of proptest (for example,
a test that draws random inputs via `rand`) must also use
explicit seeds. The seed is typically hardcoded in the test:

```rust
#[test]
fn test_random_input_sample() {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
    for _ in 0..10_000 {
        let input = rng.gen::<u32>();
        // ... test with input
    }
}
```

The seed `0xDEADBEEF` is committed. Every run uses the same
seed, produces the same inputs, and any failure is reproducible.

If the test needs different seeds on different runs (rare in
vyre's suite), the seed comes from a source the test reports
in its failure message:

```rust
let seed = std::env::var("TEST_SEED")
    .map(|s| s.parse().unwrap())
    .unwrap_or(0xDEADBEEFu64);
eprintln!("test seed: {}", seed);
let mut rng = StdRng::seed_from_u64(seed);
// ...
```

If the test fails, the seed is in the test output, and a rerun
with the same seed reproduces the failure. This pattern is
less common than the fixed-seed pattern but is sometimes
necessary.

## Why the discipline matters

### The flake trap

A proptest without the seed discipline becomes flaky. Every
run generates different inputs. Most runs pass; a small
fraction fail on inputs that triggered a bug. The CI logs
show intermittent failures that do not reproduce when rerun.

Engineers learn to ignore intermittent failures ("just re-run
CI"). The learned ignorance extends to non-intermittent
failures eventually, and the suite becomes decorative. A
seedless proptest is the entry point for this degradation.

### The regression amnesia trap

A proptest that does not commit its regression corpus forgets
every failing case after the run. A bug is caught, fixed, and
committed, and the bug-triggering input is lost. When the fix
is regressed (by a later PR, a refactor, or a merge), nothing
tells the suite to check the historical case, and the
regression is undetected until a new random run happens to
regenerate similar input.

Committing the regression corpus prevents this. Every past bug
is a permanent regression test, replayed at the start of every
run.

### The unreproducible bug trap

A bug reported in production with a specific input is a
reproducible bug only if the suite can reproduce the input.
If the input is a large random Program, and the test that
would have caught it uses seedless generation, the maintainer
cannot reproduce the bug locally. Debugging becomes archaeology:
"the bug was reported; here is a similar-looking case; we
think this is the fix." Without reproducibility, the fix is a
guess.

Seed discipline makes every past failure reproducible. If the
bug was ever caught by the suite, the corpus has the input.
If the bug was found externally, the corpus grows to include
the external case. Reproducibility is the foundation of
diagnosable testing.

## Common violations

- **Using proptest defaults.** The contributor writes
  `proptest!` without a config. The defaults have time-based
  seeding. Fix: add explicit config.
- **Not committing `proptest-regressions/`.** The corpus file
  exists but is gitignored or never staged. Fix: commit the
  file.
- **Hand-editing the corpus.** The contributor removes entries
  they think are obsolete. Fix: do not touch the corpus by
  hand; let proptest manage it.
- **Using `StdRng::from_entropy()` or
  `thread_rng()`.** These produce different random streams
  each run. Fix: use `seed_from_u64()` with a fixed seed.
- **Ignoring proptest failures on local runs.** The
  contributor sees a proptest fail locally, re-runs, sees it
  pass, and commits without investigating. Fix: treat every
  proptest failure as a finding until proven otherwise.

Each violation is caught at review by item 8 of the
[checklist](review-checklist.md) and at audit by the daily
sweep.

## Seeds across CI tiers

vyre's CI runs proptests at different case counts on different
tiers, as described in [Property tests](../categories/property.md).
The seed discipline is the same across all tiers: fixed seed,
committed corpus, explicit config. The only thing that varies
is the case count, which is higher for release and nightly
runs.

A test that passes at 1,000 cases but fails at 100,000 is a
real finding, not a flake. The higher case count is exercising
inputs that the lower count did not reach. The regression
corpus captures the new failing input, and subsequent runs
across all tiers replay it.

## Summary

Seed discipline ensures every property test failure is
reproducible. Rules: explicit config, committed corpus, fix
plus corpus in the same PR, no hand-editing, explicit seeds
everywhere randomness is used. The discipline is the defense
against flakes, regression amnesia, and unreproducible bugs.

Next: [The regression rule](regression-rule.md).
