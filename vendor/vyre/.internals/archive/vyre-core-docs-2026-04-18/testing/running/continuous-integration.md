# Continuous integration

## What CI is for

Local testing is the contributor's inner loop. CI is the
outer loop: the layer of verification that runs on every
commit regardless of what the contributor ran locally. CI
catches things the contributor forgot, things the contributor
could not run locally (GPU-specific tests, cross-backend
tests, longer fuzzing sessions), and things that only appear
on a clean machine without the contributor's local state.

CI is not a substitute for local testing. A contributor who
"let CI find the bugs" wastes everyone's time: the CI takes
longer to diagnose than a local run, and the contributor
does not learn the mistakes they are making. CI is a safety
net, not a first line of defense.

This chapter describes vyre's CI layout: what runs on every
commit, what runs on pull requests, what runs on releases,
what runs nightly. The layout is tiered because different
checks have different costs and different urgency.

## The tiers

vyre's CI has three main tiers plus a handful of specialized
jobs.

### Tier 1 — Per-commit (fast)

Runs on every commit, both on pull request branches and on the
main branch. Target: under 10 minutes total.

Contents:
- `cargo check --workspace` — fast compilation check.
- `cargo clippy --workspace` — lint.
- `cargo fmt --check` — format.
- `cargo test -p vyre` — the full default test suite.
- `cargo test -p vyre-conform` — vyre-conform tests.
- `cargo xtask coverage-check` — variant coverage meta-tests.
- `cargo xtask mutation-gate --changed-only` — mutation gate
  on the diff's changed files only.
- Documentation build: `cargo doc --workspace --no-deps`.

Any failure here blocks the PR from merging. The tier is
expected to pass for every commit that goes into main.

### Tier 2 — Per-PR release checks (thorough)

Runs on every pull request, separately from Tier 1. Target:
under 30 minutes total. Uses a beefier runner with more
parallelism.

Contents:
- `cargo test -p vyre -- --ignored` — the ignored tests
  that are slow.
- Property tests at 100,000 cases.
- Cross-backend tests on every registered backend (not just
  the default).
- Benchmark regression check against the main branch baseline.
- Sanitizer runs (ThreadSanitizer, AddressSanitizer) on a
  subset of the suite.

Failures here block the PR, but the PR author can request a
temporary override for benchmark regressions with explicit
justification. Other failures are blocking with no override.

### Tier 3 — Nightly (expensive)

Runs every night on the main branch. Target: under 6 hours
total. Uses dedicated long-running runners.

Contents:
- Property tests at 1,000,000 cases.
- Fuzz targets for 1 hour each.
- Full mutation gate (not incremental).
- Cross-version compatibility tests against historical vyre
  versions.
- Driver version sweep across multiple supported driver
  versions.

Failures here are P1 findings but do not block commits that
happened during the day. The nightly run is for catching
deep bugs that the faster tiers miss, not for gating each
commit.

## The specialized jobs

Beyond the three tiers, vyre has several specialized CI jobs
that run on specific triggers.

### Continuous fuzzing

A dedicated machine runs fuzz targets 24/7, cycling through
the targets. When a crash is found, the crash is reported as
a P1 finding, the input is minimized, and a regression test
is added.

The machine is not tied to a specific commit; it runs
against the latest main branch continuously. Findings are
reported as issues with the crash input and minimized
reproducer attached.

### Release gating

Before a release, a gating CI job runs:

- All tiers (1, 2, 3).
- All fuzz targets for an extended period (several hours
  each).
- Full cross-version test against the last five releases.
- Manual smoke tests on reference hardware.

The release is blocked until the gating job passes. The
gating is stricter than nightly because a release is a
commitment to users, and user-facing bugs in releases are
more visible than bugs caught internally.

### Documentation publishing

When a PR modifies the documentation (including this book),
a dedicated job renders the docs and publishes a preview
URL. Reviewers can see the rendered documentation before
merging, which catches formatting mistakes.

## What CI runs on for different events

| Event | Tiers that run |
|---|---|
| Push to branch | Tier 1 |
| Open PR | Tier 1, Tier 2 |
| Push to PR branch | Tier 1 (re-run), Tier 2 (re-run) |
| Merge to main | Tier 1 |
| Nightly schedule | Tier 3 |
| Release branch | Release gating |
| Fuzz machine (continuous) | Fuzz targets |

The distinction matters because different events have
different feedback budgets. A developer pushing to a branch
wants fast feedback; they get Tier 1. A PR is gating merges
and deserves more thorough checks; they get Tier 1 and Tier
2. Nightly and fuzz runs are for the long-running work that
does not fit in per-commit budgets.

## Handling CI failures

When CI fails, the PR is blocked until the failure is
resolved. The standard process:

1. **Read the failure log.** The log tells you which test
   failed, often with the exact assertion that tripped.
2. **Reproduce locally.** Run the same test on your machine
   with the same inputs. If it fails locally, you have a
   clean reproducer to debug. If it only fails in CI, you
   have a CI-environment issue to investigate.
3. **Diagnose.** Use the failure message, the stack trace,
   and any logged values to understand what went wrong.
   Consult [Debugging failures](debugging-failures.md) for
   the process.
4. **Fix.** Make the change to the code.
5. **Re-run locally.** Confirm the fix.
6. **Push.** CI re-runs and should pass this time.

If the failure is a flake (passes on re-run without code
changes), do not just re-run. Treat the flake as a finding
and investigate the root cause. See
[Flakiness](../discipline/flakiness.md) and
[Debugging flakes](debugging-flakes.md).

## CI machine configuration

The CI machines are configured for reproducibility:

- **Stable runner images.** The base OS image is pinned to
  a specific version. Updates happen intentionally, not
  silently.
- **Cached dependencies.** cargo's target directory is
  cached between runs, but the cache is invalidated when
  `Cargo.lock` changes. The cache makes CI fast without
  introducing nondeterminism.
- **Deterministic test execution.** Tests run with a fixed
  seed for any randomness. The PROPTEST_SEED is set for
  proptest runs in CI so failures are reproducible.
- **No network access during tests.** Tests that need
  network are rejected; networks in CI are unreliable and
  introduce flakiness.
- **Logged environment.** Every CI run logs the machine
  type, the OS version, the driver version (for GPU runs),
  and any other environment detail that could affect test
  behavior. When a test fails, the log includes enough
  context to reproduce.

## The cost of CI

CI is expensive. Running three tiers plus specialized jobs
plus continuous fuzzing plus release gating adds up to
significant compute time per day. vyre's CI is budgeted and
monitored: the operational notes track CI cost per month and
flag increases.

When the cost grows, the response is to optimize the slowest
jobs, not to remove coverage. A 10x speedup on a slow test
reduces CI cost more than removing a fast test. The monitoring
helps prioritize the optimization work.

Some optimizations that have mattered in practice:

- **Incremental compilation cache.** Cargo's target directory
  is cached between CI runs so the compiler is not
  re-invoked from scratch every time.
- **Selective mutation testing.** Only mutations on changed
  source files run per-commit; the full catalog runs only
  nightly.
- **Parallel workers.** Mutation tests and property tests
  use multiple workers to split the work across cores.
- **Dedicated machines.** GPU-heavy tests run on machines
  with real GPUs; CPU-only tests run on cheaper CPU
  machines.

## Summary

CI runs on multiple tiers, from fast per-commit checks to
expensive nightly deep runs. Tier 1 is the gate for PRs;
Tier 2 adds release checks; Tier 3 runs the expensive
long-running work. Specialized jobs handle continuous
fuzzing, release gating, and documentation previews. CI
failures are debugged by reproducing locally. The cost is
monitored and optimized without reducing coverage.

Next: [Debugging failures](debugging-failures.md).
