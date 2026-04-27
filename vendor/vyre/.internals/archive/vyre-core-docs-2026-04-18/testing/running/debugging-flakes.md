# Debugging flakes

## The harder case

Debugging a deterministic failure is straightforward: the
failure reproduces, the cause is traceable, the fix is
verifiable. Debugging a flaky failure is harder because the
failure does not reproduce on demand. You might run the test
ten times and see it pass ten times. You might run it a
hundred times and see it fail once. The investigation requires
different tools and a different mindset.

This chapter is about flake debugging specifically. The
general debugging process from the previous chapter still
applies, but several additional techniques are needed. The
goal is to turn a flaky failure into either a deterministic
failure (which you can then debug normally) or a confirmed
flake root cause (which you fix to eliminate the flakiness).

## Confirming the flake

Before investigating, confirm that the failure is actually a
flake and not a deterministic failure masked by your run
environment. Run the test many times:

```bash
for i in {1..100}; do
    cargo test -p vyre test_suspected_flake -- --test-threads=1 2>&1 | tail -1
done
```

The loop runs the test 100 times serially and prints the last
line of output for each run. If the test fails in some runs
and passes in others, it is a flake. If it passes every time,
the failure you saw is not reproducing on your machine — you
might need to replicate the CI environment to see it.

Common reasons a test that failed in CI passes locally:

- **Parallelism.** CI runs tests in parallel; local run
  defaulted to a different thread count. Try `--test-threads=1`
  or `--test-threads=16` to match.
- **Different CPU.** CI's CPU has different timing
  characteristics from local. Try a CI-like machine if
  available.
- **GPU differences.** CI's GPU or driver might be different.
  This matters for GPU-dependent tests.
- **Random seed.** If the test uses randomness with a
  different seed locally, the failure's specific input does
  not appear. Set the seed explicitly.

If you cannot reproduce locally after trying these, the
flake is CI-specific and must be debugged with CI logs.

## Gathering information

When a flake fires, collect as much information as possible
about the environment:

- **The exact test command and output.**
- **The CI runner's hardware specs.**
- **The driver version (for GPU tests).**
- **The time the failure occurred (for time-dependent bugs).**
- **Any other tests running concurrently (for parallelism
  bugs).**
- **The random seeds used (for proptest).**

CI logs should capture all of this automatically. If they do
not, that is a CI improvement to request.

## Classifying the flake

Flakes come in several distinct classes, and each class has
its own debugging approach.

### Timing-dependent flake

The test fires when timing is unusual (unusually fast,
unusually slow, or unusually scheduled). Symptoms:

- Fails more often on loaded machines.
- Passes reliably on your machine, fails on CI's machine.
- Passes when run alone, fails when run with other tests.

Debugging approach:

- Look for `thread::sleep` in the test or the code it
  exercises. Any sleep is suspicious.
- Look for "wait for" patterns without synchronization
  primitives.
- Look for assertions about how long something took.

The fix is usually to replace timing assumptions with
explicit synchronization (channels, barriers, mutexes).

### Ordering-dependent flake

The test fires when iteration order or execution order is
different from what the test assumed. Symptoms:

- Fails when the same test runs in a different order (after
  another test that reset some state).
- Fails when assertion iterates over a map or set whose
  order is not guaranteed.
- Passes with `--test-threads=1` (serial execution makes
  ordering more predictable).

Debugging approach:

- Look for `HashMap` iterations in assertions. Use
  `BTreeMap` for deterministic iteration.
- Look for tests that mutate shared state and assume the
  state was as they left it.
- Look for test order dependencies.

The fix is to sort values before assertion, use ordered
collections, or mark the test `#[serial]` if ordering
cannot be eliminated.

### Randomness flake

The test uses randomness with an inconsistent seed, so
different runs exercise different inputs. Symptoms:

- Fails on specific seeds that occasionally appear.
- Has `thread_rng()` or `from_entropy()` in its source.
- proptest has no fixed seed.

Debugging approach:

- Search for `rand::thread_rng()`, `rand::rngs::OsRng`, or
  `proptest::test_runner::Config` usage without seed.
- Check if the proptest regression corpus is committed. If
  not, the flake is due to missing regression replay.

The fix is in [seed discipline](../discipline/seed-discipline.md):
fixed seeds, committed corpora, explicit configuration.

### Environment flake

The test depends on an external resource (file system,
network, environment variable) that is not always consistent.
Symptoms:

- Fails in CI but not locally, or vice versa.
- Fails when certain environment variables are set or
  unset.
- Fails when the working directory is different.

Debugging approach:

- Check what the test reads from the environment.
- Check what the test writes to the file system.
- Check whether the test uses absolute paths.

The fix is to make the test self-contained: use
`std::env::temp_dir()` for file operations, use
`env!("CARGO_MANIFEST_DIR")` for paths, mock any
environment reads.

### State leakage flake

The test fails when run after another test because the other
test left state behind that this one does not expect.
Symptoms:

- Fails when run in combination with specific other tests.
- Passes when run alone.
- Does not depend on randomness or timing.

Debugging approach:

- Run tests in pairs to find which other test causes the
  failure.
- Once the leaking test is identified, inspect what state it
  modifies.
- Check whether the state is global (static variables),
  file system, or environment.

The fix is to either reset the state in a fixture at test
boundaries or to isolate the tests (run them on separate
processes, or mark them `#[serial]`).

## Running the test to reproduce the flake

Once you have classified the flake, try to make it
reproduce more reliably. Some techniques:

### Run many times

The simplest: run the test hundreds or thousands of times in
a loop. If the flake fires once per 10 runs, a 1000-iteration
loop sees it 100 times, which is enough data to diagnose.

```bash
for i in {1..1000}; do
    cargo test -p vyre test_suspected_flake --quiet 2>&1 | grep -E 'FAILED|error' && echo "iter $i failed"
done
```

### Run with high parallelism

If the flake is parallelism-related, increase the thread
count beyond your CPU count. The extra contention often
exposes the bug faster.

```bash
cargo test -p vyre test_suspected_flake -- --test-threads=32
```

### Run with sanitizers

ThreadSanitizer catches data races and AddressSanitizer
catches memory errors. Either can turn a probabilistic flake
into a deterministic failure. These are slow but very
effective for concurrency flakes.

```bash
RUSTFLAGS="-Z sanitizer=thread" cargo +nightly test -p vyre test_suspected_flake
```

### Run with stress

Load the system while the test runs: spawn background
processes, cap the CPU, run under a debugger with breakpoints
that slow execution. The goal is to create the kind of
disruption that exposes timing-dependent bugs.

## Fixing the flake

Once you have a reproducer, fix the root cause, not the
symptom. Fixing the symptom (marking the test `#[ignore]`,
relaxing an assertion, adding a retry) leaves the underlying
bug in place. The bug fires later, possibly in a worse way.

For timing flakes: replace `sleep` with synchronization.

For ordering flakes: sort before assertion, use ordered
collections, or serialize the test.

For randomness flakes: fix the seed.

For environment flakes: make the test self-contained.

For state leakage flakes: isolate the tests or reset the
state.

After the fix, run the test many times to verify the flake
is gone. A few dozen runs is the minimum; a few hundred is
more reassuring.

## When you cannot find the root cause

Sometimes a flake resists investigation. The test fails
occasionally, you cannot reproduce it on demand, and you
cannot identify the root cause. In this case, the options
are:

- **Quarantine the test with an expiration.** Mark it
  `#[quarantine]` with a reason and a deadline, as described
  in [Flakiness](../discipline/flakiness.md). The quarantine
  buys time without pretending the flake is not real.
- **File an issue with everything you know.** Every detail
  you have about the flake goes in the issue: failure modes,
  frequencies, environment details, hypotheses you have
  tried. Future investigators can pick up from your notes.
- **Run more instrumentation.** Add logging to the test so
  that the next failure produces more context. The added
  logging does not fix the flake but might help identify
  the cause next time.

The one option that is not available: leave the flake in the
suite without quarantine. An unmarked flake trains engineers
to ignore failures, which corrodes the suite over time.

## Summary

Flake debugging is harder than deterministic debugging. The
process: confirm the flake, classify it (timing, ordering,
randomness, environment, state leakage), reproduce reliably
with many runs or sanitizers, fix the root cause, verify the
fix. When investigation fails, quarantine with expiration and
file detailed issues. Never leave unmarked flakes in the
suite.

This concludes Part IX. Part X covers the relationship
between vyre's hand-written suite and vyre-conform's
generated suite.

Next: Part X opens with [The two-tier suite](../vyre-conform/two-tier-suite.md).
