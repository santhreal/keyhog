# Mutation testing at scale

## When the gate is slow

Mutation testing, as described in [Mutations](../mutations.md),
is the quality floor for vyre's test suite. The gate runs the
mutation catalog against tests and rejects any test that does
not kill the expected mutations. On a single test or a single
op, the gate is fast: a handful of mutations applied, tests
re-run, report produced. The fast case is the case most
contributors experience.

At scale, the gate is slow. Running the full mutation catalog
against the full suite takes substantial wall-clock time
because each mutation requires a compile and a test run. A
naive implementation runs thousands of compile-test cycles,
each taking seconds, for a total of hours per full-suite
mutation pass. That is too slow to run in per-commit CI and
uncomfortable to run even in nightly CI.

This chapter is about running mutation testing at vyre's scale
without the cost being prohibitive. The techniques: caching,
incremental runs, parallelism, target-directory separation,
and selective mutation. Together they reduce the cost from
hours to minutes for typical changes and keep the feedback
loop fast enough to be useful.

## The problem

A naive mutation gate on vyre:

- **Mutations in the catalog:** ~500 (arithmetic, comparison,
  bitwise, control flow, buffer access, IR-specific, law-level,
  lowering).
- **Tests in the suite:** ~5,000 (rough target including
  hand-written and generated).
- **Compile time per mutation:** ~10 seconds (incremental).
- **Test time per mutation run:** ~30 seconds (fast subset)
  to 2 minutes (full suite).

Full-suite mutation testing: 500 × 2 minutes = 1000 minutes =
~17 hours. Not viable.

Per-op mutation testing on the affected test subset: 500 × 10
seconds (compile) + 500 × 5 seconds (small test run) = 125
minutes. Better but still uncomfortable.

Per-commit mutation testing on changed files only: 50 × 5
seconds = 4 minutes. Actually viable, and this is what vyre's
gate is optimized for.

## Caching

The first and biggest optimization: cache mutation results by
source hash. When a test is unchanged and the mutated source
file is unchanged, the result of running the test on the
mutated source is deterministic and can be cached.

```rust
pub struct MutationCache {
    // Key: (test_fn_hash, source_hash, mutation_hash)
    // Value: Killed | Survived
    entries: HashMap<CacheKey, MutationResult>,
}

impl MutationCache {
    pub fn get(&self, test: &TestFn, source: &SourceFile, mutation: &Mutation) -> Option<MutationResult> {
        let key = (hash_test(test), hash_source(source), hash_mutation(mutation));
        self.entries.get(&key).copied()
    }
}
```

The cache is keyed on the exact inputs to the mutation run. If
any input changes — a test is edited, a source file is
modified, a new mutation is added — the cache entry is
invalidated and the mutation is re-run. If all three are
unchanged, the cached result is used.

The cache is persistent across runs. It lives in a file under
`target/mutation-cache/` or in a shared CI cache. A CI run
that reuses the previous cache only needs to re-run mutations
for changed tests or changed sources, which is typically a
small fraction of the full suite.

With caching, the per-commit cost drops to:

- Mutations on changed sources only: ~10-50 mutations per PR.
- Compile time per mutation: ~10 seconds.
- Test time: ~5 seconds (focused on affected tests).
- Total: ~2-13 minutes per PR.

That is the target window. Per-commit CI runs mutation testing
because the cache makes it cheap, and the cost is only felt
on the first run (and on full-cache-invalidation events like
catalog updates).

## Incremental runs

Beyond caching, the gate can be made incremental. Instead of
running every mutation on every commit, the gate runs only
the mutations that are affected by the commit:

- **Changed source files:** mutations that apply to any source
  file the PR modifies.
- **Changed tests:** tests that cover code affected by the
  mutations.
- **Changed catalog:** if the mutation catalog itself has been
  updated, the new mutations run on everything they apply to.

The incremental set is usually tiny compared to the full set.
A PR that modifies `src/ops/primitive/add.rs` only needs
mutations applicable to that file, which is maybe 20-50
mutations. A PR that adds new tests only needs mutations on
the source those tests cover, which is a small set.

The CI infrastructure tracks the change set and filters the
mutation run accordingly. The filter runs before the compile
step, so the cost of unchanged mutations is zero.

## Parallelism

A mutation run is trivially parallelizable: each mutation is
independent of the others. The gate runs N mutations in
parallel by using N separate target directories and N cargo
processes. Each process has its own mutated copy of the
source, its own build artifacts, and its own test outputs.

```
target/mutation-workers/
├── worker_0/
│   ├── src/           copy of source with mutation 0 applied
│   ├── target/        separate cargo target dir
│   └── ...
├── worker_1/
└── ...
```

With N workers, the mutation run is roughly N times faster,
up to the point where I/O or compile contention becomes the
bottleneck. In practice, N = 4 to N = 8 is the sweet spot for
typical CI hardware.

The parallelism works because cargo's target directories are
independent. Changes in one worker's target do not affect
another's, so workers do not block each other. The cost is
disk space: each worker has its own target directory, which
can be several gigabytes. The cost is usually acceptable on
CI machines with ample disk.

## Target-directory separation

Even without full parallelism, target-directory separation
helps. The default cargo build shares a target directory with
other builds, which means mutation tests contend with normal
builds for filesystem access and incremental compilation
state. Separating the mutation test target directory from the
main one lets both run without interference.

```bash
CARGO_TARGET_DIR=target/mutation cargo test ...
```

This runs the test in `target/mutation/` instead of `target/`.
The main development target is untouched by the mutation run,
which means the developer can keep working on the main target
while mutation tests run in the background.

## Selective mutation

Not every mutation in the catalog is relevant to every test.
A mutation in `src/ops/primitive/add.rs` that swaps `Add` for
`Sub` is relevant to tests that exercise `Add`; it is
irrelevant to tests that do not touch `Add` at all. Running
the mutation against tests that do not cover the source is
wasted work.

Selective mutation uses coverage information to pick the
right subset of tests for each mutation. Before the mutation
run starts, the gate records which tests execute which source
files (via coverage instrumentation). When a mutation is
applied to a source file, only tests that cover that file are
run. Tests that never touch the mutated file are skipped.

Selective mutation reduces the cost proportionally to the
test-to-source mapping density. For a suite where each source
file is covered by a few dozen tests (out of thousands), the
savings are an order of magnitude or more.

## The cache + incremental + selective stack

Combining the techniques:

1. **Caching** eliminates re-running mutations whose inputs
   have not changed.
2. **Incremental** runs only apply to the change set for each
   PR.
3. **Selective** filters tests per mutation to the covering
   subset.
4. **Parallelism** runs the remaining work across multiple
   workers.
5. **Target-directory separation** prevents contention with
   other builds.

A typical PR with these optimizations has a mutation cost of
~2-5 minutes. The full-suite cost (run on nightly CI) is under
an hour. Both are acceptable, and the gate becomes a routine
part of the development cycle rather than an obstacle.

## The minimizer

Separate from running mutations, vyre has a minimizer that
reduces failing test inputs to their smallest form. The
minimizer is used when a property test or a fuzz run discovers
a bug: the failing input is usually large, and the minimizer
shrinks it before the input becomes a regression test.

```rust
pub fn minimize<I: Shrinkable>(
    input: I,
    predicate: impl Fn(&I) -> bool,
) -> I {
    let mut current = input;
    loop {
        let candidates = current.shrink();
        let smaller = candidates.into_iter().find(|c| predicate(c));
        match smaller {
            Some(c) => current = c,
            None => return current,
        }
    }
}
```

The `predicate` is "the input still triggers the bug." The
minimizer tries smaller versions of the input and keeps the
first one that still triggers. The loop continues until no
smaller version triggers, at which point the current version
is the minimal reproducer.

Minimization is essential for good regression tests. A
50-element program that triggers a bug is hard to debug; a
3-element program that triggers the same bug is easy to
debug. The minimizer does the reduction automatically.

## Costs and trade-offs

Mutation testing at scale is expensive even with every
optimization applied. The costs:

- **Compute time.** Hours of CPU per day for the nightly full
  run. Budget this in CI planning.
- **Disk space.** Target directories for worker parallelism,
  cached mutation results, coverage data. Budget this in CI
  planning.
- **Flakiness risk.** The more complex the CI pipeline, the
  more opportunities for flakes. The caching and incremental
  systems are themselves potential sources of incorrect
  behavior if their invalidation is wrong.

The trade-off: expensive but mechanical quality enforcement
vs cheap but unreliable human enforcement. vyre chooses the
expensive mechanical path because the human path does not
scale.

## Summary

Mutation testing at scale uses caching, incremental runs,
selective mutation, parallelism, and target-directory
separation to keep the gate fast enough to run in CI. Per-PR
cost is minutes; nightly full-suite cost is under an hour.
Without these optimizations, mutation testing would be
impractical at vyre's size; with them, it is a routine part
of development.

Next: [Concurrency and ordering](concurrency-and-ordering.md).
