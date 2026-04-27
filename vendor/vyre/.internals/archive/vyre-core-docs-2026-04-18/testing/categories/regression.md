# Regression tests

## The category where bugs go to stay caught

Every bug in vyre's history has a story: how it was found, what
it affected, what the fix was, what it taught the maintainers.
Some stories are short (a one-line typo caught in review). Some
are long (a nondeterminism bug traced through three levels of
the pipeline over a week of debugging). The stories are
collectively how vyre has learned what not to do.

Regression tests are how those stories become permanent. Every
fix gets a test that would have caught the bug. The test
reproduces the exact conditions of the bug, asserts the fixed
behavior, and stays in the suite forever. If the bug ever
returns — through a refactor, a merge, an optimization, a
lowering change — the test fires immediately and the bug is
caught before it can reach users.

This category is not about finding bugs. It is about remembering
them. Every other category in Part III is for catching new bugs;
`regression/` is for ensuring old ones stay caught.

## The directory

```
tests/regression/
├── README.md
├── 2025-03-14-shl-by-32-undefined.rs
├── 2025-04-02-wire-format-roundtrip-loop-counter.rs
├── 2025-04-18-validate-nested-if-stack-overflow.rs
├── 2025-05-03-lower-wgsl-missing-bounds-check-on-dynamic.rs
├── 2025-06-11-xor-wrong-on-u64-boundary.rs
└── ... every fixed bug is here
```

One file per bug. The file name follows `YYYY-MM-DD-description.rs`,
where the date is the date the fix landed (not the date the bug
was reported) and the description is a short slug naming the
bug. Files sort chronologically in directory listings, which
makes the history of past failures visible at a glance.

The README in the regression directory is short: it describes
the format, the header requirement, and the regression rule. It
is not a catalog of bugs (the files themselves are the catalog)
and it is not a summary of which bugs have been fixed (version
control history is the summary). It is a one-page
format-and-discipline reference.

## The file format

Every regression file starts with a module-level doc comment
recording the bug:

```rust
//! Regression: 2025-03-14 — shl by 32 was undefined
//!
//! Symptom: Programs using BinOp::Shl with a shift count of 32
//! produced nondeterministic output on the wgpu backend. Some
//! runs returned 0, others returned the original value, others
//! returned garbage.
//!
//! Root cause: The lowering in src/lower/wgsl/shift.rs did not
//! emit a mask on the shift count. WGSL leaves shifts by the
//! bit width of the type undefined, and the wgpu driver
//! implemented this undefined behavior differently on each run.
//!
//! Fixed: commit 4f8a2d3 — added `& 31u` to the shift count in
//! the lowered expression. Covered by
//! tests/integration/lowering/shift_masks.rs as well, but this
//! test exercises the exact Program that triggered the original
//! report.

use vyre::ir::{Program, BinOp, Value};
use vyre::lower::wgsl;
use crate::support::programs::build_single_binop;
use crate::support::backends::run_on_default_backend;

#[test]
fn regression_shl_by_32_produces_zero() {
    let program = build_single_binop(BinOp::Shl, 0xDEADBEEFu32, 32u32);
    let result = run_on_default_backend(&program).expect("dispatch");
    assert_eq!(
        result, 0u32,
        "shl by 32 should produce 0 (the shift count is masked to 0)",
    );
}
```

The header comment has four parts:

- **Date and one-line description.** The date is when the fix
  landed. The description is a short slug.
- **Symptom.** What the bug looked like from the user's
  perspective. Written so a reader who was not there can
  understand what went wrong.
- **Root cause.** What was actually broken in the code. Written
  in enough detail to diagnose the same class of bug in the
  future.
- **Fix.** The commit that fixed it and a short description. If
  the fix is covered by other tests, that is mentioned.

The test itself is the smallest possible reproducer. It does one
thing, asserts one thing, and is written so that if it fails, the
reader immediately knows what bug has regressed.

## The regression rule

Files in `tests/regression/` are never deleted. Period.

When a regression test starts failing, the bug has returned. The
fix is to the code, not to the test. This is not negotiable and
is enforced by the review checklist: any PR that modifies a file
in `tests/regression/` is scrutinized, and any PR that deletes
one without extraordinary justification is rejected.

The reasoning is simple. A regression test exists because a bug
existed. The bug was fixed. The test was committed to ensure the
fix stuck. If someone deletes the test, they are removing the
guarantee that the fix stuck. Maybe the fix still holds and the
test is redundant; maybe the fix does not hold and deleting the
test hides the fact. In either case, the deletion is at best
neutral and at worst a regression waiting to happen. The
defensive move — never delete — costs almost nothing (a few
bytes per file) and protects against a specific class of
subtle failure.

There are two narrow exceptions:

- **The bug was a misunderstanding.** If a regression test was
  added for a behavior that turned out not to be a bug (the
  "symptom" was actually correct behavior misread as wrong), the
  test can be removed with a PR whose description explains the
  misunderstanding. The deletion is rare and highly visible.
- **The test's preconditions no longer exist.** If the bug was
  in code that has been rewritten entirely — not just refactored
  but replaced — and the regression test can no longer be built
  because the types it used have been removed, the test can be
  migrated to a new form that exercises the same symptom on the
  new code. The migration is a PR with both the old file's
  deletion and the new file's addition.

Neither exception is common. The default is permanence.

## When a regression test is added

The workflow for adding a regression test is tied to the bug-fix
workflow:

1. A bug is reported (by a user, by CI, by an internal review).
2. The bug is minimized: the smallest input that triggers it is
   identified.
3. The fix is written. The fix might be in the lowering, the
   validator, an op, or anywhere else in vyre.
4. **Before committing the fix,** a regression test is added
   that reproduces the bug's minimized input and asserts the
   fixed behavior. The test is written against the fixed code
   and passes; it would fail against the unfixed code.
5. The fix and the regression test are committed together. The
   commit message references the bug and the new test.
6. The regression test runs as part of CI from this point on.

The critical step is step 4: the test comes with the fix, not
after. If the fix is committed alone and the regression test is
left for "later," the fix is committed without its guarantee.
The rule is enforced by the review checklist: a PR that fixes a
bug must add a regression test in the same PR, or the PR is
rejected.

## What counts as a regression test

A regression test is a test that:

- Corresponds to a specific bug that existed in a specific
  version of vyre.
- Reproduces the bug's symptoms via a minimal input.
- Asserts the correct (post-fix) behavior.
- Has a header comment recording the bug.
- Lives in `tests/regression/`.

Tests that predict future bugs or test properties that might
break someday are not regression tests — they are property
tests, integration tests, or something else. The regression
category is only for bugs that actually happened.

Tests that exercise scenarios users might want covered but
which have never produced a bug are not regression tests —
they are integration tests. Do not file them here.

Tests that cover bugs in dependencies of vyre (wgpu, ash, etc.)
are not regression tests for vyre — they are regression tests
for those dependencies, which should live in those projects.
If a vyre-specific workaround was added for a dependency bug,
the workaround gets a regression test that would fail if the
workaround is accidentally removed. The comment cites the
dependency bug by URL or issue number.

## The relationship with other categories

Regression tests often duplicate coverage provided by other
categories. A bug in lowering might be covered by a general
lowering test and also by a specific regression test for the
exact input that triggered the original report. The duplication
is intentional:

- The general lowering test catches the *class* of bug. If
  lowering accepts any input in the class, the general test
  covers it.
- The regression test catches the *specific* bug. If the bug
  happened to depend on a specific input that the general test
  does not exercise, the regression test covers that specific
  input.

Both are valuable. The general test prevents the class from
returning; the regression test prevents the specific instance
from returning even if a new gap opens in the class coverage.

The duplication is also cheap: regression tests are usually tiny
and run quickly. A few hundred lines of regression code adds
negligible test runtime and provides meaningful defense in depth.

## Minimization discipline

Regression tests use minimal inputs. "Minimal" here means the
smallest input that still triggers the bug — not a simplified
version of the user's original report, but the actual smallest
case.

The minimization is produced by the minimizer in
`vyre-conform/src/minimize/`, which takes a failing input and
produces shrunken versions that still fail until the smallest is
found. See [Mutations at scale](../advanced/mutation-at-scale.md)
for the minimizer's implementation. The minimization happens
before the regression test is committed, so the committed test
is the smallest reproducer, not the original report.

Why minimize? Because a minimal reproducer is:

- Faster to run in CI.
- Easier to debug if the test fires.
- More likely to expose the exact bug class rather than the
  specific instance.
- More likely to survive refactoring (a large input has more
  things that can change; a small input is stable).

The minimization is not optional. A regression test committed
without minimization is rejected at review with a request to
minimize.

## Fuzz corpus as regression

`tests/corpus/fuzz/` is a directory of inputs discovered by
`cargo fuzz` runs that caused bugs in past versions of vyre.
Each file in the corpus is effectively a regression test: it
records an input that once failed and must never fail again.

The corpus is replayed by a test in `tests/adversarial/fuzz_corpus.rs`,
not by individual files in `tests/regression/`. The reason is
that fuzz corpus entries are binary files (the raw bytes that
triggered the fuzzer) and it would be unwieldy to wrap each in
its own Rust file with a header. The adversarial fuzz replay
test handles the entire corpus at once.

But the discipline is the same: fuzz corpus entries are never
deleted, exactly like regression test files. When a fuzz finding
is closed, the minimized input goes into the corpus permanently.

## How the category grows

Regression categories grow monotonically. Every fixed bug adds a
file. Files are rarely deleted. Over time, the category becomes
a record of every bug that has ever been caught in vyre, with
minimal reproducers for each.

The growth is a feature, not a problem. A mature regression
suite is a compressed history of the project's learning. When
a new contributor browses the directory, they see the range of
bugs that have actually occurred, which teaches them which kinds
of mistakes are common enough to deserve attention. The
directory listing is a curriculum.

As the directory grows, it becomes useful to index it — by
affected subsystem, by root cause class, by severity. The README
in the directory can be extended to provide the index, or the
index can live in [Appendix G](../appendices/G-examples-index.md).
The index does not replace the individual files; it
supplements them.

## Performance

Regression tests are fast. Each one is a minimal input, a
simple call, a simple assertion. The full regression suite
should complete in well under a minute even with hundreds of
entries. If it does not, the minimization has been sloppy and
some entries should be shrunk further.

The regression category does not typically need to be split
into fast and slow tiers. Everything runs on every CI invocation.

## Summary

Regression tests are permanent records of fixed bugs. Every bug
fix comes with one. They are never deleted. Each file has a
header recording the bug's symptom, root cause, and fix. Inputs
are minimized. The category grows over time and becomes the
project's institutional memory for past failures. It is how vyre
ensures it does not make the same mistake twice.

Next: [Benchmarks](benchmarks.md).
