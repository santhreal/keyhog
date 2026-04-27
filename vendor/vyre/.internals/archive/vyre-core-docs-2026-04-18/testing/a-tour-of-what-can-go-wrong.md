# A tour of what can go wrong

This chapter is a tour of the specific failure modes vyre's test suite
exists to prevent. Each failure mode is a category of bug that would
break vyre's promise to its users, and each category corresponds to
one or more parts of the test architecture described in Part III.
Knowing which bugs the suite catches is how you know whether the
suite is complete. Knowing how each bug manifests is how you know
whether your own test is strong enough to catch it.

The seven failure modes below are not hypothetical. Every one of them
has appeared at least once in the history of GPU compute, in systems
shipped by companies with thousands of engineers. None of them are
exotic. All of them are the kind of bug that reaches production when
the test suite was not built to catch them.

## Failure mode 1 — Miscompilation

A miscompilation is when the compiler — in vyre's case, the lowering
from `ir::Program` to a backend shader language — produces output
that does not preserve the semantics of the input. The IR says "add
these two values." The lowered shader does something that is not
adding them. The program runs. It returns values. The values are
wrong.

Miscompilations are the most dangerous class of bug because they do
not announce themselves. The program does not crash. The runtime
does not error. The test harness does not trip. A user writes a
Program, runs it, and receives answers that are plausible, repeatable,
and wrong. If the user is running an ML inference, the model
predicts subtly worse. If the user is running a cryptographic
operation, the ciphertext is subtly corrupted. If the user is
running a scientific simulation, the results disagree with reality
in ways that take months to track down.

The history of GPU compute is full of miscompilations. NVIDIA's
shader compiler has had versions that silently replaced `sin(x)`
with a low-precision approximation in contexts where the user
expected the IEEE function. AMD's GLSL compiler has had versions
that reordered associative reductions in ways that broke scientific
simulations. Intel's GPU compiler has had versions where integer
overflow on loop counters produced different behavior than the
source language required. Each of these is a miscompilation. Each
of them was caught eventually, most after shipping, some after
years.

vyre's test suite catches miscompilations through two mechanisms.
First, the reference interpreter (`vyre-conform::reference`) is a
pure-Rust evaluator that runs Programs with obvious correctness.
Every backend's output is diffed against the reference interpreter's
output for the same Program. If the lowered shader disagrees with
the reference, the lowering is wrong. Second, the lowering coverage
tests in `tests/integration/lowering/` exercise every `Expr` variant,
every `Node` variant, and every `BinOp`/`UnOp`/`AtomicOp` combination,
with enough structural diversity that a miscompilation affecting any
one variant shows up. The category map in Part III describes these
tests in detail.

The key defense against miscompilation is the oracle discipline from
[the previous chapter](oracles.md): the expected value never comes
from the lowered shader itself. It always comes from an independent
source — the reference interpreter, a specification table, a law —
so that a miscompilation cannot hide by making the test agree with
the broken output.

## Failure mode 2 — Nondeterminism

A nondeterministic operation is one that produces different results
for the same inputs on different runs, or on different devices, or
in different thread schedules. Nondeterminism is vyre's existential
enemy. The entire value proposition of vyre is byte-identical output
from identical input, forever, on every conformant backend. A single
nondeterministic operation anywhere in the system breaks this
contract and breaks the product.

GPU nondeterminism sneaks in through many channels. Parallel
reductions that are "approximately associative" produce different
sums depending on the order in which the partial sums are combined.
Atomic operations that race produce results that depend on the
schedule. Hardware that flushes subnormal floats to zero produces
different outputs from hardware that handles them correctly.
Workgroup sizes that differ across devices produce different memory
access patterns, which can expose ordering bugs that were hidden on
the original hardware. Vendor math libraries substitute different
implementations of transcendental functions, each accurate to within
a few ULP but differing in the last bits.

The test suite catches nondeterminism through the property chapter
of Part III's property tests and the determinism harnesses in Part
III's backend tests. A property test in `tests/property/determinism.rs`
runs a large population of random Programs many times and asserts
every run produces bit-identical output. A backend test in
`tests/backend/determinism_across_runs.rs` runs a curated set of
Programs one thousand times each and asserts every run agrees. A
cross-backend test runs the same Program on every registered backend
and asserts agreement to the byte.

When a nondeterminism bug is caught by the suite, the fix is almost
always at the IR level, not the backend level. The backend is doing
what it was allowed to do; the IR must forbid the operation, or
constrain it further, so that the backend no longer has the license
to be nondeterministic. See [Concurrency and
ordering](advanced/concurrency-and-ordering.md) in Part VIII for the
specific patterns vyre forbids and the tests that enforce each.

## Failure mode 3 — Backend drift

Backend drift is the cumulative divergence between two conformant
backends over time. Day zero, backend A and backend B produce
identical output for every Program. Day one hundred, they produce
identical output for almost every Program, but a small class of
inputs triggers a one-ULP difference because one backend picked up
a driver update that changed the rounding behavior of a specific
instruction. Day five hundred, the set of divergent inputs has
grown to a few percent because the drift went unnoticed and other
backends started drifting too. Day one thousand, vyre's promise is
a fiction.

Backend drift is the failure mode that kills substrates. CUDA's
early promise of portability eroded as NVIDIA and other CUDA
implementers drifted apart. OpenCL's promise eroded for the same
reason. The pattern is always the same: the specification does not
pin down a detail, two implementations interpret the gap
differently, the gap widens, the promise breaks.

vyre's defense against backend drift is cross-backend equivalence
tests that run in CI on every commit. The test corpus is the union
of every `tests/backend/` file, every `tests/integration/primitive_ops/`
file run through the backend harness, and the entire set of
vyre-conform generated tests. Every one of those tests runs on
every registered backend, and any disagreement — even a single bit
— is a CI failure. The suite does not let drift accumulate because
the suite does not let drift enter. A commit that introduces a
drift-producing change cannot land.

The stronger version of this defense is the conformance certificate.
A backend is not conformant until it has passed the full suite. A
certificate is valid only for the exact backend version that earned
it. A driver update that changes behavior invalidates the
certificate and the backend must re-earn it. See [the two-tier
suite](vyre-conform/two-tier-suite.md) in Part X for how vyre and
vyre-conform cooperate to issue and revoke certificates.

## Failure mode 4 — Composition bugs

Operations in vyre compose. A Program is a composition of nodes, each
of which contains expressions that may themselves call other
operations or read from buffers populated by previous operations.
When two correct operations compose, the composition should also be
correct. When the composition surprises, there is either a bug in
one of the operations, a bug in the composition logic, or a bug in
the algebraic theorem that claimed the composition would be
well-behaved.

Composition bugs are insidious because the individual operations
look correct when tested in isolation. `BinOp::Add` passes all its
unit tests. `BinOp::Mul` passes all its unit tests. A Program that
composes them in a specific order, perhaps under a conditional
branch with a loop counter, produces wrong output. The bug is not
in `Add` or `Mul`; the bug is in how they were joined, or in the
lowering's handling of the join, or in an optimization that fired
under the composition but not under the individual operations.

The test suite catches composition bugs through two mechanisms.
First, the integration tests in `tests/integration/` exercise
multi-op Programs directly. Every test in `primitive_ops/` builds a
small Program and runs it through the full pipeline, but larger
tests in `tests/integration/ir_construction/` build bigger Programs
with real composition structures — diamonds, chains, loops, nested
conditionals — and assert on the end-to-end output. Second,
vyre-conform's composition theorems prove certain properties are
preserved under composition, and tests that rely on those theorems
fail loudly if the composition breaks the property. A commutative
op composed under a rule that preserves commutativity must stay
commutative; a test asserts this, and if the composition violates
the theorem the test fires.

See [Composition theorem oracle](oracles.md) in the oracle chapter
for how tests leverage the theorem system.

## Failure mode 5 — Validation gaps

Validation is vyre's contract with its consumers: if `validate(program)`
returns empty, the program is safe to lower and dispatch. A validation
gap is any case where a malformed Program passes validation and then
causes a panic, an undefined behavior, an unbounded allocation, or a
wrong result at lowering or dispatch time. Validation gaps are bugs
because they break the contract; the consumer has no way to know the
program was malformed, so the responsibility falls on vyre.

Validation gaps are common in systems that grow organically. A new
feature is added, a new `Expr` variant is introduced, the lowering
handles the new variant but validation does not — nobody remembered
to update the validator. A malformed program containing the new
variant slips through validation and breaks lowering. From the
user's perspective, vyre crashed; from vyre's perspective, the
contract was violated silently until the day someone wrote the
malformed program.

vyre's defense against validation gaps is the validation test
category (`tests/integration/validation/`), which contains one test
per V-rule plus a meta-test that enumerates `ValidationRule` and
requires every variant to have a corresponding test. Adding a new
V-rule without a test is a compile error because the meta-test
enumerates the enum and fails on any unmatched variant. Removing the
meta-test itself is caught by a review rule.

The deeper defense is invariant I5 (validation soundness): every
Program that passes validation must lower safely. This is a property
that `tests/property/validation_soundness.rs` asserts by generating
random Programs, validating them, and running the validated ones
through the full pipeline. Any failure is a validation gap, which
becomes a finding and a new V-rule. The property test is the
continuous audit on the contract.

## Failure mode 6 — Float nondeterminism

Floating-point nondeterminism is nondeterminism specifically
concerning floats. It gets its own failure mode because the causes
are specific, the detection is specific, and the consequences are
specific.

A float nondeterminism bug looks like this: a Program that uses
`f32` arithmetic produces `0.1 + 0.2 == 0.30000000000000004` on one
backend and `0.1 + 0.2 == 0.30000000000000003` on another. Both
results are within one ULP of the true sum. Both are "correct" in
the informal sense. But they are different bytes, and vyre's promise
is byte-identical, so they are wrong.

The sources of float nondeterminism are the permissions the
hardware grants the compiler that vyre must forbid: fused multiply-add,
reordered reductions, subnormal flush, approximate reciprocals,
approximate square roots, vendor transcendental substitutions,
tensor-core accumulation at reduced precision. vyre's specification
forbids each of these for the strict IEEE 754 track, and the
lowering is responsible for emitting shader code that the backend
cannot optimize into a forbidden form.

The test suite catches float nondeterminism through the floating-point
category of Part VIII, which covers both the strict IEEE 754 track
and the approximate track with ULP-bounded tolerance. Every floating-point
op has cross-backend equivalence tests, determinism tests, and
boundary tests (subnormals, NaN, infinity, signed zeros, round-to-even
edge cases). See [Floating-point](advanced/floating-point.md) in
Part VIII for the full treatment.

## Failure mode 7 — Regression

A regression is when a bug that was previously fixed returns. It is
not strictly a new failure mode; it is the return of an old one. But
regressions deserve their own entry in this tour because the defense
against them is specific and non-optional.

Every bug that has been fixed in vyre is a test waiting to happen.
The bug had inputs that triggered it, behavior that was wrong, and
a fix that made the behavior right. The minimal repro for that bug
is a permanent test. If the fix is ever accidentally undone — by a
refactor that drops a branch, by an optimization that rearranges
control flow, by a merge that silently reverts a patch — the test
fires and the regression is caught before it reaches users.

The defense against regressions is `tests/regression/`. Every file
in that directory is a past bug's minimal reproducer, with a header
comment recording the bug's symptom, root cause, fix commit, and
date. Files in this directory are never deleted. If a test in
`tests/regression/` starts failing, the bug has returned, and the
fix is to the code, never to the test. See [Regression
tests](categories/regression.md) and [The regression
rule](discipline/regression-rule.md) for the complete treatment.

The cultural rule that makes this work is: when a bug is fixed, the
fix is not complete until a regression test has been committed that
would have caught the bug before the fix. This is non-optional. A
PR that fixes a bug without adding a regression test is rejected at
review. The test comes with the fix or the fix is incomplete.

## What this tour leaves out

This tour covers the big seven failure modes, but there are smaller
ones that the suite also catches:

- **Resource exhaustion:** a Program that looks well-formed but
  consumes unbounded memory or time. Caught by adversarial tests
  that feed the limits of each resource and assert graceful
  rejection.
- **IR wire format round-trip loss:** serializing a Program and
  deserializing it produces a different Program. Caught by
  `tests/integration/wire_format/roundtrip.rs` which asserts identity
  on a large corpus.
- **Validation incompleteness beyond I5:** the separability
  requirement (invariant I6) says every V-rule must be independently
  triggerable. If two rules are coupled, one of them is redundant or
  both have a gap. Caught by the validation separability audit in
  Part III's validation chapter.
- **Backend initialization bugs:** a backend that works on its
  second dispatch but fails on its first because some lazy
  initialization did not happen. Caught by running every backend
  test from a cold state in addition to the warm path.
- **Cross-version bugs:** a Program valid under v1.x that produces
  different output under v1.y. This is a stability invariant (I13)
  violation. Caught by a nightly job that runs every committed test
  against pinned historical vyre versions.

Each of these has a specific test category responsible for it, and
each category has a chapter in Part III. The mapping from failure
mode to category is [Appendix B](appendices/B-invariants-catalog.md).

## What the tour says about the suite

The suite has to catch all of these failure modes. That is a lot of
bugs to catch, and no single category of test can catch them all.
Miscompilations need lowering tests and backend diff tests.
Nondeterminism needs determinism stress and cross-backend equivalence.
Drift needs continuous cross-backend runs in CI. Composition bugs
need integration tests on real composed Programs. Validation gaps
need per-rule tests plus soundness properties. Float nondeterminism
needs dedicated float tests. Regressions need the regression corpus.

No single test catches a bug in every failure mode. The suite is
strong because it has the right categories, each doing its specific
job, with no overlap that matters and no gaps that matter. Part III
explains each category, and the [decision
tree](writing/decision-tree.md) in Part V tells you which category
your test belongs in.

Next: [The promises](the-promises.md) — the fifteen invariants the
suite must prove, expressed as promises to vyre's users rather than
as numbered rules.
