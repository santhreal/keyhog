# Introduction

## vyre's promise

vyre's promise to its users is that an `ir::Program` valid under its
specification produces byte-identical results on every conformant
backend, today and for every future version, forever. That is the
entire value proposition. Everything else vyre offers — the IR, the
lowering, the IR wire format, the op library, the engines built
on top — is in service of that promise.

The promise is not "approximately equal." It is not "equal within a
tolerance." It is not "equal for reasonable inputs." It is byte-equal,
for every input, on every conformant backend, forever. Two backends
implementing vyre's specification independently must produce the same
bytes from the same `Program`, not because they coordinated, but
because the specification is unambiguous and the conformance suite is
the arbiter.

This is the property that made Linux into infrastructure. It is the
property that made LLVM into infrastructure. It is why SQLite can be
embedded in a billion phones and work identically on every one. A
substrate that keeps its word becomes the substrate everyone builds on.
A substrate that breaks its word becomes the substrate everyone
reluctantly tolerates until something better comes along, and then
abandons without ceremony.

vyre is making the bet that GPU compute needs the former and has so
far suffered from the latter. CUDA is not portable. OpenCL never
stabilized. SPIR-V is a binary format, not a semantic contract. Every
major GPU compute framework of the last fifteen years has quietly
accepted some degree of nondeterminism and cross-vendor drift as the
cost of shipping. vyre rejects that tradeoff and pays the
corresponding cost: the specification must be precise, the
implementation must be disciplined, and the test suite must be strong
enough to enforce both.

## Why the promise is hard to keep

GPU compute is adversarial to determinism by default. A modern GPU is
allowed, by every vendor's specification, to do all of the following:

- Fuse multiply-add pairs into a single fused-multiply-add instruction,
  producing one rounding step instead of two.
- Reorder reductions, because floating-point addition is
  "approximately associative" and the vendor knows it does not hold
  exactly.
- Flush subnormal floats to zero, because handling them slows down
  compute cores.
- Substitute vendor math library implementations for standard
  operations, so `sinf(x)` on NVIDIA produces bits that `sinf(x)` on
  AMD does not.
- Use tensor cores with reduced-precision accumulators for operations
  that looked to the user like straight `f32` arithmetic.
- Approximate `rcp(x)` and `rsqrt(x)` instead of computing them
  exactly, because the approximation is close enough for rendering.
- Schedule threads nondeterministically, so two atomic operations that
  race have a result that depends on the schedule.
- Use different warp sizes, different workgroup sizes, different
  memory hierarchies — any of which can leak into a result that looked
  like it was only doing arithmetic.

Every one of these is a permission the hardware grants the driver.
Every one of these breaks determinism if vyre does not explicitly
forbid it. A vyre Program that produces `0x42` on NVIDIA and `0x42`
on AMD is not a coincidence — it is the result of the specification
telling both backends: do not fuse, do not reorder, do not flush, do
not substitute, do not approximate, do not race, and use the strict
IEEE 754 path regardless of what the hardware prefers.

This is the Rust analogy that vyre's architecture commits to. Rust is
memory-safe not because the hardware is safe but because the compiler
refuses to emit code that exercises the unsafe patterns. Safe Rust
cannot write data races, not because the atoms are different but
because the compiler will not produce the instructions that would
allow it. vyre is deterministic not because the GPU is deterministic
but because the IR forbids the patterns that make it
nondeterministic. The hardware has the same permissions it always
had. The constraints at the IR level are what preserve the guarantees.

The cost of this discipline is real. Strict IEEE 754 `sinf` is roughly
fifty times slower than the vendor's fast approximation. Strict
reduction is slower than tree reduction by a constant factor. Refusing
to fuse FMA costs a multiply-add per operation. We pay these costs
deliberately, because the alternative is a promise we cannot keep. A
vyre program that runs twice as fast but produces different bytes on
two backends is worthless. A vyre program that runs at full speed and
produces identical bytes on every backend is the product.

## What the test suite has to prove

Given that vyre's architecture chooses determinism over raw throughput
and that the specification is written to forbid every pattern that
breaks determinism, the question is: how do we know the implementation
actually obeys the specification?

This is where the test suite earns its existence. Every guarantee in
the specification is a claim that the implementation must meet. A
guarantee without a test is a wish. A test without a strong oracle
is a ritual. A suite without discipline is theater. vyre's suite
exists to convert every guarantee into a mechanically verifiable
assertion that runs on every commit and fails loudly when any claim
no longer holds.

Specifically, the suite has to prove:

- **Determinism.** Same `Program`, same inputs, same bytes, every run,
  every backend, every device. If this fails, the entire product
  fails.
- **Backend equivalence.** Two conformant backends produce identical
  bytes from identical programs. If this fails, "conformant" is a
  marketing claim, not a technical one.
- **Lowering fidelity.** The IR is the semantic ground truth; the
  lowering to every backend shader language must preserve that
  ground truth exactly. A WGSL output that differs from the intended
  semantics is a compiler bug, not a backend bug.
- **Validation soundness.** Every `Program` that passes validation
  must lower without panic, without undefined behavior, without
  unbounded allocation. Validation is a contract between vyre and
  its consumers, and the contract must be honored.
- **Validation completeness.** Every category of malformed program
  must be caught by at least one validation rule. A program that
  sneaks past validation and breaks lowering is a gap in the rule
  set, which is a bug in vyre.
- **Algebraic law preservation.** Operations that declare laws
  (commutativity, associativity, identity, etc.) must actually obey
  them, for every input, on every backend. A law is a claim about
  mathematics; if vyre breaks the claim, vyre is wrong about
  mathematics, which is not a position you want to defend.
- **IR wire format round-trip identity.** Serializing a Program and
  deserializing it produces the same Program, bit-exact. IR wire format is
  vyre's wire format; if round-trip is lossy, stored Programs can
  silently change meaning between releases.
- **Resource boundedness.** No Program allocates more than its
  declared buffers plus a predictable constant. No Program loops
  forever. No Program recurses without bound. If a user submits a
  program that triggers unbounded resource use, the violation is a
  vyre bug, not a user bug.
- **Stability across versions.** A Program valid under v1.0 is valid
  under v1.1 and produces identical results. This is the "we don't
  break userspace" rule, and vyre is committed to it for the same
  reason Linux is.

Each of these claims is an invariant the suite proves. Part I's next
chapter, [A tour of what can go wrong](a-tour-of-what-can-go-wrong.md),
walks through the specific failure modes that would violate each
invariant and the categories of test that exist to catch them. Part
I's third chapter, [The promises](the-promises.md), presents the full
catalog of fifteen invariants that the suite must prove.

## What makes vyre's suite different from a normal test suite

Most software test suites exist to catch regressions in a codebase
that is expected to change constantly. A regression-catcher suite
tests the behavior the maintainer happens to implement today, with
the goal of noticing when that behavior changes tomorrow. The suite
is a safety net under active development.

vyre's suite is not primarily a regression catcher. It is a
conformance enforcer. The difference is that a regression catcher's
oracle is "what the code does today," while a conformance enforcer's
oracle is "what the specification requires." A regression catcher
passes when the code and the tests agree. A conformance enforcer
passes when the code and the specification agree, as witnessed by
the tests.

This distinction is load-bearing. It is the reason vyre's tests never
derive expected values from the code under test. It is the reason
every test has a declared oracle, and the reason the oracle must be
the strongest one applicable. It is the reason the mutation gate
refuses to accept a test that passes on wrong code. A conformance
test that passes on a broken implementation is not a test — it is a
false claim of correctness, and false claims of correctness in
infrastructure are how users end up with silent data corruption in
production.

The suite's job is not to tell vyre's maintainers "this still works
the way it did yesterday." The suite's job is to tell vyre's users
"this is what the specification guarantees, and you can rely on it."
Those are fundamentally different assertions, backed by fundamentally
different testing discipline.

## The cost and why we pay it

The discipline this book describes is expensive. Writing a test per
op per archetype per oracle across ten primitive operations produces
a lot of tests. Running a mutation gate on each of them takes wall
clock time. Maintaining a regression corpus means never deleting old
tests even when they look redundant. Writing narration for every test
("this exists because," "the oracle is," "the expected value comes
from") takes longer than writing the test itself.

We pay these costs for a specific reason: the promise at the top of
this chapter is not free. A substrate that keeps its word has to earn
that reputation the hard way, one test at a time, for years, before
anyone trusts it enough to build on it. Once the reputation exists,
it is an asset that compounds. NVIDIA does not pay Linux kernel
engineers because Linux is free. They pay because their GPUs have to
work identically on every Linux version going back a decade, and no
other system can make that promise. vyre is building for the same
asset. This book is the cost we pay up front.

The alternative is the graveyard of frameworks that could not
guarantee their own semantics. That is not the future we are building.

## The rest of Part I

The next two chapters establish the motivating context that the rest
of the book depends on. [A tour of what can go wrong](a-tour-of-what-can-go-wrong.md)
walks through the specific failure modes — miscompilation,
nondeterminism, backend drift, composition bugs, validation gaps,
float nondeterminism, and regression — and how each one manifests.
[The promises](the-promises.md) presents the full invariants catalog
and maps each invariant to the test categories that enforce it.

After Part I, the book assumes you know what is at stake and why. Part
II teaches the vocabulary you need to talk about testing vyre
precisely. Part III is the architecture reference. Part IV is the
worked example that ties everything together. The rest of the book
is the discipline that keeps the suite honest in perpetuity.


## The adversarial gauntlet

The test suite is not just a regression catcher. The adversarial gauntlet
runs every Defendant (a deliberately-wrong CPU reference) against the
target op's declared law set. A Defendant that escapes detection
reveals a gap in the law set. See the [Trust Model](../trust-model.md)
for the full Implementor/Prosecutor/Defender framework.
