# Archetypes — the shapes of bad inputs

## You do not invent adversarial inputs

The first time a contributor writes a test for a new op, the hardest
part is picking the inputs. What numbers should the test use? Zero
and one are obvious. Maybe the maximum value. Maybe a random-looking
hex constant. After that, the well runs dry. The contributor guesses,
commits the test, and moves on — and the test does not catch the
bugs that a contributor with more experience would have caught with
inputs that look bizarre but are in fact load-bearing.

The hardest part is picking the inputs because the contributor is
being asked to solve a problem they have no principled way to
approach. "What inputs expose bugs in this op?" is a question that
requires knowing which bugs are possible in this op, which inputs
would trigger those bugs, and which combinations have historically
caught real defects in similar systems. That knowledge is not
obvious. It is accumulated by reading GPU compiler bug reports,
reading compiler verification papers, reading historical
post-mortems from vendors, and sitting next to experienced engineers
for years. It is not the sort of knowledge a new contributor or an
agent can conjure in the moment.

vyre solves this by refusing to ask the question. You do not have
to invent adversarial inputs. The archetype catalog has already
enumerated the shapes that matter. You pick the archetypes whose
signatures match your op, instantiate them for your op's types, and
the catalog does the thinking.

This chapter introduces the archetype catalog, explains the
categories of archetypes, and shows how to map from an op's
signature to the archetypes that apply to it. After reading this
chapter, you never have to stare at a blank test file wondering
which numbers to type.

## What an archetype is

An archetype is a *shape* of input, not a specific value. "Identity
pair" is an archetype. Its shape is "one or more values drawn from
the set of identity elements for the op's domain." For `BinOp::Add`
over `u32`, the identity element is `0`, so the archetype
instantiates to inputs like `(0, 0)`, `(x, 0)`, `(0, x)` for
various `x`. For `BinOp::Mul` over `u32`, the identity element is
`1`, so the same archetype instantiates differently.

An archetype knows how to instantiate itself for an op's signature
because the archetype trait carries the logic:

```rust
pub trait Archetype: Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn applies_to(&self, signature: &OpSignature) -> bool;
    fn instantiate(&self, op: &OpSpec) -> Vec<TestInput>;
}
```

The `applies_to` method filters archetypes by signature. An
arithmetic archetype applies to ops with arithmetic signatures but
not to ops that accept arbitrary byte buffers. The `instantiate`
method produces the concrete test inputs given the specific op's
spec. The archetype author writes these two methods once, and the
archetype becomes a permanent tool in the catalog.

Archetypes are defined in `vyre-conform/src/archetypes/` and
organized into four groups: arithmetic, structural, composition,
and backend. Each group catches a different class of bug.

## Arithmetic archetypes

Arithmetic archetypes target bugs in operations that manipulate
numeric values. They are the first archetypes a contributor reaches
for when testing a primitive op like `Add`, `Mul`, `Shl`, or `Xor`.

### A1 — Identity pair

The identity element of an op is the value that, combined with any
other value, returns the other value unchanged. For `Add`, the
identity is `0`: `add(x, 0) = x` and `add(0, x) = x`. For `Mul`,
it is `1`. For `Xor`, it is `0`. For `And`, it is the all-ones
value for the type.

Why this archetype exists: identity elements are frequently
special-cased in implementations. A lowering might have a fast path
for "one of the operands is the identity" that skips the operation
entirely. If the fast path is wrong, the bug fires only when the
identity is present, which is exactly what this archetype
instantiates.

Instantiation for `Add` over `u32`:
- `(0, 0)`: both operands are the identity.
- `(0xDEADBEEF, 0)`: right operand is the identity.
- `(0, 0xDEADBEEF)`: left operand is the identity.
- `(0, 1)`: identity with a simple non-identity.

Each pair is a test. The test asserts `run(program) == expected`
using a specification table row as the oracle. If the lowering's
fast path is wrong, at least one of the pairs exposes it.

### A2 — Overflow pair

Overflow pairs are input combinations that push the operation past
the maximum (or minimum, for signed types) representable value.
For `Add` over `u32`, the canonical overflow pairs are `(u32::MAX,
1)`, `(u32::MAX, u32::MAX)`, and `(2^31 - 1, 2^31)`. Each tests a
specific overflow behavior.

Why: overflow is where wrapping, saturating, and undefined behavior
differ. A lowering that should wrap but saturates silently produces
wrong output for overflow-adjacent inputs. A lowering that should
produce defined wrap behavior but triggers a sanitizer in debug
mode is broken. Overflow pairs expose all of these.

Instantiation for `Add` over `u32`:
- `(u32::MAX, 1)`: minimal overflow case, expected `0`.
- `(u32::MAX, u32::MAX)`: double-max, expected `u32::MAX - 1`.
- `(0x80000000, 0x80000000)`: sign-bit boundary, expected `0`.
- `(u32::MAX - 1, 2)`: just into overflow.

Each is a spec table row with a rationale explaining the expected
wrap behavior.

### A3 — Power-of-two boundary

Power-of-two values are where bit-level operations often change
behavior. Every `2^k` for `k` in `0..32` is a candidate, and so is
every `2^k - 1` and `2^k + 1`. Instantiation produces a sweep.

Why: shift operators, mask operations, and comparisons often have
special handling around powers of two. A shift by exactly 31 is
defined; a shift by 32 is undefined in some languages and masked
in others. Testing every power-of-two boundary catches
off-by-one-on-the-boundary bugs.

Instantiation for `Shl` over `u32`:
- `(x, 0)`, `(x, 1)`, `(x, 31)`, `(x, 32)`, `(x, 33)`, `(x, u32::MAX)`
  for a representative `x` (typically `1`, to make the output
  predictable).

The archetype produces all of these for every applicable op.

### A4 — Shift saturation

Shift saturation tests the specific case of shift counts near or
exceeding the bit width of the type. The vyre specification says
shift counts are masked (`count & 31` for `u32`), which means
`shl(x, 32) == shl(x, 0) == x`. An implementation that does not
mask produces undefined behavior or wrong results.

Why: shift masking is the most common source of lowering bugs in
GPU compilers. Every backend has a different native shift behavior,
and the lowering must insert the mask to normalize. A missing mask
is a silent bug that passes ordinary tests and fails only at the
boundary.

Instantiation for `Shl` over `u32`:
- `(x, 31)`: maximum valid shift.
- `(x, 32)`: first masked shift; expected same as `(x, 0)`.
- `(x, 33)`: second masked shift; expected same as `(x, 1)`.
- `(x, 63)`: large masked shift.
- `(x, u32::MAX)`: extreme masked shift.

Each case has a spec table row with rationale. The mutation
`LowerRemoveShiftMask` in the mutation catalog deliberately removes
the mask from the lowering; an A4 test must kill that mutation.

### A5 — Bit pattern alternation

Bit-pattern alternation uses values where the bit pattern is
distinctive enough that a bug is unlikely to coincidentally produce
the right answer. The classic values are `0x55555555` (alternating
01), `0xAAAAAAAA` (alternating 10), `0xF0F0F0F0` (nibble bands),
`0xDEADBEEF`, `0xCAFEBABE`, and zero-extended and one-extended
versions of small values.

Why: a bug that flips a bit in the implementation is invisible if
the input is zero, because zero XOR anything is itself. The same
bug is obvious if the input is an alternating pattern, because a
single bit flip is immediately visible in the output. Tests that
use alternating patterns catch bit-level bugs that tests on round
numbers miss.

Instantiation for `Xor` over `u32`:
- `(0x55555555, 0xAAAAAAAA) = 0xFFFFFFFF`
- `(0xF0F0F0F0, 0x0F0F0F0F) = 0xFFFFFFFF`
- `(0xDEADBEEF, 0xCAFEBABE) = 0x14570455`

Expected values come from a spec table. The rationale explains why
the pattern is interesting.

### A6 — Division zero

Division by zero is the canonical "operation on a forbidden input"
case. For ops that have a forbidden input (division, modulo),
the archetype instantiates all inputs with the forbidden value in
every position and asserts the test rejects the program at
validation or produces a well-defined error at runtime.

Why: forbidden inputs are often handled inconsistently. One
backend produces a runtime error; another produces a NaN-like
value; a third produces undefined behavior. The vyre specification
pins down the expected behavior (typically rejection at
validation), and the test asserts every path is consistent.

Instantiation for `Div` over `u32`:
- `(x, 0)` for a representative `x`.

The test asserts validation rejects the Program or runtime returns
a specific error, depending on the spec.

### A7 — Self-inverse trigger

A self-inverse pair is an input `(a, b)` where the operation
produces a distinguished result that reveals the presence of an
invertibility law. For `Xor`, `(x, x) = 0` — the self-inverse.
For `Sub`, `(x, x) = 0`. For `Add`, `(x, -x) = 0` in signed
arithmetic.

Why: self-inverse inputs reveal whether the implementation
correctly handles the case where both operands depend on the same
underlying value. A lowering that silently aliases or copies
operands can produce wrong results on self-inverse inputs that are
invisible when the operands are independent.

Instantiation for `Xor` over `u32`:
- `(0xDEADBEEF, 0xDEADBEEF) = 0`
- `(0, 0) = 0`
- `(u32::MAX, u32::MAX) = 0`

## Structural archetypes

Structural archetypes target bugs in the IR construction, the
validator, and the lowering — bugs that depend on the shape of the
Program rather than the specific values of its inputs. They apply
to every op that can appear in a Program, which is every op.

### S1 — Minimum program

The minimum program is the smallest legal Program: one buffer, one
op, no control flow. For `BinOp::Add`, it is a Program with two
input buffers of `u32`, one output buffer, and a single Add node.
Every op has a minimum program, and every test suite for that op
should include one.

Why: minimum programs catch bugs in the base case of IR
construction, validation, and lowering. A lowering that works for
complex programs but fails on the minimum is revealing a bug in
its minimum-case handling.

Instantiation: the archetype builds the smallest legal Program for
the op and asserts lowering produces a valid shader.

### S2 — Maximum nesting

Maximum nesting pushes the Program structure to the configured
nesting limit: loops inside conditionals inside loops, up to the
limit and then one past it. The test asserts the limit is enforced
(one-past rejected) and programs at the limit work correctly.

Why: nesting limits are edge cases that are often wrong. A limit
of `N` might be off by one in the enforcement code, accepting
`N+1` or rejecting `N`. A test at the boundary exposes either
error.

### S3 — Node-count boundary

Similar to S2 but for the total node count limit rather than
nesting depth. The archetype builds programs with exactly
`max_nodes - 1`, `max_nodes`, and `max_nodes + 1` nodes and
asserts the validator's behavior at each.

### S4 — Dead code

A Program that contains computations whose results are never used.
The lowering must not emit the dead code (for efficiency) but must
also not incorrectly optimize away live code that it mistakes for
dead. The archetype builds programs with various dead-code shapes
and asserts the lowered output is smaller (dead code removed) while
the live output remains correct.

### S5 — Diamond dataflow

A Program where one value flows into two operations and both
results feed into a merge. The shape `x → (a, b) → merge` is the
simplest diamond. The archetype exercises the lowering's handling
of shared dataflow to catch bugs where the same value is read twice
but computed twice.

Why: diamonds are where data-flow optimizations happen. An
incorrect common-subexpression elimination might merge two
computations that are not actually the same, or duplicate a
computation that should be shared. The archetype's inputs expose
both kinds of bug.

### S6 — Long dependency chain

A linear chain of `N` sequential ops, where each op depends on the
previous one's output. For `N = 1000`, the chain tests the
lowering's handling of long dependency sequences and catches bugs
where register allocation or temporary buffer reuse fails at
scale.

### S7 — Wide fanout

The inverse of S6: one value consumed by `N` ops in parallel. Tests
the lowering's handling of many consumers of a single value.

### S8 — Workgroup memory contention

All threads write to the same workgroup memory index. Tests the
lowering's handling of contended memory accesses and the backend's
atomic semantics when contention is forced.

### S9 — Workgroup memory uniqueness

Every thread writes to its own workgroup memory index. Tests the
lowering's handling of uncontended accesses.

### S10 — Atomic contention

All threads perform an atomic add to the same memory slot. Tests
atomic correctness under contention; the test asserts the final
value equals the sum of the increments regardless of ordering.

### S11 — Off-by-one buffer

Buffer accesses at `index = len - 1`, `len`, and `len + 1`. The
first is a valid boundary case; the second and third are
out-of-range. The archetype asserts the validator or the runtime
handles each correctly (valid, rejected, graceful error).

### S12 — Shadowing attempt

A variable declaration that shadows an existing declaration. The
Program is invalid and must be rejected by validation. The test
asserts the rejection.

### S13 — Barrier under divergent control

A workgroup barrier inside a conditional branch that is not
uniformly taken by all threads. The Program is invalid under
vyre's rules (barriers must be uniformly reachable). The test
asserts the rejection.

### S14 — Type confusion

A Program that passes a value of one type where another type is
expected — for example, passing a `u32` to an op signature that
expects `f32`. The validator must reject the Program with a type
error.

### S15 — Empty buffer

A buffer declared with `count = 0`. The archetype tests whether
the validator accepts or rejects the empty buffer (the rule is
spec-dependent), and if accepted, whether ops that access it
behave correctly.

## Composition archetypes

Composition archetypes target bugs in how ops combine. They apply
when a test exercises a Program with more than one op.

### C1 — Identity composition

A Program that composes an op with an identity transformation (no-op).
The composition should produce the same result as the op alone. The
archetype asserts `run(f(x)) == run(compose(f, identity)(x))`.

Why: composition with identity is the simplest form of composition.
A lowering that fails on this case is failing on a case that
contains no additional complexity.

### C2 — Associativity triple

Three ops composed under an associative operation, arranged both
left-associated and right-associated. The archetype asserts
`(a · b) · c == a · (b · c)` for every associative op.

Why: associativity is the most commonly violated law in compiled
code, because compilers often reorder associative operations for
optimization. If the ordering changes the result (as it does for
floats in non-strict mode), associativity is broken. A test
catches the break immediately.

### C3 — Commutativity swap

Two ops composed with arguments in both orders. Asserts
`f(a, b) == f(b, a)` for every commutative op.

### C4 — Involution pair

A pair of ops where the second undoes the first (for example,
`xor(x, k)` followed by `xor(result, k)` should recover `x`). The
archetype asserts the round-trip.

### C5 — Idempotent collapse

Two applications of the same idempotent op. Asserts `f(f(x)) ==
f(x)`. Examples: `min(min(x, y), y) == min(x, y)`.

### C6 — Absorbing short-circuit

An op combined with its absorbing element. For `And` over
booleans, the absorbing element is `false`: `false AND x == false`
regardless of `x`. The archetype tests the short-circuit.

### C7 — Distributivity cross

Two ops where one distributes over the other. Asserts `a · (b + c)
== (a · b) + (a · c)` for every distributing pair.

## Backend archetypes

Backend archetypes specifically target cross-backend equivalence.
They are the tests that prove invariant I3.

### X1 — Single op, every backend

For each primitive op, the archetype builds a minimal Program and
runs it on every registered backend, asserting every backend
produces bit-identical output. This is the bread-and-butter
backend equivalence test.

### X2 — Random program, every backend

A random Program (drawn from a deterministic generator) is run on
every backend. Byte-identical output is required. The randomness
covers shapes that hand-crafted tests do not, catching bugs in
lowering paths that only fire on unusual structures.

### X3 — Numerical worst case

A specific set of inputs chosen because they are known to stress
the numerical precision of the operation. For floating-point ops,
these include subnormals, NaN, infinities, and values near the
representable limits. The archetype asserts every backend produces
bit-identical output for each worst case.

### X4 — Resource saturation

A Program that uses the maximum of every resource vyre permits:
maximum threads, maximum buffer size, maximum iterations, maximum
workgroup memory. The archetype asserts the Program runs
successfully and produces consistent output.

Why: resource saturation is where backend implementations differ.
A backend that handles the typical case correctly may fail at the
limit. X4 catches these failures before users hit them.

## How the archetype catalog is used

When you write a test for an op, you select the archetypes that
apply to the op's signature (the archetype's `applies_to` method
filters them for you), and for each applicable archetype, you
instantiate one or more tests.

For `BinOp::Add` over `u32`, the applicable archetypes are A1
(identity pair), A2 (overflow pair), A3 (power-of-two boundary),
A5 (bit pattern alternation), A7 (self-inverse trigger) — and from
the structural set, S1 (minimum program), S6 (long dependency
chain), S11 (off-by-one buffer, indirectly, via the backing
buffers). The worked example in Part IV goes through each
archetype instantiation for `Add` and explains the resulting
tests.

You do not have to invent the archetypes each time. The catalog
enumerates them. You do not have to guess which apply — the
`applies_to` method filters for you. You do not have to guess what
inputs to use — the `instantiate` method produces them. Your job is
to write the test wrapper that dispatches the instantiated inputs
through the pipeline and asserts the result against the oracle.

The generator in vyre-conform automates this one step further:
given an OpSpec, it runs the catalog, filters, instantiates,
selects oracles via the hierarchy, and emits complete test
functions. Hand-written tests and generated tests share the same
archetype catalog, so the two are always consistent.

## Adding a new archetype

The archetype catalog grows. When a bug reaches production that
none of the existing archetypes would have caught, the correct
response is to add a new archetype that captures the bug's shape.
The new archetype becomes part of every future test suite for
every applicable op, and the bug class is covered forever.

A new archetype needs:

- An **id** and a **name**.
- A **description** explaining what class of bug it catches and
  why the existing catalog was insufficient.
- An **applies_to** function that identifies the signatures it
  handles.
- An **instantiate** function that produces the concrete inputs.
- **At least one regression test** using the archetype, committed
  to `vyre/tests/regression/` and referencing the bug that
  motivated the archetype.

Adding archetypes is a rare event. The existing catalog covers
most bugs; new archetypes are reserved for bugs that reveal a gap
in the enumeration.

## What archetypes are not

Archetypes are not a complete enumeration of every possible bug.
They are a representative enumeration of the shapes that have
caught bugs historically and are likely to catch bugs in the
future. The mutation gate and the oracle hierarchy exist to catch
what archetypes miss.

Archetypes are not property tests. A property test generates
random inputs and asserts an invariant. An archetype instantiates
specific inputs chosen for their shape, not randomly. The two are
complementary: archetypes catch known bug classes; properties
catch unknown ones.

Archetypes are not the same as adversarial inputs. Adversarial
inputs are specifically hostile: malformed, too large, too
nested, deliberately crafted to break things. Archetypes are
legitimate inputs that happen to be in shapes that expose bugs.
An overflow pair is a legitimate arithmetic input; a program with
a billion nodes is an adversarial input. Both have their place —
archetypes in integration testing, adversarial inputs in
`tests/adversarial/`.

## Reference

[Appendix D](appendices/D-archetypes.md) contains the complete
current archetype catalog with every archetype's id, name,
description, applies_to logic, and canonical instantiations. The
appendix is the authoritative reference; this chapter is the
conceptual introduction.

Next: Part III opens with [Architecture](architecture.md), the
directory-layout reference chapter that describes the physical
organization of the test suite.
