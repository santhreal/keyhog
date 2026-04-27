# Appendix D — Archetype reference

The complete archetype catalog used by vyre-conform's test
generator and by hand-written tests. Each entry is a
shape of input known to expose bugs in ops with matching
signatures.

The catalog is maintained in
`vyre-conform/src/archetypes/`. This appendix is a
human-readable snapshot. The authoritative source is the
code.

Archetypes are grouped by family: arithmetic (A),
structural (S), composition (C), and backend (X).

---

## Arithmetic archetypes

### A1 — Identity pair

Inputs where one or both operands are the identity element
for the op.

- For `Add`, `Xor`: `(0, 0)`, `(x, 0)`, `(0, x)` for
  arbitrary `x`.
- For `Mul`, `And`: `(1, 1)`, `(x, 1)`, `(1, x)`.

Catches: identity-element special-case bugs in lowering,
fast-path incorrectness.

### A2 — Overflow pair

Inputs that exceed the maximum representable value.

- For unsigned: `(MAX, 1)`, `(MAX, MAX)`, `(N, MAX - N + 1)`
  for small `N`.
- For signed: `(i32::MAX, 1)`, `(i32::MIN, -1)`,
  `(i32::MAX, i32::MAX)`.

Catches: wrapping vs saturating vs panicking overflow
behavior differences.

### A3 — Power-of-two boundary

Inputs involving `2^k`, `2^k + 1`, `2^k - 1` for k in
0..bit_width.

Catches: off-by-one bugs at powers of two, incorrect
comparisons against power-of-two constants.

### A4 — Shift saturation

For shift ops, shift counts at and beyond the bit width.

- `(x, bit_width - 1)`: maximum valid shift.
- `(x, bit_width)`: first masked shift; should equal `(x, 0)`.
- `(x, bit_width + 1)`: should equal `(x, 1)`.
- `(x, 2 * bit_width)`: should equal `(x, 0)`.
- `(x, MAX)`: extreme shift count.

Catches: missing shift masks in lowering, undefined behavior
from over-shift.

### A5 — Bit pattern alternation

Inputs with distinctive bit patterns.

- `0x55555555` (alternating 01).
- `0xAAAAAAAA` (alternating 10).
- `0xF0F0F0F0` (nibble bands).
- `0xDEADBEEF`, `0xCAFEBABE` (adversarial).
- `0x80000000` (sign bit only).
- `0x7FFFFFFF` (all bits except sign).

Catches: bit-level bugs that zero-input tests miss.

### A6 — Division by zero

For ops with a forbidden input, inputs that include the
forbidden value.

- For `Div`, `Mod`: `(x, 0)`.

Catches: inconsistent handling of forbidden inputs across
backends.

### A7 — Self-inverse trigger

Inputs that produce a distinguished result via the op's
self-inverse law.

- For `Xor`: `(x, x) → 0`.
- For `Sub`: `(x, x) → 0`.
- For `Add` (signed): `(x, -x) → 0`.

Catches: operand aliasing bugs, copy vs move confusion.

---

## Structural archetypes

### S1 — Minimum program

The smallest legal Program: single buffer, single op, no
control flow.

Catches: base-case handling bugs in IR construction,
validation, lowering.

### S2 — Maximum nesting

Programs at the configured nesting limit (loops inside
conditionals inside loops), and one past the limit.

Catches: nesting limit off-by-one errors.

### S3 — Node-count boundary

Programs with `max_nodes - 1`, `max_nodes`, `max_nodes + 1`
nodes.

Catches: node count limit off-by-one errors.

### S4 — Dead code

Programs with computations whose results are never used.

Catches: incorrect optimization (removing live code) or
failure to optimize (emitting dead code).

### S5 — Diamond dataflow

Programs with shape `x → (a, b) → merge`.

Catches: common-subexpression elimination bugs, value
duplication vs sharing confusion.

### S6 — Long dependency chain

Programs with N sequential ops depending on the previous
output. N = 1000 typically.

Catches: register allocation failures at scale, temporary
buffer reuse bugs.

### S7 — Wide fanout

Programs where one value is consumed by N operations in
parallel.

Catches: incorrect consumer tracking, shared-value bugs.

### S8 — Workgroup memory contention

All threads in a workgroup write to the same workgroup
memory slot.

Catches: incorrect handling of contended writes.

### S9 — Workgroup memory uniqueness

Each thread writes to its own workgroup memory slot.

Catches: incorrect handling of uncontended writes, index
calculation errors.

### S10 — Atomic contention

All threads perform an atomic add to the same memory slot.

Catches: atomic correctness under contention, ordering
bugs.

### S11 — Off-by-one buffer

Buffer accesses at `len - 1`, `len`, `len + 1`.

Catches: bounds check placement, off-by-one errors.

### S12 — Shadowing attempt

Variable redeclaration in an inner scope.

Catches: shadowing rule (V008) enforcement failures.

### S13 — Barrier under divergent control

Barrier inside a non-uniformly-taken branch.

Catches: divergent barrier rule (V010) enforcement
failures.

### S14 — Type confusion

Passing a value of the wrong type to an op's operand slot.

Catches: type checking (V007, V012) enforcement failures.

### S15 — Empty buffer

Buffer declared with `count = 0`.

Catches: edge case handling for zero-size buffers.

---

## Composition archetypes

### C1 — Identity composition

`f(x)` vs `compose(f, identity)(x)`.

Catches: composition with identity not preserving
semantics.

### C2 — Associativity triple

`(a · b) · c` vs `a · (b · c)` for associative operations.

Catches: reordering bugs, associativity violations.

### C3 — Commutativity swap

`f(a, b)` vs `f(b, a)` for commutative operations.

Catches: operand ordering bugs.

### C4 — Involution pair

`f(f(x))` vs `x` for involutive operations.

Catches: invertibility bugs.

### C5 — Idempotent collapse

`f(f(x))` vs `f(x)` for idempotent operations.

Catches: duplication bugs in idempotent ops.

### C6 — Absorbing short-circuit

`f(absorbing_elem, x)` vs `absorbing_elem`.

Catches: missing or incorrect short-circuit handling.

### C7 — Distributivity cross

`a · (b + c)` vs `(a · b) + (a · c)` for distributing
pairs.

Catches: distributivity violations, incorrect
simplification.

---

## Backend archetypes

### X1 — Single op, every backend

Build a minimal Program with one primitive op and run it
on every registered backend.

Catches: single-op backend bugs.

### X2 — Random program, every backend

Run a random Program (from a deterministic generator) on
every backend.

Catches: bugs in shape combinations not covered by
specific archetype instances.

### X3 — Numerical worst case

Inputs known to stress numerical precision (subnormals,
NaN, infinity, catastrophic cancellation).

Catches: float precision bugs, edge-case handling.

### X4 — Resource saturation

Programs using the maximum of every resource: max threads,
max buffers, max iterations, max workgroup memory.

Catches: resource limit handling bugs, scheduling failures
at the edge.

---

## Applying archetypes to ops

An op declares which archetypes apply to it in its
`OpSpec`:

```rust
archetypes: &[
    &A1_IdentityPair,
    &A2_OverflowPair,
    &A3_PowerOfTwoBoundary,
    &A5_BitPatternAlternation,
    &A7_SelfInverseTrigger,
],
```

The generator iterates the declared archetypes and
instantiates each for the op's signature. Hand-written
tests can also instantiate specific archetypes from the
catalog.

## Adding an archetype

New archetypes are added in response to post-mortems that
reveal a bug class not covered by the existing catalog.
The process:

1. Implement the archetype as a struct in
   `vyre-conform/src/archetypes/`.
2. Define `applies_to` and `instantiate` methods.
3. Add the archetype to the global registry.
4. Write a regression test that uses the archetype and
   references the bug that motivated it.
5. Update this appendix.

Archetypes, like mutations, grow monotonically. Additions
are justified by specific bugs.
