# Primitive Operations — the atoms

This chapter documents the Layer 1 primitive operations: the small,
permanent, fully-specified functions that compose everything else in
vyre.

## Why the primitive set matters

The core integer primitive set is built around a design constraint:
every operation that a GPU compute program could ever need must be
expressible as a composition of Layer 1 primitives with zero runtime
overhead.

The constraint is: **every operation that a GPU compute program could
ever need must be expressible as a composition of Layer 1 primitives
with zero runtime overhead.** This means the primitive set must be
*complete* — there must be no computation that requires a new
primitive to express. And it must be *minimal* — there must be no
primitive that can be derived from the others without cost.

Completeness is what makes vyre universal. If a user needs an
operation that cannot be expressed as a composition of primitives,
vyre cannot serve that user. The user must leave the substrate and
write raw WGSL, which defeats the purpose.

Minimality is what makes vyre maintainable. Every primitive is a
permanent commitment. It gets a CPU reference function, algebraic
laws, exhaustive conformance coverage, lowering implementations for
every backend, and a spec entry that can never be removed. A
primitive that could have been a composition wastes all of that
effort.

The primitives are the result of applying both constraints
simultaneously to the domain of GPU integer compute. They are not
the only possible set — a different designer might choose differently
— but they are a *sufficient* set: every integer computation
expressible on a GPU can be built from these atoms, and removing any
one of them would leave a gap that no composition of the others can
fill at the same cost.

## The three families

The primitives fall into three families. The families are not
organizational categories — they reflect different aspects of what
a GPU compute program does with data.

### Bitwise (14 primitives)

`xor`, `and`, `or`, `not`, `shl`, `shr`, `rotl`, `rotr`,
`popcount`, `clz`, `ctz`, `reverse_bits`, `extract_bits`,
`insert_bits`

Bitwise primitives manipulate the individual bits of a `u32` word.
They are the foundation of pattern matching (DFA transitions use
bitwise operations to walk transition tables), cryptography (every
cipher is built from XOR, shift, and rotate), hashing (FNV-1a is
XOR and multiply), data encoding (base64 decode extracts 6-bit
groups with shifts and masks), and general computation (bit flags,
bitmaps, population counting for analytics).

Why fourteen and not fewer? `rotl` and `rotr` can be derived from
`shl`, `shr`, `or`, and `sub`. But the derived version requires five
operations and a conditional to handle the zero-rotation case safely.
The primitive version is one operation. At the IR level the cost is
identical after inlining (Category A). But at the conformance level,
having `rotl` as a named primitive means it gets its own CPU
reference, its own laws (involution, popcount preservation), and its
own conformance entry. This matters because rotate operations are
where GPU shader compilers most commonly introduce bugs — the
boundary between `rotl(x, 0)` and `rotl(x, 32)` is handled
differently by different vendors, and a named primitive with explicit
conformance coverage catches this.

The same argument applies to `extract_bits` and `insert_bits`. They
can be derived from shifts and masks. They are primitives because
bit-field extraction is a common source of off-by-one bugs, and
named primitives with conformance coverage catch those bugs.

### Arithmetic (10 primitives)

`add`, `sub`, `mul`, `div`, `mod`, `min`, `max`, `clamp`, `abs`,
`negate`

Arithmetic primitives compute on `u32` values using wrapping modular
arithmetic (mod 2^32). They are the foundation of indexing (buffer
offsets are computed with `add` and `mul`), loop iteration (induction
variables use `add`), hash computation (FNV-1a's multiply step),
numerical operations (entropy estimation, distance computation,
scoring), and general-purpose computation (counters, accumulators,
statistics).

Two design decisions in the arithmetic family are load-bearing:

**Division by zero returns zero.** This is a deliberate deviation
from hardware behavior (some GPUs return `u32::MAX`, some trap, some
produce undefined results). vyre defines `div(x, 0) = 0` and
`mod(x, 0) = 0` because the alternative is nondeterminism — two
backends producing different results for the same input. Zero is
deterministic, testable, and safe. A program processing untrusted
input must not crash on a division by zero in a computed expression.
The zero result is benign; the crash is not.

**All arithmetic wraps.** `add(u32::MAX, 1) = 0`.
`mul(0x10000, 0x10000) = 0`. There is no overflow trap, no
saturation, no undefined behavior. Wrapping is the hardware's native
behavior for unsigned integers on every GPU. Matching it eliminates
a class of backend-specific divergence (some backends might insert
overflow checks; vyre forbids this).

### Comparison and selection (8 primitives)

`eq`, `ne`, `lt`, `gt`, `le`, `ge`, `select`, `logical_not`

Comparison primitives produce boolean results encoded as `u32`:
`1` for true, `0` for false. All comparisons are unsigned. `select`
is a conditional mask (`value` when condition is non-zero, `0`
otherwise — see [comparison.md](comparison.md) for the distinction
between this op and the IR-level `Expr::Select` ternary).
`logical_not` normalizes any `u32` to a boolean (`0 → 1`,
non-zero → `0`).

The boolean encoding as `u32` is a deliberate choice. GPU hardware
does not have a native boolean type at the storage level — booleans
are `u32` values in storage buffers and uniform buffers. Using `u32`
for comparison results means there is no implicit conversion at
buffer boundaries. What you compute is what you store.

## The algebraic law system

Every primitive declares zero or more algebraic laws. A law is a
mathematical property that the operation must satisfy for every
input on every backend. Laws are not tests — they are claims about
the operation's identity that the conformance suite mechanically
verifies.

The law system is defined in the `vyre-spec` crate as the
`AlgebraicLaw` enum with 14 variants. The laws used by primitives
are:

| Law | Meaning | Example |
|-----|---------|---------|
| `Commutative` | `f(a, b) = f(b, a)` | `add(3, 7) = add(7, 3)` |
| `Associative` | `f(f(a, b), c) = f(a, f(b, c))` | `add(add(1, 2), 3) = add(1, add(2, 3))` |
| `Identity { element }` | `f(a, e) = a` and `f(e, a) = a` | `add(x, 0) = x` |
| `Absorbing { element }` | `f(a, z) = z` and `f(z, a) = z` | `mul(x, 0) = 0` |
| `Idempotent` | `f(a, a) = a` | `and(x, x) = x` |
| `SelfInverse { result }` | `f(a, a) = result` | `xor(x, x) = 0` |
| `Involution` | `f(f(a)) = a` | `not(not(x)) = x` |
| `Bounded { lo, hi }` | output always in `[lo, hi]` | `popcount` in `[0, 32]` |
| `DeMorgan { inner_op, dual_op }` | `not(inner(a, b)) = dual(not(a), not(b))` | `not(and(a, b)) = or(not(a), not(b))` |
| `Monotonic { direction }` | `a <= b` implies ordered output | `clz` is NonIncreasing |
| `Complement { complement_op, universe }` | `f(a) + complement(a) = universe` | `popcount(a) + popcount(not(a)) = 32` |
| `DistributiveOver { over_op }` | `f(a, g(b, c)) = g(f(a, b), f(a, c))` | `and` over `or` |
| `ZeroProduct { holds }` | `f(a, b) = 0 implies a = 0 or b = 0` | false for wrapping `mul` |
| `Custom { name, description, check }` | arbitrary predicate function | user-defined laws |

The first 8 laws are used by primitives today. The remaining 6
(DeMorgan, Monotonic, Complement, DistributiveOver, ZeroProduct,
Custom) are available for compound ops and future primitives. All 14
are defined in `vyre-spec::AlgebraicLaw` and verified by the
conformance suite.

Laws serve three purposes in vyre:

**1. Conformance verification.** The conformance suite tests every
declared law on every op, using exhaustive coverage on the `u8`
domain and witnessed coverage on the `u32` domain. A backend that
violates a law is non-conforming, regardless of whether individual
input-output pairs match.

**2. Composition reasoning.** When two ops compose, the composition
inherits laws from the components under specific rules. If `f` is
commutative and `g` is the identity for `f`'s domain, then
`f(x, g(y)) = f(g(y), x)`. The conformance suite verifies that
composed ops satisfy the laws their components predict. This is
invariant I7 (law monotonicity) from the testing book.

**3. Mutation testing.** The mutation gate includes `LawFalselyClaim`
mutations that declare a law the op does not satisfy (e.g., claiming
`sub` is commutative). If no test kills the mutation, the law system
has a gap — either the law's test is too weak or the law is
decorative. Invariant I9 (law falsifiability) requires every declared
law to be backed by a test that would fail if the law were broken.

### Why some operations declare no laws

Several operations declare zero laws. This is not laziness — it is
precision. `div` declares no laws because none of the standard laws
apply: it is not commutative, not associative, has no identity
element (because `div(0, 0) = 0`, not `0`), and is not idempotent.
The properties that DO hold (`div(x, 1) = x`, `div(0, x) = 0` for
`x != 0`) are one-sided semantic properties, not two-sided algebraic
laws. Declaring them as laws would overstate what the conformance
suite can verify mechanically.

When custom law types are added to the algebra system (e.g., a
`RightIdentity(e)` law that requires only `f(a, e) = a`, not
`f(e, a) = a`), more operations will gain law declarations. Until
then, operations with no applicable two-sided law correctly declare
no laws, and their correctness is verified through spec table rows
and boundary values instead.

## How to read the primitive specs

Each primitive is documented in one of three spec files:

- [Bitwise](bitwise.md) — 14 ops
- [Arithmetic](arithmetic.md) — 10 ops
- [Comparison](comparison.md) — 8 ops

Each op entry contains:

- **Signature.** Input and output types (always `(u32, u32) -> u32`
  for binary ops, `(u32) -> u32` for unary ops).
- **Semantics.** The exact computation, with spec table rows for
  boundary cases.
- **Laws.** Declared algebraic laws.
- **IR.** The `BinOp` or `UnOp` variant and the standard program
  shape used by `program()`.

The spec table rows are permanent. `div(5, 0) = 0` will not change.
`shl(1, 32) = 1` (because `32 & 31 = 0`) will not change. A backend
that produces different results for any spec table row is
non-conforming, today and forever.

## Adding a thirty-third primitive

Adding a new primitive is the heaviest operation in vyre's
specification process. The primitive becomes a permanent commitment:
it cannot be removed, its semantics cannot change, and every backend
must implement it forever. The gate is:

1. **Justify necessity.** The proposed operation must not be
   expressible as a zero-cost composition of existing primitives. If
   it can be composed, it is a Layer 2 compound op, not a primitive.

2. **Define semantics completely.** Every input must produce a
   defined output. No undefined behavior. No "implementation-defined"
   results. The CPU reference function IS the specification.

3. **Declare laws.** Every applicable algebraic law must be declared.
   If the operation is commutative, say so. If it is not, say so and
   explain why.

4. **Write the CPU reference.** A pure Rust function that computes
   the correct output for every input.

5. **Write exhaustive conformance.** Exhaustive on the `u8` domain.
   Witnessed on 100K random `u32` values. Boundary cases for every
   spec table row. Law verification for every declared law.

6. **Implement `program()`.** The op must emit an `ir::Program`.

7. **Pass the mutation gate.** Every applicable mutation must be
   killed by at least one test.

8. **Increment the spec version.**

This process is deliberately heavy. Primitives are permanent. The
cost of adding one that should have been a compound op is paid
forever.

## The complete primitive table

| # | Family | Op | Signature | Key law |
|---|--------|----|-----------|---------|
| 1 | Bitwise | `xor` | `(u32, u32) -> u32` | Commutative, Associative, Identity(0), SelfInverse(0) |
| 2 | Bitwise | `and` | `(u32, u32) -> u32` | Commutative, Associative, Identity(0xFFFFFFFF), Absorbing(0), Idempotent |
| 3 | Bitwise | `or` | `(u32, u32) -> u32` | Commutative, Associative, Identity(0), Absorbing(0xFFFFFFFF), Idempotent |
| 4 | Bitwise | `not` | `(u32) -> u32` | Involution |
| 5 | Bitwise | `shl` | `(u32, u32) -> u32` | — (masked to `b & 31`) |
| 6 | Bitwise | `shr` | `(u32, u32) -> u32` | — (masked to `b & 31`) |
| 7 | Bitwise | `rotl` | `(u32, u32) -> u32` | — |
| 8 | Bitwise | `rotr` | `(u32, u32) -> u32` | — |
| 9 | Bitwise | `popcount` | `(u32) -> u32` | Bounded(0, 32) |
| 10 | Bitwise | `clz` | `(u32) -> u32` | Bounded(0, 32) |
| 11 | Bitwise | `ctz` | `(u32) -> u32` | Bounded(0, 32) |
| 12 | Bitwise | `reverse_bits` | `(u32) -> u32` | Involution |
| 13 | Bitwise | `extract_bits` | `(u32, u32) -> u32` | — |
| 14 | Bitwise | `insert_bits` | `(u32, u32) -> u32` | — |
| 15 | Arithmetic | `add` | `(u32, u32) -> u32` | Commutative, Associative, Identity(0) |
| 16 | Arithmetic | `sub` | `(u32, u32) -> u32` | SelfInverse(0) |
| 17 | Arithmetic | `mul` | `(u32, u32) -> u32` | Commutative, Associative, Identity(1), Absorbing(0) |
| 18 | Arithmetic | `div` | `(u32, u32) -> u32` | — (div by zero = 0) |
| 19 | Arithmetic | `mod` | `(u32, u32) -> u32` | SelfInverse(0) |
| 20 | Arithmetic | `min` | `(u32, u32) -> u32` | Commutative, Associative, Idempotent |
| 21 | Arithmetic | `max` | `(u32, u32) -> u32` | Commutative, Associative, Idempotent |
| 22 | Arithmetic | `clamp` | `(u32, u32) -> u32` | — (packed bounds) |
| 23 | Arithmetic | `abs` | `(u32) -> u32` | — (signed interpretation) |
| 24 | Arithmetic | `negate` | `(u32) -> u32` | Involution |
| 25 | Comparison | `eq` | `(u32, u32) -> u32` | Commutative, Bounded(0,1) |
| 26 | Comparison | `ne` | `(u32, u32) -> u32` | Commutative, Bounded(0,1) |
| 27 | Comparison | `lt` | `(u32, u32) -> u32` | Bounded(0,1) |
| 28 | Comparison | `gt` | `(u32, u32) -> u32` | Bounded(0,1) |
| 29 | Comparison | `le` | `(u32, u32) -> u32` | Bounded(0,1) |
| 30 | Comparison | `ge` | `(u32, u32) -> u32` | Bounded(0,1) |
| 31 | Comparison | `select` | `(u32, u32) -> u32` | — (conditional mask) |
| 32 | Comparison | `logical_not` | `(u32) -> u32` | Bounded(0,1) |

Every row in this table is permanent.

The library has since expanded beyond these 32 core integer primitives
to include floating-point operations (add, mul, sin, cos, sqrt, etc.),
saturation arithmetic, and extended math (gcd, lcm, sign). All new
primitives follow the same permanence rule: once admitted, they never
change.

## See also

- [Operations Overview](../overview.md)
- [Bitwise](bitwise.md)
- [Arithmetic](arithmetic.md)
- [Comparison](comparison.md)

