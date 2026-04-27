# Binary Operations

## Overview

All binary operations take two `u32` operands and produce one `u32` result
unless otherwise noted. All arithmetic uses wrapping semantics (mod 2^32).

Every entry in this document is permanent. The semantics of an operation cannot
change once defined. Two independent backend implementors reading this document
must produce identical output bytes for identical input bytes.

## Arithmetic

### Add

**Semantics:** `(a + b) mod 2^32`

Wrapping unsigned addition. Overflow wraps to zero.

| Input | Output | Notes |
|-------|--------|-------|
| `(0, 0)` | `0` | |
| `(1, 1)` | `2` | |
| `(0xFFFFFFFF, 1)` | `0` | Wrapping overflow. |
| `(0xFFFFFFFF, 0xFFFFFFFF)` | `0xFFFFFFFE` | |

**Algebraic laws:** Commutative, Associative, Identity(0).

### Sub

**Semantics:** `(a - b) mod 2^32`

Wrapping unsigned subtraction. Underflow wraps.

| Input | Output | Notes |
|-------|--------|-------|
| `(5, 3)` | `2` | |
| `(0, 1)` | `0xFFFFFFFF` | Wrapping underflow. |
| `(0, 0)` | `0` | |

**Declared algebraic laws:** SelfInverse(0), because `a - a = 0`. `a - 0 = a`
is true as a one-sided semantic property, but it is not the two-sided
`Identity(0)` law. NOT commutative. NOT associative.

### Mul

**Semantics:** `(a * b) mod 2^32`

Low 32 bits of the full 64-bit product.

| Input | Output | Notes |
|-------|--------|-------|
| `(3, 7)` | `21` | |
| `(0x10000, 0x10000)` | `0` | Overflow: full product is 0x100000000. |
| `(0xFFFFFFFF, 2)` | `0xFFFFFFFE` | |

**Declared algebraic laws:** Commutative, Associative, Identity(1),
Absorbing(0), and `ZeroProduct { holds: false }` because wrapping
multiplication can produce zero from nonzero operands.

### Div

**Semantics:** `a / b` (truncating unsigned division)

**Division by zero produces zero.** This is a deliberate deviation from
hardware behavior (some GPUs return `u32::MAX`, some trap). vyre defines it as
zero because:
- It is deterministic across all backends.
- It does not crash.
- It produces a well-defined, testable result.
- The conformance suite verifies it.

| Input | Output | Notes |
|-------|--------|-------|
| `(10, 3)` | `3` | Truncating. |
| `(5, 0)` | **`0`** | **Div by zero = 0. Permanent.** |
| `(0, 0)` | **`0`** | |
| `(0xFFFFFFFF, 1)` | `0xFFFFFFFF` | |
| `(0xFFFFFFFF, 0xFFFFFFFF)` | `1` | |

**Declared algebraic laws:** none. `a / 1 = a` and `0 / b = 0` are true
one-sided semantic properties, but neither is currently registered as a
built-in `AlgebraicLaw`. NOT commutative. NOT associative.

### Mod

**Semantics:** `a % b` (truncating unsigned remainder)

**Modulo by zero produces zero.** Same rationale as Div.

| Input | Output | Notes |
|-------|--------|-------|
| `(10, 3)` | `1` | |
| `(5, 0)` | **`0`** | **Mod by zero = 0. Permanent.** |
| `(0, 5)` | `0` | |

**Declared algebraic laws:** SelfInverse(0), because `a % a = 0` for every
`a`, including the defined `0 % 0 = 0`. `a % 1 = 0` for all a.

## Bitwise

### BitAnd

**Semantics:** `a & b`

| Input | Output |
|-------|--------|
| `(0xFF00, 0x0FF0)` | `0x0F00` |
| `(0xFFFFFFFF, x)` | `x` |
| `(0, x)` | `0` |

**Algebraic laws:** Commutative, Associative, Identity(0xFFFFFFFF), Idempotent,
Absorbing(0). Distributive over BitOr.

### BitOr

**Semantics:** `a | b`

| Input | Output |
|-------|--------|
| `(0xFF00, 0x00FF)` | `0xFFFF` |
| `(0, x)` | `x` |
| `(0xFFFFFFFF, x)` | `0xFFFFFFFF` |

**Algebraic laws:** Commutative, Associative, Identity(0), Idempotent,
Absorbing(0xFFFFFFFF). Distributive over BitAnd.

### BitXor

**Semantics:** `a ^ b`

| Input | Output |
|-------|--------|
| `(0xFF, 0xFF)` | `0` |
| `(0xFF, 0x00)` | `0xFF` |
| `(0, x)` | `x` |

**Algebraic laws:** Commutative, Associative, Identity(0), SelfInverse(0).
NOT distributive over BitAnd or BitOr.

### Shl

**Semantics:** `a << (b & 31)`

The shift amount is **masked to 5 bits** (0..31). `a << 32` is `a << 0` = `a`.
This matches WGSL behavior and eliminates undefined shift semantics.

| Input | Output | Notes |
|-------|--------|-------|
| `(1, 0)` | `1` | |
| `(1, 1)` | `2` | |
| `(1, 31)` | `0x80000000` | |
| `(1, 32)` | **`1`** | **Masked: 32 & 31 = 0.** |
| `(0xFFFFFFFF, 1)` | `0xFFFFFFFE` | High bit shifted out. |

**Declared algebraic laws:** none. `a << 0 = a` is a true one-sided semantic
property, but it is not the two-sided `Identity(0)` law. NOT commutative.

### Shr

**Semantics:** `a >> (b & 31)`

Logical (unsigned) right shift. Masked to 5 bits. Zero-fills from the left.

| Input | Output | Notes |
|-------|--------|-------|
| `(0x80000000, 1)` | `0x40000000` | Logical, not arithmetic. |
| `(1, 1)` | `0` | |
| `(1, 32)` | **`1`** | **Masked: 32 & 31 = 0.** |

**Declared algebraic laws:** none. `a >> 0 = a` is a true one-sided semantic
property, but it is not the two-sided `Identity(0)` law. NOT commutative.

## Comparison

All comparison operations return `u32`: `1` for true, `0` for false. All
comparisons are **unsigned** unless explicitly noted.

### Eq

**Semantics:** `a == b ? 1 : 0`

**Declared algebraic laws:** Commutative, SelfInverse(1), Bounded(0, 1).

### Ne

**Semantics:** `a != b ? 1 : 0`

**Declared algebraic laws:** Commutative, SelfInverse(0), Bounded(0, 1).

### Lt

**Semantics:** `a < b ? 1 : 0` (unsigned comparison)

`0xFFFFFFFF` is the largest value. `0` is the smallest.

| Input | Output | Notes |
|-------|--------|-------|
| `(0, 1)` | `1` | |
| `(1, 0)` | `0` | |
| `(5, 5)` | `0` | Not strictly less. |
| `(0xFFFFFFFE, 0xFFFFFFFF)` | `1` | Unsigned: 0xFFFFFFFE < 0xFFFFFFFF. |

**Declared algebraic laws:** SelfInverse(0), Bounded(0, 1). NOT commutative.
Anti-reflexive and transitive are true semantic properties.

### Gt

**Semantics:** `a > b ? 1 : 0` (unsigned)

Equivalent to `Lt(b, a)`.

**Declared algebraic laws:** SelfInverse(0), Bounded(0, 1).

### Le

**Semantics:** `a <= b ? 1 : 0` (unsigned)

Equivalent to `1 - Lt(b, a)`.

**Declared algebraic laws:** SelfInverse(1), Bounded(0, 1).

### Ge

**Semantics:** `a >= b ? 1 : 0` (unsigned)

Equivalent to `1 - Lt(a, b)`.

**Declared algebraic laws:** SelfInverse(1), Bounded(0, 1).

## Logical

### And

**Semantics:** `(a != 0) && (b != 0) ? 1 : 0`

Logical AND. Operands are interpreted as booleans: zero is false, non-zero is
true. Result is `u32`: 1 or 0.

| Input | Output |
|-------|--------|
| `(0, 0)` | `0` |
| `(1, 0)` | `0` |
| `(0, 1)` | `0` |
| `(1, 1)` | `1` |
| `(42, 7)` | `1` |

**Declared algebraic laws:** none for this IR `BinOp`. Commutative,
Associative, Identity(1), and Absorbing(0) hold for the normalized boolean
truth table, but `And(a, a) = 1` for any nonzero `a`, so full-domain
idempotence over `u32` is false.

### Or

**Semantics:** `(a != 0) || (b != 0) ? 1 : 0`

| Input | Output |
|-------|--------|
| `(0, 0)` | `0` |
| `(1, 0)` | `1` |
| `(0, 1)` | `1` |
| `(42, 7)` | `1` |

**Declared algebraic laws:** none for this IR `BinOp`. Commutative,
Associative, Identity(0), and absorbing nonzero truthiness hold for the
normalized boolean truth table, but there is no single `u32` absorbing element
under the formal two-sided `Absorbing(z)` law.

## Permanence

Every row in every table above is permanent. The semantics of `Div(5, 0) = 0`
will not change in any future version of vyre. A backend that produces `0` for
`Div(5, 0)` today will still be conforming in 2036. A backend that does not
will never be conforming.
