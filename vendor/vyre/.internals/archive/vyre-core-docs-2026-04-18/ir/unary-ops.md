# Unary Operations

## Overview

All unary operations take one `u32` operand and produce one `u32` result.
Every entry is permanent.

## Negate

**Semantics:** `(~a) + 1` (two's complement negation, wrapping)

| Input | Output | Notes |
|-------|--------|-------|
| `0` | `0` | |
| `1` | `0xFFFFFFFF` | |
| `0xFFFFFFFF` | `1` | |
| `0x80000000` | `0x80000000` | Wrapping: negation of MIN_I32 is MIN_I32. |

**Algebraic laws:** Involution (`Negate(Negate(a)) = a`). Bounded: output
range is all of u32 (no restriction).

## BitNot

**Semantics:** `~a` (one's complement, flip all bits)

| Input | Output |
|-------|--------|
| `0` | `0xFFFFFFFF` |
| `0xFFFFFFFF` | `0` |
| `0xFF00FF00` | `0x00FF00FF` |
| `1` | `0xFFFFFFFE` |

**Algebraic laws:** Involution (`BitNot(BitNot(a)) = a`).
DeMorgan with BitAnd/BitOr: `BitNot(BitAnd(a, b)) = BitOr(BitNot(a), BitNot(b))`.
DeMorgan with BitOr/BitAnd: `BitNot(BitOr(a, b)) = BitAnd(BitNot(a), BitNot(b))`.
Complement with identity: `BitAnd(a, BitNot(a)) = 0`.
`BitOr(a, BitNot(a)) = 0xFFFFFFFF`.

## LogicalNot

**Semantics:** `a == 0 ? 1 : 0`

| Input | Output |
|-------|--------|
| `0` | `1` |
| `1` | `0` |
| `42` | `0` |
| `0xFFFFFFFF` | `0` |

**Algebraic laws:** Bounded(0, 1). NOT involution on non-boolean inputs
(`LogicalNot(LogicalNot(42)) = 1`, not `42`). Involution only on boolean
inputs (0 and 1).

## Popcount

**Semantics:** Count of set bits in `a`.

| Input | Output |
|-------|--------|
| `0` | `0` |
| `1` | `1` |
| `0xFF` | `8` |
| `0xFFFFFFFF` | `32` |
| `0x80000001` | `2` |
| `0xAAAAAAAA` | `16` |

**Algebraic laws:** Bounded(0, 32). `Popcount(0) = 0`. `Popcount(0xFFFFFFFF) = 32`.
NOT monotone in the numeric value (`Popcount(3) = 2 > Popcount(4) = 1`).
Relationship: `Popcount(a) + Popcount(BitNot(a)) = 32`.

## Clz

**Semantics:** Count of leading zero bits (from the most significant bit).

| Input | Output | Notes |
|-------|--------|-------|
| `0` | **`32`** | **Clz(0) = 32. Permanent.** |
| `1` | `31` | |
| `0x80000000` | `0` | MSB is set. |
| `0x00010000` | `15` | |
| `0xFFFFFFFF` | `0` | |

**Algebraic laws:** Bounded(0, 32). `Clz(0) = 32`. `Clz(0x80000000) = 0`.
Monotone-decreasing: `a >= b → Clz(a) <= Clz(b)` (more bits set → fewer
leading zeros). NOT monotone-increasing.

## Ctz

**Semantics:** Count of trailing zero bits (from the least significant bit).

| Input | Output | Notes |
|-------|--------|-------|
| `0` | **`32`** | **Ctz(0) = 32. Permanent.** |
| `1` | `0` | LSB is set. |
| `2` | `1` | |
| `0x80000000` | `31` | |
| `0xFFFFFFFF` | `0` | |

**Algebraic laws:** Bounded(0, 32). `Ctz(0) = 32`. `Ctz(1) = 0`.

## ReverseBits

**Semantics:** Reverse the order of all 32 bits. Bit 0 becomes bit 31, bit 1
becomes bit 30, etc.

| Input | Output |
|-------|--------|
| `0` | `0` |
| `1` | `0x80000000` |
| `0x80000000` | `1` |
| `0xFFFFFFFF` | `0xFFFFFFFF` |
| `0x0F0F0F0F` | `0xF0F0F0F0` |

**Algebraic laws:** Involution (`ReverseBits(ReverseBits(a)) = a`).
Preserves popcount: `Popcount(ReverseBits(a)) = Popcount(a)`.

## Permanence

Every row in every table above is permanent. `Clz(0) = 32` will not change.
`Popcount(0xFFFFFFFF) = 32` will not change. These are the ground truth.
