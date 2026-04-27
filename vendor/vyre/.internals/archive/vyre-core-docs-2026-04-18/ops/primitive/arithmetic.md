# Primitive Arithmetic Operations

## Overview

Arithmetic primitives operate on `u32` words unless noted. Addition,
subtraction, multiplication, and negation wrap modulo `2^32`. Division and
modulo by zero return `0`; this is permanent and matches `ir/binary-ops.md`.

## Common Program Shape

Binary arithmetic emits:

```text
let idx = InvocationId(0)
if idx < BufLen(out):
  Store(out, idx, BinOp(OP, Load(a, idx), Load(b, idx)))
```

Unary arithmetic emits the same pattern with one input buffer and a `UnOp` or
composed expression.

## add

Signature: `(u32, u32) -> u32`.

Semantics: `(a + b) mod 2^32`.

Laws: commutative, associative, identity `0`.

IR: binary shape with `BinOp::Add`.

## sub

Signature: `(u32, u32) -> u32`.

Semantics: `(a - b) mod 2^32`.

Laws: right identity `0`; not commutative; not associative.

IR: binary shape with `BinOp::Sub`.

## mul

Signature: `(u32, u32) -> u32`.

Semantics: low 32 bits of `a * b`.

Laws: commutative, associative, identity `1`, absorbing `0`.

IR: binary shape with `BinOp::Mul`.

## div

Signature: `(u32, u32) -> u32`.

Semantics: unsigned truncating division. `a / 0 = 0`.

Laws: right identity `1`; left absorbing `0` for non-zero divisors; not
commutative.

IR: binary shape with `BinOp::Div`. Lowering must emit a zero-divisor guard.

## mod

Signature: `(u32, u32) -> u32`.

Semantics: unsigned remainder. `a % 0 = 0`.

Laws: `a % 1 = 0`; result is `< b` when `b != 0`.

IR: binary shape with `BinOp::Mod`. Lowering must emit a zero-divisor guard.

## min

Signature: `(u32, u32) -> u32`.

Semantics: unsigned minimum.

Laws: commutative, associative, idempotent.

IR: emits `Select(Le(a, b), a, b)` or a backend `min(a, b)` helper with
identical unsigned semantics.

## max

Signature: `(u32, u32) -> u32`.

Semantics: unsigned maximum.

Laws: commutative, associative, idempotent.

IR: emits `Select(Ge(a, b), a, b)` or a backend `max(a, b)` helper with
identical unsigned semantics.

## clamp

Signature: `(value: u32, bounds: u32) -> u32`.

Semantics: `bounds` packs `lo = bounds & 0xFFFF` and
`hi = (bounds >> 16) | lo`, then returns `value.clamp(lo, hi)`. The packed
encoding guarantees `hi >= lo`; there is no separate normalization step.

Laws: no built-in `AlgebraicLaw` is currently declared for this binary packed
form. The semantic checks are boundary and equivalence-class driven.

IR: emits packed-bound extraction, then composed unsigned `max` and `min`
expressions or an equivalent backend helper.

## abs

Signature: `(u32) -> u32`.

Semantics: interpret input as `i32`, return absolute value as `u32`. The value
`0x80000000` maps to `0x80000000` because two's-complement absolute value wraps.

Laws: no built-in `AlgebraicLaw` is currently declared. The key conformance
edges are non-negative signed encodings, negative signed encodings, and
`i32::MIN`.

IR: emits an explicit signed-interpretation helper or an equivalent composition
that preserves `abs(i32::MIN) = 0x80000000`.

## negate

Signature: `(u32) -> u32`.

Semantics: two's-complement wrapping negation, `0 - a`.

Laws: involution; `negate(0) = 0`.

IR: unary shape with `UnOp::Negate`.
