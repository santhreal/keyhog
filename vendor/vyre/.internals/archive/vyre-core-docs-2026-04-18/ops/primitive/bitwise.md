# Primitive Bitwise Operations

## Overview

Bitwise primitives operate on `u32` words. The canonical binary semantics are in
`ir/binary-ops.md`; unary bit operations are in `ir/unary-ops.md`. This document
specifies what each Layer 1 bitwise `Op` emits as IR.

All example programs use the standard scalar wrapper:

```rust
Program {
    buffers: [input_a, input_b, output],
    workgroup_size: [64, 1, 1],
    entry: [idx bounds check, load operands, store result],
}
```

A scalar call form may inline only the result expression.

## Common Binary Program Shape

For binary op `OP`, the emitted program is:

```text
buffers:
  a: binding 0, ReadOnly, U32
  b: binding 1, ReadOnly, U32
  out: binding 2, ReadWrite, U32
entry:
  let idx = InvocationId(0)
  if idx < BufLen(out):
    Store(out, idx, BinOp(OP, Load(a, idx), Load(b, idx)))
```

## Common Unary Program Shape

For unary op `OP`, the emitted program is:

```text
buffers:
  input: binding 0, ReadOnly, U32
  out: binding 1, ReadWrite, U32
entry:
  let idx = InvocationId(0)
  if idx < BufLen(out):
    Store(out, idx, UnOp(OP, Load(input, idx)))
```

## xor

Signature: `(u32, u32) -> u32`.

Semantics: `a ^ b`.

Laws: commutative, associative, identity `0`, self-inverse `a ^ a = 0`.

IR: common binary shape with `BinOp::BitXor`.

## and

Signature: `(u32, u32) -> u32`.

Semantics: `a & b`.

Laws: commutative, associative, identity `0xFFFFFFFF`, absorbing `0`,
idempotent.

IR: common binary shape with `BinOp::BitAnd`.

## or

Signature: `(u32, u32) -> u32`.

Semantics: `a | b`.

Laws: commutative, associative, identity `0`, absorbing `0xFFFFFFFF`,
idempotent.

IR: common binary shape with `BinOp::BitOr`.

## not

Signature: `(u32) -> u32`.

Semantics: `~a`.

Laws: declared built-in law is involution. De Morgan properties with `and` and
`or` are true semantic properties but are not currently declared in the registry
or checked by the algebra self-test.

IR: common unary shape with `UnOp::BitNot`.

## shl

Signature: `(u32, u32) -> u32`.

Semantics: `a << (amount & 31)`.

Laws: right identity `0`; not commutative; high bits shifted out are discarded.

IR: common binary shape with `BinOp::Shl`.

## shr

Signature: `(u32, u32) -> u32`.

Semantics: logical `a >> (amount & 31)`.

Laws: right identity `0`; not commutative; left bits are zero-filled.

IR: common binary shape with `BinOp::Shr`.

## rotl

Signature: `(u32, u32) -> u32`.

Semantics: rotate left by `r = amount & 31`:

```text
r == 0 ? a : (a << r) | (a >> (32 - r))
```

Laws: no built-in `AlgebraicLaw` is currently declared for rotate. Identity at
`0`, inverse-with-`rotr`, and `popcount` preservation are semantic properties
covered by examples and boundaries until custom cross-op laws are registered.

IR: program emits `let r = amount & 31`, then `Select(Eq(r, 0), a,
BitOr(Shl(a, r), Shr(a, Sub(32, r))))` with explicit safe shift amounts.

## rotr

Signature: `(u32, u32) -> u32`.

Semantics: rotate right by `r = amount & 31`:

```text
r == 0 ? a : (a >> r) | (a << (32 - r))
```

Laws: no built-in `AlgebraicLaw` is currently declared for rotate. Identity at
`0`, inverse-with-`rotl`, and `popcount` preservation are semantic properties
covered by examples and boundaries until custom cross-op laws are registered.

IR: same shape as `rotl`, swapping `Shl` and `Shr`.

## popcount

Signature: `(u32) -> u32`.

Semantics: count set bits, range `0..=32`.

Laws: declared built-in law is `Bounded(0, 32)`. Complement with `not` and
preservation under `reverse_bits` are true semantic properties but are not
currently declared in the registry or checked by the algebra self-test.

IR: common unary shape with `UnOp::Popcount`.

## clz

Signature: `(u32) -> u32`.

Semantics: count leading zero bits; `clz(0) = 32`.

Laws: bounded `0..=32`; `clz(0x80000000) = 0`.

IR: common unary shape with `UnOp::Clz`.

## ctz

Signature: `(u32) -> u32`.

Semantics: count trailing zero bits; `ctz(0) = 32`.

Laws: bounded `0..=32`; `ctz(1) = 0`.

IR: common unary shape with `UnOp::Ctz`.

## reverse_bits

Signature: `(u32) -> u32`.

Semantics: reverse all 32 bit positions.

Laws: involution; preserves `popcount`.

IR: common unary shape with `UnOp::ReverseBits`.

## extract_bits

Signature: `(value: u32, packed: u32) -> u32`.

Semantics: `packed` encodes `offset = packed & 31` and
`count = (packed >> 5) & 31`. Extract `count` bits starting at `offset` into
low bits; `count` is clamped so extraction never crosses bit 31. A zero count
returns `0`.

Laws: no built-in `AlgebraicLaw` is currently declared. The packed format cannot
request count `32`; extracting zero bits returns `0`.

IR: emits `off = packed & 31`, `width = min((packed >> 5) & 31, 32 - off)`,
`mask = width == 32 ? 0xFFFFFFFF : ((1 << width) - 1)`, and stores
`(value >> off) & mask`.

## insert_bits

Signature: `(packed: u32, original: u32) -> u32`.

Semantics: `packed` encodes `offset = packed & 31`,
`count = (packed >> 5) & 31`, and `newbits = packed >> 10`. Replace `count`
bits of `original` starting at `offset` with low bits of `newbits`. Bounds
match `extract_bits`. A zero count returns `original`.

Laws: no built-in `AlgebraicLaw` is currently declared. Zero-width insertion is
right identity for `original`.

IR: emits the same bounded `off`, `width`, and `mask`, then stores:

```text
(base & ~(mask << off)) | ((insert & mask) << off)
```
