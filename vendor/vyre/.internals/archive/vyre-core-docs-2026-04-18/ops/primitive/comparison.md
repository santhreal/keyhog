# Primitive Comparison Operations

## Overview

Comparison primitives use unsigned `u32` ordering and return `u32` booleans:
`1` for true, `0` for false. The `select` primitive consumes a `u32` condition;
zero is false and non-zero is true. The `logical_not` primitive normalizes any
`u32` to a `0/1` boolean.

## Common Program Shape

```text
let idx = InvocationId(0)
if idx < BufLen(out):
  Store(out, idx, comparison_or_select_expression)
```

## eq

Signature: `(u32, u32) -> u32`.

Semantics: `a == b ? 1 : 0`.

Laws: commutative, reflexive.

IR: `BinOp::Eq`.

## ne

Signature: `(u32, u32) -> u32`.

Semantics: `a != b ? 1 : 0`.

Laws: commutative; `ne(a, a) = 0`.

IR: `BinOp::Ne`.

## lt

Signature: `(u32, u32) -> u32`.

Semantics: unsigned `a < b ? 1 : 0`.

Laws: anti-reflexive, transitive, not commutative.

IR: `BinOp::Lt`.

## gt

Signature: `(u32, u32) -> u32`.

Semantics: unsigned `a > b ? 1 : 0`.

Laws: equivalent to `lt(b, a)`.

IR: `BinOp::Gt`.

## le

Signature: `(u32, u32) -> u32`.

Semantics: unsigned `a <= b ? 1 : 0`.

Laws: reflexive, transitive.

IR: `BinOp::Le`.

## ge

Signature: `(u32, u32) -> u32`.

Semantics: unsigned `a >= b ? 1 : 0`.

Laws: reflexive, transitive.

IR: `BinOp::Ge`.

## select

Signature: `(value: u32, condition: u32) -> u32`.

Semantics: return `value` when `condition != 0`, else `0`.

This is a **conditional mask**, not a general ternary. It wraps the IR-level
`Expr::Select { cond, true_val, false_val }` with `false_val` hardcoded to
`LitU32(0)`. The full ternary `Expr::Select` is available at the IR level for
programs that need an arbitrary false branch; the Layer 1 `select` op provides
the common masking pattern as a convenience primitive.

Laws: no built-in `AlgebraicLaw` is currently declared for this packed binary
form. Semantic properties are `select(value, 0) = 0`,
`condition != 0 -> select(value, condition) = value`, and
`select(0, condition) = 0`.

IR: `Expr::Select { cond: condition, true_val: value, false_val: LitU32(0) }`.

## logical_not

Signature: `(u32) -> u32`.

Semantics: `a == 0 ? 1 : 0`.

Laws: bounded `0/1`; involution only for normalized boolean inputs.

IR: `UnOp::LogicalNot`.

## Logical operations

### `primitive.logical.and`

Returns 1 if both inputs are nonzero, 0 otherwise. This is boolean AND
over u32 values where any nonzero value is "true."

```
logical_and(0, 0) = 0
logical_and(0, 5) = 0
logical_and(3, 7) = 1
logical_and(1, 1) = 1
```

Laws: Commutative, Associative, Absorbing(0), Bounded(0, 1).

Note: Identity and Idempotent do NOT hold because the output is always
0 or 1. `logical_and(5, 5) = 1`, not 5.

WGSL: `select(0u, 1u, input.data[0u] != 0u && input.data[1u] != 0u)`

### `primitive.logical.or`

Returns 1 if either input is nonzero, 0 otherwise.

```
logical_or(0, 0) = 0
logical_or(0, 5) = 1
logical_or(3, 7) = 1
```

Laws: Commutative, Associative, Absorbing(1), Bounded(0, 1).

WGSL: `select(0u, 1u, input.data[0u] != 0u || input.data[1u] != 0u)`
