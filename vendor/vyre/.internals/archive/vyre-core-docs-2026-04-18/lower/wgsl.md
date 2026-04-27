# WGSL Lowering

## Overview

WGSL is the reference lowering target for vyre IR. A conforming WGSL lowering
turns one `ir::Program` into one complete WebGPU compute shader. The generated
shader must preserve all vyre semantics:

- Wrapping integer arithmetic
- Div/Mod by zero returning zero
- Shift amounts masked to `b & 31`
- OOB loads returning zero, OOB stores no-oping
- Sequentially consistent atomics
- **Strict IEEE 754 for float ops**: no FMA fusion, no reduction reordering,
  no subnormal flush, correctly-rounded transcendentals, declared tensor
  core accumulator precision preserved (see `types.md` → "Float Semantics")
- No runtime dispatch or interpretation — every Program lowers to one
  specialized shader with all ops inlined (Category A+C rule, see
  `ir/categories.md`)

## Program Shape

A lowered program has this shape:

```wgsl
@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

@compute @workgroup_size(64, 1, 1)
fn main(
    @builtin(global_invocation_id) global_invocation_id: vec3<u32>,
    @builtin(workgroup_id) workgroup_id: vec3<u32>,
    @builtin(local_invocation_id) local_invocation_id: vec3<u32>,
) {
    // lowered Node list
}
```

All buffers are in `@group(0)`. `BufferDecl::binding` becomes `@binding(N)`.
The entry point name is `main` unless a backend-specific wrapper chooses another
stable name.

## Type Mapping

| IR type | WGSL expression type | WGSL storage type |
|---------|----------------------|-------------------|
| `U32` | `u32` | `array<u32>` |
| `I32` | `i32` | `array<i32>` or bit-identical `array<u32>` with casts |
| `U64` | `vec2<u32>` | `array<vec2<u32>>` |
| `Vec2U32` | `vec2<u32>` | `array<vec2<u32>>` |
| `Vec4U32` | `vec4<u32>` | `array<vec4<u32>>` |
| `Bool` | `bool` in conditions, `u32` at buffer boundaries | `array<u32>` with `0/1` encoding |
| `Bytes` | byte extraction from `u32` words | `array<u32>` packed little-endian |

Atomic buffers use `array<atomic<u32>>` for `U32` elements that are targeted by
`Expr::Atomic`.

## BufferDecl Mapping

| BufferAccess | WGSL declaration |
|--------------|------------------|
| `ReadOnly` | `@group(0) @binding(N) var<storage, read> name: array<T>;` |
| `ReadWrite` | `@group(0) @binding(N) var<storage, read_write> name: array<T>;` |
| `Uniform` | `@group(0) @binding(N) var<uniform> name: T;` or a uniform struct/array wrapper |
| `Workgroup` | `var<workgroup> name: array<T, N>;` |

Buffer names must be sanitized into valid WGSL identifiers. The mapping must be
stable and collision-free.

## Node Mapping

| IR node | WGSL construct |
|---------|----------------|
| `Node::Let { name, value }` | `let name = expr;` when immutable value is sufficient; `var name = expr;` when assigned by a later `Node::Assign`. |
| `Node::Assign { name, value }` | `name = expr;` |
| `Node::Store { buffer, index, value }` | `if (idx < arrayLength(&buffer)) { buffer[idx] = value; }` unless robust no-op store is proven. |
| `Node::If { cond, then, otherwise }` | `if (bool(cond)) { lowered then nodes } else { lowered otherwise nodes }` |
| `Node::Loop { var, from, to, body }` | `for (var i = from; i < to; i = i + 1u) { lowered body nodes }` |
| `Node::Return` | `return;` |
| `Node::Block(nodes)` | `{ lowered block nodes }` preserving statement order. |
| `Node::Barrier` | `storageBarrier(); workgroupBarrier();` when storage visibility and workgroup rendezvous are both required. |

`Let` may lower to `var` instead of `let` when the variable is assigned by a
later `Node::Assign`.
The observable semantics are unchanged.

## Expr Mapping

| IR expression | WGSL construct |
|---------------|----------------|
| `LitU32(v)` | `vu`, for example `42u`. |
| `LitI32(v)` | `vi`, for example `-7i`. |
| `LitBool(v)` | `true` or `false` in expression position; `1u` or `0u` at `u32` boundaries. |
| `Var(name)` | sanitized local identifier. |
| `Load { buffer, index }` | `select(buffer[idx], zero(T), idx >= arrayLength(&buffer))` or direct robust load when guaranteed by WebGPU. |
| `BufLen { buffer }` | `arrayLength(&buffer)` for runtime arrays. |
| `InvocationId { axis }` | `global_invocation_id.x/y/z`. |
| `WorkgroupId { axis }` | `workgroup_id.x/y/z`. |
| `LocalId { axis }` | `local_invocation_id.x/y/z`. |
| `BinOp { op, left, right }` | operator or helper listed below. |
| `UnOp { op, operand }` | operator or WGSL builtin listed below. |
| `Call { op_id, args }` | inline-expanded callee expression or generated helper call after inlining. |
| `Select { cond, true_val, false_val }` | `select(false_val, true_val, bool(cond))`; both branch expressions are evaluated. |
| `Cast { target, value }` | explicit constructor, bitcast, or helper according to `casts.md`. |
| `Atomic { op, buffer, index, expected, value }` | WGSL atomic builtin with OOB guard; returns old value. `CompareExchange` passes `expected` and replacement `value` separately. |

## Binary Operation Mapping

| IR BinOp | WGSL lowering |
|----------|---------------|
| `Add` | `left + right` |
| `Sub` | `left - right` |
| `Mul` | `left * right` |
| `Div` | `select(left / right, 0u, right == 0u)` |
| `Mod` | `select(left % right, 0u, right == 0u)` |
| `BitAnd` | `left & right` |
| `BitOr` | `left | right` |
| `BitXor` | `left ^ right` |
| `Shl` | `left << (right & 31u)` |
| `Shr` | `left >> (right & 31u)` |
| `Eq` | `select(0u, 1u, left == right)` |
| `Ne` | `select(0u, 1u, left != right)` |
| `Lt` | `select(0u, 1u, left < right)` |
| `Gt` | `select(0u, 1u, left > right)` |
| `Le` | `select(0u, 1u, left <= right)` |
| `Ge` | `select(0u, 1u, left >= right)` |
| `And` | `select(0u, 1u, bool(left) && bool(right))` |
| `Or` | `select(0u, 1u, bool(left) || bool(right))` |

`bool(x)` means `x != 0u` for `u32` expressions and the value itself for Bool
expressions.

## Unary Operation Mapping

| IR UnOp | WGSL lowering |
|---------|---------------|
| `Negate` | `0u - operand` for `u32`, `-operand` for `i32`. |
| `BitNot` | `~operand` |
| `LogicalNot` | `select(0u, 1u, operand == 0u)` |
| `Popcount` | `countOneBits(operand)` |
| `Clz` | `countLeadingZeros(operand)` |
| `Ctz` | `countTrailingZeros(operand)` |
| `ReverseBits` | `reverseBits(operand)` |

## Atomic Mapping

| IR AtomicOp | WGSL |
|-------------|------|
| `Add` | `atomicAdd(&buffer[idx], value)` |
| `Or` | `atomicOr(&buffer[idx], value)` |
| `And` | `atomicAnd(&buffer[idx], value)` |
| `Xor` | `atomicXor(&buffer[idx], value)` |
| `Min` | `atomicMin(&buffer[idx], value)` |
| `Max` | `atomicMax(&buffer[idx], value)` |
| `Exchange` | `atomicExchange(&buffer[idx], value)` |
| `CompareExchange` | `atomicCompareExchangeWeak(&buffer[idx], expected, value).old_value` |

Every atomic must be guarded:

```wgsl
var old = 0u;
if (idx < arrayLength(&buffer)) {
    old = atomicAdd(&buffer[idx], value);
}
```

OOB atomics return zero and do not modify the buffer.

## Complete Shader Requirements

A complete WGSL shader must include:

1. Declarations for every `BufferDecl`.
2. Helper functions required for casts, byte loads, `U64` emulation, and safe
   access.
3. One `@compute` entry point using the program workgroup size.
4. Builtin parameters for every identity expression used by the program.
5. Lowered entry statements in original order.
6. No dead helper that changes observable behavior or masks validation errors.

## Validation Before Lowering

The WGSL lowerer expects valid IR. Validation must reject undeclared buffers,
invalid axes, stores to read-only buffers, duplicate bindings, unknown calls,
unsupported casts, and variables used before binding.

The lowerer may still return structured errors for target limits or impossible
WGSL generation. It must not panic.

## Permanence

WGSL is the reference backend. Other backends may lower differently internally,
but their observable bytes must match the WGSL reference for every valid program.
