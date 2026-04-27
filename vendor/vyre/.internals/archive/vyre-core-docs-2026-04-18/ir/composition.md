# IR Composition

## Overview

Composition is how small vyre programs become larger programs without adding a
runtime abstraction cost. An `Expr::Call` names another operation and passes
value arguments. During lowering or optimization, the callee is expanded into
the caller with fresh local names and substituted arguments. After expansion,
there is only one straight IR program to lower.

Composition is semantic, not dynamic dispatch. There is no GPU function pointer,
heap object, virtual call, or hidden buffer sharing.

## Call Semantics

A call has the form:

```rust
Expr::Call {
    op_id: "primitive.bitwise.xor".to_string(),
    args: vec![a, b],
}
```

The callee is resolved by `op_id` in the operation registry available to the
compiler. The argument list must match the callee `OpSignature` exactly:

- same arity,
- each argument type assignable to the corresponding input type,
- output type known at validation time,
- no implicit casts except those represented by explicit `Expr::Cast` nodes.

Calls are value calls. Each argument expression is evaluated in the caller's
scope and substituted for the callee parameter value. The callee cannot mutate an
argument by reference because arguments are not references.

## Buffer Isolation

A callee does not see the caller's buffers. The only values visible to the callee
are its arguments and constants inside the callee program.

This rule has three consequences:

1. No hidden aliasing: the callee cannot accidentally write to a caller buffer.
2. No hidden dependencies: the callee cannot depend on undeclared global state.
3. No backend-specific calling ABI: the lowered code is ordinary expressions and
   statements after inlining.

If an operation must read or write buffers, it is not a scalar call. It must be a
`Program` with explicit `BufferDecl` values or an engine-level composition that
wires buffers deliberately.

## Inline Expansion

Inlining expands the callee body at the call site.

For a scalar primitive with conceptual body:

```text
fn xor(a: u32, b: u32) -> u32 {
    return a ^ b
}
```

this caller expression:

```text
Call("primitive.bitwise.xor", [Load("left", idx), Load("right", idx)])
```

becomes:

```text
BinOp(BitXor, Load("left", idx), Load("right", idx))
```

For a callee containing local statements, expansion creates fresh local names so
callee names cannot collide with caller names:

```text
caller temp -> temp
callee temp -> __call17_temp
```

The inliner must preserve statement order and expression evaluation. It must not
change atomic, load, store, barrier, or return semantics.

## Composing Two Operations

Two operations compose when the output expression of the first operation becomes
an input expression of the second operation.

Example:

```text
A: xor(a, b) -> u32
B: popcount(x) -> u32
B(A(a, b)) = popcount(xor(a, b))
```

IR after composition:

```text
UnOp(Popcount,
    BinOp(BitXor,
        Load("a", idx),
        Load("b", idx)))
```

No intermediate output buffer is required unless the author explicitly stores
one. If the composed expression is stored once, lowering emits one assignment to
the final output.

## Type Compatibility

A call is type-compatible only when each input position is satisfied by the
callee signature.

| Case | Valid? | Rule |
|------|--------|------|
| `U32 -> U32` | Yes | Exact match. |
| `Bool -> Bool` | Yes | Exact match. |
| `Bool -> U32` | No implicit conversion | Use `Cast { target: U32, value }`. |
| `U32 -> Bool` | No implicit conversion | Use `Cast { target: Bool, value }`. |
| `U64 -> Vec2U32` | No implicit conversion | Use explicit cast even though representation is shared. |
| `Bytes -> U32` | No | Load a byte or word explicitly. |

The validator rejects arity mismatch, unknown `op_id`, unsupported casts,
missing return values, and any call whose output type cannot be inferred.

## No Aliasing

Because calls pass values, not buffer views, aliases cannot be created through
composition. A primitive cannot observe whether two caller expressions came from
the same buffer. It only receives values.

Engine-level programs may use multiple `BufferDecl` values that refer to host
buffers. Any aliasing at that level is controlled by the runtime binding layer
and must be validated before dispatch. Scalar `Expr::Call` does not create or
hide aliases.

## Zero-Cost Property

Composition is zero-cost because it vanishes before backend execution.

Pipeline:

```text
Program with Call nodes
  -> resolve op_id
  -> inline callee with value substitution
  -> optimize expression tree
  -> lower final Program
```

The GPU sees only the lowered code. There is no dynamic call, no interpreter
step, and no extra dispatch. A composed primitive should lower to the same WGSL
as a handwritten expression with the same operations.

## Errors

Composition errors must be actionable:

- Unknown operation: `Fix: register an Op with id primitive.bitwise.xor before lowering.`
- Arity mismatch: `Fix: pass 2 arguments to primitive.bitwise.xor.`
- Type mismatch: `Fix: insert Cast { target: U32, value } or call an op with a Bool input.`
- Buffer access in scalar call: `Fix: expose the required value as an argument or compose at Program level.`

## Permanence

Calls are inline, value-argument composition. Callees do not see caller buffers.
No aliasing is introduced by calls. The zero-cost property is part of the IR
contract, not an optimizer preference.
