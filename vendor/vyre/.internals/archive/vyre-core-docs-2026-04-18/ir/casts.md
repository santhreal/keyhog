# Cast Semantics

## Overview

`Expr::Cast { target, value }` converts a value from one `DataType` to another.
Every supported source-target pair has a defined result. Unsupported pairs are
validation errors; no cast is lowered with undefined behavior.

## Complete Cast Table

| Source    | Target    | Semantics | Example |
|-----------|-----------|-----------|---------|
| `U32`     | `U32`     | Identity. | `42 → 42` |
| `U32`     | `I32`     | Bitcast (reinterpret bits). | `0xFFFFFFFF → -1` |
| `U32`     | `Bool`    | `0 → 0 (false)`, non-zero → `1 (true)`. | `0 → 0`, `7 → 1` |
| `U32`     | `U64`     | Zero-extend. Value preserved. | `42 → (42, 0)` as vec2 |
| `U32`     | `Vec2U32` | Splat to both components. | `5 → (5, 5)` |
| `U32`     | `Vec4U32` | Splat to all four components. | `5 → (5, 5, 5, 5)` |
| `U32`     | `Bytes`   | Not supported. `V023` validation error. | — |
| `I32`     | `I32`     | Identity. | `-1 → -1` |
| `I32`     | `U32`     | Bitcast (reinterpret bits). | `-1 → 0xFFFFFFFF` |
| `I32`     | `Bool`    | `0 → 0 (false)`, non-zero → `1 (true)`. | `0 → 0`, `-1 → 1` |
| `I32`     | `U64`     | Sign-extend to 64-bit, then store as (low, high). | `-1 → (0xFFFFFFFF, 0xFFFFFFFF)` |
| `I32`     | `Vec2U32` | Bitcast to u32, then splat. | `-1 → (0xFFFFFFFF, 0xFFFFFFFF)` |
| `I32`     | `Vec4U32` | Bitcast to u32, then splat. | `-1 → (0xFFFF.., 0xFFFF.., 0xFFFF.., 0xFFFF..)` |
| `I32`     | `Bytes`   | Not supported. `V023` validation error. | — |
| `Bool`    | `U32`     | `false → 0`, `true → 1`. | `true → 1` |
| `Bool`    | `I32`     | `false → 0`, `true → 1`. | `true → 1` |
| `Bool`    | `Bool`    | Identity. | `true → true` |
| `Bool`    | `U64`     | `false → (0, 0)`, `true → (1, 0)`. | — |
| `Bool`    | `Vec2U32` | `false → (0, 0)`, `true → (1, 1)`. | — |
| `Bool`    | `Vec4U32` | `false → (0,0,0,0)`, `true → (1,1,1,1)`. | — |
| `Bool`    | `Bytes`   | Not supported. `V023` validation error. | — |
| `U64`     | `U32`     | Truncate: take low 32 bits. | `(0xDEAD, 0xBEEF) → 0xDEAD` |
| `U64`     | `I32`     | Truncate to low 32 bits, reinterpret as i32. | `(0xFFFFFFFF, 0) → -1` |
| `U64`     | `Bool`    | `(0, 0) → false`, else → `true`. | `(1, 0) → true` |
| `U64`     | `U64`     | Identity. | — |
| `U64`     | `Vec2U32` | Identity (U64 IS vec2<u32>). | — |
| `U64`     | `Vec4U32` | Not supported. Validation error. | — |
| `U64`     | `Bytes`   | Not supported. `V023` validation error. | — |
| `Vec2U32` | `U32`     | Take component 0. | `(3, 7) → 3` |
| `Vec2U32` | `I32`     | Take component 0, reinterpret. | `(0xFFFFFFFF, 0) → -1` |
| `Vec2U32` | `U64`     | Identity (Vec2U32 IS U64 storage). | — |
| `Vec2U32` | `Vec2U32` | Identity. | — |
| `Vec2U32` | `Bool`    | `(0, 0) → false`, else → `true`. | — |
| `Vec2U32` | `Vec4U32` | Not supported. Validation error. | — |
| `Vec2U32` | `Bytes`   | Not supported. `V023` validation error. | — |
| `Vec4U32` | `U32`     | Take component 0. | `(1,2,3,4) → 1` |
| `Vec4U32` | `I32`     | Take component 0, reinterpret. | — |
| `Vec4U32` | `Vec2U32` | Take components 0 and 1. | `(1,2,3,4) → (1,2)` |
| `Vec4U32` | `Vec4U32` | Identity. | — |
| `Vec4U32` | `Bool`    | `(0,0,0,0) → false`, else → `true`. | — |
| `Vec4U32` | `U64`     | Take components 0 and 1 as (low, high). | `(1,2,3,4) → (1,2)` |
| `Vec4U32` | `Bytes`   | Not supported. `V023` validation error. | — |
| `Bytes`   | `Bytes`   | Identity. | — |
| `Bytes`   | non-`Bytes` | Not supported. Validation error. | — |

## Rules

1. **Identity casts are always valid.** `Cast { target: T, value }` where value
   is already type T is a no-op.

2. **Bitcast for same-size scalars.** U32 ↔ I32 is a bit reinterpretation with
   no value change. The 32 bits are the same; only the type interpretation
   changes.

3. **Bool is u32 on GPU.** `false = 0`, `true = 1`. Converting to Bool:
   `0 → false`, any non-zero → `true`. Converting from Bool: `false → 0`,
   `true → 1`. There are no other Bool values.

4. **Truncation takes low bits.** U64 → U32 takes the low 32 bits (component 0
   of vec2). Vec4 → Vec2 takes components 0 and 1. Vec2 → U32 takes component
   0. Information is lost.

5. **Extension preserves value.** U32 → U64 zero-extends (high = 0). I32 → U64
   sign-extends.

6. **Splat fills all components.** U32 → Vec2 puts the value in both components.
   U32 → Vec4 puts it in all four.

7. **Bytes only casts to itself.** Bytes is a variable-length buffer. It cannot
   be cast to or from scalar or vector types. A `Bytes -> Bytes` cast is the
   normal identity-cast rule. Any non-`Bytes` source cast to `Bytes` is rejected
   with `V023: cast to Bytes is unsupported in WGSL lowering. Fix: use buffer
   load/store directly for byte data.`

8. **Unsupported casts are validation errors.** Cast pairs outside the table are
   caught at Program validation time. A backend that does not yet implement a
   validation-supported target must return an actionable lowering error rather
   than inventing different semantics.

## Canonical Layout

Scalar and vector casts use a fixed little-lane layout. The reference
interpreter and every lowering must agree on these component meanings:

| Type | Storage lanes | Meaning |
|------|---------------|---------|
| `Bool` | one logical u32 lane | `0` is false, `1` is true. |
| `U32` | one u32 lane | Bits `0..31` of the integer. |
| `I32` | one i32 lane | Same 32 physical bits as `U32`, interpreted as two's-complement signed. |
| `U64` | `vec2<u32>` | lane 0 is bits `0..31`; lane 1 is bits `32..63`. |
| `Vec2U32` | `vec2<u32>` | lane 0 then lane 1, unchanged by vector identity casts. |
| `Vec4U32` | `vec4<u32>` | lanes 0, 1, 2, 3 in increasing component order. |
| `Bytes` | runtime-sized u32 storage elements | Not a scalar value; only identity casts are valid. |

`U64` and `Vec2U32` share the same physical two-lane layout. A cast between
them is a type-level reinterpretation, not a byte reorder.

## Rounding And Overflow

The stable cast table contains no numeric narrowing cast that rounds. Integer
casts are identity, bit reinterpretation, boolean normalization, extension,
truncation, splat, or component selection.

Overflow does not trap. The behavior is fully specified:

- `U32 -> U64`: zero-extends; lane 1 is `0`.
- `I32 -> U64`: sign-extends; lane 1 is `0xffff_ffff` when the sign bit is set
  and `0` otherwise.
- `U64 -> U32` and `Vec2U32 -> U32`: return lane 0 and discard lane 1.
- `Vec4U32 -> U32`: returns lane 0 and discards lanes 1 through 3.
- `Vec4U32 -> Vec2U32` and `Vec4U32 -> U64`: return lanes 0 and 1 and discard
  lanes 2 and 3.
- `U32/I32/Bool -> Vec*`: duplicate or extend exactly as stated in the table.

Boolean normalization always returns the canonical value `0` or `1`. Any
non-zero scalar or any vector with at least one non-zero lane casts to `true`.
There are no NaN, infinity, saturation, implementation-defined overflow, or
rounding-mode cases in the stable table.

## Reference Interpreter Semantics

The reference interpreter must implement casts by first evaluating the source
expression, then applying the table entry exactly:

1. Determine the source `DataType` from validation.
2. Reject unsupported pairs before execution; the interpreter must not attempt a
   best-effort conversion.
3. Represent `U64` as `(lo: u32, hi: u32)`.
4. Represent `Vec2U32` as `(x: u32, y: u32)`.
5. Represent `Vec4U32` as `(x: u32, y: u32, z: u32, w: u32)`.
6. Apply bitcasts without changing the underlying 32-bit pattern.
7. Apply truncation by selecting the documented low lane.
8. Apply extension by writing documented high lanes.
9. Apply boolean normalization after evaluating all source lanes.

For `Bytes`, the interpreter may pass through the original byte-buffer handle
for `Bytes -> Bytes`. Every other `Bytes` cast is a validation error because
the source has variable length and no single scalar lane layout.

## Planned casts (not yet in source)

The following casts will be added when their source and target types are
promoted to stable. Their semantics are specified here for forward
compatibility. **Programs cannot use these casts today.**

| Source    | Target    | Semantics |
|-----------|-----------|-----------|
| `U128`    | `U128`    | Identity. |
| `U128`    | `U32`     | Truncate: take component 0 (lowest 32 bits). |
| `U128`    | `I32`     | Truncate to component 0, reinterpret as i32. |
| `U128`    | `U64`     | Take components 0 and 1 as (low, high). |
| `U128`    | `Vec2U32` | Take components 0 and 1. |
| `U128`    | `Vec4U32` | Identity (U128 IS vec4<u32>). |
| `U128`    | `Bool`    | `(0,0,0,0) → false`, else → `true`. |
| `U32`     | `U128`    | Zero-extend: `(value, 0, 0, 0)`. |
| `I32`     | `U128`    | Sign-extend to 128-bit. |
| `U64`     | `U128`    | Zero-extend: `(low, high, 0, 0)`. |
| `Vec2U32` | `U128`    | Zero-extend: `(c0, c1, 0, 0)`. |
| `Vec4U32` | `U128`    | Identity (Vec4U32 IS U128 storage). |
| `Bool`    | `U128`    | `false → (0,0,0,0)`, `true → (1,0,0,0)`. |
| `F32`     | `U32`     | IEEE 754 binary32 to u32 bitcast. |
| `U32`     | `F32`     | u32 to IEEE 754 binary32 bitcast. |
| `F16`     | `F32`     | Lossless promotion. |
| `F32`     | `F16`     | Round-to-nearest-even truncation. |
| `BF16`    | `F32`     | Lossless promotion. |
| `F32`     | `BF16`    | Round-to-nearest-even truncation. |

Float casts follow strict IEEE 754 rounding. No vendor-specific
rounding modes. No fast-math approximations.

## Permanence

This table is permanent. Once a cast is defined, its semantics cannot change.
New source-target pairs are added when their types are promoted from planned
to stable. Existing entries are immutable.
