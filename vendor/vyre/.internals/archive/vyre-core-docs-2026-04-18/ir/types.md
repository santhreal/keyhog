# IR Types

This document defines the core type system of vyre IR. Every public type in `vyre::ir::types` is specified here.

---

## `DataType`

`DataType` is the set of value types that can appear in buffers, expressions, and casts.

### Stable types (implemented in source)

These types exist as variants of `DataType` in the current crate, have
lowering support, and are covered by the conformance suite. Programs using
only stable types work today on every conforming backend.

| Variant   | Size | WGSL mapping | Semantics |
|-----------|------|--------------|-----------|
| `U32`     | 4 bytes | `u32` | Unsigned 32-bit integer. Wrapping arithmetic modulo 2³². |
| `I32`     | 4 bytes | `i32` | Signed 32-bit integer. Two's-complement wrapping arithmetic. |
| `U64`     | 8 bytes | `vec2<u32>` | Unsigned 64-bit integer, emulated as `(low, high)`. |
| `Vec2U32` | 8 bytes | `vec2<u32>` | Two-component vector of `u32`. |
| `Vec4U32` | 16 bytes | `vec4<u32>` | Four-component vector of `u32`. |
| `Bool`    | 4 bytes | `u32` (0/1) | Boolean stored as `0` = false, `1` = true. |
| `Bytes`   | 0+ | `array<u32>` (byte view) | Variable-length byte buffer. |

### Planned types (specified but not yet in source)

These types are part of the vyre specification and will be added to `DataType`
as `#[non_exhaustive]` variants when their supporting operations, lowering
paths, and conformance coverage are ready. Their semantics are defined here so
that backend authors and op authors can plan for them, but **programs cannot
use them today**. A program that references a planned type will fail at
construction time until the variant is added to the crate.

The planned types are listed in the order they are expected to be implemented.

| Variant   | Size | WGSL mapping | Semantics | Why planned, not stable |
|-----------|------|--------------|-----------|------------------------|
| `U128`    | 16 bytes | `vec4<u32>` | Unsigned 128-bit integer, emulated as 4×u32. | Shares storage with `Vec4U32`; needs distinct cast/arithmetic ops to distinguish intent. |
| `F32`     | 4 bytes | `f32` | **Strict** IEEE 754 binary32. See Float Semantics below. | Requires float `BinOp`/`UnOp` variants (`FAdd`, `FMul`, `FSin`, etc.), strict lowering constraints, and CR-Math conformance infrastructure. |
| `F16`     | 2 bytes | `f16` | **Strict** IEEE 754 binary16. See Float Semantics below. | Depends on `F32` infrastructure plus half-precision lowering. |
| `BF16`    | 2 bytes | `u16` + ops | **Strict** bfloat16 (1-8-7). See Float Semantics below. | Non-standard format requiring explicit emulation on backends without native bfloat16. |
| `Tensor`  | 0+ | `array<T>` + strides | Multi-dimensional view over a flat buffer with element type and shape. | Requires shape/stride validation, dynamic dimension support, and tensor-specific lowering. |

When a planned type is promoted to stable, its `DataType` variant is added,
its operations are added to `BinOp`/`UnOp` (for float types) or as new
expression nodes (for tensors), its lowering is implemented, and its
conformance tests are committed. The promotion is a minor version bump. Existing
programs are unaffected because `DataType` is `#[non_exhaustive]`.

### Float Semantics — deterministic via restriction

When float types are promoted to stable, vyre will support floating-point
with **strict IEEE 754 semantics**. GPU
floating-point has historically been nondeterministic not because floats are
inherently nondeterministic but because backends were permitted to fuse,
reorder, and approximate. vyre forbids every such permission at the IR level.
The result is bit-exact IEEE 754 results across every conforming backend.

**Forbidden patterns (permanent):**

1. **FMA fusion.** `FMul(a, b) + FAdd(·, c)` is two roundings. It is never
   lowered to a hardware FMA. For one rounding, contributors explicitly use
   `FMulAdd(a, b, c)`.
2. **Reduction reordering.** `FReduceStrict` is sequential. `FReduceTreeBinary`
   is a canonical balanced tree. Unordered reductions are forbidden.
3. **Subnormal flushing.** Subnormals are always preserved. Backends must
   disable flush-to-zero mode.
4. **Vendor transcendentals.** `FSin`, `FCos`, `FExp`, `FLog`, etc. must be
   correctly-rounded per IEEE 754-2019 (CR-Math). Vendor fast-math libraries
   are forbidden.
5. **Division/sqrt approximations.** `FDiv` and `FSqrt` must be correctly
   rounded. Hardware `rcp`/`rsqrt` approximations are forbidden.
6. **Tensor core precision downgrade.** `MatMul { accumulator: F32 }` must use
   F32 accumulators. Silent TF32 substitution is forbidden.

Approximate operations (`FReduceApprox`, `FSinApprox`, etc.) are separate ops
with declared ULP tolerance. They are explicitly labeled approximate and are
verified against their tolerance, not bit-exact. Approximate and strict never
mix in the same conformance certificate.

For the full float operation catalog and conformance rules see
`vyre-conform/SPEC.md` → "Float semantics — strict IEEE 754" and
`vyre-conform/docs/certification/levels.md` → "Float track (L1f-L4f)".

### Tensor Layout

A `Tensor` is a multi-dimensional view over a flat backing buffer with
explicit strides:

```rust
pub struct TensorType {
    pub element: Box<DataType>,  // F16, F32, BF16, U32, etc.
    pub shape: Vec<Dim>,          // [batch, seq, heads, dim]
    pub strides: Vec<u32>,        // Row-major by default; explicit when needed
}

pub enum Dim {
    Static(u32),         // Compile-time constant
    Dynamic(&'static str), // Resolved at dispatch time from a uniform
}
```

Dynamic dimensions support LLM-style variable sequence length: the shape is
declared at IR construction time with a `Dynamic("seq_len")` placeholder and
resolved at dispatch time by reading a uniform buffer. This preserves
determinism — the shape is fixed for each dispatch, just not at IR time.

Out-of-bounds access on tensors follows buffer semantics: load returns zero
of the element type, store is a no-op.

### `Bytes` Layout

`Bytes` buffers are stored as packed little-endian `u32` words. Byte `i` lives
in word `i / 4` and lane `i % 4`, where lane `0` is the least-significant byte
of the word.

`BufLen` on a `Bytes` buffer returns the number of backing `u32` words, not the
number of logical bytes. Logical byte length must be carried separately by the
engine or host parameter block when padding bytes matter.

### Example

```rust
use vyre::ir::DataType;

assert_eq!(DataType::U32.min_bytes(), 4);
assert_eq!(DataType::U64.min_bytes(), 8);
assert_eq!(DataType::Bytes.min_bytes(), 0);
```

---

## `BufferAccess`

`BufferAccess` controls how a buffer may be used inside a program.

| Variant    | Readable | Writable | Atomic | Typical use |
|------------|----------|----------|--------|-------------|
| `ReadOnly` | Yes      | No       | No     | Input data arrays. |
| `ReadWrite`| Yes      | Yes      | Yes    | Output or scratch buffers. |
| `Uniform`  | Yes      | No       | No     | Small configuration constants (≤ 64 KB). |
| `Workgroup`| Yes      | Yes      | No     | Workgroup-local shared memory. Declared with a static `count`; no binding slot. |

Attempting to `Store` or perform an `Atomic` on a `ReadOnly` or `Uniform` buffer is a validation error. Attempting to perform an `Atomic` on a `Workgroup` buffer is also a validation error.

### Example

```rust
use vyre::ir::{BufferAccess, BufferDecl, DataType};

let buf = BufferDecl::storage("data", 0, BufferAccess::ReadWrite, DataType::U32);
assert_eq!(buf.access, BufferAccess::ReadWrite);
```

---

## `Convention`

`Convention` is a versioned calling contract between the host and an operation. Adding a new variant never breaks existing programs.

| Variant | Semantics |
|---------|-----------|
| `V1`    | Standard: input (read) + output (read_write) + params (uniform). |
| `V2 { lookup_binding: u32 }` | V1 plus an additional lookup-table buffer (read). Used for hash tables and encoding maps. |

Frontends and backends negotiate the convention at pipeline construction time.

---

## `OpSignature`

`OpSignature` describes the input and output types of an operation.

```rust
pub struct OpSignature {
    pub inputs: Vec<DataType>,
    pub output: DataType,
}
```

The conformance harness uses `OpSignature` to allocate correctly typed host buffers and to verify that a lowering respects the declared types.

### Example

```rust
use vyre::ir::{DataType, OpSignature};

let sig = OpSignature {
    inputs: vec![DataType::U32, DataType::U32],
    output: DataType::U32,
};
assert_eq!(sig.min_input_bytes(), 8);
```

---

## Permanence

The set of `DataType` variants, the semantics of each variant, and the
behavior of `BufferAccess` are **permanent**. New variants may be added as
hardware evolves (e.g. `FP8`, `FP4`, log-number systems), but existing
variants will never change size or meaning. See `extensibility.md` for the
general rule.
