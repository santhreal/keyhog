# OpSpec — the declarative operation contract

This chapter defines `OpSpec`, the declarative struct that replaces traits for
operation contracts in vyre. It explains the struct's fields, how to declare
Category A and C operations, and the algebraic law system that the conformance
suite verifies.

## Why a struct, not a trait

vyre's original architecture defined operations as a trait:

```rust
trait Op: Send + Sync {
    fn id(&self) -> &'static str;
    fn program(&self) -> ir::Program;
    fn signature(&self) -> OpSignature;
    // ...
}
```

This had a fundamental problem: trait objects are runtime polymorphism.
`Box<dyn Op>` means virtual dispatch. Virtual dispatch means the
compiler cannot inline, cannot specialize, cannot prove at compile
time what operation is being called. The operation's identity is
hidden behind a pointer that is resolved at runtime.

This is Category B. Runtime abstraction overhead. The very thing
vyre forbids.

The irony was not subtle. The crate that bans Category B in GPU
shaders was using Category B in its own Rust API. The trait existed
because it was the obvious Rust idiom for polymorphism. But the
obvious idiom was wrong for vyre's requirements, because vyre's
requirements are not about convenience — they are about eliminating
every form of runtime abstraction cost, including in the host code
that constructs and composes programs.

The replacement is `OpSpec`: a plain data struct with `const`
constructors and static slices. No trait objects. No vtables. No
dynamic dispatch. Every operation is a `const` value known at
compile time. The compiler sees through it completely.

```rust
pub struct OpSpec {
    id: &'static str,
    category: Category,
    inputs: &'static [DataType],
    outputs: &'static [DataType],
    laws: &'static [Law],
    compose: Compose,
}
```

An operation is declared as a `const` on the struct that owns its
`program()` function:

```rust
impl Xor {
    pub const SPEC: OpSpec = OpSpec::composition(
        "primitive.bitwise.xor",
        &[DataType::U32, DataType::U32],
        &[DataType::U32],
        &[Law::Commutative, Law::Bounded { lo: 0, hi: 32 }],
        Self::program,
    );

    pub fn program() -> Program {
        primitive::binary_u32_program(Expr::bitxor)
    }
}
```

The `compose` field is either `Compose::Composition(fn() -> Program)`
for Category A ops (the function builds the IR program) or
`Compose::Intrinsic(IntrinsicDescriptor)` for Category C ops (the
descriptor names the hardware unit).

## The fields

### id

Stable hierarchical identifier. Dot-separated namespaces:
`primitive.bitwise.xor`, `decode.base64`, `graph.bfs`. An identifier
must not be reused for different behavior at the same version. The
identifier is permanent once published.

### category

`Category::Intrinsic` for compositional operations that inline completely at
lowering time. `Category::Intrinsic { hardware, backend_availability }` for
hardware intrinsics that map to specific GPU instructions. Category B
does not exist as a variant — it is forbidden by omission.

The `backend_availability` field on Category C is a function
`fn(&Backend) -> bool` that returns whether the intrinsic is
available on a given backend. This enables multi-backend support:
a SubgroupShuffle intrinsic is available on WGSL and CUDA but not
on all Metal devices.

### inputs and outputs

Static slices of `DataType` values. The signature is known at
compile time. The conformance harness uses these to allocate
correctly typed host buffers and to verify that lowering respects
the declared types.

Using static slices instead of `Vec<DataType>` (as the old
`OpSignature` did) means zero allocation for signature queries.
Every `OpSpec` is a compile-time constant with no heap.

### laws

Static slice of `Law` values declared by the operation. Laws are
verified by the conformance suite. See the algebraic law system
section below.

### compose

Either `Compose::Composition(fn() -> Program)` or
`Compose::Intrinsic(IntrinsicDescriptor)`.

For Category A ops, the function builds and returns the canonical
`ir::Program`. The function is called when the program is needed
(for lowering, for conformance, for composition). It is not called
at declaration time — declaration is `const` and allocation-free.

For Category C ops, the `IntrinsicDescriptor` names the hardware
unit and the intrinsic. The backend uses this to emit the
appropriate hardware instruction. If the backend does not support
the intrinsic, it falls back to the Category A software composition
declared in the spec crate.

## The vyre-spec crate

The algebraic laws, categories, invariants, and type definitions
live in a separate crate: `vyre-spec`. This crate has zero
dependencies on vyre itself. A backend author can depend on
`vyre-spec` alone to implement conformance checking without
importing the entire vyre runtime.

`vyre-spec` defines:

- `DataType`, `BinOp`, `UnOp`, `AtomicOp`, `BufferAccess`,
  `Convention` — the IR type vocabulary
- `AlgebraicLaw` — 14 law variants (Commutative, Associative,
  Identity, SelfInverse, Idempotent, Absorbing, Involution,
  DeMorgan, Monotone, Monotonic, Bounded, Complement,
  DistributiveOver, ZeroProduct, Custom)
- `Category` — A (with `composition_of`) and C (with
  `IntrinsicTable` and `fallback_composition`)
- `IntrinsicTable` — per-backend intrinsic spellings (WGSL, CUDA,
  Metal, SPIR-V)
- `EngineInvariant` — the 15 invariants (I1-I15)
- `Verification` — proof evidence (ExhaustiveU8, WitnessedU32, etc.)

The separation means the specification is independently versionable
and independently publishable. A backend team at NVIDIA can depend
on `vyre-spec` without depending on vyre's WGSL lowering, runtime,
or any GPU code.

## How to declare an operation

### Category A (composition) — the common case

```rust
use crate::ir::{Expr, Program};
use crate::ops::{OpSpec, COMMUTATIVE_DETERMINISTIC, U32_OUTPUTS, U32_U32_INPUTS};
use crate::ops::primitive;

pub struct Xor;

impl Xor {
    pub const SPEC: OpSpec = OpSpec::composition(
        "primitive.bitwise.xor",
        U32_U32_INPUTS,
        U32_OUTPUTS,
        COMMUTATIVE_DETERMINISTIC,
        Self::program,
    );

    pub fn program() -> Program {
        primitive::binary_u32_program(Expr::bitxor)
    }
}
```

The `SPEC` is a `const` — no allocation, no trait object, known at
compile time. The `program()` function is called only when the IR is
needed. The helper constants (`U32_U32_INPUTS`, `COMMUTATIVE_DETERMINISTIC`)
are shared across all ops with the same signature/law pattern.

### Category C (hardware intrinsic)

```rust
pub const SPEC: OpSpec = OpSpec::intrinsic(
    "intrinsic.subgroup_shuffle",
    &[DataType::U32, DataType::U32],
    &[DataType::U32],
    &[Law::Commutative, Law::Bounded { lo: 0, hi: 32 }],
    "subgroup_shuffle",
    |backend| matches!(backend, Backend::Wgsl | Backend::Cuda),
    IntrinsicDescriptor::new("subgroup_shuffle", "warp_shuffle"),
);
```

The `backend_availability` closure determines which backends support
the intrinsic natively. Backends without support use the software
fallback — a Category A composition declared in the spec crate that
produces the same semantics at lower performance.

## The algebraic law system

The spec crate defines 14 algebraic law variants. Each law is a
mathematical property that the conformance suite verifies
mechanically:

| Law | Meaning | Example |
|-----|---------|---------|
| `Commutative` | `f(a, b) = f(b, a)` | `add(3, 7) = add(7, 3)` |
| `Associative` | `f(f(a, b), c) = f(a, f(b, c))` | `add(add(1, 2), 3) = add(1, add(2, 3))` |
| `Identity { element }` | `f(a, e) = a` and `f(e, a) = a` | `add(x, 0) = x` |
| `SelfInverse { result }` | `f(a, a) = result` | `xor(x, x) = 0` |
| `Idempotent` | `f(a, a) = a` | `and(x, x) = x` |
| `Absorbing { element }` | `f(a, z) = z` | `mul(x, 0) = 0` |
| `Involution` | `f(f(a)) = a` | `not(not(x)) = x` |
| `DeMorgan { inner_op, dual_op }` | `not(inner(a, b)) = dual(not(a), not(b))` | De Morgan's laws |
| `Monotone` | `a <= b` implies `f(a) <= f(b)` | non-decreasing functions |
| `Monotonic { direction }` | explicit NonDecreasing or NonIncreasing | `clz` is NonIncreasing |
| `Bounded { lo, hi }` | output always in `[lo, hi]` | `popcount` in `[0, 32]` |
| `Complement { complement_op, universe }` | `f(a) + complement(a) = universe` | `popcount(a) + popcount(not(a)) = 32` |
| `DistributiveOver { over_op }` | `f(a, g(b, c)) = g(f(a, b), f(a, c))` | `and` over `or` |
| `ZeroProduct { holds }` | `f(a, b) = 0` implies `a = 0` or `b = 0` | false for wrapping `mul` |
| `Custom { name, description, check }` | arbitrary predicate function | user-defined laws |

Each law carries `Verification` evidence in the conformance suite:

- `ExhaustiveU8` — proven for all `u8` inputs (exhaustive)
- `ExhaustiveU16` — proven for all `u16` inputs
- `WitnessedU32 { seed, count }` — checked on N random `u32` inputs
  with a deterministic seed
- `ExhaustiveFloat { typ }` — for future float ops

The law system is additive. New `AlgebraicLaw` variants may be added
(the enum is `#[non_exhaustive]`), but existing variants never change
meaning.

## The workspace structure

vyre is organized as a Rust workspace:

```
vyre/
├── core/          The IR, ops, lowering (crate: vyre)
├── spec/          Zero-dep specification types (crate: vyre-spec)
├── conform/       Conformance harness (crate: vyre-conform)
├── std/           Future standard library extensions
├── domains/       Future domain-specific op collections
├── libraries/     Future reusable library crates
├── applications/  Future application crates
└── docs/          The vyre book
```

`core/` contains the IR, the standard ops, and the WGSL lowering.
`spec/` contains the types that backends need for conformance without
depending on vyre itself. `conform/` contains the conformance harness.
The empty directories (`std/`, `domains/`, `libraries/`, `applications/`)
are the expansion surface for vyre's infinite abstraction layers.

## Permanence

The `OpSpec` struct shape is permanent. The `const fn` constructors
are permanent. The law system is additive — new `AlgebraicLaw`
variants may be added, but existing variants never change meaning.
The `Category` enum is permanent — A and C are the only permitted
categories. The `Backend` enum is additive — new backends may be
added. The workspace structure is permanent — new members may be
added but existing members will not be removed or renamed.

## See also

- [Operations Overview](overview.md)
- [OpSpec README](README.md)
- [Primitive Overview](primitive/overview.md)

