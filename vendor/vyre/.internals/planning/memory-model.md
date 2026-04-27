# Vyre Memory Model

> Authoritative spec for `MemoryRegion`, `MemoryKind`, `Access`, and the
> ordering contracts Vyre programs observe across substrates. Backends
> implement against this document. Conform enforces against this
> document. An unspecified case is a specification bug, not a freedom.

## Region shape: what a region is

A `MemoryRegion` is the abstract memory that a Vyre program reads from,
writes to, or synchronizes on. It has no binding slot, no address space
attribute, and no substrate-specific layout — those are backend
decisions. What a region carries is exactly enough information for a
backend to pick the best substrate-specific realization.

```rust
pub struct MemoryRegion {
    pub id: RegionId,
    pub kind: MemoryKind,
    pub access: Access,
    pub element: DataType,
    pub shape: RegionShape,
    pub hints: MemoryHints,
}
```

`RegionShape` describes topology, not layout:

```rust
pub enum RegionShape {
    Dense(u64),                      // N contiguous elements
    Sparse,                          // index-set + payload, backend chooses CSR/COO/bitmap
    VarLen,                          // prefix-length records
    CSR { node_count: u64 },         // graph-friendly: rows + cols + values
}
```

A backend maps `Dense(N)` to a plain storage buffer. A backend maps
`Sparse` to whatever is efficient on its substrate — GPU may pick CSR
with a bitmap mask; a CPU reference picks a `HashMap<u64, Value>`. The
Program never encodes the backend's choice.

## `MemoryKind`: the tier

`MemoryKind` is the single most important hint a region carries. It
tells the backend which memory tier to use.

```rust
pub enum MemoryKind {
    Global,   // device-global, slow, large
    Shared,   // workgroup-local, fast, small
    Uniform,  // cached broadcast, small, read-mostly
    Local,    // per-invocation, register-like, tiny
    Readonly, // constant across the dispatch
    Push,     // root constants / push constants
}
```

| Kind       | wgpu realization                    | Metal realization         | CUDA realization     | CPU realization  |
| ---------- | ----------------------------------- | ------------------------- | -------------------- | ---------------- |
| `Global`   | `@group(0) @binding(N) var<storage>`| `device T*`               | `__global__ T*`      | `Box<[T]>`       |
| `Shared`   | `var<workgroup, T>`                 | `threadgroup T`           | `__shared__ T`       | per-workgroup Vec |
| `Uniform`  | `var<uniform, T>` with binding      | `constant T&`             | `__constant__ T`     | `Arc<T>`         |
| `Local`    | `var<function, T>`                  | stack                     | register / local     | stack            |
| `Readonly` | `var<storage, read>`                | `device const T*`         | `__constant__ T*`    | `&[T]`           |
| `Push`     | push-constant block                 | buffer-argument inline    | kernel parameter     | function arg     |

**The kind is not a suggestion.** A backend that maps `Shared` to a
global-memory buffer is an incorrect backend — correctness tests fail.
A backend that refuses to execute a program with `Shared` regions
because its substrate lacks workgroup-local memory reports the failure
as `BackendError::UnsupportedMemoryKind { kind: Shared, backend: … }`
before dispatch — never silently.

## `Access`: the read/write contract

```rust
pub enum Access {
    Read,        // program reads only
    Write,       // program writes only (previous contents are undefined)
    ReadWrite,   // both reads and writes, no atomicity
    Atomic,      // all accesses are atomic — see MemoryOrdering
    Shared,      // read-many / write-many with explicit barriers
}
```

`Access::Atomic` requires every load and store on this region to carry
an explicit `MemoryOrdering`. The reference interpreter enforces this
by rejecting non-atomic primitives on `Atomic` regions at validation
time.

## `MemoryOrdering`: the ordering contract

Every atomic access and every barrier declares its ordering:

```rust
pub enum MemoryOrdering {
    Relaxed,    // no ordering, only atomicity
    Acquire,    // subsequent reads/writes cannot be reordered before
    Release,    // prior reads/writes cannot be reordered after
    AcqRel,     // both
    SeqCst,     // total order across all SeqCst accesses
}
```

This is the C++ memory model, chosen because it has decades of hardware
and compiler consensus behind it. Every substrate Vyre supports has a
defined mapping:

- wgpu / WGSL: `atomicLoad(ptr, order)`, `atomicStore(ptr, value, order)`.
- Metal: `atomic_load_explicit(ptr, memory_order_<X>)`.
- CUDA: `cuda::atomic_ref::load(memory_order_<X>)`.
- CPU reference: uses `core::sync::atomic::Ordering::<X>`.

## `MemoryHints`: non-binding optimization cues

```rust
pub struct MemoryHints {
    pub coalesce_axis: Option<u8>,        // which axis backend should pack along
    pub preferred_alignment: Option<u32>, // bytes; backend may exceed
    pub cache_locality: CacheLocality,
    pub expected_working_set_bytes: Option<u64>,
}

pub enum CacheLocality {
    Streaming,  // one-pass through, no reuse
    Temporal,   // reused within a dispatch
    Random,     // unpredictable access pattern
}
```

A backend that ignores every hint is still correct. A backend that
treats a hint as a contract and fails when it can't honor it is also
correct, provided it reports the failure as
`BackendError::UnhonorableMemoryHint { hint: …, reason: … }`. Hints
are opt-in contracts: a backend that advertises honoring
`coalesce_axis` MUST coalesce or reject.

## Validation order

For every `Program` entering a backend:

1. Every `RegionId` referenced by a node exists in the Program's region list.
2. Every node's expected `MemoryKind` is compatible with the region's
   declared kind (a node that needs `Shared` rejects a `Global` region).
3. Every atomic operation has a `MemoryOrdering`.
4. Every barrier declares the ordering it establishes.
5. The backend's `supported_ops()` covers every node's `kind_id()`.
6. The backend's `supported_memory_kinds()` covers every region's kind.

A failure at any step is a structured `ValidationError` with a `fix:`
message naming the exact region/node/backend combination.

## Serialization contract

`MemoryRegion` is part of the wire format. Versioning follows the
Program wire format: a v2 Program carries v2 MemoryRegions. A v1
Program's `BufferDecl` migrates to v2 by mapping `workgroup == true` to
`MemoryKind::Shared` and the rest to `MemoryKind::Global`. The
migration is mechanical and a test in `vyre-ir/tests/wire_migration.rs`
asserts that every v1 Program round-trips through v2 and back to v1
without loss (on the subset of v1 concepts v2 supports).

## What this model does NOT include (by design)

- **Binding slots.** A region does not know its `@group` / `@binding`.
  Binding assignment is a backend lowering decision. Two calls to
  `backend.execute` for the same Program may pick different bindings
  based on internal constraints; Vyre does not care.
- **Workgroup size.** A region does not know the workgroup shape.
  Workgroup sizing is in `DispatchConfig`, set by the caller per
  dispatch, not baked into the Program.
- **Address spaces.** WGSL's `private`, `function`, `workgroup`,
  `uniform`, `storage` are backend-specific address spaces that map
  from `MemoryKind`. Vyre programs never name them.
- **Alignment requirements beyond hints.** A backend may impose
  stricter alignment than a region hints. If alignment is not
  satisfiable, the backend reports `BackendError::AlignmentFailure`;
  it never silently pads.
