# Extensibility — adapting vyre to new algorithms and hardware

## The question

As GPU compute evolves — new neural architectures, new algorithms, new
hardware units, new data types — can vyre keep up without collapsing
under its own abstraction debt?

Yes. This document explains why, and what the discipline looks like.

## The principle: algorithms are compositions, primitives are stable

vyre is a substrate. It defines primitives (Category A compositional ops
and Category C hardware intrinsics). Algorithms built on top are
compositions of those primitives.

The observation: **primitives change slowly, algorithms change fast.**
New primitives require new hardware or new fundamental data types. Those
are rare events — maybe a few per year across the entire industry. New
algorithms are invented constantly — papers published daily, each
describing a new neural architecture or a new optimization technique.

If vyre's primitive set is complete enough, new algorithms are just new
compositions. The substrate does not need to change. The composition
library grows.

This is what LLVM IR achieved for CPUs. LLVM IR did not need an update
when someone invented a new sorting algorithm or a new graph algorithm.
It needed updates when SIMD widened (AVX-512) or when new instructions
were added (AVX-VNNI, AMX). Algorithms are compositions of LLVM ops.
New algorithms do not require new LLVM ops.

vyre follows the same pattern.

## What evolves without vyre changing

Everything in this list is expressible as a composition of existing vyre
primitives (current Layer 1 integer ops + planned Layer 1 float/tensor
ops + Layer 2 compound ops + Category C hardware intrinsics for MMA,
subgroup, sample, async copy, ray trace):

### Neural network architectures

- **Transformers** — matmul + softmax + layer norm + element-wise ops.
  All compositional.
- **Mamba / State Space Models** — matmul + element-wise + scan + gate.
  All compositional.
- **Mixture of Experts (MoE)** — top-k selection + indexed gather +
  weighted sum. Top-k is a Layer 2 op (partial sort). The rest are
  existing primitives.
- **Flash Attention / FlashAttention-2 / FlashAttention-3** — matmul
  tiled with online softmax + masked loads + accumulation. Every piece
  is an existing primitive or a Layer 2 compound.
- **Ring Attention** — distributed attention across multiple devices.
  Requires multi-device primitives (future Category C), not new algorithm
  primitives.
- **Diffusion models (U-Net)** — convolutions + attention + activations.
  Convolution is a Layer 2 composition of matmul with im2col.
- **Graph neural networks** — sparse matmul + aggregation + message
  passing. Sparse is a Layer 2 tensor variant; aggregation is reduce.
- **Retentive networks, Griffin, Jamba** — mixtures of existing
  mechanisms. All compositional.
- **New attention variants** (sliding window, local, sparse, linear,
  paged) — masked matmul + index gather. Existing primitives.

### Training techniques

- **Gradient accumulation** — element-wise add in a loop. Existing.
- **Mixed precision training** — cast between F16/BF16/F32. Existing
  casts.
- **Gradient checkpointing** — runtime scheduling decision, not an IR
  concern.
- **LoRA / QLoRA** — low-rank matrix decomposition. Matmul composition.
- **Quantization-aware training** — quantize/dequantize ops. New Layer 2
  compound ops, but the underlying operations are existing primitives.

### Inference techniques

- **Speculative decoding** — two model dispatches with verification.
  Runtime scheduling, not IR.
- **KV cache paging** — indexed memory operations. Existing primitives
  plus runtime management.
- **Continuous batching** — runtime scheduling, not IR.
- **Beam search** — top-k + sort + index gather. Layer 2 compounds.
- **Constrained decoding** — masked softmax + conditional sampling.
  Existing primitives.

### Non-ML algorithms

- **New sorting algorithms** — compositions of compare + swap + atomic.
- **New graph algorithms** — compositions of BFS/dataflow fixpoint.
- **New cryptographic protocols** — compositions of bitwise ops + big
  integer arithmetic (Layer 2).
- **New physics simulations** — compositions of element-wise math + reductions.
- **New signal processing kernels** — FFT (Layer 2) + element-wise +
  reductions.

None of these require vyre IR changes. Every one is a composition.

## What requires a vyre change

### New hardware units

When a GPU generation introduces a dedicated unit that cannot be matched
by software composition:

- **Example:** NVIDIA's introduction of tensor cores required matmul as
  a Category C primitive. A new sparse tensor core (e.g., 2:4 structured
  sparsity) would require a new sparse MMA primitive.
- **Process:** Add a new Category C op. Declare its semantics strictly.
  Declare per-backend availability for the intrinsic. Backends with the
  hardware use the intrinsic; backends without the hardware must reject the
  op with `Error::UnsupportedByBackend { op, backend }`. There is no
  software fallback composition, no degraded path, and no hidden
  performance loss. Conformance verifies the intrinsic semantics on each
  backend that declares support.

### New data types

When a new numeric format becomes mainstream:

- **Example:** FP8 (E4M3, E5M2) became important in 2024. FP4 is
  emerging. Log-number systems are being researched for inference.
- **Process:** Add a new `DataType` variant. Declare its strict IEEE
  semantics (or equivalent strict spec). Add conversion ops to/from
  existing types. Add bit-exact conformance rules.

### New dispatch models

Rare. Would be required if fundamentally new compute paradigms emerge:

- **Example:** quantum-GPU hybrid dispatch, optical compute, neuromorphic
  hardware.
- **Process:** Add a new `Program` variant. These are architectural
  changes, not incremental additions.

## The stability guarantee

A program written against vyre v1.0 works on vyre v1.0, v1.1, v1.2, and
any future v1.x. Only the following changes are permitted across minor
versions:

- Adding new ops (Category A or C)
- Adding new `DataType` variants
- Adding new IR node variants (via `#[non_exhaustive]`)
- Adding new conformance rules
- Adding new engines
- Adding new backends

Forbidden across any version:

- Changing the semantics of an existing op (the IR semantics are
  immutable)
- Removing an op (deprecation is allowed, removal is not)
- Changing an existing `DataType`'s behavior
- Changing an existing validation rule's decision on an existing program
- Making a previously-valid program invalid
- Making a previously-valid program produce different output

This is the Linux kernel's "we don't break userspace" rule applied to
vyre. It is not a suggestion. It is the contract that makes vyre worth
building on.

## The discipline for new op proposals

Every proposed new op goes through this gate:

1. **Can it be derived from existing ops at zero cost after lowering?**
   If yes → Category A. Add it as a composition.

2. **If derivable but slow, does a hardware unit exist that does it
   directly?** If yes → Category C. Add it as an intrinsic with explicit
   per-backend availability. Unsupported backends must return
   `Error::UnsupportedByBackend { op, backend }`.

3. **Is it actually new, or is it a specialization of an existing op?**
   If specialization → add it as a convenience wrapper over the existing
   op. No new semantics.

4. **Does it have strict deterministic semantics?** If no → reject. vyre
   does not accept nondeterministic operations.

5. **Does it have an IR or intrinsic conformance oracle?** If no → reject.
   The IR semantics are the spec.

6. **Does it have declared conformance rules (laws, invariants,
   bit-exact output)?** If no → reject. Every op must be verifiable.

7. **Can it lower to overhead-free code on the reference backend?**
   If no → reject. No runtime abstraction cost (Category B is forbidden).

Ops that pass all seven gates are added to the standard library. Ops
that fail any gate are either rejected or redesigned.

## Why this scales

The discipline is harsh but it scales because the work is bounded.

- Adding a new Category A op is a composition — the semantics are
  derived from existing ops, the conformance rules follow from the
  components' laws.
- Adding a new Category C op is a 1:1 hardware mapping plus declared
  per-backend availability. Unsupported backends reject it explicitly.
- Adding a new engine is a Program composed from existing ops. No new
  primitives.
- The composition library grows without the primitive set growing.

A researcher publishes a new neural architecture. An implementor
composes it as a Program. vyre-conform verifies the composition produces
correct results. The architecture is now available to every vyre
backend, on every conforming GPU, with bit-exact reproducibility. The
researcher did not have to write CUDA. The backend vendors did not have
to adapt. The composition is the algorithm, the algorithm is the
substrate, the substrate is forever.

This is the property that makes vyre a standard rather than a library.

## The one-op-one-directory contribution surface

New operations are added by creating a directory:

```
core/src/ops/<category>/<name>/
├── spec.toml       # identity, archetype, laws, signature
├── kernel.rs       # CPU reference function (the ground truth)
├── lowering/
│   └── wgsl.rs     # GPU kernel (the implementation under test)
├── tests/          # op-specific tests
└── README.md       # documentation
```

The build walker auto-discovers `spec.toml` files. No shared file
edits — your PR touches only your op's directory. This is how vyre
scales to hundreds of contributors without merge conflicts.

The TOML loader validates every `spec.toml` at the trust boundary:
archetype/signature compatibility, law coverage minimums, op-id
format, and injection prevention. A malformed `spec.toml` fails
the build before it reaches certification.

## The auto-registration mechanism

The "primitives stable, algorithms grow" thesis only works if adding a new
algorithm is frictionless. The enemy of frictionless growth is the central
list: every `mod.rs` that contains `pub mod foo; pub mod bar;`, every
`ALL_GATES` array, every `match` statement that must be updated when a new
variant appears. Those lists are merge-conflict magnets. When a hundred
agents work in parallel, every one of them edits the same line in the same
file.

vyre removes the list. The filesystem is the registry.

`vyre-build-scan` (workspace member at `libs/performance/matching/vyre/build_scan/`)
is a build-time filesystem scanner. It walks a flat directory of `.rs` files
and emits a typed registry to `$OUT_DIR`. The parent module includes the
generated file. Adding a new gate, oracle, archetype, or mutation is a
single-file drop. No `mod.rs` edits. No registry list edits. Zero collision
points.

### The pattern in three pieces

`build.rs` registers the directories to scan:

```rust
fn main() {
    build_scan::scan_all(&[
        build_scan::Registry {
            scan_dir: "src/enforce/gates",
            const_name: "ALL_GATES",
            element_type: "&dyn crate::enforce::Gate",
            item_const_name: "REGISTERED",
            output_file: "gates_registry.rs",
            module_prefix: "crate::enforce::gates",
        },
    ]);
}
```

A leaf file declares its contribution:

```rust
// src/enforce/gates/atomics.rs
pub struct Atomics;
impl crate::enforce::Gate for Atomics { /* ... */ }

pub const REGISTERED: Atomics = Atomics;
```

The parent module includes the generated slice:

```rust
// src/enforce/gates/mod.rs
explicit_mod_list!(pub "src/enforce/gates");
include!(concat!(env!("OUT_DIR"), "/gates_registry.rs"));
```

Build-time, `vyre-build-scan` writes `gates_registry.rs` containing:

```rust
pub static ALL_GATES: &[&dyn crate::enforce::Gate] = &[
    &crate::enforce::gates::atomics::REGISTERED,
    /* ... one entry per file ... */
];
```

### Why this matters at scale

With the auto-registration mechanism, a hundred agents can add a hundred new
gates in a hundred different files. None of those PRs touch the same file.
There is no central `ALL_GATES` array to conflict over. The filesystem
namespace is the only coordination surface, and filenames are cheap.

This is the mechanism that makes the thesis real. "Algorithms grow" is not
a wish — it is a build-time guarantee. The substrate stays stable because
new compositions do not require edits to the substrate. The registry is
emitted, not maintained. Growth becomes parallel-safe, review-light, and
mechanically verifiable.
