# vyre Memory Model

vyre's memory model is **parallel-first, substrate-neutral, and tiered**. It defines the visibility and ordering rules that every backend must preserve when lowering `Program` to hardware.

## Tiers

Memory lives in one of four tiers:

| Tier | `MemoryKind` | Visibility | Typical backend mapping |
|------|--------------|------------|-------------------------|
| **Invocation-local** | `Local` | One invocation | register, scratchpad |
| **Shared** | `Shared` | All invocations in one workgroup | LDS, groupshared, threadgroup |
| **Global** | `Global` / `Readonly` | All invocations, all workgroups | storage buffer, HBM |
| **Uniform / push** | `Uniform` / `Push` | All invocations (read-only or 256-byte pushed) | uniform buffer, push constant |

A backend that cannot distinguish shared from global (e.g. a pure scalar CPU backend) may collapse the tiers, but it must preserve the ordering and synchronization rules below.

## Ordering rules

The IR defines *when* a write becomes visible to a reader on another invocation. There are two primitives:

### 1. `Node::Barrier`

`Barrier` emits a full memory barrier across **all invocations in the current workgroup**. After the barrier:

- All shared writes issued by any invocation in the group before the barrier are visible to every invocation's reads after the barrier.
- Global writes acquire at least `Acquire` ordering relative to reads after the barrier.

Backend mapping: `barrier()` in WGSL, `__syncthreads()` in CUDA, `threadgroup_barrier(mem_flags::mem_threadgroup)` in Metal.

### 2. Atomic operations with `MemoryOrdering`

`Expr::Atomic` carries a `MemoryOrdering`:

| Ordering | Meaning |
|----------|---------|
| `Relaxed` | Atomicity only. No ordering with surrounding loads/stores. |
| `Acquire` | No loads after this atomic may be hoisted above it. |
| `Release` | No stores before this atomic may sink below it. |
| `AcquireRelease` | Both. |
| `SeqCst` | All `SeqCst` atomics agree on a single total order. |

Atomic operations may be cross-workgroup (global-tier) or workgroup-local (shared-tier). The tier is determined by the buffer's `MemoryKind`.

### Compare-exchange semantics (V7-CORR-009)

`AtomicOp::CompareExchange` always carries **strong** semantics in vyre IR.
A successful return MUST mean the comparison observed the expected value at
the location at the moment of the read-modify-write — never a spurious
failure.

Backends that lower to a hardware `compareExchangeWeak` primitive (WGSL
`atomicCompareExchangeWeak`, SPIR-V `OpAtomicCompareExchangeWeak`, the
`monitor`/`mwait` LL/SC pairs on RISC-V and ARM) MUST wrap the call in a
retry loop until success or a true value-mismatch failure. Reporting a
weak-spurious failure to the program is a conformance violation and the
conform gate rejects the backend.

Rationale: hash-based data structures and lock-free queues built on top
of vyre rely on strong semantics to bound progress. Weak semantics push
the retry obligation onto every caller and make composition unsound.

### FMA semantics (V7-CORR-011)

`Expr::Fma { a, b, c }` is an **IEEE-754 fused multiply-add** — a single
rounding step from the infinitely-precise product `a × b + c`. The CPU
reference is `f32::mul_add` byte-identical, and every backend must emit a
true hardware FMA instruction (WGSL `fma`, SPIR-V `OpExtInst Fma`,
PTX `fma.rn.f32`, AArch64 `fmla`).

Backends that emit separate multiply-then-add (two roundings) are
**non-conformant**. The conform gate's `cat_a_gpu_differential` battery
includes adversarial vectors `(a, b, c)` chosen to disagree under
two-step rounding; the rejection is automatic.

This eliminates target-dependent rounding for FMA-producing code paths
across CPU/GPU/photonic substrates. Programs that need separate-rounding
multiply-add should explicitly compose `BinOp::Mul` + `BinOp::Add`.

## Race rules

- A location read by one invocation and written by another within the same shader invocation phase (between two barriers) is **a data race**. The validator emits `V018` when it detects unsynchronized writes visible to reads.
- Atomic accesses to the same location from multiple invocations are **not** races regardless of ordering; `Relaxed` guarantees only atomicity.
- Non-atomic writes to the same location from multiple invocations are **always races** — even if they all write the same value (per SIMD lane non-determinism).

## Buffer lifetime

- Storage buffers (`Readonly`, `Global`) exist across dispatches. Data persists unless explicitly cleared.
- Shared buffers (`Shared`) are zero-initialized at workgroup start. Writes visible only within that workgroup invocation.
- Local buffers (`Local`) are zero-initialized at invocation start.
- Uniform / push buffers are read-only for the kernel.

## Invocation IDs as the only cross-invocation communication channel

`Expr::InvocationId { axis }`, `Expr::WorkgroupId { axis }`, `Expr::LocalId { axis }` are the only way to derive per-invocation identity. Invocation IDs are the **only** primitive input that differs across invocations in a dispatch — everything else (uniform/push data, global buffers, op arguments) is shared.

## Substrate-neutrality

The model is deliberately abstract. A photonic substrate whose "workgroup" is a coherence domain defined by fiber length still maps: "shared-tier writes must become visible to workgroup-local readers after a synchronization event" is a statement about ordering, not about silicon. A CPU backend collapses the tiers but emits `std::sync::atomic::fence(Ordering::SeqCst)` for `Barrier`. SPIR-V emits `OpMemoryBarrier` + `OpControlBarrier`. CUDA emits `__threadfence()` + `__syncthreads()`. Same semantic contract, different implementations.

## What the model does not define

- **Hardware-specific granularity.** Whether an atomic compiles to a single instruction or a compare-and-swap loop is a backend concern.
- **Cache coherency.** Implicit in the ordering rules. Backends insert whatever cache-line-flush / invalidate is needed to honor them.
- **Inter-dispatch ordering.** `Barrier` and atomics coordinate invocations *within one dispatch*. Cross-dispatch ordering is the host's responsibility (fence, queue signal, cudaEvent).

## Verification

Every op that reads or writes memory declares its memory-effect pattern (`MemoryEffect::{PureLocal, WorkgroupRead, WorkgroupWrite, GlobalRead, GlobalWrite, GlobalAtomic}`). The validator checks that:

1. Programs declaring only `PureLocal` effects have no `Barrier` nodes (reachable from `entry`).
2. Programs with `WorkgroupWrite` effects followed by `WorkgroupRead` effects have a `Barrier` between them.
3. Atomic ops use a `MemoryKind` buffer that supports atomics (`Global` storage, not `Readonly` or `Uniform`).

The conform gate then runs witness-based differential testing: for every boundary input (0, 1, MAX, MAX-1, ±0, ±Inf, NaN, subnormal, MSB-set, MSB-clear), the backend's output must match the CPU reference byte-for-byte.
