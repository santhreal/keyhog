# vyre roadmap (post-0.6)

vyre 0.6 ships the frozen core: IR shape, extension surface, optimization
contract, conformance-certificate infrastructure, multi-target compile
path, and 20+ Cat-A ops. Everything in this roadmap is **additive on top
of that frozen contract**. None of it requires an IR change, an API
break, or a semver-major bump. Community crates can ship any of it at
any time without waiting for a vyre-core release.

## Why these items are post-0.6

- They consume the 0.6 IR — they do not modify it.
- They ship as independent crates pinned to `vyre = "0.6"`.
- Delaying them does not damage the trust, performance, or
  extensibility contract at launch.
- Accelerating them on an unstable core would produce two LAW 1
  violations (half-implemented features on shifting ground).

## Roadmap items

### R-1 — Reverse-mode autodiff pass

**Ships as:** `vyre-autodiff` crate, version `0.6.x`.
**Contract it consumes:** `AlgebraicLaw` inventory + canonical-form
pass (both locked in 0.6 core).
**Surface:**

```rust
pub fn reverse_mode(program: &vyre::ir::Program) -> Result<vyre::ir::Program, AutodiffError>;
```

**Inputs:** any Program whose primitive set has registered a
`BackwardRule` via `inventory::submit!`.
**Outputs:** a Program whose entry computes `∂loss/∂input` for each
input buffer, accumulated into caller-provided gradient buffers.

**Why separate crate:** the pass is self-contained over the IR;
shipping autodiff inside vyre-foundation would couple the compiler
to a differentiation library most users don't need. Keeping it out
preserves the lean-core contract.

**Acceptance criteria:**
- `vyre-autodiff::reverse_mode` returns a valid Program for every op
  in vyre-libs that registers a BackwardRule.
- Differential fuzzer (0.6) catches any divergence between
  `reverse_mode(f)` and a hand-written reference gradient.
- Published with full conformance certificates.

### R-2 — `#[vyre_theorem]` attribute + Kani proof obligations

**Ships as:** `vyre-verify` crate + `vyre-macros` extension.
**Contract:** the 0.6 `vyre-spec::OpSignature` + `AlgebraicLaw`
inventory.
**Surface:**

```rust
#[vyre_theorem(|out: &[u8]| bytemuck::cast_slice::<_, f32>(out).iter().sum::<f32>() - 1.0 <= 1e-6)]
pub fn softmax(input: &str, output: &str, n: u32) -> Program { … }
```

The attribute macro emits a Kani harness that exhaustively checks the
theorem against a bounded input space. CI runs the harness per PR.

**Why separate:** Kani is a heavy dev-dep; pulling it into every
consumer is unacceptable. Vyre-verify is an opt-in overlay.

**Acceptance criteria:**
- `#[vyre_theorem]` works on every Cat-A op in vyre-libs.
- Kani proofs check in under 60s per op.
- Theorem violations fail CI with the concrete counterexample input.

### R-3 — `vyre-libs-llm` template crate

**Ships as:** `vyre-libs-llm` crate.
**Contract:** vyre-libs 0.6 primitives + frozen DataType (including
quantized F16/BF16/F8 variants locked in 0.6) + the collective
dialect's ring/tree all-reduce primitives.
**Ops:**

- FlashAttention-v2 (online softmax, tiled Q·Kᵀ·V)
- Rotary positional embeddings (RoPE)
- KV-cache append + gather
- Grouped-query attention (GQA)
- Mixture-of-Experts routing
- RMSNorm
- SwiGLU
- Sliding-window attention

**Why separate:** LLM ops are a specific domain; other consumers
(scientific compute, raytracing, video enhancement) shouldn't pull
the dep. Vyre-libs-llm sets the pattern for future domain packs.

**Acceptance criteria:**
- Every op has a CPU reference.
- Every op has a cat_a_conform witness test.
- End-to-end Llama-3-class forward pass runs through vyre-libs-llm
  on a reference 3090 with perf parity vs vLLM at ±10%.

### R-4 — Additional sparse tensor ops

**Ships as:** community PRs into `vyre-libs::sparse` (feature-gated).
**Contract:** 0.6 `DataType::CSR`, `DataType::COO`, `DataType::BSR`.
**Ops:** spmv, spmm, spadd, sptranspose, sp_to_dense, dense_to_sparse,
sparse_broadcast, csr_row_scan.

Sparse DataType enum is frozen in 0.6; specific ops compound on top.

### R-5 — Additional quantized ops

**Ships as:** community PRs into `vyre-libs::quant`.
**Contract:** 0.6 `DataType::{I8, I4, F16, BF16, F8E4M3, F8E5M2, FP4,
NF4, Quantized}`.
**Ops:** dequantize, requantize, int8_matmul, int4_matmul, block-wise
stats, per-channel scaling.

### R-6 — Additional collective op implementations

**Ships as:** community PRs into `vyre-libs::collective` (feature-gated
per topology).
**Contract:** 0.6 `DataType::DeviceMesh` + the collective-op dialect.
**Ops:** ring-all-reduce, tree-all-reduce, 2D-torus-all-reduce,
butterfly-all-gather, hierarchical-reduce-scatter. Each is a
Cat-A composition; vyre-foundation's lowering picks based on mesh
shape.

### R-7 — Photonic-native primitive ops

**Ships as:** `vyre-photonic-ops` crate once photonic hardware ships.
**Contract:** 0.6 backend-registration path in vyre-driver-photonic.
**Ops:** `interferometer_matmul`, `wavelength_multiplex`,
`mach_zehnder_reconfigure`, `photon_detection`. Each is a hardware
primitive Op (Category C) — the registration path lives in 0.6; the
ops register into it whenever the hardware is live.

### R-8 — Graph-IR compatibility bridge

**Ships as:** `vyre-graph-ir` crate on top of 0.6 statement IR.

The 0.6 statement IR is the canonical form; a graph-IR view on top
gives whole-program optimization without changing the wire format.
Vyre-graph-ir exposes `to_graph(Program) -> NodeGraph` and
`from_graph(NodeGraph) -> Program`; optimizer passes can operate on
either view and the wire format stays stable.

**Why not a core IR swap:** swapping statement-IR for graph-IR in
vyre-foundation breaks every external op and every conformance
certificate. Keeping graph-IR as a view preserves the 0.6 trust
contract forever.

## What ISN'T on this roadmap (by design)

- **Any op that changes the core DataType set.** Those freeze in 0.6;
  semver-major to extend.
- **Any op that requires new Node or Expr variants.** Those also
  freeze in 0.6; new wire tags reserve the 0x80..0xFF space for
  third-party extensions via `Expr::Opaque`/`Node::Opaque`.
- **Any pass that breaks the canonical-form invariant** from 0.6.
  Future optimizer passes preserve canonical form or run after
  `canonicalize()`.
- **Any backend that doesn't pass the conformance gate.** A new
  backend registers via the 0.6 factory path and must issue OCC
  certificates for every op it supports. No exceptions.

## Release cadence target

- vyre 0.6.0 — the frozen contract + initial 20 Cat-A ops.
- vyre 0.6.1 — R-1 (autodiff) + R-2 (theorems) as separate crates.
- vyre 0.6.2 — R-3 (LLM template) as separate crate.
- vyre 0.6.x — community R-4/R-5/R-6 sparse/quant/collective ops.
- vyre 0.7 — R-8 graph-IR bridge (additive, no IR churn).
- vyre 0.8 — photonic-live (R-7 populates when hardware ships).

No semver-major bumps inside the 0.6 series. Every 0.6.x release is
additive: new crates, new Cat-A ops, new backends. The core stays
frozen so every downstream pin stays valid.
