# RFC 0005 — Persistent megakernel + ring-buffer submission

## Summary

Add a persistent-kernel dispatch primitive: the GPU runs a single
long-lived megakernel that reads VIR0 bytecode from a ring buffer
and executes it. The CPU submits bytecode via the ring buffer
instead of launching per-Program compute pipelines. Result:
per-dispatch latency drops from ~50 µs (pipeline launch) to ~200 ns
(ring-buffer write).

This is the paradigm-shift item — turns the GPU from a coprocessor
you dispatch to into a VM you submit bytecode to.

## Motivation

Every current GPU compute stack (CUDA, wgpu, Metal, TVM, IREE,
ONNX Runtime, PyTorch) treats the GPU as a coprocessor. Each
dispatch is a pipeline launch with 10–50 µs overhead. Multi-tenancy
requires context switches.

Megakernel + io_uring-style submission rejects that model:

- Single persistent kernel never exits.
- Ring buffer is a submission queue; CPU pushes VIR0 bytecode.
- GPU decodes bytecode on-device and executes with ~zero dispatch
  overhead.
- N tenants = N submission queues, served fairly from one
  megakernel.

This is what Jim Keller described as "throw out the ISA, ship the
compiler" — vyre ships the compiler + the bytecode, and the GPU
interprets. It's the structural payoff of having a portable
bytecode IR in the first place.

## Design

Three components:

### 1. VIR0 interpreter kernel (WGSL)

A single WGSL megakernel that:
- Reads a byte at a time from a ring buffer.
- Switches on the node tag (Let / Store / If / Loop / ... / Region /
  Opaque).
- Executes the node against per-workgroup state (locals, buffers).

The interpreter is emitted via the naga-AST path; no hand-written
WGSL. The opcode set = the terminal BinOp/UnOp/AtomicOp/DataType
surface frozen in 0.6.

### 2. Ring-buffer submission API

```rust
pub trait MegakernelBackend: VyreBackend {
    fn submit_ir(&self, bytecode: &[u8], queue_id: QueueId)
        -> Result<SubmissionId, BackendError>;
    fn poll_completion(&self, submission: SubmissionId)
        -> CompletionStatus;
}
```

New method-pair on a subtrait so backends that don't support
megakernel mode are unaffected. A backend that DOES support it
registers a persistent kernel at `prepare()` time.

### 3. Multi-tenant queue routing

Each `QueueId` has its own ring buffer. The megakernel fairly
drains N queues in round-robin order. Tenant isolation at the IR
level: the validator rejects any program that reads/writes a
buffer outside the tenant's declared scope.

## Testing

- Correctness: dispatch the same Program via `VyreBackend::dispatch`
  and `MegakernelBackend::submit_ir`; assert byte-identical outputs
- Latency bench: 100,000 tiny dispatches — traditional path vs
  megakernel path; expect 100–200× speedup
- Multi-tenancy: two tenants submit disjoint work; neither sees
  the other's buffers

## Prerequisites

- RFC 0001 (Region inline pass) — megakernel needs composable
  Region-level primitives
- RFC 0002 (autodiff) OR not — orthogonal
- RFC 0003 (quantized) — megakernel decoder needs to handle
  Quantized DataType
- RFC 0004 (collectives) — multi-GPU megakernel implies cross-node
  work queues

## Alternatives considered

- **CUDA Dynamic Parallelism.** Works on CUDA only; vyre ships
  portable IR.
- **Graph APIs (CUDA Graphs, DirectX DXGraphs).** Solves dispatch
  overhead within a single graph but doesn't generalize to
  bytecode-interpreted work.
- **Per-backend megakernel implementation.** Rejected: every
  backend writes its own interpreter = 5× maintenance, no shared
  optimization.

## Open questions

- Memory budget: the interpreter's local state (program counter,
  operand stack) competes with user workgroup memory. Quantify.
- Subgroup divergence cost: different tenants' bytecode at
  different program counters create warp divergence. Bench.
- Debuggability: the interpreter hides user-level stack frames;
  how does `tracing::trace_span` survive the indirection?

## Scope for 0.7

Ship the interpreter + single-queue submission API. Defer
multi-tenancy + ring-buffer fairness + cross-node collectives to
0.8. 0.7 proves the paradigm works; 0.8 productionizes it.
