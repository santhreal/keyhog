# RFC 0004 — Collective ops (AllReduce, AllGather, ReduceScatter)

## Summary

Introduce first-class collective-communication IR nodes:
`Node::AllReduce`, `Node::AllGather`, `Node::ReduceScatter`,
`Node::Broadcast`. The distributed-backend (`VyreBackend::is_distributed()`
returning true) lowers these to the underlying communication
primitive (NCCL, SHARP, UCX, MPI) while the single-device backend
treats them as identity / local reduction no-ops.

## Motivation

Multi-GPU / multi-node inference + training relies on collective
ops. vLLM uses NCCL directly; TensorRT-LLM has its own. Today
vyre dispatches to a single device; no IR shape expresses "reduce
this buffer across N GPUs."

With `VyreBackend::is_distributed()` already in the trait, the
collective ops are the next missing primitive.

## Design

New `Node` variants (append-only, next free tag after Region):

```rust
Node::AllReduce  { buffer: Ident, op: CollectiveOp, group: CommGroup },
Node::AllGather  { input: Ident, output: Ident, group: CommGroup },
Node::ReduceScatter { input: Ident, output: Ident, op: CollectiveOp, group: CommGroup },
Node::Broadcast  { buffer: Ident, root: u32, group: CommGroup },
```

`CollectiveOp`: `Sum | Min | Max | BitAnd | BitOr | BitXor | ... | Opaque(ExtensionCollectiveOpId)`.

`CommGroup`: an opaque handle identifying the communicator
(world, tensor-parallel, pipeline-parallel, custom); resolved by
the backend at dispatch time.

Single-device backends:
- `AllReduce` over a world of size 1 is a no-op; output == input.
- `AllGather` into a concat of size 1 is a copy.
- `Broadcast` is a copy from root (always self).

Distributed backends:
- Each backend registers its communicator implementation via a
  `CollectiveDriver` trait.
- NCCL, UCX, MPI each ship as opt-in crates (`vyre-collective-nccl`,
  `vyre-collective-ucx`, `vyre-collective-mpi`).

## Wire format

Tag reservations: `Node::AllReduce = 12`, `AllGather = 13`,
`ReduceScatter = 14`, `Broadcast = 15`. Already-reserved ranges
apply.

## Testing

- Property: every collective + its no-op single-device behavior
- Adversarial: AllReduce with buffer mismatch across ranks must
  raise structured error
- Parity: collectives on a 4-GPU test bench produce byte-identical
  output to the reference sequential implementation

## Alternatives considered

- **Opaque extension via Node::Opaque.** Rejected: collectives are
  universal enough that first-class IR nodes enable cross-
  optimization passes (e.g. fuse two AllReduces on disjoint
  buffers into one).
- **Backend-specific API on VyreBackend.** Rejected: couples IR
  consumers to a specific backend's collective surface, breaking
  substrate-neutral thesis.

## Open questions

- Async collective overlap with compute — extend `PendingDispatch`
  to cover collective readiness or add a new `PendingCollective`?
- NCCL communicator initialization cost — amortize across many
  dispatches or re-init per dispatch?
