# Vyre Thesis

**The authoritative thesis lives at [`THESIS.md`](../THESIS.md) at the workspace root.**

This file previously carried the pre-rebuild manifesto written against
the closed-enum IR and the older `VyreBackend::dispatch` that accepted
`Vec<Vec<u8>>` inputs and outputs. Both designs have been deliberately
replaced in the 2026-04-18 rebuild. See `docs/audits/AUDIT_2026-04-18_*.md`
for the critique log and `ARCHITECTURE.md` for the absolute architectural
laws that supersede the old contract.

Keeping this file as a redirect preserves incoming links (README badges,
crates.io landing page, external blog posts) without propagating the
outdated contract. The post-rebuild thesis states:

- Vyre is a **substrate-neutral primitive-composition IR**. Core owns the
  graph structure and the trait contracts. Nothing else.
- The **Backend trait** is three methods — `id`, `version`, `execute`. No
  WGSL leak, no `compile_native`, no pre-compiled-handle types cross the
  core boundary.
- **IR node types are open** — a hybrid tagged union covers hot-path
  common ops (`NodeStorage::{LitU32, LitI32, BinOp, UnOp, Load, Store,
  Call}`) and an `Extern(Box<dyn NodeKind>)` escape hatch keeps the
  open-world extensibility.
- **Program has no GPU concepts.** No `workgroup_size`, no `buffers: Arc<[BufferDecl]>`,
  no `entry_op_id`. Workgroup sizing lives in `DispatchConfig`; memory
  lives in an abstract `Vec<MemoryRegion>` with `MemoryKind` spanning
  Global/Shared/Uniform/Local/Readonly/Push.
- **Conformance means enumeration, not random sampling.** Primitives
  declare their bounded-domain coverage and the conform harness
  enumerates 8-bit (256) and 16-bit (65k) input spaces exhaustively.
  "Property tests" is what we call the fallback when a primitive's
  domain exceeds the exhaustive budget; the fallback reports its own
  coverage gap honestly.
- **Downstream composition is the product.** `yaragpu`, `numpy-gpu`,
  `tensor-ml`, and whatever else the community builds are wrappers that
  compose Vyre primitives into domain tools. Vyre does not own those
  domains — it supplies the primitives and the backends.

Read [`THESIS.md`](../THESIS.md) for the full contract.
Read [`ARCHITECTURE.md`](../ARCHITECTURE.md) for the engineering rules
and the three architectural laws (A — no closed IR enums, B — no
string-based WGSL, C — supported_ops capability negotiation).
Read [`VISION.md`](../VISION.md) for the long-range product direction.
Read [`docs/memory-model.md`](memory-model.md) for the authoritative
memory contract backends implement against.
Read [`docs/targets.md`](targets.md) for the supported-target matrix
and the Tier 1 / Tier 2 / Tier 3 registration story.
