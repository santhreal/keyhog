# vyre — Roadmap

This document describes the planned evolution of vyre from the current alpha through the 1.0 stable contract. Timelines are expressed in quarters and relative years to remain valid as the calendar advances.

---

## 0.4 (alpha, shipping now)

The current development track. The goal is a working end-to-end pipeline with a single conformant backend and the architecture skeleton frozen.

- **6 frozen traits defined.** `VyreBackend`, `Finding`, `EnforceGate`, `Oracle`, `Archetype`, and `MutationClass` are specified and placed in their permanent module homes. See `ARCHITECTURE.md` for their signatures.
- **8-module architecture (in progress).** The workspace collapses from ~25 modules to the target 8: `vyre-spec`, `vyre` (core), and the six `vyre-conform` submodules (`spec`, `proof`, `enforce`, `pipeline`, `generate`, `verify`, `adversarial`, `meta`).
- **`certify()` single entry point.** The 10-item public API exposed by `vyre-conform` is wired and callable. A backend passes `certify()` and receives a `Certificate`, or fails and receives a `Violation`.
- **~50 reference ops.** The initial standard library covers foundational arithmetic, bitwise, and buffer operations across Categories A, B, and C.
- **wgpu backend.** The first conformant GPU backend ships, executing lowered WGSL kernels under `certify()`.
- **Parallel-native file-per-op contribution model.** New ops are added as single files in `vyre-core/src/ops/{category}/` with no central registry edits. Multiple contributors can land ops concurrently without merge conflicts.
- **vyre-build-scan filesystem registry.** The `build_scan` mechanism generates compile-time registries for gates, oracles, archetypes, and mutations from the filesystem layout. This replaces all manual module lists and linker-section hacks.

### Closed in this release cycle

- P-2 Arena-backed reference interpreter (3× speedup)

### Recently closed

- P-2 Arena-backed reference interpreter landed with 3x speedup and 200-case differential property test.
- P-2 / P-5 / P-7: arena values, zero-copy readback, streaming dispatch landed 2026-04-18

---

## 0.5 (next minor, Q3)

The expansion track. Focus is on backend diversity, standard library growth, and the first formal verification exports.

- **Multiple backends: Metal, CUDA.** In addition to wgpu, native Metal and CUDA backends are implemented and run through `certify()`. Each backend is a standalone trait impl with its own dispatch and memory management.
- **500+ ops in the standard library.** Community contributors scale the op catalog using the file-per-op model. Coverage spans scalar, vector, matrix, and control-flow primitives.
- **Formal verification via SMT export.** Category A compositions can be exported to SMT-LIB2 for automated equivalence proving. The export is lossless and deterministic.
- **Certificate chain — per-op replay proofs.** A `Certificate` embeds a compact, replayable trace of every gate, oracle, and archetype that passed. Third parties can re-verify a certificate offline.
- **mdBook rendered docs site.** Public documentation is built from in-source doc comments and the `rules/` TOML catalog. The site is version-locked to the crate release.

---

## 0.6+ (beyond)

Advanced features that build on the frozen 1.0 foundation. These tracks can proceed in parallel once the contract is solid.

- **Tensor ops (Layer 2+).** Generalized n-dimensional tensors with strided views, broadcasting, and fused elementwise kernels. Treated as compositions of the Layer 1 primitive ops where possible.
- **Neural network archetypes (transformer, Mamba, MoE).** Pre-built structural patterns in the `generate` layer that exercise the tensor ops with shapes and access patterns drawn from production models.
- **Subgroup/warp-level intrinsics (Cat C).** First-class exposure of warp shuffle, ballot, and matrix-multiply accumulate (MMA) instructions. Each intrinsic is a distinct, fully specified op with its own oracles.
- **WASM backend for cross-platform demos.** A CPU reference backend compiled to WebAssembly, enabling browser-based demos and educational tooling without GPU dependencies.
- **Multi-level op optimization proofs (Cat A compositions proven equivalent).** The SMT pipeline is extended to prove that high-level tensor rewrites (e.g., fusion, tiling) produce identical results to their unoptimized counterparts.

---

## 1.0 (the promise)

The stable contract. Once 1.0 ships, the project enters long-term maintenance mode on the public API.

- **Frozen contract. Every 1.x release is backwards-compatible.** No breaking changes to the 6 frozen traits, the `certify()` signature, or the public data types without a major version bump.
- **5-year stability guarantee.** A test written in year 1 still compiles and passes in year 6 on the latest 1.x release.
- **1000+ community-contributed ops.** The standard library is driven by community pull requests, validated entirely by the conform pipeline.
- **All major GPU backends supported.** wgpu, Metal, CUDA, and any additional community backends are first-class citizens in the certification matrix.
- **Published formal proofs for every Cat A composition.** Every algebraic composition in Category A has a machine-checkable proof published alongside the crate.

---

*This roadmap is a commitment, not a wish list. Items move only forward. Delays are communicated via GitHub releases, not by silently deferring milestones.*
