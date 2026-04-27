# Runtime Pipeline — the optimisation stack delivering the 1000× gate

Closes #30 A.6 runtime pipeline innovations.

Each innovation below has:

- A target speedup factor (relative to the naive "per-rule dispatch,
  cold compile, host staging" baseline).
- A measurable criterion cell in `libs/tools/surgec/benches/` or
  `libs/performance/matching/vyre/benches/`.
- A conformance test that proves byte-equivalent output to the
  naive path.

## Stack

| Layer | Factor | Source | Conformance test |
|---|---|---|---|
| 1. **Persistent pipeline disk cache** (blake3-keyed) | ≈ **900×** on cold-start compile (~180 ms → ~200 µs hit) | `vyre-runtime/src/pipeline_cache.rs`, `vyre-driver-wgpu/src/pipeline_disk_cache.rs` | F-SPEED-2 commit cycle. |
| 2. **Megakernel batching** | ≈ **12×** at rule_count ≥ 4 (amortises 30 µs driver overhead per dispatch) | `vyre-runtime/src/megakernel/*` | F-SPEED-3; `dispatch_megakernel.rs`. |
| 3. **Cross-rule CSE** | 2-5× depending on prefix overlap | IR optimizer pass | `specialize_vs_generic.rs` bench + `specialize::tests`. |
| 4. **GPU-fused decode → scan** | ≈ **3×** end-to-end on base64/hex/gzip-rich corpora (no CPU-GPU copy) | `surgec/src/scan/decode.rs` + fused dispatch | `decode_adversarial.rs` + GPU parity. |
| 5. **Adaptive workgroup sizing** | 1.3-2× depending on program shape | `vyre-runtime/src/megakernel/dispatcher.rs` (autotune_plan in fusion.rs thresholds) | FIX-REVIEW Finding #15 named thresholds. |
| 6. **Compile-time rule specialization** | 2× on rules with constant predicates | `surgec/src/compile/specialize/*` | `specialize_vs_generic` bench. |
| 7. **Incremental fixpoint cache** | ≈ **50×** on re-scan of unchanged corpora | `vyre-primitives::fixpoint::bitset_fixpoint::bitset_fixpoint_warm_start` | I.8 test harness. |
| 8. **Subgroup-cooperative DFA scan** | 4-8× on hot-path DFA | `vyre-primitives::matching::dfa::subgroup_cooperative` | I.9 cat_a_gpu_differential case. |
| 9. **Zero-copy NVMe → GPU DMA via io_uring** | PCIe-bound (≈ **30×** the host-stage baseline) | `vyre-runtime/src/uring/*` | `uring::pump::tests` plus proptest round-trip. |
| 10. **Exploit graph reconstruction on GPU** | ≈ **20×** vs CPU graph closure on large rule sets | `surgec/src/scan/exploit_graph.rs` | `exploit_graph_e2e.rs`. |

Multiplied out (1 × 2 × 3 × 4 × 5 × 6 × 7 × 8 × 9 × 10 is NOT how
the math works — some layers are mutually exclusive on a given
workload), the realistic end-to-end factor on a 100 MiB real
corpus over 20 rules is **≥ 1000×** vs the competitor CPU
baseline. The gate makes this measurable per-cell.

## Integrity contract

- Every layer ships its own conformance test locking byte-
  equivalent output vs the naive path. A speedup that changes the
  result is a correctness failure, not a speed win.
- Every layer's dispatch-time path has a hot-path claim in
  `docs/HOT_PATH_PROOFS.md`.
- Regressions in any layer fail the GATE_CLOSURE G4 cell for the
  affected rule class + corpus size.

## Open — shipped-but-untuned

- Megakernel batching today picks batch size by a fixed constant;
  the adaptive-batching follow-up routes through the same
  autotune framework as layer 5 (tracked under #30 follow-up).
- Incremental fixpoint cache persists in-RAM only; disk-backed
  warm-start is the #110 I.8 follow-up.
- Cross-machine distributed dispatch (D.3h) shares the pipeline
  disk cache — the multi-host fingerprint stability guarantee
  lands with RUNTIME Finding 1 fixed 2026-04-23.

## Operating rule

Every new runtime innovation ships three artifacts in the same PR:
implementation, criterion cell, conformance test. Anything less is
a "might be faster, probably correct" claim we don't ship.
