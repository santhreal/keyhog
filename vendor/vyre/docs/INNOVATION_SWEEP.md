# Missing-Innovation Sweep

Closes #46 D.3 (missing-innovation sweep).

A parallel to `UX_SWEEP.md`: running log of what the vision promises
that the code hasn't shipped yet, plus the concrete innovation ideas
harvested from audits and the competition landscape that should
land before 0.7.

## Shipped innovations (0.6 cycle)

| Innovation | Why it matters | Landed in |
|---|---|---|
| **Persistent pipeline cache** (blake3-keyed disk cache of canonicalised Program → SPIR-V) | Cold-start compile was ~180 ms per rule. Pipeline cache drops it to ~200 µs on cache hit. | F-SPEED-2 |
| **Megakernel batching** | Per-rule dispatch costs ~30 µs of driver overhead; fusing 4+ rules amortises that. | F-SPEED-3 |
| **Cross-rule CSE** | Two rules that share a DFA prefix compile into one GPU kernel; duplicate work elided at IR level. | I.2 |
| **GPU-fused decode → scan** | Base64 / gzip / hex decode pipelined with scan so the decoded bytes never leave GPU memory. | I.1 |
| **Adaptive workgroup sizing** | Picks workgroup size per program at dispatch time from a small measured matrix instead of a hard-coded constant. | I.6 |
| **Compile-time rule specialization** | Programs with const operands partially-evaluate at compile time, skipping whole Loop bodies on GPU. | I.10 |
| **Incremental fixpoint cache** | Warm-start `bitset_fixpoint` with the previous dispatch's final state; converges in ~0 iterations on unchanged inputs. | I.8 |
| **Subgroup-cooperative DFA scan** | 32 lanes cooperatively scan one input stream instead of racing on independent streams; ~8× throughput on hot paths. | I.9 |
| **Exploit graph reconstruction on GPU** | Moves the graph-closure step off CPU; every session-wide reachability query is a single dispatch. | I.5 |
| **Zero-copy NVMe → GPU DMA via io_uring** | Bypasses the CPU staging copy; corpus throughput ≈ PCIe bandwidth. | I.3 |
| **Live kernel hot-reload** | Edit a rule, save, see new output without restarting surgec. | D.3a |
| **Rule-differential replay** | Only emit findings that appeared after a named rule change. | D.3b |
| **Watch mode** | Same as hot-reload but streaming findings continuously. | D.3g |
| **Auto-suppression proposals** | When a fix lands, surgec offers to suppress the finding until re-scan. | D.3f |
| **Offline `.surge-bundle`** | Sign a compiled Program + rule set for air-gapped dispatch. | D.3k |
| **surgec `run_program` API + E2E** | Arbitrary compute dispatch, not just scan; the V4 + V10 foundation. | VISION V4 + V10 |
| **Dangerous-exploits feature gate** | Offensive PoCs behind a conscious opt-in instead of shipping by default. | POCGEN 1.1 |
| **Succinct rank/select bitvector navigation** | Rank1 superblocks, rank1 queries, and select1 queries give compact AST/graph navigation over packed bitvectors without pointer-heavy host structures. | `vyre-libs::math::succinct` |

## Open — not yet landed

| Innovation | Why it matters | Tracked |
|---|---|---|
| Surge-lang **predicate registry** replacing hardcoded `emit_predicate` arms | A community predicate becomes a file drop instead of 3-crate edits. | VISION V3 (#230) |
| **`surgec run` CLI verb** | Makes the arbitrary-compute path first-class at the CLI surface, not just the library surface. | VISION V4 CLI half (#231 done Rust-level) |
| **Metal / DX12 / CUDA PTX / photonic backends** | Vulkan + SPIR-V today; VISION promises the backend list goes wider. `docs/targets.md` sketches the order. | #29 (naga lowering holes block cross-backend coverage) |
| **Taint-flow as a first-class Program** | Currently vein-style CPU graph; hoisting into vyre IR unifies the analysis with matching compute. | #79 F-A5 |
| **GPU-resident AST as a first-class buffer** | Treat the AST as a graph in GPU memory so structural queries dispatch the same way as scans. | I.7 |
| **Incremental AST zippers from data-structure derivatives** | Regular-type derivatives give one-hole contexts; in vyre this becomes a concrete edit-context buffer for localized AST invalidation, taint recomputation, and parser cache repair without full-tree diffing. Roadmap only until VAST/PG columns are stable. | Parser roadmap A10 |
| **Method of Four Russians packed boolean kernels** | Boolean matrix multiplication, parser reachability, and DFA/dataflow closure can trade repeated branchy work for block lookup tables over `log2(n)`-sized chunks. This is a real substrate optimization for boolean semiring kernels, not a blanket 10-50x guarantee. | Semiring/GraphBLAS backlog |
| **Spectral graph summaries** | Laplacian/Fiedler-value style summaries are useful for component, bottleneck, and partition telemetry over huge analysis graphs. They do not replace exact source-to-sink reachability, but can guide scheduling and graph sharding. | Graph telemetry backlog |
| **Fixpoint verifier** | Mathematically prove a fixpoint converged, not just "we iterated N times". | C.1 richness thread |
| **ByteRange + tag → dialect-scoped return types** | Each dialect owns how it tags ranges; `vyre_primitives::range::ByteRange` is the foundation. | VISION V1 |
| **Surgec distributed dispatch** | Shard a huge corpus across N machines sharing the pipeline disk cache. | D.3h (partial) |
| ~~Neural-net suspicion pre-filter~~ | ~~Route only "suspicious" inputs to the full scan.~~ | **I.4 — RETIRED.** The 2026-04 implementation was a no-op workgroup-size nudge gated on `vyre-libs::nn::` region names, not a neural network. The cooperative DFA (I.9) covers the "skip regions that can't match" case structurally. Do not resurrect under the same name — if learned routing is wanted, design an actual inference path with a conformance-signed model bundle and a proof it beats the DFA. |
| **Region-chain CI gate against Tier-2 leaves** | Not just "a Region chain exists" but "bottoms at an intrinsic". | VISION V7 landed; stricter variant TBD |
| **F-NAGA naga lowering holes closure** | Subgroup ballot / shuffle / gather still reject on a couple of shapes. | #171 |
| **Benchmark-driven CI thresholds** | Replace hand-set `thresholds.toml` with "previous release minus 3σ". | D.3 follow-up |
| ~~NTT / approximate matching~~ | ~~Polynomial convolution is useful for fuzzy matching, but it has different correctness and false-positive contracts than VYRE substrate matching.~~ | **RETIRED FROM ACTIVE VYRE.** Future domain-specific wrapper only. |
| ~~Gröbner-basis rule solving as a general rule engine~~ | ~~Boolean formulas can be encoded as polynomials over GF(2), but Gröbner-basis computation is not a guaranteed bypass for NP-hard logical search.~~ | **RETIRED FROM ACTIVE VYRE.** Keep only as a research note for tiny fixed-shape algebraic simplification. |
| ~~Braid-group taint/concurrency~~ | ~~Braid groups and normal forms are real, but taint safety, sanitization, domination, and path feasibility do not reduce cleanly to braid identity.~~ | **RETIRED FROM ACTIVE VYRE.** |
| ~~Homology/Betti CFG analysis as semantic reachability~~ | ~~Betti numbers can summarize components/cycles, but program reachability, termination, and scope semantics do not become homology alone.~~ | **RETIRED FROM ACTIVE VYRE.** |
| ~~LSH / continuous vector spaces for fuzzy code similarity~~ | ~~LSH is valid approximate nearest-neighbor machinery, but fuzzy matching is a product/domain wrapper concern, not core VYRE substrate.~~ | **RETIRED FROM ACTIVE VYRE.** Future wrapper only. |

## Review cadence

This doc refreshes every session. Innovations that land move to
Shipped; new ideas from audits / competition studies land in Open.
The trend over sessions is the only metric that matters — Open
shrinking while Shipped grows.
