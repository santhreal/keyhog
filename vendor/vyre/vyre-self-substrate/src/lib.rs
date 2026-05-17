#![allow(
    clippy::doc_lazy_continuation,
    clippy::double_must_use,
    clippy::manual_div_ceil,
    clippy::needless_range_loop,
    clippy::collapsible_if,
    clippy::match_like_matches_macro,
    clippy::redundant_closure
)]
//! Self-substrate — vyre using its own primitives to compile/dispatch vyre.
//!
//! These modules realize the **recursion thesis** (#30): every Tier-2.5
//! primitive shipped in `vyre-primitives` also has a vyre-self consumer
//! here that uses the same Program at compile / dispatch time.
//!
//! # Layering (audit cleanup A10, 2026-04-30)
//!
//! Extracted from `vyre-driver/src/self_substrate/` into a dedicated
//! crate so the substrate-self-uses live at a layer that depends only
//! on `vyre-foundation` + `vyre-primitives` — eliminating the layering
//! muddle where backend-specific dispatch code and substrate self-uses
//! shared one home in `vyre-driver`.
//!
//! ```text
//!   vyre-foundation
//!         ↑
//!   vyre-primitives
//!         ↑
//!   vyre-self-substrate          ← THIS CRATE (no driver deps)
//!         ↑
//!   vyre-driver / vyre-runtime / vyre-libs / vyre-driver-{cuda,wgpu}
//! ```
//!
//! No cycles. Every consumer above this crate reaches the substrate
//! via `vyre_self_substrate::*` directly.
//!
//! `vyre-foundation` cannot consume `self_substrate` from here because
//! `self_substrate` depends on `vyre-primitives` which depends on
//! `vyre-foundation` — that's the cycle that justifies the dedicated
//! crate. Foundation has its own smaller substrate at
//! `vyre_foundation::pass_substrate` (with the math kernels it needs
//! inlined locally — same pattern Linux uses for arch-local libs vs
//! `lib/`).
//!
//! # Module list
//!
//! - `dataflow_fixpoint` (#26) — Region-graph dataflow fixpoint via
//!   `vyre-primitives::math::semiring_gemm` over the Region adjacency.
//! - `cost_model` (#28) — probabilistic dispatch cost model via
//!   `vyre-primitives::graph::sum_product_circuit` + conformal
//!   intervals from `vyre-primitives::math::conformal`.
//! - `vsa_fingerprint` (#29) — VSA op-cache key via
//!   `vyre-primitives::hash::hypervector`.
//! - `spectral_schedule` (#23) — spectral clustering of dispatch
//!   graph via `vyre-primitives::graph::chebyshev_filter` +
//!   `vyre-primitives::math::spectral_shape`.
//! - `differentiable_autotune` (#27) — differentiable autotuner via
//!   `vyre-primitives::math::differentiable`.
//! - `polyhedral_fusion` (#19) — polyhedral / affine fusion via
//!   `vyre-primitives::math::semiring_gemm` on the affine-dependency
//!   adjacency.
//! - `megakernel_schedule` (#22) — megakernel ILP relaxation via
//!   `vyre-primitives::opt::homotopy` continuation.
//! - `tensor_train_chain_fusion` (#6) — chain-shaped Region fusion via
//!   `vyre-primitives::math::tensor_train::tt_contract_step` contraction.
//! - `do_calculus_change_impact` (#36) — rule-graph change-impact analysis
//!   via `vyre-primitives::graph::do_calculus` graph surgery.
//! - `scallop_provenance` (#39) — GPU-resident rule provenance closure via
//!   `vyre-primitives::math::scallop_join` Datalog fixpoint.
//! - `matroid_megakernel_scheduler` (#46) — discrete fusion-grouping via
//!   matroid intersection augmenting paths. Complements
//!   `megakernel_schedule` (#22 homotopy continuous solver) with the
//!   exact combinatorial selection.
//! - `mori_zwanzig_region_coarsen` (#58) — Region-tree coarse-graining
//!   via Mori-Zwanzig projection. Reduces O(N²) all-pairs analyses to
//!   O(K²) at workspace scale with quantified projection error.
//! - `fmm_polyhedral_compress` (#51) — FMM hierarchical compression of
//!   #19 polyhedral fusion's all-pairs affinity. Drops cost from O(N²)
//!   to O(N log N) at workspace scale.
//! - `submodular_cache_eviction` (#45) — pipeline-cache eviction via
//!   submodular maximization. Replaces LRU's heuristic with the
//!   provably-(1-1/e) greedy approximation.
//! - `qsvt_matrix_function_fusion` (#34) — transport-based fusion
//!   analysis via QSVT-applied matrix functions. Computes Wasserstein
//!   distances on dispatch graphs in O(K·N²) instead of O(N³).
//! - `persistent_homology_loop_signature` (#15) — Region-tree loop
//!   topology via Vietoris-Rips filtration. Fusion-vs-fission decision
//!   informed by H₁ persistent features.
//! - `adjustment_set_pass_dependency` (#37) — optimizer pass-ordering
//!   validity via causal back-door analysis on the rewrite-precondition
//!   graph.
//! - `functorial_pass_composition` (#52) — IR transform passes as
//!   categorical functors. Compositionality, equational reasoning, free
//!   adjoint pairs — pass framework moves from hand-managed DAG to a
//!   typed functor-category.
//! - `string_diagram_ir_rewrite` (#53) — Vyre IR Region tree IS a
//!   string diagram in Cat(GPU buffers, Programs). Optimizer rewrites
//!   become string-diagram rewrites; coherence theorems give free
//!   correctness proofs.
//! - `planar_rewrite_pass_scheduler` (#11) — schedule batch IR rewrites
//!   onto disjoint sub-trees via planar non-overlapping selection.
//!   Drops dispatch count from O(N) sequential to O(log N) batched.

pub mod adjustment_set_pass_dependency;
pub mod alias_registry;
pub mod amg_pass_solver;
pub mod bellman_tn_order;
pub mod bitset_summary;
pub mod categorical_check;
pub mod cost_model;
pub mod csr_bidirectional;
pub mod csr_forward_or_changed;
pub mod dataflow_fixpoint;
pub mod decision_telemetry;
pub mod differentiable_autotune;
pub mod dnnf_compile;
pub mod do_calculus_change_impact;
pub mod dominator_frontier;
pub mod effect_signature_check;
pub mod exploded;
pub mod fmm_polyhedral_compress;
pub mod functorial_pass_composition;
pub mod kfac_autotune_step;
pub mod knowledge_compile_pass_precondition;
pub mod level_wave_pass;
pub mod linear_type_check;
pub mod matroid_exact_megakernel;
pub mod matroid_megakernel_scheduler;
pub mod megakernel_schedule;
pub mod mori_zwanzig_region_coarsen;
pub mod motif;
pub mod multigrid_matroid_solver;
pub mod natural_gradient_autotuner;
pub mod observability;
pub mod path_reconstruct;
pub mod persistent_bfs;
pub mod persistent_fixpoint_program;
pub mod persistent_homology_loop_signature;
pub mod planar_rewrite_pass_scheduler;
pub mod polyhedral_fusion;
pub mod qsvt_matrix_function_fusion;
pub mod scallop_provenance;
pub mod scallop_provenance_wide;
pub mod shape_smt_check;
pub mod sheaf_heterophilic_dispatch;
pub mod sheaf_spectral_clustering;
pub mod sinkhorn_dispatch_clustering;
pub mod sinkhorn_full_clustering;
pub mod spectral_schedule;
pub mod string_diagram_ir_rewrite;
pub mod submodular_cache_eviction;
pub mod tensor_network_fusion_order;
pub mod tensor_train_chain_fusion;
pub mod tensor_train_compression;
pub mod toposort;
pub mod union_find_emit;
pub mod vsa_fingerprint;
pub mod zx_rewrite;
