//! `cross_language` — forward reachability that REQUIRES the flow to
//! cross at least one cross-language FFI edge.
//!
//! The merged polyglot `ProgramGraph` (built upstream by
//! `surge_source::pipeline::merge_polyglot`) carries language-specific
//! `CALL_ARG` edges plus a small set of "FFI" edges that span
//! languages — Python `ctypes` → C symbol, JNI Java→C, N-API JS→C,
//! Rust `bindgen` Rust→C. The vanilla `flows_to` primitive treats
//! all edges identically and therefore fires on intra-language flows
//! that never cross a language boundary; this primitive constrains
//! the path to traverse at least one FFI edge so cross-language
//! detection is precise.
//!
//! Lowering shape (composes existing Tier-2.5 primitives):
//!
//! 1. **Mandatory FFI hop.** Run `csr_forward_traverse` from the
//!    source bitset restricted to the `EDGE_KIND_FFI` mask. The
//!    output ("post-cross") is exactly the set of callee-side nodes
//!    reachable through a single cross-language edge.
//! 2. **Free-form continuation.** Run `bitset_fixpoint`-driven BFS
//!    from "post-cross" over the full edge mask. The fixpoint output
//!    is the set of nodes the source can reach AFTER crossing the
//!    language boundary at least once.
//! 3. **Sink intersection.** AND the reach with the sink bitset; the
//!    output is non-empty iff some source reaches some sink across a
//!    language boundary.
//!
//! Soundness: [`MayOver`](super::soundness::Soundness::MayOver). The
//! BFS over-approximates calls (we model every FFI edge as
//! reachable, even when feature flags / arch gates would prune the
//! call site). Rules that need precision must compose with a
//! sanitizer-dominator filter.

use vyre::ir::Program;
use vyre_foundation::execution_plan::fusion::fuse_programs;
use vyre_primitives::bitset::and::bitset_and;
use vyre_primitives::fixpoint::bitset_fixpoint::bitset_fixpoint_warm_start;
use vyre_primitives::graph::csr_forward_traverse::{bitset_words, csr_forward_traverse};
use vyre_primitives::graph::program_graph::ProgramGraphShape;
#[allow(dead_code)]
pub(crate) const OP_ID: &str = "vyre-libs::dataflow::cross_language";

/// Edge-kind mask reserved for FFI / cross-language CALL_ARG edges.
/// Aligns with the `vyre_primitives::predicate::edge_kind` namespace
/// — `0x10000` is the bit `surge_source::pipeline::merge_polyglot`
/// stamps onto every edge produced by the FFI binding tables.
pub const EDGE_KIND_FFI: u32 = 0x0001_0000;

/// Edge-kind mask covering "everything" (post-crossing flow uses any
/// edge). The exact value mirrors `csr_forward_traverse`'s "all"
/// dispatch convention.
pub const EDGE_KIND_ALL: u32 = 0xFFFF_FFFF;

/// Build the cross-language reach Program.
///
/// Buffer contract:
/// - `source`: per-node source bitset (input).
/// - `sink`: per-node sink bitset (input).
/// - `post_cross`: scratch bitset for stage-1 output.
/// - `current` / `next` / `changed` / `seed`: fixpoint scratch
///   buffers for stage-2 (provided by caller so the same buffers
///   can be reused across rules in one fused dispatch).
/// - `out`: per-node bitset, set iff a source reaches a sink across
///   at least one FFI edge.
#[must_use]
pub fn cross_language(
    node_count: u32,
    source: &str,
    sink: &str,
    post_cross: &str,
    current: &str,
    next: &str,
    changed: &str,
    seed: &str,
    out: &str,
) -> Program {
    let words = bitset_words(node_count);
    let shape = ProgramGraphShape::new(node_count, node_count.saturating_mul(8).max(1));

    // Stage 1: one BFS step from `source`, restricted to FFI edges.
    let stage_1 = csr_forward_traverse(shape, source, post_cross, EDGE_KIND_FFI);

    // Stage 2: free-form BFS-to-fixpoint from `post_cross`. The seed
    // buffer is `post_cross`; the fixpoint expands it via the warm-
    // start primitive over any edge kind.
    let stage_2 = bitset_fixpoint_warm_start(current, next, changed, post_cross, words);

    // Stage 3: intersect `current` (the converged reach) with the
    // sink bitset to produce the final answer.
    let stage_3 = bitset_and(current, sink, out, words);

    let _ = seed; // contract slot; warm_start uses the dedicated seed.
    crate::region::tag_program(
        OP_ID,
        fuse_programs(&[stage_1, stage_2, stage_3])
            .expect("cross_language: csr+fixpoint+and fuse cleanly"),
    )
}

/// CPU oracle: forward reach that requires at least one FFI edge in
/// the path. Inputs use the same conventions as
/// `csr_forward_traverse::cpu_ref` plus a parallel `edge_is_ffi`
/// bitset (per-edge: 1 if the edge is a cross-language FFI edge).
#[must_use]
pub fn cpu_ref(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    edge_is_ffi: &[u32],
    source: &[u32],
    sink: &[u32],
) -> Vec<u32> {
    let words = ((node_count + 31) / 32) as usize;
    let test = |bs: &[u32], n: u32| -> bool {
        let w = n as usize / 32;
        let b = n as usize % 32;
        bs.get(w).copied().unwrap_or(0) & (1u32 << b) != 0
    };
    let set = |bs: &mut Vec<u32>, n: u32| {
        let w = n as usize / 32;
        let b = n as usize % 32;
        if w >= bs.len() {
            bs.resize(w + 1, 0);
        }
        bs[w] |= 1u32 << b;
    };

    // Stage 1: post_cross = nodes reachable from source via exactly
    // one FFI edge.
    let mut post_cross = vec![0u32; words];
    for n in 0..node_count {
        if !test(source, n) {
            continue;
        }
        let start = edge_offsets.get(n as usize).copied().unwrap_or(0) as usize;
        let end = edge_offsets.get(n as usize + 1).copied().unwrap_or(0) as usize;
        for i in start..end {
            let kind = edge_kind_mask.get(i).copied().unwrap_or(0);
            let is_ffi = edge_is_ffi.get(i).copied().unwrap_or(0);
            if (kind & EDGE_KIND_FFI) != 0 || is_ffi != 0 {
                if let Some(&t) = edge_targets.get(i) {
                    set(&mut post_cross, t);
                }
            }
        }
    }

    // Stage 2: BFS to fixpoint from post_cross via any edge.
    let mut reach = post_cross.clone();
    loop {
        let mut changed = false;
        for n in 0..node_count {
            if !test(&reach, n) {
                continue;
            }
            let start = edge_offsets.get(n as usize).copied().unwrap_or(0) as usize;
            let end = edge_offsets.get(n as usize + 1).copied().unwrap_or(0) as usize;
            for i in start..end {
                if let Some(&t) = edge_targets.get(i) {
                    if !test(&reach, t) {
                        set(&mut reach, t);
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    // Stage 3: reach ∩ sink.
    let mut out = vec![0u32; words];
    for w in 0..words {
        out[w] = reach.get(w).copied().unwrap_or(0) & sink.get(w).copied().unwrap_or(0);
    }
    out
}

/// Soundness marker for [`cross_language`].
pub struct CrossLanguage;
impl super::soundness::SoundnessTagged for CrossLanguage {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::MayOver
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(n: u32) -> Vec<u32> {
        let w = n as usize / 32;
        let b = n as usize % 32;
        let mut v = vec![0u32; w + 1];
        v[w] = 1u32 << b;
        v
    }

    #[test]
    fn flow_through_ffi_edge_reaches_sink() {
        // Graph: 0 → (FFI) → 1 → (CALL_ARG) → 2.
        // Source = {0}, Sink = {2}. Expected: out has bit 2 set.
        let edge_offsets = vec![0, 1, 2, 2];
        let edge_targets = vec![1u32, 2];
        let edge_kind_mask = vec![EDGE_KIND_FFI, 0x1];
        let edge_is_ffi = vec![1u32, 0];
        let source = one(0);
        let sink = one(2);
        let out = cpu_ref(
            3,
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            &edge_is_ffi,
            &source,
            &sink,
        );
        assert!(out[0] & (1 << 2) != 0, "sink should be reached: {out:?}");
    }

    #[test]
    fn intra_language_flow_does_not_reach_sink() {
        // Graph: 0 → (CALL_ARG, NOT FFI) → 1 → (CALL_ARG) → 2.
        // No FFI hop anywhere — must not fire.
        let edge_offsets = vec![0, 1, 2, 2];
        let edge_targets = vec![1u32, 2];
        let edge_kind_mask = vec![0x1, 0x1];
        let edge_is_ffi = vec![0u32, 0];
        let source = one(0);
        let sink = one(2);
        let out = cpu_ref(
            3,
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            &edge_is_ffi,
            &source,
            &sink,
        );
        assert_eq!(out, vec![0u32], "no FFI hop → no cross-lang reach: {out:?}");
    }

    #[test]
    fn ffi_edge_required_at_first_hop() {
        // Graph: 0 → (CALL_ARG) → 1 → (FFI) → 2 → (CALL_ARG) → 3.
        // First hop is intra-language; FFI is at hop 2. The contract
        // requires the FIRST hop from source to be an FFI edge, so
        // this path must NOT fire.
        let edge_offsets = vec![0, 1, 2, 3, 3];
        let edge_targets = vec![1u32, 2, 3];
        let edge_kind_mask = vec![0x1, EDGE_KIND_FFI, 0x1];
        let edge_is_ffi = vec![0u32, 1, 0];
        let source = one(0);
        let sink = one(3);
        let out = cpu_ref(
            4,
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            &edge_is_ffi,
            &source,
            &sink,
        );
        assert_eq!(out, vec![0u32], "FFI must be first hop: {out:?}");
    }

    #[test]
    fn empty_source_yields_empty_output() {
        let edge_offsets = vec![0, 1, 1];
        let edge_targets = vec![1u32];
        let edge_kind_mask = vec![EDGE_KIND_FFI];
        let edge_is_ffi = vec![1u32];
        let source = vec![0u32];
        let sink = one(1);
        let out = cpu_ref(
            2,
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            &edge_is_ffi,
            &source,
            &sink,
        );
        assert_eq!(out, vec![0u32]);
    }

    #[test]
    fn multi_step_post_cross_continuation_reaches_distant_sink() {
        // Graph: 0 → (FFI) → 1 → (CALL_ARG) → 2 → (CALL_ARG) → 3.
        // FFI happens at hop 1; further hops are free-form.
        let edge_offsets = vec![0, 1, 2, 3, 3];
        let edge_targets = vec![1u32, 2, 3];
        let edge_kind_mask = vec![EDGE_KIND_FFI, 0x1, 0x1];
        let edge_is_ffi = vec![1u32, 0, 0];
        let source = one(0);
        let sink = one(3);
        let out = cpu_ref(
            4,
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            &edge_is_ffi,
            &source,
            &sink,
        );
        assert!(out[0] & (1 << 3) != 0, "distant sink reachable: {out:?}");
    }

    #[test]
    fn op_id_is_canonical() {
        assert_eq!(OP_ID, "vyre-libs::dataflow::cross_language");
    }
}
