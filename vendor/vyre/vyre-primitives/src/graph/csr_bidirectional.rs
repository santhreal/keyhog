//! `csr_bidirectional` — one BFS step over BOTH forward + backward
//! edges of a ProgramGraph CSR. Used for undirected reachability
//! (e.g. component discovery, alias unification).

use vyre_foundation::execution_plan::fusion::fuse_programs;
use vyre_foundation::ir::{DataType, Program};

use crate::graph::csr_backward_traverse::csr_backward_traverse;
use crate::graph::csr_forward_traverse::{bitset_words, csr_forward_traverse};
use crate::graph::program_graph::ProgramGraphShape;

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::csr_bidirectional";

/// Build a Program: emit one forward step + one backward step,
/// fused into one Region. Both writes target `frontier_out` so a
/// single dispatch covers both directions.
#[must_use]
pub fn csr_bidirectional(
    shape: ProgramGraphShape,
    frontier_in: &str,
    frontier_out: &str,
    edge_kind_mask: u32,
) -> Program {
    let fwd = csr_forward_traverse(shape, frontier_in, frontier_out, edge_kind_mask);
    let bwd = csr_backward_traverse(shape, frontier_in, frontier_out, edge_kind_mask);
    fuse_programs(&[fwd, bwd]).unwrap_or_else(|error| {
        crate::invalid_output_program(
            OP_ID,
            frontier_out,
            DataType::U32,
            format!("Fix: csr_bidirectional forward+backward fusion failed: {error}"),
        )
    })
}

/// CPU reference: union of forward + backward one-step reach.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
) -> Vec<u32> {
    let mut out = Vec::new();
    cpu_ref_into(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        allow_mask,
        &mut out,
    );
    out
}

/// CPU reference writing the unioned forward/backward step into caller-owned storage.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_into(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
    out: &mut Vec<u32>,
) {
    let words = crate::graph::csr_forward_traverse::bitset_words(node_count) as usize;
    out.clear();
    out.resize(words, 0);
    validate_csr_inputs(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
    )
    .unwrap_or_else(|err| panic!("csr_bidirectional CPU oracle received malformed input. {err}"));
    for src in 0..node_count as usize {
        let src_word = src / 32;
        let src_bit = 1u32 << (src % 32);
        let src_in_frontier =
            src_word < frontier_in.len() && (frontier_in[src_word] & src_bit) != 0;
        let edge_start = edge_offsets[src] as usize;
        let edge_end = edge_offsets[src + 1] as usize;
        let mut backward_hit = false;
        for edge in edge_start..edge_end.min(edge_targets.len()).min(edge_kind_mask.len()) {
            if edge_kind_mask[edge] & allow_mask == 0 {
                continue;
            }
            let dst = edge_targets[edge] as usize;
            let dst_word = dst / 32;
            let dst_bit = 1u32 << (dst % 32);
            if src_in_frontier && dst < node_count as usize {
                out[dst_word] |= dst_bit;
            }
            if dst_word < frontier_in.len() && (frontier_in[dst_word] & dst_bit) != 0 {
                backward_hit = true;
            }
        }
        if backward_hit && src_word < out.len() {
            out[src_word] |= src_bit;
        }
    }
}

/// Validated dispatch layout for bidirectional CSR traversal.
///
/// The primitive owns these derived values so dispatch wrappers do not fork
/// CSR/frontier layout rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CsrBidirectionalLayout {
    /// Number of nodes accepted by the primitive.
    pub node_count: u32,
    /// Number of `u32` frontier words required for `node_count`.
    pub words: usize,
    /// Number of node-index words required by graph-indexed scratch buffers.
    pub node_words: usize,
    /// Exact edge count declared by `edge_offsets[node_count]`.
    pub edge_count: u32,
    /// Number of u32 words required by physical edge buffers after padding.
    pub edge_storage_words: usize,
}

/// Validate the public CSR/frontier inputs consumed by the bidirectional
/// traversal primitive.
///
/// Returns the full dispatch layout so wrappers can build padded device buffers
/// without re-parsing the CSR contract locally.
///
/// # Errors
///
/// Returns an actionable diagnostic when offsets, edge arrays, frontier width,
/// or destinations violate the primitive's contract.
pub fn validate_csr_inputs(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
) -> Result<CsrBidirectionalLayout, String> {
    let expected_offsets = (node_count as usize).checked_add(1).ok_or_else(|| {
        format!(
            "Fix: csr_bidirectional node_count + 1 overflows usize for node_count={node_count}."
        )
    })?;
    if edge_offsets.len() != expected_offsets {
        return Err(format!(
            "Fix: csr_bidirectional requires edge_offsets.len() == node_count + 1, got len={}, node_count={node_count}.",
            edge_offsets.len()
        ));
    }

    let expected_frontier_words = bitset_words(node_count) as usize;
    if frontier_in.len() != expected_frontier_words {
        return Err(format!(
            "Fix: csr_bidirectional expected frontier length {expected_frontier_words} words for {node_count} nodes, got {}.",
            frontier_in.len()
        ));
    }

    if edge_targets.len() != edge_kind_mask.len() {
        return Err(format!(
            "Fix: csr_bidirectional requires edge_targets.len() == edge_kind_mask.len(), got {} vs {}.",
            edge_targets.len(),
            edge_kind_mask.len()
        ));
    }

    if let Some(&first) = edge_offsets.first() {
        if first != 0 {
            return Err(format!(
                "Fix: csr_bidirectional requires edge_offsets[0] == 0, got {first}."
            ));
        }
    }
    for (index, pair) in edge_offsets.windows(2).enumerate() {
        if pair[0] > pair[1] {
            return Err(format!(
                "Fix: csr_bidirectional offsets must be monotonic; offsets[{index}]={} > offsets[{}]={}.",
                pair[0],
                index + 1,
                pair[1]
            ));
        }
    }

    let edge_count = edge_offsets[expected_offsets - 1] as usize;
    if edge_targets.len() != edge_count {
        return Err(format!(
            "Fix: csr_bidirectional final offset declares edge_count={edge_count}, but targets_len={} and kind_mask_len={}.",
            edge_targets.len(),
            edge_kind_mask.len()
        ));
    }
    for (index, &target) in edge_targets.iter().enumerate() {
        if target >= node_count {
            return Err(format!(
                "Fix: csr_bidirectional edge_targets[{index}]={target} is outside node_count {node_count}."
            ));
        }
    }
    let edge_count = u32::try_from(edge_count).map_err(|_| {
        format!("Fix: csr_bidirectional edge count {edge_count} exceeds u32 index space.")
    })?;
    Ok(CsrBidirectionalLayout {
        node_count,
        words: expected_frontier_words,
        node_words: node_count as usize,
        edge_count,
        edge_storage_words: edge_targets.len().max(1),
    })
}

/// CPU reference: iterate bidirectional one-step reach to fixpoint or `max_iters`.
///
/// This computes the connected-neighborhood closure of `seed` under
/// `allow_mask` using the same one-step oracle as [`cpu_ref`]. It lives in
/// primitives so consumers do not fork fixpoint semantics.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_closure(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
) -> Vec<u32> {
    let mut current = Vec::new();
    let mut next = Vec::new();
    cpu_ref_closure_into(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        seed,
        allow_mask,
        max_iters,
        &mut current,
        &mut next,
    );
    current
}

/// CPU reference: closure into caller-owned buffers.
#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_closure_into(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
) {
    cpu_ref_closure_into_with_step_hook(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        seed,
        allow_mask,
        max_iters,
        current,
        next,
        || {},
    );
}

/// CPU reference: closure into caller-owned buffers with a per-step hook.
///
/// Consumers use `on_step` for telemetry only; closure semantics remain owned
/// by this primitive module.
#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_closure_into_with_step_hook<F>(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
    mut on_step: F,
) where
    F: FnMut(),
{
    current.clear();
    current.extend_from_slice(seed);
    next.clear();
    for _ in 0..max_iters {
        on_step();
        cpu_ref_into(
            node_count,
            edge_offsets,
            edge_targets,
            edge_kind_mask,
            current,
            allow_mask,
            next,
        );
        if !merge_frontier_or_changed(current, next) {
            return;
        }
    }
}

/// Merge a bidirectional step frontier into the accumulated closure.
///
/// Returns `true` when at least one bit was newly set. This helper owns the
/// fixpoint-merge semantics so dispatch consumers do not fork closure logic.
///
/// # Panics
///
/// Panics when the two frontier slices differ in length. That is a caller
/// contract violation: both slices must be bitsets for the same `node_count`.
#[must_use]
pub fn merge_frontier_or_changed(current: &mut [u32], next: &[u32]) -> bool {
    assert_eq!(
        current.len(),
        next.len(),
        "Fix: bidirectional frontier merge requires equal bitset word counts, got current={} next={}.",
        current.len(),
        next.len()
    );
    let mut changed = false;
    for (dst, src) in current.iter_mut().zip(next.iter()) {
        let merged = *dst | *src;
        changed |= merged != *dst;
        *dst = merged;
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linear_graph() -> (Vec<u32>, Vec<u32>, Vec<u32>) {
        // 0 -> 1 -> 2 -> 3
        (vec![0, 1, 2, 3, 3], vec![1, 2, 3], vec![1, 1, 1])
    }

    #[test]
    fn forward_step_propagates() {
        let (off, tgt, msk) = linear_graph();
        let out = cpu_ref(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF);
        // 0's forward neighbor = 1 → bit 1 set.
        assert!(out[0] & 0b0010 != 0);
    }

    #[test]
    fn empty_seed_yields_empty_step() {
        let (off, tgt, msk) = linear_graph();
        let out = cpu_ref(4, &off, &tgt, &msk, &[0], 0xFFFF_FFFF);
        assert_eq!(out, vec![0]);
    }

    #[test]
    fn allow_mask_zero_blocks_all() {
        let (off, tgt, msk) = linear_graph();
        let out = cpu_ref(4, &off, &tgt, &msk, &[0b0001], 0);
        assert_eq!(out, vec![0]);
    }

    #[test]
    fn bidirectional_includes_both_directions() {
        let (off, tgt, msk) = linear_graph();
        // From {1}, forward reaches {2}; backward reaches {0}.
        let out = cpu_ref(4, &off, &tgt, &msk, &[0b0010], 0xFFFF_FFFF);
        assert!(out[0] & 0b0001 != 0, "bwd should reach node 0");
        assert!(out[0] & 0b0100 != 0, "fwd should reach node 2");
    }

    #[test]
    fn closure_reaches_full_linear_component() {
        let (off, tgt, msk) = linear_graph();
        let out = cpu_ref_closure(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 5);
        assert_eq!(out, vec![0b1111]);
    }

    #[test]
    fn closure_into_reuses_caller_buffers() {
        let (off, tgt, msk) = linear_graph();
        let mut current = Vec::with_capacity(8);
        let mut next = Vec::with_capacity(8);
        cpu_ref_closure_into(
            4,
            &off,
            &tgt,
            &msk,
            &[0b0001],
            0xFFFF_FFFF,
            5,
            &mut current,
            &mut next,
        );
        assert_eq!(current, vec![0b1111]);
        assert_eq!(current.capacity(), 8);
        assert_eq!(next.capacity(), 8);
    }

    #[test]
    fn merge_frontier_reports_change_and_or_merges_words() {
        let mut current = [0b0001u32, 0b1000];
        let next = [0b0110u32, 0b1000];
        assert!(merge_frontier_or_changed(&mut current, &next));
        assert_eq!(current, [0b0111, 0b1000]);
        assert!(!merge_frontier_or_changed(&mut current, &next));
    }

    #[test]
    #[should_panic(
        expected = "Fix: bidirectional frontier merge requires equal bitset word counts"
    )]
    fn merge_frontier_rejects_mismatched_word_counts() {
        let mut current = [0u32];
        let next = [1u32, 2];
        let _ = merge_frontier_or_changed(&mut current, &next);
    }

    #[test]
    fn validate_csr_inputs_accepts_empty_and_canonical_graphs() {
        assert_eq!(
            validate_csr_inputs(0, &[0], &[], &[], &[]).unwrap(),
            CsrBidirectionalLayout {
                node_count: 0,
                words: 0,
                node_words: 0,
                edge_count: 0,
                edge_storage_words: 1,
            }
        );

        let (off, tgt, msk) = linear_graph();
        assert_eq!(
            validate_csr_inputs(4, &off, &tgt, &msk, &[0]).unwrap(),
            CsrBidirectionalLayout {
                node_count: 4,
                words: 1,
                node_words: 4,
                edge_count: 3,
                edge_storage_words: 3,
            }
        );
    }

    #[test]
    fn validate_csr_inputs_rejects_frontier_and_csr_contract_violations() {
        let err = validate_csr_inputs(2, &[0, 1, 1], &[1], &[1], &[]).unwrap_err();
        assert!(err.contains("expected frontier length"));

        let err = validate_csr_inputs(2, &[0, 1, 1], &[1], &[], &[0]).unwrap_err();
        assert!(err.contains("edge_targets.len() == edge_kind_mask.len()"));

        let err = validate_csr_inputs(2, &[0, 2, 1], &[1], &[1], &[0]).unwrap_err();
        assert!(err.contains("offsets must be monotonic"));

        let err = validate_csr_inputs(2, &[0, 1, 1], &[5], &[1], &[0]).unwrap_err();
        assert!(err.contains("outside node_count"));
    }
}
