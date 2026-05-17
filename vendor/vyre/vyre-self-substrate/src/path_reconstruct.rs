//! Path-reconstruction substrate consumer.
//!
//! Wires `vyre_primitives::graph::path_reconstruct::cpu_ref` so the
//! optimizer can recover an explicit walk from a parent vector. Used
//! by call-graph diagnostics (which path led from entry to a region
//! flagged by an analysis pass), megakernel chain reconstruction, and
//! schedule-explanation telemetry.
//!
//! Per the primitive's spec: walks parent links from `target` back to
//! the root (a node whose parent points at itself), writing the
//! materialized path into a caller-provided scratch buffer and
//! returning its length.

use vyre_primitives::graph::path_reconstruct::cpu_ref as path_reconstruct_cpu;

/// Reconstruct the path from `target` to its root, writing the
/// `(target, parent, ..., root)` sequence into `scratch`. Returns the
/// number of valid entries written; trailing slots up to `max_depth`
/// are zero-filled to keep the buffer size predictable.
///
/// Bumps the dataflow-fixpoint substrate counter so observability
/// captures every reconstruction.
#[must_use]
pub fn reconstruct_path(
    parent: &[u32],
    target: u32,
    max_depth: u32,
    scratch: &mut Vec<u32>,
) -> u32 {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    path_reconstruct_cpu(parent, target, max_depth, scratch)
}

/// Convenience wrapper: returns the reconstructed path as an owned
/// `Vec<u32>` truncated to actual length. Allocates fresh on every
/// call — callers in hot paths should use [`reconstruct_path`] with
/// a reusable scratch buffer instead.
#[must_use]
pub fn path_to_root(parent: &[u32], target: u32, max_depth: u32) -> Vec<u32> {
    let mut scratch = Vec::with_capacity(max_depth as usize);
    let len = reconstruct_path(parent, target, max_depth, &mut scratch);
    scratch.truncate(len as usize);
    scratch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_chain_to_root() {
        // 0 is root (parent[0] = 0); 1 -> 0; 2 -> 1; 3 -> 2.
        let parent = vec![0, 0, 1, 2];
        let path = path_to_root(&parent, 3, 4);
        assert_eq!(path, vec![3, 2, 1, 0]);
    }

    #[test]
    fn reconstructs_root_yields_singleton() {
        let parent = vec![0, 0, 1];
        let path = path_to_root(&parent, 0, 4);
        assert_eq!(path, vec![0]);
    }

    /// Closure-bar: substrate call equals primitive call exactly.
    #[test]
    fn matches_primitive_directly() {
        let parent = vec![0, 0, 1, 2];
        let mut a = Vec::new();
        let mut b = Vec::new();
        let len_a = reconstruct_path(&parent, 3, 4, &mut a);
        let len_b = path_reconstruct_cpu(&parent, 3, 4, &mut b);
        assert_eq!((len_a, &a), (len_b, &b));
    }

    /// Adversarial: max_depth bound must terminate even on a cycle
    /// (parent forms a non-trivial loop). The primitive's contract:
    /// stop when length reaches `max_depth`.
    #[test]
    fn max_depth_terminates_on_cycle() {
        // 0 -> 1 -> 2 -> 0 (cycle, no real root).
        let parent = vec![1, 2, 0];
        let path = path_to_root(&parent, 0, 5);
        assert_eq!(path.len(), 5);
    }

    /// Adversarial: scratch buffer is zero-filled to `max_depth`
    /// past the actual path length. A common bug is to leave stale
    /// values in scratch slots beyond `len` — assert all unused
    /// slots are zero.
    #[test]
    fn scratch_zero_filled_past_len() {
        let parent = vec![0, 0, 1];
        let mut scratch = Vec::new();
        let len = reconstruct_path(&parent, 2, 8, &mut scratch);
        assert_eq!(len, 3);
        assert_eq!(scratch.len(), 8);
        for &v in &scratch[len as usize..] {
            assert_eq!(v, 0, "trailing slots must be zero-filled");
        }
    }

    /// Adversarial: scratch is cleared before each call, so reuse
    /// across reconstructions doesn't leak old paths.
    #[test]
    fn scratch_cleared_between_calls() {
        let parent = vec![0, 0, 1, 2];
        let mut scratch = Vec::new();
        // First call: deep path.
        assert_eq!(reconstruct_path(&parent, 3, 4, &mut scratch), 4);
        // Second call: target is root, expect path length 1.
        let len = reconstruct_path(&parent, 0, 4, &mut scratch);
        assert_eq!(len, 1);
        assert_eq!(scratch[0], 0);
    }
}
