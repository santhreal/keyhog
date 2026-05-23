//! Path-reconstruction substrate consumer.
//!
//! Wires `vyre_primitives::graph::path_reconstruct` so the optimizer can
//! recover an explicit walk from a parent vector. Used by call-graph
//! diagnostics (which path led from entry to a region flagged by an analysis
//! pass), megakernel chain reconstruction, and schedule-explanation telemetry.
//!
//! Per the primitive's spec: walks parent links from `target` back to
//! the root (a node whose parent points at itself), writing the
//! materialized path into a caller-provided scratch buffer and
//! returning its length.

#[cfg(test)]
use vyre_primitives::graph::path_reconstruct::cpu_ref as path_reconstruct_cpu;
use vyre_primitives::graph::path_reconstruct::{
    batched_path_reconstruct as primitive_batched_path_reconstruct,
    path_reconstruct as primitive_path_reconstruct, validate_batched_path_reconstruct_layout,
    BATCHED_WORKGROUP_SIZE,
};

use crate::dispatch_buffers::{
    ceil_div_u32, decode_u32_output_exact, ensure_input_slots, u32_word_bytes,
    write_u32_slice_le_bytes, write_zero_bytes, write_zero_u32_words,
};
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher};
#[cfg(test)]
use vyre_foundation::ir::Program;

/// Caller-owned GPU dispatch scratch for path reconstruction.
#[derive(Debug, Default)]
pub struct PathReconstructGpuScratch {
    target_buf: Vec<u32>,
    inputs: Vec<Vec<u8>>,
    len_out: Vec<u32>,
}

/// Reconstruct the path from `target` to its root, writing the
/// `(target, parent, ..., root)` sequence into `scratch`. Returns the
/// number of valid entries written; trailing slots up to `max_depth`
/// are zero-filled to keep the buffer size predictable.
///
/// Bumps the dataflow-fixpoint substrate counter so observability
/// captures every reconstruction.
#[must_use]
#[cfg(test)]
pub fn reference_reconstruct_path(
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
#[cfg(test)]
pub fn path_to_root(parent: &[u32], target: u32, max_depth: u32) -> Vec<u32> {
    let mut scratch = Vec::with_capacity(max_depth as usize);
    let len = reference_reconstruct_path(parent, target, max_depth, &mut scratch);
    scratch.truncate(len as usize);
    scratch
}

/// GPU dispatch wrapper around [`reconstruct_path`]. Returns the
/// number of valid entries written to `scratch` (zero-padded to
/// `max_depth`).
///
/// # Errors
///
/// Propagates dispatch failures and rejects malformed readback.
pub fn reconstruct_path_via(
    dispatcher: &dyn OptimizerDispatcher,
    parent: &[u32],
    target: u32,
    max_depth: u32,
    scratch: &mut Vec<u32>,
) -> Result<u32, DispatchError> {
    let mut dispatch_scratch = PathReconstructGpuScratch::default();
    reconstruct_path_via_with_scratch(
        dispatcher,
        parent,
        target,
        max_depth,
        &mut dispatch_scratch,
        scratch,
    )
}

/// GPU dispatch wrapper around the path-reconstruction primitive with caller-owned dispatch scratch.
pub fn reconstruct_path_via_with_scratch(
    dispatcher: &dyn OptimizerDispatcher,
    parent: &[u32],
    target: u32,
    max_depth: u32,
    dispatch_scratch: &mut PathReconstructGpuScratch,
    scratch: &mut Vec<u32>,
) -> Result<u32, DispatchError> {
    if max_depth == 0 {
        return Err(DispatchError::BadInputs(
            "Fix: reconstruct_path_via requires max_depth > 0.".to_string(),
        ));
    }
    let depth = max_depth as usize;
    let program = primitive_path_reconstruct("parent", "target", "path_out", "path_len", max_depth);
    dispatch_scratch.target_buf.clear();
    dispatch_scratch.target_buf.push(target);
    ensure_input_slots(&mut dispatch_scratch.inputs, 4);
    write_u32_slice_le_bytes(&mut dispatch_scratch.inputs[0], parent);
    write_u32_slice_le_bytes(
        &mut dispatch_scratch.inputs[1],
        &dispatch_scratch.target_buf,
    );
    let path_bytes = u32_word_bytes(depth, "reconstruct_path_via path_out")?;
    write_zero_bytes(&mut dispatch_scratch.inputs[2], path_bytes);
    write_zero_u32_words(
        &mut dispatch_scratch.inputs[3],
        1,
        "reconstruct_path_via path_len",
    )?;
    let outputs = dispatcher.dispatch(&program, &dispatch_scratch.inputs, Some([1, 1, 1]))?;
    if outputs.len() != 2 {
        return Err(DispatchError::BackendError(format!(
            "Fix: reconstruct_path_via expected 2 output buffers (path_out, path_len), got {}.",
            outputs.len()
        )));
    }
    decode_u32_output_exact(&outputs[0], depth, "reconstruct_path_via path_out", scratch)?;
    decode_u32_output_exact(
        &outputs[1],
        1,
        "reconstruct_path_via path_len",
        &mut dispatch_scratch.len_out,
    )?;
    Ok(dispatch_scratch.len_out[0])
}

/// Convenience wrapper for dispatcher-backed single-target reconstruction.
///
/// Returns the reconstructed path truncated to the actual length. Callers that
/// reconstruct many targets should use [`reconstruct_paths_via`] to avoid
/// launch-per-target amplification.
///
/// # Errors
///
/// Returns [`DispatchError`] when validation or backend execution fails.
pub fn path_to_root_via(
    dispatcher: &dyn OptimizerDispatcher,
    parent: &[u32],
    target: u32,
    max_depth: u32,
) -> Result<Vec<u32>, DispatchError> {
    let mut scratch = Vec::with_capacity(max_depth as usize);
    let len = reconstruct_path_via(dispatcher, parent, target, max_depth, &mut scratch)?;
    scratch.truncate(len as usize);
    Ok(scratch)
}

/// GPU dispatch wrapper around batched parent-walk: reconstructs the
/// path-to-root for every entry in `targets` simultaneously. Returns
/// `(paths, lens)` where `paths` is the concatenation of each
/// target's `max_depth`-padded scratch buffer and `lens[i]` is the
/// valid length for `targets[i]`.
///
/// # Errors
///
/// Propagates path-reconstruction dispatch failures.
pub fn reconstruct_paths_via(
    dispatcher: &dyn OptimizerDispatcher,
    parent: &[u32],
    targets: &[u32],
    max_depth: u32,
) -> Result<(Vec<u32>, Vec<u32>), DispatchError> {
    let mut scratch = PathReconstructGpuScratch::default();
    let mut paths = Vec::new();
    let mut lens = Vec::new();
    reconstruct_paths_via_with_scratch_into(
        dispatcher,
        parent,
        targets,
        max_depth,
        &mut scratch,
        &mut paths,
        &mut lens,
    )?;
    Ok((paths, lens))
}

/// GPU dispatch wrapper around batched parent-walk into caller-owned output storage.
pub fn reconstruct_paths_via_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    parent: &[u32],
    targets: &[u32],
    max_depth: u32,
    scratch: &mut PathReconstructGpuScratch,
    paths: &mut Vec<u32>,
    lens: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let layout = validate_batched_path_reconstruct_layout(targets.len(), max_depth)
        .map_err(DispatchError::BadInputs)?;
    if layout.target_count == 0 {
        paths.clear();
        lens.clear();
        return Ok(());
    }
    let program = primitive_batched_path_reconstruct(layout.target_count, max_depth);
    ensure_input_slots(&mut scratch.inputs, 4);
    write_u32_slice_le_bytes(&mut scratch.inputs[0], parent);
    write_u32_slice_le_bytes(&mut scratch.inputs[1], targets);
    let path_bytes = u32_word_bytes(layout.path_words, "reconstruct_paths_via paths")?;
    let lens_bytes = u32_word_bytes(targets.len(), "reconstruct_paths_via lens")?;
    write_zero_bytes(&mut scratch.inputs[2], path_bytes);
    write_zero_bytes(&mut scratch.inputs[3], lens_bytes);
    let outputs = dispatcher.dispatch(
        &program,
        &scratch.inputs,
        Some([
            ceil_div_u32(layout.target_count, BATCHED_WORKGROUP_SIZE),
            1,
            1,
        ]),
    )?;
    if outputs.len() != 2 {
        return Err(DispatchError::BackendError(format!(
            "Fix: reconstruct_paths_via expected 2 output buffers (paths, lens), got {}.",
            outputs.len()
        )));
    }
    decode_u32_output_exact(
        &outputs[0],
        layout.path_words,
        "reconstruct_paths_via paths",
        paths,
    )?;
    decode_u32_output_exact(
        &outputs[1],
        targets.len(),
        "reconstruct_paths_via lens",
        lens,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch_buffers::u32_slice_to_le_bytes;
    use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher};

    struct PathDispatcher;

    impl OptimizerDispatcher for PathDispatcher {
        fn dispatch(
            &self,
            _program: &Program,
            inputs: &[Vec<u8>],
            grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            assert_eq!(inputs.len(), 4);
            let parent = read_u32s(&inputs[0]);
            let targets = read_u32s(&inputs[1]);
            let out_words = inputs[2].len() / std::mem::size_of::<u32>();
            let max_depth = out_words / targets.len().max(1);
            if targets.len() == 1 {
                assert_eq!(grid_override, Some([1, 1, 1]));
            } else {
                assert_eq!(grid_override, Some([1, 1, 1]));
            }
            let mut paths = Vec::with_capacity(out_words);
            let mut lens = Vec::with_capacity(targets.len());
            for target in targets {
                let start = paths.len();
                let mut current = target;
                let mut len = 0u32;
                while len < max_depth as u32 {
                    paths.push(current);
                    len += 1;
                    let next = parent.get(current as usize).copied().unwrap_or(current);
                    if next == current {
                        break;
                    }
                    current = next;
                }
                while paths.len() < start + max_depth {
                    paths.push(0);
                }
                lens.push(len);
            }
            Ok(vec![
                u32_slice_to_le_bytes(&paths),
                u32_slice_to_le_bytes(&lens),
            ])
        }
    }

    fn read_u32s(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(std::mem::size_of::<u32>())
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect()
    }

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
        let len_a = reference_reconstruct_path(&parent, 3, 4, &mut a);
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
        let len = reference_reconstruct_path(&parent, 2, 8, &mut scratch);
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
        assert_eq!(reference_reconstruct_path(&parent, 3, 4, &mut scratch), 4);
        // Second call: target is root, expect path length 1.
        let len = reference_reconstruct_path(&parent, 0, 4, &mut scratch);
        assert_eq!(len, 1);
        assert_eq!(scratch[0], 0);
    }

    #[test]
    fn reconstruct_path_via_dispatches_single_target() {
        let parent = vec![0, 0, 1, 2];
        let mut scratch = Vec::new();

        let len = reconstruct_path_via(&PathDispatcher, &parent, 3, 4, &mut scratch).unwrap();

        assert_eq!(len, 4);
        assert_eq!(scratch, vec![3, 2, 1, 0]);
    }

    #[test]
    fn path_to_root_via_truncates_padding() {
        let parent = vec![0, 0, 1, 2];

        let path = path_to_root_via(&PathDispatcher, &parent, 2, 8).unwrap();

        assert_eq!(path, vec![2, 1, 0]);
    }

    #[test]
    fn reconstruct_paths_via_batches_targets_in_one_dispatch() {
        let parent = vec![0, 0, 1, 2];

        let (paths, lens) = reconstruct_paths_via(&PathDispatcher, &parent, &[3, 0, 2], 4).unwrap();

        assert_eq!(lens, vec![4, 1, 3]);
        assert_eq!(paths, vec![3, 2, 1, 0, 0, 0, 0, 0, 2, 1, 0, 0]);
    }

    #[test]
    fn reconstruct_paths_via_with_scratch_reuses_dispatch_and_outputs() {
        let parent = vec![0, 0, 1, 2];
        let mut dispatch_scratch = PathReconstructGpuScratch::default();
        let mut paths = Vec::with_capacity(12);
        let mut lens = Vec::with_capacity(3);

        reconstruct_paths_via_with_scratch_into(
            &PathDispatcher,
            &parent,
            &[3, 0, 2],
            4,
            &mut dispatch_scratch,
            &mut paths,
            &mut lens,
        )
        .unwrap();

        let input_capacities = dispatch_scratch
            .inputs
            .iter()
            .map(Vec::capacity)
            .collect::<Vec<_>>();
        let paths_capacity = paths.capacity();
        let lens_capacity = lens.capacity();

        reconstruct_paths_via_with_scratch_into(
            &PathDispatcher,
            &parent,
            &[2, 1, 0],
            4,
            &mut dispatch_scratch,
            &mut paths,
            &mut lens,
        )
        .unwrap();

        assert_eq!(
            dispatch_scratch
                .inputs
                .iter()
                .map(Vec::capacity)
                .collect::<Vec<_>>(),
            input_capacities
        );
        assert_eq!(paths.capacity(), paths_capacity);
        assert_eq!(lens.capacity(), lens_capacity);
        assert_eq!(lens, vec![3, 2, 1]);
        assert_eq!(paths, vec![2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn reconstruct_paths_via_rejects_zero_depth() {
        let err = reconstruct_paths_via(&PathDispatcher, &[0], &[0], 0).unwrap_err();

        assert!(matches!(err, DispatchError::BadInputs(_)));
    }

    #[test]
    fn production_source_keeps_cpu_path_helpers_out_of_via_path() {
        let source = include_str!("path_reconstruct.rs");
        let via_section = source
            .split("pub fn reconstruct_path_via(")
            .nth(1)
            .expect("via section should exist")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("test module marker should exist");

        assert!(!via_section.contains("path_reconstruct_cpu"));
        assert!(!via_section.contains("reference_reconstruct_path"));
        assert!(!via_section.contains("path_words * std::mem::size_of::<u32>()"));
        assert!(!via_section.contains("targets.len() * std::mem::size_of::<u32>()"));
        assert!(via_section.contains("u32_word_bytes"));
        assert!(via_section.contains("reconstruct_paths_via paths"));
        assert!(via_section.contains("reconstruct_paths_via lens"));
    }
}
