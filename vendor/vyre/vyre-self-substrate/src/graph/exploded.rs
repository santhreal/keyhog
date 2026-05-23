//! Exploded-supergraph (IFDS encoding) substrate consumer.
//!
//! Wires `vyre_primitives::graph::exploded::build_cpu_reference` (zero
//! prior consumers) into the substrate so the optimizer can build
//! interprocedural-dataflow graphs directly. The IFDS encoding packs
//! `(proc_id, block_id, fact_id)` into a u32 node id, then composes
//! intra-/inter-procedural edges + GEN/KILL flow into a CSR ready for
//! reachability/closure analysis.

#[cfg(any(test, feature = "cpu-parity"))]
use vyre_primitives::graph::exploded::build_cpu_reference;
#[cfg(any(test, feature = "cpu-parity"))]
use vyre_primitives::graph::exploded::canonicalize_csr_within_rows;
use vyre_primitives::graph::exploded::{
    build_ifds_csr_program,
    canonicalize_csr_within_rows_in_place as primitive_canonicalize_csr_within_rows_in_place,
    dense_to_encoded, encoded_to_dense, ifds_node_count_saturating, validate_ifds_csr_inputs,
};

use crate::dispatch_buffers::{
    decode_u32_output_exact, ensure_input_slots, u32_word_bytes, write_u32_slice_or_zero_words,
    write_zero_bytes, write_zero_u32_words,
};
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher};

/// Caller-owned GPU dispatch scratch for exploded IFDS CSR construction.
#[derive(Debug, Default)]
pub struct IfdsCsrGpuScratch {
    intra_proc: Vec<u32>,
    intra_src_block: Vec<u32>,
    intra_dst_block: Vec<u32>,
    inter_src_proc: Vec<u32>,
    inter_src_block: Vec<u32>,
    inter_dst_proc: Vec<u32>,
    inter_dst_block: Vec<u32>,
    gen_proc: Vec<u32>,
    gen_block: Vec<u32>,
    gen_fact: Vec<u32>,
    kill_proc: Vec<u32>,
    kill_block: Vec<u32>,
    kill_fact: Vec<u32>,
    inputs: Vec<Vec<u8>>,
    row_cursor: Vec<u32>,
    col_len_words: Vec<u32>,
}

/// Build an exploded supergraph and return its CSR `(row_ptr, col_idx)`.
/// Inputs match the underlying primitive's contract; the wrapper bumps
/// the dataflow-fixpoint observability counter so dispatch-time IFDS
/// graph builds are visible in dashboards.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn reference_build_ifds_csr(
    num_procs: u32,
    blocks_per_proc: u32,
    facts_per_proc: u32,
    intra_edges: &[(u32, u32, u32)],
    inter_edges: &[(u32, u32, u32, u32)],
    flow_gen: &[(u32, u32, u32)],
    flow_kill: &[(u32, u32, u32)],
) -> (Vec<u32>, Vec<u32>) {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    build_cpu_reference(
        num_procs,
        blocks_per_proc,
        facts_per_proc,
        intra_edges,
        inter_edges,
        flow_gen,
        flow_kill,
    )
}

/// Total node count of the exploded supergraph for the given
/// dimensions. Equivalent to `row_ptr.len() - 1` after the CSR is
/// built; useful when the caller needs to size frontier bitsets
/// before invoking [`reference_build_ifds_csr`].
#[must_use]
pub fn ifds_node_count(num_procs: u32, blocks_per_proc: u32, facts_per_proc: u32) -> u32 {
    ifds_node_count_saturating(num_procs, blocks_per_proc, facts_per_proc)
}

/// Helper: round-trip a dense index through the packed encoding and
/// back. Used by callers that emit findings keyed on the packed id
/// but operate on dense indices internally.
#[must_use]
pub fn round_trip_dense(dense: u32, blocks_per_proc: u32, facts_per_proc: u32) -> Option<u32> {
    let encoded = dense_to_encoded(dense, blocks_per_proc, facts_per_proc)?;
    encoded_to_dense(encoded, blocks_per_proc, facts_per_proc)
}

/// Sort each row's column indices in ascending order. Pure CPU helper
/// used by parity tests to compare CSRs whose row contents may have
/// been emitted in different orders by parallel kernels.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn reference_canonicalize_csr_within_rows(
    row_ptr: &[u32],
    col_idx: &[u32],
) -> (Vec<u32>, Vec<u32>) {
    canonicalize_csr_within_rows(row_ptr, col_idx)
}

/// GPU dispatch wrapper around [`reference_build_ifds_csr`].
///
/// Returns the supergraph CSR in canonical (within-row sorted) form
/// so callers comparing against the reference oracle don't need to
/// re-canonicalise the output.
///
/// # Errors
///
/// Propagates dispatch failures and rejects dimensions or readback
/// shapes that cannot represent an exploded CSR safely.
#[allow(clippy::too_many_arguments)]
pub fn build_ifds_csr_via(
    dispatcher: &dyn OptimizerDispatcher,
    num_procs: u32,
    blocks_per_proc: u32,
    facts_per_proc: u32,
    intra_edges: &[(u32, u32, u32)],
    inter_edges: &[(u32, u32, u32, u32)],
    flow_gen: &[(u32, u32, u32)],
    flow_kill: &[(u32, u32, u32)],
) -> Result<(Vec<u32>, Vec<u32>), DispatchError> {
    let mut row_ptr = Vec::new();
    let mut col_idx = Vec::new();
    build_ifds_csr_via_into(
        dispatcher,
        num_procs,
        blocks_per_proc,
        facts_per_proc,
        intra_edges,
        inter_edges,
        flow_gen,
        flow_kill,
        &mut row_ptr,
        &mut col_idx,
    )?;
    Ok((row_ptr, col_idx))
}

/// GPU dispatch wrapper around [`reference_build_ifds_csr`] into caller-owned CSR buffers.
#[allow(clippy::too_many_arguments)]
pub fn build_ifds_csr_via_into(
    dispatcher: &dyn OptimizerDispatcher,
    num_procs: u32,
    blocks_per_proc: u32,
    facts_per_proc: u32,
    intra_edges: &[(u32, u32, u32)],
    inter_edges: &[(u32, u32, u32, u32)],
    flow_gen: &[(u32, u32, u32)],
    flow_kill: &[(u32, u32, u32)],
    row_ptr_out: &mut Vec<u32>,
    col_idx_out: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let mut scratch = IfdsCsrGpuScratch::default();
    build_ifds_csr_via_with_scratch_into(
        dispatcher,
        num_procs,
        blocks_per_proc,
        facts_per_proc,
        intra_edges,
        inter_edges,
        flow_gen,
        flow_kill,
        &mut scratch,
        row_ptr_out,
        col_idx_out,
    )
}

/// GPU dispatch wrapper around [`reference_build_ifds_csr`] into caller-owned
/// dispatch scratch and CSR buffers.
#[allow(clippy::too_many_arguments)]
pub fn build_ifds_csr_via_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    num_procs: u32,
    blocks_per_proc: u32,
    facts_per_proc: u32,
    intra_edges: &[(u32, u32, u32)],
    inter_edges: &[(u32, u32, u32, u32)],
    flow_gen: &[(u32, u32, u32)],
    flow_kill: &[(u32, u32, u32)],
    scratch: &mut IfdsCsrGpuScratch,
    row_ptr_out: &mut Vec<u32>,
    col_idx_out: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let layout = validate_ifds_csr_inputs(
        num_procs,
        blocks_per_proc,
        facts_per_proc,
        intra_edges,
        inter_edges,
        flow_gen,
        flow_kill,
    )
    .map_err(DispatchError::BadInputs)?;
    if layout.empty {
        row_ptr_out.clear();
        row_ptr_out.push(0);
        col_idx_out.clear();
        return Ok(());
    }
    let row_bytes = u32_word_bytes(layout.row_words, "build_ifds_csr_via row_ptr")?;
    let row_cursor_bytes =
        u32_word_bytes(layout.row_cursor_words, "build_ifds_csr_via row_cursor")?;
    let col_buffer_bytes = u32_word_bytes(layout.col_buffer_words, "build_ifds_csr_via col_idx")?;

    split3_into(
        intra_edges,
        &mut scratch.intra_proc,
        &mut scratch.intra_src_block,
        &mut scratch.intra_dst_block,
    );
    split4_into(
        inter_edges,
        &mut scratch.inter_src_proc,
        &mut scratch.inter_src_block,
        &mut scratch.inter_dst_proc,
        &mut scratch.inter_dst_block,
    );
    split3_into(
        flow_gen,
        &mut scratch.gen_proc,
        &mut scratch.gen_block,
        &mut scratch.gen_fact,
    );
    split3_into(
        flow_kill,
        &mut scratch.kill_proc,
        &mut scratch.kill_block,
        &mut scratch.kill_fact,
    );
    let program = build_ifds_csr_program(
        layout.num_procs,
        layout.blocks_per_proc,
        layout.facts_per_proc,
        layout.intra_count,
        layout.inter_count,
        layout.gen_count,
        layout.kill_count,
        layout.max_col_count,
    );
    ensure_input_slots(&mut scratch.inputs, 17);
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[0],
        &scratch.intra_proc,
        layout.intra_storage_words,
        "build_ifds_csr_via intra_proc",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[1],
        &scratch.intra_src_block,
        layout.intra_storage_words,
        "build_ifds_csr_via intra_src_block",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[2],
        &scratch.intra_dst_block,
        layout.intra_storage_words,
        "build_ifds_csr_via intra_dst_block",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[3],
        &scratch.inter_src_proc,
        layout.inter_storage_words,
        "build_ifds_csr_via inter_src_proc",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[4],
        &scratch.inter_src_block,
        layout.inter_storage_words,
        "build_ifds_csr_via inter_src_block",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[5],
        &scratch.inter_dst_proc,
        layout.inter_storage_words,
        "build_ifds_csr_via inter_dst_proc",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[6],
        &scratch.inter_dst_block,
        layout.inter_storage_words,
        "build_ifds_csr_via inter_dst_block",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[7],
        &scratch.gen_proc,
        layout.gen_storage_words,
        "build_ifds_csr_via gen_proc",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[8],
        &scratch.gen_block,
        layout.gen_storage_words,
        "build_ifds_csr_via gen_block",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[9],
        &scratch.gen_fact,
        layout.gen_storage_words,
        "build_ifds_csr_via gen_fact",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[10],
        &scratch.kill_proc,
        layout.kill_storage_words,
        "build_ifds_csr_via kill_proc",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[11],
        &scratch.kill_block,
        layout.kill_storage_words,
        "build_ifds_csr_via kill_block",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[12],
        &scratch.kill_fact,
        layout.kill_storage_words,
        "build_ifds_csr_via kill_fact",
    )?;
    write_zero_bytes(&mut scratch.inputs[13], row_bytes);
    write_zero_bytes(&mut scratch.inputs[14], row_cursor_bytes);
    write_zero_bytes(&mut scratch.inputs[15], col_buffer_bytes);
    write_zero_u32_words(
        &mut scratch.inputs[16],
        1,
        "build_ifds_csr_via overflow flag",
    )?;
    let outputs = dispatcher.dispatch(&program, &scratch.inputs, Some([1, 1, 1]))?;
    if outputs.len() != 4 {
        return Err(DispatchError::BackendError(format!(
            "Fix: build_ifds_csr_via expected exactly 4 output buffers (row_ptr, row_cursor, col_idx, col_len), got {}.",
            outputs.len()
        )));
    }
    decode_u32_output_exact(
        &outputs[0],
        layout.row_words,
        "build_ifds_csr_via row_ptr",
        row_ptr_out,
    )?;
    decode_u32_output_exact(
        &outputs[1],
        layout.row_cursor_words,
        "build_ifds_csr_via row_cursor",
        &mut scratch.row_cursor,
    )?;
    decode_u32_output_exact(
        &outputs[2],
        layout.col_buffer_words,
        "build_ifds_csr_via col_idx",
        col_idx_out,
    )?;
    decode_u32_output_exact(
        &outputs[3],
        1,
        "build_ifds_csr_via col_len",
        &mut scratch.col_len_words,
    )?;
    let col_len = scratch.col_len_words[0];
    if col_len > layout.max_col_count {
        return Err(DispatchError::BackendError(format!(
            "Fix: build_ifds_csr_via GPU reported col_len {col_len} above allocated maximum {}.",
            layout.max_col_count
        )));
    }
    col_idx_out.truncate(col_len as usize);
    canonicalize_csr_within_rows_in_place(row_ptr_out, col_idx_out)?;
    Ok(())
}

fn split3_into(triples: &[(u32, u32, u32)], a: &mut Vec<u32>, b: &mut Vec<u32>, c: &mut Vec<u32>) {
    a.clear();
    b.clear();
    c.clear();
    a.reserve(triples.len());
    b.reserve(triples.len());
    c.reserve(triples.len());
    for &(x, y, z) in triples {
        a.push(x);
        b.push(y);
        c.push(z);
    }
}

fn split4_into(
    quads: &[(u32, u32, u32, u32)],
    a: &mut Vec<u32>,
    b: &mut Vec<u32>,
    c: &mut Vec<u32>,
    d: &mut Vec<u32>,
) {
    a.clear();
    b.clear();
    c.clear();
    d.clear();
    a.reserve(quads.len());
    b.reserve(quads.len());
    c.reserve(quads.len());
    d.reserve(quads.len());
    for &(w, x, y, z) in quads {
        a.push(w);
        b.push(x);
        c.push(y);
        d.push(z);
    }
}

fn canonicalize_csr_within_rows_in_place(
    row_ptr: &[u32],
    col_idx: &mut [u32],
) -> Result<(), DispatchError> {
    primitive_canonicalize_csr_within_rows_in_place(row_ptr, col_idx)
        .map_err(DispatchError::BackendError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch_buffers::u32_slice_to_le_bytes;
    use vyre_foundation::ir::Program;

    struct IfdsDispatcher {
        outputs: Vec<Vec<u8>>,
    }

    impl OptimizerDispatcher for IfdsDispatcher {
        fn dispatch(
            &self,
            _program: &Program,
            inputs: &[Vec<u8>],
            grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            assert_eq!(grid_override, Some([1, 1, 1]));
            if inputs.len() != 17 {
                return Err(DispatchError::BadInputs(format!(
                    "Fix: IFDS test dispatcher expected 17 inputs, got {}.",
                    inputs.len()
                )));
            }
            Ok(self.outputs.clone())
        }
    }

    /// Two procs, 2 blocks each, 2 facts each. One intra edge per
    /// proc, no inter, no flow. The CSR row count must equal the
    /// total node count.
    #[test]
    fn csr_row_count_matches_node_count() {
        let (row_ptr, _) =
            reference_build_ifds_csr(2, 2, 2, &[(0, 0, 1), (1, 0, 1)], &[], &[], &[]);
        // Total = 2 * 2 * 2 = 8.
        assert_eq!(row_ptr.len(), 9);
        assert_eq!(ifds_node_count(2, 2, 2), 8);
    }

    /// Closure-bar: substrate output equals primitive output.
    #[test]
    fn matches_primitive_directly() {
        let intra = vec![(0, 0, 1), (1, 0, 1)];
        let inter = vec![(0, 1, 1, 0)];
        let gen_edges = vec![(0, 0, 1)];
        let kill = vec![(1, 0, 0)];
        let via_substrate = reference_build_ifds_csr(2, 2, 2, &intra, &inter, &gen_edges, &kill);
        let via_primitive = build_cpu_reference(2, 2, 2, &intra, &inter, &gen_edges, &kill);
        assert_eq!(via_substrate, via_primitive);
    }

    /// Empty IFDS domains are invalid: parity/reference graph construction
    /// needs a real exploded-supergraph domain, not a fake host-side empty CSR.
    #[test]
    #[should_panic(expected = "exploded IFDS CPU reference dimensions must be nonzero")]
    fn empty_graph_rejects_zero_domain() {
        let _ = reference_build_ifds_csr(0, 0, 0, &[], &[], &[], &[]);
    }

    /// Adversarial: KILL must suppress fact propagation along an
    /// intra edge. (proc 0, block 0, fact 1) is killed → no edge
    /// emitted from (0, 0, 1) to (0, 1, 1).
    #[test]
    fn kill_suppresses_fact_propagation() {
        let intra = vec![(0, 0, 1)];
        let kill = vec![(0, 0, 1)];
        let (row_ptr, col_idx) = reference_build_ifds_csr(1, 2, 2, &intra, &[], &[], &kill);
        // Node (0, 0, 1) is at dense index 0 * 4 + 0 * 2 + 1 = 1.
        let src = 1usize;
        let row_start = row_ptr[src] as usize;
        let row_end = row_ptr[src + 1] as usize;
        let neighbors = &col_idx[row_start..row_end];
        // Should have NO edge to (0, 1, 1) (= dense 0*4 + 1*2 + 1 = 3).
        assert!(!neighbors.contains(&3), "killed fact must not propagate");
    }

    /// Adversarial: GEN must inject the new fact along the intra
    /// edge. (proc 0, block 0, gen fact 1) → edge from (0, 0, 0)
    /// (the 0-fact) to (0, 1, 1).
    #[test]
    fn gen_injects_new_fact() {
        let intra = vec![(0, 0, 1)];
        let gen_edges = vec![(0, 0, 1)];
        let (row_ptr, col_idx) = reference_build_ifds_csr(1, 2, 2, &intra, &[], &gen_edges, &[]);
        // 0-fact at (0, 0, 0) → dense index 0.
        let row_start = row_ptr[0] as usize;
        let row_end = row_ptr[1] as usize;
        let neighbors = &col_idx[row_start..row_end];
        // Edge to (0, 1, 1) → dense 3.
        assert!(neighbors.contains(&3), "gen must emit edge to new fact");
    }

    /// Round-trip dense ↔ encoded must be identity for valid indices.
    #[test]
    fn round_trip_dense_is_identity() {
        let blocks_per_proc = 4;
        let facts_per_proc = 8;
        for dense in 0..32 {
            assert_eq!(
                round_trip_dense(dense, blocks_per_proc, facts_per_proc),
                Some(dense)
            );
        }
    }

    /// Adversarial: inter-procedural edge propagates EVERY fact
    /// (IFDS upper bound). For 2 facts, expect 2 edges from
    /// (sp, sb, *) to (dp, db, *).
    #[test]
    fn inter_edge_propagates_every_fact() {
        let inter = vec![(0, 0, 1, 1)];
        let (row_ptr, col_idx) = reference_build_ifds_csr(2, 2, 2, &[], &inter, &[], &[]);
        let dense_src_f0 = 0; // (0, 0, 0)
        let dense_src_f1 = 1; // (0, 0, 1)
        let row0 = &col_idx[row_ptr[dense_src_f0] as usize..row_ptr[dense_src_f0 + 1] as usize];
        let row1 = &col_idx[row_ptr[dense_src_f1] as usize..row_ptr[dense_src_f1 + 1] as usize];
        // (1, 1, 0) = 1*4 + 1*2 + 0 = 6
        // (1, 1, 1) = 1*4 + 1*2 + 1 = 7
        assert!(row0.contains(&6), "fact 0 must propagate via inter edge");
        assert!(row1.contains(&7), "fact 1 must propagate via inter edge");
    }

    #[test]
    fn via_decodes_exact_csr_outputs_into_reused_buffers() {
        let dispatcher = IfdsDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[0, 1, 1]),
                u32_slice_to_le_bytes(&[1, 1]),
                u32_slice_to_le_bytes(&[1]),
                u32_slice_to_le_bytes(&[1]),
            ],
        };
        let mut row_ptr = Vec::with_capacity(4);
        let mut col_idx = Vec::with_capacity(4);
        let row_ptr_ptr = row_ptr.as_ptr();
        let col_idx_ptr = col_idx.as_ptr();
        build_ifds_csr_via_into(
            &dispatcher,
            1,
            2,
            1,
            &[(0, 0, 1)],
            &[],
            &[],
            &[],
            &mut row_ptr,
            &mut col_idx,
        )
        .expect("dispatch succeeds");
        assert_eq!(row_ptr, vec![0, 1, 1]);
        assert_eq!(col_idx, vec![1]);
        assert_eq!(row_ptr.as_ptr(), row_ptr_ptr);
        assert_eq!(col_idx.as_ptr(), col_idx_ptr);
    }

    #[test]
    fn via_with_scratch_reuses_split_dispatch_decode_and_output_storage() {
        let dispatcher = IfdsDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[0, 1, 1]),
                u32_slice_to_le_bytes(&[1, 1]),
                u32_slice_to_le_bytes(&[1]),
                u32_slice_to_le_bytes(&[1]),
            ],
        };
        let mut scratch = IfdsCsrGpuScratch::default();
        let mut row_ptr = Vec::with_capacity(3);
        let mut col_idx = Vec::with_capacity(1);

        build_ifds_csr_via_with_scratch_into(
            &dispatcher,
            1,
            2,
            1,
            &[(0, 0, 1)],
            &[],
            &[],
            &[],
            &mut scratch,
            &mut row_ptr,
            &mut col_idx,
        )
        .expect("dispatch succeeds");

        let input_capacities = scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>();
        let intra_proc_capacity = scratch.intra_proc.capacity();
        let row_cursor_capacity = scratch.row_cursor.capacity();
        let col_len_capacity = scratch.col_len_words.capacity();
        let row_ptr_capacity = row_ptr.capacity();
        let col_idx_capacity = col_idx.capacity();

        build_ifds_csr_via_with_scratch_into(
            &dispatcher,
            1,
            2,
            1,
            &[(0, 0, 1)],
            &[],
            &[],
            &[],
            &mut scratch,
            &mut row_ptr,
            &mut col_idx,
        )
        .expect("dispatch succeeds");

        assert_eq!(
            scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>(),
            input_capacities
        );
        assert_eq!(scratch.intra_proc.capacity(), intra_proc_capacity);
        assert_eq!(scratch.row_cursor.capacity(), row_cursor_capacity);
        assert_eq!(scratch.col_len_words.capacity(), col_len_capacity);
        assert_eq!(row_ptr.capacity(), row_ptr_capacity);
        assert_eq!(col_idx.capacity(), col_idx_capacity);
        assert_eq!(row_ptr, vec![0, 1, 1]);
        assert_eq!(col_idx, vec![1]);
    }

    #[test]
    fn via_rejects_extra_outputs() {
        let dispatcher = IfdsDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[0, 0]),
                u32_slice_to_le_bytes(&[0]),
                u32_slice_to_le_bytes(&[0]),
                u32_slice_to_le_bytes(&[0]),
                u32_slice_to_le_bytes(&[0]),
            ],
        };
        let err = build_ifds_csr_via(&dispatcher, 1, 1, 1, &[], &[], &[], &[])
            .expect_err("extra outputs must be rejected");
        assert!(
            matches!(err, DispatchError::BackendError(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn via_rejects_trailing_col_len_bytes() {
        let dispatcher = IfdsDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[0, 0]),
                u32_slice_to_le_bytes(&[0]),
                u32_slice_to_le_bytes(&[0]),
                vec![0, 0, 0, 0, 1],
            ],
        };
        let err = build_ifds_csr_via(&dispatcher, 1, 1, 1, &[], &[], &[], &[])
            .expect_err("trailing col_len bytes must be rejected");
        assert!(
            matches!(err, DispatchError::BackendError(_)),
            "unexpected error: {err:?}"
        );
    }
}
