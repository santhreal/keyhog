//! Exploded supergraph primitive (G3).
//!
//! # What this is
//!
//! IFDS / IDE reframes interprocedural dataflow as a reachability
//! problem on the **exploded supergraph**: each `(proc, block,
//! fact)` triple is a graph vertex, and the edges are the flow
//! functions (GEN / KILL + summary + call-to-return). Once
//! expanded, the analysis collapses to a BFS over this graph —
//! which is the exact shape
//! [`crate::graph::csr_forward_traverse`] already handles.
//!
//! This module owns the **node encoding** — the bit-layout that
//! packs `(proc_id, block_id, fact_id)` into a single `u32` node id
//! — plus a CPU reference that builds the exploded CSR so tests in
//! `vyre-libs::dataflow::ifds_gpu` can prove the GPU kernel produces
//! byte-identical CSR output.
//!
//! # Bit layout
//!
//! ```text
//!   bits 31..20   proc_id   (12 bits — 4096 procedures per module)
//!   bits 19..10   block_id  (10 bits — 1024 blocks per procedure)
//!   bits 9..0     fact_id   (10 bits — 1024 facts per workgroup;
//!                            matches FACTS_PER_WORKGROUP and the
//!                            NFA subgroup sizing)
//! ```
//!
//! This deliberately leaves no room for >4096 procedures in a
//! single module. Any real codebase that exceeds that split along
//! a module boundary first — doing interprocedural dataflow over
//! 10 000+ procs in one pass is a different problem that we don't
//! solve here and shouldn't pretend to.
//!
//! # Status
//!
//! Node encoding, CSR builder, and tests. The GPU Program wrapper
//! (the actual kernel that walks edges in parallel) lives in
//! `vyre-libs::dataflow::ifds_gpu` and composes this encoding with
//! `csr_forward_traverse`.

/// Bits reserved for each component of the packed node id.
pub const PROC_BITS: u32 = 12;
/// Bits reserved for the basic-block component of the packed node id.
pub const BLOCK_BITS: u32 = 10;
/// Bits reserved for the fact component of the packed node id.
pub const FACT_BITS: u32 = 10;
const _SANITY: () = assert!(PROC_BITS + BLOCK_BITS + FACT_BITS == 32);

/// Max values for each component — one less than the available
/// space because zero is a valid id.
pub const MAX_PROC_ID: u32 = (1 << PROC_BITS) - 1;
/// Maximum encodable basic-block id.
pub const MAX_BLOCK_ID: u32 = (1 << BLOCK_BITS) - 1;
/// Maximum encodable fact id.
pub const MAX_FACT_ID: u32 = (1 << FACT_BITS) - 1;

/// Number of facts per workgroup lane. A 32-lane subgroup x
/// 32 bits = 1024 facts; wider subgroup layouts preserve the same budget.
/// Matches the
/// NFA window sizing in `nfa::subgroup_nfa` so both subsystems
/// share occupancy budget.
pub const FACTS_PER_WORKGROUP: usize = 1024;

const BLOCK_SHIFT: u32 = FACT_BITS;
const PROC_SHIFT: u32 = FACT_BITS + BLOCK_BITS;
const FACT_MASK: u32 = MAX_FACT_ID;
const BLOCK_MASK: u32 = MAX_BLOCK_ID;
const PROC_MASK: u32 = MAX_PROC_ID;

/// Pack a `(proc_id, block_id, fact_id)` triple into a 32-bit
/// node id.
///
/// Invalid triples have no non-aliasing `u32` representation, so the
/// failure is explicit instead of silently clamping or masking.
#[must_use]
pub fn encode_node(proc_id: u32, block_id: u32, fact_id: u32) -> Option<u32> {
    fits(proc_id, block_id, fact_id)
        .then_some((proc_id << PROC_SHIFT) | (block_id << BLOCK_SHIFT) | fact_id)
}

/// Unpack a node id back into `(proc_id, block_id, fact_id)`.
#[must_use]
pub fn decode_node(node_id: u32) -> (u32, u32, u32) {
    let proc_id = (node_id >> PROC_SHIFT) & PROC_MASK;
    let block_id = (node_id >> BLOCK_SHIFT) & BLOCK_MASK;
    let fact_id = node_id & FACT_MASK;
    (proc_id, block_id, fact_id)
}

/// Whether a `(proc, block, fact)` triple fits in the packed
/// 32-bit representation. Callers on the production path should
/// verify this before calling [`encode_node`].
#[must_use]
pub fn fits(proc_id: u32, block_id: u32, fact_id: u32) -> bool {
    proc_id <= MAX_PROC_ID && block_id <= MAX_BLOCK_ID && fact_id <= MAX_FACT_ID
}

/// CPU-reference CSR builder for the exploded supergraph.
///
/// `intra_edges` are `(src_block, dst_block)` pairs **within** a
/// procedure — the standard CFG. `inter_edges` are `(src_proc,
/// src_block, dst_proc, dst_block)` call / return edges. Flow
/// functions are encoded as per-block GEN / KILL bitsets over the
/// fact domain.
///
/// Returns `(row_ptr, col_idx)` in the **dense** index space
/// `idx(p, b, f) = p * blocks * facts + b * facts + f`. This is
/// the space every traversal kernel operates in — packing via
/// [`encode_node`] is only used at the I/O boundary when the
/// caller needs to report results as `(proc, block, fact)`
/// triples. The two spaces coincide only in the degenerate case
/// `blocks_per_proc == 1 << BLOCK_BITS` and `facts_per_proc == 1 << FACT_BITS`;
/// the dense layout works for any dimensions that fit in
/// 32-bit encoding.
#[must_use]
pub fn build_cpu_reference(
    num_procs: u32,
    blocks_per_proc: u32,
    facts_per_proc: u32,
    intra_edges: &[(u32, u32, u32)], // (proc, src_block, dst_block)
    inter_edges: &[(u32, u32, u32, u32)], // (src_proc, src_block, dst_proc, dst_block)
    flow_gen: &[(u32, u32, u32)],    // (proc, block, fact) — GEN bits
    flow_kill: &[(u32, u32, u32)],   // (proc, block, fact) — KILL bits
) -> (Vec<u32>, Vec<u32>) {
    if num_procs == 0 || blocks_per_proc == 0 || facts_per_proc == 0 {
        return (vec![0], Vec::new());
    }
    if !fits(
        num_procs.saturating_sub(1),
        blocks_per_proc.saturating_sub(1),
        facts_per_proc.saturating_sub(1),
    ) {
        return (vec![0], Vec::new());
    }

    // PHASE7_GRAPH C4: every multiply checked. The previous unchecked
    // chain (`blocks * facts`, then `procs * slots`) wraps silently
    // when the caller passes the maximum dimensions for each field
    // (4096 × 1024 × 1024 = 2^32 = wraps to 0 on 32-bit usize and
    // sits exactly at the overflow boundary on 64-bit). Either case
    // produced a tiny `Vec<Vec<u32>>` and catastrophic OOB writes in
    // the edge-emit loops below.
    let Some(slots_per_proc) = (blocks_per_proc as usize).checked_mul(facts_per_proc as usize)
    else {
        return (vec![0], Vec::new());
    };
    let Some(total_nodes) = (num_procs as usize).checked_mul(slots_per_proc) else {
        return (vec![0], Vec::new());
    };
    if total_nodes > u32::MAX as usize {
        return (vec![0], Vec::new());
    }
    let mut edges_flat: Vec<(u32, u32)> = Vec::new();
    let block_count = (num_procs as usize) * (blocks_per_proc as usize);

    let idx = |p: u32, b: u32, f: u32| -> u32 {
        ((p as usize) * slots_per_proc + (b as usize) * facts_per_proc as usize + f as usize) as u32
    };
    let block_idx =
        |p: u32, b: u32| -> usize { (p as usize) * blocks_per_proc as usize + b as usize };
    let in_space =
        |p: u32, b: u32, f: u32| p < num_procs && b < blocks_per_proc && f < facts_per_proc;

    let mut killed = vec![false; total_nodes];
    for &(p, b, f) in flow_kill {
        if in_space(p, b, f) {
            killed[idx(p, b, f) as usize] = true;
        }
    }

    let mut gen_offsets = vec![0usize; block_count + 1];
    for &(p, b, f) in flow_gen {
        if in_space(p, b, f) {
            gen_offsets[block_idx(p, b) + 1] += 1;
        }
    }
    for i in 1..gen_offsets.len() {
        gen_offsets[i] += gen_offsets[i - 1];
    }
    let mut gen_cursor = gen_offsets[..block_count].to_vec();
    let mut gen_facts = vec![0u32; gen_offsets[block_count]];
    for &(p, b, f) in flow_gen {
        if in_space(p, b, f) {
            let key = block_idx(p, b);
            let slot = gen_cursor[key];
            gen_facts[slot] = f;
            gen_cursor[key] += 1;
        }
    }

    // Intra-procedural CFG edges, cross-producted with fact-propagation:
    // an edge (B_src -> B_dst) gives rise to an edge in the exploded
    // supergraph between every pair (f, f) that survives the flow
    // function at B_src (fact f propagates iff f is not killed).
    for &(p, src_b, dst_b) in intra_edges {
        if p >= num_procs || src_b >= blocks_per_proc || dst_b >= blocks_per_proc {
            continue;
        }
        for f in 0..facts_per_proc {
            if killed[idx(p, src_b, f) as usize] {
                continue;
            }
            edges_flat.push((idx(p, src_b, f), idx(p, dst_b, f)));
        }
        // GEN edges: standard IFDS 0-fact encoding — fact 0 is the
        // tautological "always present" fact. `GEN(src_b, gf)` emits
        // edge `(src_b, 0) → (dst_b, gf)`, so seeding `(entry, 0)`
        // triggers every GEN along the reachable CFG. Callers that
        // don't use the 0-fact convention see GEN as a no-op.
        let gen_key = block_idx(p, src_b);
        for &gf in &gen_facts[gen_offsets[gen_key]..gen_offsets[gen_key + 1]] {
            edges_flat.push((idx(p, src_b, 0), idx(p, dst_b, gf)));
        }
    }

    // Inter-procedural call / return edges propagate every fact
    // (IFDS handles parameter mapping via summary edges in the full
    // algorithm; this CPU reference is the unfiltered
    // "every-fact-flows" upper bound used for correctness tests).
    for &(sp, sb, dp, db) in inter_edges {
        if sp >= num_procs || dp >= num_procs || sb >= blocks_per_proc || db >= blocks_per_proc {
            continue;
        }
        for f in 0..facts_per_proc {
            edges_flat.push((idx(sp, sb, f), idx(dp, db, f)));
        }
    }

    // Flatten into CSR — row_ptr has total_nodes+1 entries.
    if edges_flat.len() > u32::MAX as usize {
        return (vec![0], Vec::new());
    }
    let mut row_ptr = vec![0u32; total_nodes + 1];
    for &(src, _) in &edges_flat {
        let row = src as usize;
        row_ptr[row + 1] = row_ptr[row + 1].saturating_add(1);
    }
    for row in 1..row_ptr.len() {
        row_ptr[row] = row_ptr[row].saturating_add(row_ptr[row - 1]);
    }
    let mut cursor = row_ptr[..total_nodes]
        .iter()
        .map(|&offset| offset as usize)
        .collect::<Vec<_>>();
    let mut col_idx = vec![0u32; edges_flat.len()];
    for (src, dst) in edges_flat {
        let row = src as usize;
        let slot = cursor[row];
        col_idx[slot] = dst;
        cursor[row] += 1;
    }
    (row_ptr, col_idx)
}

/// Convert a dense `(proc, block, fact)` index — the space
/// [`build_cpu_reference`] operates in — into the packed
/// [`encode_node`] form for reporting or cross-subsystem handoff.
#[must_use]
pub fn dense_to_encoded(dense: u32, blocks_per_proc: u32, facts_per_proc: u32) -> Option<u32> {
    let slots_per_proc = blocks_per_proc.checked_mul(facts_per_proc)?;
    if slots_per_proc == 0 {
        return None;
    }
    let p = dense / slots_per_proc;
    let within_proc = dense % slots_per_proc;
    let b = within_proc / facts_per_proc;
    let f = within_proc % facts_per_proc;
    encode_node(p, b, f)
}

/// Inverse of [`dense_to_encoded`].
#[must_use]
pub fn encoded_to_dense(node_id: u32, blocks_per_proc: u32, facts_per_proc: u32) -> Option<u32> {
    let (p, b, f) = decode_node(node_id);
    let proc_span = blocks_per_proc.checked_mul(facts_per_proc)?;
    let proc_offset = p.checked_mul(proc_span)?;
    let block_offset = b.checked_mul(facts_per_proc)?;
    proc_offset.checked_add(block_offset)?.checked_add(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrips_at_max_values() {
        let n = encode_node(MAX_PROC_ID, MAX_BLOCK_ID, MAX_FACT_ID).unwrap();
        assert_eq!(n, u32::MAX);
        assert_eq!(decode_node(n), (MAX_PROC_ID, MAX_BLOCK_ID, MAX_FACT_ID));
    }

    #[test]
    fn encode_decode_roundtrips_at_zero() {
        let n = encode_node(0, 0, 0).unwrap();
        assert_eq!(n, 0);
        assert_eq!(decode_node(n), (0, 0, 0));
    }

    #[test]
    fn encode_decode_roundtrips_at_component_boundaries() {
        for (p, b, f) in [
            (0, 0, 1),
            (0, 1, 0),
            (1, 0, 0),
            (0, 0, MAX_FACT_ID),
            (0, MAX_BLOCK_ID, 0),
            (MAX_PROC_ID, 0, 0),
            (1, 2, 3),
            (42, 17, 99),
            (MAX_PROC_ID / 2, MAX_BLOCK_ID / 2, MAX_FACT_ID / 2),
        ] {
            let n = encode_node(p, b, f).unwrap();
            assert_eq!(
                decode_node(n),
                (p, b, f),
                "roundtrip failed for {p}/{b}/{f}"
            );
        }
    }

    #[test]
    fn fits_catches_over_range_components() {
        assert!(fits(MAX_PROC_ID, MAX_BLOCK_ID, MAX_FACT_ID));
        assert!(!fits(MAX_PROC_ID + 1, 0, 0));
        assert!(!fits(0, MAX_BLOCK_ID + 1, 0));
        assert!(!fits(0, 0, MAX_FACT_ID + 1));
        assert_eq!(encode_node(MAX_PROC_ID + 1, 0, 0), None);
    }

    #[test]
    fn csr_of_empty_graph_has_only_sentinel_row_ptr() {
        let (row_ptr, col_idx) = build_cpu_reference(1, 1, 1, &[], &[], &[], &[]);
        assert_eq!(row_ptr, vec![0, 0]);
        assert!(col_idx.is_empty());
    }

    // Dense-index helper mirrors the one inside build_cpu_reference.
    fn di(p: u32, b: u32, f: u32, blocks: u32, facts: u32) -> u32 {
        p * blocks * facts + b * facts + f
    }

    #[test]
    fn csr_single_intra_edge_produces_per_fact_duplicate_edges() {
        // 1 proc, 2 blocks (B0→B1), 4 facts; no kills → each fact
        // flows forward once.
        let (row_ptr, col_idx) = build_cpu_reference(1, 2, 4, &[(0, 0, 1)], &[], &[], &[]);
        assert_eq!(row_ptr.len(), 9);
        assert_eq!(col_idx.len(), 4);
        for f in 0..4 {
            let src = di(0, 0, f, 2, 4) as usize;
            let edge_start = row_ptr[src] as usize;
            assert_eq!(col_idx[edge_start], di(0, 1, f, 2, 4));
        }
    }

    #[test]
    fn csr_kill_suppresses_edge_for_that_fact() {
        let (row_ptr, col_idx) = build_cpu_reference(
            1,
            2,
            4,
            &[(0, 0, 1)],
            &[],
            &[],
            &[(0, 0, 2)], // KILL fact 2 at (0, 0)
        );
        let n_edges: u32 = row_ptr.windows(2).map(|w| w[1] - w[0]).sum();
        assert_eq!(n_edges, 3);
        assert_eq!(col_idx.len(), n_edges as usize);
        let killed_src = di(0, 0, 2, 2, 4) as usize;
        assert_eq!(row_ptr[killed_src + 1] - row_ptr[killed_src], 0);
    }

    #[test]
    fn csr_inter_edges_connect_procs() {
        let (row_ptr, col_idx) = build_cpu_reference(
            2,
            2,
            2,
            &[],
            &[(0, 1, 1, 0)], // call: P0/B1 → P1/B0
            &[],
            &[],
        );
        assert_eq!(row_ptr.len(), 9);
        assert_eq!(col_idx.len(), 2);
        let src0 = di(0, 1, 0, 2, 2) as usize;
        let src1 = di(0, 1, 1, 2, 2) as usize;
        assert_eq!(
            &col_idx[row_ptr[src0] as usize..row_ptr[src0 + 1] as usize],
            &[di(1, 0, 0, 2, 2)]
        );
        assert_eq!(
            &col_idx[row_ptr[src1] as usize..row_ptr[src1 + 1] as usize],
            &[di(1, 0, 1, 2, 2)]
        );
    }

    #[test]
    fn dense_encoded_roundtrips() {
        for &(p, b, f, blocks, facts) in &[
            (0_u32, 0_u32, 0_u32, 2_u32, 2_u32),
            (1, 1, 1, 2, 2),
            (42, 17, 99, 64, 128),
            (MAX_PROC_ID, 3, 7, 16, 16),
        ] {
            let d = di(p, b, f, blocks, facts);
            let enc = dense_to_encoded(d, blocks, facts).unwrap();
            assert_eq!(decode_node(enc), (p, b, f));
            let back = encoded_to_dense(enc, blocks, facts).unwrap();
            assert_eq!(back, d, "roundtrip mismatch {p}/{b}/{f}");
        }
    }

    #[test]
    fn csr_gen_introduces_new_fact_flow_from_zero_fact() {
        // B0 → B1, GEN fact 2 at B0. Per IFDS 0-fact convention,
        // GEN emits edge (B0, 0) → (B1, 2). The intra loop still
        // propagates every non-killed fact (0..3), so total edges
        // are 4 (intra) + 1 (GEN from 0-fact) = 5. The GEN edge
        // specifically targets fact 2 at B1 even though fact 2 did
        // not flow in through any predecessor — that is the point.
        let (row_ptr, col_idx) = build_cpu_reference(1, 2, 4, &[(0, 0, 1)], &[], &[(0, 0, 2)], &[]);
        assert_eq!(col_idx.len(), 5);
        // Verify the GEN edge is attached to the 0-fact source, not
        // to fact-2 (which would be redundant with the intra edge).
        let zero_src = di(0, 0, 0, 2, 4) as usize;
        let fact2_dst = di(0, 1, 2, 2, 4);
        let zero_neighbours = &col_idx[row_ptr[zero_src] as usize..row_ptr[zero_src + 1] as usize];
        assert!(zero_neighbours.contains(&fact2_dst));
    }

    #[test]
    fn csr_rejects_dimensions_overflowing_encoding() {
        // (MAX_PROC_ID + 2) × anything overflows PROC_BITS.
        let (row_ptr, col_idx) = build_cpu_reference(MAX_PROC_ID + 2, 1, 1, &[], &[], &[], &[]);
        assert_eq!(row_ptr, vec![0]);
        assert!(col_idx.is_empty());
    }

    #[test]
    fn row_ptr_length_is_nodes_plus_one() {
        let procs = 3;
        let blocks = 4;
        let facts = 8;
        let (row_ptr, _) = build_cpu_reference(procs, blocks, facts, &[], &[], &[], &[]);
        assert_eq!(
            row_ptr.len(),
            (procs as usize * blocks as usize * facts as usize) + 1
        );
    }

    #[test]
    fn facts_per_workgroup_matches_max_fact_id_plus_one() {
        // G3 docstring claim: lane sizing matches NFA's.
        assert_eq!(FACTS_PER_WORKGROUP as u32, MAX_FACT_ID + 1);
    }
}
