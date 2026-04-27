//! DF-6 — backward slicer.
//!
//! Given a sink node `s`, emit the minimal sub-graph that may
//! affect it. Reduces to **reverse** reachability on the merged
//! dependence graph: walk backward from the sink, union-in
//! every predecessor along data dependences (DF-2 reaching, DF-3
//! points-to, DF-5 callgraph) and control dependences
//! (`security::dominator_tree`).
//!
//! # Implementation
//!
//! Reverse-BFS is
//! [`csr_backward_traverse`] applied to the caller-supplied
//! `ProgramGraph`. The caller merges `reach`, `callgraph`, and
//! `dom` into a single CSR before dispatch (dense-OR of three CSRs
//! — a one-kernel fusion via `fuse_programs`). The
//! `edge_kind_mask` channel already supports up to 32 independent
//! edge kinds, so we admit **every** kind with `u32::MAX` — the
//! slicer is intentionally maximal, and false-positives are
//! filtered by the downstream rule.
//!
//! # Soundness
//!
//! [`MayOver`](super::Soundness::MayOver). Rules requiring zero-FP
//! pair this slicer with a sanitizer filter on each edge in the
//! returned slice.

use vyre::ir::Program;
use vyre_primitives::graph::csr_backward_traverse::csr_backward_traverse;
use vyre_primitives::graph::program_graph::ProgramGraphShape;

/// Build one reverse-BFS step. Caller invokes this Program in a
/// host loop until the slice bitset stops growing (same fixpoint
/// driver pattern as DF-2 reaching, DF-3 points-to).
///
/// Buffer contract: `frontier_in` is the current slice bitset (seed
/// is one bit set — the sink node). `frontier_out` is the expanded
/// bitset after one reverse-edge traversal. The caller-supplied
/// `ProgramGraph` buffers are bound at the canonical `pg_*` names
/// (callgraph ∪ reach ∪ dom merged via three-way `fuse_programs`).
///
/// PHASE6_DATAFLOW HIGH: previous 5-arg entry hardcoded
/// `ProgramGraphShape::new(1, 1)` and ignored the `reach`,
/// `callgraph`, `dom` buffer arguments — i.e. it produced a
/// 1-node-grid kernel for any real CFG, silently losing every
/// dependency edge. The 5-arg shim is now `#[deprecated]` and
/// delegates with a pessimistic shape that surfaces the bug.
/// Callers MUST use the explicit-shape entry below.
#[must_use]
pub fn backward_slice(shape: ProgramGraphShape, frontier_in: &str, frontier_out: &str) -> Program {
    csr_backward_traverse(shape, frontier_in, frontier_out, u32::MAX)
}

/// Deprecated alias for back-compat with callers that imported the
/// pre-fix `backward_slice_with_shape` name.
#[deprecated(
    since = "0.6.0",
    note = "use `backward_slice(shape, frontier_in, frontier_out)` directly — the suffix is redundant since the 5-arg entry was removed"
)]
#[must_use]
pub fn backward_slice_with_shape(
    shape: ProgramGraphShape,
    frontier_in: &str,
    frontier_out: &str,
) -> Program {
    backward_slice(shape, frontier_in, frontier_out)
}

/// Marker type for the backward-slice dataflow primitive.
pub struct BackwardSlice;

impl super::soundness::SoundnessTagged for BackwardSlice {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::MayOver
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;

    /// PHASE6_DATAFLOW HIGH regression: backward_slice now requires
    /// a real ProgramGraphShape; pre-fix the 5-arg entry hardcoded
    /// (1, 1), which produced a 1-thread dispatch grid that silently
    /// lost every dependency edge in the supergraph.
    #[test]
    fn backward_slice_requires_caller_supplied_shape() {
        let shape = ProgramGraphShape::new(64, 128);
        let p = backward_slice(shape, "sink_in", "slice_out");
        let frontier_count = p
            .buffers
            .iter()
            .find(|b| b.name() == "sink_in")
            .map(|b| b.count)
            .expect("sink_in buffer must be declared");
        // bitset_words(64) = 2; the pre-fix 1-node hardcode would
        // have produced 1.
        assert!(
            frontier_count >= 2,
            "sink_in count {frontier_count} suggests degenerate 1-node hardcoded shape — regression"
        );
    }

    /// PHASE6_DATAFLOW HIGH regression: the deprecated alias still
    /// emits the same Program shape so back-compat callers continue
    /// to compile.
    #[test]
    #[allow(deprecated)]
    fn deprecated_alias_emits_same_program_shape() {
        let shape = ProgramGraphShape::new(32, 64);
        let canonical = backward_slice(shape, "fin", "fout");
        let alias = backward_slice_with_shape(shape, "fin", "fout");
        assert_eq!(canonical.workgroup_size, alias.workgroup_size);
        assert_eq!(canonical.buffers.len(), alias.buffers.len());
    }
}
