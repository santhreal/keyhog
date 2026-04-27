//! `flows_to_with_sanitizer` — composite source→sink reachability
//! with explicit sanitizer kill, in one fused Region.
//!
//! This is the CodeQL `DataFlow::Configuration` shape compressed into
//! a single emitted Program:
//!
//! ```text
//!   clean    = source AND NOT sanitizers
//!   reach    = csr_forward_traverse(clean, FLOWS_TO_MASK)
//!   alive    = reach AND NOT sanitizers
//!   hits     = alive AND sink
//!   any_hit  = bitset_any(hits) → u32
//! ```
//!
//! Surgec rules currently express this composition as a chain of
//! three predicates (`flows_to($src, $sink)` AND `not sanitized_by($src, @san)`).
//! That works but emits three separate dispatches and intermediate
//! buffers. Centralising it here lets the rule write one `lhs`-shaped
//! predicate that the optimizer fuses, caches, and CSEs across rules.
//!
//! Soundness: [`Exact`](weir::soundness::Soundness::Exact)
//! when iterated to fixpoint with the same sanitizer mask supplied
//! at every step. One step alone is
//! [`MayOver`](weir::soundness::Soundness::MayOver) — the
//! caller is responsible for the fixpoint loop, which is the same
//! contract every other reachability primitive in this module honours.

use vyre::ir::Program;
use vyre_primitives::graph::program_graph::ProgramGraphShape;

use crate::security::flow_composition::{sanitized_dataflow_hit, sanitized_dataflow_hit_program};

pub(crate) const OP_ID: &str = "vyre-libs::security::flows_to_with_sanitizer";

/// Build one BFS step of `source \ sanitizers` along dataflow edges,
/// re-killed by `sanitizers` on landing, intersected with `sink`,
/// reduced to a single u32 in `out_scalar_buf`.
///
/// Buffer ownership:
/// * `source_buf`, `sink_buf`, `sanitizer_buf` — read-only.
/// * `clean_buf`, `reach_buf`, `alive_buf`, `hits_buf` — read-write
///   scratch sized to `bitset_words(shape.node_count)`.
/// * `out_scalar_buf` — read-write 1-word output, nonzero iff any
///   non-sanitized source-reachable bit overlaps with sink.
#[must_use]
pub fn flows_to_with_sanitizer(
    shape: ProgramGraphShape,
    source_buf: &str,
    sink_buf: &str,
    sanitizer_buf: &str,
    clean_buf: &str,
    reach_buf: &str,
    alive_buf: &str,
    hits_buf: &str,
    out_scalar_buf: &str,
) -> Program {
    sanitized_dataflow_hit_program(
        OP_ID,
        shape,
        source_buf,
        sink_buf,
        sanitizer_buf,
        clean_buf,
        reach_buf,
        alive_buf,
        hits_buf,
        out_scalar_buf,
    )
}

/// CPU oracle: full one-step semantic for differential testing
/// against the GPU emit.
#[must_use]
pub fn cpu_ref(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    source: &[u32],
    sink: &[u32],
    sanitizer: &[u32],
) -> u32 {
    sanitized_dataflow_hit(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        source,
        sink,
        sanitizer,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::flow_composition::linear_dataflow;

    #[test]
    fn unsanitized_source_reaches_sink_returns_one() {
        let (off, tgt, msk) = linear_dataflow(4);
        // 0 → 1 → 2 → 3, source = {0}, sink = {1}, no sanitizer.
        let result = cpu_ref(4, &off, &tgt, &msk, &[0b0001], &[0b0010], &[0]);
        assert_eq!(result, 1);
    }

    #[test]
    fn source_killed_by_sanitizer_returns_zero() {
        let (off, tgt, msk) = linear_dataflow(4);
        // Sanitizer covers the source itself — nothing flows.
        let result = cpu_ref(4, &off, &tgt, &msk, &[0b0001], &[0b0010], &[0b0001]);
        assert_eq!(result, 0);
    }

    #[test]
    fn landing_killed_by_sanitizer_returns_zero() {
        let (off, tgt, msk) = linear_dataflow(4);
        // Source = {0}, sink = {1}, sanitizer = {1} — sink itself is
        // sanitized, so the landing kill drops it before the AND-sink.
        let result = cpu_ref(4, &off, &tgt, &msk, &[0b0001], &[0b0010], &[0b0010]);
        assert_eq!(result, 0);
    }

    #[test]
    fn unrelated_sanitizer_passes_through() {
        let (off, tgt, msk) = linear_dataflow(4);
        // Sanitizer covers node 3 (downstream of sink) — irrelevant.
        let result = cpu_ref(4, &off, &tgt, &msk, &[0b0001], &[0b0010], &[0b1000]);
        assert_eq!(result, 1);
    }

    #[test]
    fn empty_source_returns_zero() {
        let (off, tgt, msk) = linear_dataflow(4);
        let result = cpu_ref(4, &off, &tgt, &msk, &[0], &[0b0010], &[0]);
        assert_eq!(result, 0);
    }

    #[test]
    fn empty_sink_returns_zero() {
        let (off, tgt, msk) = linear_dataflow(4);
        let result = cpu_ref(4, &off, &tgt, &msk, &[0b0001], &[0], &[0]);
        assert_eq!(result, 0);
    }
}
