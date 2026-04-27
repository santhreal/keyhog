//! `segment_reduce_sum` — per-segment wrapping unsigned sum.
//!
//! Each work-group thread handles one segment.  The `segment_offsets`
//! buffer is CSR-style: `offsets[i]..offsets[i+1]` is the range of
//! `input` belonging to segment `i`.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::reduce::segment_reduce_sum";

/// Build a Program: `output[seg] = Σ input[offsets[seg]..offsets[seg+1]]`.
///
/// # Panics
///
/// Panics with an actionable message if `num_segments` is zero or
/// exceeds the workgroup size (256).  Larger counts must be tiled by
/// the caller.
#[must_use]
pub fn segment_reduce_sum(
    input: &str,
    segment_offsets: &str,
    output: &str,
    num_segments: u32,
) -> Program {
    assert!(
        num_segments > 0 && num_segments <= 256,
        "Fix: segment_reduce_sum requires 0 < num_segments <= 256, got {num_segments}. \
         For larger counts, tile the dispatch across multiple work-groups.",
    );

    let lane = Expr::InvocationId { axis: 0 };

    let body = vec![
        Node::let_bind("start", Expr::load(segment_offsets, lane.clone())),
        Node::let_bind(
            "end",
            Expr::load(segment_offsets, Expr::add(lane.clone(), Expr::u32(1))),
        ),
        Node::let_bind("acc", Expr::u32(0)),
        Node::loop_for(
            "i",
            Expr::var("start"),
            Expr::var("end"),
            vec![Node::assign(
                "acc",
                Expr::add(Expr::var("acc"), Expr::load(input, Expr::var("i"))),
            )],
        ),
        Node::store(output, lane.clone(), Expr::var("acc")),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32),
            BufferDecl::storage(segment_offsets, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(num_segments + 1),
            BufferDecl::storage(output, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(num_segments),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(lane.clone(), Expr::u32(num_segments)),
                body,
            )]),
        }],
    )
}

/// CPU reference.
///
/// `segment_offsets` must contain `num_segments + 1` entries in
/// non-decreasing order and the last entry must not exceed
/// `input.len()`.
#[must_use]
pub fn cpu_ref(input: &[u32], segment_offsets: &[u32]) -> Vec<u32> {
    let num_segments = segment_offsets.len().saturating_sub(1);
    let mut out = Vec::with_capacity(num_segments);
    for seg in 0..num_segments {
        let start = segment_offsets[seg] as usize;
        let end = segment_offsets[seg + 1] as usize;
        let sum = input[start..end]
            .iter()
            .copied()
            .fold(0u32, u32::wrapping_add);
        out.push(sum);
    }
    out
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || segment_reduce_sum("input", "segment_offsets", "output", 2),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[1, 2, 3, 4, 5]),
                to_bytes(&[0, 2, 5]),
                to_bytes(&[0, 0]),
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[3, 12])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_segments() {
        assert_eq!(cpu_ref(&[1, 2, 3, 4, 5], &[0, 2, 5]), vec![3, 12]);
    }

    #[test]
    fn single_segment() {
        assert_eq!(cpu_ref(&[10, 20, 30], &[0, 3]), vec![60]);
    }

    #[test]
    fn empty_segment() {
        assert_eq!(cpu_ref(&[1, 2, 3], &[0, 0, 3]), vec![0, 6]);
    }

    #[test]
    fn wraps_on_overflow() {
        assert_eq!(cpu_ref(&[u32::MAX, 1, 2], &[0, 2, 3]), vec![0, 2]);
    }

    #[test]
    fn emitted_program_has_expected_buffers() {
        let p = segment_reduce_sum("input", "segment_offsets", "output", 4);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["input", "segment_offsets", "output"]);
    }

    #[test]
    #[should_panic(expected = "num_segments <= 256")]
    fn zero_segments_panics() {
        let _ = segment_reduce_sum("input", "segment_offsets", "output", 0);
    }

    #[test]
    #[should_panic(expected = "num_segments <= 256")]
    fn over_limit_segments_panics() {
        let _ = segment_reduce_sum("input", "segment_offsets", "output", 257);
    }
}
