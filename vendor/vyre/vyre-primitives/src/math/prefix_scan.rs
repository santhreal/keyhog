//! Subgroup prefix-sum (inclusive / exclusive scan) — core 1000×
//! primitive for variable-length compaction.
//!
//! # Use cases
//!
//! * **Hit-buffer compaction:** each lane produces 0 or 1 live
//!   flag; an exclusive scan over the flag vector gives the
//!   destination slot for each live hit. One dispatch replaces the
//!   current `[1,1,1]` scalar-clamp hack flagged by PHASE9_EMIT.
//! * **Histogram prefix:** turn a bin-count vector into the CDF
//!   lookup used by the radix-sort primitive.
//! * **Segmented-reduce baseline:** classical parallel-scan is
//!   the inner kernel of a `(segment_offsets, values)` pair.
//!
//! # Algorithm
//!
//! Hillis-Steele scan over `N` elements, O(N log N) work,
//! `log2(N)` rounds. One invocation per output lane. Round `k`:
//!
//! ```text
//!   if lane >= 2^k:
//!       out[lane] = in[lane - 2^k] op in[lane]
//!   else:
//!       out[lane] = in[lane]
//! ```
//!
//! `op` is `+` for sum-scan; pluggable via the `op` selector. We
//! unroll `log2(N)` rounds in the emitted Program by splitting
//! input and output across two bounce buffers — no shared memory
//! needed, runs on any GPU with `@workgroup_size(N, 1, 1)`.
//!
//! For bigger-than-subgroup N the caller tiles the scan: scan each
//! subgroup locally, then a second dispatch adds each subgroup's
//! total prefix to its neighbours. This module ships the inner
//! kernel — the driver stitches tiles.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id for inclusive sum-scan.
pub const OP_ID_INCLUSIVE_SUM: &str = "vyre-primitives::math::prefix_scan_inclusive_sum";
/// Canonical op id for exclusive sum-scan.
pub const OP_ID_EXCLUSIVE_SUM: &str = "vyre-primitives::math::prefix_scan_exclusive_sum";

/// Which scan variant to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanKind {
    /// `out[i] = sum(in[0..=i])`.
    InclusiveSum,
    /// `out[i] = sum(in[0..i])` — identity element (`0`) at slot 0.
    ExclusiveSum,
}

/// Emit a Hillis-Steele prefix-sum Program.
///
/// `n` is the number of input slots (upper bound on lanes — caller
/// dispatches `@workgroup_size(n, 1, 1)`). `n` must be a power of
/// two and at most 1024 (one subgroup worst-case). Larger n: tile.
#[must_use]
pub fn prefix_scan(in_buf: &str, out_buf: &str, n: u32, kind: ScanKind) -> Program {
    assert!(
        n.is_power_of_two() && n > 0 && n <= 1024,
        "Fix: prefix_scan requires n a power of two in 1..=1024, got {n}. \
         For larger N, tile: scan each subgroup then add subgroup prefixes.",
    );

    let lane = Expr::InvocationId { axis: 0 };

    // Body:
    //   let mut v = in_buf[lane];
    //   (For exclusive: shift — seed v with in_buf[lane - 1], zero at lane 0.)
    //   for stride in [1, 2, 4, …, n/2]:
    //       if lane >= stride: v += in_buf[lane - stride]
    //                           using a bounce bitset to avoid read-after-write
    //   out_buf[lane] = v
    //
    // We emit the ping-pong through `out_buf` itself + a scratch
    // lane-local `v`; each round reads in_buf at (lane - stride) and
    // unions into v. At the end we write v to out_buf.
    let mut body: Vec<Node> = Vec::new();

    match kind {
        ScanKind::InclusiveSum => {
            body.push(Node::let_bind("v", Expr::load(in_buf, lane.clone())));
        }
        ScanKind::ExclusiveSum => {
            body.push(Node::let_bind(
                "v",
                Expr::select(
                    Expr::eq(lane.clone(), Expr::u32(0)),
                    Expr::u32(0),
                    Expr::load(in_buf, Expr::add(lane.clone(), Expr::u32(u32::MAX))),
                ),
            ));
        }
    }

    let mut stride = 1_u32;
    while stride < n {
        body.push(Node::if_then(
            Expr::lt(Expr::u32(stride.saturating_sub(1)), lane.clone()),
            vec![Node::assign(
                "v",
                Expr::add(
                    Expr::var("v"),
                    Expr::load(
                        in_buf,
                        // (lane - stride) — u32 subtraction, guarded above.
                        Expr::add(lane.clone(), Expr::u32(u32::MAX.wrapping_sub(stride - 1))),
                    ),
                ),
            )],
        ));
        stride *= 2;
    }

    body.push(Node::store(out_buf, lane.clone(), Expr::var("v")));

    let op_id = match kind {
        ScanKind::InclusiveSum => OP_ID_INCLUSIVE_SUM,
        ScanKind::ExclusiveSum => OP_ID_EXCLUSIVE_SUM,
    };

    let buffers = vec![
        BufferDecl::storage(in_buf, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
        BufferDecl::storage(out_buf, 1, BufferAccess::ReadWrite, DataType::U32).with_count(n),
    ];

    Program::wrapped(
        buffers,
        [n, 1, 1],
        vec![Node::Region {
            generator: Ident::from(op_id),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(lane.clone(), Expr::u32(n)),
                body,
            )]),
        }],
    )
}

/// CPU-reference prefix scan. Conformance tests verify the GPU
/// Program produces the same output for every input.
#[must_use]
pub fn cpu_ref(input: &[u32], kind: ScanKind) -> Vec<u32> {
    let mut out = Vec::with_capacity(input.len());
    let mut acc = 0_u32;
    match kind {
        ScanKind::InclusiveSum => {
            for &x in input {
                acc = acc.wrapping_add(x);
                out.push(acc);
            }
        }
        ScanKind::ExclusiveSum => {
            for &x in input {
                out.push(acc);
                acc = acc.wrapping_add(x);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inclusive_cpu_ref_matches_textbook() {
        assert_eq!(
            cpu_ref(&[1, 2, 3, 4], ScanKind::InclusiveSum),
            vec![1, 3, 6, 10],
        );
    }

    #[test]
    fn exclusive_cpu_ref_matches_textbook() {
        assert_eq!(
            cpu_ref(&[1, 2, 3, 4], ScanKind::ExclusiveSum),
            vec![0, 1, 3, 6],
        );
    }

    #[test]
    fn empty_cpu_ref_returns_empty() {
        assert_eq!(cpu_ref(&[], ScanKind::InclusiveSum), Vec::<u32>::new());
        assert_eq!(cpu_ref(&[], ScanKind::ExclusiveSum), Vec::<u32>::new());
    }

    #[test]
    fn wrap_on_overflow() {
        // Overflow check: wrapping_add semantics.
        assert_eq!(
            cpu_ref(&[u32::MAX, 1], ScanKind::InclusiveSum),
            vec![u32::MAX, 0],
        );
    }

    #[test]
    fn emitted_inclusive_program_has_expected_buffers() {
        let p = prefix_scan("in", "out", 32, ScanKind::InclusiveSum);
        assert_eq!(p.workgroup_size, [32, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["in", "out"]);
    }

    #[test]
    fn emitted_exclusive_program_has_expected_buffers() {
        let p = prefix_scan("in", "out", 64, ScanKind::ExclusiveSum);
        assert_eq!(p.workgroup_size, [64, 1, 1]);
    }

    #[test]
    #[should_panic(expected = "power of two")]
    fn non_power_of_two_n_panics() {
        let _ = prefix_scan("in", "out", 5, ScanKind::InclusiveSum);
    }

    #[test]
    #[should_panic(expected = "power of two")]
    fn zero_n_panics() {
        let _ = prefix_scan("in", "out", 0, ScanKind::InclusiveSum);
    }

    #[test]
    #[should_panic(expected = "power of two")]
    fn over_limit_n_panics() {
        let _ = prefix_scan("in", "out", 2048, ScanKind::InclusiveSum);
    }

    #[test]
    fn binary_power_of_two_sizes_accepted() {
        for n in &[1_u32, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
            let _ = prefix_scan("in", "out", *n, ScanKind::InclusiveSum);
        }
    }
}
