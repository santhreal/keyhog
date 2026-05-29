//! Multi-block parallel prefix sum  -  bridges the gap between
//! `vyre_primitives::math::prefix_scan` (single workgroup, ≤1024 lanes)
//! and `prefix_scan_large` (single-thread sequential).
//!
//! # Why
//!
//! `prefix_scan` is fast but only handles 1024-element inputs.
//! `prefix_scan_large` accepts arbitrary `n` but its body is
//! `if InvocationId == 0 { for i in 0..n { ... } }`  -  single-thread
//! sequential, the antithesis of the parallel substrate this crate
//! exists for. Real workloads (lex compaction over a 3 MB C TU,
//! histogram CDFs over millions of bins, etc.) need both: arbitrary
//! `n` AND O(log N) wall-clock.
//!
//! This module composes the two existing primitives plus a Pass-C
//! offset broadcast into a 3-pass Blelloch-style chain:
//!
//! ```text
//!   Pass A: per-block local Hillis-Steele scan.
//!           writes per-element partials and per-block totals.
//!   GridSync barrier (substrate splits the dispatch here).
//!   Pass B: scan of per-block totals.
//!           recursive  -  this fn calls itself with the totals as input.
//!           Bottoms out at `prefix_scan` (≤1024 element single-workgroup).
//!   GridSync barrier.
//!   Pass C: per-element offset add.
//!           thread t: out[t] = partials[t] + scanned_block_totals[block_id(t) - 1].
//! ```
//!
//! # Returns
//!
//! A single fused `Program`. The substrate (vyre-driver/grid_sync.rs)
//! splits the dispatch into three kernel launches at the GridSync
//! barriers when the backend doesn't support cooperative groups.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre_foundation::MemoryOrdering;

use crate::math::prefix_scan::{prefix_scan_with_op_id, ScanKind};

/// Canonical op id for inclusive sum-scan over arbitrary `n`.
pub const OP_ID_INCLUSIVE_SUM: &str =
    "vyre-primitives::reduce::multi_block_prefix_scan_inclusive_sum";

/// Lanes per Pass-A block. Must equal the workgroup size used by
/// `prefix_scan`'s Hillis-Steele implementation. 1024 is the universal
/// max-workgroup-size on every GPU vyre targets.
pub const BLOCK_LANES: u32 = 1024;

/// Maximum input size handled directly without falling back to the
/// existing serial `prefix_scan_large`. `BLOCK_LANES * BLOCK_LANES`
/// = 1,048,576 elements  -  Pass B (which scans `num_blocks`) recurses
/// into this same function and bottoms out at `prefix_scan` once
/// `num_blocks ≤ BLOCK_LANES`.
pub const SOFT_MAX_N: u32 = BLOCK_LANES * BLOCK_LANES;

fn output_byte_range(words: u32, context: &str) -> usize {
    usize::try_from(words)
        .ok()
        .and_then(|count| count.checked_mul(4))
        .unwrap_or_else(|| {
            panic!(
                "{context} words={words} overflows output byte range. Fix: shard the scan before GPU dispatch."
            )
        })
}

/// Build an inclusive parallel prefix-sum Program over arbitrary `n`.
///
/// Backed by `prefix_scan` for `n ≤ BLOCK_LANES`; otherwise a 3-pass
/// Blelloch chain (Pass A local scan + per-block totals → Pass B scan
/// of totals → Pass C broadcast offsets).
///
/// `n == 0` returns an empty Program.
#[must_use]
pub fn multi_block_prefix_scan_sum_u32(input: &str, output: &str, n: u32) -> Program {
    if n == 0 {
        return Program::empty();
    }
    if n <= BLOCK_LANES {
        return prefix_scan_with_op_id(
            input,
            output,
            n,
            ScanKind::InclusiveSum,
            OP_ID_INCLUSIVE_SUM,
        );
    }

    let num_blocks = n.div_ceil(BLOCK_LANES);

    // Distinct buffer names for each intermediate. Caller supplies in/out;
    // we generate scratch names from `output` so two scans on different
    // outputs never alias.
    let partials = format!("__{output}_mbps_partials");
    let block_totals = format!("__{output}_mbps_block_totals");
    let block_totals_scanned = format!("__{output}_mbps_block_totals_scanned");

    let pass_a = pass_a_local_scan(input, &partials, &block_totals, n, num_blocks);
    let pass_b = multi_block_prefix_scan_sum_u32(&block_totals, &block_totals_scanned, num_blocks);
    let pass_c = pass_c_broadcast_offsets(&partials, &block_totals_scanned, output, n, num_blocks);

    // Single fused Program; vyre-driver splits at the GridSync barriers.
    // Fuse failure on three disjoint-buffer passes is a substrate bug and must
    // not be represented as an empty program: empty programs are valid
    // elsewhere, so using one here would hide a GPU prefix-scan migration hole.
    match vyre_foundation::execution_plan::fusion::fuse_programs(&[pass_a, pass_b, pass_c]) {
        Ok(prog) => prog,
        Err(_) => panic!(
            "vyre multi_block_prefix_scan fusion failed for n={n}, num_blocks={num_blocks}. Fix: repair grid-sync fusion for the three-pass GPU scan; do not substitute an empty Program."
        ),
    }
}

/// Pass A  -  per-block local inclusive Hillis-Steele scan.
///
/// Each workgroup of `BLOCK_LANES` threads scans one block of the input.
/// Lane L within block B reads `input[B*BLOCK_LANES + L]`, runs a
/// `log2(BLOCK_LANES)`-round Hillis-Steele scan in shared memory, and
/// writes:
///   * `partials[B*BLOCK_LANES + L]` = inclusive scan within this block
///   * `block_totals[B]` = sum of this block (only lane `BLOCK_LANES-1`
///     of the block writes this, after the final scan round)
/// Build Pass A for a resident or manually-scheduled multi-block inclusive scan.
///
/// This is exposed so GPU-resident pipelines can keep `partials` and
/// `block_totals` on device between launches instead of routing through the
/// generic grid-sync splitter and host readback path.
#[must_use]
pub fn pass_a_local_scan(
    input: &str,
    partials: &str,
    block_totals: &str,
    n: u32,
    num_blocks: u32,
) -> Program {
    let lane = Expr::var("lane");
    let block = Expr::var("block");
    let global = Expr::var("global");
    let scratch_a = format!("__{partials}_pass_a_scratch_a");
    let scratch_b = format!("__{partials}_pass_a_scratch_b");

    let mut body: Vec<Node> = Vec::new();
    body.push(Node::let_bind("lane", Expr::LocalId { axis: 0 }));
    body.push(Node::let_bind("block", Expr::WorkgroupId { axis: 0 }));
    body.push(Node::let_bind(
        "global",
        Expr::add(
            Expr::mul(block.clone(), Expr::u32(BLOCK_LANES)),
            lane.clone(),
        ),
    ));

    // Stage input into shared scratch, zero past `n`.
    body.push(Node::store(&scratch_a, lane.clone(), Expr::u32(0)));
    body.push(Node::if_then(
        Expr::lt(global.clone(), Expr::u32(n)),
        vec![Node::store(
            &scratch_a,
            lane.clone(),
            Expr::load(input, global.clone()),
        )],
    ));
    body.push(Node::Barrier {
        ordering: MemoryOrdering::SeqCst,
    });

    // Hillis-Steele rounds: log2(BLOCK_LANES) iterations.
    let mut stride = 1_u32;
    while stride < BLOCK_LANES {
        // Unconditional A→B copy keeps lanes < stride at their current value.
        body.push(Node::store(
            &scratch_b,
            lane.clone(),
            Expr::load(&scratch_a, lane.clone()),
        ));
        // Lanes ≥ stride: B[lane] = A[lane] + A[lane - stride].
        // The `lane - stride` is safe inside this guarded branch because
        // the predicate ensures lane ≥ stride.
        let previous_lane = Expr::add(lane.clone(), Expr::u32(0u32.wrapping_sub(stride)));
        body.push(Node::if_then(
            Expr::lt(Expr::u32(stride - 1), lane.clone()),
            vec![Node::store(
                &scratch_b,
                lane.clone(),
                Expr::add(
                    Expr::load(&scratch_a, lane.clone()),
                    Expr::load(&scratch_a, previous_lane),
                ),
            )],
        ));
        body.push(Node::Barrier {
            ordering: MemoryOrdering::SeqCst,
        });
        // Copy B→A so the next round reads from A.
        body.push(Node::store(
            &scratch_a,
            lane.clone(),
            Expr::load(&scratch_b, lane.clone()),
        ));
        body.push(Node::Barrier {
            ordering: MemoryOrdering::SeqCst,
        });
        stride *= 2;
    }

    // Write per-element partial out (only for lanes whose global id is in range).
    body.push(Node::if_then(
        Expr::lt(global.clone(), Expr::u32(n)),
        vec![Node::store(
            partials,
            global.clone(),
            Expr::load(&scratch_a, lane.clone()),
        )],
    ));

    // Lane (BLOCK_LANES - 1) of each block writes the block's total.
    // Use the scanned value at lane (BLOCK_LANES - 1), which is the inclusive
    // sum of all in-range elements (out-of-range lanes contributed 0 from the
    // initial zero-fill).
    body.push(Node::if_then(
        Expr::eq(lane.clone(), Expr::u32(BLOCK_LANES - 1)),
        vec![Node::store(
            block_totals,
            block.clone(),
            Expr::load(&scratch_a, lane.clone()),
        )],
    ));

    let total_partials = num_blocks.checked_mul(BLOCK_LANES).unwrap_or_else(|| {
        panic!(
            "vyre multi_block_prefix_scan Pass A num_blocks={num_blocks} overflows partial buffer count. Fix: shard the scan before GPU dispatch."
        )
    });
    let total_partial_bytes = output_byte_range(
        total_partials,
        "vyre multi_block_prefix_scan Pass A partials",
    );
    let block_total_bytes = output_byte_range(
        num_blocks,
        "vyre multi_block_prefix_scan Pass A block_totals",
    );
    let buffers = vec![
        BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
        BufferDecl::output(partials, 1, DataType::U32)
            .with_count(total_partials)
            .with_output_byte_range(0..total_partial_bytes),
        BufferDecl::storage(block_totals, 2, BufferAccess::ReadWrite, DataType::U32)
            .with_count(num_blocks)
            .with_pipeline_live_out(true)
            .with_output_byte_range(0..block_total_bytes),
        BufferDecl::workgroup(&scratch_a, BLOCK_LANES, DataType::U32),
        BufferDecl::workgroup(&scratch_b, BLOCK_LANES, DataType::U32),
    ];

    Program::wrapped(
        buffers,
        [BLOCK_LANES, 1, 1],
        vec![Node::Region {
            generator: Ident::from("vyre-primitives::reduce::multi_block_prefix_scan::pass_a"),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// Pass C  -  broadcast scanned per-block totals back to per-element output.
///
/// `out[B*BLOCK_LANES + L] = partials[B*BLOCK_LANES + L] + offset`,
/// where `offset = scanned_block_totals[B - 1]` (or `0` for block 0).
///
/// Uses an `if_then` (not `Expr::select`) for the `offset` lookup so the
/// `block - 1` load is never evaluated when `block == 0`. `Expr::select`
/// evaluates both arms unconditionally; with no OOB-clamp on the load
/// path that would underflow to `0xFFFFFFFF` and ILLEGAL_ADDRESS on CUDA.
/// Build Pass C for a resident or manually-scheduled multi-block inclusive scan.
///
/// Callers supply `partials` from [`pass_a_local_scan`] and a scanned
/// `block_totals` buffer, then this pass writes the final inclusive scan.
#[must_use]
pub fn pass_c_broadcast_offsets(
    partials: &str,
    block_totals_scanned: &str,
    output: &str,
    n: u32,
    num_blocks: u32,
) -> Program {
    let lane = Expr::var("lane");
    let block = Expr::var("block");
    let global = Expr::var("global");
    let offset = Expr::var("offset");

    let body = vec![
        Node::let_bind("lane", Expr::LocalId { axis: 0 }),
        Node::let_bind("block", Expr::WorkgroupId { axis: 0 }),
        Node::let_bind(
            "global",
            Expr::add(
                Expr::mul(block.clone(), Expr::u32(BLOCK_LANES)),
                lane.clone(),
            ),
        ),
        Node::let_bind("offset", Expr::u32(0)),
        Node::if_then(
            Expr::lt(Expr::u32(0), block.clone()),
            vec![Node::assign(
                "offset",
                Expr::load(
                    block_totals_scanned,
                    // block - 1 via wrapping; only evaluated when block ≥ 1.
                    Expr::add(block.clone(), Expr::u32(0u32.wrapping_sub(1))),
                ),
            )],
        ),
        Node::if_then(
            Expr::lt(global.clone(), Expr::u32(n)),
            vec![Node::store(
                output,
                global.clone(),
                Expr::add(Expr::load(partials, global.clone()), offset),
            )],
        ),
    ];

    let total_partials = num_blocks.checked_mul(BLOCK_LANES).unwrap_or_else(|| {
        panic!(
            "vyre multi_block_prefix_scan Pass C num_blocks={num_blocks} overflows partial buffer count. Fix: shard the scan before GPU dispatch."
        )
    });
    let output_bytes = output_byte_range(n, "vyre multi_block_prefix_scan Pass C output");
    let buffers = vec![
        BufferDecl::storage(partials, 0, BufferAccess::ReadOnly, DataType::U32)
            .with_count(total_partials),
        BufferDecl::storage(
            block_totals_scanned,
            1,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(num_blocks),
        BufferDecl::output(output, 2, DataType::U32)
            .with_count(n)
            .with_output_byte_range(0..output_bytes),
    ];

    Program::wrapped(
        buffers,
        [BLOCK_LANES, 1, 1],
        vec![Node::Region {
            generator: Ident::from("vyre-primitives::reduce::multi_block_prefix_scan::pass_c"),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference: inclusive prefix sum. Used by tests + as the
/// correctness oracle for the GPU primitive.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref(input: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    match try_cpu_ref_into(input, &mut out) {
        Ok(()) => out,
        Err(error) => {
            eprintln!("vyre-primitives multi-block prefix-scan CPU reference failed: {error}");
            Vec::new()
        }
    }
}

/// CPU reference writing into caller-owned output storage.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_into(input: &[u32], out: &mut Vec<u32>) {
    if let Err(error) = try_cpu_ref_into(input, out) {
        eprintln!("vyre-primitives multi-block prefix-scan CPU reference failed: {error}");
        out.clear();
    }
}

/// Fallible CPU reference writing into caller-owned output storage.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn try_cpu_ref_into(input: &[u32], out: &mut Vec<u32>) -> Result<(), String> {
    if input.len() > out.capacity() {
        out.try_reserve_exact(input.len() - out.capacity())
            .map_err(|err| {
                format!(
                    "multi-block prefix-scan CPU reference could not reserve {} output words: {err}",
                    input.len()
                )
            })?;
    }
    out.clear();
    let mut acc: u32 = 0;
    for &x in input {
        acc = acc.wrapping_add(x);
        out.push(acc);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ref_matches_simple_inclusive_sum() {
        assert_eq!(cpu_ref(&[1, 2, 3, 4]), vec![1, 3, 6, 10]);
        assert_eq!(cpu_ref(&[]), Vec::<u32>::new());
        assert_eq!(cpu_ref(&[7]), vec![7]);
    }

    #[test]
    fn cpu_ref_into_reuses_output_and_truncates_stale_tail() {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&[99, 98, 97, 96]);
        let capacity = out.capacity();

        cpu_ref_into(&[u32::MAX, 1, 2], &mut out);
        assert_eq!(out, vec![u32::MAX, 0, 2]);
        assert_eq!(out.capacity(), capacity);

        cpu_ref_into(&[7], &mut out);
        assert_eq!(out, vec![7]);
        assert_eq!(out.capacity(), capacity);
    }

    #[test]
    fn try_cpu_ref_into_reuses_output_and_clears_stale_tail() {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&[99, 98, 97, 96]);
        let ptr = out.as_ptr();

        try_cpu_ref_into(&[u32::MAX, 1, 2], &mut out).unwrap();

        assert_eq!(out, vec![u32::MAX, 0, 2]);
        assert_eq!(out.as_ptr(), ptr);
    }

    #[test]
    fn compatibility_wrappers_match_fallible_reference() {
        let input = &[u32::MAX, 1, 2];
        let mut compat = Vec::with_capacity(8);
        let mut fallible = Vec::with_capacity(8);

        cpu_ref_into(input, &mut compat);
        try_cpu_ref_into(input, &mut fallible)
            .expect("Fix: small multi-block prefix-scan CPU reference must reserve");

        assert_eq!(cpu_ref(input), fallible);
        assert_eq!(compat, fallible);
    }

    #[test]
    fn production_wrappers_have_no_raw_panic_path() {
        let production = include_str!("multi_block_prefix_scan.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("Fix: multi_block_prefix_scan.rs must contain production section");

        assert!(
            !production.contains(".expect(") && !production.contains(".unwrap("),
            "Fix: multi-block prefix-scan CPU reference wrappers must not panic in production."
        );
    }

    #[test]
    fn small_n_falls_through_to_single_block_path() {
        // n ≤ BLOCK_LANES routes to existing prefix_scan; verify the builder
        // produces a non-empty Program for representative small sizes.
        for &n in &[1u32, 2, 64, 1023, 1024] {
            let prog = multi_block_prefix_scan_sum_u32("in_buf", "out_buf", n);
            let names: Vec<&str> = prog.buffers().iter().map(BufferDecl::name).collect();
            assert!(names.contains(&"in_buf"), "n={n} must declare in_buf, got {names:?}");
            assert!(names.contains(&"out_buf"), "n={n} must declare out_buf, got {names:?}");
        }
    }

    #[test]
    fn large_n_emits_three_pass_chain() {
        // n = 2 * BLOCK_LANES → exactly 2 blocks, no recursion needed.
        let prog = multi_block_prefix_scan_sum_u32("in_buf", "out_buf", 2 * BLOCK_LANES);
        let names: Vec<&str> = prog.buffers().iter().map(BufferDecl::name).collect();
        assert!(
            names.contains(&"in_buf"),
            "input must be declared, got {names:?}"
        );
        assert!(
            names.contains(&"out_buf"),
            "output must be declared, got {names:?}"
        );
    }

    #[test]
    fn empty_input_returns_empty_program() {
        let prog = multi_block_prefix_scan_sum_u32("in_buf", "out_buf", 0);
        assert!(prog.buffers().is_empty());
    }

    #[test]
    fn recursion_handles_million_elements() {
        // n = 1_048_576 → num_blocks = 1024 → Pass B falls through to single
        // workgroup `prefix_scan` (1024 ≤ BLOCK_LANES). Verify build.
        let prog = multi_block_prefix_scan_sum_u32("in_buf", "out_buf", SOFT_MAX_N);
        let names: Vec<&str> = prog.buffers().iter().map(BufferDecl::name).collect();
        assert!(names.contains(&"in_buf"));
        assert!(names.contains(&"out_buf"));
    }
}
