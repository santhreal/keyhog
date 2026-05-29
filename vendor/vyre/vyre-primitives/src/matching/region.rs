//! Span-region dedup primitive.
//!
//! Every multimatch consumer (`vyre-libs::matching` engines, scanner consumer,
//! external analyzer) ends up doing the same operation after the GPU dispatch
//! returns: take the raw `Vec<Match>`, collapse adjacent overlapping
//! or duplicate spans into a representative, return the deduped set.
//! Each consumer wrote it differently  -  some by `(detector_id,
//! credential)` HashMap, some by `(start, end)` pair sort, some by ad-
//! hoc loop. The lego-block fix is one primitive every consumer calls.
//!
//! # Algorithm
//!
//! Given a slice of `(pid, start, end)` triples sorted by `start`,
//! emit one representative per maximal cluster of triples that
//! overlap (`start[i] < end[max_end_so_far]`) AND have the same
//! `pid`. This collapses both:
//!
//!   - `(pid=0, 5, 10)` and `(pid=0, 6, 11)` → `(pid=0, 5, 11)`
//!     (overlapping, same pattern  -  extend span).
//!   - `(pid=0, 5, 10)` and `(pid=0, 5, 10)` → one entry
//!     (exact dup).
//!
//! Distinct `pid`s never merge  -  two patterns matching the same
//! region produce two output spans (cross-pattern dedup is a
//! different operation; consumers that want it apply a second pass).
//!
//! # CPU + GPU
//!
//! - `dedup_regions_cpu` is the reference implementation: pure data,
//!   no IR, no backend. CPU-side consumers and parity tests use it.
//! - `dedup_regions_program` returns a `vyre::Program` that performs
//!   the same operation on a GPU-resident `(pid, start, end)` buffer.
//!   Composed via `fuse_programs` into the host's match pipeline so
//!   no PCIe readback happens before dedup.
//!
//! Both share a single golden test fixture set so any divergence is
//! caught at conform time.

use std::cmp::Ordering;

/// One match as exposed by `vyre_foundation::match_result::Match`  -
/// duplicated here as a plain triple so this primitive doesn't depend
/// on foundation. Consumers convert at the boundary.
///
/// `pid`: pattern id; `start` / `end`: byte offsets, half-open
/// `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionTriple {
    /// Pattern id (which detector emitted this match).
    pub pid: u32,
    /// Inclusive start byte offset.
    pub start: u32,
    /// Exclusive end byte offset.
    pub end: u32,
}

impl RegionTriple {
    /// Construct a region triple. `end` must be `>= start`; equal
    /// values represent a zero-width match (legal for some regex
    /// constructs).
    #[must_use]
    pub const fn new(pid: u32, start: u32, end: u32) -> Self {
        Self { pid, start, end }
    }
}

impl Ord for RegionTriple {
    fn cmp(&self, other: &Self) -> Ordering {
        // Sort by (pid, start, end) so the dedup loop sees cluster
        // members consecutively without a secondary group-by pass.
        self.pid
            .cmp(&other.pid)
            .then(self.start.cmp(&other.start))
            .then(self.end.cmp(&other.end))
    }
}

impl PartialOrd for RegionTriple {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Reference CPU implementation: collapse same-pid overlapping spans.
///
/// Sort happens inline (`sort_unstable`); the input may arrive in any
/// order. Pre-sorted callers should still see linear behavior since
/// `sort_unstable` is `O(n log n)` worst case, `O(n)` on already-
/// sorted input.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn dedup_regions_cpu(input: Vec<RegionTriple>) -> Vec<RegionTriple> {
    let mut owned = input;
    dedup_regions_inplace(&mut owned);
    owned
}

/// GPU companion to [`dedup_regions_inplace`].
///
/// Input contract: `pids`, `starts`, `ends` are three parallel
/// storage buffers, sorted by `(pid, start, end)`  -  the same order
/// the CPU reference produces after `sort_unstable`. Each lane reads
/// its own slot and one neighbour, then writes a `0`/`1` survivor
/// flag into the `survivors` buffer. The flag is `1` when the slot
/// starts a fresh `(pid, start..end)` run that does **not** merge
/// into the previous slot; it is `0` for slots whose `start <=
/// prev.end` and `pid == prev.pid` (the merge condition).
///
/// Composition: pair this Program with
/// [`crate::math::stream_compact::stream_compact`] over the same
/// flag buffer to obtain a packed deduped output. The two Programs
/// share the lego-block contract that backs the CPU
/// [`dedup_regions_inplace`]  -  caller does the host-side sort,
/// then dispatches `dedup_regions_flag_program` followed by
/// `stream_compact` to land the deduped triples on-device without a
/// readback round-trip.
///
/// The buffer count is the unit of dispatch (`workgroup_size[0]`
/// must divide it). Lane 0 always writes `1` because the first slot
/// has no predecessor to merge into.
#[must_use]
pub fn dedup_regions_flag_program(
    pids: &str,
    starts: &str,
    ends: &str,
    survivors: &str,
    count: u32,
) -> vyre_foundation::ir::Program {
    use std::sync::Arc;
    use vyre_foundation::ir::model::expr::Ident;
    use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

    let t = Expr::InvocationId { axis: 0 };

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(count)),
        vec![
            Node::let_bind("pid_self", Expr::load(pids, t.clone())),
            Node::let_bind("start_self", Expr::load(starts, t.clone())),
            Node::if_then(
                Expr::eq(t.clone(), Expr::u32(0)),
                vec![Node::store(survivors, t.clone(), Expr::u32(1))],
            ),
            Node::if_then(
                Expr::ne(t.clone(), Expr::u32(0)),
                vec![
                    Node::let_bind(
                        "pid_prev",
                        Expr::load(pids, Expr::sub(t.clone(), Expr::u32(1))),
                    ),
                    Node::let_bind(
                        "end_prev",
                        Expr::load(ends, Expr::sub(t.clone(), Expr::u32(1))),
                    ),
                    // Survivor flag = 1 iff this lane starts a new
                    // (pid, run)  -  either the pid changed, or the
                    // sorted start is past the previous end. The
                    // CPU reference uses `next.start <= last.end`
                    // as the merge predicate; we negate it here so
                    // 1 = keep, 0 = drop.
                    Node::let_bind(
                        "different_pid",
                        Expr::ne(Expr::var("pid_self"), Expr::var("pid_prev")),
                    ),
                    Node::let_bind(
                        "no_overlap",
                        Expr::gt(Expr::var("start_self"), Expr::var("end_prev")),
                    ),
                    Node::let_bind(
                        "flag",
                        Expr::select(
                            Expr::or(Expr::var("different_pid"), Expr::var("no_overlap")),
                            Expr::u32(1),
                            Expr::u32(0),
                        ),
                    ),
                    Node::store(survivors, t.clone(), Expr::var("flag")),
                ],
            ),
        ],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(pids, 0, BufferAccess::ReadOnly, DataType::U32).with_count(count),
            BufferDecl::storage(starts, 1, BufferAccess::ReadOnly, DataType::U32).with_count(count),
            BufferDecl::storage(ends, 2, BufferAccess::ReadOnly, DataType::U32).with_count(count),
            BufferDecl::storage(survivors, 3, BufferAccess::WriteOnly, DataType::U32)
                .with_count(count),
        ],
        [count.clamp(1, 64), 1, 1],
        vec![Node::Region {
            generator: Ident::from("vyre-primitives::matching::region::dedup_regions_flag"),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference for [`region_sort_program`]  -  stable lexicographic
/// sort of `(pid, start, end)` triples by composite key.
///
/// `dedup_regions_inplace` already sorts internally, so callers that
/// only want dedup don't need this helper. It exists for parity tests
/// against the GPU sort and for pipelines that need the sorted-but-
/// not-yet-deduped view (e.g. when stream_compact runs separately).
#[cfg(any(test, feature = "cpu-parity"))]
pub fn sort_regions_cpu(input: &mut [RegionTriple]) {
    input.sort();
}

/// GPU stable rank sort of three parallel `(pid, start, end)` buffers
/// by composite lexicographic key  -  closes the host-side sort gap in
/// the dedup pipeline.
///
/// Pairs with [`dedup_regions_flag_program`] +
/// [`crate::math::stream_compact::stream_compact`] to land deduped
/// regions on-device with no PCIe round-trip:
///
/// ```text
/// region_sort_program(in_p, in_s, in_e, out_p, out_s, out_e, n)
///   → dedup_regions_flag_program(out_p, out_s, out_e, flags, n)
///   → prefix_scan(flags, offsets, n)
///   → stream_compact(/* per-buffer */)
/// ```
///
/// # Algorithm
///
/// Each invocation `i` computes its rank among the input by counting
/// how many input slots `j` carry a strictly-smaller composite key,
/// plus a stable tie-break (`j < i` for equal keys). The output
/// triples land at the rank position. Composite-key compare is the
/// 3-way lexicographic order `(pid, start, end)`  -  the same order
/// `RegionTriple`'s [`Ord`] impl produces, so CPU and GPU outputs
/// must agree triple-for-triple.
///
/// This is a single-dispatch O(n²) rank sort, like
/// [`crate::reduce::radix_sort`]. The algorithm is correct for any
/// `count`; bench-scale dispatches (up to ~10K matches per scan
/// window) are the scanner consumer/external analyzer target. The multi-dispatch radix
/// pipeline can replace this body once pipeline-level scratch is
/// available  -  the function signature is stable.
#[must_use]
pub fn region_sort_program(
    pids_in: &str,
    starts_in: &str,
    ends_in: &str,
    pids_out: &str,
    starts_out: &str,
    ends_out: &str,
    count: u32,
) -> vyre_foundation::ir::Program {
    use std::sync::Arc;
    use vyre_foundation::ir::model::expr::Ident;
    use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

    if count == 0 {
        return crate::invalid_output_program(
            "vyre-primitives::matching::region::sort_regions",
            pids_out,
            DataType::U32,
            format!("Fix: region_sort_program requires count > 0, got {count}."),
        );
    }

    let t = Expr::InvocationId { axis: 0 };

    // Composite-key compare: key_j < key_i ⇔
    //   pid_j < pid_i
    //   ∨ (pid_j == pid_i ∧ start_j < start_i)
    //   ∨ (pid_j == pid_i ∧ start_j == start_i ∧ end_j < end_i)
    let pid_eq = Expr::eq(Expr::var("pid_j"), Expr::var("pid_i"));
    let start_eq = Expr::eq(Expr::var("start_j"), Expr::var("start_i"));
    let lower_key = Expr::or(
        Expr::lt(Expr::var("pid_j"), Expr::var("pid_i")),
        Expr::or(
            Expr::and(
                pid_eq.clone(),
                Expr::lt(Expr::var("start_j"), Expr::var("start_i")),
            ),
            Expr::and(
                pid_eq.clone(),
                Expr::and(
                    start_eq.clone(),
                    Expr::lt(Expr::var("end_j"), Expr::var("end_i")),
                ),
            ),
        ),
    );
    // Stable tie-break: equal composite key ∧ j < i
    let stable_tie = Expr::and(
        pid_eq,
        Expr::and(
            start_eq,
            Expr::and(
                Expr::eq(Expr::var("end_j"), Expr::var("end_i")),
                Expr::lt(Expr::var("j"), Expr::var("i")),
            ),
        ),
    );

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(count)),
        vec![
            Node::let_bind("i", t.clone()),
            Node::let_bind("pid_i", Expr::load(pids_in, Expr::var("i"))),
            Node::let_bind("start_i", Expr::load(starts_in, Expr::var("i"))),
            Node::let_bind("end_i", Expr::load(ends_in, Expr::var("i"))),
            Node::let_bind("rank", Expr::u32(0)),
            Node::loop_for(
                "j",
                Expr::u32(0),
                Expr::u32(count),
                vec![
                    Node::let_bind("pid_j", Expr::load(pids_in, Expr::var("j"))),
                    Node::let_bind("start_j", Expr::load(starts_in, Expr::var("j"))),
                    Node::let_bind("end_j", Expr::load(ends_in, Expr::var("j"))),
                    Node::if_then(
                        Expr::or(lower_key.clone(), stable_tie.clone()),
                        vec![Node::assign(
                            "rank",
                            Expr::add(Expr::var("rank"), Expr::u32(1)),
                        )],
                    ),
                ],
            ),
            Node::store(pids_out, Expr::var("rank"), Expr::var("pid_i")),
            Node::store(starts_out, Expr::var("rank"), Expr::var("start_i")),
            Node::store(ends_out, Expr::var("rank"), Expr::var("end_i")),
        ],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(pids_in, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(count),
            BufferDecl::storage(starts_in, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(count),
            BufferDecl::storage(ends_in, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(count),
            BufferDecl::storage(pids_out, 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(count),
            BufferDecl::storage(starts_out, 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(count),
            BufferDecl::storage(ends_out, 5, BufferAccess::ReadWrite, DataType::U32)
                .with_count(count),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from("vyre-primitives::matching::region::region_sort"),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// Sort and merge overlapping regions in place.
///
/// Regions are ordered by `(pid, start, end)`. Adjacent entries with the same
/// pattern id and overlapping or touching byte spans are coalesced into a
/// single [`RegionTriple`]. The vector is truncated to the deduplicated length.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn dedup_regions_inplace(input: &mut Vec<RegionTriple>) {
    if input.is_empty() {
        return;
    }
    input.sort_unstable();

    // Two-cursor compaction: `write` indexes the next slot to populate,
    // `read` walks the (sorted) input. Each merge folds the read entry
    // into `input[write - 1]`; each non-merge advances `write`.
    let mut write = 1usize;
    for read in 1..input.len() {
        let next = input[read];
        let last = input[write - 1];
        let same_pid = next.pid == last.pid;
        let overlap_or_touch = next.start <= last.end;
        if same_pid && overlap_or_touch {
            if next.end > last.end {
                input[write - 1].end = next.end;
            }
        } else {
            input[write] = next;
            write += 1;
        }
    }
    input.truncate(write);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input() {
        assert!(dedup_regions_cpu(vec![]).is_empty());
    }

    #[test]
    fn single_pass_through() {
        let r = RegionTriple::new(0, 5, 10);
        assert_eq!(dedup_regions_cpu(vec![r]), vec![r]);
    }

    #[test]
    fn exact_duplicate_collapses() {
        let r = RegionTriple::new(0, 5, 10);
        assert_eq!(dedup_regions_cpu(vec![r, r]), vec![r]);
    }

    #[test]
    fn overlapping_same_pid_merges() {
        let a = RegionTriple::new(0, 5, 10);
        let b = RegionTriple::new(0, 7, 12);
        assert_eq!(
            dedup_regions_cpu(vec![a, b]),
            vec![RegionTriple::new(0, 5, 12)]
        );
    }

    #[test]
    fn touching_same_pid_merges() {
        // [5,10) and [10,15): adjacent but not overlapping. Merge
        // anyway to avoid two near-zero-gap spans for the same pid.
        let a = RegionTriple::new(0, 5, 10);
        let b = RegionTriple::new(0, 10, 15);
        assert_eq!(
            dedup_regions_cpu(vec![a, b]),
            vec![RegionTriple::new(0, 5, 15)]
        );
    }

    #[test]
    fn different_pids_never_merge() {
        let a = RegionTriple::new(0, 5, 10);
        let b = RegionTriple::new(1, 5, 10);
        let mut got = dedup_regions_cpu(vec![a, b]);
        got.sort_unstable();
        assert_eq!(got, vec![a, b]);
    }

    #[test]
    fn unsorted_input_handled() {
        let a = RegionTriple::new(0, 5, 10);
        let b = RegionTriple::new(0, 7, 12);
        let c = RegionTriple::new(1, 3, 4);
        let got = dedup_regions_cpu(vec![b, a, c]);
        assert_eq!(got, vec![RegionTriple::new(0, 5, 12), c]);
    }


    #[test]
    fn cluster_of_three_merges() {
        let a = RegionTriple::new(0, 1, 3);
        let b = RegionTriple::new(0, 2, 5);
        let c = RegionTriple::new(0, 4, 8);
        assert_eq!(
            dedup_regions_cpu(vec![a, b, c]),
            vec![RegionTriple::new(0, 1, 8)]
        );
    }

    #[test]
    fn zero_width_matches_preserved() {
        let a = RegionTriple::new(0, 5, 5); // zero-width
        let b = RegionTriple::new(1, 5, 5); // zero-width different pid
        let mut got = dedup_regions_cpu(vec![a, b]);
        got.sort_unstable();
        assert_eq!(got, vec![a, b]);
    }

    #[test]
    fn sort_regions_cpu_matches_ord_impl() {
        let mut a = vec![
            RegionTriple::new(2, 0, 1),
            RegionTriple::new(0, 5, 10),
            RegionTriple::new(1, 3, 4),
            RegionTriple::new(0, 5, 8),
            RegionTriple::new(0, 5, 10),
        ];
        sort_regions_cpu(&mut a);
        assert_eq!(
            a,
            vec![
                RegionTriple::new(0, 5, 8),
                RegionTriple::new(0, 5, 10),
                RegionTriple::new(0, 5, 10),
                RegionTriple::new(1, 3, 4),
                RegionTriple::new(2, 0, 1),
            ]
        );
    }

    #[test]
    fn sort_regions_cpu_is_stable_for_equal_triples() {
        // Equal triples are indistinguishable post-sort, but stability
        // here means "no panic, no reorder of distinct ranks". Use a
        // surrounding triple to anchor position.
        let mut a = vec![
            RegionTriple::new(0, 5, 10),
            RegionTriple::new(0, 5, 10),
            RegionTriple::new(0, 5, 10),
        ];
        sort_regions_cpu(&mut a);
        assert_eq!(a.len(), 3);
        for r in &a {
            assert_eq!(*r, RegionTriple::new(0, 5, 10));
        }
    }

    #[test]
    fn region_sort_program_emits_expected_buffers() {
        let p = region_sort_program("pi", "si", "ei", "po", "so", "eo", 64);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["pi", "si", "ei", "po", "so", "eo"]);
        for buf in p.buffers.iter() {
            assert_eq!(buf.count(), 64);
        }
    }

    #[test]
    fn region_sort_program_zero_count_traps() {
        let p = region_sort_program("pi", "si", "ei", "po", "so", "eo", 0);
        assert!(p.stats().trap());
    }

    #[test]
    fn region_sort_program_pipeline_composes_with_dedup_flags() {
        // Smoke test the composition contract: sort program must use
        // the same buffer-name surface that dedup_regions_flag_program
        // can consume. This checks the doc-claim wiring at construction
        // time without running a real GPU dispatch.
        let sort_p = region_sort_program("pi", "si", "ei", "ps", "ss", "es", 32);
        let flag_p = dedup_regions_flag_program("ps", "ss", "es", "flags", 32);
        // The sort writes (ps, ss, es); the flag program reads them.
        let sort_outputs: Vec<&str> = sort_p
            .buffers
            .iter()
            .filter(|b| b.access() == vyre_foundation::ir::BufferAccess::ReadWrite)
            .map(|b| b.name())
            .collect();
        assert_eq!(sort_outputs, vec!["ps", "ss", "es"]);
        let flag_inputs: Vec<&str> = flag_p
            .buffers
            .iter()
            .filter(|b| b.access() == vyre_foundation::ir::BufferAccess::ReadOnly)
            .map(|b| b.name())
            .collect();
        assert_eq!(flag_inputs, vec!["ps", "ss", "es"]);
    }
}

