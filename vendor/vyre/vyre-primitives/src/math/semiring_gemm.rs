//! Generic-semiring matrix multiply — the spine of the LEGO substrate.
//!
//! `semiring_gemm` is one Program builder parameterized by a closed semiring
//! choice. It emits IR specialized to that semiring at build time — the
//! emitted body contains zero runtime branches over the semiring tag, so
//! Tensor Cores and subgroup-mat-mul intrinsics see the same shape they
//! would for a standard `(×, +)` gemm.
//!
//! # Why this primitive is dual-use
//!
//! Same Program is consumed by user-dialect callers (Tier 3 `vyre-libs`) AND
//! by vyre's own substrate (`vyre-foundation::transform`):
//!
//! | Semiring | User-dialect consumer | vyre-self consumer |
//! |---|---|---|
//! | `Real` (×, +) | every numeric workload | dispatch-cost matrix products |
//! | `MinPlus` (+, min) | shortest-path graphs in `vyre-libs::security` | dependency-graph longest-path for #19 polyhedral fusion |
//! | `MaxPlus` (+, max) | scheduling, rate analysis | critical-path of dispatch graph for #22 megakernel scheduler |
//! | `BoolOr` (∧, ∨) | reachability in `vyre-libs::dataflow` | Region-tree reachability for #26 dataflow fixpoint |
//! | `MaxTimes` (×, max) | Viterbi/HMM forward in ML consumers | rule-conflict probability resolution |
//! | `Provenance` | `vyre-libs::scallop_join` (#39) | rule provenance tracking in frontend |
//! | `Gf2` (∧, ⊕) | crypto / linear-code dialects | bitset adjacency under XOR closure |
//!
//! Six self-consumers, six user-dialect consumers — clears the recursion-thesis
//! bar from day 1.
//!
//! # Algorithm
//!
//! ```text
//! C[i,j] = ⊕_k (A[i,k] ⊗ B[k,j])
//! ```
//!
//! where `⊕` is the additive (accumulate) op, `⊗` is the multiplicative
//! (combine) op, and the accumulator initializes to the additive identity.
//! The flat invocation `t = i*N + j` covers `M*N` output cells; the inner
//! `k` loop runs serially per lane.
//!
//! # Variant Boundaries
//!
//! Block-tiled, sparse-adjacency, and user-supplied combine/accumulate
//! forms are distinct registered ops. This module's contract is the
//! dense enum-specialized semiring GEMM over the seven well-known
//! semirings.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
pub use vyre_spec::Semiring;

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::math::semiring_gemm";

fn semiring_combine_expr(semiring: Semiring, a: Expr, b: Expr) -> Expr {
    match semiring {
        Semiring::Real | Semiring::MaxTimes => Expr::mul(a, b),
        Semiring::MinPlus => {
            // saturating add: if either operand is MAX, result is MAX,
            // otherwise a + b. Keeps MAX absorbing under min-plus.
            let max_const = Expr::u32(u32::MAX);
            let either_inf = Expr::or(
                Expr::eq(a.clone(), max_const.clone()),
                Expr::eq(b.clone(), max_const.clone()),
            );
            Expr::select(either_inf, max_const, Expr::add(a, b))
        }
        Semiring::MaxPlus => Expr::add(a, b),
        Semiring::BoolOr | Semiring::Gf2 => Expr::bitand(a, b),
        Semiring::BoolAnd => Expr::bitor(a, b),
        Semiring::Lineage => {
            // Zero-absorbing OR: if either operand is 0 (no edge),
            // the join is 0. Otherwise OR the fact bitsets along
            // the path step. Distinguishes "no edge" from
            // "edge with empty fact-set" — single-u32 lineage.
            let either_zero = Expr::or(
                Expr::eq(a.clone(), Expr::u32(0)),
                Expr::eq(b.clone(), Expr::u32(0)),
            );
            Expr::select(either_zero, Expr::u32(0), Expr::bitor(a, b))
        }
    }
}

fn semiring_accumulate_expr(semiring: Semiring, acc: Expr, val: Expr) -> Expr {
    match semiring {
        Semiring::Real | Semiring::MaxPlus => Expr::add(acc, val),
        Semiring::MinPlus => Expr::min(acc, val),
        Semiring::MaxTimes => Expr::max(acc, val),
        Semiring::BoolOr | Semiring::Lineage => Expr::bitor(acc, val),
        Semiring::BoolAnd => Expr::bitand(acc, val),
        Semiring::Gf2 => Expr::bitxor(acc, val),
    }
}

/// Emit a generic-semiring `M × K · K × N → M × N` matmul Program.
///
/// `a` is laid out row-major with stride `k` (`A[i, kk] = a[i*k + kk]`).
/// `b` is laid out row-major with stride `n` (`B[kk, j] = b[kk*n + j]`).
/// `c` is laid out row-major with stride `n` (`C[i, j] = c[i*n + j]`).
/// All buffers are `u32`. For non-integer semirings, callers encode their
/// own fixed-point scaling on top.
///
/// # Panics
///
/// Panics if any of `m`, `n`, `k` is zero.
#[must_use]
pub fn semiring_gemm(
    a: &str,
    b: &str,
    c: &str,
    m: u32,
    n: u32,
    k: u32,
    semiring: Semiring,
) -> Program {
    if m == 0 {
        return crate::invalid_output_program(
            OP_ID,
            c,
            DataType::U32,
            format!("Fix: semiring_gemm requires m > 0, got {m}."),
        );
    }
    if n == 0 {
        return crate::invalid_output_program(
            OP_ID,
            c,
            DataType::U32,
            format!("Fix: semiring_gemm requires n > 0, got {n}."),
        );
    }
    if k == 0 {
        return crate::invalid_output_program(
            OP_ID,
            c,
            DataType::U32,
            format!("Fix: semiring_gemm requires k > 0, got {k}."),
        );
    }

    let Some(cell_count) = m.checked_mul(n) else {
        return crate::invalid_output_program(
            OP_ID,
            c,
            DataType::U32,
            format!("Fix: semiring_gemm output cells overflow u32: m={m}, n={n}."),
        );
    };
    let Some(a_count) = m.checked_mul(k) else {
        return crate::invalid_output_program(
            OP_ID,
            c,
            DataType::U32,
            format!("Fix: semiring_gemm A buffer cells overflow u32: m={m}, k={k}."),
        );
    };
    let Some(b_count) = k.checked_mul(n) else {
        return crate::invalid_output_program(
            OP_ID,
            c,
            DataType::U32,
            format!("Fix: semiring_gemm B buffer cells overflow u32: k={k}, n={n}."),
        );
    };
    let t = Expr::InvocationId { axis: 0 };

    // Decode flat invocation into (i, j): t = i*n + j.
    // i = t / n, j = t mod n.
    let i_expr = Expr::div(t.clone(), Expr::u32(n));
    let j_expr = Expr::rem(t.clone(), Expr::u32(n));

    // a_idx = i*k + kk ; b_idx = kk*n + j
    let a_idx = Expr::add(Expr::mul(Expr::var("i"), Expr::u32(k)), Expr::var("kk"));
    let b_idx = Expr::add(Expr::mul(Expr::var("kk"), Expr::u32(n)), Expr::var("j"));

    let combine = semiring_combine_expr(semiring, Expr::load(a, a_idx), Expr::load(b, b_idx));
    let accumulate = semiring_accumulate_expr(semiring, Expr::var("acc"), combine);

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(cell_count)),
        vec![
            Node::let_bind("i", i_expr),
            Node::let_bind("j", j_expr),
            Node::let_bind("acc", Expr::u32(semiring.identity())),
            Node::loop_for(
                "kk",
                Expr::u32(0),
                Expr::u32(k),
                vec![Node::assign("acc", accumulate)],
            ),
            Node::store(c, t, Expr::var("acc")),
        ],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(a, 0, BufferAccess::ReadOnly, DataType::U32).with_count(a_count),
            BufferDecl::storage(b, 1, BufferAccess::ReadOnly, DataType::U32).with_count(b_count),
            BufferDecl::storage(c, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(cell_count),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference — exact byte-for-byte target the GPU dispatch must hit.
///
/// `a` is `m × k`, `b` is `k × n`, output is `m × n`, all row-major.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn semiring_gemm_cpu(
    a: &[u32],
    b: &[u32],
    m: u32,
    n: u32,
    k: u32,
    semiring: Semiring,
) -> Vec<u32> {
    let mut c = Vec::new();
    semiring_gemm_cpu_into(a, b, m, n, k, semiring, &mut c);
    c
}

/// CPU reference using a caller-owned output buffer.
///
/// This is the hot-path oracle for higher-level fixpoint primitives:
/// callers can keep one scratch allocation across thousands of GEMM
/// rounds instead of allocating a fresh result per iteration.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn semiring_gemm_cpu_into(
    a: &[u32],
    b: &[u32],
    m: u32,
    n: u32,
    k: u32,
    semiring: Semiring,
    c: &mut Vec<u32>,
) {
    let m_usize = m as usize;
    let n_usize = n as usize;
    let k_usize = k as usize;
    let cell_count = m_usize
        .checked_mul(n_usize)
        .expect("Fix: semiring_gemm_cpu_into output cells overflow usize.");
    c.clear();
    c.resize(cell_count, semiring.identity());
    for i in 0..m_usize {
        for j in 0..n_usize {
            let mut acc = semiring.identity();
            for kk in 0..k_usize {
                let a_v = a
                    .get(i * k_usize + kk)
                    .copied()
                    .unwrap_or(semiring.identity());
                let b_v = b
                    .get(kk * n_usize + j)
                    .copied()
                    .unwrap_or(semiring.identity());
                let combined = semiring_combine_cpu(semiring, a_v, b_v);
                acc = semiring_accumulate_cpu(semiring, acc, combined);
            }
            c[i * n_usize + j] = acc;
        }
    }
}

#[inline]
#[cfg(any(test, feature = "cpu-parity"))]
fn semiring_combine_cpu(s: Semiring, a: u32, b: u32) -> u32 {
    match s {
        Semiring::Real | Semiring::MaxTimes => a.wrapping_mul(b),
        Semiring::MinPlus => {
            if a == u32::MAX || b == u32::MAX {
                u32::MAX
            } else {
                a.saturating_add(b)
            }
        }
        Semiring::MaxPlus => a.saturating_add(b),
        Semiring::BoolOr | Semiring::Gf2 => a & b,
        Semiring::BoolAnd => a | b,
        Semiring::Lineage => {
            if a == 0 || b == 0 {
                0
            } else {
                a | b
            }
        }
    }
}

#[inline]
#[cfg(any(test, feature = "cpu-parity"))]
fn semiring_accumulate_cpu(s: Semiring, acc: u32, val: u32) -> u32 {
    match s {
        Semiring::Real | Semiring::MaxPlus => acc.wrapping_add(val),
        Semiring::MinPlus => acc.min(val),
        Semiring::MaxTimes => acc.max(val),
        Semiring::BoolOr | Semiring::Lineage => acc | val,
        Semiring::BoolAnd => acc & val,
        Semiring::Gf2 => acc ^ val,
    }
}

#[cfg(feature = "inventory-registry")]
fn fixture_u32(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || semiring_gemm("a", "b", "c", 2, 2, 2, Semiring::Real),
        Some(|| vec![vec![
            fixture_u32(&[1, 2, 3, 4]),
            fixture_u32(&[5, 6, 7, 8]),
            fixture_u32(&[0, 0, 0, 0]),
        ]]),
        Some(|| vec![vec![fixture_u32(&[19, 22, 43, 50])]]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_real_2x2() {
        // [[1,2],[3,4]] · [[5,6],[7,8]] = [[19,22],[43,50]]
        let a = vec![1, 2, 3, 4];
        let b = vec![5, 6, 7, 8];
        let c = semiring_gemm_cpu(&a, &b, 2, 2, 2, Semiring::Real);
        assert_eq!(c, vec![19, 22, 43, 50]);
    }

    #[test]
    fn cpu_real_identity() {
        // A · I = A
        let a = vec![3, 5, 7, 11];
        let i = vec![1, 0, 0, 1];
        let c = semiring_gemm_cpu(&a, &i, 2, 2, 2, Semiring::Real);
        assert_eq!(c, a);
    }

    #[test]
    fn cpu_min_plus_shortest_path_step() {
        // MinPlus matmul = one Bellman-Ford relaxation step.
        // Adjacency: 0→1 cost 5, 1→2 cost 3, 0→2 cost MAX (no direct edge).
        let inf = u32::MAX;
        let a = vec![
            inf, 5, inf, // row 0: from 0
            inf, inf, 3, // row 1: from 1
            inf, inf, inf, // row 2: from 2
        ];
        // A · A — squaring under min-plus = paths of length ≤ 2.
        let c = semiring_gemm_cpu(&a, &a, 3, 3, 3, Semiring::MinPlus);
        // 0→2 via 1: 5 + 3 = 8.
        assert_eq!(c[0 * 3 + 2], 8);
        // 0→1 has no length-exactly-2 path: MAX.
        assert_eq!(c[0 * 3 + 1], inf);
    }

    #[test]
    fn cpu_min_plus_saturating_no_overflow() {
        // Two MAX entries combined must stay MAX, not wrap to MAX-1.
        let inf = u32::MAX;
        let a = vec![inf, inf, inf, inf];
        let b = vec![inf, inf, inf, inf];
        let c = semiring_gemm_cpu(&a, &b, 2, 2, 2, Semiring::MinPlus);
        for v in c {
            assert_eq!(v, inf);
        }
    }

    #[test]
    fn cpu_bool_or_reachability() {
        // 3-node graph: 0→1, 1→2. Adjacency squared = 0→2 reachable in ≤2.
        let a = vec![
            0, 1, 0, // row 0
            0, 0, 1, // row 1
            0, 0, 0, // row 2
        ];
        let c = semiring_gemm_cpu(&a, &a, 3, 3, 3, Semiring::BoolOr);
        assert_eq!(c[0 * 3 + 2], 1);
        assert_eq!(c[0 * 3 + 1], 0); // length-exactly-2 from 0 to 1: none
    }

    #[test]
    fn cpu_lineage_scallop_join() {
        // Scallop-style which-facts-used provenance (#39).
        // Each bit in a u32 names a clause / fact:
        //   bit 0 = "fact f1 used", bit 1 = "fact f2 used".
        //
        // Edges (entry value = bitset of facts justifying that edge):
        //   0→1 justified by {f1} = 0b01
        //   1→2 justified by {f2} = 0b10
        //
        // One join step (matmul under Lineage) — path 0→2 should carry
        // {f1, f2} = 0b11 (both facts contributed along the derivation).
        let f1 = 0b01;
        let f2 = 0b10;
        let a = vec![
            0, f1, 0, // 0
            0, 0, f2, // 1
            0, 0, 0, // 2
        ];
        let c = semiring_gemm_cpu(&a, &a, 3, 3, 3, Semiring::Lineage);
        assert_eq!(c[0 * 3 + 2], f1 | f2, "lineage = union of facts along path");
        // No path 0→1 of length exactly 2 → identity 0.
        assert_eq!(c[0 * 3 + 1], 0);
    }

    #[test]
    fn cpu_lineage_alternative_paths_union() {
        // Two parallel routes 0→3, both length 2:
        //   route via 1: edges {f1}, {f2}
        //   route via 2: edges {f3}, {f4}
        // After one join step (length-2 paths), c[0,3] should accumulate
        // BOTH route's lineage sets via OR of OR.
        let f1 = 0b0001;
        let f2 = 0b0010;
        let f3 = 0b0100;
        let f4 = 0b1000;
        let a = vec![
            0, f1, f3, 0, // 0
            0, 0, 0, f2, // 1
            0, 0, 0, f4, // 2
            0, 0, 0, 0, // 3
        ];
        let c = semiring_gemm_cpu(&a, &a, 4, 4, 4, Semiring::Lineage);
        assert_eq!(
            c[0 * 4 + 3],
            f1 | f2 | f3 | f4,
            "expected union over both paths"
        );
    }

    #[test]
    fn cpu_max_plus_longest_path() {
        // 0→1 weight 5, 1→2 weight 3. (max,+) squared: longest path 0→2 = 8.
        let a = vec![
            0, 5, 0, // row 0
            0, 0, 3, // row 1
            0, 0, 0, // row 2
        ];
        let c = semiring_gemm_cpu(&a, &a, 3, 3, 3, Semiring::MaxPlus);
        assert_eq!(c[0 * 3 + 2], 8);
    }

    #[test]
    fn cpu_gf2_xor_closure() {
        // GF(2): (×, +) over Z/2 = (∧, ⊕). Should be the boolean XOR-AND ring.
        let a = vec![1, 0, 1, 1];
        let b = vec![1, 1, 0, 1];
        // c[0,0] = (1∧1) ⊕ (0∧0) = 1
        // c[0,1] = (1∧1) ⊕ (0∧1) = 1
        // c[1,0] = (1∧1) ⊕ (1∧0) = 1
        // c[1,1] = (1∧1) ⊕ (1∧1) = 0
        let c = semiring_gemm_cpu(&a, &b, 2, 2, 2, Semiring::Gf2);
        assert_eq!(c, vec![1, 1, 1, 0]);
    }

    #[test]
    fn cpu_max_times_viterbi() {
        // (×, max): emission-times-transition along best path.
        // start probs * trans probs over 1 step, 2 states:
        // a = [0.5, 0.5] (as fixed-point u32: 50, 50)
        // b = [[0.6, 0.4], [0.3, 0.7]] (60/40, 30/70)
        let a = vec![50, 50];
        let b = vec![60, 40, 30, 70];
        // c[0,0] = max(50*60, 50*30) = max(3000, 1500) = 3000
        // c[0,1] = max(50*40, 50*70) = max(2000, 3500) = 3500
        let c = semiring_gemm_cpu(&a, &b, 1, 2, 2, Semiring::MaxTimes);
        assert_eq!(c, vec![3000, 3500]);
    }

    #[test]
    fn emitted_program_buffer_layout() {
        let p = semiring_gemm("A", "B", "C", 4, 5, 3, Semiring::Real);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["A", "B", "C"]);
        assert_eq!(p.buffers[0].count(), 4 * 3); // m*k
        assert_eq!(p.buffers[1].count(), 3 * 5); // k*n
        assert_eq!(p.buffers[2].count(), 4 * 5); // m*n
    }

    #[test]
    fn emitted_program_buffer_access_modes() {
        let p = semiring_gemm("A", "B", "C", 2, 2, 2, Semiring::MinPlus);
        assert_eq!(p.buffers[0].access(), BufferAccess::ReadOnly);
        assert_eq!(p.buffers[1].access(), BufferAccess::ReadOnly);
        assert_eq!(p.buffers[2].access(), BufferAccess::ReadWrite);
    }

    #[test]
    fn zero_m_traps() {
        let p = semiring_gemm("A", "B", "C", 0, 1, 1, Semiring::Real);
        assert!(p.stats().trap());
    }

    #[test]
    fn zero_n_traps() {
        let p = semiring_gemm("A", "B", "C", 1, 0, 1, Semiring::Real);
        assert!(p.stats().trap());
    }

    #[test]
    fn zero_k_traps() {
        let p = semiring_gemm("A", "B", "C", 1, 1, 0, Semiring::Real);
        assert!(p.stats().trap());
    }

    #[test]
    fn identity_table_matches_doc() {
        assert_eq!(Semiring::Real.identity(), 0);
        assert_eq!(Semiring::MinPlus.identity(), u32::MAX);
        assert_eq!(Semiring::MaxPlus.identity(), 0);
        assert_eq!(Semiring::MaxTimes.identity(), 0);
        assert_eq!(Semiring::BoolOr.identity(), 0);
        assert_eq!(Semiring::BoolAnd.identity(), u32::MAX);
        assert_eq!(Semiring::Gf2.identity(), 0);
        assert_eq!(Semiring::Lineage.identity(), 0);
    }
}
