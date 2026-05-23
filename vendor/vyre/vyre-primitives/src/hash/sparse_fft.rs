//! Sparse FFT primitives — Hassanieh-Indyk-Katabi-Price 2012.
//!
//! For a length-`n` signal whose frequency-domain support is k-sparse
//! (k nonzero coefficients, k ≪ n), the sparse FFT recovers the
//! support and values in `O(k log² n)` vs full FFT's `O(n log n)`.
//! For `k = √n` the speedup is √n; for k = polylog(n), it's
//! near-linear in k.
//!
//! Algorithm sketch (HIKP):
//! 1. **Permutation + filtering** — apply a random permutation to
//!    the time-domain signal and convolve with a flat-window filter.
//! 2. **Subsampled FFT** — small FFT of length B (B = O(k)).
//! 3. **Hashing + voting** — frequencies hash to B bins; the median
//!    over multiple permutations recovers k-sparse support.
//!
//! This file ships the **bin hashing** primitive — given a signal and
//! a permutation/filter pair, hash each frequency into one of B bins
//! and accumulate. Subsequent steps (subsampled FFT, voting) compose
//! from existing #4 NTT or future small-FFT primitives.
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | future `vyre-libs::signal::audio` | sparse audio analysis |
//! | future `vyre-libs::signal::radio` | sparse radio spectrum monitoring |
//! | future `vyre-libs::sci::imaging` | MRI / sparse-aperture imaging |
//!
//! Self-consumer is weak; flagged research-only in the frontier memo.
//! Shipping the primitive nonetheless unblocks future signal-domain
//! dialects.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::hash::sparse_fft_bin_hash";

/// Hash each frequency index `f` into one of `b` bins via a linear
/// hash `bin = (a · f + c) mod b`. Accumulate the signal's `f`-th
/// coefficient (already pre-filtered+permuted by the caller) into
/// `bins[bin]`. One workgroup cooperates over the signal with a
/// grid-stride loop and atomic bin accumulation, so hash collisions
/// preserve wrapping-add semantics without serializing all samples on
/// lane zero.
#[must_use]
pub fn sparse_fft_bin_hash(signal: &str, bins: &str, a: u32, c: u32, b: u32, n: u32) -> Program {
    if n == 0 {
        return crate::invalid_output_program(
            OP_ID,
            bins,
            DataType::U32,
            format!("Fix: sparse_fft_bin_hash requires n > 0, got {n}."),
        );
    }
    if b == 0 {
        return crate::invalid_output_program(
            OP_ID,
            bins,
            DataType::U32,
            format!("Fix: sparse_fft_bin_hash requires b > 0, got {b}."),
        );
    }

    let local = Expr::LocalId { axis: 0 };
    let body = vec![Node::if_then(
        Expr::eq(Expr::WorkgroupId { axis: 0 }, Expr::u32(0)),
        vec![Node::loop_for(
            "chunk",
            Expr::u32(0),
            Expr::div(Expr::add(Expr::u32(n), Expr::u32(255)), Expr::u32(256)),
            vec![
                Node::let_bind(
                    "f",
                    Expr::add(Expr::mul(Expr::var("chunk"), Expr::u32(256)), local),
                ),
                Node::if_then(
                    Expr::lt(Expr::var("f"), Expr::u32(n)),
                    vec![
                        Node::let_bind(
                            "bin",
                            Expr::rem(
                                Expr::add(Expr::mul(Expr::u32(a), Expr::var("f")), Expr::u32(c)),
                                Expr::u32(b),
                            ),
                        ),
                        Node::let_bind(
                            "_old_bin",
                            Expr::atomic_add(
                                bins,
                                Expr::var("bin"),
                                Expr::load(signal, Expr::var("f")),
                            ),
                        ),
                    ],
                ),
            ],
        )],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(signal, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(bins, 1, BufferAccess::ReadWrite, DataType::U32).with_count(b),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference: linear-hash binning of an arbitrary numeric signal.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn sparse_fft_bin_hash_cpu(signal: &[u32], a: u32, c: u32, b: u32) -> Vec<u32> {
    let mut bins = vec![0u32; b as usize];
    for (f, &v) in signal.iter().enumerate() {
        let f = f as u32;
        let bin = a.wrapping_mul(f).wrapping_add(c) % b;
        bins[bin as usize] = bins[bin as usize].wrapping_add(v);
    }
    bins
}

/// Voting recovery (CPU helper): given `m` binnings under different
/// (a, c) pairs, find the indices most consistently mapped to the
/// same bin (heuristic median-vote support recovery).
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn voting_recovery_cpu(
    binnings: &[(u32, u32, Vec<u32>)],
    threshold: u32,
    n: u32,
    b: u32,
) -> Vec<u32> {
    let n = n as usize;
    let mut votes = vec![0u32; n];
    for (a, c, bins) in binnings {
        for (f, vote) in votes.iter_mut().enumerate() {
            let bin = (a.wrapping_mul(f as u32).wrapping_add(*c) % b) as usize;
            // If this bin has nonzero energy, vote for f.
            if bins[bin] > 0 {
                *vote = vote.wrapping_add(1);
            }
        }
    }
    (0..n)
        .filter(|&f| votes[f] >= threshold)
        .map(|f| f as u32)
        .collect()
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || sparse_fft_bin_hash("signal", "bins", 1, 0, 4, 8),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[1, 2, 3, 4, 5, 6, 7, 8]),
                to_bytes(&[0, 0, 0, 0]),
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[6, 8, 10, 12])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_hash_distributes_across_bins() {
        let signal = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let bins = sparse_fft_bin_hash_cpu(&signal, 1, 0, 4);
        // Identity hash bin = f % 4.
        // bin 0: f∈{0,4}, value 1+5 = 6
        // bin 1: f∈{1,5}, value 2+6 = 8
        // bin 2: f∈{2,6}, value 3+7 = 10
        // bin 3: f∈{3,7}, value 4+8 = 12
        assert_eq!(bins, vec![6, 8, 10, 12]);
    }

    #[test]
    fn cpu_constant_hash_a_zero_collapses_to_one_bin() {
        let signal = vec![1, 2, 3, 4];
        let bins = sparse_fft_bin_hash_cpu(&signal, 0, 1, 4);
        // a=0, c=1 → all f map to bin 1.
        assert_eq!(bins[1], 10);
        assert_eq!(bins[0], 0);
    }

    #[test]
    fn cpu_voting_picks_signaled_indices() {
        // Synthetic: indices 2 and 5 carry energy across multiple
        // hash patterns.
        let mut signal = vec![0u32; 8];
        signal[2] = 100;
        signal[5] = 100;
        let h1 = sparse_fft_bin_hash_cpu(&signal, 3, 0, 4);
        let h2 = sparse_fft_bin_hash_cpu(&signal, 5, 1, 4);
        let h3 = sparse_fft_bin_hash_cpu(&signal, 7, 2, 4);
        let recovered = voting_recovery_cpu(&[(3, 0, h1), (5, 1, h2), (7, 2, h3)], 3, 8, 4);
        assert!(recovered.contains(&2));
        assert!(recovered.contains(&5));
    }

    #[test]
    fn cpu_zero_signal_zero_bins() {
        let signal = vec![0u32; 8];
        let bins = sparse_fft_bin_hash_cpu(&signal, 1, 0, 4);
        assert_eq!(bins, vec![0; 4]);
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = sparse_fft_bin_hash("sig", "bins", 7, 1, 8, 64);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["sig", "bins"]);
        assert_eq!(p.buffers[0].count(), 64);
        assert_eq!(p.buffers[1].count(), 8);
    }

    #[test]
    fn ir_uses_parallel_atomic_bin_accumulation() {
        let p = sparse_fft_bin_hash("sig", "bins", 7, 1, 8, 64);
        let entry = format!("{:?}", p.entry());
        assert!(
            entry.contains("Atomic"),
            "Fix: sparse_fft_bin_hash must use atomic bin accumulation instead of serial stores: {entry}"
        );
        assert!(
            entry.contains("LocalId"),
            "Fix: sparse_fft_bin_hash must distribute samples across local lanes: {entry}"
        );
    }

    #[test]
    fn zero_n_traps() {
        let p = sparse_fft_bin_hash("s", "b", 1, 0, 4, 0);
        assert!(p.stats().trap());
    }

    #[test]
    fn zero_b_traps() {
        let p = sparse_fft_bin_hash("s", "b", 1, 0, 0, 4);
        assert!(p.stats().trap());
    }
}
