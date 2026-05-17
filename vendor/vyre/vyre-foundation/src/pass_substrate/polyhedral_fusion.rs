//! Polyhedral / affine fusion queries over pass dependency graphs.

use super::dataflow_fixpoint::reachability_closure;

/// Return an `n x n` mask of independently fusable pass pairs.
///
/// `adj[i*n + j] != 0` means pass `i` must precede pass `j`. Two
/// passes are fusable when neither reaches the other in the transitive
/// dependency closure.
#[must_use]
pub fn fusable_pairs(adj: &[u32], n: u32, max_iters: u32) -> Vec<u32> {
    if n == 0 {
        return Vec::new();
    }
    let Some(cells) = n.checked_mul(n).map(|v| v as usize) else {
        return Vec::new();
    };
    if adj.len() != cells {
        return Vec::new();
    }
    let closure = reachability_closure(adj, n, max_iters.max(1));
    let n_usize = n as usize;
    let mut out = vec![0u32; n_usize * n_usize];
    for i in 0..n_usize {
        for j in 0..n_usize {
            if i != j && closure[i * n_usize + j] == 0 && closure[j * n_usize + i] == 0 {
                out[i * n_usize + j] = 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_passes_are_fusable() {
        // 3 passes, no dependencies → all pairs fusable.
        #[rustfmt::skip]
        let adj = vec![
            0, 0, 0,
            0, 0, 0,
            0, 0, 0,
        ];
        let fused = fusable_pairs(&adj, 3, 3);
        // (0,1), (1,0), (0,2), (2,0), (1,2), (2,1) should all be 1.
        assert_eq!(fused[0 * 3 + 1], 1);
        assert_eq!(fused[1 * 3 + 0], 1);
        assert_eq!(fused[0 * 3 + 2], 1);
        assert_eq!(fused[2 * 3 + 0], 1);
        // Diagonal is always 0 (can't fuse with self).
        assert_eq!(fused[0], 0);
    }

    #[test]
    fn dependent_passes_are_not_fusable() {
        // Chain: 0 → 1 → 2.
        #[rustfmt::skip]
        let adj = vec![
            0, 1, 0,
            0, 0, 1,
            0, 0, 0,
        ];
        let fused = fusable_pairs(&adj, 3, 3);
        // 0 reaches 1 and 2 transitively, 1 reaches 2. No independent pairs.
        assert_eq!(fused[0 * 3 + 1], 0);
        assert_eq!(fused[0 * 3 + 2], 0);
        assert_eq!(fused[1 * 3 + 2], 0);
    }

    #[test]
    fn diamond_top_and_bottom_not_fusable() {
        // Diamond: 0 → 1, 0 → 2, 1 → 3, 2 → 3.
        #[rustfmt::skip]
        let adj = vec![
            0, 1, 1, 0,
            0, 0, 0, 1,
            0, 0, 0, 1,
            0, 0, 0, 0,
        ];
        let fused = fusable_pairs(&adj, 4, 4);
        // 1 and 2 are independent (neither reaches the other).
        assert_eq!(fused[1 * 4 + 2], 1);
        assert_eq!(fused[2 * 4 + 1], 1);
        // 0 and 3 are NOT fusable (0 reaches 3 transitively).
        assert_eq!(fused[0 * 4 + 3], 0);
    }

    #[test]
    fn empty_graph_returns_empty() {
        let fused = fusable_pairs(&[], 0, 0);
        assert!(fused.is_empty());
    }
}
