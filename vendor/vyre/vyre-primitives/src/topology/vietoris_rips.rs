//! Vietoris-Rips filtration boundary primitive (#15).
//!
//! Persistent homology computes topological features (connected
//! components, loops, voids) of point clouds across multiple scales.
//! The Vietoris-Rips (V-R) filtration builds simplicial complexes by
//! adding all simplices whose pairwise distances are below a
//! threshold ε. Recent work (Bauer 2021 Ripser++, Lewis 2024 chunked
//! GPU reduction) makes V-R practical at billions of simplices.
//!
//! This file ships the **edge filtration step** primitive — given
//! a pairwise-distance matrix and the current threshold ε, output a
//! sorted list of edges (pairs of vertices) whose distance ≤ ε. Edges
//! are encoded as `u32` packed `(u_vertex << 16) | v_vertex`.
//!
//! Composes with #1 semiring_gemm (boundary matrix products = MinPlus
//! semiring on the edge incidence matrix) for the chunk-reduction
//! step that extracts persistence pairs.
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | future `vyre-libs::topology::tda` | shape analysis, anomaly detection |
//! | future `vyre-libs::ml::scattering` | persistent landscape features for NN inputs |
//! | future `vyre-libs::security::callgraph_topology` | call-graph topological signature |

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::topology::vietoris_rips_edge_filter";

/// Emit the edge filter Program.
///
/// Inputs:
/// - `dist_matrix`: row-major `n × n` u32 (pairwise distances, 16.16
///   fp). Symmetric with zero diagonal.
/// - `epsilon`: 1-element u32 — current scale.
///
/// Output:
/// - `edge_mask`: row-major `n × n` u32 — `1` if (i, j) is an edge
///   at scale ε (i < j AND dist[i, j] ≤ ε), else `0`. Half of the
///   matrix (lower triangular) is zero by construction (i ≥ j).
///
/// Lane `t` = flattened (i, j) cell. Caller composes with stream-
/// compaction to extract the actual edge list.
#[must_use]
pub fn vietoris_rips_edge_filter(
    dist_matrix: &str,
    epsilon: &str,
    edge_mask: &str,
    n: u32,
) -> Program {
    if n == 0 {
        return crate::invalid_output_program(
            OP_ID,
            edge_mask,
            DataType::U32,
            format!("Fix: vietoris_rips_edge_filter requires n > 0, got {n}."),
        );
    }

    let cells = n * n;
    let t = Expr::InvocationId { axis: 0 };
    let i_expr = Expr::div(t.clone(), Expr::u32(n));
    let j_expr = Expr::rem(t.clone(), Expr::u32(n));

    // Edge mask: 1 iff (i < j) AND (dist[i, j] ≤ ε)
    let in_upper = Expr::lt(i_expr, j_expr);
    let in_eps = Expr::le(
        Expr::load(dist_matrix, t.clone()),
        Expr::load(epsilon, Expr::u32(0)),
    );
    let value = Expr::select(Expr::and(in_upper, in_eps), Expr::u32(1), Expr::u32(0));

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(cells)),
        vec![Node::store(edge_mask, t, value)],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(dist_matrix, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(cells),
            BufferDecl::storage(epsilon, 1, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage(edge_mask, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(cells),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference: emit edge mask as a flat row-major `n × n` array.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn vietoris_rips_edge_filter_cpu(dist_matrix: &[f64], epsilon: f64, n: u32) -> Vec<u32> {
    let n = n as usize;
    let mut out = vec![0u32; n * n];
    for i in 0..n {
        for j in 0..n {
            let addr = i * n + j;
            if i < j && dist_matrix.get(addr).copied().unwrap_or(f64::INFINITY) <= epsilon {
                out[addr] = 1;
            }
        }
    }
    out
}

/// CPU helper: extract the edge list from a mask. Returns
/// `Vec<(u_vertex, v_vertex)>`.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn extract_edges_cpu(edge_mask: &[u32], n: u32) -> Vec<(u32, u32)> {
    let n = n as usize;
    let mut edges = Vec::new();
    for i in 0..n {
        for j in (i + 1)..n {
            if edge_mask.get(i * n + j).copied().unwrap_or(0) != 0 {
                edges.push((i as u32, j as u32));
            }
        }
    }
    edges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_edge_filter_full_threshold_includes_all() {
        // 3 points at unit triangle: dist 1.0 between all pairs.
        let d = vec![0.0, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 1.0, 0.0];
        let mask = vietoris_rips_edge_filter_cpu(&d, 1.0, 3);
        // Upper triangular pairs: (0,1), (0,2), (1,2) all included.
        assert_eq!(mask[0 * 3 + 1], 1);
        assert_eq!(mask[0 * 3 + 2], 1);
        assert_eq!(mask[1 * 3 + 2], 1);
        // Diagonal + lower triangular zeros.
        for i in 0..3 {
            assert_eq!(mask[i * 3 + i], 0);
        }
        assert_eq!(mask[1 * 3 + 0], 0);
        assert_eq!(mask[2 * 3 + 0], 0);
        assert_eq!(mask[2 * 3 + 1], 0);
    }

    #[test]
    fn cpu_edge_filter_low_threshold_excludes() {
        let d = vec![0.0, 1.0, 5.0, 1.0, 0.0, 5.0, 5.0, 5.0, 0.0];
        let mask = vietoris_rips_edge_filter_cpu(&d, 2.0, 3);
        assert_eq!(mask[0 * 3 + 1], 1); // dist 1, included
        assert_eq!(mask[0 * 3 + 2], 0); // dist 5, excluded
        assert_eq!(mask[1 * 3 + 2], 0);
    }

    #[test]
    fn cpu_extract_edges_returns_correct_pairs() {
        let mask = vec![0u32, 1, 0, 0, 0, 1, 0, 0, 0];
        let edges = extract_edges_cpu(&mask, 3);
        assert_eq!(edges, vec![(0, 1), (1, 2)]);
    }

    #[test]
    fn cpu_short_buffers_treat_missing_entries_as_absent() {
        let mask = vietoris_rips_edge_filter_cpu(&[0.0, 0.5], 1.0, 2);
        assert_eq!(mask, vec![0, 1, 0, 0]);

        let edges = extract_edges_cpu(&[0, 1], 2);
        assert_eq!(edges, vec![(0, 1)]);
        assert!(extract_edges_cpu(&[0], 2).is_empty());
    }

    #[test]
    fn cpu_zero_threshold_no_edges() {
        let d = vec![0.0, 0.5, 0.5, 0.5, 0.0, 0.5, 0.5, 0.5, 0.0];
        let mask = vietoris_rips_edge_filter_cpu(&d, 0.0, 3);
        for v in mask {
            assert_eq!(v, 0);
        }
    }

    #[test]
    fn cpu_filtration_grows_monotonically() {
        // As ε increases, the number of edges only grows.
        let d = vec![0.0, 1.0, 3.0, 1.0, 0.0, 2.0, 3.0, 2.0, 0.0];
        let edges_eps1 = extract_edges_cpu(&vietoris_rips_edge_filter_cpu(&d, 1.0, 3), 3);
        let edges_eps2 = extract_edges_cpu(&vietoris_rips_edge_filter_cpu(&d, 2.0, 3), 3);
        let edges_eps3 = extract_edges_cpu(&vietoris_rips_edge_filter_cpu(&d, 3.0, 3), 3);
        assert!(edges_eps1.len() <= edges_eps2.len());
        assert!(edges_eps2.len() <= edges_eps3.len());
        assert_eq!(edges_eps3.len(), 3); // all 3 upper-tri edges
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = vietoris_rips_edge_filter("d", "e", "m", 4);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["d", "e", "m"]);
        assert_eq!(p.buffers[0].count(), 16);
        assert_eq!(p.buffers[1].count(), 1);
        assert_eq!(p.buffers[2].count(), 16);
    }

    #[test]
    fn zero_n_traps() {
        let p = vietoris_rips_edge_filter("d", "e", "m", 0);
        assert!(p.stats().trap());
    }
}
